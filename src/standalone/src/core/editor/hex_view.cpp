#include "hex_view.hpp"

#include "../analysis/workspace/overlay_journal.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/hex_preview_adapter.hpp"
#else
#include "../infra/taskflow_runtime.hpp"
#include "standalone_driver.hpp"
#endif
#include "../ui/components.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "../ui/metrics.hpp"
#include "../ui/task_center.hpp"
#include "../ui/theme.hpp"
#include "../infra/executor.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../ui/ui_thread_dispatcher.hpp"
#endif

#include "imgui/imgui.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hex_view {

namespace {

struct patch_span_t {
    std::uint64_t offset = 0;
    std::vector<std::uint8_t> bytes;
};

struct state_t {
    std::uint64_t base_addr = 0;
    std::string source_name;
    bool active = false;
    std::int64_t sel_start = -1;
    std::int64_t sel_end = -1;
    bool selecting = false;
    float scroll_y = 0.0f;
    float target_scroll_y = 0.0f;
    bool goto_visible = false;
    char goto_buf[32] = {};
    bool search_visible = false;
    char search_buf[256] = {};
    bool search_hex = true;
    std::int64_t search_match = -1;
    std::uint64_t search_match_len = 0;
    std::int64_t search_match_idx = -1;
    std::vector<std::uint64_t> search_matches;
    std::string search_last_query;
    bool search_last_hex = true;
    std::uint64_t context_offset = 0;
    std::uint64_t context_generation = 0;
    std::uint64_t context_overlay_revision = 0;
    std::uint8_t context_value = 0;
    bool context_live = false;
    bool context_valid = false;
};

enum class source_kind_t : std::uint8_t {
    workspace_provider,
    live_memory
};

struct workspace_hex_state_t final : aida::analysis::workspace_lifecycle_participant_t {
    std::mutex mutex;
    state_t ui;
    std::weak_ptr<aida::analysis::analysis_workspace_t> owner;
    aida::analysis::binary_id_t owner_id;
    source_kind_t source_kind = source_kind_t::workspace_provider;
    std::vector<std::uint8_t> live_bytes;
    std::uint64_t live_base = 0;
    aida::analysis::byte_view_t window;
    std::uint64_t window_offset = 0;
    std::uint64_t window_size = 0;
    std::uint64_t patch_revision = (std::numeric_limits<std::uint64_t>::max)();
    std::vector<patch_span_t> patches;
    std::atomic<bool> patch_refreshing{false};
    std::shared_ptr<aida::analysis::cancellation_source_t> search_cancellation;
    std::atomic<std::uint64_t> search_serial{1};
    std::atomic<bool> searching{false};
    std::atomic<bool> live_loading{false};
    std::atomic<std::uint64_t> live_request_serial{0};
    std::atomic<std::uint64_t> live_dispatch_failure_serial{0};
    std::shared_ptr<std::atomic<bool>> live_cancellation;
    std::atomic<bool> cancelled{false};
    std::atomic<std::uint32_t> pending_jobs{0};
    std::mutex drain_mutex;
    std::condition_variable drain_cv;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::infra::taskflow_runtime::job_handle_t patch_job;
    aida::infra::taskflow_runtime::job_handle_t search_job;
#endif
    std::uint64_t scroll_to_offset = (std::numeric_limits<std::uint64_t>::max)();
    std::string error;

    void request_cancel() noexcept override;
    aida::analysis::workspace_result_t<void> drain(
        std::chrono::steady_clock::time_point deadline) override;
};

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
struct pending_job_t final {
    explicit pending_job_t(std::shared_ptr<workspace_hex_state_t> state_value)
        : state(std::move(state_value)) {
        state->pending_jobs.fetch_add(1, std::memory_order_acq_rel);
    }

    ~pending_job_t() {
        state->pending_jobs.fetch_sub(1, std::memory_order_acq_rel);
        state->drain_cv.notify_all();
    }

    std::shared_ptr<workspace_hex_state_t> state;
};
#endif

std::mutex& registry_mutex() {
    static std::mutex value;
    return value;
}

std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<workspace_hex_state_t>,
    aida::analysis::binary_id_hash_t>& registry() {
    static std::unordered_map<aida::analysis::binary_id_t,
        std::shared_ptr<workspace_hex_state_t>, aida::analysis::binary_id_hash_t> value;
    return value;
}

void unregister_state(const aida::analysis::binary_id_t& id,
                      const workspace_hex_state_t* state) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    auto& values = registry();
    const auto found = values.find(id);
    if (found != values.end() && found->second.get() == state)
        values.erase(found);
}

void workspace_hex_state_t::request_cancel() noexcept {
    cancelled.store(true, std::memory_order_release);
    std::shared_ptr<aida::analysis::cancellation_source_t> search;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::infra::taskflow_runtime::job_handle_t patch;
    aida::infra::taskflow_runtime::job_handle_t search_task;
#endif
    {
        std::lock_guard<std::mutex> lock(mutex);
        search = search_cancellation;
        search_cancellation.reset();
        if (live_cancellation)
            live_cancellation->store(true, std::memory_order_release);
        live_cancellation.reset();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        patch = patch_job;
        search_task = search_job;
        patch_job = {};
        search_job = {};
#endif
        window = {};
        window_size = 0;
        live_bytes.clear();
    }
    live_loading.store(false, std::memory_order_release);
    live_request_serial.fetch_add(1, std::memory_order_acq_rel);
    if (search)
        search->request_cancel();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (patch.valid())
        aida::infra::taskflow_runtime::cancel(patch);
    if (search_task.valid())
        aida::infra::taskflow_runtime::cancel(search_task);
#endif
    unregister_state(owner_id, this);
}

aida::analysis::workspace_result_t<void> workspace_hex_state_t::drain(
    std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(drain_mutex);
    if (!drain_cv.wait_until(lock, deadline, [this] {
        return pending_jobs.load(std::memory_order_acquire) == 0;
    }))
        return aida::analysis::workspace_result_t<void>::failure(
            aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::deadline_exceeded,
                "hex view cancellation reached its workspace close deadline", "hex_view"));
    return aida::analysis::workspace_result_t<void>::success();
}

bool state_matches(const disasm_view::workspace_context_t& context,
                   const std::shared_ptr<workspace_hex_state_t>& state) {
    if (!context.workspace || !state || state->cancelled.load(std::memory_order_acquire))
        return false;
    const auto owner = state->owner.lock();
    return owner && owner == context.workspace && !owner->closing() && !owner->closed();
}

std::shared_ptr<workspace_hex_state_t> state_for(
    const disasm_view::workspace_context_t& context) {
    if (!context.workspace || context.workspace->closing() || context.workspace->closed())
        return {};
    const auto id = context.workspace->identity().binary_id();
    auto created = std::make_shared<workspace_hex_state_t>();
    created->owner = context.workspace;
    created->owner_id = id;
    created->ui.active = true;
    created->ui.base_addr = context.workspace->identity().image_base();
    created->ui.source_name = context.workspace->identity().bin_name();
    {
        std::lock_guard<std::mutex> lock(registry_mutex());
        auto& values = registry();
        auto found = values.find(id);
        if (found != values.end() && state_matches(context, found->second))
            return found->second;
        if (found != values.end())
            values.erase(found);
        values.emplace(id, created);
    }
    auto registered = context.workspace->register_lifecycle_participant(created);
    if (!registered) {
        created->request_cancel();
        return {};
    }
    return created;
}

std::optional<std::vector<std::uint8_t>> parse_hex(std::string text) {
    std::vector<std::uint8_t> output;
    int high = -1;
    for (char character : text) {
        if (std::isspace(static_cast<unsigned char>(character)))
            continue;
        int value = -1;
        if (character >= '0' && character <= '9')
            value = character - '0';
        else if (character >= 'a' && character <= 'f')
            value = character - 'a' + 10;
        else if (character >= 'A' && character <= 'F')
            value = character - 'A' + 10;
        else
            return {};
        if (high < 0)
            high = value;
        else {
            output.push_back(static_cast<std::uint8_t>((high << 4) | value));
            high = -1;
        }
    }
    if (high >= 0 || output.empty())
        return {};
    return output;
}

std::vector<std::uint8_t> search_pattern(const state_t& state) {
    if (state.search_hex) {
        auto parsed = parse_hex(state.search_buf);
        return parsed ? std::move(*parsed) : std::vector<std::uint8_t>();
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(state.search_buf);
    return std::vector<std::uint8_t>(begin, begin + std::strlen(state.search_buf));
}

void request_patch_refresh(const disasm_view::workspace_context_t& context,
                           const std::shared_ptr<workspace_hex_state_t>& state) {
    if (!state_matches(context, state))
        return;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->source_kind != source_kind_t::workspace_provider ||
            state->patch_revision == context.workspace->overlay_revision())
            return;
    }
    if (state->patch_refreshing.exchange(true, std::memory_order_acq_rel))
        return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::vector<patch_span_t> patches;
    if (auto overlay = context.workspace->overlay()) {
        const auto operations = overlay->patch_operations();
        patches.reserve(operations.size());
        for (const auto& operation : operations) {
            const auto offset = disasm_view::provider_offset(context, operation.address);
            if (!offset || operation.bytes.empty())
                continue;
            patches.push_back({*offset, operation.bytes});
        }
        std::sort(patches.begin(), patches.end(), [](const auto& left, const auto& right) {
            return left.offset < right.offset;
        });
    }
    if (state_matches(context, state)) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->patches = std::move(patches);
        state->patch_revision = context.workspace->overlay_revision();
    }
    state->patch_refreshing.store(false, std::memory_order_release);
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    auto pending = std::make_shared<pending_job_t>(state);
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "hex_view";
    descriptor.label = "refresh_workspace_patches";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, pending](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::vector<patch_span_t> patches;
        if (!cancel.requested.load(std::memory_order_acquire) && state_matches(context, state)) {
            if (auto overlay = context.workspace->overlay()) {
                const auto operations = overlay->patch_operations();
                patches.reserve(operations.size());
                for (const auto& operation : operations) {
                    if (cancel.requested.load(std::memory_order_acquire))
                        break;
                    const auto offset = disasm_view::provider_offset(context, operation.address);
                    if (!offset || operation.bytes.empty())
                        continue;
                    patches.push_back({*offset, operation.bytes});
                }
                std::sort(patches.begin(), patches.end(), [](const auto& left, const auto& right) {
                    return left.offset < right.offset;
                });
            }
        }
        if (state_matches(context, state)) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->patches = std::move(patches);
            state->patch_revision = context.workspace->overlay_revision();
        }
        state->patch_refreshing.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->patch_refreshing.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = submitted.reject_reason;
    } else {
        bool cancel_submitted = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            cancel_submitted = state->cancelled.load(std::memory_order_acquire);
            if (!cancel_submitted)
                state->patch_job = submitted.handle;
        }
        if (cancel_submitted)
            aida::infra::taskflow_runtime::cancel(submitted.handle);
    }
#endif
}

bool ensure_window(const disasm_view::workspace_context_t& context,
                   const std::shared_ptr<workspace_hex_state_t>& state,
                   std::uint64_t begin, std::uint64_t end) {
    if (!state_matches(context, state) || begin >= end)
        return false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->source_kind == source_kind_t::live_memory)
            return end <= state->live_bytes.size();
        if (end > context.workspace->provider().size())
            return false;
        if (!state->window.empty() && begin >= state->window_offset &&
            end <= state->window_offset + state->window_size)
            return true;
    }
    constexpr std::uint64_t window_capacity = 4ULL << 20;
    const std::uint64_t aligned = begin & ~static_cast<std::uint64_t>(0xFFFF);
    const std::uint64_t required = end - aligned;
    const std::uint64_t available = context.workspace->provider().size() - aligned;
    const std::uint64_t length = (std::min)(available,
        (std::max)(required, window_capacity));
    auto lease = context.workspace->provider().lease(aligned, length,
        context.workspace->cancellation_token());
    if (!lease) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = lease.error().stable_code() + ": " + lease.error().message;
        state->window = {};
        state->window_size = 0;
        return false;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    state->window = lease.take_value();
    state->window_offset = aligned;
    state->window_size = length;
    state->error.clear();
    return true;
}

std::uint8_t patched_byte(const workspace_hex_state_t& state,
                          std::uint64_t offset, std::uint8_t original,
                          bool* patched) {
    if (patched)
        *patched = false;
    auto found = std::upper_bound(state.patches.begin(), state.patches.end(), offset,
        [](std::uint64_t value, const patch_span_t& span) {
            return value < span.offset;
        });
    if (found == state.patches.begin())
        return original;
    --found;
    if (offset < found->offset || offset - found->offset >= found->bytes.size())
        return original;
    if (patched)
        *patched = true;
    return found->bytes[static_cast<std::size_t>(offset - found->offset)];
}

void start_search(const disasm_view::workspace_context_t& context,
                  const std::shared_ptr<workspace_hex_state_t>& state) {
    std::vector<std::uint8_t> pattern;
    std::vector<std::uint8_t> live_source;
    std::uint64_t serial = 0;
    std::shared_ptr<aida::analysis::cancellation_source_t> cancellation;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        pattern = search_pattern(state->ui);
        if (pattern.empty()) {
            state->error = "Search pattern is empty or malformed.";
            return;
        }
        if (state->search_cancellation)
            state->search_cancellation->request_cancel();
        cancellation = std::make_shared<aida::analysis::cancellation_source_t>();
        state->search_cancellation = cancellation;
        serial = state->search_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
        state->ui.search_matches.clear();
        state->ui.search_match = -1;
        state->ui.search_match_idx = -1;
        state->ui.search_match_len = pattern.size();
        state->error.clear();
        if (state->source_kind == source_kind_t::live_memory)
            live_source = state->live_bytes;
    }
    state->searching.store(true, std::memory_order_release);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    constexpr std::uint64_t chunk_size = 4ULL << 20;
    constexpr std::size_t maximum_matches = 100000;
    std::vector<std::uint64_t> matches;
    std::uint64_t cursor = 0;
    if (!live_source.empty() && state_matches(context, state) &&
        !cancellation->token().stop_requested()) {
        auto found = std::search(live_source.begin(), live_source.end(),
            pattern.begin(), pattern.end());
        while (found != live_source.end() && matches.size() < maximum_matches &&
               !cancellation->token().stop_requested()) {
            matches.push_back(static_cast<std::uint64_t>(
                std::distance(live_source.begin(), found)));
            found = std::search(found + 1, live_source.end(), pattern.begin(), pattern.end());
        }
    }
    while (live_source.empty() && cursor < context.workspace->provider().size() &&
           matches.size() < maximum_matches && state_matches(context, state) &&
           !cancellation->token().stop_requested()) {
        const std::uint64_t remaining = context.workspace->provider().size() - cursor;
        const std::uint64_t length = (std::min)(remaining, chunk_size);
        auto lease = context.workspace->provider().lease(cursor, length,
            cancellation->token());
        if (!lease)
            break;
        const auto& view = lease.value();
        if (view.size() >= pattern.size()) {
            auto found = std::search(view.begin(), view.end(), pattern.begin(), pattern.end());
            while (found != view.end() && matches.size() < maximum_matches) {
                matches.push_back(cursor + static_cast<std::uint64_t>(
                    std::distance(view.begin(), found)));
                found = std::search(found + 1, view.end(), pattern.begin(), pattern.end());
            }
        }
        if (length == remaining)
            break;
        const std::uint64_t overlap = pattern.size() > 1 ? pattern.size() - 1 : 0;
        cursor += length - (std::min)(length - 1, overlap);
    }
    if (state_matches(context, state)) {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->search_serial.load(std::memory_order_acquire) == serial) {
            state->ui.search_matches = std::move(matches);
            state->ui.search_match_idx = state->ui.search_matches.empty() ? -1 : 0;
            state->ui.search_match = state->ui.search_matches.empty() ? -1 :
                static_cast<std::int64_t>(state->ui.search_matches.front());
            if (!state->ui.search_matches.empty())
                state->scroll_to_offset = state->ui.search_matches.front();
        }
    }
    state->searching.store(false, std::memory_order_release);
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    auto pending = std::make_shared<pending_job_t>(state);
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "hex_view";
    descriptor.label = "search_workspace_bytes";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, pending, pattern = std::move(pattern),
                                   live_source = std::move(live_source), cancellation, serial](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        constexpr std::uint64_t chunk_size = 4ULL << 20;
        constexpr std::size_t maximum_matches = 100000;
        std::vector<std::uint64_t> matches;
        std::uint64_t cursor = 0;
        if (!live_source.empty() && state_matches(context, state) &&
            !runtime_cancel.requested.load(std::memory_order_acquire) &&
            !cancellation->token().stop_requested()) {
            auto found = std::search(live_source.begin(), live_source.end(),
                pattern.begin(), pattern.end());
            while (found != live_source.end() && matches.size() < maximum_matches &&
                   !runtime_cancel.requested.load(std::memory_order_acquire) &&
                   !cancellation->token().stop_requested()) {
                matches.push_back(static_cast<std::uint64_t>(
                    std::distance(live_source.begin(), found)));
                found = std::search(found + 1, live_source.end(), pattern.begin(), pattern.end());
            }
        }
        while (live_source.empty() && cursor < context.workspace->provider().size() &&
               matches.size() < maximum_matches &&
               state_matches(context, state) &&
               !runtime_cancel.requested.load(std::memory_order_acquire) &&
               !cancellation->token().stop_requested()) {
            const std::uint64_t remaining = context.workspace->provider().size() - cursor;
            const std::uint64_t length = (std::min)(remaining, chunk_size);
            auto lease = context.workspace->provider().lease(cursor, length,
                cancellation->token());
            if (!lease)
                break;
            const auto& view = lease.value();
            if (view.size() >= pattern.size()) {
                auto found = std::search(view.begin(), view.end(), pattern.begin(), pattern.end());
                while (found != view.end() && matches.size() < maximum_matches) {
                    matches.push_back(cursor + static_cast<std::uint64_t>(
                        std::distance(view.begin(), found)));
                    found = std::search(found + 1, view.end(), pattern.begin(), pattern.end());
                }
            }
            if (length == remaining)
                break;
            const std::uint64_t overlap = pattern.size() > 1 ? pattern.size() - 1 : 0;
            cursor += length - (std::min)(length - 1, overlap);
        }
        if (state_matches(context, state)) {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->search_serial.load(std::memory_order_acquire) == serial) {
                state->ui.search_matches = std::move(matches);
                state->ui.search_match_idx = state->ui.search_matches.empty() ? -1 : 0;
                state->ui.search_match = state->ui.search_matches.empty() ? -1 :
                    static_cast<std::int64_t>(state->ui.search_matches.front());
                if (!state->ui.search_matches.empty()) {
                    state->scroll_to_offset = state->ui.search_matches.front();
                }
            }
        }
        state->searching.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->searching.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = submitted.reject_reason;
    } else {
        bool cancel_submitted = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            cancel_submitted = state->cancelled.load(std::memory_order_acquire);
            if (!cancel_submitted)
                state->search_job = submitted.handle;
        }
        if (cancel_submitted)
            aida::infra::taskflow_runtime::cancel(submitted.handle);
    }
#endif
}

void step_search_result(const std::shared_ptr<workspace_hex_state_t>& state, int direction) {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->ui.search_matches.empty())
        return;
    const std::int64_t count = static_cast<std::int64_t>((std::min)(
        state->ui.search_matches.size(),
        static_cast<std::size_t>((std::numeric_limits<std::int64_t>::max)())));
    std::int64_t index = state->ui.search_match_idx;
    if (index < 0 || index >= count)
        index = direction < 0 ? count - 1 : 0;
    else
        index = (index + (direction < 0 ? -1 : 1) + count) % count;
    state->ui.search_match_idx = index;
    state->ui.search_match = static_cast<std::int64_t>(
        state->ui.search_matches[static_cast<std::size_t>(index)]);
    state->scroll_to_offset = state->ui.search_matches[static_cast<std::size_t>(index)];
}

std::optional<std::uint64_t> parse_u64(std::string text) {
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return result.ec == std::errc() && result.ptr == text.data() + text.size()
        ? std::optional<std::uint64_t>(value) : std::nullopt;
}

std::optional<aida::analysis::address_t> normalized_address_for_file_offset(
    const disasm_view::workspace_context_t& context,
    std::uint64_t offset) {
    if (!context.workspace)
        return {};
    const auto image = context.workspace->normalized_image();
    if (!image)
        return {};
    const auto& identity = context.workspace->identity();
    for (const auto& mapping : image->address_mappings) {
        if (mapping.source_space != aida::analysis::address_space_id_t::file_offset ||
            mapping.size == 0 || offset < mapping.source_start)
            continue;
        const std::uint64_t delta = offset - mapping.source_start;
        if (delta >= mapping.size)
            continue;
        if (mapping.target_start >
            (std::numeric_limits<std::uint64_t>::max)() - delta)
            return {};
        aida::analysis::address_t address;
        address.space = mapping.target_space;
        address.value = mapping.target_start + delta;
        address.architecture = identity.architecture();
        address.mode = image->architecture_mode;
        return address;
    }
    return {};
}

std::optional<std::uint64_t> display_address_for_file_offset(
    const disasm_view::workspace_context_t& context,
    std::uint64_t offset) {
    auto address = normalized_address_for_file_offset(context, offset);
    if (address) {
        if (address->space == aida::analysis::address_space_id_t::virtual_address)
            return address->value;
        if (address->space == aida::analysis::address_space_id_t::relative_virtual) {
            const auto image = context.workspace ? context.workspace->normalized_image() : nullptr;
            if (!image)
                return {};
            if (image->image_base >
                (std::numeric_limits<std::uint64_t>::max)() - address->value)
                return {};
            return image->image_base + address->value;
        }
    }
    if (context.image) {
        auto rva = context.image->file_offset_to_rva(offset);
        if (rva) {
            auto va = context.image->rva_to_va(rva.value());
            if (va)
                return va.value();
        }
    }
    return {};
}

std::optional<std::uint64_t> file_offset_for_normalized_address(
    const disasm_view::workspace_context_t& context,
    std::uint64_t value) {
    if (!context.workspace)
        return {};
    const auto image = context.workspace->normalized_image();
    if (!image)
        return {};
    const auto checked_mapping_offset = [&](aida::analysis::address_space_id_t target_space,
                                            std::uint64_t target_value) -> std::optional<std::uint64_t> {
        for (const auto& mapping : image->address_mappings) {
            if (mapping.source_space != aida::analysis::address_space_id_t::file_offset ||
                mapping.target_space != target_space || mapping.size == 0 ||
                target_value < mapping.target_start)
                continue;
            const std::uint64_t delta = target_value - mapping.target_start;
            if (delta >= mapping.size)
                continue;
            if (mapping.source_start >
                (std::numeric_limits<std::uint64_t>::max)() - delta)
                return {};
            return mapping.source_start + delta;
        }
        return {};
    };
    if (auto offset = checked_mapping_offset(
            aida::analysis::address_space_id_t::virtual_address, value))
        return offset;
    if (image->image_base <= value) {
        const std::uint64_t rva = value - image->image_base;
        if (auto offset = checked_mapping_offset(
                aida::analysis::address_space_id_t::relative_virtual, rva))
            return offset;
    }
    return checked_mapping_offset(aida::analysis::address_space_id_t::relative_virtual, value);
}

void copy_selection(const disasm_view::workspace_context_t& context,
                    const std::shared_ptr<workspace_hex_state_t>& state) {
    std::int64_t begin = -1;
    std::int64_t end = -1;
    std::vector<std::uint8_t> live_bytes;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        begin = state->ui.sel_start;
        end = state->ui.sel_end;
        if (state->source_kind == source_kind_t::live_memory)
            live_bytes = state->live_bytes;
    }
    if (begin < 0 || end < 0)
        return;
    if (begin > end)
        std::swap(begin, end);
    const std::uint64_t count = static_cast<std::uint64_t>(end - begin + 1);
    if (count > (1ULL << 20))
        return;
    std::vector<std::uint8_t> selected;
    if (!live_bytes.empty()) {
        if (static_cast<std::uint64_t>(end) >= live_bytes.size())
            return;
        using byte_difference_t = std::vector<std::uint8_t>::difference_type;
        if (end >= static_cast<std::int64_t>(std::numeric_limits<byte_difference_t>::max()))
            return;
        const auto first = static_cast<byte_difference_t>(begin);
        const auto last = static_cast<byte_difference_t>(end + 1);
        selected.assign(live_bytes.begin() + first, live_bytes.begin() + last);
    } else {
        auto bytes = context.workspace->provider().read_vector(static_cast<std::uint64_t>(begin),
            count, 1ULL << 20, context.workspace->cancellation_token());
        if (!bytes)
            return;
        selected = bytes.take_value();
    }
    std::string text;
    text.reserve(selected.size() * 3);
    char encoded[4]{};
    for (std::uint8_t byte : selected) {
        if (!text.empty())
            text.push_back(' ');
        std::snprintf(encoded, sizeof(encoded), "%02X", byte);
        text.append(encoded);
    }
    ImGui::SetClipboardText(text.c_str());
}

bool context_key_pressed() {
    return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
        (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

}

void activate(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->live_cancellation)
        state->live_cancellation->store(true, std::memory_order_release);
    state->live_cancellation.reset();
    state->live_request_serial.fetch_add(1, std::memory_order_acq_rel);
    state->live_loading.store(false, std::memory_order_release);
    state->source_kind = source_kind_t::workspace_provider;
    state->live_bytes.clear();
    state->live_base = 0;
    state->ui.base_addr = context.workspace->identity().image_base();
    state->ui.source_name = context.workspace->identity().bin_name();
    if (const auto& member = context.workspace->identity().normalized_member_path())
        state->ui.source_name.append("::").append(*member);
    state->ui.active = true;
    state->window = {};
    state->window_size = 0;
    state->patch_revision = (std::numeric_limits<std::uint64_t>::max)();
    state->patches.clear();
    state->error.clear();
}

bool focus_address(const disasm_view::workspace_context_t& context,
                   const aida::analysis::address_t& address,
                   std::string* error) {
    auto state = state_for(context);
    if (!state) {
        if (error) *error = "The selected workspace has no hex provider.";
        return false;
    }
    const auto offset = disasm_view::provider_offset(context, address);
    if (!offset || *offset >= context.workspace->provider().size() ||
        *offset > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
        if (error) *error = "The selected address has no mapped file or provider offset.";
        return false;
    }
    activate(context);
    std::lock_guard<std::mutex> lock(state->mutex);
    state->scroll_to_offset = *offset;
    state->ui.sel_start = static_cast<std::int64_t>(*offset);
    state->ui.sel_end = static_cast<std::int64_t>(*offset);
    state->error.clear();
    if (error) error->clear();
    return true;
}

bool request_live_memory(const disasm_view::workspace_context_t& context,
                         std::uint64_t address, std::size_t size) {
    auto state = state_for(context);
    if (!state)
        return false;
    if (!context.workspace->identity().process() || address == 0 || size == 0 ||
        size > (64ULL << 20) || address > (std::numeric_limits<std::uint64_t>::max)() -
            static_cast<std::uint64_t>(size - 1)) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = "INVALID_ARGUMENT: live-memory preview requires a bound process, address, and bounded size";
        return false;
    }
    const std::uint32_t pid = context.workspace->identity().process()->pid;
    const std::uint64_t generation = context.workspace->generation();
    const std::uint64_t serial = state->live_request_serial.fetch_add(1,
        std::memory_order_acq_rel) + 1;
    auto cancellation = std::make_shared<std::atomic<bool>>(false);
    const std::string task_id = "hex.live." + context.workspace->identity().binary_id().to_hex() +
        "." + std::to_string(serial);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->live_cancellation)
            state->live_cancellation->store(true, std::memory_order_release);
        state->live_cancellation = cancellation;
        state->source_kind = source_kind_t::live_memory;
        state->live_bytes.clear();
        state->live_base = address;
        state->ui.base_addr = address;
        state->ui.source_name = context.workspace->identity().bin_name() + " memory";
        state->ui.active = true;
        state->ui.sel_start = -1;
        state->ui.sel_end = -1;
        state->window = {};
        state->window_size = 0;
        state->patches.clear();
        state->error.clear();
    }
    state->live_loading.store(true, std::memory_order_release);

    aida::ui::task_center::task_registration_t registration;
    registration.id = task_id;
    registration.source = "hex_view";
    registration.owner = "Hex Editor";
    registration.owner_view = "document.hex";
    registration.owner_action = "Open live memory";
    registration.target = "PID " + std::to_string(pid);
    registration.label = "Read live memory";
    registration.stage = "Queued bounded read";
    char range_label[80]{};
    std::snprintf(range_label, sizeof(range_label), "0x%016llX (%zu bytes)",
        static_cast<unsigned long long>(address), size);
    registration.affected_entity = range_label;
    registration.cancellation_is_safe = true;
    registration.callbacks.cancel = [cancellation] {
        bool expected = false;
        return cancellation->compare_exchange_strong(expected, true,
            std::memory_order_acq_rel);
    };
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        cancellation->store(true, std::memory_order_release);
        state->live_loading.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = "TASK_OWNERSHIP_FAILURE: Task Center rejected the live-memory read";
        return false;
    }

    auto result = std::make_shared<std::vector<std::uint8_t>>();
    auto failure = std::make_shared<std::string>();
    auto workspace = context.workspace;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "hex_view";
    submission.label = "hex.live_memory.read";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 4;
    submission.target_pid = pid;
    submission.generation = generation;
    submission.cancel_hook = [cancellation] {
        cancellation->store(true, std::memory_order_release);
    };
    submission.body = [state, workspace, cancellation, result, failure, task_id,
        pid, address, size, generation, serial]() {
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::running, 0.1f,
            "Reading exact bounded range"));
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        pending_job_t pending(state);
#endif
        if (cancellation->load(std::memory_order_acquire)) {
            *failure = "CANCELLED: live-memory read was cancelled";
        } else {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            *result = aida::preview::hex::live_memory(pid, address, size);
            if (result->size() != size)
                *failure = "IO_FAILURE: Studio fixture did not provide the exact requested byte count";
#else
            if (!driver_bridge::read_memory_for(pid, address, size, *result) ||
                result->size() != size)
                *failure = "IO_FAILURE: bounded live-memory read failed or returned a partial range";
#endif
        }
        if (cancellation->load(std::memory_order_acquire) && failure->empty())
            *failure = "CANCELLED: live-memory read was cancelled";
        auto publish = [state, workspace, cancellation, result, failure, task_id,
            pid, address, generation, serial]() {
            const auto process = workspace ? workspace->identity().process() : std::nullopt;
            const bool current = workspace && !workspace->closing() && !workspace->closed() &&
                workspace->generation() == generation && process && process->pid == pid &&
                state->live_request_serial.load(std::memory_order_acquire) == serial &&
                !state->cancelled.load(std::memory_order_acquire);
            if (!current) {
                if (state->live_request_serial.load(std::memory_order_acquire) == serial)
                    state->live_loading.store(false, std::memory_order_release);
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::cancelled, 1.0f,
                    "Discarded stale publication", "Workspace, target, or request changed"));
                return;
            }
            state->live_loading.store(false, std::memory_order_release);
            std::lock_guard<std::mutex> lock(state->mutex);
            if (cancellation->load(std::memory_order_acquire) || !failure->empty()) {
                state->error = failure->empty() ? "CANCELLED: live-memory read was cancelled" : *failure;
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    cancellation->load(std::memory_order_acquire)
                        ? aida::ui::task_center::task_state_t::cancelled
                        : aida::ui::task_center::task_state_t::failed,
                    1.0f, "Live-memory read did not publish", state->error));
                return;
            }
            state->live_bytes = std::move(*result);
            state->live_base = address;
            state->error.clear();
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::completed, 1.0f,
                "Exact range published", std::to_string(state->live_bytes.size()) + " bytes"));
        };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        publish();
#else
        if (!aida::ui_thread::post(std::move(publish), "hex_view",
                "publish_live_memory", "worker_completion")) {
            state->live_dispatch_failure_serial.store(serial, std::memory_order_release);
            state->live_loading.store(false, std::memory_order_release);
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "UI publication rejected", "The UI dispatcher rejected the completed read"));
        }
#endif
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        cancellation->store(true, std::memory_order_release);
        state->live_loading.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->error = "QUEUE_REJECTED: " + submitted.reject_reason;
        }
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Worker queue rejected", submitted.reject_reason));
        return false;
    }
    return true;
}

void close(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return;
    state->request_cancel();
}

bool active(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return false;
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->ui.active && (state->source_kind == source_kind_t::live_memory
        ? !state->live_bytes.empty() : context.workspace->provider().size() != 0);
}

std::string source_name(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return {};
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->ui.source_name.empty() ? context.workspace->identity().bin_name() :
        state->ui.source_name;
}

std::string last_error(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return "TARGET_NOT_FOUND: workspace is unavailable";
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->error;
}

void render(float, float, float width, float height,
            float alpha, float, float, float,
            const disasm_view::workspace_context_t& context) {
    if (!context) {
        ImGui::BeginChild("##workspace_hex_empty", ImVec2(width, height), false);
        aida::ui::compact_empty_state("hex_workspace_empty", "No workspace selected",
            "Open or attach to a target to inspect its bytes.", nullptr,
            ImVec2(0.0f, (std::max)(152.0f, height - aida::ui::metrics::spacing::lg)));
        ImGui::EndChild();
        return;
    }
    auto state = state_for(context);
    if (!state)
        return;
    const std::uint64_t dispatch_failure = state->live_dispatch_failure_serial.exchange(
        0, std::memory_order_acq_rel);
    if (dispatch_failure != 0 &&
        dispatch_failure == state->live_request_serial.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = "PUBLICATION_REJECTED: the UI dispatcher rejected the completed live-memory read";
    }
    bool provider_source = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        provider_source = state->source_kind == source_kind_t::workspace_provider;
    }
    if (provider_source)
        request_patch_refresh(context, state);
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_hex", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));

    std::string current_source_name;
    bool live_source_header = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        current_source_name = state->ui.source_name.empty()
            ? context.workspace->identity().bin_name() : state->ui.source_name;
        live_source_header = state->source_kind == source_kind_t::live_memory;
    }
    const auto header = aida::ui::view_header("Hex Editor", current_source_name.c_str(),
        "Search", "Go to", live_source_header ? aida::ui::status_kind_t::accent
                                                : aida::ui::status_kind_t::success);
    if (header.secondary_clicked) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->ui.goto_visible = true;
        state->ui.goto_buf[0] = '\0';
    }
    if (header.primary_clicked) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->ui.search_visible = !state->ui.search_visible;
    }

    aida::ui::begin_toolbar("##hex_toolbar",
        aida::ui::metrics::control::toolbar_h +
        aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
    if (aida::ui::toolbar_button("copy_selection", "Copy selection", false, false,
            "Copy the selected byte range"))
        copy_selection(context, state);
    ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
    aida::ui::status_badge(live_source_header ? "Live memory" : "Workspace image",
        live_source_header ? aida::ui::status_kind_t::accent
                           : aida::ui::status_kind_t::neutral);
    aida::ui::end_toolbar();

    bool goto_visible = false;
    bool search_visible = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        goto_visible = state->ui.goto_visible;
        search_visible = state->ui.search_visible;
    }
    if (goto_visible) {
        aida::ui::begin_toolbar("##hex_goto_toolbar",
            aida::ui::metrics::control::toolbar_h +
            aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
        ImGui::PushID("hex_goto");
        const ImGuiID goto_input = ImGui::GetID("##input");
        ImGui::PopID();
        static_cast<void>(aida::ui::search_field("hex_goto", state->ui.goto_buf,
            sizeof(state->ui.goto_buf), "File offset or virtual address", 300.0f));
        const bool enter = ImGui::GetActiveID() == goto_input &&
            ImGui::IsKeyPressed(ImGuiKey_Enter, false);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        const bool submit_goto = aida::ui::toolbar_button("goto_submit", "Go", false, false,
            "Navigate to this offset or address") || enter;
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        const bool close_goto = aida::ui::toolbar_button("goto_close", "Close", false,
            false, "Close address search");
        aida::ui::end_toolbar();
        if (submit_goto) {
            if (auto value = parse_u64(state->ui.goto_buf)) {
                std::uint64_t offset = *value;
                bool live_source = false;
                std::uint64_t live_base = 0;
                std::uint64_t source_size = context.workspace->provider().size();
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    live_source = state->source_kind == source_kind_t::live_memory;
                    live_base = state->live_base;
                    if (live_source)
                        source_size = static_cast<std::uint64_t>(state->live_bytes.size());
                }
                if (live_source && *value >= live_base)
                    offset = *value - live_base;
                else if (!live_source) {
                    if (auto normalized_offset = file_offset_for_normalized_address(context, *value))
                        offset = *normalized_offset;
                    else if (auto typed = disasm_view::typed_address(context, *value))
                        offset = disasm_view::provider_offset(context, *typed).value_or(offset);
                }
                if (offset < source_size) {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->ui.target_scroll_y = static_cast<float>(offset / 16) *
                        ImGui::GetTextLineHeightWithSpacing();
                }
            }
            std::lock_guard<std::mutex> lock(state->mutex);
            state->ui.goto_visible = false;
        } else if (close_goto) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->ui.goto_visible = false;
        }
    }
    if (search_visible) {
        bool search_hex = false;
        std::int64_t match_index = -1;
        std::size_t match_count = 0;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            search_hex = state->ui.search_hex;
            match_index = state->ui.search_match_idx;
            match_count = state->ui.search_matches.size();
        }
        const bool searching = state->searching.load(std::memory_order_acquire);
        aida::ui::begin_toolbar("##hex_search_toolbar",
            aida::ui::metrics::control::toolbar_h +
            aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
        ImGui::PushID("hex_search");
        const ImGuiID search_input = ImGui::GetID("##input");
        ImGui::PopID();
        const float search_width = (std::max)(160.0f,
            (std::min)(320.0f, ImGui::GetContentRegionAvail().x - 390.0f));
        static_cast<void>(aida::ui::search_field("hex_search", state->ui.search_buf,
            sizeof(state->ui.search_buf), "Bytes or text", search_width));
        const bool enter = ImGui::GetActiveID() == search_input &&
            ImGui::IsKeyPressed(ImGuiKey_Enter, false);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        if (ImGui::Checkbox("Hex", &search_hex)) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->ui.search_hex = search_hex;
        }
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        if ((aida::ui::toolbar_button("find", "Find", false, searching,
                "Search from the current source") || enter) && !searching)
            start_search(context, state);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        if (searching) {
            if (aida::ui::toolbar_button("cancel_search", "Cancel", false, false,
                    "Cancel the active search")) {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->search_cancellation)
                    state->search_cancellation->request_cancel();
            }
        }
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        if (aida::ui::toolbar_button("previous_match", "Previous", false,
                match_count == 0, "Select the previous match"))
            step_search_result(state, -1);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        if (aida::ui::toolbar_button("next_match", "Next", false,
                match_count == 0, "Select the next match"))
            step_search_result(state, 1);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        char match_label[48]{};
        if (searching)
            std::snprintf(match_label, sizeof(match_label), "Searching");
        else if (match_count == 0)
            std::snprintf(match_label, sizeof(match_label), "No matches");
        else
            std::snprintf(match_label, sizeof(match_label), "%lld / %zu",
                static_cast<long long>(match_index + 1), match_count);
        aida::ui::status_badge(match_label,
            searching ? aida::ui::status_kind_t::info
                      : match_count == 0 ? aida::ui::status_kind_t::neutral
                                         : aida::ui::status_kind_t::success);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        if (aida::ui::toolbar_button("close_search", "Close", false, false,
                "Close byte search")) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->ui.search_visible = false;
        }
        aida::ui::end_toolbar();
    }
    std::string error;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        error = state->error;
    }
    const bool live_loading = state->live_loading.load(std::memory_order_acquire);
    if (live_loading)
        aida::ui::inline_notice("hex_live_loading", "Reading live memory",
            "The exact bounded range is being read in the background. The previous snapshot is not reused.",
            aida::ui::status_kind_t::info);
    if (!error.empty())
        aida::ui::inline_notice("hex_error", "Hex view unavailable", error.c_str(),
            aida::ui::status_kind_t::error);

    ImGui::PushStyleColor(ImGuiCol_ChildBg,
        ImGui::ColorConvertU32ToFloat4(theme.panel_header));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
        ImVec2(aida::ui::metrics::table::cell_pad_x,
            aida::ui::metrics::table::cell_pad_y));
    ImGui::BeginChild("##hex_header", ImVec2(0.0f, aida::ui::metrics::table::header_h),
        true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::TextDisabled("Address");
    ImGui::SameLine(170.0f);
    ImGui::TextDisabled("Bytes");
    ImGui::SameLine(650.0f);
    ImGui::TextDisabled("ASCII");
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::BeginChild("##hex_rows", ImVec2(0.0f, 0.0f), false,
        ImGuiWindowFlags_HorizontalScrollbar);
    std::uint64_t byte_count = 0;
    bool live_source = false;
    std::uint64_t live_base = 0;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        live_source = state->source_kind == source_kind_t::live_memory;
        live_base = state->live_base;
        byte_count = live_source ? static_cast<std::uint64_t>(state->live_bytes.size()) :
            context.workspace->provider().size();
    }
    if (byte_count == 0) {
        aida::ui::compact_empty_state("hex_source_empty", "No bytes available",
            live_source && live_loading ? "Reading the selected live-memory range..."
                        : live_source ? "The selected memory snapshot does not contain readable bytes."
                        : "The workspace provider has not published readable bytes.",
            nullptr, ImVec2(0.0f, 152.0f));
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopID();
        return;
    }
    const std::uint64_t row_count64 = (byte_count + 15) / 16;
    const int row_count = row_count64 > static_cast<std::uint64_t>((std::numeric_limits<int>::max)())
        ? (std::numeric_limits<int>::max)() : static_cast<int>(row_count64);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->scroll_to_offset != (std::numeric_limits<std::uint64_t>::max)()) {
            state->ui.target_scroll_y = static_cast<float>(state->scroll_to_offset / 16) *
                ImGui::GetTextLineHeightWithSpacing();
            state->scroll_to_offset = (std::numeric_limits<std::uint64_t>::max)();
        }
        if (state->ui.target_scroll_y > 0.0f) {
            ImGui::SetScrollY(state->ui.target_scroll_y);
            state->ui.target_scroll_y = 0.0f;
        }
    }
    ImGuiListClipper clipper;
    const float row_height = (std::max)(aida::ui::metrics::table::compact_row_h,
        ImGui::GetTextLineHeightWithSpacing());
    clipper.Begin(row_count, row_height);
    bool open_hex_context = false;
    auto hex_context_origin = aida::ui::context_menu_open_origin_t::pointer;
    while (clipper.Step()) {
        const std::uint64_t begin = static_cast<std::uint64_t>(clipper.DisplayStart) * 16;
        const std::uint64_t end = (std::min)(byte_count,
            static_cast<std::uint64_t>(clipper.DisplayEnd) * 16);
        if (!ensure_window(context, state, begin, end))
            continue;
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::uint64_t row_offset = static_cast<std::uint64_t>(row) * 16;
            if (row_offset >= byte_count)
                break;
            char address[32]{};
            std::uint64_t display_address = live_source ? live_base + row_offset : row_offset;
            if (!live_source) {
                if (auto translated = display_address_for_file_offset(context, row_offset))
                    display_address = *translated;
            }
            std::snprintf(address, sizeof(address), "%016llX",
                static_cast<unsigned long long>(display_address));
            ImGui::TextUnformatted(address);
            std::string ascii;
            ascii.reserve(16);
            for (std::uint64_t column = 0; column < 16; ++column) {
                const std::uint64_t offset = row_offset + column;
                if (offset >= byte_count)
                    break;
                std::uint8_t value = 0;
                bool patched = false;
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (live_source) {
                        if (offset >= state->live_bytes.size())
                            continue;
                        value = state->live_bytes[static_cast<std::size_t>(offset)];
                    } else {
                        const auto relative = offset - state->window_offset;
                        if (relative >= state->window.size())
                            continue;
                        value = patched_byte(*state, offset,
                            state->window[static_cast<std::size_t>(relative)], &patched);
                    }
                }
                ImGui::SameLine(170.0f + static_cast<float>(column) * 29.0f);
                ImGui::PushID(static_cast<int>((offset ^ (offset >> 32)) & 0x7FFFFFFF));
                char encoded[4]{};
                std::snprintf(encoded, sizeof(encoded), "%02X", value);
                std::int64_t selection_begin = -1;
                std::int64_t selection_end = -1;
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    selection_begin = state->ui.sel_start;
                    selection_end = state->ui.sel_end;
                }
                const auto low = (std::min)(selection_begin, selection_end);
                const auto high = (std::max)(selection_begin, selection_end);
                const bool selected = selection_begin >= 0 &&
                    static_cast<std::int64_t>(offset) >= low &&
                    static_cast<std::int64_t>(offset) <= high;
                if (patched)
                    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.warning, alpha));
                if (ImGui::Selectable(encoded, selected,
                        ImGuiSelectableFlags_AllowDoubleClick, ImVec2(27.0f, row_height))) {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (ImGui::GetIO().KeyShift && state->ui.sel_start >= 0)
                        state->ui.sel_end = static_cast<std::int64_t>(offset);
                    else
                        state->ui.sel_start = state->ui.sel_end =
                            static_cast<std::int64_t>(offset);
                    if (!live_source && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        if (auto translated = normalized_address_for_file_offset(context, offset)) {
                            disasm_view::goto_address(*translated, context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                            aida::preview::hex::opened_disassembly(offset);
#else
                            aida::ui::application_views::open_or_focus(
                                aida::ui::stable_view_id_t("document.disassembly"));
#endif
                        }
                    }
                }
                if (patched)
                    ImGui::PopStyleColor();
                const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
                const bool keyboard_context = ImGui::IsItemFocused() && context_key_pressed();
                if (pointer_context || keyboard_context) {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->ui.sel_start = state->ui.sel_end = static_cast<std::int64_t>(offset);
                    state->ui.context_offset = offset;
                    state->ui.context_generation = context.publication ? context.publication->generation : 0;
                    state->ui.context_overlay_revision = context.workspace->overlay_revision();
                    state->ui.context_value = value;
                    state->ui.context_live = live_source;
                    state->ui.context_valid = true;
                    open_hex_context = true;
                    if (keyboard_context)
                        hex_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
                            ? aida::ui::context_menu_open_origin_t::menu_key
                            : aida::ui::context_menu_open_origin_t::shift_f10;
                }
                ImGui::PopID();
                ascii.push_back(value >= 0x20 && value <= 0x7E ? static_cast<char>(value) : '.');
            }
            ImGui::SameLine(650.0f);
            ImGui::TextUnformatted(ascii.c_str());
        }
    }
    if (open_hex_context) {
        state_t snapshot;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            snapshot.context_offset = state->ui.context_offset;
            snapshot.context_generation = state->ui.context_generation;
            snapshot.context_overlay_revision = state->ui.context_overlay_revision;
            snapshot.context_value = state->ui.context_value;
            snapshot.context_live = state->ui.context_live;
            snapshot.context_valid = state->ui.context_valid;
            snapshot.sel_start = state->ui.sel_start;
            snapshot.sel_end = state->ui.sel_end;
        }
        const bool generation_current = snapshot.context_valid && context.publication &&
            snapshot.context_generation == context.publication->generation;
        const bool overlay_current = snapshot.context_live ||
            snapshot.context_overlay_revision == context.workspace->overlay_revision();
        const bool current = generation_current && overlay_current && snapshot.context_offset < byte_count;
        const std::uint64_t selection_size = snapshot.sel_start >= 0 && snapshot.sel_end >= 0
            ? static_cast<std::uint64_t>((std::max)(snapshot.sel_start, snapshot.sel_end) -
                (std::min)(snapshot.sel_start, snapshot.sel_end)) + 1U : 0U;
        const std::uint64_t display_address = snapshot.context_live
            ? live_base + snapshot.context_offset
            : display_address_for_file_offset(context, snapshot.context_offset).value_or(snapshot.context_offset);
        const auto typed = snapshot.context_live
            ? disasm_view::typed_address(context, display_address)
            : normalized_address_for_file_offset(context, snapshot.context_offset);
        const std::uint64_t selection_begin = snapshot.sel_start >= 0 && snapshot.sel_end >= 0
            ? static_cast<std::uint64_t>((std::min)(snapshot.sel_start, snapshot.sel_end))
            : snapshot.context_offset;
        const auto patch_address = snapshot.context_live
            ? std::optional<aida::analysis::address_t>{}
            : normalized_address_for_file_offset(context, selection_begin);
        const bool can_stage_overlay = current && !snapshot.context_live && typed.has_value();
        const bool can_stage_selection = current && !snapshot.context_live &&
            patch_address.has_value() && selection_size != 0 && selection_size <= 64U * 1024U;
        const auto context_pid = snapshot.context_live ? get_attached_pid() : 0UL;
        aida::ui::application_ui::retained_entity_context_t retained;
        retained.owner_id = "hex.byte";
        retained.entity_id = std::to_string(snapshot.context_offset);
        retained.entity_generation = snapshot.context_generation;
        retained.active_view = aida::ui::stable_view_id_t("document.hex");
        retained.validate_identity = [state, context, snapshot, byte_count, context_pid]() {
            if (!context.publication || context.publication->generation != snapshot.context_generation)
                return aida::ui::capability_state_t::unavailable("The analysis publication changed; reopen the menu.");
            if (snapshot.context_live && get_attached_pid() != context_pid)
                return aida::ui::capability_state_t::unavailable("The live Hex target process changed; reopen the menu.");
            if (!snapshot.context_live && context.workspace->overlay_revision() != snapshot.context_overlay_revision)
                return aida::ui::capability_state_t::unavailable("The overlay revision changed; reopen the menu.");
            if (snapshot.context_offset >= byte_count)
                return aida::ui::capability_state_t::unavailable("The selected byte is outside the current source.");
            std::lock_guard<std::mutex> lock(state->mutex);
            const bool same = state->ui.context_valid && state->ui.context_offset == snapshot.context_offset &&
                state->ui.context_generation == snapshot.context_generation &&
                state->ui.sel_start == snapshot.sel_start && state->ui.sel_end == snapshot.sel_end;
            return same ? aida::ui::capability_state_t::available()
                : aida::ui::capability_state_t::unavailable("The byte selection changed; reopen the menu.");
        };
        auto add = [&](const char* id, bool enabled, const char* reason, auto invoke) {
            retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
                : aida::ui::capability_state_t::unavailable(reason), invoke});
        };
        add("hex.copy_byte", current, "The byte selection is stale; select it again.", [snapshot]() {
            char encoded[4]{};
            std::snprintf(encoded, sizeof(encoded), "%02X", snapshot.context_value);
            ImGui::SetClipboardText(encoded);
            return aida::ui::action_handler_result_t::completed();
        });
        add("hex.copy_selection", current && selection_size != 0 && selection_size <= (1ULL << 20),
            !current ? "The byte selection is stale; select it again."
                : selection_size > (1ULL << 20) ? "Clipboard selection is limited to 1 MiB."
                : "No current byte range is selected.", [context, state]() {
                copy_selection(context, state);
                return aida::ui::action_handler_result_t::completed();
            });
        add("hex.copy_address", current, "The byte selection is stale.", [display_address]() {
            char address[24]{};
            std::snprintf(address, sizeof(address), "0x%016llX",
                static_cast<unsigned long long>(display_address));
            ImGui::SetClipboardText(address);
            return aida::ui::action_handler_result_t::completed();
        });
        add("hex.open_disassembly", current && typed.has_value(),
            !current ? "The byte selection is stale; select it again."
                : "The selected byte has no current mapped analysis address.", [typed, context]() {
                disasm_view::goto_address(*typed, context);
                aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("document.disassembly"));
                return aida::ui::action_handler_result_t::completed();
            });
        add("hex.stage_zero_overlay", can_stage_overlay,
            !current ? "The byte selection is stale; select it again."
                : snapshot.context_live ? "Live memory writes require the reviewed Patches view."
                : "The selected byte has no current mapped analysis address.", [typed, context]() {
                if (!typed)
                    return aida::ui::action_handler_result_t::failed(
                        "The retained byte no longer has a mapped workspace address.");
                std::string error;
                if (!disasm_view::open_static_patch_review(context, *typed, 1,
                        disasm_view::static_patch_mode_t::bytes, &error))
                    return aida::ui::action_handler_result_t::failed(error);
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->static_patch_input.fill('\0');
                context.view->static_patch_input[0] = '0';
                context.view->static_patch_input[1] = '0';
                context.view->static_patch_proposed.assign(1, 0);
                context.view->static_patch_parse_error.clear();
                return aida::ui::action_handler_result_t::completed();
            });
        add("hex.stage_patch_overlay", can_stage_selection,
            !current ? "The byte selection is stale; select it again."
                : snapshot.context_live ? "Live memory writes require the reviewed Debugger Patches view."
                : selection_size > 64U * 1024U ? "Interactive overlay review is limited to 64 KiB."
                : "Select a fully mapped provider-backed byte range.",
            [patch_address, selection_size, context]() {
                if (!patch_address)
                    return aida::ui::action_handler_result_t::failed(
                        "The retained selection no longer has a mapped workspace address.");
                std::string error;
                return disasm_view::open_static_patch_review(context, *patch_address,
                    selection_size, disasm_view::static_patch_mode_t::bytes, &error)
                    ? aida::ui::action_handler_result_t::completed()
                    : aida::ui::action_handler_result_t::failed(error);
            });
        add("hex.stage_nop_overlay", can_stage_selection,
            !current ? "The byte selection is stale; select it again."
                : snapshot.context_live ? "Live memory writes require the reviewed Debugger Patches view."
                : selection_size > 64U * 1024U ? "Interactive overlay review is limited to 64 KiB."
                : "Select a fully mapped provider-backed byte range.",
            [patch_address, selection_size, context]() {
                if (!patch_address)
                    return aida::ui::action_handler_result_t::failed(
                        "The retained selection no longer has a mapped workspace address.");
                std::string error;
                return disasm_view::open_static_patch_review(context, *patch_address,
                    selection_size, disasm_view::static_patch_mode_t::nop_fill, &error)
                    ? aida::ui::action_handler_result_t::completed()
                    : aida::ui::action_handler_result_t::failed(error);
            });
        char display_address_text[24]{};
        char byte_text[4]{};
        std::snprintf(display_address_text, sizeof(display_address_text), "0x%016llX",
            static_cast<unsigned long long>(display_address));
        std::snprintf(byte_text, sizeof(byte_text), "%02X", snapshot.context_value);
        aida::automation_ui::entity_evidence::snapshot_t evidence;
        evidence.workspace_id = snapshot.context_live
            ? "pid:" + std::to_string(context_pid)
            : context.workspace->identity().binary_id().to_hex();
        evidence.source_view_id = "document.hex";
        evidence.source_kind = snapshot.context_live ? "live_hex_byte" : "static_hex_byte";
        evidence.entity_id = retained.entity_id;
        evidence.display_label = std::string("Hex byte ") + display_address_text;
        evidence.excerpt = "Source: " + std::string(snapshot.context_live
            ? "live process" : "static analysis") +
            "\nAddress: " + display_address_text +
            "\nFile/source offset: " + std::to_string(snapshot.context_offset) +
            "\nValue: " + byte_text +
            "\nSelection bytes: " + std::to_string(selection_size) +
            "\nOverlay revision: " + std::to_string(snapshot.context_overlay_revision) +
            "\nPublication generation: " + std::to_string(snapshot.context_generation);
        evidence.address = display_address;
        evidence.revision = snapshot.context_overlay_revision;
        evidence.generation = snapshot.context_generation;
        evidence.sensitive = snapshot.context_live;
        evidence.return_to_source = [state, context, snapshot, byte_count,
            context_pid](std::string& reason) {
            if (!context.publication || context.publication->generation != snapshot.context_generation ||
                (!snapshot.context_live &&
                    context.workspace->overlay_revision() != snapshot.context_overlay_revision) ||
                (snapshot.context_live && get_attached_pid() != context_pid) ||
                snapshot.context_offset >= byte_count) {
                reason = "The Hex source, publication, or overlay changed; capture the byte again.";
                return false;
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->ui.sel_start = snapshot.sel_start;
                state->ui.sel_end = snapshot.sel_end;
                state->ui.context_offset = snapshot.context_offset;
                state->ui.context_generation = snapshot.context_generation;
                state->ui.context_overlay_revision = snapshot.context_overlay_revision;
                state->ui.context_value = snapshot.context_value;
                state->ui.context_live = snapshot.context_live;
                state->ui.context_valid = true;
            }
            const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.hex"));
            if (!opened.ok()) {
                reason = opened.detail;
                return false;
            }
            reason.clear();
            return true;
        };
        aida::automation_ui::entity_evidence::append_actions(retained,
            std::move(evidence), current
                ? aida::ui::capability_state_t::available()
                : aida::ui::capability_state_t::unavailable(
                    "The retained Hex byte or its publication changed; select it again."));
        aida::ui::application_ui::open_retained_entity_context_menu(
            std::move(retained), hex_context_origin);
    }
    aida::ui::application_ui::render_retained_entity_context_menu("hex.byte");
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
}

}
