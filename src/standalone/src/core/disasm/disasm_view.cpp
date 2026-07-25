#include "disasm_view.hpp"

#include "comment_dialog.hpp"
#include "disasm_theme.hpp"
#include "file_metadata_banner.hpp"
#include "pseudocode_view.hpp"
#include "rename_dialog.hpp"
#include "../analysis/auto_comment_store.hpp"
#include "../analysis/types_hub_view.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/disasm_preview_adapter.hpp"
#include "../../preview/studio_semantics.hpp"
#else
#include "../analysis/source_reconstruct_view.hpp"
#endif
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../analysis/workspace/x86_decoder.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/taskflow_runtime.hpp"
#include "../scanner/aob_generator.hpp"
#include "../scanner/scan_hub_view.hpp"
#endif
#include "../ui/components.hpp"
#include "../ui/design_system.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/fonts.hpp"
#include "../ui/metrics.hpp"
#include "../ui/task_center.hpp"
#include "../ui/theme.hpp"
#include "../ai/standalone_chat.hpp"
#include "../debugger/debugger_view.hpp"
#include "../editor/hex_view.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/globals.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cfloat>
#include <cstdio>
#include <cstring>
#include <exception>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <fstream>
#endif
#include <limits>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace disasm_view {

struct workspace_model_t {
    workspace_model_t(const aida::analysis::binary_id_t& id,
                      const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
        : automatic_comments(id), view(std::make_shared<state_t>()), owner(workspace) {}

    auto_comment_store::workspace_store_t automatic_comments;
    std::shared_ptr<state_t> view;
    std::unordered_map<std::string, std::shared_ptr<state_t>> presentations;
    std::weak_ptr<aida::analysis::analysis_workspace_t> owner;
    std::mutex mutation_mutex;
    std::mutex initialization_mutex;
    std::atomic<bool> initialized{false};
    std::atomic<std::uint32_t> format_generation{1};
    std::atomic<std::uint64_t> presentation_selection_revision{0};
};

namespace {

using namespace aida::analysis;

std::mutex& model_registry_mutex() {
    static std::mutex value;
    return value;
}

std::unordered_map<binary_id_t, std::shared_ptr<workspace_model_t>, binary_id_hash_t>&
model_registry() {
    static std::unordered_map<binary_id_t, std::shared_ptr<workspace_model_t>, binary_id_hash_t> value;
    return value;
}

std::shared_ptr<workspace_model_t> model_for(const std::shared_ptr<analysis_workspace_t>& workspace) {
    if (!workspace)
        return {};
    const auto id = workspace->identity().binary_id();
    std::lock_guard<std::mutex> lock(model_registry_mutex());
    auto& registry = model_registry();
    for (auto it = registry.begin(); it != registry.end();) {
        const auto owner = it->second ? it->second->owner.lock() : nullptr;
        if (!owner || owner->closed())
            it = registry.erase(it);
        else
            ++it;
    }
    auto found = registry.find(id);
    if (found != registry.end())
        return found->second;
    auto created = std::make_shared<workspace_model_t>(id, workspace);
    registry[id] = created;
    return created;
}

void initialize_model(const std::shared_ptr<analysis_workspace_t>& workspace,
                      const std::shared_ptr<workspace_model_t>& model) {
    if (!workspace || !model || model->initialized.load(std::memory_order_acquire))
        return;
    std::lock_guard<std::mutex> lock(model->initialization_mutex);
    if (model->initialized.load(std::memory_order_acquire))
        return;
    model->initialized.store(true, std::memory_order_release);
}

std::shared_ptr<state_t> presentation_for(
    const std::shared_ptr<workspace_model_t>& model, std::string_view key) {
    if (!model || key.empty())
        return model ? model->view : nullptr;
    std::lock_guard<std::mutex> lock(model->initialization_mutex);
    const std::string identity(key);
    const auto found = model->presentations.find(identity);
    if (found != model->presentations.end())
        return found->second;
    auto created = std::make_shared<state_t>();
    model->presentations.emplace(identity, created);
    return created;
}

std::shared_ptr<state_t> authoritative_state(const workspace_context_t& context) {
    return context.model ? context.model->view : context.view;
}

workspace_context_t authoritative_context(const workspace_context_t& context) {
    workspace_context_t result = context;
    result.view = authoritative_state(context);
    return result;
}

std::optional<std::uint64_t> checked_add(std::uint64_t left, std::uint64_t right) {
    if (right > (std::numeric_limits<std::uint64_t>::max)() - left)
        return {};
    return left + right;
}

std::optional<std::uint64_t> optional_value(
    aida::analysis::workspace_result_t<std::uint64_t> result) {
    if (!result)
        return {};
    return result.take_value();
}

std::optional<std::uint64_t> display_base_override(const workspace_context_t& context) {
    if (!context.view)
        return {};
    std::lock_guard<std::mutex> lock(context.view->mutex);
    return context.view->display_image_base;
}

std::uint64_t display_image_base(const workspace_context_t& context) {
    if (const auto value = display_base_override(context))
        return *value;
    return context.image ? context.image->image_base() : 0;
}

std::string byte_text(const byte_view_t& view, std::uint64_t view_offset,
                      std::uint64_t instruction_offset, std::uint8_t length) {
    if (instruction_offset < view_offset)
        return {};
    const std::uint64_t relative = instruction_offset - view_offset;
    if (relative > view.size() || length > view.size() - static_cast<std::size_t>(relative))
        return {};
    std::string output;
    output.reserve(static_cast<std::size_t>(length) * 3);
    char buffer[4]{};
    for (std::uint8_t index = 0; index < length; ++index) {
        std::snprintf(buffer, sizeof(buffer), "%02X",
            view[static_cast<std::size_t>(relative) + index]);
        if (!output.empty())
            output.push_back(' ');
        output.append(buffer);
    }
    return output;
}

std::uint64_t format_page_key(const workspace_context_t& context,
                              std::size_t begin, std::size_t end) {
    std::uint64_t value = context.publication ? context.publication->generation : 0;
    value ^= (context.publication ? context.publication->analysis_revision : 0) *
             0x9E3779B185EBCA87ULL;
    value ^= (context.publication ? context.publication->overlay_revision : 0) *
             0xC2B2AE3D27D4EB4FULL;
    value ^= static_cast<std::uint64_t>(begin) * 0x165667B19E3779F9ULL;
    value ^= static_cast<std::uint64_t>(end) * 0x85EBCA77C2B2AE63ULL;
    return value;
}

std::optional<std::pair<std::size_t, std::size_t>> instruction_range(
    const workspace_context_t& context) {
    if (!context || !context.publication->snapshot)
        return {};
    const auto& instructions = context.publication->snapshot->instructions;
    std::size_t begin = 0;
    std::size_t end = instructions.size();
    int section_index = -1;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        section_index = context.view->active_section;
    }
    if (section_index < 0 || !context.image ||
        static_cast<std::size_t>(section_index) >= context.image->sections().size())
        return std::make_pair(begin, end);
    const auto& section = context.image->sections()[static_cast<std::size_t>(section_index)];
    const auto section_end = checked_add(section.virtual_address,
        (std::max)(section.virtual_size, section.raw_size));
    if (!section_end)
        return {};
    const auto lower = std::lower_bound(instructions.begin(), instructions.end(),
        section.virtual_address, [](const instruction_record_t& instruction, std::uint64_t rva) {
            return instruction.address.value < rva;
        });
    const auto upper = std::lower_bound(lower, instructions.end(), *section_end,
        [](const instruction_record_t& instruction, std::uint64_t rva) {
            return instruction.address.value < rva;
        });
    begin = static_cast<std::size_t>(std::distance(instructions.begin(), lower));
    end = static_cast<std::size_t>(std::distance(instructions.begin(), upper));
    return std::make_pair(begin, end);
}

void publish_format_failure(const workspace_context_t& context,
                            std::uint64_t page_key, std::string error) {
    if (!context.view)
        return;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->pending_format_pages.erase(page_key);
    context.view->format_error = std::move(error);
}

void request_format_page(const workspace_context_t& context,
                         std::size_t begin, std::size_t end) {
    if (!context || !context.publication->snapshot || !context.image || begin >= end ||
        end > context.publication->snapshot->instructions.size())
        return;
    const auto page_key = format_page_key(context, begin, end);
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (!context.view->pending_format_pages.insert(page_key).second)
            return;
    }
    const auto format_body = [context, begin, end, page_key](const std::atomic<bool>& cancelled) {
        if (cancelled.load(std::memory_order_acquire) ||
            context.workspace->cancellation_token().stop_requested()) {
            publish_format_failure(context, page_key, "Formatting cancelled.");
            return;
        }
        auto decoder_result = worker_owned_x86_decoder_t::create(
            context.image->architecture_mode());
        if (!decoder_result) {
            publish_format_failure(context, page_key, decoder_result.error().message);
            return;
        }
        auto decoder = decoder_result.take_value();
        const auto& instructions = context.publication->snapshot->instructions;
        std::vector<std::uint64_t> offsets(end - begin, 0);
        std::uint64_t minimum = (std::numeric_limits<std::uint64_t>::max)();
        std::uint64_t maximum = 0;
        bool contiguous_lease = true;
        for (std::size_t index = begin; index < end; ++index) {
            const auto offset = provider_offset(context, instructions[index].address);
            if (!offset) {
                contiguous_lease = false;
                continue;
            }
            offsets[index - begin] = *offset;
            minimum = (std::min)(minimum, *offset);
            const auto finish = checked_add(*offset, instructions[index].length);
            if (!finish) {
                contiguous_lease = false;
                continue;
            }
            maximum = (std::max)(maximum, *finish);
        }
        constexpr std::uint64_t maximum_page_lease = 8ULL << 20;
        if (minimum == (std::numeric_limits<std::uint64_t>::max)() || maximum < minimum ||
            maximum - minimum > maximum_page_lease)
            contiguous_lease = false;
        byte_view_t page_view;
        if (contiguous_lease) {
            auto lease = context.workspace->provider().lease(minimum, maximum - minimum,
                context.workspace->cancellation_token());
            if (lease)
                page_view = lease.take_value();
            else
                contiguous_lease = false;
        }
        std::unordered_map<entity_id_t, formatted_instruction_t> completed;
        completed.reserve(end - begin);
        instruction_format_options_t options;
        options.maximum_text_bytes = 2048;
        for (std::size_t index = begin; index < end; ++index) {
            if (cancelled.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested())
                break;
            const auto& instruction = instructions[index];
            formatted_instruction_t row;
            row.instruction_id = instruction.id;
            row.generation = context.publication->generation;
            row.analysis_revision = context.publication->analysis_revision;
            row.overlay_revision = context.publication->overlay_revision;
            row.runtime_address = runtime_address(context, instruction.address).value_or(
                instruction.address.value);
            workspace_result_t<std::string> formatted = contiguous_lease
                ? decoder->format_one(page_view, minimum, context.workspace->provider(),
                    *context.image, instruction, options,
                    context.workspace->cancellation_token())
                : decoder->format_one(context.workspace->provider(), *context.image,
                    instruction, options, context.workspace->cancellation_token());
            if (formatted)
                row.text = formatted.take_value();
            else
                row.error = formatted.error().stable_code() + ": " + formatted.error().message;
            const auto offset = offsets[index - begin];
            if (contiguous_lease) {
                row.bytes = byte_text(page_view, minimum, offset, instruction.length);
            } else {
                auto lease = context.workspace->provider().lease(offset, instruction.length,
                    context.workspace->cancellation_token());
                if (lease)
                    row.bytes = byte_text(lease.value(), offset, offset, instruction.length);
            }
            completed.emplace(instruction.id, std::move(row));
        }
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->pending_format_pages.erase(page_key);
        if (!context.workspace || context.workspace->closed() ||
            context.workspace->generation() != context.publication->generation)
            return;
        for (auto& item : completed)
            context.view->formatted.insert_or_assign(item.first, std::move(item.second));
        context.view->format_error.clear();
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::atomic<bool> cancelled{false};
    format_body(cancelled);
    aida::preview::disasm::record("format_visible_disassembly", begin,
        std::to_string(end - begin));
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "format_visible_disassembly";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [format_body](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        format_body(runtime_cancel.requested);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted)
        publish_format_failure(context, page_key,
            submitted.reject_reason.empty() ? "Formatting queue rejected the page." :
                                               submitted.reject_reason);
#endif
}

bool reconcile_committed_overlay_state(const workspace_context_t& context,
                                       std::string& error) {
    try {
        if (!context.workspace) {
            error = "The workspace presentation state is unavailable.";
            return false;
        }
        const auto existing = context.workspace->overlay_presentation();
        if (existing && existing->overlay_revision ==
                context.workspace->overlay_revision()) {
            error.clear();
            return true;
        }
        const auto overlay = context.workspace->overlay();
        if (!overlay) {
            error = "The committed workspace overlay is unavailable.";
            return false;
        }
        const auto snapshot = overlay->snapshot();
        if (snapshot.revision != context.workspace->overlay_revision()) {
            error = "The authoritative overlay revision changed before derived publication.";
            return false;
        }
        auto next = std::make_shared<workspace_overlay_presentation_t>();
        next->overlay_revision = snapshot.revision;
        next->comments.reserve(snapshot.items.size());
        next->renames.reserve(snapshot.items.size());
        next->bookmarks.reserve(snapshot.items.size());
        next->workspace_bookmarks.reserve(snapshot.items.size());
        for (const auto& item : snapshot.items) {
            const auto& operation = item.second;
            if (operation.target_discriminator !=
                overlay_target_discriminator_v9_t::native_address)
                continue;
            switch (operation.kind) {
            case overlay_operation_kind_t::comment:
            case overlay_operation_kind_t::comment_update:
                next->comments.push_back({operation.address, operation.text});
                break;
            case overlay_operation_kind_t::name:
                next->renames.push_back({operation.address, operation.name});
                break;
            case overlay_operation_kind_t::bookmark:
                next->bookmarks.push_back({operation.address, operation.name});
                next->workspace_bookmarks.push_back(operation.address);
                break;
            default:
                break;
            }
        }
        const auto address_less = [](const auto& left, const auto& right) {
            return left.address < right.address;
        };
        std::sort(next->comments.begin(), next->comments.end(), address_less);
        std::sort(next->renames.begin(), next->renames.end(), address_less);
        std::sort(next->bookmarks.begin(), next->bookmarks.end(), address_less);
        std::sort(next->workspace_bookmarks.begin(), next->workspace_bookmarks.end());
        auto published = context.workspace->publish_overlay_presentation(
            snapshot.revision,
            std::static_pointer_cast<const workspace_overlay_presentation_t>(
                std::move(next)));
        if (!published) {
            error = published.error().stable_code() + ": " +
                published.error().message;
            return false;
        }
        error.clear();
        return true;
    } catch (const std::exception& exception) {
        error = std::string("Derived overlay publication preparation failed: ") +
            exception.what();
        return false;
    } catch (...) {
        error = "Derived overlay publication preparation failed.";
        return false;
    }
}

class pending_mutation_guard_t final {
public:
    explicit pending_mutation_guard_t(std::shared_ptr<state_t> state) noexcept
        : state_(std::move(state)) {}

    ~pending_mutation_guard_t() {
        if (state_)
            state_->pending_mutations.fetch_sub(1, std::memory_order_acq_rel);
    }

    void release() noexcept {
        state_.reset();
    }

private:
    std::shared_ptr<state_t> state_;
};

class derived_publication_retry_guard_t final {
public:
    explicit derived_publication_retry_guard_t(
        std::shared_ptr<state_t> state) noexcept
        : state_(std::move(state)) {}

    ~derived_publication_retry_guard_t() {
        if (state_)
            state_->derived_publication_retry_pending.store(
                false, std::memory_order_release);
    }

private:
    std::shared_ptr<state_t> state_;
};

void record_overlay_presentation_result(const workspace_context_t& source_context,
                                        bool published,
                                        std::string detail) {
    const auto context = authoritative_context(source_context);
    if (!context.view || !context.workspace)
        return;
    const auto publication = context.workspace->analysis_publication();
    const auto presentation = publication
        ? publication->overlay_presentation : nullptr;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->derived_publication_target_revision =
        publication ? publication->overlay_revision : 0;
    context.view->derived_publication_revision = presentation
        ? presentation->overlay_revision : 0;
    context.view->derived_publication_error = published
        ? std::string() : (detail.empty()
            ? "The committed overlay is awaiting derived presentation publication."
            : std::move(detail));
}

bool queue_overlay_presentation_retry(const workspace_context_t& source_context) {
    const auto context = authoritative_context(source_context);
    if (!context || !context.workspace->overlay())
        return false;
    bool expected = false;
    if (!context.view->derived_publication_retry_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        return false;
    auto body = [context]() {
        derived_publication_retry_guard_t pending(context.view);
        std::string detail;
        bool published = false;
        try {
            std::lock_guard<std::mutex> mutation_lock(context.model->mutation_mutex);
            published = reconcile_committed_overlay_state(context, detail);
        } catch (const std::exception& exception) {
            detail = std::string("Derived overlay publication retry failed: ") +
                exception.what();
        } catch (...) {
            detail = "Derived overlay publication retry failed.";
        }
        try {
            record_overlay_presentation_result(
                context, published, std::move(detail));
        } catch (...) {
        }
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    body();
    return true;
#else
    try {
        aida::infra::taskflow_runtime::task_descriptor_t descriptor;
        descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        descriptor.owner_subsystem = "analysis_ui";
        descriptor.label = "workspace_overlay_presentation_retry";
        const std::string target_id = context.workspace->identity().binary_id().to_hex();
        descriptor.target_id = target_id.c_str();
        descriptor.generation = context.workspace->generation();
        descriptor.cancellable_body = [body = std::move(body)](
            const aida::infra::taskflow_runtime::cancellation_token_t&) mutable {
            body();
        };
        const auto submitted = aida::infra::taskflow_runtime::submit(
            std::move(descriptor));
        if (submitted.submitted)
            return true;
        context.view->derived_publication_retry_pending.store(
            false, std::memory_order_release);
        record_overlay_presentation_result(context, false,
            submitted.reject_reason.empty()
                ? "The derived overlay publication retry queue rejected the request."
                : submitted.reject_reason);
        return false;
    } catch (const std::exception& exception) {
        context.view->derived_publication_retry_pending.store(
            false, std::memory_order_release);
        try {
            record_overlay_presentation_result(context, false,
                std::string("The derived overlay publication retry could not be queued: ") +
                    exception.what());
        } catch (...) {
        }
        return false;
    } catch (...) {
        context.view->derived_publication_retry_pending.store(
            false, std::memory_order_release);
        try {
            record_overlay_presentation_result(context, false,
                "The derived overlay publication retry could not be queued.");
        } catch (...) {
        }
        return false;
    }
#endif
}

bool queue_overlay_transaction(const workspace_context_t& source_context,
                               std::vector<overlay_operation_t> operations,
                               std::optional<std::uint64_t> required_generation = {},
                               std::optional<std::uint64_t> required_analysis_revision = {},
                               std::optional<std::uint64_t> required_overlay_revision = {},
                               overlay_completion_t completion = {}) {
    const auto context = authoritative_context(source_context);
    if (!context || context.workspace->closing() || context.workspace->closed() ||
        !context.workspace->overlay() || operations.empty())
        return false;
    const auto expected_generation = required_generation.value_or(context.workspace->generation());
    const auto expected_analysis_revision = required_analysis_revision.value_or(
        context.workspace->analysis_revision());
    const auto expected_overlay_revision = required_overlay_revision.value_or(
        context.workspace->overlay_revision());
    if (context.workspace->generation() != expected_generation ||
        context.workspace->analysis_revision() != expected_analysis_revision ||
        context.workspace->overlay_revision() != expected_overlay_revision)
        return false;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::size_t operation_count = operations.size();
#endif
    context.view->pending_mutations.fetch_add(1, std::memory_order_acq_rel);
    pending_mutation_guard_t setup_pending(context.view);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto preview_kind = operations.front().kind;
    const auto preview_address = operations.front().address.value;
#endif
    auto mutation_body = [context, operations = std::move(operations),
                          expected_generation, expected_analysis_revision,
                          expected_overlay_revision, completion = std::move(completion)](
        bool cancelled) mutable {
        pending_mutation_guard_t pending(context.view);
        std::string error;
        bool authoritative_succeeded = false;
        try {
            if (cancelled) {
                error = "Mutation cancelled before execution.";
            } else if (context.workspace->generation() != expected_generation ||
                       context.workspace->analysis_revision() != expected_analysis_revision) {
                error = "The analysis publication changed before the mutation ran; select the item and retry.";
            } else {
                std::lock_guard<std::mutex> mutation_lock(
                    context.model->mutation_mutex);
                auto overlay = context.workspace->overlay();
                if (!overlay) {
                    error = "Workspace overlay is unavailable.";
                } else {
                    overlay_transaction_request_t request;
                    request.expected_revision = expected_overlay_revision;
                    request.operations = operations;
                    auto result = overlay->transact(
                        request, context.workspace->cancellation_token());
                    if (result) {
                        authoritative_succeeded = true;
                        try {
                            std::string publication_detail;
                            const bool published =
                                reconcile_committed_overlay_state(
                                    context, publication_detail);
                            record_overlay_presentation_result(
                                context, published,
                                std::move(publication_detail));
                        } catch (const std::exception& exception) {
                            try {
                                record_overlay_presentation_result(context, false,
                                    std::string("Derived overlay publication failed: ") +
                                        exception.what());
                            } catch (...) {
                            }
                        } catch (...) {
                            try {
                                record_overlay_presentation_result(context, false,
                                    "Derived overlay publication failed.");
                            } catch (...) {
                            }
                        }
                    } else {
                        error = result.error().stable_code() + ": " +
                            result.error().message;
                    }
                }
            }
        } catch (const std::exception& exception) {
            if (!authoritative_succeeded)
                error = std::string("Overlay mutation execution failed: ") +
                    exception.what();
        } catch (...) {
            if (!authoritative_succeeded)
                error = "Overlay mutation execution failed.";
        }
        const bool succeeded = authoritative_succeeded && error.empty();
        std::string completion_error;
        try {
            completion_error = error;
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = std::move(error);
            context.view->formatted.clear();
            context.view->cached_overlay_revision = context.workspace->overlay_revision();
        } catch (...) {
        }
        if (completion) {
            try {
                completion(succeeded, completion_error);
            } catch (...) {
            }
        }
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    setup_pending.release();
    mutation_body(false);
    bool succeeded = false;
    std::string mutation_detail;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        succeeded = context.view->mutation_error.empty();
        mutation_detail = succeeded
            ? std::to_string(static_cast<unsigned>(preview_kind))
            : context.view->mutation_error;
    }
    aida::preview::disasm::record("workspace_overlay_mutation", preview_address,
        std::move(mutation_detail));
    return succeeded;
#else
    bool accepted = false;
    try {
        const std::string target_id =
            context.workspace->identity().binary_id().to_hex();
        aida::infra::taskflow_runtime::task_descriptor_t descriptor;
        descriptor.domain =
            aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        descriptor.owner_subsystem = "analysis_ui";
        descriptor.label = "workspace_overlay_mutation";
        descriptor.target_id = target_id.c_str();
        descriptor.generation = context.publication->generation;
        descriptor.cancellable_body = [mutation_body = std::move(mutation_body)](
            const aida::infra::taskflow_runtime::cancellation_token_t&
                runtime_cancel) mutable {
            mutation_body(runtime_cancel.requested.load(
                std::memory_order_acquire));
        };
        const auto submitted = aida::infra::taskflow_runtime::submit(
            std::move(descriptor));
        if (!submitted.submitted) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = submitted.reject_reason.empty()
                ? "Mutation queue rejected the request."
                : submitted.reject_reason;
            return false;
        }
        setup_pending.release();
        accepted = true;
        aida::ui::task_center::task_registration_t registration;
        registration.owner = "analysis";
        registration.owner_view = "document.disassembly";
        registration.owner_action = "analysis.overlay.mutate";
        registration.target = target_id;
        registration.label = "Apply reviewed analysis overlay mutation";
        registration.stage = "Queued";
        registration.affected_entity = std::to_string(operation_count) +
            " overlay operation(s)";
        registration.progress = -1.f;
        registration.cancellation_is_safe = true;
        registration.callbacks.focus = [] {
            static_cast<void>(aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.disassembly")));
        };
        static_cast<void>(aida::ui::task_center::register_taskflow_job(
            submitted.handle, std::move(registration)));
        return true;
    } catch (const std::exception& exception) {
        if (accepted)
            return true;
        try {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error =
                std::string("Mutation queue setup failed: ") + exception.what();
        } catch (...) {
        }
        return false;
    } catch (...) {
        if (accepted)
            return true;
        try {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = "Mutation queue setup failed.";
        } catch (...) {
        }
        return false;
    }
#endif
}

std::weak_ptr<analysis_workspace_t>& static_patch_owner() {
    static std::weak_ptr<analysis_workspace_t> value;
    return value;
}

constexpr std::size_t k_static_patch_maximum_bytes = 64U * 1024U;

std::string encode_patch_bytes(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string encoded;
    if (!bytes.empty())
        encoded.reserve(bytes.size() * 3U - 1U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0)
            encoded.push_back(' ');
        encoded.push_back(digits[(bytes[index] >> 4U) & 0x0fU]);
        encoded.push_back(digits[bytes[index] & 0x0fU]);
    }
    return encoded;
}

std::optional<std::vector<std::uint8_t>> decode_patch_bytes(
    std::string_view encoded, std::string& error) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve((std::min)(k_static_patch_maximum_bytes,
        (encoded.size() + 1U) / 2U));
    int high = -1;
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const unsigned char value = static_cast<unsigned char>(encoded[index]);
        if (std::isspace(value) || value == ',' || value == ':' || value == '_' || value == '-') {
            if (high != -1) {
                error = "Each byte must contain exactly two hexadecimal digits.";
                return {};
            }
            continue;
        }
        if (value == '0' && index + 1U < encoded.size() &&
            (encoded[index + 1U] == 'x' || encoded[index + 1U] == 'X') && high == -1) {
            ++index;
            continue;
        }
        int nibble = -1;
        if (value >= '0' && value <= '9') nibble = value - '0';
        else if (value >= 'a' && value <= 'f') nibble = value - 'a' + 10;
        else if (value >= 'A' && value <= 'F') nibble = value - 'A' + 10;
        if (nibble < 0) {
            error = "Patch bytes may contain only hexadecimal digits and separators.";
            return {};
        }
        if (high < 0) {
            high = nibble;
        } else {
            if (bytes.size() >= k_static_patch_maximum_bytes) {
                error = "Interactive patch review is limited to 64 KiB per operation.";
                return {};
            }
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    if (high != -1) {
        error = "The final byte is missing its second hexadecimal digit.";
        return {};
    }
    if (bytes.empty()) {
        error = "Enter at least one replacement byte.";
        return {};
    }
    error.clear();
    return bytes;
}

bool queue_overlay_operation(const workspace_context_t& context,
                             overlay_operation_t operation,
                             std::optional<std::uint64_t> required_generation = {},
                             std::optional<std::uint64_t> required_analysis_revision = {},
                             std::optional<std::uint64_t> required_overlay_revision = {},
                             overlay_completion_t completion = {}) {
    std::vector<overlay_operation_t> operations;
    operations.push_back(std::move(operation));
    return queue_overlay_transaction(context, std::move(operations),
        required_generation, required_analysis_revision, required_overlay_revision,
        std::move(completion));
}

bool queue_overlay_history(const workspace_context_t& source_context, bool redo,
                           std::uint64_t expected_generation,
                           std::uint64_t expected_analysis_revision,
                           std::uint64_t expected_overlay_revision) {
    const auto context = authoritative_context(source_context);
    if (!context || !context.workspace->overlay() ||
        context.workspace->generation() != expected_generation ||
        context.workspace->analysis_revision() != expected_analysis_revision ||
        context.workspace->overlay_revision() != expected_overlay_revision)
        return false;
    context.view->pending_mutations.fetch_add(1, std::memory_order_acq_rel);
    pending_mutation_guard_t setup_pending(context.view);
    auto body = [context, redo, expected_generation, expected_analysis_revision,
                 expected_overlay_revision](bool cancelled) {
        pending_mutation_guard_t pending(context.view);
        std::string error;
        bool authoritative_succeeded = false;
        try {
            if (cancelled) {
                error = "Overlay history request was cancelled before execution.";
            } else if (context.workspace->generation() != expected_generation ||
                       context.workspace->analysis_revision() != expected_analysis_revision) {
                error = "The analysis publication changed before the overlay history request ran.";
            } else {
                std::lock_guard<std::mutex> mutation_lock(
                    context.model->mutation_mutex);
                auto overlay = context.workspace->overlay();
                if (!overlay) {
                    error = "Workspace overlay history is unavailable.";
                } else {
                    const auto result = redo
                        ? overlay->redo(expected_overlay_revision,
                            context.workspace->cancellation_token())
                        : overlay->undo(expected_overlay_revision,
                            context.workspace->cancellation_token());
                    if (!result) {
                        error = result.error().stable_code() + ": " +
                            result.error().message;
                    } else {
                        authoritative_succeeded = true;
                        try {
                            std::string publication_detail;
                            const bool published =
                                reconcile_committed_overlay_state(
                                    context, publication_detail);
                            record_overlay_presentation_result(
                                context, published,
                                std::move(publication_detail));
                        } catch (const std::exception& exception) {
                            try {
                                record_overlay_presentation_result(context, false,
                                    std::string("Derived overlay publication failed: ") +
                                        exception.what());
                            } catch (...) {
                            }
                        } catch (...) {
                            try {
                                record_overlay_presentation_result(context, false,
                                    "Derived overlay publication failed.");
                            } catch (...) {
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& exception) {
            if (!authoritative_succeeded)
                error = std::string("Overlay history execution failed: ") +
                    exception.what();
        } catch (...) {
            if (!authoritative_succeeded)
                error = "Overlay history execution failed.";
        }
        try {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = std::move(error);
            context.view->formatted.clear();
            context.view->cached_overlay_revision = context.workspace->overlay_revision();
        } catch (...) {
        }
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    setup_pending.release();
    body(false);
    std::lock_guard<std::mutex> lock(context.view->mutex);
    return context.view->mutation_error.empty();
#else
    try {
        aida::infra::taskflow_runtime::task_descriptor_t descriptor;
        descriptor.domain =
            aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        descriptor.owner_subsystem = "analysis_ui";
        descriptor.label = redo
            ? "workspace_overlay_redo" : "workspace_overlay_undo";
        const std::string target_id =
            context.workspace->identity().binary_id().to_hex();
        descriptor.target_id = target_id.c_str();
        descriptor.generation = expected_generation;
        descriptor.cancellable_body = [body = std::move(body)](
            const aida::infra::taskflow_runtime::cancellation_token_t& cancel) mutable {
            body(cancel.requested.load(std::memory_order_acquire));
        };
        const auto submitted = aida::infra::taskflow_runtime::submit(
            std::move(descriptor));
        if (!submitted.submitted) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = submitted.reject_reason.empty()
                ? "Overlay history queue rejected the request."
                : submitted.reject_reason;
            return false;
        }
        setup_pending.release();
        return true;
    } catch (const std::exception& exception) {
        try {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error =
                std::string("Overlay history queue setup failed: ") +
                    exception.what();
        } catch (...) {
        }
        return false;
    } catch (...) {
        try {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error =
                "Overlay history queue setup failed.";
        } catch (...) {
        }
        return false;
    }
#endif
}

std::string address_label(const workspace_context_t& context,
                          const address_t& address, addr_format_t format) {
    char buffer[48]{};
    if (format == addr_format_t::rva) {
        std::uint64_t rva = address.value;
        if (address.space != address_space_id_t::relative_virtual && context.image) {
            const auto runtime = runtime_address(context, address);
            if (runtime) {
                const auto base = display_base_override(context);
                const auto translated = base && *runtime >= *base
                    ? std::optional<std::uint64_t>(*runtime - *base)
                    : optional_value(context.image->va_to_rva(*runtime));
                if (translated)
                    rva = *translated;
            }
        }
        std::snprintf(buffer, sizeof(buffer), "+%08llX",
            static_cast<unsigned long long>(rva));
    } else if (format == addr_format_t::file_offset) {
        const auto offset = provider_offset(context, address);
        if (offset)
            std::snprintf(buffer, sizeof(buffer), "%08llX",
                static_cast<unsigned long long>(*offset));
        else
            std::snprintf(buffer, sizeof(buffer), "--------");
    } else {
        std::snprintf(buffer, sizeof(buffer), "%016llX",
            static_cast<unsigned long long>(runtime_address(context, address).value_or(address.value)));
    }
    return buffer;
}

std::optional<std::uint64_t> parse_address_text(const workspace_context_t& context,
                                                std::string text) {
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), [](char value) {
        return value != ' ' && value != '\t';
    }));
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.pop_back();
    if (text.empty())
        return {};
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (parsed.ec == std::errc() && parsed.ptr == text.data() + text.size())
        return value;
    if (context.publication && context.publication->snapshot) {
        const auto& symbols = context.publication->snapshot->symbols;
        auto found = std::find_if(symbols.begin(), symbols.end(), [&](const symbol_record_t& symbol) {
            return symbol.name == text;
        });
        if (found != symbols.end())
            return runtime_address(context, found->address);
    }
    return {};
}

void render_xref_popup(const workspace_context_t& context) {
    if (!context.view)
        return;
    bool open = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        open = context.view->xref_popup_open;
    }
    if (open)
        ImGui::OpenPopup("Cross references##workspace_xrefs");
    if (!aida::ui::design::begin_dialog_exact("Cross references##workspace_xrefs",
            ImVec2(720.0f, 560.0f), ImVec2(420.0f, 320.0f)))
        return;
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Close", nullptr);
    aida::ui::design::begin_dialog_body("workspace_xrefs_body", footer_height);
    std::vector<xref_popup_entry_t> entries;
    bool scanning = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        entries = context.view->xref_results;
        scanning = context.view->xref_scanning.load(std::memory_order_acquire);
    }
    static_cast<void>(aida::ui::search_field("xref_filter",
        context.view->xref_popup_filter, sizeof(context.view->xref_popup_filter),
        "Filter by name or address", ImGui::GetContentRegionAvail().x));
    if (scanning)
        aida::ui::inline_notice("xref_scanning", "Searching cross references",
            "Querying the workspace index for matching callers and targets.",
            aida::ui::status_kind_t::info);
    ImGui::BeginChild("##xref_rows", ImVec2(0.0f, ImGui::GetContentRegionAvail().y), true);
    const bool rows_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    const std::string filter(context.view->xref_popup_filter);
    std::vector<std::size_t> visible_indices;
    visible_indices.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        char address[32]{};
        std::snprintf(address, sizeof(address), "%016llX",
            static_cast<unsigned long long>(entry.addr));
        if (!filter.empty() && entry.function_name.find(filter) == std::string::npos &&
            std::string(address).find(filter) == std::string::npos)
            continue;
        visible_indices.push_back(index);
    }
    int selected_index = -1;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        selected_index = context.view->xref_popup_selected;
    }
    bool keyboard_selection_changed = false;
    if (visible_indices.empty()) {
        selected_index = -1;
    } else {
        selected_index = (std::clamp)(selected_index, 0,
            static_cast<int>(visible_indices.size() - 1));
        if (rows_focused) {
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) {
                selected_index = (std::max)(0, selected_index - 1);
                keyboard_selection_changed = true;
            }
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) {
                selected_index = (std::min)(static_cast<int>(visible_indices.size() - 1),
                    selected_index + 1);
                keyboard_selection_changed = true;
            }
        }
    }
    for (std::size_t visible = 0; visible < visible_indices.size(); ++visible) {
        const auto& entry = entries[visible_indices[visible]];
        char address[32]{};
        std::snprintf(address, sizeof(address), "%016llX",
            static_cast<unsigned long long>(entry.addr));
        std::string label = std::string(address) + "  " + entry.function_name;
        if (ImGui::Selectable(label.c_str(), selected_index == static_cast<int>(visible),
                ImGuiSelectableFlags_AllowDoubleClick)) {
            selected_index = static_cast<int>(visible);
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                goto_address(entry.addr, context);
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->xref_popup_open = false;
                ImGui::CloseCurrentPopup();
            }
        }
        if (keyboard_selection_changed && selected_index == static_cast<int>(visible))
            ImGui::SetScrollHereY(0.5f);
    }
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_selected = selected_index;
    }
    if (visible_indices.empty() && !scanning)
        aida::ui::compact_empty_state("xref_empty", "No cross references found",
            filter.empty() ? "No indexed references target this location."
                           : "No references match the current filter.",
            nullptr, ImVec2(0.0f, 140.0f));
    ImGui::EndChild();
    if (rows_focused && !visible_indices.empty() && selected_index >= 0 &&
        ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
        goto_address(entries[visible_indices[static_cast<std::size_t>(selected_index)]].addr,
            context);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_open = false;
        ImGui::CloseCurrentPopup();
    }
    aida::ui::design::end_dialog_body();
    const auto footer = aida::ui::design::dialog_footer("workspace_xrefs_footer",
        "Close", true, false, nullptr);
    if (footer.confirmed || footer.cancelled) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_open = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void queue_listing_export(const workspace_context_t& context) {
    if (!context || !context.image || !context.publication ||
        !context.publication->snapshot ||
        context.view->export_pending.exchange(true, std::memory_order_acq_rel))
        return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto count = context.publication->snapshot->instructions.size();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_error.clear();
        context.view->export_status = "Exported " + std::to_string(count) +
            " instructions to aida_disasm_dump.txt.";
    }
    context.view->export_pending.store(false, std::memory_order_release);
    aida::preview::disasm::record("export_workspace_disassembly", count,
        "aida_disasm_dump.txt");
#else
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_error.clear();
        context.view->export_status = "Exporting full listing...";
    }
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    const std::string export_path = "aida_disasm_dump.txt";
    const std::string temporary_path = export_path + "." + target_id + "." +
        std::to_string(context.publication->generation) + ".tmp";
    const auto presentation_base = display_base_override(context);
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::long_running;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "export_workspace_disassembly";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, export_path, temporary_path, presentation_base](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        std::string error;
        std::size_t written = 0;
        std::ofstream output(temporary_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "Unable to open aida_disasm_dump.txt for writing.";
        } else {
            auto decoder_result = worker_owned_x86_decoder_t::create(
                context.image->architecture_mode());
            if (!decoder_result) {
                error = decoder_result.error().stable_code() + ": " +
                    decoder_result.error().message;
            } else {
                auto decoder = decoder_result.take_value();
                instruction_format_options_t options;
                options.maximum_text_bytes = 2048;
                for (const auto& instruction : context.publication->snapshot->instructions) {
                    if (runtime_cancel.requested.load(std::memory_order_acquire) ||
                        context.workspace->cancellation_token().stop_requested()) {
                        error = "Listing export cancelled.";
                        break;
                    }
                    const auto formatted = decoder->format_one(context.workspace->provider(),
                        *context.image, instruction, options,
                        context.workspace->cancellation_token());
                    if (!formatted) {
                        error = formatted.error().stable_code() + ": " + formatted.error().message;
                        break;
                    }
                    std::string bytes;
                    if (const auto offset = provider_offset(context, instruction.address)) {
                        auto lease = context.workspace->provider().lease(*offset,
                            instruction.length, context.workspace->cancellation_token());
                        if (lease)
                            bytes = byte_text(lease.value(), *offset, *offset, instruction.length);
                    }
                    std::uint64_t display_address = instruction.address.value;
                    if (presentation_base && instruction.address.space ==
                        aida::analysis::address_space_id_t::relative_virtual) {
                        display_address = checked_add(*presentation_base,
                            instruction.address.value).value_or(instruction.address.value);
                    } else {
                        display_address = runtime_address(context,
                            instruction.address).value_or(instruction.address.value);
                    }
                    char address[32]{};
                    std::snprintf(address, sizeof(address), "%016llX",
                        static_cast<unsigned long long>(display_address));
                    output << address << "  " << bytes << "  " << formatted.value() << "\r\n";
                    if (!output) {
                        error = "Writing aida_disasm_dump.txt failed.";
                        break;
                    }
                    ++written;
                }
            }
        }
        output.close();
        if (error.empty() && !MoveFileExA(temporary_path.c_str(), export_path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            error = "Replacing aida_disasm_dump.txt failed with Win32 error " +
                std::to_string(GetLastError()) + ".";
        }
        if (!error.empty())
            DeleteFileA(temporary_path.c_str());
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->export_error = std::move(error);
            context.view->export_status = context.view->export_error.empty()
                ? "Exported " + std::to_string(written) +
                    " instructions to aida_disasm_dump.txt."
                : std::string();
        }
        context.view->export_pending.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        context.view->export_pending.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_status.clear();
        context.view->export_error = submitted.reject_reason.empty()
            ? "Listing export queue rejected the request." : submitted.reject_reason;
    }
#endif
}

}

workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    std::string_view presentation_key) {
    workspace_context_t context;
    if (!workspace || workspace->closed())
        return context;
    context.workspace = workspace;
    context.publication = workspace->analysis_publication();
    context.image = context.publication && context.publication->snapshot
        ? context.publication->snapshot->image : workspace->image();
    context.model = model_for(workspace);
    context.view = presentation_for(context.model, presentation_key);
    context.progress = workspace->progress();
    initialize_model(workspace, context.model);
    if (context.model && context.view && context.publication &&
        context.publication->overlay_revision != 0) {
        const auto authority = authoritative_context(context);
        const auto presentation = context.publication->overlay_presentation;
        bool attempted = false;
        {
            std::lock_guard<std::mutex> lock(authority.view->mutex);
            attempted = authority.view->derived_publication_target_revision ==
                context.publication->overlay_revision;
        }
        if ((!presentation || presentation->overlay_revision !=
                context.publication->overlay_revision) && !attempted &&
            authority.view->pending_mutations.load(std::memory_order_acquire) == 0) {
            try {
                std::unique_lock<std::mutex> mutation_lock(
                    context.model->mutation_mutex, std::try_to_lock);
                if (mutation_lock.owns_lock()) {
                    std::string detail;
                    const bool published = reconcile_committed_overlay_state(
                        authority, detail);
                    record_overlay_presentation_result(
                        authority, published, std::move(detail));
                    if (published) {
                        const auto refreshed = workspace->analysis_publication();
                        if (refreshed &&
                            refreshed->generation ==
                                context.publication->generation &&
                            refreshed->analysis_revision ==
                                context.publication->analysis_revision &&
                            refreshed->overlay_revision ==
                                context.publication->overlay_revision) {
                            context.publication = refreshed;
                            context.image = refreshed->snapshot
                                ? refreshed->snapshot->image : workspace->image();
                        }
                    }
                }
            } catch (...) {
                try {
                    record_overlay_presentation_result(authority, false,
                        "Derived overlay publication recovery failed.");
                } catch (...) {
                }
            }
        }
    }
    if (context.view && context.publication) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (context.view->cached_generation != context.publication->generation ||
            context.view->cached_analysis_revision != context.publication->analysis_revision ||
            context.view->cached_overlay_revision != context.publication->overlay_revision) {
            context.view->formatted.clear();
            context.view->pending_format_pages.clear();
            context.view->cached_generation = context.publication->generation;
            context.view->cached_analysis_revision = context.publication->analysis_revision;
            context.view->cached_overlay_revision = context.publication->overlay_revision;
            context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
        }
        const auto workspace_view = workspace->view_state();
        if (!context.view->selection_initialized ||
            (presentation_key.empty() && workspace_view.revision != 0 &&
             workspace_view.revision != context.model->presentation_selection_revision.load(
                std::memory_order_acquire))) {
            context.view->selection = workspace_view.selection;
            context.view->selection_initialized = true;
            if (presentation_key.empty())
                context.model->presentation_selection_revision.store(
                    workspace_view.revision, std::memory_order_release);
        }
    }
    return context;
}

workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    return capture_workspace(workspace, {});
}

workspace_context_t capture_selected_workspace() {
    return capture_workspace(
        aida::analysis::workspace_registry().selected_for_ui(),
        aida::ui::application_views::focused_disassembly_presentation_key());
}

workspace_context_t capture_selected_workspace(std::string_view presentation_key) {
    return capture_workspace(
        aida::analysis::workspace_registry().selected_for_ui(), presentation_key);
}

void reset_presentation(std::string_view presentation_key) {
    if (presentation_key.empty())
        return;
    std::lock_guard<std::mutex> registry_lock(model_registry_mutex());
    for (auto& [_, model] : model_registry()) {
        if (model) {
            std::lock_guard<std::mutex> model_lock(model->initialization_mutex);
            model->presentations[std::string(presentation_key)] =
                std::make_shared<state_t>();
        }
    }
}

void release_presentation(std::string_view presentation_key) {
    if (presentation_key.empty())
        return;
    std::lock_guard<std::mutex> registry_lock(model_registry_mutex());
    for (auto& [_, model] : model_registry()) {
        if (model) {
            std::lock_guard<std::mutex> model_lock(model->initialization_mutex);
            model->presentations.erase(std::string(presentation_key));
        }
    }
}

void clone_presentation(std::string_view source_key, std::string_view target_key) {
    if (target_key.empty() || source_key == target_key)
        return;
    std::lock_guard<std::mutex> registry_lock(model_registry_mutex());
    for (auto& [_, model] : model_registry()) {
        if (model) {
            const auto source = presentation_for(model, source_key);
            const auto target = presentation_for(model, target_key);
            if (!source || !target)
                continue;
            std::scoped_lock state_lock(source->mutex, target->mutex);
            target->addr_format = source->addr_format;
            target->show_bytes = source->show_bytes;
            target->display_image_base = source->display_image_base;
            target->banner_selected_all = source->banner_selected_all;
            target->banner_selected_line = source->banner_selected_line;
            target->active_section = source->active_section;
            target->selection = source->selection;
            target->target_scroll_y = source->target_scroll_y;
            target->scroll_restore_pending = true;
            target->scroll_to_selection = false;
            target->selection_initialized = source->selection_initialized;
        }
    }
}

bool capture_selected_presentation(std::string_view presentation_key,
                                   presentation_snapshot_t& snapshot) {
    const auto context = capture_selected_workspace(presentation_key);
    if (!context.view)
        return false;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    snapshot.addr_format = context.view->addr_format;
    snapshot.show_bytes = context.view->show_bytes;
    snapshot.display_image_base = context.view->display_image_base;
    snapshot.active_section = context.view->active_section;
    snapshot.selection = context.view->selection;
    snapshot.scroll_y = context.view->target_scroll_y;
    return true;
}

bool restore_selected_presentation(std::string_view presentation_key,
                                   const presentation_snapshot_t& snapshot) {
    if (presentation_key.empty())
        return false;
    const auto context = capture_selected_workspace(presentation_key);
    if (!context.view)
        return false;
    if (snapshot.active_section >= 0 && (!context.image ||
        static_cast<std::size_t>(snapshot.active_section) >=
            context.image->sections().size()))
        return false;
    if (snapshot.selection) {
        if (snapshot.selection->architecture !=
                context.workspace->identity().architecture() ||
            (context.image && snapshot.selection->mode !=
                context.image->architecture_mode()) ||
            !runtime_address(context, *snapshot.selection))
            return false;
    }
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->addr_format = snapshot.addr_format;
    context.view->show_bytes = snapshot.show_bytes;
    context.view->display_image_base = snapshot.display_image_base;
    context.view->active_section = snapshot.active_section;
    context.view->selection = snapshot.selection;
    context.view->selection_initialized = true;
    context.view->target_scroll_y = (std::max)(snapshot.scroll_y, 0.0f);
    context.view->scroll_restore_pending = true;
    context.view->scroll_to_selection = false;
    return true;
}

std::optional<aida::analysis::address_t> typed_address(
    const workspace_context_t& context, std::uint64_t value) {
    if (!context.workspace)
        return {};
    const auto& identity = context.workspace->identity();
    aida::analysis::address_t address;
    address.architecture = identity.architecture();
    address.mode = context.image ? context.image->architecture_mode() :
        (identity.architecture() == aida::analysis::architecture_id_t::x86_64
            ? aida::analysis::architecture_mode_t::x86_64
            : aida::analysis::architecture_mode_t::x86_32);
    if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        address.space = aida::analysis::address_space_id_t::live_virtual;
        address.value = value;
        return address;
    }
    if (!context.image)
        return {};
    const auto display_base = display_base_override(context);
    const std::uint64_t base = display_base.value_or(context.image->image_base());
    if (value >= base) {
        std::optional<std::uint64_t> rva;
        if (display_base) {
            const auto candidate = value - base;
            if (candidate < context.image->image_size())
                rva = candidate;
        } else {
            rva = optional_value(context.image->va_to_rva(value));
        }
        if (!rva) return {};
        address.space = aida::analysis::address_space_id_t::relative_virtual;
        address.value = *rva;
        return address;
    }
    if (value < context.image->image_size()) {
        address.space = aida::analysis::address_space_id_t::relative_virtual;
        address.value = value;
        return address;
    }
    return {};
}

std::optional<std::uint64_t> runtime_address(
    const workspace_context_t& context, const aida::analysis::address_t& address) {
    using aida::analysis::address_space_id_t;
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual)
        return address.value;
    if (!context.image)
        return {};
    if (address.space == address_space_id_t::relative_virtual) {
        if (const auto base = display_base_override(context))
            return checked_add(*base, address.value);
        return optional_value(context.image->rva_to_va(address.value));
    }
    if (address.space == address_space_id_t::file_offset) {
        auto rva = optional_value(context.image->file_offset_to_rva(address.value));
        if (!rva)
            return {};
        if (const auto base = display_base_override(context))
            return checked_add(*base, *rva);
        return optional_value(context.image->rva_to_va(*rva));
    }
    return {};
}

std::optional<std::uint64_t> provider_offset(
    const workspace_context_t& context, const aida::analysis::address_t& address) {
    using aida::analysis::address_space_id_t;
    if (!context.workspace)
        return {};
    if (address.space == address_space_id_t::file_offset)
        return address.value < context.workspace->provider().size()
            ? std::optional<std::uint64_t>(address.value) : std::nullopt;
    if (address.space == address_space_id_t::live_virtual) {
        const auto& module = context.workspace->identity().module();
        if (!module || address.value < module->base || address.value - module->base >= module->size)
            return {};
        return address.value - module->base;
    }
    if (!context.image)
        return {};
    std::optional<std::uint64_t> rva;
    if (address.space == address_space_id_t::relative_virtual)
        rva = address.value;
    else if (address.space == address_space_id_t::virtual_address)
        rva = optional_value(context.image->va_to_rva(address.value));
    return rva ? optional_value(context.image->rva_to_file_offset(*rva)) : std::nullopt;
}

aida::analysis::workspace_result_t<std::vector<std::uint8_t>> read_bytes(
    const workspace_context_t& context, const aida::analysis::address_t& address,
    std::size_t size) {
    using namespace aida::analysis;
    if (!context.workspace)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                "workspace is unavailable", "ui_read"));
    const auto offset = provider_offset(context, address);
    if (!offset)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::out_of_range,
                "address is not backed by the workspace provider", "ui_read"));
    return context.workspace->provider().read_vector(*offset, size, 64ULL << 20,
        context.workspace->cancellation_token());
}

std::string resolve_symbol(const workspace_context_t& context,
                           const aida::analysis::address_t& address) {
    if (!context.publication || !context.publication->snapshot)
        return {};
    const auto& symbols = context.publication->snapshot->symbols;
    auto found = std::lower_bound(symbols.begin(), symbols.end(), address,
        [](const aida::analysis::symbol_record_t& symbol,
           const aida::analysis::address_t& value) {
            return symbol.address < value;
        });
    if (found != symbols.end() && found->address == address)
        return found->name;
    if (found != symbols.begin()) {
        --found;
        if (found->address.space == address.space && found->address.value <= address.value) {
            char suffix[32]{};
            std::snprintf(suffix, sizeof(suffix), "+0x%llX",
                static_cast<unsigned long long>(address.value - found->address.value));
            return found->name + suffix;
        }
    }
    return {};
}

std::string resolve_name(const workspace_context_t& context,
                         const aida::analysis::address_t& address) {
    const auto presentation = context.publication
        ? context.publication->overlay_presentation : nullptr;
    if (presentation &&
        presentation->overlay_revision == context.publication->overlay_revision) {
        const auto found = std::lower_bound(
            presentation->renames.begin(), presentation->renames.end(), address,
            [](const auto& entry, const auto& value) {
                return entry.address < value;
            });
        if (found != presentation->renames.end() && found->address == address)
            return found->text;
    }
    return resolve_symbol(context, address);
}

std::string comment(const workspace_context_t& context,
                    const aida::analysis::address_t& address) {
    const auto presentation = context.publication
        ? context.publication->overlay_presentation : nullptr;
    if (!presentation ||
        presentation->overlay_revision != context.publication->overlay_revision)
        return {};
    const auto found = std::lower_bound(
        presentation->comments.begin(), presentation->comments.end(), address,
        [](const auto& entry, const auto& value) {
            return entry.address < value;
        });
    return found != presentation->comments.end() && found->address == address
        ? found->text : std::string();
}

std::string auto_comment(const workspace_context_t& context,
                         const aida::analysis::address_t& address) {
    return context.model ? context.model->automatic_comments.get(address) : std::string();
}

void request_format_range(const workspace_context_t& context,
                          std::size_t begin, std::size_t end) {
    request_format_page(context, begin, end);
}

std::optional<formatted_instruction_t> formatted_instruction(
    const workspace_context_t& context, aida::analysis::entity_id_t instruction_id) {
    if (!context.view)
        return {};
    std::lock_guard<std::mutex> lock(context.view->mutex);
    auto found = context.view->formatted.find(instruction_id);
    return found == context.view->formatted.end()
        ? std::nullopt : std::optional<formatted_instruction_t>(found->second);
}

bool queue_comment(const workspace_context_t& context,
                   const aida::analysis::address_t& address, std::string text,
                   std::optional<std::uint64_t> required_generation,
                   std::optional<std::uint64_t> required_analysis_revision,
                   std::optional<std::uint64_t> required_overlay_revision,
                   overlay_completion_t completion) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::comment;
    operation.address = address;
    operation.text = std::move(text);
    return queue_overlay_operation(context, std::move(operation), required_generation,
        required_analysis_revision, required_overlay_revision, std::move(completion));
}

bool queue_rename(const workspace_context_t& context,
                  const aida::analysis::address_t& address, std::string name,
                  std::optional<std::uint64_t> required_generation,
                  std::optional<std::uint64_t> required_analysis_revision,
                  std::optional<std::uint64_t> required_overlay_revision,
                  overlay_completion_t completion) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::name;
    operation.address = address;
    operation.name = std::move(name);
    return queue_overlay_operation(context, std::move(operation), required_generation,
        required_analysis_revision, required_overlay_revision, std::move(completion));
}

std::vector<bookmark_t> bookmark_snapshot(const workspace_context_t& context) {
    std::vector<bookmark_t> result;
    const auto presentation = context.publication
        ? context.publication->overlay_presentation : nullptr;
    if (!presentation ||
        presentation->overlay_revision != context.publication->overlay_revision)
        return result;
    result.reserve(presentation->bookmarks.size());
    for (const auto& entry : presentation->bookmarks)
        result.push_back({entry.address.value, entry.text});
    return result;
}

bool bookmarked(const workspace_context_t& context,
                const aida::analysis::address_t& address) {
    const auto presentation = context.publication
        ? context.publication->overlay_presentation : nullptr;
    if (!presentation ||
        presentation->overlay_revision != context.publication->overlay_revision)
        return false;
    const auto found = std::lower_bound(
        presentation->bookmarks.begin(), presentation->bookmarks.end(), address,
        [](const auto& entry, const auto& value) {
            return entry.address < value;
        });
    return found != presentation->bookmarks.end() && found->address == address;
}

bool queue_bookmark(const workspace_context_t& context,
                    const aida::analysis::address_t& address, std::string label) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::bookmark;
    operation.address = address;
    operation.name = std::move(label);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_patch(const workspace_context_t& context,
                 const aida::analysis::address_t& address,
                 std::vector<std::uint8_t> bytes) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::byte_patch;
    operation.address = address;
    operation.bytes = std::move(bytes);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_type_application(const workspace_context_t& context,
                            const aida::analysis::address_t& address,
                            std::string type,
                            std::optional<std::uint64_t> required_generation,
                            std::optional<std::uint64_t> required_analysis_revision,
                            std::optional<std::uint64_t> required_overlay_revision,
                            overlay_completion_t completion) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::type_application;
    operation.address = address;
    operation.type = std::move(type);
    return queue_overlay_operation(context, std::move(operation), required_generation,
        required_analysis_revision, required_overlay_revision, std::move(completion));
}

bool queue_type_declaration(const workspace_context_t& context,
                            std::string declaration) {
    if (!context.workspace || !context.image)
        return false;
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::type_declaration;
    operation.address.space = aida::analysis::address_space_id_t::relative_virtual;
    operation.address.value = 0;
    operation.address.architecture = context.workspace->identity().architecture();
    operation.address.mode = context.image->architecture_mode();
    operation.text = std::move(declaration);
    return queue_overlay_operation(context, std::move(operation));
}

bool initialize_static_patch_review(const workspace_context_t& context,
                                    const aida::analysis::address_t& address,
                                    std::uint64_t extent,
                                    static_patch_mode_t mode,
                                    std::vector<std::uint8_t> original,
                                    std::vector<std::uint8_t> proposed,
                                    bool prefer_existing_patch,
                                    bool focus_input,
                                    std::string description,
                                    std::string status,
                                    std::optional<std::uint64_t> required_generation,
                                    std::optional<std::uint64_t> required_analysis_revision,
                                    std::optional<std::uint64_t> required_overlay_revision,
                                    std::string* error) {
    const auto authority = authoritative_context(context);
    const auto fail = [error](std::string message) {
        if (error) *error = std::move(message);
        return false;
    };
    const std::uint64_t generation = required_generation.value_or(
        context.workspace->generation());
    const std::uint64_t analysis_revision = required_analysis_revision.value_or(
        context.workspace->analysis_revision());
    const std::uint64_t overlay_revision = required_overlay_revision.value_or(
        context.workspace->overlay_revision());
    const auto fence_current = [&] {
        return context.workspace->generation() == generation &&
            context.workspace->analysis_revision() == analysis_revision &&
            context.workspace->overlay_revision() == overlay_revision;
    };
    if (!fence_current())
        return fail("The patch review publication fence changed before the modal could be initialized.");
    bool existing_patch = false;
    std::uint64_t existing_patch_size = 0;
    if (const auto overlay = context.workspace->overlay()) {
        const auto patches = overlay->patch_operations();
        const auto existing = std::find_if(patches.begin(), patches.end(),
            [&address](const overlay_operation_t& operation) {
                return operation.address == address && !operation.remove;
            });
        if (existing != patches.end()) {
            existing_patch = true;
            existing_patch_size = existing->bytes.size();
            if (prefer_existing_patch && existing->bytes.size() <= k_static_patch_maximum_bytes)
                proposed = existing->bytes;
        }
    }
    if (mode == static_patch_mode_t::nop_fill)
        proposed.assign(static_cast<std::size_t>(extent), 0x90U);
    const std::string encoded = encode_patch_bytes(proposed);
    if (encoded.size() >= authority.view->static_patch_input.size())
        return fail("The selected patch cannot be represented within the bounded review editor.");
    if (!fence_current())
        return fail("The patch review publication fence changed before the modal could be initialized.");
    {
        std::lock_guard<std::mutex> lock(authority.view->mutex);
        authority.view->static_patch_open = true;
        authority.view->static_patch_focus_input = focus_input;
        authority.view->static_patch_mode = mode;
        authority.view->static_patch_address = address;
        authority.view->static_patch_extent = extent;
        authority.view->static_patch_generation = generation;
        authority.view->static_patch_analysis_revision = analysis_revision;
        authority.view->static_patch_overlay_revision = overlay_revision;
        authority.view->static_patch_existing = existing_patch;
        authority.view->static_patch_existing_size = existing_patch_size;
        authority.view->static_patch_original = std::move(original);
        authority.view->static_patch_proposed = std::move(proposed);
        authority.view->static_patch_input.fill('\0');
        std::memcpy(authority.view->static_patch_input.data(), encoded.data(), encoded.size());
        authority.view->static_patch_description.fill('\0');
        const std::size_t description_size = (std::min)(description.size(),
            authority.view->static_patch_description.size() - 1U);
        std::memcpy(authority.view->static_patch_description.data(),
            description.data(), description_size);
        authority.view->static_patch_error.clear();
        authority.view->static_patch_parse_error.clear();
        authority.view->static_patch_status = existing_patch_size > k_static_patch_maximum_bytes
            ? "The existing overlay exceeds the 64 KiB interactive editor bound. The editor shows the selected immutable baseline; Revert This Overlay remains available."
            : std::move(status);
    }
    static_patch_owner() = context.workspace;
    if (error) error->clear();
    return true;
}

bool open_static_patch_review(const workspace_context_t& context,
                              const aida::analysis::address_t& address,
                              std::uint64_t extent,
                              static_patch_mode_t mode,
                              std::string* error) {
    const auto fail = [error](std::string message) {
        if (error) *error = std::move(message);
        return false;
    };
    if (!context || context.workspace->closing() || context.workspace->closed() ||
        !context.workspace->overlay())
        return fail("The selected workspace has no writable overlay journal.");
    if (mode == static_patch_mode_t::assembly)
        return fail("No reusable standalone assembler provider is registered. Zydis encoding is a build dependency, but the UI has no validated assembly parser/provider; use reviewed Patch Bytes or NOP Fill.");
    if (extent == 0 || extent > k_static_patch_maximum_bytes)
        return fail("Interactive static patch review requires a mapped selection from 1 byte through 64 KiB.");
    if (extent > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return fail("The selected patch extent exceeds this host's addressable size.");
    const auto offset = provider_offset(context, address);
    if (!offset || *offset > context.workspace->provider().size() ||
        extent > context.workspace->provider().size() - *offset)
        return fail("The selected range is not fully backed by the immutable workspace provider.");
    auto original = read_bytes(context, address, static_cast<std::size_t>(extent));
    if (!original)
        return fail(original.error().stable_code() + ": " + original.error().message);
    auto proposed = original.value();
    return initialize_static_patch_review(context, address, extent, mode,
        original.take_value(), std::move(proposed), true,
        mode == static_patch_mode_t::bytes,
        mode == static_patch_mode_t::nop_fill
            ? "Static NOP overlay" : "Static byte overlay",
        {}, {}, {}, {}, error);
}

bool open_selected_patch_review(static_patch_mode_t mode, std::string* error) {
    const auto fail = [error](const char* message) {
        if (error) *error = message;
        return false;
    };
    const auto context = capture_selected_workspace();
    if (!context || !context.publication || !context.publication->snapshot)
        return fail("No analyzed workspace is selected.");
    std::optional<address_t> selected;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        selected = context.view->selection;
    }
    if (!selected)
        return fail("Select an instruction before opening the patch workflow.");
    const auto found = std::find_if(context.publication->snapshot->instructions.begin(),
        context.publication->snapshot->instructions.end(), [&selected](const instruction_record_t& instruction) {
            return instruction.address == *selected;
        });
    if (found == context.publication->snapshot->instructions.end() || found->length == 0)
        return fail("The selected analysis entity has no current instruction byte range.");
    const std::uint64_t runtime = runtime_address(context, *selected).value_or(selected->value);
    const auto process = context.workspace->identity().process();
    if (process && driver_bridge::attached_pid() == process->pid) {
        if (mode == static_patch_mode_t::assembly)
            return fail("No reusable standalone assembler provider is registered; use reviewed Patch Bytes or NOP Fill.");
        const auto debugger_context = debugger_interaction::capture(
            debugger_interaction::kind_t::instruction, runtime, 0, -1, 0,
            static_cast<std::uint64_t>(found->length));
        if (process->creation_time_100ns == 0 ||
            debugger_context.target_pid != process->pid ||
            debugger_context.process_creation_time_100ns !=
                process->creation_time_100ns ||
            !debugger_interaction::is_current(debugger_context))
            return fail("The disassembly workspace process identity or debugger stop changed before patch review.");
        const bool opened = mode == static_patch_mode_t::nop_fill
            ? debugger_view::stage_nop_review(debugger_context, found->length, error)
            : debugger_view::stage_patch_review(debugger_context, found->length,
                "Reviewed patch from Disassembly shortcut", error);
        if (opened)
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.debug.patches"));
        return opened;
    }
    return open_static_patch_review(context, *selected, found->length, mode, error);
}

bool open_exact_static_patch_review(const workspace_context_t& context,
                                    const address_t& address,
                                    const std::vector<std::uint8_t>& expected_before,
                                    const std::vector<std::uint8_t>& reviewed_after,
                                    const std::string& provenance,
                                    std::uint64_t expected_generation,
                                    std::uint64_t expected_analysis_revision,
                                    std::uint64_t expected_overlay_revision,
                                    std::string* error) {
    if (expected_before.empty() || reviewed_after.empty() ||
        expected_before.size() != reviewed_after.size() ||
        reviewed_after.size() > k_static_patch_maximum_bytes) {
        if (error) *error = "Exact static patch review requires matching before/after ranges from 1 byte through 64 KiB.";
        return false;
    }
    if (provenance.empty() || provenance.size() > 512U) {
        if (error) *error = "Exact static patch review requires bounded proposal provenance.";
        return false;
    }
    if (!context || context.workspace->closing() || context.workspace->closed() ||
        context.workspace->generation() != expected_generation ||
        context.workspace->analysis_revision() != expected_analysis_revision ||
        context.workspace->overlay_revision() != expected_overlay_revision) {
        if (error) *error = "The exact static patch publication fence changed before review opened.";
        return false;
    }
    const auto offset = provider_offset(context, address);
    if (!offset || *offset > context.workspace->provider().size() ||
        reviewed_after.size() > context.workspace->provider().size() - *offset) {
        if (error) *error = "The exact static patch range is not fully backed by the immutable workspace provider.";
        return false;
    }
    return initialize_static_patch_review(context, address, reviewed_after.size(),
        static_patch_mode_t::bytes, expected_before, reviewed_after, false, false,
        "AI reviewed proposal: " + provenance,
        "AI before/after bytes were identity-checked; confirm Apply Patch here to commit the reversible overlay transaction.",
        expected_generation, expected_analysis_revision, expected_overlay_revision,
        error);
}

bool queue_type_declaration_and_application(
    const workspace_context_t& context,
    const aida::analysis::address_t& address,
    std::string declaration,
    std::string canonical_type) {
    if (declaration.empty() || canonical_type.empty())
        return false;
    aida::analysis::overlay_operation_t declaration_operation;
    declaration_operation.kind = aida::analysis::overlay_operation_kind_t::type_declaration;
    declaration_operation.address.space = aida::analysis::address_space_id_t::relative_virtual;
    declaration_operation.address.value = 0;
    declaration_operation.address.architecture = context.workspace
        ? context.workspace->identity().architecture()
        : address.architecture;
    declaration_operation.address.mode = context.image
        ? context.image->architecture_mode() : address.mode;
    declaration_operation.text = std::move(declaration);
    aida::analysis::overlay_operation_t application_operation;
    application_operation.kind = aida::analysis::overlay_operation_kind_t::type_application;
    application_operation.address = address;
    application_operation.type = std::move(canonical_type);
    std::vector<aida::analysis::overlay_operation_t> operations;
    operations.reserve(2);
    operations.push_back(std::move(declaration_operation));
    operations.push_back(std::move(application_operation));
    return queue_overlay_transaction(context, std::move(operations));
}

mutation_state_t mutation_state(const workspace_context_t& context) {
    mutation_state_t result;
    const auto authority = authoritative_state(context);
    if (!context.workspace || !authority)
        return result;
    result.pending = authority->pending_mutations.load(std::memory_order_acquire);
    result.overlay_revision = context.workspace->overlay_revision();
    std::lock_guard<std::mutex> lock(authority->mutex);
    result.error = authority->mutation_error;
    result.derived_publication_pending =
        authority->derived_publication_retry_pending.load(
            std::memory_order_acquire);
    result.derived_publication_revision =
        authority->derived_publication_revision;
    result.derived_publication_error =
        authority->derived_publication_error;
    return result;
}

bool queue_overlay_undo(const workspace_context_t& context) {
    if (!context.workspace)
        return false;
    return queue_overlay_history(context, false, context.workspace->generation(),
        context.workspace->analysis_revision(), context.workspace->overlay_revision());
}

bool queue_overlay_redo(const workspace_context_t& context) {
    if (!context.workspace)
        return false;
    return queue_overlay_history(context, true, context.workspace->generation(),
        context.workspace->analysis_revision(), context.workspace->overlay_revision());
}

void render_static_patch_workflow() {
    const auto owner = static_patch_owner().lock();
    if (!owner)
        return;
    const auto context = capture_workspace(owner);
    if (!context || !context.view)
        return;
    auto& state = *context.view;
    if (state.static_patch_open && !ImGui::IsPopupOpen("Static Patch Review###workspace_overlay"))
        aida::ui::design::open_dialog("workspace_overlay", "Static Patch Review");
    if (!aida::ui::design::begin_dialog("workspace_overlay", "Static Patch Review",
            ImVec2(760.0f, 620.0f), ImVec2(420.0f, 360.0f)))
        return;

    const bool generation_current = context.workspace->generation() ==
        state.static_patch_generation;
    const bool analysis_current = context.workspace->analysis_revision() ==
        state.static_patch_analysis_revision;
    const bool overlay_current = context.workspace->overlay_revision() ==
        state.static_patch_overlay_revision;
    const bool pending = state.pending_mutations.load(std::memory_order_acquire) != 0;
    const bool identity_current = generation_current && analysis_current && overlay_current &&
        !context.workspace->closing() && !context.workspace->closed();
    const auto display = runtime_address(context, state.static_patch_address).value_or(
        state.static_patch_address.value);
    const auto dialog_metrics = aida::ui::design::metrics();
    const float footer_height = aida::ui::design::dialog_footer_reserve_height(
        "Commit Workspace Overlay", "Close");
    aida::ui::design::begin_dialog_body("static_patch_body", footer_height);
    ImGui::TextUnformatted("Review immutable-source bytes and commit a reversible workspace overlay");
    ImGui::Separator();
    ImGui::Text("Workspace: %s", context.workspace->identity().bin_name().c_str());
    ImGui::Text("Address:   0x%016llX", static_cast<unsigned long long>(display));
    ImGui::Text("Selection: %llu byte%s", static_cast<unsigned long long>(state.static_patch_extent),
        state.static_patch_extent == 1U ? "" : "s");
    ImGui::TextDisabled("Fence: generation %llu / analysis %llu / overlay %llu",
        static_cast<unsigned long long>(state.static_patch_generation),
        static_cast<unsigned long long>(state.static_patch_analysis_revision),
        static_cast<unsigned long long>(state.static_patch_overlay_revision));
    if (!identity_current)
        aida::ui::inline_notice("static_patch_stale", "Review is stale",
            "The workspace publication or overlay changed. Close and reopen the patch action so the original-byte diff cannot target stale state.",
            aida::ui::status_kind_t::warning);
    if (pending)
        aida::ui::inline_notice("static_patch_pending", "Overlay mutation pending",
            "Wait for the current workspace mutation to publish before committing another operation.",
            aida::ui::status_kind_t::info);
    ImGui::TextUnformatted(state.static_patch_mode == static_patch_mode_t::nop_fill
        ? "Proposed NOP bytes" : "Replacement bytes");
    if (state.static_patch_focus_input) {
        ImGui::SetKeyboardFocusHere();
        state.static_patch_focus_input = false;
    }
    const bool readonly = state.static_patch_mode == static_patch_mode_t::nop_fill;
    if (readonly) ImGui::BeginDisabled();
    const bool input_changed = ImGui::InputTextMultiline("##static_patch_bytes", state.static_patch_input.data(),
        state.static_patch_input.size(), ImVec2(-1.0f,
            aida::ui::scale_px(82.0f, dialog_metrics.scale)),
        ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_AllowTabInput);
    if (readonly) ImGui::EndDisabled();
    ImGui::TextUnformatted("Description");
    ImGui::InputText("##static_patch_description", state.static_patch_description.data(),
        state.static_patch_description.size());

    if (input_changed && state.static_patch_mode == static_patch_mode_t::bytes) {
        auto decoded = decode_patch_bytes(state.static_patch_input.data(),
            state.static_patch_parse_error);
        state.static_patch_proposed = decoded ? std::move(*decoded)
                                              : std::vector<std::uint8_t>{};
    }
    if (!state.static_patch_parse_error.empty())
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::resolved().error),
            "%s", state.static_patch_parse_error.c_str());

    if (!state.static_patch_status.empty())
        aida::ui::inline_notice("static_patch_status", "Existing overlay detail",
            state.static_patch_status.c_str(), aida::ui::status_kind_t::info);
    if (state.static_patch_existing) {
        aida::ui::status_badge("Existing overlay at address", aida::ui::status_kind_t::warning);
        ImGui::SameLine();
        ImGui::TextDisabled("%llu byte%s",
            static_cast<unsigned long long>(state.static_patch_existing_size),
            state.static_patch_existing_size == 1U ? "" : "s");
    }

    const auto& proposed = state.static_patch_proposed;
    const std::size_t proposed_size = proposed.size();
    const std::size_t diff_rows = (std::max)(state.static_patch_original.size(), proposed_size);
    const float diff_height = (std::min)(aida::ui::scale_px(250.0f, dialog_metrics.scale),
        (std::max)(aida::ui::scale_px(120.0f, dialog_metrics.scale),
            ImGui::GetContentRegionAvail().y * 0.55f));
    if (ImGui::BeginTable("##static_patch_diff", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Resizable, ImVec2(-1.0f, diff_height))) {
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Proposed", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        const int bounded_rows = diff_rows > static_cast<std::size_t>((std::numeric_limits<int>::max)())
            ? (std::numeric_limits<int>::max)() : static_cast<int>(diff_rows);
        clipper.Begin(bounded_rows, ImGui::GetTextLineHeightWithSpacing());
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto index = static_cast<std::size_t>(row);
                const bool has_original = index < state.static_patch_original.size();
                const bool has_proposed = index < proposed.size();
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("+0x%04X", row);
                ImGui::TableSetColumnIndex(1);
                if (has_original) ImGui::Text("%02X", state.static_patch_original[index]);
                else ImGui::TextDisabled("--");
                ImGui::TableSetColumnIndex(2);
                if (has_proposed) ImGui::Text("%02X", proposed[index]);
                else ImGui::TextDisabled("--");
                ImGui::TableSetColumnIndex(3);
                if (!has_original) ImGui::TextUnformatted("extends overlay range");
                else if (!has_proposed) ImGui::TextUnformatted("outside replacement range");
                else if (state.static_patch_original[index] == proposed[index])
                    ImGui::TextDisabled("unchanged");
                else ImGui::TextUnformatted("replace");
            }
        }
        ImGui::EndTable();
    }

    if (!state.static_patch_error.empty())
        aida::ui::inline_notice("static_patch_error", "Patch workflow error",
            state.static_patch_error.c_str(), aida::ui::status_kind_t::error);
    const bool can_commit = identity_current && !pending &&
        state.static_patch_parse_error.empty() && !proposed.empty();
    if (!identity_current || pending) ImGui::BeginDisabled();
    if (aida::ui::button("Undo Last Overlay", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm, ImVec2(150.0f, 30.0f))) {
        if (queue_overlay_history(context, false, state.static_patch_generation,
                state.static_patch_analysis_revision, state.static_patch_overlay_revision)) {
            state.static_patch_open = false;
            ImGui::CloseCurrentPopup();
        } else {
            state.static_patch_error = "No generation-fenced overlay transaction was available to undo.";
        }
    }
    if (!identity_current || pending) ImGui::EndDisabled();
    ImGui::SameLine();
    if (!identity_current || pending) ImGui::BeginDisabled();
    if (aida::ui::button("Redo Last Overlay", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm, ImVec2(150.0f, 30.0f))) {
        if (queue_overlay_history(context, true, state.static_patch_generation,
                state.static_patch_analysis_revision, state.static_patch_overlay_revision)) {
            state.static_patch_open = false;
            ImGui::CloseCurrentPopup();
        } else {
            state.static_patch_error = "No generation-fenced overlay transaction was available to redo.";
        }
    }
    if (!identity_current || pending) ImGui::EndDisabled();
    ImGui::NewLine();
    if (!state.static_patch_existing || !identity_current || pending) ImGui::BeginDisabled();
    if (aida::ui::button("Revert This Overlay", aida::ui::button_kind_t::destructive,
            aida::ui::size_t_::sm, ImVec2(155.0f, 30.0f)) && state.static_patch_existing) {
        std::optional<overlay_operation_t> exact_patch;
        if (const auto overlay = context.workspace->overlay()) {
            const auto patches = overlay->patch_operations();
            const auto found = std::find_if(patches.begin(), patches.end(),
                [&state](const overlay_operation_t& operation) {
                    return operation.address == state.static_patch_address && !operation.remove;
                });
            if (found != patches.end())
                exact_patch = *found;
        }
        if (exact_patch) {
            exact_patch->remove = true;
            std::vector<overlay_operation_t> operations;
            operations.push_back(std::move(*exact_patch));
            if (queue_overlay_transaction(context, std::move(operations),
                    state.static_patch_generation, state.static_patch_analysis_revision,
                    state.static_patch_overlay_revision)) {
                state.static_patch_open = false;
                ImGui::CloseCurrentPopup();
            } else {
                state.static_patch_error = "The exact overlay changed before it could be reverted.";
            }
        } else {
            state.static_patch_error = "The exact overlay no longer exists; reopen the review against current state.";
        }
    }
    if (!state.static_patch_existing || !identity_current || pending) ImGui::EndDisabled();
    aida::ui::design::end_dialog_body();

    const auto footer = aida::ui::design::dialog_footer("static_patch_footer",
        "Commit Workspace Overlay", can_commit, false, "Close");
    if (footer.confirmed) {
        overlay_operation_t operation;
        operation.kind = overlay_operation_kind_t::byte_patch;
        operation.address = state.static_patch_address;
        operation.bytes = proposed;
        operation.text = state.static_patch_description.data();
        std::vector<overlay_operation_t> operations;
        operations.push_back(std::move(operation));
        if (queue_overlay_transaction(context, std::move(operations),
                state.static_patch_generation, state.static_patch_analysis_revision,
                state.static_patch_overlay_revision)) {
            state.static_patch_open = false;
            ImGui::CloseCurrentPopup();
        } else {
            state.static_patch_error = "The generation-fenced overlay queue rejected the patch; reopen the review against current state.";
        }
    }
    if (footer.cancelled) {
        state.static_patch_open = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

namespace {

constexpr std::size_t kWorkspaceNavigationHistoryLimit = 4096;

void trim_workspace_navigation(std::vector<aida::analysis::address_t>& entries) {
    if (entries.size() > kWorkspaceNavigationHistoryLimit)
        entries.erase(entries.begin(),
            entries.begin() + static_cast<std::ptrdiff_t>(
                entries.size() - kWorkspaceNavigationHistoryLimit));
}

bool publish_workbench_selection(const workspace_context_t& context,
                                 const aida::analysis::address_t& destination,
                                 bool record_history) {
    const auto runtime = runtime_address(context, destination).value_or(destination.value);
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::address;
    selection.has_address = true;
    selection.address = runtime;
    selection.extent = 1;
    selection.entity_key = "analysis.address." + std::to_string(destination.value);
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = runtime;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    if (record_history) {
        return aida::workbench::workbench_shell_runtime_t::instance()
            .publish_selection(context.workspace, selection, cursor,
                aida::workbench::navigation_origin_t::user, workbench).ok();
    }
    return true;
}

void synchronize_workspace_selection(const workspace_context_t& context,
                                     const aida::analysis::address_t& destination,
                                     bool reveal) {
    if (!context.workspace || !context.view)
        return;
    const auto updated = context.workspace->update_view_state(
        [&](aida::analysis::workspace_view_state_t& state) {
            state.selection = destination;
        });
    if (!updated)
        return;
    if (context.model) {
        context.model->presentation_selection_revision.store(
            context.workspace->view_state().revision, std::memory_order_release);
    }
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->selection = destination;
    context.view->scroll_to_selection = reveal;
}

void synchronize_workspace_navigation(const workspace_context_t& context,
                                      const aida::analysis::address_t& destination,
                                      bool reveal,
                                      bool record_navigation,
                                      bool clear_forward) {
    if (!context.workspace || !context.view)
        return;
    std::optional<aida::analysis::address_t> current;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        current = context.view->selection;
    }
    const auto updated = context.workspace->update_view_state(
        [&](aida::analysis::workspace_view_state_t& state) {
            const auto previous = state.selection ? state.selection : current;
            if (record_navigation && previous && *previous != destination) {
                state.navigation_back.push_back(*previous);
                trim_workspace_navigation(state.navigation_back);
            }
            if (clear_forward)
                state.navigation_forward.clear();
            state.selection = destination;
        });
    if (!updated)
        return;
    if (context.model) {
        context.model->presentation_selection_revision.store(
            context.workspace->view_state().revision, std::memory_order_release);
    }
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->selection = destination;
    context.view->scroll_to_selection = reveal;
}

std::optional<aida::analysis::address_t> navigate_workspace_history(
    const workspace_context_t& context,
    bool forward) {
    if (!context.workspace || !context.view)
        return {};
    std::optional<aida::analysis::address_t> destination;
    const auto updated = context.workspace->update_view_state(
        [&](aida::analysis::workspace_view_state_t& state) {
            auto& source = forward ? state.navigation_forward : state.navigation_back;
            auto& target = forward ? state.navigation_back : state.navigation_forward;
            if (source.empty())
                return;
            destination = source.back();
            source.pop_back();
            if (state.selection && *state.selection != *destination) {
                target.push_back(*state.selection);
                trim_workspace_navigation(target);
            }
            state.selection = *destination;
        });
    if (!updated || !destination)
        return {};
    if (context.model) {
        context.model->presentation_selection_revision.store(
            context.workspace->view_state().revision, std::memory_order_release);
    }
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->selection = *destination;
    context.view->scroll_to_selection = true;
    return destination;
}

std::optional<aida::analysis::address_t> history_selection(
    const workspace_context_t& context,
    const aida::workbench::workbench_shell_workspace_context_t& workbench) {
    const auto active = std::find_if(
        workbench.persistence.documents.begin(), workbench.persistence.documents.end(),
        [&workbench](const aida::workbench::document_persistence_dto_t& document) {
            return document.id == workbench.persistence.active_document;
        });
    if (active == workbench.persistence.documents.end() ||
        !active->local_state.selection.has_address)
        return {};
    return typed_address(context, active->local_state.selection.address);
}

}

void select_address(const aida::analysis::address_t& destination,
                    const workspace_context_t& context,
                    bool record_history) {
    if (!context.workspace || !context.view || !context.model)
        return;
    std::optional<aida::analysis::address_t> current;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        current = context.view->selection;
    }
    if (current && *current == destination) {
        synchronize_workspace_selection(context, destination, false);
        return;
    }
    if (record_history && !publish_workbench_selection(context, destination, true))
        return;
    synchronize_workspace_selection(context, destination, false);
}

void select_address(std::uint64_t value, const workspace_context_t& context,
                    bool record_history) {
    const auto destination = typed_address(context, value);
    if (destination)
        select_address(*destination, context, record_history);
}

void goto_address(const aida::analysis::address_t& destination,
                  const workspace_context_t& context) {
    if (!context.workspace || !context.view || !context.model)
        return;
    std::optional<aida::analysis::address_t> current;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        current = context.view->selection;
    }
    if (current && *current == destination) {
        synchronize_workspace_selection(context, destination, true);
        return;
    }
    if (!publish_workbench_selection(context, destination, true))
        return;
    synchronize_workspace_navigation(context, destination, true, true, true);
}

void goto_address(std::uint64_t value, const workspace_context_t& context) {
    const auto destination = typed_address(context, value);
    if (!destination)
        return;
    goto_address(*destination, context);
}

bool request_goto(const workspace_context_t& context) {
    if (!context.view)
        return false;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->goto_visible = true;
    context.view->goto_buf[0] = '\0';
    return true;
}

void navigate_back(const workspace_context_t& context) {
    if (!context.workspace)
        return;
    const auto local_destination = navigate_workspace_history(context, false);
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto result = aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_history(context.workspace, false, workbench);
    if (!result || local_destination)
        return;
    if (const auto destination = history_selection(context, workbench))
        synchronize_workspace_selection(context, *destination, true);
}

void navigate_forward(const workspace_context_t& context) {
    if (!context.workspace)
        return;
    const auto local_destination = navigate_workspace_history(context, true);
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto result = aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_history(context.workspace, true, workbench);
    if (!result || local_destination)
        return;
    if (const auto destination = history_selection(context, workbench))
        synchronize_workspace_selection(context, *destination, true);
}

void open_xrefs(std::uint64_t value, const workspace_context_t& context) {
    const auto address = typed_address(context, value);
    if (!address || !context.publication || !context.publication->snapshot ||
        context.view->xref_scanning.exchange(true, std::memory_order_acq_rel))
        return;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_open = true;
        context.view->xref_popup_address = *address;
        context.view->xref_results.clear();
        context.view->xref_popup_selected = -1;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::vector<xref_popup_entry_t> results;
    results.reserve(256);
    constexpr std::size_t maximum_results = 10000;
    for (const auto& xref : context.publication->snapshot->xrefs) {
        if (context.workspace->cancellation_token().stop_requested())
            break;
        if (xref.target != *address)
            continue;
        xref_popup_entry_t entry;
        entry.addr = runtime_address(context, xref.source).value_or(xref.source.value);
        entry.type = static_cast<int>(xref.kind);
        entry.module_name = context.workspace->identity().bin_name();
        entry.function_name = resolve_name(context, xref.source);
        results.push_back(std::move(entry));
        if (results.size() >= maximum_results)
            break;
    }
    const auto result_count = results.size();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_results = std::move(results);
    }
    context.view->xref_scanning.store(false, std::memory_order_release);
    aida::preview::disasm::record("workspace_xref_query", value,
        std::to_string(result_count));
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "workspace_xref_query";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, address = *address](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::vector<xref_popup_entry_t> results;
        results.reserve(256);
        constexpr std::size_t maximum_results = 10000;
        for (const auto& xref : context.publication->snapshot->xrefs) {
            if (cancel.requested.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested())
                break;
            if (xref.target != address)
                continue;
            xref_popup_entry_t entry;
            entry.addr = runtime_address(context, xref.source).value_or(xref.source.value);
            entry.type = static_cast<int>(xref.kind);
            entry.module_name = context.workspace->identity().bin_name();
            entry.function_name = resolve_name(context, xref.source);
            results.push_back(std::move(entry));
            if (results.size() >= maximum_results)
                break;
        }
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->xref_results = std::move(results);
        }
        context.view->xref_scanning.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        context.view->xref_scanning.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->format_error = submitted.reject_reason;
    }
#endif
}

void bump_format_generation(const workspace_context_t& context) {
    if (!context.model || !context.view)
        return;
    context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->formatted.clear();
    context.view->pending_format_pages.clear();
}

void bump_format_generation() {
    bump_format_generation(capture_selected_workspace());
}

std::uint32_t format_generation(const workspace_context_t& context) {
    return context.model ? context.model->format_generation.load(std::memory_order_acquire) : 0;
}

std::uint64_t enclosing_function_start(std::uint64_t value,
                                       const workspace_context_t& context) {
    const auto address = typed_address(context, value);
    if (!address || !context.publication || !context.publication->snapshot)
        return 0;
    const auto& functions = context.publication->snapshot->functions;
    auto found = std::upper_bound(functions.begin(), functions.end(), *address,
        [](const aida::analysis::address_t& target,
           const aida::analysis::function_record_t& function) {
            return target < function.start;
        });
    if (found == functions.begin())
        return 0;
    --found;
    if (found->start.space != address->space || address->value < found->start.value ||
        address->value >= found->end.value)
        return 0;
    return runtime_address(context, found->start).value_or(found->start.value);
}

namespace {

std::uint64_t context_generation(const workspace_context_t& context) {
    if (!context.workspace)
        return 0;
    const auto generation = context.workspace->generation();
    const auto revision = context.workspace->analysis_revision();
    return generation ^ (revision + 0x9E3779B97F4A7C15ull +
        (generation << 6u) + (generation >> 2u));
}

std::uint64_t evidence_hash(const std::string& value) {
    std::uint64_t hash = 1469598103934665603ull;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        hash ^= byte;
        hash *= 1099511628211ull;
    }
    return hash == 0 ? 1 : hash;
}

auto make_instruction_menu(const workspace_context_t& context,
                           const aida::analysis::instruction_record_t& instruction,
                           const std::optional<formatted_instruction_t>& formatted)
    -> aida::ui::analysis_context_menu::context_t {
    using namespace aida::ui::analysis_context_menu;
    using aida::ui::action_check_state_t;
    using aida::ui::action_handler_result_t;
    using aida::ui::capability_state_t;
    context_t menu;
    menu.kind = menu_kind_t::instruction;
    menu.entity_id = "instruction:" + std::to_string(instruction.id) + ":" +
        std::to_string(instruction.address.value);
    menu.generation = context_generation(context);
    menu.live_generation = [context]() { return context_generation(context); };
    menu.validate_identity = [view = context.view, expected = instruction.address]() {
        std::lock_guard<std::mutex> lock(view->mutex);
        return view->selection && *view->selection == expected
            ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(
                "The selected disassembly instruction changed");
    };
    const auto runtime = runtime_address(context, instruction.address).value_or(
        instruction.address.value);
    addr_format_t format;
    bool show_bytes;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        format = context.view->addr_format;
        show_bytes = context.view->show_bytes;
    }
    const auto address = address_label(context, instruction.address, format);
    const auto text = formatted ? formatted->text : std::string();
    const auto bytes = formatted ? formatted->bytes : std::string();
    const auto name = resolve_name(context, instruction.address);
    auto copy = [&menu](const char* id, std::string value, const char* reason) {
        action_slot_t slot;
        if (value.empty())
            slot.capability = capability_state_t::unavailable(reason);
        slot.invoke = [value = std::move(value)]() {
            ImGui::SetClipboardText(value.c_str());
            return action_handler_result_t::completed();
        };
        menu.actions.emplace(id, std::move(slot));
    };
    auto unavailable = [&menu](const char* id, std::string reason) {
        action_slot_t slot;
        slot.capability = capability_state_t::unavailable(reason);
        slot.invoke = [reason = std::move(reason)]() {
            return action_handler_result_t::failed(reason);
        };
        menu.actions.insert_or_assign(id, std::move(slot));
    };
    unavailable("analysis.navigate.disassembly_side",
        "Independent side documents require per-instance disassembly presentation state");
    unavailable("analysis.navigate.follow",
        "The selected instruction has no direct resolved target");
    unavailable("analysis.navigate.callers",
        "The selected instruction is not inside a discovered function");
    unavailable("analysis.navigate.callees",
        "The current cross-reference provider does not expose a filtered outgoing-call view");
    unavailable("analysis.navigate.pseudocode",
        "The selected instruction is not inside a discovered function");
    unavailable("analysis.function.decompile",
        "The selected instruction is not inside a discovered function");
    unavailable("analysis.modify.retype",
        "The selected address cannot be staged in the canonical Types apply workflow");
    unavailable("analysis.modify.patch",
        "Reviewed runtime patching requires a process-backed workspace");
    unavailable("analysis.modify.assemble",
        "No assembler provider is registered; use reviewed Patch Bytes with explicitly assembled bytes");
    unavailable("analysis.modify.nop",
        "Reviewed NOP staging requires a process-backed instruction with a known byte length");
    unavailable("analysis.modify.bookmark",
        "The selected address is already bookmarked");
    unavailable("analysis.modify.remove_bookmark",
        "The selected address is not bookmarked");
    unavailable("analysis.debug.breakpoint",
        "Breakpoint definitions require a process-backed debugger workspace");
    unavailable("analysis.debug.hardware_breakpoint",
        "Mode-specific breakpoint preselection is not exposed; stage the address, then choose Add HW Exec in Breakpoints");
    copy("analysis.copy.line", address + "  " + text,
        "The instruction address is unavailable");
    copy("analysis.copy.text", text, "The instruction is not formatted");
    copy("analysis.copy.instruction", text, "The instruction is not formatted");
    copy("analysis.copy.address", address, "The address is unavailable");
    copy("analysis.copy.bytes", bytes, "The instruction bytes are not formatted");
    copy("analysis.copy.name", name, "The selected address has no symbol name");
    const std::string address_va = address_label(context, instruction.address, addr_format_t::va);
    const std::string address_rva = address_label(context, instruction.address, addr_format_t::rva);
    const auto file_offset = provider_offset(context, instruction.address);
    copy("analysis.copy.address_va", address_va, "The selected virtual address is unavailable");
    copy("analysis.copy.address_rva", context.image ? address_rva : std::string(),
        "The selected workspace has no image mapping for an RVA");
    copy("analysis.copy.address_file", file_offset
        ? address_label(context, instruction.address, addr_format_t::file_offset)
        : std::string(), "The selected address has no mapped file offset");
    std::string module_address;
    const auto image_base = context.workspace->identity().image_base();
    if (context.image && runtime >= image_base &&
        runtime - image_base < context.image->image_size()) {
        char offset[48]{};
        std::snprintf(offset, sizeof(offset), "%s+0x%llX",
            context.workspace->identity().bin_name().c_str(),
            static_cast<unsigned long long>(runtime - image_base));
        module_address = offset;
    }
    copy("analysis.copy.address_module", module_address,
        "The selected address is outside the workspace module mapping");
    copy("analysis.export.line", formatted ? address + "  " + bytes + "  " + text : std::string(),
        "The instruction is not formatted");
    menu.actions["analysis.navigate.back"].invoke = [context]() {
        navigate_back(context);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.forward"].invoke = [context]() {
        navigate_forward(context);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.disassembly"].invoke = [context, runtime]() {
        goto_address(runtime, context);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.disassembly"));
        return action_handler_result_t::completed();
    };
    if (file_offset) {
        menu.actions["analysis.navigate.hex"].invoke = [context, address = instruction.address]() {
            std::string error;
            if (!hex_view::focus_address(context, address, &error))
                return action_handler_result_t::failed(error);
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.hex"));
            return action_handler_result_t::completed();
        };
    } else {
        unavailable("analysis.navigate.hex",
            "The selected address has no file or provider mapping for the Hex document");
    }
    menu.actions["analysis.navigate.functions"].invoke = [context, runtime]() {
        select_address(runtime, context, false);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.analysis.functions"));
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.structures"].invoke = [context, runtime]() {
        select_address(runtime, context, false);
        types_hub_view::set_sub_tab(context, types_hub_view::sub_tab_t::structs);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.types.structures"));
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.types"].invoke = [context, runtime]() {
        select_address(runtime, context, false);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.types.inferred"));
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.xrefs"].invoke = [context, runtime]() {
        open_xrefs(runtime, context);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.xrefs_from"].invoke = [context, runtime]() {
        select_address(runtime, context, false);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.analysis.references"));
        return action_handler_result_t::completed();
    };
    if (instruction.target_fact_count != 0 &&
        instruction.target_fact_begin < context.publication->snapshot->target_facts.size()) {
        const auto target = context.publication->snapshot->target_facts[instruction.target_fact_begin];
        if (target.direct) {
            menu.actions["analysis.navigate.follow"].invoke = [context, target]() {
                goto_address(runtime_address(context, target.target).value_or(target.target.value), context);
                return action_handler_result_t::completed();
            };
            menu.actions["analysis.navigate.follow"].capability = capability_state_t::available();
        }
    }
    menu.actions["analysis.modify.rename"].invoke = [context, value = instruction.address]() {
        rename_dialog::open(context, value);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.modify.comment"].invoke = [context, value = instruction.address]() {
        comment_dialog::open(context, value);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.modify.retype"].invoke = [context, value = instruction.address]() {
        std::string error;
        if (!types_hub_view::stage_type_application(context, value, &error))
            return action_handler_result_t::failed(error);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.types.structures"));
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.modify.retype"].capability = capability_state_t::available();
    if (disasm_view::bookmarked(context, instruction.address)) {
        menu.actions["analysis.modify.remove_bookmark"].invoke = [context, value = instruction.address]() {
            return queue_bookmark(context, value, {})
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The bookmark update was rejected");
        };
        menu.actions["analysis.modify.remove_bookmark"].capability = capability_state_t::available();
    } else {
        menu.actions["analysis.modify.bookmark"].invoke =
            [context, value = instruction.address, label = name.empty() ? address : name]() {
                return queue_bookmark(context, value, label)
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed("The bookmark update was rejected");
            };
        menu.actions["analysis.modify.bookmark"].capability = capability_state_t::available();
    }
    const auto function = enclosing_function_start(runtime, context);
    if (function != 0) {
        menu.actions["analysis.navigate.graph"].invoke = [context, runtime]() {
            goto_address(runtime, context);
            const auto opened = aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.graph"));
            return opened.ok()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(opened.detail.empty()
                    ? "The Graph document could not be opened or focused"
                    : opened.detail);
        };
        menu.actions["analysis.navigate.graph"].capability = capability_state_t::available();
        auto decompile = [context, function]() {
            pseudocode_view::request_decompile(context, function, false);
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.pseudocode"));
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.pseudocode"].invoke = decompile;
        menu.actions["analysis.navigate.pseudocode"].capability = capability_state_t::available();
        menu.actions["analysis.function.decompile"].invoke = std::move(decompile);
        menu.actions["analysis.function.decompile"].capability = capability_state_t::available();
        menu.actions["analysis.navigate.callers"].invoke = [context, function]() {
            open_xrefs(function, context);
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.callers"].capability = capability_state_t::available();
    } else {
        unavailable("analysis.navigate.graph",
            "No recovered function contains the selected instruction");
    }
    const auto process = context.workspace->identity().process();
    if (instruction.length != 0 && file_offset) {
        menu.actions["analysis.modify.patch"].invoke =
            [context, value = instruction.address,
             extent = static_cast<std::uint64_t>(instruction.length)]() {
                std::string error;
                if (!open_static_patch_review(context, value, extent,
                        static_patch_mode_t::bytes, &error))
                    return action_handler_result_t::failed(error);
                return action_handler_result_t::completed();
            };
        menu.actions["analysis.modify.patch"].capability = capability_state_t::available();
        menu.actions["analysis.modify.nop"].invoke =
            [context, value = instruction.address,
             extent = static_cast<std::uint64_t>(instruction.length)]() {
                std::string error;
                if (!open_static_patch_review(context, value, extent,
                        static_patch_mode_t::nop_fill, &error))
                    return action_handler_result_t::failed(error);
                return action_handler_result_t::completed();
            };
        menu.actions["analysis.modify.nop"].capability = capability_state_t::available();
    } else {
        unavailable("analysis.modify.patch",
            "The selected instruction has no fully provider-backed byte range");
        unavailable("analysis.modify.nop",
            "The selected instruction has no fully provider-backed byte range");
    }
    const auto debugger_context = debugger_interaction::capture(
        debugger_interaction::kind_t::instruction, runtime, 0, -1, 0,
        static_cast<std::uint64_t>(instruction.length));
    const bool debugger_matches_workspace = process &&
        process->creation_time_100ns != 0 &&
        debugger_context.target_pid == process->pid &&
        debugger_context.process_creation_time_100ns == process->creation_time_100ns &&
        debugger_interaction::is_current(debugger_context);
    if (debugger_matches_workspace) {
        menu.actions["analysis.modify.patch"].invoke =
            [debugger_context,
             extent = static_cast<std::uint64_t>(instruction.length)]() {
                std::string error;
                if (!debugger_view::stage_patch_review(debugger_context, extent,
                        "Reviewed patch from Disassembly", &error))
                    return action_handler_result_t::failed(error);
                aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("view.debug.patches"));
                return action_handler_result_t::completed();
            };
        menu.actions["analysis.modify.patch"].capability = capability_state_t::available();
        if (instruction.length != 0) {
            menu.actions["analysis.modify.nop"].invoke =
                [debugger_context,
                 extent = static_cast<std::uint64_t>(instruction.length)]() {
                    std::string error;
                    if (!debugger_view::stage_nop_review(debugger_context, extent, &error))
                        return action_handler_result_t::failed(error);
                    aida::ui::application_views::open_or_focus(
                        aida::ui::stable_view_id_t("view.debug.patches"));
                    return action_handler_result_t::completed();
                };
            menu.actions["analysis.modify.nop"].capability = capability_state_t::available();
        }
        const auto breakpoint_capability = debugger_view::address_mutation_capability(
            debugger_context, true);
        if (breakpoint_capability.enabled) {
            menu.actions["analysis.debug.breakpoint"].invoke =
                [debugger_context]() {
                    std::string error;
                    if (!debugger_view::queue_toggle_breakpoint(debugger_context, &error))
                        return action_handler_result_t::failed(error);
                    return action_handler_result_t::completed();
                };
            menu.actions["analysis.debug.breakpoint"].capability =
                capability_state_t::available();
        } else {
            unavailable("analysis.debug.breakpoint",
                breakpoint_capability.disabled_reason
                    ? breakpoint_capability.disabled_reason
                    : "Breakpoint toggle is unavailable");
        }
    } else if (process) {
        const std::string reason = "Attach the debugger to PID " +
            std::to_string(process->pid) + " before staging a runtime breakpoint; Patch and NOP remain reversible workspace overlays";
        unavailable("analysis.debug.breakpoint", reason);
    }
    menu.actions["analysis.function.source"].invoke = [context, runtime]() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::disasm::record("reconstruct_source", runtime);
#else
        source_reconstruct_view::open(context);
#endif
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.function.aob"].invoke = [context, runtime]() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::disasm::record("generate_aob_signature", runtime, "16:auto_wildcard");
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.memory.aob"));
#else
        const auto generator = aob_generator::state_for(context);
        int count = 16;
        bool wildcard = true;
        if (generator) {
            std::lock_guard<std::mutex> lock(generator->mutex);
            std::snprintf(generator->address_input, sizeof(generator->address_input), "%llX",
                static_cast<unsigned long long>(runtime));
            count = generator->instruction_count;
            wildcard = generator->auto_wildcard;
        }
        aob_generator::generate_from_address(context, runtime, count, wildcard);
        scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.memory.aob"));
#endif
        return action_handler_result_t::completed();
    };
    if (context.view->export_pending.load(std::memory_order_acquire)) {
        unavailable("analysis.export.listing",
            "A disassembly listing export is already running");
    } else {
        menu.actions["analysis.export.listing"].invoke = [context]() {
            std::string error;
            return request_listing_export(context, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        };
        menu.actions["analysis.export.listing"].capability =
            capability_state_t::available();
    }
    const auto evidence_action = [context, instruction, address, bytes, text, name](bool agent) {
        std::string excerpt = address;
        if (!bytes.empty()) excerpt.append("  ").append(bytes);
        if (!text.empty()) excerpt.append("  ").append(text);
        if (!name.empty()) excerpt.append("  <").append(name).append(">");
        aida::automation_ui::evidence_envelope_t envelope;
        envelope.workspace_id = context.workspace->identity().binary_id().to_hex();
        envelope.source_view_id = "document.disassembly";
        envelope.source_kind = "instruction";
        envelope.entity_id = "instruction:" + std::to_string(instruction.id);
        envelope.display_label = name.empty() ? address : name;
        envelope.return_target = "address:" + address;
        envelope.excerpt = excerpt;
        envelope.address = runtime_address(context, instruction.address).value_or(
            instruction.address.value);
        envelope.revision = context.publication->analysis_revision;
        envelope.generation = context.publication->generation;
        envelope.snapshot_hash = context_generation(context);
        envelope.content_hash = evidence_hash(excerpt);
        const std::string evidence_id =
            aida::automation_ui::register_evidence(std::move(envelope));
        if (evidence_id.empty())
            return action_handler_result_t::failed(
                "The bounded evidence registry rejected this instruction snapshot");
        std::string error;
        const bool queued = agent
            ? aida::automation_ui::queue_evidence_for_agent(evidence_id, error)
            : aida::automation_ui::queue_evidence_for_chat(evidence_id, error);
        return queued ? action_handler_result_t::completed()
                      : action_handler_result_t::failed(error);
    };
    menu.actions["analysis.evidence.chat"].invoke = [evidence_action]() {
        return evidence_action(false);
    };
    menu.actions["analysis.evidence.agent"].invoke = [evidence_action]() {
        return evidence_action(true);
    };
    auto display = [&menu, context, format](const char* id, addr_format_t target) {
        action_slot_t slot;
        slot.check_state = format == target ? action_check_state_t::checked : action_check_state_t::unchecked;
        slot.invoke = [context, target]() {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->addr_format = target;
            return action_handler_result_t::completed();
        };
        menu.actions.emplace(id, std::move(slot));
    };
    display("analysis.view.va", addr_format_t::va);
    display("analysis.view.rva", addr_format_t::rva);
    display("analysis.view.file_offset", addr_format_t::file_offset);
    menu.actions["analysis.view.bytes"] = {capability_state_t::available(), [context]() {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->show_bytes = !context.view->show_bytes;
        return action_handler_result_t::completed();
    }, show_bytes ? action_check_state_t::checked : action_check_state_t::unchecked};
    menu.actions["analysis.view.full_line"] = {capability_state_t::available(), []() {
        editor_config::disasm_full_line_select = !editor_config::disasm_full_line_select;
        return action_handler_result_t::completed();
    }, editor_config::disasm_full_line_select ? action_check_state_t::checked : action_check_state_t::unchecked};
    return menu;
}

void open_instruction_menu(const workspace_context_t& context,
                           const aida::analysis::instruction_record_t& instruction,
                           const std::optional<formatted_instruction_t>& formatted,
                           aida::ui::context_menu_open_origin_t origin) {
    aida::ui::analysis_context_menu::open(
        make_instruction_menu(context, instruction, formatted), origin);
}

}

bool request_rebase(const workspace_context_t& context, std::string* error) {
    if (!context.workspace || !context.image || !context.view) {
        if (error) *error = "Open a static file-backed analysis workspace before rebasing";
        return false;
    }
    if (context.workspace->target_kind() != aida::analysis::target_kind_t::static_file) {
        if (error) *error = "Rebase is available only for static file-backed workspaces";
        return false;
    }
    const auto base = display_image_base(context);
    std::lock_guard<std::mutex> lock(context.view->mutex);
    std::snprintf(context.view->rebase_buf, sizeof(context.view->rebase_buf),
        "0x%llX", static_cast<unsigned long long>(base));
    context.view->rebase_error.clear();
    context.view->rebase_popup_open = true;
    if (error) error->clear();
    return true;
}

bool request_listing_export(const workspace_context_t& context, std::string* error) {
    if (!context || !context.image || !context.publication ||
        !context.publication->snapshot) {
        if (error) *error = "A published file-backed analysis listing is required for export";
        return false;
    }
    if (context.view->export_pending.load(std::memory_order_acquire)) {
        if (error) *error = "A disassembly listing export is already running";
        return false;
    }
    queue_listing_export(context);
    if (context.view->export_pending.load(std::memory_order_acquire)) {
        if (error) error->clear();
        return true;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (error) error->clear();
    return true;
#else
    std::lock_guard<std::mutex> lock(context.view->mutex);
    if (error) *error = context.view->export_error.empty()
        ? "The disassembly listing export request was rejected"
        : context.view->export_error;
    return false;
#endif
}

void render(float, float, float width, float height,
            float alpha, float, float, float,
            const workspace_context_t& context, float) {
    if (!context) {
        ImGui::BeginChild("##workspace_disassembly_empty", ImVec2(width, height), false);
        aida::ui::compact_empty_state("disassembly_workspace_empty", "No workspace selected",
            "Open or attach to a target to inspect its disassembly.", nullptr,
            ImVec2(0.0f, (std::max)(152.0f, height - aida::ui::metrics::spacing::lg)));
        ImGui::EndChild();
        return;
    }
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_disassembly", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));

    const bool can_rebase =
        context.workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
        context.image;
    file_metadata_banner::refresh(context);

    bool show_bytes = false;
    int address_format = 0;
    int active_section = -1;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        show_bytes = context.view->show_bytes;
        address_format = static_cast<int>(context.view->addr_format);
        active_section = context.view->active_section;
    }
    aida::ui::begin_toolbar("##disassembly_toolbar",
        aida::ui::metrics::control::toolbar_h +
        aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
    aida::ui::begin_toolbar_group("history");
    const auto render_navigation_action = [](const char* action_id,
                                              const char* stable_id,
                                              const char* fallback_label,
                                              const char* fallback_tooltip) {
        const auto presentation = aida::ui::application_ui::present_action(action_id);
        std::string tooltip = presentation.description.empty()
            ? std::string(fallback_tooltip) : presentation.description;
        if (!presentation.shortcut.empty())
            tooltip.append(" (").append(presentation.shortcut).append(")");
        if (!presentation.enabled && !presentation.disabled_reason.empty())
            tooltip.append("\n").append(presentation.disabled_reason);
        if (!presentation.enabled) ImGui::BeginDisabled();
        const bool invoked = aida::ui::toolbar_button(stable_id,
            presentation.label.empty() ? fallback_label : presentation.label.c_str(),
            false, false, tooltip.c_str());
        if (!presentation.enabled) ImGui::EndDisabled();
        if (!invoked)
            return;
        static_cast<void>(aida::ui::application_ui::execute_action(action_id,
            aida::ui::action_invocation_source_t::toolbar));
    };
    render_navigation_action("analysis.navigate.back", "back", "Back",
        "Navigate to the previous location");
    ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
    render_navigation_action("analysis.navigate.forward", "forward", "Forward",
        "Navigate to the next location");
    ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
    render_navigation_action("analysis.navigate.goto", "goto", "Go to",
        "Go to an address or symbol");
    if (can_rebase) {
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        const auto rebase_presentation =
            aida::ui::application_ui::present_action("analysis.modify.rebase");
        std::string rebase_tooltip = "Set the listing image base";
        if (!rebase_presentation.shortcut.empty())
            rebase_tooltip.append(" (").append(rebase_presentation.shortcut).append(")");
        if (!rebase_presentation.enabled)
            ImGui::BeginDisabled();
        if (aida::ui::toolbar_button("rebase", "Rebase", false, false,
                rebase_tooltip.c_str()))
            static_cast<void>(aida::ui::application_ui::execute_action(
                "analysis.modify.rebase",
                aida::ui::action_invocation_source_t::toolbar));
        if (!rebase_presentation.enabled)
            ImGui::EndDisabled();
    }
    aida::ui::end_toolbar_group();
    aida::ui::begin_toolbar_group("display");
    if (ImGui::Checkbox("Bytes", &show_bytes)) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->show_bytes = show_bytes;
    }
    ImGui::SameLine();
    const char* formats[] = {"VA", "RVA", "File"};
    ImGui::SetNextItemWidth(92.0f);
    if (ImGui::Combo("##address_format", &address_format, formats, 3)) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->addr_format = static_cast<addr_format_t>(address_format);
    }
    if (context.image && !context.image->sections().empty()) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180.0f);
        const char* preview = active_section < 0 ? "All executable ranges" :
            context.image->sections()[static_cast<std::size_t>(active_section)].name.c_str();
        if (ImGui::BeginCombo("##section", preview)) {
            if (ImGui::Selectable("All executable ranges", active_section < 0)) {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->active_section = -1;
            }
            for (std::size_t index = 0; index < context.image->sections().size(); ++index) {
                const auto& section = context.image->sections()[index];
                if (!section.executable)
                    continue;
                if (ImGui::Selectable(section.name.c_str(),
                        active_section == static_cast<int>(index))) {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->active_section = static_cast<int>(index);
                }
            }
            ImGui::EndCombo();
        }
    }
    aida::ui::end_toolbar_group();
    aida::ui::begin_toolbar_group("analysis_actions");
    struct toolbar_action_binding_t {
        const char* id;
        const char* fallback_label;
        const char* compact_label;
        aida::ui::application_ui::action_presentation_t presentation;
        std::string tooltip;
    };
    std::array<toolbar_action_binding_t, 5> action_bindings{{
        {"analysis.modify.rename", "Rename", "N", {}, {}},
        {"analysis.navigate.xrefs", "Cross References", "Xrefs", {}, {}},
        {"analysis.decompile_or_focus_pseudocode", "Decompile", "F5", {}, {}},
        {"analysis.navigate.graph", "Graph", "Graph", {}, {}},
        {"analysis.modify.patch", "Patch", "Patch", {}, {}}
    }};
    std::array<aida::ui::design::action_t, 5> toolbar_actions{};
    for (std::size_t index = 0; index < action_bindings.size(); ++index) {
        auto& binding = action_bindings[index];
        binding.presentation = aida::ui::application_ui::present_action(binding.id);
        binding.tooltip = binding.presentation.description;
        if (!binding.presentation.enabled && !binding.presentation.disabled_reason.empty()) {
            if (!binding.tooltip.empty()) binding.tooltip.append("\n");
            binding.tooltip.append(binding.presentation.disabled_reason);
        }
        toolbar_actions[index] = {
            binding.id,
            binding.presentation.label.empty() ? binding.fallback_label : binding.presentation.label.c_str(),
            binding.compact_label,
            binding.tooltip.c_str(),
            binding.presentation.shortcut.empty() ? nullptr : binding.presentation.shortcut.c_str(),
            nullptr,
            aida::ui::components::button_kind_t::ghost,
            binding.presentation.enabled,
            false,
            binding.presentation.visible
        };
    }
    const auto invoked_action = aida::ui::design::render_toolbar(
        "disassembly.analysis-actions", toolbar_actions.data(), toolbar_actions.size(),
        (std::max)(1.f, ImGui::GetContentRegionAvail().x));
    if (invoked_action.invoked && invoked_action.id) {
        static_cast<void>(aida::ui::application_ui::execute_action(
            invoked_action.id, aida::ui::action_invocation_source_t::toolbar));
    }
    aida::ui::end_toolbar_group(false);
    aida::ui::end_toolbar();

    const auto progress = context.progress;
    const bool progress_incomplete = progress.total_units == 0 ||
        progress.completed_units < progress.total_units;
    if (((progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
          progress.readiness == aida::analysis::workspace_readiness_t::partial) &&
         progress_incomplete) ||
        progress.readiness == aida::analysis::workspace_readiness_t::cancelling) {
        const float fraction = progress.total_units == 0 ? 0.0f :
            static_cast<float>(progress.completed_units) /
            static_cast<float>(progress.total_units);
        char progress_message[128]{};
        std::snprintf(progress_message, sizeof(progress_message), "%llu of %llu units · %.0f%%",
            static_cast<unsigned long long>(progress.completed_units),
            static_cast<unsigned long long>(progress.total_units),
            (std::clamp)(fraction, 0.0f, 1.0f) * 100.0f);
        if (aida::ui::inline_notice("analysis_progress", progress.phase.c_str(),
                progress_message, aida::ui::status_kind_t::info,
                progress.readiness == aida::analysis::workspace_readiness_t::cancelling
                    ? nullptr : "Cancel"))
            context.workspace->request_cancel();
    }
    if (progress.error) {
        const std::string message = progress.error->stable_code() + ": " +
            progress.error->message;
        aida::ui::inline_notice("analysis_error", "Analysis failed", message.c_str(),
            aida::ui::status_kind_t::error);
    }
    std::string mutation_error;
    std::string derived_publication_error;
    bool derived_publication_pending = false;
    std::string format_error;
    std::string export_error;
    std::string export_status;
    {
        const auto authority = authoritative_state(context);
        std::lock_guard<std::mutex> lock(authority->mutex);
        mutation_error = authority->mutation_error;
        derived_publication_error = authority->derived_publication_error;
        derived_publication_pending =
            authority->derived_publication_retry_pending.load(
                std::memory_order_acquire);
    }
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        format_error = context.view->format_error;
        export_error = context.view->export_error;
        export_status = context.view->export_status;
    }
    if (!mutation_error.empty())
        aida::ui::inline_notice("overlay_error", "Overlay update failed",
            mutation_error.c_str(), aida::ui::status_kind_t::error);
    if (!derived_publication_error.empty() &&
        aida::ui::inline_notice("overlay_derived_publication_error",
            "Overlay committed; presentation refresh pending",
            derived_publication_error.c_str(), aida::ui::status_kind_t::warning,
            derived_publication_pending ? nullptr : "Retry"))
        static_cast<void>(queue_overlay_presentation_retry(context));
    if (!format_error.empty() &&
        aida::ui::inline_notice("format_error", "Formatting failed", format_error.c_str(),
            aida::ui::status_kind_t::error, "Retry")) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->format_error.clear();
        context.view->formatted.clear();
        context.view->pending_format_pages.clear();
    }
    if (!export_error.empty()) {
        aida::ui::inline_notice("export_error", "Export failed", export_error.c_str(),
            aida::ui::status_kind_t::error);
    } else if (!export_status.empty()) {
        aida::ui::inline_notice("export_status", "Listing export", export_status.c_str(),
            aida::ui::status_kind_t::info);
    }
    bool escape_consumed = false;
    if (context.view->rebase_popup_open &&
        !ImGui::IsPopupOpen("Rebase###disasm_rebase_modal"))
        ImGui::OpenPopup("Rebase###disasm_rebase_modal");
    if (context.view->rebase_popup_open &&
        aida::ui::design::begin_dialog_exact("Rebase###disasm_rebase_modal",
            ImVec2(460.0f, 300.0f), ImVec2(360.0f, 240.0f))) {
        const float footer_height = aida::ui::design::dialog_footer_reserve_height(
            "Apply", "Cancel");
        aida::ui::design::begin_dialog_body("disasm_rebase_body", footer_height);
        ImGui::TextUnformatted("Image base");
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        const bool enter = ImGui::InputTextWithHint("##rebase_image_base", "0x140000000",
            context.view->rebase_buf, sizeof(context.view->rebase_buf),
            ImGuiInputTextFlags_EnterReturnsTrue);
        if (!context.view->rebase_error.empty())
            aida::ui::inline_notice("rebase_error", "Invalid image base",
                context.view->rebase_error.c_str(), aida::ui::status_kind_t::error);
        aida::ui::design::end_dialog_body();
        const auto footer = aida::ui::design::dialog_footer("disasm_rebase_footer",
            "Apply", true, false, "Cancel");
        const bool apply = footer.confirmed || enter;
        const bool cancel = footer.cancelled;
        if (apply) {
            const auto base = parse_address_text(context, context.view->rebase_buf);
            if (!base || *base == 0 || context.image->image_size() >
                (std::numeric_limits<std::uint64_t>::max)() - *base) {
                context.view->rebase_error = "Invalid image base.";
            } else {
                {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->display_image_base = *base == context.image->image_base()
                        ? std::nullopt : std::optional<std::uint64_t>(*base);
                    context.view->rebase_error.clear();
                    context.view->rebase_popup_open = false;
                    context.view->formatted.clear();
                    context.view->pending_format_pages.clear();
                }
                context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
                ImGui::CloseCurrentPopup();
            }
        } else if (cancel) {
			escape_consumed = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->rebase_error.clear();
            context.view->rebase_popup_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    bool goto_visible = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        goto_visible = context.view->goto_visible;
    }
    if (goto_visible) {
        aida::ui::begin_toolbar("##disassembly_goto",
            aida::ui::metrics::control::toolbar_h +
            aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
        ImGui::PushID("goto_address");
        const ImGuiID goto_input = ImGui::GetID("##input");
        ImGui::PopID();
        static_cast<void>(aida::ui::search_field("goto_address", context.view->goto_buf,
            sizeof(context.view->goto_buf), "VA, RVA, or symbol", 300.0f));
        const bool enter = ImGui::GetActiveID() == goto_input &&
            ImGui::IsKeyPressed(ImGuiKey_Enter, false);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        const bool go = aida::ui::toolbar_button("goto_submit", "Go", false, false,
            "Navigate to the resolved address") || enter;
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        const bool close_goto = aida::ui::toolbar_button("goto_close", "Close", false,
            false, "Close address search");
        aida::ui::end_toolbar();
        if (go) {
            if (auto value = parse_address_text(context, context.view->goto_buf))
                goto_address(*value, context);
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->goto_visible = false;
        } else if (close_goto) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->goto_visible = false;
		} else if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			std::lock_guard<std::mutex> lock(context.view->mutex);
			context.view->goto_visible = false;
			escape_consumed = true;
        }
    }
    const auto range = instruction_range(context);
    if (!range || !context.publication->snapshot || range->first >= range->second) {
        if (progress.readiness == aida::analysis::workspace_readiness_t::failed) {
            aida::ui::error_state("disassembly_unavailable", "Disassembly unavailable",
                "Analysis failed before any instruction records were published.", nullptr,
                ImVec2(0.0f, 152.0f));
        } else if (progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
                   progress.readiness == aida::analysis::workspace_readiness_t::partial ||
                   progress.readiness == aida::analysis::workspace_readiness_t::cancelling) {
            aida::ui::loading_state("disassembly_loading", "Preparing disassembly",
                "Instruction records will appear as soon as analysis publishes them.",
                ImVec2(0.0f, 152.0f));
        } else {
            aida::ui::compact_empty_state("disassembly_no_records", "No instructions available",
                "This target has no instruction records at the current readiness level.", nullptr,
                ImVec2(0.0f, 152.0f));
        }
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopID();
        comment_dialog::render();
        rename_dialog::render();
        return;
    }
    {
        const float band_width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x);
        ImGui::InvisibleButton("##disasm_navigation_band", ImVec2(band_width, 6.0f));
        const ImVec2 band_min = ImGui::GetItemRectMin();
        const ImVec2 band_max = ImGui::GetItemRectMax();
        ImDrawList* band_draw = ImGui::GetWindowDrawList();
        band_draw->AddRectFilled(band_min, band_max,
            aida::ui::with_alpha(theme.bg_elevated, alpha));
        const auto& navigation_instructions = context.publication->snapshot->instructions;
        const std::size_t navigation_count = range->second - range->first;
        const std::size_t marker_budget = (std::max)(static_cast<std::size_t>(1),
            static_cast<std::size_t>(band_width));
        const std::size_t marker_step = (std::max)(static_cast<std::size_t>(1),
            (navigation_count + marker_budget - 1) / marker_budget);
        std::optional<aida::analysis::address_t> band_selection;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            band_selection = context.view->selection;
            for (std::size_t offset = 0; offset < navigation_count; offset += marker_step) {
                const auto& marker = navigation_instructions[range->first + offset];
                ImU32 color = theme.text_dim;
                if ((marker.flow_flags & aida::analysis::flow_return) != 0)
                    color = disasm_theme::mnem_ret();
                else if ((marker.flow_flags & aida::analysis::flow_call) != 0)
                    color = disasm_theme::mnem_call();
                else if ((marker.flow_flags & aida::analysis::flow_branch) != 0)
                    color = disasm_theme::mnem_branch();
                else {
                    const auto formatted = context.view->formatted.find(marker.id);
                    if (formatted != context.view->formatted.end()) {
                        const auto& text = formatted->second.text;
                        if (text.size() >= 3 &&
                            (text[0] == 'n' || text[0] == 'N') &&
                            (text[1] == 'o' || text[1] == 'O') &&
                            (text[2] == 'p' || text[2] == 'P'))
                            color = disasm_theme::mnem_nop();
                    }
                }
                const float x = band_min.x +
                    (static_cast<float>(offset) / static_cast<float>(navigation_count)) * band_width;
                band_draw->AddRectFilled(ImVec2(x, band_min.y + 1.0f),
                    ImVec2((std::min)(x + 1.0f, band_max.x), band_max.y - 1.0f),
                    aida::ui::with_alpha(color, alpha * 0.9f));
            }
        }
        if (band_selection) {
            const auto selected = std::lower_bound(
                navigation_instructions.begin() + static_cast<std::ptrdiff_t>(range->first),
                navigation_instructions.begin() + static_cast<std::ptrdiff_t>(range->second),
                *band_selection,
                [](const aida::analysis::instruction_record_t& item,
                   const aida::analysis::address_t& address) { return item.address < address; });
            if (selected != navigation_instructions.begin() +
                    static_cast<std::ptrdiff_t>(range->second) &&
                selected->address == *band_selection) {
                const auto selected_offset = static_cast<std::size_t>(std::distance(
                    navigation_instructions.begin() + static_cast<std::ptrdiff_t>(range->first),
                    selected));
                const float x = band_min.x +
                    (static_cast<float>(selected_offset) / static_cast<float>(navigation_count)) *
                    band_width;
                band_draw->AddRectFilled(ImVec2(x - 1.0f, band_min.y),
                    ImVec2(x + 2.0f, band_max.y),
                    aida::ui::with_alpha(theme.accent_u32, alpha));
            }
        }
        if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            const float normalized = (std::clamp)(
                (ImGui::GetIO().MousePos.x - band_min.x) / band_width, 0.0f, 0.999999f);
            const auto offset = (std::min)(navigation_count - 1,
                static_cast<std::size_t>(normalized * static_cast<float>(navigation_count)));
            goto_address(runtime_address(context,
                navigation_instructions[range->first + offset].address).value_or(
                    navigation_instructions[range->first + offset].address.value), context);
        }
    }
    ImGui::PushStyleColor(ImGuiCol_ChildBg,
        ImGui::ColorConvertU32ToFloat4(disasm_theme::panel_bg()));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::BeginChild("##instruction_rows", ImVec2(0.0f, 0.0f), false,
        ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (context.view->scroll_restore_pending) {
            ImGui::SetScrollY(context.view->target_scroll_y);
            context.view->scroll_restore_pending = false;
        }
    }
    const auto& instructions = context.publication->snapshot->instructions;
    const std::size_t count_size = range->second - range->first;
    const auto& metadata_lines = context.view->metadata_lines;
    const std::size_t metadata_count = metadata_lines.size();
    const auto make_metadata_menu = [&](std::size_t line_index)
            -> std::optional<aida::ui::analysis_context_menu::context_t> {
        if (line_index >= metadata_lines.size())
            return std::nullopt;
        std::string listing;
        for (const auto& item : metadata_lines) {
            listing.append(item.text);
            listing.push_back('\n');
        }
        const std::string selected_line = metadata_lines[line_index].text;
        std::uint64_t image_base = context.image ? context.image->image_base() : 0;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            if (context.view->display_image_base)
                image_base = *context.view->display_image_base;
        }
        char identity_buffer[512]{};
        std::snprintf(identity_buffer, sizeof(identity_buffer), "%s  %s  image 0x%016llX  entry +0x%08llX",
            context.workspace->identity().bin_name().c_str(),
            context.image ? file_metadata_banner::machine_name(context.image->machine()).c_str() : "unknown",
            static_cast<unsigned long long>(image_base),
            static_cast<unsigned long long>(context.image ? context.image->entry_rva() : 0));
        const std::string identity_line = identity_buffer;
        char address_buffer[32]{};
        std::snprintf(address_buffer, sizeof(address_buffer), "%016llX",
            static_cast<unsigned long long>(image_base));
        const std::string image_base_text = address_buffer;
        aida::ui::analysis_context_menu::context_t menu;
        menu.kind = aida::ui::analysis_context_menu::menu_kind_t::metadata;
        menu.entity_id = "metadata:" + std::to_string(image_base) + ":" +
            std::to_string(line_index);
        menu.generation = context_generation(context);
        menu.live_generation = [context]() { return context_generation(context); };
        menu.validate_identity = [view = context.view, line_index]() {
            std::lock_guard<std::mutex> lock(view->mutex);
            return view->banner_selected_line == line_index
                ? aida::ui::capability_state_t::available()
                : aida::ui::capability_state_t::unavailable(
                    "The selected metadata row changed");
        };
        aida::ui::analysis_context_menu::action_slot_t copy_all;
        copy_all.invoke = [listing = std::move(listing)] {
            ImGui::SetClipboardText(listing.c_str());
            return aida::ui::action_handler_result_t::completed();
        };
        menu.actions.emplace("analysis.copy.metadata", std::move(copy_all));
        aida::ui::analysis_context_menu::action_slot_t copy_line;
        copy_line.invoke = [identity_line] {
            ImGui::SetClipboardText(identity_line.c_str());
            return aida::ui::action_handler_result_t::completed();
        };
        menu.actions.emplace("analysis.copy.metadata_line", std::move(copy_line));
        aida::ui::analysis_context_menu::action_slot_t copy_current_line;
        copy_current_line.invoke = [selected_line] {
            ImGui::SetClipboardText(selected_line.c_str());
            return aida::ui::action_handler_result_t::completed();
        };
        menu.actions.emplace("analysis.copy.metadata_current_line", std::move(copy_current_line));
        aida::ui::analysis_context_menu::action_slot_t copy_address;
        copy_address.invoke = [image_base_text] {
            ImGui::SetClipboardText(image_base_text.c_str());
            return aida::ui::action_handler_result_t::completed();
        };
        menu.actions.emplace("analysis.copy.metadata_address", std::move(copy_address));
        aida::ui::analysis_context_menu::action_slot_t select_all;
        select_all.invoke = [view = context.view] {
            std::lock_guard<std::mutex> lock(view->mutex);
            view->banner_selected_all = true;
            return aida::ui::action_handler_result_t::completed();
        };
        menu.actions.emplace("analysis.select.metadata_all", std::move(select_all));
        return menu;
    };
    const auto open_metadata_menu = [&](std::size_t line_index,
            aida::ui::context_menu_open_origin_t origin) {
        auto menu = make_metadata_menu(line_index);
        if (menu)
            aida::ui::analysis_context_menu::open(std::move(*menu), origin);
    };
    const std::size_t total_size = count_size > static_cast<std::size_t>((std::numeric_limits<int>::max)()) -
        metadata_count ? static_cast<std::size_t>((std::numeric_limits<int>::max)())
        : count_size + metadata_count;
    const int count = static_cast<int>(total_size);
    ImFont* code_font = aida::ui::fonts::code();
    if (!code_font)
        code_font = ImGui::GetFont();
    ImGui::PushFont(code_font);
    const ImVec2 listing_item_spacing = ImGui::GetStyle().ItemSpacing;
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
        ImVec2(listing_item_spacing.x, 0.0f));
    const float code_size = ImGui::GetFontSize();
    const float char_width = (std::max)(1.0f,
        code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f, "0").x);
    const float row_height = 16.0f;
    const float available_width = ImGui::GetContentRegionAvail().x;
    const bool draw_bytes = show_bytes && available_width >= char_width * 88.0f;
    const float gutter_width = 20.0f;
    const float bytes_width = char_width * 31.0f;
    std::optional<aida::analysis::address_t> selection;
    bool scroll_to_selection = false;
    std::vector<bookmark_t> bookmarks;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        selection = context.view->selection;
        scroll_to_selection = context.view->scroll_to_selection;
    }
    bookmarks = bookmark_snapshot(context);
    if (scroll_to_selection && selection) {
        auto found = std::lower_bound(instructions.begin() + static_cast<std::ptrdiff_t>(range->first),
            instructions.begin() + static_cast<std::ptrdiff_t>(range->second), *selection,
            [](const aida::analysis::instruction_record_t& instruction,
               const aida::analysis::address_t& address) {
                return instruction.address < address;
            });
        if (found != instructions.begin() + static_cast<std::ptrdiff_t>(range->second)) {
            const auto index = static_cast<std::size_t>(std::distance(
                instructions.begin() + static_cast<std::ptrdiff_t>(range->first), found));
            ImGui::SetScrollY(static_cast<float>(metadata_count + index) * row_height);
        }
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->scroll_to_selection = false;
    }
    auto section_for = [&](const aida::analysis::address_t& address)
        -> const aida::analysis::pe_section_t* {
        if (!context.image)
            return nullptr;
        const auto runtime = runtime_address(context, address).value_or(address.value);
        const auto rva = optional_value(context.image->va_to_rva(runtime));
        if (!rva)
            return nullptr;
        const auto found = std::find_if(context.image->sections().begin(),
            context.image->sections().end(), [&](const auto& section) {
                const std::uint64_t extent = (std::max)(section.virtual_size, section.raw_size);
                return *rva >= section.virtual_address &&
                    *rva - section.virtual_address < extent;
            });
        return found == context.image->sections().end() ? nullptr : &*found;
    };
    auto prefix_text = [&](const aida::analysis::address_t& address) {
        const auto section = section_for(address);
        return std::string(section ? section->name : ".text") + ":" +
            address_label(context, address, static_cast<addr_format_t>(address_format));
    };
    ImGuiListClipper clipper;
    clipper.Begin(count, row_height);
    while (clipper.Step()) {
        const std::size_t visible_start = static_cast<std::size_t>((std::max)(0, clipper.DisplayStart));
        const std::size_t visible_end = static_cast<std::size_t>((std::max)(0, clipper.DisplayEnd));
        const std::size_t instruction_start = visible_start > metadata_count
            ? visible_start - metadata_count : 0;
        const std::size_t instruction_end = visible_end > metadata_count
            ? visible_end - metadata_count : 0;
        const std::size_t page_begin = range->first + (std::min)(count_size, instruction_start);
        const std::size_t page_end = (std::min)(range->second,
            range->first + (std::min)(count_size, instruction_end));
        if (page_begin < page_end)
            request_format_page(context, page_begin, page_end);
        float prefix_width = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
            address_format == static_cast<int>(addr_format_t::rva)
                ? ".text:+00000000" : ".text:0000000000000000").x;
        for (std::size_t sample = page_begin; sample < page_end; ++sample) {
            const auto text = prefix_text(instructions[sample].address);
            prefix_width = (std::max)(prefix_width,
                code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f, text.c_str()).x);
        }
        for (int virtual_row = clipper.DisplayStart; virtual_row < clipper.DisplayEnd; ++virtual_row) {
            if (virtual_row < 0)
                continue;
            const auto virtual_index = static_cast<std::size_t>(virtual_row);
            if (virtual_index < metadata_count) {
                const auto& line = metadata_lines[virtual_index];
                ImGui::PushID(-1 - virtual_row);
                bool selected_banner = false;
                {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    selected_banner = context.view->banner_selected_all;
                }
                ImGui::InvisibleButton("##metadata",
                    ImVec2((std::max)(1.0f, ImGui::GetContentRegionAvail().x), row_height),
                    ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
                const bool metadata_left_clicked =
                    ImGui::IsItemClicked(ImGuiMouseButton_Left);
                const bool metadata_right_clicked =
                    ImGui::IsItemClicked(ImGuiMouseButton_Right);
                const bool metadata_hovered = ImGui::IsItemHovered();
                if (metadata_left_clicked) {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->banner_selected_all = true;
                    context.view->banner_selected_line = virtual_index;
                    context.view->selection.reset();
                    selection.reset();
                }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                if (ImGui::IsItemVisible()) {
                    const std::string metadata_semantic_id =
                        aida::preview::semantics::stable_id(
                            "aida.disassembly.metadata-row",
                            "row-" + std::to_string(virtual_index));
                    aida::preview::semantics::register_last_item(
                        metadata_semantic_id, "disassembly-metadata-row");
                }
#endif
                const ImVec2 minimum = ImGui::GetItemRectMin();
                const ImVec2 maximum = ImGui::GetItemRectMax();
                ImDrawList* draw_list = ImGui::GetWindowDrawList();
                if (selected_banner || metadata_hovered) {
                    draw_list->AddRectFilled(minimum, maximum,
                        ImGui::GetColorU32(selected_banner
                            ? ImGuiCol_Header : ImGuiCol_HeaderHovered));
                }
                const float prefix_x = minimum.x + gutter_width + char_width * 0.5f;
                const float text_x = prefix_x + prefix_width + char_width * 1.5f;
                const float text_y = minimum.y + (row_height - code_size) * 0.5f;
                const auto first_instruction = instructions.begin() +
                    static_cast<std::ptrdiff_t>(range->first);
                const auto banner_section = section_for(first_instruction->address);
                const std::string section = banner_section ? banner_section->name : ".text";
                const std::string address = address_label(context, first_instruction->address,
                    static_cast<addr_format_t>(address_format));
                const ImU32 segment_color = aida::ui::with_alpha(disasm_theme::segment(), alpha);
                const ImU32 address_color = aida::ui::with_alpha(disasm_theme::address(), alpha);
                draw_list->AddText(code_font, code_size, ImVec2(prefix_x, text_y),
                    segment_color, section.c_str());
                const float section_width = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                    section.c_str()).x;
                draw_list->AddText(code_font, code_size,
                    ImVec2(prefix_x + section_width, text_y),
                    aida::ui::with_alpha(disasm_theme::separator(), alpha), ":");
                draw_list->AddText(code_font, code_size,
                    ImVec2(prefix_x + section_width + char_width, text_y),
                    address_color, address.c_str());
                ImU32 line_color = disasm_theme::comment();
                if (line.kind == metadata_line_kind_t::banner)
                    line_color = disasm_theme::banner();
                else if (line.kind == metadata_line_kind_t::directive)
                    line_color = disasm_theme::directive();
                else if (line.kind == metadata_line_kind_t::keyword)
                    line_color = disasm_theme::keyword();
                const ImVec4 clip_rect(minimum.x, minimum.y, maximum.x, maximum.y);
                draw_list->AddText(code_font, code_size, ImVec2(text_x, text_y),
                    aida::ui::with_alpha(line_color, alpha), line.text.c_str(), nullptr,
                    0.0f, &clip_rect);
                if (metadata_right_clicked) {
                    {
                        std::lock_guard<std::mutex> lock(context.view->mutex);
                        context.view->banner_selected_line = virtual_index;
                    }
                }
                ImGui::PopID();
                if (metadata_right_clicked) {
                    open_metadata_menu(virtual_index,
                        aida::ui::context_menu_open_origin_t::pointer);
                }
                continue;
            }
            const std::size_t row_index = virtual_index - metadata_count;
            const std::size_t index = range->first + row_index;
            if (index >= range->second)
                break;
            const auto& instruction = instructions[index];
            formatted_instruction_t formatted;
            bool formatted_ready = false;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                auto found = context.view->formatted.find(instruction.id);
                if (found != context.view->formatted.end()) {
                    formatted = found->second;
                    formatted_ready = true;
                }
            }
            const bool selected = selection && *selection == instruction.address;
            ImGui::PushID(static_cast<int>(instruction.id & 0x7FFFFFFF));
            const ImGuiSelectableFlags selection_flags =
                ImGuiSelectableFlags_AllowDoubleClick |
                (editor_config::disasm_full_line_select ?
                    ImGuiSelectableFlags_SpanAllColumns : ImGuiSelectableFlags_None);
            if (ImGui::Selectable("##instruction", selected,
                    selection_flags, ImVec2(0.0f, row_height))) {
                select_address(instruction.address, context, false);
                selection = instruction.address;
                {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->banner_selected_all = false;
                }
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                    instruction.target_fact_count != 0) {
                    const auto target_index = instruction.target_fact_begin;
                    if (target_index < context.publication->snapshot->target_facts.size()) {
                        const auto& target = context.publication->snapshot->target_facts[target_index];
                        if (target.direct)
                            goto_address(runtime_address(context, target.target).value_or(
                                target.target.value), context);
                    }
                }
            }
            const bool typed_pointer_request =
                ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const ImVec2 minimum = ImGui::GetItemRectMin();
            const ImVec2 maximum = ImGui::GetItemRectMax();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            if (ImGui::IsItemVisible()) {
                const std::string instruction_semantic_id =
                    aida::preview::semantics::stable_id(
                        "aida.disassembly.instruction-row",
                        "address-" + std::to_string(instruction.address.value));
                aida::preview::semantics::register_last_item(
                    instruction_semantic_id, "disassembly-instruction-row");
            }
#endif
            if (typed_pointer_request && (!selection || *selection != instruction.address)) {
                select_address(instruction.address, context, false);
                selection = instruction.address;
            }
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->PushClipRect(minimum, maximum, true);
            if (selected) {
                draw_list->AddRectFilled(minimum, ImVec2(minimum.x + 3.0f, maximum.y),
                    aida::ui::with_alpha(theme.accent_u32, alpha));
            }
            const bool bookmarked = std::any_of(bookmarks.begin(), bookmarks.end(),
                [&](const bookmark_t& item) { return item.addr == instruction.address.value; });
            if (bookmarked) {
                draw_list->AddRectFilled(ImVec2(minimum.x + 4.0f, minimum.y),
                    ImVec2(minimum.x + 7.0f, maximum.y),
                    aida::ui::with_alpha(theme.warning, alpha));
            }
            const float text_y = minimum.y + (row_height - code_size) * 0.5f;
            const float prefix_x = minimum.x + gutter_width + char_width * 0.5f;
            const float bytes_x = prefix_x + prefix_width + char_width * 1.5f;
            const float instruction_x = draw_bytes
                ? bytes_x + bytes_width + char_width
                : bytes_x;
            const auto runtime = runtime_address(context, instruction.address).value_or(
                instruction.address.value);
            const auto instruction_section = section_for(instruction.address);
            const std::string section = instruction_section ? instruction_section->name : ".text";
            const std::string address = address_label(context, instruction.address,
                static_cast<addr_format_t>(address_format));
            const float section_width = code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                section.c_str()).x;
            draw_list->AddText(code_font, code_size, ImVec2(prefix_x, text_y),
                aida::ui::with_alpha(disasm_theme::segment(), alpha),
                section.c_str());
            draw_list->AddText(code_font, code_size,
                ImVec2(prefix_x + section_width, text_y),
                aida::ui::with_alpha(disasm_theme::separator(), alpha), ":");
            draw_list->AddText(code_font, code_size,
                ImVec2(prefix_x + section_width + char_width, text_y),
                aida::ui::with_alpha(disasm_theme::address(), alpha), address.c_str());
            if (draw_bytes && formatted_ready) {
                const ImVec4 bytes_clip(bytes_x, minimum.y,
                    instruction_x - char_width * 0.5f, maximum.y);
                draw_list->AddText(code_font, code_size, ImVec2(bytes_x, text_y),
                    aida::ui::with_alpha(disasm_theme::bytes(), alpha), formatted.bytes.c_str(),
                    nullptr, 0.0f, &bytes_clip);
            }
            const std::string name = resolve_name(context, instruction.address);
            const std::string user_comment = comment(context, instruction.address);
            const std::string generated_comment = auto_comment(context, instruction.address);
            const auto function = std::lower_bound(
                context.publication->snapshot->functions.begin(),
                context.publication->snapshot->functions.end(), instruction.address,
                [](const aida::analysis::function_record_t& item,
                   const aida::analysis::address_t& value) { return item.start < value; });
            const bool function_start = function != context.publication->snapshot->functions.end() &&
                function->start == instruction.address;
            float cursor_x = instruction_x;
            if (function_start) {
                draw_list->AddLine(ImVec2(instruction_x, minimum.y),
                    ImVec2(maximum.x, minimum.y),
                    aida::ui::with_alpha(disasm_theme::banner(), alpha * 0.65f));
                draw_list->AddRectFilled(ImVec2(minimum.x, minimum.y),
                    ImVec2(minimum.x + 3.0f, maximum.y),
                    aida::ui::with_alpha(disasm_theme::func_name(), alpha));
                std::string function_name = name;
                if (function_name.empty()) {
                    char generated[48]{};
                    std::snprintf(generated, sizeof(generated), "sub_%llX",
                        static_cast<unsigned long long>(runtime));
                    function_name = generated;
                }
                function_name.append(":  ");
                draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                    aida::ui::with_alpha(disasm_theme::func_name(), alpha),
                    function_name.c_str());
                cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                    function_name.c_str()).x;
            } else if (!name.empty()) {
                const std::string label = name + ":  ";
                draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                    aida::ui::with_alpha(disasm_theme::loc_label(), alpha), label.c_str());
                cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                    label.c_str()).x;
            }
            if (formatted_ready && formatted.error.empty()) {
                const std::string_view line(formatted.text);
                const auto mnemonic_end = line.find_first_of(" \t");
                const auto mnemonic = line.substr(0, mnemonic_end);
                ImU32 mnemonic_color = disasm_theme::mnemonic();
                if (!mnemonic.empty() && (mnemonic.front() == 'j' || mnemonic.front() == 'J'))
                    mnemonic_color = disasm_theme::mnem_branch();
                else if (mnemonic == "call" || mnemonic == "CALL")
                    mnemonic_color = disasm_theme::mnem_call();
                else if (mnemonic == "ret" || mnemonic == "retn" || mnemonic == "RET")
                    mnemonic_color = disasm_theme::mnem_ret();
                draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                    aida::ui::with_alpha(mnemonic_color, alpha),
                    mnemonic.data(), mnemonic.data() + mnemonic.size());
                cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                    mnemonic.data(), mnemonic.data() + mnemonic.size()).x;
                if (mnemonic_end != std::string_view::npos) {
                    const auto operands = line.substr(mnemonic_end);
                    auto equals_ci = [](std::string_view left, std::string_view right) {
                        return left.size() == right.size() && std::equal(left.begin(), left.end(),
                            right.begin(), [](char l, char r) {
                                return std::tolower(static_cast<unsigned char>(l)) ==
                                    std::tolower(static_cast<unsigned char>(r));
                            });
                    };
                    auto token_color = [&](std::string_view token) {
                        static constexpr std::array<std::string_view, 33> registers{
                            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                            "ax", "bx", "cx", "dx", "al", "ah", "bl", "bh", "cl",
                            "ch", "dl", "dh", "rip", "eip", "cs", "ds", "ss"};
                        if (std::any_of(registers.begin(), registers.end(),
                                [&](std::string_view value) { return equals_ci(token, value); }) ||
                            (token.size() >= 2 && (token[0] == 'r' || token[0] == 'R') &&
                             std::isdigit(static_cast<unsigned char>(token[1])) != 0))
                            return disasm_theme::reg();
                        if (!token.empty() &&
                            (std::isdigit(static_cast<unsigned char>(token.front())) != 0 ||
                             token.front() == '-' || token.front() == '+'))
                            return disasm_theme::immediate_num();
                        static constexpr std::array<std::string_view, 10> type_tokens{
                            "byte", "word", "dword", "qword", "tbyte", "xmmword", "ymmword",
                            "zmmword", "ptr", "offset"};
                        if (std::any_of(type_tokens.begin(), type_tokens.end(),
                                [&](std::string_view value) { return equals_ci(token, value); }))
                            return disasm_theme::keyword();
                        if (!name.empty() && equals_ci(token, name))
                            return disasm_theme::func_name();
                        if (token.size() > 4 &&
                            (equals_ci(token.substr(0, 4), "sub_") ||
                             equals_ci(token.substr(0, 4), "loc_") ||
                             equals_ci(token.substr(0, 4), "off_")))
                            return disasm_theme::sub_label();
                        if (token.find('_') != std::string_view::npos)
                            return disasm_theme::sub_label();
                        return theme.text_secondary;
                    };
                    std::size_t operand_offset = 0;
                    const std::size_t operand_limit = (std::min)(operands.size(),
                        static_cast<std::size_t>(512));
                    while (operand_offset < operand_limit) {
                        const auto begin = operand_offset;
                        if (operands[operand_offset] == '"' || operands[operand_offset] == '\'') {
                            const char quote = operands[operand_offset++];
                            while (operand_offset < operand_limit && operands[operand_offset] != quote)
                                ++operand_offset;
                            if (operand_offset < operand_limit)
                                ++operand_offset;
                            const auto token = operands.substr(begin, operand_offset - begin);
                            draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                                aida::ui::with_alpha(disasm_theme::string_ref(), alpha),
                                token.data(), token.data() + token.size());
                            cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                                token.data(), token.data() + token.size()).x;
                            continue;
                        }
                        const auto current = static_cast<unsigned char>(operands[operand_offset]);
                        const bool word = std::isalnum(current) != 0 || operands[operand_offset] == '_' ||
                            operands[operand_offset] == '.' || operands[operand_offset] == '$' ||
                            operands[operand_offset] == '?' || operands[operand_offset] == '@' ||
                            operands[operand_offset] == '+' || operands[operand_offset] == '-';
                        ++operand_offset;
                        while (operand_offset < operand_limit) {
                            const auto value = static_cast<unsigned char>(operands[operand_offset]);
                            const bool next_word = std::isalnum(value) != 0 ||
                                operands[operand_offset] == '_' || operands[operand_offset] == '.' ||
                                operands[operand_offset] == '$' || operands[operand_offset] == '?' ||
                                operands[operand_offset] == '@' || operands[operand_offset] == '+' ||
                                operands[operand_offset] == '-';
                            if (next_word != word)
                                break;
                            ++operand_offset;
                        }
                        const auto token = operands.substr(begin, operand_offset - begin);
                        const bool memory_punctuation = !word &&
                            (token.find('[') != std::string_view::npos ||
                             token.find(']') != std::string_view::npos);
                        const ImU32 color = word ? token_color(token)
                            : memory_punctuation ? disasm_theme::reg_ptr()
                            : theme.text_secondary;
                        draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                            aida::ui::with_alpha(color, alpha), token.data(),
                            token.data() + token.size());
                        cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f,
                            token.data(), token.data() + token.size()).x;
                    }
                }
            } else {
                const char* pending = formatted_ready ? formatted.error.c_str() : "Formatting...";
                draw_list->AddText(code_font, code_size, ImVec2(cursor_x, text_y),
                    aida::ui::with_alpha(theme.text_dim, alpha), pending);
                cursor_x += code_font->CalcTextSizeA(code_size, FLT_MAX, 0.0f, pending).x;
            }
            if (!user_comment.empty() || !generated_comment.empty()) {
                const std::string combined = user_comment.empty() ? generated_comment :
                    generated_comment.empty() ? user_comment : user_comment + "; " + generated_comment;
                const std::string rendered_comment = "  ; " + combined;
                draw_list->AddText(code_font, code_size,
                    ImVec2(cursor_x + char_width, text_y),
                    aida::ui::with_alpha(disasm_theme::comment(), alpha),
                    rendered_comment.c_str());
            }
            draw_list->PopClipRect();
            if (instruction.target_fact_count != 0 &&
                instruction.target_fact_begin < context.publication->snapshot->target_facts.size()) {
                const auto& target = context.publication->snapshot->target_facts[
                    instruction.target_fact_begin];
                if (target.direct) {
                    const auto target_instruction = std::lower_bound(
                        instructions.begin() + static_cast<std::ptrdiff_t>(range->first),
                        instructions.begin() + static_cast<std::ptrdiff_t>(range->second), target.target,
                        [](const aida::analysis::instruction_record_t& item,
                           const aida::analysis::address_t& value) { return item.address < value; });
                    if (target_instruction != instructions.begin() +
                            static_cast<std::ptrdiff_t>(range->second) &&
                        target_instruction->address == target.target) {
                        const auto target_index = static_cast<std::size_t>(std::distance(
                            instructions.begin(), target_instruction));
                        const float target_y_unclamped = minimum.y +
                            (static_cast<float>(target_index) - static_cast<float>(index)) * row_height +
                            row_height * 0.5f;
                        const float target_y = (std::clamp)(target_y_unclamped,
                            ImGui::GetWindowPos().y, ImGui::GetWindowPos().y + ImGui::GetWindowHeight());
                        const float source_y = minimum.y + row_height * 0.5f;
                        const float flow_x = minimum.x + char_width * 0.75f;
                        const ImU32 flow_color = aida::ui::with_alpha(
                            target_y_unclamped < source_y ? disasm_theme::arrow_up()
                                : disasm_theme::arrow_down(), alpha * 0.8f);
                        draw_list->AddLine(ImVec2(flow_x, source_y), ImVec2(flow_x, target_y),
                            flow_color, 1.0f);
                        draw_list->AddLine(ImVec2(flow_x, target_y),
                            ImVec2(flow_x + char_width * 0.65f, target_y), flow_color, 1.0f);
                        const float cue_x = maximum.x - 7.0f;
                        const float cue_y = minimum.y + row_height * 0.5f;
                        if (target_y_unclamped < source_y) {
                            draw_list->AddTriangleFilled(ImVec2(cue_x, cue_y - 4.0f),
                                ImVec2(cue_x - 4.0f, cue_y + 3.0f),
                                ImVec2(cue_x + 4.0f, cue_y + 3.0f), flow_color);
                        } else {
                            draw_list->AddTriangleFilled(ImVec2(cue_x, cue_y + 4.0f),
                                ImVec2(cue_x - 4.0f, cue_y - 3.0f),
                                ImVec2(cue_x + 4.0f, cue_y - 3.0f), flow_color);
                        }
                    }
                }
            }
            ImGui::PopID();
            if (typed_pointer_request) {
                open_instruction_menu(context, instruction,
                    formatted_ready ? std::optional<formatted_instruction_t>(formatted) : std::nullopt,
                    aida::ui::context_menu_open_origin_t::pointer);
            }
        }
    }
    ImGui::PopStyleVar();
    ImGui::PopFont();
    aida::ui::context_menu_open_origin_t analysis_menu_origin{};
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        aida::ui::analysis_context_menu::keyboard_request(analysis_menu_origin)) {
        bool banner_selected = false;
        std::size_t banner_line = 0;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            banner_selected = context.view->banner_selected_all;
            banner_line = context.view->banner_selected_line;
        }
        if (banner_selected) {
            open_metadata_menu(banner_line, analysis_menu_origin);
        } else if (selection) {
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), *selection,
                [](const aida::analysis::instruction_record_t& instruction,
                   const aida::analysis::address_t& address) { return instruction.address < address; });
            if (found != instructions.end() && found->address == *selection)
                open_instruction_menu(context, *found, formatted_instruction(context, found->id),
                    analysis_menu_origin);
        }
    }
    aida::ui::analysis_context_menu::render();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        const auto& io = ImGui::GetIO();
		const bool copy_pressed = io.KeyCtrl &&
			(ImGui::IsKeyPressed(ImGuiKey_C, false) ||
			 ImGui::IsKeyPressed(ImGuiKey_Insert, false));
        if (selection && copy_pressed) {
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), *selection,
                [](const aida::analysis::instruction_record_t& instruction,
                   const aida::analysis::address_t& address) {
                    return instruction.address < address;
                });
            if (found != instructions.end() && found->address == *selection)
                aida::ui::analysis_context_menu::execute_shortcut(
                    make_instruction_menu(context, *found,
                        formatted_instruction(context, found->id)),
                    "analysis.copy.line");
        }
        bool banner_selected = false;
        std::size_t banner_line = 0;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            banner_selected = context.view->banner_selected_all;
            banner_line = context.view->banner_selected_line;
        }
		if (banner_selected && copy_pressed) {
			auto menu = make_metadata_menu(banner_line);
			if (menu)
				aida::ui::analysis_context_menu::execute_shortcut(
					std::move(*menu), "analysis.copy.metadata");
		}
		if (!escape_consumed && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			bool xrefs_open = false;
			bool rebase_open = false;
			{
				std::lock_guard<std::mutex> lock(context.view->mutex);
				xrefs_open = context.view->xref_popup_open;
				rebase_open = context.view->rebase_popup_open;
			}
			if (!xrefs_open && !rebase_open)
				navigate_back(context);
		}
    }
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->target_scroll_y = ImGui::GetScrollY();
    }
    ImGui::EndChild();
    render_xref_popup(context);
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
    comment_dialog::render();
    rename_dialog::render();
}

}
