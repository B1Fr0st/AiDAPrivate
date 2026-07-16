#pragma once

#include "../disasm/disasm_view.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../ui/theme.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "../ui/application_view_registry.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xref_db_view {

struct result_t {
    aida::analysis::address_t source;
    aida::analysis::address_t target;
    aida::analysis::xref_kind_t kind = aida::analysis::xref_kind_t::code;
};

struct display_result_t {
    result_t result;
    std::uint64_t runtime = 0;
    std::string name;
    std::string label;
};

struct state_t {
    std::mutex mutex;
    char address[64] = {};
    char filter[128] = {};
    bool query_to = true;
    std::shared_ptr<const std::vector<result_t>> results;
    std::shared_ptr<const std::vector<display_result_t>> visible_results;
    std::uint64_t results_version = 0;
    std::uint64_t visible_version = 0;
    std::string visible_filter;
    std::atomic<bool> searching{false};
    std::atomic<bool> filtering{false};
    std::atomic<std::uint64_t> serial{1};
    std::shared_ptr<aida::analysis::cancellation_source_t> cancellation;
    std::string error;
    std::uint64_t selected_runtime = 0;
};

inline std::mutex& registry_mutex() {
    static std::mutex value;
    return value;
}

inline std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
    aida::analysis::binary_id_hash_t>& registry() {
    static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
        aida::analysis::binary_id_hash_t> value;
    return value;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context) {
    if (!context.workspace)
        return {};
    std::lock_guard<std::mutex> lock(registry_mutex());
    auto& values = registry();
    const auto id = context.workspace->identity().binary_id();
    auto found = values.find(id);
    if (found != values.end())
        return found->second;
    auto created = std::make_shared<state_t>();
    values.emplace(id, created);
    return created;
}

inline std::optional<std::uint64_t> parse_address(std::string text) {
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size()
        ? std::optional<std::uint64_t>(value) : std::nullopt;
}

inline const char* kind_name(aida::analysis::xref_kind_t kind) {
    using aida::analysis::xref_kind_t;
    switch (kind) {
    case xref_kind_t::code: return "code";
    case xref_kind_t::call: return "call";
    case xref_kind_t::read: return "read";
    case xref_kind_t::write: return "write";
    case xref_kind_t::address: return "address";
    case xref_kind_t::relocation: return "relocation";
    }
    return "unknown";
}

inline void submit_query(const disasm_view::workspace_context_t& context,
                         const std::shared_ptr<state_t>& state,
                         const aida::analysis::address_t& address,
                         bool query_to) {
    if (!context.publication || !context.publication->snapshot ||
        state->searching.exchange(true, std::memory_order_acq_rel))
        return;
    std::uint64_t serial = 0;
    auto cancellation = std::make_shared<aida::analysis::cancellation_source_t>();
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->cancellation)
            state->cancellation->request_cancel();
        state->cancellation = cancellation;
        state->results.reset();
        state->visible_results.reset();
        ++state->results_version;
        state->visible_version = 0;
        state->error.clear();
        state->query_to = query_to;
        serial = state->serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    }
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "xref_db_view";
    descriptor.label = "workspace_xref_page";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, address, query_to, cancellation, serial](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        std::vector<result_t> results;
        constexpr std::size_t maximum_results = 100000;
        results.reserve((std::min)(context.publication->snapshot->xrefs.size(),
            static_cast<std::size_t>(1024)));
        for (const auto& xref : context.publication->snapshot->xrefs) {
            if (runtime_cancel.requested.load(std::memory_order_acquire) ||
                cancellation->token().stop_requested())
                break;
            if ((query_to && xref.target == address) || (!query_to && xref.source == address))
                results.push_back({xref.source, xref.target, xref.kind});
            if (results.size() >= maximum_results)
                break;
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->serial.load(std::memory_order_acquire) == serial) {
                state->results = std::make_shared<const std::vector<result_t>>(std::move(results));
                state->visible_results.reset();
                ++state->results_version;
                state->visible_version = 0;
            }
        }
        state->searching.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->searching.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = submitted.reject_reason;
    }
}

inline void request_filter(const disasm_view::workspace_context_t& context,
                           const std::shared_ptr<state_t>& state) {
    std::shared_ptr<const std::vector<result_t>> results;
    std::string filter;
    std::uint64_t version = 0;
    bool query_to = true;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        results = state->results;
        filter = state->filter;
        version = state->results_version;
        query_to = state->query_to;
        if (!results || (state->visible_results && state->visible_version == version &&
            state->visible_filter == filter))
            return;
    }
    if (state->filtering.exchange(true, std::memory_order_acq_rel))
        return;
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "xref_db_view";
    descriptor.label = "workspace_xref_filter";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, results, filter = std::move(filter),
                                   version, query_to](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::vector<display_result_t> visible;
        visible.reserve((std::min)(results->size(), static_cast<std::size_t>(4096)));
        for (const auto& result : *results) {
            if (cancel.requested.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested())
                break;
            const auto display = query_to ? result.source : result.target;
            const auto runtime = disasm_view::runtime_address(context, display).value_or(
                display.value);
            const std::string name = disasm_view::resolve_name(context, display);
            char address[32]{};
            std::snprintf(address, sizeof(address), "%016llX",
                static_cast<unsigned long long>(runtime));
            if (!filter.empty() && name.find(filter) == std::string::npos &&
                std::string(address).find(filter) == std::string::npos)
                continue;
            char label[256]{};
            std::snprintf(label, sizeof(label), "%016llX  %-10s  %s",
                static_cast<unsigned long long>(runtime), kind_name(result.kind), name.c_str());
            visible.push_back({result, runtime, name, label});
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->results_version == version && std::string(state->filter) == filter) {
                state->visible_results =
                    std::make_shared<const std::vector<display_result_t>>(std::move(visible));
                state->visible_version = version;
                state->visible_filter = filter;
            }
        }
        state->filtering.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->filtering.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = submitted.reject_reason;
    }
}

inline void render(float, float, float width, float height,
                   float alpha, float, float, float,
                   const disasm_view::workspace_context_t& context) {
    if (!context) {
        ImGui::BeginChild("##xref_workspace_empty", ImVec2(width, height), false);
        ImGui::TextUnformatted("No analysis workspace is selected.");
        ImGui::EndChild();
        return;
    }
    if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        ImGui::BeginChild("##xref_live_unsupported", ImVec2(width, height), false);
        ImGui::TextUnformatted("LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
        ImGui::TextWrapped("Live targets support bounded on-demand disassembly and decompilation, not a whole-process xref index.");
        ImGui::EndChild();
        return;
    }
    auto state = state_for(context);
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_xrefs", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));
    bool query_to = true;
    std::array<char, 64> address_input{};
    std::array<char, 128> filter_input{};
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        query_to = state->query_to;
        std::copy(state->address, state->address + sizeof(state->address), address_input.begin());
        std::copy(state->filter, state->filter + sizeof(state->filter), filter_input.begin());
    }
    ImGui::SetNextItemWidth(220.0f);
    const bool enter = ImGui::InputTextWithHint("##xref_address", "Address",
        address_input.data(), address_input.size(), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
	if (ImGui::RadioButton("XRefs To", query_to)) query_to = true;
	ImGui::SameLine();
	if (ImGui::RadioButton("XRefs From", !query_to)) query_to = false;
    ImGui::SameLine();
    const bool index_requested = enter || ImGui::Button("Index");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240.0f);
    ImGui::InputTextWithHint("##xref_filter", "Filter symbols or addresses",
        filter_input.data(), filter_input.size());
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->query_to = query_to;
        std::copy(address_input.begin(), address_input.end(), state->address);
        std::copy(filter_input.begin(), filter_input.end(), state->filter);
    }
    if (index_requested) {
        if (auto value = parse_address(address_input.data())) {
            if (auto address = disasm_view::typed_address(context, *value))
                submit_query(context, state, *address, query_to);
        }
    }
    if (state->searching.load(std::memory_order_acquire)) {
        ImGui::TextUnformatted("Searching the immutable xref publication...");
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->cancellation)
                state->cancellation->request_cancel();
        }
    }
    request_filter(context, state);
    std::shared_ptr<const std::vector<display_result_t>> visible_handle;
    std::string error;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        visible_handle = state->visible_results;
        error = state->error;
    }
    if (!error.empty())
        ImGui::TextWrapped("%s", error.c_str());
    if (state->filtering.load(std::memory_order_acquire))
        ImGui::TextUnformatted("Filtering xref results...");
    static const std::vector<display_result_t> empty_results;
    const auto& visible = visible_handle ? *visible_handle : empty_results;
    ImGui::Separator();
    ImGui::BeginChild("##xref_results", ImVec2(0.0f, 0.0f), false);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>((std::min)(visible.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& result = visible[static_cast<std::size_t>(row)];
            bool selected = false;
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                selected = state->selected_runtime == result.runtime;
            }
            if (ImGui::Selectable(result.label.c_str(), selected,
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    state->selected_runtime = result.runtime;
                }
                disasm_view::select_address(result.runtime, context);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    disasm_view::goto_address(result.runtime, context);
                    aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
                }
            }
            aida::ui::context_menu_open_origin_t origin{};
            const bool pointer = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const bool keyboard = selected &&
                aida::ui::analysis_context_menu::keyboard_request(origin);
			if (pointer || keyboard) {
				using namespace aida::ui::analysis_context_menu;
				using aida::ui::action_handler_result_t;
                context_t menu;
                menu.kind = menu_kind_t::xref;
                const auto generation = context.workspace->generation();
                const auto revision = context.workspace->analysis_revision();
                menu.generation = generation ^ (revision + 0x9E3779B97F4A7C15ull +
                    (generation << 6u) + (generation >> 2u));
                menu.live_generation = [workspace = context.workspace]() {
                    const auto current = workspace->generation();
                    const auto current_revision = workspace->analysis_revision();
                    return current ^ (current_revision + 0x9E3779B97F4A7C15ull +
                        (current << 6u) + (current >> 2u));
                };
                menu.actions["analysis.navigate.disassembly"].invoke = [context, runtime = result.runtime]() {
                    disasm_view::goto_address(runtime, context);
                    aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
                    return action_handler_result_t::completed();
                };
                menu.actions["analysis.navigate.xrefs"].invoke = [context, runtime = result.runtime]() {
                    disasm_view::open_xrefs(runtime, context);
                    return action_handler_result_t::completed();
                };
                menu.actions["analysis.copy.line"].invoke = [value = result.label]() {
                    ImGui::SetClipboardText(value.c_str());
                    return action_handler_result_t::completed();
                };
                menu.actions["analysis.copy.name"].invoke = [value = result.name]() {
                    ImGui::SetClipboardText(value.c_str());
                    return action_handler_result_t::completed();
                };
                char address[32]{};
                std::snprintf(address, sizeof(address), "%016llX",
                    static_cast<unsigned long long>(result.runtime));
                menu.actions["analysis.copy.address"].invoke = [value = std::string(address)]() {
                    ImGui::SetClipboardText(value.c_str());
                    return action_handler_result_t::completed();
                };
                open(std::move(menu), pointer
                    ? aida::ui::context_menu_open_origin_t::pointer : origin);
            }
        }
    }
    aida::ui::analysis_context_menu::render();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b) {
    render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
        disasm_view::capture_selected_workspace());
}

}
