#include "pseudocode_view.hpp"

#include "comment_dialog.hpp"
#include "rename_dialog.hpp"
#include "../ui/theme.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#include "../../helpers/globals.h"

#include "imgui/imgui.h"

#include <algorithm>
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

namespace pseudocode_view {

namespace {

using pseudocode_cache_state_t =
    aida::workbench::pseudocode_document::pseudocode_cache_state_t;
using pseudocode_request_t =
    aida::workbench::pseudocode_document::pseudocode_request_t;

struct tab_t {
    std::uint64_t address = 0;
    std::string label;
    pseudocode_request_t request;
    bool has_request = false;
    std::uint64_t job_id = 0;
    pseudocode_cache_state_t state = pseudocode_cache_state_t::empty;
    std::string error;
    bool error_acknowledged = false;
};

struct state_t {
    std::mutex mutex;
    std::vector<tab_t> tabs;
    int active = -1;
    int selected_line = -1;
    std::uint64_t generation = 0;
};

std::mutex& state_registry_mutex()
{
    static std::mutex value;
    return value;
}

std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
    aida::analysis::binary_id_hash_t>& state_registry()
{
    static std::unordered_map<aida::analysis::binary_id_t,
        std::shared_ptr<state_t>, aida::analysis::binary_id_hash_t> value;
    return value;
}

std::shared_ptr<state_t> state_for(
    const disasm_view::workspace_context_t& context)
{
    if (!context.workspace)
        return {};
    const auto binary_id = context.workspace->identity().binary_id();
    std::lock_guard<std::mutex> lock(state_registry_mutex());
    auto& registry = state_registry();
    const auto found = registry.find(binary_id);
    if (found != registry.end())
        return found->second;
    auto created = std::make_shared<state_t>();
    registry.emplace(binary_id, created);
    return created;
}

std::optional<aida::analysis::address_t> function_address(
    const disasm_view::workspace_context_t& context,
    std::uint64_t address)
{
    const auto function = disasm_view::enclosing_function_start(address, context);
    if (function == 0)
        return std::nullopt;
    return disasm_view::typed_address(context, function);
}

std::uint64_t runtime_address(
    const disasm_view::workspace_context_t& context,
    const aida::analysis::address_t& address)
{
    return disasm_view::runtime_address(context, address).value_or(address.value);
}

std::string label_for(const disasm_view::workspace_context_t& context,
                      std::uint64_t address)
{
    const auto typed = function_address(context, address);
    if (typed) {
        auto label = disasm_view::resolve_name(context, *typed);
        if (!label.empty())
            return label;
    }
    char buffer[40]{};
    std::snprintf(buffer, sizeof(buffer), "sub_%llX",
        static_cast<unsigned long long>(address));
    return buffer;
}

std::optional<std::size_t> find_tab(const state_t& state,
                                    std::uint64_t address)
{
    for (std::size_t index = 0; index < state.tabs.size(); ++index) {
        if (state.tabs[index].address == address)
            return index;
    }
    return std::nullopt;
}

bool workbench_context(
    const disasm_view::workspace_context_t& context,
    aida::workbench::workbench_shell_workspace_context_t& output)
{
    output = {};
    if (!context || !context.workspace || context.workspace->closing() ||
        context.workspace->closed())
        return false;
    return static_cast<bool>(
        aida::workbench::workbench_shell_runtime_t::instance()
            .workspace_context(context.workspace, output));
}

void synchronize_tabs(
    const disasm_view::workspace_context_t& context,
    const aida::workbench::workbench_shell_workspace_context_t& workbench,
    const std::shared_ptr<state_t>& state)
{
    std::lock_guard<std::mutex> lock(state->mutex);
    const auto previous_active =
        state->active >= 0 &&
        static_cast<std::size_t>(state->active) < state->tabs.size()
            ? state->tabs[static_cast<std::size_t>(state->active)].address
            : 0;
    const bool generation_changed =
        state->generation != 0 && state->generation != workbench.analysis_generation;
    std::vector<tab_t> synchronized;
    synchronized.reserve(workbench.persistence.documents.size());
    int active = -1;
    for (const auto& document : workbench.persistence.documents) {
        if (document.identity.kind !=
                aida::workbench::document_kind_t::pseudocode ||
            !document.identity.has_address || document.identity.address == 0)
            continue;
        tab_t tab;
        const auto existing = find_tab(*state, document.identity.address);
        if (existing)
            tab = std::move(state->tabs[*existing]);
        tab.address = document.identity.address;
        tab.label = label_for(context, tab.address);
        if (generation_changed) {
            tab.request = {};
            tab.has_request = false;
            tab.job_id = 0;
            tab.state = pseudocode_cache_state_t::empty;
            tab.error.clear();
            tab.error_acknowledged = false;
        }
        if (document.id == workbench.persistence.active_document)
            active = static_cast<int>(synchronized.size());
        synchronized.push_back(std::move(tab));
    }
    state->tabs = std::move(synchronized);
    state->active = active;
    state->generation = workbench.analysis_generation;
    const auto current_active =
        active >= 0 && static_cast<std::size_t>(active) < state->tabs.size()
            ? state->tabs[static_cast<std::size_t>(active)].address
            : 0;
    if (previous_active != current_active || generation_changed)
        state->selected_line = -1;
}

std::string pseudocode_error_text(
    const aida::workbench::pseudocode_document::pseudocode_error_t& error)
{
    return "decompiler.document.error." +
        std::to_string(static_cast<unsigned>(error.code));
}

std::string first_diagnostic(
    aida::workbench::pseudocode_document::pseudocode_document_model_t& model)
{
    const auto diagnostics = model.diagnostics();
    if (diagnostics.empty())
        return {};
    if (!diagnostics.front().message.empty())
        return diagnostics.front().message;
    return diagnostics.front().localization_key;
}

void refresh_tab_states(
    aida::workbench::pseudocode_document::pseudocode_document_model_t& model,
    const std::shared_ptr<state_t>& state)
{
    std::lock_guard<std::mutex> lock(state->mutex);
    for (auto& tab : state->tabs) {
        if (!tab.has_request)
            continue;
        auto activated = model.activate(tab.request.entity);
        if (!activated) {
            tab.state = pseudocode_cache_state_t::failed;
            tab.error = pseudocode_error_text(activated);
            continue;
        }
        const auto* cached = model.cached_document();
        if (cached && cached->state == pseudocode_cache_state_t::requesting) {
            static_cast<void>(model.poll(cached->job_id));
            static_cast<void>(model.activate(tab.request.entity));
            cached = model.cached_document();
        }
        if (!cached)
            continue;
        tab.job_id = cached->job_id;
        tab.state = cached->state;
        if (tab.state == pseudocode_cache_state_t::failed ||
            tab.state == pseudocode_cache_state_t::stale ||
            tab.state == pseudocode_cache_state_t::cancelled) {
            tab.error = first_diagnostic(model);
            if (tab.error.empty())
                tab.error = "decompiler.document.error." +
                    std::to_string(static_cast<unsigned>(tab.state));
        } else if (tab.state == pseudocode_cache_state_t::cached) {
            tab.error.clear();
            tab.error_acknowledged = false;
        }
    }
    if (state->active >= 0 &&
        static_cast<std::size_t>(state->active) < state->tabs.size()) {
        const auto& active = state->tabs[static_cast<std::size_t>(state->active)];
        if (active.has_request)
            static_cast<void>(model.activate(active.request.entity));
    }
}

disasm_view::workspace_context_t selected_context()
{
    return disasm_view::capture_selected_workspace();
}

std::optional<aida::analysis::address_t> typed_source_address(
    const disasm_view::workspace_context_t& context,
    std::uint64_t address)
{
    if (context.workspace && context.image &&
        context.workspace->identity().target_kind() ==
            aida::analysis::target_kind_t::live_snapshot &&
        address < context.image->image_size() &&
        address <= (std::numeric_limits<std::uint64_t>::max)() -
            context.image->image_base())
        address += context.image->image_base();
    return disasm_view::typed_address(context, address);
}

std::optional<std::uint64_t> line_source_address(
    aida::workbench::pseudocode_document::pseudocode_document_model_t& model,
    const aida::workbench::pseudocode_document::pseudocode_line_view_t& line,
    const aida::workbench::pseudocode_document::pseudocode_page_t& page)
{
    aida::workbench::pseudocode_document::pseudocode_address_map_entry_t mapped;
    if (model.resolve_token(line.text_begin, mapped))
        return mapped.address;
    for (const auto& source_map : page.source_maps) {
        if (source_map.token_end <= line.text_begin ||
            source_map.token_begin >= line.text_end || !source_map.has_address)
            continue;
        return source_map.address;
    }
    return std::nullopt;
}

void navigate_to_disassembly(
    const disasm_view::workspace_context_t& context,
    std::uint64_t source_address)
{
    const auto typed = typed_source_address(context, source_address);
    const auto target = typed ? runtime_address(context, *typed) : source_address;
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::address;
    selection.has_address = true;
    selection.address = target;
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = target;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    static_cast<void>(
        aida::workbench::workbench_shell_runtime_t::instance()
            .navigate_document(context.workspace,
                aida::workbench::document_kind_t::disassembly,
                std::nullopt, selection, cursor, workbench));
    disasm_view::goto_address(target, context);
    globals::ui::active_center_view = center_view_t::disassembly;
}

void persist_line_selection(
    const disasm_view::workspace_context_t& context,
    std::uint64_t document_address,
    const aida::workbench::pseudocode_document::pseudocode_line_view_t& line,
    std::optional<std::uint64_t> source_address)
{
    aida::workbench::selection_context_t selection;
    selection.kind = source_address
        ? aida::workbench::selection_kind_t::address
        : aida::workbench::selection_kind_t::source;
    if (source_address) {
        const auto typed = typed_source_address(context, *source_address);
        selection.has_address = true;
        selection.address = typed ? runtime_address(context, *typed) : *source_address;
    } else {
        selection.entity_key = "pseudocode.line." +
            std::to_string(line.line_number);
    }
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = line.line_number;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    static_cast<void>(
        aida::workbench::workbench_shell_runtime_t::instance()
            .navigate_document(context.workspace,
                aida::workbench::document_kind_t::pseudocode,
                document_address, selection, cursor, workbench));
}

}

void request_decompile(const disasm_view::workspace_context_t& context,
                       std::uint64_t address, bool force_refresh)
{
    if (!context || context.workspace->closing() || context.workspace->closed())
        return;
    const auto typed = function_address(context, address);
    if (!typed)
        return;
    const auto canonical_address = runtime_address(context, *typed);
    auto state = state_for(context);
    if (!state)
        return;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto activated =
        aida::workbench::workbench_shell_runtime_t::instance()
            .activate_document(context.workspace,
                aida::workbench::document_kind_t::pseudocode,
                canonical_address, workbench);
    if (!activated || !workbench.pseudocode_document)
        return;
    synchronize_tabs(context, workbench, state);

    pseudocode_request_t request;
    const auto resolved = workbench.pseudocode_document->resolve_request(
        typed->value, aida::analysis::decompiler_profile_id_t::balanced,
        aida::workbench::pseudocode_document::
            k_pseudocode_document_default_timeout_ms,
        request);
    aida::workbench::pseudocode_document::pseudocode_error_t requested;
    if (resolved)
        requested = workbench.pseudocode_document->request(request, force_refresh);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto index = find_tab(*state, canonical_address);
        if (!index)
            return;
        auto& tab = state->tabs[*index];
        tab.error_acknowledged = false;
        if (!resolved) {
            tab.has_request = false;
            tab.state = pseudocode_cache_state_t::failed;
            tab.error = pseudocode_error_text(resolved);
            return;
        }
        tab.request = request;
        tab.has_request = true;
        if (!requested && requested.code !=
                aida::workbench::pseudocode_document::
                    pseudocode_error_code_t::request_in_progress) {
            tab.state = pseudocode_cache_state_t::failed;
            tab.error = pseudocode_error_text(requested);
            return;
        }
        static_cast<void>(workbench.pseudocode_document->activate(request.entity));
        if (const auto* cached = workbench.pseudocode_document->cached_document()) {
            tab.job_id = cached->job_id;
            tab.state = cached->state;
        }
        tab.error.clear();
    }
}

void request_decompile(std::uint64_t address, const DisasmFile*, bool force_refresh)
{
    request_decompile(selected_context(), address, force_refresh);
}

void close_tab_by_addr(const disasm_view::workspace_context_t& context,
                       std::uint64_t address)
{
    if (!context)
        return;
    const auto typed = function_address(context, address);
    if (!typed)
        return;
    const auto canonical_address = runtime_address(context, *typed);
    aida::workbench::workbench_shell_workspace_context_t workbench;
    if (workbench_context(context, workbench) && workbench.pseudocode_document) {
        auto state = state_for(context);
        if (state) {
            std::lock_guard<std::mutex> lock(state->mutex);
            const auto index = find_tab(*state, canonical_address);
            if (index && state->tabs[*index].has_request &&
                state->tabs[*index].state == pseudocode_cache_state_t::requesting)
                static_cast<void>(workbench.pseudocode_document->cancel(
                    state->tabs[*index].job_id));
        }
    }
    static_cast<void>(
        aida::workbench::workbench_shell_runtime_t::instance()
            .close_document(context.workspace,
                aida::workbench::document_kind_t::pseudocode,
                canonical_address, workbench));
    if (auto state = state_for(context))
        synchronize_tabs(context, workbench, state);
}

void close_active_tab(const disasm_view::workspace_context_t& context)
{
    const auto address = active_tab_address(context);
    if (address != 0)
        close_tab_by_addr(context, address);
}

void close_all_tabs(const disasm_view::workspace_context_t& context)
{
    const auto tabs = snapshot_tabs(context);
    for (const auto& tab : tabs)
        close_tab_by_addr(context, tab.addr);
}

void activate_tab_by_addr(const disasm_view::workspace_context_t& context,
                          std::uint64_t address)
{
    if (!context)
        return;
    const auto typed = function_address(context, address);
    if (!typed)
        return;
    const auto canonical_address = runtime_address(context, *typed);
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto activated =
        aida::workbench::workbench_shell_runtime_t::instance()
            .activate_document(context.workspace,
                aida::workbench::document_kind_t::pseudocode,
                canonical_address, workbench);
    if (!activated)
        return;
    if (auto state = state_for(context)) {
        synchronize_tabs(context, workbench, state);
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto index = find_tab(*state, canonical_address);
        if (index && state->tabs[*index].has_request &&
            workbench.pseudocode_document)
            static_cast<void>(workbench.pseudocode_document->activate(
                state->tabs[*index].request.entity));
    }
}

void cancel_active_decompile(const disasm_view::workspace_context_t& context)
{
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench) ||
        !workbench.pseudocode_document)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->active < 0 ||
        static_cast<std::size_t>(state->active) >= state->tabs.size())
        return;
    auto& tab = state->tabs[static_cast<std::size_t>(state->active)];
    if (!tab.has_request || tab.state != pseudocode_cache_state_t::requesting)
        return;
    static_cast<void>(workbench.pseudocode_document->activate(tab.request.entity));
    const auto cancelled = workbench.pseudocode_document->cancel(tab.job_id);
    if (cancelled)
        tab.state = pseudocode_cache_state_t::cancelled;
}

void refresh_active_tab(const disasm_view::workspace_context_t& context)
{
    const auto address = active_tab_address(context);
    if (address != 0)
        request_decompile(context, address, true);
}

void refresh_all_tabs(const disasm_view::workspace_context_t& context)
{
    const auto tabs = snapshot_tabs(context);
    for (const auto& tab : tabs)
        request_decompile(context, tab.addr, true);
}

bool has_active_tab(const disasm_view::workspace_context_t& context)
{
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench))
        return false;
    synchronize_tabs(context, workbench, state);
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->active >= 0 &&
        static_cast<std::size_t>(state->active) < state->tabs.size();
}

bool has_tab_for(const disasm_view::workspace_context_t& context,
                 std::uint64_t address)
{
    const auto typed = function_address(context, address);
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!typed || !state || !workbench_context(context, workbench))
        return false;
    synchronize_tabs(context, workbench, state);
    std::lock_guard<std::mutex> lock(state->mutex);
    return find_tab(*state, runtime_address(context, *typed)).has_value();
}

std::uint64_t active_tab_address(const disasm_view::workspace_context_t& context)
{
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench))
        return 0;
    synchronize_tabs(context, workbench, state);
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->active < 0 ||
        static_cast<std::size_t>(state->active) >= state->tabs.size())
        return 0;
    return state->tabs[static_cast<std::size_t>(state->active)].address;
}

int tab_count(const disasm_view::workspace_context_t& context)
{
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench))
        return 0;
    synchronize_tabs(context, workbench, state);
    std::lock_guard<std::mutex> lock(state->mutex);
    return static_cast<int>((std::min)(state->tabs.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)())));
}

std::vector<tab_info_t> snapshot_tabs(
    const disasm_view::workspace_context_t& context)
{
    std::vector<tab_info_t> output;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench))
        return output;
    synchronize_tabs(context, workbench, state);
    if (workbench.pseudocode_document)
        refresh_tab_states(*workbench.pseudocode_document, state);
    std::lock_guard<std::mutex> lock(state->mutex);
    output.reserve(state->tabs.size());
    for (const auto& tab : state->tabs) {
        tab_info_t info;
        info.addr = tab.address;
        info.label = tab.label;
        info.function_name = tab.label;
        info.loaded = tab.state == pseudocode_cache_state_t::cached;
        info.decompiling = tab.state == pseudocode_cache_state_t::requesting;
        info.is_error = tab.state == pseudocode_cache_state_t::failed ||
                        tab.state == pseudocode_cache_state_t::stale;
        output.push_back(std::move(info));
    }
    return output;
}

void render(float, float, float width, float height,
            float alpha, float, float, float,
            const disasm_view::workspace_context_t& context)
{
    if (!context) {
        ImGui::BeginChild("##workspace_pseudocode_empty", ImVec2(width, height), false);
        ImGui::TextUnformatted("No analysis workspace is selected.");
        ImGui::EndChild();
        return;
    }
    aida::workbench::workbench_shell_workspace_context_t workbench;
    auto state = state_for(context);
    if (!state || !workbench_context(context, workbench) ||
        !workbench.pseudocode_document)
        return;
    synchronize_tabs(context, workbench, state);
    refresh_tab_states(*workbench.pseudocode_document, state);

    std::uint64_t lazy_address = 0;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->active >= 0 &&
            static_cast<std::size_t>(state->active) < state->tabs.size() &&
            !state->tabs[static_cast<std::size_t>(state->active)].has_request)
            lazy_address = state->tabs[static_cast<std::size_t>(state->active)].address;
    }
    if (lazy_address != 0) {
        request_decompile(context, lazy_address, false);
        if (!workbench_context(context, workbench) ||
            !workbench.pseudocode_document)
            return;
        synchronize_tabs(context, workbench, state);
        refresh_tab_states(*workbench.pseudocode_document, state);
    }

    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_pseudocode", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text,
        aida::ui::with_alpha(theme.text_primary, alpha));

    const auto tabs = snapshot_tabs(context);
    int active = -1;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        active = state->active;
    }
    std::optional<std::uint64_t> activate_address;
    std::optional<std::uint64_t> close_address;
    for (std::size_t index = 0; index < tabs.size(); ++index) {
        if (index != 0)
            ImGui::SameLine();
        ImGui::PushID(static_cast<int>(index));
        const std::string label = tabs[index].label +
            (tabs[index].decompiling ? "  *" : tabs[index].is_error ? "  !" : "");
        if (ImGui::Selectable(label.c_str(), active == static_cast<int>(index),
                0, ImVec2(0.0f, ImGui::GetFrameHeight())))
            activate_address = tabs[index].addr;
        ImGui::SameLine();
        if (ImGui::SmallButton("x"))
            close_address = tabs[index].addr;
        ImGui::PopID();
        if (close_address)
            break;
    }
    if (activate_address)
        activate_tab_by_addr(context, *activate_address);
    if (close_address)
        close_tab_by_addr(context, *close_address);

    ImGui::Separator();
    if (ImGui::Button("Refresh"))
        refresh_active_tab(context);
    ImGui::SameLine();
    if (ImGui::Button("Cancel"))
        cancel_active_decompile(context);
    ImGui::SameLine();
    if (ImGui::Button("Disasm")) {
        const auto address = active_tab_address(context);
        if (address != 0)
            navigate_to_disassembly(context, address);
    }

    tab_t active_tab;
    bool has_active = false;
    int selected_line = -1;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->active >= 0 &&
            static_cast<std::size_t>(state->active) < state->tabs.size()) {
            active_tab = state->tabs[static_cast<std::size_t>(state->active)];
            has_active = true;
            selected_line = state->selected_line;
        }
    }

    const aida::workbench::pseudocode_document::pseudocode_cached_document_t* cached = nullptr;
    if (has_active && active_tab.has_request &&
        workbench.pseudocode_document->activate(active_tab.request.entity))
        cached = workbench.pseudocode_document->cached_document();
    const auto status = cached ? cached->state : active_tab.state;
    const auto diagnostics = workbench.pseudocode_document->diagnostics();
    std::string error = active_tab.error;
    if (error.empty() && !diagnostics.empty())
        error = diagnostics.front().message.empty()
            ? diagnostics.front().localization_key
            : diagnostics.front().message;

    if (cached && cached->document &&
        status == pseudocode_cache_state_t::cached && ImGui::Button("Copy"))
        ImGui::SetClipboardText(cached->document->rendered_text.c_str());
    if ((status == pseudocode_cache_state_t::failed ||
         status == pseudocode_cache_state_t::stale ||
         status == pseudocode_cache_state_t::cancelled) &&
        ImGui::Button("Retry"))
        refresh_active_tab(context);
    if ((status == pseudocode_cache_state_t::failed ||
         status == pseudocode_cache_state_t::stale ||
         status == pseudocode_cache_state_t::cancelled) &&
        !active_tab.error_acknowledged) {
        ImGui::SameLine();
        if (ImGui::Button("OK")) {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->active >= 0 &&
                static_cast<std::size_t>(state->active) < state->tabs.size())
                state->tabs[static_cast<std::size_t>(state->active)]
                    .error_acknowledged = true;
            active_tab.error_acknowledged = true;
        }
    }
    if (!diagnostics.empty() && ImGui::CollapsingHeader("Diagnostics")) {
        for (const auto& diagnostic : diagnostics) {
            const auto& message = diagnostic.message.empty()
                ? diagnostic.localization_key : diagnostic.message;
            ImGui::TextWrapped("%s",
                message.empty() ? "decompiler_diagnostic" : message.c_str());
        }
    }

    if (!has_active || tabs.empty()) {
        ImGui::TextUnformatted("Press F5 in disassembly or choose Decompile function.");
    } else if (status == pseudocode_cache_state_t::requesting ||
               status == pseudocode_cache_state_t::empty) {
        ImGui::TextUnformatted("Decompiling the selected function...");
    } else if (status == pseudocode_cache_state_t::cancelled) {
        ImGui::TextUnformatted(error.empty()
            ? "Decompilation was cancelled." : error.c_str());
    } else if (status == pseudocode_cache_state_t::failed ||
               status == pseudocode_cache_state_t::stale || !cached ||
               !cached->document) {
        if (!active_tab.error_acknowledged)
            ImGui::TextWrapped("%s", error.empty()
                ? "Decompilation failed without a result." : error.c_str());
        else
            ImGui::TextUnformatted(
                "The decompilation error was acknowledged. Press Retry to run it again.");
    } else {
        ImGui::BeginChild("##pseudocode_lines", ImVec2(0.0f, 0.0f), false,
            ImGuiWindowFlags_HorizontalScrollbar);
        aida::workbench::pseudocode_document::pseudocode_page_t first_page;
        const auto first_page_error = workbench.pseudocode_document->page(
            {0, 1}, first_page);
        const auto line_count = first_page_error
            ? static_cast<int>((std::min)(
                first_page.total_lines,
                static_cast<std::uint32_t>((std::numeric_limits<int>::max)())))
            : 0;
        ImGuiListClipper clipper;
        clipper.Begin(line_count, ImGui::GetTextLineHeightWithSpacing());
        while (clipper.Step()) {
            auto first = static_cast<std::uint32_t>(clipper.DisplayStart);
            const auto end = static_cast<std::uint32_t>(clipper.DisplayEnd);
            while (first < end) {
                const auto count = (std::min)(
                    end - first,
                    aida::workbench::pseudocode_document::
                        k_pseudocode_document_max_page_lines);
                aida::workbench::pseudocode_document::pseudocode_page_t page;
                if (!workbench.pseudocode_document->page({first, count}, page))
                    break;
                for (const auto& line : page.lines) {
                    const auto line_index = static_cast<int>(line.line_number - 1U);
                    const auto source_address = line_source_address(
                        *workbench.pseudocode_document, line, page);
                    ImGui::PushID(line_index);
                    if (ImGui::Selectable("##pseudocode_line",
                            selected_line == line_index,
                            ImGuiSelectableFlags_AllowDoubleClick,
                            ImVec2(0.0f,
                                ImGui::GetTextLineHeightWithSpacing()))) {
                        {
                            std::lock_guard<std::mutex> lock(state->mutex);
                            state->selected_line = line_index;
                        }
                        selected_line = line_index;
                        aida::workbench::pseudocode_document::pseudocode_selection_t selection;
                        selection.line_number = line.line_number;
                        if (source_address) {
                            selection.kind = aida::workbench::selection_kind_t::address;
                            selection.has_address = true;
                            selection.address = *source_address;
                            selection.token_begin = line.text_begin;
                            selection.token_end = (std::max)(
                                line.text_end, line.text_begin + 1U);
                        } else if (line.text_end > line.text_begin) {
                            selection.kind = aida::workbench::selection_kind_t::source;
                            selection.token_begin = line.text_begin;
                            selection.token_end = line.text_end;
                        }
                        if (selection.kind != aida::workbench::selection_kind_t::none)
                            static_cast<void>(
                                workbench.pseudocode_document->select(selection));
                        persist_line_selection(context, active_tab.address, line,
                            source_address);
                        if (source_address &&
                            ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                            navigate_to_disassembly(context, *source_address);
                    }
                    ImGui::SameLine(0.0f, 0.0f);
                    ImGui::TextUnformatted(line.text.c_str());
                    if (ImGui::BeginPopupContextItem("##pseudocode_actions")) {
                        if (ImGui::MenuItem("Copy line"))
                            ImGui::SetClipboardText(line.text.c_str());
                        if (source_address && ImGui::MenuItem("Go to disassembly"))
                            navigate_to_disassembly(context, *source_address);
                        const auto typed = source_address
                            ? typed_source_address(context, *source_address)
                            : std::nullopt;
                        if (typed && ImGui::MenuItem("Rename"))
                            rename_dialog::open(context, *typed);
                        if (typed && ImGui::MenuItem("Edit comment"))
                            comment_dialog::open(context, *typed);
                        ImGui::EndPopup();
                    }
                    ImGui::PopID();
                }
                first += count;
            }
        }
        ImGui::EndChild();
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_F5, false))
        refresh_active_tab(context);
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
    comment_dialog::render();
    rename_dialog::render();
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
        selected_context());
}

void close_active_tab() { close_active_tab(selected_context()); }
void close_all_tabs() { close_all_tabs(selected_context()); }
void close_tab_by_addr(std::uint64_t address)
{
    close_tab_by_addr(selected_context(), address);
}
void activate_tab_by_addr(std::uint64_t address)
{
    activate_tab_by_addr(selected_context(), address);
}
void cancel_active_decompile() { cancel_active_decompile(selected_context()); }
void refresh_active_tab() { refresh_active_tab(selected_context()); }
void refresh_all_tabs() { refresh_all_tabs(selected_context()); }
bool has_active_tab() { return has_active_tab(selected_context()); }
bool has_tab_for(std::uint64_t address)
{
    return has_tab_for(selected_context(), address);
}
std::uint64_t active_tab_address()
{
    return active_tab_address(selected_context());
}
int tab_count() { return tab_count(selected_context()); }
std::vector<tab_info_t> snapshot_tabs()
{
    return snapshot_tabs(selected_context());
}

}
