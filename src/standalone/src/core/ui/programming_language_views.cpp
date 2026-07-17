#include "programming_language_views.hpp"

#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "../editor/programming_language_service.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

namespace aida::ui::programming_language_views {
namespace {

namespace language = aida::editor::language_service;

struct surface_state_t {
    char filter[256] = {};
    std::uint64_t request_id = 0;
    std::uint64_t request_generation = 0;
    std::string applied_filter;
    std::vector<std::size_t> visible;
    int selected = -1;
};

struct rename_dialog_state_t {
    bool requested = false;
    bool focus_replacement = false;
    char identifier[256] = {};
    char replacement[256] = {};
    std::string error;
};

surface_state_t& outline_state()
{
    static surface_state_t value;
    return value;
}

surface_state_t& references_state()
{
    static surface_state_t value;
    return value;
}

rename_dialog_state_t& rename_dialog_state()
{
    static rename_dialog_state_t value;
    return value;
}

bool contains_folded(const std::string& text, const std::string& query)
{
    if (query.empty())
        return true;
    auto found = std::search(text.begin(), text.end(), query.begin(), query.end(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        });
    return found != text.end();
}

void render_index_status()
{
    const auto publication = language::workspace_index_snapshot();
    const std::string status = language::workspace_index_status();
    ImGui::TextUnformatted("Workspace Text Index");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", status.c_str());
    if (publication) {
        const std::string skipped = publication->skipped_files != 0
            ? "  [skipped " + std::to_string(publication->skipped_files) + "]"
            : std::string{};
        ImGui::SameLine();
        ImGui::TextDisabled("Gen %llu  %zu files  %.1f MiB%s%s",
            static_cast<unsigned long long>(publication->generation),
            publication->indexed_files,
            static_cast<double>(publication->indexed_bytes) / (1024.0 * 1024.0),
            publication->truncated ? "  [bounded]" : "", skipped.c_str());
    }
    ImGui::TextDisabled("Published workspace files only; unsaved editor changes require Save and Rebuild.");
}

bool action_button(const char* action_id, const char* compact_label)
{
    const auto presentation = application_ui::present_action(action_id);
    if (!presentation.visible)
        return false;
    if (!presentation.enabled)
        ImGui::BeginDisabled();
    const bool invoked = ImGui::SmallButton(compact_label && compact_label[0]
        ? compact_label : presentation.label.c_str());
    if (!presentation.enabled)
        ImGui::EndDisabled();
    if (!presentation.enabled &&
        ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
        !presentation.disabled_reason.empty())
        ImGui::SetTooltip("%s", presentation.disabled_reason.c_str());
    if (invoked)
        static_cast<void>(application_ui::execute_action(action_id,
            action_invocation_source_t::toolbar));
    return invoked;
}

void render_result_state(const language::query_snapshot_t& snapshot,
    const char* empty_title, const char* empty_hint)
{
    design::state_presentation_t state;
    state.stable_id = "programming.language.state";
    state.title = empty_title;
    state.hint = empty_hint;
    if (!snapshot) {
        state.state = design::view_state_t::empty;
        state.message = "No provider query has been published for this view.";
    } else {
        state.message = snapshot->status.c_str();
        state.target = snapshot->provider_name.c_str();
        switch (snapshot->state) {
        case language::result_state_t::loading:
            state.state = design::view_state_t::loading;
            state.title = "Querying language provider";
            break;
        case language::result_state_t::cancelled:
            state.state = design::view_state_t::empty;
            state.title = "Query cancelled";
            break;
        case language::result_state_t::error:
            state.state = design::view_state_t::error;
            state.title = "Language provider failed";
            break;
        case language::result_state_t::unavailable:
            state.state = design::view_state_t::disconnected;
            state.title = "Capability unavailable";
            break;
        case language::result_state_t::empty:
        case language::result_state_t::ready:
            state.state = design::view_state_t::empty;
            break;
        }
    }
    static_cast<void>(design::render_state(state, ImVec2(0.0f, 120.0f)));
}

template <typename Predicate>
void rebuild_visible(surface_state_t& view, const language::query_result_t& result,
    std::size_t count, Predicate&& predicate)
{
    const std::string filter(view.filter);
    if (view.request_id == result.request_id &&
        view.request_generation == result.request_generation &&
        view.applied_filter == filter)
        return;
    view.request_id = result.request_id;
    view.request_generation = result.request_generation;
    view.applied_filter = filter;
    view.visible.clear();
    view.visible.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
        if (predicate(index, filter))
            view.visible.push_back(index);
    if (view.selected >= static_cast<int>(view.visible.size()))
        view.selected = view.visible.empty() ? -1 : static_cast<int>(view.visible.size() - 1);
}

void handle_keyboard_selection(surface_state_t& view, std::size_t count)
{
    if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) || count == 0)
        return;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false))
        view.selected = (std::min)(static_cast<int>(count) - 1, view.selected + 1);
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false))
        view.selected = (std::max)(0, view.selected - 1);
    if (ImGui::IsKeyPressed(ImGuiKey_Home, false))
        view.selected = 0;
    if (ImGui::IsKeyPressed(ImGuiKey_End, false))
        view.selected = static_cast<int>(count) - 1;
}

void open_context(const language::location_t& location, std::string label,
    const language::query_result_t& result, context_menu_open_origin_t origin)
{
    application_ui::open_programming_result_context_menu(location,
        std::move(label), result.provider_name, result.kind, result.request_id,
        result.request_generation, result.provider_generation,
        result.index_generation, origin);
}

context_menu_open_origin_t keyboard_context_origin()
{
    return ImGui::IsKeyPressed(ImGuiKey_Menu, false)
        ? context_menu_open_origin_t::menu_key
        : context_menu_open_origin_t::shift_f10;
}

void render_outline_rows(const language::query_snapshot_t& snapshot)
{
    auto& view = outline_state();
    rebuild_visible(view, *snapshot, snapshot->symbols.size(),
        [&](std::size_t index, const std::string& filter) {
            const auto& symbol = snapshot->symbols[index];
            return contains_folded(symbol.name, filter) ||
                contains_folded(symbol.kind, filter);
        });
    handle_keyboard_selection(view, view.visible.size());
    if (design::begin_expert_table("programming.outline.table", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch, 0.58f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 88.0f);
        ImGui::TableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, 58.0f);
        ImGui::TableHeadersRow();
        design::render_clipped_rows(view.visible.size(), design::metrics().table_row_height,
            [&](std::size_t visible_index) {
                const auto& symbol = snapshot->symbols[view.visible[visible_index]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(visible_index));
                const bool selected = view.selected == static_cast<int>(visible_index);
                if (ImGui::Selectable(symbol.name.c_str(), selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    view.selected = static_cast<int>(visible_index);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        static_cast<void>(language::open_location(symbol.location));
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    open_context(symbol.location, symbol.name,
                        *snapshot, context_menu_open_origin_t::pointer);
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%s", symbol.kind.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%d", symbol.location.line);
            });
        design::end_expert_table();
    }
    if (view.selected >= 0 && static_cast<std::size_t>(view.selected) < view.visible.size()) {
        const auto& symbol = snapshot->symbols[view.visible[static_cast<std::size_t>(view.selected)]];
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
            static_cast<void>(language::open_location(symbol.location));
        if (design::selection_context_requested())
            open_context(symbol.location, symbol.name, *snapshot,
                keyboard_context_origin());
    }
}

void render_reference_rows(const language::query_snapshot_t& snapshot)
{
    auto& view = references_state();
    rebuild_visible(view, *snapshot, snapshot->locations.size(),
        [&](std::size_t index, const std::string& filter) {
            const auto& location = snapshot->locations[index];
            return contains_folded(location.file_path, filter) ||
                contains_folded(location.preview, filter);
        });
    handle_keyboard_selection(view, view.visible.size());
    if (design::begin_expert_table("programming.references.table", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, 78.0f);
        ImGui::TableSetupColumn("Preview", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        design::render_clipped_rows(view.visible.size(), design::metrics().table_row_height,
            [&](std::size_t visible_index) {
                const auto& location = snapshot->locations[view.visible[visible_index]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(visible_index));
                const std::string leaf = std::filesystem::path(location.file_path).filename().string();
                const bool selected = view.selected == static_cast<int>(visible_index);
                if (ImGui::Selectable(leaf.c_str(), selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    view.selected = static_cast<int>(visible_index);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        static_cast<void>(language::open_location(location));
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    open_context(location, snapshot->query_text,
                        *snapshot, context_menu_open_origin_t::pointer);
                }
                ImGui::PopID();
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", location.file_path.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%d:%d", location.line, location.column);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(location.preview.c_str());
            });
        design::end_expert_table();
    }
    if (view.selected >= 0 && static_cast<std::size_t>(view.selected) < view.visible.size()) {
        const auto& location = snapshot->locations[view.visible[static_cast<std::size_t>(view.selected)]];
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
            static_cast<void>(language::open_location(location));
        if (design::selection_context_requested())
            open_context(location, snapshot->query_text, *snapshot,
                keyboard_context_origin());
    }
}

void render_completion_rows(const language::query_snapshot_t& snapshot)
{
    if (!design::begin_expert_table("programming.completions.table", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail()))
        return;
    ImGui::TableSetupColumn("Completion", ImGuiTableColumnFlags_WidthStretch, 0.45f);
    ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 90.0f);
    ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.55f);
    ImGui::TableHeadersRow();
    design::render_clipped_rows(snapshot->completions.size(),
        design::metrics().table_row_height, [&](std::size_t index) {
            const auto& item = snapshot->completions[index];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(item.label.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s%s", item.kind.c_str(), item.snippet ? " snippet" : "");
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(item.detail.c_str());
        });
    design::end_expert_table();
}

void render_information_rows(const language::query_snapshot_t& snapshot)
{
    if (!design::begin_expert_table("programming.information.table", 2,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail()))
        return;
    ImGui::TableSetupColumn("Item", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Information", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    design::render_clipped_rows(snapshot->information.size(),
        design::metrics().table_row_height, [&](std::size_t index) {
            const auto& item = snapshot->information[index];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(item.label.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(item.content.c_str());
        });
    design::end_expert_table();
}

void render_diagnostic_rows(const language::query_snapshot_t& snapshot)
{
    auto& view = references_state();
    rebuild_visible(view, *snapshot, snapshot->diagnostics.size(),
        [&](std::size_t index, const std::string& filter) {
            const auto& diagnostic = snapshot->diagnostics[index];
            return contains_folded(diagnostic.message, filter) ||
                contains_folded(diagnostic.location.file_path, filter) ||
                contains_folded(diagnostic.severity, filter) ||
                contains_folded(diagnostic.source, filter);
        });
    handle_keyboard_selection(view, view.visible.size());
    if (design::begin_expert_table("programming.diagnostics.table", 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 78.0f);
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, 78.0f);
        ImGui::TableSetupColumn("Message", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        design::render_clipped_rows(view.visible.size(), design::metrics().table_row_height,
            [&](std::size_t visible_index) {
                const auto& diagnostic = snapshot->diagnostics[view.visible[visible_index]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(visible_index));
                const bool selected = view.selected == static_cast<int>(visible_index);
                if (ImGui::Selectable(diagnostic.severity.c_str(), selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    view.selected = static_cast<int>(visible_index);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        static_cast<void>(language::open_location(diagnostic.location));
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                    open_context(diagnostic.location, diagnostic.message, *snapshot,
                        context_menu_open_origin_t::pointer);
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(std::filesystem::path(
                    diagnostic.location.file_path).filename().string().c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%d:%d", diagnostic.location.line,
                    diagnostic.location.column);
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(diagnostic.message.c_str());
            });
        design::end_expert_table();
    }
    if (view.selected >= 0 && static_cast<std::size_t>(view.selected) < view.visible.size()) {
        const auto& diagnostic = snapshot->diagnostics[
            view.visible[static_cast<std::size_t>(view.selected)]];
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
            static_cast<void>(language::open_location(diagnostic.location));
        if (design::selection_context_requested())
            open_context(diagnostic.location, diagnostic.message, *snapshot,
                keyboard_context_origin());
    }
}

language::location_t edit_location(const language::text_edit_t& edit,
    const language::query_result_t& result)
{
    language::location_t location;
    location.root_path = result.root_path;
    location.file_path = edit.file_path;
    location.line = edit.range.start.line;
    location.column = edit.range.start.column;
    location.match_length = (std::max)(0,
        edit.range.end.column - edit.range.start.column);
    location.preview = edit.expected_text;
    return location;
}

void render_edit_rows(const language::query_snapshot_t& snapshot)
{
    auto& view = references_state();
    rebuild_visible(view, *snapshot, snapshot->proposed_edits.size(),
        [&](std::size_t index, const std::string& filter) {
            const auto& edit = snapshot->proposed_edits[index];
            return contains_folded(edit.file_path, filter) ||
                contains_folded(edit.expected_text, filter) ||
                contains_folded(edit.replacement_text, filter);
        });
    handle_keyboard_selection(view, view.visible.size());
    if (design::begin_expert_table("programming.edits.table", 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Range", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Expected", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Replacement", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableHeadersRow();
        design::render_clipped_rows(view.visible.size(), design::metrics().table_row_height,
            [&](std::size_t visible_index) {
                const auto& edit = snapshot->proposed_edits[view.visible[visible_index]];
                const auto location = edit_location(edit, *snapshot);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(visible_index));
                const bool selected = view.selected == static_cast<int>(visible_index);
                if (ImGui::Selectable(std::filesystem::path(edit.file_path).filename().string().c_str(),
                    selected, ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                    view.selected = static_cast<int>(visible_index);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                        static_cast<void>(language::open_location(location));
                }
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                    open_context(location, "Proposed edit", *snapshot,
                        context_menu_open_origin_t::pointer);
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%d:%d-%d:%d", edit.range.start.line,
                    edit.range.start.column, edit.range.end.line, edit.range.end.column);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(edit.expected_text.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(edit.replacement_text.c_str());
            });
        design::end_expert_table();
    }
    if (view.selected >= 0 && static_cast<std::size_t>(view.selected) < view.visible.size()) {
        const auto& edit = snapshot->proposed_edits[
            view.visible[static_cast<std::size_t>(view.selected)]];
        const auto location = edit_location(edit, *snapshot);
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false))
            static_cast<void>(language::open_location(location));
        if (design::selection_context_requested())
            open_context(location, "Proposed edit", *snapshot,
                keyboard_context_origin());
    }
}

void render_code_action_rows(const language::query_snapshot_t& snapshot)
{
    if (!design::begin_expert_table("programming.code_actions.table", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImGui::GetContentRegionAvail()))
        return;
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch, 0.45f);
    ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 120.0f);
    ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.55f);
    ImGui::TableHeadersRow();
    design::render_clipped_rows(snapshot->code_actions.size(),
        design::metrics().table_row_height, [&](std::size_t index) {
            const auto& action = snapshot->code_actions[index];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(action.title.c_str());
            if (action.preferred) {
                ImGui::SameLine();
                ImGui::TextDisabled("preferred");
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s", action.kind.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(action.disabled_reason.empty()
                ? action.detail.c_str() : action.disabled_reason.c_str());
        });
    design::end_expert_table();
}

language::query_snapshot_t latest_result(
    std::initializer_list<language::capability_kind_t> kinds)
{
    language::query_snapshot_t latest;
    for (const auto kind : kinds) {
        const auto candidate = language::result(kind);
        if (candidate && (!latest || candidate->request_id > latest->request_id))
            latest = candidate;
    }
    return latest;
}

void render_rename_dialog()
{
    auto& dialog = rename_dialog_state();
    if (dialog.requested) {
        dialog.requested = false;
        ImGui::OpenPopup("Semantic Rename###programming.language.rename.dialog");
    }
    ImGui::SetNextWindowSizeConstraints(ImVec2(360.0f, 0.0f), ImVec2(680.0f, 420.0f));
    if (!ImGui::BeginPopupModal("Semantic Rename###programming.language.rename.dialog",
            nullptr, ImGuiWindowFlags_AlwaysAutoResize))
        return;
    ImGui::TextUnformatted("Provider-reviewed semantic rename");
    ImGui::TextDisabled("The provider must return revision-bound proposed edits. AiDA does not apply them automatically.");
    ImGui::Separator();
    ImGui::TextUnformatted("Identifier");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("##programming_rename_identifier", dialog.identifier,
        sizeof(dialog.identifier), ImGuiInputTextFlags_ReadOnly);
    ImGui::TextUnformatted("New name");
    ImGui::SetNextItemWidth(-1.0f);
    if (dialog.focus_replacement) {
        ImGui::SetKeyboardFocusHere();
        dialog.focus_replacement = false;
    }
    const bool submitted = ImGui::InputText("##programming_rename_replacement",
        dialog.replacement, sizeof(dialog.replacement), ImGuiInputTextFlags_EnterReturnsTrue);
    if (!dialog.error.empty())
        ImGui::TextColored(ImVec4(0.95f, 0.38f, 0.35f, 1.0f), "%s", dialog.error.c_str());
    ImGui::Separator();
    if (ImGui::Button("Cancel")) {
        dialog.error.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    const bool request_edits = ImGui::Button("Request reviewed edits") || submitted;
    if (request_edits) {
        const std::string identifier(dialog.identifier);
        const std::string replacement(dialog.replacement);
        if (identifier.empty()) {
            dialog.error = "The caret identifier is no longer available; close and retry from the editor.";
        } else if (replacement.empty()) {
            dialog.error = "Enter a non-empty replacement name.";
        } else if (replacement == identifier) {
            dialog.error = "The replacement must differ from the current identifier.";
        } else {
            language::query_t query;
            query.kind = language::capability_kind_t::semantic_rename;
            query.document = language::active_document_context();
            query.text = identifier;
            query.replacement_text = replacement;
            query.maximum_results = 4096;
            const auto requested = language::request(std::move(query));
            if (!requested.accepted) {
                dialog.error = requested.reason;
            } else {
                dialog.error.clear();
                ImGui::CloseCurrentPopup();
            }
        }
    }
    ImGui::EndPopup();
}

}

void open_rename_dialog()
{
    auto& dialog = rename_dialog_state();
    const std::string identifier = language::active_query_text();
    std::snprintf(dialog.identifier, sizeof(dialog.identifier), "%s", identifier.c_str());
    dialog.replacement[0] = '\0';
    dialog.error.clear();
    dialog.focus_replacement = true;
    dialog.requested = true;
}

void render_outline()
{
    const auto document = language::active_document_context();
    auto snapshot = latest_result({language::capability_kind_t::document_symbols,
        language::capability_kind_t::workspace_symbols});
    if (snapshot && snapshot->kind == language::capability_kind_t::document_symbols &&
        (snapshot->document_id != document.document_id ||
         snapshot->document_path != document.file_path)) {
        auto unavailable = std::make_shared<language::query_result_t>();
        unavailable->state = language::result_state_t::unavailable;
        unavailable->kind = language::capability_kind_t::document_symbols;
        unavailable->document_id = document.document_id;
        unavailable->document_revision = document.revision;
        unavailable->document_path = document.file_path;
        const auto capability = language::capability(
            language::capability_kind_t::document_symbols, document);
        unavailable->status = capability.available
            ? "The Programming Outline is waiting for the active document query"
            : capability.reason;
        snapshot = std::move(unavailable);
    }
    const std::string breadcrumb = document.file_path.empty()
        ? "Programming / Plain Text" : "Programming / " +
            std::filesystem::path(document.file_path).filename().string();
    const design::header_t header{"programming.outline.header", "Programming Outline",
        breadcrumb.c_str(), snapshot ? snapshot->provider_name.c_str() : "No provider", nullptr,
        snapshot && snapshot->state == language::result_state_t::ready
            ? design::semantic_t::success : design::semantic_t::neutral};
    static_cast<void>(design::render_view_header(header));
    render_index_status();
    action_button("programming.index.rebuild", "Rebuild");
    ImGui::SameLine();
    action_button("programming.index.cancel", "Cancel");
    ImGui::SameLine();
    ImGui::SetNextItemWidth((std::max)(160.0f, ImGui::GetContentRegionAvail().x));
    ImGui::InputTextWithHint("##programming_outline_filter", "Filter symbols...",
        outline_state().filter, sizeof(outline_state().filter));
    if (!snapshot || snapshot->state != language::result_state_t::ready) {
        render_result_state(snapshot, "No document symbols", "Open a C or C++ source file, then rebuild the Workspace Text Index.");
        application_ui::render_programming_result_context_menu();
        return;
    }
    if (snapshot->truncated) {
        ImGui::TextColored(ImVec4(0.95f, 0.68f, 0.24f, 1.0f),
            "Bounded result: additional symbols may exist outside this publication.");
    }
    render_outline_rows(snapshot);
    application_ui::render_programming_result_context_menu();
}

void render_references()
{
    render_rename_dialog();
    auto snapshot = latest_result({language::capability_kind_t::references,
        language::capability_kind_t::definition,
        language::capability_kind_t::completion,
        language::capability_kind_t::hover,
        language::capability_kind_t::signature_help,
        language::capability_kind_t::diagnostics,
        language::capability_kind_t::semantic_rename,
        language::capability_kind_t::formatting,
        language::capability_kind_t::code_actions});
    const design::header_t header{"programming.references.header", "Programming References",
        "Programming / Provider Results",
        snapshot ? snapshot->provider_name.c_str() : "Workspace Text Index", "Shift+F12",
        snapshot && snapshot->state == language::result_state_t::ready
            ? design::semantic_t::success : design::semantic_t::neutral};
    static_cast<void>(design::render_view_header(header));
    render_index_status();
    auto& view = references_state();
    if (snapshot && snapshot->request_id != view.request_id &&
        !snapshot->query_text.empty())
        std::snprintf(view.filter, sizeof(view.filter), "%s",
            snapshot->query_text.c_str());
    ImGui::SetNextItemWidth((std::max)(180.0f, ImGui::GetContentRegionAvail().x - 138.0f));
    const bool submitted = ImGui::InputTextWithHint("##programming_reference_query",
        "Identifier or text...", view.filter, sizeof(view.filter),
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    const bool find = ImGui::SmallButton("Find");
    ImGui::SameLine();
    action_button("programming.language.cancel_query", "Cancel");
    if (submitted || find) {
        language::query_t query;
        query.kind = language::capability_kind_t::references;
        query.document = language::active_document_context();
        query.text = view.filter;
        query.maximum_results = 4096;
        static_cast<void>(language::request(std::move(query)));
        snapshot = language::result(language::capability_kind_t::references);
    }
    if (!snapshot || snapshot->state != language::result_state_t::ready) {
        render_result_state(snapshot, "No programming references",
            "Place the caret on an identifier and press Shift+F12, or enter a bounded lexical query.");
        application_ui::render_programming_result_context_menu();
        return;
    }
    const std::size_t result_count = snapshot->locations.size() +
        snapshot->symbols.size() + snapshot->completions.size() +
        snapshot->information.size() + snapshot->diagnostics.size() +
        snapshot->proposed_edits.size() + snapshot->code_actions.size();
    ImGui::TextDisabled("%zu result%s for '%s'  |  %s  |  generation %llu%s",
        result_count, result_count == 1 ? "" : "s",
        snapshot->query_text.c_str(), snapshot->provider_name.c_str(),
        static_cast<unsigned long long>(snapshot->index_generation),
        snapshot->truncated ? "  |  truncated" : "");
    if (!snapshot->locations.empty()) {
        render_reference_rows(snapshot);
    } else if (!snapshot->symbols.empty()) {
        render_outline_rows(snapshot);
    } else if (!snapshot->completions.empty()) {
        render_completion_rows(snapshot);
    } else if (!snapshot->information.empty()) {
        render_information_rows(snapshot);
    } else if (!snapshot->diagnostics.empty()) {
        render_diagnostic_rows(snapshot);
    } else if (!snapshot->proposed_edits.empty()) {
        render_edit_rows(snapshot);
    } else if (!snapshot->code_actions.empty()) {
        render_code_action_rows(snapshot);
    }
    application_ui::render_programming_result_context_menu();
}

}
