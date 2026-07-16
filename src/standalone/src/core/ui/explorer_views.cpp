#include "explorer_views.hpp"

#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/helpers.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../analysis/workspace_search.hpp"
#endif
#include "../session/analysis_session.hpp"
#include "../settings/standalone_settings.hpp"

#include "imgui/imgui.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::ui::explorer_views {
namespace {

bool context_key_pressed(context_menu_open_origin_t& origin) {
    if (ImGui::IsKeyPressed(ImGuiKey_Menu, false)) {
        origin = context_menu_open_origin_t::menu_key;
        return true;
    }
    if (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)) {
        origin = context_menu_open_origin_t::shift_f10;
        return true;
    }
    return false;
}

std::string path_key(const std::string& path) {
    std::string normalized = std::filesystem::path(path).lexically_normal().generic_string();
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return normalized;
}

std::string path_leaf(const std::string& path) {
    const std::string value = std::filesystem::path(path).filename().string();
    return value.empty() ? path : value;
}

void open_search_result(const workspace_search::match_result_t& result) {
    std::ifstream input(result.filepath, std::ios::binary);
    if (!input.is_open())
        return;
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    file_tabs::open_or_focus(result.filepath, path_leaf(result.filepath), content);
    autocomplete::cursor_line = (std::max)(0, result.line_number - 1);
    autocomplete::cursor_col = (std::max)(0, result.col_start);
    application_views::open_or_focus(stable_view_id_t("document.code"));
}

void request_recent_open(const std::string& path) {
    file_browser::pending_open_path = path;
    file_browser::pending_open_filename = path_leaf(path);
    file_browser::pending_open_should_open = true;
    file_browser::pending_open_modal_visible = true;
}

}

void render_project_explorer() {
    g_render_section = "registry_project_explorer";
    if (ImGui::Button("Open Folder..."))
        application_ui::execute_action("file.open_folder", action_invocation_source_t::toolbar);
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        file_browser::needs_refresh = true;
    ImGui::SameLine();
    if (ImGui::Button("Search"))
        application_ui::execute_action("explorer.search", action_invocation_source_t::toolbar);
    ImGui::Separator();

    if (file_browser::needs_refresh) {
        g_render_section = "registry_project_explorer_refresh";
        file_browser::refresh();
    }
    file_browser::tick_watcher();

    int focused_index = -1;
    bool row_context_opened = false;
    if (file_browser::entries.empty()) {
        if (file_browser::current_dir.empty()) {
            ImGui::TextDisabled("No folder is open.");
            ImGui::TextWrapped("Open a folder to browse source files, scripts, binaries, and project artifacts.");
        } else {
            ImGui::TextDisabled("This folder is empty.");
            ImGui::TextWrapped("%s", file_browser::current_dir.c_str());
        }
    } else {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(file_browser::entries.size()), ImGui::GetTextLineHeightWithSpacing());
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                auto& entry = file_browser::entries[static_cast<std::size_t>(index)];
                ImGui::PushID(index);
                ImGui::Indent(static_cast<float>(entry.depth) * 16.0f);
                const std::string label = std::string(entry.is_dir ? (entry.expanded ? "v " : "> ") : "  ") + entry.name;
                const bool activated = ImGui::Selectable(label.c_str(), file_browser::selected_idx == index,
                    ImGuiSelectableFlags_AllowDoubleClick);
                const bool focused = ImGui::IsItemFocused();
                const bool context_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
                if (focused)
                    focused_index = index;
                if (activated && !ui_input_gate::popup_blocks_background_input()) {
                    file_browser::selected_idx = index;
                    if (entry.is_dir)
                        file_browser::toggle_dir(index);
                    else
                        file_browser::open_file(index);
                }
                if (context_clicked && !ui_input_gate::popup_blocks_background_input()) {
                    file_browser::selected_idx = index;
                    row_context_opened = true;
                    application_ui::open_explorer_context_menu(index, context_menu_open_origin_t::pointer);
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", entry.full_path.c_str());
                ImGui::Unindent(static_cast<float>(entry.depth) * 16.0f);
                ImGui::PopID();
            }
        }
    }

    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin)) {
        const int index = focused_index >= 0 ? focused_index : file_browser::selected_idx;
        if (index >= 0 && static_cast<std::size_t>(index) < file_browser::entries.size())
            application_ui::open_explorer_context_menu(index, origin);
        else
            application_ui::open_explorer_empty_context_menu(origin);
    }
    if (!row_context_opened && ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
        !ImGui::IsAnyItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
        application_ui::open_explorer_empty_context_menu(context_menu_open_origin_t::pointer);
    application_ui::render_explorer_context_menu();
}

void render_workspace_search() {
    g_render_section = "registry_workspace_search";
    ImGui::SetNextItemWidth(-1.0f);
    const bool submitted = ImGui::InputTextWithHint("##workspace_search_query", "Search workspace",
        workspace_search::g_search.query_buf, sizeof(workspace_search::g_search.query_buf),
        ImGuiInputTextFlags_EnterReturnsTrue);
    if (submitted)
        workspace_search::start_search(file_browser::current_dir);

    ImGui::Checkbox("Match case", &workspace_search::g_search.case_sensitive);
    ImGui::SameLine();
    ImGui::Checkbox("Whole word", &workspace_search::g_search.whole_word);
    ImGui::SameLine();
    ImGui::Checkbox("Regex", &workspace_search::g_search.use_regex);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##workspace_search_include", "Files to include, for example *.cpp,*.h",
        workspace_search::g_search.include_buf, sizeof(workspace_search::g_search.include_buf));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##workspace_search_exclude", "Files to exclude, for example build,*_generated.h",
        workspace_search::g_search.exclude_buf, sizeof(workspace_search::g_search.exclude_buf));

    const bool searching = workspace_search::g_search.searching.load(std::memory_order_acquire);
    if (searching) {
        ImGui::Text("Searching... %d files, %d matches",
            workspace_search::g_search.files_scanned.load(std::memory_order_acquire),
            workspace_search::g_search.match_count.load(std::memory_order_acquire));
        ImGui::SameLine();
        if (ImGui::Button("Cancel"))
            workspace_search::g_search.cancel.store(true, std::memory_order_release);
    } else {
        if (ImGui::Button("Search"))
            workspace_search::start_search(file_browser::current_dir);
    }
    ImGui::Separator();

    std::vector<std::pair<int, workspace_search::match_result_t>> results;
    {
        std::lock_guard<std::mutex> lock(workspace_search::g_search.results_mtx);
        const std::size_t count = (std::min)(workspace_search::g_search.results.size(), std::size_t{500});
        results.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            results.emplace_back(static_cast<int>(index), workspace_search::g_search.results[index]);
    }
    if (results.empty()) {
        if (searching)
            ImGui::TextDisabled("Results will appear as matching files are scanned.");
        else if (workspace_search::g_search.query_buf[0] == '\0')
            ImGui::TextDisabled("Enter text to search the open workspace.");
        else
            ImGui::TextDisabled("No matches were found.");
        return;
    }

    ImGui::TextDisabled("%zu result%s%s", results.size(), results.size() == 1 ? "" : "s",
        workspace_search::g_search.match_count.load(std::memory_order_acquire) > 500 ? " (first 500 shown)" : "");
    int focused_index = -1;
    std::size_t group_start = 0;
    while (group_start < results.size()) {
        const std::string& filepath = results[group_start].second.filepath;
        std::size_t group_end = group_start + 1;
        while (group_end < results.size() && results[group_end].second.filepath == filepath)
            ++group_end;
        ImGui::PushID(filepath.c_str());
        const std::string group_label = path_leaf(filepath) + " (" +
            std::to_string(group_end - group_start) + ")";
        const bool group_open = ImGui::TreeNodeEx("##workspace_search_group",
            ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanAvailWidth,
            "%s", group_label.c_str());
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", filepath.c_str());
        if (group_open) {
            for (std::size_t result_index = group_start; result_index < group_end; ++result_index) {
                const int source_index = results[result_index].first;
                const auto& result = results[result_index].second;
                ImGui::PushID(source_index);
                const std::string label = std::to_string(result.line_number) + ": " + result.line_text;
                if (ImGui::Selectable(label.c_str(), workspace_search::g_search.selected_idx == source_index)) {
                    workspace_search::g_search.selected_idx = source_index;
                    open_search_result(result);
                }
                if (ImGui::IsItemFocused())
                    focused_index = source_index;
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    workspace_search::g_search.selected_idx = source_index;
                    application_ui::open_workspace_search_context_menu(source_index,
                        context_menu_open_origin_t::pointer);
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
        group_start = group_end;
    }
    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin)) {
        const int index = focused_index >= 0 ? focused_index : workspace_search::g_search.selected_idx;
        if (index >= 0)
            application_ui::open_workspace_search_context_menu(index, origin);
    }
    application_ui::render_workspace_search_context_menu();
}

void render_recent() {
    g_render_section = "registry_recent";
    std::vector<std::string> recent_paths;
    if (!g_sa_settings.recent_workspaces_json.empty()) {
        const auto json = nlohmann::json::parse(g_sa_settings.recent_workspaces_json, nullptr, false);
        if (!json.is_discarded() && json.is_array()) {
            for (const auto& value : json)
                if (value.is_string())
                    recent_paths.push_back(value.get<std::string>());
        }
    }

    const std::size_t open_count = analysis_session::session_count();
    const std::size_t active_index = analysis_session::active_session_idx();
    std::unordered_set<std::string> open_paths;
    bool any = false;
    std::optional<std::size_t> close_requested;
    static std::string selected_path;
    static bool selected_open = false;
    bool focused_row = false;

    if (open_count != 0) {
        ImGui::SeparatorText("Open Binaries");
        for (std::size_t index = 0; index < open_count; ++index) {
            const auto session = analysis_session::session_handle_at(index);
            if (!session)
                continue;
            any = true;
            open_paths.insert(path_key(session->path));
            ImGui::PushID(static_cast<int>(index));
            const std::string label = (session->filename.empty() ? path_leaf(session->path) : session->filename) +
                "\n" + session->path;
            const float row_width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x - 54.0f);
            if (ImGui::Selectable(label.c_str(), index == active_index || selected_path == session->path,
                    ImGuiSelectableFlags_AllowDoubleClick, ImVec2(row_width, 0.0f))) {
                selected_path = session->path;
                selected_open = true;
                analysis_session::switch_session(index);
            }
            if (ImGui::IsItemFocused()) {
                selected_path = session->path;
                selected_open = true;
                focused_row = true;
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                selected_path = session->path;
                selected_open = true;
                application_ui::open_recent_context_menu(session->path, true,
                    context_menu_open_origin_t::pointer);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", session->path.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Close"))
                close_requested = index;
            ImGui::PopID();
        }
        if (close_requested)
            analysis_session::close_session(*close_requested);
    }

    std::vector<std::string> closed_paths;
    for (const auto& path : recent_paths) {
        if (open_paths.find(path_key(path)) == open_paths.end())
            closed_paths.push_back(path);
        if (closed_paths.size() == 10)
            break;
    }
    if (!closed_paths.empty()) {
        ImGui::SeparatorText("Recent (Closed)");
        for (std::size_t index = 0; index < closed_paths.size(); ++index) {
            const auto& path = closed_paths[index];
            any = true;
            ImGui::PushID(static_cast<int>(open_count + index));
            const std::string label = path_leaf(path) + "\n" + path;
            if (ImGui::Selectable(label.c_str(), selected_path == path)) {
                selected_path = path;
                selected_open = false;
                request_recent_open(path);
            }
            if (ImGui::IsItemFocused()) {
                selected_path = path;
                selected_open = false;
                focused_row = true;
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                selected_path = path;
                selected_open = false;
                application_ui::open_recent_context_menu(path, false,
                    context_menu_open_origin_t::pointer);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", path.c_str());
            ImGui::PopID();
        }
    }

    if (!any) {
        ImGui::TextDisabled("No recent binaries.");
        ImGui::TextWrapped("Open a binary from Project Explorer. Open and closed sessions will remain discoverable here.");
    }

    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin) &&
        (!selected_path.empty() || focused_row))
        application_ui::open_recent_context_menu(selected_path, selected_open, origin);
    application_ui::render_recent_context_menu();
}

}
