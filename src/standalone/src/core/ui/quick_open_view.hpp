#pragma once

#include "application_ui_runtime.hpp"
#include "application_view_registry.hpp"
#include "../editor/programming_language_service.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "../settings/standalone_settings.hpp"
#include "theme.hpp"
#include "toast_notification.hpp"
#include "../../helpers/globals.h"
#include "../../preview/studio_semantics.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::quick_open {

namespace detail {

constexpr std::size_t k_maximum_results = 128;
constexpr std::size_t k_candidates_per_frame = 4096;
constexpr std::size_t k_maximum_mru_workspaces = 16;
constexpr std::size_t k_maximum_mru_files = 32;
constexpr std::size_t k_maximum_path_bytes = 4096;

enum class result_kind_t : std::uint8_t {
    file,
    symbol,
    view,
    command
};

struct result_t {
    result_kind_t kind = result_kind_t::file;
    std::string identity;
    std::string label;
    std::string detail;
    std::string relative_path;
    std::string target_id;
    int line = 1;
    int column = 1;
    int score = 0;
    std::uint64_t index_generation = 0;
    std::string root_path;
    bool enabled = true;
    std::string disabled_reason;
};

struct mru_workspace_t {
    std::string root;
    std::vector<std::string> files;
};

struct runtime_t {
    std::shared_ptr<const code_index::published_index_t> index;
    std::vector<result_t> results;
    std::vector<mru_workspace_t> mru;
    std::string query;
    std::string selected_identity;
    std::string status;
    std::string error;
    std::size_t file_cursor = 0;
    std::size_t symbol_cursor = 0;
    std::size_t scanned_candidates = 0;
    std::size_t total_candidates = 0;
    bool auxiliary_complete = false;
    bool result_limit_reached = false;
    bool was_open = false;
    bool request_focus = false;
};

inline runtime_t& runtime()
{
    static runtime_t value;
    return value;
}

inline std::string lower_ascii(std::string value)
{
    std::replace(value.begin(), value.end(), '\\', '/');
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return value;
}

inline std::filesystem::path path_from_utf8(std::string_view value)
{
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value.begin(), value.end());
#endif
}

inline std::string path_to_utf8(const std::filesystem::path& value)
{
    const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
    return encoded;
#endif
}

inline bool normalized_relative_path(std::string_view value, std::string& output)
{
    if (value.empty() || value.size() > k_maximum_path_bytes)
        return false;
    try {
        const auto path = path_from_utf8(value).lexically_normal();
        if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
            return false;
        for (const auto& component : path) {
            if (component == "..")
                return false;
        }
        output = path_to_utf8(path);
        return !output.empty() && output != "." && output.size() <= k_maximum_path_bytes;
    } catch (...) {
        return false;
    }
}

inline bool normalized_root_path(std::string_view value, std::string& output)
{
    if (value.empty() || value.size() > k_maximum_path_bytes)
        return false;
    try {
        const auto path = path_from_utf8(value).lexically_normal();
        const bool drive_absolute = value.size() >= 3 &&
            std::isalpha(static_cast<unsigned char>(value[0])) != 0 &&
            value[1] == ':' && (value[2] == '/' || value[2] == '\\');
        if (path.empty() || (!path.is_absolute() && !drive_absolute))
            return false;
        output = path_to_utf8(path);
        return !output.empty() && output.size() <= k_maximum_path_bytes;
    } catch (...) {
        return false;
    }
}

inline std::vector<mru_workspace_t> load_mru()
{
    std::vector<mru_workspace_t> output;
    const auto parsed = nlohmann::json::parse(
        g_sa_settings.workspace.quick_open_mru_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object() ||
        parsed.value("version", 0) != 1 || !parsed.contains("workspaces") ||
        !parsed["workspaces"].is_array())
        return output;
    for (const auto& item : parsed["workspaces"]) {
        if (output.size() >= k_maximum_mru_workspaces)
            break;
        if (!item.is_object() || !item.contains("root") || !item["root"].is_string() ||
            !item.contains("files") || !item["files"].is_array())
            continue;
        mru_workspace_t workspace;
        if (!normalized_root_path(item["root"].get<std::string>(), workspace.root))
            continue;
        for (const auto& file : item["files"]) {
            if (workspace.files.size() >= k_maximum_mru_files)
                break;
            if (!file.is_string())
                continue;
            std::string relative;
            if (!normalized_relative_path(file.get<std::string>(), relative))
                continue;
            const std::string key = lower_ascii(relative);
            const bool duplicate = std::any_of(workspace.files.begin(), workspace.files.end(),
                [&](const std::string& existing) { return lower_ascii(existing) == key; });
            if (!duplicate)
                workspace.files.push_back(std::move(relative));
        }
        output.push_back(std::move(workspace));
    }
    return output;
}

inline bool persist_mru(runtime_t& state, std::string_view root, std::string_view relative)
{
    std::string normalized_relative;
    std::string normalized_root;
    if (!normalized_root_path(root, normalized_root) ||
        !normalized_relative_path(relative, normalized_relative))
        return false;
    const std::string root_key = lower_ascii(normalized_root);
    auto found = std::find_if(state.mru.begin(), state.mru.end(),
        [&](const mru_workspace_t& item) { return lower_ascii(item.root) == root_key; });
    mru_workspace_t workspace;
    if (found != state.mru.end()) {
        workspace = std::move(*found);
        state.mru.erase(found);
    } else {
        workspace.root = std::move(normalized_root);
    }
    const std::string path_key = lower_ascii(normalized_relative);
    workspace.files.erase(std::remove_if(workspace.files.begin(), workspace.files.end(),
        [&](const std::string& item) { return lower_ascii(item) == path_key; }),
        workspace.files.end());
    workspace.files.insert(workspace.files.begin(), std::move(normalized_relative));
    if (workspace.files.size() > k_maximum_mru_files)
        workspace.files.resize(k_maximum_mru_files);
    state.mru.insert(state.mru.begin(), std::move(workspace));
    if (state.mru.size() > k_maximum_mru_workspaces)
        state.mru.resize(k_maximum_mru_workspaces);

    auto serialize = [&]() {
        nlohmann::json workspaces = nlohmann::json::array();
        for (const auto& item : state.mru)
            workspaces.push_back({{"root", item.root}, {"files", item.files}});
        return nlohmann::json{{"version", 1},
            {"workspaces", std::move(workspaces)}}.dump();
    };
    std::string encoded = serialize();
    while (encoded.size() > 256U * 1024U && !state.mru.empty()) {
        auto& oldest = state.mru.back();
        if (oldest.files.size() > 1)
            oldest.files.pop_back();
        else
            state.mru.pop_back();
        encoded = serialize();
    }
    if (encoded.size() > 256U * 1024U)
        return false;
    g_sa_settings.workspace.quick_open_mru_json = std::move(encoded);
    return aida::settings_persistence::accepted(
        aida::settings_persistence::request_save(g_sa_settings));
}

inline int mru_bonus(const runtime_t& state, std::string_view root,
    std::string_view relative)
{
    const std::string root_key = lower_ascii(std::string(root));
    const std::string path_key = lower_ascii(std::string(relative));
    const auto workspace = std::find_if(state.mru.begin(), state.mru.end(),
        [&](const mru_workspace_t& item) { return lower_ascii(item.root) == root_key; });
    if (workspace == state.mru.end())
        return 0;
    for (std::size_t index = 0; index < workspace->files.size(); ++index) {
        if (lower_ascii(workspace->files[index]) == path_key)
            return 1600 - static_cast<int>((std::min)(index, std::size_t{31})) * 25;
    }
    return 0;
}

inline int fuzzy_score(std::string_view query, std::string_view label,
    std::string_view detail)
{
    if (query.empty())
        return -1;
    const std::string needle = lower_ascii(std::string(query));
    const std::string primary = lower_ascii(std::string(label));
    const std::string secondary = lower_ascii(std::string(detail));
    const std::string candidate = primary + " " + secondary;
    const auto exact = candidate.find(needle);
    if (exact != std::string::npos) {
        int score = 5000 - static_cast<int>((std::min)(exact, std::size_t{4000}));
        if (exact == 0)
            score += 1800;
        const auto slash = primary.find_last_of('/');
        if (slash != std::string::npos && exact == slash + 1)
            score += 1400;
        return score;
    }
    std::size_t cursor = 0;
    std::size_t previous = 0;
    int score = 900;
    for (const char character : needle) {
        const auto found = candidate.find(character, cursor);
        if (found == std::string::npos)
            return -1;
        if (cursor != 0)
            score -= static_cast<int>((std::min)(found - previous - 1, std::size_t{32})) * 8;
        if (found == 0 || candidate[found - 1] == '/' || candidate[found - 1] == '_' ||
            candidate[found - 1] == '-' || candidate[found - 1] == ' ')
            score += 90;
        previous = found;
        cursor = found + 1;
    }
    return score;
}

inline int kind_bonus(result_kind_t kind) noexcept
{
    switch (kind) {
    case result_kind_t::file: return 400;
    case result_kind_t::symbol: return 300;
    case result_kind_t::view: return 200;
    case result_kind_t::command: return 100;
    }
    return 0;
}

inline void consider(runtime_t& state, result_t result)
{
    if (result.score < 0)
        return;
    result.score += kind_bonus(result.kind);
    const auto duplicate = std::find_if(state.results.begin(), state.results.end(),
        [&](const result_t& existing) { return existing.identity == result.identity; });
    if (duplicate != state.results.end()) {
        if (result.score > duplicate->score)
            *duplicate = std::move(result);
        return;
    }
    if (state.results.size() < k_maximum_results) {
        state.results.push_back(std::move(result));
        return;
    }
    state.result_limit_reached = true;
    const auto lowest = std::min_element(state.results.begin(), state.results.end(),
        [](const result_t& left, const result_t& right) {
            return left.score < right.score;
        });
    if (lowest != state.results.end() && result.score > lowest->score)
        *lowest = std::move(result);
}

inline std::vector<result_t> ordered_results(const runtime_t& state)
{
    std::vector<result_t> output = state.results;
    std::sort(output.begin(), output.end(), [](const result_t& left, const result_t& right) {
        if (left.score != right.score)
            return left.score > right.score;
        if (left.kind != right.kind)
            return static_cast<unsigned>(left.kind) < static_cast<unsigned>(right.kind);
        if (left.label != right.label)
            return left.label < right.label;
        return left.identity < right.identity;
    });
    return output;
}

inline const char* kind_label(result_kind_t kind) noexcept
{
    switch (kind) {
    case result_kind_t::file: return "FILE";
    case result_kind_t::symbol: return "SYMBOL";
    case result_kind_t::view: return "VIEW";
    case result_kind_t::command: return "COMMAND";
    }
    return "ITEM";
}

inline std::uint64_t identity_hash(std::string_view value) noexcept
{
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

inline void reset_search(runtime_t& state, std::string query,
    std::shared_ptr<const code_index::published_index_t> index)
{
    state.query = std::move(query);
    state.index = std::move(index);
    state.results.clear();
    state.selected_identity.clear();
    state.status.clear();
    state.error.clear();
    state.file_cursor = 0;
    state.symbol_cursor = 0;
    state.scanned_candidates = 0;
    state.total_candidates = 0;
    state.auxiliary_complete = false;
    state.result_limit_reached = false;
    if (state.mru.empty())
        state.mru = load_mru();
    if (state.index) {
        if (state.index->file_paths)
            state.total_candidates += state.index->file_paths->size();
        if (state.index->symbols)
            state.total_candidates += state.index->symbols->size();
    }
}

inline void scan_auxiliary(runtime_t& state)
{
    if (state.auxiliary_complete)
        return;
    ui::application_views::for_each_menu_entry([&](const ui::application_views::menu_entry_t& entry) {
        result_t result;
        result.kind = result_kind_t::view;
        result.identity = "view:" + entry.id.value();
        result.label = entry.label;
        result.detail = std::string(ui::application_views::category_label(entry.category)) +
            (entry.open ? " · open" : " · closed");
        result.target_id = entry.id.value();
        result.enabled = entry.enabled;
        result.disabled_reason = entry.disabled_reason;
        result.score = fuzzy_score(state.query, result.label, result.target_id);
        consider(state, std::move(result));
        ++state.scanned_candidates;
        ++state.total_candidates;
    });
    auto actions = ui::application_ui::list_actions(ui::action_surface_t::command_palette);
    for (const auto& action : actions) {
        if (!action.visible || action.id == "file.quick_open" ||
            action.id.compare(0, 11, "view.focus.") == 0)
            continue;
        result_t result;
        result.kind = result_kind_t::command;
        result.identity = "command:" + action.id;
        result.label = action.label;
        result.detail = action.category.empty() ? action.description :
            action.category + " · " + action.description;
        result.target_id = action.id;
        result.enabled = action.enabled;
        result.disabled_reason = action.disabled_reason;
        result.score = fuzzy_score(state.query, result.label,
            result.target_id + " " + result.detail);
        consider(state, std::move(result));
        ++state.scanned_candidates;
        ++state.total_candidates;
    }
    state.auxiliary_complete = true;
}

inline void scan_index(runtime_t& state)
{
    if (state.query.empty())
        return;
    scan_auxiliary(state);
    std::size_t budget = k_candidates_per_frame;
    if (state.index && state.index->file_paths) {
        const auto& files = *state.index->file_paths;
        while (state.file_cursor < files.size() && budget != 0) {
            const std::string& path = files[state.file_cursor++];
            --budget;
            ++state.scanned_candidates;
            result_t result;
            result.kind = result_kind_t::file;
            result.identity = "file:" + path;
            result.label = path;
            result.detail = state.index->root_path;
            result.relative_path = path;
            result.root_path = state.index->root_path;
            result.index_generation = state.index->generation;
            result.score = fuzzy_score(state.query, path, {});
            if (result.score >= 0)
                result.score += mru_bonus(state, result.root_path, result.relative_path);
            consider(state, std::move(result));
        }
    }
    if (budget != 0 && state.index && state.index->symbols) {
        const auto& symbols = *state.index->symbols;
        while (state.symbol_cursor < symbols.size() && budget != 0) {
            const auto& symbol = symbols[state.symbol_cursor++];
            --budget;
            ++state.scanned_candidates;
            result_t result;
            result.kind = result_kind_t::symbol;
            result.identity = "symbol:" + symbol.file_path + ":" +
                std::to_string(symbol.line_number) + ":" + symbol.symbol_name;
            result.label = symbol.symbol_name;
            result.detail = symbol.symbol_type + " · " + symbol.file_path + ":" +
                std::to_string(symbol.line_number);
            result.relative_path = symbol.file_path;
            result.root_path = state.index->root_path;
            result.line = (std::max)(1, symbol.line_number);
            result.column = (std::max)(1, symbol.column_number);
            result.index_generation = state.index->generation;
            result.score = fuzzy_score(state.query, result.label,
                symbol.file_path + " " + symbol.symbol_type);
            if (result.score >= 0)
                result.score += mru_bonus(state, result.root_path, result.relative_path);
            consider(state, std::move(result));
        }
    }
}

inline bool scan_complete(const runtime_t& state) noexcept
{
    const bool files_complete = !state.index || !state.index->file_paths ||
        state.file_cursor >= state.index->file_paths->size();
    const bool symbols_complete = !state.index || !state.index->symbols ||
        state.symbol_cursor >= state.index->symbols->size();
    return state.auxiliary_complete && files_complete && symbols_complete;
}

inline bool activate(runtime_t& state, const result_t& result, bool open_to_side)
{
    state.error.clear();
    if (!result.enabled) {
        state.error = result.disabled_reason.empty() ?
            "The selected item is unavailable" : result.disabled_reason;
        return false;
    }
    if (result.kind == result_kind_t::file || result.kind == result_kind_t::symbol) {
        const auto current = editor::language_service::workspace_index_snapshot();
        if (!current || current->generation != result.index_generation ||
            lower_ascii(current->root_path) != lower_ascii(result.root_path)) {
            state.error = "The workspace index changed; review the refreshed results before opening this item";
            return false;
        }
        std::string relative;
        if (!normalized_relative_path(result.relative_path, relative)) {
            state.error = "The selected result is no longer a valid workspace-relative path";
            return false;
        }
        editor::language_service::location_t location;
        location.root_path = result.root_path;
        location.file_path = relative;
        location.line = result.line;
        location.column = result.column;
        if (!editor::language_service::open_location(location, open_to_side)) {
            state.error = "The selected file could not be opened inside the indexed workspace";
            return false;
        }
        if (!persist_mru(state, result.root_path, relative))
            toast_notification::push("The file opened, but Quick Open history could not be queued for persistence",
                toast_notification::toast_type_t::warning, 6.0f);
        return true;
    }
    if (result.kind == result_kind_t::view) {
        const auto opened = ui::application_views::open_or_focus(
            ui::stable_view_id_t(result.target_id));
        if (!opened.ok()) {
            state.error = opened.detail.empty() ? "The selected view could not be opened" : opened.detail;
            return false;
        }
        return true;
    }
    const auto executed = ui::application_ui::execute_action(result.target_id.c_str(),
        ui::action_invocation_source_t::command_palette);
    if (!executed.executed()) {
        state.error = executed.message.empty() ?
            "The selected command could not be executed" : executed.message;
        return false;
    }
    return true;
}

inline void close(runtime_t& state)
{
    globals::ui::quick_open_open = false;
    globals::ui::quick_open_buf[0] = '\0';
    state.query.clear();
    state.results.clear();
    state.selected_identity.clear();
    state.error.clear();
    state.status.clear();
    state.index.reset();
    state.was_open = false;
    state.request_focus = false;
}

}

inline void render()
{
    using namespace detail;
    auto& state = runtime();
    if (!globals::ui::quick_open_open) {
        if (state.was_open)
            close(state);
        return;
    }
    const bool just_opened = !state.was_open;
    state.was_open = true;
    if (just_opened) {
        globals::ui::command_palette_open = false;
        globals::ui::quick_open_buf[0] = '\0';
        state.request_focus = true;
        state.mru = load_mru();
        reset_search(state, {}, editor::language_service::workspace_index_snapshot());
    }

    const auto current_index = editor::language_service::workspace_index_snapshot();
    const std::string query(globals::ui::quick_open_buf);
    const bool source_changed = (current_index && !state.index) || (!current_index && state.index) ||
        (current_index && state.index &&
         (current_index->generation != state.index->generation ||
          lower_ascii(current_index->root_path) != lower_ascii(state.index->root_path)));
    if (query != state.query || source_changed)
        reset_search(state, query, current_index);
    if (!state.query.empty())
        scan_index(state);

    auto ordered = ordered_results(state);
    if (state.selected_identity.empty() && !ordered.empty())
        state.selected_identity = ordered.front().identity;
    auto selected = std::find_if(ordered.begin(), ordered.end(),
        [&](const result_t& item) { return item.identity == state.selected_identity; });
    if (selected == ordered.end() && !ordered.empty()) {
        selected = ordered.begin();
        state.selected_identity = selected->identity;
    }
    int selected_index = selected == ordered.end() ? -1 :
        static_cast<int>(std::distance(ordered.begin(), selected));

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float dpi = viewport && viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const ImVec2 work_pos = viewport ? viewport->WorkPos : ImVec2(0.0f, 0.0f);
    const ImVec2 work_size = viewport ? viewport->WorkSize : ImGui::GetIO().DisplaySize;
    const float width = (std::min)(720.0f * dpi, (std::max)(320.0f * dpi, work_size.x - 32.0f * dpi));
    const float height = (std::min)(460.0f * dpi, (std::max)(260.0f * dpi, work_size.y - 48.0f * dpi));
    const ImVec2 position(work_pos.x + (work_size.x - width) * 0.5f,
        work_pos.y + (std::max)(18.0f * dpi, (work_size.y - height) * 0.18f));
    ImGui::GetForegroundDrawList(viewport)->AddRectFilled(work_pos,
        ImVec2(work_pos.x + work_size.x, work_pos.y + work_size.y), IM_COL32(5, 9, 16, 138));
    ImGui::SetNextWindowPos(position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_Always);
    if (state.request_focus) {
        ImGui::SetNextWindowFocus();
        state.request_focus = false;
    }
    const auto& theme = ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(theme.bg_elevated));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(theme.border_focus));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f * dpi);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f * dpi, 12.0f * dpi));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoSavedSettings;
#ifdef IMGUI_HAS_DOCK
    flags |= ImGuiWindowFlags_NoDocking;
#endif
    const bool visible = ImGui::Begin("Quick Open###aida.quick_open", nullptr, flags);
    if (!visible) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
        return;
    }

    ImGui::TextUnformatted("Quick Open");
    ImGui::SameLine();
    ImGui::TextDisabled("Files, symbols, views and commands");
    ImGui::SameLine(ImGui::GetWindowWidth() - 92.0f * dpi);
    ImGui::TextDisabled("Ctrl+P");
    if (just_opened)
        ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-1.0f);
    const bool enter = ImGui::InputTextWithHint("##quick_open_query",
        "Type a file, symbol, view or command name",
        globals::ui::quick_open_buf, sizeof(globals::ui::quick_open_buf),
        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::semantics::register_last_item(
        "aida.quick-open.input", "quick-open-input");
#endif

    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
        close(state);
        ImGui::End();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
        return;
    }
    if (!ordered.empty() && ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
        selected_index = (selected_index + 1) % static_cast<int>(ordered.size());
        state.selected_identity = ordered[static_cast<std::size_t>(selected_index)].identity;
    }
    if (!ordered.empty() && ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
        selected_index = (selected_index - 1 + static_cast<int>(ordered.size())) %
            static_cast<int>(ordered.size());
        state.selected_identity = ordered[static_cast<std::size_t>(selected_index)].identity;
    }

    const auto index_state = editor::language_service::workspace_index_state();
    const bool complete = state.query.empty() ? true : scan_complete(state);
    if (!state.error.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.38f, 1.0f), "%s", state.error.c_str());
    } else if (state.query.empty()) {
        ImGui::TextDisabled("Type to search. Query text is never persisted.");
    } else if (!complete) {
        const float progress = state.total_candidates == 0 ? 0.0f :
            static_cast<float>((std::min)(state.scanned_candidates, state.total_candidates)) /
            static_cast<float>(state.total_candidates);
        ImGui::ProgressBar(progress, ImVec2(-1.0f, 3.0f * dpi), "");
        ImGui::TextDisabled("Filtering immutable workspace index incrementally...");
    } else if (ordered.empty()) {
        if (!state.index && index_state == code_index::index_state_t::indexing)
            ImGui::TextDisabled("Workspace indexing is in progress; views and commands remain searchable.");
        else if (!state.index && index_state == code_index::index_state_t::cancelled)
            ImGui::TextDisabled("Workspace indexing was cancelled; no file publication is available.");
        else if (!state.index && index_state == code_index::index_state_t::error)
            ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.38f, 1.0f), "%s",
                editor::language_service::workspace_index_status().c_str());
        else
            ImGui::TextDisabled("No matching files, symbols, views or commands.");
    } else {
        const bool bounded = state.result_limit_reached ||
            (state.index && (state.index->truncated || state.index->skipped_files != 0));
        ImGui::TextDisabled("%zu results%s | Enter opens | Ctrl+Enter opens file to side | Esc closes",
            ordered.size(), bounded ? " (bounded)" : "");
        if (!state.index) {
            if (index_state == code_index::index_state_t::indexing)
                ImGui::TextDisabled("Workspace indexing is in progress; showing views and commands.");
            else if (index_state == code_index::index_state_t::cancelled)
                ImGui::TextDisabled("Workspace indexing was cancelled; showing views and commands.");
            else if (index_state == code_index::index_state_t::error)
                ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.38f, 1.0f), "%s",
                    editor::language_service::workspace_index_status().c_str());
            else
                ImGui::TextDisabled("Workspace file index is unavailable; showing views and commands.");
        }
    }

    ImGui::Separator();
    const float footer = 24.0f * dpi;
    ImGui::BeginChild("##quick_open_results", ImVec2(0.0f,
        (std::max)(1.0f, ImGui::GetContentRegionAvail().y - footer)), false,
        ImGuiWindowFlags_NoBackground);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(ordered.size()), 38.0f * dpi);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& result = ordered[static_cast<std::size_t>(row)];
            ImGui::PushID(result.identity.c_str());
            const bool selected_row = result.identity == state.selected_identity;
            if (!result.enabled)
                ImGui::BeginDisabled();
            const bool clicked = ImGui::Selectable("##result", selected_row,
                ImGuiSelectableFlags_AllowDoubleClick, ImVec2(0.0f, 36.0f * dpi));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            char hash[17]{};
            std::snprintf(hash, sizeof(hash), "%016llx",
                static_cast<unsigned long long>(identity_hash(result.identity)));
            const std::string semantic = std::string("aida.quick-open.result.") + hash;
            aida::preview::semantics::register_last_item(
                semantic, "quick-open-result", false, !result.enabled);
#endif
            const ImVec2 minimum = ImGui::GetItemRectMin();
            const ImVec2 maximum = ImGui::GetItemRectMax();
            ImDrawList* draw = ImGui::GetWindowDrawList();
            draw->AddText(ImVec2(minimum.x + 8.0f * dpi, minimum.y + 5.0f * dpi),
                result.enabled ? theme.text_primary : theme.text_dim, result.label.c_str());
            const char* kind = kind_label(result.kind);
            const ImVec2 kind_size = ImGui::CalcTextSize(kind);
            draw->AddText(ImVec2(maximum.x - kind_size.x - 8.0f * dpi,
                minimum.y + 5.0f * dpi), theme.text_dim, kind);
            if (!result.detail.empty())
                draw->AddText(ImVec2(minimum.x + 8.0f * dpi, minimum.y + 21.0f * dpi),
                    theme.text_secondary, result.detail.c_str());
            if (!result.enabled)
                ImGui::EndDisabled();
            if (clicked) {
                state.selected_identity = result.identity;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                    activate(state, result, false)) {
                    close(state);
                    ImGui::PopID();
                    clipper.End();
                    ImGui::EndChild();
                    ImGui::End();
                    ImGui::PopStyleVar(2);
                    ImGui::PopStyleColor(2);
                    return;
                }
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();

    if (enter && selected_index >= 0 && selected_index < static_cast<int>(ordered.size())) {
        const bool open_to_side = ImGui::GetIO().KeyCtrl;
        if (activate(state, ordered[static_cast<std::size_t>(selected_index)], open_to_side)) {
            close(state);
            ImGui::End();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);
            return;
        }
    }
    ImGui::TextDisabled("Results are generation-fenced; moved or stale paths fail visibly.");
    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

}
