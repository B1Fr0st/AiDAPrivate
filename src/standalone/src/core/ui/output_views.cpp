#include "output_views.hpp"

#include "application_ui_runtime.hpp"
#include "terminal_view.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/helpers.h"
#include "../settings/standalone_settings.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview.hpp"
#else
#include "../../helpers/diag_log.hpp"
#include "../../helpers/win32_dialog.hpp"
#endif

#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <deque>
#include <fstream>
#include <string>
#include <vector>

namespace aida::ui::output_views {
namespace {

struct view_state_t {
    std::array<std::array<char, 256>, static_cast<std::size_t>(bottom_tab_t::COUNT)> filters{};
    std::array<bool, static_cast<std::size_t>(bottom_tab_t::COUNT)> focus_filter{};
    std::array<std::uint64_t, static_cast<std::size_t>(bottom_tab_t::COUNT)> versions{};
    std::array<std::vector<std::string>, static_cast<std::size_t>(bottom_tab_t::COUNT)> snapshots;
    std::array<std::size_t, static_cast<std::size_t>(bottom_tab_t::COUNT)> totals{};
    std::array<std::string, static_cast<std::size_t>(bottom_tab_t::COUNT)> applied_filters;
    std::array<std::string, static_cast<std::size_t>(bottom_tab_t::COUNT)> applied_filter_inputs;
    std::array<std::vector<std::size_t>, static_cast<std::size_t>(bottom_tab_t::COUNT)> filtered_indices;
    std::array<bool, static_cast<std::size_t>(bottom_tab_t::COUNT)> selected_all{};
    bool terminal_select_all = false;
    bool terminal_start_attempted = false;
    std::string terminal_start_error;
    int terminal_last_render_frame = -2;
};

view_state_t& state() {
    static view_state_t value;
    return value;
}

std::size_t index(bottom_tab_t tab) {
    return static_cast<std::size_t>(output_log::tab_index(tab));
}

bool terminal_tab(bottom_tab_t tab) noexcept {
    return tab == bottom_tab_t::terminal;
}

const char* label(bottom_tab_t tab) noexcept {
    switch (tab) {
    case bottom_tab_t::output: return "Output";
    case bottom_tab_t::mcp_log: return "MCP Log";
    case bottom_tab_t::driver_log: return "Driver Log";
    case bottom_tab_t::sandbox_log: return "Sandbox Log";
    case bottom_tab_t::terminal: return "Terminal";
    case bottom_tab_t::COUNT: break;
    }
    return "Output";
}

void log_lock_busy(const char* operation, bottom_tab_t tab) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static std::atomic<unsigned long long> last_log_ms{0};
    static std::atomic<unsigned long long> busy_count{0};
    const unsigned long long now = aida::shell_platform::tick_ms();
    const unsigned long long count = busy_count.fetch_add(1, std::memory_order_acq_rel) + 1ULL;
    unsigned long long last = last_log_ms.load(std::memory_order_acquire);
    if (count != 1ULL && now - last < 500ULL)
        return;
    if (count != 1ULL && !last_log_ms.compare_exchange_strong(last, now, std::memory_order_acq_rel))
        return;
    unsigned long owner_tid = 0;
    unsigned long long owner_age = 0;
    int owner_tab = -1;
    int owner_op = 0;
    output_log::snapshot_owner(owner_tid, owner_age, owner_tab, owner_op);
    diag::log_tagged_fmt("ui",
        "OUTPUT_VIEW_LOCK_BUSY op=%s tab=%d busy_count=%llu owner_tid=%lu owner_age_ms=%llu owner_tab=%d owner_op=%s owner_op_id=%d frame=%d tid=%lu",
        operation ? operation : "<null>", static_cast<int>(tab), count, owner_tid, owner_age,
        owner_tab, output_log::op_name(owner_op), owner_op, ImGui::GetFrameCount(),
        static_cast<unsigned long>(aida::shell_platform::thread_id()));
#else
    static_cast<void>(operation);
    static_cast<void>(tab);
#endif
}

bool snapshot_text(bottom_tab_t tab, std::string& text) {
    text.clear();
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.current();
        if (!terminal)
            return false;
        if (!terminal_view::try_copy_all_text(*terminal, text)) {
            log_lock_busy("terminal_snapshot", tab);
            return false;
        }
        return true;
    }
#endif
    std::deque<std::string> lines;
    if (!output_log::try_snapshot_all(tab, lines)) {
        log_lock_busy("log_snapshot_all", tab);
        return false;
    }
    std::size_t bytes = 0;
    for (const auto& line : lines)
        bytes += line.size() + 1;
    text.reserve(bytes);
    for (const auto& line : lines) {
        text.append(line);
        text.push_back('\n');
    }
    return true;
}

bool contains_case_insensitive(const std::string& value, const std::string& normalized_filter) {
    if (normalized_filter.empty())
        return true;
    return std::search(value.begin(), value.end(), normalized_filter.begin(), normalized_filter.end(),
        [](unsigned char lhs, unsigned char rhs) {
            return std::tolower(lhs) == std::tolower(rhs);
        }) != value.end();
}

context_menu_open_origin_t context_origin() {
    if (ImGui::IsKeyPressed(ImGuiKey_Menu, false))
        return context_menu_open_origin_t::menu_key;
    return context_menu_open_origin_t::shift_f10;
}

bool context_key_pressed() {
    return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
        (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

void render_toolbar(bottom_tab_t tab) {
    const auto invoke = [tab](const char* action) {
        application_ui::execute_output_action(static_cast<int>(tab), action,
            action_invocation_source_t::toolbar);
    };
    const bool content = has_content(tab);
    ImGui::BeginDisabled(!content);
    if (ImGui::Button("Copy All")) invoke("output.copy_all");
    ImGui::SameLine();
    if (ImGui::Button("Select All")) invoke("output.select_all");
    ImGui::SameLine();
    if (ImGui::Button("Clear")) invoke("output.clear");
    ImGui::SameLine();
    if (ImGui::Button("Export...")) invoke("output.export");
    ImGui::EndDisabled();
    ImGui::SameLine();
    bool follow = follows_tail(tab);
    if (ImGui::Checkbox("Follow tail", &follow))
        invoke("output.follow");
    if (supports_filter(tab)) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth((std::max)(120.0f, ImGui::GetContentRegionAvail().x));
        const auto slot = index(tab);
        if (state().focus_filter[slot]) {
            ImGui::SetKeyboardFocusHere();
            state().focus_filter[slot] = false;
        }
        ImGui::InputTextWithHint("##output_filter", "Filter output",
            state().filters[slot].data(), state().filters[slot].size());
    }
    ImGui::Separator();
}

void render_log(bottom_tab_t tab) {
    const auto slot = index(tab);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static std::uint64_t preview_revision = 0;
    if (aida::preview::controls().invalidate_bottom_cache &&
        preview_revision != aida::preview::controls().revision) {
        preview_revision = aida::preview::controls().revision;
        state().versions.fill(0);
        state().totals.fill(0);
        for (auto& snapshot : state().snapshots)
            snapshot.clear();
        for (auto& filtered : state().filtered_indices)
            filtered.clear();
    }
#endif
    std::size_t total = state().totals[slot];
    bool snapshot_changed = false;
    if (!output_log::try_snapshot_tail_if_changed(tab, output_log::MAX_RENDER_LINES,
            state().versions[slot], state().snapshots[slot], &total, &snapshot_changed)) {
        log_lock_busy("log_snapshot", tab);
    } else {
        state().totals[slot] = total;
    }
    const auto& snapshot = state().snapshots[slot];
    const bool filter_changed = state().applied_filter_inputs[slot] != state().filters[slot].data();
    if (filter_changed) {
        state().applied_filter_inputs[slot] = state().filters[slot].data();
        state().applied_filters[slot] = state().applied_filter_inputs[slot];
        std::transform(state().applied_filters[slot].begin(), state().applied_filters[slot].end(),
            state().applied_filters[slot].begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    }
    if (snapshot_changed || filter_changed) {
        const auto& normalized_filter = state().applied_filters[slot];
        auto& filtered = state().filtered_indices[slot];
        filtered.clear();
        filtered.reserve(snapshot.size());
        for (std::size_t line_index = 0; line_index < snapshot.size(); ++line_index)
            if (contains_case_insensitive(snapshot[line_index], normalized_filter))
                filtered.push_back(line_index);
    }
    const auto& visible = state().filtered_indices[slot];
    if (snapshot.empty()) {
        ImGui::TextDisabled("No %s entries yet.", label(tab));
        if (tab == bottom_tab_t::mcp_log)
            ImGui::TextWrapped("MCP request and tool activity will appear here when the local MCP service is active.");
        else if (tab == bottom_tab_t::driver_log)
            ImGui::TextWrapped("Driver diagnostics will appear here after a driver-backed operation reports status.");
        else if (tab == bottom_tab_t::sandbox_log)
            ImGui::TextWrapped("Sandbox execution and isolation diagnostics will appear here when a sandbox task runs.");
        else
            ImGui::TextWrapped("Analysis, file, automation, and IDE diagnostics will appear here as work runs.");
    } else if (visible.empty()) {
        ImGui::TextDisabled("No entries match the current filter.");
    } else {
        ImGui::PushFont(aida::ui::fonts::code());
        const float line_height = ImGui::GetTextLineHeightWithSpacing();
        const bool near_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - line_height * 2.0f;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible.size()), line_height);
        while (clipper.Step())
            for (int line_index = clipper.DisplayStart; line_index < clipper.DisplayEnd; ++line_index)
                ImGui::TextUnformatted(snapshot[visible[static_cast<std::size_t>(line_index)]].c_str());
        if (follows_tail(tab) && near_bottom)
            ImGui::SetScrollHereY(1.0f);
        ImGui::PopFont();
        if (state().selected_all[slot]) {
            const ImVec2 position = ImGui::GetWindowPos();
            const ImVec2 size = ImGui::GetWindowSize();
            ImGui::GetWindowDrawList()->AddRect(position,
                ImVec2(position.x + size.x, position.y + size.y),
                ImGui::GetColorU32(ImGuiCol_NavHighlight), 0.0f, 0, 2.0f);
        }
    }
}

void render_terminal() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    render_log(bottom_tab_t::terminal);
#else
    auto& manager = globals::terminal_mgr;
    const int frame = ImGui::GetFrameCount();
    if (frame > state().terminal_last_render_frame + 1 && !manager.current()) {
        state().terminal_start_attempted = false;
        state().terminal_start_error.clear();
    }
    state().terminal_last_render_frame = frame;
    if (!manager.current() && !state().terminal_start_attempted) {
        state().terminal_start_attempted = true;
        std::wstring shell(g_sa_settings.terminal_shell.begin(), g_sa_settings.terminal_shell.end());
        if (!manager.create_terminal(shell.c_str()))
            state().terminal_start_error = "The configured terminal shell could not be started";
        else
            state().terminal_start_error.clear();
    }
    auto* terminal = manager.current();
    if (!terminal) {
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s.",
            state().terminal_start_error.empty() ? "Terminal session is not running" : state().terminal_start_error.c_str());
        ImGui::TextWrapped("Verify the configured terminal shell path in Settings. AiDA will not fall back to an unconfigured shell.");
        if (ImGui::Button("Retry configured shell")) {
            state().terminal_start_attempted = true;
            std::wstring shell(g_sa_settings.terminal_shell.begin(), g_sa_settings.terminal_shell.end());
            if (!manager.create_terminal(shell.c_str()))
                state().terminal_start_error = "The configured terminal shell could not be started";
            else
                state().terminal_start_error.clear();
        }
        return;
    }
    const auto& theme = aida::ui::resolved();
    const ImVec2 size = ImGui::GetContentRegionAvail();
    terminal_view::render_terminal(*terminal, size,
        aida::ui::with_alpha(theme.bg_base, 0.9f), theme.accent_u32);
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        auto& io = ImGui::GetIO();
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
            state().terminal_select_all = true;
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
            if (state().terminal_select_all) {
                copy_all(bottom_tab_t::terminal);
                state().terminal_select_all = false;
            } else {
                terminal_view::send_input(*terminal, "\x03", 1);
            }
        } else {
            for (int character_index = 0; character_index < io.InputQueueCharacters.Size; ++character_index) {
                const ImWchar character = io.InputQueueCharacters[character_index];
                if (character >= 32 && character < 127)
                    terminal_view::send_key(*terminal, static_cast<char>(character));
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Enter, false)) terminal_view::send_input(*terminal, "\r", 1);
            if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false)) terminal_view::send_input(*terminal, "\x7f", 1);
            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) terminal_view::send_input(*terminal, "\t", 1);
            if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) terminal_view::send_input(*terminal, "\x1b", 1);
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) terminal_view::send_input(*terminal, "\x1b[A", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) terminal_view::send_input(*terminal, "\x1b[B", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, false)) terminal_view::send_input(*terminal, "\x1b[C", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false)) terminal_view::send_input(*terminal, "\x1b[D", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) terminal_view::send_input(*terminal, "\x1b[H", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_End, false)) terminal_view::send_input(*terminal, "\x1b[F", 3);
            if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) terminal_view::send_input(*terminal, "\x1b[3~", 4);
            if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_D, false)) terminal_view::send_input(*terminal, "\x04", 1);
            if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z, false)) terminal_view::send_input(*terminal, "\x1a", 1);
        }
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) || (!io.KeyCtrl && io.InputQueueCharacters.Size > 0))
            state().terminal_select_all = false;
    } else {
        state().terminal_select_all = false;
    }
    if (state().terminal_select_all) {
        const ImVec2 position = ImGui::GetWindowPos();
        const ImVec2 window_size = ImGui::GetWindowSize();
        ImGui::GetWindowDrawList()->AddRect(position,
            ImVec2(position.x + window_size.x, position.y + window_size.y),
            ImGui::GetColorU32(ImGuiCol_NavHighlight), 0.0f, 0, 2.0f);
    }
#endif
}

}

operation_result_t copy_all(bottom_tab_t tab) {
    std::string text;
    if (!snapshot_text(tab, text))
        return {false, terminal_tab(tab) ? "The terminal session is unavailable or busy" : "The output buffer is busy"};
    if (text.empty())
        return {false, "There is no text to copy"};
    ImGui::SetClipboardText(text.c_str());
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::record(aida::preview::shell_action_t::copy_text, label(tab));
#endif
    return {true, {}};
}

operation_result_t clear(bottom_tab_t tab) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.current();
        if (!terminal)
            return {false, "The terminal session is unavailable"};
        if (!terminal_view::try_clear_session(*terminal)) {
            log_lock_busy("terminal_clear", tab);
            return {false, "The terminal buffer is busy"};
        }
        state().terminal_select_all = false;
        state().selected_all[index(tab)] = false;
        return {true, {}};
    }
#endif
    if (!output_log::try_clear(tab)) {
        log_lock_busy("log_clear", tab);
        return {false, "The output buffer is busy"};
    }
    state().selected_all[index(tab)] = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab))
        aida::preview::record(aida::preview::shell_action_t::terminal_clear, "terminal");
#endif
    return {true, {}};
}

operation_result_t select_all(bottom_tab_t tab) {
    if (!has_content(tab))
        return {false, "There is no text to select"};
    if (terminal_tab(tab))
        state().terminal_select_all = true;
    else {
        output_log::set_select_all(tab, true);
    }
    state().selected_all[index(tab)] = true;
    return {true, {}};
}

operation_result_t toggle_follow(bottom_tab_t tab) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.current();
        if (!terminal)
            return {false, "The terminal session is unavailable"};
        terminal->auto_follow = !terminal->auto_follow;
        if (terminal->auto_follow)
            terminal->scroll_to_bottom = true;
        return {true, {}};
    }
#endif
    bool follow = true;
    if (!output_log::try_is_auto_scroll(tab, follow) ||
        !output_log::try_set_auto_scroll(tab, !follow)) {
        log_lock_busy("toggle_follow", tab);
        return {false, "The output buffer is busy"};
    }
    return {true, {}};
}

operation_result_t focus_filter(bottom_tab_t tab) {
    if (!supports_filter(tab))
        return {false, "Terminal output cannot be filtered without changing interactive terminal semantics"};
    state().focus_filter[index(tab)] = true;
    return {true, {}};
}

operation_result_t export_all(bottom_tab_t tab) {
    std::string text;
    if (!snapshot_text(tab, text))
        return {false, "The output source is unavailable or busy"};
    if (text.empty())
        return {false, "There is no text to export"};
    char path[1024] = {};
    std::snprintf(path, sizeof(path), "%s.log", label(tab));
    static const char filter[] = "Log files (*.log)\0*.log\0Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
    if (!win32_dialog::show_save_file_dialog(g_hwnd, "Export Output", filter, "log",
            path, sizeof(path), "output_view_export"))
        return {true, {}};
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open())
        return {false, "The export destination could not be opened"};
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.flush();
    return stream.good() ? operation_result_t{true, {}}
        : operation_result_t{false, "The export could not be written completely"};
}

bool has_content(bottom_tab_t tab) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.current();
        return terminal && terminal->prev_line_count != 0;
    }
#endif
    return !state().snapshots[index(tab)].empty();
}

bool supports_filter(bottom_tab_t tab) noexcept {
    return !terminal_tab(tab);
}

bool follows_tail(bottom_tab_t tab) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.current();
        return terminal && terminal->auto_follow;
    }
#endif
    bool enabled = true;
    if (!output_log::try_is_auto_scroll(tab, enabled))
        log_lock_busy("follow_state", tab);
    return enabled;
}

bool source_available(bottom_tab_t tab) noexcept {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (terminal_tab(tab))
        return globals::terminal_mgr.current() != nullptr;
#else
    static_cast<void>(tab);
#endif
    return true;
}

void render(bottom_tab_t tab) {
    g_render_section = terminal_tab(tab) ? "registry_terminal" : "registry_output";
    render_toolbar(tab);
    ImGui::BeginChild("##output_content", ImGui::GetContentRegionAvail(), false,
        ImGuiWindowFlags_NoBackground);
    if (terminal_tab(tab))
        render_terminal();
    else
        render_log(tab);
    if (!terminal_tab(tab) && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
            application_ui::execute_output_action(static_cast<int>(tab), "output.select_all",
                action_invocation_source_t::shortcut);
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false))
            application_ui::execute_output_action(static_cast<int>(tab), "output.copy_all",
                action_invocation_source_t::shortcut);
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed())
        application_ui::open_output_context_menu(static_cast<int>(tab), context_origin());
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows |
            ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Right))
        application_ui::open_output_context_menu(static_cast<int>(tab),
            context_menu_open_origin_t::pointer);
    application_ui::render_output_context_menu();
    ImGui::EndChild();
}

}
