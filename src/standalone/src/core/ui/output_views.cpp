#include "output_views.hpp"

#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "programming_tasks.hpp"
#include "task_center.hpp"
#include "terminal_view.hpp"
#include "ui_thread_dispatcher.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/helpers.h"
#include "../infra/executor.hpp"
#include "../settings/standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview.hpp"
#else
#include "../../helpers/diag_log.hpp"
#include "../../helpers/win32_dialog.hpp"
#endif

#include "imgui/imgui.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
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
    std::vector<terminal_view::profile_t> terminal_profiles;
    int terminal_profile = 0;
    std::array<char, 1024> terminal_cwd{};
    std::array<char, 256> terminal_search{};
    bool terminal_search_visible = false;
    bool terminal_focus_search = false;
    bool terminal_select_requested = false;
    bool terminal_restored = false;
    std::uint64_t terminal_persistence_generation = 0;
    std::uint64_t terminal_settings_generation = 0;
    bool terminal_persistence_in_flight = false;
    std::string terminal_persistence_payload;
    std::string terminal_persistence_profile;
    std::string terminal_persistence_cwd;
    std::string terminal_persistence_error;
    std::string applied_task_output_channel;
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

std::string narrow(const std::wstring& value) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return std::string(value.begin(), value.end());
#else
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size)
        return {};
    return result;
#endif
}

std::wstring widen(const std::string& value) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return std::wstring(value.begin(), value.end());
#else
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size) != size)
        return {};
    return result;
#endif
}

void ensure_terminal_profiles() {
    auto& view = state();
    if (!view.terminal_profiles.empty()) return;
    view.terminal_profiles = terminal_view::available_profiles(g_sa_settings.terminal_shell);
    if (view.terminal_profiles.empty()) return;
    const auto selected = std::find_if(view.terminal_profiles.begin(), view.terminal_profiles.end(),
        [](const terminal_view::profile_t& profile) {
            return profile.id == g_sa_settings.terminal_profile_id;
        });
    view.terminal_profile = selected == view.terminal_profiles.end() ? 0 :
        static_cast<int>(std::distance(view.terminal_profiles.begin(), selected));
    const std::size_t count = (std::min)(g_sa_settings.terminal_default_cwd.size(),
        view.terminal_cwd.size() - 1);
    std::memcpy(view.terminal_cwd.data(), g_sa_settings.terminal_default_cwd.data(), count);
    view.terminal_cwd[count] = '\0';
}

terminal_view::TerminalSession* create_selected_terminal() {
    ensure_terminal_profiles();
    auto& view = state();
    if (view.terminal_profile < 0 ||
        view.terminal_profile >= static_cast<int>(view.terminal_profiles.size())) {
        view.terminal_start_error = "No available terminal profile is selected";
        return nullptr;
    }
    const auto& profile = view.terminal_profiles[static_cast<std::size_t>(view.terminal_profile)];
    const std::wstring cwd = widen(view.terminal_cwd.data());
    auto* session = globals::terminal_mgr.create_terminal(profile.command.c_str(),
        cwd.empty() ? nullptr : cwd.c_str(), profile.id.c_str(), profile.label.c_str());
    if (!session) {
        view.terminal_start_error = globals::terminal_mgr.last_error;
        return nullptr;
    }
    session->max_lines = (std::clamp)(g_sa_settings.terminal_scrollback, 1000, 100000);
    view.terminal_start_error.clear();
    return session;
}

void schedule_terminal_persistence();

void persist_terminal_state() {
    auto& manager = globals::terminal_mgr;
    nlohmann::json root = nlohmann::json::object();
    root["version"] = 1;
    root["active"] = manager.active_tab;
    root["secondary"] = manager.secondary_tab;
    root["split"] = manager.split_mode == terminal_view::split_mode_t::vertical ? "vertical" :
        manager.split_mode == terminal_view::split_mode_t::horizontal ? "horizontal" : "none";
    root["sessions"] = nlohmann::json::array();
    for (const auto* session : manager.sessions) {
        if (!session) continue;
        root["sessions"].push_back({
            {"profile", session->profile_id},
            {"cwd", narrow(session->cwd)}
        });
    }
    auto& view = state();
    view.terminal_persistence_payload = root.dump();
    view.terminal_persistence_profile = view.terminal_profiles.empty() || view.terminal_profile < 0 ||
        view.terminal_profile >= static_cast<int>(view.terminal_profiles.size())
        ? std::string{} : view.terminal_profiles[static_cast<std::size_t>(view.terminal_profile)].id;
    view.terminal_persistence_cwd = view.terminal_cwd.data();
    ++view.terminal_persistence_generation;
    schedule_terminal_persistence();
}

void schedule_terminal_persistence() {
    auto& view = state();
    if (view.terminal_persistence_in_flight) return;
    const std::string payload = view.terminal_persistence_payload;
    const std::string profile = view.terminal_persistence_profile;
    const std::string cwd = view.terminal_persistence_cwd;
    g_sa_settings.terminal_sessions_json = payload;
    g_sa_settings.terminal_profile_id = profile;
    g_sa_settings.terminal_default_cwd = cwd;
    std::uint64_t settings_generation = 0;
    const auto requested = aida::settings_persistence::request_save(g_sa_settings,
        &settings_generation);
    if (aida::settings_persistence::accepted(requested)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        view.terminal_persistence_in_flight = false;
        view.terminal_persistence_error.clear();
#else
        view.terminal_persistence_in_flight = true;
        view.terminal_settings_generation = settings_generation;
#endif
    } else {
        view.terminal_persistence_in_flight = false;
        view.terminal_persistence_error =
            "Terminal session persistence could not capture an immutable settings snapshot";
    }
}

void restore_terminal_state() {
    auto& view = state();
    if (view.terminal_restored) return;
    view.terminal_restored = true;
    ensure_terminal_profiles();
    if (!g_sa_settings.terminal_restore_sessions || g_sa_settings.terminal_sessions_json.empty())
        return;
    try {
        const auto root = nlohmann::json::parse(g_sa_settings.terminal_sessions_json);
        if (!root.is_object() || root.value("version", 0) != 1 ||
            !root.contains("sessions") || !root["sessions"].is_array())
            return;
        std::size_t restored = 0;
        for (const auto& record : root["sessions"]) {
            if (!record.is_object() || restored >= 12) break;
            const std::string profile_id = record.value("profile", std::string{});
            const auto profile = std::find_if(view.terminal_profiles.begin(), view.terminal_profiles.end(),
                [&](const terminal_view::profile_t& item) { return item.id == profile_id; });
            if (profile == view.terminal_profiles.end()) continue;
            const std::wstring cwd = widen(record.value("cwd", std::string{}));
            if (auto* session = globals::terminal_mgr.create_terminal(profile->command.c_str(),
                    cwd.empty() ? nullptr : cwd.c_str(), profile->id.c_str(),
                    profile->label.c_str())) {
                session->max_lines = (std::clamp)(g_sa_settings.terminal_scrollback, 1000, 100000);
                ++restored;
            }
        }
        if (globals::terminal_mgr.sessions.empty()) return;
        globals::terminal_mgr.active_tab = (std::clamp)(root.value("active", 0), 0,
            static_cast<int>(globals::terminal_mgr.sessions.size()) - 1);
        const std::string split = root.value("split", std::string("none"));
        const int secondary = root.value("secondary", -1);
        if (secondary >= 0 && secondary < static_cast<int>(globals::terminal_mgr.sessions.size()) &&
            secondary != globals::terminal_mgr.active_tab) {
            globals::terminal_mgr.secondary_tab = secondary;
            globals::terminal_mgr.split_mode = split == "vertical"
                ? terminal_view::split_mode_t::vertical : split == "horizontal"
                ? terminal_view::split_mode_t::horizontal : terminal_view::split_mode_t::none;
        }
    } catch (const std::exception& error) {
        view.terminal_persistence_error = error.what();
    }
}

const char* label(bottom_tab_t tab) noexcept {
    switch (tab) {
    case bottom_tab_t::output: return "Output";
    case bottom_tab_t::mcp_log: return "MCP Activity";
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
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.focused();
        if (!terminal)
            return false;
        if (!terminal_view::try_copy_all_text(*terminal, text)) {
            log_lock_busy("terminal_snapshot", tab);
            return false;
        }
        return true;
    }
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
        if (tab == bottom_tab_t::output && !programming_tasks::output_line_visible(line))
            continue;
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

void render_toolbar(bottom_tab_t tab, const char* stable_scope) {
    const auto invoke = [tab](const char* action) {
        application_ui::execute_output_action(static_cast<int>(tab), action,
            action_invocation_source_t::toolbar);
    };
    const auto metrics = design::metrics();
    const float available = (std::max)(1.0f, ImGui::GetContentRegionAvail().x);
    const bool supports_search = supports_filter(tab);
    const bool wide = supports_search && available >= 620.0f * metrics.scale;
    const bool follow = follows_tail(tab);
    const char* follow_label = follow ? "Following" : "Follow tail";
    const char* follow_compact = follow ? "Follow: on" : "Follow: off";
    const auto copy = application_ui::present_output_action(
        static_cast<int>(tab), "output.copy_all");
    const auto select = application_ui::present_output_action(
        static_cast<int>(tab), "output.select_all");
    const auto clear = application_ui::present_output_action(
        static_cast<int>(tab), "output.clear");
    const auto export_output = application_ui::present_output_action(
        static_cast<int>(tab), "output.export");
    const auto follow_output = application_ui::present_output_action(
        static_cast<int>(tab), "output.follow");
    const auto filter = application_ui::present_output_action(
        static_cast<int>(tab), "output.filter");
    const auto tooltip = [](const application_ui::action_presentation_t& presentation,
            const char* fallback) {
        if (!presentation.enabled && !presentation.disabled_reason.empty())
            return presentation.disabled_reason.c_str();
        return presentation.description.empty()
            ? fallback : presentation.description.c_str();
    };
    const auto shortcut = [](const application_ui::action_presentation_t& presentation) {
        return presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str();
    };
    const design::action_t actions[] = {
        {"output.copy_all", "Copy All", "Copy", tooltip(copy, "Copy all output text"),
            shortcut(copy), nullptr, components::button_kind_t::secondary,
            copy.enabled, false, copy.visible},
        {"output.select_all", "Select All", "Select", tooltip(select, "Select all output text"),
            shortcut(select), nullptr, components::button_kind_t::secondary,
            select.enabled, false, select.visible},
        {"output.clear", "Clear", "Clear", tooltip(clear, "Clear this output buffer"), nullptr,
            "Clears the visible output buffer", components::button_kind_t::secondary,
            clear.enabled, false, clear.visible},
        {"output.export", "Export...", "Export", tooltip(export_output,
            "Export all output to a file"), nullptr, nullptr,
            components::button_kind_t::secondary, export_output.enabled, false,
            export_output.visible},
        {"output.follow", follow_label, follow_compact,
            tooltip(follow_output, follow ? "Stop following new output" :
                "Follow new output as it arrives"), nullptr, nullptr,
            components::button_kind_t::ghost, follow_output.enabled, false,
            follow_output.visible},
        {"output.filter", "Filter...", "Filter", tooltip(filter, "Focus the output filter"),
            shortcut(filter), nullptr, components::button_kind_t::ghost,
            filter.enabled, false, filter.visible}
    };
    const float toolbar_height = metrics.control_height + 4.0f * metrics.scale;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
        ImVec2(0.0f, 2.0f * metrics.scale));
    ImGui::BeginChild("##output_toolbar", ImVec2(available, toolbar_height), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
        ImGuiWindowFlags_NoSavedSettings);
    const float filter_width = wide
        ? (std::min)(260.0f * metrics.scale, available * 0.34f) : 0.0f;
    const float action_width = wide
        ? (std::max)(metrics.control_height,
            available - filter_width - metrics.spacing_sm) : available;
    const auto result = design::render_toolbar(stable_scope, actions,
        sizeof(actions) / sizeof(actions[0]), action_width);
    if (result.invoked && result.id)
        invoke(result.id);
    if (wide) {
        ImGui::SameLine(0.0f, metrics.spacing_sm);
        ImGui::SetCursorPosX((std::max)(ImGui::GetCursorPosX(),
            ImGui::GetWindowContentRegionMax().x - filter_width));
        ImGui::SetNextItemWidth(filter_width);
        const auto slot = index(tab);
        if (state().focus_filter[slot]) {
            ImGui::SetKeyboardFocusHere();
            state().focus_filter[slot] = false;
        }
        ImGui::InputTextWithHint("##output_filter", "Filter output",
            state().filters[slot].data(), state().filters[slot].size());
        design::tooltip_for_last_item("Filter visible output", shortcut(filter));
        design::draw_focus_ring_for_last_item();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    if (!wide && supports_search) {
        const auto slot = index(tab);
        if (state().focus_filter[slot])
            ImGui::OpenPopup("##output_filter_popup");
        ImGui::SetNextWindowSize(ImVec2(320.0f * metrics.scale, 0.0f), ImGuiCond_Appearing);
        if (ImGui::BeginPopup("##output_filter_popup")) {
            ImGui::TextUnformatted("Filter output");
            ImGui::SetNextItemWidth(-1.0f);
            if (state().focus_filter[slot]) {
                ImGui::SetKeyboardFocusHere();
                state().focus_filter[slot] = false;
            }
            ImGui::InputTextWithHint("##output_filter", "Type to filter visible entries",
                state().filters[slot].data(), state().filters[slot].size());
            design::draw_focus_ring_for_last_item();
            ImGui::EndPopup();
        }
    }
    const ImVec2 line = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(line,
        ImVec2(line.x + available, line.y), ImGui::GetColorU32(ImGuiCol_Border));
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
    const bool snapshot_available = output_log::try_snapshot_tail_if_changed(
        tab, output_log::MAX_RENDER_LINES, state().versions[slot],
        state().snapshots[slot], &total, &snapshot_changed);
    if (!snapshot_available) {
        log_lock_busy("log_snapshot", tab);
    } else {
        state().totals[slot] = total;
    }
    const auto& snapshot = state().snapshots[slot];
    const std::string task_channel = tab == bottom_tab_t::output
        ? programming_tasks::selected_output_channel() : std::string{};
    const bool channel_changed = tab == bottom_tab_t::output &&
        state().applied_task_output_channel != task_channel;
    const bool filter_changed = state().applied_filter_inputs[slot] != state().filters[slot].data();
    if (filter_changed) {
        state().applied_filter_inputs[slot] = state().filters[slot].data();
        state().applied_filters[slot] = state().applied_filter_inputs[slot];
        std::transform(state().applied_filters[slot].begin(), state().applied_filters[slot].end(),
            state().applied_filters[slot].begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    }
    if (channel_changed) state().applied_task_output_channel = task_channel;
    if (snapshot_changed || filter_changed || channel_changed) {
        const auto& normalized_filter = state().applied_filters[slot];
        auto& filtered = state().filtered_indices[slot];
        filtered.clear();
        filtered.reserve(snapshot.size());
        for (std::size_t line_index = 0; line_index < snapshot.size(); ++line_index)
            if ((tab != bottom_tab_t::output ||
                    programming_tasks::output_line_visible(snapshot[line_index])) &&
                contains_case_insensitive(snapshot[line_index], normalized_filter))
                filtered.push_back(line_index);
    }
    const auto& visible = state().filtered_indices[slot];
    if (snapshot.empty()) {
        const char* message = "Analysis, file, automation, and IDE diagnostics appear here as work runs.";
        if (tab == bottom_tab_t::mcp_log)
            message = "MCP requests and tool activity appear here when the local MCP service is active.";
        else if (tab == bottom_tab_t::driver_log)
            message = "Driver diagnostics appear here after a driver-backed operation reports status.";
        else if (tab == bottom_tab_t::sandbox_log)
            message = "Sandbox execution and isolation diagnostics appear here when a sandbox task runs.";
        const design::state_presentation_t presentation{
            snapshot_available ? "output.empty" : "output.loading",
            snapshot_available ? design::view_state_t::empty : design::view_state_t::loading,
            snapshot_available ? "No output yet" : "Reading output",
            snapshot_available ? message : "The output buffer is busy. AiDA will retry without discarding existing data.",
            label(tab), snapshot_available ? nullptr : "Waiting for the output buffer",
            nullptr, nullptr, snapshot_available ? "Output appears automatically; no refresh is required." : nullptr,
            -1.0f, 0.0, false, nullptr, 0};
        design::render_state(presentation, ImGui::GetContentRegionAvail());
    } else if (visible.empty()) {
        const bool channel_empty = tab == bottom_tab_t::output && !task_channel.empty() &&
            state().filters[slot][0] == '\0';
        const design::state_presentation_t presentation{
            "output.no-results", design::view_state_t::empty,
            channel_empty ? "No output in this channel" : "No matching output",
            channel_empty ? "The selected task channel has no retained entries."
                : "No entries match the current filter.",
            channel_empty ? task_channel.c_str() : state().filters[slot].data(),
            nullptr, nullptr, nullptr,
            channel_empty ? "Select All Output or run the configuration again."
                : "Clear or broaden the filter to restore hidden entries.", -1.0f, 0.0,
            false, nullptr, 0};
        design::render_state(presentation, ImGui::GetContentRegionAvail());
    } else {
        ImGui::BeginChild("##output_scroll", ImGui::GetContentRegionAvail(), false,
            ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
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
        ImGui::EndChild();
    }
}

void render_terminal_input(terminal_view::TerminalSession& terminal) {
    if (!terminal.focused) return;
    auto& io = ImGui::GetIO();
    if (io.WantTextInput) return;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false))
        state().terminal_select_all = true;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
        if (state().terminal_select_all) {
            copy_all(bottom_tab_t::terminal);
            state().terminal_select_all = false;
        } else {
            terminal_view::send_input(terminal, "\x03", 1);
        }
        return;
    }
    if (!io.KeyCtrl && !io.KeyAlt)
        for (int index = 0; index < io.InputQueueCharacters.Size; ++index) {
            const std::uint32_t character = static_cast<std::uint32_t>(io.InputQueueCharacters[index]);
            if (character < 32 || character > 0x10ffff ||
                (character >= 0xd800 && character <= 0xdfff))
                continue;
            char encoded[4]{};
            std::size_t length = 0;
            if (character < 0x80) {
                encoded[0] = static_cast<char>(character);
                length = 1;
            } else if (character < 0x800) {
                encoded[0] = static_cast<char>(0xc0 | (character >> 6));
                encoded[1] = static_cast<char>(0x80 | (character & 0x3f));
                length = 2;
            } else if (character < 0x10000) {
                encoded[0] = static_cast<char>(0xe0 | (character >> 12));
                encoded[1] = static_cast<char>(0x80 | ((character >> 6) & 0x3f));
                encoded[2] = static_cast<char>(0x80 | (character & 0x3f));
                length = 3;
            } else {
                encoded[0] = static_cast<char>(0xf0 | (character >> 18));
                encoded[1] = static_cast<char>(0x80 | ((character >> 12) & 0x3f));
                encoded[2] = static_cast<char>(0x80 | ((character >> 6) & 0x3f));
                encoded[3] = static_cast<char>(0x80 | (character & 0x3f));
                length = 4;
            }
            terminal_view::send_input(terminal, encoded, length);
        }
    if (ImGui::IsKeyPressed(ImGuiKey_Enter, false)) terminal_view::send_input(terminal, "\r", 1);
    if (ImGui::IsKeyPressed(ImGuiKey_Backspace, false)) terminal_view::send_input(terminal, "\x7f", 1);
    if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) terminal_view::send_input(terminal, "\t", 1);
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) terminal_view::send_input(terminal, "\x1b", 1);
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, false)) terminal_view::send_input(terminal, "\x1b[A", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, false)) terminal_view::send_input(terminal, "\x1b[B", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, false)) terminal_view::send_input(terminal, "\x1b[C", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false)) terminal_view::send_input(terminal, "\x1b[D", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) terminal_view::send_input(terminal, "\x1b[H", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_End, false)) terminal_view::send_input(terminal, "\x1b[F", 3);
    if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) terminal_view::send_input(terminal, "\x1b[3~", 4);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_D, false)) terminal_view::send_input(terminal, "\x04", 1);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z, false)) terminal_view::send_input(terminal, "\x1a", 1);
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) || (!io.KeyCtrl && io.InputQueueCharacters.Size > 0))
        state().terminal_select_all = false;
}

void render_terminal_pane(terminal_view::TerminalSession& terminal, const ImVec2& size) {
    ImGui::PushID(static_cast<int>(terminal.id));
    const auto& theme = aida::ui::resolved();
    terminal_view::render_terminal(terminal, size,
        aida::ui::with_alpha(theme.bg_base, 0.9f), theme.accent_u32);
    render_terminal_input(terminal);
    ImGui::PopID();
}

void render_terminal_search(terminal_view::TerminalSession& terminal) {
    auto& view = state();
    if (!view.terminal_search_visible) return;
    if (view.terminal_focus_search) {
        ImGui::SetKeyboardFocusHere();
        view.terminal_focus_search = false;
    }
    const float scale = design::metrics().scale;
    const bool compact = ImGui::GetContentRegionAvail().x < aida::ui::scale_px(520.0f, scale);
    ImGui::SetNextItemWidth(compact ? ImGui::GetContentRegionAvail().x :
        (std::max)(aida::ui::scale_px(100.0f, scale),
            ImGui::GetContentRegionAvail().x - aida::ui::scale_px(210.0f, scale)));
    const bool submitted = ImGui::InputTextWithHint("##terminal_search", "Search terminal output",
        view.terminal_search.data(), view.terminal_search.size(), ImGuiInputTextFlags_EnterReturnsTrue);
    terminal_view::refresh_search(terminal, view.terminal_search.data());
    if (submitted)
        terminal_view::move_search_match(terminal, ImGui::GetIO().KeyShift ? -1 : 1);
    if (!compact) ImGui::SameLine();
    if (ImGui::SmallButton("Previous")) terminal_view::move_search_match(terminal, -1);
    ImGui::SameLine();
    if (ImGui::SmallButton("Next")) terminal_view::move_search_match(terminal, 1);
    ImGui::SameLine();
    ImGui::TextDisabled("%d/%zu", terminal.active_search_match < 0 ? 0 :
        terminal.active_search_match + 1, terminal.search_matches.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Close") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
        view.terminal_search_visible = false;
        terminal.search_query.clear();
        terminal.search_matches.clear();
        terminal.active_search_match = -1;
    }
}

void render_terminal_session_bar() {
    auto& manager = globals::terminal_mgr;
    auto& view = state();
    int close_index = -1;
    bool active_changed = false;
    if (ImGui::BeginTabBar("##terminal_sessions",
            ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (int index = 0; index < static_cast<int>(manager.sessions.size()); ++index) {
            auto* terminal = manager.sessions[static_cast<std::size_t>(index)];
            if (!terminal) continue;
            bool open = true;
            std::string label = terminal->title;
            if (!terminal->alive.load(std::memory_order_acquire)) {
                const auto code = terminal->exit_code.load(std::memory_order_acquire);
                label += code == std::numeric_limits<std::uint32_t>::max()
                    ? " [stopped]" : " [exit " + std::to_string(code) + "]";
            }
            const ImGuiTabItemFlags flags = view.terminal_select_requested &&
                manager.active_tab == index ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
            if (ImGui::BeginTabItem((label + "###terminal." + std::to_string(terminal->id)).c_str(),
                    &open, flags)) {
                active_changed = active_changed || manager.active_tab != index;
                manager.active_tab = index;
                ImGui::EndTabItem();
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("%s\nCommand: %s\nLaunch directory: %s",
                    terminal->profile_label.c_str(), narrow(terminal->command).c_str(),
                    terminal->cwd.empty() ? "Inherited" : narrow(terminal->cwd).c_str());
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Middle)) open = false;
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                active_changed = active_changed || manager.active_tab != index;
                manager.active_tab = index;
                application_ui::open_output_context_menu(static_cast<int>(bottom_tab_t::terminal),
                    context_menu_open_origin_t::pointer);
            }
            if (!open) close_index = index;
        }
        view.terminal_select_requested = false;
        if (ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing))
            ImGui::OpenPopup("##new_terminal_profile");
        ImGui::EndTabBar();
    }
    if (close_index >= 0) {
        manager.close_terminal(close_index);
        persist_terminal_state();
        active_changed = false;
    }
    if (active_changed) persist_terminal_state();
    if (ImGui::BeginPopup("##new_terminal_profile")) {
        ImGui::TextUnformatted("New terminal profile");
        ImGui::Separator();
        ImGui::SetNextItemWidth(360.0f);
        ImGui::InputTextWithHint("##terminal_cwd", "Launch working directory (optional)",
            view.terminal_cwd.data(), view.terminal_cwd.size());
        for (int index = 0; index < static_cast<int>(view.terminal_profiles.size()); ++index) {
            const auto& profile = view.terminal_profiles[static_cast<std::size_t>(index)];
            if (ImGui::Selectable(profile.label.c_str(), index == view.terminal_profile)) {
                view.terminal_profile = index;
                if (create_selected_terminal()) {
                    view.terminal_select_requested = true;
                    persist_terminal_state();
                }
                ImGui::CloseCurrentPopup();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", narrow(profile.command).c_str());
        }
        ImGui::EndPopup();
    }
    const float action_bar_height = ImGui::GetFrameHeightWithSpacing() + ImGui::GetStyle().ScrollbarSize;
    ImGui::BeginChild("##terminal_actions", ImVec2(0.0f, action_bar_height), false,
        ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBackground);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4.0f, 3.0f));
    const auto terminal_action = [](const char* action_id, const char* label) {
        const auto presentation = application_ui::present_output_action(
            static_cast<int>(bottom_tab_t::terminal), action_id);
        if (!presentation.visible)
            return false;
        ImGui::BeginDisabled(!presentation.enabled);
        const bool clicked = ImGui::SmallButton(label);
        ImGui::EndDisabled();
        const char* detail = !presentation.enabled && !presentation.disabled_reason.empty()
            ? presentation.disabled_reason.c_str() : presentation.description.c_str();
        design::tooltip_for_last_item(detail,
            presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str());
        if (clicked)
            static_cast<void>(application_ui::execute_output_action(
                static_cast<int>(bottom_tab_t::terminal), action_id,
                action_invocation_source_t::toolbar));
        return clicked;
    };
    const auto new_terminal = application_ui::present_output_action(
        static_cast<int>(bottom_tab_t::terminal), "terminal.new");
    ImGui::BeginDisabled(!new_terminal.enabled);
    const bool choose_new_terminal = ImGui::SmallButton("New");
    ImGui::EndDisabled();
    design::tooltip_for_last_item(new_terminal.enabled
        ? "Choose a terminal profile and working directory"
        : new_terminal.disabled_reason.c_str(),
        new_terminal.shortcut.empty() ? nullptr : new_terminal.shortcut.c_str());
    if (choose_new_terminal)
        ImGui::OpenPopup("##new_terminal_profile");
    ImGui::SameLine();
    terminal_action("terminal.split_vertical", "Split Right");
    ImGui::SameLine();
    terminal_action("terminal.split_horizontal", "Split Down");
    if (manager.split_mode != terminal_view::split_mode_t::none) {
        ImGui::SameLine();
        terminal_action("terminal.unsplit", "Unsplit");
    }
    ImGui::SameLine();
    terminal_action("terminal.search", "Search");
    ImGui::SameLine();
    terminal_action("terminal.restart", "Restart");
    ImGui::SameLine();
    terminal_action("terminal.close", "Close");
    ImGui::PopStyleVar();
    if (!view.terminal_persistence_error.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("Session layout not saved");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", view.terminal_persistence_error.c_str());
    }
    ImGui::EndChild();
}

void render_terminal() {
    auto& view = state();
    if (view.terminal_persistence_in_flight) {
        const auto persistence = aida::settings_persistence::status();
        if (persistence.committed_generation >= view.terminal_settings_generation) {
            view.terminal_persistence_in_flight = false;
            view.terminal_persistence_error.clear();
            if (view.terminal_persistence_generation != 0 &&
                view.terminal_persistence_payload != g_sa_settings.terminal_sessions_json)
                schedule_terminal_persistence();
        } else if (!persistence.pending && persistence.failed &&
            persistence.generation >= view.terminal_settings_generation) {
            view.terminal_persistence_in_flight = false;
            view.terminal_persistence_error = persistence.error.empty()
                ? "Terminal session layout could not be saved" : persistence.error;
        }
    }
    auto& manager = globals::terminal_mgr;
    manager.reap_retired_sessions();
    restore_terminal_state();
    const int frame = ImGui::GetFrameCount();
    if (frame > state().terminal_last_render_frame + 1 && !manager.current()) {
        state().terminal_start_attempted = false;
        state().terminal_start_error.clear();
    }
    state().terminal_last_render_frame = frame;
    if (!manager.current() && !state().terminal_start_attempted) {
        state().terminal_start_attempted = true;
        if (create_selected_terminal()) persist_terminal_state();
    }
    auto* terminal = manager.current();
    if (!terminal) {
        const design::action_t retry{
            "terminal.retry", "Retry configured shell", "Retry",
            "Start the terminal using the configured shell path", nullptr, nullptr,
            components::button_kind_t::primary, true, true, true};
        const design::state_presentation_t presentation{
            "terminal.unavailable", design::view_state_t::error,
            state().terminal_start_error.empty() ? "Terminal unavailable" : "Terminal failed to start",
            state().terminal_start_error.empty()
                ? "The configured terminal session is not running."
                : state().terminal_start_error.c_str(),
            g_sa_settings.terminal_shell.c_str(), nullptr, nullptr, nullptr,
            "Verify the terminal shell path in Settings. AiDA does not fall back to an unconfigured shell.",
            -1.0f, 0.0, false, &retry, 1};
        const auto result = design::render_state(presentation, ImGui::GetContentRegionAvail());
        if (result.invoked) {
            state().terminal_start_attempted = true;
            if (create_selected_terminal()) persist_terminal_state();
        }
        return;
    }
    render_terminal_session_bar();
    terminal = manager.current();
    if (!terminal) return;
    if (manager.secondary_tab == manager.active_tab) {
        if (manager.sessions.size() > 1)
            manager.secondary_tab = manager.active_tab == 0 ? 1 : 0;
        else
            manager.set_split(terminal_view::split_mode_t::none);
    }
    auto* search_terminal = manager.focused();
    render_terminal_search(*(search_terminal ? search_terminal : terminal));
    for (auto* session : manager.sessions)
        if (session) session->focused = false;
    auto* secondary = manager.secondary();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (!secondary || manager.split_mode == terminal_view::split_mode_t::none) {
        render_terminal_pane(*terminal, available);
    } else if (manager.split_mode == terminal_view::split_mode_t::vertical) {
        if (ImGui::BeginTable("##terminal_split_vertical", 2,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV,
                available)) {
            ImGui::TableNextColumn();
            render_terminal_pane(*terminal, ImGui::GetContentRegionAvail());
            ImGui::TableNextColumn();
            render_terminal_pane(*secondary, ImGui::GetContentRegionAvail());
            ImGui::EndTable();
        }
    } else {
        const float gap = ImGui::GetStyle().ItemSpacing.y;
        const float first_height = (std::max)(1.0f, (available.y - gap) * 0.5f);
        render_terminal_pane(*terminal, ImVec2(available.x, first_height));
        render_terminal_pane(*secondary,
            ImVec2(available.x, (std::max)(1.0f, available.y - first_height - gap)));
    }
    if (state().terminal_select_all) {
        const ImVec2 position = ImGui::GetWindowPos();
        const ImVec2 window_size = ImGui::GetWindowSize();
        ImGui::GetWindowDrawList()->AddRect(position,
            ImVec2(position.x + window_size.x, position.y + window_size.y),
            ImGui::GetColorU32(ImGuiCol_NavHighlight), 0.0f, 0, 2.0f);
    }
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
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.focused();
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
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.focused();
        if (!terminal)
            return {false, "The terminal session is unavailable"};
        terminal->auto_follow = !terminal->auto_follow;
        if (terminal->auto_follow)
            terminal->scroll_to_bottom = true;
        return {true, {}};
    }
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
    if (file_tabs::find_path_document(path) >= 0)
        return {false, "Choose a destination that is not open in the code editor"};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::record(aida::preview::shell_action_t::save_file, path);
    return {false, "Output export requires the native AiDA runtime"};
#else
    struct export_state_t {
        std::string id;
        std::string path;
        std::string text;
    };
    static std::atomic<std::uint64_t> sequence{1};
    auto export_state = std::make_shared<export_state_t>();
    export_state->id = "output.export." + std::to_string(GetTickCount64()) + "." +
        std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
    export_state->path = path;
    export_state->text = std::move(text);
    task_center::task_registration_t registration;
    registration.id = export_state->id;
    registration.source = "output.export";
    registration.owner = "Output Export";
    registration.owner_view = terminal_tab(tab) ? "view.terminal" : "view.output";
    registration.owner_action = "output.export";
    registration.target = export_state->path;
    registration.label = std::string("Export ") + label(tab);
    registration.stage = "Queued for atomic file export";
    registration.affected_entity = export_state->path;
    registration.callbacks.focus = [tab] {
        static_cast<void>(aida::ui_thread::post([tab] {
            static_cast<void>(application_views::open_or_focus(stable_view_id_t(
                terminal_tab(tab) ? "view.terminal" : "view.output")));
        }, "output_export", "output_export_focus", "task_center_callback"));
    };
    registration.callbacks.open_log = registration.callbacks.focus;
    if (!task_center::register_task(std::move(registration)))
        return {false, "The Task Center rejected the output export"};
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "output_export";
    submission.label = "output.atomic_export";
    submission.thread_class = "bounded_file_io";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.session_id = export_state->id.c_str();
    submission.target_id = export_state->path.c_str();
    submission.diagnostic_id = export_state->id.c_str();
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.shutdown_policy = "drain";
    submission.body = [export_state] {
        try {
            static_cast<void>(task_center::update_task(export_state->id,
                task_center::task_state_t::running, -1.0f, "Writing same-directory temporary file"));
            const auto result = file_tabs::atomic_write_file(export_state->path, export_state->text);
            export_state->text.clear();
            export_state->text.shrink_to_fit();
            if (result.succeeded) {
                static_cast<void>(task_center::update_task(export_state->id,
                    task_center::task_state_t::completed, 1.0f, "Finished",
                    "Output exported atomically"));
            } else {
                static_cast<void>(task_center::update_task(export_state->id,
                    task_center::task_state_t::failed, 1.0f, "Atomic export failed",
                    result.detail, "diagnostic." + export_state->id));
            }
        } catch (const std::exception& exception) {
            static_cast<void>(task_center::update_task(export_state->id,
                task_center::task_state_t::failed, 1.0f, "Atomic export failed",
                exception.what(), "diagnostic." + export_state->id));
        } catch (...) {
            static_cast<void>(task_center::update_task(export_state->id,
                task_center::task_state_t::failed, 1.0f, "Atomic export failed",
                "Unknown export failure", "diagnostic." + export_state->id));
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        static_cast<void>(task_center::update_task(export_state->id,
            task_center::task_state_t::failed, 1.0f, "Executor rejected export",
            submitted.reject_reason, "diagnostic." + export_state->id));
        return {false, "The output export executor rejected the request: " + submitted.reject_reason};
    }
    return {true, "Output export queued"};
#endif
}

operation_result_t terminal_new() {
    if (!create_selected_terminal())
        return {false, state().terminal_start_error};
    state().terminal_select_requested = true;
    state().terminal_start_attempted = true;
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_new_at(const std::string& working_directory) {
    if (working_directory.empty())
        return {false, "Select a workspace directory first"};
    if (working_directory.size() >= state().terminal_cwd.size())
        return {false, "The terminal working directory exceeds the 1023-byte UTF-8 limit"};
    if (widen(working_directory).empty())
        return {false, "The terminal working directory is not valid UTF-8"};
    auto& view = state();
    std::memcpy(view.terminal_cwd.data(), working_directory.data(), working_directory.size());
    view.terminal_cwd[working_directory.size()] = '\0';
    if (!create_selected_terminal())
        return {false, view.terminal_start_error};
    view.terminal_select_requested = true;
    view.terminal_start_attempted = true;
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_close() {
    auto& manager = globals::terminal_mgr;
    const int index = manager.focused_index();
    if (index < 0) return {false, "There is no active terminal session"};
    manager.close_terminal(index);
    state().terminal_select_all = false;
    state().terminal_start_attempted = true;
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_restart() {
    auto& manager = globals::terminal_mgr;
    const int index = manager.focused_index();
    if (index < 0) return {false, "There is no active terminal session"};
    if (!manager.restart_terminal(index))
        return {false, manager.last_error.empty() ? "The terminal session could not be restarted" : manager.last_error};
    state().terminal_select_requested = true;
    state().terminal_select_all = false;
    return {true, {}};
}

operation_result_t terminal_next() {
    if (!globals::terminal_mgr.cycle(1))
        return {false, "There are no terminal sessions"};
    state().terminal_select_requested = true;
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_previous() {
    if (!globals::terminal_mgr.cycle(-1))
        return {false, "There are no terminal sessions"};
    state().terminal_select_requested = true;
    persist_terminal_state();
    return {true, {}};
}

operation_result_t set_terminal_split(terminal_view::split_mode_t mode) {
    auto& manager = globals::terminal_mgr;
    if (!manager.current()) return {false, "There is no active terminal session"};
    if (manager.sessions.size() < 2 && !create_selected_terminal())
        return {false, state().terminal_start_error};
    if (!manager.set_split(mode))
        return {false, "A second terminal session is required for a split"};
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_split_vertical() {
    return set_terminal_split(terminal_view::split_mode_t::vertical);
}

operation_result_t terminal_split_horizontal() {
    return set_terminal_split(terminal_view::split_mode_t::horizontal);
}

operation_result_t terminal_unsplit() {
    auto& manager = globals::terminal_mgr;
    if (manager.split_mode == terminal_view::split_mode_t::none)
        return {false, "The terminal is not split"};
    manager.set_split(terminal_view::split_mode_t::none);
    persist_terminal_state();
    return {true, {}};
}

operation_result_t terminal_focus_search() {
    if (!globals::terminal_mgr.current())
        return {false, "There is no active terminal session"};
    state().terminal_search_visible = true;
    state().terminal_focus_search = true;
    return {true, {}};
}

operation_result_t terminal_paste() {
    auto* terminal = globals::terminal_mgr.focused();
    if (!terminal || !terminal->alive.load(std::memory_order_acquire))
        return {false, "The active terminal process is not running"};
    const char* clipboard = ImGui::GetClipboardText();
    if (!clipboard || *clipboard == '\0')
        return {false, "The clipboard has no text"};
    std::size_t length = 0;
    while (length < terminal_view::TerminalSession::MAX_INPUT_QUEUE_BYTES && clipboard[length] != '\0')
        ++length;
    if (length == terminal_view::TerminalSession::MAX_INPUT_QUEUE_BYTES)
        return {false, "Clipboard text exceeds the terminal's 1 MiB input limit"};
    terminal_view::send_input(*terminal, clipboard, length);
    state().terminal_select_all = false;
    return {true, {}};
}

bool has_content(bottom_tab_t tab) {
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.focused();
        return terminal && terminal->prev_line_count != 0;
    }
    if (tab == bottom_tab_t::output && !programming_tasks::selected_output_channel().empty())
        return std::any_of(state().snapshots[index(tab)].begin(), state().snapshots[index(tab)].end(),
            [](const std::string& line) { return programming_tasks::output_line_visible(line); });
    return !state().snapshots[index(tab)].empty();
}

bool supports_filter(bottom_tab_t tab) noexcept {
    return !terminal_tab(tab);
}

bool follows_tail(bottom_tab_t tab) {
    if (terminal_tab(tab)) {
        auto* terminal = globals::terminal_mgr.focused();
        return terminal && terminal->auto_follow;
    }
    bool enabled = true;
    if (!output_log::try_is_auto_scroll(tab, enabled))
        log_lock_busy("follow_state", tab);
    return enabled;
}

bool source_available(bottom_tab_t tab) noexcept {
    if (terminal_tab(tab))
        return globals::terminal_mgr.current() != nullptr;
    return true;
}

std::size_t terminal_session_count() noexcept {
    return globals::terminal_mgr.sessions.size();
}

bool terminal_is_split() noexcept {
    return globals::terminal_mgr.split_mode != terminal_view::split_mode_t::none;
}

void render(bottom_tab_t tab, std::string_view stable_view_id,
    std::string_view stable_instance_key) {
    g_render_section = terminal_tab(tab) ? "registry_terminal" : "registry_output";
    std::string stable_scope(stable_view_id);
    if (stable_scope.empty())
        stable_scope = "view.output-unowned";
    if (!stable_instance_key.empty()) {
        stable_scope.append(".instance.");
        stable_scope.append(stable_instance_key);
    }
    if (tab == bottom_tab_t::output)
        programming_tasks::render_output_controls();
    render_toolbar(tab, stable_scope.c_str());
    if (terminal_tab(tab)) {
        render_terminal();
    } else {
        render_log(tab);
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed())
        application_ui::open_output_context_menu(static_cast<int>(tab), context_origin());
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows |
            ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Right))
        application_ui::open_output_context_menu(static_cast<int>(tab),
            context_menu_open_origin_t::pointer);
    application_ui::render_output_context_menu();
}

}
