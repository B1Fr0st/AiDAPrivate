#include "core/ui/ide_shell.hpp"

#include "core/ui/application_view_registry.hpp"
#include "core/ui/application_ui_runtime.hpp"
#include "core/ui/design_system.hpp"
#include "core/ui/explorer_views.hpp"
#include "core/ui/task_center.hpp"
#include "core/ui/theme.hpp"
#include "core/ui/workspace_layout.hpp"
#include "core/ai/standalone_chat.hpp"
#include "core/debugger/debugger_engine.hpp"
#include "core/debugger/debugger_view.hpp"
#include "core/disasm/disasm_view.hpp"
#include "core/editor/code_editor.hpp"
#include "core/network/network_view.hpp"
#include "core/runtime/standalone_driver.hpp"
#include "core/session/analysis_session.hpp"
#include "core/settings/standalone_settings.hpp"
#include "helpers/globals.h"
#include "ide_icons.h"
#include "imgui/imgui_internal.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#endif
#if !defined(__EMSCRIPTEN__) && !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "helpers/diag_log.hpp"
#endif

namespace aida::ui::ide_shell {
namespace {

constexpr const char* kRootDockspaceName = "AiDA.RootDockSpace.v1";
constexpr const char* kChromeWindowName = "AiDA Chrome###aida.shell.chrome";
#if defined(IMGUI_HAS_DOCK)
constexpr const char* kRootWindowName = "AiDA IDE###aida.shell.root";
constexpr const char* kStatusWindowName = "AiDA Status###aida.shell.status";
#endif

struct state_t {
    bool initialized = false;
    bool chrome_surface_active = false;
    int submitted_frame = -1;
    int primary_surfaces_frame = -1;
};

state_t& state() noexcept
{
    static state_t value;
    return value;
}

float chrome_height_for(const ImGuiViewport* viewport) noexcept
{
    if (!viewport)
        return 0.0f;
    const float dpi = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const auto metrics = aida::ui::shell_metrics(dpi);
    return metrics.title_h + metrics.menu_h;
}

enum class status_action_t : std::uint8_t {
    none,
    sessions,
    debugger,
    network,
    mcp,
    driver,
    tasks,
    diagnostics
};

struct status_segment_t {
    const char* id = nullptr;
    const char* label = nullptr;
    const char* tooltip = nullptr;
    status_action_t action = status_action_t::none;
    design::semantic_t semantic = design::semantic_t::neutral;
    float minimum_width = 0.0f;
    float maximum_width = 0.0f;
    float width = 0.0f;
    bool visible = false;
    bool trailing = false;
};

void invoke_status_action(status_action_t action) noexcept
{
    const char* view = nullptr;
    switch (action) {
    case status_action_t::sessions: view = "view.sessions"; break;
    case status_action_t::debugger: view = "view.debug.cpu"; break;
    case status_action_t::network: view = "view.network.capture"; break;
    case status_action_t::mcp: view = "view.mcp_log"; break;
    case status_action_t::driver: view = "view.driver_log"; break;
    case status_action_t::tasks: view = "view.background_tasks"; break;
    case status_action_t::diagnostics: view = "view.diagnostics"; break;
    case status_action_t::none: break;
    }
    if (view)
        application_views::open_or_focus(stable_view_id_t(view));
}

float desired_status_width(const status_segment_t& segment, float scale) noexcept
{
    const float text = ImGui::CalcTextSize(segment.label ? segment.label : "").x + 16.0f * scale;
    return (std::max)(segment.minimum_width,
        (std::min)(segment.maximum_width, text));
}

void render_status_segment(const status_segment_t& segment, float height, float scale) noexcept
{
    if (!segment.visible || segment.width <= 0.0f)
        return;
    ImGui::PushID(segment.id ? segment.id : "status");
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const bool pressed = ImGui::InvisibleButton("##segment", ImVec2(segment.width, height));
    const bool hovered = ImGui::IsItemHovered();
    const auto& theme = aida::ui::resolved();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (hovered)
        draw->AddRectFilled(origin, ImVec2(origin.x + segment.width, origin.y + height),
            aida::ui::with_alpha(theme.accent_u32, 0.13f));
    const ImVec2 text_min(origin.x + 8.0f * scale,
        origin.y + (height - ImGui::GetFontSize()) * 0.5f);
    const ImVec2 text_max(origin.x + segment.width - 8.0f * scale, origin.y + height);
    const ImU32 text_color = segment.semantic == design::semantic_t::neutral
        ? theme.text_secondary : design::semantic_color(segment.semantic);
    draw->PushClipRect(origin, ImVec2(origin.x + segment.width, origin.y + height), true);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(text_color));
    ImGui::RenderTextEllipsis(draw, text_min, text_max, text_max.x,
        segment.label ? segment.label : "", nullptr, nullptr);
    ImGui::PopStyleColor();
    if (segment.semantic != design::semantic_t::neutral)
        draw->AddCircleFilled(ImVec2(origin.x + 4.0f * scale, origin.y + height * 0.5f),
            1.5f * scale, text_color);
    draw->PopClipRect();
    draw->AddLine(ImVec2(origin.x + segment.width, origin.y + 4.0f * scale),
        ImVec2(origin.x + segment.width, origin.y + height - 4.0f * scale),
        theme.border_subtle);
    if (pressed)
        invoke_status_action(segment.action);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::semantics::register_last_item(
        aida::preview::semantics::stable_id("aida.status", segment.id ? segment.id : "segment"),
        "status-segment");
#endif
    design::tooltip_for_last_item(segment.tooltip ? segment.tooltip : segment.label);
    design::draw_focus_ring_for_last_item();
    ImGui::PopID();
}

const char* debugger_status_label(debugger_engine::dbg_status_t status) noexcept
{
    switch (status) {
    case debugger_engine::dbg_status_t::running: return "Running";
    case debugger_engine::dbg_status_t::paused: return "Paused";
    case debugger_engine::dbg_status_t::stepping: return "Stepping";
    case debugger_engine::dbg_status_t::terminated: return "Terminated";
    case debugger_engine::dbg_status_t::idle: return "Idle";
    }
    return "Unknown";
}

void render_status_bar() noexcept
{
#if defined(IMGUI_HAS_DOCK)
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport)
        return;
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float height = 24.0f * scale;
    const ImVec2 position(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - height);
    ImGui::SetNextWindowPos(position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height), ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    if (ImGui::Begin(kStatusWindowName, nullptr, flags)) {
        const std::string_view workspace = workspace_layout::active_preset_name();
        const bool compact = viewport->WorkSize.x / scale < 900.0f;
        const auto status = task_center::status_summary();
        char target[256] = {};
        char target_tooltip[512] = {};
        const std::size_t session_index = analysis_session::active_session_idx();
        const auto session = session_index < analysis_session::session_count()
            ? analysis_session::session_handle_at(session_index) : nullptr;
        if (session) {
            const char* name = session->filename.empty() ? session->session_name.c_str() : session->filename.c_str();
            if (session->attached_pid != 0)
                std::snprintf(target, sizeof(target), compact ? "%s · %u" : "%s · PID %u",
                    name, session->attached_pid);
            else
                std::snprintf(target, sizeof(target), "%s", name);
            std::snprintf(target_tooltip, sizeof(target_tooltip), "%s%s%s",
                session->path.empty() ? name : session->path.c_str(),
                session->session_name.empty() ? "" : "\nSession: ",
                session->session_name.empty() ? "" : session->session_name.c_str());
        } else {
            std::snprintf(target, sizeof(target), "No target");
            std::snprintf(target_tooltip, sizeof(target_tooltip),
                "No active analysis or process session. Open Sessions to select a target.");
        }

        char location[128] = {};
        char location_tooltip[192] = {};
		const auto focused = application_views::registry().focused_instance();
		const auto editor_document = code_editor_widget::document_state();
		const bool editor_focused = focused && focused->view.value() == "document.code" && editor_document.active;
        if (editor_focused) {
            int line = 0;
            int column = 0;
            code_editor_widget::get_caret(line, column);
            std::snprintf(location, sizeof(location), code_editor_widget::has_selection()
                ? "Ln %d, Col %d · selection" : "Ln %d, Col %d", line + 1, column + 1);
            std::snprintf(location_tooltip, sizeof(location_tooltip),
				"Caret in %s%s", editor_document.filename.empty() ? "active code document" : editor_document.filename.c_str(),
                code_editor_widget::has_selection() ? " with selected text" : "");
        } else if (const auto workspace_handle = analysis_session::active_workspace()) {
            const auto selection = workspace_handle->view_state().selection;
            if (selection) {
                std::snprintf(location, sizeof(location), "0x%llX",
                    static_cast<unsigned long long>(selection->value));
                std::snprintf(location_tooltip, sizeof(location_tooltip),
                    "Current analysis selection: 0x%llX",
                    static_cast<unsigned long long>(selection->value));
            }
        }

        char workspace_label[96] = {};
        std::snprintf(workspace_label, sizeof(workspace_label), compact ? "%.*s" : "Workspace: %.*s",
            static_cast<int>(workspace.empty() ? 7u : workspace.size()),
            workspace.empty() ? "Unknown" : workspace.data());

        char debugger[96] = {};
        const auto debugger_state = debugger_engine::g_state.status.load(std::memory_order_acquire);
        const bool debugger_available = driver_bridge::attached_pid() != 0 ||
            debugger_state != debugger_engine::dbg_status_t::idle;
        if (debugger_available)
            std::snprintf(debugger, sizeof(debugger), compact ? "Debug: %s" : "Debugger: %s",
                debugger_status_label(debugger_state));

        char network[96] = {};
        const bool network_available = network_view::g_state.cap_running.load(std::memory_order_acquire) ||
            network_view::g_state.cap_start_pending.load(std::memory_order_acquire) ||
            network_view::g_state.cap_stop_pending.load(std::memory_order_acquire);
        if (network_available)
            std::snprintf(network, sizeof(network), "Capture: %s",
                network_view::g_state.cap_running.load(std::memory_order_acquire) ? "live" : "changing");

        char mcp[96] = {};
        auto& mcp_server = get_local_mcp_server();
        const bool mcp_available = mcp_server.is_running();
        if (mcp_available) {
            if (compact)
                std::snprintf(mcp, sizeof(mcp), "MCP: on");
            else
                std::snprintf(mcp, sizeof(mcp), "MCP: localhost:%d", mcp_server.get_port());
        }

        char driver[192] = {};
        const bool driver_available = !globals::ui::status_driver_info.empty();
        if (driver_available) {
            if (compact)
                std::snprintf(driver, sizeof(driver), "Driver: ready");
            else
                std::snprintf(driver, sizeof(driver), "Driver: %s",
                    globals::ui::status_driver_info.c_str());
        }

        char tasks[128] = {};
        if (status.running == 0 && status.queued == 0 && status.cancellation_requested == 0)
            std::snprintf(tasks, sizeof(tasks), compact ? "Idle" :
                "Tasks: idle");
        else if (compact)
            std::snprintf(tasks, sizeof(tasks), "Tasks %u/%u/%u",
                status.running, status.queued, status.cancellation_requested);
        else
            std::snprintf(tasks, sizeof(tasks), "Tasks: %u running, %u queued, %u cancelling",
                status.running, status.queued, status.cancellation_requested);
        char diagnostics[96] = {};
        std::snprintf(diagnostics, sizeof(diagnostics), compact ? "Diag: %u" : "Diagnostics: %u",
            status.unacknowledged_diagnostics);
        char frame[64] = {};
        if (g_sa_settings.ui_diagnostics_mode) {
            const float frame_ms = ImGui::GetIO().Framerate > 0.0f ? 1000.0f / ImGui::GetIO().Framerate : 0.0f;
            std::snprintf(frame, sizeof(frame), "%.1f ms", frame_ms);
        }

        std::array<status_segment_t, 10> segments{{
            {"target", target, target_tooltip, status_action_t::sessions, design::semantic_t::neutral,
                104.0f * scale, 300.0f * scale, 0.0f, true, false},
            {"location", location, location_tooltip, status_action_t::none, design::semantic_t::brand,
                84.0f * scale, 190.0f * scale, 0.0f, location[0] != '\0', false},
            {"workspace", workspace_label, "Active workspace. Use the Workspace menu to switch, save, lock, or recover layouts.",
                status_action_t::none, design::semantic_t::neutral, 90.0f * scale, 180.0f * scale, 0.0f, true, false},
            {"debugger", debugger, "Open the CPU debugger view", status_action_t::debugger,
                debugger_state == debugger_engine::dbg_status_t::paused ? design::semantic_t::warning : design::semantic_t::live,
                90.0f * scale, 150.0f * scale, 0.0f, debugger_available, false},
            {"network", network, "Open network capture", status_action_t::network, design::semantic_t::live,
                90.0f * scale, 140.0f * scale, 0.0f, network_available, false},
            {"mcp", mcp, "Open MCP activity output", status_action_t::mcp, design::semantic_t::success,
                76.0f * scale, 150.0f * scale, 0.0f, mcp_available, false},
            {"driver", driver, "Open driver diagnostics", status_action_t::driver, design::semantic_t::info,
                90.0f * scale, 210.0f * scale, 0.0f, driver_available, false},
            {"tasks", tasks, "Open Background Tasks", status_action_t::tasks,
                status.running || status.queued ? design::semantic_t::live : design::semantic_t::neutral,
                74.0f * scale, 220.0f * scale, 0.0f, true, true},
            {"diagnostics", diagnostics, "Open persistent diagnostics and recovery actions",
                status_action_t::diagnostics,
                status.unacknowledged_diagnostics ? design::semantic_t::error : design::semantic_t::neutral,
                72.0f * scale, 140.0f * scale, 0.0f, true, true},
            {"frame", frame, "UI frame time is visible because diagnostics mode is enabled",
                status_action_t::none, design::semantic_t::neutral,
                58.0f * scale, 82.0f * scale, 0.0f, g_sa_settings.ui_diagnostics_mode, true}
        }};

        const float available = ImGui::GetContentRegionAvail().x;
        float total = 0.0f;
        for (auto& segment : segments) {
            if (!segment.visible)
                continue;
            segment.width = desired_status_width(segment, scale);
            total += segment.width;
        }
        constexpr std::array<std::size_t, 5> hide_order{{6, 5, 4, 3, 9}};
        for (const std::size_t index : hide_order) {
            if (total <= available || !segments[index].visible)
                continue;
            total -= segments[index].width;
            segments[index].visible = false;
            segments[index].width = 0.0f;
        }
        if (total > available) {
            for (const std::size_t index : {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{7}}) {
                if (!segments[index].visible || total <= available)
                    continue;
                const float reduction = (std::min)(total - available,
                    segments[index].width - segments[index].minimum_width);
                segments[index].width -= reduction;
                total -= reduction;
            }
        }
        if (total > available && segments[1].visible) {
            total -= segments[1].width;
            segments[1].visible = false;
            segments[1].width = 0.0f;
        }
        if (total > available && segments[0].visible) {
            const float reduction = (std::min)(total - available,
                segments[0].width - 56.0f * scale);
            segments[0].width -= reduction;
            total -= reduction;
        }

        float trailing_width = 0.0f;
        for (const auto& segment : segments)
            if (segment.visible && segment.trailing)
                trailing_width += segment.width;
        bool rendered = false;
        for (const auto& segment : segments) {
            if (!segment.visible || segment.trailing)
                continue;
            if (rendered)
                ImGui::SameLine(0.0f, 0.0f);
            render_status_segment(segment, height, scale);
            rendered = true;
        }
        if (trailing_width > 0.0f) {
            if (rendered)
                ImGui::SameLine(0.0f, 0.0f);
            ImGui::SetCursorPosX((std::max)(ImGui::GetCursorPosX(), available - trailing_width));
            bool trailing_rendered = false;
            for (const auto& segment : segments) {
                if (!segment.visible || !segment.trailing)
                    continue;
                if (trailing_rendered)
                    ImGui::SameLine(0.0f, 0.0f);
                render_status_segment(segment, height, scale);
                trailing_rendered = true;
            }
        }
        ImGui::GetWindowDrawList()->AddLine(position,
            ImVec2(position.x + viewport->WorkSize.x, position.y),
            aida::ui::resolved().border_subtle);
    }
    ImGui::End();
    ImGui::PopStyleVar(4);
#endif
}

enum class activity_glyph_t : std::uint8_t {
    analysis,
    debugging,
    memory,
    types,
    network,
    programming,
    automation,
    explorer,
    search,
    recent,
    more,
    settings
};

void draw_activity_glyph(ImDrawList* draw, activity_glyph_t glyph, ImVec2 center,
    float scale, ImU32 color) noexcept
{
    const float unit = scale;
    const float stroke = (std::max)(1.25f, 1.5f * unit);
    switch (glyph) {
    case activity_glyph_t::analysis:
        draw->AddCircle(center, 7.0f * unit, color, 20, stroke);
        draw->AddLine(ImVec2(center.x + 5.0f * unit, center.y + 5.0f * unit),
            ImVec2(center.x + 10.0f * unit, center.y + 10.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x - 3.5f * unit, center.y),
            ImVec2(center.x + 3.5f * unit, center.y), color, stroke);
        draw->AddLine(ImVec2(center.x, center.y - 3.5f * unit),
            ImVec2(center.x, center.y + 3.5f * unit), color, stroke);
        break;
    case activity_glyph_t::debugging:
        draw->AddRect(ImVec2(center.x - 6.0f * unit, center.y - 6.0f * unit),
            ImVec2(center.x + 6.0f * unit, center.y + 7.0f * unit), color, 3.0f * unit, 0, stroke);
        draw->AddCircleFilled(ImVec2(center.x - 2.3f * unit, center.y - 1.5f * unit), 1.1f * unit, color);
        draw->AddCircleFilled(ImVec2(center.x + 2.3f * unit, center.y - 1.5f * unit), 1.1f * unit, color);
        for (float offset : {-4.0f, 0.0f, 4.0f}) {
            draw->AddLine(ImVec2(center.x - 9.0f * unit, center.y + offset * unit),
                ImVec2(center.x - 6.0f * unit, center.y + offset * unit), color, stroke);
            draw->AddLine(ImVec2(center.x + 6.0f * unit, center.y + offset * unit),
                ImVec2(center.x + 9.0f * unit, center.y + offset * unit), color, stroke);
        }
        break;
    case activity_glyph_t::memory:
        draw->AddRect(ImVec2(center.x - 7.0f * unit, center.y - 6.0f * unit),
            ImVec2(center.x + 7.0f * unit, center.y + 6.0f * unit), color, 2.0f * unit, 0, stroke);
        for (float offset : {-4.0f, 0.0f, 4.0f}) {
            draw->AddLine(ImVec2(center.x + offset * unit, center.y - 9.0f * unit),
                ImVec2(center.x + offset * unit, center.y - 6.0f * unit), color, stroke);
            draw->AddLine(ImVec2(center.x + offset * unit, center.y + 6.0f * unit),
                ImVec2(center.x + offset * unit, center.y + 9.0f * unit), color, stroke);
        }
        draw->AddLine(ImVec2(center.x - 3.5f * unit, center.y),
            ImVec2(center.x + 3.5f * unit, center.y), color, stroke);
        break;
    case activity_glyph_t::types:
        draw->AddRect(ImVec2(center.x - 8.0f * unit, center.y - 8.0f * unit),
            ImVec2(center.x + 8.0f * unit, center.y + 8.0f * unit), color, 2.0f * unit, 0, stroke);
        draw->AddLine(ImVec2(center.x - 2.0f * unit, center.y - 8.0f * unit),
            ImVec2(center.x - 2.0f * unit, center.y + 8.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x - 2.0f * unit, center.y - 2.0f * unit),
            ImVec2(center.x + 8.0f * unit, center.y - 2.0f * unit), color, stroke);
        break;
    case activity_glyph_t::network:
        draw->AddCircleFilled(ImVec2(center.x, center.y - 7.0f * unit), 2.2f * unit, color);
        draw->AddCircleFilled(ImVec2(center.x - 8.0f * unit, center.y + 6.0f * unit), 2.2f * unit, color);
        draw->AddCircleFilled(ImVec2(center.x + 8.0f * unit, center.y + 6.0f * unit), 2.2f * unit, color);
        draw->AddLine(ImVec2(center.x - 1.2f * unit, center.y - 5.0f * unit),
            ImVec2(center.x - 6.8f * unit, center.y + 4.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x + 1.2f * unit, center.y - 5.0f * unit),
            ImVec2(center.x + 6.8f * unit, center.y + 4.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x - 5.5f * unit, center.y + 6.0f * unit),
            ImVec2(center.x + 5.5f * unit, center.y + 6.0f * unit), color, stroke);
        break;
    case activity_glyph_t::programming:
        draw->AddLine(ImVec2(center.x - 2.5f * unit, center.y - 7.0f * unit),
            ImVec2(center.x - 8.0f * unit, center.y), color, stroke);
        draw->AddLine(ImVec2(center.x - 8.0f * unit, center.y),
            ImVec2(center.x - 2.5f * unit, center.y + 7.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x + 2.5f * unit, center.y - 7.0f * unit),
            ImVec2(center.x + 8.0f * unit, center.y), color, stroke);
        draw->AddLine(ImVec2(center.x + 8.0f * unit, center.y),
            ImVec2(center.x + 2.5f * unit, center.y + 7.0f * unit), color, stroke);
        break;
    case activity_glyph_t::automation:
        draw->AddCircle(center, 7.0f * unit, color, 20, stroke);
        for (int index = 0; index < 8; ++index) {
            const float x = index == 0 || index == 4 ? 0.0f : (index < 4 ? 1.0f : -1.0f);
            const float y = index == 2 || index == 6 ? 0.0f : (index < 2 || index > 6 ? 1.0f : -1.0f);
            const ImVec2 direction(x, y);
            draw->AddLine(ImVec2(center.x + direction.x * 7.5f * unit, center.y + direction.y * 7.5f * unit),
                ImVec2(center.x + direction.x * 10.0f * unit, center.y + direction.y * 10.0f * unit), color, stroke);
        }
        draw->AddCircleFilled(center, 2.5f * unit, color);
        break;
    case activity_glyph_t::explorer:
        draw->AddRect(ImVec2(center.x - 8.0f * unit, center.y - 5.0f * unit),
            ImVec2(center.x + 8.0f * unit, center.y + 7.0f * unit), color, 2.0f * unit, 0, stroke);
        draw->AddLine(ImVec2(center.x - 7.0f * unit, center.y - 5.0f * unit),
            ImVec2(center.x - 3.0f * unit, center.y - 9.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x - 3.0f * unit, center.y - 9.0f * unit),
            ImVec2(center.x + 2.0f * unit, center.y - 9.0f * unit), color, stroke);
        draw->AddLine(ImVec2(center.x + 2.0f * unit, center.y - 9.0f * unit),
            ImVec2(center.x + 4.0f * unit, center.y - 5.0f * unit), color, stroke);
        break;
    case activity_glyph_t::search:
        draw->AddCircle(ImVec2(center.x - 2.0f * unit, center.y - 2.0f * unit),
            6.0f * unit, color, 20, stroke);
        draw->AddLine(ImVec2(center.x + 2.5f * unit, center.y + 2.5f * unit),
            ImVec2(center.x + 9.0f * unit, center.y + 9.0f * unit), color, stroke);
        break;
    case activity_glyph_t::recent:
        draw->AddCircle(center, 8.0f * unit, color, 20, stroke);
        draw->AddLine(center, ImVec2(center.x, center.y - 5.0f * unit), color, stroke);
        draw->AddLine(center, ImVec2(center.x + 4.5f * unit, center.y + 2.5f * unit), color, stroke);
        break;
    case activity_glyph_t::more:
        for (float offset : {-6.0f, 0.0f, 6.0f})
            draw->AddCircleFilled(ImVec2(center.x + offset * unit, center.y),
                1.6f * unit, color, 12);
        break;
    case activity_glyph_t::settings:
        draw->AddCircle(center, 4.0f * unit, color, 20, stroke);
        draw->AddCircle(center, 8.0f * unit, color, 20, stroke);
        for (float offset : {-7.0f, 7.0f}) {
            draw->AddLine(ImVec2(center.x + offset * unit, center.y - 3.0f * unit),
                ImVec2(center.x + offset * unit, center.y + 3.0f * unit), color, stroke);
            draw->AddLine(ImVec2(center.x - 3.0f * unit, center.y + offset * unit),
                ImVec2(center.x + 3.0f * unit, center.y + offset * unit), color, stroke);
        }
        break;
    }
}

bool render_activity_button(const char* stable_id, const char* action_id,
    const char* tooltip, activity_glyph_t glyph, bool active,
    ImVec2 size, float scale) noexcept
{
    ImGui::PushID(stable_id);
    const auto& theme = aida::ui::resolved();
    const auto capability = action_id
        ? application_ui::action_capability(action_id)
        : capability_state_t::available();
    const bool enabled = capability.visible && capability.enabled;
    const ImVec2 minimum = ImGui::GetCursorScreenPos();
    ImGui::PushStyleColor(ImGuiCol_Button, active
        ? ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(theme.accent_u32, 0.18f))
        : ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
        ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(theme.accent_u32, 0.13f)));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
        ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(theme.accent_u32, 0.24f)));
    if (!enabled)
        ImGui::BeginDisabled();
    const bool invoked = ImGui::Button("##activity", size);
    if (!enabled)
        ImGui::EndDisabled();
    ImGui::PopStyleColor(3);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (active) {
        draw->AddRectFilled(minimum, ImVec2(minimum.x + 3.0f * scale, minimum.y + size.y),
            theme.accent_u32, 2.0f * scale);
    }
    const ImU32 glyph_color = !enabled ? theme.text_dim : active ? theme.accent_u32 :
        (ImGui::IsItemHovered() || ImGui::IsItemFocused() ? theme.text_primary : theme.text_secondary);
    draw_activity_glyph(draw, glyph,
        ImVec2(minimum.x + size.x * 0.5f, minimum.y + size.y * 0.5f), scale, glyph_color);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::semantics::register_last_item(
        aida::preview::semantics::stable_id("aida.activity", stable_id),
        "activity-action", false, !enabled);
#endif
    design::tooltip_for_last_item(enabled || capability.disabled_reason.empty()
        ? tooltip : capability.disabled_reason.c_str());
    design::draw_focus_ring_for_last_item();
    if (invoked && action_id)
        static_cast<void>(application_ui::execute_action(
            action_id, action_invocation_source_t::activity_bar));
    ImGui::PopID();
    return invoked;
}

void render_activity_overflow_action(const char* stable_id, const char* label,
    const char* action_id, bool selected, float scale) noexcept
{
    const auto capability = application_ui::action_capability(action_id);
    const bool enabled = capability.visible && capability.enabled;
    ImGui::PushID(stable_id);
    if (!enabled)
        ImGui::BeginDisabled();
    const bool invoked = ImGui::Selectable(label, selected,
        ImGuiSelectableFlags_None, ImVec2(0.0f, 30.0f * scale));
    if (!enabled)
        ImGui::EndDisabled();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::semantics::register_last_item(
        aida::preview::semantics::stable_id("aida.activity.overflow", stable_id),
        "activity-overflow-action", true, !enabled);
#endif
    design::tooltip_for_last_item(enabled || capability.disabled_reason.empty()
        ? label : capability.disabled_reason.c_str());
    design::draw_focus_ring_for_last_item();
    if (invoked)
        static_cast<void>(application_ui::execute_action(
            action_id, action_invocation_source_t::activity_bar));
    ImGui::PopID();
}

void render_activity_bar() noexcept
{
#if defined(IMGUI_HAS_DOCK)
    if (!g_sa_settings.activity_bar_visible)
        return;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport)
        return;
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float width = 48.0f * scale;
    const float chrome_height = chrome_height_for(viewport);
    const float status_height = 24.0f * scale;
    const float activity_height = (std::max)(1.0f,
        viewport->WorkSize.y - chrome_height - status_height);
    const float button_height = 34.0f * scale;
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + chrome_height), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(width, activity_height), ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.0f * scale, 6.0f * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 2.0f * scale));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus;
    flags |= ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    if (ImGui::Begin("Activity###aida.shell.activity", nullptr, flags)) {
        struct workspace_entry_t {
            const char* id;
            const char* action;
            const char* label;
            const char* tooltip;
            workspace_layout::workspace_preset_t preset;
            activity_glyph_t glyph;
        };
        constexpr workspace_entry_t workspaces[] = {
            {"workspace.analysis", "workspace.switch.analysis", "Analysis", "Analysis workspace", workspace_layout::workspace_preset_t::analysis, activity_glyph_t::analysis},
            {"workspace.debugging", "workspace.switch.debugging", "Debugging", "Debugging workspace", workspace_layout::workspace_preset_t::debugging, activity_glyph_t::debugging},
            {"workspace.memory", "workspace.switch.memory", "Memory", "Memory workspace", workspace_layout::workspace_preset_t::memory, activity_glyph_t::memory},
            {"workspace.types", "workspace.switch.types-structures", "Types and Structures", "Types and Structures workspace", workspace_layout::workspace_preset_t::types_structures, activity_glyph_t::types},
            {"workspace.network", "workspace.switch.network", "Network", "Network workspace", workspace_layout::workspace_preset_t::network, activity_glyph_t::network},
            {"workspace.programming", "workspace.switch.programming", "Programming", "Programming workspace", workspace_layout::workspace_preset_t::programming, activity_glyph_t::programming},
            {"workspace.automation", "workspace.switch.automation-ai", "Automation and AI", "Automation and AI workspace", workspace_layout::workspace_preset_t::automation_ai, activity_glyph_t::automation}
        };
        struct utility_entry_t {
            const char* id;
            const char* action;
            const char* label;
            const char* tooltip;
            const char* view;
            activity_glyph_t glyph;
        };
        constexpr utility_entry_t utilities[] = {
            {"utility.explorer", "view.focus.view.project_explorer", "Project Explorer", "Project Explorer", "view.project_explorer", activity_glyph_t::explorer},
            {"utility.search", "view.focus.view.workspace_search", "Workspace Search", "Workspace Search", "view.workspace_search", activity_glyph_t::search},
            {"utility.recent", "view.focus.view.recent", "Recent", "Recent files and sessions", "view.recent", activity_glyph_t::recent}
        };
        const ImVec2 size((std::max)(18.0f * scale, ImGui::GetContentRegionAvail().x),
            button_height);
        const auto focused = application_views::registry().focused_instance();
        const std::string_view focused_view = focused ? focused->view.value() : std::string_view{};
        const bool utility_focused = focused_view == "view.project_explorer" ||
            focused_view == "view.workspace_search" || focused_view == "view.recent" ||
            focused_view == "view.settings";
        const float stride = button_height + ImGui::GetStyle().ItemSpacing.y;
        const float decoration_height = 12.0f * scale;
        const float available_buttons = (std::max)(0.0f,
            ImGui::GetContentRegionAvail().y - decoration_height);
        const std::size_t maximum_slots = (std::max)(std::size_t{3},
            static_cast<std::size_t>(available_buttons / (std::max)(stride, 1.0f)));
        const bool overflow_required = maximum_slots <
            std::size(workspaces) + std::size(utilities) + 1;
        const std::size_t direct_workspace_capacity = overflow_required
            ? (std::min)(std::size(workspaces), maximum_slots > 2 ? maximum_slots - 2 : 1)
            : std::size(workspaces);
        std::array<bool, std::size(workspaces)> direct_workspaces{};
        for (std::size_t index = 0; index < direct_workspace_capacity; ++index)
            direct_workspaces[index] = true;
        const auto active_preset = workspace_layout::active_preset();
        std::size_t active_workspace_index = 0;
        for (std::size_t index = 0; index < std::size(workspaces); ++index)
            if (workspaces[index].preset == active_preset)
                active_workspace_index = index;
        if (overflow_required && !direct_workspaces[active_workspace_index]) {
            direct_workspaces[direct_workspace_capacity - 1] = false;
            direct_workspaces[active_workspace_index] = true;
        }
        for (std::size_t index = 0; index < std::size(workspaces); ++index) {
            if (!direct_workspaces[index])
                continue;
            const auto& entry = workspaces[index];
            const bool active = !utility_focused && workspace_layout::active_preset() == entry.preset;
            render_activity_button(entry.id, entry.action, entry.tooltip,
                entry.glyph, active, size, scale);
        }
        ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
        if (!overflow_required) {
            for (const auto& entry : utilities) {
                const bool active = focused_view == entry.view;
                render_activity_button(entry.id, entry.action, entry.tooltip,
                    entry.glyph, active, size, scale);
            }
        } else {
            const bool overflow_active = utility_focused && focused_view != "view.settings";
            if (render_activity_button("utility.more", nullptr, "More workspaces and tools",
                    activity_glyph_t::more, overflow_active, size, scale))
                ImGui::OpenPopup("More Activities###aida.activity.more.popup");
            ImGui::SetNextWindowSizeConstraints(ImVec2(210.0f * scale, 0.0f),
                ImVec2(320.0f * scale, activity_height * 0.88f));
            if (ImGui::BeginPopup("More Activities###aida.activity.more.popup")) {
                bool has_hidden_workspace = false;
                for (bool direct : direct_workspaces)
                    has_hidden_workspace |= !direct;
                if (has_hidden_workspace) {
                    ImGui::TextDisabled("WORKSPACES");
                    for (std::size_t index = 0; index < std::size(workspaces); ++index) {
                        if (direct_workspaces[index])
                            continue;
                        const auto& entry = workspaces[index];
                        render_activity_overflow_action(entry.id, entry.label, entry.action,
                            !utility_focused && active_preset == entry.preset, scale);
                    }
                    ImGui::Separator();
                }
                ImGui::TextDisabled("TOOLS");
                for (const auto& entry : utilities)
                    render_activity_overflow_action(entry.id, entry.label, entry.action,
                        focused_view == entry.view, scale);
                ImGui::EndPopup();
            }
        }
        const float settings_y = ImGui::GetWindowHeight() - size.y - 10.0f * scale;
        if (ImGui::GetCursorPosY() < settings_y)
            ImGui::SetCursorPosY(settings_y);
        render_activity_button("utility.settings", "view.focus.view.settings", "Settings",
            activity_glyph_t::settings, focused_view == "view.settings", size, scale);
    }
    ImGui::End();
    ImGui::PopStyleVar(4);
#endif
}

}

ImGuiID root_dockspace_id() noexcept
{
    return ImHashStr(kRootDockspaceName);
}

void configure_io(ImGuiIO& io) noexcept
{
#if defined(IMGUI_HAS_DOCK)
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
#endif
    io.ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable;
    io.IniFilename = nullptr;
}

bool initialize() noexcept
{
    state_t& current = state();
    if (current.initialized)
        return true;
    current.initialized = true;
    application_views::registry();
    const bool persistence_ready = workspace_layout::initialize(root_dockspace_id());
#if !defined(__EMSCRIPTEN__) && !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    diag::log_tagged_fmt("ide_shell", "initialized root=0x%08X docking=1 viewports=0 persistence=%d",
        root_dockspace_id(), persistence_ready ? 1 : 0);
#endif
    return persistence_ready;
}

void begin_frame() noexcept
{
    state_t& current = state();
    if (!current.initialized || ImGui::GetCurrentContext() == nullptr)
        return;
    const int frame = ImGui::GetFrameCount();
    if (current.submitted_frame == frame)
        return;
    current.chrome_surface_active = false;
    application_views::begin_frame();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport)
        return;
#if defined(IMGUI_HAS_DOCK)
    const ImGuiID dockspace = root_dockspace_id();
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float chrome_height = chrome_height_for(viewport);
    const float activity_width = g_sa_settings.activity_bar_visible ? 48.0f * scale : 0.0f;
    const float status_height = 24.0f * scale;
    const ImVec2 dock_position(
        viewport->WorkPos.x + activity_width,
        viewport->WorkPos.y + chrome_height);
    const ImVec2 dock_size(
        viewport->WorkSize.x > activity_width ? viewport->WorkSize.x - activity_width : 1.0f,
        viewport->WorkSize.y > chrome_height + status_height
            ? viewport->WorkSize.y - chrome_height - status_height
            : 1.0f);

    ImGui::SetNextWindowPos(dock_position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(dock_size, ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    const ImGuiWindowFlags root_flags =
        ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;
    ImGui::Begin(kRootWindowName, nullptr, root_flags);
    ImGui::PopStyleVar(3);
    ImGui::SetCursorScreenPos(dock_position);
    workspace_layout::prepare_root(dockspace, dock_position, dock_size);
    application_views::synchronize_workspace_visibility(
        workspace_layout::active_preset());
    ImGui::DockSpace(dockspace, dock_size, ImGuiDockNodeFlags_PassthruCentralNode);
    ImGui::End();
#else
    static_cast<void>(viewport);
#endif
    current.submitted_frame = frame;
}

void end_frame() noexcept
{
    state_t& current = state();
    if (!current.initialized || ImGui::GetCurrentContext() == nullptr)
        return;
    render_primary_surfaces();
    workspace_layout::render_global_dock_navigator();
    workspace_layout::settle_default_selection();
    workspace_layout::persist_if_requested();
}

void render_primary_surfaces() noexcept
{
    state_t& current = state();
    if (!current.initialized || ImGui::GetCurrentContext() == nullptr)
        return;
    const int frame = ImGui::GetFrameCount();
    if (current.primary_surfaces_frame == frame)
        return;
    if (workspace_layout::surfaces_ready()) {
        application_views::render_registry_owned_windows();
        explorer_views::render_global_file_operation_dialogs();
        disasm_view::render_static_patch_workflow();
        debugger_view::render_global_dialogs();
    }
    render_activity_bar();
    render_status_bar();
    current.primary_surfaces_frame = frame;
}

void shutdown() noexcept
{
    state_t& current = state();
    if (!current.initialized)
        return;
    if (ImGui::GetCurrentContext() != nullptr)
        workspace_layout::shutdown();
    current = {};
}

float reserved_chrome_height() noexcept
{
    return chrome_height_for(ImGui::GetMainViewport());
}

bool begin_global_chrome_surface() noexcept
{
    state_t& current = state();
    if (!current.initialized || current.chrome_surface_active)
        return false;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport)
        return false;
    const float height = chrome_height_for(viewport);
    ImGui::SetNextWindowPos(viewport->WorkPos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height), ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
#if defined(IMGUI_HAS_DOCK)
    flags |= ImGuiWindowFlags_NoDocking;
#endif
    const bool visible = ImGui::Begin(kChromeWindowName, nullptr, flags);
    ImGui::PopStyleVar(3);
    current.chrome_surface_active = true;
    return visible;
}

void end_global_chrome_surface() noexcept
{
    state_t& current = state();
    if (!current.chrome_surface_active)
        return;
    ImGui::End();
    current.chrome_surface_active = false;
}

}
