#include "core/ui/ide_shell.hpp"

#include "core/ui/application_view_registry.hpp"
#include "core/ui/design_system.hpp"
#include "core/ui/task_center.hpp"
#include "core/ui/workspace_layout.hpp"
#include "core/settings/standalone_settings.hpp"
#include "ide_icons.h"
#include "imgui/imgui_internal.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <string_view>
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <iostream>
#endif
#if !defined(__EMSCRIPTEN__) && !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "helpers/diag_log.hpp"
#endif

namespace aida::ui::ide_shell {
namespace {

constexpr const char* kRootDockspaceName = "AiDA.RootDockSpace.v1";
#if defined(IMGUI_HAS_DOCK)
constexpr const char* kRootWindowName = "AiDA IDE###aida.shell.root";
constexpr const char* kCompatibilityWindowName = "Compatibility IDE###aida.view.shell.compatibility";
constexpr const char* kStatusWindowName = "AiDA Status###aida.shell.status";
#endif

struct state_t {
    bool initialized = false;
    bool compatibility_host_active = false;
    int submitted_frame = -1;
    ImVec2 compatibility_position{0.0f, 0.0f};
    ImVec2 compatibility_size{0.0f, 0.0f};
};

state_t& state() noexcept
{
    static state_t value;
    return value;
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
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f * scale, 2.0f * scale));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin(kStatusWindowName, nullptr, flags)) {
        const std::string_view workspace = workspace_layout::active_preset_name();
        const bool compact = viewport->WorkSize.x / scale < 900.0f;
        ImGui::TextDisabled(compact ? "%.*s" : "Workspace: %.*s",
            static_cast<int>(workspace.empty() ? 7u : workspace.size()),
            workspace.empty() ? "Unknown" : workspace.data());
        design::tooltip_for_last_item("Active workspace. Use the Workspace menu to switch, save, lock, or recover layouts.");
        ImGui::SameLine();
        const auto status = task_center::status_summary();
        char tasks[128] = {};
        if (status.running == 0 && status.queued == 0 && status.cancellation_requested == 0)
            std::snprintf(tasks, sizeof(tasks), compact ? "Idle###aida.status.tasks" :
                "Tasks: idle###aida.status.tasks");
        else if (compact)
            std::snprintf(tasks, sizeof(tasks), "Tasks %u/%u/%u###aida.status.tasks",
                status.running, status.queued, status.cancellation_requested);
        else
            std::snprintf(tasks, sizeof(tasks), "Tasks: %u running, %u queued, %u cancelling###aida.status.tasks",
                status.running, status.queued, status.cancellation_requested);
        if (ImGui::SmallButton(tasks))
            application_views::open_or_focus(stable_view_id_t("view.background_tasks"));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::semantics::register_last_item(
            "aida.status.background-tasks", "status-action");
#endif
        design::tooltip_for_last_item("Open Background Tasks");
        design::draw_focus_ring_for_last_item();
        if (status.failures != 0 || status.unacknowledged_diagnostics != 0) {
            ImGui::SameLine();
            char diagnostics[96] = {};
            std::snprintf(diagnostics, sizeof(diagnostics), compact ?
                "Diag: %u###aida.status.diagnostics" : "Diagnostics: %u###aida.status.diagnostics",
                status.unacknowledged_diagnostics);
            if (ImGui::SmallButton(diagnostics))
                application_views::open_or_focus(stable_view_id_t("view.diagnostics"));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            aida::preview::semantics::register_last_item(
                "aida.status.diagnostics", "status-action");
#endif
            design::tooltip_for_last_item("Open persistent diagnostics and recovery actions");
            design::draw_focus_ring_for_last_item();
        }
        if (g_sa_settings.ui_diagnostics_mode) {
            const float frame_ms = ImGui::GetIO().Framerate > 0.0f ? 1000.0f / ImGui::GetIO().Framerate : 0.0f;
            char frame[64] = {};
            std::snprintf(frame, sizeof(frame), "%.1f ms", frame_ms);
            const float frame_width = ImGui::CalcTextSize(frame).x;
            ImGui::SameLine((std::max)(ImGui::GetCursorPosX(), ImGui::GetWindowWidth() - frame_width - 14.0f * scale));
            ImGui::TextDisabled("%s", frame);
        }
    }
    ImGui::End();
    ImGui::PopStyleVar(3);
#endif
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
    const float width = 52.0f * scale;
    const float chrome_height = 0.0f;
    const float status_height = 24.0f * scale;
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + chrome_height), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(width,
        (std::max)(1.0f, viewport->WorkSize.y - chrome_height - status_height)), ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.0f * scale, 8.0f * scale));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin("Activity###aida.shell.activity", nullptr, flags)) {
        struct activity_entry_t {
            const char* button;
            const char* tooltip;
            const char* view;
        };
        constexpr activity_entry_t entries[] = {
            {ICON_FILES_EMPTY "##activity_explorer", "Project Explorer", "view.project_explorer"},
            {ICON_SEARCH "##activity_search", "Workspace Search", "view.workspace_search"},
            {ICON_HISTORY "##activity_recent", "Recent", "view.recent"}
        };
        const ImVec2 size(40.0f * scale, 40.0f * scale);
        for (const auto& entry : entries) {
            const stable_view_id_t id(entry.view);
            const bool open = application_views::is_open(id);
            if (open)
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive));
            if (ImGui::Button(entry.button, size))
                application_views::open_or_focus(id);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string semantic_id = aida::preview::semantics::stable_id(
                "aida.activity", entry.view);
            aida::preview::semantics::register_last_item(
                semantic_id, "activity-view-action");
#endif
            if (open)
                ImGui::PopStyleColor();
            design::tooltip_for_last_item(entry.tooltip);
            design::draw_focus_ring_for_last_item();
        }
        const float settings_y = ImGui::GetWindowHeight() - size.y - 10.0f * scale;
        if (ImGui::GetCursorPosY() < settings_y)
            ImGui::SetCursorPosY(settings_y);
        if (ImGui::Button(ICON_COG "##activity_settings", size))
            application_views::open_or_focus(stable_view_id_t("view.settings"));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::semantics::register_last_item(
            "aida.activity.settings", "activity-view-action");
#endif
        design::tooltip_for_last_item("Settings");
        design::draw_focus_ring_for_last_item();
    }
    ImGui::End();
    ImGui::PopStyleVar(3);
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
    application_views::begin_frame();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport)
        return;
#if defined(IMGUI_HAS_DOCK)
    const ImGuiID dockspace = root_dockspace_id();
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float chrome_height = 0.0f;
    const float activity_width = g_sa_settings.activity_bar_visible ? 52.0f * scale : 0.0f;
    const float status_height = 24.0f * scale;
    const ImVec2 dock_position(
        viewport->WorkPos.x + activity_width,
        viewport->WorkPos.y + chrome_height);
    const ImVec2 dock_size(
        viewport->WorkSize.x > activity_width ? viewport->WorkSize.x - activity_width : 1.0f,
        viewport->WorkSize.y > chrome_height + status_height
            ? viewport->WorkSize.y - chrome_height - status_height
            : 1.0f);

    ImGui::SetNextWindowPos(viewport->WorkPos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(viewport->WorkSize, ImGuiCond_Always);
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
    application_views::render_registry_owned_windows();
    render_activity_bar();
    render_status_bar();
    workspace_layout::persist_if_requested();
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

void render_compatibility_host(compatibility_renderer_t renderer, void* context)
{
    if (!renderer)
        return;
#if defined(IMGUI_HAS_DOCK)
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=before_style\n";
#endif
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=before_begin\n";
#endif
    ImGui::Begin(kCompatibilityWindowName, nullptr,
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoCollapse);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=after_begin\n";
#endif
    ImGui::PopStyleVar();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=after_style\n";
#endif
    state_t& current = state();
    current.compatibility_position = ImGui::GetCursorScreenPos();
    current.compatibility_size = ImGui::GetContentRegionAvail();
    current.compatibility_host_active = true;
    struct compatibility_scope_t {
        state_t& state;
        ~compatibility_scope_t() { state.compatibility_host_active = false; }
    } compatibility_scope{current};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=before_renderer\n";
#endif
    renderer(context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::cerr << "[AIDA_PREVIEW] compatibility stage=after_renderer\n";
#endif
    ImGui::End();
#else
    renderer(context);
#endif
}

bool compatibility_content_rect(ImVec2& position, ImVec2& size) noexcept
{
    const state_t& current = state();
    if (!current.compatibility_host_active ||
        current.compatibility_size.x < 1.0f || current.compatibility_size.y < 1.0f)
        return false;
    position = current.compatibility_position;
    size = current.compatibility_size;
    return true;
}

}
