#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "application_view_registry.hpp"
#include "design_system.hpp"
#include "theme.hpp"

#include "../session/analysis_session.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace loading_binary_overlay {

enum class completion_action_t : unsigned int {
    none = 0,
    switch_to_disassembly = 1,
    switch_to_disassembly_or_hex = 2,
};

enum class phase_t : unsigned int {
    idle = 0,
    loading = 1,
    awaiting_analysis = 2,
    awaiting_pdb_decision = 3,
    loading_pdb = 4,
    finalizing = 5,
    complete = 6
};

namespace detail {

struct state_t {
    std::string session_id;
    std::string path;
    std::string filename;
    completion_action_t action = completion_action_t::none;
    std::atomic<bool> completion_applied{false};
    std::atomic<bool> cancellation_requested{false};
    std::atomic<float> visual_progress{0.f};
    std::atomic<float> visual_alpha{0.f};
    std::chrono::steady_clock::time_point tracked_at = std::chrono::steady_clock::now();
};

inline std::mutex& registry_mutex()
{
    static std::mutex value;
    return value;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& registry()
{
    static std::unordered_map<std::string, std::shared_ptr<state_t>> value;
    return value;
}

inline std::string derive_filename(const std::string& path)
{
    const size_t separator = path.find_last_of("/\\");
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

inline const char* phase_name(phase_t phase)
{
    switch (phase) {
    case phase_t::idle: return "idle";
    case phase_t::loading: return "loading";
    case phase_t::awaiting_analysis: return "awaiting_analysis";
    case phase_t::awaiting_pdb_decision: return "awaiting_pdb_decision";
    case phase_t::loading_pdb: return "loading_pdb";
    case phase_t::finalizing: return "finalizing";
    case phase_t::complete: return "complete";
    default: return "unknown";
    }
}

inline std::shared_ptr<state_t> selected_state()
{
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return {};
    const auto summary = analysis_session::summarize_session_at(active);
    if (summary.id.empty()) return {};
    std::lock_guard<std::mutex> lock(registry_mutex());
    const auto found = registry().find(summary.id);
    return found == registry().end() ? nullptr : found->second;
}

inline phase_t phase_for(const analysis_session::session_summary_t& summary)
{
    if (summary.pdb_loading) return phase_t::loading_pdb;
    if (summary.pdb_remote_pending || summary.pdb_local_pending)
        return phase_t::awaiting_pdb_decision;
    switch (summary.load_state) {
    case analysis_session::session_load_state_t::opening:
        return phase_t::loading;
    case analysis_session::session_load_state_t::analyzing:
        return phase_t::awaiting_analysis;
    case analysis_session::session_load_state_t::ready:
    case analysis_session::session_load_state_t::failed:
    case analysis_session::session_load_state_t::closed:
        return phase_t::complete;
    case analysis_session::session_load_state_t::closing:
        return phase_t::finalizing;
    default:
        return phase_t::idle;
    }
}

inline float progress_for(const analysis_session::session_summary_t& summary)
{
    if (summary.pdb_loading) {
        if (summary.pdb_bytes_total != 0) {
            return static_cast<float>((std::min)(1.0L,
                static_cast<long double>(summary.pdb_bytes_received) /
                static_cast<long double>(summary.pdb_bytes_total)));
        }
        return static_cast<float>((std::max)(0, (std::min)(100,
            summary.pdb_progress_percent))) / 100.0f;
    }
    const auto workspace = analysis_session::workspace_for_session_id(summary.id);
    if (!workspace) return -1.f;
    const auto progress = workspace->progress();
    if (summary.load_state == analysis_session::session_load_state_t::ready) return 1.f;
    if (progress.total_bytes != 0) {
        return (std::min)(0.99f, static_cast<float>(
            static_cast<long double>(progress.completed_bytes) /
            static_cast<long double>(progress.total_bytes)));
    }
    if (progress.total_units != 0) {
        return (std::min)(0.99f, static_cast<float>(
            static_cast<long double>(progress.completed_units) /
            static_cast<long double>(progress.total_units)));
    }
    return -1.f;
}

inline std::string label_for(const analysis_session::session_summary_t& summary)
{
    if (summary.error)
        return summary.error->stable_code() + ": " + summary.error->message;
    if (summary.pdb_loading || summary.pdb_remote_pending || summary.pdb_local_pending)
        return summary.pdb_status.empty() ? "Debug symbols require attention"
            : summary.pdb_status;
    const auto workspace = analysis_session::workspace_for_session_id(summary.id);
    if (!workspace) return "Opening mapped workspace...";
    const auto progress = workspace->progress();
    if (!progress.phase.empty()) return progress.phase;
    return summary.load_state == analysis_session::session_load_state_t::ready
        ? "Analysis ready"
        : "Analyzing workspace...";
}

}

inline void track_session(const std::string& session_id, const std::string& path,
                          completion_action_t action)
{
    if (session_id.empty() || path.empty()) return;
    auto value = std::make_shared<detail::state_t>();
    value->session_id = session_id;
    value->path = path;
    value->filename = detail::derive_filename(path);
    value->action = action;
    std::lock_guard<std::mutex> lock(detail::registry_mutex());
    detail::registry().insert_or_assign(session_id, std::move(value));
}

inline void release_session(const std::string& session_id)
{
    if (session_id.empty()) return;
    std::lock_guard<std::mutex> lock(detail::registry_mutex());
    detail::registry().erase(session_id);
}

inline phase_t current_phase()
{
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return phase_t::idle;
    return detail::phase_for(analysis_session::summarize_session_at(active));
}

inline const char* current_phase_name()
{
    return detail::phase_name(current_phase());
}

inline bool is_active()
{
    const phase_t phase = current_phase();
    return phase != phase_t::idle && phase != phase_t::complete;
}

inline bool is_waiting_for_user_decision()
{
    return current_phase() == phase_t::awaiting_pdb_decision;
}

inline void log_state(const char* reason)
{
    const size_t active = analysis_session::active_session_idx();
    const auto summary = active == static_cast<size_t>(-1)
        ? analysis_session::session_summary_t{}
        : analysis_session::summarize_session_at(active);
    diag::log_tagged_fmt("loading_binary_overlay",
        "state reason=%s session=%s binary_id=%s phase=%s load_state=%u readiness=%u error=%s",
        reason ? reason : "",
        summary.id.c_str(), summary.binary_id.c_str(), current_phase_name(),
        static_cast<unsigned>(summary.load_state),
        static_cast<unsigned>(summary.readiness),
        summary.error ? summary.error->stable_code().c_str() : "none");
}

inline bool cancel_queued_load(const char* reason)
{
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return false;
    const bool cancelled = analysis_session::cancel_session(active);
    diag::log_tagged_fmt("loading_binary_overlay",
        "cancel reason=%s active=%llu cancelled=%d",
        reason ? reason : "",
        static_cast<unsigned long long>(active), cancelled ? 1 : 0);
    return cancelled;
}

inline bool is_load_ready_for_tools()
{
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return false;
    const auto summary = analysis_session::summarize_session_at(active);
    return summary.load_state == analysis_session::session_load_state_t::ready &&
        (summary.kind == analysis_session::session_kind_t::live_attach ||
         summary.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
         summary.readiness == aida::analysis::workspace_readiness_t::partial);
}

inline bool is_blocking_views()
{
    return current_phase() == phase_t::loading;
}

inline void begin_load(const std::string& path,
                       completion_action_t action = completion_action_t::switch_to_disassembly)
{
    if (path.empty()) return;
    size_t existing = 0;
    if (analysis_session::find_session_by_path(path, &existing)) {
        (void)analysis_session::switch_session(existing);
        const auto summary = analysis_session::summarize_session_at(existing);
        track_session(summary.id, path, action);
        return;
    }
    if (!analysis_session::open_session(path)) return;
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return;
    const auto summary = analysis_session::summarize_session_at(active);
    track_session(summary.id, path, action);
}

inline void poll_completion()
{
    const size_t active = analysis_session::active_session_idx();
    if (active == static_cast<size_t>(-1)) return;
    const auto summary = analysis_session::summarize_session_at(active);
    if (summary.id.empty() || summary.load_state != analysis_session::session_load_state_t::ready)
        return;
    auto state = detail::selected_state();
    if (!state || state->completion_applied.exchange(true, std::memory_order_acq_rel))
        return;
    if (state->action == completion_action_t::switch_to_disassembly ||
        state->action == completion_action_t::switch_to_disassembly_or_hex)
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.disassembly"));
}

inline void render()
{
    poll_completion();
    const size_t active = analysis_session::active_session_idx();
    const auto summary = active == static_cast<size_t>(-1)
        ? analysis_session::session_summary_t{}
        : analysis_session::summarize_session_at(active);
    const bool visible = !summary.id.empty() &&
        ((summary.load_state != analysis_session::session_load_state_t::ready &&
          summary.load_state != analysis_session::session_load_state_t::closed) ||
         summary.pdb_loading);
    auto state = detail::selected_state();
    if (!state) return;
    const float delta = ImGui::GetIO().DeltaTime;
    float alpha = state->visual_alpha.load(std::memory_order_acquire);
    alpha += ((visible ? 1.f : 0.f) - alpha) * (std::min)(delta * 14.f, 1.f);
    if (std::fabs(alpha - (visible ? 1.f : 0.f)) < 0.003f)
        alpha = visible ? 1.f : 0.f;
    state->visual_alpha.store(alpha, std::memory_order_release);
    if (alpha < 0.005f) return;
    const float target_progress = detail::progress_for(summary);
    float progress = state->visual_progress.load(std::memory_order_acquire);
    if (target_progress >= 0.f) {
        if (progress < 0.f) progress = target_progress;
        else progress += (target_progress - progress) * (std::min)(delta * 9.f, 1.f);
    }
    else
        progress = -1.f;
    state->visual_progress.store(progress, std::memory_order_release);
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (!viewport) return;
    ImVec2 region_position = viewport->WorkPos;
    ImVec2 region_size = viewport->WorkSize;
#if defined(IMGUI_HAS_DOCK)
    if (ImGuiDockNode* central = ImGui::DockBuilderGetCentralNode(ImHashStr("AiDA.RootDockSpace.v1"));
        central && central->Size.x > 1.f && central->Size.y > 1.f) {
        region_position = central->Pos;
        region_size = central->Size;
    } else
#endif
    {
        const float scale = viewport->DpiScale > 0.f ? viewport->DpiScale : 1.f;
        const auto shell = aida::ui::shell_metrics(scale);
        const float chrome = shell.title_h + shell.menu_h;
        const float status = 24.f * scale;
        region_position.y += chrome;
        region_size.y = (std::max)(1.f, region_size.y - chrome - status);
    }
    ImDrawList* draw = ImGui::GetForegroundDrawList();
    draw->AddRectFilled(region_position,
        ImVec2(region_position.x + region_size.x, region_position.y + region_size.y),
        IM_COL32(0, 0, 0, static_cast<int>(150.f * alpha)));
    const float scale = viewport->DpiScale > 0.f ? viewport->DpiScale : 1.f;
    const float horizontal_margin = aida::ui::scale_px(16.f, scale);
    const float vertical_margin = aida::ui::scale_px(12.f, scale);
    const ImVec2 card_size(
        (std::max)(1.f, (std::min)(aida::ui::scale_px(620.f, scale), region_size.x - horizontal_margin * 2.f)),
        (std::max)(1.f, (std::min)(aida::ui::scale_px(300.f, scale), region_size.y - vertical_margin * 2.f)));
    const ImVec2 card_position(
        region_position.x + (region_size.x - card_size.x) * 0.5f,
        region_position.y + (region_size.y - card_size.y) * 0.5f);
    const bool failed = summary.load_state == analysis_session::session_load_state_t::failed;
    const bool cancelled = summary.error && summary.error->cancellation;
    const phase_t phase = current_phase();
    const bool owner_cancellable = !failed && !state->cancellation_requested.load(std::memory_order_acquire) &&
        (phase == phase_t::loading || phase == phase_t::awaiting_analysis || phase == phase_t::loading_pdb);
    const char* title = cancelled ? "Analysis cancelled" : failed ? "Analysis failed" :
        summary.pdb_loading ? "Loading debug symbols" :
        phase == phase_t::awaiting_pdb_decision ? "Debug symbols require a decision" :
        phase == phase_t::loading ? "Loading binary" :
        phase == phase_t::finalizing ? "Finalizing analysis" : "Analyzing binary";
    std::string label = state->cancellation_requested.load(std::memory_order_acquire)
        ? "Cancellation requested; waiting for the analysis owner to confirm a terminal state."
        : detail::label_for(summary);
    aida::ui::design::action_t actions[2]{};
    std::size_t action_count = 0;
    if (failed) {
        actions[action_count++] = {"loading.view-details", "View Details", "Details",
            "Open persistent diagnostics for this failure", nullptr, nullptr,
            aida::ui::components::button_kind_t::secondary, true, true, true};
    } else if (owner_cancellable) {
        actions[action_count++] = {"loading.cancel", "Cancel Analysis", "Cancel",
            "Request cancellation from the active analysis owner", nullptr,
            "The session remains active until the owner confirms cancellation.",
            aida::ui::components::button_kind_t::destructive, true, false, true};
    }
    aida::ui::design::state_presentation_t presentation;
    presentation.stable_id = "loading-binary.state";
    presentation.state = failed ? aida::ui::design::view_state_t::error
                                : aida::ui::design::view_state_t::loading;
    presentation.title = title;
    presentation.message = label.c_str();
    presentation.target = state->filename.c_str();
    presentation.stage = detail::phase_name(phase);
    const std::string diagnostic_id = summary.error ? summary.error->stable_code() : std::string();
    presentation.diagnostic_id = diagnostic_id.empty() ? nullptr : diagnostic_id.c_str();
    presentation.progress = progress;
    presentation.elapsed_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - state->tracked_at).count();
    presentation.actions = actions;
    presentation.action_count = action_count;

    ImGui::SetNextWindowPos(card_position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(card_size, ImGuiCond_Always);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("Analysis progress###aida.loading-binary", nullptr, flags);
    const auto result = aida::ui::design::render_state(presentation, card_size);
    ImGui::End();
    ImGui::PopStyleVar(2);
    if (result.invoked && result.id) {
        if (std::strcmp(result.id, "loading.cancel") == 0) {
            if (cancel_queued_load("human_overlay"))
                state->cancellation_requested.store(true, std::memory_order_release);
        } else if (std::strcmp(result.id, "loading.view-details") == 0) {
            static_cast<void>(aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.diagnostics")));
        }
    }
}

}
