#pragma once

#include "imgui/imgui.h"

#include "fonts.hpp"
#include "theme.hpp"
#include "ui_anim.hpp"

#include "../session/analysis_session.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <algorithm>
#include <atomic>
#include <cmath>
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
    std::atomic<float> visual_progress{0.f};
    std::atomic<float> visual_alpha{0.f};
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
    if (!workspace) return summary.load_state == analysis_session::session_load_state_t::opening
        ? 0.05f
        : 0.f;
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
    return 0.12f;
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
        globals::ui::active_center_view = center_view_t::disassembly;
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
    progress += (target_progress - progress) * (std::min)(delta * 9.f, 1.f);
    state->visual_progress.store(progress, std::memory_order_release);
    const auto& theme = aida::ui::resolved();
    const ImVec2 viewport = ImGui::GetIO().DisplaySize;
    ImDrawList* draw = ImGui::GetForegroundDrawList();
    draw->AddRectFilled(ImVec2(0, 0), viewport,
        IM_COL32(0, 0, 0, static_cast<int>(150.f * alpha)));
    const ImVec2 minimum((viewport.x - 460.f) * 0.5f, (viewport.y - 190.f) * 0.5f);
    const ImVec2 maximum(minimum.x + 460.f, minimum.y + 190.f);
    draw->AddRectFilled(minimum, maximum,
        aida::ui::with_alpha(theme.bg_elevated, alpha * 0.98f), 12.f);
    draw->AddRect(minimum, maximum,
        aida::ui::with_alpha(theme.border_strong, alpha), 12.f, 0, 1.2f);
    ui_anim::render_spinner(draw, minimum.x + 44.f, minimum.y + 82.f, 18.f, 3.f,
        aida::ui::with_alpha(theme.accent_u32, alpha),
        static_cast<float>(ImGui::GetTime()));
    const char* title = summary.pdb_loading
        ? "Loading debug symbols..."
        : summary.load_state == analysis_session::session_load_state_t::failed
        ? "Analysis failed"
        : current_phase() == phase_t::loading
            ? "Loading binary..."
            : "Analyzing binary...";
    ImFont* body = aida::ui::fonts::body_strong();
    draw->AddText(body, 16.f, ImVec2(minimum.x + 88.f, minimum.y + 28.f),
        aida::ui::with_alpha(theme.text_primary, alpha), title);
    ImFont* caption = aida::ui::fonts::caption();
    draw->AddText(caption, 12.f, ImVec2(minimum.x + 88.f, minimum.y + 53.f),
        aida::ui::with_alpha(theme.text_dim, alpha), state->filename.c_str());
    const float bar_x = minimum.x + 88.f;
    const float bar_y = minimum.y + 88.f;
    const float bar_width = maximum.x - bar_x - 28.f;
    draw->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_width, bar_y + 4.f),
        aida::ui::with_alpha(theme.panel_header, alpha), 2.f);
    draw->AddRectFilled(ImVec2(bar_x, bar_y),
        ImVec2(bar_x + bar_width * (std::max)(0.f, (std::min)(1.f, progress)), bar_y + 4.f),
        aida::ui::with_alpha(theme.accent_u32, alpha), 2.f);
    const std::string label = detail::label_for(summary);
    draw->AddText(caption, 11.5f, ImVec2(bar_x, bar_y + 16.f),
        aida::ui::with_alpha(summary.error ? theme.error : theme.text_secondary, alpha),
        label.c_str());
}

}
