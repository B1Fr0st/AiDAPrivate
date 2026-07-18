#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/initial_analysis_preview_adapter.hpp"
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "initial_analysis.hpp"
#include "symbol_store.hpp"
#endif
#include "../disasm/disasm_view.hpp"
#include "../session/analysis_session.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/fonts.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/ide_shell.hpp"
#include "../ui/workspace_layout.hpp"
#include "../ui/design_system.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/win32_dialog.hpp"
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
extern HWND g_hwnd;
#endif

namespace initial_analysis_view {

enum class pdb_prompt_status_t : int {
    pending = 0,
    loading = 1,
    success = 2,
    failed = 3,
};

struct pdb_prompt_state_t {
    bool visible = false;
    std::string codeview_id;
    std::string suggested_path;
    std::optional<std::string> user_selected_path;
    pdb_prompt_status_t status = pdb_prompt_status_t::pending;
    std::string error_message;
};

struct view_state_t {
	bool dismissed = false;
	bool load_types = true;
	bool load_names = true;
	std::uint64_t generation = 0;
	std::array<char, 32768> local_pdb_path{};
	std::string analysis_error;
	std::string pdb_error;
	pdb_prompt_state_t pdb_prompt;
};

inline std::mutex& states_mutex()
{
	static std::mutex mutex;
	return mutex;
}

inline std::unordered_map<std::string, std::shared_ptr<view_state_t>>& states()
{
	static std::unordered_map<std::string, std::shared_ptr<view_state_t>> value;
	return value;
}

inline std::shared_ptr<view_state_t> state_for(
	const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(states_mutex());
	auto& state = states()[key];
	if (!state) state = std::make_shared<view_state_t>();
	if (state->generation != context.workspace->generation()) {
		state->generation = context.workspace->generation();
		state->dismissed = false;
		state->load_types = true;
		state->load_names = true;
		state->local_pdb_path.fill('\0');
		state->analysis_error.clear();
		state->pdb_error.clear();
	}
	return state;
}

namespace detail {

inline void sync_pdb_prompt_state(
    const disasm_view::workspace_context_t& context,
    const std::shared_ptr<view_state_t>& state)
{
    if (!context.workspace || !state) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    auto snapshot = aida::preview::initial_analysis::pdb_prompt_snapshot(
        context.workspace);
#else
    auto snapshot = analysis_session::pdb_prompt_snapshot(context.workspace);
#endif
    if (!snapshot) {
        state->pdb_prompt.visible = false;
        state->pdb_prompt.status = pdb_prompt_status_t::pending;
        return;
    }
    const auto& snap = snapshot.value();
    state->pdb_prompt.visible = snap.remote_pending || snap.local_pending || snap.loading;
    char codeview_buf[64]{};
    std::snprintf(codeview_buf, sizeof(codeview_buf), "%s/%u",
        snap.pdb_guid.c_str(), static_cast<unsigned>(snap.pdb_age));
    state->pdb_prompt.codeview_id = codeview_buf;
    state->pdb_prompt.suggested_path = snap.local_candidate;
    if (state->local_pdb_path[0] != '\0')
        state->pdb_prompt.user_selected_path = std::string(state->local_pdb_path.data());
    else
        state->pdb_prompt.user_selected_path = std::nullopt;
    if (snap.loading)
        state->pdb_prompt.status = pdb_prompt_status_t::loading;
    else if (snap.failed)
        state->pdb_prompt.status = pdb_prompt_status_t::failed;
    else if (!snap.remote_pending && !snap.local_pending && !snap.loading &&
             !snap.failed && snap.symbol_revision > 0)
        state->pdb_prompt.status = pdb_prompt_status_t::success;
    else
        state->pdb_prompt.status = pdb_prompt_status_t::pending;
    state->pdb_prompt.error_message = state->pdb_error;
}

inline const char* readiness_name(aida::analysis::workspace_readiness_t readiness)
{
	using aida::analysis::workspace_readiness_t;
	switch (readiness) {
	case workspace_readiness_t::created: return "Created";
	case workspace_readiness_t::provider_ready: return "Provider ready";
	case workspace_readiness_t::parsed: return "Parsed";
	case workspace_readiness_t::analyzing: return "Analyzing";
	case workspace_readiness_t::baseline_ready: return "Baseline ready";
	case workspace_readiness_t::partial: return "Partial";
	case workspace_readiness_t::failed: return "Failed";
	case workspace_readiness_t::cancelling: return "Cancelling";
	case workspace_readiness_t::closing: return "Closing";
	case workspace_readiness_t::closed: return "Closed";
	default: return "Unknown";
	}
}

inline bool target_matches(const disasm_view::workspace_context_t& context)
{
	return context.workspace && context.workspace->target_kind() ==
		aida::analysis::target_kind_t::static_file &&
		!context.workspace->closing() && !context.workspace->closed();
}

inline void suppress_automated_prompts(
	const disasm_view::workspace_context_t& context)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const bool pdb_skip_active = aida::preview::initial_analysis::pdb_skip_active();
#else
	const auto automation = symbol_store::pdb_automation_context();
	const bool pdb_skip_active = automation.pdb_skip_active;
#endif
	if (!pdb_skip_active || !context.workspace) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto snapshot = aida::preview::initial_analysis::pdb_prompt_snapshot(
		context.workspace);
#else
	auto snapshot = analysis_session::pdb_prompt_snapshot(context.workspace);
#endif
	if (!snapshot) return;
	if (snapshot.value().remote_pending)
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)aida::preview::initial_analysis::decline_remote_pdb(context.workspace);
#else
		(void)analysis_session::decline_remote_pdb(context.workspace);
#endif
	if (snapshot.value().local_pending)
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		(void)aida::preview::initial_analysis::decline_local_pdb(context.workspace);
#else
		(void)analysis_session::decline_local_pdb(context.workspace);
#endif
}

inline float progress_fraction(const aida::analysis::workspace_progress_t& progress)
{
	if (progress.total_units != 0)
		return static_cast<float>((std::min)(1.0,
			static_cast<double>(progress.completed_units) /
			static_cast<double>(progress.total_units)));
	if (progress.total_bytes != 0)
		return static_cast<float>((std::min)(1.0,
			static_cast<double>(progress.completed_bytes) /
			static_cast<double>(progress.total_bytes)));
	return progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ? 1.0f : 0.0f;
}

inline std::string browse_for_pdb(const disasm_view::workspace_context_t& context,
	const std::string& initial_name)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(context);
	static_cast<void>(initial_name);
	return aida::preview::initial_analysis::browse_for_pdb();
#else
	if (symbol_store::pdb_automation_context().pdb_skip_active) {
		if (context.workspace)
			(void)analysis_session::decline_local_pdb(context.workspace);
		return {};
	}
	std::array<char, 32768> path{};
	if (!initial_name.empty())
		std::strncpy(path.data(), initial_name.c_str(), path.size() - 1);
	static const char filter[] =
		"PDB files (*.pdb)\0*.pdb\0"
		"All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_open_file_dialog(g_hwnd, "Select PDB file", filter,
		path.data(), path.size(), "initial_analysis_view::browse_for_pdb")) return {};
	return path.data();
#endif
}

inline void render_progress(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<view_state_t>& state)
{
	if (!context.workspace || !state || state->dismissed) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const auto progress = aida::preview::initial_analysis::progress_snapshot(
		context.workspace);
#else
	const auto progress = context.workspace->progress();
#endif
	using aida::analysis::workspace_readiness_t;
	const bool completed_without_error = progress.total_units != 0 &&
		progress.completed_units >= progress.total_units && !progress.error;
	const bool visible = progress.readiness == workspace_readiness_t::analyzing ||
		progress.readiness == workspace_readiness_t::cancelling ||
		progress.readiness == workspace_readiness_t::failed ||
		(progress.readiness == workspace_readiness_t::partial &&
			!completed_without_error);
	if (!visible) return;
	const auto& theme = aida::ui::resolved();
	const ImVec2 size(430.0f,
		(progress.error || !state->analysis_error.empty()) ? 196.0f : 166.0f);
#if defined(IMGUI_HAS_DOCK)
	const ImGuiID bottom_node = aida::ui::workspace_layout::node_id(
		aida::ui::workspace_layout::dock_role_t::bottom);
	const ImGuiID target_node = bottom_node != 0
		? bottom_node : aida::ui::ide_shell::root_dockspace_id();
	if (target_node != 0)
		ImGui::SetNextWindowDockID(target_node, ImGuiCond_Appearing);
#else
	const ImGuiViewport* viewport = ImGui::GetMainViewport();
	const ImVec2 position(viewport->WorkPos.x + (viewport->WorkSize.x - size.x) * 0.5f,
		viewport->WorkPos.y + aida::ui::ide_shell::reserved_chrome_height() + 20.0f);
	ImGui::SetNextWindowPos(position, ImGuiCond_Appearing);
#endif
	ImGui::SetNextWindowSize(size, ImGuiCond_Appearing);
	ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(theme.bg_elevated, 0.98f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(theme.border_strong, 1.0f));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
	const bool window_visible = ImGui::Begin(
		"Workspace Analysis###aida.workspace.analysis.progress", nullptr,
		ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
	if (!window_visible) {
		ImGui::End();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(2);
		return;
	}
	ImGui::PushFont(aida::ui::fonts::body_em());
	ImGui::TextUnformatted(context.workspace->identity().bin_name().c_str());
	ImGui::PopFont();
	ImGui::SameLine();
	ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_dim), "%s",
		readiness_name(progress.readiness));
	ImGui::Spacing();
	ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_secondary), "%s",
		progress.phase.empty() ? "Preparing analysis" : progress.phase.c_str());
	const float fraction = progress_fraction(progress);
	ImGui::ProgressBar(fraction, ImVec2(-1.0f, 8.0f), "");
	if (progress.total_units != 0)
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_dim),
			"%llu / %llu units",
			static_cast<unsigned long long>(progress.completed_units),
			static_cast<unsigned long long>(progress.total_units));
	if (progress.error)
		ImGui::TextWrapped("%s: %s", progress.error->stable_code().c_str(),
			progress.error->message.c_str());
	if (!state->analysis_error.empty())
		ImGui::TextWrapped("%s", state->analysis_error.c_str());
	const bool running = progress.readiness == workspace_readiness_t::analyzing ||
		progress.readiness == workspace_readiness_t::cancelling;
	if (running) {
		if (aida::ui::button(progress.readiness == workspace_readiness_t::cancelling
			? "Cancelling" : "Cancel", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(), progress.cancellation_requested))
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aida::preview::initial_analysis::request_cancel(context.workspace);
#else
			context.workspace->request_cancel();
#endif
	} else if (progress.readiness != workspace_readiness_t::baseline_ready) {
		if (aida::ui::button("Retry", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm)) {
			state->dismissed = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			auto started = aida::preview::initial_analysis::run_initial_analysis(
				context.workspace);
#else
			auto started = initial_analysis::run_initial_analysis(context.workspace);
#endif
			if (started) {
				state->analysis_error.clear();
			} else {
				state->analysis_error = started.error().stable_code() + ": " +
					started.error().message;
			}
		}
	}
	if (!running) {
		if (progress.readiness != workspace_readiness_t::baseline_ready) ImGui::SameLine();
		if (aida::ui::button("Dismiss", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm)) state->dismissed = true;
	}
	ImGui::End();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
}

inline void render_remote_pdb(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<view_state_t>& state)
{
	if (!state || !target_matches(context)) return;
	suppress_automated_prompts(context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto prompt = aida::preview::initial_analysis::pdb_prompt_snapshot(
		context.workspace);
#else
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
#endif
	if (!prompt || !prompt.value().remote_pending) return;
	const std::string popup = "Debug information available##" +
		context.workspace->identity().binary_id().to_hex();
	ImGui::OpenPopup(popup.c_str());
	if (!aida::ui::design::begin_dialog_exact(popup.c_str(), ImVec2(620.0f, 420.0f),
		ImVec2(400.0f, 300.0f))) return;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Yes, download", "No, skip");
	aida::ui::design::begin_dialog_body("remote_pdb_prompt_body", footer_height);
	ImGui::PushFont(aida::ui::fonts::h2());
	ImGui::TextUnformatted("Debug information available");
	ImGui::PopFont();
	ImGui::Separator();
	ImGui::TextWrapped("The selected workspace references %s.",
		prompt.value().pdb_name.empty() ? "an external PDB" :
		prompt.value().pdb_name.c_str());
	ImGui::TextWrapped("GUID: %s   Age: %u", prompt.value().pdb_guid.c_str(),
		static_cast<unsigned>(prompt.value().pdb_age));
	if (!prompt.value().symbol_server.empty())
		ImGui::TextWrapped("%s", prompt.value().symbol_server.c_str());
	if (!prompt.value().status.empty()) ImGui::TextWrapped("%s",
		prompt.value().status.c_str());
	if (!state->pdb_error.empty()) ImGui::TextWrapped("%s", state->pdb_error.c_str());
	aida::ui::toggle_switch("Load types", &state->load_types, aida::ui::size_t_::md);
	aida::ui::toggle_switch("Load names", &state->load_names, aida::ui::size_t_::md);
	aida::ui::design::end_dialog_body();
	const bool download_enabled = state->load_types || state->load_names;
	const auto footer = aida::ui::design::dialog_footer("remote_pdb_prompt_footer",
		"Yes, download", download_enabled, false, "No, skip");
	if (footer.confirmed) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		auto accepted = aida::preview::initial_analysis::approve_remote_pdb(
			context.workspace, state->load_types, state->load_names);
#else
		auto accepted = analysis_session::approve_remote_pdb(context.workspace,
			state->load_types, state->load_names);
#endif
		if (accepted) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = accepted.error().stable_code() + ": " +
				accepted.error().message;
		}
	}
	if (footer.cancelled) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		auto declined = aida::preview::initial_analysis::decline_remote_pdb(
			context.workspace);
#else
		auto declined = analysis_session::decline_remote_pdb(context.workspace);
#endif
		if (declined) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = declined.error().stable_code() + ": " +
				declined.error().message;
		}
	}
	ImGui::EndPopup();
}

inline void render_local_pdb(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<view_state_t>& state)
{
	if (!state || !target_matches(context)) return;
	suppress_automated_prompts(context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto prompt = aida::preview::initial_analysis::pdb_prompt_snapshot(
		context.workspace);
#else
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
#endif
	if (!prompt || !prompt.value().local_pending) return;
	if (state->local_pdb_path[0] == '\0' && !prompt.value().local_candidate.empty())
		std::strncpy(state->local_pdb_path.data(), prompt.value().local_candidate.c_str(),
			state->local_pdb_path.size() - 1);
	const std::string popup = "Locate local PDB##" +
		context.workspace->identity().binary_id().to_hex();
	ImGui::OpenPopup(popup.c_str());
	if (!aida::ui::design::begin_dialog_exact(popup.c_str(), ImVec2(620.0f, 460.0f),
		ImVec2(400.0f, 320.0f))) return;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Load this PDB", "No, skip");
	aida::ui::design::begin_dialog_body("local_pdb_prompt_body", footer_height);
	ImGui::PushFont(aida::ui::fonts::h2());
	ImGui::TextUnformatted("Locate local debug symbols");
	ImGui::PopFont();
	ImGui::Separator();
	ImGui::TextWrapped("%s", prompt.value().module_name.empty()
		? context.workspace->identity().bin_name().c_str()
		: prompt.value().module_name.c_str());
	if (!prompt.value().reason.empty())
		ImGui::TextWrapped("%s", prompt.value().reason.c_str());
	if (!prompt.value().status.empty())
		ImGui::TextWrapped("%s", prompt.value().status.c_str());
	if (!state->pdb_error.empty()) ImGui::TextWrapped("%s", state->pdb_error.c_str());
	aida::ui::toggle_switch("Load types", &state->load_types, aida::ui::size_t_::md);
	aida::ui::toggle_switch("Load names", &state->load_names, aida::ui::size_t_::md);
	if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
	const bool path_submitted = ImGui::InputText("PDB path",
		state->local_pdb_path.data(), state->local_pdb_path.size(),
		ImGuiInputTextFlags_EnterReturnsTrue);
	if (aida::ui::button("Browse...", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::md)) {
		const std::string selected = browse_for_pdb(context,
			state->local_pdb_path.data());
		if (!selected.empty()) {
			state->local_pdb_path.fill('\0');
			std::strncpy(state->local_pdb_path.data(), selected.c_str(),
				state->local_pdb_path.size() - 1);
		}
	}
	const bool valid = state->local_pdb_path[0] != '\0';
	aida::ui::design::end_dialog_body();
	const bool load_enabled = valid && (state->load_types || state->load_names);
	const auto footer = aida::ui::design::dialog_footer("local_pdb_prompt_footer",
		"Load this PDB", load_enabled, false, "No, skip");
	if (footer.confirmed || (path_submitted && load_enabled)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		auto accepted = aida::preview::initial_analysis::approve_local_pdb(
			context.workspace, state->local_pdb_path.data(), state->load_types,
			state->load_names);
#else
		auto accepted = analysis_session::approve_local_pdb(context.workspace,
			state->local_pdb_path.data(), state->load_types, state->load_names);
#endif
		if (accepted) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = accepted.error().stable_code() + ": " +
				accepted.error().message;
		}
	}
	if (footer.cancelled) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		auto declined = aida::preview::initial_analysis::decline_local_pdb(
			context.workspace);
#else
		auto declined = analysis_session::decline_local_pdb(context.workspace);
#endif
		if (declined) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = declined.error().stable_code() + ": " +
				declined.error().message;
		}
	}
	ImGui::EndPopup();
}

inline void render_pdb_status(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<view_state_t>& state)
{
	if (!state || !target_matches(context)) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto prompt = aida::preview::initial_analysis::pdb_prompt_snapshot(
		context.workspace);
#else
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
#endif
	if (!prompt || !prompt.value().loading) return;
	const auto& theme = aida::ui::resolved();
	const ImGuiViewport* viewport = ImGui::GetMainViewport();
	const ImVec2 size(430.0f, 132.0f);
	const ImVec2 position(viewport->WorkPos.x + viewport->WorkSize.x - size.x - 20.0f,
		viewport->WorkPos.y + 224.0f);
	ImGui::SetNextWindowPos(position, ImGuiCond_Always);
	ImGui::SetNextWindowSize(size, ImGuiCond_Always);
	ImGui::PushStyleColor(ImGuiCol_WindowBg,
		aida::ui::with_alpha(theme.bg_elevated, 0.98f));
	ImGui::PushStyleColor(ImGuiCol_Border,
		aida::ui::with_alpha(theme.border_strong, 1.0f));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
	const std::string title = "PDB operation##" + prompt.value().binary_id;
	ImGui::Begin(title.c_str(), nullptr, ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoSavedSettings);
	ImGui::PushFont(aida::ui::fonts::body_em());
	ImGui::TextUnformatted(prompt.value().module_name.c_str());
	ImGui::PopFont();
	ImGui::TextWrapped("%s", prompt.value().status.c_str());
	const float fraction = prompt.value().bytes_total != 0
		? static_cast<float>((std::min)(1.0,
			static_cast<double>(prompt.value().bytes_received) /
			static_cast<double>(prompt.value().bytes_total)))
		: static_cast<float>((std::clamp)(prompt.value().progress_percent,
			0, 100)) / 100.0f;
	ImGui::ProgressBar(fraction, ImVec2(-1.0f, 8.0f), "");
	if (aida::ui::button("Cancel PDB", aida::ui::button_kind_t::destructive,
		aida::ui::size_t_::sm)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		auto cancelled = aida::preview::initial_analysis::cancel_pdb(
			context.workspace);
#else
		auto cancelled = analysis_session::cancel_pdb(context.workspace);
#endif
		if (!cancelled) state->pdb_error = cancelled.error().stable_code() + ": " +
			cancelled.error().message;
	}
	ImGui::End();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
}

}

inline void render_frame(const disasm_view::workspace_context_t& context)
{
	const auto state = state_for(context);
	if (!state) return;
	detail::sync_pdb_prompt_state(context, state);
	detail::render_progress(context, state);
	detail::render_remote_pdb(context, state);
	detail::render_local_pdb(context, state);
	detail::render_pdb_status(context, state);
}

inline void render_frame()
{
	render_frame(disasm_view::capture_selected_workspace());
}

}
