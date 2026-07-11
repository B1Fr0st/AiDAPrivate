#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "initial_analysis.hpp"
#include "symbol_store.hpp"
#include "../disasm/disasm_view.hpp"
#include "../session/analysis_session.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/fonts.hpp"
#include "../ui/blur_layer.hpp"
#include "../../helpers/win32_dialog.hpp"

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

extern HWND g_hwnd;

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
    auto snapshot = analysis_session::pdb_prompt_snapshot(context.workspace);
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
	const auto automation = symbol_store::pdb_automation_context();
	if (!automation.pdb_skip_active || !context.workspace) return;
	auto snapshot = analysis_session::pdb_prompt_snapshot(context.workspace);
	if (!snapshot) return;
	if (snapshot.value().remote_pending)
		(void)analysis_session::decline_remote_pdb(context.workspace);
	if (snapshot.value().local_pending)
		(void)analysis_session::decline_local_pdb(context.workspace);
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
}

inline void render_progress(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<view_state_t>& state)
{
	if (!context.workspace || !state || state->dismissed) return;
	const auto progress = context.workspace->progress();
	using aida::analysis::workspace_readiness_t;
	const bool visible = progress.readiness == workspace_readiness_t::analyzing ||
		progress.readiness == workspace_readiness_t::baseline_ready ||
		progress.readiness == workspace_readiness_t::cancelling ||
		progress.readiness == workspace_readiness_t::failed ||
		progress.readiness == workspace_readiness_t::partial;
	if (!visible) return;
	const auto& theme = aida::ui::resolved();
	const ImGuiViewport* viewport = ImGui::GetMainViewport();
	const ImVec2 size(430.0f,
		(progress.error || !state->analysis_error.empty()) ? 196.0f : 166.0f);
	const ImVec2 position(viewport->WorkPos.x + viewport->WorkSize.x - size.x - 20.0f,
		viewport->WorkPos.y + 20.0f);
	ImGui::SetNextWindowPos(position, ImGuiCond_Always);
	ImGui::SetNextWindowSize(size, ImGuiCond_Always);
	ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(theme.bg_elevated, 0.98f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(theme.border_strong, 1.0f));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 16.0f));
	ImGui::Begin("Workspace analysis##workspace_analysis_progress", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
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
			context.workspace->request_cancel();
	} else if (progress.readiness != workspace_readiness_t::baseline_ready) {
		if (aida::ui::button("Retry", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm)) {
			state->dismissed = false;
			auto started = initial_analysis::run_initial_analysis(context.workspace);
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
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
	if (!prompt || !prompt.value().remote_pending) return;
	const std::string popup = "Debug information available##" +
		context.workspace->identity().binary_id().to_hex();
	ImGui::OpenPopup(popup.c_str());
	ImGui::SetNextWindowSize(ImVec2(620.0f, 0.0f), ImGuiCond_Appearing);
	if (!ImGui::BeginPopupModal(popup.c_str(), nullptr,
		ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
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
	if (aida::ui::button("Yes, download", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::md, ImVec2(), !state->load_types && !state->load_names)) {
		auto accepted = analysis_session::approve_remote_pdb(context.workspace,
			state->load_types, state->load_names);
		if (accepted) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = accepted.error().stable_code() + ": " +
				accepted.error().message;
		}
	}
	ImGui::SameLine();
	if (aida::ui::button("No, skip", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::md) || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
		auto declined = analysis_session::decline_remote_pdb(context.workspace);
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
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
	if (!prompt || !prompt.value().local_pending) return;
	if (state->local_pdb_path[0] == '\0' && !prompt.value().local_candidate.empty())
		std::strncpy(state->local_pdb_path.data(), prompt.value().local_candidate.c_str(),
			state->local_pdb_path.size() - 1);
	const std::string popup = "Locate local PDB##" +
		context.workspace->identity().binary_id().to_hex();
	ImGui::OpenPopup(popup.c_str());
	ImGui::SetNextWindowSize(ImVec2(620.0f, 0.0f), ImGuiCond_Appearing);
	if (!ImGui::BeginPopupModal(popup.c_str(), nullptr,
		ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
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
	ImGui::InputText("PDB path", state->local_pdb_path.data(), state->local_pdb_path.size());
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
	ImGui::SameLine();
	const bool valid = state->local_pdb_path[0] != '\0';
	if (aida::ui::button("Load this PDB", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::md, ImVec2(), !valid ||
			(!state->load_types && !state->load_names))) {
		auto accepted = analysis_session::approve_local_pdb(context.workspace,
			state->local_pdb_path.data(), state->load_types, state->load_names);
		if (accepted) {
			state->pdb_error.clear();
			ImGui::CloseCurrentPopup();
		} else {
			state->pdb_error = accepted.error().stable_code() + ": " +
				accepted.error().message;
		}
	}
	ImGui::SameLine();
	if (aida::ui::button("No, skip", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::md) || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
		auto declined = analysis_session::decline_local_pdb(context.workspace);
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
	auto prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
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
		auto cancelled = analysis_session::cancel_pdb(context.workspace);
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
