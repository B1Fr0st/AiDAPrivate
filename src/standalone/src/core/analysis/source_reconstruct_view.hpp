#pragma once

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#endif

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/source_reconstructor_preview.hpp"
#else
#include "../helpers/win32_dialog.hpp"
#include "source_reconstructor.hpp"
#endif
#include "../ui/design_system.hpp"
#include "../disasm/disasm_view.hpp"

namespace source_reconstruct_view {

struct view_state_t {
	bool   open = false;
	bool   prev_open = false;
	char   output_dir[512] = {};
	bool   started = false;
	bool   cancellation_requested = false;
	bool   focus_output = false;
	aida::ui::design::form_state_t form;
	source_reconstructor::workspace_reconstruction_state_t recon_state;
};

namespace {

inline std::mutex& view_registry_mutex() {
	static std::mutex value;
	return value;
}

inline std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<view_state_t>, aida::analysis::binary_id_hash_t>&
view_registry() {
	static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<view_state_t>, aida::analysis::binary_id_hash_t> value;
	return value;
}

inline std::shared_ptr<view_state_t> view_for(const disasm_view::workspace_context_t& context) {
	if (!context.workspace)
		return {};
	const auto id = context.workspace->identity().binary_id();
	std::lock_guard<std::mutex> lock(view_registry_mutex());
	auto& registry = view_registry();
	for (auto it = registry.begin(); it != registry.end();) {
		if (it->second && !it->second->open &&
		    !source_reconstructor::is_running_workspace(it->second->recon_state))
			it = registry.erase(it);
		else
			++it;
	}
	auto found = registry.find(id);
	if (found != registry.end())
		return found->second;
	auto created = std::make_shared<view_state_t>();
	registry[id] = created;
	return created;
}

inline std::shared_ptr<view_state_t> view_for_selected() {
	return view_for(disasm_view::capture_selected_workspace());
}

}

inline bool is_open() {
	auto st = view_for_selected();
	if (!st) return false;
	return st->open;
}

inline void apply_default_output_dir(view_state_t& st) {
	if (st.output_dir[0] != '\0') return;
	char home[MAX_PATH] = {};
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const char* fallback = std::getenv("USERPROFILE");
	if (fallback && *fallback)
		std::strncpy(home, fallback, MAX_PATH - 1);
#else
	DWORD got = GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH);
	if (got == 0 || got >= MAX_PATH) {
		const char* fallback = std::getenv("USERPROFILE");
		if (fallback && *fallback) {
			std::strncpy(home, fallback, MAX_PATH - 1);
		}
	}
#endif
	if (home[0] == '\0') {
		std::strncpy(st.output_dir, "C:\\AiDA_Reconstruction", sizeof(st.output_dir) - 1);
		return;
	}
	std::snprintf(st.output_dir, sizeof(st.output_dir),
		"%s\\Documents\\AiDA_Reconstruction", home);
}

inline void restore_running_state(view_state_t& st) {
	st.started = true;
	st.cancellation_requested =
		st.recon_state.cancel_requested.load(std::memory_order_acquire);
	std::string retained_output;
	{
		std::lock_guard<std::mutex> lock(st.recon_state.mutex);
		retained_output = st.recon_state.last_result.output_dir;
	}
	if (!retained_output.empty() && retained_output.size() < sizeof(st.output_dir)) {
		std::memcpy(st.output_dir, retained_output.data(), retained_output.size());
		st.output_dir[retained_output.size()] = '\0';
	}
}

inline void open(const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	const bool running = source_reconstructor::is_running_workspace(st->recon_state);
	st->open = true;
	st->started = running;
	st->cancellation_requested = false;
	st->form.clear();
	if (running) {
		restore_running_state(*st);
	} else {
		apply_default_output_dir(*st);
	}
}

inline void close(const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	if (source_reconstructor::is_running_workspace(st->recon_state))
		source_reconstructor::cancel_workspace(st->recon_state);
	st->open = false;
}

inline bool pick_output_directory(HWND owner, char* buf, std::size_t buf_size) {
	if (!buf || buf_size < 4) return false;
	std::string picked;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	(void)owner;
	picked = "C:/Preview/ReverseEngineering/reconstructed";
	aida::preview::record(aida::preview::shell_action_t::source_reconstruct,
		"source_reconstruction_output_directory");
#else
	if (!win32_dialog::show_open_folder_dialog(owner,
			L"Select Output Directory",
			picked,
			"source_reconstruct_view::pick_output_directory")) {
		return false;
	}
#endif
	if (picked.empty() || picked.size() + 1 > buf_size) return false;
	std::memcpy(buf, picked.data(), picked.size());
	buf[picked.size()] = '\0';
	return true;
}

inline const char* stage_label(source_reconstructor::stage_t stage) {
	switch (stage) {
	case source_reconstructor::stage_t::idle: return "Ready";
	case source_reconstructor::stage_t::collect: return "Collecting functions";
	case source_reconstructor::stage_t::decompile: return "Decompiling";
	case source_reconstructor::stage_t::cluster: return "Clustering modules";
	case source_reconstructor::stage_t::headers: return "Generating headers";
	case source_reconstructor::stage_t::modules: return "Writing modules";
	case source_reconstructor::stage_t::metadata: return "Writing metadata";
	case source_reconstructor::stage_t::done: return "Complete";
	case source_reconstructor::stage_t::failed: return "Failed";
	}
	return "Unknown";
}

inline const char* diagnostic_severity_label(
	aida::analysis::decompiler_diagnostic_severity_t severity) {
	switch (severity) {
	case aida::analysis::decompiler_diagnostic_severity_t::note: return "Note";
	case aida::analysis::decompiler_diagnostic_severity_t::warning: return "Warning";
	case aida::analysis::decompiler_diagnostic_severity_t::error: return "Error";
	}
	return "Diagnostic";
}

inline std::string diagnostic_text(
	const aida::analysis::decompiler_diagnostic_t& diagnostic) {
	std::string text = diagnostic_severity_label(diagnostic.severity);
	if (diagnostic.ordinal != 0) {
		text += " #";
		text += std::to_string(diagnostic.ordinal);
	}
	text += " [code ";
	text += std::to_string(static_cast<unsigned int>(diagnostic.code));
	text += "]: ";
	text += diagnostic.localization_key.empty()
		? "decompiler_diagnostic" : diagnostic.localization_key;
	for (const auto& argument : diagnostic.localization_arguments) {
		text.push_back(' ');
		text += argument;
	}
	if (diagnostic.retryable)
		text += " [retryable]";
	if (diagnostic.confidence != 0) {
		text += " [confidence ";
		text += std::to_string(diagnostic.confidence);
		text += "%]";
	}
	return text;
}

inline void render_impl(float alpha, float ar, float ag, float ab,
                        view_state_t& st,
                        const disasm_view::workspace_context_t& context) {
	(void)alpha;
	(void)ar;
	(void)ag;
	(void)ab;
	const bool opening = st.open && !st.prev_open;
	st.prev_open = st.open;
	if (opening) {
		aida::ui::design::open_dialog(
			"aida.analysis.source-reconstruction", "Reconstruct Source");
	}
	if (!st.open)
		return;

	if (!aida::ui::design::begin_dialog(
			"aida.analysis.source-reconstruction", "Reconstruct Source",
			ImVec2(680.0f, 520.0f), ImVec2(420.0f, 320.0f)))
		return;

	const bool running = source_reconstructor::is_running_workspace(st.recon_state);
	if (running && !st.started)
		restore_running_state(st);
	const bool workspace_available = context.workspace && !context.workspace->closed();
	st.form.clear();
	if (st.output_dir[0] == '\0')
		st.form.reject("output-directory", "Choose an output directory.");
	if (!workspace_available)
		st.form.reject("workspace", "The retained binary workspace is no longer available.");

	const char* confirm_label = !st.started ? "Start Reconstruction"
		: running && st.cancellation_requested ? "Cancellation Requested"
			: running ? "Request Cancellation" : "Close";
	const char* cancel_label = !st.started ? "Cancel" : nullptr;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		confirm_label, cancel_label);
	aida::ui::design::begin_dialog_body(
		"source-reconstruction.body", footer_height);

	if (aida::ui::design::begin_property_grid(
			"source-reconstruction.identity", 150.0f)) {
		const std::string binary_name = workspace_available
			? context.workspace->identity().bin_name() : std::string("Unavailable");
		aida::ui::design::property_value("binary", "Binary", binary_name.c_str(),
			workspace_available ? aida::ui::design::semantic_t::neutral
				: aida::ui::design::semantic_t::stale);
		aida::ui::design::property_value("scope", "Scope",
			"Functions, imports, exports, headers, modules, metadata");
		aida::ui::design::end_property_grid();
	}

	if (!st.started) {
		if (st.focus_output) {
			ImGui::SetKeyboardFocusHere();
			st.focus_output = false;
		}
		aida::ui::design::form_input_text(
			"output-directory", "Output directory", st.output_dir,
			sizeof(st.output_dir), st.form, "C:\\path\\to\\output");
		if (ImGui::Button("Browse...##source-reconstruction-output"))
			pick_output_directory(::g_hwnd, st.output_dir, sizeof(st.output_dir));
		aida::ui::design::tooltip_for_last_item(
			"Choose the directory that will receive the reconstructed project");
		aida::ui::design::form_summary("source-reconstruction.form", st.form);
		ImGui::TextWrapped(
			"Reconstruction writes a CMake project and recovered source artifacts to the selected directory. The active analysis workspace is not modified.");
	} else if (running) {
		const auto stage = static_cast<source_reconstructor::stage_t>(
			st.recon_state.stage.load(std::memory_order_relaxed));
		const int total = source_reconstructor::get_total_functions_workspace(st.recon_state);
		const int done = source_reconstructor::get_decompiled_count_workspace(st.recon_state);
		const float progress = (std::clamp)(
			source_reconstructor::get_progress_workspace(st.recon_state), 0.0f, 1.0f);
		const std::string status = source_reconstructor::get_status_workspace(st.recon_state);
		aida::ui::design::state_presentation_t state;
		state.stable_id = "source-reconstruction.progress";
		state.state = aida::ui::design::view_state_t::loading;
		state.title = stage_label(stage);
		state.message = st.cancellation_requested
			? "Cancellation was requested. Waiting for the worker to publish its terminal result."
			: status.empty() ? "Reconstructing source artifacts." : status.c_str();
		state.target = st.output_dir;
		state.stage = stage_label(stage);
		state.progress = progress;
		state.preserves_stale_data = true;
		aida::ui::design::render_state(state);
		ImGui::TextDisabled("%d of %d functions processed", done, total);
		ImGui::TextWrapped(
			"Cancellation is cooperative. The dialog remains available until the worker publishes its final result.");
	} else {
		const auto& result = source_reconstructor::get_last_result_workspace(st.recon_state);
		const bool cancelled = !result.success && result.error == "Cancelled.";
		const std::string summary = std::to_string(result.decompiled_functions) +
			" of " + std::to_string(result.total_functions) +
			" functions; " + std::to_string(result.files_created.size()) +
			" files; " + std::to_string(result.diagnostics.size()) + " diagnostics.";
		aida::ui::design::state_presentation_t state;
		state.stable_id = "source-reconstruction.result";
		state.state = result.success || cancelled
			? aida::ui::design::view_state_t::empty
			: aida::ui::design::view_state_t::error;
		state.title = result.success ? "Reconstruction complete"
			: cancelled ? "Reconstruction cancelled" : "Reconstruction incomplete";
		state.message = summary.c_str();
		state.target = st.output_dir;
		state.diagnostic_id = result.success ? nullptr : "source-reconstruction.result";
		aida::ui::design::render_state(state);
		if (!result.error.empty())
			ImGui::TextWrapped("%s", result.error.c_str());
		if (!result.files_created.empty()) {
			ImGui::SeparatorText("Output files");
			aida::ui::design::render_clipped_rows(result.files_created.size(),
				ImGui::GetTextLineHeightWithSpacing(), [&](std::size_t index) {
					ImGui::TextUnformatted(result.files_created[index].c_str());
				});
		}
		if (!result.diagnostics.empty()) {
			ImGui::SeparatorText("Diagnostics");
			aida::ui::design::render_clipped_rows(result.diagnostics.size(),
				ImGui::GetTextLineHeightWithSpacing(), [&](std::size_t index) {
					const std::string row = diagnostic_text(result.diagnostics[index]);
					ImGui::TextUnformatted(row.c_str());
				});
		}
	}

	aida::ui::design::end_dialog_body();
	const bool confirm_enabled = !st.started ? st.form.valid() && !running
		: !(running && st.cancellation_requested);
	const auto footer = aida::ui::design::dialog_footer(
		"source-reconstruction.footer", confirm_label, confirm_enabled, false,
		cancel_label, true, !running);

	if (!st.started && !running && footer.confirmed) {
		if (!st.form.valid()) {
			st.focus_output = true;
		} else {
			source_reconstructor::workspace_reconstruction_config_t config;
			config.workspace = context.workspace;
			config.output_dir = st.output_dir;
			config.project_name = "reconstructed";
			config.include_imports = true;
			config.include_exports = true;
			config.generate_cmake = true;
			config.max_functions = 0;
			source_reconstructor::reconstruct_workspace(config, st.recon_state);
			st.started = true;
		}
	} else if (running && footer.confirmed) {
		st.cancellation_requested = true;
		source_reconstructor::cancel_workspace(st.recon_state);
	} else if (st.started && !running && footer.confirmed) {
		st.open = false;
		ImGui::CloseCurrentPopup();
	}

	if (footer.cancelled) {
		st.open = false;
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}
inline void render(float alpha, float ar, float ag, float ab,
                   const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	render_impl(alpha, ar, ag, ab, *st, context);
}

inline void render(float alpha, float ar, float ag, float ab) {
	auto st = view_for_selected();
	if (!st) return;
	render_impl(alpha, ar, ag, ab, *st, disasm_view::capture_selected_workspace());
}

}
