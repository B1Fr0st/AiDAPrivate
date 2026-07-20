#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/decompiler/decompiler_contracts.hpp"
#include "../core/analysis/workspace/analysis_workspace.hpp"
#include "shell_preview.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace source_reconstructor {

enum class stage_t : int {
	idle = 0,
	collect,
	decompile,
	cluster,
	headers,
	modules,
	metadata,
	done,
	failed
};

struct workspace_reconstruction_config_t {
	std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
	std::string output_dir;
	std::string project_name = "reconstructed";
	bool include_imports = true;
	bool include_exports = true;
	bool generate_cmake = true;
	int max_functions = 0;
};

struct workspace_reconstruction_result_t {
	bool success = false;
	std::string error;
	std::string module_name;
	int total_functions = 0;
	int decompiled_functions = 0;
	int failed_functions = 0;
	int modules_created = 0;
	std::vector<std::string> files_created;
	std::vector<aida::analysis::decompiler_diagnostic_t> diagnostics;
	std::string output_dir;
};

struct workspace_reconstruction_state_t {
	std::atomic<bool> running{false};
	std::atomic<bool> cancel_requested{false};
	std::atomic<float> progress{0.f};
	std::atomic<int> stage{static_cast<int>(stage_t::idle)};
	mutable std::mutex mutex;
	std::string status_text = "Ready";
	workspace_reconstruction_result_t last_result;
};

inline bool is_running_workspace(const workspace_reconstruction_state_t& state)
{
	return state.running.load(std::memory_order_acquire);
}

inline float get_progress_workspace(const workspace_reconstruction_state_t& state)
{
	return state.progress.load(std::memory_order_relaxed);
}

inline std::string get_status_workspace(const workspace_reconstruction_state_t& state)
{
	std::lock_guard<std::mutex> lock(state.mutex);
	return state.status_text;
}

inline int get_total_functions_workspace(const workspace_reconstruction_state_t& state)
{
	std::lock_guard<std::mutex> lock(state.mutex);
	return state.last_result.total_functions;
}

inline int get_decompiled_count_workspace(const workspace_reconstruction_state_t& state)
{
	std::lock_guard<std::mutex> lock(state.mutex);
	return state.last_result.decompiled_functions;
}

inline const workspace_reconstruction_result_t& get_last_result_workspace(
	const workspace_reconstruction_state_t& state)
{
	return state.last_result;
}

inline void cancel_workspace(workspace_reconstruction_state_t& state)
{
	state.cancel_requested.store(true, std::memory_order_release);
	state.running.store(false, std::memory_order_release);
	std::lock_guard<std::mutex> lock(state.mutex);
	state.status_text = "Cancelled";
	aida::preview::record(aida::preview::shell_action_t::source_reconstruct,
		"source_reconstruction_cancelled");
}

inline void reconstruct_workspace(
	const workspace_reconstruction_config_t& config,
	workspace_reconstruction_state_t& state)
{
	state.cancel_requested.store(false, std::memory_order_release);
	state.running.store(false, std::memory_order_release);
	state.progress.store(1.f, std::memory_order_release);
	state.stage.store(static_cast<int>(stage_t::done), std::memory_order_release);
	std::lock_guard<std::mutex> lock(state.mutex);
	state.status_text = "Preview reconstruction complete";
	state.last_result.success = true;
	state.last_result.error.clear();
	state.last_result.module_name = config.project_name.empty()
		? "reconstructed" : config.project_name;
	state.last_result.total_functions = 1284;
	state.last_result.decompiled_functions = 1284;
	state.last_result.failed_functions = 0;
	state.last_result.modules_created = 7;
	state.last_result.files_created = {
		config.output_dir + "/include/reconstructed.hpp",
		config.output_dir + "/src/reconstructed.cpp",
		config.output_dir + "/CMakeLists.txt"
	};
	aida::analysis::decompiler_diagnostic_t receipt;
	receipt.severity = aida::analysis::decompiler_diagnostic_severity_t::note;
	receipt.code = aida::analysis::decompiler_diagnostic_code_t::unsupported_provider;
	receipt.localization_key = "studio.preview.reconstruction_receipt";
	receipt.confidence = 100;
	receipt.ordinal = 1;
	state.last_result.diagnostics = {std::move(receipt)};
	state.last_result.output_dir = config.output_dir;
	aida::preview::record(aida::preview::shell_action_t::source_reconstruct,
		config.output_dir);
}

}

#endif
