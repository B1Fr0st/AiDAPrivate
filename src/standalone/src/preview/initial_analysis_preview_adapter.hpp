#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "re_hubs_preview_adapter.hpp"
#include "shell_preview.hpp"
#include "../core/session/analysis_session.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace aida::preview::initial_analysis {

inline constexpr int receipt_index = -1;

enum class analysis_scenario_t : int {
	analyzing,
	baseline_ready,
	partial,
	failed
};

enum class pdb_scenario_t : int {
	remote_prompt,
	local_prompt,
	loading,
	complete,
	failed
};

struct backend_state_t {
	analysis::workspace_progress_t progress;
	analysis_session::pdb_prompt_snapshot_t pdb;
};

inline std::mutex& states_mutex()
{
	static std::mutex value;
	return value;
}

inline std::unordered_map<std::string, backend_state_t>& states()
{
	static std::unordered_map<std::string, backend_state_t> value;
	return value;
}

inline backend_state_t make_state(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	backend_state_t state;
	state.progress = workspace->progress();
	state.pdb.binary_id = workspace->identity().binary_id().to_hex();
	state.pdb.module_name = workspace->identity().bin_name();
	state.pdb.pdb_name = "AiDA_Target.pdb";
	state.pdb.pdb_guid = "A1DA7B4294114C2DA870455972E3018D";
	state.pdb.pdb_age = 1;
	state.pdb.symbol_server = "https://msdl.microsoft.com/download/symbols";
	state.pdb.local_candidate =
		"C:/Preview/ReverseEngineering/symbols/AiDA_Target.pdb";
	state.pdb.status = "Symbols indexed from deterministic preview data";
	state.pdb.progress_percent = 100;
	state.pdb.symbol_revision = 3;
	return state;
}

inline backend_state_t& state_for_locked(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	const std::string key = workspace->identity().binary_id().to_hex();
	auto& values = states();
	auto found = values.find(key);
	if (found == values.end())
		found = values.emplace(key, make_state(workspace)).first;
	return found->second;
}

inline analysis::workspace_result_t<void> require_workspace(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
	const char* operation)
{
	if (workspace)
		return analysis::workspace_result_t<void>::success();
	return analysis::workspace_result_t<void>::failure(
		analysis::make_workspace_error(
			analysis::workspace_error_code_t::target_required,
			"preview initial analysis requires a workspace",
			operation ? operation : "preview_initial_analysis"));
}

inline analysis::workspace_progress_t progress_snapshot(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	if (!workspace)
		return {};
	std::lock_guard<std::mutex> lock(states_mutex());
	return state_for_locked(workspace).progress;
}

inline void set_analysis_scenario(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
	analysis_scenario_t scenario)
{
	if (!workspace)
		return;
	std::lock_guard<std::mutex> lock(states_mutex());
	auto& progress = state_for_locked(workspace).progress;
	progress.error.reset();
	progress.cancellation_requested = false;
	progress.total_units = 7;
	progress.total_bytes = workspace->source_provider().size();
	switch (scenario) {
	case analysis_scenario_t::analyzing:
		progress.readiness = analysis::workspace_readiness_t::analyzing;
		progress.phase = "Recovering control flow";
		progress.completed_units = 4;
		progress.completed_bytes = progress.total_bytes * 3 / 4;
		break;
	case analysis_scenario_t::baseline_ready:
		progress.readiness = analysis::workspace_readiness_t::baseline_ready;
		progress.phase = "Baseline analysis complete";
		progress.completed_units = progress.total_units;
		progress.completed_bytes = progress.total_bytes;
		break;
	case analysis_scenario_t::partial:
		progress.readiness = analysis::workspace_readiness_t::partial;
		progress.phase = "Partial analysis available";
		progress.completed_units = 5;
		progress.completed_bytes = progress.total_bytes * 4 / 5;
		break;
	case analysis_scenario_t::failed:
		progress.readiness = analysis::workspace_readiness_t::failed;
		progress.phase = "Analysis failed";
		progress.completed_units = 2;
		progress.completed_bytes = progress.total_bytes / 3;
		progress.error = analysis::make_workspace_error(
			analysis::workspace_error_code_t::decode_failure,
			"The deterministic fixture encountered an undecodable region",
			"preview_initial_analysis");
		break;
	}
}

inline void set_pdb_scenario(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
	pdb_scenario_t scenario)
{
	if (!workspace)
		return;
	std::lock_guard<std::mutex> lock(states_mutex());
	auto& pdb = state_for_locked(workspace).pdb;
	pdb.remote_pending = false;
	pdb.local_pending = false;
	pdb.loading = false;
	pdb.failed = false;
	pdb.declined = false;
	pdb.bytes_received = 0;
	pdb.bytes_total = 0;
	pdb.progress_percent = 0;
	pdb.symbol_revision = 0;
	switch (scenario) {
	case pdb_scenario_t::remote_prompt:
		pdb.remote_pending = true;
		pdb.status = "Matching symbols are available from the configured server";
		break;
	case pdb_scenario_t::local_prompt:
		pdb.local_pending = true;
		pdb.reason = "Automatic symbol lookup was skipped";
		pdb.status = "Choose the matching local program database";
		break;
	case pdb_scenario_t::loading:
		pdb.loading = true;
		pdb.status = "Downloading and indexing debug symbols";
		pdb.bytes_received = 7340032;
		pdb.bytes_total = 10485760;
		pdb.progress_percent = 70;
		break;
	case pdb_scenario_t::complete:
		pdb.status = "Symbols indexed from deterministic preview data";
		pdb.progress_percent = 100;
		pdb.symbol_revision = 3;
		break;
	case pdb_scenario_t::failed:
		pdb.failed = true;
		pdb.status = "Symbol loading failed";
		break;
	}
}

inline analysis::workspace_result_t<analysis_session::pdb_prompt_snapshot_t>
pdb_prompt_snapshot(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	auto valid = require_workspace(workspace, "preview_pdb_snapshot");
	if (!valid)
		return analysis::workspace_result_t<analysis_session::pdb_prompt_snapshot_t>::failure(
			valid.error());
	std::lock_guard<std::mutex> lock(states_mutex());
	return analysis::workspace_result_t<analysis_session::pdb_prompt_snapshot_t>::success(
		state_for_locked(workspace).pdb);
}

inline bool pdb_skip_active()
{
	return false;
}

inline std::string browse_for_pdb()
{
	const std::string path =
		"C:/Preview/ReverseEngineering/symbols/AiDA_Target.pdb";
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.browse_pdb", path);
	aida::preview::record(shell_action_t::open_file, path);
	return path;
}

inline analysis::workspace_result_t<void> run_initial_analysis(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.retry", workspace
			? workspace->identity().binary_id().to_hex() : std::string{});
	auto valid = require_workspace(workspace, "preview_initial_analysis");
	if (!valid)
		return valid;
	set_analysis_scenario(workspace, analysis_scenario_t::baseline_ready);
	return analysis::workspace_result_t<void>::success();
}

inline void request_cancel(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.cancel", workspace
			? workspace->identity().binary_id().to_hex() : std::string{});
	if (!workspace)
		return;
	std::lock_guard<std::mutex> lock(states_mutex());
	auto& progress = state_for_locked(workspace).progress;
	progress.readiness = analysis::workspace_readiness_t::cancelling;
	progress.phase = "Cancelling analysis";
	progress.cancellation_requested = true;
}

inline analysis::workspace_result_t<void> approve_remote_pdb(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
	bool load_types, bool load_names)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.remote_pdb.approve",
		std::string("types=") + (load_types ? "1" : "0") +
		",names=" + (load_names ? "1" : "0"));
	auto valid = require_workspace(workspace, "preview_remote_pdb");
	if (!valid)
		return valid;
	set_pdb_scenario(workspace, pdb_scenario_t::loading);
	return analysis::workspace_result_t<void>::success();
}

inline analysis::workspace_result_t<void> decline_remote_pdb(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.remote_pdb.decline");
	auto valid = require_workspace(workspace, "preview_remote_pdb");
	if (!valid)
		return valid;
	set_pdb_scenario(workspace, pdb_scenario_t::local_prompt);
	return analysis::workspace_result_t<void>::success();
}

inline analysis::workspace_result_t<void> approve_local_pdb(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
	const std::string& path, bool load_types, bool load_names)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.local_pdb.approve",
		path + ",types=" + (load_types ? "1" : "0") +
		",names=" + (load_names ? "1" : "0"));
	auto valid = require_workspace(workspace, "preview_local_pdb");
	if (!valid)
		return valid;
	if (path.empty())
		return analysis::workspace_result_t<void>::failure(
			analysis::make_workspace_error(
				analysis::workspace_error_code_t::invalid_argument,
				"a deterministic PDB path is required",
				"preview_local_pdb"));
	set_pdb_scenario(workspace, pdb_scenario_t::loading);
	return analysis::workspace_result_t<void>::success();
}

inline analysis::workspace_result_t<void> decline_local_pdb(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.local_pdb.decline");
	auto valid = require_workspace(workspace, "preview_local_pdb");
	if (!valid)
		return valid;
	std::lock_guard<std::mutex> lock(states_mutex());
	auto& pdb = state_for_locked(workspace).pdb;
	pdb.local_pending = false;
	pdb.declined = true;
	pdb.status = "Continuing without debug symbols";
	return analysis::workspace_result_t<void>::success();
}

inline analysis::workspace_result_t<void> cancel_pdb(
	const std::shared_ptr<analysis::analysis_workspace_t>& workspace)
{
	re_hubs::action(re_hubs::domain_t::analysis, receipt_index,
		"initial_analysis.pdb.cancel");
	auto valid = require_workspace(workspace, "preview_pdb_cancel");
	if (!valid)
		return valid;
	set_pdb_scenario(workspace, pdb_scenario_t::failed);
	return analysis::workspace_result_t<void>::success();
}

}

#endif
