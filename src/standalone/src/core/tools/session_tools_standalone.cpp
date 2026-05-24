#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../mcp/mcp_standalone.hpp"
#include "../session/analysis_session.hpp"
#include "../session/session_health.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/run_target.hpp"
#include "../ui/loading_binary_overlay.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace session_tools {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

json summary_to_json(const analysis_session::session_summary_t& s)
{
	json o;
	o["id"] = s.id;
	o["kind"] = (s.kind == analysis_session::session_kind_t::live_attach) ? "live" : "file";
	o["path"] = s.path;
	o["filename"] = s.filename;
	o["pid"] = s.pid;
	o["process_name"] = s.process_name;
	o["is_active"] = s.is_active;
	if (s.pid != 0) {
		o["is_alive"] = session_health::is_alive(s.pid);
	} else {
		o["is_alive"] = true;
	}
	o["last_active_steady_ms"] = static_cast<uint64_t>(s.last_active_steady_ms);
	return o;
}

uint32_t parse_pid(const json& v)
{
	if (v.is_number_unsigned()) return static_cast<uint32_t>(v.get<uint64_t>());
	if (v.is_number_integer()) {
		int64_t s = v.get<int64_t>();
		return (s > 0) ? static_cast<uint32_t>(s) : 0u;
	}
	if (v.is_string()) {
		try { return static_cast<uint32_t>(std::stoul(v.get<std::string>(), nullptr, 0)); }
		catch (...) { return 0u; }
	}
	return 0u;
}

bool wait_for_binary_load_quiescent(uint32_t timeout_ms)
{
	const ULONGLONG start = GetTickCount64();
	for (;;) {
		loading_binary_overlay::poll_completion();
		if (!loading_binary_overlay::is_active())
			return true;
		if (GetTickCount64() - start >= timeout_ms)
			return false;
		Sleep(25);
	}
}

}

static tool_result_t sessions_list(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_list entry");
	(void)params;
	auto sessions = analysis_session::list_session_summaries();
	json arr = json::array();
	for (const auto& s : sessions) arr.push_back(summary_to_json(s));
	json root;
	root["count"] = sessions.size();
	root["sessions"] = arr;
	diag::log_tagged_fmt("sess_tools",
		"sessions_list returned=%llu",
		static_cast<unsigned long long>(sessions.size()));
	return tool_result_t::ok(root);
}

static tool_result_t sessions_get_active(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_get_active entry");
	(void)params;
	size_t idx = analysis_session::active_session_idx();
	if (idx == static_cast<size_t>(-1)) {
		json root;
		root["active"] = nullptr;
		root["has_active"] = false;
		return tool_result_t::ok(root);
	}
	auto sum = analysis_session::summarize_session_at(idx);
	json root;
	root["active"] = summary_to_json(sum);
	root["has_active"] = true;
	root["index"] = static_cast<uint64_t>(idx);
	return tool_result_t::ok(root);
}

static tool_result_t sessions_switch(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_switch entry id='%s'",
		params.contains("binary_id") && params["binary_id"].is_string()
			? params["binary_id"].get<std::string>().c_str() : "");
	if (!params.contains("binary_id") || !params["binary_id"].is_string()) {
		return tool_result_t::error("binary_id (string) is required");
	}
	if (!wait_for_binary_load_quiescent(30000)) {
		return tool_result_t::error("switch failed: load timeout");
	}
	std::string id = params["binary_id"].get<std::string>();
	size_t idx = 0;
	if (!analysis_session::find_session_by_id(id, &idx)) {
		diag::log_tagged_fmt("sess_tools",
			"sessions_switch id='%s' not_found", id.c_str());
		return tool_result_t::error("binary_id not found: " + id);
	}
	if (!analysis_session::switch_session(idx)) {
		std::string err = analysis_session::last_error();
		diag::log_tagged_fmt("sess_tools",
			"sessions_switch id='%s' switch_failed err='%s'", id.c_str(), err.c_str());
		return tool_result_t::error(std::string("switch failed: ") + err);
	}
	auto sum = analysis_session::summarize_session_at(idx);
	json root;
	root["switched_to"] = summary_to_json(sum);
	diag::log_tagged_fmt("sess_tools",
		"sessions_switch id='%s' switched_idx=%llu",
		id.c_str(), static_cast<unsigned long long>(idx));
	return tool_result_t::ok(root);
}

static tool_result_t sessions_open_file(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_open_file entry path='%.120s'",
		params.contains("path") && params["path"].is_string()
			? params["path"].get<std::string>().c_str() : "");
	if (!params.contains("path") || !params["path"].is_string()) {
		return tool_result_t::error("path (string) is required");
	}
	std::string path = params["path"].get<std::string>();
	if (path.empty()) {
		return tool_result_t::error("path must be non-empty");
	}
	if (!analysis_session::open_session(path)) {
		std::string err = analysis_session::last_error();
		size_t idx = 0;
		if (analysis_session::find_session_by_path(path, &idx)) {
			auto sum = analysis_session::summarize_session_at(idx);
			json root;
			root["opened"] = summary_to_json(sum);
			root["already_open"] = true;
			diag::log_tagged_fmt("sess_tools",
				"sessions_open_file path='%s' already_open id='%s'",
				path.c_str(), sum.id.c_str());
			return tool_result_t::ok(root);
		}
		diag::log_tagged_fmt("sess_tools",
			"sessions_open_file path='%s' open_failed err='%s'",
			path.c_str(), err.c_str());
		return tool_result_t::error(std::string("open failed: ") + err);
	}
	size_t idx = 0;
	if (!analysis_session::find_session_by_path(path, &idx)) {
		return tool_result_t::error("session created but lookup failed");
	}
	auto sum = analysis_session::summarize_session_at(idx);
	json root;
	root["opened"] = summary_to_json(sum);
	root["already_open"] = false;
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file path='%s' opened id='%s'",
		path.c_str(), sum.id.c_str());
	return tool_result_t::ok(root);
}

static tool_result_t sessions_attach_pid(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_attach_pid entry");
	if (!params.contains("pid")) {
		return tool_result_t::error("pid is required");
	}
	uint32_t pid = parse_pid(params["pid"]);
	if (pid == 0) {
		return tool_result_t::error("invalid pid");
	}
	if (!wait_for_binary_load_quiescent(30000)) {
		return tool_result_t::error("attach failed: load timeout");
	}
	std::string err;
	if (!analysis_session::open_attach_session(pid, &err)) {
		diag::log_tagged_fmt("sess_tools",
			"sessions_attach_pid pid=%u attach_failed err='%s'", pid, err.c_str());
		return tool_result_t::error(std::string("attach failed: ") + err);
	}
	size_t idx = 0;
	if (!analysis_session::find_session_by_pid(pid, &idx)) {
		return tool_result_t::error("session attached but lookup failed");
	}
	auto sum = analysis_session::summarize_session_at(idx);
	json root;
	root["attached"] = summary_to_json(sum);
	diag::log_tagged_fmt("sess_tools",
		"sessions_attach_pid pid=%u attached id='%s'",
		pid, sum.id.c_str());
	return tool_result_t::ok(root);
}

static tool_result_t sessions_close(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_close entry id='%s'",
		params.contains("binary_id") && params["binary_id"].is_string()
			? params["binary_id"].get<std::string>().c_str() : "");
	if (!params.contains("binary_id") || !params["binary_id"].is_string()) {
		return tool_result_t::error("binary_id (string) is required");
	}
	if (!wait_for_binary_load_quiescent(30000)) {
		return tool_result_t::error("close failed: load timeout");
	}
	std::string id = params["binary_id"].get<std::string>();
	size_t idx = 0;
	if (!analysis_session::find_session_by_id(id, &idx)) {
		return tool_result_t::error("binary_id not found: " + id);
	}
	if (!analysis_session::close_session(idx)) {
		std::string err = analysis_session::last_error();
		return tool_result_t::error(std::string("close failed: ") + err);
	}
	json root;
	root["closed_id"] = id;
	root["closed_idx"] = static_cast<uint64_t>(idx);
	diag::log_tagged_fmt("sess_tools",
		"sessions_close id='%s' idx=%llu",
		id.c_str(), static_cast<unsigned long long>(idx));
	return tool_result_t::ok(root);
}

static std::wstring widen(const std::string& s)
{
	if (s.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), out.data(), needed);
	return out;
}

static tool_result_t sessions_run_binary(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_run_binary entry path='%.120s'",
		params.contains("path") && params["path"].is_string()
			? params["path"].get<std::string>().c_str() : "");
	if (!params.contains("path") || !params["path"].is_string()) {
		return tool_result_t::error("path (string) is required");
	}
	run_target::launch_options_t opts;
	opts.exe_path = widen(params["path"].get<std::string>());
	if (params.contains("args") && params["args"].is_string())
		opts.args = widen(params["args"].get<std::string>());
	if (params.contains("working_dir") && params["working_dir"].is_string())
		opts.working_dir = widen(params["working_dir"].get<std::string>());
	if (params.contains("block_network") && params["block_network"].is_boolean())
		opts.block_network = params["block_network"].get<bool>();
	if (params.contains("kill_on_host_exit") && params["kill_on_host_exit"].is_boolean())
		opts.kill_on_host_exit = params["kill_on_host_exit"].get<bool>();
	if (params.contains("attach_after_resume") && params["attach_after_resume"].is_boolean())
		opts.attach_after_resume = params["attach_after_resume"].get<bool>();
	if (params.contains("memory_cap_mb") && params["memory_cap_mb"].is_number_unsigned())
		opts.memory_cap_mb = static_cast<uint32_t>(params["memory_cap_mb"].get<uint64_t>());
	if (params.contains("auto_terminate_sec") && params["auto_terminate_sec"].is_number_unsigned())
		opts.auto_terminate_sec = static_cast<uint32_t>(params["auto_terminate_sec"].get<uint64_t>());

	if (params.contains("isolation") && params["isolation"].is_string()) {
		std::string iso = params["isolation"].get<std::string>();
		if (iso == "appcontainer") opts.isolation = run_target::isolation_t::appcontainer;
		else if (iso == "windows_sandbox") opts.isolation = run_target::isolation_t::windows_sandbox;
		else opts.isolation = run_target::isolation_t::same_desktop_jobbed;
	}

	run_target::launch_result_t result;
	bool ok = run_target::launch(opts, result);
	if (!ok || !result.ok) {
		diag::log_tagged_fmt("sess_tools",
			"sessions_run_binary path='%s' launch_failed err='%s'",
			params["path"].get<std::string>().c_str(), result.error.c_str());
		return tool_result_t::error(std::string("launch failed: ") + result.error);
	}

	if (opts.attach_after_resume && result.pid != 0) {
		std::string attach_err;
		(void)analysis_session::open_attach_session(result.pid, &attach_err);
	}

	json root;
	root["pid"] = result.pid;
	root["firewall_rule_name"] = result.firewall_rule_name;
	root["attached"] = (opts.attach_after_resume && result.pid != 0);
	diag::log_tagged_fmt("sess_tools",
		"sessions_run_binary launched pid=%u",
		result.pid);
	return tool_result_t::ok(root);
}

void register_session_tools(mcp_standalone::server_t& srv)
{
	diag::log_tagged_fmt("sess_tools", "register_session_tools entry");
	srv.register_tool({
		"sessions_list",
		"List all open analysis sessions (static files and live process attaches). Returns each session's id, kind (file|live), path, pid, process name, is_active, is_alive, and last_active_steady_ms. Use the returned id as `binary_id` on any other tool call to target that session.",
		{},
		true,
		&sessions_list
	});

	srv.register_tool({
		"sessions_get_active",
		"Return the currently active session, or null if none are open.",
		{},
		true,
		&sessions_get_active
	});

	srv.register_tool({
		"sessions_switch",
		"Switch the active analysis session by id. Required for swapping which binary the UI shows. Other tools auto-route via the `binary_id` parameter without changing the active session.",
		{{"binary_id", "string", "Session id returned by sessions_list", true}},
		false,
		&sessions_switch
	});

	srv.register_tool({
		"sessions_open_file",
		"Open a static PE/ELF/Mach-O file as a new session. Returns the new session id.",
		{{"path", "string", "Absolute path to the binary file", true}},
		false,
		&sessions_open_file
	});

	srv.register_tool({
		"sessions_attach_pid",
		"Attach the kernel driver to a running process and open it as a new live session. Returns the new session id.",
		{{"pid", "number", "Target process id", true}},
		false,
		&sessions_attach_pid
	});

	srv.register_tool({
		"sessions_close",
		"Close a session by id. Detaches the driver if it's a live session.",
		{{"binary_id", "string", "Session id returned by sessions_list", true}},
		false,
		&sessions_close
	});

	srv.register_tool({
		"sessions_run_binary",
		"Launch a binary inside an isolation container (default: same-desktop jobbed with firewall block) and optionally attach to it. Returns the new pid.",
		{
			{"path", "string", "Absolute path to the binary to launch", true},
			{"args", "string", "Command-line arguments (optional)", false},
			{"working_dir", "string", "Working directory (optional)", false},
			{"isolation", "string", "Isolation level: same_desktop_jobbed | appcontainer | windows_sandbox", false},
			{"block_network", "boolean", "Block all outbound network traffic from the target (default true)", false},
			{"kill_on_host_exit", "boolean", "Kill the target when AiDAStandalone exits (default true)", false},
			{"attach_after_resume", "boolean", "Auto-attach as a live session after launch (default true)", false},
			{"memory_cap_mb", "number", "Hard memory cap in MiB (0 = unlimited)", false},
			{"auto_terminate_sec", "number", "Kill the target after this many seconds (0 = never)", false}
		},
		false,
		&sessions_run_binary
	});
}

}

namespace session_tools_ext {
	void register_tools(mcp_standalone::server_t& srv) {
		session_tools::register_session_tools(srv);
	}
}
