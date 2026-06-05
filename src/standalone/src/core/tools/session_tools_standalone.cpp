#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../mcp/mcp_standalone.hpp"
#include "../session/analysis_session.hpp"
#include "../session/session_health.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/guest_lab_bridge.hpp"
#include "../ui/loading_binary_overlay.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
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

bool parse_u32_value(const json& v, uint32_t& out)
{
	uint64_t raw = 0;
	if (v.is_number_unsigned()) {
		raw = v.get<uint64_t>();
	} else if (v.is_number_integer()) {
		int64_t s = v.get<int64_t>();
		if (s < 0)
			return false;
		raw = static_cast<uint64_t>(s);
	} else if (v.is_string()) {
		try {
			const std::string text = v.get<std::string>();
			if (!text.empty() && text[0] == '-')
				return false;
			raw = std::stoull(text, nullptr, 0);
		} catch (...) {
			return false;
		}
	} else {
		return false;
	}
	out = static_cast<uint32_t>(raw > 0xFFFFFFFFull ? 0xFFFFFFFFu : raw);
	return true;
}

bool wait_for_binary_load_quiescent(uint32_t timeout_ms)
{
	const ULONGLONG start = GetTickCount64();
	ULONGLONG last_log = 0;
	ULONGLONG last_poll_log = 0;
	uint32_t poll_count = 0;
	bool first_poll = true;
	loading_binary_overlay::log_state("session_wait_begin");
	for (;;) {
		const ULONGLONG before_tick = GetTickCount64();
		const ULONGLONG before_elapsed = before_tick - start;
		const char* phase_before = loading_binary_overlay::current_phase_name();
		const bool log_poll = first_poll || before_elapsed - last_poll_log >= 250;
		if (log_poll) {
			last_poll_log = before_elapsed;
			diag::log_tagged_fmt("sess_tools",
				"session_wait_poll_pre poll=%u elapsed_ms=%llu timeout_ms=%u phase=%s active=%d",
				poll_count,
				static_cast<unsigned long long>(before_elapsed),
				timeout_ms,
				phase_before,
				loading_binary_overlay::is_active() ? 1 : 0);
		}
		try {
			loading_binary_overlay::poll_completion();
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("sess_tools",
				"session_wait_poll_exception poll=%u elapsed_ms=%llu phase_before=%s what=%s",
				poll_count,
				static_cast<unsigned long long>(GetTickCount64() - start),
				phase_before,
				ex.what());
			loading_binary_overlay::log_state("session_wait_poll_exception");
			return false;
		} catch (...) {
			diag::log_tagged_fmt("sess_tools",
				"session_wait_poll_exception poll=%u elapsed_ms=%llu phase_before=%s what=unknown",
				poll_count,
				static_cast<unsigned long long>(GetTickCount64() - start),
				phase_before);
			loading_binary_overlay::log_state("session_wait_poll_exception");
			return false;
		}
		++poll_count;
		first_poll = false;
		if (log_poll) {
			diag::log_tagged_fmt("sess_tools",
				"session_wait_poll_post poll=%u elapsed_ms=%llu phase_before=%s phase_after=%s active=%d waiting_decision=%d",
				poll_count,
				static_cast<unsigned long long>(GetTickCount64() - start),
				phase_before,
				loading_binary_overlay::current_phase_name(),
				loading_binary_overlay::is_active() ? 1 : 0,
				loading_binary_overlay::is_waiting_for_user_decision() ? 1 : 0);
		}
		if (!loading_binary_overlay::is_active()) {
			diag::log_tagged_fmt("sess_tools",
				"session_wait_done elapsed_ms=%llu phase=%s polls=%u",
				static_cast<unsigned long long>(GetTickCount64() - start),
				loading_binary_overlay::current_phase_name(),
				poll_count);
			return true;
		}
		if (loading_binary_overlay::is_waiting_for_user_decision()) {
			diag::log_tagged_fmt("sess_tools",
				"session_wait_quiescent_user_decision elapsed_ms=%llu phase=%s polls=%u",
				static_cast<unsigned long long>(GetTickCount64() - start),
				loading_binary_overlay::current_phase_name(),
				poll_count);
			return true;
		}
		const ULONGLONG elapsed = GetTickCount64() - start;
		if (elapsed - last_log >= 1000) {
			last_log = elapsed;
			diag::log_tagged_fmt("sess_tools",
				"session_wait_pending elapsed_ms=%llu timeout_ms=%u phase=%s",
				static_cast<unsigned long long>(elapsed),
				timeout_ms,
				loading_binary_overlay::current_phase_name());
		}
		if (elapsed >= timeout_ms) {
			loading_binary_overlay::log_state("session_wait_timeout");
			diag::log_tagged_fmt("sess_tools",
				"session_wait_timeout elapsed_ms=%llu timeout_ms=%u phase=%s polls=%u",
				static_cast<unsigned long long>(elapsed),
				timeout_ms,
				loading_binary_overlay::current_phase_name(),
				poll_count);
			return false;
		}
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
	std::string id = params["binary_id"].get<std::string>();
	size_t idx = 0;
	if (!analysis_session::find_session_by_id(id, &idx)) {
		diag::log_tagged_fmt("sess_tools",
			"sessions_switch id='%s' not_found", id.c_str());
		return tool_result_t::error("binary_id not found: " + id);
	}
	const size_t active = analysis_session::active_session_idx();
	diag::log_tagged_fmt("sess_tools",
		"sessions_switch resolved id='%s' idx=%llu active=%llu phase=%s",
		id.c_str(),
		static_cast<unsigned long long>(idx),
		static_cast<unsigned long long>(active),
		loading_binary_overlay::current_phase_name());
	if (idx == active) {
		auto sum = analysis_session::summarize_session_at(idx);
		json root;
		root["switched_to"] = summary_to_json(sum);
		root["already_active"] = true;
		diag::log_tagged_fmt("sess_tools",
			"sessions_switch id='%s' already_active idx=%llu",
			id.c_str(), static_cast<unsigned long long>(idx));
		return tool_result_t::ok(root);
	}
	if (!wait_for_binary_load_quiescent(30000)) {
		return tool_result_t::error("switch failed: load timeout");
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
	const size_t before_count = analysis_session::list_session_summaries().size();
	const size_t before_active = analysis_session::active_session_idx();
	const uint32_t attached_before = driver_bridge::attached_pid();
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file open_begin path='%s' sessions_before=%llu active_before=%llu attached_pid=%u phase=%s",
		path.c_str(),
		static_cast<unsigned long long>(before_count),
		static_cast<unsigned long long>(before_active),
		attached_before,
		loading_binary_overlay::current_phase_name());
	const bool opened = analysis_session::open_session(path);
	const size_t after_count = analysis_session::list_session_summaries().size();
	const size_t after_active = analysis_session::active_session_idx();
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file open_return path='%s' opened=%d sessions_after=%llu active_after=%llu attached_pid=%u phase=%s",
		path.c_str(),
		opened ? 1 : 0,
		static_cast<unsigned long long>(after_count),
		static_cast<unsigned long long>(after_active),
		driver_bridge::attached_pid(),
		loading_binary_overlay::current_phase_name());
	if (!opened) {
		std::string err = analysis_session::last_error();
		size_t idx = 0;
		if (analysis_session::find_session_by_path(path, &idx)) {
			diag::log_tagged_fmt("sess_tools",
				"sessions_open_file existing_session_found path='%s' idx=%llu err='%s'",
				path.c_str(),
				static_cast<unsigned long long>(idx),
				err.c_str());
			const bool wait_ok = wait_for_binary_load_quiescent(30000);
			diag::log_tagged_fmt("sess_tools",
				"sessions_open_file existing_wait_done path='%s' idx=%llu wait_ok=%d phase=%s",
				path.c_str(),
				static_cast<unsigned long long>(idx),
				wait_ok ? 1 : 0,
				loading_binary_overlay::current_phase_name());
			if (!wait_ok) {
				return tool_result_t::error("open failed: load timeout");
			}
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
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file wait_begin path='%s' phase=%s attached_pid=%u",
		path.c_str(),
		loading_binary_overlay::current_phase_name(),
		driver_bridge::attached_pid());
	const bool wait_ok = wait_for_binary_load_quiescent(30000);
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file wait_done path='%s' wait_ok=%d phase=%s attached_pid=%u",
		path.c_str(),
		wait_ok ? 1 : 0,
		loading_binary_overlay::current_phase_name(),
		driver_bridge::attached_pid());
	if (!wait_ok) {
		return tool_result_t::error("open failed: load timeout");
	}
	size_t idx = 0;
	if (!analysis_session::find_session_by_path(path, &idx)) {
		diag::log_tagged_fmt("sess_tools",
			"sessions_open_file lookup_failed path='%s' sessions_after_wait=%llu active=%llu",
			path.c_str(),
			static_cast<unsigned long long>(analysis_session::list_session_summaries().size()),
			static_cast<unsigned long long>(analysis_session::active_session_idx()));
		return tool_result_t::error("session created but lookup failed");
	}
	auto sum = analysis_session::summarize_session_at(idx);
	json root;
	root["opened"] = summary_to_json(sum);
	root["already_open"] = false;
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file path='%s' opened id='%s' idx=%llu active=%d attached_pid=%u",
		path.c_str(),
		sum.id.c_str(),
		static_cast<unsigned long long>(idx),
		sum.is_active ? 1 : 0,
		driver_bridge::attached_pid());
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
	diag::log_tagged_fmt("sess_tools",
		"sessions_attach_pid parsed pid=%u attached_pid=%u phase=%s",
		pid,
		driver_bridge::attached_pid(),
		loading_binary_overlay::current_phase_name());
	size_t existing_idx = 0;
	if (analysis_session::find_session_by_pid(pid, &existing_idx)) {
		auto sum = analysis_session::summarize_session_at(existing_idx);
		json root;
		root["attached"] = summary_to_json(sum);
		root["already_attached"] = true;
		diag::log_tagged_fmt("sess_tools",
			"sessions_attach_pid pid=%u existing_session idx=%llu id='%s'",
			pid,
			static_cast<unsigned long long>(existing_idx),
			sum.id.c_str());
		return tool_result_t::ok(root);
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
	std::string id = params["binary_id"].get<std::string>();
	size_t idx = 0;
	if (!analysis_session::find_session_by_id(id, &idx)) {
		return tool_result_t::error("binary_id not found: " + id);
	}
	diag::log_tagged_fmt("sess_tools",
		"sessions_close resolved id='%s' idx=%llu active=%llu phase=%s",
		id.c_str(),
		static_cast<unsigned long long>(idx),
		static_cast<unsigned long long>(analysis_session::active_session_idx()),
		loading_binary_overlay::current_phase_name());
	if (!wait_for_binary_load_quiescent(30000)) {
		return tool_result_t::error("close failed: load timeout");
	}
	if (!analysis_session::close_session(idx)) {
		std::string err = analysis_session::last_error();
		diag::log_tagged_fmt("sess_tools",
			"sessions_close id='%s' close_failed err='%s'",
			id.c_str(), err.c_str());
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

static std::string narrow(const std::wstring& s)
{
	if (s.empty()) return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, s.c_str(),
		static_cast<int>(s.size()), out.data(), needed, nullptr, nullptr);
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
	opts.isolation = run_target::isolation_t::windows_sandbox;
	opts.attach_after_resume = false;
	if (params.contains("args") && params["args"].is_string())
		opts.args = widen(params["args"].get<std::string>());
	if (params.contains("working_dir") && params["working_dir"].is_string())
		opts.working_dir = widen(params["working_dir"].get<std::string>());
	if (params.contains("block_network") && params["block_network"].is_boolean())
		opts.block_network = params["block_network"].get<bool>();
	if (params.contains("kill_on_host_exit") && params["kill_on_host_exit"].is_boolean())
		opts.kill_on_host_exit = params["kill_on_host_exit"].get<bool>();
	if (params.contains("attach_after_resume") && params["attach_after_resume"].is_boolean()
	    && params["attach_after_resume"].get<bool>())
		return tool_result_t::error("sessions_run_binary uses Windows Sandbox and cannot attach the host driver to the guest process.");
	uint32_t parsed_u32 = 0;
	if (params.contains("memory_cap_mb") && parse_u32_value(params["memory_cap_mb"], parsed_u32))
		opts.memory_cap_mb = parsed_u32;
	if (params.contains("auto_terminate_sec") && parse_u32_value(params["auto_terminate_sec"], parsed_u32))
		opts.auto_terminate_sec = parsed_u32;

	if (params.contains("isolation") && params["isolation"].is_string()) {
		std::string iso = params["isolation"].get<std::string>();
		if (iso != "windows_sandbox")
			return tool_result_t::error("sessions_run_binary no longer supports host execution. Use windows_sandbox for interactive malware lab runs.");
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
	root["sandbox_dir"] = narrow(result.sandbox_dir);
	root["guest_lab_active"] = guest_lab::is_active();
	root["guest_bridge_dir"] = narrow(guest_lab::current().bridge_dir);
	root["attached"] = false;
	diag::log_tagged_fmt("sess_tools",
		"sessions_run_binary launched pid=%u",
		result.pid);
	run_target::cleanup(result);
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
		"Launch a binary inside an interactive Windows Sandbox VM. Host execution and host driver attach are disabled for malware safety.",
		{
			{"path", "string", "Absolute path to the binary to launch", true},
			{"args", "string", "Command-line arguments (optional)", false},
			{"working_dir", "string", "Ignored for Windows Sandbox runs; the sample starts from the VM input folder", false},
			{"isolation", "string", "Isolation level: windows_sandbox", false},
			{"block_network", "boolean", "Block all outbound network traffic from the target (default true)", false},
			{"kill_on_host_exit", "boolean", "Kill the target when AiDAStandalone exits (default true)", false},
			{"attach_after_resume", "boolean", "Must be false because the process runs inside the VM", false},
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
