#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../mcp/ida_compat_schemas.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "../session/analysis_session.hpp"
#include "../analysis/workspace/workspace_database.hpp"
#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../session/session_health.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/vm_guest_bridge.hpp"
#include "../anti-tamper/self_guard.hpp"
#include "../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <limits>
#include <string>
#include <thread>
#include <utility>

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

const char* readiness_name(aida::analysis::workspace_readiness_t readiness)
{
	switch (readiness) {
	case aida::analysis::workspace_readiness_t::created: return "created";
	case aida::analysis::workspace_readiness_t::provider_ready: return "provider_ready";
	case aida::analysis::workspace_readiness_t::parsed: return "parsed";
	case aida::analysis::workspace_readiness_t::analyzing: return "analyzing";
	case aida::analysis::workspace_readiness_t::baseline_ready: return "baseline_ready";
	case aida::analysis::workspace_readiness_t::partial: return "partial";
	case aida::analysis::workspace_readiness_t::failed: return "failed";
	case aida::analysis::workspace_readiness_t::cancelling: return "cancelling";
	case aida::analysis::workspace_readiness_t::closing: return "closing";
	case aida::analysis::workspace_readiness_t::closed: return "closed";
	}
	return "unknown";
}

const char* architecture_name(aida::analysis::architecture_id_t architecture)
{
	switch (architecture) {
	case aida::analysis::architecture_id_t::x86: return "x86";
	case aida::analysis::architecture_id_t::x86_64: return "x86_64";
	default: return "unknown";
	}
}

const char* format_name(aida::analysis::format_id_t format)
{
	switch (format) {
	case aida::analysis::format_id_t::pe32: return "pe32";
	case aida::analysis::format_id_t::pe32_plus: return "pe32_plus";
	default: return "unknown";
	}
}

tool_result_t list_instances(int port)
{
	auto workspaces = aida::analysis::workspace_registry().list();
	json instances = json::array();
	std::uint32_t only_live_pid = 0;
	std::size_t live_count = 0;
	for (const auto& workspace : workspaces) {
		const auto& identity = workspace->identity();
		const bool live = identity.target_kind() == aida::analysis::target_kind_t::live_snapshot;
		const std::uint32_t pid = live && identity.process() ? identity.process()->pid : 0;
		std::shared_ptr<const aida::analysis::live_snapshot_provider_t> live_provider;
		bool snapshot_stale = false;
		if (live) {
			live_provider = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
				workspace->provider_handle());
			snapshot_stale = !live_provider || !live_provider->validate_current_identity();
		}
		if (pid != 0 && !snapshot_stale) {
			++live_count;
			only_live_pid = pid;
		}
		json instance;
		instance["pid"] = pid;
		instance["binary"] = identity.bin_name();
		instance["host"] = "127.0.0.1";
		instance["port"] = port;
		auto database = workspace->database();
		instance["idb_path"] = database ? database->path() : std::string();
		instance["backend"] = live ? "aida_driver_live" : "aida_static";
		instance["binary_id"] = identity.binary_id().to_hex();
		instance["kind"] = live ? "live" : "static";
		instance["path"] = identity.normalized_source_path();
		instance["process_creation_id"] = identity.process()
			? json(std::to_string(identity.process()->creation_time_100ns))
			: json(nullptr);
		instance["architecture"] = architecture_name(identity.architecture());
		instance["format"] = format_name(identity.format());
		instance["analysis_revision"] = workspace->analysis_revision();
		instance["overlay_revision"] = workspace->overlay_revision();
		instance["readiness"] = readiness_name(workspace->progress().readiness);
		instance["snapshot_stale"] = snapshot_stale;
		if (live_provider) {
			const auto& metadata = live_provider->metadata();
			instance["capture_time_100ns"] = std::to_string(metadata.capture_time_100ns);
			instance["capture_address"] = std::to_string(metadata.capture_address);
			instance["capture_size"] = metadata.capture_size;
			instance["capture_hash"] = metadata.capture_hash.to_hex();
			instance["module_base"] = std::to_string(metadata.module.base);
			instance["module_size"] = metadata.module.size;
			instance["module_name"] = metadata.module.normalized_name;
		}
		instances.push_back(std::move(instance));
	}
	json result;
	result["instances"] = std::move(instances);
	result["count"] = workspaces.size();
	result["default_pid"] = live_count == 1 ? json(only_live_pid) : json(nullptr);
	return tool_result_t::ok(result);
}

bool parse_pid(const json& value, uint32_t& out, std::string* out_code = nullptr, std::string* out_message = nullptr, json* out_details = nullptr)
{
	auto set_error = [&](const char* code, const char* message, std::int64_t provided) {
		if (out_code) *out_code = code;
		if (out_message) *out_message = message;
		if (out_details) *out_details = json{{"provided", provided}, {"min", 0}, {"max", 4294967295u}};
	};

	std::int64_t signed_value = 0;
	bool have_signed = false;

	if (value.is_number_integer()) {
		signed_value = value.get<std::int64_t>();
		have_signed = true;
	} else if (value.is_number_unsigned()) {
		const std::uint64_t unsigned_value = value.get<std::uint64_t>();
		if (unsigned_value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
			set_error("INVALID_ARGUMENT", "pid exceeds the valid 32-bit process id range",
				static_cast<std::int64_t>((std::numeric_limits<std::int64_t>::max)()));
			if (out_details) (*out_details)["provided"] = unsigned_value;
			return false;
		}
		signed_value = static_cast<std::int64_t>(unsigned_value);
		have_signed = true;
	} else if (value.is_string()) {
		try {
			const std::string text = value.get<std::string>();
			if (text.empty()) {
				set_error("INVALID_ARGUMENT", "pid string is empty", 0);
				return false;
			}
			if (text.front() == '-') {
				set_error("INVALID_ARGUMENT", "pid must be non-negative", 0);
				if (out_details) (*out_details)["provided"] = text;
				return false;
			}
			std::size_t consumed = 0;
			const std::uint64_t parsed = std::stoull(text, &consumed, 0);
			if (consumed != text.size()) {
				set_error("INVALID_ARGUMENT", "pid string has trailing characters", 0);
				if (out_details) (*out_details)["provided"] = text;
				return false;
			}
			if (parsed > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
				set_error("INVALID_ARGUMENT", "pid exceeds the valid 32-bit process id range",
					static_cast<std::int64_t>((std::numeric_limits<std::int64_t>::max)()));
				if (out_details) (*out_details)["provided"] = parsed;
				return false;
			}
			signed_value = static_cast<std::int64_t>(parsed);
			have_signed = true;
		} catch (...) {
			set_error("INVALID_ARGUMENT", "pid string could not be parsed", 0);
			return false;
		}
	} else {
		set_error("INVALID_ARGUMENT", "pid must be a number or numeric string", 0);
		return false;
	}

	if (!have_signed) {
		set_error("INVALID_ARGUMENT", "pid could not be parsed", 0);
		return false;
	}
	if (signed_value < 0) {
		set_error("INVALID_ARGUMENT", "pid must be non-negative", signed_value);
		return false;
	}
	if (static_cast<std::uint64_t>(signed_value) > static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())) {
		set_error("INVALID_ARGUMENT", "pid exceeds the 32-bit process id range", signed_value);
		return false;
	}
	if (signed_value == 0) {
		set_error("INVALID_ARGUMENT", "pid must be a positive process id", 0);
		return false;
	}
	out = static_cast<std::uint32_t>(signed_value);
	return true;
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
			size_t consumed = 0;
			raw = std::stoull(text, &consumed, 0);
			if (consumed != text.size())
				return false;
		} catch (...) {
			return false;
		}
	} else {
		return false;
	}
	if (raw > (std::numeric_limits<uint32_t>::max)())
		return false;
	out = static_cast<uint32_t>(raw);
	return true;
}

tool_result_t session_wait_error(const std::string& message, const std::string& code,
                                 const std::string& session_id)
{
	return tool_result_t::error(message, code, json{{"session_id", session_id}});
}

tool_result_t wait_for_workspace_closed(
	const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const std::string& session_id)
{
	if (!workspace || workspace->closed())
		return tool_result_t::ok(json{{"session_id", session_id}, {"drain_pending", false}});
	const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
	if (deadline == 0)
		return tool_result_t::ok(json{{"session_id", session_id}, {"drain_pending", true}});
	while (!workspace->closed()) {
		if (mcp_standalone::current_call_cancelled())
			return session_wait_error("Session close wait was cancelled", "CANCELLED", session_id);
		if (static_cast<std::uint64_t>(GetTickCount64()) >= deadline)
			return session_wait_error("Session close drain deadline expired", "DEADLINE_EXCEEDED", session_id);
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	return tool_result_t::ok(json{{"session_id", session_id}, {"drain_pending", false}});
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

static tool_result_t sessions_open_file(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_open_file entry path='%.120s'",
		params.contains("path") && params["path"].is_string()
			? params["path"].get<std::string>().c_str() : "");
	if (!params.contains("path") || !params["path"].is_string())
		return tool_result_t::error("path (string) is required");
	const std::string path = params["path"].get<std::string>();
	if (path.empty())
		return tool_result_t::error("path must be non-empty");
	{
		self_guard::self_guard_context_t sg_ctx;
		sg_ctx.tool_name = "sessions_open_file";
		sg_ctx.has_binary_path = true;
		sg_ctx.target_binary_path = path;
		auto guard_result = self_guard::invoke_self_guard(sg_ctx);
		if (guard_result != self_guard::self_guard_result_t::allow)
			self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
	}
	size_t existing_index = 0;
	const bool already_open = analysis_session::find_session_by_path(path, &existing_index);
	if (!analysis_session::open_session(path)) {
		if (!analysis_session::find_session_by_path(path, &existing_index))
			return tool_result_t::error(std::string("open failed: ") + analysis_session::last_error());
	}
	size_t index = 0;
	if (!analysis_session::find_session_by_path(path, &index))
		return tool_result_t::error("session created but lookup failed", "SESSION_LOOKUP_FAILED", json::object());
	const auto summary = analysis_session::summarize_session_at(index);
	json root;
	root["opened"] = summary_to_json(summary);
	root["already_open"] = already_open;
	diag::log_tagged_fmt("sess_tools",
		"sessions_open_file ready path='%s' id='%s' binary_id='%s' readiness=%s",
		path.c_str(), summary.id.c_str(), summary.binary_id.c_str(), readiness_name(summary.readiness));
	return tool_result_t::ok(root);
}

static tool_result_t sessions_attach_pid(const json& params)
{
	diag::log_tagged_fmt("sess_tools", "sessions_attach_pid entry");
	if (!params.contains("pid"))
		return tool_result_t::error("pid is required");
	uint32_t pid = 0;
	std::string pid_code, pid_message;
	json pid_details;
	if (!parse_pid(params["pid"], pid, &pid_code, &pid_message, &pid_details))
		return tool_result_t::error(pid_message.empty() ? std::string("invalid pid") : pid_message,
			pid_code.empty() ? std::string("INVALID_ARGUMENT") : pid_code,
			pid_details.is_object() ? pid_details : json::object());
	{
		self_guard::self_guard_context_t sg_ctx;
		sg_ctx.tool_name = "sessions_attach_pid";
		sg_ctx.has_pid = true;
		sg_ctx.target_pid = pid;
		auto guard_result = self_guard::invoke_self_guard(sg_ctx);
		if (guard_result != self_guard::self_guard_result_t::allow)
			self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
	}
	size_t index = 0;
	const bool already_attached = analysis_session::find_session_by_pid(pid, &index);
	if (!already_attached) {
		std::string error;
		if (!analysis_session::open_attach_session(pid, &error)) {
			if (analysis_session::find_session_by_pid(pid, &index)) {
				diag::log_tagged_fmt("sess_tools",
					"sessions_attach_pid pid=%u attach_failed_but_found error='%s'",
					pid, error.c_str());
			} else {
				return tool_result_t::error(std::string("attach failed: ") + error);
			}
		} else if (!analysis_session::find_session_by_pid(pid, &index))
			return tool_result_t::error("session attached but lookup failed",
				"SESSION_LOOKUP_FAILED", json{{"pid", pid}});
	}
	const auto summary = analysis_session::summarize_session_at(index);
	if (summary.load_state == analysis_session::session_load_state_t::failed && summary.error)
		return tool_result_t::error(summary.error->message, summary.error->stable_code(),
			json{{"pid", pid}, {"phase", summary.error->phase}});
	json root;
	root["attached"] = summary_to_json(summary);
	root["already_attached"] = already_attached;
	root["cleared_stale_load"] = false;
	diag::log_tagged_fmt("sess_tools",
		"sessions_attach_pid pid=%u id='%s' binary_id='%s' already=%d",
		pid, summary.id.c_str(), summary.binary_id.c_str(), already_attached ? 1 : 0);
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
	auto workspace = analysis_session::workspace_for_session(idx);
	diag::log_tagged_fmt("sess_tools",
		"sessions_close resolved id='%s' idx=%llu active=%llu binary_id='%s'",
		id.c_str(),
		static_cast<unsigned long long>(idx),
		static_cast<unsigned long long>(analysis_session::active_session_idx()),
		workspace ? workspace->identity().binary_id().to_hex().c_str() : "");
	if (!analysis_session::close_session(idx)) {
		std::string err = analysis_session::last_error();
		diag::log_tagged_fmt("sess_tools",
			"sessions_close id='%s' close_failed err='%s'",
			id.c_str(), err.c_str());
		return tool_result_t::error(std::string("close failed: ") + err);
	}
	auto drained = wait_for_workspace_closed(workspace, id);
	if (!drained.success)
		return drained;
	json root;
	root["closed_id"] = id;
	root["closed_idx"] = static_cast<uint64_t>(idx);
	root["drain_pending"] = drained.data.value("drain_pending", false);
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
	{
		const std::string run_path = params["path"].get<std::string>();
		if (!run_path.empty()) {
			self_guard::self_guard_context_t sg_ctx;
			sg_ctx.tool_name = "sessions_run_binary";
			sg_ctx.has_binary_path = true;
			sg_ctx.target_binary_path = run_path;
			auto guard_result = self_guard::invoke_self_guard(sg_ctx);
			if (guard_result != self_guard::self_guard_result_t::allow)
				self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
		}
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

	const auto caps = run_target::probe_capabilities();
	if (!caps.has_windows_sandbox) {
		json root;
		root["dependency"] = "windows_sandbox";
		root["dependency_available"] = false;
		root["dependency_unavailable"] = true;
		root["dependency_blocked"] = true;
		root["feature_available"] = false;
		root["host_execution_attempted"] = false;
		root["isolation"] = "windows_sandbox";
		root["path"] = params["path"].get<std::string>();
		root["reason"] = "windows_sandbox_feature_unavailable";
		root["windows_build"] = caps.windows_build;
		return tool_result_t::error("launch failed: Windows Sandbox is unavailable. Enable Windows Sandbox on Windows Pro, Enterprise, or Education with virtualization enabled. Admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All", root);
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
	root["vm_bridge_active"] = vm_guest_bridge::is_active();
	root["vm_bridge_dir"] = narrow(vm_guest_bridge::current().bridge_dir);
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
	mcp_standalone::tool_def_t instances;
	instances.name = "list_instances";
	instances.description = "List every open AiDA static workspace and driver-backed live target without consulting or changing the active UI tab.";
	instances.read_only = true;
	instances.handler = [&srv](const json&) -> tool_result_t { return list_instances(srv.get_port()); };
	if (const auto* schema = mcp_standalone::ida_compat::find_schema("list_instances"))
		instances.input_schema = *schema;
	srv.register_tool(std::move(instances));
	srv.register_tool({
		"sessions_manage",
		"Manage static file, live process, and sandbox sessions. Actions: list, get_active, open_file, attach_pid, close, run_binary.",
		{
			{"action", "string", "list|get_active|open_file|attach_pid|close|run_binary", true},
			{"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
			{"binary_id", "string", "Session id returned by sessions_manage action=list", false},
			{"path", "string", "Absolute path to the binary to open or launch", false},
			{"pid", "number", "Target process id for attach_pid", false},
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
		[](const json& params) -> tool_result_t {
			const std::string action = params.contains("action") && params["action"].is_string()
				? params["action"].get<std::string>()
				: (params.contains("operation") && params["operation"].is_string() ? params["operation"].get<std::string>() : std::string());
			json p = params.is_object() ? params : json::object();
			if (params.contains("payload") && params["payload"].is_object()) {
				for (auto it = params["payload"].begin(); it != params["payload"].end(); ++it)
					p[it.key()] = it.value();
			}
			p.erase("action");
			p.erase("operation");
			p.erase("payload");
			if (action == "list") return sessions_list(p);
			if (action == "get_active") return sessions_get_active(p);
			if (action == "open_file") return sessions_open_file(p);
			if (action == "attach_pid") return sessions_attach_pid(p);
			if (action == "close") return sessions_close(p);
			if (action == "run_binary") return sessions_run_binary(p);
			return tool_result_t::error("sessions_manage unknown action: " + action);
		}
	});
}

}

namespace session_tools_ext {
	void register_tools(mcp_standalone::server_t& srv) {
		session_tools::register_session_tools(srv);
	}
}
