#pragma once

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <commdlg.h>
#include <ShlObj.h>
#include <shellapi.h>
#include <objbase.h>
#endif
#ifdef small
#undef small
#endif

#include <cstring>
#include <cstdio>
#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <filesystem>
#endif

#include "imgui/imgui.h"
#include "../ui/components.hpp"
#include "../ui/theme.hpp"
#include "../ui/fonts.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#endif
#include "../runtime/run_target.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../runtime/vm_guest_bridge.hpp"
#endif
#include "../ui/toast_notification.hpp"
#include "../ui/task_center.hpp"
#include "../infra/executor.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../auth/auth_browser_launch.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#else
#include "../../preview/debugger_preview_runtime.hpp"
#endif

extern HWND g_hwnd;

namespace spawn_target_dialog {

struct result_t {
	std::wstring                exe_path;
	std::wstring                args;
	std::wstring                working_dir;
	run_target::launch_options_t launch_options;
	bool                        accepted = false;
};

namespace detail {

inline bool& open_flag() {
	static bool v = false;
	return v;
}

inline bool& should_open() {
	static bool v = false;
	return v;
}

inline char* exe_buf() {
	static char buf[1024] = {};
	return buf;
}

inline char* args_buf() {
	static char buf[2048] = {};
	return buf;
}

inline char* cwd_buf() {
	static char buf[1024] = {};
	return buf;
}

inline char* custom_bridge_buf() {
	static char buf[1024] = {};
	return buf;
}

inline char* custom_guest_bridge_buf() {
	static char buf[1024] = {};
	return buf;
}

inline char* custom_guest_sample_buf() {
	static char buf[1024] = {};
	return buf;
}

inline bool& pending_result_ready() {
	static bool v = false;
	return v;
}

inline result_t& pending_result() {
	static result_t r;
	return r;
}

inline run_target::capability_probe_t& cached_capabilities() {
	static run_target::capability_probe_t p;
	return p;
}

inline int& isolation_choice() {
	static int v = static_cast<int>(run_target::isolation_t::windows_sandbox);
	return v;
}

inline int& run_mode_choice() {
	static int v = 0;
	return v;
}

inline bool& host_confirm_open() {
	static bool v = false;
	return v;
}

inline bool& block_network_flag() {
	static bool v = true;
	return v;
}

inline bool& kill_on_host_exit_flag() {
	static bool v = true;
	return v;
}

inline int& memory_cap_mb_value() {
	static int v = 0;
	return v;
}

inline int& auto_terminate_sec_value() {
	static int v = 0;
	return v;
}

inline bool& malware_safe_mode_flag() {
	static bool v = true;
	return v;
}

inline bool& log_network_traffic_flag() {
	static bool v = true;
	return v;
}

inline bool& lower_integrity_untrusted_flag() {
	static bool v = false;
	return v;
}

inline bool& allow_child_processes_flag() {
	static bool v = true;
	return v;
}

inline bool& force_mitigations_strict_flag() {
	static bool v = false;
	return v;
}

inline bool& redirect_user_paths_flag() {
	static bool v = true;
	return v;
}

inline bool& register_kernel_guard_flag() {
	static bool v = true;
	return v;
}

inline std::wstring& last_sandbox_dir() {
	static std::wstring v;
	return v;
}

inline std::wstring& last_custom_bridge_dir() {
	static std::wstring v;
	return v;
}

enum class custom_bridge_status_t : std::uint8_t {
	idle,
	queued,
	running,
	succeeded,
	failed,
	cancelled
};

struct custom_bridge_operation_t {
	std::atomic<bool> cancel_requested{false};
	std::atomic<unsigned> phase{0};
	std::atomic<unsigned> irreversible_gate{0};
	std::uint64_t serial = 0;
};

inline custom_bridge_status_t& custom_bridge_status() {
	static custom_bridge_status_t value = custom_bridge_status_t::idle;
	return value;
}

inline std::string& custom_bridge_status_text() {
	static std::string value;
	return value;
}

inline std::shared_ptr<custom_bridge_operation_t>& custom_bridge_operation() {
	static std::shared_ptr<custom_bridge_operation_t> value;
	return value;
}

inline std::atomic<std::uint64_t>& custom_bridge_sequence() {
	static std::atomic<std::uint64_t> value{1};
	return value;
}

inline std::atomic<std::uint64_t>& custom_bridge_dispatch_failure() {
	static std::atomic<std::uint64_t> value{0};
	return value;
}

inline std::atomic<std::uint64_t>& custom_bridge_dispatch_applied() {
	static std::atomic<std::uint64_t> value{0};
	return value;
}

inline bool custom_bridge_pending() {
	return custom_bridge_status() == custom_bridge_status_t::queued ||
		custom_bridge_status() == custom_bridge_status_t::running;
}

inline bool request_custom_bridge_cancel() {
	const auto operation = custom_bridge_operation();
	if (!operation || !custom_bridge_pending())
		return false;
	unsigned expected_gate = 0;
	if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
			std::memory_order_acq_rel))
		return false;
	operation->cancel_requested.store(true, std::memory_order_release);
	const std::string task_id = "debugger.custom_vm_bridge." +
		std::to_string(operation->serial);
	static_cast<void>(aida::ui::task_center::update_task(task_id,
		aida::ui::task_center::task_state_t::cancellation_requested, -1.0f,
		"Cancellation requested before activation"));
	custom_bridge_status_text() = "Cancellation requested; waiting for the current reversible step.";
	return true;
}

inline void poll_custom_bridge_dispatch_failure() {
	const auto operation = custom_bridge_operation();
	if (!operation)
		return;
	const unsigned phase = operation->phase.load(std::memory_order_acquire);
	if (custom_bridge_pending() && phase > 0 && phase < 6) {
		custom_bridge_status() = custom_bridge_status_t::running;
		switch (phase) {
		case 1: custom_bridge_status_text() = "Validating bridge directories."; break;
		case 2: custom_bridge_status_text() = "Staging the reviewed sample."; break;
		case 3: custom_bridge_status_text() = "Staging AiDAGuestAgent.exe."; break;
		case 4: custom_bridge_status_text() = "Preparing bridge metadata."; break;
		case 5: custom_bridge_status_text() = "Activating the custom VM bridge."; break;
		default: break;
		}
	}
	const std::uint64_t failed = custom_bridge_dispatch_failure().exchange(0,
		std::memory_order_acq_rel);
	if (failed == 0 || failed != operation->serial)
		return;
	if (custom_bridge_dispatch_applied().exchange(0, std::memory_order_acq_rel) == failed) {
		custom_bridge_status() = custom_bridge_status_t::succeeded;
		custom_bridge_status_text() = "The bridge was activated, but its detailed UI receipt could not be published.";
	} else {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "The bridge operation finished, but its result could not be published. Retry after reviewing Task Center.";
	}
}

inline void reset_inputs() {
	std::memset(exe_buf(), 0, 1024);
	std::memset(args_buf(), 0, 2048);
	std::memset(cwd_buf(), 0, 1024);
	std::memset(custom_bridge_buf(), 0, 1024);
	std::memset(custom_guest_bridge_buf(), 0, 1024);
	std::memset(custom_guest_sample_buf(), 0, 1024);
	isolation_choice() = static_cast<int>(run_target::isolation_t::windows_sandbox);
	run_mode_choice() = 0;
	host_confirm_open() = false;
	block_network_flag() = true;
	kill_on_host_exit_flag() = true;
	memory_cap_mb_value() = 0;
	auto_terminate_sec_value() = 0;
	malware_safe_mode_flag() = true;
	log_network_traffic_flag() = true;
	lower_integrity_untrusted_flag() = false;
	allow_child_processes_flag() = true;
	force_mitigations_strict_flag() = false;
	redirect_user_paths_flag() = true;
	register_kernel_guard_flag() = true;
}



inline std::wstring widen_utf8(const char* utf8) {
	if (!utf8 || !*utf8) return std::wstring();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::wstring out;
	while (*utf8) out.push_back(static_cast<unsigned char>(*utf8++));
	return out;
#else
	int needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
	if (needed <= 1) return std::wstring();
	std::wstring out(static_cast<size_t>(needed - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out.data(), needed);
	return out;
#endif
}

inline std::string narrow_utf8(const wchar_t* w) {
	if (!w || !*w) return std::string();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::string out;
	while (*w) out.push_back(static_cast<char>(*w++ & 0xFF));
	return out;
#else
	int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
	if (needed <= 1) return std::string();
	std::string out(static_cast<size_t>(needed - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
	return out;
#endif
}

inline std::string parent_dir(const std::string& path) {
	if (path.empty()) return std::string();
	size_t pos = path.find_last_of("\\/");
	if (pos == std::string::npos) return std::string();
	return path.substr(0, pos);
}

inline std::string trim(const char* s) {
	if (!s) return std::string();
	std::string out(s);
	while (!out.empty()) {
		char c = out.back();
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') out.pop_back();
		else break;
	}
	size_t i = 0;
	while (i < out.size()) {
		char c = out[i];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i;
		else break;
	}
	if (i > 0) out.erase(0, i);
	return out;
}

inline std::wstring resolve_guest_agent_exe() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return L"C:/Preview/AiDAGuestAgent.exe";
#else
	wchar_t module_path[MAX_PATH] = {};
	DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return {};
	std::filesystem::path p(module_path);
	std::filesystem::path agent = p.parent_path() / L"AiDAGuestAgent.exe";
	std::error_code ec;
	if (!std::filesystem::exists(agent, ec) || ec) return {};
	return agent.wstring();
#endif
}

inline std::string join_guest_path(std::string base, const std::string& leaf) {
	if (base.empty()) return leaf;
	while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
	return base + "\\" + leaf;
}

inline std::string quote_arg(std::string value) {
	std::string out;
	out.reserve(value.size() + 2);
	out.push_back('"');
	for (char c : value) {
		if (c == '"') out += "\\\"";
		else out.push_back(c);
	}
	out.push_back('"');
	return out;
}

inline std::string custom_guest_command() {
	std::string guest_bridge = trim(custom_guest_bridge_buf());
	if (guest_bridge.empty()) return {};
	std::string agent = join_guest_path(guest_bridge, "agent\\AiDAGuestAgent.exe");
	return quote_arg(agent) + " --bridge " + quote_arg(guest_bridge);
}

inline void open_custom_vm_guide() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::record("open_guide", "custom-vm-bridge-guide.md");
#else
	static std::atomic<std::uint64_t> sequence{1};
	const std::uint64_t serial = sequence.fetch_add(1, std::memory_order_relaxed);
	const std::string task_id = "debugger.custom_vm_guide." + std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "debugger.spawn_target";
	registration.owner = "Run Target";
	registration.owner_view = "view.debug.cpu";
	registration.owner_action = "Open custom VM guide";
	registration.target = "custom-vm-bridge-guide.md";
	registration.label = "Locate and open custom VM guide";
	registration.stage = "Queued";
	registration.affected_entity = "custom-vm-bridge-guide.md";
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		toast_notification::push("Task Center rejected the guide lookup.",
			toast_notification::toast_type_t::error, 4.0f);
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.custom_vm_guide.open";
	submission.thread_class = "bounded_file_io";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 1;
	submission.generation = serial;
	submission.diagnostic_id = task_id.c_str();
	submission.ui_access_policy = "ui_dispatch_only";
	submission.failure_policy = "typed_diagnostic";
	submission.shutdown_policy = "drain";
	submission.body = [task_id]() {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, -1.0f,
			"Resolving bounded guide candidates"));
		bool opened = false;
		std::string error;
		try {
			const std::filesystem::path relative = L"docs\\custom-vm-bridge-guide.md";
			std::error_code filesystem_error;
			std::array<std::filesystem::path, 4> candidates{};
			candidates[0] = std::filesystem::current_path(filesystem_error) / relative;
			wchar_t module_path[MAX_PATH] = {};
			const DWORD length = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
			if (length > 0 && length < MAX_PATH) {
				const std::filesystem::path module_directory =
					std::filesystem::path(module_path).parent_path();
				candidates[1] = module_directory / relative;
				candidates[2] = module_directory.parent_path() / relative;
				candidates[3] = module_directory.parent_path().parent_path() / relative;
			}
			for (const auto& candidate : candidates) {
				filesystem_error.clear();
				if (candidate.empty() || !std::filesystem::is_regular_file(candidate,
						filesystem_error) || filesystem_error)
					continue;
				const auto result = reinterpret_cast<std::intptr_t>(ShellExecuteW(g_hwnd,
					L"open", candidate.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
				opened = result > 32;
				if (!opened)
					error = "Windows rejected the guide open request.";
				break;
			}
			if (!opened && error.empty())
				error = "The guide was not found in any approved installation or repository location.";
		} catch (const std::exception& exception) {
			error = exception.what();
		} catch (...) {
			error = "Unknown guide lookup failure.";
		}
		auto publish = [task_id, opened, error] {
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				opened ? aida::ui::task_center::task_state_t::completed :
					aida::ui::task_center::task_state_t::failed,
				1.0f, opened ? "Guide opened" : "Guide unavailable",
				opened ? "Opened custom VM bridge guide" : error,
				opened ? std::string() : "diagnostic." + task_id));
			if (!opened)
				toast_notification::push(error, toast_notification::toast_type_t::error, 6.0f);
		};
		if (!aida::ui_thread::post(std::move(publish), "spawn_target_dialog",
				"publish_custom_vm_guide", "worker_completion")) {
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				aida::ui::task_center::task_state_t::failed, 1.0f,
				"UI publication rejected", opened ?
					"The guide opened, but its UI receipt could not be published" :
					"The guide result could not be published",
				"diagnostic." + task_id));
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Executor rejected guide lookup", submitted.reject_reason,
			"diagnostic." + task_id));
		toast_notification::push("The guide lookup could not be queued; see Task Center.",
			toast_notification::toast_type_t::error, 5.0f);
	}
#endif
}

inline bool activate_custom_bridge() {
	if (custom_bridge_pending())
		return false;
	const std::string host_bridge_text = trim(custom_bridge_buf());
	const std::string guest_bridge_text = trim(custom_guest_bridge_buf());
	const std::string executable_text = trim(exe_buf());
	const std::string arguments_text = trim(args_buf());
	const std::string guest_sample_text = trim(custom_guest_sample_buf());
	if (host_bridge_text.empty()) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Choose a host bridge folder first.";
		return false;
	}
	if (guest_bridge_text.empty()) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Enter the guest path for the shared bridge folder.";
		return false;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::record("activate_vm_bridge", guest_bridge_text);
	last_custom_bridge_dir() = widen_utf8(host_bridge_text.c_str());
	custom_bridge_status() = custom_bridge_status_t::succeeded;
	custom_bridge_status_text() = "Deterministic custom VM bridge preview activated.";
	toast_notification::push("Custom VM bridge preview activated.", toast_notification::toast_type_t::success, 5.0f);
	return true;
#else
	const std::uint64_t serial = custom_bridge_sequence().fetch_add(1,
		std::memory_order_relaxed);
	auto operation = std::make_shared<custom_bridge_operation_t>();
	operation->serial = serial;
	custom_bridge_operation() = operation;
	custom_bridge_status() = custom_bridge_status_t::queued;
	custom_bridge_status_text() = "Queued bridge staging and activation.";
	const std::string task_id = "debugger.custom_vm_bridge." + std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "debugger.spawn_target";
	registration.owner = "Run Target";
	registration.owner_view = "view.debug.cpu";
	registration.owner_action = "Activate custom VM bridge";
	registration.target = "Custom VM bridge";
	registration.label = "Stage and activate custom VM bridge";
	registration.stage = "Queued";
	registration.affected_entity = "Custom VM bridge";
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [operation] {
		unsigned expected_gate = 0;
		if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
				std::memory_order_acq_rel))
			return false;
		operation->cancel_requested.store(true, std::memory_order_release);
		return true;
	};
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Task Center rejected ownership of the bridge operation.";
		custom_bridge_operation().reset();
		return false;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.custom_vm_bridge.activate";
	submission.thread_class = "bounded_file_io";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 2;
	submission.generation = serial;
	submission.diagnostic_id = task_id.c_str();
	submission.ui_access_policy = "ui_dispatch_only";
	submission.failure_policy = "retain_review_and_report";
	submission.shutdown_policy = "drain";
	submission.cancel_hook = [operation] {
		unsigned expected_gate = 0;
		if (operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
				std::memory_order_acq_rel))
			operation->cancel_requested.store(true, std::memory_order_release);
	};
	submission.body = [operation, task_id, host_bridge_text, guest_bridge_text,
		executable_text, arguments_text, guest_sample_text]() {
		operation->phase.store(1, std::memory_order_release);
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.05f,
			"Validating reviewed bridge paths"));
		bool activated = false;
		bool cancelled = false;
		std::string error;
		std::wstring host_bridge = widen_utf8(host_bridge_text.c_str());
		std::wstring guest_sample = widen_utf8(guest_sample_text.c_str());
		const std::wstring arguments = widen_utf8(arguments_text.c_str());
		try {
			const auto cancellation_requested = [&] {
				cancelled = operation->cancel_requested.load(std::memory_order_acquire);
				if (cancelled && error.empty())
					error = "Bridge activation was cancelled before its irreversible phase.";
				return cancelled;
			};
			std::filesystem::path host_bridge_path(host_bridge);
			std::error_code filesystem_error;
			if (host_bridge.empty() || guest_bridge_text.empty())
				error = "The reviewed host or guest bridge path is invalid.";
			else if (cancellation_requested()) {
			} else {
				std::filesystem::create_directories(host_bridge_path / L"samples", filesystem_error);
				if (!filesystem_error)
					std::filesystem::create_directories(host_bridge_path / L"agent", filesystem_error);
				if (filesystem_error)
					error = "Could not create the bridge directories: " + filesystem_error.message();
			}
			operation->phase.store(2, std::memory_order_release);
			if (error.empty() && !cancellation_requested() && !executable_text.empty()) {
				const std::filesystem::path host_sample(widen_utf8(executable_text.c_str()));
				filesystem_error.clear();
				const auto size = std::filesystem::file_size(host_sample, filesystem_error);
				const auto modified = filesystem_error ? std::filesystem::file_time_type{} :
					std::filesystem::last_write_time(host_sample, filesystem_error);
				if (filesystem_error || size == 0 || size > 2ULL * 1024ULL * 1024ULL * 1024ULL)
					error = "The reviewed host sample is unavailable, empty, or exceeds 2 GiB.";
				else if (std::filesystem::is_directory(host_sample, filesystem_error) || filesystem_error)
					error = "The reviewed host sample is not a regular file.";
				else {
					const std::filesystem::path staged_sample =
						host_bridge_path / L"samples" / host_sample.filename();
					std::filesystem::copy_file(host_sample, staged_sample,
						std::filesystem::copy_options::overwrite_existing, filesystem_error);
					if (filesystem_error)
						error = "Could not stage the reviewed sample: " + filesystem_error.message();
					else {
						filesystem_error.clear();
						const auto source_size_after = std::filesystem::file_size(host_sample,
							filesystem_error);
						const auto source_modified_after = filesystem_error ?
							std::filesystem::file_time_type{} :
							std::filesystem::last_write_time(host_sample, filesystem_error);
						const auto staged_size = filesystem_error ? std::uintmax_t{0} :
							std::filesystem::file_size(staged_sample, filesystem_error);
						if (filesystem_error || source_size_after != size || staged_size != size ||
							source_modified_after != modified)
							error = "The reviewed host sample changed during staging or the copy was not exact.";
					}
					if (error.empty() && guest_sample.empty()) {
						const std::string filename = narrow_utf8(host_sample.filename().wstring().c_str());
						const std::string generated = join_guest_path(
							join_guest_path(guest_bridge_text, "samples"), filename);
						guest_sample = widen_utf8(generated.c_str());
					}
				}
			}
			operation->phase.store(3, std::memory_order_release);
			if (error.empty() && !cancellation_requested()) {
				const std::wstring agent_source = resolve_guest_agent_exe();
				if (agent_source.empty())
					error = "AiDAGuestAgent.exe is missing beside AiDAStandalone.exe.";
				else {
					filesystem_error.clear();
					const std::filesystem::path agent_source_path(agent_source);
					const auto agent_size = std::filesystem::file_size(agent_source_path, filesystem_error);
					const auto agent_modified = filesystem_error ? std::filesystem::file_time_type{} :
						std::filesystem::last_write_time(agent_source_path, filesystem_error);
					if (filesystem_error || agent_size == 0 || agent_size > 512ULL * 1024ULL * 1024ULL)
						error = "AiDAGuestAgent.exe is invalid or exceeds 512 MiB.";
					else {
						const std::filesystem::path staged_agent =
							host_bridge_path / L"agent" / L"AiDAGuestAgent.exe";
						std::filesystem::copy_file(agent_source_path, staged_agent,
							std::filesystem::copy_options::overwrite_existing, filesystem_error);
						if (filesystem_error)
							error = "Could not stage AiDAGuestAgent.exe: " + filesystem_error.message();
						else {
							filesystem_error.clear();
							const auto source_size_after = std::filesystem::file_size(agent_source_path,
								filesystem_error);
							const auto source_modified_after = filesystem_error ?
								std::filesystem::file_time_type{} :
								std::filesystem::last_write_time(agent_source_path, filesystem_error);
							const auto staged_size = filesystem_error ? std::uintmax_t{0} :
								std::filesystem::file_size(staged_agent, filesystem_error);
							if (filesystem_error || source_size_after != agent_size ||
								staged_size != agent_size || source_modified_after != agent_modified)
								error = "AiDAGuestAgent.exe changed during staging or the copy was not exact.";
						}
					}
				}
			}
			operation->phase.store(4, std::memory_order_release);
			if (error.empty() && !cancellation_requested()) {
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.65f,
					"Preparing bridge metadata and launch contract"));
				if (!vm_guest_bridge::prepare_bridge_directory(host_bridge, guest_sample,
						arguments, &error) && error.empty())
					error = "Bridge preparation failed.";
			}
			if (error.empty()) {
				unsigned expected_gate = 0;
				if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 2,
						std::memory_order_acq_rel)) {
					cancelled = expected_gate == 1;
					error = cancelled ? "Bridge activation was cancelled before its irreversible phase." :
						"Bridge activation could not acquire its irreversible-phase gate.";
				}
			}
			if (error.empty()) {
				operation->phase.store(5, std::memory_order_release);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.9f,
					"Activating reviewed custom VM bridge"));
				if (!vm_guest_bridge::activate_bridge(host_bridge, host_bridge, guest_sample,
						"custom_vm", &error) && error.empty())
					error = "Bridge activation failed.";
				else if (error.empty())
					activated = true;
			}
		} catch (const std::exception& exception) {
			error = exception.what();
		} catch (...) {
			error = "Unknown bridge activation failure.";
		}
		operation->phase.store(6, std::memory_order_release);
		const std::string guest_sample_result = narrow_utf8(guest_sample.c_str());
		auto publish = [operation, task_id, host_bridge, guest_sample_result,
			host_bridge_text, guest_bridge_text, arguments_text, activated, cancelled,
			error]() {
			if (!custom_bridge_operation() ||
				custom_bridge_operation()->serial != operation->serial)
				return;
			if (activated) {
				last_custom_bridge_dir() = host_bridge;
				if (!guest_sample_result.empty()) {
					std::snprintf(custom_guest_sample_buf(), 1024, "%s",
						guest_sample_result.c_str());
				}
				custom_bridge_status() = custom_bridge_status_t::succeeded;
				custom_bridge_status_text() = "Bridge activated. Start the displayed guest command inside the VM.";
				diag::log_tagged_critical_fmt("spawn",
					"custom_vm_bridge_activated host_bridge='%s' guest_bridge='%s' guest_sample='%s' args_len=%zu",
					host_bridge_text.c_str(), guest_bridge_text.c_str(),
					guest_sample_result.c_str(), arguments_text.size());
				toast_notification::push("Custom VM bridge activated. Start the guest command inside the VM.",
					toast_notification::toast_type_t::success, 5.0f);
			} else if (cancelled) {
				custom_bridge_status() = custom_bridge_status_t::cancelled;
				custom_bridge_status_text() = error.empty() ? "Bridge activation was cancelled." : error;
			} else {
				custom_bridge_status() = custom_bridge_status_t::failed;
				custom_bridge_status_text() = error.empty() ? "Bridge activation failed." : error;
				toast_notification::push(custom_bridge_status_text(),
					toast_notification::toast_type_t::error, 6.0f);
			}
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				activated ? aida::ui::task_center::task_state_t::completed :
					cancelled ? aida::ui::task_center::task_state_t::cancelled :
						aida::ui::task_center::task_state_t::failed,
				1.0f, activated ? "Bridge activated" : cancelled ? "Cancelled" : "Activation failed",
				activated ? "Custom VM bridge activation verified" : custom_bridge_status_text(),
				activated ? std::string() : "diagnostic." + task_id));
		};
		if (!aida::ui_thread::post(std::move(publish), "spawn_target_dialog",
				"publish_custom_vm_bridge", "worker_completion")) {
			custom_bridge_dispatch_failure().store(operation->serial,
				std::memory_order_release);
			if (activated)
				custom_bridge_dispatch_applied().store(operation->serial,
					std::memory_order_release);
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				activated ? aida::ui::task_center::task_state_t::partial :
					aida::ui::task_center::task_state_t::failed,
				1.0f, "UI publication rejected",
				activated ? "Bridge activation succeeded but UI publication was rejected" :
					"Bridge activation result could not be published",
				"diagnostic." + task_id));
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "The executor rejected bridge activation: " +
			submitted.reject_reason;
		custom_bridge_operation().reset();
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Executor rejected activation", submitted.reject_reason,
			"diagnostic." + task_id));
		return false;
	}
	return true;
#endif
}

inline void open_url(const wchar_t* url) {
	if (!url || !*url) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::debugger::record("open_url", narrow_utf8(url));
#else
	const int len = WideCharToMultiByte(CP_UTF8, 0, url, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1) return;
	std::string utf8(static_cast<size_t>(len), '\0');
	WideCharToMultiByte(CP_UTF8, 0, url, -1, utf8.data(), len, nullptr, nullptr);
	if (!utf8.empty() && utf8.back() == '\0') utf8.pop_back();
	const auto submitted = aida::auth::submit_open_url_external(std::move(utf8));
	if (!submitted.submitted) {
		toast_notification::push("Camoufox could not queue the requested page",
			toast_notification::toast_type_t::error, 5.0f);
	}
#endif
}

inline bool prepare_launch_result(bool host_mode) {
	std::string exe_trim = trim(exe_buf());
	if (exe_trim.empty()) return false;
	std::string args_trim = trim(args_buf());
	std::string cwd_trim = host_mode ? trim(cwd_buf()) : std::string();

	result_t& pending = pending_result();
	pending = result_t{};
	pending.exe_path     = widen_utf8(exe_trim.c_str());
	pending.args         = widen_utf8(args_trim.c_str());
	pending.working_dir  = widen_utf8(cwd_trim.c_str());

	run_target::launch_options_t& lo = pending.launch_options;
	lo.exe_path           = pending.exe_path;
	lo.args               = pending.args;
	lo.working_dir        = pending.working_dir;
	lo.isolation          = host_mode
		? run_target::isolation_t::same_desktop_jobbed
		: run_target::isolation_t::windows_sandbox;
	lo.block_network      = block_network_flag();
	lo.kill_on_host_exit  = kill_on_host_exit_flag();
	lo.attach_after_resume = host_mode;
	int mem = memory_cap_mb_value();
	lo.memory_cap_mb      = mem > 0 ? static_cast<uint32_t>(mem) : 0u;
	int term = auto_terminate_sec_value();
	lo.auto_terminate_sec = term > 0 ? static_cast<uint32_t>(term) : 0u;
	lo.malware_safe_mode = false;
	lo.log_network_traffic = false;
	lo.lower_integrity_untrusted = false;
	lo.allow_child_processes = true;
	lo.force_mitigations_strict = false;
	lo.redirect_user_paths_to_sandbox = false;
	lo.register_kernel_sandbox_guard = false;

	pending.accepted = true;
	pending_result_ready() = true;

	diag::log_tagged_critical_fmt("spawn",
		"spawn_dialog_launch exe='%s' args_len=%zu cwd='%s' iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u attach=%d host_mode=%d",
		exe_trim.c_str(), args_trim.size(),
		cwd_trim.empty() ? "<inherit>" : cwd_trim.c_str(),
		static_cast<int>(lo.isolation),
		lo.block_network ? 1 : 0,
		lo.kill_on_host_exit ? 1 : 0,
		static_cast<unsigned>(lo.memory_cap_mb),
		static_cast<unsigned>(lo.auto_terminate_sec),
		lo.attach_after_resume ? 1 : 0,
		host_mode ? 1 : 0);
	return true;
}

inline void browse_executable() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::snprintf(exe_buf(), 1024, "%s", "C:/Preview/Samples/sample.exe");
	std::snprintf(cwd_buf(), 1024, "%s", "C:/Preview/Samples");
	aida::preview::debugger::record("browse_executable", exe_buf());
#else
	diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable invoking show_open_file_dialog_w");
	wchar_t path_buf[1024] = {};
	std::string current = trim(exe_buf());
	if (!current.empty()) {
		std::wstring w = widen_utf8(current.c_str());
		size_t n = w.size();
		if (n >= 1023) n = 1023;
		if (n > 0) std::memcpy(path_buf, w.data(), n * sizeof(wchar_t));
		path_buf[n] = L'\0';
	}

	static const wchar_t k_spawn_exe_filter[] =
		L"Binary files (*.exe;*.dll;*.sys;*.com;*.scr;*.efi;*.cpl)\0*.exe;*.dll;*.sys;*.com;*.scr;*.efi;*.cpl\0"
		L"Executable files (*.exe;*.com;*.scr)\0*.exe;*.com;*.scr\0"
		L"Libraries (*.dll;*.cpl)\0*.dll;*.cpl\0"
		L"Drivers (*.sys;*.efi)\0*.sys;*.efi\0"
		L"All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_open_file_dialog_w(g_hwnd,
			L"Select target binary (.exe / .dll / .sys)",
			k_spawn_exe_filter,
			path_buf, 1024,
			"spawn_target::browse_executable")) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable cancelled_or_failed");
		return;
	}

	std::string sel = narrow_utf8(path_buf);
	if (sel.empty()) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_executable empty_path");
		return;
	}

	{
		DWORD attrs = ::GetFileAttributesW(path_buf);
		if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
			diag::log_tagged_critical_fmt("file_dialog",
				"spawn_target.browse_executable missing_or_dir path='%s' attrs=0x%08X",
				sel.c_str(), static_cast<unsigned int>(attrs));
			toast_notification::push(
				"Selected file does not exist on disk: " + sel,
				toast_notification::toast_type_t::error, 5.0f);
			return;
		}
	}

	std::strncpy(exe_buf(), sel.c_str(), 1023);
	exe_buf()[1023] = '\0';

	if (cwd_buf()[0] == '\0') {
		std::string parent = parent_dir(sel);
		if (!parent.empty()) {
			std::strncpy(cwd_buf(), parent.c_str(), 1023);
			cwd_buf()[1023] = '\0';
		}
	}

	diag::log_tagged_critical_fmt("file_dialog",
		"spawn_target.browse_executable ok path='%s'", sel.c_str());
	diag::log_tagged_critical_fmt("dialog",
		"spawn_browse_exe_selected path='%s'", sel.c_str());
#endif
}

inline void browse_working_dir() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::snprintf(cwd_buf(), 1024, "%s", "C:/Preview/Samples");
	aida::preview::debugger::record("browse_working_directory", cwd_buf());
#else
	diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir invoking show_open_folder_dialog_ex");
	std::string current = trim(cwd_buf());
	std::wstring initial = current.empty() ? std::wstring() : widen_utf8(current.c_str());
	std::string picked;
	if (!win32_dialog::show_open_folder_dialog_ex(g_hwnd,
			L"Select working directory",
			initial.empty() ? nullptr : initial.c_str(),
			picked,
			"spawn_target::browse_working_dir")) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir cancelled_or_failed");
		return;
	}
	if (picked.empty()) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_working_dir empty_path");
		return;
	}
	std::strncpy(cwd_buf(), picked.c_str(), 1023);
	cwd_buf()[1023] = '\0';
	diag::log_tagged_critical_fmt("file_dialog",
		"spawn_target.browse_working_dir ok path='%s'", picked.c_str());
	diag::log_tagged_critical_fmt("dialog",
		"spawn_browse_cwd_selected path='%s'", picked.c_str());
#endif
}

inline void browse_custom_bridge_dir() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	std::snprintf(custom_bridge_buf(), 1024, "%s", "C:/Preview/VMBridge");
	aida::preview::debugger::record("browse_vm_bridge", custom_bridge_buf());
#else
	diag::log_tagged_critical("file_dialog", "spawn_target.browse_custom_bridge invoking show_open_folder_dialog_ex");
	std::string current = trim(custom_bridge_buf());
	std::wstring initial = current.empty() ? std::wstring() : widen_utf8(current.c_str());
	std::string picked;
	if (!win32_dialog::show_open_folder_dialog_ex(g_hwnd,
			L"Select host-side custom VM bridge folder",
			initial.empty() ? nullptr : initial.c_str(),
			picked,
			"spawn_target::browse_custom_bridge")) {
		diag::log_tagged_critical("file_dialog", "spawn_target.browse_custom_bridge cancelled_or_failed");
		return;
	}
	if (picked.empty()) return;
	std::strncpy(custom_bridge_buf(), picked.c_str(), 1023);
	custom_bridge_buf()[1023] = '\0';
	diag::log_tagged_critical_fmt("dialog",
		"spawn_browse_custom_bridge_selected path='%s'", picked.c_str());
#endif
}

}

inline bool is_open() {
	return detail::open_flag() || detail::should_open();
}

inline void request_open() {
	detail::reset_inputs();
	detail::pending_result_ready() = false;
	detail::pending_result() = result_t{};
	detail::cached_capabilities() = run_target::probe_capabilities();
	detail::should_open() = true;
	diag::log_tagged_critical("spawn", "spawn_dialog_open_requested");
}

inline void request_open(const std::string& executable_path) {
	request_open();
	if (executable_path.empty())
		return;
	std::strncpy(detail::exe_buf(), executable_path.c_str(), 1023);
	detail::exe_buf()[1023] = '\0';
}

inline bool consume_result(result_t& out) {
	if (!detail::pending_result_ready()) return false;
	out = std::move(detail::pending_result());
	detail::pending_result() = result_t{};
	detail::pending_result_ready() = false;
	return true;
}

inline void render() {
	detail::poll_custom_bridge_dispatch_failure();
	static int s_last_render_frame = -1;
	int cur_frame = ImGui::GetFrameCount();
	if (s_last_render_frame == cur_frame) return;
	s_last_render_frame = cur_frame;

	if (detail::should_open()) {
		ImGui::OpenPopup("Malware Lab Run###aida_spawn_target_dialog");
		detail::should_open() = false;
		detail::open_flag() = true;
	}

	if (!detail::open_flag()) return;

	const auto& tk = aida::ui::resolved();
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.f, 18.f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10.f, 12.f));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(tk.bg_overlay));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));

	ImVec2 viewport_center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(viewport_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSizeConstraints(ImVec2(620.f, 0.f), ImVec2(620.f, FLT_MAX));
	ImGui::SetNextWindowSize(ImVec2(620.f, 0.f), ImGuiCond_Appearing);

	bool open_flag_local = true;
	const bool bridge_modal_pending = detail::custom_bridge_pending();
	bool launch_now = false;
	bool cancel_now = false;
	bool close_parent_after_host_confirm = false;

	if (ImGui::BeginPopupModal("Malware Lab Run###aida_spawn_target_dialog",
	                           bridge_modal_pending ? nullptr : &open_flag_local,
	                           ImGuiWindowFlags_NoSavedSettings |
	                           ImGuiWindowFlags_NoResize)) {

		ImFont* title_font = aida::ui::fonts::h1();
		ImFont* body_font  = aida::ui::fonts::body();
		ImFont* caption    = aida::ui::fonts::caption();

		if (title_font) ImGui::PushFont(title_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_primary),
		                   "Malware Lab Run");
		if (title_font) ImGui::PopFont();

		if (caption) ImGui::PushFont(caption);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Choose Windows Sandbox, Custom VM, or Host every time you launch a sample.");
		if (caption) ImGui::PopFont();
		ImGui::Dummy(ImVec2(0.f, 4.f));

		if (body_font) ImGui::PushFont(body_font);

		const bool top_custom_mode = detail::run_mode_choice() == 1;
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   top_custom_mode ? "Host sample path (optional, staged into the bridge)" : "Executable path");
		float browse_btn_w = 96.f;
		float input_w = ImGui::GetContentRegionAvail().x - browse_btn_w - 10.f;
		if (input_w < 200.f) input_w = 200.f;

		aida::ui::input_text("##spawn_exe_path", detail::exe_buf(), 1024,
		                     top_custom_mode ? "C:\\samples\\target.exe" : "C:\\path\\to\\target.exe", false,
		                     ImVec2(input_w, 36.f));
		ImGui::SameLine();
		if (aida::ui::button("Browse...", aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md,
		                     ImVec2(browse_btn_w, 36.f), false, nullptr, false)) {
			detail::browse_executable();
		}
		ImGui::Dummy(ImVec2(0.f, 2.f));

		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Arguments (optional)");
		aida::ui::input_text("##spawn_args", detail::args_buf(), 2048,
		                     "--example-arg value",
		                     false, ImVec2(0.f, 36.f));
		ImGui::Dummy(ImVec2(0.f, 2.f));

		if (body_font) ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 10.f));

		if (body_font) ImGui::PushFont(body_font);
		ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
		                   "Launch target");
		if (body_font) ImGui::PopFont();
		ImGui::Dummy(ImVec2(0.f, 2.f));

		{
			int& mode = detail::run_mode_choice();
			ImGui::RadioButton("Windows Sandbox", &mode, 0);
			ImGui::SameLine(0.f, 20.f);
			ImGui::RadioButton("Custom VM", &mode, 1);
			ImGui::SameLine(0.f, 20.f);
			ImGui::RadioButton("Host", &mode, 2);
			detail::isolation_choice() = mode == 0
				? static_cast<int>(run_target::isolation_t::windows_sandbox)
				: static_cast<int>(run_target::isolation_t::same_desktop_jobbed);
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		const bool sandbox_mode = detail::run_mode_choice() == 0;
		const bool custom_vm_mode = detail::run_mode_choice() == 1;
		if (sandbox_mode) {
			if (caption) ImGui::PushFont(caption);
			ImGui::TextWrapped("First-time setup for Run in VM");
			ImGui::BulletText("Windows edition: Pro, Enterprise, or Education. Windows Home users need a full VM such as VMware Workstation Pro or VirtualBox.");
			ImGui::BulletText("For QEMU, VirtualBox, or VMware, keep AiDAStandalone.exe on the host. Do not copy AiDAStandalone.exe into the guest VM.");
			ImGui::BulletText("Run only the target sample and your MCP client or guest agent in the guest VM. Route that client through an authenticated host bridge or tunnel that terminates at AiDA's localhost MCP endpoint.");
			ImGui::BulletText("Do not bind AiDA's MCP endpoint directly to a guest, LAN, or untrusted adapter. MCP tools can mutate host files, sessions, debugger state, and process memory.");
			ImGui::BulletText("For VMware, VirtualBox, QEMU, Hyper-V, or a manual Windows VM, use Custom VM mode to activate a shared-folder bridge through AiDAGuestAgent.");
			ImGui::BulletText("Download for full VM fallback: VMware Workstation Pro or Oracle VirtualBox, then a Windows evaluation ISO.");
			ImGui::BulletText("BIOS/UEFI: enable Intel VT-x or AMD-V/SVM, then boot back into Windows.");
			ImGui::BulletText("Admin PowerShell: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All");
			ImGui::BulletText("Reboot, reopen AiDA, press Run, select Run in VM, then Open VM.");
			ImGui::BulletText("The built-in Open VM flow opens the sample inside Windows Sandbox and stages only the sandbox guest bridge, not AiDAStandalone.exe.");
			const auto& caps = detail::cached_capabilities();
			if (!caps.has_windows_sandbox) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.warning),
				                   "Windows Sandbox is not available on this PC right now.");
			}
			if (caption) ImGui::PopFont();
			if (aida::ui::button("Sandbox Docs", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(118.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install");
			}
			ImGui::SameLine();
			if (aida::ui::button("WSB Config", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(104.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file");
			}
			ImGui::SameLine();
			if (aida::ui::button("Eval ISO", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(90.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise");
			}
			if (aida::ui::button("VMware", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(92.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://knowledge.broadcom.com/external/article/344595/downloading-vmware-workstation-pro.html");
			}
			ImGui::SameLine();
			if (aida::ui::button("VirtualBox", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm, ImVec2(108.f, 30.f), false, nullptr, false)) {
				detail::open_url(L"https://www.virtualbox.org/wiki/Downloads");
			}
		} else if (custom_vm_mode) {
			if (caption) ImGui::PushFont(caption);
			ImGui::TextWrapped("Custom VM bridge for VMware, VirtualBox, QEMU, Hyper-V, or a manually built Windows VM");
			ImGui::BulletText("Share one folder between host and guest. AiDA writes requests on the host; AiDAGuestAgent reads them inside the guest.");
			ImGui::BulletText("AiDAStandalone.exe remains on the host. The guest receives only the selected sample, launch_config.json, and AiDAGuestAgent.exe.");
			ImGui::BulletText("Keep the shared folder private to this VM. Do not expose AiDA's localhost MCP server to the VM network.");
			ImGui::BulletText("After activation, copy the guest command below and run it inside the VM.");
			if (caption) ImGui::PopFont();
			ImGui::Dummy(ImVec2(0.f, 2.f));

			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Host bridge folder");
			float custom_btn_w = 96.f;
			float custom_input_w = ImGui::GetContentRegionAvail().x - custom_btn_w - 10.f;
			if (custom_input_w < 200.f) custom_input_w = 200.f;
			aida::ui::input_text("##custom_bridge_host", detail::custom_bridge_buf(), 1024,
			                     "C:\\AiDA-VM-Bridge\\case-001", false,
			                     ImVec2(custom_input_w, 36.f));
			ImGui::SameLine();
			if (aida::ui::button("Browse##custom_bridge", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::md,
			                     ImVec2(custom_btn_w, 36.f), false, nullptr, false)) {
				detail::browse_custom_bridge_dir();
			}
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Guest path to the same shared folder");
			aida::ui::input_text("##custom_bridge_guest", detail::custom_guest_bridge_buf(), 1024,
			                     "Z:\\AiDA-VM-Bridge\\case-001", false,
			                     ImVec2(0.f, 36.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Guest sample path (optional; auto-filled when host sample is staged)");
			aida::ui::input_text("##custom_guest_sample", detail::custom_guest_sample_buf(), 1024,
			                     "Z:\\AiDA-VM-Bridge\\case-001\\samples\\sample.exe", false,
			                     ImVec2(0.f, 36.f));
			std::string command = detail::custom_guest_command();
			if (!command.empty()) {
				if (caption) ImGui::PushFont(caption);
				ImGui::TextWrapped("Guest command: %s", command.c_str());
				if (caption) ImGui::PopFont();
				if (aida::ui::button("Copy command", aida::ui::button_kind_t::secondary,
				                     aida::ui::size_t_::sm, ImVec2(120.f, 30.f), false, nullptr, false)) {
					ImGui::SetClipboardText(command.c_str());
					toast_notification::push("Guest command copied.", toast_notification::toast_type_t::success, 3.0f);
				}
				ImGui::SameLine();
				if (aida::ui::button("Guide", aida::ui::button_kind_t::secondary,
				                     aida::ui::size_t_::sm, ImVec2(80.f, 30.f), false, nullptr, false)) {
					detail::open_custom_vm_guide();
				}
			}
		} else {
			if (caption) ImGui::PushFont(caption);
			ImGui::TextWrapped("Host mode runs the selected binary on this Windows installation. It is not a malware or BYOVD containment boundary and can compromise the host.");
			if (caption) ImGui::PopFont();
			ImGui::Dummy(ImVec2(0.f, 2.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Working directory");
			float browse_btn_w2 = 96.f;
			float input_w2 = ImGui::GetContentRegionAvail().x - browse_btn_w2 - 10.f;
			if (input_w2 < 200.f) input_w2 = 200.f;
			aida::ui::input_text("##spawn_cwd", detail::cwd_buf(), 1024,
			                     "C:\\path\\to\\working-directory", false,
			                     ImVec2(input_w2, 36.f));
			ImGui::SameLine();
			if (aida::ui::button("Browse##cwd", aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::md,
			                     ImVec2(browse_btn_w2, 36.f), false, nullptr, false)) {
				detail::browse_working_dir();
			}
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			bool* bn = &detail::block_network_flag();
			aida::ui::toggle_switch("Block network access", bn, aida::ui::size_t_::sm);
			ImGui::SameLine(0.f, 18.f);
			bool* ke = &detail::kill_on_host_exit_flag();
			aida::ui::toggle_switch("Kill target on AiDA exit", ke, aida::ui::size_t_::sm);
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Memory limit (MB, 0 = no limit)");
			aida::ui::input_int("##spawn_memcap", &detail::memory_cap_mb_value(),
			                    ImVec2(input_w, 36.f));
			if (detail::memory_cap_mb_value() < 0) detail::memory_cap_mb_value() = 0;
		}

		ImGui::Dummy(ImVec2(0.f, 4.f));
		{
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Auto-terminate after (seconds, 0 = no limit)");
			aida::ui::input_int("##spawn_autoterm", &detail::auto_terminate_sec_value(),
			                    ImVec2(input_w, 36.f));
			if (detail::auto_terminate_sec_value() < 0) detail::auto_terminate_sec_value() = 0;
		}

		ImGui::Dummy(ImVec2(0.f, 10.f));

		if (!detail::last_sandbox_dir().empty()) {
			ImGui::Dummy(ImVec2(0.f, 4.f));
			std::string sb_utf8 = detail::narrow_utf8(detail::last_sandbox_dir().c_str());
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.text_secondary),
			                   "Last VM workspace: %s", sb_utf8.c_str());
			ImGui::SameLine();
			if (aida::ui::button("Open folder##spawn_open_sandbox",
			                     aida::ui::button_kind_t::secondary,
			                     aida::ui::size_t_::sm,
			                     ImVec2(110.f, 28.f), false, nullptr, false)) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				aida::preview::debugger::record("open_sandbox_folder", sb_utf8);
#else
				ShellExecuteW(g_hwnd, L"open", detail::last_sandbox_dir().c_str(),
				              nullptr, nullptr, SW_SHOWNORMAL);
#endif
			}
		}

		ImGui::Dummy(ImVec2(0.f, 6.f));

		{
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 pos = ImGui::GetCursorScreenPos();
			float w = ImGui::GetContentRegionAvail().x;
			float pad_x = 14.f;
			float pad_y = 10.f;
			ImFont* warn_font = aida::ui::fonts::body_em();
			if (!warn_font) warn_font = ImGui::GetFont();
			ImFont* base = ImGui::GetFont();
			float fs_title = aida::ui::fonts::size_or(warn_font, ImGui::GetFontSize());
			float fs_body = aida::ui::fonts::size_or(base, ImGui::GetFontSize());

			const bool host_mode = detail::run_mode_choice() == 2;
			const bool custom_mode = detail::run_mode_choice() == 1;
			const char* warn_title = host_mode ? "Host execution warning" : (custom_mode ? "Custom VM bridge" : "Interactive VM sandbox");
			const char* warn_body  = host_mode
				? "Run in Host starts the selected binary on this Windows installation and may attach AiDA's host driver. Do not use this for malware, cheat loaders, BYOVD samples, unknown drivers, or anything you do not fully trust."
				: (custom_mode
					? "Custom VM activates a shared-folder bridge for a guest-side AiDAGuestAgent. AiDA never exposes the host MCP listener to the VM; the guest only sees files in the bridge folder you choose."
					: "Run in VM copies the sample into a disposable Windows Sandbox workspace, disables clipboard and device redirection, optionally disables networking, and starts the sample in the sandbox window. AiDAStandalone.exe remains on the host; the sandbox receives only the staged sample and guest bridge.");

			ImVec2 ts_title = warn_font->CalcTextSizeA(fs_title, FLT_MAX, w - pad_x * 2.f, warn_title);
			ImVec2 ts_body = base->CalcTextSizeA(fs_body, FLT_MAX, w - pad_x * 2.f, warn_body);
			float box_h = pad_y * 2.f + ts_title.y + 6.f + ts_body.y;
			ImVec2 a = pos;
			ImVec2 b = ImVec2(pos.x + w, pos.y + box_h);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(tk.warning, 0.18f), 8.f);
			dl->AddRect(a, b, aida::ui::with_alpha(tk.warning, 0.65f), 8.f, 0, 1.25f);
			dl->AddText(warn_font, fs_title,
			            ImVec2(a.x + pad_x, a.y + pad_y),
			            tk.warning, warn_title);
			dl->AddText(base, fs_body,
			            ImVec2(a.x + pad_x, a.y + pad_y + ts_title.y + 6.f),
			            aida::ui::with_alpha(tk.text_primary, 0.92f),
			            warn_body, nullptr, w - pad_x * 2.f);
			ImGui::Dummy(ImVec2(w, box_h));
		}

		ImGui::Dummy(ImVec2(0.f, 6.f));

		std::string exe_trim = detail::trim(detail::exe_buf());
		std::string custom_bridge_trim = detail::trim(detail::custom_bridge_buf());
		std::string custom_guest_bridge_trim = detail::trim(detail::custom_guest_bridge_buf());
		const bool bridge_pending = detail::custom_bridge_pending();
		if (detail::run_mode_choice() == 1 &&
			detail::custom_bridge_status() != detail::custom_bridge_status_t::idle &&
			!detail::custom_bridge_status_text().empty()) {
			const ImVec4 status_color = detail::custom_bridge_status() == detail::custom_bridge_status_t::failed
				? ImGui::ColorConvertU32ToFloat4(tk.error)
				: detail::custom_bridge_status() == detail::custom_bridge_status_t::succeeded
					? ImGui::ColorConvertU32ToFloat4(tk.success)
					: detail::custom_bridge_status() == detail::custom_bridge_status_t::cancelled
						? ImGui::ColorConvertU32ToFloat4(tk.warning)
						: ImGui::ColorConvertU32ToFloat4(tk.info);
			ImGui::TextColored(status_color, "%s", detail::custom_bridge_status_text().c_str());
			if (bridge_pending)
				ImGui::TextDisabled("The reviewed configuration remains editable after this operation reaches a terminal state.");
			ImGui::Dummy(ImVec2(0.f, 4.f));
		}
		bool launch_disabled =
			(detail::run_mode_choice() == 0 && (exe_trim.empty() || !detail::cached_capabilities().has_windows_sandbox))
			|| (detail::run_mode_choice() == 1 && (custom_bridge_trim.empty() || custom_guest_bridge_trim.empty() || bridge_pending))
			|| (detail::run_mode_choice() == 2 && exe_trim.empty());

		float total_w = ImGui::GetContentRegionAvail().x;
		float btn_w = 130.f;
		float gap = 10.f;
		float row_w = btn_w * 2.f + gap;
		float row_x_offset = total_w - row_w;
		if (row_x_offset < 0.f) row_x_offset = 0.f;
		ImGui::Dummy(ImVec2(row_x_offset, 0.f));
		ImGui::SameLine();

		const char* cancel_label = bridge_pending ? "Cancel activation" : "Cancel";
		if (aida::ui::button(cancel_label, aida::ui::button_kind_t::secondary,
		                     aida::ui::size_t_::md,
		                     ImVec2(btn_w, 40.f), false, nullptr, false)) {
			if (bridge_pending)
				static_cast<void>(detail::request_custom_bridge_cancel());
			else
				cancel_now = true;
		}
		ImGui::SameLine(0.f, gap);
		const char* launch_label = detail::run_mode_choice() == 0 ? "Open VM" : (detail::run_mode_choice() == 1 ? "Activate" : "Run Host");
		if (aida::ui::button(launch_label, aida::ui::button_kind_t::primary,
		                     aida::ui::size_t_::md,
		                     ImVec2(btn_w, 40.f), launch_disabled, nullptr, false)) {
			launch_now = true;
		}
		if (launch_disabled && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
			const char* reason = bridge_pending ?
				"A custom VM bridge operation is already active; cancel it or wait for its terminal state." :
				detail::run_mode_choice() == 1 ?
					"Choose both the host bridge folder and guest shared-folder path." :
					detail::run_mode_choice() == 0 ?
						"Choose an executable and ensure Windows Sandbox is available." :
						"Choose an executable before reviewing a Host run.";
			ImGui::SetTooltip("%s", reason);
		}

		ImGuiIO& io = ImGui::GetIO();
		if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			if (bridge_pending)
				static_cast<void>(detail::request_custom_bridge_cancel());
			else
				cancel_now = true;
		}
		if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Enter, false) && !launch_disabled)
			launch_now = true;

		if (launch_now && !launch_disabled) {
			if (detail::run_mode_choice() == 2) {
				detail::host_confirm_open() = true;
				ImGui::OpenPopup("Confirm Host Run###aida_spawn_host_confirm");
			} else if (detail::run_mode_choice() == 1) {
				(void)detail::activate_custom_bridge();
			} else if (detail::prepare_launch_result(false)) {
				ImGui::CloseCurrentPopup();
				detail::open_flag() = false;
			}
		} else if ((cancel_now || !open_flag_local) && !bridge_pending) {
			detail::pending_result_ready() = false;
			detail::pending_result() = result_t{};
			diag::log_tagged_critical("spawn", "spawn_dialog_cancelled");
			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		}

		if (detail::host_confirm_open()) {
			ImGui::SetNextWindowSize(ImVec2(520.f, 0.f), ImGuiCond_Appearing);
			bool confirm_open = true;
			if (ImGui::BeginPopupModal("Confirm Host Run###aida_spawn_host_confirm",
			                           &confirm_open,
			                           ImGuiWindowFlags_NoSavedSettings |
			                           ImGuiWindowFlags_NoResize)) {
				if (title_font) ImGui::PushFont(title_font);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(tk.warning),
				                   "Run in Host?");
				if (title_font) ImGui::PopFont();
				if (caption) ImGui::PushFont(caption);
				ImGui::TextWrapped("This will execute the selected binary on your real desktop, not inside the VM.");
				ImGui::TextWrapped("Cancel unless the file is trusted. Host mode can expose your PC, credentials, kernel, files, and drivers to the sample.");
				if (caption) ImGui::PopFont();
				ImGui::Dummy(ImVec2(0.f, 8.f));
				float cw = ImGui::GetContentRegionAvail().x;
				float cbw = 150.f;
				float cgap = 10.f;
				float cx = cw - cbw * 2.f - cgap;
				if (cx < 0.f) cx = 0.f;
				ImGui::Dummy(ImVec2(cx, 0.f));
				ImGui::SameLine();
				if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
				                     aida::ui::size_t_::md,
				                     ImVec2(cbw, 40.f), false, nullptr, false)) {
					detail::host_confirm_open() = false;
					ImGui::CloseCurrentPopup();
				}
				ImGui::SameLine(0.f, cgap);
				if (aida::ui::button("Run in Host", aida::ui::button_kind_t::destructive,
				                     aida::ui::size_t_::md,
				                     ImVec2(cbw, 40.f), false, nullptr, false)) {
					if (detail::prepare_launch_result(true)) {
						detail::host_confirm_open() = false;
						ImGui::CloseCurrentPopup();
						close_parent_after_host_confirm = true;
					}
				}
				if (!confirm_open) {
					detail::host_confirm_open() = false;
				}
				ImGui::EndPopup();
			} else if (!confirm_open) {
				detail::host_confirm_open() = false;
			}
		}

		if (close_parent_after_host_confirm) {
			ImGui::CloseCurrentPopup();
			detail::open_flag() = false;
		}

		ImGui::EndPopup();
	} else {
		detail::open_flag() = false;
	}

	ImGui::PopStyleColor(4);
	ImGui::PopStyleVar(4);
}

}
