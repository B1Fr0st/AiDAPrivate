#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <userenv.h>
#include <objbase.h>
#include <objidl.h>
#include <oleauto.h>
#include <comdef.h>
#include <netfw.h>
#include <shlwapi.h>
#include <processthreadsapi.h>
#include <jobapi2.h>
#include <jobapi.h>

#include "run_target.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <locale>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace run_target {

namespace {

struct co_init_scope_t {
	bool need_uninit = false;
	bool ok = false;
	co_init_scope_t() {
		HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		if (hr == RPC_E_CHANGED_MODE) {
			ok = true;
			need_uninit = false;
		} else if (SUCCEEDED(hr)) {
			ok = true;
			need_uninit = true;
		} else if (hr == S_FALSE) {
			ok = true;
			need_uninit = true;
		} else {
			ok = false;
			need_uninit = false;
		}
	}
	~co_init_scope_t() {
		if (need_uninit) CoUninitialize();
	}
	co_init_scope_t(const co_init_scope_t&) = delete;
	co_init_scope_t& operator=(const co_init_scope_t&) = delete;
};

std::string narrow_utf8(const std::wstring& w) {
	if (w.empty()) return {};
	int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (needed <= 1) return {};
	std::string out(static_cast<size_t>(needed - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), needed, nullptr, nullptr);
	return out;
}

std::wstring widen_utf8(const std::string& s) {
	if (s.empty()) return {};
	int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	if (needed <= 1) return {};
	std::wstring out(static_cast<size_t>(needed - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), needed);
	return out;
}

std::string format_win_message(DWORD err) {
	LPSTR buf = nullptr;
	DWORD n = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&buf), 0, nullptr);
	std::string out;
	if (n > 0 && buf) {
		while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == '.' || buf[n - 1] == ' ')) {
			buf[--n] = '\0';
		}
		out.assign(buf, buf + n);
	} else {
		char tmp[64];
		std::snprintf(tmp, sizeof(tmp), "Unknown error 0x%08lX", static_cast<unsigned long>(err));
		out = tmp;
	}
	if (buf) LocalFree(buf);
	return out;
}

void log_fail(const char* step, DWORD gle, const std::string& extra = {}) {
	std::string m = format_win_message(gle);
	if (!extra.empty()) {
		diag::log_tagged_critical_fmt("run_target",
			"launch_FAILED step=%s gle=%lu msg='%s' %s",
			step ? step : "?",
			static_cast<unsigned long>(gle),
			m.c_str(),
			extra.c_str());
	} else {
		diag::log_tagged_critical_fmt("run_target",
			"launch_FAILED step=%s gle=%lu msg='%s'",
			step ? step : "?",
			static_cast<unsigned long>(gle),
			m.c_str());
	}
}

std::string format_error(const char* step, DWORD gle) {
	char buf[512];
	std::string m = format_win_message(gle);
	std::snprintf(buf, sizeof(buf), "%s failed (gle=%lu): %s",
		step ? step : "step", static_cast<unsigned long>(gle), m.c_str());
	return std::string(buf);
}

uint32_t get_windows_build_number() {
	HMODULE h = GetModuleHandleW(L"ntdll.dll");
	if (!h) return 0;
	using rtl_get_version_fn = LONG (NTAPI*)(PRTL_OSVERSIONINFOW);
	rtl_get_version_fn fn = reinterpret_cast<rtl_get_version_fn>(
		reinterpret_cast<void*>(GetProcAddress(h, "RtlGetVersion")));
	if (!fn) return 0;
	RTL_OSVERSIONINFOEXW info{};
	info.dwOSVersionInfoSize = sizeof(info);
	if (fn(reinterpret_cast<PRTL_OSVERSIONINFOW>(&info)) != 0) return 0;
	return static_cast<uint32_t>(info.dwBuildNumber);
}

bool file_exists_w(const std::wstring& path) {
	DWORD a = GetFileAttributesW(path.c_str());
	return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring resolve_windows_sandbox_exe() {
	wchar_t sysroot[MAX_PATH] = {};
	UINT n = GetSystemDirectoryW(sysroot, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return {};
	std::wstring p = std::wstring(sysroot) + L"\\WindowsSandbox.exe";
	if (!file_exists_w(p)) return {};
	return p;
}

std::string make_unique_rule_name() {
	GUID g{};
	if (CoCreateGuid(&g) != S_OK) {
		auto tick = static_cast<uint64_t>(GetTickCount64());
		char buf[64];
		std::snprintf(buf, sizeof(buf), "AiDA-Run-%llu-%lu",
			static_cast<unsigned long long>(tick),
			static_cast<unsigned long>(GetCurrentProcessId()));
		return std::string(buf);
	}
	char buf[80];
	std::snprintf(buf, sizeof(buf),
		"AiDA-Run-%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		static_cast<unsigned long>(g.Data1), g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
	return std::string(buf);
}

bool firewall_add_block_rule(const std::wstring& exe_path,
                              const std::string& rule_name_utf8,
                              std::string* fail_reason) {
	co_init_scope_t coscope;
	if (!coscope.ok) {
		if (fail_reason) *fail_reason = "CoInitializeEx failed";
		return false;
	}

	INetFwPolicy2* policy = nullptr;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
		reinterpret_cast<void**>(&policy));
	if (FAILED(hr) || !policy) {
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "CoCreate NetFwPolicy2 hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	INetFwRules* rules = nullptr;
	hr = policy->get_Rules(&rules);
	if (FAILED(hr) || !rules) {
		policy->Release();
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "get_Rules hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	INetFwRule* rule = nullptr;
	hr = CoCreateInstance(__uuidof(NetFwRule), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
		reinterpret_cast<void**>(&rule));
	if (FAILED(hr) || !rule) {
		rules->Release();
		policy->Release();
		if (fail_reason) {
			char b[96];
			std::snprintf(b, sizeof(b), "CoCreate NetFwRule hr=0x%08lX",
				static_cast<unsigned long>(hr));
			*fail_reason = b;
		}
		return false;
	}

	auto sysalloc_w = [](const wchar_t* s) -> BSTR {
		return SysAllocString(s ? s : L"");
	};

	std::wstring rule_name_w = widen_utf8(rule_name_utf8);
	std::wstring desc_w = L"AiDA Run Target outbound block (auto-cleaned).";

	BSTR b_name = sysalloc_w(rule_name_w.c_str());
	BSTR b_desc = sysalloc_w(desc_w.c_str());
	BSTR b_path = sysalloc_w(exe_path.c_str());
	BSTR b_grouping = sysalloc_w(L"AiDA Run Target");

	bool ok = true;
	HRESULT lasthr = S_OK;
	auto check = [&](HRESULT h, const char* label) {
		if (FAILED(h)) {
			ok = false;
			lasthr = h;
			if (fail_reason && fail_reason->empty()) {
				char buf[96];
				std::snprintf(buf, sizeof(buf), "%s hr=0x%08lX",
					label, static_cast<unsigned long>(h));
				*fail_reason = buf;
			}
		}
	};

	check(rule->put_Name(b_name), "put_Name");
	check(rule->put_Description(b_desc), "put_Description");
	check(rule->put_ApplicationName(b_path), "put_ApplicationName");
	check(rule->put_Action(NET_FW_ACTION_BLOCK), "put_Action");
	check(rule->put_Direction(NET_FW_RULE_DIR_OUT), "put_Direction");
	check(rule->put_Enabled(VARIANT_TRUE), "put_Enabled");
	check(rule->put_Profiles(NET_FW_PROFILE2_ALL), "put_Profiles");
	check(rule->put_Grouping(b_grouping), "put_Grouping");

	if (ok) {
		hr = rules->Add(rule);
		if (FAILED(hr)) {
			ok = false;
			lasthr = hr;
			if (fail_reason) {
				char buf[96];
				std::snprintf(buf, sizeof(buf), "rules->Add hr=0x%08lX",
					static_cast<unsigned long>(hr));
				*fail_reason = buf;
			}
		}
	}

	SysFreeString(b_name);
	SysFreeString(b_desc);
	SysFreeString(b_path);
	SysFreeString(b_grouping);
	rule->Release();
	rules->Release();
	policy->Release();

	if (!ok) {
		(void)lasthr;
	}
	return ok;
}

bool firewall_remove_rule(const std::string& rule_name_utf8) {
	if (rule_name_utf8.empty()) return true;
	co_init_scope_t coscope;
	if (!coscope.ok) return false;

	INetFwPolicy2* policy = nullptr;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
		CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
		reinterpret_cast<void**>(&policy));
	if (FAILED(hr) || !policy) return false;

	INetFwRules* rules = nullptr;
	hr = policy->get_Rules(&rules);
	if (FAILED(hr) || !rules) {
		policy->Release();
		return false;
	}

	std::wstring name_w = widen_utf8(rule_name_utf8);
	BSTR b = SysAllocString(name_w.c_str());
	HRESULT del_hr = rules->Remove(b);
	SysFreeString(b);

	rules->Release();
	policy->Release();
	return SUCCEEDED(del_hr);
}

void spawn_watchdog_kill(HANDLE process_handle, HANDLE job_handle, uint32_t sec, uint32_t pid) {
	if (sec == 0) return;
	if (process_handle == nullptr) return;

	HANDLE dup_proc = nullptr;
	HANDLE dup_job = nullptr;
	HANDLE me = GetCurrentProcess();
	if (!DuplicateHandle(me, process_handle, me, &dup_proc, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		return;
	}
	if (job_handle != nullptr) {
		if (!DuplicateHandle(me, job_handle, me, &dup_job, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			dup_job = nullptr;
		}
	}

	const uint32_t timeout_ms = sec * 1000u;
	uint32_t local_pid = pid;
	std::thread([dup_proc, dup_job, timeout_ms, local_pid]() mutable {
		DWORD w = WaitForSingleObject(dup_proc, timeout_ms);
		if (w == WAIT_TIMEOUT) {
			diag::log_tagged_critical_fmt("run_target",
				"watchdog auto_terminate pid=%u after_ms=%lu",
				static_cast<unsigned>(local_pid),
				static_cast<unsigned long>(timeout_ms));
			if (dup_job) {
				TerminateJobObject(dup_job, 0xDEAD);
			} else {
				TerminateProcess(dup_proc, 0xDEAD);
			}
		}
		if (dup_job) CloseHandle(dup_job);
		CloseHandle(dup_proc);
	}).detach();
}

bool launch_jobbed(const launch_options_t& opts, launch_result_t& out, bool inherit_appcontainer);

bool launch_same_desktop(const launch_options_t& opts, launch_result_t& out) {
	return launch_jobbed(opts, out, false);
}

bool launch_appcontainer(const launch_options_t& opts, launch_result_t& out) {
	uint32_t build = get_windows_build_number();
	if (build < 15063) {
		out.error = "AppContainer requires Windows 10 build 15063 or newer.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_appcontainer_unsupported windows_build=%u", build);
		return false;
	}

	wchar_t name_buf[64];
	uint64_t tick = GetTickCount64();
	uint32_t self_pid = GetCurrentProcessId();
	int wn = std::swprintf(name_buf, 64, L"AiDA.RunTarget.%llu.%lu",
		static_cast<unsigned long long>(tick),
		static_cast<unsigned long>(self_pid));
	if (wn <= 0) {
		out.error = "Internal: failed to format AppContainer profile name";
		return false;
	}
	std::wstring profile_name(name_buf);
	std::wstring display_name = L"AiDA Run Target";
	std::wstring description = L"Ephemeral AppContainer profile created by AiDAStandalone.";

	PSID app_sid = nullptr;
	HRESULT hr = ::CreateAppContainerProfile(
		profile_name.c_str(), display_name.c_str(), description.c_str(),
		nullptr, 0, &app_sid);
	bool profile_existed = false;
	if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		profile_existed = true;
		hr = ::DeriveAppContainerSidFromAppContainerName(profile_name.c_str(), &app_sid);
	}
	if (FAILED(hr) || app_sid == nullptr) {
		out.error = format_error("CreateAppContainerProfile", static_cast<DWORD>(hr));
		diag::log_tagged_critical_fmt("run_target",
			"launch_appcontainer CreateAppContainerProfile_FAILED hr=0x%08lX existed=%d",
			static_cast<unsigned long>(hr), profile_existed ? 1 : 0);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer profile_ready name='%ls' existed=%d",
		profile_name.c_str(), profile_existed ? 1 : 0);

	SECURITY_CAPABILITIES sec_caps{};
	sec_caps.AppContainerSid = app_sid;
	sec_caps.Capabilities = nullptr;
	sec_caps.CapabilityCount = 0;
	sec_caps.Reserved = 0;

	SIZE_T attr_size = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
	if (attr_size == 0) {
		out.error = "InitializeProcThreadAttributeList sizing failed";
		::FreeSid(app_sid);
		return false;
	}
	std::vector<uint8_t> attr_buf(attr_size, 0);
	LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
		reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
	if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
		DWORD gle = GetLastError();
		out.error = format_error("InitializeProcThreadAttributeList", gle);
		log_fail("InitializeProcThreadAttributeList", gle);
		::FreeSid(app_sid);
		return false;
	}
	if (!UpdateProcThreadAttribute(attr_list, 0,
		PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
		&sec_caps, sizeof(sec_caps),
		nullptr, nullptr)) {
		DWORD gle = GetLastError();
		out.error = format_error("UpdateProcThreadAttribute SECURITY_CAPABILITIES", gle);
		log_fail("UpdateProcThreadAttribute", gle);
		DeleteProcThreadAttributeList(attr_list);
		::FreeSid(app_sid);
		return false;
	}

	STARTUPINFOEXW siex{};
	siex.StartupInfo.cb = sizeof(siex);
	siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	siex.StartupInfo.wShowWindow = SW_SHOWNORMAL;
	siex.lpAttributeList = attr_list;

	std::wstring cmd;
	cmd.reserve(opts.exe_path.size() + opts.args.size() + 4);
	cmd.push_back(L'"');
	cmd.append(opts.exe_path);
	cmd.push_back(L'"');
	if (!opts.args.empty()) {
		cmd.push_back(L' ');
		cmd.append(opts.args);
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	const wchar_t* cwd_ptr = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();
	DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE;
	PROCESS_INFORMATION pi{};

	BOOL cp_ok = CreateProcessW(
		nullptr,
		cmd_buf.data(),
		nullptr, nullptr, FALSE,
		flags,
		nullptr,
		cwd_ptr,
		&siex.StartupInfo,
		&pi);
	if (!cp_ok) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateProcessW (AppContainer)", gle);
		log_fail("CreateProcessW.AppContainer", gle);
		DeleteProcThreadAttributeList(attr_list);
		::FreeSid(app_sid);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer CreateProcessW ok pid=%lu tid=%lu",
		pi.dwProcessId, pi.dwThreadId);

	DeleteProcThreadAttributeList(attr_list);
	::FreeSid(app_sid);

	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateJobObjectW (AppContainer)", gle);
		log_fail("CreateJobObjectW.AppContainer", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
	DWORD lim_flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	if (opts.kill_on_host_exit) lim_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (opts.memory_cap_mb > 0) {
		lim_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = static_cast<SIZE_T>(opts.memory_cap_mb) * 1024ull * 1024ull;
	}
	jeli.BasicLimitInformation.LimitFlags = lim_flags;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
		DWORD gle = GetLastError();
		log_fail("SetInformationJobObject.AppContainer", gle);
		out.error = format_error("SetInformationJobObject (AppContainer)", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(job);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer SetInformationJobObject ok flags=0x%lX mem_mb=%u",
		static_cast<unsigned long>(lim_flags), opts.memory_cap_mb);

	if (!AssignProcessToJobObject(job, pi.hProcess)) {
		DWORD gle = GetLastError();
		log_fail("AssignProcessToJobObject.AppContainer", gle);
		out.error = format_error("AssignProcessToJobObject (AppContainer)", gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(job);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_appcontainer AssignProcessToJobObject ok pid=%lu",
		pi.dwProcessId);

	if (opts.block_network) {
		std::string rule = make_unique_rule_name();
		std::string fr;
		bool fok = firewall_add_block_rule(opts.exe_path, rule, &fr);
		if (fok) {
			out.firewall_rule_name = rule;
			diag::log_tagged_critical_fmt("run_target",
				"launch_appcontainer firewall_block ok rule_name='%s'", rule.c_str());
		} else {
			diag::log_tagged_critical_fmt("run_target",
				"launch_appcontainer firewall_block FAILED rule_name='%s' reason='%s'",
				rule.c_str(), fr.c_str());
		}
	}

	out.ok = true;
	out.pid = pi.dwProcessId;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = reinterpret_cast<uintptr_t>(pi.hThread);
	out.job_handle = reinterpret_cast<uintptr_t>(job);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, job, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

bool launch_jobbed(const launch_options_t& opts, launch_result_t& out, bool /*inherit_appcontainer*/) {
	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateJobObjectW", gle);
		log_fail("CreateJobObjectW", gle);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed CreateJobObjectW handle=%p", static_cast<void*>(job));

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
	DWORD lim_flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	if (opts.kill_on_host_exit) lim_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (opts.memory_cap_mb > 0) {
		lim_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = static_cast<SIZE_T>(opts.memory_cap_mb) * 1024ull * 1024ull;
	}
	jeli.BasicLimitInformation.LimitFlags = lim_flags;

	BOOL set_ok = SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
	if (!set_ok) {
		DWORD gle = GetLastError();
		log_fail("SetInformationJobObject", gle);
		out.error = format_error("SetInformationJobObject", gle);
		CloseHandle(job);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed SetInformationJobObject ok=1 flags=0x%lX mem_mb=%u",
		static_cast<unsigned long>(lim_flags), opts.memory_cap_mb);

	std::wstring cmd;
	cmd.reserve(opts.exe_path.size() + opts.args.size() + 4);
	cmd.push_back(L'"');
	cmd.append(opts.exe_path);
	cmd.push_back(L'"');
	if (!opts.args.empty()) {
		cmd.push_back(L' ');
		cmd.append(opts.args);
	}
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	STARTUPINFOW si{};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;

	PROCESS_INFORMATION pi{};
	const wchar_t* cwd_ptr = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();
	DWORD flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE;

	BOOL cp_ok = CreateProcessW(
		nullptr,
		cmd_buf.data(),
		nullptr, nullptr, FALSE,
		flags,
		nullptr,
		cwd_ptr,
		&si,
		&pi);
	DWORD cp_gle = cp_ok ? 0 : GetLastError();
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed CreateProcessW ok=%d pid=%lu tid=%lu gle=%lu",
		cp_ok ? 1 : 0,
		cp_ok ? pi.dwProcessId : 0u,
		cp_ok ? pi.dwThreadId : 0u,
		static_cast<unsigned long>(cp_gle));
	if (!cp_ok) {
		out.error = format_error("CreateProcessW", cp_gle);
		log_fail("CreateProcessW", cp_gle);
		CloseHandle(job);
		return false;
	}

	BOOL assign_ok = AssignProcessToJobObject(job, pi.hProcess);
	DWORD assign_gle = assign_ok ? 0 : GetLastError();
	diag::log_tagged_critical_fmt("run_target",
		"launch_jobbed AssignProcessToJobObject ok=%d gle=%lu",
		assign_ok ? 1 : 0,
		static_cast<unsigned long>(assign_gle));
	if (!assign_ok) {
		log_fail("AssignProcessToJobObject", assign_gle);
		out.error = format_error("AssignProcessToJobObject", assign_gle);
		TerminateProcess(pi.hProcess, 0xDEAD);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(job);
		return false;
	}

	if (opts.block_network) {
		std::string rule = make_unique_rule_name();
		std::string fr;
		bool fok = firewall_add_block_rule(opts.exe_path, rule, &fr);
		diag::log_tagged_critical_fmt("run_target",
			"launch_jobbed firewall_block ok=%d rule_name='%s'%s%s",
			fok ? 1 : 0, rule.c_str(),
			fok ? "" : " reason=",
			fok ? "" : fr.c_str());
		if (fok) {
			out.firewall_rule_name = rule;
		}
	}

	out.ok = true;
	out.pid = pi.dwProcessId;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = reinterpret_cast<uintptr_t>(pi.hThread);
	out.job_handle = reinterpret_cast<uintptr_t>(job);

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, job, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

std::wstring xml_escape_w(const std::wstring& text) {
	std::wstring out;
	out.reserve(text.size() + 16);
	for (wchar_t c : text) {
		switch (c) {
			case L'&':  out += L"&amp;";  break;
			case L'<':  out += L"&lt;";   break;
			case L'>':  out += L"&gt;";   break;
			case L'"':  out += L"&quot;"; break;
			case L'\'': out += L"&apos;"; break;
			default:    out.push_back(c); break;
		}
	}
	return out;
}

std::wstring ps_quote_w(const std::wstring& text) {
	std::wstring out;
	out.push_back(L'\'');
	for (wchar_t c : text) {
		if (c == L'\'') out += L"''";
		else            out.push_back(c);
	}
	out.push_back(L'\'');
	return out;
}

bool launch_windows_sandbox(const launch_options_t& opts, launch_result_t& out) {
	std::wstring sandbox_exe = resolve_windows_sandbox_exe();
	if (sandbox_exe.empty()) {
		out.error = "Windows Sandbox is unavailable. Enable the Windows Sandbox feature first.";
		diag::log_tagged_critical("run_target",
			"launch_windows_sandbox unavailable_no_exe");
		return false;
	}

	if (opts.exe_path.empty()) {
		out.error = "Empty executable path.";
		return false;
	}

	std::filesystem::path exe_path(opts.exe_path);
	std::error_code ec;
	if (!std::filesystem::exists(exe_path, ec)) {
		out.error = "Target executable does not exist.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox exe_missing path='%s'",
			narrow_utf8(opts.exe_path).c_str());
		return false;
	}

	wchar_t temp_path[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, temp_path);
	uint64_t tick = static_cast<uint64_t>(GetTickCount64());
	std::filesystem::path session_dir = std::filesystem::path(temp_path)
		/ L"AiDAStandalone" / L"RunTarget"
		/ std::to_wstring(GetCurrentProcessId())
		/ std::to_wstring(tick);
	std::filesystem::create_directories(session_dir, ec);
	if (ec) {
		out.error = "Failed to create session directory.";
		diag::log_tagged_critical_fmt("run_target",
			"launch_windows_sandbox create_session_dir_FAILED ec=%d msg='%s'",
			ec.value(), ec.message().c_str());
		return false;
	}

	std::filesystem::path host_input = session_dir / L"input";
	std::filesystem::create_directories(host_input, ec);

	std::filesystem::path host_script = session_dir / L"run.ps1";
	std::filesystem::path host_wsb = session_dir / L"session.wsb";

	std::filesystem::path source_dir =
		(!opts.working_dir.empty() && std::filesystem::exists(opts.working_dir, ec))
		? std::filesystem::path(opts.working_dir)
		: exe_path.parent_path();

	if (std::filesystem::exists(source_dir, ec)) {
		for (auto it = std::filesystem::recursive_directory_iterator(source_dir, ec);
		     it != std::filesystem::recursive_directory_iterator(); ++it) {
			if (ec) break;
			auto rel = std::filesystem::relative(it->path(), source_dir, ec);
			if (ec) { ec.clear(); continue; }
			auto dst = host_input / rel;
			if (it->is_directory(ec)) {
				std::filesystem::create_directories(dst, ec);
				ec.clear();
				continue;
			}
			if (!it->is_regular_file(ec)) { ec.clear(); continue; }
			std::filesystem::create_directories(dst.parent_path(), ec);
			ec.clear();
			std::filesystem::copy_file(it->path(), dst,
				std::filesystem::copy_options::overwrite_existing, ec);
			ec.clear();
		}
	}

	std::filesystem::path target_in_input = host_input / exe_path.filename();
	if (!std::filesystem::exists(target_in_input, ec)) {
		std::filesystem::copy_file(exe_path, target_in_input,
			std::filesystem::copy_options::overwrite_existing, ec);
	}
	ec.clear();

	std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
	std::wstring guest_input = guest_root + L"\\input";
	std::wstring guest_exe = guest_input + L"\\" + exe_path.filename().wstring();

	{
		std::wofstream ofs(host_script.wstring(), std::ios::trunc);
		if (!ofs.is_open()) {
			out.error = "Failed to write run.ps1 in session directory.";
			return false;
		}
		ofs.imbue(std::locale::classic());
		ofs << L"$ErrorActionPreference = 'SilentlyContinue'\n";
		ofs << L"$exePath = " << ps_quote_w(guest_exe) << L"\n";
		ofs << L"$argLine = " << ps_quote_w(opts.args) << L"\n";
		ofs << L"$workDir = Split-Path -Path $exePath -Parent\n";
		ofs << L"if ([string]::IsNullOrWhiteSpace($argLine)) {\n";
		ofs << L"  $proc = Start-Process -FilePath $exePath -WorkingDirectory $workDir -PassThru -WindowStyle Normal\n";
		ofs << L"} else {\n";
		ofs << L"  $proc = Start-Process -FilePath $exePath -ArgumentList $argLine -WorkingDirectory $workDir -PassThru -WindowStyle Normal\n";
		ofs << L"}\n";
		ofs << L"if ($proc -ne $null) { $proc.WaitForExit() }\n";
	}

	uint64_t script_bytes = 0;
	{
		std::error_code sec_ec;
		auto sz = std::filesystem::file_size(host_script, sec_ec);
		if (!sec_ec) script_bytes = static_cast<uint64_t>(sz);
	}

	{
		std::wofstream ofs(host_wsb.wstring(), std::ios::trunc);
		if (!ofs.is_open()) {
			out.error = "Failed to write session.wsb in session directory.";
			return false;
		}
		ofs.imbue(std::locale::classic());
		std::wstring host_root_esc = xml_escape_w(session_dir.wstring());
		std::wstring guest_root_esc = xml_escape_w(guest_root);
		std::wstring host_input_esc = xml_escape_w(host_input.wstring());
		std::wstring guest_input_esc = xml_escape_w(guest_input);

		ofs << L"<Configuration>\n";
		ofs << L"  <Networking>" << (opts.block_network ? L"Disable" : L"Default") << L"</Networking>\n";
		ofs << L"  <ClipboardRedirection>Disable</ClipboardRedirection>\n";
		ofs << L"  <PrinterRedirection>Disable</PrinterRedirection>\n";
		ofs << L"  <AudioInput>Disable</AudioInput>\n";
		ofs << L"  <VideoInput>Disable</VideoInput>\n";
		ofs << L"  <vGPU>Disable</vGPU>\n";
		if (opts.memory_cap_mb > 0)
			ofs << L"  <MemoryInMB>" << opts.memory_cap_mb << L"</MemoryInMB>\n";
		ofs << L"  <MappedFolders>\n";
		ofs << L"    <MappedFolder>\n";
		ofs << L"      <HostFolder>" << host_input_esc << L"</HostFolder>\n";
		ofs << L"      <SandboxFolder>" << guest_input_esc << L"</SandboxFolder>\n";
		ofs << L"      <ReadOnly>true</ReadOnly>\n";
		ofs << L"    </MappedFolder>\n";
		ofs << L"    <MappedFolder>\n";
		ofs << L"      <HostFolder>" << host_root_esc << L"</HostFolder>\n";
		ofs << L"      <SandboxFolder>" << guest_root_esc << L"</SandboxFolder>\n";
		ofs << L"      <ReadOnly>false</ReadOnly>\n";
		ofs << L"    </MappedFolder>\n";
		ofs << L"  </MappedFolders>\n";
		ofs << L"  <LogonCommand>\n";
		ofs << L"    <Command>powershell.exe -ExecutionPolicy Bypass -File "
		    << guest_root_esc << L"\\run.ps1</Command>\n";
		ofs << L"  </LogonCommand>\n";
		ofs << L"</Configuration>\n";
	}

	diag::log_tagged_critical_fmt("run_target",
		"launch_windows_sandbox wsb_written session_dir='%s' script_bytes=%llu interactive_window=1",
		narrow_utf8(session_dir.wstring()).c_str(),
		static_cast<unsigned long long>(script_bytes));

	std::wstring cmd = L"\"" + sandbox_exe + L"\" \"" + host_wsb.wstring() + L"\"";
	std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
	cmd_buf.push_back(L'\0');

	STARTUPINFOW si{};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi{};

	BOOL cp_ok = CreateProcessW(nullptr, cmd_buf.data(),
		nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE,
		nullptr, session_dir.c_str(), &si, &pi);
	if (!cp_ok) {
		DWORD gle = GetLastError();
		out.error = format_error("CreateProcessW (WindowsSandbox.exe)", gle);
		log_fail("CreateProcessW.WindowsSandbox", gle);
		return false;
	}
	diag::log_tagged_critical_fmt("run_target",
		"launch_windows_sandbox WindowsSandbox.exe_started host_pid=%lu",
		pi.dwProcessId);

	CloseHandle(pi.hThread);

	out.ok = true;
	out.pid = 0;
	out.process_handle = reinterpret_cast<uintptr_t>(pi.hProcess);
	out.thread_handle = 0;
	out.job_handle = 0;

	if (opts.auto_terminate_sec > 0) {
		spawn_watchdog_kill(pi.hProcess, nullptr, opts.auto_terminate_sec, pi.dwProcessId);
	}
	return true;
}

}

capability_probe_t probe_capabilities() {
	capability_probe_t p{};
	p.windows_build = get_windows_build_number();
	p.has_jobobject = true;
	p.has_appcontainer = (p.windows_build >= 15063);
	p.has_firewall_inet = (p.windows_build >= 7600);
	p.has_windows_sandbox = !resolve_windows_sandbox_exe().empty();
	diag::log_tagged_critical_fmt("run_target",
		"probe_capabilities win_build=%u job=%d ac=%d fw=%d wsb=%d",
		p.windows_build,
		p.has_jobobject ? 1 : 0,
		p.has_appcontainer ? 1 : 0,
		p.has_firewall_inet ? 1 : 0,
		p.has_windows_sandbox ? 1 : 0);
	return p;
}

bool launch(const launch_options_t& opts, launch_result_t& out) {
	out = launch_result_t{};
	if (opts.exe_path.empty()) {
		out.error = "Empty executable path.";
		diag::log_tagged_critical("run_target", "launch_REJECTED empty_exe_path");
		return false;
	}

	std::string exe_utf8 = narrow_utf8(opts.exe_path);
	std::string cwd_utf8 = narrow_utf8(opts.working_dir);
	diag::log_tagged_critical_fmt("run_target",
		"launch entry exe='%s' args_len=%zu iso=%d block_net=%d kill_on_exit=%d mem_cap=%u auto_term=%u cwd='%s'",
		exe_utf8.c_str(),
		opts.args.size(),
		static_cast<int>(opts.isolation),
		opts.block_network ? 1 : 0,
		opts.kill_on_host_exit ? 1 : 0,
		static_cast<unsigned>(opts.memory_cap_mb),
		static_cast<unsigned>(opts.auto_terminate_sec),
		cwd_utf8.empty() ? "<inherit>" : cwd_utf8.c_str());

	if (opts.isolation == isolation_t::same_desktop_jobbed
	    || opts.isolation == isolation_t::appcontainer) {
		DWORD attrs = GetFileAttributesW(opts.exe_path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			DWORD gle = GetLastError();
			out.error = "Target executable does not exist.";
			diag::log_tagged_critical_fmt("run_target",
				"launch exe_missing path='%s' gle=%lu",
				exe_utf8.c_str(), static_cast<unsigned long>(gle));
			return false;
		}
		if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
			out.error = "Path is a directory, not an executable.";
			return false;
		}
	}

	bool ok = false;
	switch (opts.isolation) {
		case isolation_t::same_desktop_jobbed:
			ok = launch_same_desktop(opts, out);
			break;
		case isolation_t::appcontainer:
			ok = launch_appcontainer(opts, out);
			break;
		case isolation_t::windows_sandbox:
			ok = launch_windows_sandbox(opts, out);
			break;
		default:
			out.error = "Unknown isolation mode.";
			return false;
	}

	if (ok) {
		diag::log_tagged_critical_fmt("run_target",
			"launch ok iso=%d pid=%u job=%p firewall_rule='%s'",
			static_cast<int>(opts.isolation),
			out.pid,
			reinterpret_cast<void*>(out.job_handle),
			out.firewall_rule_name.c_str());
	} else {
		diag::log_tagged_critical_fmt("run_target",
			"launch FAILED iso=%d error='%s'",
			static_cast<int>(opts.isolation),
			out.error.c_str());
	}
	return ok;
}

bool cleanup(launch_result_t& result) {
	bool fw_removed = false;
	bool job_closed = false;
	bool proc_closed = false;
	bool thr_closed = false;

	if (!result.firewall_rule_name.empty()) {
		fw_removed = firewall_remove_rule(result.firewall_rule_name);
		result.firewall_rule_name.clear();
	}
	if (result.job_handle != 0) {
		CloseHandle(reinterpret_cast<HANDLE>(result.job_handle));
		result.job_handle = 0;
		job_closed = true;
	}
	if (result.thread_handle != 0) {
		CloseHandle(reinterpret_cast<HANDLE>(result.thread_handle));
		result.thread_handle = 0;
		thr_closed = true;
	}
	if (result.process_handle != 0) {
		CloseHandle(reinterpret_cast<HANDLE>(result.process_handle));
		result.process_handle = 0;
		proc_closed = true;
	}
	diag::log_tagged_critical_fmt("run_target",
		"cleanup ok=1 job_closed=%d proc_closed=%d thr_closed=%d firewall_removed=%d",
		job_closed ? 1 : 0,
		proc_closed ? 1 : 0,
		thr_closed ? 1 : 0,
		fw_removed ? 1 : 0);
	return true;
}

}
