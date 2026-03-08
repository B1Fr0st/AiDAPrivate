#pragma once

#ifdef __NT__

#include <windows.h>

#include <intrin.h>

#include <cstdint>
#include <mutex>
#include <vector>

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

}

#define ANTI_RE_GUARD() do { \
	(void)anti_re::guard(); \
} while (0)

#else

#define ANTI_RE_GUARD() ((void)0)
namespace anti_re {
inline bool initialize() { return true; }
inline bool guard() { return true; }
}

#endif
