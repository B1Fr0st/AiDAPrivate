#pragma once

#ifdef __NT__

#include <windows.h>

#include <intrin.h>

#include <cstdint>
#include <mutex>

#include "driver_loader.hpp"
#include "../driver/comm.h"
#include "license.hpp"

namespace anti_re {
namespace detail {

static constexpr std::uint32_t DEBUG_NT_GLOBAL_MASK = 0x70u;
static constexpr ULONGLONG VERIFY_INTERVAL_MS = 1500u;

struct runtime_state_t
{
	std::mutex mutex;
	bool initialized = false;
	bool trusted = false;
	HMODULE module = nullptr;
	HMODULE process_image = nullptr;
	DWORD pid = 0;
	ULONGLONG last_verified_ms = 0;
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
