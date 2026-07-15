#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "../infra/executor.hpp"

using DWORD = std::uint32_t;

inline std::uint64_t GetTickCount64()
{
	using clock_t = std::chrono::steady_clock;
	return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		clock_t::now().time_since_epoch()).count());
}

inline void* SecureZeroMemory(void* pointer, std::size_t size)
{
	volatile unsigned char* cursor = static_cast<volatile unsigned char*>(pointer);
	while (size-- != 0) *cursor++ = 0;
	return pointer;
}

namespace diag {

template <typename... Args>
inline void log_tagged_fmt(const char*, const char*, Args&&...)
{
}

}

namespace aida::infra::win_thread {

inline DWORD run_function_seh_guarded(const std::function<void()>& body)
{
	if (body) body();
	return 0;
}

}

#endif
