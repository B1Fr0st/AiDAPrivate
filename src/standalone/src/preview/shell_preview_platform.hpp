#pragma once

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

using BOOL = int;
using DWORD = std::uint32_t;
using ULONGLONG = unsigned long long;
using LONGLONG = long long;
using HWND = void*;
using UINT_PTR = std::uintptr_t;

inline constexpr BOOL TRUE = 1;
inline constexpr BOOL FALSE = 0;
inline constexpr DWORD ERROR_SUCCESS = 0;
inline constexpr std::size_t MAX_PATH = 260;
inline constexpr std::size_t _TRUNCATE = static_cast<std::size_t>(-1);

inline DWORD& preview_last_error_storage()
{
	static DWORD value = ERROR_SUCCESS;
	return value;
}

inline DWORD GetLastError()
{
	return preview_last_error_storage();
}

inline void SetLastError(DWORD value)
{
	preview_last_error_storage() = value;
}

inline int _snprintf_s(char* buffer, std::size_t size, std::size_t, const char* format, ...)
{
	if (!buffer || size == 0)
		return -1;
	va_list args;
	va_start(args, format);
	const int result = std::vsnprintf(buffer, size, format, args);
	va_end(args);
	buffer[size - 1] = '\0';
	return result;
}

inline int _vsnprintf_s(char* buffer, std::size_t size, std::size_t, const char* format, va_list args)
{
	if (!buffer || size == 0)
		return -1;
	const int result = std::vsnprintf(buffer, size, format, args);
	buffer[size - 1] = '\0';
	return result;
}

inline int strncpy_s(char* destination, std::size_t capacity, const char* source, std::size_t)
{
	if (!destination || capacity == 0)
		return 1;
	if (!source) {
		destination[0] = '\0';
		return 0;
	}
	const std::size_t count = (std::min)(std::strlen(source), capacity - 1);
	std::memcpy(destination, source, count);
	destination[count] = '\0';
	return 0;
}

template <std::size_t N>
inline int strncpy_s(char (&destination)[N], const char* source, std::size_t count)
{
	return strncpy_s(destination, N, source, count);
}

namespace diag
{
	inline void log_tagged(const char*, const char*) {}
	inline void log_tagged_critical(const char*, const char*) {}
	inline void log_tagged_fmt(const char*, const char*, ...) {}
	inline void log_tagged_critical_fmt(const char*, const char*, ...) {}
}

namespace anti_tamper
{
	namespace webhook
	{
		inline void write_log(const char*, const char*) {}
	}

	namespace state
	{
		struct state_t
		{
			std::atomic<bool> violation_latched{false};
			std::atomic<bool> license_pending_activation{false};
			std::atomic<bool> activation_hardening_done{true};
			std::atomic<bool> driver_hardening_active{false};
			std::atomic<bool> driver_hardening_done{true};
			std::atomic<bool> initialized{true};
			std::mutex mtx;
			std::string violation_reason;
			std::string violation_detail;
		};

		inline state_t& get()
		{
			static state_t value;
			return value;
		}
	}
}

namespace standalone_license
{
	inline bool is_valid() { return true; }
	inline bool is_arc_loaded() { return true; }
	inline bool is_arc_download_in_progress() { return false; }
	inline bool is_arc_transfer_in_progress() { return false; }
	inline std::string last_error() { return "Preview fixture"; }
}

namespace session_health
{
	inline bool is_alive(std::uint32_t) { return true; }
}

namespace analysis_session
{
	inline bool has_active_target() { return true; }
}

namespace aida::preview::platform
{
	using save_dialog_observer_t = void (*)(const char*);
	inline save_dialog_observer_t save_dialog_observer = nullptr;
}

namespace win32_dialog
{
	inline bool show_save_file_dialog(HWND, const char* title, const char*,
		const char* default_extension, char* output_path,
		std::size_t capacity, const char* context)
	{
		if (!output_path || capacity == 0)
			return false;
		const std::string_view context_view = context ? context : "";
		if (context_view.rfind("debugger_view::", 0) == 0 ||
			context_view.rfind("memory_map_view::", 0) == 0) {
			if (aida::preview::platform::save_dialog_observer)
				aida::preview::platform::save_dialog_observer(title ? title : "Save");
			return false;
		}
		std::string path = output_path;
		if (path.empty()) {
			path = "/aida-preview/exports/network";
			if (default_extension && default_extension[0] != '\0') {
				path.push_back('.');
				path += default_extension;
			}
		}
		std::snprintf(output_path, capacity, "%s", path.c_str());
		return true;
	}
}

namespace workspace_search
{
	struct match_result_t
	{
		std::string filepath;
		std::string filename;
		int line_number = 0;
		int col_start = 0;
		int col_end = 0;
		std::string line_text;
	};

	struct search_state_t
	{
		char query_buf[512] = "VirtualProtect";
		char include_buf[256] = "*.cpp;*.hpp;*.asm";
		char exclude_buf[256] = "build;third_party";
		bool case_sensitive = false;
		bool whole_word = false;
		bool use_regex = false;
		std::vector<match_result_t> results = {
			{ "C:/Preview/ReverseEngineering/src/unpacker.cpp", "unpacker.cpp", 184, 8, 22, "if (!VirtualProtect(region, size, PAGE_EXECUTE_READWRITE, &old_protect))" },
			{ "C:/Preview/ReverseEngineering/src/anti_debug.cpp", "anti_debug.cpp", 71, 14, 28, "resolve_api(\"VirtualProtect\");" },
			{ "C:/Preview/ReverseEngineering/asm/entry.asm", "entry.asm", 43, 9, 23, "call qword ptr [VirtualProtect]" }
		};
		int selected_idx = -1;
		std::atomic<bool> searching{false};
		std::atomic<bool> cancel{false};
		std::atomic<bool> launch_pending{false};
		std::atomic<int> files_scanned{42};
		std::atomic<int> match_count{3};
		bool panel_open = false;
	};

	inline search_state_t g_search;

	inline void start_search(const std::string&)
	{
		g_search.searching.store(false, std::memory_order_release);
		g_search.files_scanned.store(42, std::memory_order_release);
		g_search.match_count.store(static_cast<int>(g_search.results.size()), std::memory_order_release);
	}
}
