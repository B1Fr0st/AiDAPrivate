#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "../../helpers/diag_log.hpp"

namespace pdb_parser {

struct pdb_symbol_t {
	std::string name;
	uint64_t    rva = 0;
	uint32_t    type_index = 0;
	uint32_t    size = 0;
	bool        is_function = false;
};

struct struct_member_t {
	std::string name;
	std::string type_name;
	uint64_t    offset = 0;
	uint64_t    size = 0;
	uint32_t    type_index = 0;
	int         bit_offset = -1;
	int         bit_size = -1;
	bool        is_pointer = false;
	int         pointer_depth = 0;
	bool        is_array = false;
	int         array_count = 0;
};

struct struct_def_t {
	std::string name;
	uint64_t    size = 0;
	uint32_t    type_index = 0;
	bool        is_union = false;
	std::vector<struct_member_t> members;
};

struct enum_member_t {
	std::string name;
	int64_t     value = 0;
};

struct enum_def_t {
	std::string name;
	uint32_t    type_index = 0;
	std::vector<enum_member_t> members;
};

struct pdb_info_t {
	std::string                        file_path;
	std::string                        module_name;
	std::vector<pdb_symbol_t>          symbols;
	std::vector<struct_def_t>          structs;
	std::vector<enum_def_t>            enums;
	std::unordered_map<std::string, size_t> symbol_by_name;
	std::unordered_map<uint64_t, size_t>    symbol_by_rva;
	std::unordered_map<std::string, size_t> struct_by_name;
	std::unordered_map<uint32_t, size_t>    struct_by_ti;
	bool loaded = false;
};

typedef BOOL (WINAPI *fn_SymInitializeW)(HANDLE, PCWSTR, BOOL);
typedef BOOL (WINAPI *fn_SymCleanup)(HANDLE);
typedef DWORD64 (WINAPI *fn_SymLoadModuleExW)(HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, void*, DWORD);
typedef BOOL (WINAPI *fn_SymUnloadModule64)(HANDLE, DWORD64);
typedef BOOL (WINAPI *fn_SymSetSearchPathW)(HANDLE, PCWSTR);
typedef DWORD (WINAPI *fn_SymSetOptions)(DWORD);
typedef DWORD (WINAPI *fn_SymGetOptions)();

#pragma pack(push, 8)
struct SYMBOL_INFOW_EX {
	ULONG   SizeOfStruct;
	ULONG   TypeIndex;
	ULONG64 Reserved[2];
	ULONG   Index;
	ULONG   Size;
	ULONG64 ModBase;
	ULONG   Flags;
	ULONG64 Value;
	ULONG64 Address;
	ULONG   Register;
	ULONG   Scope;
	ULONG   Tag;
	ULONG   NameLen;
	ULONG   MaxNameLen;
	WCHAR   Name[1];
};

struct TI_FINDCHILDREN_PARAMS_EX {
	ULONG Count;
	ULONG Start;
	ULONG ChildId[1];
};
#pragma pack(pop)

enum IMAGEHLP_SYMBOL_TYPE_INFO_E {
	TI_GET_SYMTAG = 0,
	TI_GET_SYMNAME = 1,
	TI_GET_LENGTH = 2,
	TI_GET_TYPE = 3,
	TI_FINDCHILDREN = 4,
	TI_GET_DATAKIND = 5,
	TI_GET_ADDRESSOFFSET = 6,
	TI_GET_OFFSET = 7,
	TI_GET_VALUE = 8,
	TI_GET_COUNT = 9,
	TI_GET_CHILDRENCOUNT = 10,
	TI_GET_BITPOSITION = 11,
	TI_GET_VIRTUALBASECLASS = 12,
	TI_GET_TYPEID = 13,
	TI_GET_BASETYPE = 14,
	TI_GET_ARRAYINDEXTYPEID = 15,
	TI_FINDCHILDREN_EX = 16,
	TI_GET_NESTED = 18,
	TI_GET_SYMINDEX = 19,
	TI_GET_LEXICALPARENT = 20,
	TI_GET_CLASSPARENTID = 21,
	TI_GET_UDTKIND = 24,
};

enum SymTagEnum_E {
	SymTagNull = 0,
	SymTagExe = 1,
	SymTagCompiland = 2,
	SymTagFunction = 5,
	SymTagData = 7,
	SymTagUDT = 11,
	SymTagEnum = 12,
	SymTagFunctionType = 13,
	SymTagPointerType = 14,
	SymTagArrayType = 15,
	SymTagBaseType = 16,
	SymTagTypedef = 17,
	SymTagBaseClass = 18,
};

enum BasicType_E {
	btNoType = 0,
	btVoid = 1,
	btChar = 2,
	btWChar = 3,
	btInt = 6,
	btUInt = 7,
	btFloat = 8,
	btBool = 10,
	btLong = 13,
	btULong = 14,
	btHresult = 31,
};

typedef BOOL (WINAPI *fn_SymEnumSymbolsExW)(HANDLE, ULONG64, PCWSTR,
    BOOL (CALLBACK*)(SYMBOL_INFOW_EX*, ULONG, void*), void*, DWORD);
typedef BOOL (WINAPI *fn_SymGetTypeInfo)(HANDLE, DWORD64, ULONG,
    IMAGEHLP_SYMBOL_TYPE_INFO_E, void*);
typedef BOOL (WINAPI *fn_SymEnumTypesW)(HANDLE, ULONG64,
    BOOL (CALLBACK*)(SYMBOL_INFOW_EX*, ULONG, void*), void*);

struct dbghelp_api_t {
	HMODULE                 hmod = nullptr;
	fn_SymInitializeW       pSymInitializeW = nullptr;
	fn_SymCleanup           pSymCleanup = nullptr;
	fn_SymLoadModuleExW     pSymLoadModuleExW = nullptr;
	fn_SymUnloadModule64    pSymUnloadModule64 = nullptr;
	fn_SymSetSearchPathW    pSymSetSearchPathW = nullptr;
	fn_SymSetOptions        pSymSetOptions = nullptr;
	fn_SymGetOptions        pSymGetOptions = nullptr;
	fn_SymEnumSymbolsExW    pSymEnumSymbolsExW = nullptr;
	fn_SymGetTypeInfo       pSymGetTypeInfo = nullptr;
	fn_SymEnumTypesW        pSymEnumTypesW = nullptr;

	bool loaded = false;
};

inline dbghelp_api_t g_api;
inline std::mutex g_api_mutex;
inline std::mutex g_dbghelp_call_mutex;
inline std::condition_variable g_dbghelp_load_cv;
inline std::mutex g_last_error_mutex;
inline std::string g_last_error;
inline std::atomic<uint64_t> g_parse_generation{1};

inline constexpr uint64_t k_dbghelp_load_watchdog_ms = 30000;

struct dbghelp_load_state_t {
	bool in_progress = false;
	bool stuck = false;
	bool terminal = false;
	bool last_success = false;
	DWORD caller_pid = 0;
	DWORD caller_tid = 0;
	DWORD worker_pid = 0;
	DWORD worker_tid = 0;
	DWORD thread_id = 0;
	uint64_t started_ms = 0;
	uint64_t completed_ms = 0;
	uint64_t attempt = 0;
	DWORD last_gle = ERROR_SUCCESS;
	HMODULE last_hmod = nullptr;
	std::string phase;
	std::string path;
	std::string loaded_path;
	std::string terminal_detail;
};

inline dbghelp_load_state_t g_dbghelp_load_state;

struct dbghelp_load_watchdog_context_t {
	DWORD thread_id = 0;
	uint64_t started_ms = 0;
	uint64_t attempt = 0;
	std::string path;
};

inline void set_last_error_text(const std::string& text)
{
	std::lock_guard<std::mutex> lk(g_last_error_mutex);
	g_last_error = text;
}

inline std::string last_error()
{
	std::lock_guard<std::mutex> lk(g_last_error_mutex);
	return g_last_error;
}

inline std::string dbghelp_load_state_text_locked(uint64_t now_ms)
{
	const uint64_t elapsed_ms = g_dbghelp_load_state.started_ms ? now_ms - g_dbghelp_load_state.started_ms : 0;
	char buf[1536];
	std::snprintf(buf, sizeof(buf),
		"dbghelp loaded=%d in_progress=%d stuck=%d terminal=%d success=%d attempt=%llu caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu elapsed_ms=%llu completed_ms=%llu phase='%s' path='%s' loaded_path='%s' gle=%lu hmod=%p detail='%s'",
		g_api.loaded ? 1 : 0,
		g_dbghelp_load_state.in_progress ? 1 : 0,
		g_dbghelp_load_state.stuck ? 1 : 0,
		g_dbghelp_load_state.terminal ? 1 : 0,
		g_dbghelp_load_state.last_success ? 1 : 0,
		static_cast<unsigned long long>(g_dbghelp_load_state.attempt),
		g_dbghelp_load_state.caller_pid,
		g_dbghelp_load_state.caller_tid,
		g_dbghelp_load_state.worker_pid,
		g_dbghelp_load_state.worker_tid,
		static_cast<unsigned long long>(elapsed_ms),
		static_cast<unsigned long long>(g_dbghelp_load_state.completed_ms),
		g_dbghelp_load_state.phase.c_str(),
		g_dbghelp_load_state.path.c_str(),
		g_dbghelp_load_state.loaded_path.c_str(),
		g_dbghelp_load_state.last_gle,
		g_dbghelp_load_state.last_hmod,
		g_dbghelp_load_state.terminal_detail.c_str());
	return buf;
}

inline std::string dbghelp_load_diagnostic()
{
	std::lock_guard<std::mutex> lk(g_api_mutex);
	return dbghelp_load_state_text_locked(GetTickCount64());
}

inline std::string dbghelp_wide_to_utf8(const std::wstring& value)
{
	if (value.empty()) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1) return {};
	std::string out(static_cast<size_t>(len - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), len, nullptr, nullptr);
	return out;
}

inline size_t dbghelp_first_nul_pos(const std::wstring& value)
{
	return value.find(L'\0');
}

inline long long dbghelp_first_nul_log_index(const std::wstring& value)
{
	const size_t pos = dbghelp_first_nul_pos(value);
	return pos == std::wstring::npos ? -1LL : static_cast<long long>(pos);
}

inline std::wstring dbghelp_visible_path(std::wstring path)
{
	const size_t pos = dbghelp_first_nul_pos(path);
	if (pos != std::wstring::npos)
		path.resize(pos);
	return path;
}

inline std::wstring resolve_dbghelp_path()
{
	wchar_t sys_dir[MAX_PATH] = {};
	UINT len = GetSystemDirectoryW(sys_dir, MAX_PATH);
	if (len == 0 || len >= MAX_PATH)
		return L"C:\\Windows\\System32\\dbghelp.dll";
	std::wstring path(sys_dir, sys_dir + len);
	if (!path.empty() && path.back() != L'\\')
		path.push_back(L'\\');
	path += L"dbghelp.dll";
	return path;
}

inline bool get_dbghelp_module_path(HMODULE module, std::wstring& out, DWORD& gle)
{
	out.clear();
	for (DWORD capacity = MAX_PATH;;) {
		std::wstring path(capacity, L'\0');
		SetLastError(ERROR_SUCCESS);
		DWORD len = GetModuleFileNameW(module, &path[0], capacity);
		gle = GetLastError();
		if (len == 0)
			return false;
		if (len < capacity) {
			path.resize(len);
			out = path;
			return true;
		}
		if (capacity == 32768)
			break;
		DWORD next_capacity = capacity * 2;
		if (next_capacity < capacity || next_capacity > 32768)
			next_capacity = 32768;
		capacity = next_capacity;
	}
	gle = ERROR_INSUFFICIENT_BUFFER;
	return false;
}

inline bool dbghelp_is_path_slash(wchar_t ch)
{
	return ch == L'\\' || ch == L'/';
}

inline std::wstring dbghelp_strip_extended_path_prefix(const std::wstring& path)
{
	const std::wstring visible_path = dbghelp_visible_path(path);
	if (visible_path.rfind(L"\\\\?\\UNC\\", 0) == 0)
		return L"\\\\" + visible_path.substr(8);
	if (visible_path.rfind(L"\\\\?\\", 0) == 0)
		return visible_path.substr(4);
	if (visible_path.rfind(L"\\??\\", 0) == 0)
		return visible_path.substr(4);
	return visible_path;
}

inline std::wstring dbghelp_normalize_path_for_compare(std::wstring path)
{
	path = dbghelp_strip_extended_path_prefix(path);
	for (wchar_t& ch : path) {
		if (ch == L'/')
			ch = L'\\';
	}
	return path;
}

inline std::wstring dbghelp_trim_trailing_slashes(std::wstring path)
{
	path = dbghelp_normalize_path_for_compare(path);
	while (path.size() > 3 && dbghelp_is_path_slash(path.back()))
		path.pop_back();
	return path;
}

inline bool dbghelp_path_equal(const std::wstring& lhs, const std::wstring& rhs)
{
	const std::wstring lhs_visible = dbghelp_visible_path(lhs);
	const std::wstring rhs_visible = dbghelp_visible_path(rhs);
	if (lhs_visible.empty() || rhs_visible.empty())
		return lhs_visible.empty() && rhs_visible.empty();
	return CompareStringOrdinal(lhs_visible.c_str(), static_cast<int>(lhs_visible.size()),
		rhs_visible.c_str(), static_cast<int>(rhs_visible.size()), TRUE) == CSTR_EQUAL;
}

inline std::wstring dbghelp_parent_path(const std::wstring& path)
{
	std::wstring normalized = dbghelp_trim_trailing_slashes(path);
	const size_t pos = normalized.find_last_of(L'\\');
	if (pos == std::wstring::npos)
		return {};
	return normalized.substr(0, pos);
}

inline std::wstring dbghelp_file_name(const std::wstring& path)
{
	std::wstring normalized = dbghelp_trim_trailing_slashes(path);
	const size_t pos = normalized.find_last_of(L'\\');
	if (pos == std::wstring::npos)
		return normalized;
	return normalized.substr(pos + 1);
}

inline std::wstring dbghelp_append_dbghelp_dll(std::wstring directory)
{
	if (directory.empty())
		return L"dbghelp.dll";
	if (!dbghelp_is_path_slash(directory.back()))
		directory.push_back(L'\\');
	directory += L"dbghelp.dll";
	return directory;
}

struct dbghelp_file_id_t {
	DWORD volume_serial = 0;
	DWORD file_index_high = 0;
	DWORD file_index_low = 0;
};

inline bool dbghelp_same_file_id(const dbghelp_file_id_t& lhs, const dbghelp_file_id_t& rhs)
{
	return lhs.volume_serial == rhs.volume_serial &&
	       lhs.file_index_high == rhs.file_index_high &&
	       lhs.file_index_low == rhs.file_index_low;
}

struct dbghelp_canonical_path_t {
	std::wstring full_path;
	std::wstring final_path;
	std::wstring canonical_path;
	dbghelp_file_id_t file_id{};
	bool full_ok = false;
	bool open_ok = false;
	bool info_ok = false;
	bool final_ok = false;
	DWORD full_gle = ERROR_SUCCESS;
	DWORD open_gle = ERROR_SUCCESS;
	DWORD info_gle = ERROR_SUCCESS;
	DWORD final_gle = ERROR_SUCCESS;
};

inline dbghelp_canonical_path_t dbghelp_canonicalize_path(const std::wstring& path)
{
	dbghelp_canonical_path_t result{};
	const std::wstring visible_path = dbghelp_visible_path(path);
	if (!visible_path.empty()) {
		SetLastError(ERROR_SUCCESS);
		DWORD needed = GetFullPathNameW(visible_path.c_str(), 0, nullptr, nullptr);
		result.full_gle = GetLastError();
		if (needed > 0) {
			std::wstring buffer(static_cast<size_t>(needed) + 1, L'\0');
			SetLastError(ERROR_SUCCESS);
			DWORD len = GetFullPathNameW(visible_path.c_str(), static_cast<DWORD>(buffer.size()), &buffer[0], nullptr);
			result.full_gle = GetLastError();
			if (len > 0 && len < static_cast<DWORD>(buffer.size())) {
				buffer.resize(len);
				result.full_path = dbghelp_normalize_path_for_compare(buffer);
				result.full_ok = true;
			}
		}

		SetLastError(ERROR_SUCCESS);
		HANDLE file = CreateFileW(visible_path.c_str(), FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
		result.open_gle = GetLastError();
		if (file != INVALID_HANDLE_VALUE) {
			result.open_ok = true;
			BY_HANDLE_FILE_INFORMATION info{};
			SetLastError(ERROR_SUCCESS);
			if (GetFileInformationByHandle(file, &info)) {
				result.info_ok = true;
				result.file_id.volume_serial = info.dwVolumeSerialNumber;
				result.file_id.file_index_high = info.nFileIndexHigh;
				result.file_id.file_index_low = info.nFileIndexLow;
			}
			result.info_gle = GetLastError();

			std::wstring final_buffer(32768, L'\0');
			SetLastError(ERROR_SUCCESS);
			DWORD final_len = GetFinalPathNameByHandleW(file, &final_buffer[0], static_cast<DWORD>(final_buffer.size()),
				FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
			result.final_gle = GetLastError();
			if (final_len > 0 && final_len < static_cast<DWORD>(final_buffer.size())) {
				final_buffer.resize(final_len);
				result.final_path = dbghelp_normalize_path_for_compare(final_buffer);
				result.final_ok = true;
			}
			CloseHandle(file);
		}
	}
	if (result.final_ok)
		result.canonical_path = result.final_path;
	else if (result.full_ok)
		result.canonical_path = result.full_path;
	else
		result.canonical_path = dbghelp_normalize_path_for_compare(visible_path);
	return result;
}

struct dbghelp_path_verification_t {
	bool accepted = false;
	bool recovered_directory = false;
	bool file_id_available = false;
	bool file_id_match = false;
	bool canonical_match = false;
	bool actual_in_system32 = false;
	bool expected_is_system32_dbghelp = false;
	bool actual_is_dbghelp = false;
	bool actual_visible_ended_with_slash = false;
	size_t actual_wchars = 0;
	size_t actual_visible_wchars = 0;
	long long actual_first_nul = -1;
	unsigned int actual_last_wchar_hex = 0;
	DWORD result_gle = ERROR_SUCCESS;
	DWORD recovery_probe_gle = ERROR_SUCCESS;
	std::wstring recovered_actual_path;
	std::string raw_expected_log;
	std::string raw_actual_log;
	std::string visible_expected_log;
	std::string visible_actual_log;
	std::string canonical_expected_log;
	std::string canonical_actual_log;
	std::string selected_actual_log;
	std::string reason;
	dbghelp_canonical_path_t expected;
	dbghelp_canonical_path_t actual;
	dbghelp_canonical_path_t expected_dir;
	dbghelp_canonical_path_t actual_dir_probe;
};

inline std::string dbghelp_verification_summary(const dbghelp_path_verification_t& result)
{
	const std::string actual_dir_probe_log = dbghelp_wide_to_utf8(result.actual_dir_probe.canonical_path);
	char buf[4096];
	std::snprintf(buf, sizeof(buf),
		"actual_wchars=%zu actual_visible_wchars=%zu actual_first_nul=%lld actual_last_wchar_hex=0x%04X actual_visible_ended_with_slash=%d visible_actual='%s' canonical_actual_dir_probe='%s' recovered_directory=%d recovery_probe_gle=%lu recovery_full_ok=%d recovery_full_gle=%lu recovery_open_ok=%d recovery_open_gle=%lu recovery_info_ok=%d recovery_info_gle=%lu recovery_final_ok=%d recovery_final_gle=%lu actual_in_system32=%d actual_dbghelp_name=%d canonical_match=%d file_id_available=%d file_id_match=%d accepted=%d reason='%s' result_gle=%lu",
		result.actual_wchars,
		result.actual_visible_wchars,
		result.actual_first_nul,
		result.actual_last_wchar_hex,
		result.actual_visible_ended_with_slash ? 1 : 0,
		result.visible_actual_log.c_str(),
		actual_dir_probe_log.c_str(),
		result.recovered_directory ? 1 : 0,
		result.recovery_probe_gle,
		result.actual_dir_probe.full_ok ? 1 : 0,
		result.actual_dir_probe.full_gle,
		result.actual_dir_probe.open_ok ? 1 : 0,
		result.actual_dir_probe.open_gle,
		result.actual_dir_probe.info_ok ? 1 : 0,
		result.actual_dir_probe.info_gle,
		result.actual_dir_probe.final_ok ? 1 : 0,
		result.actual_dir_probe.final_gle,
		result.actual_in_system32 ? 1 : 0,
		result.actual_is_dbghelp ? 1 : 0,
		result.canonical_match ? 1 : 0,
		result.file_id_available ? 1 : 0,
		result.file_id_match ? 1 : 0,
		result.accepted ? 1 : 0,
		result.reason.c_str(),
		result.result_gle);
	return buf;
}

inline dbghelp_path_verification_t verify_dbghelp_system_path(const std::wstring& expected_path, const std::wstring& actual_path,
                                                             bool actual_path_ok, DWORD actual_path_gle,
                                                             const char* context, uint64_t attempt, HMODULE hmod)
{
	dbghelp_path_verification_t result{};
	const DWORD pid = GetCurrentProcessId();
	const DWORD tid = GetCurrentThreadId();
	const std::wstring expected_visible = dbghelp_visible_path(expected_path);
	const std::wstring actual_visible = dbghelp_visible_path(actual_path);
	result.actual_wchars = actual_path.size();
	result.actual_visible_wchars = actual_visible.size();
	result.actual_first_nul = dbghelp_first_nul_log_index(actual_path);
	result.actual_last_wchar_hex = actual_path.empty() ? 0U : static_cast<unsigned int>(actual_path.back());
	result.actual_visible_ended_with_slash = !actual_visible.empty() && dbghelp_is_path_slash(actual_visible.back());
	result.raw_expected_log = dbghelp_wide_to_utf8(expected_path);
	result.raw_actual_log = dbghelp_wide_to_utf8(actual_path);
	result.visible_expected_log = dbghelp_wide_to_utf8(expected_visible);
	result.visible_actual_log = dbghelp_wide_to_utf8(actual_visible);
	result.expected = dbghelp_canonicalize_path(expected_visible);
	const std::wstring expected_parent = dbghelp_parent_path(result.expected.canonical_path);
	result.expected_dir = dbghelp_canonicalize_path(expected_parent);
	const bool expected_name_ok = dbghelp_path_equal(dbghelp_file_name(result.expected.canonical_path), L"dbghelp.dll");
	const bool expected_dir_name_ok = dbghelp_path_equal(dbghelp_file_name(result.expected_dir.canonical_path), L"System32");
	result.expected_is_system32_dbghelp = expected_name_ok && expected_dir_name_ok && !result.expected.canonical_path.empty();
	std::wstring candidate_actual = actual_visible;
	if (!actual_path_ok || actual_visible.empty()) {
		result.reason = "actual_module_path_unavailable";
		result.result_gle = actual_path_gle ? actual_path_gle : ERROR_MOD_NOT_FOUND;
	} else {
		if (result.actual_visible_ended_with_slash) {
			const std::wstring actual_dir_path = dbghelp_trim_trailing_slashes(actual_visible);
			result.actual_dir_probe = dbghelp_canonicalize_path(actual_dir_path);
			result.recovery_probe_gle = result.actual_dir_probe.final_gle ? result.actual_dir_probe.final_gle :
				(result.actual_dir_probe.info_gle ? result.actual_dir_probe.info_gle :
				(result.actual_dir_probe.open_gle ? result.actual_dir_probe.open_gle : result.actual_dir_probe.full_gle));
			if (!result.expected_dir.canonical_path.empty() &&
			    dbghelp_path_equal(result.actual_dir_probe.canonical_path, result.expected_dir.canonical_path)) {
				candidate_actual = dbghelp_append_dbghelp_dll(actual_visible);
				result.recovered_actual_path = candidate_actual;
				result.recovered_directory = true;
			}
		}
		result.actual = dbghelp_canonicalize_path(candidate_actual);
		result.file_id_available = result.expected.info_ok && result.actual.info_ok;
		result.file_id_match = result.file_id_available && dbghelp_same_file_id(result.expected.file_id, result.actual.file_id);
		result.canonical_match = !result.expected.canonical_path.empty() &&
			!result.actual.canonical_path.empty() &&
			dbghelp_path_equal(result.expected.canonical_path, result.actual.canonical_path);
		const std::wstring actual_parent = dbghelp_parent_path(result.actual.canonical_path);
		result.actual_in_system32 = !actual_parent.empty() &&
			!result.expected_dir.canonical_path.empty() &&
			dbghelp_path_equal(actual_parent, result.expected_dir.canonical_path);
		result.actual_is_dbghelp = dbghelp_path_equal(dbghelp_file_name(result.actual.canonical_path), L"dbghelp.dll");
		if (!result.expected_is_system32_dbghelp) {
			result.reason = "expected_path_not_system32_dbghelp";
			result.result_gle = ERROR_INVALID_NAME;
		} else if (result.actual.canonical_path.empty()) {
			result.reason = "actual_canonical_path_unavailable";
			result.result_gle = result.actual.full_gle ? result.actual.full_gle : ERROR_INVALID_NAME;
		} else if (!result.actual_in_system32) {
			result.reason = "actual_not_system32_dbghelp";
			result.result_gle = ERROR_ACCESS_DENIED;
		} else if (!result.actual_is_dbghelp) {
			result.reason = "actual_not_dbghelp_dll";
			result.result_gle = ERROR_ACCESS_DENIED;
		} else if (result.file_id_available) {
			if (result.file_id_match) {
				result.accepted = true;
				result.reason = result.recovered_directory ? "recovered_system32_directory_file_id_match" : "file_identity_match";
			} else {
				result.reason = "file_identity_mismatch";
				result.result_gle = ERROR_ACCESS_DENIED;
			}
		} else if (result.canonical_match) {
			result.accepted = true;
			result.reason = result.recovered_directory ? "recovered_system32_directory_canonical_match" : "canonical_path_match";
		} else {
			result.reason = "canonical_path_mismatch";
			result.result_gle = ERROR_ACCESS_DENIED;
		}
	}
	if (result.accepted)
		result.result_gle = ERROR_SUCCESS;
	result.canonical_expected_log = dbghelp_wide_to_utf8(result.expected.canonical_path);
	result.canonical_actual_log = dbghelp_wide_to_utf8(result.actual.canonical_path);
	result.selected_actual_log = !result.canonical_actual_log.empty()
		? result.canonical_actual_log
		: (!result.recovered_actual_path.empty() ? dbghelp_wide_to_utf8(result.recovered_actual_path) : result.raw_actual_log);
	const std::string recovered_log = dbghelp_wide_to_utf8(result.recovered_actual_path);
	const std::string expected_dir_log = dbghelp_wide_to_utf8(result.expected_dir.canonical_path);
	const std::string actual_dir_probe_log = dbghelp_wide_to_utf8(result.actual_dir_probe.canonical_path);
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_path_verify context=%s attempt=%llu pid=%lu tid=%lu hmod=%p raw_expected='%s' visible_expected='%s' raw_actual='%s' visible_actual='%s' actual_wchars=%zu actual_visible_wchars=%zu actual_first_nul=%lld actual_last_wchar_hex=0x%04X actual_visible_ended_with_slash=%d actual_path_ok=%d actual_path_gle=%lu canonical_expected='%s' canonical_actual='%s' canonical_expected_dir='%s' canonical_actual_dir_probe='%s' recovered_directory=%d recovered_actual='%s' recovery_probe_gle=%lu recovery_full_ok=%d recovery_full_gle=%lu recovery_open_ok=%d recovery_open_gle=%lu recovery_info_ok=%d recovery_info_gle=%lu recovery_final_ok=%d recovery_final_gle=%lu expected_system32_dbghelp=%d actual_in_system32=%d actual_dbghelp_name=%d canonical_match=%d file_id_available=%d file_id_match=%d expected_full_ok=%d expected_full_gle=%lu expected_open_ok=%d expected_open_gle=%lu expected_info_ok=%d expected_info_gle=%lu expected_final_ok=%d expected_final_gle=%lu actual_full_ok=%d actual_full_gle=%lu actual_open_ok=%d actual_open_gle=%lu actual_info_ok=%d actual_info_gle=%lu actual_final_ok=%d actual_final_gle=%lu accepted=%d reason='%s' result_gle=%lu",
		context ? context : "<empty>",
		static_cast<unsigned long long>(attempt),
		pid,
		tid,
		hmod,
		result.raw_expected_log.c_str(),
		result.visible_expected_log.c_str(),
		result.raw_actual_log.c_str(),
		result.visible_actual_log.c_str(),
		result.actual_wchars,
		result.actual_visible_wchars,
		result.actual_first_nul,
		result.actual_last_wchar_hex,
		result.actual_visible_ended_with_slash ? 1 : 0,
		actual_path_ok ? 1 : 0,
		actual_path_gle,
		result.canonical_expected_log.c_str(),
		result.canonical_actual_log.c_str(),
		expected_dir_log.c_str(),
		actual_dir_probe_log.c_str(),
		result.recovered_directory ? 1 : 0,
		recovered_log.c_str(),
		result.recovery_probe_gle,
		result.actual_dir_probe.full_ok ? 1 : 0,
		result.actual_dir_probe.full_gle,
		result.actual_dir_probe.open_ok ? 1 : 0,
		result.actual_dir_probe.open_gle,
		result.actual_dir_probe.info_ok ? 1 : 0,
		result.actual_dir_probe.info_gle,
		result.actual_dir_probe.final_ok ? 1 : 0,
		result.actual_dir_probe.final_gle,
		result.expected_is_system32_dbghelp ? 1 : 0,
		result.actual_in_system32 ? 1 : 0,
		result.actual_is_dbghelp ? 1 : 0,
		result.canonical_match ? 1 : 0,
		result.file_id_available ? 1 : 0,
		result.file_id_match ? 1 : 0,
		result.expected.full_ok ? 1 : 0,
		result.expected.full_gle,
		result.expected.open_ok ? 1 : 0,
		result.expected.open_gle,
		result.expected.info_ok ? 1 : 0,
		result.expected.info_gle,
		result.expected.final_ok ? 1 : 0,
		result.expected.final_gle,
		result.actual.full_ok ? 1 : 0,
		result.actual.full_gle,
		result.actual.open_ok ? 1 : 0,
		result.actual.open_gle,
		result.actual.info_ok ? 1 : 0,
		result.actual.info_gle,
		result.actual.final_ok ? 1 : 0,
		result.actual.final_gle,
		result.accepted ? 1 : 0,
		result.reason.c_str(),
		result.result_gle);
	return result;
}

inline void log_dbghelp_prestate(DWORD tid, const std::wstring& dbghelp_path, const std::string& dbghelp_path_log)
{
	const DWORD pid = GetCurrentProcessId();
	SetLastError(ERROR_SUCCESS);
	HMODULE existing = GetModuleHandleW(L"dbghelp.dll");
	DWORD existing_gle = GetLastError();
	wchar_t existing_path[MAX_PATH] = {};
	DWORD existing_len = 0;
	DWORD existing_path_gle = ERROR_SUCCESS;
	if (existing) {
		SetLastError(ERROR_SUCCESS);
		existing_len = GetModuleFileNameW(existing, existing_path, MAX_PATH);
		existing_path_gle = GetLastError();
	}
	WIN32_FILE_ATTRIBUTE_DATA attrs{};
	SetLastError(ERROR_SUCCESS);
	BOOL attrs_ok = GetFileAttributesExW(dbghelp_path.c_str(), GetFileExInfoStandard, &attrs);
	DWORD attrs_gle = GetLastError();
	ULARGE_INTEGER size{};
	if (attrs_ok) {
		size.HighPart = attrs.nFileSizeHigh;
		size.LowPart = attrs.nFileSizeLow;
	}
	const std::string existing_path_log = existing_len ? dbghelp_wide_to_utf8(std::wstring(existing_path, existing_path + existing_len)) : std::string();
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_prestate pid=%lu tid=%lu requested_path='%s' existing_hmod=%p existing_gle=%lu existing_path='%s' existing_path_len=%lu existing_path_gle=%lu attrs_ok=%d attrs=0x%08lX size=%llu attrs_gle=%lu",
		pid,
		tid,
		dbghelp_path_log.c_str(),
		existing,
		existing_gle,
		existing_path_log.c_str(),
		existing_len,
		existing_path_gle,
		attrs_ok ? 1 : 0,
		attrs_ok ? attrs.dwFileAttributes : 0,
		static_cast<unsigned long long>(size.QuadPart),
		attrs_gle);
}

inline void CALLBACK dbghelp_load_watchdog_cb(PVOID param, BOOLEAN) noexcept
{
	auto* ctx = static_cast<dbghelp_load_watchdog_context_t*>(param);
	if (!ctx)
		return;
	uint64_t elapsed = GetTickCount64() - ctx->started_ms;
	bool marked = false;
	{
		std::lock_guard<std::mutex> lk(g_api_mutex);
		if (g_dbghelp_load_state.in_progress &&
			g_dbghelp_load_state.attempt == ctx->attempt &&
			g_dbghelp_load_state.thread_id == ctx->thread_id) {
			g_dbghelp_load_state.stuck = true;
			marked = true;
		}
	}
	if (marked) {
		char detail[512];
		std::snprintf(detail, sizeof(detail),
			"DbgHelp LoadLibrary still has not returned after %llu ms for %s on tid %lu",
			static_cast<unsigned long long>(elapsed),
			ctx->path.c_str(),
			ctx->thread_id);
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_watchdog_stuck tid=%lu attempt=%llu path='%s' elapsed_ms=%llu",
			ctx->thread_id,
			static_cast<unsigned long long>(ctx->attempt),
			ctx->path.c_str(),
			static_cast<unsigned long long>(elapsed));
	}
}

inline bool resolve_dbghelp_exports(HMODULE hmod, const char* source, uint64_t attempt, dbghelp_api_t& candidate, std::string& detail)
{
	const DWORD pid = GetCurrentProcessId();
	const DWORD tid = GetCurrentThreadId();
	candidate = {};
	candidate.hmod = hmod;
	auto gp = [&](const char* name) -> FARPROC {
		const uint64_t export_start = GetTickCount64();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_api_resolve_begin source=%s attempt=%llu pid=%lu tid=%lu hmod=%p name=%s",
			source ? source : "<empty>",
			static_cast<unsigned long long>(attempt),
			pid,
			tid,
			hmod,
			name);
		SetLastError(ERROR_SUCCESS);
		FARPROC proc = GetProcAddress(hmod, name);
		DWORD export_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_api_resolve_end source=%s attempt=%llu pid=%lu tid=%lu hmod=%p name=%s proc=%p ok=%d gle=%lu elapsed_ms=%llu",
			source ? source : "<empty>",
			static_cast<unsigned long long>(attempt),
			pid,
			tid,
			hmod,
			name,
			proc,
			proc ? 1 : 0,
			export_gle,
			static_cast<unsigned long long>(GetTickCount64() - export_start));
		return proc;
	};

	candidate.pSymInitializeW    = reinterpret_cast<fn_SymInitializeW>(gp("SymInitializeW"));
	candidate.pSymCleanup        = reinterpret_cast<fn_SymCleanup>(gp("SymCleanup"));
	candidate.pSymLoadModuleExW  = reinterpret_cast<fn_SymLoadModuleExW>(gp("SymLoadModuleExW"));
	candidate.pSymUnloadModule64 = reinterpret_cast<fn_SymUnloadModule64>(gp("SymUnloadModule64"));
	candidate.pSymSetSearchPathW = reinterpret_cast<fn_SymSetSearchPathW>(gp("SymSetSearchPathW"));
	candidate.pSymSetOptions     = reinterpret_cast<fn_SymSetOptions>(gp("SymSetOptions"));
	candidate.pSymGetOptions     = reinterpret_cast<fn_SymGetOptions>(gp("SymGetOptions"));
	candidate.pSymEnumSymbolsExW = reinterpret_cast<fn_SymEnumSymbolsExW>(gp("SymEnumSymbolsExW"));
	candidate.pSymGetTypeInfo    = reinterpret_cast<fn_SymGetTypeInfo>(gp("SymGetTypeInfo"));
	candidate.pSymEnumTypesW     = reinterpret_cast<fn_SymEnumTypesW>(gp("SymEnumTypesW"));

	if (!candidate.pSymInitializeW || !candidate.pSymCleanup || !candidate.pSymLoadModuleExW ||
	    !candidate.pSymUnloadModule64 || !candidate.pSymEnumSymbolsExW || !candidate.pSymGetTypeInfo) {
		char buf[512];
		std::snprintf(buf, sizeof(buf),
			"DbgHelp missing required exports init=%d cleanup=%d loadmod=%d unload=%d enumsym=%d gettypeinfo=%d enumtypes=%d source=%s",
			candidate.pSymInitializeW    ? 1 : 0,
			candidate.pSymCleanup        ? 1 : 0,
			candidate.pSymLoadModuleExW  ? 1 : 0,
			candidate.pSymUnloadModule64 ? 1 : 0,
			candidate.pSymEnumSymbolsExW ? 1 : 0,
			candidate.pSymGetTypeInfo    ? 1 : 0,
			candidate.pSymEnumTypesW     ? 1 : 0,
			source ? source : "<empty>");
		detail = buf;
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_failed_missing_export source=%s attempt=%llu init=%d cleanup=%d loadmod=%d unload=%d enumsym=%d gettypeinfo=%d enumtypes=%d",
			source ? source : "<empty>",
			static_cast<unsigned long long>(attempt),
			candidate.pSymInitializeW    ? 1 : 0,
			candidate.pSymCleanup        ? 1 : 0,
			candidate.pSymLoadModuleExW  ? 1 : 0,
			candidate.pSymUnloadModule64 ? 1 : 0,
			candidate.pSymEnumSymbolsExW ? 1 : 0,
			candidate.pSymGetTypeInfo    ? 1 : 0,
			candidate.pSymEnumTypesW     ? 1 : 0);
		return false;
	}

	candidate.loaded = true;
	detail.clear();
	return true;
}

inline void set_dbghelp_terminal_locked(bool success, bool stuck, const std::string& phase, const std::string& path,
                                        const std::string& loaded_path, DWORD gle, HMODULE hmod,
                                        const std::string& detail)
{
	g_dbghelp_load_state.in_progress = false;
	g_dbghelp_load_state.stuck = stuck;
	g_dbghelp_load_state.terminal = true;
	g_dbghelp_load_state.last_success = success;
	g_dbghelp_load_state.completed_ms = GetTickCount64();
	g_dbghelp_load_state.phase = phase;
	g_dbghelp_load_state.path = path;
	g_dbghelp_load_state.loaded_path = loaded_path;
	g_dbghelp_load_state.last_gle = gle;
	g_dbghelp_load_state.last_hmod = hmod;
	g_dbghelp_load_state.terminal_detail = detail;
	if (success)
		g_dbghelp_load_state.thread_id = 0;
}

inline int try_use_preloaded_dbghelp_locked(const std::wstring& dbghelp_path, const std::string& dbghelp_path_log, uint64_t attempt)
{
	const DWORD pid = GetCurrentProcessId();
	const DWORD tid = GetCurrentThreadId();
	HMODULE existing_by_path = nullptr;
	SetLastError(ERROR_SUCCESS);
	BOOL by_path_ok = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, dbghelp_path.c_str(), &existing_by_path);
	DWORD by_path_gle = GetLastError();
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_preloaded_probe_by_path attempt=%llu pid=%lu tid=%lu path='%s' ok=%d hmod=%p gle=%lu",
		static_cast<unsigned long long>(attempt),
		pid,
		tid,
		dbghelp_path_log.c_str(),
		by_path_ok ? 1 : 0,
		existing_by_path,
		by_path_gle);

	HMODULE existing = existing_by_path;
	if (!existing) {
		SetLastError(ERROR_SUCCESS);
		existing = GetModuleHandleW(L"dbghelp.dll");
		DWORD existing_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_preloaded_probe_by_name attempt=%llu pid=%lu tid=%lu hmod=%p gle=%lu",
			static_cast<unsigned long long>(attempt),
			pid,
			tid,
			existing,
			existing_gle);
	}
	if (!existing)
		return 0;

	std::wstring loaded_module_path;
	DWORD loaded_path_gle = ERROR_SUCCESS;
	const bool loaded_path_ok = get_dbghelp_module_path(existing, loaded_module_path, loaded_path_gle);
	const dbghelp_path_verification_t path_check = verify_dbghelp_system_path(dbghelp_path, loaded_module_path,
		loaded_path_ok, loaded_path_gle, "preloaded", attempt, existing);
	const std::string loaded_module_path_log = path_check.selected_actual_log;
	const std::string verifier_summary = dbghelp_verification_summary(path_check);
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_preloaded_path attempt=%llu pid=%lu tid=%lu expected_path='%s' hmod=%p loaded_path_ok=%d raw_loaded_path='%s' verified_loaded_path='%s' path_gle=%lu accepted=%d reason='%s' verifier=\"%s\"",
		static_cast<unsigned long long>(attempt),
		pid,
		tid,
		dbghelp_path_log.c_str(),
		existing,
		loaded_path_ok ? 1 : 0,
		path_check.raw_actual_log.c_str(),
		loaded_module_path_log.c_str(),
		loaded_path_gle,
		path_check.accepted ? 1 : 0,
		path_check.reason.c_str(),
		verifier_summary.c_str());
	if (!path_check.accepted) {
		char detail[768];
		std::snprintf(detail, sizeof(detail), "DbgHelp was already loaded from unexpected path %s while %s was required; verifier=%s",
			path_check.raw_actual_log.c_str(), dbghelp_path_log.c_str(), path_check.reason.c_str());
		set_last_error_text(detail);
		set_dbghelp_terminal_locked(false, false, "preloaded_rejected", dbghelp_path_log, loaded_module_path_log,
			path_check.result_gle, existing, detail);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_preloaded_rejected attempt=%llu expected='%s' loaded='%s' canonical_expected='%s' canonical_actual='%s' path_ok=%d path_gle=%lu verifier_gle=%lu recovered_directory=%d file_id_match=%d reason='%s' verifier=\"%s\"",
			static_cast<unsigned long long>(attempt),
			dbghelp_path_log.c_str(),
			loaded_module_path_log.c_str(),
			path_check.canonical_expected_log.c_str(),
			path_check.canonical_actual_log.c_str(),
			loaded_path_ok ? 1 : 0,
			loaded_path_gle,
			path_check.result_gle,
			path_check.recovered_directory ? 1 : 0,
			path_check.file_id_match ? 1 : 0,
			path_check.reason.c_str(),
			verifier_summary.c_str());
		g_dbghelp_load_cv.notify_all();
		return -1;
	}

	dbghelp_api_t candidate{};
	std::string detail;
	if (!resolve_dbghelp_exports(existing, "preloaded", attempt, candidate, detail)) {
		set_last_error_text(detail);
		set_dbghelp_terminal_locked(false, false, "preloaded_exports", dbghelp_path_log, loaded_module_path_log,
			ERROR_PROC_NOT_FOUND, existing, detail);
		g_dbghelp_load_cv.notify_all();
		return -1;
	}

	g_api = candidate;
	set_last_error_text({});
	set_dbghelp_terminal_locked(true, false, "preloaded_ok", dbghelp_path_log, loaded_module_path_log,
		ERROR_SUCCESS, existing, "DbgHelp preloaded system module accepted");
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_preloaded_ok attempt=%llu pid=%lu tid=%lu hmod=%p loaded_path='%s' verifier=\"%s\"",
		static_cast<unsigned long long>(attempt),
		pid,
		tid,
		existing,
		loaded_module_path_log.c_str(),
		verifier_summary.c_str());
	g_dbghelp_load_cv.notify_all();
	return 1;
}

inline void dbghelp_load_worker(uint64_t attempt, std::wstring dbghelp_path, std::string dbghelp_path_log,
                                DWORD caller_pid, DWORD caller_tid) noexcept
{
	const DWORD worker_pid = GetCurrentProcessId();
	const DWORD worker_tid = GetCurrentThreadId();
	const uint64_t worker_start = GetTickCount64();
	try {
		{
			std::lock_guard<std::mutex> lk(g_api_mutex);
			if (g_dbghelp_load_state.attempt == attempt) {
				g_dbghelp_load_state.worker_pid = worker_pid;
				g_dbghelp_load_state.worker_tid = worker_tid;
				g_dbghelp_load_state.phase = "LoadLibraryW";
			}
		}
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_worker_enter attempt=%llu caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu path='%s'",
			static_cast<unsigned long long>(attempt),
			caller_pid,
			caller_tid,
			worker_pid,
			worker_tid,
			dbghelp_path_log.c_str());
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_LoadLibrary_begin attempt=%llu caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu api=LoadLibraryW path='%s'",
			static_cast<unsigned long long>(attempt),
			caller_pid,
			caller_tid,
			worker_pid,
			worker_tid,
			dbghelp_path_log.c_str());
		SetLastError(ERROR_SUCCESS);
		HMODULE loaded_hmod = LoadLibraryW(dbghelp_path.c_str());
		DWORD load_gle = GetLastError();
		const uint64_t load_elapsed = GetTickCount64() - worker_start;
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_LoadLibrary_end attempt=%llu caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu api=LoadLibraryW path='%s' hmod=%p gle=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(attempt),
			caller_pid,
			caller_tid,
			worker_pid,
			worker_tid,
			dbghelp_path_log.c_str(),
			loaded_hmod,
			load_gle,
			static_cast<unsigned long long>(load_elapsed));
		if (!loaded_hmod) {
			char detail[512];
			std::snprintf(detail, sizeof(detail), "LoadLibraryW(%s) failed with Win32 error %lu", dbghelp_path_log.c_str(), load_gle);
			{
				std::lock_guard<std::mutex> lk(g_api_mutex);
				if (g_dbghelp_load_state.attempt == attempt)
					set_dbghelp_terminal_locked(false, false, "LoadLibraryW_failed", dbghelp_path_log, {}, load_gle, loaded_hmod, detail);
			}
			set_last_error_text(detail);
			g_dbghelp_load_cv.notify_all();
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_worker_failed attempt=%llu reason='LoadLibraryW' path='%s' gle=%lu elapsed_ms=%llu",
				static_cast<unsigned long long>(attempt),
				dbghelp_path_log.c_str(),
				load_gle,
				static_cast<unsigned long long>(load_elapsed));
			return;
		}

		std::wstring loaded_module_path;
		DWORD loaded_path_gle = ERROR_SUCCESS;
		const bool loaded_path_ok = get_dbghelp_module_path(loaded_hmod, loaded_module_path, loaded_path_gle);
		const dbghelp_path_verification_t path_check = verify_dbghelp_system_path(dbghelp_path, loaded_module_path,
			loaded_path_ok, loaded_path_gle, "LoadLibraryW", attempt, loaded_hmod);
		const std::string loaded_module_path_log = path_check.selected_actual_log;
		const std::string verifier_summary = dbghelp_verification_summary(path_check);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_loaded_path attempt=%llu worker_pid=%lu worker_tid=%lu expected_path='%s' hmod=%p loaded_path_ok=%d raw_loaded_path='%s' verified_loaded_path='%s' path_gle=%lu accepted=%d reason='%s' verifier=\"%s\"",
			static_cast<unsigned long long>(attempt),
			worker_pid,
			worker_tid,
			dbghelp_path_log.c_str(),
			loaded_hmod,
			loaded_path_ok ? 1 : 0,
			path_check.raw_actual_log.c_str(),
			loaded_module_path_log.c_str(),
			loaded_path_gle,
			path_check.accepted ? 1 : 0,
			path_check.reason.c_str(),
			verifier_summary.c_str());
		if (!path_check.accepted) {
			FreeLibrary(loaded_hmod);
			char detail[768];
			std::snprintf(detail, sizeof(detail), "DbgHelp resolved to unexpected module path %s while %s was required; verifier=%s",
				path_check.raw_actual_log.c_str(), dbghelp_path_log.c_str(), path_check.reason.c_str());
			{
				std::lock_guard<std::mutex> lk(g_api_mutex);
				if (g_dbghelp_load_state.attempt == attempt)
					set_dbghelp_terminal_locked(false, false, "unexpected_module_path", dbghelp_path_log, loaded_module_path_log,
						path_check.result_gle, loaded_hmod, detail);
			}
			set_last_error_text(detail);
			g_dbghelp_load_cv.notify_all();
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_worker_failed attempt=%llu reason='unexpected_module_path' expected='%s' loaded='%s' canonical_expected='%s' canonical_actual='%s' path_ok=%d path_gle=%lu verifier_gle=%lu recovered_directory=%d file_id_match=%d verifier_reason='%s' elapsed_ms=%llu verifier=\"%s\"",
				static_cast<unsigned long long>(attempt),
				dbghelp_path_log.c_str(),
				loaded_module_path_log.c_str(),
				path_check.canonical_expected_log.c_str(),
				path_check.canonical_actual_log.c_str(),
				loaded_path_ok ? 1 : 0,
				loaded_path_gle,
				path_check.result_gle,
				path_check.recovered_directory ? 1 : 0,
				path_check.file_id_match ? 1 : 0,
				path_check.reason.c_str(),
				static_cast<unsigned long long>(GetTickCount64() - worker_start),
				verifier_summary.c_str());
			return;
		}

		dbghelp_api_t candidate{};
		std::string detail;
		if (!resolve_dbghelp_exports(loaded_hmod, "LoadLibraryW", attempt, candidate, detail)) {
			FreeLibrary(loaded_hmod);
			{
				std::lock_guard<std::mutex> lk(g_api_mutex);
				if (g_dbghelp_load_state.attempt == attempt)
					set_dbghelp_terminal_locked(false, false, "missing_export", dbghelp_path_log, loaded_module_path_log,
						ERROR_PROC_NOT_FOUND, loaded_hmod, detail);
			}
			set_last_error_text(detail);
			g_dbghelp_load_cv.notify_all();
			return;
		}

		{
			std::lock_guard<std::mutex> lk(g_api_mutex);
			if (g_dbghelp_load_state.attempt == attempt) {
				const bool completed_after_timeout = g_dbghelp_load_state.stuck || g_dbghelp_load_state.phase == "LoadLibraryW_timeout";
				g_api = candidate;
				set_dbghelp_terminal_locked(true, false, "loaded", dbghelp_path_log, loaded_module_path_log,
					ERROR_SUCCESS, loaded_hmod, "DbgHelp loaded successfully");
				if (!completed_after_timeout)
					set_last_error_text({});
			}
		}
		g_dbghelp_load_cv.notify_all();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_worker_ok attempt=%llu path='%s' loaded_path='%s' hmod=%p elapsed_ms=%llu verifier=\"%s\"",
			static_cast<unsigned long long>(attempt),
			dbghelp_path_log.c_str(),
			loaded_module_path_log.c_str(),
			loaded_hmod,
			static_cast<unsigned long long>(GetTickCount64() - worker_start),
			verifier_summary.c_str());
	} catch (...) {
		const std::string detail = "DbgHelp loader worker threw an unknown exception";
		{
			std::lock_guard<std::mutex> lk(g_api_mutex);
			if (g_dbghelp_load_state.attempt == attempt)
				set_dbghelp_terminal_locked(false, false, "worker_exception", dbghelp_path_log, {}, ERROR_UNHANDLED_EXCEPTION, nullptr, detail);
		}
		set_last_error_text(detail);
		g_dbghelp_load_cv.notify_all();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_worker_exception attempt=%llu caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(attempt),
			caller_pid,
			caller_tid,
			worker_pid,
			worker_tid,
			static_cast<unsigned long long>(GetTickCount64() - worker_start));
	}
}

inline bool load_dbghelp()
{
	const DWORD tid = GetCurrentThreadId();
	const DWORD pid = GetCurrentProcessId();
	const uint64_t wait_start = GetTickCount64();
	const std::wstring dbghelp_path = resolve_dbghelp_path();
	const std::string dbghelp_path_log = dbghelp_wide_to_utf8(dbghelp_path);
	uint64_t attempt = 0;
	bool start_worker = false;
	diag::log_tagged_fmt("pdb", "load_dbghelp_enter pid=%lu tid=%lu path='%s'", pid, tid, dbghelp_path_log.c_str());
	log_dbghelp_prestate(tid, dbghelp_path, dbghelp_path_log);
	{
		std::unique_lock<std::mutex> lk(g_api_mutex);
		diag::log_tagged_fmt("pdb", "load_dbghelp_locked pid=%lu tid=%lu wait_ms=%llu state=\"%s\"",
			pid,
			tid,
			static_cast<unsigned long long>(GetTickCount64() - wait_start),
			dbghelp_load_state_text_locked(GetTickCount64()).c_str());
		if (g_api.loaded) {
			set_last_error_text({});
			diag::log_tagged_fmt("pdb", "load_dbghelp_cached_success pid=%lu tid=%lu hmod=%p path='%s'",
				pid, tid, g_api.hmod, g_dbghelp_load_state.loaded_path.c_str());
			return true;
		}
		if (g_dbghelp_load_state.terminal && !g_dbghelp_load_state.last_success && !g_dbghelp_load_state.in_progress) {
			const std::string detail = g_dbghelp_load_state.terminal_detail.empty()
				? dbghelp_load_state_text_locked(GetTickCount64())
				: g_dbghelp_load_state.terminal_detail;
			set_last_error_text(detail);
			diag::log_tagged_fmt("pdb", "load_dbghelp_cached_terminal_failure pid=%lu tid=%lu state=\"%s\"",
				pid, tid, dbghelp_load_state_text_locked(GetTickCount64()).c_str());
			return false;
		}
		if (g_dbghelp_load_state.in_progress) {
			const uint64_t owner_elapsed = GetTickCount64() - g_dbghelp_load_state.started_ms;
			if (owner_elapsed >= k_dbghelp_load_watchdog_ms) {
				g_dbghelp_load_state.stuck = true;
				g_dbghelp_load_state.phase = "LoadLibraryW_timeout";
				if (g_dbghelp_load_state.terminal_detail.empty()) {
					char stuck_detail[768];
					std::snprintf(stuck_detail, sizeof(stuck_detail),
						"DbgHelp LoadLibraryW is stuck after %llu ms; caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu path=%s",
						static_cast<unsigned long long>(owner_elapsed),
						g_dbghelp_load_state.caller_pid,
						g_dbghelp_load_state.caller_tid,
						g_dbghelp_load_state.worker_pid,
						g_dbghelp_load_state.worker_tid,
						g_dbghelp_load_state.path.c_str());
					g_dbghelp_load_state.terminal_detail = stuck_detail;
				}
			}
			char detail[512];
			std::snprintf(detail, sizeof(detail),
				"DbgHelp loader is already %s on caller tid %lu worker tid %lu for %llu ms while loading %s",
				g_dbghelp_load_state.stuck ? "stuck" : "in progress",
				g_dbghelp_load_state.caller_tid,
				g_dbghelp_load_state.worker_tid,
				static_cast<unsigned long long>(owner_elapsed),
				g_dbghelp_load_state.path.c_str());
			set_last_error_text(detail);
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_busy pid=%lu tid=%lu owner_pid=%lu owner_tid=%lu worker_pid=%lu worker_tid=%lu owner_elapsed_ms=%llu owner_attempt=%llu stuck=%d path='%s' state=\"%s\"",
				pid,
				tid,
				g_dbghelp_load_state.caller_pid,
				g_dbghelp_load_state.caller_tid,
				g_dbghelp_load_state.worker_pid,
				g_dbghelp_load_state.worker_tid,
				static_cast<unsigned long long>(owner_elapsed),
				static_cast<unsigned long long>(g_dbghelp_load_state.attempt),
				g_dbghelp_load_state.stuck ? 1 : 0,
				g_dbghelp_load_state.path.c_str(),
				dbghelp_load_state_text_locked(GetTickCount64()).c_str());
			return false;
		}

		attempt = g_dbghelp_load_state.attempt + 1;
		g_dbghelp_load_state.in_progress = false;
		g_dbghelp_load_state.stuck = false;
		g_dbghelp_load_state.terminal = false;
		g_dbghelp_load_state.last_success = false;
		g_dbghelp_load_state.caller_pid = pid;
		g_dbghelp_load_state.caller_tid = tid;
		g_dbghelp_load_state.worker_pid = 0;
		g_dbghelp_load_state.worker_tid = 0;
		g_dbghelp_load_state.thread_id = tid;
		g_dbghelp_load_state.started_ms = GetTickCount64();
		g_dbghelp_load_state.completed_ms = 0;
		g_dbghelp_load_state.path = dbghelp_path_log;
		g_dbghelp_load_state.loaded_path.clear();
		g_dbghelp_load_state.terminal_detail.clear();
		g_dbghelp_load_state.phase = "preloaded_probe";
		g_dbghelp_load_state.last_gle = ERROR_SUCCESS;
		g_dbghelp_load_state.last_hmod = nullptr;
		g_dbghelp_load_state.attempt = attempt;
		const int preloaded = try_use_preloaded_dbghelp_locked(dbghelp_path, dbghelp_path_log, attempt);
		if (preloaded > 0)
			return true;
		if (preloaded < 0)
			return false;

		g_dbghelp_load_state.in_progress = true;
		g_dbghelp_load_state.started_ms = GetTickCount64();
		g_dbghelp_load_state.phase = "queued";
		start_worker = true;
	}

	if (start_worker) {
		try {
			std::thread(dbghelp_load_worker, attempt, dbghelp_path, dbghelp_path_log, pid, tid).detach();
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_worker_started attempt=%llu caller_pid=%lu caller_tid=%lu wait_timeout_ms=%llu path='%s'",
				static_cast<unsigned long long>(attempt),
				pid,
				tid,
				static_cast<unsigned long long>(k_dbghelp_load_watchdog_ms),
				dbghelp_path_log.c_str());
		} catch (const std::exception& ex) {
			std::lock_guard<std::mutex> lk(g_api_mutex);
			char detail[768];
			std::snprintf(detail, sizeof(detail), "Failed to start DbgHelp loader worker: %s", ex.what());
			set_dbghelp_terminal_locked(false, false, "worker_start_failed", dbghelp_path_log, {}, GetLastError(), nullptr, detail);
			set_last_error_text(detail);
			g_dbghelp_load_cv.notify_all();
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_worker_start_failed attempt=%llu caller_pid=%lu caller_tid=%lu err='%s'",
				static_cast<unsigned long long>(attempt),
				pid,
				tid,
				ex.what());
			return false;
		} catch (...) {
			std::lock_guard<std::mutex> lk(g_api_mutex);
			const std::string detail = "Failed to start DbgHelp loader worker: unknown exception";
			set_dbghelp_terminal_locked(false, false, "worker_start_failed", dbghelp_path_log, {}, GetLastError(), nullptr, detail);
			set_last_error_text(detail);
			g_dbghelp_load_cv.notify_all();
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_worker_start_failed attempt=%llu caller_pid=%lu caller_tid=%lu err='<unknown>'",
				static_cast<unsigned long long>(attempt),
				pid,
				tid);
			return false;
		}
	}

	std::unique_lock<std::mutex> wait_lk(g_api_mutex);
	const bool completed = g_dbghelp_load_cv.wait_for(wait_lk, std::chrono::milliseconds(k_dbghelp_load_watchdog_ms), [attempt]() {
		return g_api.loaded || !g_dbghelp_load_state.in_progress || g_dbghelp_load_state.attempt != attempt;
	});
	const std::string state_text = dbghelp_load_state_text_locked(GetTickCount64());
	if (g_api.loaded) {
		set_last_error_text({});
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_ok attempt=%llu caller_pid=%lu caller_tid=%lu completed=%d elapsed_ms=%llu state=\"%s\"",
			static_cast<unsigned long long>(attempt),
			pid,
			tid,
			completed ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - wait_start),
			state_text.c_str());
		return true;
	}

	if (!completed && g_dbghelp_load_state.attempt == attempt && g_dbghelp_load_state.in_progress) {
		const uint64_t owner_elapsed = GetTickCount64() - g_dbghelp_load_state.started_ms;
		g_dbghelp_load_state.stuck = true;
		g_dbghelp_load_state.phase = "LoadLibraryW_timeout";
		char detail[512];
		std::snprintf(detail, sizeof(detail),
			"DbgHelp LoadLibraryW timed out after %llu ms; caller_pid=%lu caller_tid=%lu worker_pid=%lu worker_tid=%lu path=%s",
			static_cast<unsigned long long>(owner_elapsed),
			g_dbghelp_load_state.caller_pid,
			g_dbghelp_load_state.caller_tid,
			g_dbghelp_load_state.worker_pid,
			g_dbghelp_load_state.worker_tid,
			g_dbghelp_load_state.path.c_str());
		g_dbghelp_load_state.terminal_detail = detail;
		g_dbghelp_load_state.last_gle = WAIT_TIMEOUT;
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_wait_timeout attempt=%llu caller_pid=%lu caller_tid=%lu timeout_ms=%llu state=\"%s\"",
			static_cast<unsigned long long>(attempt),
			pid,
			tid,
			static_cast<unsigned long long>(k_dbghelp_load_watchdog_ms),
			dbghelp_load_state_text_locked(GetTickCount64()).c_str());
		return false;
	}

	const std::string detail = g_dbghelp_load_state.terminal_detail.empty()
		? dbghelp_load_state_text_locked(GetTickCount64())
		: g_dbghelp_load_state.terminal_detail;
	set_last_error_text(detail);
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_failed attempt=%llu caller_pid=%lu caller_tid=%lu completed=%d elapsed_ms=%llu state=\"%s\"",
		static_cast<unsigned long long>(attempt),
		pid,
		tid,
		completed ? 1 : 0,
		static_cast<unsigned long long>(GetTickCount64() - wait_start),
		dbghelp_load_state_text_locked(GetTickCount64()).c_str());
	return false;
}

namespace detail {

inline std::string wstr_to_utf8(const wchar_t* ws)
{
	if (!ws || !*ws) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 0) return {};
	std::string out(len - 1, '\0');
	WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), len, nullptr, nullptr);
	return out;
}

inline std::wstring utf8_to_wstr(const std::string& s)
{
	if (s.empty()) return {};
	int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	if (len <= 0) return {};
	std::wstring out(len - 1, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
	return out;
}

inline std::string get_base_type_name(BasicType_E bt, uint64_t length)
{
	switch (bt) {
	case btVoid:   return "void";
	case btChar:   return "char";
	case btWChar:  return "wchar_t";
	case btBool:   return "bool";
	case btFloat:  return (length == 4) ? "float" : "double";
	case btHresult: return "HRESULT";
	case btInt:
		switch (length) {
		case 1: return "int8_t";
		case 2: return "int16_t";
		case 4: return "int32_t";
		case 8: return "int64_t";
		default: return "int";
		}
	case btUInt:
		switch (length) {
		case 1: return "uint8_t";
		case 2: return "uint16_t";
		case 4: return "uint32_t";
		case 8: return "uint64_t";
		default: return "unsigned int";
		}
	case btLong:
		return (length == 8) ? "int64_t" : "long";
	case btULong:
		return (length == 8) ? "uint64_t" : "unsigned long";
	default:
		char buf[32];
		snprintf(buf, sizeof(buf), "unk_%llu", static_cast<unsigned long long>(length));
		return buf;
	}
}

inline std::string resolve_type_name(HANDLE hProc, DWORD64 modBase, ULONG typeIndex)
{
	DWORD tag = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_SYMTAG, &tag))
		return "unk";

	switch (tag) {
	case SymTagBaseType: {
		DWORD bt = 0;
		ULONG64 len = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_BASETYPE, &bt);
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_LENGTH, &len);
		return get_base_type_name(static_cast<BasicType_E>(bt), len);
	}
	case SymTagPointerType: {
		DWORD innerTypeId = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_TYPEID, &innerTypeId)) {
			return resolve_type_name(hProc, modBase, innerTypeId) + "*";
		}
		return "void*";
	}
	case SymTagArrayType: {
		DWORD elemTypeId = 0;
		DWORD count = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_TYPEID, &elemTypeId);
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_COUNT, &count);
		char buf[16];
		snprintf(buf, sizeof(buf), "[%u]", count);
		return resolve_type_name(hProc, modBase, elemTypeId) + buf;
	}
	case SymTagUDT:
	case SymTagEnum:
	case SymTagTypedef: {
		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_SYMNAME, &pName) && pName) {
			std::string name = wstr_to_utf8(pName);
			LocalFree(pName);
			return name;
		}
		return "unk_udt";
	}
	case SymTagFunctionType:
		return "fn_ptr";
	default: {
		char buf[32];
		snprintf(buf, sizeof(buf), "tag_%u", tag);
		return buf;
	}
	}
}

struct sym_enum_ctx_t {
	HANDLE                      hProc;
	DWORD64                     modBase;
	std::vector<pdb_symbol_t>*  symbols;
};

inline BOOL CALLBACK sym_enum_callback(SYMBOL_INFOW_EX* pSymInfo, ULONG symSize, void* ctx)
{
	(void)symSize;
	auto* c = static_cast<sym_enum_ctx_t*>(ctx);

	pdb_symbol_t sym;
	sym.name = wstr_to_utf8(pSymInfo->Name);
	sym.rva = static_cast<uint64_t>(pSymInfo->Address - pSymInfo->ModBase);
	sym.type_index = pSymInfo->TypeIndex;
	sym.size = pSymInfo->Size;
	sym.is_function = (pSymInfo->Tag == SymTagFunction);

	c->symbols->push_back(std::move(sym));
	return TRUE;
}

struct type_enum_ctx_t {
	HANDLE                      hProc;
	DWORD64                     modBase;
	std::vector<ULONG>          udt_indices;
	std::vector<ULONG>          enum_indices;
};

inline BOOL CALLBACK type_enum_callback(SYMBOL_INFOW_EX* pSymInfo, ULONG symSize, void* ctx)
{
	(void)symSize;
	auto* c = static_cast<type_enum_ctx_t*>(ctx);

	if (pSymInfo->Tag == SymTagUDT)
		c->udt_indices.push_back(pSymInfo->TypeIndex);
	else if (pSymInfo->Tag == SymTagEnum)
		c->enum_indices.push_back(pSymInfo->TypeIndex);

	return TRUE;
}

inline void import_struct_members(HANDLE hProc, DWORD64 modBase, ULONG typeIndex, struct_def_t& def)
{
	DWORD childCount = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_CHILDRENCOUNT, &childCount) || childCount == 0)
		return;

	size_t alloc_sz = sizeof(TI_FINDCHILDREN_PARAMS_EX) + (childCount - 1) * sizeof(ULONG);
	std::vector<uint8_t> buf(alloc_sz, 0);
	auto* fc = reinterpret_cast<TI_FINDCHILDREN_PARAMS_EX*>(buf.data());
	fc->Count = childCount;
	fc->Start = 0;

	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_FINDCHILDREN, fc))
		return;

	for (ULONG i = 0; i < childCount; ++i) {
		ULONG childId = fc->ChildId[i];
		DWORD tag = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMTAG, &tag);

		if (tag != SymTagData) continue;

		struct_member_t member;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMNAME, &pName) && pName) {
			member.name = wstr_to_utf8(pName);
			LocalFree(pName);
		}

		DWORD offset = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_OFFSET, &offset);
		member.offset = offset;

		DWORD memTypeId = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_TYPEID, &memTypeId)) {
			member.type_index = memTypeId;
			member.type_name = resolve_type_name(hProc, modBase, memTypeId);

			ULONG64 memLen = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_LENGTH, &memLen);
			member.size = memLen;

			DWORD memTag = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_SYMTAG, &memTag);

			if (memTag == SymTagPointerType) {
				member.is_pointer = true;
				member.pointer_depth = 1;
				DWORD inner = memTypeId;
				for (int d = 0; d < 8; ++d) {
					DWORD next = 0;
					if (!g_api.pSymGetTypeInfo(hProc, modBase, inner, TI_GET_TYPEID, &next)) break;
					DWORD nextTag = 0;
					g_api.pSymGetTypeInfo(hProc, modBase, next, TI_GET_SYMTAG, &nextTag);
					if (nextTag != SymTagPointerType) break;
					member.pointer_depth++;
					inner = next;
				}
			}

			if (memTag == SymTagArrayType) {
				member.is_array = true;
				DWORD count = 0;
				g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_COUNT, &count);
				member.array_count = static_cast<int>(count);
			}
		}

		DWORD bitPos = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_BITPOSITION, &bitPos)) {
			member.bit_offset = static_cast<int>(bitPos);
			ULONG64 bitLen = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_LENGTH, &bitLen);
			member.bit_size = static_cast<int>(bitLen);
		}

		def.members.push_back(std::move(member));
	}

	std::sort(def.members.begin(), def.members.end(),
	          [](const struct_member_t& a, const struct_member_t& b) { return a.offset < b.offset; });
}

inline void import_enum_members(HANDLE hProc, DWORD64 modBase, ULONG typeIndex, enum_def_t& def)
{
	DWORD childCount = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_CHILDRENCOUNT, &childCount) || childCount == 0)
		return;

	size_t alloc_sz = sizeof(TI_FINDCHILDREN_PARAMS_EX) + (childCount - 1) * sizeof(ULONG);
	std::vector<uint8_t> buf(alloc_sz, 0);
	auto* fc = reinterpret_cast<TI_FINDCHILDREN_PARAMS_EX*>(buf.data());
	fc->Count = childCount;
	fc->Start = 0;

	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_FINDCHILDREN, fc))
		return;

	for (ULONG i = 0; i < childCount; ++i) {
		ULONG childId = fc->ChildId[i];
		enum_member_t em;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMNAME, &pName) && pName) {
			em.name = wstr_to_utf8(pName);
			LocalFree(pName);
		}

		VARIANT val;
		VariantInit(&val);
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_VALUE, &val)) {
			switch (val.vt) {
			case VT_I1:  em.value = val.cVal; break;
			case VT_I2:  em.value = val.iVal; break;
			case VT_I4:  em.value = val.lVal; break;
			case VT_I8:  em.value = val.llVal; break;
			case VT_UI1: em.value = val.bVal; break;
			case VT_UI2: em.value = val.uiVal; break;
			case VT_UI4: em.value = val.ulVal; break;
			case VT_UI8: em.value = static_cast<int64_t>(val.ullVal); break;
			default: break;
			}
			VariantClear(&val);
		}

		def.members.push_back(std::move(em));
	}
}

}

inline bool parse_pdb(const std::string& pdb_path,
                      const std::string& symbol_search_path,
                      pdb_info_t& out,
                      std::atomic<float>* progress = nullptr,
                      std::atomic<bool>* cancel = nullptr)
{
	uint64_t t_begin = GetTickCount64();
	const uint64_t parse_generation = g_parse_generation.fetch_add(1, std::memory_order_acq_rel);
	const DWORD pid = GetCurrentProcessId();
	const DWORD tid = GetCurrentThreadId();
	uint64_t pdb_bytes = 0;
	{
		std::error_code ec;
		auto sz = std::filesystem::file_size(pdb_path, ec);
		if (!ec) pdb_bytes = static_cast<uint64_t>(sz);
	}
	diag::log_tagged_fmt("pdb",
		"parse_pdb_entry generation=%llu pid=%lu tid=%lu worker_tid=%lu path='%s' bytes=%llu search_len=%zu cancel_ptr=%p loader_state=\"%s\"",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		tid,
		pdb_path.c_str(), static_cast<unsigned long long>(pdb_bytes),
		symbol_search_path.size(), static_cast<void*>(cancel),
		dbghelp_load_diagnostic().c_str());
	set_last_error_text({});

	if (!load_dbghelp()) {
		const std::string detail = last_error();
		diag::log_tagged_fmt("pdb",
			"parse_pdb_failed generation=%llu pid=%lu tid=%lu reason='dbghelp_load' path='%s' detail='%s' loader_state=\"%s\"",
			static_cast<unsigned long long>(parse_generation),
			pid,
			tid,
			pdb_path.c_str(),
			detail.c_str(),
			dbghelp_load_diagnostic().c_str());
		set_last_error_text(detail);
		return false;
	}

	uint64_t dbghelp_wait_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_dbghelp_mutex_wait generation=%llu pid=%lu tid=%lu path='%s'",
		static_cast<unsigned long long>(parse_generation), pid, tid, pdb_path.c_str());
	std::unique_lock<std::mutex> dbghelp_lk(g_dbghelp_call_mutex, std::defer_lock);
	while (!dbghelp_lk.try_lock()) {
		const uint64_t waited = GetTickCount64() - dbghelp_wait_start;
		if (waited >= 30000) {
			char detail[512];
			std::snprintf(detail, sizeof(detail), "DbgHelp call mutex was not acquired after %llu ms for %s",
				static_cast<unsigned long long>(waited),
				pdb_path.c_str());
			set_last_error_text(detail);
			diag::log_tagged_fmt("pdb",
				"parse_pdb_failed generation=%llu reason='dbghelp_mutex_timeout' pid=%lu tid=%lu wait_ms=%llu path='%s'",
				static_cast<unsigned long long>(parse_generation),
				pid,
				tid,
				static_cast<unsigned long long>(waited),
				pdb_path.c_str());
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_dbghelp_mutex_acquired generation=%llu pid=%lu tid=%lu wait_ms=%llu path='%s'",
		static_cast<unsigned long long>(parse_generation), pid, tid, static_cast<unsigned long long>(GetTickCount64() - dbghelp_wait_start), pdb_path.c_str());

	out = {};
	out.file_path = pdb_path;

	auto stem = std::filesystem::path(pdb_path).stem().string();
	out.module_name = stem;

	HANDLE hFakeProc = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(GetCurrentProcessId() ^ 0xABCD0000));

	std::string search_lower = symbol_search_path;
	std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	const bool local_only_search = !symbol_search_path.empty() &&
		search_lower.find("srv*") == std::string::npos &&
		search_lower.find("symsrv") == std::string::npos;
	DWORD opts = g_api.pSymGetOptions ? g_api.pSymGetOptions() : 0;
	const DWORD old_opts = opts;
	opts |= 0x00000004;
	opts |= 0x00000010;
	opts |= 0x00000200;
	if (local_only_search) {
		opts |= 0x00001000;
		opts |= 0x00020000;
		opts |= 0x00080000;
		opts |= 0x02000000;
		opts |= 0x40000000;
	}
	opts &= ~0x00000001;
	DWORD applied_opts = opts;
	if (g_api.pSymSetOptions)
		applied_opts = g_api.pSymSetOptions(opts);
	diag::log_tagged_fmt("pdb",
		"parse_pdb_SymSetOptions generation=%llu pid=%lu tid=%lu old=0x%08lX requested=0x%08lX applied=0x%08lX local_only=%d",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		old_opts,
		opts,
		applied_opts,
		local_only_search ? 1 : 0);

	std::wstring wSearchPath = detail::utf8_to_wstr(symbol_search_path);
	uint64_t phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymInitialize_begin generation=%llu pid=%lu tid=%lu fake_proc=%p search_len=%zu",
		static_cast<unsigned long long>(parse_generation), pid, tid, hFakeProc, wSearchPath.size());
	SetLastError(ERROR_SUCCESS);
	BOOL init_ok = g_api.pSymInitializeW(hFakeProc, wSearchPath.empty() ? nullptr : wSearchPath.c_str(), FALSE);
	DWORD init_err = GetLastError();
	diag::log_tagged_fmt("pdb",
		"parse_pdb_SymInitialize_end generation=%llu pid=%lu tid=%lu ok=%d fake_proc=%p gle=%lu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		init_ok ? 1 : 0,
		hFakeProc,
		init_err,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));
	if (!init_ok) {
		char detail[512];
		std::snprintf(detail, sizeof(detail), "SymInitializeW failed with Win32 error %lu for %s", init_err, pdb_path.c_str());
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"parse_pdb_failed generation=%llu reason='SymInitializeW' path='%s' err=%lu",
			static_cast<unsigned long long>(parse_generation), pdb_path.c_str(), init_err);
		return false;
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_SymInitialize_ok generation=%llu pid=%lu tid=%lu fake_proc=%p",
		static_cast<unsigned long long>(parse_generation), pid, tid, hFakeProc);

	if (!wSearchPath.empty() && g_api.pSymSetSearchPathW) {
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_SymSetSearchPath_begin generation=%llu pid=%lu tid=%lu search_len=%zu",
			static_cast<unsigned long long>(parse_generation), pid, tid, wSearchPath.size());
		SetLastError(ERROR_SUCCESS);
		BOOL search_ok = g_api.pSymSetSearchPathW(hFakeProc, wSearchPath.c_str());
		DWORD search_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"parse_pdb_SymSetSearchPath_end generation=%llu pid=%lu tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(parse_generation),
			pid,
			tid,
			search_ok ? 1 : 0,
			search_gle,
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
	}

	std::wstring wPdbPath = detail::utf8_to_wstr(pdb_path);
	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymLoadModule_begin generation=%llu pid=%lu tid=%lu path='%s'",
		static_cast<unsigned long long>(parse_generation), pid, tid, pdb_path.c_str());
	SetLastError(ERROR_SUCCESS);
	DWORD64 modBase = g_api.pSymLoadModuleExW(hFakeProc, nullptr, wPdbPath.c_str(), nullptr,
	                                           0x10000000, 0x01000000, nullptr, 0);
	DWORD load_module_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymLoadModule_end generation=%llu pid=%lu tid=%lu modBase=0x%llX gle=%lu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		static_cast<unsigned long long>(modBase),
		load_module_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));
	if (!modBase) {
		char detail[512];
		std::snprintf(detail, sizeof(detail), "SymLoadModuleExW failed with Win32 error %lu for %s", load_module_gle, pdb_path.c_str());
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"parse_pdb_failed generation=%llu reason='SymLoadModuleExW' path='%s' err=%lu",
			static_cast<unsigned long long>(parse_generation), pdb_path.c_str(), load_module_gle);
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_after_load_failure_begin generation=%llu pid=%lu tid=%lu",
			static_cast<unsigned long long>(parse_generation), pid, tid);
		SetLastError(ERROR_SUCCESS);
		g_api.pSymCleanup(hFakeProc);
		diag::log_tagged_fmt("pdb",
			"parse_pdb_cleanup_after_load_failure_end generation=%llu pid=%lu tid=%lu gle=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(parse_generation),
			pid,
			tid,
			GetLastError(),
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
		return false;
	}

	diag::log_tagged_fmt("pdb",
		"parse_pdb_begin generation=%llu pid=%lu tid=%lu path='%s' bytes=%llu module='%s'",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		pdb_path.c_str(),
		static_cast<unsigned long long>(pdb_bytes),
		stem.c_str());

	if (progress) progress->store(0.1f);

	detail::sym_enum_ctx_t symCtx;
	symCtx.hProc = hFakeProc;
	symCtx.modBase = modBase;
	symCtx.symbols = &out.symbols;

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumSymbols_begin generation=%llu pid=%lu tid=%lu modBase=0x%llX",
		static_cast<unsigned long long>(parse_generation), pid, tid, static_cast<unsigned long long>(modBase));
	SetLastError(ERROR_SUCCESS);
	BOOL enum_symbols_ok = g_api.pSymEnumSymbolsExW(hFakeProc, modBase, L"*", detail::sym_enum_callback, &symCtx, 0);
	DWORD enum_symbols_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumSymbols_end generation=%llu pid=%lu tid=%lu ok=%d symbols=%zu gle=%lu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		enum_symbols_ok ? 1 : 0,
		out.symbols.size(),
		enum_symbols_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	if (progress) progress->store(0.4f);
	if (cancel && cancel->load()) {
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_cancel_cleanup_begin generation=%llu pid=%lu tid=%lu modBase=0x%llX",
			static_cast<unsigned long long>(parse_generation), pid, tid, static_cast<unsigned long long>(modBase));
		SetLastError(ERROR_SUCCESS);
		g_api.pSymUnloadModule64(hFakeProc, modBase);
		g_api.pSymCleanup(hFakeProc);
		diag::log_tagged_fmt("pdb", "parse_pdb_cancel_cleanup_end generation=%llu pid=%lu tid=%lu gle=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(parse_generation),
			pid,
			tid,
			GetLastError(),
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
		set_last_error_text("PDB parse was cancelled by caller");
		diag::log_tagged_fmt("pdb",
			"parse_pdb_cancelled generation=%llu path='%s' syms=%zu",
			static_cast<unsigned long long>(parse_generation), pdb_path.c_str(), out.symbols.size());
		return false;
	}

	for (size_t i = 0; i < out.symbols.size(); ++i) {
		out.symbol_by_name[out.symbols[i].name] = i;
		out.symbol_by_rva[out.symbols[i].rva] = i;
	}

	if (progress) progress->store(0.5f);

	detail::type_enum_ctx_t typeCtx;
	typeCtx.hProc = hFakeProc;
	typeCtx.modBase = modBase;

	if (g_api.pSymEnumTypesW) {
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_begin generation=%llu pid=%lu tid=%lu modBase=0x%llX",
			static_cast<unsigned long long>(parse_generation), pid, tid, static_cast<unsigned long long>(modBase));
		SetLastError(ERROR_SUCCESS);
		BOOL enum_types_ok = g_api.pSymEnumTypesW(hFakeProc, modBase, detail::type_enum_callback, &typeCtx);
		DWORD enum_types_gle = GetLastError();
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_end generation=%llu pid=%lu tid=%lu ok=%d udt=%zu enums=%zu gle=%lu elapsed_ms=%llu",
			static_cast<unsigned long long>(parse_generation),
			pid,
			tid,
			enum_types_ok ? 1 : 0,
			typeCtx.udt_indices.size(),
			typeCtx.enum_indices.size(),
			enum_types_gle,
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
	} else {
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_missing generation=%llu pid=%lu tid=%lu",
			static_cast<unsigned long long>(parse_generation), pid, tid);
	}

	if (progress) progress->store(0.6f);

	size_t total_types = typeCtx.udt_indices.size() + typeCtx.enum_indices.size();
	size_t processed = 0;

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_import_udt_begin generation=%llu pid=%lu tid=%lu total=%zu",
		static_cast<unsigned long long>(parse_generation), pid, tid, typeCtx.udt_indices.size());
	for (ULONG ti : typeCtx.udt_indices) {
		if (cancel && cancel->load()) break;

		struct_def_t def;
		def.type_index = ti;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_SYMNAME, &pName) && pName) {
			def.name = detail::wstr_to_utf8(pName);
			LocalFree(pName);
		}

		ULONG64 length = 0;
		g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_LENGTH, &length);
		def.size = length;

		DWORD udtKind = 0;
		g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_UDTKIND, &udtKind);
		def.is_union = (udtKind == 1);

		detail::import_struct_members(hFakeProc, modBase, ti, def);

		if (!def.name.empty()) {
			out.struct_by_name[def.name] = out.structs.size();
			out.struct_by_ti[def.type_index] = out.structs.size();
		}
		out.structs.push_back(std::move(def));

		++processed;
		if (progress && total_types > 0)
			progress->store(0.6f + 0.35f * (static_cast<float>(processed) / static_cast<float>(total_types)));
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_import_udt_end generation=%llu pid=%lu tid=%lu structs=%zu processed=%zu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		out.structs.size(),
		processed,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_import_enum_begin generation=%llu pid=%lu tid=%lu total=%zu",
		static_cast<unsigned long long>(parse_generation), pid, tid, typeCtx.enum_indices.size());
	for (ULONG ti : typeCtx.enum_indices) {
		if (cancel && cancel->load()) break;

		enum_def_t def;
		def.type_index = ti;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_SYMNAME, &pName) && pName) {
			def.name = detail::wstr_to_utf8(pName);
			LocalFree(pName);
		}

		detail::import_enum_members(hFakeProc, modBase, ti, def);
		out.enums.push_back(std::move(def));

		++processed;
		if (progress && total_types > 0)
			progress->store(0.6f + 0.35f * (static_cast<float>(processed) / static_cast<float>(total_types)));
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_import_enum_end generation=%llu pid=%lu tid=%lu enums=%zu processed=%zu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		out.enums.size(),
		processed,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_begin generation=%llu pid=%lu tid=%lu modBase=0x%llX",
		static_cast<unsigned long long>(parse_generation), pid, tid, static_cast<unsigned long long>(modBase));
	SetLastError(ERROR_SUCCESS);
	BOOL unload_ok = g_api.pSymUnloadModule64(hFakeProc, modBase);
	DWORD unload_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymUnloadModule_end generation=%llu pid=%lu tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		unload_ok ? 1 : 0,
		unload_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));
	phase_start = GetTickCount64();
	SetLastError(ERROR_SUCCESS);
	BOOL cleanup_ok = g_api.pSymCleanup(hFakeProc);
	DWORD cleanup_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_end generation=%llu pid=%lu tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		cleanup_ok ? 1 : 0,
		cleanup_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	out.loaded = true;
	if (progress) progress->store(1.f);
	set_last_error_text({});

	uint64_t elapsed_ms = GetTickCount64() - t_begin;
	bool cancelled = (cancel && cancel->load());
	diag::log_tagged_fmt("pdb",
		"parse_pdb_done generation=%llu pid=%lu tid=%lu path='%s' bytes=%llu syms=%zu structs=%zu enums=%zu types=%zu udt=%zu enum_total=%zu loaded=%d cancelled=%d elapsed_ms=%llu loader_state=\"%s\"",
		static_cast<unsigned long long>(parse_generation),
		pid,
		tid,
		pdb_path.c_str(),
		static_cast<unsigned long long>(pdb_bytes),
		out.symbols.size(),
		out.structs.size(),
		out.enums.size(),
		out.structs.size() + out.enums.size(),
		typeCtx.udt_indices.size(),
		typeCtx.enum_indices.size(),
		out.loaded ? 1 : 0,
		cancelled ? 1 : 0,
		static_cast<unsigned long long>(elapsed_ms),
		dbghelp_load_diagnostic().c_str());

	return true;
}

inline std::string struct_to_cpp(const struct_def_t& def)
{
	std::string out;
	out += def.is_union ? "union " : "struct ";
	out += def.name;
	out += " {\n";

	uint64_t last_end = 0;
	int pad_idx = 0;

	for (auto& m : def.members) {
		if (m.offset > last_end) {
			uint64_t gap = m.offset - last_end;
			char buf[64];
			snprintf(buf, sizeof(buf), "    uint8_t _pad%d[%llu];\n", pad_idx++,
			         static_cast<unsigned long long>(gap));
			out += buf;
		}

		if (m.bit_size >= 0) {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s : %d;\n",
			         m.type_name.c_str(), m.name.c_str(), m.bit_size);
			out += buf;
		} else if (m.is_array) {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s[%d];\n",
			         m.type_name.c_str(), m.name.c_str(), m.array_count);
			out += buf;
		} else {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s;\n",
			         m.type_name.c_str(), m.name.c_str());
			out += buf;
		}

		last_end = m.offset + m.size;
	}

	if (last_end < def.size) {
		uint64_t gap = def.size - last_end;
		char buf[64];
		snprintf(buf, sizeof(buf), "    uint8_t _pad%d[%llu];\n", pad_idx,
		         static_cast<unsigned long long>(gap));
		out += buf;
	}

	char size_comment[64];
	snprintf(size_comment, sizeof(size_comment), "}; // size: 0x%llX (%llu bytes)\n",
	         static_cast<unsigned long long>(def.size), static_cast<unsigned long long>(def.size));
	out += size_comment;
	return out;
}

}
