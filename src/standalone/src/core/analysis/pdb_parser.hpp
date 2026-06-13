#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
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
inline std::mutex g_last_error_mutex;
inline std::string g_last_error;

inline constexpr uint64_t k_dbghelp_load_watchdog_ms = 30000;

struct dbghelp_load_state_t {
	bool in_progress = false;
	bool stuck = false;
	DWORD thread_id = 0;
	uint64_t started_ms = 0;
	uint64_t attempt = 0;
	std::string path;
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

inline std::string dbghelp_wide_to_utf8(const std::wstring& value)
{
	if (value.empty()) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1) return {};
	std::string out(static_cast<size_t>(len - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), len, nullptr, nullptr);
	return out;
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

inline void log_dbghelp_prestate(DWORD tid, const std::wstring& dbghelp_path, const std::string& dbghelp_path_log)
{
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
		"load_dbghelp_prestate tid=%lu requested_path='%s' existing_hmod=%p existing_gle=%lu existing_path='%s' existing_path_len=%lu existing_path_gle=%lu attrs_ok=%d attrs=0x%08lX size=%llu attrs_gle=%lu",
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
			"DbgHelp LoadLibraryExW still has not returned after %llu ms for %s on tid %lu",
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

inline bool load_dbghelp()
{
	const DWORD tid = GetCurrentThreadId();
	uint64_t wait_start = GetTickCount64();
	const std::wstring dbghelp_path = resolve_dbghelp_path();
	const std::string dbghelp_path_log = dbghelp_wide_to_utf8(dbghelp_path);
	uint64_t attempt = 0;
	diag::log_tagged_fmt("pdb", "load_dbghelp_enter tid=%lu path='%s'", tid, dbghelp_path_log.c_str());
	log_dbghelp_prestate(tid, dbghelp_path, dbghelp_path_log);
	{
		std::unique_lock<std::mutex> lk(g_api_mutex);
		diag::log_tagged_fmt("pdb", "load_dbghelp_locked tid=%lu wait_ms=%llu cached=%d hmod=%p in_progress=%d stuck=%d owner_tid=%lu owner_elapsed_ms=%llu",
			tid,
			static_cast<unsigned long long>(GetTickCount64() - wait_start),
			g_api.loaded ? 1 : 0,
			g_api.hmod,
			g_dbghelp_load_state.in_progress ? 1 : 0,
			g_dbghelp_load_state.stuck ? 1 : 0,
			g_dbghelp_load_state.thread_id,
			g_dbghelp_load_state.in_progress ? static_cast<unsigned long long>(GetTickCount64() - g_dbghelp_load_state.started_ms) : 0ULL);
		if (g_api.loaded) {
			set_last_error_text({});
			return true;
		}
		if (g_dbghelp_load_state.in_progress) {
			const uint64_t owner_elapsed = GetTickCount64() - g_dbghelp_load_state.started_ms;
			if (owner_elapsed >= k_dbghelp_load_watchdog_ms)
				g_dbghelp_load_state.stuck = true;
			char detail[512];
			std::snprintf(detail, sizeof(detail),
				"DbgHelp loader is already %s on tid %lu for %llu ms while loading %s",
				g_dbghelp_load_state.stuck ? "stuck" : "in progress",
				g_dbghelp_load_state.thread_id,
				static_cast<unsigned long long>(owner_elapsed),
				g_dbghelp_load_state.path.c_str());
			set_last_error_text(detail);
			diag::log_tagged_fmt("pdb",
				"load_dbghelp_busy tid=%lu owner_tid=%lu owner_elapsed_ms=%llu owner_attempt=%llu stuck=%d path='%s'",
				tid,
				g_dbghelp_load_state.thread_id,
				static_cast<unsigned long long>(owner_elapsed),
				static_cast<unsigned long long>(g_dbghelp_load_state.attempt),
				g_dbghelp_load_state.stuck ? 1 : 0,
				g_dbghelp_load_state.path.c_str());
			return false;
		}
		g_dbghelp_load_state.in_progress = true;
		g_dbghelp_load_state.stuck = false;
		g_dbghelp_load_state.thread_id = tid;
		g_dbghelp_load_state.started_ms = GetTickCount64();
		g_dbghelp_load_state.path = dbghelp_path_log;
		attempt = ++g_dbghelp_load_state.attempt;
	}

	auto* watchdog_ctx = new dbghelp_load_watchdog_context_t{};
	watchdog_ctx->thread_id = tid;
	watchdog_ctx->started_ms = GetTickCount64();
	watchdog_ctx->attempt = attempt;
	watchdog_ctx->path = dbghelp_path_log;
	HANDLE watchdog_timer = nullptr;
	SetLastError(ERROR_SUCCESS);
	BOOL watchdog_ok = CreateTimerQueueTimer(&watchdog_timer, nullptr, dbghelp_load_watchdog_cb, watchdog_ctx,
		static_cast<DWORD>(k_dbghelp_load_watchdog_ms), 0, WT_EXECUTEDEFAULT);
	DWORD watchdog_gle = GetLastError();
	diag::log_tagged_fmt("pdb",
		"load_dbghelp_watchdog_schedule tid=%lu attempt=%llu ok=%d timer=%p timeout_ms=%llu gle=%lu",
		tid,
		static_cast<unsigned long long>(attempt),
		watchdog_ok ? 1 : 0,
		watchdog_timer,
		static_cast<unsigned long long>(k_dbghelp_load_watchdog_ms),
		watchdog_gle);

	const uint64_t load_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "load_dbghelp_LoadLibrary_begin tid=%lu path='%s'", tid, dbghelp_path_log.c_str());
	SetLastError(ERROR_SUCCESS);
	HMODULE loaded_hmod = LoadLibraryExW(dbghelp_path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	DWORD load_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "load_dbghelp_LoadLibrary_end tid=%lu path='%s' hmod=%p gle=%lu elapsed_ms=%llu",
		tid, dbghelp_path_log.c_str(), loaded_hmod, load_gle,
		static_cast<unsigned long long>(GetTickCount64() - load_start));
	if (watchdog_ok) {
		SetLastError(ERROR_SUCCESS);
		BOOL deleted = DeleteTimerQueueTimer(nullptr, watchdog_timer, INVALID_HANDLE_VALUE);
		DWORD delete_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_watchdog_delete tid=%lu attempt=%llu ok=%d gle=%lu",
			tid,
			static_cast<unsigned long long>(attempt),
			deleted ? 1 : 0,
			delete_gle);
	}
	delete watchdog_ctx;
	if (!loaded_hmod) {
		{
			std::lock_guard<std::mutex> lk(g_api_mutex);
			if (g_dbghelp_load_state.attempt == attempt) {
				g_dbghelp_load_state.in_progress = false;
				g_dbghelp_load_state.thread_id = 0;
			}
		}
		char detail[512];
		std::snprintf(detail, sizeof(detail), "LoadLibraryExW(%s) failed with Win32 error %lu", dbghelp_path_log.c_str(), load_gle);
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp failed reason='LoadLibraryExW' path='%s' err=%lu elapsed_ms=%llu",
			dbghelp_path_log.c_str(), load_gle,
			static_cast<unsigned long long>(GetTickCount64() - wait_start));
		return false;
	}

	dbghelp_api_t candidate{};
	candidate.hmod = loaded_hmod;
	auto gp = [&](const char* name) -> FARPROC {
		const uint64_t export_start = GetTickCount64();
		SetLastError(ERROR_SUCCESS);
		FARPROC proc = GetProcAddress(loaded_hmod, name);
		DWORD export_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"load_dbghelp_export name=%s ok=%d elapsed_ms=%llu gle=%lu",
			name,
			proc ? 1 : 0,
			static_cast<unsigned long long>(GetTickCount64() - export_start),
			export_gle);
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
	    !candidate.pSymEnumSymbolsExW || !candidate.pSymGetTypeInfo) {
		FreeLibrary(loaded_hmod);
		diag::log_tagged_fmt("pdb",
			"load_dbghelp failed reason='missing_export' init=%d cleanup=%d loadmod=%d enumsym=%d gettypeinfo=%d",
			candidate.pSymInitializeW    ? 1 : 0,
			candidate.pSymCleanup        ? 1 : 0,
			candidate.pSymLoadModuleExW  ? 1 : 0,
			candidate.pSymEnumSymbolsExW ? 1 : 0,
			candidate.pSymGetTypeInfo    ? 1 : 0);
		{
			std::lock_guard<std::mutex> lk(g_api_mutex);
			if (g_dbghelp_load_state.attempt == attempt) {
				g_dbghelp_load_state.in_progress = false;
				g_dbghelp_load_state.thread_id = 0;
			}
		}
		set_last_error_text("DbgHelp was loaded but required Sym* exports were missing");
		return false;
	}

	candidate.loaded = true;
	{
		std::lock_guard<std::mutex> lk(g_api_mutex);
		g_api = candidate;
		if (g_dbghelp_load_state.attempt == attempt) {
			g_dbghelp_load_state.in_progress = false;
			g_dbghelp_load_state.stuck = false;
			g_dbghelp_load_state.thread_id = 0;
		}
	}
	set_last_error_text({});
	diag::log_tagged_fmt("pdb", "load_dbghelp ok path='%s' elapsed_ms=%llu",
		dbghelp_path_log.c_str(),
		static_cast<unsigned long long>(GetTickCount64() - wait_start));
	return true;
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
	const DWORD tid = GetCurrentThreadId();
	uint64_t pdb_bytes = 0;
	{
		std::error_code ec;
		auto sz = std::filesystem::file_size(pdb_path, ec);
		if (!ec) pdb_bytes = static_cast<uint64_t>(sz);
	}
	diag::log_tagged_fmt("pdb",
		"parse_pdb_entry tid=%lu path='%s' bytes=%llu search_len=%zu cancel_ptr=%p",
		tid, pdb_path.c_str(), static_cast<unsigned long long>(pdb_bytes),
		symbol_search_path.size(), static_cast<void*>(cancel));
	set_last_error_text({});

	if (!load_dbghelp()) {
		const std::string detail = last_error();
		diag::log_tagged_fmt("pdb",
			"parse_pdb_failed reason='dbghelp_load' path='%s' detail='%s'",
			pdb_path.c_str(), detail.c_str());
		return false;
	}

	uint64_t dbghelp_wait_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_dbghelp_mutex_wait tid=%lu path='%s'", tid, pdb_path.c_str());
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
				"parse_pdb_failed reason='dbghelp_mutex_timeout' tid=%lu wait_ms=%llu path='%s'",
				tid,
				static_cast<unsigned long long>(waited),
				pdb_path.c_str());
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(25));
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_dbghelp_mutex_acquired tid=%lu wait_ms=%llu path='%s'",
		tid, static_cast<unsigned long long>(GetTickCount64() - dbghelp_wait_start), pdb_path.c_str());

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
		"parse_pdb_SymSetOptions tid=%lu old=0x%08lX requested=0x%08lX applied=0x%08lX local_only=%d",
		tid,
		old_opts,
		opts,
		applied_opts,
		local_only_search ? 1 : 0);

	std::wstring wSearchPath = detail::utf8_to_wstr(symbol_search_path);
	uint64_t phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymInitialize_begin tid=%lu fake_proc=%p search_len=%zu",
		tid, hFakeProc, wSearchPath.size());
	SetLastError(ERROR_SUCCESS);
	BOOL init_ok = g_api.pSymInitializeW(hFakeProc, wSearchPath.empty() ? nullptr : wSearchPath.c_str(), FALSE);
	DWORD init_err = GetLastError();
	diag::log_tagged_fmt("pdb",
		"parse_pdb_SymInitialize_end tid=%lu ok=%d fake_proc=%p gle=%lu elapsed_ms=%llu",
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
			"parse_pdb_failed reason='SymInitializeW' path='%s' err=%lu",
			pdb_path.c_str(), init_err);
		return false;
	}
	diag::log_tagged_fmt("pdb", "parse_pdb_SymInitialize_ok tid=%lu fake_proc=%p", tid, hFakeProc);

	if (!wSearchPath.empty() && g_api.pSymSetSearchPathW) {
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_SymSetSearchPath_begin tid=%lu search_len=%zu",
			tid, wSearchPath.size());
		SetLastError(ERROR_SUCCESS);
		BOOL search_ok = g_api.pSymSetSearchPathW(hFakeProc, wSearchPath.c_str());
		DWORD search_gle = GetLastError();
		diag::log_tagged_fmt("pdb",
			"parse_pdb_SymSetSearchPath_end tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
			tid,
			search_ok ? 1 : 0,
			search_gle,
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
	}

	std::wstring wPdbPath = detail::utf8_to_wstr(pdb_path);
	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymLoadModule_begin tid=%lu path='%s'", tid, pdb_path.c_str());
	SetLastError(ERROR_SUCCESS);
	DWORD64 modBase = g_api.pSymLoadModuleExW(hFakeProc, nullptr, wPdbPath.c_str(), nullptr,
	                                           0x10000000, 0x01000000, nullptr, 0);
	DWORD load_module_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymLoadModule_end tid=%lu modBase=0x%llX gle=%lu elapsed_ms=%llu",
		tid,
		static_cast<unsigned long long>(modBase),
		load_module_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));
	if (!modBase) {
		char detail[512];
		std::snprintf(detail, sizeof(detail), "SymLoadModuleExW failed with Win32 error %lu for %s", load_module_gle, pdb_path.c_str());
		set_last_error_text(detail);
		diag::log_tagged_fmt("pdb",
			"parse_pdb_failed reason='SymLoadModuleExW' path='%s' err=%lu",
			pdb_path.c_str(), load_module_gle);
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_after_load_failure_begin tid=%lu", tid);
		SetLastError(ERROR_SUCCESS);
		g_api.pSymCleanup(hFakeProc);
		diag::log_tagged_fmt("pdb",
			"parse_pdb_cleanup_after_load_failure_end tid=%lu gle=%lu elapsed_ms=%llu",
			tid,
			GetLastError(),
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
		return false;
	}

	diag::log_tagged_fmt("pdb",
		"parse_pdb_begin path='%s' bytes=%llu module='%s'",
		pdb_path.c_str(),
		static_cast<unsigned long long>(pdb_bytes),
		stem.c_str());

	if (progress) progress->store(0.1f);

	detail::sym_enum_ctx_t symCtx;
	symCtx.hProc = hFakeProc;
	symCtx.modBase = modBase;
	symCtx.symbols = &out.symbols;

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumSymbols_begin tid=%lu modBase=0x%llX",
		tid, static_cast<unsigned long long>(modBase));
	SetLastError(ERROR_SUCCESS);
	BOOL enum_symbols_ok = g_api.pSymEnumSymbolsExW(hFakeProc, modBase, L"*", detail::sym_enum_callback, &symCtx, 0);
	DWORD enum_symbols_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumSymbols_end tid=%lu ok=%d symbols=%zu gle=%lu elapsed_ms=%llu",
		tid,
		enum_symbols_ok ? 1 : 0,
		out.symbols.size(),
		enum_symbols_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	if (progress) progress->store(0.4f);
	if (cancel && cancel->load()) {
		phase_start = GetTickCount64();
		diag::log_tagged_fmt("pdb", "parse_pdb_cancel_cleanup_begin tid=%lu modBase=0x%llX",
			tid, static_cast<unsigned long long>(modBase));
		SetLastError(ERROR_SUCCESS);
		g_api.pSymUnloadModule64(hFakeProc, modBase);
		g_api.pSymCleanup(hFakeProc);
		diag::log_tagged_fmt("pdb", "parse_pdb_cancel_cleanup_end tid=%lu gle=%lu elapsed_ms=%llu",
			tid,
			GetLastError(),
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
		set_last_error_text("PDB parse was cancelled by caller");
		diag::log_tagged_fmt("pdb",
			"parse_pdb_cancelled path='%s' syms=%zu",
			pdb_path.c_str(), out.symbols.size());
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
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_begin tid=%lu modBase=0x%llX",
			tid, static_cast<unsigned long long>(modBase));
		SetLastError(ERROR_SUCCESS);
		BOOL enum_types_ok = g_api.pSymEnumTypesW(hFakeProc, modBase, detail::type_enum_callback, &typeCtx);
		DWORD enum_types_gle = GetLastError();
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_end tid=%lu ok=%d udt=%zu enums=%zu gle=%lu elapsed_ms=%llu",
			tid,
			enum_types_ok ? 1 : 0,
			typeCtx.udt_indices.size(),
			typeCtx.enum_indices.size(),
			enum_types_gle,
			static_cast<unsigned long long>(GetTickCount64() - phase_start));
	} else {
		diag::log_tagged_fmt("pdb", "parse_pdb_SymEnumTypes_missing tid=%lu", tid);
	}

	if (progress) progress->store(0.6f);

	size_t total_types = typeCtx.udt_indices.size() + typeCtx.enum_indices.size();
	size_t processed = 0;

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_import_udt_begin tid=%lu total=%zu", tid, typeCtx.udt_indices.size());
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
	diag::log_tagged_fmt("pdb", "parse_pdb_import_udt_end tid=%lu structs=%zu processed=%zu elapsed_ms=%llu",
		tid,
		out.structs.size(),
		processed,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_import_enum_begin tid=%lu total=%zu", tid, typeCtx.enum_indices.size());
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
	diag::log_tagged_fmt("pdb", "parse_pdb_import_enum_end tid=%lu enums=%zu processed=%zu elapsed_ms=%llu",
		tid,
		out.enums.size(),
		processed,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));

	phase_start = GetTickCount64();
	diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_begin tid=%lu modBase=0x%llX", tid, static_cast<unsigned long long>(modBase));
	SetLastError(ERROR_SUCCESS);
	BOOL unload_ok = g_api.pSymUnloadModule64(hFakeProc, modBase);
	DWORD unload_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_SymUnloadModule_end tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
		tid,
		unload_ok ? 1 : 0,
		unload_gle,
		static_cast<unsigned long long>(GetTickCount64() - phase_start));
	phase_start = GetTickCount64();
	SetLastError(ERROR_SUCCESS);
	BOOL cleanup_ok = g_api.pSymCleanup(hFakeProc);
	DWORD cleanup_gle = GetLastError();
	diag::log_tagged_fmt("pdb", "parse_pdb_cleanup_end tid=%lu ok=%d gle=%lu elapsed_ms=%llu",
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
		"parse_pdb_done path='%s' bytes=%llu syms=%zu structs=%zu enums=%zu udt=%zu enum_total=%zu cancelled=%d elapsed_ms=%llu",
		pdb_path.c_str(),
		static_cast<unsigned long long>(pdb_bytes),
		out.symbols.size(),
		out.structs.size(),
		out.enums.size(),
		typeCtx.udt_indices.size(),
		typeCtx.enum_indices.size(),
		cancelled ? 1 : 0,
		static_cast<unsigned long long>(elapsed_ms));

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
