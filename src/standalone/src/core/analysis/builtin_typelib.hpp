#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace builtin_typelib {

using entry_t = std::pair<uint64_t, const char*>;

inline constexpr std::array<entry_t, 73> kNtstatusTable = {{
	{ 0x00000000ull, "STATUS_SUCCESS" },
	{ 0x40000005ull, "STATUS_BUFFER_OVERFLOW" },
	{ 0x4000000Aull, "STATUS_LOCAL_USER_SESSION_KEY" },
	{ 0x40000016ull, "STATUS_NOTIFY_CLEANUP" },
	{ 0x80000001ull, "STATUS_GUARD_PAGE_VIOLATION" },
	{ 0x80000002ull, "STATUS_DATATYPE_MISALIGNMENT" },
	{ 0x80000003ull, "STATUS_BREAKPOINT" },
	{ 0x80000004ull, "STATUS_SINGLE_STEP" },
	{ 0x80000005ull, "STATUS_BUFFER_OVERFLOW_INFO" },
	{ 0x80000006ull, "STATUS_NO_MORE_FILES" },
	{ 0x80000007ull, "STATUS_WAKE_SYSTEM_DEBUGGER" },
	{ 0xC0000001ull, "STATUS_UNSUCCESSFUL" },
	{ 0xC0000002ull, "STATUS_NOT_IMPLEMENTED" },
	{ 0xC0000003ull, "STATUS_INVALID_INFO_CLASS" },
	{ 0xC0000004ull, "STATUS_INFO_LENGTH_MISMATCH" },
	{ 0xC0000005ull, "STATUS_ACCESS_VIOLATION" },
	{ 0xC0000006ull, "STATUS_IN_PAGE_ERROR" },
	{ 0xC0000007ull, "STATUS_PAGEFILE_QUOTA" },
	{ 0xC0000008ull, "STATUS_INVALID_HANDLE" },
	{ 0xC0000009ull, "STATUS_BAD_INITIAL_STACK" },
	{ 0xC000000Aull, "STATUS_BAD_INITIAL_PC" },
	{ 0xC000000Bull, "STATUS_INVALID_CID" },
	{ 0xC000000Dull, "STATUS_INVALID_PARAMETER" },
	{ 0xC000000Eull, "STATUS_NO_SUCH_DEVICE" },
	{ 0xC000000Full, "STATUS_NO_SUCH_FILE" },
	{ 0xC0000010ull, "STATUS_INVALID_DEVICE_REQUEST" },
	{ 0xC0000011ull, "STATUS_END_OF_FILE" },
	{ 0xC0000012ull, "STATUS_WRONG_VOLUME" },
	{ 0xC0000013ull, "STATUS_NO_MEDIA_IN_DEVICE" },
	{ 0xC0000016ull, "STATUS_MORE_PROCESSING_REQUIRED" },
	{ 0xC0000017ull, "STATUS_NO_MEMORY" },
	{ 0xC0000018ull, "STATUS_CONFLICTING_ADDRESSES" },
	{ 0xC000001Cull, "STATUS_ILLEGAL_INSTRUCTION" },
	{ 0xC000001Dull, "STATUS_NONCONTINUABLE_EXCEPTION" },
	{ 0xC000001Eull, "STATUS_INVALID_DISPOSITION" },
	{ 0xC0000022ull, "STATUS_ACCESS_DENIED" },
	{ 0xC0000023ull, "STATUS_BUFFER_TOO_SMALL" },
	{ 0xC0000024ull, "STATUS_OBJECT_TYPE_MISMATCH" },
	{ 0xC0000025ull, "STATUS_NONCONTINUABLE" },
	{ 0xC0000026ull, "STATUS_INVALID_DISPOSITION_FAULT" },
	{ 0xC000002Cull, "STATUS_PORT_ALREADY_SET" },
	{ 0xC000003Aull, "STATUS_OBJECT_PATH_NOT_FOUND" },
	{ 0xC000003Bull, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
	{ 0xC000003Cull, "STATUS_DATA_OVERRUN" },
	{ 0xC0000034ull, "STATUS_OBJECT_NAME_NOT_FOUND" },
	{ 0xC0000035ull, "STATUS_OBJECT_NAME_COLLISION" },
	{ 0xC0000043ull, "STATUS_SHARING_VIOLATION" },
	{ 0xC0000044ull, "STATUS_QUOTA_EXCEEDED" },
	{ 0xC0000054ull, "STATUS_FILE_LOCK_CONFLICT" },
	{ 0xC0000055ull, "STATUS_LOCK_NOT_GRANTED" },
	{ 0xC0000056ull, "STATUS_DELETE_PENDING" },
	{ 0xC000005Aull, "STATUS_INVALID_OWNER" },
	{ 0xC000005Cull, "STATUS_NO_LOGON_SERVERS" },
	{ 0xC000006Dull, "STATUS_LOGON_FAILURE" },
	{ 0xC000006Eull, "STATUS_ACCOUNT_RESTRICTION" },
	{ 0xC0000071ull, "STATUS_PASSWORD_EXPIRED" },
	{ 0xC0000072ull, "STATUS_ACCOUNT_DISABLED" },
	{ 0xC000007Aull, "STATUS_PROCEDURE_NOT_FOUND" },
	{ 0xC000007Bull, "STATUS_INVALID_IMAGE_FORMAT" },
	{ 0xC0000094ull, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
	{ 0xC0000095ull, "STATUS_INTEGER_OVERFLOW" },
	{ 0xC0000096ull, "STATUS_PRIVILEGED_INSTRUCTION" },
	{ 0xC0000098ull, "STATUS_FILE_INVALID" },
	{ 0xC00000BAull, "STATUS_FILE_IS_A_DIRECTORY" },
	{ 0xC00000BBull, "STATUS_NOT_SUPPORTED" },
	{ 0xC00000FDull, "STATUS_STACK_OVERFLOW" },
	{ 0xC0000120ull, "STATUS_CANCELLED" },
	{ 0xC0000135ull, "STATUS_DLL_NOT_FOUND" },
	{ 0xC0000139ull, "STATUS_ENTRYPOINT_NOT_FOUND" },
	{ 0xC000013Aull, "STATUS_CONTROL_C_EXIT" },
	{ 0xC0000142ull, "STATUS_DLL_INIT_FAILED" },
	{ 0xC0000409ull, "STATUS_STACK_BUFFER_OVERRUN" },
	{ 0xC0000417ull, "STATUS_INVALID_CRUNTIME_PARAMETER" },
}};

inline constexpr std::array<entry_t, 44> kHresultTable = {{
	{ 0x00000000ull, "S_OK" },
	{ 0x00000001ull, "S_FALSE" },
	{ 0x80004001ull, "E_NOTIMPL" },
	{ 0x80004002ull, "E_NOINTERFACE" },
	{ 0x80004003ull, "E_POINTER" },
	{ 0x80004004ull, "E_ABORT" },
	{ 0x80004005ull, "E_FAIL" },
	{ 0x8000FFFFull, "E_UNEXPECTED" },
	{ 0x80070005ull, "E_ACCESSDENIED" },
	{ 0x80070006ull, "E_HANDLE" },
	{ 0x8007000Eull, "E_OUTOFMEMORY" },
	{ 0x80070057ull, "E_INVALIDARG" },
	{ 0x80030002ull, "STG_E_FILENOTFOUND" },
	{ 0x80030003ull, "STG_E_PATHNOTFOUND" },
	{ 0x80030004ull, "STG_E_TOOMANYOPENFILES" },
	{ 0x80030005ull, "STG_E_ACCESSDENIED" },
	{ 0x80030008ull, "STG_E_INSUFFICIENTMEMORY" },
	{ 0x80030012ull, "STG_E_NOMOREFILES" },
	{ 0x8002000Aull, "DISP_E_OVERFLOW" },
	{ 0x8002000Eull, "DISP_E_BADPARAMCOUNT" },
	{ 0x80020005ull, "DISP_E_TYPEMISMATCH" },
	{ 0x80040154ull, "REGDB_E_CLASSNOTREG" },
	{ 0x80040155ull, "REGDB_E_IIDNOTREG" },
	{ 0x800401F0ull, "CO_E_NOTINITIALIZED" },
	{ 0x800401F3ull, "CO_E_CLASSSTRING" },
	{ 0x80010001ull, "RPC_E_CALL_REJECTED" },
	{ 0x80010002ull, "RPC_E_CALL_CANCELED" },
	{ 0x80010108ull, "RPC_E_DISCONNECTED" },
	{ 0x80010109ull, "RPC_E_SERVER_DIED" },
	{ 0x80010100ull, "RPC_E_TIMEOUT" },
	{ 0x80010106ull, "RPC_E_CANTCALLOUT_ININPUTSYNCCALL" },
	{ 0x80010107ull, "RPC_E_WRONG_THREAD" },
	{ 0x800706BAull, "HRESULT_RPC_S_SERVER_UNAVAILABLE" },
	{ 0x800706BEull, "HRESULT_RPC_S_CALL_FAILED" },
	{ 0x800706F7ull, "HRESULT_RPC_X_BAD_STUB_DATA" },
	{ 0x80070103ull, "HRESULT_NO_MORE_ITEMS" },
	{ 0x800B0100ull, "TRUST_E_NOSIGNATURE" },
	{ 0x800B0101ull, "CERT_E_EXPIRED" },
	{ 0x800B0109ull, "CERT_E_UNTRUSTEDROOT" },
	{ 0x80092004ull, "CRYPT_E_NOT_FOUND" },
	{ 0x80090016ull, "NTE_BAD_KEYSET" },
	{ 0x80090005ull, "NTE_BAD_DATA" },
	{ 0x8009000Bull, "NTE_BAD_KEY_STATE" },
	{ 0x80090029ull, "NTE_NOT_SUPPORTED" },
}};

inline constexpr std::array<entry_t, 1> kWaitResultTable = {{
	{ 0xFFFFFFFFFFFFFFFFull, "INFINITE" },
}};

namespace detail {

inline bool find_in_table_u32(const entry_t* table, size_t count, uint64_t value, std::string& out_label) {
	const uint32_t v32 = static_cast<uint32_t>(value);
	for (size_t i = 0; i < count; ++i) {
		if (static_cast<uint32_t>(table[i].first) == v32) {
			out_label.assign(table[i].second);
			return true;
		}
	}
	return false;
}

inline bool find_in_table_u64(const entry_t* table, size_t count, uint64_t value, std::string& out_label) {
	for (size_t i = 0; i < count; ++i) {
		if (table[i].first == value) {
			out_label.assign(table[i].second);
			return true;
		}
	}
	return false;
}

inline bool ieq(std::string_view a, std::string_view b) {
	if (a.size() != b.size())
		return false;
	for (size_t i = 0; i < a.size(); ++i) {
		char ca = a[i];
		char cb = b[i];
		if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca + 32);
		if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb + 32);
		if (ca != cb)
			return false;
	}
	return true;
}

}

inline bool looks_like_status(uint64_t value) {
	if (value == 0xFFFFFFFFFFFFFFFFull)
		return true;
	const uint32_t v32 = static_cast<uint32_t>(value);
	if (v32 == 0)
		return false;
	const uint32_t hi = v32 & 0xFF000000u;
	if (hi == 0xC0000000u || hi == 0x80000000u || hi == 0x40000000u)
		return true;
	const uint32_t hi16 = v32 & 0xFFFF0000u;
	if (hi16 == 0x80070000u || hi16 == 0x80040000u || hi16 == 0x80030000u || hi16 == 0x80020000u ||
		hi16 == 0x80010000u || hi16 == 0x80004000u || hi16 == 0x80090000u || hi16 == 0x800B0000u ||
		hi16 == 0x80092000u)
		return true;
	return false;
}

inline bool lookup_with_hint(std::string_view hint, uint64_t value, std::string& out_label) {
	if (detail::ieq(hint, "NTSTATUS"))
		return detail::find_in_table_u32(kNtstatusTable.data(), kNtstatusTable.size(), value, out_label);
	if (detail::ieq(hint, "HRESULT"))
		return detail::find_in_table_u32(kHresultTable.data(), kHresultTable.size(), value, out_label);
	if (detail::ieq(hint, "WIN32_ERROR") || detail::ieq(hint, "WIN32") || detail::ieq(hint, "LASTERROR"))
		return false;
	if (detail::ieq(hint, "WAIT_RESULT") || detail::ieq(hint, "WAIT"))
		return detail::find_in_table_u64(kWaitResultTable.data(), kWaitResultTable.size(), value, out_label);
	return false;
}

inline bool lookup_auto(uint64_t value, std::string& out_label) {
	if (value == 0xFFFFFFFFFFFFFFFFull) {
		out_label.assign("INFINITE");
		return true;
	}

	const uint32_t v32 = static_cast<uint32_t>(value);
	const uint32_t hi = v32 & 0xFF000000u;

	if (hi == 0xC0000000u || hi == 0x80000000u || hi == 0x40000000u) {
		if (detail::find_in_table_u32(kNtstatusTable.data(), kNtstatusTable.size(), value, out_label))
			return true;
		if (detail::find_in_table_u32(kHresultTable.data(), kHresultTable.size(), value, out_label))
			return true;
	}

	const uint32_t hi16 = v32 & 0xFFFF0000u;
	if (hi16 == 0x80070000u || hi16 == 0x80040000u || hi16 == 0x80030000u || hi16 == 0x80020000u ||
		hi16 == 0x80010000u || hi16 == 0x80004000u || hi16 == 0x80090000u || hi16 == 0x800B0000u ||
		hi16 == 0x80092000u) {
		if (detail::find_in_table_u32(kHresultTable.data(), kHresultTable.size(), value, out_label))
			return true;
	}

	return false;
}

struct member_desc_t {
	const char* name;
	const char* type_name;
	uint32_t    offset;
	uint32_t    size;
	bool        is_pointer;
	bool        is_array;
	int         array_count;
};

struct struct_desc_t {
	const char*         name;
	const char*         lib;
	uint32_t            size;
	bool                is_union;
	const member_desc_t* members;
	size_t              member_count;
};

struct enum_value_desc_t {
	const char* name;
	int64_t     value;
};

struct enum_desc_t {
	const char*               name;
	const char*               lib;
	const enum_value_desc_t*  values;
	size_t                    value_count;
};

struct typedef_desc_t {
	const char* name;
	const char* target;
	const char* lib;
	uint32_t    size;
};

inline constexpr member_desc_t kMembers_POINT[] = {
	{ "x", "LONG", 0, 4, false, false, 0 },
	{ "y", "LONG", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_POINTL[] = {
	{ "x", "LONG", 0, 4, false, false, 0 },
	{ "y", "LONG", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_SIZE[] = {
	{ "cx", "LONG", 0, 4, false, false, 0 },
	{ "cy", "LONG", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_RECT[] = {
	{ "left",   "LONG", 0,  4, false, false, 0 },
	{ "top",    "LONG", 4,  4, false, false, 0 },
	{ "right",  "LONG", 8,  4, false, false, 0 },
	{ "bottom", "LONG", 12, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_FILETIME[] = {
	{ "dwLowDateTime",  "DWORD", 0, 4, false, false, 0 },
	{ "dwHighDateTime", "DWORD", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_LARGE_INTEGER[] = {
	{ "LowPart",  "DWORD", 0, 4, false, false, 0 },
	{ "HighPart", "LONG",  4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_ULARGE_INTEGER[] = {
	{ "LowPart",  "DWORD", 0, 4, false, false, 0 },
	{ "HighPart", "DWORD", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_SYSTEMTIME[] = {
	{ "wYear",         "WORD", 0,  2, false, false, 0 },
	{ "wMonth",        "WORD", 2,  2, false, false, 0 },
	{ "wDayOfWeek",    "WORD", 4,  2, false, false, 0 },
	{ "wDay",          "WORD", 6,  2, false, false, 0 },
	{ "wHour",         "WORD", 8,  2, false, false, 0 },
	{ "wMinute",       "WORD", 10, 2, false, false, 0 },
	{ "wSecond",       "WORD", 12, 2, false, false, 0 },
	{ "wMilliseconds", "WORD", 14, 2, false, false, 0 },
};
inline constexpr member_desc_t kMembers_GUID[] = {
	{ "Data1", "unsigned long",  0,  4, false, false,  0 },
	{ "Data2", "unsigned short", 4,  2, false, false,  0 },
	{ "Data3", "unsigned short", 6,  2, false, false,  0 },
	{ "Data4", "unsigned char",  8,  8, false, true,   8 },
};
inline constexpr member_desc_t kMembers_LIST_ENTRY[] = {
	{ "Flink", "LIST_ENTRY *", 0, 8, true, false, 0 },
	{ "Blink", "LIST_ENTRY *", 8, 8, true, false, 0 },
};
inline constexpr member_desc_t kMembers_UNICODE_STRING[] = {
	{ "Length",        "USHORT",  0,  2, false, false, 0 },
	{ "MaximumLength", "USHORT",  2,  2, false, false, 0 },
	{ "Buffer",        "WCHAR *", 8,  8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_ANSI_STRING[] = {
	{ "Length",        "USHORT", 0,  2, false, false, 0 },
	{ "MaximumLength", "USHORT", 2,  2, false, false, 0 },
	{ "Buffer",        "PCHAR",  8,  8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_OBJECT_ATTRIBUTES[] = {
	{ "Length",                   "ULONG",            0,  4, false, false, 0 },
	{ "RootDirectory",            "HANDLE",           8,  8, true,  false, 0 },
	{ "ObjectName",               "PUNICODE_STRING",  16, 8, true,  false, 0 },
	{ "Attributes",               "ULONG",            24, 4, false, false, 0 },
	{ "SecurityDescriptor",       "PVOID",            32, 8, true,  false, 0 },
	{ "SecurityQualityOfService", "PVOID",            40, 8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_IO_STATUS_BLOCK[] = {
	{ "Status",      "NTSTATUS",  0, 4, false, false, 0 },
	{ "Information", "ULONG_PTR", 8, 8, false, false, 0 },
};
inline constexpr member_desc_t kMembers_PROCESS_INFORMATION[] = {
	{ "hProcess",    "HANDLE", 0,  8, true,  false, 0 },
	{ "hThread",     "HANDLE", 8,  8, true,  false, 0 },
	{ "dwProcessId", "DWORD",  16, 4, false, false, 0 },
	{ "dwThreadId",  "DWORD",  20, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_SECURITY_ATTRIBUTES[] = {
	{ "nLength",              "DWORD", 0, 4, false, false, 0 },
	{ "lpSecurityDescriptor", "LPVOID", 8, 8, true,  false, 0 },
	{ "bInheritHandle",       "BOOL",  16, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_OVERLAPPED[] = {
	{ "Internal",     "ULONG_PTR", 0,  8, false, false, 0 },
	{ "InternalHigh", "ULONG_PTR", 8,  8, false, false, 0 },
	{ "Offset",       "DWORD",     16, 4, false, false, 0 },
	{ "OffsetHigh",   "DWORD",     20, 4, false, false, 0 },
	{ "hEvent",       "HANDLE",    24, 8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_STARTUPINFOW[] = {
	{ "cb",              "DWORD",   0,  4, false, false, 0 },
	{ "lpReserved",      "LPWSTR",  8,  8, true,  false, 0 },
	{ "lpDesktop",       "LPWSTR",  16, 8, true,  false, 0 },
	{ "lpTitle",         "LPWSTR",  24, 8, true,  false, 0 },
	{ "dwX",             "DWORD",   32, 4, false, false, 0 },
	{ "dwY",             "DWORD",   36, 4, false, false, 0 },
	{ "dwXSize",         "DWORD",   40, 4, false, false, 0 },
	{ "dwYSize",         "DWORD",   44, 4, false, false, 0 },
	{ "dwXCountChars",   "DWORD",   48, 4, false, false, 0 },
	{ "dwYCountChars",   "DWORD",   52, 4, false, false, 0 },
	{ "dwFillAttribute", "DWORD",   56, 4, false, false, 0 },
	{ "dwFlags",         "DWORD",   60, 4, false, false, 0 },
	{ "wShowWindow",     "WORD",    64, 2, false, false, 0 },
	{ "cbReserved2",     "WORD",    66, 2, false, false, 0 },
	{ "lpReserved2",     "LPBYTE",  72, 8, true,  false, 0 },
	{ "hStdInput",       "HANDLE",  80, 8, true,  false, 0 },
	{ "hStdOutput",      "HANDLE",  88, 8, true,  false, 0 },
	{ "hStdError",       "HANDLE",  96, 8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_MEMORY_BASIC_INFORMATION[] = {
	{ "BaseAddress",       "PVOID",  0,  8, true,  false, 0 },
	{ "AllocationBase",    "PVOID",  8,  8, true,  false, 0 },
	{ "AllocationProtect", "DWORD",  16, 4, false, false, 0 },
	{ "PartitionId",       "WORD",   20, 2, false, false, 0 },
	{ "RegionSize",        "SIZE_T", 24, 8, false, false, 0 },
	{ "State",             "DWORD",  32, 4, false, false, 0 },
	{ "Protect",           "DWORD",  36, 4, false, false, 0 },
	{ "Type",              "DWORD",  40, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_MODULEENTRY32W[] = {
	{ "dwSize",        "DWORD",   0,    4,   false, false, 0 },
	{ "th32ModuleID",  "DWORD",   4,    4,   false, false, 0 },
	{ "th32ProcessID", "DWORD",   8,    4,   false, false, 0 },
	{ "GlblcntUsage",  "DWORD",   12,   4,   false, false, 0 },
	{ "ProccntUsage",  "DWORD",   16,   4,   false, false, 0 },
	{ "modBaseAddr",   "BYTE *",  24,   8,   true,  false, 0 },
	{ "modBaseSize",   "DWORD",   32,   4,   false, false, 0 },
	{ "hModule",       "HMODULE", 40,   8,   true,  false, 0 },
	{ "szModule",      "WCHAR",   48,   512, false, true,  256 },
	{ "szExePath",     "WCHAR",   560,  520, false, true,  260 },
};
inline constexpr member_desc_t kMembers_CONTEXT_X64[] = {
	{ "P1Home",            "DWORD64",   0,   8, false, false, 0 },
	{ "P2Home",            "DWORD64",   8,   8, false, false, 0 },
	{ "P3Home",            "DWORD64",   16,  8, false, false, 0 },
	{ "P4Home",            "DWORD64",   24,  8, false, false, 0 },
	{ "P5Home",            "DWORD64",   32,  8, false, false, 0 },
	{ "P6Home",            "DWORD64",   40,  8, false, false, 0 },
	{ "ContextFlags",      "DWORD",     48,  4, false, false, 0 },
	{ "MxCsr",             "DWORD",     52,  4, false, false, 0 },
	{ "SegCs",             "WORD",      56,  2, false, false, 0 },
	{ "SegDs",             "WORD",      58,  2, false, false, 0 },
	{ "SegEs",             "WORD",      60,  2, false, false, 0 },
	{ "SegFs",             "WORD",      62,  2, false, false, 0 },
	{ "SegGs",             "WORD",      64,  2, false, false, 0 },
	{ "SegSs",             "WORD",      66,  2, false, false, 0 },
	{ "EFlags",            "DWORD",     68,  4, false, false, 0 },
	{ "Dr0",               "DWORD64",   72,  8, false, false, 0 },
	{ "Dr1",               "DWORD64",   80,  8, false, false, 0 },
	{ "Dr2",               "DWORD64",   88,  8, false, false, 0 },
	{ "Dr3",               "DWORD64",   96,  8, false, false, 0 },
	{ "Dr6",               "DWORD64",   104, 8, false, false, 0 },
	{ "Dr7",               "DWORD64",   112, 8, false, false, 0 },
	{ "Rax",               "DWORD64",   120, 8, false, false, 0 },
	{ "Rcx",               "DWORD64",   128, 8, false, false, 0 },
	{ "Rdx",               "DWORD64",   136, 8, false, false, 0 },
	{ "Rbx",               "DWORD64",   144, 8, false, false, 0 },
	{ "Rsp",               "DWORD64",   152, 8, false, false, 0 },
	{ "Rbp",               "DWORD64",   160, 8, false, false, 0 },
	{ "Rsi",               "DWORD64",   168, 8, false, false, 0 },
	{ "Rdi",               "DWORD64",   176, 8, false, false, 0 },
	{ "R8",                "DWORD64",   184, 8, false, false, 0 },
	{ "R9",                "DWORD64",   192, 8, false, false, 0 },
	{ "R10",               "DWORD64",   200, 8, false, false, 0 },
	{ "R11",               "DWORD64",   208, 8, false, false, 0 },
	{ "R12",               "DWORD64",   216, 8, false, false, 0 },
	{ "R13",               "DWORD64",   224, 8, false, false, 0 },
	{ "R14",               "DWORD64",   232, 8, false, false, 0 },
	{ "R15",               "DWORD64",   240, 8, false, false, 0 },
	{ "Rip",               "DWORD64",   248, 8, false, false, 0 },
};
inline constexpr member_desc_t kMembers_EXCEPTION_RECORD[] = {
	{ "ExceptionCode",        "DWORD",                0,  4, false, false, 0  },
	{ "ExceptionFlags",       "DWORD",                4,  4, false, false, 0  },
	{ "ExceptionRecord",      "EXCEPTION_RECORD *",   8,  8, true,  false, 0  },
	{ "ExceptionAddress",     "PVOID",                16, 8, true,  false, 0  },
	{ "NumberParameters",     "DWORD",                24, 4, false, false, 0  },
	{ "ExceptionInformation", "ULONG_PTR",            32, 120, false, true, 15 },
};
inline constexpr member_desc_t kMembers_TEB_PARTIAL[] = {
	{ "NtTib",                       "NT_TIB",      0,   56, false, false, 0 },
	{ "EnvironmentPointer",          "PVOID",       56,  8,  true,  false, 0 },
	{ "ClientId_UniqueProcess",      "HANDLE",      64,  8,  true,  false, 0 },
	{ "ClientId_UniqueThread",       "HANDLE",      72,  8,  true,  false, 0 },
	{ "ActiveRpcHandle",             "PVOID",       80,  8,  true,  false, 0 },
	{ "ThreadLocalStoragePointer",   "PVOID",       88,  8,  true,  false, 0 },
	{ "ProcessEnvironmentBlock",     "PPEB",        96,  8,  true,  false, 0 },
	{ "LastErrorValue",              "ULONG",       104, 4,  false, false, 0 },
};
inline constexpr member_desc_t kMembers_PEB_PARTIAL[] = {
	{ "InheritedAddressSpace",    "BOOLEAN",       0,  1, false, false, 0 },
	{ "ReadImageFileExecOptions", "BOOLEAN",       1,  1, false, false, 0 },
	{ "BeingDebugged",            "BOOLEAN",       2,  1, false, false, 0 },
	{ "BitField",                 "BOOLEAN",       3,  1, false, false, 0 },
	{ "Mutant",                   "HANDLE",        8,  8, true,  false, 0 },
	{ "ImageBaseAddress",         "PVOID",         16, 8, true,  false, 0 },
	{ "Ldr",                      "PPEB_LDR_DATA", 24, 8, true,  false, 0 },
	{ "ProcessParameters",        "PVOID",         32, 8, true,  false, 0 },
};
inline constexpr member_desc_t kMembers_IMAGE_DOS_HEADER[] = {
	{ "e_magic",    "WORD", 0,  2,  false, false, 0  },
	{ "e_cblp",     "WORD", 2,  2,  false, false, 0  },
	{ "e_cp",       "WORD", 4,  2,  false, false, 0  },
	{ "e_crlc",     "WORD", 6,  2,  false, false, 0  },
	{ "e_cparhdr",  "WORD", 8,  2,  false, false, 0  },
	{ "e_minalloc", "WORD", 10, 2,  false, false, 0  },
	{ "e_maxalloc", "WORD", 12, 2,  false, false, 0  },
	{ "e_ss",       "WORD", 14, 2,  false, false, 0  },
	{ "e_sp",       "WORD", 16, 2,  false, false, 0  },
	{ "e_csum",     "WORD", 18, 2,  false, false, 0  },
	{ "e_ip",       "WORD", 20, 2,  false, false, 0  },
	{ "e_cs",       "WORD", 22, 2,  false, false, 0  },
	{ "e_lfarlc",   "WORD", 24, 2,  false, false, 0  },
	{ "e_ovno",     "WORD", 26, 2,  false, false, 0  },
	{ "e_res",      "WORD", 28, 8,  false, true,  4  },
	{ "e_oemid",    "WORD", 36, 2,  false, false, 0  },
	{ "e_oeminfo",  "WORD", 38, 2,  false, false, 0  },
	{ "e_res2",     "WORD", 40, 20, false, true,  10 },
	{ "e_lfanew",   "LONG", 60, 4,  false, false, 0  },
};
inline constexpr member_desc_t kMembers_IMAGE_FILE_HEADER[] = {
	{ "Machine",              "WORD",  0,  2, false, false, 0 },
	{ "NumberOfSections",     "WORD",  2,  2, false, false, 0 },
	{ "TimeDateStamp",        "DWORD", 4,  4, false, false, 0 },
	{ "PointerToSymbolTable", "DWORD", 8,  4, false, false, 0 },
	{ "NumberOfSymbols",      "DWORD", 12, 4, false, false, 0 },
	{ "SizeOfOptionalHeader", "WORD",  16, 2, false, false, 0 },
	{ "Characteristics",      "WORD",  18, 2, false, false, 0 },
};
inline constexpr member_desc_t kMembers_IMAGE_DATA_DIRECTORY[] = {
	{ "VirtualAddress", "DWORD", 0, 4, false, false, 0 },
	{ "Size",           "DWORD", 4, 4, false, false, 0 },
};
inline constexpr member_desc_t kMembers_IMAGE_SECTION_HEADER[] = {
	{ "Name",                 "BYTE",  0,  8, false, true,  8 },
	{ "VirtualSize",          "DWORD", 8,  4, false, false, 0 },
	{ "VirtualAddress",       "DWORD", 12, 4, false, false, 0 },
	{ "SizeOfRawData",        "DWORD", 16, 4, false, false, 0 },
	{ "PointerToRawData",     "DWORD", 20, 4, false, false, 0 },
	{ "PointerToRelocations", "DWORD", 24, 4, false, false, 0 },
	{ "PointerToLinenumbers", "DWORD", 28, 4, false, false, 0 },
	{ "NumberOfRelocations",  "WORD",  32, 2, false, false, 0 },
	{ "NumberOfLinenumbers",  "WORD",  34, 2, false, false, 0 },
	{ "Characteristics",      "DWORD", 36, 4, false, false, 0 },
};

inline constexpr struct_desc_t kBuiltinStructs[] = {
	{ "POINT",                       "mssdk",  8,    false, kMembers_POINT,                       sizeof(kMembers_POINT) / sizeof(kMembers_POINT[0])                       },
	{ "POINTL",                      "mssdk",  8,    false, kMembers_POINTL,                      sizeof(kMembers_POINTL) / sizeof(kMembers_POINTL[0])                     },
	{ "SIZE",                        "mssdk",  8,    false, kMembers_SIZE,                        sizeof(kMembers_SIZE) / sizeof(kMembers_SIZE[0])                         },
	{ "RECT",                        "mssdk",  16,   false, kMembers_RECT,                        sizeof(kMembers_RECT) / sizeof(kMembers_RECT[0])                         },
	{ "FILETIME",                    "mssdk",  8,    false, kMembers_FILETIME,                    sizeof(kMembers_FILETIME) / sizeof(kMembers_FILETIME[0])                 },
	{ "LARGE_INTEGER",               "mssdk",  8,    false, kMembers_LARGE_INTEGER,               sizeof(kMembers_LARGE_INTEGER) / sizeof(kMembers_LARGE_INTEGER[0])       },
	{ "ULARGE_INTEGER",              "mssdk",  8,    false, kMembers_ULARGE_INTEGER,              sizeof(kMembers_ULARGE_INTEGER) / sizeof(kMembers_ULARGE_INTEGER[0])     },
	{ "SYSTEMTIME",                  "mssdk",  16,   false, kMembers_SYSTEMTIME,                  sizeof(kMembers_SYSTEMTIME) / sizeof(kMembers_SYSTEMTIME[0])             },
	{ "GUID",                        "mssdk",  16,   false, kMembers_GUID,                        sizeof(kMembers_GUID) / sizeof(kMembers_GUID[0])                         },
	{ "LIST_ENTRY",                  "ntddk",  16,   false, kMembers_LIST_ENTRY,                  sizeof(kMembers_LIST_ENTRY) / sizeof(kMembers_LIST_ENTRY[0])             },
	{ "UNICODE_STRING",              "ntddk",  16,   false, kMembers_UNICODE_STRING,              sizeof(kMembers_UNICODE_STRING) / sizeof(kMembers_UNICODE_STRING[0])     },
	{ "ANSI_STRING",                 "ntddk",  16,   false, kMembers_ANSI_STRING,                 sizeof(kMembers_ANSI_STRING) / sizeof(kMembers_ANSI_STRING[0])           },
	{ "OBJECT_ATTRIBUTES",           "ntddk",  48,   false, kMembers_OBJECT_ATTRIBUTES,           sizeof(kMembers_OBJECT_ATTRIBUTES) / sizeof(kMembers_OBJECT_ATTRIBUTES[0]) },
	{ "IO_STATUS_BLOCK",             "ntddk",  16,   false, kMembers_IO_STATUS_BLOCK,             sizeof(kMembers_IO_STATUS_BLOCK) / sizeof(kMembers_IO_STATUS_BLOCK[0])   },
	{ "PROCESS_INFORMATION",         "mssdk",  24,   false, kMembers_PROCESS_INFORMATION,         sizeof(kMembers_PROCESS_INFORMATION) / sizeof(kMembers_PROCESS_INFORMATION[0]) },
	{ "SECURITY_ATTRIBUTES",         "mssdk",  24,   false, kMembers_SECURITY_ATTRIBUTES,         sizeof(kMembers_SECURITY_ATTRIBUTES) / sizeof(kMembers_SECURITY_ATTRIBUTES[0]) },
	{ "OVERLAPPED",                  "mssdk",  32,   false, kMembers_OVERLAPPED,                  sizeof(kMembers_OVERLAPPED) / sizeof(kMembers_OVERLAPPED[0])             },
	{ "STARTUPINFOW",                "mssdk",  104,  false, kMembers_STARTUPINFOW,                sizeof(kMembers_STARTUPINFOW) / sizeof(kMembers_STARTUPINFOW[0])         },
	{ "MEMORY_BASIC_INFORMATION",    "mssdk",  48,   false, kMembers_MEMORY_BASIC_INFORMATION,    sizeof(kMembers_MEMORY_BASIC_INFORMATION) / sizeof(kMembers_MEMORY_BASIC_INFORMATION[0]) },
	{ "MODULEENTRY32W",              "mssdk",  1080, false, kMembers_MODULEENTRY32W,              sizeof(kMembers_MODULEENTRY32W) / sizeof(kMembers_MODULEENTRY32W[0])     },
	{ "CONTEXT",                     "mssdk",  256,  false, kMembers_CONTEXT_X64,                 sizeof(kMembers_CONTEXT_X64) / sizeof(kMembers_CONTEXT_X64[0])           },
	{ "EXCEPTION_RECORD",            "mssdk",  152,  false, kMembers_EXCEPTION_RECORD,            sizeof(kMembers_EXCEPTION_RECORD) / sizeof(kMembers_EXCEPTION_RECORD[0]) },
	{ "TEB",                         "ntddk",  112,  false, kMembers_TEB_PARTIAL,                 sizeof(kMembers_TEB_PARTIAL) / sizeof(kMembers_TEB_PARTIAL[0])           },
	{ "PEB",                         "ntddk",  40,   false, kMembers_PEB_PARTIAL,                 sizeof(kMembers_PEB_PARTIAL) / sizeof(kMembers_PEB_PARTIAL[0])           },
	{ "IMAGE_DOS_HEADER",            "mssdk",  64,   false, kMembers_IMAGE_DOS_HEADER,            sizeof(kMembers_IMAGE_DOS_HEADER) / sizeof(kMembers_IMAGE_DOS_HEADER[0]) },
	{ "IMAGE_FILE_HEADER",           "mssdk",  20,   false, kMembers_IMAGE_FILE_HEADER,           sizeof(kMembers_IMAGE_FILE_HEADER) / sizeof(kMembers_IMAGE_FILE_HEADER[0]) },
	{ "IMAGE_DATA_DIRECTORY",        "mssdk",  8,    false, kMembers_IMAGE_DATA_DIRECTORY,        sizeof(kMembers_IMAGE_DATA_DIRECTORY) / sizeof(kMembers_IMAGE_DATA_DIRECTORY[0]) },
	{ "IMAGE_SECTION_HEADER",        "mssdk",  40,   false, kMembers_IMAGE_SECTION_HEADER,        sizeof(kMembers_IMAGE_SECTION_HEADER) / sizeof(kMembers_IMAGE_SECTION_HEADER[0]) },
};

inline constexpr enum_value_desc_t kEnumValues_MemProtect[] = {
	{ "PAGE_NOACCESS",            0x01 },
	{ "PAGE_READONLY",            0x02 },
	{ "PAGE_READWRITE",           0x04 },
	{ "PAGE_WRITECOPY",           0x08 },
	{ "PAGE_EXECUTE",             0x10 },
	{ "PAGE_EXECUTE_READ",        0x20 },
	{ "PAGE_EXECUTE_READWRITE",   0x40 },
	{ "PAGE_EXECUTE_WRITECOPY",   0x80 },
	{ "PAGE_GUARD",               0x100 },
	{ "PAGE_NOCACHE",             0x200 },
	{ "PAGE_WRITECOMBINE",        0x400 },
};
inline constexpr enum_value_desc_t kEnumValues_MemState[] = {
	{ "MEM_COMMIT",  0x1000 },
	{ "MEM_RESERVE", 0x2000 },
	{ "MEM_DECOMMIT",0x4000 },
	{ "MEM_RELEASE", 0x8000 },
	{ "MEM_FREE",    0x10000 },
	{ "MEM_PRIVATE", 0x20000 },
	{ "MEM_MAPPED",  0x40000 },
	{ "MEM_RESET",   0x80000 },
	{ "MEM_TOP_DOWN",0x100000 },
	{ "MEM_IMAGE",   0x1000000 },
};
inline constexpr enum_value_desc_t kEnumValues_AccessRights[] = {
	{ "DELETE",                   0x00010000 },
	{ "READ_CONTROL",             0x00020000 },
	{ "WRITE_DAC",                0x00040000 },
	{ "WRITE_OWNER",              0x00080000 },
	{ "SYNCHRONIZE",              0x00100000 },
	{ "STANDARD_RIGHTS_REQUIRED", 0x000F0000 },
	{ "STANDARD_RIGHTS_READ",     0x00020000 },
	{ "STANDARD_RIGHTS_WRITE",    0x00020000 },
	{ "STANDARD_RIGHTS_EXECUTE",  0x00020000 },
	{ "STANDARD_RIGHTS_ALL",      0x001F0000 },
	{ "GENERIC_READ",             static_cast<int64_t>(0x80000000) },
	{ "GENERIC_WRITE",            0x40000000 },
	{ "GENERIC_EXECUTE",          0x20000000 },
	{ "GENERIC_ALL",              0x10000000 },
};
inline constexpr enum_value_desc_t kEnumValues_FileShare[] = {
	{ "FILE_SHARE_NONE",   0x00000000 },
	{ "FILE_SHARE_READ",   0x00000001 },
	{ "FILE_SHARE_WRITE",  0x00000002 },
	{ "FILE_SHARE_DELETE", 0x00000004 },
};
inline constexpr enum_value_desc_t kEnumValues_CreationDisposition[] = {
	{ "CREATE_NEW",        1 },
	{ "CREATE_ALWAYS",     2 },
	{ "OPEN_EXISTING",     3 },
	{ "OPEN_ALWAYS",       4 },
	{ "TRUNCATE_EXISTING", 5 },
};
inline constexpr enum_value_desc_t kEnumValues_WaitResult[] = {
	{ "WAIT_OBJECT_0",   0x00000000 },
	{ "WAIT_ABANDONED",  0x00000080 },
	{ "WAIT_TIMEOUT",    0x00000102 },
	{ "WAIT_FAILED",     static_cast<int64_t>(0xFFFFFFFF) },
	{ "WAIT_IO_COMPLETION", 0x000000C0 },
};

inline constexpr enum_desc_t kBuiltinEnums[] = {
	{ "MEM_PROTECT",          "mssdk",   kEnumValues_MemProtect,          sizeof(kEnumValues_MemProtect) / sizeof(kEnumValues_MemProtect[0])                 },
	{ "MEM_STATE",            "mssdk",   kEnumValues_MemState,            sizeof(kEnumValues_MemState) / sizeof(kEnumValues_MemState[0])                     },
	{ "ACCESS_MASK",          "mssdk",   kEnumValues_AccessRights,        sizeof(kEnumValues_AccessRights) / sizeof(kEnumValues_AccessRights[0])             },
	{ "FILE_SHARE_FLAGS",     "mssdk",   kEnumValues_FileShare,           sizeof(kEnumValues_FileShare) / sizeof(kEnumValues_FileShare[0])                   },
	{ "CREATION_DISPOSITION", "mssdk",   kEnumValues_CreationDisposition, sizeof(kEnumValues_CreationDisposition) / sizeof(kEnumValues_CreationDisposition[0]) },
	{ "WAIT_RESULT",          "mssdk",   kEnumValues_WaitResult,          sizeof(kEnumValues_WaitResult) / sizeof(kEnumValues_WaitResult[0])                 },
};

inline constexpr typedef_desc_t kBuiltinTypedefs[] = {
	{ "BYTE",          "unsigned char",      "mssdk",  1 },
	{ "WORD",          "unsigned short",     "mssdk",  2 },
	{ "DWORD",         "unsigned long",      "mssdk",  4 },
	{ "QWORD",         "unsigned __int64",   "mssdk",  8 },
	{ "DWORD64",       "unsigned __int64",   "mssdk",  8 },
	{ "INT8",          "signed char",        "mssdk",  1 },
	{ "INT16",         "short",              "mssdk",  2 },
	{ "INT32",         "int",                "mssdk",  4 },
	{ "INT64",         "__int64",            "mssdk",  8 },
	{ "UINT8",         "unsigned char",      "mssdk",  1 },
	{ "UINT16",        "unsigned short",     "mssdk",  2 },
	{ "UINT32",        "unsigned int",       "mssdk",  4 },
	{ "UINT64",        "unsigned __int64",   "mssdk",  8 },
	{ "LONG",          "long",               "mssdk",  4 },
	{ "ULONG",         "unsigned long",      "mssdk",  4 },
	{ "USHORT",        "unsigned short",     "mssdk",  2 },
	{ "UCHAR",         "unsigned char",      "mssdk",  1 },
	{ "BOOL",          "int",                "mssdk",  4 },
	{ "BOOLEAN",       "unsigned char",      "ntddk",  1 },
	{ "CHAR",          "char",               "mssdk",  1 },
	{ "WCHAR",         "wchar_t",            "mssdk",  2 },
	{ "TCHAR",         "wchar_t",            "mssdk",  2 },
	{ "SHORT",         "short",              "mssdk",  2 },
	{ "INT",           "int",                "mssdk",  4 },
	{ "UINT",          "unsigned int",       "mssdk",  4 },
	{ "LONGLONG",      "__int64",            "mssdk",  8 },
	{ "ULONGLONG",     "unsigned __int64",   "mssdk",  8 },
	{ "HANDLE",        "void *",             "mssdk",  8 },
	{ "HMODULE",       "void *",             "mssdk",  8 },
	{ "HINSTANCE",     "void *",             "mssdk",  8 },
	{ "HWND",          "void *",             "mssdk",  8 },
	{ "HDC",           "void *",             "mssdk",  8 },
	{ "HBITMAP",       "void *",             "mssdk",  8 },
	{ "HBRUSH",        "void *",             "mssdk",  8 },
	{ "HKEY",          "void *",             "mssdk",  8 },
	{ "HMENU",         "void *",             "mssdk",  8 },
	{ "PVOID",         "void *",             "mssdk",  8 },
	{ "LPVOID",        "void *",             "mssdk",  8 },
	{ "LPCVOID",       "const void *",       "mssdk",  8 },
	{ "LPSTR",         "char *",             "mssdk",  8 },
	{ "LPCSTR",        "const char *",       "mssdk",  8 },
	{ "LPWSTR",        "wchar_t *",          "mssdk",  8 },
	{ "LPCWSTR",       "const wchar_t *",    "mssdk",  8 },
	{ "LPBYTE",        "unsigned char *",    "mssdk",  8 },
	{ "LPDWORD",       "DWORD *",            "mssdk",  8 },
	{ "LPHANDLE",      "HANDLE *",           "mssdk",  8 },
	{ "LRESULT",       "__int64",            "mssdk",  8 },
	{ "WPARAM",        "unsigned __int64",   "mssdk",  8 },
	{ "LPARAM",        "__int64",            "mssdk",  8 },
	{ "SIZE_T",        "unsigned __int64",   "mssdk",  8 },
	{ "SSIZE_T",       "__int64",            "mssdk",  8 },
	{ "PTRDIFF_T",     "__int64",            "mssdk",  8 },
	{ "ULONG_PTR",     "unsigned __int64",   "mssdk",  8 },
	{ "LONG_PTR",      "__int64",            "mssdk",  8 },
	{ "DWORD_PTR",     "unsigned __int64",   "mssdk",  8 },
	{ "NTSTATUS",      "long",               "ntddk",  4 },
	{ "KIRQL",         "unsigned char",      "ntddk",  1 },
	{ "ACCESS_MASK_T", "ULONG",              "ntddk",  4 },
	{ "PHANDLE",       "HANDLE *",           "mssdk",  8 },
	{ "PCHAR",         "char *",             "mssdk",  8 },
	{ "PWCHAR",        "wchar_t *",          "mssdk",  8 },
	{ "PULONG",        "ULONG *",            "ntddk",  8 },
	{ "PUNICODE_STRING", "UNICODE_STRING *", "ntddk",  8 },
	{ "PIO_STATUS_BLOCK", "IO_STATUS_BLOCK *", "ntddk", 8 },
	{ "POBJECT_ATTRIBUTES", "OBJECT_ATTRIBUTES *", "ntddk", 8 },
	{ "HRESULT",       "long",               "mssdk",  4 },
};

}
