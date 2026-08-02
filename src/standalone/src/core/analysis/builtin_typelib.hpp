#pragma once

#include <array>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

namespace builtin_typelib {

using entry_t = std::pair<uint64_t, const char*>;

inline constexpr std::array<entry_t, 78> kNtstatusTable = {{
	{ 0x00000000ull, "STATUS_SUCCESS" },
	{ 0x00000080ull, "STATUS_ABANDONED_WAIT_0" },
	{ 0x000000C0ull, "STATUS_USER_APC" },
	{ 0x00000101ull, "STATUS_ALERTED" },
	{ 0x00000102ull, "STATUS_TIMEOUT" },
	{ 0x00000103ull, "STATUS_PENDING" },
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
inline constexpr member_desc_t kMembers_RTL_CRITICAL_SECTION[] = {
	{ "DebugInfo",      "PVOID",     0,  8, true,  false, 0 },
	{ "LockCount",      "LONG",      8,  4, false, false, 0 },
	{ "RecursionCount", "LONG",      12, 4, false, false, 0 },
	{ "OwningThread",   "HANDLE",    16, 8, true,  false, 0 },
	{ "LockSemaphore",  "HANDLE",    24, 8, true,  false, 0 },
	{ "SpinCount",      "ULONG_PTR", 32, 8, false, false, 0 },
};
inline constexpr member_desc_t kMembers_SYSTEM_INFO[] = {
	{ "wProcessorArchitecture",      "WORD",      0,  2, false, false, 0 },
	{ "wReserved",                   "WORD",      2,  2, false, false, 0 },
	{ "dwPageSize",                  "DWORD",     4,  4, false, false, 0 },
	{ "lpMinimumApplicationAddress", "PVOID",     8,  8, true,  false, 0 },
	{ "lpMaximumApplicationAddress", "PVOID",     16, 8, true,  false, 0 },
	{ "dwActiveProcessorMask",       "ULONG_PTR", 24, 8, false, false, 0 },
	{ "dwNumberOfProcessors",        "DWORD",     32, 4, false, false, 0 },
	{ "dwProcessorType",             "DWORD",     36, 4, false, false, 0 },
	{ "dwAllocationGranularity",     "DWORD",     40, 4, false, false, 0 },
	{ "wProcessorLevel",             "WORD",      44, 2, false, false, 0 },
	{ "wProcessorRevision",          "WORD",      46, 2, false, false, 0 },
};
inline constexpr member_desc_t kMembers_WIN32_FIND_DATAW[] = {
	{ "dwFileAttributes",    "DWORD",    0,   4,   false, false, 0   },
	{ "ftCreationTime",      "FILETIME", 4,   8,   false, false, 0   },
	{ "ftLastAccessTime",    "FILETIME", 12,  8,   false, false, 0   },
	{ "ftLastWriteTime",     "FILETIME", 20,  8,   false, false, 0   },
	{ "nFileSizeHigh",       "DWORD",    28,  4,   false, false, 0   },
	{ "nFileSizeLow",        "DWORD",    32,  4,   false, false, 0   },
	{ "dwReserved0",         "DWORD",    36,  4,   false, false, 0   },
	{ "dwReserved1",         "DWORD",    40,  4,   false, false, 0   },
	{ "cFileName",           "WCHAR",    44,  520, false, true,  260 },
	{ "cAlternateFileName",  "WCHAR",    564, 28,  false, true,  14  },
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
	{ "IMAGE_SECTION_HEADER",        "mssdk",  40,   false, kMembers_IMAGE_SECTION_HEADER,         sizeof(kMembers_IMAGE_SECTION_HEADER) / sizeof(kMembers_IMAGE_SECTION_HEADER[0]) },
	{ "RTL_CRITICAL_SECTION",        "ntddk",  40,   false, kMembers_RTL_CRITICAL_SECTION,         sizeof(kMembers_RTL_CRITICAL_SECTION) / sizeof(kMembers_RTL_CRITICAL_SECTION[0]) },
	{ "SYSTEM_INFO",                 "mssdk",  48,   false, kMembers_SYSTEM_INFO,                  sizeof(kMembers_SYSTEM_INFO) / sizeof(kMembers_SYSTEM_INFO[0]) },
	{ "WIN32_FIND_DATAW",            "mssdk",  592,  false, kMembers_WIN32_FIND_DATAW,             sizeof(kMembers_WIN32_FIND_DATAW) / sizeof(kMembers_WIN32_FIND_DATAW[0]) },
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

enum class equate_table_id_t : std::uint8_t {
	ntstatus = 1,
	hresult = 2,
	win32_error = 3,
	wait_result = 4,
	mem_protect = 5,
	mem_state = 6,
	generic_access = 7,
	file_share = 8,
	creation_disposition = 9,
	file_flags = 10,
	socket_address_family = 11,
	socket_type = 12,
	socket_protocol = 13,
	window_message = 14,
	dialog_result = 15,
	heap_flags = 16,
	process_access = 17,
	thread_access = 18,
	token_access = 19,
	key_access = 20,
};

struct equate_match_t {
	equate_table_id_t table = equate_table_id_t::ntstatus;
	const char*         name = nullptr;
};

inline constexpr entry_t kEquateNtstatus[] = {
	{ 0x00000000ull, "STATUS_SUCCESS" },
	{ 0x00000080ull, "STATUS_ABANDONED_WAIT_0" },
	{ 0x000000C0ull, "STATUS_USER_APC" },
	{ 0x00000102ull, "STATUS_TIMEOUT" },
	{ 0x00000103ull, "STATUS_ALERTED" },
	{ 0x00000104ull, "STATUS_TIMEOUT" },
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
	{ 0xC0000034ull, "STATUS_OBJECT_NAME_NOT_FOUND" },
	{ 0xC0000035ull, "STATUS_OBJECT_NAME_COLLISION" },
	{ 0xC000003Aull, "STATUS_OBJECT_PATH_NOT_FOUND" },
	{ 0xC000003Bull, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
	{ 0xC000003Cull, "STATUS_DATA_OVERRUN" },
	{ 0xC0000043ull, "STATUS_SHARING_VIOLATION" },
	{ 0xC0000044ull, "STATUS_QUOTA_EXCEEDED" },
	{ 0xC0000054ull, "STATUS_FILE_LOCK_CONFLICT" },
	{ 0xC0000055ull, "STATUS_LOCK_NOT_GRANTED" },
	{ 0xC0000056ull, "STATUS_DELETE_PENDING" },
	{ 0xC000005Aull, "STATUS_INVALID_OWNER" },
	{ 0xC000005Cull, "STATUS_NO_LOGON_SERVERS" },
	{ 0xC0000061ull, "STATUS_PRIVILEGE_NOT_HELD" },
	{ 0xC000006Aull, "STATUS_WRONG_PASSWORD" },
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
	{ 0xC00000A2ull, "STATUS_MEDIA_WRITE_PROTECTED" },
	{ 0xC00000BAull, "STATUS_FILE_IS_A_DIRECTORY" },
	{ 0xC00000BBull, "STATUS_NOT_SUPPORTED" },
	{ 0xC00000E5ull, "STATUS_INTERNAL_ERROR" },
	{ 0xC00000FDull, "STATUS_STACK_OVERFLOW" },
	{ 0xC0000101ull, "STATUS_DIRECTORY_NOT_EMPTY" },
	{ 0xC0000102ull, "STATUS_FILE_CORRUPT_ERROR" },
	{ 0xC0000103ull, "STATUS_NOT_A_DIRECTORY" },
	{ 0xC000010Aull, "STATUS_PROCESS_IS_TERMINATING" },
	{ 0xC0000120ull, "STATUS_CANCELLED" },
	{ 0xC0000121ull, "STATUS_CANNOT_DELETE" },
	{ 0xC0000122ull, "STATUS_FILE_DELETED" },
	{ 0xC0000135ull, "STATUS_DLL_NOT_FOUND" },
	{ 0xC0000138ull, "STATUS_ORDINAL_NOT_FOUND" },
	{ 0xC0000139ull, "STATUS_ENTRYPOINT_NOT_FOUND" },
	{ 0xC000013Aull, "STATUS_CONTROL_C_EXIT" },
	{ 0xC0000142ull, "STATUS_DLL_INIT_FAILED" },
	{ 0xC000014Bull, "STATUS_PIPE_BROKEN" },
	{ 0xC0000194ull, "STATUS_POSSIBLE_DEADLOCK" },
	{ 0xC0000221ull, "STATUS_IMAGE_CHECKSUM_MISMATCH" },
	{ 0xC0000224ull, "STATUS_PASSWORD_MUST_CHANGE" },
	{ 0xC0000234ull, "STATUS_ACCOUNT_LOCKED_OUT" },
	{ 0xC0000263ull, "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND" },
	{ 0xC0000409ull, "STATUS_STACK_BUFFER_OVERRUN" },
	{ 0xC0000417ull, "STATUS_INVALID_CRUNTIME_PARAMETER" },
	{ 0xC0000428ull, "STATUS_INVALID_IMAGE_HASH" },
};

inline constexpr entry_t kEquateHresult[] = {
	{ 0x00000000ull, "S_OK" },
	{ 0x00000001ull, "S_FALSE" },
	{ 0x80004001ull, "E_NOTIMPL" },
	{ 0x80004002ull, "E_NOINTERFACE" },
	{ 0x80004003ull, "E_POINTER" },
	{ 0x80004004ull, "E_ABORT" },
	{ 0x80004005ull, "E_FAIL" },
	{ 0x8000FFFFull, "E_UNEXPECTED" },
	{ 0x80010001ull, "RPC_E_CALL_REJECTED" },
	{ 0x80010002ull, "RPC_E_CALL_CANCELED" },
	{ 0x80010100ull, "RPC_E_TIMEOUT" },
	{ 0x80010106ull, "RPC_E_CANTCALLOUT_ININPUTSYNCCALL" },
	{ 0x80010107ull, "RPC_E_WRONG_THREAD" },
	{ 0x80010108ull, "RPC_E_DISCONNECTED" },
	{ 0x80010109ull, "RPC_E_SERVER_DIED" },
	{ 0x80020005ull, "DISP_E_TYPEMISMATCH" },
	{ 0x8002000Aull, "DISP_E_OVERFLOW" },
	{ 0x8002000Eull, "DISP_E_BADPARAMCOUNT" },
	{ 0x80030002ull, "STG_E_FILENOTFOUND" },
	{ 0x80030003ull, "STG_E_PATHNOTFOUND" },
	{ 0x80030004ull, "STG_E_TOOMANYOPENFILES" },
	{ 0x80030005ull, "STG_E_ACCESSDENIED" },
	{ 0x80030008ull, "STG_E_INSUFFICIENTMEMORY" },
	{ 0x80030012ull, "STG_E_NOMOREFILES" },
	{ 0x80040154ull, "REGDB_E_CLASSNOTREG" },
	{ 0x80040155ull, "REGDB_E_IIDNOTREG" },
	{ 0x800401F0ull, "CO_E_NOTINITIALIZED" },
	{ 0x800401F3ull, "CO_E_CLASSSTRING" },
	{ 0x80070005ull, "E_ACCESSDENIED" },
	{ 0x80070006ull, "E_HANDLE" },
	{ 0x8007000Eull, "E_OUTOFMEMORY" },
	{ 0x80070057ull, "E_INVALIDARG" },
	{ 0x80070103ull, "HRESULT_NO_MORE_ITEMS" },
	{ 0x800706BAull, "HRESULT_RPC_S_SERVER_UNAVAILABLE" },
	{ 0x800706BEull, "HRESULT_RPC_S_CALL_FAILED" },
	{ 0x800706F7ull, "HRESULT_RPC_X_BAD_STUB_DATA" },
	{ 0x80090005ull, "NTE_BAD_DATA" },
	{ 0x8009000Bull, "NTE_BAD_KEY_STATE" },
	{ 0x80090016ull, "NTE_BAD_KEYSET" },
	{ 0x80090029ull, "NTE_NOT_SUPPORTED" },
	{ 0x80092004ull, "CRYPT_E_NOT_FOUND" },
	{ 0x800B0100ull, "TRUST_E_NOSIGNATURE" },
	{ 0x800B0101ull, "CERT_E_EXPIRED" },
	{ 0x800B0109ull, "CERT_E_UNTRUSTEDROOT" },
};

inline constexpr entry_t kEquateWin32Error[] = {
	{ 0ull, "ERROR_SUCCESS" },
	{ 1ull, "ERROR_INVALID_FUNCTION" },
	{ 2ull, "ERROR_FILE_NOT_FOUND" },
	{ 3ull, "ERROR_PATH_NOT_FOUND" },
	{ 4ull, "ERROR_TOO_MANY_OPEN_FILES" },
	{ 5ull, "ERROR_ACCESS_DENIED" },
	{ 6ull, "ERROR_INVALID_HANDLE" },
	{ 7ull, "ERROR_ARENA_TRASHED" },
	{ 8ull, "ERROR_NOT_ENOUGH_MEMORY" },
	{ 9ull, "ERROR_INVALID_BLOCK" },
	{ 10ull, "ERROR_BAD_ENVIRONMENT" },
	{ 11ull, "ERROR_BAD_FORMAT" },
	{ 12ull, "ERROR_INVALID_ACCESS" },
	{ 13ull, "ERROR_INVALID_DATA" },
	{ 14ull, "ERROR_OUTOFMEMORY" },
	{ 15ull, "ERROR_INVALID_DRIVE" },
	{ 16ull, "ERROR_CURRENT_DIRECTORY" },
	{ 17ull, "ERROR_NOT_SAME_DEVICE" },
	{ 18ull, "ERROR_NO_MORE_FILES" },
	{ 19ull, "ERROR_WRITE_PROTECT" },
	{ 20ull, "ERROR_BAD_UNIT" },
	{ 21ull, "ERROR_NOT_READY" },
	{ 22ull, "ERROR_BAD_COMMAND" },
	{ 23ull, "ERROR_CRC" },
	{ 24ull, "ERROR_BAD_LENGTH" },
	{ 25ull, "ERROR_SEEK" },
	{ 26ull, "ERROR_NOT_DOS_DISK" },
	{ 27ull, "ERROR_SECTOR_NOT_FOUND" },
	{ 28ull, "ERROR_OUT_OF_PAPER" },
	{ 29ull, "ERROR_WRITE_FAULT" },
	{ 30ull, "ERROR_READ_FAULT" },
	{ 31ull, "ERROR_GEN_FAILURE" },
	{ 32ull, "ERROR_SHARING_VIOLATION" },
	{ 33ull, "ERROR_LOCK_VIOLATION" },
	{ 34ull, "ERROR_WRONG_DISK" },
	{ 36ull, "ERROR_SHARING_BUFFER_EXCEEDED" },
	{ 38ull, "ERROR_HANDLE_EOF" },
	{ 39ull, "ERROR_HANDLE_DISK_FULL" },
	{ 50ull, "ERROR_NOT_SUPPORTED" },
	{ 51ull, "ERROR_REM_NOT_LIST" },
	{ 52ull, "ERROR_DUP_NAME" },
	{ 53ull, "ERROR_BAD_NETPATH" },
	{ 54ull, "ERROR_NETWORK_BUSY" },
	{ 55ull, "ERROR_DEV_NOT_EXIST" },
	{ 56ull, "ERROR_TOO_MANY_CMDS" },
	{ 57ull, "ERROR_ADAP_HDW_ERR" },
	{ 58ull, "ERROR_BAD_NET_RESP" },
	{ 59ull, "ERROR_UNEXP_NET_ERR" },
	{ 60ull, "ERROR_BAD_REM_ADAP" },
	{ 61ull, "ERROR_PRINTQ_FULL" },
	{ 62ull, "ERROR_NO_SPOOL_SPACE" },
	{ 63ull, "ERROR_PRINT_CANCELLED" },
	{ 64ull, "ERROR_NETNAME_DELETED" },
	{ 65ull, "ERROR_NETWORK_ACCESS_DENIED" },
	{ 66ull, "ERROR_BAD_DEV_TYPE" },
	{ 67ull, "ERROR_BAD_NET_NAME" },
	{ 68ull, "ERROR_TOO_MANY_NAMES" },
	{ 69ull, "ERROR_TOO_MANY_SESS" },
	{ 70ull, "ERROR_SHARING_PAUSED" },
	{ 71ull, "ERROR_REQ_NOT_ACCEP" },
	{ 72ull, "ERROR_REDIR_PAUSED" },
	{ 80ull, "ERROR_FILE_EXISTS" },
	{ 82ull, "ERROR_CANNOT_MAKE" },
	{ 83ull, "ERROR_FAIL_I24" },
	{ 84ull, "ERROR_OUT_OF_STRUCTURES" },
	{ 85ull, "ERROR_ALREADY_ASSIGNED" },
	{ 86ull, "ERROR_INVALID_PASSWORD" },
	{ 87ull, "ERROR_INVALID_PARAMETER" },
	{ 88ull, "ERROR_NET_WRITE_FAULT" },
	{ 89ull, "ERROR_NO_PROC_SLOTS" },
	{ 100ull, "ERROR_TOO_MANY_SEMAPHORES" },
	{ 101ull, "ERROR_EXCL_SEM_ALREADY_OWNED" },
	{ 102ull, "ERROR_SEM_IS_SET" },
	{ 103ull, "ERROR_TOO_MANY_SEM_REQUESTS" },
	{ 104ull, "ERROR_INVALID_AT_INTERRUPT_TIME" },
	{ 105ull, "ERROR_SEM_OWNER_DIED" },
	{ 106ull, "ERROR_SEM_USER_LIMIT" },
	{ 107ull, "ERROR_DISK_CHANGE" },
	{ 108ull, "ERROR_DRIVE_LOCKED" },
	{ 109ull, "ERROR_BROKEN_PIPE" },
	{ 110ull, "ERROR_OPEN_FAILED" },
	{ 111ull, "ERROR_BUFFER_OVERFLOW" },
	{ 112ull, "ERROR_DISK_FULL" },
	{ 113ull, "ERROR_NO_MORE_SEARCH_HANDLES" },
	{ 114ull, "ERROR_INVALID_TARGET_HANDLE" },
	{ 117ull, "ERROR_INVALID_CATEGORY" },
	{ 118ull, "ERROR_INVALID_VERIFY_SWITCH" },
	{ 119ull, "ERROR_BAD_DRIVER_LEVEL" },
	{ 120ull, "ERROR_CALL_NOT_IMPLEMENTED" },
	{ 121ull, "ERROR_SEM_TIMEOUT" },
	{ 122ull, "ERROR_INSUFFICIENT_BUFFER" },
	{ 123ull, "ERROR_INVALID_NAME" },
	{ 124ull, "ERROR_INVALID_LEVEL" },
	{ 125ull, "ERROR_NO_VOLUME_LABEL" },
	{ 126ull, "ERROR_MOD_NOT_FOUND" },
	{ 127ull, "ERROR_PROC_NOT_FOUND" },
	{ 128ull, "ERROR_WAIT_NO_CHILDREN" },
	{ 129ull, "ERROR_CHILD_NOT_COMPLETE" },
	{ 130ull, "ERROR_DIRECT_ACCESS_HANDLE" },
	{ 131ull, "ERROR_NEGATIVE_SEEK" },
	{ 132ull, "ERROR_SEEK_ON_DEVICE" },
	{ 133ull, "ERROR_IS_JOIN_TARGET" },
	{ 134ull, "ERROR_IS_JOINED" },
	{ 135ull, "ERROR_IS_SUBSTED" },
	{ 136ull, "ERROR_NOT_JOINED" },
	{ 137ull, "ERROR_NOT_SUBSTED" },
	{ 138ull, "ERROR_JOIN_TO_JOIN" },
	{ 139ull, "ERROR_SUBST_TO_SUBST" },
	{ 140ull, "ERROR_JOIN_TO_SUBST" },
	{ 141ull, "ERROR_SUBST_TO_JOIN" },
	{ 142ull, "ERROR_BUSY_DRIVE" },
	{ 143ull, "ERROR_SAME_DRIVE" },
	{ 144ull, "ERROR_DIR_NOT_ROOT" },
	{ 145ull, "ERROR_DIR_NOT_EMPTY" },
	{ 146ull, "ERROR_IS_SUBST_PATH" },
	{ 147ull, "ERROR_IS_JOIN_PATH" },
	{ 148ull, "ERROR_PATH_BUSY" },
	{ 149ull, "ERROR_IS_SUBST_TARGET" },
	{ 150ull, "ERROR_SYSTEM_TRACE" },
	{ 151ull, "ERROR_INVALID_EVENT_COUNT" },
	{ 152ull, "ERROR_TOO_MANY_MUXWAITERS" },
	{ 153ull, "ERROR_INVALID_LIST_FORMAT" },
	{ 154ull, "ERROR_LABEL_TOO_LONG" },
	{ 155ull, "ERROR_TOO_MANY_TCBS" },
	{ 156ull, "ERROR_SIGNAL_REFUSED" },
	{ 157ull, "ERROR_DISCARDED" },
	{ 158ull, "ERROR_NOT_LOCKED" },
	{ 159ull, "ERROR_BAD_THREADID_ADDR" },
	{ 160ull, "ERROR_BAD_ARGUMENTS" },
	{ 161ull, "ERROR_BAD_PATHNAME" },
	{ 162ull, "ERROR_SIGNAL_PENDING" },
	{ 164ull, "ERROR_MAX_THRDS_REACHED" },
	{ 167ull, "ERROR_LOCK_FAILED" },
	{ 170ull, "ERROR_BUSY" },
	{ 173ull, "ERROR_CANCEL_VIOLATION" },
	{ 174ull, "ERROR_ATOMIC_LOCKS_NOT_SUPPORTED" },
	{ 180ull, "ERROR_INVALID_SEGMENT_NUMBER" },
	{ 182ull, "ERROR_INVALID_ORDINAL" },
	{ 183ull, "ERROR_ALREADY_EXISTS" },
	{ 186ull, "ERROR_INVALID_FLAG_NUMBER" },
	{ 187ull, "ERROR_SEM_NOT_FOUND" },
	{ 188ull, "ERROR_INVALID_STARTING_CODESEG" },
	{ 189ull, "ERROR_INVALID_STACKSEG" },
	{ 190ull, "ERROR_INVALID_MODULETYPE" },
	{ 191ull, "ERROR_INVALID_EXE_SIGNATURE" },
	{ 192ull, "ERROR_EXE_MARKED_INVALID" },
	{ 193ull, "ERROR_BAD_EXE_FORMAT" },
	{ 194ull, "ERROR_ITERATED_DATA_EXCEEDS_64k" },
	{ 195ull, "ERROR_INVALID_MINALLOCSIZE" },
	{ 196ull, "ERROR_DYNLINK_FROM_INVALID_RING" },
	{ 197ull, "ERROR_IOPL_NOT_ENABLED" },
	{ 198ull, "ERROR_INVALID_SEGDPL" },
	{ 199ull, "ERROR_AUTODATASEG_EXCEEDS_64k" },
	{ 200ull, "ERROR_RING2SEG_MUST_BE_MOVABLE" },
	{ 201ull, "ERROR_RELOC_CHAIN_XEEDS_SEGLIM" },
	{ 202ull, "ERROR_INFLOOP_IN_RELOC_CHAIN" },
	{ 203ull, "ERROR_ENVVAR_NOT_FOUND" },
	{ 205ull, "ERROR_NO_SIGNAL_SENT" },
	{ 206ull, "ERROR_FILENAME_EXCED_RANGE" },
	{ 207ull, "ERROR_RING2_STACK_IN_USE" },
	{ 208ull, "ERROR_META_EXPANSION_TOO_LONG" },
	{ 209ull, "ERROR_INVALID_SIGNAL_NUMBER" },
	{ 210ull, "ERROR_THREAD_1_INACTIVE" },
	{ 212ull, "ERROR_LOCKED" },
	{ 214ull, "ERROR_TOO_MANY_MODULES" },
	{ 215ull, "ERROR_NESTING_NOT_ALLOWED" },
	{ 216ull, "ERROR_EXE_MACHINE_TYPE_MISMATCH" },
	{ 220ull, "ERROR_FILE_CHECKED_OUT" },
	{ 221ull, "ERROR_CHECKOUT_REQUIRED" },
	{ 222ull, "ERROR_BAD_FILE_TYPE" },
	{ 223ull, "ERROR_FILE_TOO_LARGE" },
	{ 225ull, "ERROR_VIRUS_INFECTED" },
	{ 226ull, "ERROR_VIRUS_DELETED" },
	{ 229ull, "ERROR_PIPE_LOCAL" },
	{ 230ull, "ERROR_BAD_PIPE" },
	{ 231ull, "ERROR_PIPE_BUSY" },
	{ 232ull, "ERROR_NO_DATA" },
	{ 233ull, "ERROR_PIPE_NOT_CONNECTED" },
	{ 234ull, "ERROR_MORE_DATA" },
	{ 240ull, "ERROR_VC_DISCONNECTED" },
	{ 254ull, "ERROR_INVALID_EA_NAME" },
	{ 255ull, "ERROR_EA_LIST_INCONSISTENT" },
	{ 259ull, "ERROR_NO_MORE_ITEMS" },
	{ 266ull, "ERROR_CANNOT_COPY" },
	{ 267ull, "ERROR_DIRECTORY" },
	{ 275ull, "ERROR_EAS_DIDNT_FIT" },
	{ 276ull, "ERROR_EA_FILE_CORRUPT" },
	{ 277ull, "ERROR_EA_TABLE_FULL" },
	{ 278ull, "ERROR_INVALID_EA_HANDLE" },
	{ 282ull, "ERROR_EAS_NOT_SUPPORTED" },
	{ 288ull, "ERROR_NOT_OWNER" },
	{ 298ull, "ERROR_TOO_MANY_POSTS" },
	{ 299ull, "ERROR_PARTIAL_COPY" },
	{ 300ull, "ERROR_OPLOCK_NOT_GRANTED" },
	{ 301ull, "ERROR_INVALID_OPLOCK_PROTOCOL" },
	{ 302ull, "ERROR_DISK_TOO_FRAGMENTED" },
	{ 303ull, "ERROR_DELETE_PENDING" },
	{ 317ull, "ERROR_MR_MID_NOT_FOUND" },
	{ 318ull, "ERROR_SCOPE_NOT_FOUND" },
	{ 350ull, "ERROR_FAIL_NOACTION_REBOOT" },
	{ 351ull, "ERROR_FAIL_SHUTDOWN" },
	{ 352ull, "ERROR_FAIL_RESTART" },
	{ 353ull, "ERROR_MAX_SESSIONS_REACHED" },
	{ 487ull, "ERROR_INVALID_ADDRESS" },
	{ 500ull, "ERROR_USER_PROFILE_LOAD" },
	{ 534ull, "ERROR_ARITHMETIC_OVERFLOW" },
	{ 535ull, "ERROR_PIPE_CONNECTED" },
	{ 536ull, "ERROR_PIPE_LISTENING" },
	{ 537ull, "ERROR_VERIFIER_STOP" },
	{ 541ull, "ERROR_TIMER_NOT_CANCELED" },
	{ 542ull, "ERROR_UNWIND" },
	{ 543ull, "ERROR_BAD_STACK" },
	{ 544ull, "ERROR_INVALID_UNWIND_TARGET" },
	{ 546ull, "ERROR_PORT_MESSAGE_TOO_LONG" },
	{ 547ull, "ERROR_INVALID_QUOTA_LOWER" },
	{ 548ull, "ERROR_DEVICE_ALREADY_ATTACHED" },
	{ 550ull, "ERROR_PROFILING_NOT_STARTED" },
	{ 551ull, "ERROR_PROFILING_NOT_STOPPED" },
	{ 552ull, "ERROR_COULD_NOT_INTERPRET" },
	{ 553ull, "ERROR_PROFILING_AT_LIMIT" },
	{ 554ull, "ERROR_CANT_WAIT" },
	{ 555ull, "ERROR_CANT_TERMINATE_SELF" },
	{ 559ull, "ERROR_BAD_FUNCTION_TABLE" },
	{ 560ull, "ERROR_NO_GUID_TRANSLATION" },
	{ 561ull, "ERROR_INVALID_LDT_SIZE" },
	{ 563ull, "ERROR_INVALID_LDT_OFFSET" },
	{ 564ull, "ERROR_INVALID_LDT_DESCRIPTOR" },
	{ 565ull, "ERROR_TOO_MANY_THREADS" },
	{ 566ull, "ERROR_THREAD_NOT_IN_PROCESS" },
	{ 570ull, "ERROR_FILE_INVALID" },
	{ 572ull, "ERROR_NO_SUCH_LOGON_SESSION" },
	{ 995ull, "ERROR_OPERATION_ABORTED" },
	{ 997ull, "ERROR_IO_PENDING" },
	{ 998ull, "ERROR_NOACCESS" },
	{ 1004ull, "ERROR_INVALID_FLAGS" },
	{ 1005ull, "ERROR_UNRECOGNIZED_VOLUME" },
	{ 1006ull, "ERROR_FILE_INVALID" },
	{ 1008ull, "ERROR_NO_TOKEN" },
	{ 1052ull, "ERROR_INVALID_SERVICE_CONTROL" },
	{ 1053ull, "ERROR_SERVICE_REQUEST_TIMEOUT" },
	{ 1054ull, "ERROR_SERVICE_NO_THREAD" },
	{ 1055ull, "ERROR_SERVICE_DATABASE_LOCKED" },
	{ 1056ull, "ERROR_SERVICE_ALREADY_RUNNING" },
	{ 1057ull, "ERROR_INVALID_SERVICE_ACCOUNT" },
	{ 1058ull, "ERROR_SERVICE_DISABLED" },
	{ 1059ull, "ERROR_CIRCULAR_DEPENDENCY" },
	{ 1060ull, "ERROR_SERVICE_DOES_NOT_EXIST" },
	{ 1061ull, "ERROR_SERVICE_CANNOT_ACCEPT_CTRL" },
	{ 1062ull, "ERROR_SERVICE_NOT_ACTIVE" },
	{ 1063ull, "ERROR_FAILED_SERVICE_CONTROLLER_CONNECT" },
	{ 1064ull, "ERROR_EXCEPTION_IN_SERVICE" },
	{ 1066ull, "ERROR_SERVICE_SPECIFIC_ERROR" },
	{ 1067ull, "ERROR_PROCESS_ABORTED" },
	{ 1068ull, "ERROR_SERVICE_DEPENDENCY_FAIL" },
	{ 1069ull, "ERROR_SERVICE_LOGON_FAILED" },
	{ 1070ull, "ERROR_SERVICE_START_HANG" },
	{ 1071ull, "ERROR_INVALID_SERVICE_LOCK" },
	{ 1072ull, "ERROR_SERVICE_MARKED_FOR_DELETE" },
	{ 1073ull, "ERROR_SERVICE_EXISTS" },
	{ 1075ull, "ERROR_SERVICE_DEPENDENCY_DELETED" },
	{ 1078ull, "ERROR_DUPLICATE_SERVICE_NAME" },
	{ 1115ull, "ERROR_SHUTDOWN_IN_PROGRESS" },
	{ 1116ull, "ERROR_NO_SHUTDOWN_IN_PROGRESS" },
	{ 1130ull, "ERROR_NOT_ENOUGH_SERVER_MEMORY" },
	{ 1131ull, "ERROR_POSSIBLE_DEADLOCK" },
	{ 1150ull, "ERROR_OLD_WIN_VERSION" },
	{ 1151ull, "ERROR_APP_WRONG_OS" },
	{ 1152ull, "ERROR_SINGLE_INSTANCE_APP" },
	{ 1155ull, "ERROR_NO_ASSOCIATION" },
	{ 1156ull, "ERROR_DDE_FAIL" },
	{ 1157ull, "ERROR_DLL_NOT_FOUND" },
	{ 1168ull, "ERROR_NOT_FOUND" },
	{ 1219ull, "ERROR_SESSION_CREDENTIAL_CONFLICT" },
	{ 1221ull, "ERROR_DUP_DOMAINNAME" },
	{ 1222ull, "ERROR_NO_NETWORK" },
	{ 1223ull, "ERROR_CANCELLED" },
	{ 1224ull, "ERROR_USER_MAPPED_FILE" },
	{ 1225ull, "ERROR_CONNECTION_REFUSED" },
	{ 1226ull, "ERROR_GRACEFUL_DISCONNECT" },
	{ 1227ull, "ERROR_ADDRESS_ALREADY_ASSOCIATED" },
	{ 1228ull, "ERROR_ADDRESS_NOT_ASSOCIATED" },
	{ 1229ull, "ERROR_CONNECTION_INVALID" },
	{ 1230ull, "ERROR_CONNECTION_ACTIVE" },
	{ 1231ull, "ERROR_NETWORK_UNREACHABLE" },
	{ 1232ull, "ERROR_HOST_UNREACHABLE" },
	{ 1233ull, "ERROR_PROTOCOL_UNREACHABLE" },
	{ 1234ull, "ERROR_PORT_UNREACHABLE" },
	{ 1236ull, "ERROR_CONNECTION_ABORTED" },
	{ 1237ull, "ERROR_RETRY" },
	{ 1238ull, "ERROR_CONNECTION_COUNT_LIMIT" },
	{ 1239ull, "ERROR_LOGIN_TIME_RESTRICTION" },
	{ 1240ull, "ERROR_LOGIN_WKSTA_RESTRICTION" },
	{ 1326ull, "ERROR_LOGON_FAILURE" },
	{ 1327ull, "ERROR_ACCOUNT_RESTRICTION" },
	{ 1328ull, "ERROR_INVALID_LOGON_HOURS" },
	{ 1329ull, "ERROR_INVALID_WORKSTATION" },
	{ 1330ull, "ERROR_PASSWORD_EXPIRED" },
	{ 1331ull, "ERROR_ACCOUNT_DISABLED" },
	{ 1332ull, "ERROR_NONE_MAPPED" },
	{ 1333ull, "ERROR_TOO_MANY_LUIDS_REQUESTED" },
	{ 1334ull, "ERROR_LUIDS_EXHAUSTED" },
	{ 1335ull, "ERROR_INVALID_SUB_AUTHORITY" },
	{ 1336ull, "ERROR_INVALID_ACL" },
	{ 1337ull, "ERROR_INVALID_SID" },
	{ 1338ull, "ERROR_INVALID_SECURITY_DESCR" },
	{ 1340ull, "ERROR_BAD_INHERITANCE_ACL" },
	{ 1342ull, "ERROR_SERVER_DISABLED" },
	{ 1343ull, "ERROR_SERVER_NOT_DISABLED" },
	{ 1355ull, "ERROR_NO_SUCH_DOMAIN" },
	{ 1356ull, "ERROR_DOMAIN_EXISTS" },
	{ 1357ull, "ERROR_DOMAIN_LIMIT_EXCEEDED" },
	{ 1385ull, "ERROR_LOGON_NOT_GRANTED" },
	{ 1387ull, "ERROR_NO_SUCH_MEMBER" },
	{ 1388ull, "ERROR_INVALID_MEMBER" },
	{ 1389ull, "ERROR_TOO_MANY_SECRETS" },
	{ 1390ull, "ERROR_SECRET_TOO_LONG" },
	{ 1391ull, "ERROR_INTERNAL_DB_ERROR" },
	{ 1392ull, "ERROR_TOO_MANY_CONTEXT_IDS" },
	{ 1393ull, "ERROR_LOGON_TYPE_NOT_GRANTED" },
	{ 1394ull, "ERROR_NO_SUCH_ALIAS" },
	{ 1395ull, "ERROR_MEMBER_IN_ALIAS" },
	{ 1396ull, "ERROR_ALIAS_EXISTS" },
	{ 1397ull, "ERROR_LOGON_SESSION_EXISTS" },
	{ 1398ull, "ERROR_TIME_SKEW" },
	{ 1400ull, "ERROR_INVALID_WINDOW_HANDLE" },
	{ 1401ull, "ERROR_INVALID_MENU_HANDLE" },
	{ 1402ull, "ERROR_INVALID_CURSOR_HANDLE" },
	{ 1403ull, "ERROR_INVALID_ACCEL_HANDLE" },
	{ 1404ull, "ERROR_INVALID_HOOK_HANDLE" },
	{ 1405ull, "ERROR_INVALID_DWP_HANDLE" },
	{ 1406ull, "ERROR_TLW_WITH_WSCHILD" },
	{ 1407ull, "ERROR_CANNOT_FIND_WND_CLASS" },
	{ 1408ull, "ERROR_WINDOW_OF_OTHER_THREAD" },
	{ 1409ull, "ERROR_HOTKEY_ALREADY_REGISTERED" },
	{ 1410ull, "ERROR_CLASS_ALREADY_EXISTS" },
	{ 1411ull, "ERROR_CLASS_DOES_NOT_EXIST" },
	{ 1412ull, "ERROR_CLASS_HAS_WINDOWS" },
	{ 1413ull, "ERROR_INVALID_INDEX" },
	{ 1414ull, "ERROR_INVALID_ICON_HANDLE" },
	{ 1415ull, "ERROR_PRIVATE_DIALOG_INDEX" },
	{ 1416ull, "ERROR_LISTBOX_ID_NOT_FOUND" },
	{ 1417ull, "ERROR_NO_WILDCARD_CHARACTERS" },
	{ 1418ull, "ERROR_CLIPBOARD_NOT_OPEN" },
	{ 1419ull, "ERROR_HOTKEY_NOT_REGISTERED" },
	{ 1420ull, "ERROR_WINDOW_NOT_DIALOG" },
	{ 1421ull, "ERROR_CONTROL_ID_NOT_FOUND" },
	{ 1422ull, "ERROR_INVALID_COMBOBOX_MESSAGE" },
	{ 1423ull, "ERROR_WINDOW_NOT_COMBOBOX" },
	{ 1424ull, "ERROR_INVALID_EDIT_HEIGHT" },
	{ 1425ull, "ERROR_DC_NOT_FOUND" },
	{ 1426ull, "ERROR_INVALID_HOOK_FILTER" },
	{ 1427ull, "ERROR_INVALID_FILTER_PROC" },
	{ 1428ull, "ERROR_HOOK_NEEDS_HMOD" },
	{ 1429ull, "ERROR_GLOBAL_ONLY_HOOK" },
	{ 1430ull, "ERROR_JOURNAL_HOOK_SET" },
	{ 1431ull, "ERROR_HOOK_NOT_INSTALLED" },
	{ 1432ull, "ERROR_INVALID_LB_MESSAGE" },
	{ 1433ull, "ERROR_SETCOUNT_ON_BAD_LB" },
	{ 1434ull, "ERROR_LB_WITHOUT_TABSTOPS" },
	{ 1438ull, "ERROR_INVALID_GW_COMMAND" },
	{ 1500ull, "ERROR_EVENTLOG_FILE_CORRUPT" },
	{ 1501ull, "ERROR_EVENTLOG_CANT_START" },
	{ 1502ull, "ERROR_LOG_FILE_FULL" },
	{ 1503ull, "ERROR_EVENTLOG_FILE_CHANGED" },
	{ 1722ull, "RPC_S_SERVER_UNAVAILABLE" },
	{ 1726ull, "RPC_S_CALL_FAILED" },
	{ 1789ull, "ERROR_TRUSTED_RELATIONSHIP_FAILURE" },
	{ 1794ull, "ERROR_REDIRECTOR_HAS_OPEN_HANDLES" },
	{ 1812ull, "ERROR_RESOURCE_DATA_NOT_FOUND" },
	{ 1813ull, "ERROR_RESOURCE_TYPE_NOT_FOUND" },
	{ 1814ull, "ERROR_RESOURCE_NAME_NOT_FOUND" },
	{ 1815ull, "ERROR_RESOURCE_LANG_NOT_FOUND" },
	{ 1816ull, "ERROR_NOT_ENOUGH_QUOTA" },
	{ 1907ull, "ERROR_PASSWORD_RESTRICTION" },
	{ 1908ull, "ERROR_ACCOUNT_LOCKED_OUT" },
};

inline constexpr entry_t kEquateWaitResult[] = {
	{ 0x00000000ull, "WAIT_OBJECT_0" },
	{ 0x00000080ull, "WAIT_ABANDONED" },
	{ 0x000000C0ull, "WAIT_IO_COMPLETION" },
	{ 0x00000102ull, "WAIT_TIMEOUT" },
	{ 0xFFFFFFFFull, "INFINITE" },
};

inline constexpr entry_t kEquateMemProtect[] = {
	{ 0x01ull, "PAGE_NOACCESS" },
	{ 0x02ull, "PAGE_READONLY" },
	{ 0x04ull, "PAGE_READWRITE" },
	{ 0x08ull, "PAGE_WRITECOPY" },
	{ 0x10ull, "PAGE_EXECUTE" },
	{ 0x20ull, "PAGE_EXECUTE_READ" },
	{ 0x40ull, "PAGE_EXECUTE_READWRITE" },
	{ 0x80ull, "PAGE_EXECUTE_WRITECOPY" },
	{ 0x100ull, "PAGE_GUARD" },
	{ 0x200ull, "PAGE_NOCACHE" },
	{ 0x400ull, "PAGE_WRITECOMBINE" },
};

inline constexpr entry_t kEquateMemState[] = {
	{ 0x1000ull, "MEM_COMMIT" },
	{ 0x2000ull, "MEM_RESERVE" },
	{ 0x4000ull, "MEM_DECOMMIT" },
	{ 0x8000ull, "MEM_RELEASE" },
	{ 0x10000ull, "MEM_FREE" },
	{ 0x20000ull, "MEM_PRIVATE" },
	{ 0x40000ull, "MEM_MAPPED" },
	{ 0x80000ull, "MEM_RESET" },
	{ 0x100000ull, "MEM_TOP_DOWN" },
	{ 0x1000000ull, "MEM_IMAGE" },
};

inline constexpr entry_t kEquateGenericAccess[] = {
	{ 0x00010000ull, "DELETE" },
	{ 0x00020000ull, "READ_CONTROL" },
	{ 0x00040000ull, "WRITE_DAC" },
	{ 0x00080000ull, "WRITE_OWNER" },
	{ 0x000F0000ull, "STANDARD_RIGHTS_REQUIRED" },
	{ 0x00100000ull, "SYNCHRONIZE" },
	{ 0x001F0000ull, "STANDARD_RIGHTS_ALL" },
	{ 0x10000000ull, "GENERIC_ALL" },
	{ 0x20000000ull, "GENERIC_EXECUTE" },
	{ 0x40000000ull, "GENERIC_WRITE" },
	{ 0x80000000ull, "GENERIC_READ" },
};

inline constexpr entry_t kEquateFileShare[] = {
	{ 0x00000001ull, "FILE_SHARE_READ" },
	{ 0x00000002ull, "FILE_SHARE_WRITE" },
	{ 0x00000004ull, "FILE_SHARE_DELETE" },
};

inline constexpr entry_t kEquateCreationDisposition[] = {
	{ 1ull, "CREATE_NEW" },
	{ 2ull, "CREATE_ALWAYS" },
	{ 3ull, "OPEN_EXISTING" },
	{ 4ull, "OPEN_ALWAYS" },
	{ 5ull, "TRUNCATE_EXISTING" },
};

inline constexpr entry_t kEquateFileFlags[] = {
	{ 0x00000001ull, "FILE_ATTRIBUTE_READONLY" },
	{ 0x00000002ull, "FILE_ATTRIBUTE_HIDDEN" },
	{ 0x00000004ull, "FILE_ATTRIBUTE_SYSTEM" },
	{ 0x00000010ull, "FILE_ATTRIBUTE_DIRECTORY" },
	{ 0x00000020ull, "FILE_ATTRIBUTE_ARCHIVE" },
	{ 0x00000040ull, "FILE_ATTRIBUTE_DEVICE" },
	{ 0x00000080ull, "FILE_ATTRIBUTE_NORMAL" },
	{ 0x00000100ull, "FILE_ATTRIBUTE_TEMPORARY" },
	{ 0x00000200ull, "FILE_ATTRIBUTE_SPARSE_FILE" },
	{ 0x00000400ull, "FILE_ATTRIBUTE_REPARSE_POINT" },
	{ 0x00000800ull, "FILE_ATTRIBUTE_COMPRESSED" },
	{ 0x00001000ull, "FILE_ATTRIBUTE_OFFLINE" },
	{ 0x00002000ull, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" },
	{ 0x00004000ull, "FILE_ATTRIBUTE_ENCRYPTED" },
	{ 0x02000000ull, "FILE_FLAG_BACKUP_SEMANTICS" },
	{ 0x04000000ull, "FILE_FLAG_DELETE_ON_CLOSE" },
	{ 0x08000000ull, "FILE_FLAG_SEQUENTIAL_SCAN" },
	{ 0x10000000ull, "FILE_FLAG_RANDOM_ACCESS" },
	{ 0x20000000ull, "FILE_FLAG_NO_BUFFERING" },
	{ 0x40000000ull, "FILE_FLAG_OVERLAPPED" },
	{ 0x80000000ull, "FILE_FLAG_WRITE_THROUGH" },
};

inline constexpr entry_t kEquateSocketAddressFamily[] = {
	{ 0ull, "AF_UNSPEC" },
	{ 1ull, "AF_UNIX" },
	{ 2ull, "AF_INET" },
	{ 3ull, "AF_IMPLINK" },
	{ 4ull, "AF_PUP" },
	{ 5ull, "AF_CHAOS" },
	{ 6ull, "AF_IPX" },
	{ 7ull, "AF_ISO" },
	{ 8ull, "AF_ECMA" },
	{ 9ull, "AF_DATAKIT" },
	{ 10ull, "AF_CCITT" },
	{ 11ull, "AF_SNA" },
	{ 12ull, "AF_DECnet" },
	{ 13ull, "AF_DLI" },
	{ 14ull, "AF_LAT" },
	{ 15ull, "AF_HYLINK" },
	{ 16ull, "AF_APPLETALK" },
	{ 17ull, "AF_NETBIOS" },
	{ 18ull, "AF_VOICEVIEW" },
	{ 19ull, "AF_FIREFOX" },
	{ 20ull, "AF_UNKNOWN1" },
	{ 21ull, "AF_BAN" },
	{ 22ull, "AF_ATM" },
	{ 23ull, "AF_INET6" },
	{ 24ull, "AF_CLUSTER" },
	{ 25ull, "AF_12844" },
	{ 26ull, "AF_IRDA" },
	{ 28ull, "AF_NETDES" },
	{ 29ull, "AF_TCNPROCESS" },
	{ 30ull, "AF_TCNMESSAGE" },
	{ 31ull, "AF_ICLFXBM" },
	{ 32ull, "AF_BTH" },
};

inline constexpr entry_t kEquateSocketType[] = {
	{ 1ull, "SOCK_STREAM" },
	{ 2ull, "SOCK_DGRAM" },
	{ 3ull, "SOCK_RAW" },
	{ 4ull, "SOCK_RDM" },
	{ 5ull, "SOCK_SEQPACKET" },
};

inline constexpr entry_t kEquateSocketProtocol[] = {
	{ 0ull, "IPPROTO_IP" },
	{ 1ull, "IPPROTO_ICMP" },
	{ 2ull, "IPPROTO_IGMP" },
	{ 6ull, "IPPROTO_TCP" },
	{ 17ull, "IPPROTO_UDP" },
	{ 41ull, "IPPROTO_IPV6" },
	{ 58ull, "IPPROTO_ICMPV6" },
	{ 255ull, "IPPROTO_RAW" },
};

inline constexpr entry_t kEquateWindowMessage[] = {
	{ 0ull, "WM_NULL" },
	{ 1ull, "WM_CREATE" },
	{ 2ull, "WM_DESTROY" },
	{ 3ull, "WM_MOVE" },
	{ 5ull, "WM_SIZE" },
	{ 6ull, "WM_ACTIVATE" },
	{ 7ull, "WM_SETFOCUS" },
	{ 8ull, "WM_KILLFOCUS" },
	{ 10ull, "WM_ENABLE" },
	{ 11ull, "WM_SETREDRAW" },
	{ 12ull, "WM_SETTEXT" },
	{ 13ull, "WM_GETTEXT" },
	{ 14ull, "WM_GETTEXTLENGTH" },
	{ 15ull, "WM_PAINT" },
	{ 16ull, "WM_CLOSE" },
	{ 17ull, "WM_QUERYENDSESSION" },
	{ 18ull, "WM_QUIT" },
	{ 19ull, "WM_QUERYOPEN" },
	{ 20ull, "WM_ERASEBKGND" },
	{ 21ull, "WM_SYSCOLORCHANGE" },
	{ 22ull, "WM_ENDSESSION" },
	{ 24ull, "WM_SHOWWINDOW" },
	{ 26ull, "WM_SETTINGCHANGE" },
	{ 27ull, "WM_DEVMODECHANGE" },
	{ 28ull, "WM_ACTIVATEAPP" },
	{ 29ull, "WM_FONTCHANGE" },
	{ 30ull, "WM_TIMECHANGE" },
	{ 31ull, "WM_CANCELMODE" },
	{ 32ull, "WM_SETCURSOR" },
	{ 33ull, "WM_MOUSEACTIVATE" },
	{ 34ull, "WM_CHILDACTIVATE" },
	{ 35ull, "WM_QUEUESYNC" },
	{ 36ull, "WM_GETMINMAXINFO" },
	{ 38ull, "WM_PAINTICON" },
	{ 39ull, "WM_ICONERASEBKGND" },
	{ 40ull, "WM_NEXTDLGCTL" },
	{ 42ull, "WM_SPOOLERSTATUS" },
	{ 43ull, "WM_DRAWITEM" },
	{ 44ull, "WM_MEASUREITEM" },
	{ 45ull, "WM_DELETEITEM" },
	{ 46ull, "WM_VKEYTOITEM" },
	{ 47ull, "WM_CHARTOITEM" },
	{ 48ull, "WM_SETFONT" },
	{ 49ull, "WM_GETFONT" },
	{ 50ull, "WM_SETHOTKEY" },
	{ 51ull, "WM_GETHOTKEY" },
	{ 55ull, "WM_QUERYDRAGICON" },
	{ 57ull, "WM_COMPAREITEM" },
	{ 61ull, "WM_GETOBJECT" },
	{ 65ull, "WM_COMPACTING" },
	{ 68ull, "WM_COMMNOTIFY" },
	{ 70ull, "WM_WINDOWPOSCHANGING" },
	{ 71ull, "WM_WINDOWPOSCHANGED" },
	{ 72ull, "WM_POWER" },
	{ 74ull, "WM_COPYDATA" },
	{ 75ull, "WM_CANCELJOURNAL" },
	{ 78ull, "WM_NOTIFY" },
	{ 80ull, "WM_INPUTLANGCHANGEREQUEST" },
	{ 81ull, "WM_INPUTLANGCHANGE" },
	{ 82ull, "WM_TCARD" },
	{ 83ull, "WM_HELP" },
	{ 84ull, "WM_USERCHANGED" },
	{ 85ull, "WM_NOTIFYFORMAT" },
	{ 123ull, "WM_CONTEXTMENU" },
	{ 124ull, "WM_STYLECHANGING" },
	{ 125ull, "WM_STYLECHANGED" },
	{ 126ull, "WM_DISPLAYCHANGE" },
	{ 127ull, "WM_GETICON" },
	{ 128ull, "WM_SETICON" },
	{ 129ull, "WM_NCCREATE" },
	{ 130ull, "WM_NCDESTROY" },
	{ 131ull, "WM_NCCALCSIZE" },
	{ 132ull, "WM_NCHITTEST" },
	{ 133ull, "WM_NCPAINT" },
	{ 134ull, "WM_NCACTIVATE" },
	{ 135ull, "WM_GETDLGCODE" },
	{ 136ull, "WM_SYNCPAINT" },
	{ 160ull, "WM_NCMOUSEMOVE" },
	{ 161ull, "WM_NCLBUTTONDOWN" },
	{ 162ull, "WM_NCLBUTTONUP" },
	{ 163ull, "WM_NCLBUTTONDBLCLK" },
	{ 164ull, "WM_NCRBUTTONDOWN" },
	{ 165ull, "WM_NCRBUTTONUP" },
	{ 166ull, "WM_NCRBUTTONDBLCLK" },
	{ 167ull, "WM_NCMBUTTONDOWN" },
	{ 168ull, "WM_NCMBUTTONUP" },
	{ 169ull, "WM_NCMBUTTONDBLCLK" },
	{ 256ull, "WM_KEYDOWN" },
	{ 257ull, "WM_KEYUP" },
	{ 258ull, "WM_CHAR" },
	{ 259ull, "WM_DEADCHAR" },
	{ 260ull, "WM_SYSKEYDOWN" },
	{ 261ull, "WM_SYSKEYUP" },
	{ 262ull, "WM_SYSCHAR" },
	{ 263ull, "WM_SYSDEADCHAR" },
	{ 265ull, "WM_UNICHAR" },
	{ 269ull, "WM_IME_STARTCOMPOSITION" },
	{ 270ull, "WM_IME_ENDCOMPOSITION" },
	{ 271ull, "WM_IME_COMPOSITION" },
	{ 272ull, "WM_INITDIALOG" },
	{ 273ull, "WM_COMMAND" },
	{ 274ull, "WM_SYSCOMMAND" },
	{ 275ull, "WM_TIMER" },
	{ 276ull, "WM_HSCROLL" },
	{ 277ull, "WM_VSCROLL" },
	{ 278ull, "WM_INITMENU" },
	{ 279ull, "WM_INITMENUPOPUP" },
	{ 287ull, "WM_MENUSELECT" },
	{ 288ull, "WM_MENUCHAR" },
	{ 289ull, "WM_ENTERIDLE" },
	{ 290ull, "WM_MENURBUTTONUP" },
	{ 291ull, "WM_MENUDRAG" },
	{ 292ull, "WM_MENUGETOBJECT" },
	{ 293ull, "WM_UNINITMENUPOPUP" },
	{ 294ull, "WM_MENUCOMMAND" },
	{ 295ull, "WM_CHANGEUISTATE" },
	{ 296ull, "WM_UPDATEUISTATE" },
	{ 297ull, "WM_QUERYUISTATE" },
	{ 306ull, "WM_CTLCOLORMSGBOX" },
	{ 307ull, "WM_CTLCOLOREDIT" },
	{ 308ull, "WM_CTLCOLORLISTBOX" },
	{ 309ull, "WM_CTLCOLORBTN" },
	{ 310ull, "WM_CTLCOLORDLG" },
	{ 311ull, "WM_CTLCOLORSCROLLBAR" },
	{ 312ull, "WM_CTLCOLORSTATIC" },
	{ 512ull, "WM_MOUSEMOVE" },
	{ 513ull, "WM_LBUTTONDOWN" },
	{ 514ull, "WM_LBUTTONUP" },
	{ 515ull, "WM_LBUTTONDBLCLK" },
	{ 516ull, "WM_RBUTTONDOWN" },
	{ 517ull, "WM_RBUTTONUP" },
	{ 518ull, "WM_RBUTTONDBLCLK" },
	{ 519ull, "WM_MBUTTONDOWN" },
	{ 520ull, "WM_MBUTTONUP" },
	{ 521ull, "WM_MBUTTONDBLCLK" },
	{ 522ull, "WM_MOUSEWHEEL" },
	{ 523ull, "WM_XBUTTONDOWN" },
	{ 524ull, "WM_XBUTTONUP" },
	{ 525ull, "WM_XBUTTONDBLCLK" },
	{ 526ull, "WM_MOUSEHWHEEL" },
	{ 528ull, "WM_PARENTNOTIFY" },
	{ 529ull, "WM_ENTERMENULOOP" },
	{ 530ull, "WM_EXITMENULOOP" },
	{ 531ull, "WM_NEXTMENU" },
	{ 532ull, "WM_SIZING" },
	{ 533ull, "WM_CAPTURECHANGED" },
	{ 534ull, "WM_MOVING" },
	{ 536ull, "WM_POWERBROADCAST" },
	{ 537ull, "WM_DEVICECHANGE" },
	{ 544ull, "WM_MDICREATE" },
	{ 545ull, "WM_MDIDESTROY" },
	{ 546ull, "WM_MDIACTIVATE" },
	{ 547ull, "WM_MDIRESTORE" },
	{ 548ull, "WM_MDINEXT" },
	{ 549ull, "WM_MDIMAXIMIZE" },
	{ 550ull, "WM_MDITILE" },
	{ 551ull, "WM_MDICASCADE" },
	{ 552ull, "WM_MDIICONARRANGE" },
	{ 553ull, "WM_MDIGETACTIVE" },
	{ 560ull, "WM_MDISETMENU" },
	{ 561ull, "WM_ENTERSIZEMOVE" },
	{ 562ull, "WM_EXITSIZEMOVE" },
	{ 563ull, "WM_DROPFILES" },
	{ 564ull, "WM_MDIREFRESHMENU" },
	{ 641ull, "WM_IME_SETCONTEXT" },
	{ 642ull, "WM_IME_NOTIFY" },
	{ 643ull, "WM_IME_CONTROL" },
	{ 644ull, "WM_IME_COMPOSITIONFULL" },
	{ 645ull, "WM_IME_SELECT" },
	{ 646ull, "WM_IME_CHAR" },
	{ 648ull, "WM_IME_REQUEST" },
	{ 656ull, "WM_IME_KEYDOWN" },
	{ 657ull, "WM_IME_KEYUP" },
	{ 672ull, "WM_NCMOUSEHOVER" },
	{ 673ull, "WM_MOUSEHOVER" },
	{ 674ull, "WM_NCMOUSELEAVE" },
	{ 675ull, "WM_MOUSELEAVE" },
	{ 689ull, "WM_WTSSESSION_CHANGE" },
	{ 768ull, "WM_CUT" },
	{ 769ull, "WM_COPY" },
	{ 770ull, "WM_PASTE" },
	{ 771ull, "WM_CLEAR" },
	{ 772ull, "WM_UNDO" },
	{ 773ull, "WM_RENDERFORMAT" },
	{ 774ull, "WM_RENDERALLFORMATS" },
	{ 775ull, "WM_DESTROYCLIPBOARD" },
	{ 776ull, "WM_DRAWCLIPBOARD" },
	{ 777ull, "WM_PAINTCLIPBOARD" },
	{ 778ull, "WM_VSCROLLCLIPBOARD" },
	{ 779ull, "WM_SIZECLIPBOARD" },
	{ 780ull, "WM_ASKCBFORMATNAME" },
	{ 781ull, "WM_CHANGECBCHAIN" },
	{ 782ull, "WM_HSCROLLCLIPBOARD" },
	{ 783ull, "WM_QUERYNEWPALETTE" },
	{ 784ull, "WM_PALETTEISCHANGING" },
	{ 785ull, "WM_PALETTECHANGED" },
	{ 786ull, "WM_HOTKEY" },
	{ 791ull, "WM_PRINT" },
	{ 792ull, "WM_PRINTCLIENT" },
	{ 793ull, "WM_APPCOMMAND" },
	{ 794ull, "WM_THEMECHANGED" },
	{ 795ull, "WM_CLIPBOARDUPDATE" },
	{ 798ull, "WM_DWMCOMPOSITIONCHANGED" },
	{ 799ull, "WM_GETTITLEBARINFOEX" },
	{ 1024ull, "WM_USER" },
	{ 32768ull, "WM_APP" },
};

inline constexpr entry_t kEquateDialogResult[] = {
	{ 1ull, "IDOK" },
	{ 2ull, "IDCANCEL" },
	{ 3ull, "IDABORT" },
	{ 4ull, "IDRETRY" },
	{ 5ull, "IDIGNORE" },
	{ 6ull, "IDYES" },
	{ 7ull, "IDNO" },
	{ 8ull, "IDCLOSE" },
	{ 9ull, "IDHELP" },
	{ 10ull, "IDTRYAGAIN" },
	{ 11ull, "IDCONTINUE" },
};

inline constexpr entry_t kEquateHeapFlags[] = {
	{ 0x00000001ull, "HEAP_NO_SERIALIZE" },
	{ 0x00000002ull, "HEAP_GROWABLE" },
	{ 0x00000004ull, "HEAP_GENERATE_EXCEPTIONS" },
	{ 0x00000008ull, "HEAP_ZERO_MEMORY" },
	{ 0x00000010ull, "HEAP_REALLOC_IN_PLACE_ONLY" },
	{ 0x00000020ull, "HEAP_TAIL_CHECKING_ENABLED" },
	{ 0x00000040ull, "HEAP_FREE_CHECKING_ENABLED" },
	{ 0x00000080ull, "HEAP_DISABLE_COALESCE" },
	{ 0x00010000ull, "HEAP_CREATE_ALIGN_16" },
	{ 0x00020000ull, "HEAP_CREATE_ENABLE_TRACING" },
	{ 0x00040000ull, "HEAP_CREATE_ENABLE_EXECUTE" },
};

inline constexpr entry_t kEquateProcessAccess[] = {
	{ 0x0001ull, "PROCESS_TERMINATE" },
	{ 0x0002ull, "PROCESS_CREATE_THREAD" },
	{ 0x0004ull, "PROCESS_SET_SESSIONID" },
	{ 0x0008ull, "PROCESS_VM_OPERATION" },
	{ 0x0010ull, "PROCESS_VM_READ" },
	{ 0x0020ull, "PROCESS_VM_WRITE" },
	{ 0x0040ull, "PROCESS_DUP_HANDLE" },
	{ 0x0080ull, "PROCESS_CREATE_PROCESS" },
	{ 0x0100ull, "PROCESS_SET_QUOTA" },
	{ 0x0200ull, "PROCESS_SET_INFORMATION" },
	{ 0x0400ull, "PROCESS_QUERY_INFORMATION" },
	{ 0x0800ull, "PROCESS_SUSPEND_RESUME" },
	{ 0x1000ull, "PROCESS_QUERY_LIMITED_INFORMATION" },
	{ 0x1FFFFFull, "PROCESS_ALL_ACCESS" },
};

inline constexpr entry_t kEquateThreadAccess[] = {
	{ 0x0001ull, "THREAD_TERMINATE" },
	{ 0x0002ull, "THREAD_SUSPEND_RESUME" },
	{ 0x0008ull, "THREAD_GET_CONTEXT" },
	{ 0x0010ull, "THREAD_SET_CONTEXT" },
	{ 0x0020ull, "THREAD_SET_INFORMATION" },
	{ 0x0040ull, "THREAD_QUERY_INFORMATION" },
	{ 0x0080ull, "THREAD_SET_THREAD_TOKEN" },
	{ 0x0100ull, "THREAD_IMPERSONATE" },
	{ 0x0200ull, "THREAD_DIRECT_IMPERSONATION" },
	{ 0x0400ull, "THREAD_SET_LIMITED_INFORMATION" },
	{ 0x0800ull, "THREAD_QUERY_LIMITED_INFORMATION" },
	{ 0x1FFFFFull, "THREAD_ALL_ACCESS" },
};

inline constexpr entry_t kEquateTokenAccess[] = {
	{ 0x0001ull, "TOKEN_ASSIGN_PRIMARY" },
	{ 0x0002ull, "TOKEN_DUPLICATE" },
	{ 0x0004ull, "TOKEN_IMPERSONATE" },
	{ 0x0008ull, "TOKEN_QUERY" },
	{ 0x0010ull, "TOKEN_QUERY_SOURCE" },
	{ 0x0020ull, "TOKEN_ADJUST_PRIVILEGES" },
	{ 0x0040ull, "TOKEN_ADJUST_GROUPS" },
	{ 0x0080ull, "TOKEN_ADJUST_DEFAULT" },
	{ 0x0100ull, "TOKEN_ADJUST_SESSIONID" },
};

inline constexpr entry_t kEquateKeyAccess[] = {
	{ 0x0001ull, "KEY_QUERY_VALUE" },
	{ 0x0002ull, "KEY_SET_VALUE" },
	{ 0x0004ull, "KEY_CREATE_SUB_KEY" },
	{ 0x0008ull, "KEY_ENUMERATE_SUB_KEYS" },
	{ 0x0010ull, "KEY_NOTIFY" },
	{ 0x0020ull, "KEY_CREATE_LINK" },
	{ 0x0100ull, "KEY_WOW64_64KEY" },
	{ 0x0200ull, "KEY_WOW64_32KEY" },
	{ 0x20006ull, "KEY_WRITE" },
	{ 0x20019ull, "KEY_READ" },
	{ 0xF003Full, "KEY_ALL_ACCESS" },
};

namespace detail {

template <typename T, std::size_t N>
constexpr bool entries_sorted(const T (&table)[N])
{
	for (std::size_t i = 1; i < N; ++i) {
		if (!(table[i - 1].first < table[i].first))
			return false;
	}
	return true;
}

static_assert(entries_sorted(kEquateNtstatus), "kEquateNtstatus must be strictly sorted");
static_assert(entries_sorted(kEquateHresult), "kEquateHresult must be strictly sorted");
static_assert(entries_sorted(kEquateWin32Error), "kEquateWin32Error must be strictly sorted");
static_assert(entries_sorted(kEquateWaitResult), "kEquateWaitResult must be strictly sorted");
static_assert(entries_sorted(kEquateMemProtect), "kEquateMemProtect must be strictly sorted");
static_assert(entries_sorted(kEquateMemState), "kEquateMemState must be strictly sorted");
static_assert(entries_sorted(kEquateGenericAccess), "kEquateGenericAccess must be strictly sorted");
static_assert(entries_sorted(kEquateFileShare), "kEquateFileShare must be strictly sorted");
static_assert(entries_sorted(kEquateCreationDisposition), "kEquateCreationDisposition must be strictly sorted");
static_assert(entries_sorted(kEquateFileFlags), "kEquateFileFlags must be strictly sorted");
static_assert(entries_sorted(kEquateSocketAddressFamily), "kEquateSocketAddressFamily must be strictly sorted");
static_assert(entries_sorted(kEquateSocketType), "kEquateSocketType must be strictly sorted");
static_assert(entries_sorted(kEquateSocketProtocol), "kEquateSocketProtocol must be strictly sorted");
static_assert(entries_sorted(kEquateWindowMessage), "kEquateWindowMessage must be strictly sorted");
static_assert(entries_sorted(kEquateDialogResult), "kEquateDialogResult must be strictly sorted");
static_assert(entries_sorted(kEquateHeapFlags), "kEquateHeapFlags must be strictly sorted");
static_assert(entries_sorted(kEquateProcessAccess), "kEquateProcessAccess must be strictly sorted");
static_assert(entries_sorted(kEquateThreadAccess), "kEquateThreadAccess must be strictly sorted");
static_assert(entries_sorted(kEquateTokenAccess), "kEquateTokenAccess must be strictly sorted");
static_assert(entries_sorted(kEquateKeyAccess), "kEquateKeyAccess must be strictly sorted");

inline const entry_t* find_sorted(const entry_t* table, std::size_t count, std::uint64_t value)
{
	std::size_t lo = 0;
	std::size_t hi = count;
	while (lo < hi) {
		const std::size_t mid = lo + (hi - lo) / 2;
		if (table[mid].first < value)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < count && table[lo].first == value)
		return &table[lo];
	return nullptr;
}

inline bool name_starts_with(std::string_view name, std::string_view prefix)
{
	return name.size() >= prefix.size() && name.compare(0, prefix.size(), prefix) == 0;
}

inline bool name_contains(std::string_view name, std::string_view needle)
{
	return name.find(needle) != std::string_view::npos;
}

inline bool name_contains_any(std::string_view name,
                              std::initializer_list<std::string_view> needles)
{
	for (const auto needle : needles) {
		if (name_contains(name, needle))
			return true;
	}
	return false;
}

}

inline const entry_t* equate_table_data(equate_table_id_t table, std::size_t& count)
{
	switch (table) {
	case equate_table_id_t::ntstatus: count = std::size(kEquateNtstatus); return kEquateNtstatus;
	case equate_table_id_t::hresult: count = std::size(kEquateHresult); return kEquateHresult;
	case equate_table_id_t::win32_error: count = std::size(kEquateWin32Error); return kEquateWin32Error;
	case equate_table_id_t::wait_result: count = std::size(kEquateWaitResult); return kEquateWaitResult;
	case equate_table_id_t::mem_protect: count = std::size(kEquateMemProtect); return kEquateMemProtect;
	case equate_table_id_t::mem_state: count = std::size(kEquateMemState); return kEquateMemState;
	case equate_table_id_t::generic_access: count = std::size(kEquateGenericAccess); return kEquateGenericAccess;
	case equate_table_id_t::file_share: count = std::size(kEquateFileShare); return kEquateFileShare;
	case equate_table_id_t::creation_disposition: count = std::size(kEquateCreationDisposition); return kEquateCreationDisposition;
	case equate_table_id_t::file_flags: count = std::size(kEquateFileFlags); return kEquateFileFlags;
	case equate_table_id_t::socket_address_family: count = std::size(kEquateSocketAddressFamily); return kEquateSocketAddressFamily;
	case equate_table_id_t::socket_type: count = std::size(kEquateSocketType); return kEquateSocketType;
	case equate_table_id_t::socket_protocol: count = std::size(kEquateSocketProtocol); return kEquateSocketProtocol;
	case equate_table_id_t::window_message: count = std::size(kEquateWindowMessage); return kEquateWindowMessage;
	case equate_table_id_t::dialog_result: count = std::size(kEquateDialogResult); return kEquateDialogResult;
	case equate_table_id_t::heap_flags: count = std::size(kEquateHeapFlags); return kEquateHeapFlags;
	case equate_table_id_t::process_access: count = std::size(kEquateProcessAccess); return kEquateProcessAccess;
	case equate_table_id_t::thread_access: count = std::size(kEquateThreadAccess); return kEquateThreadAccess;
	case equate_table_id_t::token_access: count = std::size(kEquateTokenAccess); return kEquateTokenAccess;
	case equate_table_id_t::key_access: count = std::size(kEquateKeyAccess); return kEquateKeyAccess;
	}
	count = 0;
	return nullptr;
}

inline bool lookup_equate_table(equate_table_id_t table, std::uint64_t value, std::string& out_label)
{
	if (value == 0 || value > 0xFFFFFFFFull)
		return false;
	std::size_t count = 0;
	const entry_t* data = equate_table_data(table, count);
	if (!data)
		return false;
	const entry_t* hit = detail::find_sorted(data, count, value);
	if (!hit)
		return false;
	out_label.assign(hit->second);
	return true;
}

inline bool lookup_equate_shaped(std::uint64_t value, equate_match_t& out)
{
	if (!looks_like_status(value))
		return false;
	if (const entry_t* hit = detail::find_sorted(
			kEquateNtstatus, std::size(kEquateNtstatus), value)) {
		out.table = equate_table_id_t::ntstatus;
		out.name = hit->second;
		return true;
	}
	if (const entry_t* hit = detail::find_sorted(
			kEquateHresult, std::size(kEquateHresult), value)) {
		out.table = equate_table_id_t::hresult;
		out.name = hit->second;
		return true;
	}
	return false;
}

inline bool lookup_equate_affinity(std::string_view callee_name,
                                   std::uint64_t value,
                                   equate_match_t& out)
{
	if (callee_name.empty() || value == 0 || value > 0xFFFFFFFFull)
		return false;
	const auto match = [value, &out](equate_table_id_t table) {
		std::size_t count = 0;
		const entry_t* data = equate_table_data(table, count);
		if (!data)
			return false;
		const entry_t* hit = detail::find_sorted(data, count, value);
		if (!hit)
			return false;
		out.table = table;
		out.name = hit->second;
		return true;
	};
	if (detail::name_contains_any(callee_name, {
			"SendMessage", "PostMessage", "PostThreadMessage", "DefWindowProc",
			"CallWindowProc", "RegisterClass", "CreateWindow", "GetDlgItem",
			"SetDlgItem", "SendNotifyMessage", "SendMessageTimeout",
			"SendDlgItemMessage", "DispatchMessage", "RegisterWindowMessage" })) {
		if (match(equate_table_id_t::window_message))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"DialogBox", "CreateDialog", "MessageBox", "EndDialog" })) {
		if (match(equate_table_id_t::dialog_result))
			return true;
	}
	if ((detail::name_starts_with(callee_name, "Reg") ||
	     detail::name_contains(callee_name, "!Reg")) &&
	    !detail::name_contains(callee_name, "ister")) {
		if (match(equate_table_id_t::key_access))
			return true;
		if (match(equate_table_id_t::win32_error))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"WaitFor", "Sleep", "SignalObjectAndWait", "MsgWait" })) {
		if (match(equate_table_id_t::wait_result))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"VirtualAlloc", "VirtualProtect", "VirtualFree", "VirtualQuery",
			"NtAllocateVirtualMemory", "NtProtectVirtualMemory",
			"NtFreeVirtualMemory", "NtQueryVirtualMemory",
			"NtMapViewOfSection", "NtUnmapViewOfSection" })) {
		if (match(equate_table_id_t::mem_protect))
			return true;
		if (match(equate_table_id_t::mem_state))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"CreateFile", "CreateFileMapping", "CreateMutex", "OpenMutex",
			"CreateEvent", "OpenEvent", "CreateSemaphore", "OpenSemaphore",
			"CreateNamedPipe", "CreateJobObject", "OpenJobObject",
			"OpenFileMapping", "MapViewOfFile", "NtCreateFile",
			"NtOpenSection", "NtCreateMutant", "NtCreateEvent",
			"NtCreateSemaphore", "NtCreateJobObject" })) {
		if (match(equate_table_id_t::generic_access))
			return true;
		if (match(equate_table_id_t::file_share))
			return true;
		if (match(equate_table_id_t::creation_disposition))
			return true;
		if (match(equate_table_id_t::file_flags))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"socket", "WSAConnect", "connect", "bind", "accept",
			"sendto", "recvfrom", "setsockopt", "getaddrinfo", "GetAddrInfo" })) {
		if (match(equate_table_id_t::socket_address_family))
			return true;
		if (match(equate_table_id_t::socket_type))
			return true;
		if (match(equate_table_id_t::socket_protocol))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"HeapAlloc", "HeapReAlloc", "HeapFree", "HeapCreate",
			"HeapSetInformation", "HeapQueryInformation", "RtlAllocateHeap",
			"RtlCreateHeap", "RtlFreeHeap", "RtlReAllocateHeap" })) {
		if (match(equate_table_id_t::heap_flags))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"OpenProcessToken", "OpenThreadToken", "NtOpenProcessToken",
			"NtOpenThreadToken", "AdjustTokenPrivileges", "SetTokenInformation" })) {
		if (match(equate_table_id_t::token_access))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"OpenProcess", "NtOpenProcess", "CreateProcess" })) {
		if (match(equate_table_id_t::process_access))
			return true;
	}
	if (detail::name_contains_any(callee_name, {
			"OpenThread", "NtOpenThread", "CreateRemoteThread",
			"NtCreateThreadEx" })) {
		if (match(equate_table_id_t::thread_access))
			return true;
	}
	if (detail::name_starts_with(callee_name, "Nt") ||
	    detail::name_starts_with(callee_name, "Zw")) {
		if (match(equate_table_id_t::ntstatus))
			return true;
	}
	if (detail::name_starts_with(callee_name, "Rtl")) {
		if (match(equate_table_id_t::ntstatus))
			return true;
	}
	return false;
}

}
