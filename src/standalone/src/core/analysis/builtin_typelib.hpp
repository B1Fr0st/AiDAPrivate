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

}
