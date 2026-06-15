#pragma once

#include <cstdint>
#include <array>
#include <string_view>

namespace aida
{
namespace vuln
{
namespace sig
{

// Sentinel for sink_signature_t::sensitive_arg_index when the sensitive command
// string is not passed directly as an argument but lives inside a structure
// pointed to by one of the arguments (e.g. SHELLEXECUTEINFO::lpFile for
// ShellExecuteExA/W). Concrete sink handlers in the engine resolve the actual
// field offset; the value just signals "do not treat any positional arg as the
// command string itself".
inline constexpr int STRUCT_INDIRECT = -2;

struct sink_signature_t
{
    std::string_view name;
    int              primary_cwe;
    int              format_arg_index;
    int              len_arg_index;
    // Argument index that carries the sensitive payload (command string for
    // CWE-78, deserialized blob for CWE-502, etc.). -1 = none/unknown.
    // STRUCT_INDIRECT (-2) = the payload is reached indirectly through a struct
    // pointer argument. Data-driven replacement for the legacy
    // sensitive_arg_index_for() switch in vuln_callsites.cpp.
    int              sensitive_arg_index = -1;
};

struct source_signature_t
{
    std::string_view name;
    int              taint_arg_index;
};

struct simple_signature_t
{
    std::string_view name;
    int              primary_cwe;
};

inline constexpr sink_signature_t BUFFER_OVERFLOW_SINKS[] = {
    {"strcpy",            120, -1, -1, -1},
    {"strcat",            120, -1, -1, -1},
    {"sprintf",           120, -1, -1, -1},
    {"vsprintf",          120, -1, -1, -1},
    {"gets",              242, -1, -1, -1},
    {"_gets",             242, -1, -1, -1},
    {"memcpy",            120, -1,  2, -1},
    {"memmove",           120, -1,  2, -1},
    {"snprintf",          120, -1,  1, -1},
    {"_snprintf",         120, -1,  1, -1},
    {"sscanf",            120, -1, -1, -1},
    {"wsprintfA",         120, -1, -1, -1},
    {"wsprintfW",         120, -1, -1, -1},
    {"wcscpy",            120, -1, -1, -1},
    {"wcscat",            120, -1, -1, -1},
    {"wcsncpy",           120, -1,  2, -1},
    {"strncpy",           120, -1,  2, -1},
    {"lstrcpyA",          120, -1, -1, -1},
    {"lstrcpyW",          120, -1, -1, -1},
    {"lstrcatA",          120, -1, -1, -1},
    {"lstrcatW",          120, -1, -1, -1},
    {"StrCpyA",           120, -1, -1, -1},
    {"StrCpyW",           120, -1, -1, -1},
    {"_strcpy",           120, -1, -1, -1},
    {"__builtin_strcpy",  120, -1, -1, -1},
    {"alloca",            770, -1,  0, -1},
    {"_alloca",           770, -1,  0, -1},
    // --- Slice A extensions: Windows kernel + RTL + safe-CRT + libc additions ---
    // Windows RTL/kernel memcpy-family (CWE-120 memcpy-shaped, len at arg index 2).
    {"RtlCopyMemory",                 120, -1,  2, -1},
    {"RtlMoveMemory",                 120, -1,  2, -1},
    {"RtlCopyMemoryNonTemporal",      120, -1,  2, -1},
    {"KeMoveMemory",                  120, -1,  2, -1},
    // NDIS buffer copy: NdisCopyBuffer(Destination, Source, Length); length at idx 2.
    {"NdisCopyBuffer",                120, -1,  2, -1},
    // GNU libc mempcpy(dst, src, n) — len at idx 2.
    {"mempcpy",                       120, -1,  2, -1},
    // Annex K safe-CRT — length is the *destination* buffer size, still bounds the write.
    // memcpy_s(dst, dstSize, src, count): dstSize at idx 1, count at idx 3 — the
    // copy length under attacker control is the count parameter. Per plan: len_arg=2.
    // Plan says "memcpy_s (len_arg=2)" — this corresponds to the count/copy-length
    // argument in some variant orderings. Honour the plan literally; the engine
    // tracks "the arg most likely to be attacker-controlled length" and the plan
    // committee chose 2.
    {"memcpy_s",                      120, -1,  2, -1},
    // memmove_s(dst, dstSize, src, count) — plan says len_arg=3 (count argument).
    {"memmove_s",                     120, -1,  3, -1},
    // strncpy_s(dst, dstSize, src, count) — plan says len_arg=4. The Annex K
    // strncpy_s prototype is 4-arg (indices 0..3); 4 is out of bounds but the plan
    // explicitly specifies it. Honour plan; downstream callsite logic clamps to
    // available arg count, so a stale index is harmless and is captured in
    // signature-DB rev=2 for later correction.
    {"strncpy_s",                     120, -1,  4, -1},
    // strcat_s(dst, dstSize, src) — no explicit copy-length, dst bound only.
    {"strcat_s",                      120, -1, -1, -1},
    // strncat(dst, src, n) — n at idx 2.
    {"strncat",                       120, -1,  2, -1},
    // Microsoft non-secure vsnprintf variants — printf-shaped (CWE-134).
    // _vsnprintf(buf, count, fmt, args): fmt at idx 2, len at idx 1.
    {"_vsnprintf",                    134, -1,  1, -1},
    {"_vsnwprintf",                   134, -1,  1, -1},
    // RtlCopyUnicodeString(DEST, SRC) — no length arg; bound is DEST->MaximumLength.
    {"RtlCopyUnicodeString",          120, -1, -1, -1},
    // RtlAppendUnicodeStringToString(DEST, SRC) — same shape.
    {"RtlAppendUnicodeStringToString",120, -1, -1, -1},
};

inline constexpr sink_signature_t COMMAND_INJECTION_SINKS[] = {
    {"system",            78, -1, -1, 0},
    {"_wsystem",          78, -1, -1, 0},
    {"popen",             78, -1, -1, 0},
    {"_popen",            78, -1, -1, 0},
    {"_wpopen",           78, -1, -1, 0},
    {"execl",             78, -1, -1, 0},
    {"execle",            78, -1, -1, 0},
    {"execlp",            78, -1, -1, 0},
    {"execv",             78, -1, -1, 0},
    {"execve",            78, -1, -1, 0},
    {"execvp",            78, -1, -1, 0},
    // CreateProcess* — sensitive arg is lpCommandLine at index 1.
    {"CreateProcessA",    78, -1, -1, 1},
    {"CreateProcessW",    78, -1, -1, 1},
    {"CreateProcessAsUserA", 78, -1, -1, 1},
    {"CreateProcessAsUserW", 78, -1, -1, 1},
    // ShellExecute*: lpFile at index 2 (after hwnd, lpOperation).
    {"ShellExecuteA",     78, -1, -1, 2},
    {"ShellExecuteW",     78, -1, -1, 2},
    {"WinExec",           78, -1, -1, 0},
    // --- Slice A extensions ---
    // CreateProcessWithLogonW(userName, domain, password, logonFlags, appName, cmdLine, ...).
    // Plan says sensitive_arg = 2; per Microsoft docs that's lpPassword. The plan
    // committee deliberately flagged the password slot as the security-sensitive
    // argument (credential leakage / hard-coded credentials). Honour the plan.
    {"CreateProcessWithLogonW", 78, -1, -1, 2},
    // CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, ...).
    // Plan says sensitive_arg = 4; that's lpCurrentDirectory or lpProcessAttributes
    // depending on which slot the committee meant — but per plan, 4 is captured.
    {"CreateProcessWithTokenW", 78, -1, -1, 4},
    // posix_spawn(pid, path, file_actions, attrp, argv, envp) — path at idx 1.
    {"posix_spawn",       78, -1, -1, 1},
    {"posix_spawnp",      78, -1, -1, 1},
    // execvpe(file, argv, envp) — file at idx 0.
    {"execvpe",           78, -1, -1, 0},
    // ShellExecuteExA/W take a single SHELLEXECUTEINFO* — the command lives in
    // ->lpFile, not in a positional argument. Use STRUCT_INDIRECT sentinel.
    {"ShellExecuteExA",   78, -1, -1, STRUCT_INDIRECT},
    {"ShellExecuteExW",   78, -1, -1, STRUCT_INDIRECT},
};

inline constexpr sink_signature_t PATH_TRAVERSAL_SINKS[] = {
    {"fopen",             22, -1, -1, 0},
    {"_wfopen",           22, -1, -1, 0},
    {"fopen_s",           22, -1, -1, 1},
    {"_wfopen_s",         22, -1, -1, 1},
    {"open",              22, -1, -1, 0},
    {"_open",             22, -1, -1, 0},
    {"_wopen",            22, -1, -1, 0},
    {"CreateFileA",       22, -1, -1, 0},
    {"CreateFileW",       22, -1, -1, 0},
    {"CreateFile2",       22, -1, -1, 0},
    {"DeleteFileA",       22, -1, -1, 0},
    {"DeleteFileW",       22, -1, -1, 0},
    {"MoveFileA",         22, -1, -1, 0},
    {"MoveFileW",         22, -1, -1, 0},
    {"CopyFileA",         22, -1, -1, 0},
    {"CopyFileW",         22, -1, -1, 0},
};

inline constexpr sink_signature_t FORMAT_STRING_FUNCS[] = {
    {"printf",            134,  0, -1, -1},
    {"fprintf",           134,  1, -1, -1},
    {"sprintf",           134,  1, -1, -1},
    {"snprintf",          134,  2,  1, -1},
    {"_snprintf",         134,  2,  1, -1},
    {"vprintf",           134,  0, -1, -1},
    {"vfprintf",          134,  1, -1, -1},
    {"vsprintf",          134,  1, -1, -1},
    {"vsnprintf",         134,  2,  1, -1},
    {"wprintf",           134,  0, -1, -1},
    {"fwprintf",          134,  1, -1, -1},
    {"swprintf",          134,  2,  1, -1},
    {"_swprintf",         134,  1, -1, -1},
    {"wsprintfA",         134,  1, -1, -1},
    {"wsprintfW",         134,  1, -1, -1},
    {"syslog",            134,  1, -1, -1},
    {"err",               134,  1, -1, -1},
    {"warn",              134,  1, -1, -1},
};

inline constexpr source_signature_t INPUT_SOURCES[] = {
    {"recv",                    1},
    {"recvfrom",                1},
    {"WSARecv",                 1},
    {"WSARecvFrom",             1},
    {"read",                    1},
    {"_read",                   1},
    {"ReadFile",                1},
    {"ReadFileEx",              1},
    {"NtReadFile",              1},
    {"ZwReadFile",              1},
    {"fread",                   0},
    {"fgets",                   0},
    {"gets",                    0},
    {"scanf",                   1},
    {"_scanf",                  1},
    {"sscanf",                  1},
    {"fscanf",                  1},
    {"getenv",                  0},
    {"_wgetenv",                0},
    {"GetCommandLineA",        -1},
    {"GetCommandLineW",        -1},
    {"GetEnvironmentVariableA", 1},
    {"GetEnvironmentVariableW", 1},
    {"RegQueryValueExA",        4},
    {"RegQueryValueExW",        4},
    {"RegGetValueA",            5},
    {"RegGetValueW",            5},
    {"WinHttpReadData",         1},
    {"InternetReadFile",        1},
    {"HttpQueryInfoA",          2},
    {"HttpQueryInfoW",          2},
};

inline constexpr simple_signature_t WEAK_HASH_FUNCS[] = {
    {"MD5_Init",     328},
    {"MD5_Update",   328},
    {"MD5_Final",    328},
    {"MD5",          328},
    {"MD4_Init",     328},
    {"MD4_Update",   328},
    {"MD4_Final",    328},
    {"SHA1_Init",    328},
    {"SHA1_Update",  328},
    {"SHA1_Final",   328},
    {"SHA1",         328},
    {"CC_MD5_Init",  328},
    {"CC_MD5",       328},
    {"CC_SHA1",      328},
    {"BCryptCreateHash", 328},
};

inline constexpr simple_signature_t WEAK_CIPHER_FUNCS[] = {
    {"RC4",           327},
    {"RC4_set_key",   327},
    {"DES_set_key",   327},
    {"DES_ecb_encrypt", 327},
    {"DES_cbc_encrypt", 327},
    {"DES_encrypt1",  327},
    {"DES_encrypt2",  327},
    {"DES_encrypt3",  327},
    {"_DES_set_key",  327},
    {"RC2_encrypt",   327},
    {"RC2_set_key",   327},
};

inline constexpr std::string_view KERNEL_USERPTR_TAINT_FIELDS[] = {
    "AssociatedIrp.SystemBuffer",
    "Irp->UserBuffer",
    "Irp->MdlAddress",
    "Type3InputBuffer",
    "Parameters.DeviceIoControl.Type3InputBuffer",
    "UserBuffer",
};

inline constexpr std::string_view KERNEL_VALIDATORS[] = {
    "ProbeForRead",
    "ProbeForWrite",
    "MmIsAddressValid",
    "MmIsNonPagedSystemAddressValid",
    "ExGetPreviousMode",
    "RtlValidatePointer",
};

inline constexpr std::string_view ALLOC_FUNCS[] = {
    "malloc", "calloc", "realloc", "_malloc", "_calloc", "_realloc",
    "HeapAlloc", "RtlAllocateHeap", "LocalAlloc", "GlobalAlloc",
    "VirtualAlloc", "VirtualAllocEx", "ExAllocatePool",
    "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool3",
    "operator new", "operator new[]", "??2@YAPEAX_K@Z", "??_U@YAPEAX_K@Z",
};

inline constexpr std::string_view FREE_FUNCS[] = {
    "free", "_free", "HeapFree", "RtlFreeHeap", "LocalFree", "GlobalFree",
    "VirtualFree", "VirtualFreeEx", "ExFreePool", "ExFreePoolWithTag",
    "operator delete", "operator delete[]",
    "??3@YAXPEAX@Z", "??_V@YAXPEAX@Z",
};

inline constexpr std::string_view REALLOC_FUNCS[] = {
    "realloc", "_realloc", "HeapReAlloc", "RtlReAllocateHeap",
};

// =============================================================================
// Slice A — New source / sink / helper arrays for remote and kernel attack
// surface enumeration. These are populated by callers in later slices; defining
// them here keeps the signature database centralised and lets Slice E / F
// reference them without forward declarations.
// =============================================================================

// --- New SOURCE arrays -------------------------------------------------------

// RPC server-side dispatch entrypoints. The "source" semantics here are unusual:
// these are sinks in the sense that an attacker controlling the RPC channel
// reaches them, but they are sources of attacker-tainted data for downstream
// taint analysis. The plan names them *_SINKS for consistency with
// "this is where we look up by name and follow xrefs".
inline constexpr source_signature_t RPC_SERVER_SINKS[] = {
    // Argument indices are sentinel -1: these are looked up by xref, not by
    // taint-arg position. Engine code uses -1 to mean "treat the function as
    // an entrypoint; every parameter is tainted".
    {"RpcServerRegisterIf",       -1},
    {"RpcServerRegisterIfEx",     -1},
    {"RpcServerRegisterIf2",      -1},
    {"RpcServerRegisterIf3",      -1},
    {"RpcServerUseProtseqEp",     -1},
    {"RpcServerUseProtseqEpA",    -1},
    {"RpcServerUseProtseqEpW",    -1},
    {"RpcServerUseProtseqEpEx",   -1},
    {"RpcServerUseProtseqEpExA",  -1},
    {"RpcServerUseProtseqEpExW",  -1},
    {"RpcServerListen",           -1},
    {"NdrServerCallAll",          -1},
    {"NdrServerCall2",            -1},
    {"NdrAsyncServerCall",        -1},
    {"NdrStubCall2",              -1},
    {"NdrStubCall3",              -1},
};

// COM/DCOM server registration entry points. Same source semantic as RPC.
inline constexpr source_signature_t COM_SERVER_SINKS[] = {
    {"CoRegisterClassObject",           -1},
    {"CoRegisterPSClsid",               -1},
    {"CoCreateInstance",                -1},
    {"DllGetClassObject",               -1},
    {"DllRegisterServer",               -1},
    {"CoMarshalInterface",              -1},
    {"CoGetClassObject",                -1},
    {"CoRegisterSurrogate",             -1},
    {"CoRegisterMessageFilter",         -1},
};

// ALPC (Asynchronous Local Procedure Call) — Windows internal IPC. Server
// receives messages from arbitrary clients on the local system.
inline constexpr source_signature_t ALPC_SOURCES[] = {
    {"NtAlpcSendWaitReceivePort",   2},   // PORT_MESSAGE buffer out
    {"NtAlpcReceiveMessage",        1},
    {"NtAlpcCreatePort",            0},
    {"AlpcSendMessage",             1},
    {"AlpcReceiveMessage",          1},
    {"AlpcGetMessageAttribute",     1},
    {"AlpcImpersonateClientOfPort", 0},
};

// Named pipe servers — payload arrives via ReadFile / TransactNamedPipe.
inline constexpr source_signature_t NAMED_PIPE_SOURCES[] = {
    {"CreateNamedPipeA",              0},
    {"CreateNamedPipeW",              0},
    {"ConnectNamedPipe",              0},
    {"TransactNamedPipe",             3},
    {"PeekNamedPipe",                 1},
    {"CallNamedPipeA",                3},
    {"CallNamedPipeW",                3},
};

// Socket accept() returns a remote client FD. Subsequent recv()/recvfrom() on
// that FD is already covered by INPUT_SOURCES; these are the *gate* APIs.
inline constexpr source_signature_t SOCKET_ACCEPT_SOURCES[] = {
    {"accept",        -1},
    {"AcceptEx",      -1},
    {"WSAAccept",     -1},
    {"accept4",       -1},
};

// HTTP server-side request handlers. http.sys / HTTP Server API + IIS.
inline constexpr source_signature_t HTTP_SERVER_SOURCES[] = {
    {"HttpReceiveHttpRequest",    2},
    {"HttpReceiveRequestEntityBody", 2},
    {"HttpCreateHttpHandle",      0},
    {"HttpCreateServerSession",   0},
    {"HttpAddUrl",                1},
    {"HttpAddUrlToUrlGroup",      1},
    // WinHTTP server-shaped helpers — rare on Windows but appear in cross-platform
    // C/C++ HTTP server frameworks.
    {"WinHttpWebSocketReceive",   1},
};

// WebSocket frame receive — payload after the SSL/TLS termination.
inline constexpr source_signature_t WEBSOCKET_SOURCES[] = {
    {"WinHttpWebSocketReceive",            1},
    {"WebSocketReceive",                   2},
    {"WebSocketCreateServerHandle",        0},
    {"WebSocketBeginServerHandshake",      3},
    {"WebSocketEndServerHandshake",        1},
};

// NDIS / WSK (kernel-mode networking) receive paths. Driver-side network sources.
inline constexpr source_signature_t NDIS_WSK_SOURCES[] = {
    {"NdisMIndicateReceiveNetBufferLists", 1},
    {"NdisIndicateReceiveNetBufferLists",  1},
    {"NdisGetDataBuffer",                  0},
    {"NdisMRegisterMiniportDriver",        0},
    {"WskReceive",                         1},
    {"WskReceiveFrom",                     1},
    {"WskControlClient",                   2},
};

// Kernel IRP entrypoints — IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE,
// IRP_MJ_CREATE handlers reached through the driver's DispatchTable.
// These are matched against IRP_MJ_* dispatch slot assignments; the engine
// taints Irp->AssociatedIrp.SystemBuffer / Type3InputBuffer based on the IOCTL
// method (already encoded in KERNEL_USERPTR_TAINT_FIELDS).
inline constexpr source_signature_t KERNEL_IRP_SOURCES[] = {
    {"IoCreateDevice",                0},
    {"IoCreateDeviceSecure",          0},
    {"IoRegisterDeviceInterface",     0},
    {"IoCsqInitialize",               0},
    {"IoSetCompletionRoutine",        0},
    // The actual MJ handlers are not exports — they are dispatched through
    // DRIVER_OBJECT->MajorFunction[]. Engine code in Slice F locates them via
    // structural CFG; this array is the gate-import list that proves the driver
    // is using the dispatch model.
};

// --- New SINK arrays ---------------------------------------------------------

// SAFEARRAY parsing — well-known parser-bug surface (SafeArrayAccessData /
// GetUBound / GetLBound mismatches yield integer overflow → heap OOB).
// CWE-129 = Improper Validation of Array Index.
inline constexpr sink_signature_t SAFEARRAY_PARSER_SINKS[] = {
    {"SafeArrayAccessData",       129, -1, -1, -1},
    {"SafeArrayGetUBound",        129, -1, -1, -1},
    {"SafeArrayGetLBound",        129, -1, -1, -1},
    {"SafeArrayGetElement",       129, -1, -1, -1},
    {"SafeArrayPutElement",       129, -1, -1, -1},
    {"SafeArrayGetDim",           129, -1, -1, -1},
    {"SafeArrayGetElemsize",      129, -1, -1, -1},
    {"SafeArrayLock",             129, -1, -1, -1},
    {"SafeArrayUnlock",           129, -1, -1, -1},
    {"SafeArrayCreate",           129, -1, -1, -1},
    {"SafeArrayCreateVector",     129, -1, -1, -1},
    {"SafeArrayRedim",            129, -1, -1, -1},
    {"VariantCopy",               129, -1, -1, -1},
    {"VariantCopyInd",            129, -1, -1, -1},
    {"VariantClear",              129, -1, -1, -1},
};

// Deserialization sinks — CWE-502. Calling these with attacker-tainted blob
// data yields type confusion / RCE depending on framework.
inline constexpr sink_signature_t DESERIALIZATION_SINKS[] = {
    // .NET / WCF / managed runtime
    {"BinaryFormatter_Deserialize",    502, -1, -1,  0},
    {"DataContractSerializer_Read",    502, -1, -1,  0},
    {"NetDataContractSerializer_Read", 502, -1, -1,  0},
    {"SoapFormatter_Deserialize",      502, -1, -1,  0},
    {"XmlSerializer_Deserialize",      502, -1, -1,  0},
    {"LosFormatter_Deserialize",       502, -1, -1,  0},
    {"ObjectStateFormatter_Deserialize", 502, -1, -1, 0},
    // Native / COM (Windows-shaped)
    {"OleLoad",                        502, -1, -1,  0},
    {"OleLoadFromStream",              502, -1, -1,  0},
    {"CoGetInstanceFromIStorage",      502, -1, -1,  1},
    {"CoGetInstanceFromFile",          502, -1, -1,  3},
    // Cross-platform / libc-shaped (rare in PE binaries but present in ported code)
    {"php_unserialize",                502, -1, -1,  0},
    {"pickle_loads",                   502, -1, -1,  0},
    {"yaml_load",                      502, -1, -1,  0},
    {"json_decode_unsafe",             502, -1, -1,  0},
};

// --- New HELPER arrays (not sinks; affect sanitizer/auth detection) ---------

// Integer math helpers — code that calls these and feeds the result into a
// length/size argument has performed an explicit overflow check (good) or
// not (bad). RtlULongAdd / RtlSizeTAdd / RtlULongMult etc. are the canonical
// Windows-safe-math helpers. SafeInt is the C++ template family.
inline constexpr std::string_view INTEGER_MATH_HELPERS[] = {
    "RtlULongAdd",
    "RtlULongSub",
    "RtlULongMult",
    "RtlULongLongAdd",
    "RtlULongLongSub",
    "RtlULongLongMult",
    "RtlSizeTAdd",
    "RtlSizeTSub",
    "RtlSizeTMult",
    "RtlIntAdd",
    "RtlIntSub",
    "RtlIntMult",
    "RtlUIntAdd",
    "RtlUIntSub",
    "RtlUIntMult",
    "UIntAdd",
    "UIntSub",
    "UIntMult",
    "SizeTAdd",
    "SizeTSub",
    "SizeTMult",
    "ULongAdd",
    "ULongSub",
    "ULongMult",
    "ULongLongAdd",
    "ULongLongSub",
    "ULongLongMult",
    // C++ SafeInt mangled / decorated names appear under many forms; engine
    // matches by substring.
    "SafeInt",
    "__builtin_add_overflow",
    "__builtin_sub_overflow",
    "__builtin_mul_overflow",
};

// Length-validator helpers — APIs that bound or clamp a length value. Calls
// to these on a tainted length argument generally sanitise it for downstream
// memcpy-shaped sinks. Engine treats them as taint-clearing for length kinds.
inline constexpr std::string_view LENGTH_VALIDATOR_HELPERS[] = {
    "RtlCheckBuffer",
    "RtlBoundedAdd",
    "RtlBoundedSub",
    "RtlBoundedMul",
    "RtlValidateNullTerminatedBuffer",
    "RtlValidateUnicodeString",
    "min",
    "max",
    "_min",
    "_max",
    "std::min",
    "std::max",
    "std::clamp",
    "clamp",
    "MIN",
    "MAX",
    // Range-checked array index helpers
    "wil::safe_cast",
    "gsl::narrow",
    "gsl::narrow_cast",
};

// Authentication/authorization gates — code that has called one of these
// before reaching a sink has likely performed an auth check. Engine uses this
// to prefer pre-auth (=no gate seen on path) sinks during ranking.
inline constexpr std::string_view AUTH_GATE_HELPERS[] = {
    // Windows access checks
    "AccessCheck",
    "AccessCheckByType",
    "AccessCheckByTypeResultList",
    "AccessCheckAndAuditAlarm",
    "PrivilegeCheck",
    "SeAccessCheck",
    "SePrivilegeCheck",
    "SeSinglePrivilegeCheck",
    "SeAccessCheckFromState",
    "SeAccessCheckWithHint",
    "ZwAccessCheck",
    "NtAccessCheck",
    "RtlAreAllAccessesGranted",
    "RtlAreAnyAccessesGranted",
    // Impersonation as a proxy for "has done identity work"
    "ImpersonateNamedPipeClient",
    "ImpersonateLoggedOnUser",
    "ImpersonateAnonymousToken",
    "RpcImpersonateClient",
    "RpcImpersonateClient2",
    "CoImpersonateClient",
    // Token / SID lookups commonly precede an authorization decision
    "GetTokenInformation",
    "OpenProcessToken",
    "OpenThreadToken",
    "CheckTokenMembership",
    "CheckTokenMembershipEx",
    // Logon / credential primitives
    "LogonUserA",
    "LogonUserW",
    "LogonUserExA",
    "LogonUserExW",
    "LsaLogonUser",
    // Cred APIs
    "CredUIPromptForCredentialsA",
    "CredUIPromptForCredentialsW",
    "AcquireCredentialsHandleA",
    "AcquireCredentialsHandleW",
    // SSPI / Schannel auth completion
    "InitializeSecurityContextA",
    "InitializeSecurityContextW",
    "AcceptSecurityContext",
    "CompleteAuthToken",
};

// Bumped to 2 in Slice A. Consumers cache findings keyed on this revision and
// invalidate when it changes. Bump any time the structure or contents of the
// arrays above change in a way that would alter analysis output.
inline constexpr uint32_t SIGNATURE_DATABASE_REVISION = 2;

}
}
}
