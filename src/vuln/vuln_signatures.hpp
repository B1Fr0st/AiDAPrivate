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

struct sink_signature_t
{
    std::string_view name;
    int              primary_cwe;
    int              format_arg_index;
    int              len_arg_index;
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
    {"strcpy",            120, -1, -1},
    {"strcat",            120, -1, -1},
    {"sprintf",           120, -1, -1},
    {"vsprintf",          120, -1, -1},
    {"gets",              242, -1, -1},
    {"_gets",             242, -1, -1},
    {"memcpy",            120, -1,  2},
    {"memmove",           120, -1,  2},
    {"snprintf",          120, -1,  1},
    {"_snprintf",         120, -1,  1},
    {"sscanf",            120, -1, -1},
    {"wsprintfA",         120, -1, -1},
    {"wsprintfW",         120, -1, -1},
    {"wcscpy",            120, -1, -1},
    {"wcscat",            120, -1, -1},
    {"wcsncpy",           120, -1,  2},
    {"strncpy",           120, -1,  2},
    {"lstrcpyA",          120, -1, -1},
    {"lstrcpyW",          120, -1, -1},
    {"lstrcatA",          120, -1, -1},
    {"lstrcatW",          120, -1, -1},
    {"StrCpyA",           120, -1, -1},
    {"StrCpyW",           120, -1, -1},
    {"_strcpy",           120, -1, -1},
    {"__builtin_strcpy",  120, -1, -1},
    {"alloca",            770, -1,  0},
    {"_alloca",           770, -1,  0},
};

inline constexpr sink_signature_t COMMAND_INJECTION_SINKS[] = {
    {"system",            78, -1, -1},
    {"_wsystem",          78, -1, -1},
    {"popen",             78, -1, -1},
    {"_popen",            78, -1, -1},
    {"_wpopen",           78, -1, -1},
    {"execl",             78, -1, -1},
    {"execle",            78, -1, -1},
    {"execlp",            78, -1, -1},
    {"execv",             78, -1, -1},
    {"execve",            78, -1, -1},
    {"execvp",            78, -1, -1},
    {"CreateProcessA",    78, -1, -1},
    {"CreateProcessW",    78, -1, -1},
    {"CreateProcessAsUserA", 78, -1, -1},
    {"CreateProcessAsUserW", 78, -1, -1},
    {"ShellExecuteA",     78, -1, -1},
    {"ShellExecuteW",     78, -1, -1},
    {"ShellExecuteExA",   78, -1, -1},
    {"ShellExecuteExW",   78, -1, -1},
    {"WinExec",           78, -1, -1},
};

inline constexpr sink_signature_t PATH_TRAVERSAL_SINKS[] = {
    {"fopen",             22, -1, -1},
    {"_wfopen",           22, -1, -1},
    {"fopen_s",           22, -1, -1},
    {"_wfopen_s",         22, -1, -1},
    {"open",              22, -1, -1},
    {"_open",             22, -1, -1},
    {"_wopen",            22, -1, -1},
    {"CreateFileA",       22, -1, -1},
    {"CreateFileW",       22, -1, -1},
    {"CreateFile2",       22, -1, -1},
    {"DeleteFileA",       22, -1, -1},
    {"DeleteFileW",       22, -1, -1},
    {"MoveFileA",         22, -1, -1},
    {"MoveFileW",         22, -1, -1},
    {"CopyFileA",         22, -1, -1},
    {"CopyFileW",         22, -1, -1},
};

inline constexpr sink_signature_t FORMAT_STRING_FUNCS[] = {
    {"printf",            134,  0, -1},
    {"fprintf",           134,  1, -1},
    {"sprintf",           134,  1, -1},
    {"snprintf",          134,  2,  1},
    {"_snprintf",         134,  2,  1},
    {"vprintf",           134,  0, -1},
    {"vfprintf",          134,  1, -1},
    {"vsprintf",          134,  1, -1},
    {"vsnprintf",         134,  2,  1},
    {"wprintf",           134,  0, -1},
    {"fwprintf",          134,  1, -1},
    {"swprintf",          134,  2,  1},
    {"_swprintf",         134,  1, -1},
    {"wsprintfA",         134,  1, -1},
    {"wsprintfW",         134,  1, -1},
    {"syslog",            134,  1, -1},
    {"err",               134,  1, -1},
    {"warn",              134,  1, -1},
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

inline constexpr uint32_t SIGNATURE_DATABASE_REVISION = 1;

}
}
}
