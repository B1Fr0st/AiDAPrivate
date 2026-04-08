#pragma once
#include <imports/Defs.h>
#include <core/DispatchGuard.h>
#include <nmmintrin.h>


namespace self_protect {
    __forceinline bool safe_write_memory(PVOID dest, PVOID src, SIZE_T size);
}


namespace integrity {


    inline volatile UINT32 g_baseline_crc = 0;
    inline volatile PVOID  g_code_base    = nullptr;
    inline volatile ULONG  g_code_size    = 0;
    inline PUCHAR          g_shadow_copy  = nullptr;

    // Hardware-accelerated CRC32C using SSE4.2 _mm_crc32_u64.
    // Processes 8 bytes per iteration instead of the old bit-by-bit loop
    // that did 8 conditional branch ops per single byte.
    // On a 5 MB .text section this reduces ~40 million branch-dependent
    // operations to ~625 thousand pipelined CRC instructions — roughly
    // 50-100x faster and eliminates the single largest source of DPC CPU time.
    __forceinline UINT32 compute_crc32(const PVOID data, ULONG size) {

        if (!data || size == 0)
            return 0;

        const UCHAR* p = static_cast<const UCHAR*>(data);
        UINT64 crc = 0xFFFFFFFFULL;

        // Process 8 bytes at a time using hardware CRC32C
        ULONG aligned_end = size & ~7UL;
        for (ULONG i = 0; i < aligned_end; i += 8) {
            crc = _mm_crc32_u64(crc, *reinterpret_cast<const UINT64*>(p + i));
        }

        // Handle remaining 0-7 bytes
        for (ULONG i = aligned_end; i < size; i++) {
            crc = _mm_crc32_u8(static_cast<UINT32>(crc), p[i]);
        }

        return static_cast<UINT32>(~crc);
    }


    __forceinline bool create_shadow_copy(PVOID code_base, ULONG code_size) {
        if (!code_base || code_size == 0 || code_size > 10 * 1024 * 1024)
            return false;

        g_shadow_copy = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, code_size, 'mCmM')
        );

        if (!g_shadow_copy)
            return false;

        __try {
            RtlCopyMemory(g_shadow_copy, code_base, code_size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ExFreePoolWithTag(g_shadow_copy, 'mCmM');
            g_shadow_copy = nullptr;
            return false;
        }

        return true;
    }


    __forceinline PVOID scan_for_breakpoints(PVOID code_base, ULONG code_size) {
        if (!code_base || !g_shadow_copy || code_size == 0)
            return nullptr;

        const UCHAR* current = static_cast<const UCHAR*>(code_base);
        const UCHAR* original = g_shadow_copy;

        __try {
            for (ULONG i = 0; i < code_size; i++) {


                if (current[i] == 0xCC && original[i] != 0xCC) {
                    return (PVOID)(static_cast<const UCHAR*>(code_base) + i);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }

        return nullptr;
    }


    __forceinline ULONG find_first_diff(PVOID code_base, ULONG code_size) {
        if (!code_base || !g_shadow_copy || code_size == 0)
            return (ULONG)-1;

        const UCHAR* current = static_cast<const UCHAR*>(code_base);
        const UCHAR* original = g_shadow_copy;

        __try {
            for (ULONG i = 0; i < code_size; i++) {
                if (current[i] != original[i])
                    return i;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return (ULONG)-1;
        }

        return (ULONG)-1;
    }

    __forceinline bool init(PVOID code_base, ULONG code_size) {
        SN_LOG("integrity::init: code_base=%p code_size=0x%lx", code_base, code_size);
        if (!code_base || code_size == 0) {
            SN_LOG("integrity::init: FAIL - null base or zero size");
            return false;
        }


        if (!_MmIsAddressValid(code_base) ||
            !_MmIsAddressValid(static_cast<PUCHAR>(code_base) + code_size - 1)) {
            SN_LOG("integrity::init: FAIL - address not valid");
            return false;
        }

        g_code_base = code_base;
        g_code_size = code_size;

        if (!create_shadow_copy(code_base, code_size)) {
            SN_LOG("integrity::init: FAIL - create_shadow_copy failed");
            return false;
        }

        g_baseline_crc = compute_crc32(code_base, code_size);
        SN_LOG("integrity::init: baseline_crc=0x%08lx", g_baseline_crc);

        if (g_baseline_crc == 0) {
            SN_LOG("integrity::init: FAIL - CRC is zero");
            ExFreePoolWithTag(g_shadow_copy, 'mCmM');
            g_shadow_copy = nullptr;
            return false;
        }

        SN_LOG("integrity::init: SUCCESS");
        return true;
    }


    inline volatile LONG g_integrity_strikes = 0;
    constexpr LONG       INTEGRITY_STRIKE_THRESHOLD = 5;

    __forceinline bool verify() {
        PVOID base = (PVOID)g_code_base;
        ULONG size = g_code_size;

        if (!base || size == 0)
            return true;

        if (!_MmIsAddressValid(base))
            return true;


        PVOID bp = scan_for_breakpoints(base, size);
        if (bp) {
            ULONG offset = (ULONG)((ULONG_PTR)bp - (ULONG_PTR)base);


            UCHAR original_byte = g_shadow_copy[offset];
            bool restored = self_protect::safe_write_memory(
                bp, &original_byte, 1);

            if (!restored) {

                LONG strikes = _InterlockedIncrement(&g_integrity_strikes);
                if (strikes >= INTEGRITY_STRIKE_THRESHOLD) {
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(
                            0xDEAD5E01,
                            (ULONG_PTR)bp,
                            (ULONG_PTR)0xCC,
                            (ULONG_PTR)offset,
                            (ULONG_PTR)1
                        );
                    }
                    return false;
                }
            }


            return true;
        }


        UINT32 current_crc = compute_crc32(base, size);

        if (current_crc != g_baseline_crc) {
            ULONG diff_offset = find_first_diff(base, size);

            if (diff_offset != (ULONG)-1) {


                UCHAR* diff_addr = static_cast<UCHAR*>(base) + diff_offset;


                UCHAR modified_bytes[16] = {};
                ULONG bytes_to_read = min(16UL, size - diff_offset);
                __try {
                    RtlCopyMemory(modified_bytes, diff_addr, bytes_to_read);
                } __except (EXCEPTION_EXECUTE_HANDLER) {

                    goto count_strike;
                }


                PVOID hook_dest = dispatch_guard::resolve_hook_destination(
                    modified_bytes, diff_addr);

                if (hook_dest && dispatch_guard::is_address_in_loaded_module(hook_dest)) {


                    g_baseline_crc = current_crc;
                    __try {
                        RtlCopyMemory(g_shadow_copy, base, size);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {

                    }
                    _InterlockedExchange(&g_integrity_strikes, 0);
                    return true;
                }


                bool restored = self_protect::safe_write_memory(
                    diff_addr, g_shadow_copy + diff_offset,
                    min((ULONG)64, size - diff_offset));

                if (restored) {

                    UINT32 after_crc = compute_crc32(base, size);
                    if (after_crc == g_baseline_crc) {

                        _InterlockedExchange(&g_integrity_strikes, 0);
                        return true;
                    }
                }
            }

        count_strike:

            LONG strikes = _InterlockedIncrement(&g_integrity_strikes);
            if (strikes >= INTEGRITY_STRIKE_THRESHOLD) {
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        0xDEAD5E01,
                        (ULONG_PTR)base + diff_offset,
                        (ULONG_PTR)g_baseline_crc,
                        (ULONG_PTR)current_crc,
                        (ULONG_PTR)0
                    );
                }
                return false;
            }
            return true;
        }


        _InterlockedExchange(&g_integrity_strikes, 0);
        return true;
    }
}
