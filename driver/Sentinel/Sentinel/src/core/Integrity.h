#pragma once
#include <imports/Defs.h>
#include <core/DispatchGuard.h>
#include <nmmintrin.h>
#include <intrin.h>


namespace self_protect {
    __forceinline bool safe_write_memory(PVOID dest, PVOID src, SIZE_T size);
}


namespace integrity {

    struct sensor_data_t
    {
        UINT64 cr4_smep_smap;
        UINT64 lstar_msr;
        UINT64 idtr_base;
        UINT16 idtr_limit;
        UINT32 vector_2d_hash;
        UINT32 vector_e9_hash;
    };

    inline sensor_data_t g_baseline_sensors = {};
    inline volatile LONG g_sensors_initialized = 0;

    __forceinline UINT32 hash_prologue(const UINT8* data, ULONG len)
    {
        UINT32 h = 0x811C9DC5u;
        for (ULONG i = 0; i < len; i++)
        {
            h ^= data[i];
            h *= 0x01000193u;
        }
        return h;
    }

    __forceinline sensor_data_t collect_sensors()
    {
        sensor_data_t s = {};

        __try {
            UINT64 cr4 = __readcr4();
            s.cr4_smep_smap = cr4 & ((1ULL << 20) | (1ULL << 21));
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s.cr4_smep_smap = 0;
        }

        __try {
            s.lstar_msr = __readmsr(0xC0000082);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s.lstar_msr = 0;
        }

        __try {
            UINT8 idtr_buf[10] = {};
            __sidt(idtr_buf);
            s.idtr_limit = *reinterpret_cast<UINT16*>(idtr_buf);
            s.idtr_base = *reinterpret_cast<UINT64*>(idtr_buf + 2);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s.idtr_base = 0;
            s.idtr_limit = 0;
        }

        __try {
            if (s.idtr_base && _MmIsAddressValid(reinterpret_cast<PVOID>(s.idtr_base)))
            {
                constexpr ULONG IDT_ENTRY_SIZE = 16;
                UINT8* idt = reinterpret_cast<UINT8*>(s.idtr_base);

                UINT8* entry_2d = idt + (0x2D * IDT_ENTRY_SIZE);
                if (_MmIsAddressValid(entry_2d))
                {
                    UINT64 handler_2d = 0;
                    handler_2d = static_cast<UINT64>(*reinterpret_cast<UINT16*>(entry_2d));
                    handler_2d |= static_cast<UINT64>(*reinterpret_cast<UINT16*>(entry_2d + 6)) << 16;
                    handler_2d |= static_cast<UINT64>(*reinterpret_cast<UINT32*>(entry_2d + 8)) << 32;

                    if (handler_2d && _MmIsAddressValid(reinterpret_cast<PVOID>(handler_2d)))
                    {
                        UINT8 prologue[16];
                        RtlCopyMemory(prologue, reinterpret_cast<PVOID>(handler_2d), 16);
                        s.vector_2d_hash = hash_prologue(prologue, 16);
                    }
                }

                UINT8* entry_e9 = idt + (0xE9 * IDT_ENTRY_SIZE);
                if (_MmIsAddressValid(entry_e9))
                {
                    UINT64 handler_e9 = 0;
                    handler_e9 = static_cast<UINT64>(*reinterpret_cast<UINT16*>(entry_e9));
                    handler_e9 |= static_cast<UINT64>(*reinterpret_cast<UINT16*>(entry_e9 + 6)) << 16;
                    handler_e9 |= static_cast<UINT64>(*reinterpret_cast<UINT32*>(entry_e9 + 8)) << 32;

                    if (handler_e9 && _MmIsAddressValid(reinterpret_cast<PVOID>(handler_e9)))
                    {
                        UINT8 prologue[16];
                        RtlCopyMemory(prologue, reinterpret_cast<PVOID>(handler_e9), 16);
                        s.vector_e9_hash = hash_prologue(prologue, 16);
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        return s;
    }

    __forceinline void collect_sensor_baseline()
    {
        g_baseline_sensors = collect_sensors();
        _InterlockedExchange(&g_sensors_initialized, 1);
    }

    __forceinline BOOLEAN detect_sensor_anomaly()
    {
        if (!_InterlockedCompareExchange(&g_sensors_initialized, 1, 1))
            return FALSE;

        sensor_data_t current = collect_sensors();

        if (g_baseline_sensors.cr4_smep_smap != 0 &&
            current.cr4_smep_smap != g_baseline_sensors.cr4_smep_smap)
            return TRUE;

        if (g_baseline_sensors.lstar_msr != 0 &&
            current.lstar_msr != g_baseline_sensors.lstar_msr)
            return TRUE;

        if (g_baseline_sensors.idtr_base != 0 &&
            current.idtr_base != g_baseline_sensors.idtr_base)
            return TRUE;

        if (g_baseline_sensors.vector_2d_hash != 0 &&
            current.vector_2d_hash != g_baseline_sensors.vector_2d_hash)
            return TRUE;

        if (g_baseline_sensors.vector_e9_hash != 0 &&
            current.vector_e9_hash != g_baseline_sensors.vector_e9_hash)
            return TRUE;

        return FALSE;
    }


    inline volatile UINT32 g_baseline_crc = 0;
    inline volatile PVOID  g_code_base    = nullptr;
    inline volatile ULONG  g_code_size    = 0;
    inline PUCHAR          g_shadow_copy  = nullptr;


    __forceinline UINT32 compute_crc32(const PVOID data, ULONG size) {

        if (!data || size == 0)
            return 0;

        const UCHAR* p = static_cast<const UCHAR*>(data);
        UINT64 crc = 0xFFFFFFFFULL;


        ULONG aligned_end = size & ~7UL;
        for (ULONG i = 0; i < aligned_end; i += 8) {
            crc = _mm_crc32_u64(crc, *reinterpret_cast<const UINT64*>(p + i));
        }


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


            if (hvci_detect::is_hvci_enabled()) {
                SN_LOG("integrity::verify: HVCI active, breakpoint at +0x%lx (detect-only)", offset);
                return true;
            }

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


                if (!hvci_detect::is_hvci_enabled()) {
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
            }

        count_strike:

            LONG strikes = _InterlockedIncrement(&g_integrity_strikes);
            if (strikes >= INTEGRITY_STRIKE_THRESHOLD) {


                if (hvci_detect::is_hvci_enabled()) {
                    SN_LOG("integrity::verify: HVCI active, suppressing BSOD (strikes=%ld)", strikes);
                    return true;
                }
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
