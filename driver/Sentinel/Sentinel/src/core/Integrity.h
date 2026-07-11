#pragma once
#include <imports/Defs.h>
#include <core/DispatchGuard.h>
#include <core/KernelCrypto.h>
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

    inline UINT8 g_usermode_last_computed_sha256[32] = {};
    inline volatile UINT64 g_usermode_text_base = 0;
    inline volatile UINT64 g_usermode_text_size = 0;
    inline UINT8 g_usermode_expected_sha256[32] = {};
    inline volatile LONG g_usermode_hash_initialized = 0;


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
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        0xA1DA0002,
                        (ULONG_PTR)bp,
                        (ULONG_PTR)0xCC,
                        (ULONG_PTR)offset,
                        (ULONG_PTR)1
                    );
                }
                return false;
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
                    goto integrity_fail;
                }

                PVOID hook_dest = dispatch_guard::resolve_hook_destination(
                    modified_bytes, diff_addr);

                if (hook_dest && dispatch_guard::is_address_in_loaded_module(hook_dest)) {
                    g_baseline_crc = current_crc;
                    __try {
                        RtlCopyMemory(g_shadow_copy, base, size);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                    }
                    return true;
                }

                if (!hvci_detect::is_hvci_enabled()) {
                    bool restored = self_protect::safe_write_memory(
                        diff_addr, g_shadow_copy + diff_offset,
                        min((ULONG)64, size - diff_offset));

                    if (restored) {
                        UINT32 after_crc = compute_crc32(base, size);
                        if (after_crc == g_baseline_crc) {
                            return true;
                        }
                    }
                }
            }

        integrity_fail:

            if (hvci_detect::is_hvci_enabled()) {
                SN_LOG("integrity::verify: HVCI active, suppressing BSOD (crc mismatch)");
                return true;
            }
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    0xA1DA0002,
                    (ULONG_PTR)base + (diff_offset != (ULONG)-1 ? diff_offset : 0),
                    (ULONG_PTR)g_baseline_crc,
                    (ULONG_PTR)current_crc,
                    (ULONG_PTR)0
                );
            }
            return false;
        }

        return true;
    }


#pragma pack(push, 1)
    struct reloc_mask_entry_t {
        UINT32 offset;
        UINT32 size;
        UINT32 reloc_type;
        UINT32 _pad;
        UINT8  original_value[8];
    };
#pragma pack(pop)
    static_assert(sizeof(reloc_mask_entry_t) == 24, "reloc_mask_entry_t must be 24 bytes");

    constexpr UINT32 IMAGE_REL_BASED_DIR64    = 10;
    constexpr UINT32 IMAGE_REL_BASED_HIGHLOW  = 3;
    constexpr ULONG  USERMODE_HASH_BATCH_PAGES   = 64;
    constexpr ULONG  USERMODE_HASH_BUFFER_SIZE   = 4096 * USERMODE_HASH_BATCH_PAGES;
    constexpr ULONG  MAX_RELOC_MASK_ENTRIES      = 512;

    inline volatile UINT64 g_usermode_text_base = 0;
    inline volatile UINT64 g_usermode_text_size = 0;
    inline volatile UINT64 g_usermode_reloc_delta = 0;
    inline UINT8  g_usermode_expected_sha256[32] = {};
    inline volatile LONG g_usermode_hash_initialized = 0;
    inline UINT8  g_usermode_last_computed_sha256[32] = {};
    inline PUCHAR g_usermode_read_buffer = nullptr;
    inline reloc_mask_entry_t g_usermode_reloc_mask[MAX_RELOC_MASK_ENTRIES] = {};
    inline volatile LONG g_usermode_reloc_count = 0;
    inline HANDLE g_usermode_target_pid = nullptr;

    __forceinline bool init_usermode_hash(
        UINT64 text_base, UINT64 text_size,
        UINT64 reloc_delta,
        const UINT8 expected_sha256[32],
        const reloc_mask_entry_t* mask_entries,
        UINT32 mask_count)
    {
        if (text_base == 0 || text_size == 0)
            return false;
        if (mask_count > MAX_RELOC_MASK_ENTRIES)
            return false;

        g_usermode_text_base = text_base;
        g_usermode_text_size = text_size;
        g_usermode_reloc_delta = reloc_delta;

        RtlCopyMemory(g_usermode_expected_sha256, expected_sha256, 32);

        if (mask_count > 0 && mask_entries) {
            RtlCopyMemory(g_usermode_reloc_mask, mask_entries,
                          mask_count * sizeof(reloc_mask_entry_t));
        }
        _InterlockedExchange(&g_usermode_reloc_count, (LONG)mask_count);

        if (!g_usermode_read_buffer) {
            g_usermode_read_buffer = static_cast<PUCHAR>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, USERMODE_HASH_BUFFER_SIZE, 'uHSn'));
            if (!g_usermode_read_buffer) {
                SN_LOG("integrity::init_usermode_hash: FAIL - buffer alloc failed");
                return false;
            }
        }

        _InterlockedExchange(&g_usermode_hash_initialized, 1);
        SN_LOG("integrity::init_usermode_hash: OK base=0x%llx size=0x%llx delta=0x%llx mask_count=%lu",
            (unsigned long long)text_base,
            (unsigned long long)text_size,
            (unsigned long long)reloc_delta,
            mask_count);
        return true;
    }

    __forceinline bool verify_usermode_from_kernel(HANDLE target_pid)
    {
        if (!_InterlockedCompareExchange(&g_usermode_hash_initialized, 1, 1))
            return true;

        UINT64 text_base = g_usermode_text_base;
        UINT64 text_size = g_usermode_text_size;
        if (!text_base || !text_size)
            return true;

        if (!g_usermode_read_buffer)
            return true;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(target_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return true;

        kernel_crypto::sha256_ctx_t sha_ctx;
        kernel_crypto::sha256_init(&sha_ctx);

        KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);

        bool read_ok = true;

        __try {
            UINT64 offset = 0;
            while (offset < text_size) {
                ULONG this_batch = (ULONG)min(
                    (UINT64)USERMODE_HASH_BUFFER_SIZE,
                    text_size - offset);

                __try {
                    RtlCopyMemory(
                        g_usermode_read_buffer,
                        reinterpret_cast<PVOID>(text_base + offset),
                        this_batch);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    read_ok = false;
                    break;
                }

                offset += this_batch;
            }

            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(proc);

            if (!read_ok) {
                SN_LOG("integrity::verify_usermode: read failed in target process");
                return true;
            }

            UINT64 reloc_delta = g_usermode_reloc_delta;
            LONG reloc_count = _InterlockedCompareExchange(&g_usermode_reloc_count, 0, 0);

            for (LONG i = 0; i < reloc_count; i++) {
                reloc_mask_entry_t* entry = &g_usermode_reloc_mask[i];
                if (entry->offset + entry->size > (UINT32)text_size)
                    continue;

                ULONG buf_offset = entry->offset;
                UINT64 actual_value = 0;
                RtlCopyMemory(&actual_value,
                    g_usermode_read_buffer + buf_offset, entry->size);

                UINT64 original_value = 0;
                RtlCopyMemory(&original_value, entry->original_value, entry->size);

                UINT64 expected_value = 0;
                if (entry->reloc_type == IMAGE_REL_BASED_DIR64) {
                    expected_value = original_value + reloc_delta;
                } else if (entry->reloc_type == IMAGE_REL_BASED_HIGHLOW) {
                    expected_value = (original_value + (reloc_delta & 0xFFFFFFFF)) & 0xFFFFFFFF;
                } else {
                    continue;
                }

                UINT64 actual_masked = actual_value;
                if (entry->size == 4)
                    actual_masked &= 0xFFFFFFFF;

                if (actual_masked != expected_value) {
                    SN_LOG("integrity::verify_usermode: RELOC TAMPER offset=%u type=%u actual=0x%llx expected=0x%llx",
                        entry->offset, entry->reloc_type,
                        (unsigned long long)actual_masked,
                        (unsigned long long)expected_value);

                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(
                            0xA1DA0002,
                            (ULONG_PTR)(text_base + entry->offset),
                            (ULONG_PTR)actual_masked,
                            (ULONG_PTR)expected_value,
                            (ULONG_PTR)entry->reloc_type
                        );
                    }
                    return false;
                }

                RtlZeroMemory(g_usermode_read_buffer + buf_offset, entry->size);
            }

            kernel_crypto::sha256_update(&sha_ctx,
                g_usermode_read_buffer, (ULONG)text_size);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(proc);
            SN_LOG("integrity::verify_usermode: EXCEPTION during hash compute");
            return true;
        }

        UINT8 computed_sha256[32] = {};
        kernel_crypto::sha256_final(&sha_ctx, computed_sha256);

        RtlCopyMemory(g_usermode_last_computed_sha256, computed_sha256, 32);

        bool hash_ok = (RtlCompareMemory(
            computed_sha256, g_usermode_expected_sha256, 32) == 32);

        if (!hash_ok) {
            SN_LOG("integrity::verify_usermode: HASH MISMATCH - KeBugCheckEx 0xA1DA0002");
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    0xA1DA0002,
                    (ULONG_PTR)g_usermode_text_base,
                    (ULONG_PTR)g_usermode_text_size,
                    0,
                    0
                );
            }
            return false;
        }

        return true;
    }

    struct cross_ring_evidence_t {
        UINT32 detecting_checker_id;
        UINT32 target_checker_id;
        UINT64 region_base;
        UINT64 region_size;
        UINT8  expected_hash[32];
        UINT8  actual_hash[32];
        UINT8  modified_bytes[256];
        UINT32 modified_bytes_len;
        UINT32 _pad;
    };
    static_assert(sizeof(cross_ring_evidence_t) == 352, "cross_ring_evidence_t must be 352 bytes");

    __forceinline bool verify_cross_ring_evidence(const cross_ring_evidence_t* evidence)
    {
        if (!evidence)
            return false;

        if (evidence->region_base == 0 || evidence->region_size == 0)
            return false;

        if (evidence->modified_bytes_len == 0 ||
            evidence->modified_bytes_len > 256)
            return false;

        if (!g_shadow_copy)
            return false;

        UINT64 text_base = g_usermode_text_base;
        UINT64 text_size = g_usermode_text_size;

        if (text_base == 0 || text_size == 0)
            return false;

        if (evidence->region_base < text_base ||
            evidence->region_base + evidence->region_size > text_base + text_size)
            return false;

        ULONG region_offset = (ULONG)(evidence->region_base - text_base);
        ULONG region_size = (ULONG)evidence->region_size;

        if (region_offset + region_size > text_size)
            return false;

        UCHAR kernel_bytes[256] = {};
        ULONG bytes_to_read = min(region_size, (ULONG)256);

        __try {
            RtlCopyMemory(kernel_bytes,
                reinterpret_cast<PVOID>(evidence->region_base),
                bytes_to_read);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("integrity::verify_cross_ring_evidence: read failed at 0x%llx",
                (unsigned long long)evidence->region_base);
            return false;
        }

        volatile UINT8 diff = 0;
        for (ULONG i = 0; i < bytes_to_read; i++) {
            diff |= kernel_bytes[i] ^ g_shadow_copy[region_offset + i];
        }

        if (diff != 0) {
            SN_LOG("integrity::verify_cross_ring_evidence: CONFIRMED modification checker=%u target=%u region=0x%llx",
                evidence->detecting_checker_id,
                evidence->target_checker_id,
                (unsigned long long)evidence->region_base);

            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    0xA1DA0003,
                    (ULONG_PTR)evidence->detecting_checker_id,
                    (ULONG_PTR)evidence->region_base,
                    (ULONG_PTR)evidence->modified_bytes,
                    (ULONG_PTR)evidence->modified_bytes_len
                );
            }
            return false;
        }

        SN_LOG("integrity::verify_cross_ring_evidence: no modification confirmed checker=%u target=%u",
            evidence->detecting_checker_id,
            evidence->target_checker_id);
        return true;
    }

    __forceinline bool kernel_read_user_memory(
        HANDLE target_pid, UINT64 address, PVOID out_buffer, ULONG len, PULONG out_read)
    {
        if (out_read)
            *out_read = 0;

        if (!out_buffer || len == 0)
            return false;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(target_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return false;

        KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);

        bool ok = false;
        __try {
            RtlCopyMemory(out_buffer, reinterpret_cast<PVOID>(address), len);
            ok = true;
            if (out_read)
                *out_read = len;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
        }

        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return ok;
    }
}
