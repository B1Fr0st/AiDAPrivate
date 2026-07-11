#include <ntifs.h>
#include <intrin.h>
#include "../Struct.h"
#include "../Functions.h"
#include "../CoreSecurity.h"
#include "../KernelLayout.h"
#include "../../imports/Defs.h"

extern "C" PPEB PsGetProcessPeb(PEPROCESS Process);


namespace dll_protection {


    static constexpr UINT32 MAX_PROTECT_SLOTS = 4;
    static constexpr UINT32 BASELINE_PREFIX_MAX = 64;
    static constexpr UINT32 DPRT_POLICY_HARD_BUGCHECK = 0x00000001u;
    static constexpr UINT32 DPRT_MISMATCH_UNKNOWN = 0xFFFFFFFFu;
    static constexpr UINT32 DPRT_HARD_BUGCHECK_MIN_MISMATCHES = 3;
    static constexpr UINT32 DPRT_HARD_BUGCHECK_ARM_DELAY_MS = 15000;
    static constexpr UINT32 DPRT_HARD_BUGCHECK_MIN_SPAN_MS = 4000;
    static constexpr UINT64 DTB_ADDRESS_MASK = 0x000FFFFFFFFFF000ULL;
    static constexpr UINT64 DTB_MAX_PFN = 0x1000000ULL;
    static constexpr UINT32 EPROCESS_DIRECTORY_TABLE_BASE_OFFSET = 0x28;
    static constexpr ULONG DPRT_REASON_FOREIGN_INSTRUMENTATION = 0xAE46u;
    static constexpr LONGLONG DPRT_REPETITIVE_LOG_INTERVAL_100NS = 30LL * 1000LL * 10000LL;
    static constexpr UINT64 DPRT_TIMER_WORK_SLOW_100NS = 50ULL * 1000ULL;

    struct protection_entry_t {
        volatile LONG active;
        UINT32 pid;
        UINT64 module_base;
        UINT64 text_va;
        UINT32 text_size;
        UINT64 expected_hash;
        UINT64 current_hash;
        UINT32 status;
        UINT32 check_interval_ms;
        UINT64 last_check_tsc;
        UINT64 check_count;
        UINT32 baseline_prefix_size;
        UINT32 policy_flags;
        UINT32 owner_pid;
        UINT64 register_interrupt_time;
        UINT64 first_mismatch_interrupt_time;
        UINT64 last_mismatch_interrupt_time;
        UINT64 first_mismatch_hash;
        UINT32 first_mismatch_offset;
        UINT32 mismatch_count;
        UINT8 baseline_prefix[BASELINE_PREFIX_MAX];
    };

    static protection_entry_t g_slots[MAX_PROTECT_SLOTS] = {};
    static KDPC   g_timer_dpc;
    static KTIMER g_timer;
    static WORK_QUEUE_ITEM g_timer_work_item = {};
    static KEVENT g_timer_work_done = {};
    static volatile LONG g_timer_initialized = 0;
    static volatile LONG g_timer_work_sync_initialized = 0;
    static volatile LONG g_timer_running = 0;
    static volatile LONG g_timer_work_item_queued = 0;
    static volatile LONG g_timer_work_item_running = 0;
    static volatile LONG g_timer_work_run_count = 0;
    static volatile LONG64 g_instr_noncanonical_log_last_time = 0;
    static volatile LONG g_instr_noncanonical_log_emitted = 0;
    static volatile LONG g_instr_noncanonical_log_suppressed = 0;
    static volatile LONG64 g_instr_check_log_last_time = 0;
    static volatile LONG g_instr_check_log_emitted = 0;
    static volatile LONG g_instr_check_log_suppressed = 0;


    static UINT64 compute_code_hash_physical(UINT32 pid, UINT64 va, UINT32 size);
    static BOOLEAN check_peb_debugger_physical(UINT32 pid);

    static BOOLEAN should_log_repetitive_diagnostic(
        volatile LONG64* last_time,
        volatile LONG* emitted_count,
        volatile LONG* suppressed_count,
        LONG64 now,
        ULONG* suppressed_out)
    {
        if (suppressed_out)
            *suppressed_out = 0;

        LONG emitted = _InterlockedIncrement(emitted_count);
        if (emitted <= 4) {
            LONG suppressed = _InterlockedExchange(suppressed_count, 0);
            if (suppressed_out && suppressed > 0)
                *suppressed_out = static_cast<ULONG>(suppressed);
            return TRUE;
        }

        LONG64 previous = _InterlockedCompareExchange64(last_time, 0, 0);
        if (previous == 0 || now - previous >= DPRT_REPETITIVE_LOG_INTERVAL_100NS) {
            if (_InterlockedCompareExchange64(last_time, now, previous) == previous) {
                LONG suppressed = _InterlockedExchange(suppressed_count, 0);
                if (suppressed_out && suppressed > 0)
                    *suppressed_out = static_cast<ULONG>(suppressed);
                return TRUE;
            }
        }

        _InterlockedIncrement(suppressed_count);
        return FALSE;
    }

    struct memory_snapshot_t {
        NTSTATUS lookup_status;
        NTSTATUS query_status;
        UINT64 base;
        UINT64 allocation_base;
        UINT64 region_size;
        ULONG state;
        ULONG protect;
        ULONG allocation_protect;
        ULONG type;
        SIZE_T returned_length;
        BOOLEAN valid;
    };

    static UINT64 cached_dtb_for_pid(UINT32 pid)
    {
        if (pid == 0)
            return 0;
        UINT64 cached = 0;
        if (LookupDTBCache(pid, &cached))
            return cached;
        return 0;
    }

    static BOOLEAN is_valid_dtb_value(UINT64 dtb)
    {
        UINT64 masked = dtb & DTB_ADDRESS_MASK;
        UINT64 pfn = (masked >> 12) & 0xFFFFFFFFFULL;
        if (masked == 0 || pfn == 0)
            return FALSE;
        if (pfn > DTB_MAX_PFN)
            return FALSE;
        return TRUE;
    }

    static UINT64 resolve_dtb_for_pid(UINT32 pid, const char* tag, BOOLEAN force_refresh = FALSE)
    {
        if (pid == 0)
            return 0;

        if (!force_refresh) {
            UINT64 cached = cached_dtb_for_pid(pid);
            if (is_valid_dtb_value(cached))
                return cached;
        }

        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            WW_LOG("[DLL-PROTECT] dtb_resolve_defer_irql tag=%s pid=%u irql=%lu",
                tag ? tag : "unknown",
                pid,
                KeGetCurrentIrql());
            return 0;
        }

        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process) {
            WW_LOG("[DLL-PROTECT] dtb_resolve_lookup_failed tag=%s pid=%u status=0x%08X",
                tag ? tag : "unknown",
                pid,
                st);
            return 0;
        }

        UINT64 dir_base = 0;
        __try {
            dir_base = *reinterpret_cast<UINT64*>(reinterpret_cast<UCHAR*>(process) + EPROCESS_DIRECTORY_TABLE_BASE_OFFSET);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ObDereferenceObject(process);
            WW_LOG("[DLL-PROTECT] dtb_resolve_exception tag=%s pid=%u code=0x%08X",
                tag ? tag : "unknown",
                pid,
                GetExceptionCode());
            return 0;
        }

        ObDereferenceObject(process);

        UINT64 dtb = dir_base & DTB_ADDRESS_MASK;
        if (!is_valid_dtb_value(dtb)) {
            WW_LOG("[DLL-PROTECT] dtb_resolve_invalid tag=%s pid=%u dir_base=0x%llX masked=0x%llX",
                tag ? tag : "unknown",
                pid,
                dir_base,
                dtb);
            return 0;
        }

        InsertDTBCache(pid, dtb);
        WW_LOG("[DLL-PROTECT] dtb_resolve_ok tag=%s pid=%u dtb=0x%llX forced=%u",
            tag ? tag : "unknown",
            pid,
            dtb,
            force_refresh ? 1u : 0u);
        return dtb;
    }

    static UINT64 translate_virtual_with_dtb_retry(UINT32 pid, UINT64 va, UINT64* inout_dtb, const char* tag)
    {
        if (pid == 0 || va == 0 || !inout_dtb || *inout_dtb == 0)
            return 0;

        UINT64 phys = strong::translate_virtual_address(*inout_dtb, va);
        if (phys != 0)
            return phys;

        UINT64 stale_dtb = *inout_dtb;
        InvalidateDTBCache(pid);
        UINT64 refreshed = resolve_dtb_for_pid(pid, tag, TRUE);
        if (refreshed == 0) {
            *inout_dtb = 0;
            WW_LOG("[DLL-PROTECT] translate_retry_no_dtb tag=%s pid=%u va=0x%llX stale_dtb=0x%llX",
                tag ? tag : "unknown",
                pid,
                va,
                stale_dtb);
            return 0;
        }

        *inout_dtb = refreshed;
        phys = strong::translate_virtual_address(refreshed, va);
        if (phys == 0) {
            WW_LOG("[DLL-PROTECT] translate_failed tag=%s pid=%u va=0x%llX stale_dtb=0x%llX refreshed_dtb=0x%llX",
                tag ? tag : "unknown",
                pid,
                va,
                stale_dtb,
                refreshed);
        }
        return phys;
    }

    static BOOLEAN slot_hard_bugcheck_enabled(const protection_entry_t& slot)
    {
        return (slot.policy_flags & DPRT_POLICY_HARD_BUGCHECK) != 0;
    }

    static UINT64 interrupt_elapsed_ms(UINT64 now, UINT64 then)
    {
        if (then == 0 || now < then)
            return 0;
        return (now - then) / 10000ULL;
    }

    static void clear_mismatch_tracking(protection_entry_t& slot)
    {
        slot.first_mismatch_interrupt_time = 0;
        slot.last_mismatch_interrupt_time = 0;
        slot.first_mismatch_hash = 0;
        slot.first_mismatch_offset = DPRT_MISMATCH_UNKNOWN;
        slot.mismatch_count = 0;
    }

    static const char* slot_policy_name(const protection_entry_t& slot)
    {
        return slot_hard_bugcheck_enabled(slot) ? "module_hard_bugcheck" : "diagnostic_fail_closed";
    }

    NTSTATUS read_process_bytes_physical(UINT32 pid, UINT64 va, UINT8* out, UINT32 size, UINT32* bytes_read)
    {
        if (bytes_read)
            *bytes_read = 0;
        if (pid == 0 || va == 0 || !out || size == 0)
            return STATUS_INVALID_PARAMETER;

        UINT64 dtb = resolve_dtb_for_pid(pid, "read");
        if (dtb == 0)
            return STATUS_NOT_FOUND;

        UINT64 cursor = va;
        UINT32 remaining = size;
        UINT32 total = 0;

        while (remaining > 0) {
            UINT32 page_offset = (UINT32)(cursor & 0xFFF);
            UINT32 to_read = 0x1000 - page_offset;
            if (to_read > remaining)
                to_read = remaining;

            UINT64 phys = translate_virtual_with_dtb_retry(pid, cursor, &dtb, "read");
            if (phys == 0) {
                if (bytes_read)
                    *bytes_read = total;
                return STATUS_UNSUCCESSFUL;
            }

            SIZE_T got = 0;
            NTSTATUS st = strong::read_physical(phys, out + total, to_read, &got);
            if (!NT_SUCCESS(st) || got != to_read) {
                if (bytes_read)
                    *bytes_read = total + (UINT32)got;
                return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
            }

            cursor += to_read;
            remaining -= to_read;
            total += to_read;
        }

        if (bytes_read)
            *bytes_read = total;
        return STATUS_SUCCESS;
    }

    static UINT32 capture_baseline_prefix(protection_entry_t& slot)
    {
        slot.baseline_prefix_size = 0;
        RtlZeroMemory(slot.baseline_prefix, sizeof(slot.baseline_prefix));

        UINT32 wanted = slot.text_size;
        if (wanted > BASELINE_PREFIX_MAX)
            wanted = BASELINE_PREFIX_MAX;
        if (wanted == 0)
            return 0;

        UINT32 got = 0;
        NTSTATUS st = read_process_bytes_physical(slot.pid, slot.text_va, slot.baseline_prefix, wanted, &got);
        if (!NT_SUCCESS(st) || got == 0)
            return 0;

        if (got > wanted)
            got = wanted;
        slot.baseline_prefix_size = got;
        return got;
    }

    static UINT32 first_mismatch_offset(const protection_entry_t& slot)
    {
        if (slot.baseline_prefix_size == 0 || slot.baseline_prefix_size > BASELINE_PREFIX_MAX)
            return DPRT_MISMATCH_UNKNOWN;

        UINT8 now[BASELINE_PREFIX_MAX];
        RtlZeroMemory(now, sizeof(now));
        UINT32 got = 0;
        NTSTATUS st = read_process_bytes_physical(slot.pid, slot.text_va, now, slot.baseline_prefix_size, &got);
        if (!NT_SUCCESS(st) || got == 0)
            return DPRT_MISMATCH_UNKNOWN;

        UINT32 limit = got;
        if (limit > slot.baseline_prefix_size)
            limit = slot.baseline_prefix_size;
        for (UINT32 i = 0; i < limit; ++i) {
            if (now[i] != slot.baseline_prefix[i])
                return i;
        }
        if (got < slot.baseline_prefix_size)
            return got;
        return DPRT_MISMATCH_UNKNOWN;
    }

    static void publish_bridge_command(ULONG cmd, ULONG param)
    {
        sentinel_bridge::bridge_encrypt_cmd(cmd, param);
        _InterlockedExchange(
            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
            static_cast<LONG>(cmd));
        _InterlockedExchange(
            reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
            static_cast<LONG>(param));
    }

    static void publish_re_evidence(ULONG reason, ULONG family, ULONG score, ULONG pid,
                                    ULONG64 image_hash, ULONG64 bitmap, ULONG64 siphash)
    {
        sentinel_bridge::populate_evidence_blob(family, reason, score, pid, image_hash, bitmap, siphash);
        publish_bridge_command(sentinel_bridge::BRIDGE_CMD_RE_EVIDENCE, reason);
    }

    static void publish_text_integrity_evidence(const protection_entry_t& slot)
    {
        publish_re_evidence(sentinel_bridge::RE_REASON_TEXT_WRITABLE,
            sentinel_bridge::EVIDENCE_FAMILY_INTEGRITY,
            100,
            slot.pid,
            slot.module_base,
            slot.text_va,
            slot.expected_hash ^ slot.current_hash);
    }

    static void reset_slot(protection_entry_t& slot)
    {
        _InterlockedExchange(&slot.active, 0);
        slot.pid = 0;
        slot.module_base = 0;
        slot.text_va = 0;
        slot.text_size = 0;
        slot.expected_hash = 0;
        slot.current_hash = 0;
        slot.status = DPRT_STATUS_INACTIVE;
        slot.check_interval_ms = 0;
        slot.last_check_tsc = 0;
        slot.check_count = 0;
        slot.baseline_prefix_size = 0;
        slot.policy_flags = 0;
        slot.owner_pid = 0;
        slot.register_interrupt_time = 0;
        clear_mismatch_tracking(slot);
        RtlZeroMemory(slot.baseline_prefix, sizeof(slot.baseline_prefix));
    }

    static UINT32 active_slot_count()
    {
        UINT32 count = 0;
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1)
                ++count;
        }
        return count;
    }

    static void copy_process_image_name(UINT32 pid, char* out, SIZE_T cap)
    {
        if (!out || cap == 0)
            return;
        RtlZeroMemory(out, cap);
        out[0] = '?';
        if (pid == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return;
        UCHAR* image = PsGetProcessImageFileName(process);
        if (image) {
            RtlZeroMemory(out, cap);
            SIZE_T limit = cap - 1;
            if (limit > 15)
                limit = 15;
            for (SIZE_T i = 0; i < limit && image[i] != 0; ++i)
                out[i] = (char)image[i];
        }
        ObDereferenceObject(process);
    }

    static BOOLEAN image_name_equals_ascii(const char* image, const char* expected)
    {
        if (!image || !expected)
            return FALSE;
        SIZE_T i = 0;
        for (; expected[i] != '\0'; ++i) {
            char a = image[i];
            char b = expected[i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
            if (a != b)
                return FALSE;
        }
        return image[i] == '\0' ? TRUE : FALSE;
    }

    static BOOLEAN is_fileless_terminal_slot(const protection_entry_t& slot)
    {
        if (slot.pid == 0 || slot.owner_pid == 0 || slot.owner_pid != slot.pid)
            return FALSE;
        char image[16];
        copy_process_image_name(slot.pid, image, sizeof(image));
        return image_name_equals_ascii(image, "powershell.exe") ||
            image_name_equals_ascii(image, "pwsh.exe");
    }

    static memory_snapshot_t query_memory_snapshot(UINT32 pid, UINT64 va)
    {
        memory_snapshot_t snap = {};
        snap.lookup_status = STATUS_UNSUCCESSFUL;
        snap.query_status = STATUS_UNSUCCESSFUL;

        if (pid == 0 || va == 0) {
            snap.lookup_status = STATUS_INVALID_PARAMETER;
            snap.query_status = STATUS_INVALID_PARAMETER;
            return snap;
        }
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            snap.lookup_status = STATUS_INVALID_DEVICE_STATE;
            snap.query_status = STATUS_INVALID_DEVICE_STATE;
            return snap;
        }
        if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory) {
            snap.lookup_status = STATUS_PROCEDURE_NOT_FOUND;
            snap.query_status = STATUS_PROCEDURE_NOT_FOUND;
            return snap;
        }

        PEPROCESS process = nullptr;
        snap.lookup_status = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(snap.lookup_status) || !process)
            return snap;

        KAPC_STATE apc_state;
        _KeStackAttachProcess(process, &apc_state);

        MEMORY_BASIC_INFORMATION mbi;
        RtlZeroMemory(&mbi, sizeof(mbi));
        SIZE_T returned = 0;
        snap.query_status = _ZwQueryVirtualMemory(
            (HANDLE)-1,
            (PVOID)va,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returned);

        _KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(process);

        snap.returned_length = returned;
        if (NT_SUCCESS(snap.query_status)) {
            snap.base = (UINT64)mbi.BaseAddress;
            snap.allocation_base = (UINT64)mbi.AllocationBase;
            snap.region_size = (UINT64)mbi.RegionSize;
            snap.state = mbi.State;
            snap.protect = mbi.Protect;
            snap.allocation_protect = mbi.AllocationProtect;
            snap.type = mbi.Type;
            snap.valid = TRUE;
        }
        return snap;
    }

    static void log_slot_state(const char* tag, int idx, protection_entry_t& slot,
                               UINT64 observed_hash, const memory_snapshot_t* snap,
                               UINT32 first_mismatch = DPRT_MISMATCH_UNKNOWN,
                               const char* policy_override = nullptr,
                               LONG previous_active = 0x7FFFFFFFL,
                               UINT32 previous_status = 0xFFFFFFFFu)
    {
        char image[16];
        copy_process_image_name(slot.pid, image, sizeof(image));
        LARGE_INTEGER system_time;
        KeQuerySystemTime(&system_time);
        UINT64 interrupt_time = KeQueryInterruptTime();
        UINT64 slot_age_ms = interrupt_elapsed_ms(interrupt_time, slot.register_interrupt_time);
        UINT64 mismatch_span_ms = interrupt_elapsed_ms(interrupt_time, slot.first_mismatch_interrupt_time);
        KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
        const char* policy = policy_override ? policy_override : slot_policy_name(slot);
        WW_LOG("[DLL-PROTECT] %s idx=%d pid=%u owner_pid=%u image=%.15s prev_active=%ld active=%ld prev_status=%u status=%u policy=%s module=0x%llX text=0x%llX size=0x%X expected=0x%llX current=0x%llX observed=0x%llX mismatch=0x%X prefix=%u interval=%u checks=%llu last_tsc=%llu system_time=%lld interrupt_time=%llu age_ms=%llu mismatch_count=%u mismatch_span_ms=%llu first_mismatch=0x%llX first_mismatch_offset=0x%X dtb=0x%llX irql=%lu mode=%u current_pid=0x%llX tid=0x%llX slots=%u running=%ld queued=%ld work=%ld",
            tag ? tag : "slot",
            idx,
            slot.pid,
            slot.owner_pid,
            image,
            previous_active,
            _InterlockedCompareExchange(&slot.active, 1, 1),
            previous_status,
            slot.status,
            policy,
            slot.module_base,
            slot.text_va,
            slot.text_size,
            slot.expected_hash,
            slot.current_hash,
            observed_hash,
            first_mismatch,
            slot.baseline_prefix_size,
            slot.check_interval_ms,
            slot.check_count,
            slot.last_check_tsc,
            system_time.QuadPart,
            interrupt_time,
            slot_age_ms,
            slot.mismatch_count,
            mismatch_span_ms,
            slot.first_mismatch_hash,
            slot.first_mismatch_offset,
            cached_dtb_for_pid(slot.pid),
            KeGetCurrentIrql(),
            (UINT32)previous_mode,
            (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
            (UINT64)(ULONG_PTR)PsGetCurrentThreadId(),
            active_slot_count(),
            _InterlockedCompareExchange(&g_timer_running, 1, 1),
            _InterlockedCompareExchange(&g_timer_work_item_queued, 1, 1),
            _InterlockedCompareExchange(&g_timer_work_item_running, 1, 1));
        if (snap) {
            WW_LOG("[DLL-PROTECT] %s memory idx=%d lookup=0x%08X query=0x%08X valid=%u base=0x%llX alloc=0x%llX region=0x%llX state=0x%lX protect=0x%lX alloc_protect=0x%lX type=0x%lX returned=0x%llX",
                tag ? tag : "slot",
                idx,
                snap->lookup_status,
                snap->query_status,
                snap->valid ? 1u : 0u,
                snap->base,
                snap->allocation_base,
                snap->region_size,
                snap->state,
                snap->protect,
                snap->allocation_protect,
                snap->type,
                (UINT64)snap->returned_length);
        }
    }

    static void ensure_timer_work_sync_initialized()
    {
        if (_InterlockedCompareExchange(&g_timer_work_sync_initialized, 1, 0) == 0)
            KeInitializeEvent(&g_timer_work_done, NotificationEvent, TRUE);
    }


    __forceinline UINT64 crc_combine(UINT64 h1, UINT64 h2, const UINT8* data, SIZE_T len) {
        SIZE_T aligned_end = len & ~7ULL;
        for (SIZE_T i = 0; i < aligned_end; i += 8) {
            UINT64 block = *reinterpret_cast<const UINT64*>(data + i);
            h1 = _mm_crc32_u64(h1, block);
            h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
        }
        for (SIZE_T i = aligned_end; i < len; ++i) {
            h1 = _mm_crc32_u8((UINT32)h1, data[i]);
            h2 = _mm_crc32_u8((UINT32)h2, data[i] ^ 0xA5u);
        }
        return (h1 & 0xFFFFFFFF) | ((h2 & 0xFFFFFFFF) << 32);
    }

    static UINT64 compute_code_hash_physical(UINT32 pid, UINT64 va, UINT32 size) {
        if (pid == 0 || va == 0 || size == 0)
            return 0;

        UINT64 dtb = resolve_dtb_for_pid(pid, "hash");
        if (dtb == 0)
            return 0;

        UINT64 h1 = 0xFFFFFFFFULL;
        UINT64 h2 = 0x85EBCA6BULL;

        UINT64 cursor = va;
        UINT32 remaining = size;
        UINT8 page_buf[0x1000];

        while (remaining > 0) {
            UINT32 page_offset = (UINT32)(cursor & 0xFFF);
            UINT32 to_read = 0x1000 - page_offset;
            if (to_read > remaining)
                to_read = remaining;

            UINT64 phys = translate_virtual_with_dtb_retry(pid, cursor, &dtb, "hash");
            if (phys == 0)
                return 0;

            SIZE_T bytes_read = 0;
            NTSTATUS st = strong::read_physical(phys, page_buf, to_read, &bytes_read);
            if (!NT_SUCCESS(st) || bytes_read != to_read)
                return 0;


            UINT32 aligned_end = to_read & ~7u;
            for (UINT32 i = 0; i < aligned_end; i += 8) {
                UINT64 block = *reinterpret_cast<const UINT64*>(page_buf + i);
                h1 = _mm_crc32_u64(h1, block);
                h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
            }
            for (UINT32 i = aligned_end; i < to_read; i++) {
                h1 = _mm_crc32_u8((UINT32)h1, page_buf[i]);
                h2 = _mm_crc32_u8((UINT32)h2, page_buf[i] ^ 0xA5u);
            }

            cursor += to_read;
            remaining -= to_read;
        }

        return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
    }


    static BOOLEAN check_peb_debugger_physical(UINT32 pid) {
        if (pid == 0)
            return FALSE;

        UINT64 dtb = resolve_dtb_for_pid(pid, "peb");
        if (dtb == 0)
            return FALSE;


        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return FALSE;

        UINT64 peb_addr = (UINT64)PsGetProcessPeb(process);
        ObDereferenceObject(process);

        if (peb_addr == 0)
            return FALSE;

        UINT8 being_debugged = 0;
        UINT32 nt_global_flag = 0;

        auto read_byte_physical = [&](UINT64 va) -> UINT8 {
            UINT64 phys = translate_virtual_with_dtb_retry(pid, va, &dtb, "peb");
            if (phys == 0)
                return 0;
            UINT8 val = 0;
            SIZE_T bytes_read = 0;
            NTSTATUS s = strong::read_physical(phys, &val, sizeof(val), &bytes_read);
            if (!NT_SUCCESS(s) || bytes_read != sizeof(val))
                return 0;
            return val;
        };

        being_debugged = read_byte_physical(peb_addr + 0x02);

        UINT8 ngf_bytes[4];
        for (int b = 0; b < 4; b++)
            ngf_bytes[b] = read_byte_physical(peb_addr + 0xBC + b);
        nt_global_flag = *(UINT32*)ngf_bytes;

        if (being_debugged != 0)
            return TRUE;
        if ((nt_global_flag & 0x70) != 0)
            return TRUE;

        return FALSE;
    }


    static BOOLEAN check_debug_port_eprocess(UINT32 pid, UINT64* out_port) {
        *out_port = 0;
        if (pid == 0) return FALSE;

        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return FALSE;

        BOOLEAN detected = FALSE;
        __try {
            UINT8* eprocess = (UINT8*)process;
            SIZE_T debug_port_offset = whoswho_kernel_layout::eprocess_debug_port_offset();
            if (debug_port_offset == 0) {
                WW_LOG("[DLL-PROTECT] debug_port_check fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                    pid,
                    whoswho_kernel_layout::build_number());
                ObDereferenceObject(process);
                return FALSE;
            }
            volatile PVOID* debug_port = (volatile PVOID*)(eprocess + debug_port_offset);
            if (_MmIsAddressValid((PVOID)debug_port)) {
                PVOID port = *debug_port;
                UINT64 port_value = (UINT64)(ULONG_PTR)port;
                if (port != nullptr && port_value >= 0xFFFF800000000000ull) {
                    *out_port = (UINT64)(ULONG_PTR)port;
                    detected = TRUE;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            detected = FALSE;
        }

        ObDereferenceObject(process);
        return detected;
    }


    static BOOLEAN is_canonical_pointer(UINT64 value) {
        return value == 0 ||
            value < 0x0000800000000000ull ||
            value >= 0xFFFF800000000000ull;
    }

    static BOOLEAN check_foreign_instrumentation(UINT32 pid, UINT64* out_cb) {
        *out_cb = 0;
        if (pid == 0) return FALSE;

        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return FALSE;

        BOOLEAN detected = FALSE;
        __try {
            UINT8* eprocess = (UINT8*)process;
            SIZE_T instr_offset = whoswho_kernel_layout::eprocess_instrumentation_callback_offset();
            if (instr_offset == 0) {
                WW_LOG("[DLL-PROTECT] instrumentation_check fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                    pid,
                    whoswho_kernel_layout::build_number());
                ObDereferenceObject(process);
                return FALSE;
            }
            volatile PVOID* instr_cb = (volatile PVOID*)(eprocess + instr_offset);
            if (_MmIsAddressValid((PVOID)instr_cb)) {
                PVOID cb = *instr_cb;
                if (cb != nullptr) {
                    UINT64 cb_value = (UINT64)(ULONG_PTR)cb;
                    *out_cb = cb_value;
                    if (is_canonical_pointer(cb_value)) {
                        detected = TRUE;
                    } else {
                        UINT32 cb_tag = static_cast<UINT32>((cb_value >> 32) ^ cb_value ^ 0x0A1DA460u);
                        LARGE_INTEGER now;
                        KeQuerySystemTime(&now);
                        ULONG suppressed = 0;
                        if (should_log_repetitive_diagnostic(
                            &g_instr_noncanonical_log_last_time,
                            &g_instr_noncanonical_log_emitted,
                            &g_instr_noncanonical_log_suppressed,
                            now.QuadPart,
                            &suppressed)) {
                            WW_LOG("[DLL-PROTECT] pid=%u instrumentation_noncanonical_ignored cb_tag=0x%08X suppressed=%lu",
                                pid, cb_tag, suppressed);
                        }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            detected = FALSE;
        }

        ObDereferenceObject(process);
        return detected;
    }


    static BOOLEAN scan_thread_drs(UINT32 pid, UINT64 text_va, UINT32 text_size,
                                   UINT32* out_tid, int* out_index, UINT64* out_dr_value) {
        *out_tid = 0;
        *out_index = -1;
        *out_dr_value = 0;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return FALSE;
        if (!_PsGetNextProcessThread || !_PsGetContextThread)
            return FALSE;

        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return FALSE;

        UINT64 text_end = text_va + text_size;
        BOOLEAN found = FALSE;
        PETHREAD thread = nullptr;
        int scanned = 0;

        __try {
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr) {
                if (++scanned > 256) break;

                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                NTSTATUS ctx_st = _PsGetContextThread(thread, &ctx, KernelMode);
                if (!NT_SUCCESS(ctx_st))
                    continue;

                UINT64 drs[4] = { ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 };
                for (int i = 0; i < 4; ++i) {
                    if (drs[i] != 0 && drs[i] >= text_va && drs[i] < text_end) {
                        *out_tid = (UINT32)(ULONG_PTR)PsGetThreadId(thread);
                        *out_index = i;
                        *out_dr_value = drs[i];
                        found = TRUE;
                        break;
                    }
                }

                if (!found && (ctx.Dr7 & 0x55ULL) != 0) {
                    UINT8 enabled_mask = (UINT8)(ctx.Dr7 & 0x55ULL);
                    for (int i = 0; i < 4; ++i) {
                        if (enabled_mask & (1 << (i * 2))) {
                            if (drs[i] != 0) {
                                *out_tid = (UINT32)(ULONG_PTR)PsGetThreadId(thread);
                                *out_index = 4 + i;
                                *out_dr_value = drs[i];
                                found = TRUE;
                                break;
                            }
                        }
                    }
                }

                if (found) break;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            found = FALSE;
        }

        ObDereferenceObject(process);
        return found;
    }


    static int find_slot(UINT32 pid, UINT64 module_base) {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                g_slots[i].pid == pid &&
                g_slots[i].module_base == module_base)
                return i;
        }
        return -1;
    }


    static int find_slot_by_pid(UINT32 pid) {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                g_slots[i].pid == pid)
                return i;
        }
        return -1;
    }


    static int find_free_slot() {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 0, 0) == 0)
                return i;
        }
        return -1;
    }


    static BOOLEAN any_active() {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1)
                return TRUE;
        }
        return FALSE;
    }


    static UINT32 compute_min_interval() {
        UINT32 min_iv = 0xFFFFFFFFu;
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1) {
                if (g_slots[i].check_interval_ms < min_iv)
                    min_iv = g_slots[i].check_interval_ms;
            }
        }
        return (min_iv == 0xFFFFFFFFu) ? 0 : min_iv;
    }


    static void stop_timer() {
        if (_InterlockedCompareExchange(&g_timer_running, 0, 1) == 1)
            KeCancelTimer(&g_timer);
        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
        ensure_timer_work_sync_initialized();
        if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
            (_InterlockedCompareExchange(&g_timer_work_item_queued, 0, 0) != 0 ||
             _InterlockedCompareExchange(&g_timer_work_item_running, 0, 0) != 0)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50'000'000LL;
            KeWaitForSingleObject(&g_timer_work_done, Executive, KernelMode, FALSE, &timeout);
        }
    }

    static void start_or_restart_timer();

    static UINT32 pid_from_handle(HANDLE pid)
    {
        return static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(pid));
    }

    static UINT32 current_owner_pid()
    {
        HANDLE registered = caller_validation::g_registered_client_pid;
        if (registered)
            return pid_from_handle(registered);
        return 0;
    }

    static BOOLEAN slot_owner_authenticated(const protection_entry_t& slot)
    {
        UINT32 owner_pid = slot.owner_pid != 0 ? slot.owner_pid : slot.pid;
        if (owner_pid == 0)
            return FALSE;

        if (_InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0) == 0)
            return FALSE;

        HANDLE registered = caller_validation::g_registered_client_pid;
        if (!registered)
            return FALSE;

        return pid_from_handle(registered) == owner_pid;
    }

    static BOOLEAN lock_slot_owner_for_hard_bugcheck(const protection_entry_t& slot)
    {
        UINT32 owner_pid = slot.owner_pid != 0 ? slot.owner_pid : slot.pid;
        if (owner_pid == 0)
            return FALSE;

        caller_validation::acquire_lock();
        BOOLEAN ok = FALSE;
        if (_InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0) != 0) {
            HANDLE registered = caller_validation::g_registered_client_pid;
            ok = registered && pid_from_handle(registered) == owner_pid;
        }
        if (!ok)
            caller_validation::release_lock();
        return ok;
    }

    static BOOLEAN slot_matches_cleanup_pid(const protection_entry_t& slot, UINT32 pid)
    {
        if (pid == 0)
            return FALSE;
        if (slot.pid == pid)
            return TRUE;
        if (slot.owner_pid != 0 && slot.owner_pid == pid)
            return TRUE;
        return FALSE;
    }

    static void disarm_stale_slot(int idx, protection_entry_t& slot)
    {
        LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
        UINT32 previous_status = slot.status;
        UINT32 registered_pid = current_owner_pid();
        LONG validation_enabled = _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0);
        log_slot_state("timer_stale_session_disarm", idx, slot, slot.current_hash, nullptr,
            DPRT_MISMATCH_UNKNOWN, "owner_session_invalid_disarm",
            previous_active, previous_status);
        UINT32 target_pid = slot.pid;
        UINT32 owner_pid = slot.owner_pid;
        reset_slot(slot);
        WW_LOG("[DLL-PROTECT] timer_stale_session_disarmed idx=%d pid=%u owner_pid=%u registered_pid=%u validation_enabled=%ld active_slots=%u timer_running=%ld",
            idx,
            target_pid,
            owner_pid,
            registered_pid,
            validation_enabled,
            active_slot_count(),
            _InterlockedCompareExchange(&g_timer_running, 1, 1));
    }

    static ULONG cleanup_for_pid_internal(UINT32 pid, const char* reason, const char* slot_tag, const char* summary_tag)
    {
        if (pid == 0)
            return 0;

        ULONG cleared = 0;
        bool matched = false;
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                slot_matches_cleanup_pid(g_slots[i], pid)) {
                matched = true;
                break;
            }
        }
        if (!matched)
            return 0;

        stop_timer();
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                slot_matches_cleanup_pid(g_slots[i], pid)) {
                log_slot_state(slot_tag ? slot_tag : "cleanup_unregister_pid", i, g_slots[i],
                    g_slots[i].current_hash, nullptr);
                reset_slot(g_slots[i]);
                ++cleared;
            }
        }

        if (cleared != 0) {
            if (any_active())
                start_or_restart_timer();
            else
                stop_timer();
            WW_LOG("[DLL-PROTECT] %s reason=%s pid=%u cleared=%lu active_slots=%u timer_running=%ld",
                summary_tag ? summary_tag : "cleanup_for_pid",
                reason ? reason : "unknown",
                pid,
                cleared,
                active_slot_count(),
                _InterlockedCompareExchange(&g_timer_running, 1, 1));
        }
        return cleared;
    }

    ULONG cleanup_for_pid(UINT32 pid)
    {
        return cleanup_for_pid_internal(pid, "process_exit", "process_exit_unregister_pid", "process_exit_cleanup");
    }

    BOOLEAN has_tracked_pid(UINT32 pid)
    {
        if (pid == 0)
            return FALSE;
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                slot_matches_cleanup_pid(g_slots[i], pid)) {
                return TRUE;
            }
        }
        return FALSE;
    }

    ULONG cleanup_for_session_reset(UINT32 pid, const char* reason)
    {
        ULONG cleared = cleanup_for_pid_internal(pid, reason, "session_reset_unregister_pid", "session_reset_cleanup");
        if (pid != 0 && cleared == 0) {
            WW_LOG("[DLL-PROTECT] session_reset_cleanup_no_slots reason=%s pid=%u active_slots=%u timer_running=%ld",
                reason ? reason : "unknown",
                pid,
                active_slot_count(),
                _InterlockedCompareExchange(&g_timer_running, 1, 1));
        }
        return cleared;
    }

    static void protection_timer_body()
    {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) != 1)
                continue;

            auto& slot = g_slots[i];
            if (!slot_owner_authenticated(slot)) {
                disarm_stale_slot(i, slot);
                continue;
            }

            slot.check_count++;


            if (check_peb_debugger_physical(slot.pid)) {
                if (!slot_owner_authenticated(slot)) {
                    disarm_stale_slot(i, slot);
                    continue;
                }
                LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
                UINT32 previous_status = slot.status;
                slot.status = DPRT_STATUS_DEBUGGER;
                _InterlockedExchange(&slot.active, 0);

                memory_snapshot_t snap = query_memory_snapshot(slot.pid, slot.text_va);
                log_slot_state("timer_peb_debugger_bugcheck", i, slot, 0, &snap,
                    DPRT_MISMATCH_UNKNOWN, "peb_debugger_hard_bugcheck",
                    previous_active, previous_status);
                if (!lock_slot_owner_for_hard_bugcheck(slot)) {
                    disarm_stale_slot(i, slot);
                    continue;
                }
                WW_LOG("[DLL-PROTECT] bugcheck policy=peb_debugger code=0xDEAD0ADA pid=%u text=0x%llX p3=0x%llX p4=0x%llX",
                    slot.pid, slot.text_va, 0xDB6ULL, (UINT64)i);
                KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                             (ULONG_PTR)slot.text_va, 0xDB6u, (ULONG_PTR)i);
                return;
            }


            UINT64 debug_port = 0;
            if (check_debug_port_eprocess(slot.pid, &debug_port)) {
                UINT32 port_tag = static_cast<UINT32>((debug_port >> 32) ^ debug_port ^ 0x0A1DADBAu);
                WW_LOG("[DLL-PROTECT] pid=%u debug_port_present tag=0x%08X", slot.pid, port_tag);
                sentinel_bridge::populate_evidence_blob(
                    sentinel_bridge::EVIDENCE_FAMILY_DEBUG,
                    sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                    100,
                    slot.pid,
                    0,
                    0,
                    port_tag);
                publish_bridge_command(sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND, port_tag);
            }


            {
                UINT32 bad_tid = 0;
                int dr_idx = -1;
                UINT64 dr_val = 0;
                if (scan_thread_drs(slot.pid, slot.text_va, slot.text_size,
                                    &bad_tid, &dr_idx, &dr_val)) {
                    if (!slot_owner_authenticated(slot)) {
                        disarm_stale_slot(i, slot);
                        continue;
                    }
                    LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
                    UINT32 previous_status = slot.status;
                    slot.status = DPRT_STATUS_DEBUGGER;
                    _InterlockedExchange(&slot.active, 0);
                    memory_snapshot_t snap = query_memory_snapshot(slot.pid, slot.text_va);
                    log_slot_state("timer_thread_dr_bugcheck", i, slot, 0, &snap,
                        DPRT_MISMATCH_UNKNOWN, "thread_dr_hard_bugcheck",
                        previous_active, previous_status);
                    if (!lock_slot_owner_for_hard_bugcheck(slot)) {
                        disarm_stale_slot(i, slot);
                        continue;
                    }
                    WW_LOG("[DLL-PROTECT] bugcheck policy=thread_dr pid=%u bad_tid=%u dr=0x%llX dr_idx=%d p4=0x%llX",
                        slot.pid, bad_tid, dr_val, dr_idx, (UINT64)(0xD7D70000u | (UINT32)dr_idx));
                    KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                                 (ULONG_PTR)bad_tid,
                                 (ULONG_PTR)dr_val,
                                 (ULONG_PTR)(0xD7D70000u | (UINT32)dr_idx));
                    return;
                }
            }


            {
                UINT64 instr_cb = 0;
                BOOLEAN has_instr = check_foreign_instrumentation(slot.pid, &instr_cb);
                UINT32 instr_tag = static_cast<UINT32>((instr_cb >> 32) ^ instr_cb ^ 0x0A1DA461u);
                BOOLEAN fileless_terminal = is_fileless_terminal_slot(slot);
                ULONG suppressed = 0;
                BOOLEAN log_instrumentation_check = has_instr ? TRUE : FALSE;
                if (!log_instrumentation_check) {
                    LARGE_INTEGER now;
                    KeQuerySystemTime(&now);
                    log_instrumentation_check = should_log_repetitive_diagnostic(
                        &g_instr_check_log_last_time,
                        &g_instr_check_log_emitted,
                        &g_instr_check_log_suppressed,
                        now.QuadPart,
                        &suppressed);
                }
                if (log_instrumentation_check) {
                    WW_LOG("[DLL-PROTECT] pid=%u check_foreign_instrumentation=%d cb_present=%u cb_tag=0x%08X fileless_terminal=%u suppressed=%lu",
                        slot.pid, has_instr ? 1 : 0, instr_cb != 0 ? 1u : 0u, instr_tag, fileless_terminal ? 1u : 0u, suppressed);
                }
                if (has_instr) {
                    if (fileless_terminal) {
                        WW_LOG("[DLL-PROTECT] pid=%u foreign_instr_cb_fileless_terminal_suppressed reason=0x%08X cb_tag=0x%08X owner_pid=%u module=0x%llX text=0x%llX",
                            slot.pid,
                            DPRT_REASON_FOREIGN_INSTRUMENTATION,
                            instr_tag,
                            slot.owner_pid,
                            slot.module_base,
                            slot.text_va);
                    } else {
                        WW_LOG("[DLL-PROTECT] pid=%u foreign_instr_cb_observed reason=0x%08X cb_tag=0x%08X", slot.pid, DPRT_REASON_FOREIGN_INSTRUMENTATION, instr_tag);
                        publish_re_evidence(DPRT_REASON_FOREIGN_INSTRUMENTATION,
                            sentinel_bridge::EVIDENCE_FAMILY_SIDECHANNEL,
                            35,
                            slot.pid,
                            0,
                            static_cast<ULONG64>(instr_cb),
                            instr_tag);
                    }
                }
            }


            UINT64 hash = compute_code_hash_physical(slot.pid, slot.text_va, slot.text_size);
            slot.last_check_tsc = __rdtsc();

            if (hash == 0) {

                LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
                UINT32 previous_status = slot.status;
                slot.current_hash = 0;
                slot.status = DPRT_STATUS_INACTIVE;
                _InterlockedExchange(&slot.active, 0);
                memory_snapshot_t snap = query_memory_snapshot(slot.pid, slot.text_va);
                log_slot_state("timer_hash_unavailable_deactivate", i, slot, hash, &snap,
                    DPRT_MISMATCH_UNKNOWN, "hash_unavailable_fail_closed",
                    previous_active, previous_status);
                continue;
            }

            slot.current_hash = hash;

            if (hash != slot.expected_hash) {
                if (!slot_owner_authenticated(slot)) {
                    disarm_stale_slot(i, slot);
                    continue;
                }
                LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
                UINT32 previous_status = slot.status;
                UINT32 mismatch_offset = first_mismatch_offset(slot);
                slot.status = DPRT_STATUS_TAMPERED;

                memory_snapshot_t snap = query_memory_snapshot(slot.pid, slot.text_va);
                if (slot_hard_bugcheck_enabled(slot)) {
                    UINT64 now_interrupt = KeQueryInterruptTime();
                    if (slot.mismatch_count == 0) {
                        slot.first_mismatch_interrupt_time = now_interrupt;
                        slot.first_mismatch_hash = hash;
                        slot.first_mismatch_offset = mismatch_offset;
                        slot.mismatch_count = 1;
                    } else if (slot.mismatch_count < 0xFFFFFFFFu) {
                        ++slot.mismatch_count;
                    }
                    slot.last_mismatch_interrupt_time = now_interrupt;
                    UINT64 slot_age_ms = interrupt_elapsed_ms(now_interrupt, slot.register_interrupt_time);
                    UINT64 mismatch_span_ms = interrupt_elapsed_ms(now_interrupt, slot.first_mismatch_interrupt_time);
                    BOOLEAN confirmed = slot.mismatch_count >= DPRT_HARD_BUGCHECK_MIN_MISMATCHES &&
                        slot_age_ms >= DPRT_HARD_BUGCHECK_ARM_DELAY_MS &&
                        mismatch_span_ms >= DPRT_HARD_BUGCHECK_MIN_SPAN_MS;
                    publish_text_integrity_evidence(slot);
                    if (!confirmed) {
                        log_slot_state("timer_hash_mismatch_deferred", i, slot, hash, &snap,
                            mismatch_offset, "hash_mismatch_hard_bugcheck_deferred",
                            previous_active, previous_status);
                        WW_LOG("[DLL-PROTECT] no_bugcheck policy=hash_mismatch_deferred pid=%u module=0x%llX text=0x%llX expected=0x%llX actual=0x%llX mismatch=0x%X count=%u required=%u age_ms=%llu arm_delay_ms=%u span_ms=%llu required_span_ms=%u evidence=dllprotect_status_log",
                            slot.pid,
                            slot.module_base,
                            slot.text_va,
                            slot.expected_hash,
                            hash,
                            mismatch_offset,
                            slot.mismatch_count,
                            DPRT_HARD_BUGCHECK_MIN_MISMATCHES,
                            slot_age_ms,
                            DPRT_HARD_BUGCHECK_ARM_DELAY_MS,
                            mismatch_span_ms,
                            DPRT_HARD_BUGCHECK_MIN_SPAN_MS);
                        continue;
                    }
                    _InterlockedExchange(&slot.active, 0);
                    if (!lock_slot_owner_for_hard_bugcheck(slot)) {
                        disarm_stale_slot(i, slot);
                        continue;
                    }
                    log_slot_state("timer_hash_mismatch_bugcheck", i, slot, hash, &snap,
                        mismatch_offset, "hash_mismatch_hard_bugcheck",
                        previous_active, previous_status);
                    WW_LOG("[DLL-PROTECT] bugcheck policy=hash_mismatch code=0xDEAD0ADA pid=%u text=0x%llX expected=0x%llX actual=0x%llX mismatch=0x%X count=%u age_ms=%llu span_ms=%llu p3=0x%llX p4=0x%llX",
                        slot.pid,
                        slot.text_va,
                        slot.expected_hash,
                        hash,
                        mismatch_offset,
                        slot.mismatch_count,
                        slot_age_ms,
                        mismatch_span_ms,
                        (slot.expected_hash >> 32),
                        (hash >> 32));
                    KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                                 (ULONG_PTR)slot.text_va,
                                 (ULONG_PTR)(slot.expected_hash >> 32),
                                 (ULONG_PTR)(hash >> 32));
                    return;
                }

                _InterlockedExchange(&slot.active, 0);
                log_slot_state("timer_hash_mismatch_fail_closed", i, slot, hash, &snap,
                    mismatch_offset, "hash_mismatch_diagnostic_fail_closed",
                    previous_active, previous_status);
                WW_LOG("[DLL-PROTECT] no_bugcheck policy=hash_mismatch_diagnostic_fail_closed pid=%u module=0x%llX text=0x%llX expected=0x%llX actual=0x%llX mismatch=0x%X evidence=dllprotect_status_log",
                    slot.pid,
                    slot.module_base,
                    slot.text_va,
                    slot.expected_hash,
                    hash,
                    mismatch_offset);
                continue;
            }

            if (slot.mismatch_count != 0) {
                log_slot_state("timer_hash_recovered", i, slot, hash, nullptr);
                clear_mismatch_tracking(slot);
            }
            slot.status = DPRT_STATUS_ACTIVE;
            if (slot.check_count <= 2 || (slot.check_count & 0x3FULL) == 0)
                log_slot_state("timer_hash_ok", i, slot, hash, nullptr);
        }


        if (!any_active()) {
            _InterlockedExchange(&g_timer_running, 0);
            KeCancelTimer(&g_timer);
        }
    }

    static VOID NTAPI protection_timer_work_item(PVOID)
    {
        _InterlockedExchange(&g_timer_work_item_running, 1);
        if (_InterlockedCompareExchange(&g_timer_running, 1, 1) != 1) {
            _InterlockedExchange(&g_timer_work_item_running, 0);
            _InterlockedExchange(&g_timer_work_item_queued, 0);
            KeSetEvent(&g_timer_work_done, IO_NO_INCREMENT, FALSE);
            return;
        }

        UINT64 start_interrupt_time = KeQueryInterruptTime();
        BOOLEAN exception_seen = FALSE;
        __try {
            protection_timer_body();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            exception_seen = TRUE;
            WW_LOG("[DLL-PROTECT] protection work exception");
        }
        UINT64 end_interrupt_time = KeQueryInterruptTime();
        UINT64 elapsed_100ns = end_interrupt_time >= start_interrupt_time ? end_interrupt_time - start_interrupt_time : 0;
        LONG runs = _InterlockedIncrement(&g_timer_work_run_count);
        BOOLEAN log_work_exit = exception_seen ? TRUE : FALSE;
        if (!log_work_exit && elapsed_100ns >= DPRT_TIMER_WORK_SLOW_100NS)
            log_work_exit = TRUE;
        if (!log_work_exit && (runs <= 2 || ((static_cast<ULONG>(runs) & 0x3FUL) == 0)))
            log_work_exit = TRUE;
        if (log_work_exit) {
            WW_LOG("[DLL-PROTECT] protection_timer_work_exit elapsed_us=%llu runs=%ld exception=%u active_slots=%lu running=%ld queued=%ld work_running=%ld current_pid=0x%llX irql=%lu",
                elapsed_100ns / 10ULL,
                runs,
                exception_seen ? 1u : 0u,
                active_slot_count(),
                _InterlockedCompareExchange(&g_timer_running, 1, 1),
                _InterlockedCompareExchange(&g_timer_work_item_queued, 1, 1),
                _InterlockedCompareExchange(&g_timer_work_item_running, 1, 1),
                (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
                KeGetCurrentIrql());
        }

        _InterlockedExchange(&g_timer_work_item_running, 0);
        _InterlockedExchange(&g_timer_work_item_queued, 0);
        KeSetEvent(&g_timer_work_done, IO_NO_INCREMENT, FALSE);
    }

    static VOID NTAPI protection_timer_dpc(
        PKDPC , PVOID ,
        PVOID , PVOID )
    {
        if (_InterlockedCompareExchange(&g_timer_running, 1, 1) != 1)
            return;
        if (_InterlockedCompareExchange(&g_timer_work_item_queued, 1, 0) != 0)
            return;

        ensure_timer_work_sync_initialized();
        KeClearEvent(&g_timer_work_done);
        ExInitializeWorkItem(&g_timer_work_item, protection_timer_work_item, nullptr);
        if (_ExQueueWorkItem)
            _ExQueueWorkItem(&g_timer_work_item, DelayedWorkQueue);
        else
            ExQueueWorkItem(&g_timer_work_item, DelayedWorkQueue);
    }

    static void start_or_restart_timer() {
        UINT32 min_iv = compute_min_interval();
        if (min_iv == 0) {
            stop_timer();
            return;
        }

        if (_InterlockedCompareExchange(&g_timer_initialized, 1, 0) == 0) {
            ensure_timer_work_sync_initialized();
            KeSetEvent(&g_timer_work_done, IO_NO_INCREMENT, FALSE);
            KeInitializeTimer(&g_timer);
            KeInitializeDpc(&g_timer_dpc, protection_timer_dpc, nullptr);
        }

        LARGE_INTEGER due_time;
        due_time.QuadPart = -((LONGLONG)min_iv * 10000LL);
        KeSetTimerEx(&g_timer, due_time, (LONG)min_iv, &g_timer_dpc);
        _InterlockedExchange(&g_timer_running, 1);
    }

}


namespace anti_dump_driver {

    inline NTSTATUS trim_working_set(UINT32 pid)
    {
        UNREFERENCED_PARAMETER(pid);
        return STATUS_NOT_SUPPORTED;
    }

    inline NTSTATUS detect_external_handles(UINT32 target_pid, UINT64* suspicious_pid)
    {
        *suspicious_pid = 0;

        __try {
            PEPROCESS target_proc = nullptr;
            NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid, &target_proc);
            if (!NT_SUCCESS(st)) return st;

            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial) {
                ObDereferenceObject(target_proc);
                return STATUS_UNSUCCESSFUL;
            }

            SIZE_T active_links_offset = whoswho_kernel_layout::eprocess_active_process_links_offset();
            SIZE_T object_table_offset = whoswho_kernel_layout::eprocess_object_table_offset();
            if (active_links_offset == 0 || object_table_offset == 0) {
                WW_LOG("[DLL-PROTECT] detect_external_handles fail_closed target_pid=%u build=%lu active_offset=0x%llx object_offset=0x%llx",
                    target_pid,
                    whoswho_kernel_layout::build_number(),
                    static_cast<unsigned long long>(active_links_offset),
                    static_cast<unsigned long long>(object_table_offset));
                ObDereferenceObject(target_proc);
                return STATUS_NOT_SUPPORTED;
            }

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + active_links_offset);
            PLIST_ENTRY entry = list_head->Flink;

            for (int iter = 0; iter < 2048 && entry != list_head; ++iter, entry = entry->Flink)
            {
                PEPROCESS scan_proc = (PEPROCESS)((UINT8*)entry - active_links_offset);
                if (!_MmIsAddressValid(scan_proc)) continue;
                if (scan_proc == target_proc) continue;

                HANDLE scan_pid = PsGetProcessId(scan_proc);
                if ((UINT64)(ULONG_PTR)scan_pid <= 4) continue;

                UINT8* eproc = (UINT8*)scan_proc;
                if (!_MmIsAddressValid(eproc + object_table_offset)) continue;

                volatile UINT64* object_table = (volatile UINT64*)(eproc + object_table_offset);
                if (*object_table == 0) continue;

                UCHAR* image_name = PsGetProcessImageFileName(scan_proc);
                if (!image_name || !_MmIsAddressValid(image_name)) continue;

                const char* dump_tools[] = {
                    "processdump", "procdump", "taskdmp", "minidumper",
                    "hollowshunt", "pe-sieve", "scylla"
                };

                for (int n = 0; n < (int)(sizeof(dump_tools) / sizeof(dump_tools[0])); ++n) {
                    const char* target = dump_tools[n];
                    BOOLEAN match = TRUE;
                    for (int c = 0; target[c] != '\0'; ++c) {
                        char a = (char)(image_name[c] | 0x20);
                        char b = (char)(target[c] | 0x20);
                        if (a != b) { match = FALSE; break; }
                    }
                    if (match) {
                        *suspicious_pid = (UINT64)(ULONG_PTR)scan_pid;
                        ObDereferenceObject(target_proc);
                        return STATUS_SUCCESS;
                    }
                }
            }

            ObDereferenceObject(target_proc);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_NOT_FOUND;
    }

    inline NTSTATUS corrupt_vad_protection(UINT32 pid, UINT64 region_base)
    {
        UNREFERENCED_PARAMETER(pid);
        UNREFERENCED_PARAMETER(region_base);
        return STATUS_NOT_SUPPORTED;
    }

}


NTSTATUS functions::handle_dll_protect(p_dll_protect request) {
    if (!request)
        return STATUS_INVALID_PARAMETER;

    __try {
        switch (request->operation) {
        case DPRT_OP_REGISTER:
        {
            if (request->pid == 0 || request->text_section_va == 0 ||
                request->text_section_size == 0 || request->expected_hash == 0) {
                WW_LOG("[DLL-PROTECT] register_reject invalid pid=%u module=0x%llX text=0x%llX size=0x%X expected=0x%llX irql=%lu tid=0x%llX",
                    request->pid,
                    request->module_base,
                    request->text_section_va,
                    request->text_section_size,
                    request->expected_hash,
                    KeGetCurrentIrql(),
                    (UINT64)(ULONG_PTR)PsGetCurrentThreadId());
                return STATUS_INVALID_PARAMETER;
            }


            int idx = dll_protection::find_slot(request->pid, request->module_base);
            if (idx < 0)
                idx = dll_protection::find_free_slot();
            if (idx < 0) {
                WW_LOG("[DLL-PROTECT] register_reject no_slot pid=%u module=0x%llX text=0x%llX size=0x%X expected=0x%llX active_slots=%u",
                    request->pid,
                    request->module_base,
                    request->text_section_va,
                    request->text_section_size,
                    request->expected_hash,
                    dll_protection::active_slot_count());
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            UINT32 interval = 10000;
            if (request->check_interval > 0 && request->check_interval <= 30000)
                interval = request->check_interval;

            auto& slot = dll_protection::g_slots[idx];
            LONG previous_active = _InterlockedCompareExchange(&slot.active, 1, 1);
            UINT32 previous_status = slot.status;

            dll_protection::protection_entry_t preview = {};
            preview.pid = request->pid;
            preview.module_base = request->module_base;
            preview.text_va = request->text_section_va;
            preview.text_size = request->text_section_size;
            preview.expected_hash = request->expected_hash;
            preview.check_interval_ms = interval;
            preview.last_check_tsc = __rdtsc();
            preview.owner_pid = dll_protection::current_owner_pid();
            preview.register_interrupt_time = KeQueryInterruptTime();
            preview.first_mismatch_offset = dll_protection::DPRT_MISMATCH_UNKNOWN;
            if (preview.owner_pid == 0) {
                WW_LOG("[DLL-PROTECT] register_reject no_owner pid=%u module=0x%llX text=0x%llX size=0x%X validation_enabled=%ld",
                    request->pid,
                    request->module_base,
                    request->text_section_va,
                    request->text_section_size,
                    _InterlockedCompareExchange(&caller_validation::g_validation_enabled, 0, 0));
                return STATUS_ACCESS_DENIED;
            }
            preview.policy_flags = 0;
            preview.current_hash = dll_protection::compute_code_hash_physical(
                request->pid,
                request->text_section_va,
                request->text_section_size);
            preview.status = preview.current_hash == 0 ? DPRT_STATUS_INACTIVE : DPRT_STATUS_TAMPERED;

            dll_protection::memory_snapshot_t snap = dll_protection::query_memory_snapshot(
                request->pid,
                request->text_section_va);

            if (preview.current_hash == 0) {
                request->status = DPRT_STATUS_INACTIVE;
                request->current_hash = 0;
                request->check_interval = interval;
                request->last_check_tsc = preview.last_check_tsc;
                dll_protection::log_slot_state("register_reject_hash_unavailable", idx, preview, 0, &snap,
                    dll_protection::DPRT_MISMATCH_UNKNOWN, "register_hash_unavailable_fail_closed",
                    previous_active, previous_status);
                return STATUS_SUCCESS;
            }

            if (preview.current_hash != request->expected_hash) {
                request->status = DPRT_STATUS_TAMPERED;
                request->current_hash = preview.current_hash;
                request->check_interval = interval;
                request->last_check_tsc = preview.last_check_tsc;
                dll_protection::log_slot_state("register_reject_hash_mismatch", idx, preview, preview.current_hash, &snap,
                    dll_protection::DPRT_MISMATCH_UNKNOWN, "register_hash_mismatch_fail_closed_no_baseline",
                    previous_active, previous_status);
                WW_LOG("[DLL-PROTECT] register_reject_hash_mismatch pid=%u module=0x%llX text=0x%llX size=0x%X expected=0x%llX actual=0x%llX evidence=dllprotect_status_log",
                    request->pid,
                    request->module_base,
                    request->text_section_va,
                    request->text_section_size,
                    request->expected_hash,
                    preview.current_hash);
                return STATUS_SUCCESS;
            }

            _InterlockedExchange(&slot.active, 0);
            slot.pid = request->pid;
            slot.module_base = request->module_base;
            slot.text_va = request->text_section_va;
            slot.text_size = request->text_section_size;
            slot.expected_hash = request->expected_hash;
            slot.current_hash = preview.current_hash;
            slot.check_interval_ms = interval;
            slot.status = DPRT_STATUS_ACTIVE;
            slot.last_check_tsc = preview.last_check_tsc;
            slot.check_count = 0;
            slot.policy_flags = (request->module_base != 0) ? dll_protection::DPRT_POLICY_HARD_BUGCHECK : 0;
            slot.owner_pid = preview.owner_pid;
            slot.register_interrupt_time = preview.register_interrupt_time;
            dll_protection::clear_mismatch_tracking(slot);
            dll_protection::capture_baseline_prefix(slot);

            _InterlockedExchange(&slot.active, 1);

            dll_protection::start_or_restart_timer();

            request->status = DPRT_STATUS_ACTIVE;
            request->current_hash = slot.current_hash;
            request->check_interval = slot.check_interval_ms;
            request->last_check_tsc = slot.last_check_tsc;
            dll_protection::log_slot_state("register_ok", idx, slot, slot.current_hash, &snap,
                dll_protection::DPRT_MISMATCH_UNKNOWN, nullptr,
                previous_active, previous_status);
            return STATUS_SUCCESS;
        }

        case DPRT_OP_QUERY:
        {


            int idx = -1;
            if (request->pid != 0 && request->module_base != 0)
                idx = dll_protection::find_slot(request->pid, request->module_base);
            else if (request->pid != 0)
                idx = dll_protection::find_slot_by_pid(request->pid);
            else {

                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    if (_InterlockedCompareExchange(&dll_protection::g_slots[i].active, 1, 1) == 1) {
                        idx = i;
                        break;
                    }
                }
            }

            if (idx < 0) {

                WW_LOG("[DLL-PROTECT] query_inactive pid=%u module=0x%llX active_slots=%u irql=%lu tid=0x%llX",
                    request->pid,
                    request->module_base,
                    dll_protection::active_slot_count(),
                    KeGetCurrentIrql(),
                    (UINT64)(ULONG_PTR)PsGetCurrentThreadId());
                request->pid = 0;
                request->module_base = 0;
                request->text_section_va = 0;
                request->text_section_size = 0;
                request->expected_hash = 0;
                request->current_hash = 0;
                request->status = DPRT_STATUS_INACTIVE;
                request->check_interval = 0;
                request->last_check_tsc = 0;
                return STATUS_SUCCESS;
            }

            auto& slot = dll_protection::g_slots[idx];
            request->pid = slot.pid;
            request->module_base = slot.module_base;
            request->text_section_va = slot.text_va;
            request->text_section_size = slot.text_size;
            request->expected_hash = slot.expected_hash;
            request->current_hash = slot.current_hash;
            request->status = slot.status;
            request->check_interval = slot.check_interval_ms;
            request->last_check_tsc = slot.last_check_tsc;
            dll_protection::log_slot_state("query_ok", idx, slot, slot.current_hash, nullptr);
            return STATUS_SUCCESS;
        }

        case DPRT_OP_UNREGISTER:
        {

            dll_protection::stop_timer();

            if (request->pid != 0 && request->module_base != 0) {
                int idx = dll_protection::find_slot(request->pid, request->module_base);
                if (idx >= 0) {
                    dll_protection::log_slot_state("unregister_one", idx, dll_protection::g_slots[idx],
                        dll_protection::g_slots[idx].current_hash, nullptr);
                    dll_protection::reset_slot(dll_protection::g_slots[idx]);
                }
            } else if (request->pid != 0) {
                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    if (_InterlockedCompareExchange(&dll_protection::g_slots[i].active, 1, 1) == 1 &&
                        dll_protection::g_slots[i].pid == request->pid) {
                        dll_protection::log_slot_state("unregister_pid", i, dll_protection::g_slots[i],
                            dll_protection::g_slots[i].current_hash, nullptr);
                        dll_protection::reset_slot(dll_protection::g_slots[i]);
                    }
                }
            } else {

                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    if (_InterlockedCompareExchange(&dll_protection::g_slots[i].active, 1, 1) == 1)
                        dll_protection::log_slot_state("unregister_all", i, dll_protection::g_slots[i],
                            dll_protection::g_slots[i].current_hash, nullptr);
                    dll_protection::reset_slot(dll_protection::g_slots[i]);
                }
            }


            if (dll_protection::any_active())
                dll_protection::start_or_restart_timer();
            else
                dll_protection::stop_timer();

            request->status = DPRT_STATUS_INACTIVE;
            WW_LOG("[DLL-PROTECT] unregister_done request_pid=%u request_module=0x%llX active_slots=%u timer_running=%ld",
                request->pid,
                request->module_base,
                dll_protection::active_slot_count(),
                _InterlockedCompareExchange(&dll_protection::g_timer_running, 1, 1));
            return STATUS_SUCCESS;
        }

        default:
            return STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}
