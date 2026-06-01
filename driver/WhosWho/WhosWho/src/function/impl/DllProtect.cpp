#include <ntifs.h>
#include <intrin.h>
#include "../Struct.h"
#include "../Functions.h"
#include "../CoreSecurity.h"
#include "../../imports/Defs.h"

extern "C" PPEB PsGetProcessPeb(PEPROCESS Process);


namespace dll_protection {


    static constexpr UINT32 MAX_PROTECT_SLOTS = 4;

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


    static UINT64 compute_code_hash_physical(UINT32 pid, UINT64 va, UINT32 size);
    static BOOLEAN check_peb_debugger_physical(UINT32 pid);

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

        UINT64 dtb = 0;
        for (int i = 0; i < DTB_CACHE_SIZE; i++) {
            if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
                dtb = g_dtb_cache[i].dtb;
                break;
            }
        }
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

            UINT64 phys = strong::translate_virtual_address(dtb, cursor);
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

        UINT64 dtb = 0;
        for (int i = 0; i < DTB_CACHE_SIZE; i++) {
            if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
                dtb = g_dtb_cache[i].dtb;
                break;
            }
        }
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
            UINT64 phys = strong::translate_virtual_address(dtb, va);
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
            volatile PVOID* debug_port = (volatile PVOID*)(eprocess + 0x578);
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
            volatile PVOID* instr_cb = (volatile PVOID*)(eprocess + 0x460);
            if (_MmIsAddressValid((PVOID)instr_cb)) {
                PVOID cb = *instr_cb;
                if (cb != nullptr) {
                    UINT64 cb_value = (UINT64)(ULONG_PTR)cb;
                    *out_cb = cb_value;
                    if (is_canonical_pointer(cb_value)) {
                        detected = TRUE;
                    } else {
                        UINT32 cb_tag = static_cast<UINT32>((cb_value >> 32) ^ cb_value ^ 0x0A1DA460u);
                        WW_LOG("[DLL-PROTECT] pid=%u instrumentation_noncanonical_ignored cb_tag=0x%08X",
                            pid, cb_tag);
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


    static void protection_timer_body()
    {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) != 1)
                continue;

            auto& slot = g_slots[i];


            if (check_peb_debugger_physical(slot.pid)) {
                slot.status = DPRT_STATUS_DEBUGGER;
                _InterlockedExchange(&slot.active, 0);


                KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                             (ULONG_PTR)slot.text_va, 0xDB6u, (ULONG_PTR)i);
                return;
            }


            UINT64 debug_port = 0;
            if (check_debug_port_eprocess(slot.pid, &debug_port)) {
                UINT32 port_tag = static_cast<UINT32>((debug_port >> 32) ^ debug_port ^ 0x0A1DADBAu);
                WW_LOG("[DLL-PROTECT] pid=%u debug_port_present tag=0x%08X", slot.pid, port_tag);
                sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
                sentinel_bridge::g_bridge.sentinel_cmd_param = port_tag;
            }


            {
                UINT32 bad_tid = 0;
                int dr_idx = -1;
                UINT64 dr_val = 0;
                if (scan_thread_drs(slot.pid, slot.text_va, slot.text_size,
                                    &bad_tid, &dr_idx, &dr_val)) {
                    slot.status = DPRT_STATUS_DEBUGGER;
                    _InterlockedExchange(&slot.active, 0);
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
                WW_LOG("[DLL-PROTECT] pid=%u check_foreign_instrumentation=%d cb_present=%u cb_tag=0x%08X",
                    slot.pid, has_instr ? 1 : 0, instr_cb != 0 ? 1u : 0u, instr_tag);
                if (has_instr) {
                    WW_LOG("[DLL-PROTECT] pid=%u FOREIGN_INSTR_CB triggering BRIDGE_CMD_DEBUGGER_FOUND cb_tag=0x%08X", slot.pid, instr_tag);
                    sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
                    sentinel_bridge::g_bridge.sentinel_cmd_param = (ULONG)(instr_cb & 0xFFFFFFFFu);
                }
            }


            UINT64 hash = compute_code_hash_physical(slot.pid, slot.text_va, slot.text_size);
            slot.last_check_tsc = __rdtsc();

            if (hash == 0) {

                slot.status = DPRT_STATUS_INACTIVE;
                _InterlockedExchange(&slot.active, 0);
                continue;
            }

            slot.current_hash = hash;

            if (hash != slot.expected_hash) {
                slot.status = DPRT_STATUS_TAMPERED;
                _InterlockedExchange(&slot.active, 0);

                KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                             (ULONG_PTR)slot.text_va,
                             (ULONG_PTR)(slot.expected_hash >> 32),
                             (ULONG_PTR)(hash >> 32));
                return;
            }

            slot.status = DPRT_STATUS_ACTIVE;
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

        __try {
            protection_timer_body();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("[DLL-PROTECT] protection work exception");
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

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + 0x448);
            PLIST_ENTRY entry = list_head->Flink;

            for (int iter = 0; iter < 2048 && entry != list_head; ++iter, entry = entry->Flink)
            {
                PEPROCESS scan_proc = (PEPROCESS)((UINT8*)entry - 0x448);
                if (!_MmIsAddressValid(scan_proc)) continue;
                if (scan_proc == target_proc) continue;

                HANDLE scan_pid = PsGetProcessId(scan_proc);
                if ((UINT64)(ULONG_PTR)scan_pid <= 4) continue;

                UINT8* eproc = (UINT8*)scan_proc;
                if (!_MmIsAddressValid(eproc + 0x570)) continue;

                volatile UINT64* object_table = (volatile UINT64*)(eproc + 0x570);
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
                request->text_section_size == 0 || request->expected_hash == 0)
                return STATUS_INVALID_PARAMETER;


            int idx = dll_protection::find_slot(request->pid, request->module_base);
            if (idx < 0)
                idx = dll_protection::find_free_slot();
            if (idx < 0)
                return STATUS_INSUFFICIENT_RESOURCES;

            auto& slot = dll_protection::g_slots[idx];
            slot.pid = request->pid;
            slot.module_base = request->module_base;
            slot.text_va = request->text_section_va;
            slot.text_size = request->text_section_size;
            slot.expected_hash = request->expected_hash;
            slot.current_hash = request->expected_hash;


            if (request->check_interval > 0 && request->check_interval <= 30000)
                slot.check_interval_ms = request->check_interval;
            else
                slot.check_interval_ms = 10000;
            slot.status = DPRT_STATUS_ACTIVE;
            slot.last_check_tsc = __rdtsc();

            _InterlockedExchange(&slot.active, 1);

            dll_protection::start_or_restart_timer();

            request->status = DPRT_STATUS_ACTIVE;
            request->current_hash = request->expected_hash;
            request->last_check_tsc = slot.last_check_tsc;
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
            return STATUS_SUCCESS;
        }

        case DPRT_OP_UNREGISTER:
        {


            if (request->pid != 0 && request->module_base != 0) {
                int idx = dll_protection::find_slot(request->pid, request->module_base);
                if (idx >= 0) {
                    _InterlockedExchange(&dll_protection::g_slots[idx].active, 0);
                    dll_protection::g_slots[idx].status = DPRT_STATUS_INACTIVE;
                    dll_protection::g_slots[idx].pid = 0;
                    dll_protection::g_slots[idx].module_base = 0;
                    dll_protection::g_slots[idx].text_va = 0;
                    dll_protection::g_slots[idx].text_size = 0;
                    dll_protection::g_slots[idx].expected_hash = 0;
                    dll_protection::g_slots[idx].current_hash = 0;
                }
            } else if (request->pid != 0) {
                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    if (_InterlockedCompareExchange(&dll_protection::g_slots[i].active, 1, 1) == 1 &&
                        dll_protection::g_slots[i].pid == request->pid) {
                        _InterlockedExchange(&dll_protection::g_slots[i].active, 0);
                        dll_protection::g_slots[i].status = DPRT_STATUS_INACTIVE;
                        dll_protection::g_slots[i].pid = 0;
                        dll_protection::g_slots[i].module_base = 0;
                        dll_protection::g_slots[i].text_va = 0;
                        dll_protection::g_slots[i].text_size = 0;
                        dll_protection::g_slots[i].expected_hash = 0;
                        dll_protection::g_slots[i].current_hash = 0;
                    }
                }
            } else {

                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    _InterlockedExchange(&dll_protection::g_slots[i].active, 0);
                    dll_protection::g_slots[i].status = DPRT_STATUS_INACTIVE;
                    dll_protection::g_slots[i].pid = 0;
                    dll_protection::g_slots[i].module_base = 0;
                    dll_protection::g_slots[i].text_va = 0;
                    dll_protection::g_slots[i].text_size = 0;
                    dll_protection::g_slots[i].expected_hash = 0;
                    dll_protection::g_slots[i].current_hash = 0;
                }
            }


            if (dll_protection::any_active())
                dll_protection::start_or_restart_timer();
            else
                dll_protection::stop_timer();

            request->status = DPRT_STATUS_INACTIVE;
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
