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
    static volatile LONG g_timer_initialized = 0;
    static volatile LONG g_timer_running = 0;


    static UINT64 compute_code_hash_physical(UINT32 pid, UINT64 va, UINT32 size);
    static BOOLEAN check_peb_debugger_physical(UINT32 pid);


    __forceinline UINT64 crc_combine(UINT64 h1, UINT64 h2, const UINT8* data, SIZE_T len) {
        for (SIZE_T i = 0; i < len; ++i) {
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

            for (UINT32 i = 0; i < to_read; i++) {
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
    }

    static void start_or_restart_timer();


    static VOID NTAPI protection_timer_dpc(
        PKDPC , PVOID ,
        PVOID , PVOID )
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


        if (!any_active())
            stop_timer();
    }

    static void start_or_restart_timer() {
        UINT32 min_iv = compute_min_interval();
        if (min_iv == 0) {
            stop_timer();
            return;
        }

        if (_InterlockedCompareExchange(&g_timer_initialized, 1, 0) == 0) {
            KeInitializeTimer(&g_timer);
            KeInitializeDpc(&g_timer_dpc, protection_timer_dpc, nullptr);
        }

        LARGE_INTEGER due_time;
        due_time.QuadPart = -((LONGLONG)min_iv * 10000LL);
        KeSetTimerEx(&g_timer, due_time, (LONG)min_iv, &g_timer_dpc);
        _InterlockedExchange(&g_timer_running, 1);
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
            slot.check_interval_ms =
                (request->check_interval > 0 && request->check_interval <= 30000)
                    ? request->check_interval : 2000;
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
