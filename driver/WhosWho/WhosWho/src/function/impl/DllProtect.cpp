#include <ntifs.h>
#include <intrin.h>
#include "../Struct.h"
#include "../Functions.h"
#include "../CoreSecurity.h"
#include "../../imports/Defs.h"

// WHY: PsGetProcessPeb is an undocumented ntoskrnl.exe export. Older WDK
// toolsets do not prototype it in <ntifs.h>, so we declare it explicitly.
// The function has been stable and exported since Windows XP.
extern "C" PPEB PsGetProcessPeb(PEPROCESS Process);

// ──────────────────────────────────────────────────────────────────────────
// Module Protection — kernel-resident integrity monitor for AiDA modules
//
// WHY this exists:
//   Every prior crack followed the same pattern:
//     1. Patch out integrity checks in .text
//     2. NOP the BSOD enforcement
//     3. Bypass the license watchdog
//   All of those patches happen in user-mode, meaning a reverse engineer
//   only needs to modify memory in their own process. The user-mode code
//   *cannot protect itself* because it can always be patched before it runs.
//
//   By moving the hash verification and BSOD trigger into the kernel driver,
//   the attacker must *also* patch the driver — which requires loading their
//   own kernel code, bypassing PatchGuard, or disabling DSE. This raises the
//   bar from "five minutes in x64dbg" to a full kernel exploit.
//
// WHY multi-slot:
//   AiDA ships as both a DLL plugin (loaded in IDA) and a standalone EXE.
//   Both can run on the same machine simultaneously and both need kernel-
//   side integrity monitoring. The old single-slot design forced a choice:
//   protect the DLL *or* the EXE. With multiple slots, every registered
//   module is verified independently by the same DPC timer.
//
// HOW it works:
//   1. User-mode registers a module's .text section (PID + base VA + size + hash).
//   2. A single kernel DPC timer fires periodically and iterates all active
//      protection slots, reading each section via the process' DTB (physical
//      page walk) and computing a CRC hash.
//   3. If any hash mismatches the registered value → immediate bugcheck.
//   4. The timer also checks for debugger attachment via PEB.BeingDebugged
//      and NtGlobalFlag, read through physical memory (immune to PEB spoofs
//      done via NtSetInformationProcess in the target process).
// ──────────────────────────────────────────────────────────────────────────

namespace dll_protection {

    // Up to 4 independent protection slots — one for AiDA.dll and standalone
    // EXE, with two spare for future modules (e.g. helper DLLs).
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

    // Forward declarations
    static UINT64 compute_code_hash_physical(UINT32 pid, UINT64 va, UINT32 size);
    static BOOLEAN check_peb_debugger_physical(UINT32 pid);

    // ── Hash computation via physical memory read ──
    // WHY physical: Reading through the process VA via MmCopyVirtualMemory can
    // be intercepted/redirected by user-mode hooks. Physical reads bypass
    // any usermode shenanigans.

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

        // Look up DTB from cache (same mechanism used by existing read_raw)
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

            // Translate virtual to physical via 4-level page walk
            UINT64 phys = 0;
            {
                UINT64 pml4e_addr = (dtb & ~0xFFFULL) | (((cursor >> 39) & 0x1FF) << 3);
                UINT64 pml4e = 0;
                PHYSICAL_ADDRESS pa;
                pa.QuadPart = (LONGLONG)pml4e_addr;
                PVOID mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                if (!mapped) return 0;
                pml4e = *(volatile UINT64*)mapped;
                MmUnmapIoSpace(mapped, sizeof(UINT64));
                if (!(pml4e & 1)) return 0;

                UINT64 pdpte_addr = (pml4e & ~0xFFFULL) | (((cursor >> 30) & 0x1FF) << 3);
                pa.QuadPart = (LONGLONG)pdpte_addr;
                mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                if (!mapped) return 0;
                UINT64 pdpte = *(volatile UINT64*)mapped;
                MmUnmapIoSpace(mapped, sizeof(UINT64));
                if (!(pdpte & 1)) return 0;
                if (pdpte & 0x80) { // 1GB page
                    phys = (pdpte & 0xFFFFFFC0000000ULL) | (cursor & 0x3FFFFFFFULL);
                } else {
                    UINT64 pde_addr = (pdpte & ~0xFFFULL) | (((cursor >> 21) & 0x1FF) << 3);
                    pa.QuadPart = (LONGLONG)pde_addr;
                    mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                    if (!mapped) return 0;
                    UINT64 pde = *(volatile UINT64*)mapped;
                    MmUnmapIoSpace(mapped, sizeof(UINT64));
                    if (!(pde & 1)) return 0;
                    if (pde & 0x80) { // 2MB page
                        phys = (pde & 0xFFFFFFFE00000ULL) | (cursor & 0x1FFFFFULL);
                    } else {
                        UINT64 pte_addr = (pde & ~0xFFFULL) | (((cursor >> 12) & 0x1FF) << 3);
                        pa.QuadPart = (LONGLONG)pte_addr;
                        mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                        if (!mapped) return 0;
                        UINT64 pte = *(volatile UINT64*)mapped;
                        MmUnmapIoSpace(mapped, sizeof(UINT64));
                        if (!(pte & 1)) return 0;
                        phys = (pte & ~0xFFFULL) | (cursor & 0xFFFULL);
                    }
                }
            }

            // Read the physical page
            PHYSICAL_ADDRESS read_pa;
            read_pa.QuadPart = (LONGLONG)phys;
            PVOID mapped = MmMapIoSpace(read_pa, to_read, MmNonCached);
            if (!mapped)
                return 0;
            RtlCopyMemory(page_buf, mapped, to_read);
            MmUnmapIoSpace(mapped, to_read);

            // Accumulate hash
            for (UINT32 i = 0; i < to_read; i++) {
                h1 = _mm_crc32_u8((UINT32)h1, page_buf[i]);
                h2 = _mm_crc32_u8((UINT32)h2, page_buf[i] ^ 0xA5u);
            }

            cursor += to_read;
            remaining -= to_read;
        }

        return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
    }

    // ── Debugger check via physical PEB read ──
    // WHY: User-mode anti-debug can be spoofed by NtSetInformationProcess.
    // Reading the PEB through physical memory bypasses that entirely.
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

        // PEB is at gs:[0x60] on x64 — we need the process' PEB address.
        // We'll use the EPROCESS to get PEB address via kernel APIs.
        PEPROCESS process = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &process);
        if (!NT_SUCCESS(st) || !process)
            return FALSE;

        UINT64 peb_addr = (UINT64)PsGetProcessPeb(process);
        ObDereferenceObject(process);

        if (peb_addr == 0)
            return FALSE;

        // Read BeingDebugged byte (offset 0x02) and NtGlobalFlag (offset 0xBC)
        // via physical memory
        UINT8 being_debugged = 0;
        UINT32 nt_global_flag = 0;

        // Translate PEB + 0x02
        auto read_byte_physical = [&](UINT64 va) -> UINT8 {
            UINT64 phys = 0;
            UINT64 pml4e_addr = (dtb & ~0xFFFULL) | (((va >> 39) & 0x1FF) << 3);
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = (LONGLONG)pml4e_addr;
            PVOID mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
            if (!mapped) return 0;
            UINT64 pml4e = *(volatile UINT64*)mapped;
            MmUnmapIoSpace(mapped, sizeof(UINT64));
            if (!(pml4e & 1)) return 0;

            UINT64 pdpte_addr = (pml4e & ~0xFFFULL) | (((va >> 30) & 0x1FF) << 3);
            pa.QuadPart = (LONGLONG)pdpte_addr;
            mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
            if (!mapped) return 0;
            UINT64 pdpte = *(volatile UINT64*)mapped;
            MmUnmapIoSpace(mapped, sizeof(UINT64));
            if (!(pdpte & 1)) return 0;
            if (pdpte & 0x80) {
                phys = (pdpte & 0xFFFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
            } else {
                UINT64 pde_addr = (pdpte & ~0xFFFULL) | (((va >> 21) & 0x1FF) << 3);
                pa.QuadPart = (LONGLONG)pde_addr;
                mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                if (!mapped) return 0;
                UINT64 pde = *(volatile UINT64*)mapped;
                MmUnmapIoSpace(mapped, sizeof(UINT64));
                if (!(pde & 1)) return 0;
                if (pde & 0x80) {
                    phys = (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
                } else {
                    UINT64 pte_addr = (pde & ~0xFFFULL) | (((va >> 12) & 0x1FF) << 3);
                    pa.QuadPart = (LONGLONG)pte_addr;
                    mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
                    if (!mapped) return 0;
                    UINT64 pte = *(volatile UINT64*)mapped;
                    MmUnmapIoSpace(mapped, sizeof(UINT64));
                    if (!(pte & 1)) return 0;
                    phys = (pte & ~0xFFFULL) | (va & 0xFFFULL);
                }
            }

            pa.QuadPart = (LONGLONG)phys;
            mapped = MmMapIoSpace(pa, 1, MmNonCached);
            if (!mapped) return 0;
            UINT8 val = *(volatile UINT8*)mapped;
            MmUnmapIoSpace(mapped, 1);
            return val;
        };

        being_debugged = read_byte_physical(peb_addr + 0x02);

        // NtGlobalFlag at PEB + 0xBC (4 bytes), read byte by byte
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

    // ── Slot lookup helpers ──

    // Find slot matching pid + module_base (exact match for REGISTER updates).
    static int find_slot(UINT32 pid, UINT64 module_base) {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                g_slots[i].pid == pid &&
                g_slots[i].module_base == module_base)
                return i;
        }
        return -1;
    }

    // Find first slot matching pid (for QUERY/UNREGISTER when module_base is 0).
    static int find_slot_by_pid(UINT32 pid) {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1 &&
                g_slots[i].pid == pid)
                return i;
        }
        return -1;
    }

    // Find first free (inactive) slot.
    static int find_free_slot() {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 0, 0) == 0)
                return i;
        }
        return -1;
    }

    // Returns TRUE if any slot is active.
    static BOOLEAN any_active() {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) == 1)
                return TRUE;
        }
        return FALSE;
    }

    // Compute the minimum check interval across all active slots.
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

    // ── Timer management ──
    // A single DPC timer covers all slots. Its period is the minimum
    // check_interval across all active entries, so every slot is verified
    // at least as frequently as it requested.

    static void stop_timer() {
        if (_InterlockedCompareExchange(&g_timer_running, 0, 1) == 1)
            KeCancelTimer(&g_timer);
    }

    static void start_or_restart_timer();

    // ── DPC timer callback ──
    // Runs at DISPATCH_LEVEL periodically to verify ALL active module slots.
    // On any mismatch or debugger detection → KeBugCheckEx (0xDEAD0ADA).
    static VOID NTAPI protection_timer_dpc(
        PKDPC /*Dpc*/, PVOID /*DeferredContext*/,
        PVOID /*SystemArgument1*/, PVOID /*SystemArgument2*/)
    {
        for (int i = 0; i < (int)MAX_PROTECT_SLOTS; i++) {
            if (_InterlockedCompareExchange(&g_slots[i].active, 1, 1) != 1)
                continue;

            auto& slot = g_slots[i];

            // Check for debugger via physical PEB
            if (check_peb_debugger_physical(slot.pid)) {
                slot.status = DPRT_STATUS_DEBUGGER;
                _InterlockedExchange(&slot.active, 0);
                // 0xDEAD0ADA = "DEAD AiDA" — custom bugcheck code
                // Param4 = slot index so post-mortem analysis knows which slot triggered
                KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                             (ULONG_PTR)slot.text_va, 0xDB6u, (ULONG_PTR)i);
                return; // never reached
            }

            // Compute current hash of the .text section
            UINT64 hash = compute_code_hash_physical(slot.pid, slot.text_va, slot.text_size);
            slot.last_check_tsc = __rdtsc();

            if (hash == 0) {
                // Process may have exited — deactivate this slot silently
                slot.status = DPRT_STATUS_INACTIVE;
                _InterlockedExchange(&slot.active, 0);
                continue;
            }

            slot.current_hash = hash;

            if (hash != slot.expected_hash) {
                slot.status = DPRT_STATUS_TAMPERED;
                _InterlockedExchange(&slot.active, 0);
                // Immediate BSOD — code was modified
                KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)slot.pid,
                             (ULONG_PTR)slot.text_va,
                             (ULONG_PTR)(slot.expected_hash >> 32),
                             (ULONG_PTR)(hash >> 32));
                return; // never reached
            }

            slot.status = DPRT_STATUS_ACTIVE;
        }

        // If every slot was deactivated (all processes exited), stop the timer
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
        due_time.QuadPart = -((LONGLONG)min_iv * 10000LL); // relative time in 100ns units
        KeSetTimerEx(&g_timer, due_time, (LONG)min_iv, &g_timer_dpc);
        _InterlockedExchange(&g_timer_running, 1);
    }

} // namespace dll_protection


// ── IOCTL handler ──
// Supports multiple simultaneous protection registrations identified by
// (pid, module_base). This lets the DLL and standalone EXE each register
// their own .text section independently.
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

            // Try to find an existing slot for this (pid, module_base) pair,
            // otherwise allocate a free one.
            int idx = dll_protection::find_slot(request->pid, request->module_base);
            if (idx < 0)
                idx = dll_protection::find_free_slot();
            if (idx < 0)
                return STATUS_INSUFFICIENT_RESOURCES; // all slots occupied

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
            // Find the slot to query:
            //  - If pid and module_base are both set → exact match
            //  - If only pid is set → first slot for that pid
            //  - If pid is 0 → first active slot (backward compat)
            int idx = -1;
            if (request->pid != 0 && request->module_base != 0)
                idx = dll_protection::find_slot(request->pid, request->module_base);
            else if (request->pid != 0)
                idx = dll_protection::find_slot_by_pid(request->pid);
            else {
                // Legacy: return the first active slot
                for (int i = 0; i < (int)dll_protection::MAX_PROTECT_SLOTS; i++) {
                    if (_InterlockedCompareExchange(&dll_protection::g_slots[i].active, 1, 1) == 1) {
                        idx = i;
                        break;
                    }
                }
            }

            if (idx < 0) {
                // No matching slot found — return inactive status
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
            // Find slot(s) to unregister:
            //  - If pid and module_base are both set → unregister exact slot
            //  - If only pid is set → unregister all slots for that pid
            //  - If pid is 0 → unregister all slots (backward compat)
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
                // Legacy: unregister everything
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

            // Stop or restart timer depending on remaining active slots
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
