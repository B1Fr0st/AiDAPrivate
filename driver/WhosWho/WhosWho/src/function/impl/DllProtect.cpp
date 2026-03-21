#include <ntifs.h>
#include <intrin.h>
#include "../Struct.h"
#include "../Functions.h"
#include "../CoreSecurity.h"
#include "../../imports/Defs.h"

// ──────────────────────────────────────────────────────────────────────────
// DLL Protection — kernel-resident integrity monitor for AiDA.dll
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
// HOW it works:
//   1. User-mode registers the DLL's .text section (base VA + size + hash).
//   2. A kernel DPC timer fires every N ms and reads the section via the
//      process' DTB (physical page walk), computing a CRC hash.
//   3. If the hash mismatches the registered value → immediate bugcheck.
//   4. The timer also checks for debugger attachment via PEB.BeingDebugged
//      and NtGlobalFlag, read through physical memory (immune to PEB spoofs
//      done via NtSetInformationProcess in the target process).
// ──────────────────────────────────────────────────────────────────────────

namespace dll_protection {

    // Protection state — one slot (we only need to protect one DLL per session)
    static volatile LONG g_active = 0;
    static UINT32 g_pid = 0;
    static UINT64 g_module_base = 0;
    static UINT64 g_text_va = 0;
    static UINT32 g_text_size = 0;
    static UINT64 g_expected_hash = 0;
    static UINT64 g_current_hash = 0;
    static UINT32 g_status = DPRT_STATUS_INACTIVE;
    static UINT32 g_check_interval_ms = 2000;
    static UINT64 g_last_check_tsc = 0;
    static KDPC   g_timer_dpc;
    static KTIMER g_timer;
    static volatile LONG g_timer_initialized = 0;

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
                SIZE_T r = 0;
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

    // ── DPC timer callback ──
    // Runs at DISPATCH_LEVEL periodically to verify DLL integrity.
    // On any mismatch → KeBugCheckEx (0xDEAD0ADA = "DEAD AiDA").
    static VOID NTAPI protection_timer_dpc(
        PKDPC /*Dpc*/, PVOID /*DeferredContext*/,
        PVOID /*SystemArgument1*/, PVOID /*SystemArgument2*/)
    {
        if (_InterlockedCompareExchange(&g_active, 1, 1) != 1)
            return;

        // Check for debugger via physical PEB
        if (check_peb_debugger_physical(g_pid)) {
            g_status = DPRT_STATUS_DEBUGGER;
            _InterlockedExchange(&g_active, 0);
            // 0xDEAD0ADA = "DEAD AiDA" — custom bugcheck code
            KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)g_pid,
                         (ULONG_PTR)g_text_va, 0xDB6u, 0);
            return; // never reached
        }

        // Compute current hash of the .text section
        UINT64 hash = compute_code_hash_physical(g_pid, g_text_va, g_text_size);
        g_last_check_tsc = __rdtsc();

        if (hash == 0) {
            // Process may have exited — deactivate silently
            g_status = DPRT_STATUS_INACTIVE;
            _InterlockedExchange(&g_active, 0);
            return;
        }

        g_current_hash = hash;

        if (hash != g_expected_hash) {
            g_status = DPRT_STATUS_TAMPERED;
            _InterlockedExchange(&g_active, 0);
            // Immediate BSOD — code was modified
            KeBugCheckEx(0xDEAD0ADAu, (ULONG_PTR)g_pid,
                         (ULONG_PTR)g_text_va,
                         (ULONG_PTR)(g_expected_hash >> 32),
                         (ULONG_PTR)(hash >> 32));
            return; // never reached
        }

        g_status = DPRT_STATUS_ACTIVE;
    }

    static void start_timer() {
        if (_InterlockedCompareExchange(&g_timer_initialized, 1, 0) == 0) {
            KeInitializeTimer(&g_timer);
            KeInitializeDpc(&g_timer_dpc, protection_timer_dpc, nullptr);
        }

        LARGE_INTEGER due_time;
        due_time.QuadPart = -((LONGLONG)g_check_interval_ms * 10000LL); // relative time in 100ns units
        KeSetTimerEx(&g_timer, due_time,
                     (LONG)g_check_interval_ms, &g_timer_dpc);
    }

    static void stop_timer() {
        if (g_timer_initialized)
            KeCancelTimer(&g_timer);
    }

} // namespace dll_protection


// ── IOCTL handler ──
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

            // Only allow one registration at a time
            if (_InterlockedCompareExchange(&dll_protection::g_active, 0, 0) == 1) {
                // Already active — update if same PID, reject otherwise
                if (dll_protection::g_pid != request->pid)
                    return STATUS_DEVICE_BUSY;
            }

            dll_protection::g_pid = request->pid;
            dll_protection::g_module_base = request->module_base;
            dll_protection::g_text_va = request->text_section_va;
            dll_protection::g_text_size = request->text_section_size;
            dll_protection::g_expected_hash = request->expected_hash;
            dll_protection::g_current_hash = request->expected_hash;
            dll_protection::g_check_interval_ms =
                (request->check_interval > 0 && request->check_interval <= 30000)
                    ? request->check_interval : 2000;
            dll_protection::g_status = DPRT_STATUS_ACTIVE;
            dll_protection::g_last_check_tsc = __rdtsc();

            _InterlockedExchange(&dll_protection::g_active, 1);

            dll_protection::start_timer();

            request->status = DPRT_STATUS_ACTIVE;
            request->current_hash = request->expected_hash;
            request->last_check_tsc = dll_protection::g_last_check_tsc;
            return STATUS_SUCCESS;
        }

        case DPRT_OP_QUERY:
        {
            request->pid = dll_protection::g_pid;
            request->module_base = dll_protection::g_module_base;
            request->text_section_va = dll_protection::g_text_va;
            request->text_section_size = dll_protection::g_text_size;
            request->expected_hash = dll_protection::g_expected_hash;
            request->current_hash = dll_protection::g_current_hash;
            request->status = dll_protection::g_status;
            request->check_interval = dll_protection::g_check_interval_ms;
            request->last_check_tsc = dll_protection::g_last_check_tsc;
            return STATUS_SUCCESS;
        }

        case DPRT_OP_UNREGISTER:
        {
            dll_protection::stop_timer();
            _InterlockedExchange(&dll_protection::g_active, 0);
            dll_protection::g_status = DPRT_STATUS_INACTIVE;
            dll_protection::g_pid = 0;
            dll_protection::g_text_va = 0;
            dll_protection::g_text_size = 0;
            dll_protection::g_expected_hash = 0;
            dll_protection::g_current_hash = 0;
            dll_protection::g_module_base = 0;

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
