#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include <function/CoreSecurity.h>
#include <function/SentinelBridge.h>
#include <function/impl/driver/Strong.h>
#include <function/TargetingLatch.h>

namespace anti_dma_canary {

    constexpr ULONG POOL_TAG       = 'aCiA';
    constexpr ULONG MAX_CANARIES   = 32;
    constexpr ULONG SCAN_BATCH     = 512;
    constexpr ULONG PERSIST_STRIKE = 2;
    constexpr LONG64 PERIOD_MS     = 2000;

    struct canary_t {
        UINT64 va;
        UINT64 pa;
        UINT64 size;
        UINT32 owner_pid;
        UINT32 active;
    };

    inline canary_t       g_canaries[MAX_CANARIES] = {};
    inline volatile ULONG g_canary_count = 0;
    inline KSPIN_LOCK     g_canary_lock;
    inline volatile LONG  g_lock_init = 0;

    inline KTIMER         g_timer = {};
    inline KDPC           g_dpc = {};
    inline WORK_QUEUE_ITEM g_work = {};
    inline volatile LONG  g_running = 0;
    inline volatile LONG  g_work_queued = 0;
    inline volatile LONG  g_scan_cursor_pid = 4;
    inline volatile LONG  g_strike_pid = 0;
    inline volatile LONG  g_strike_count = 0;

    __forceinline void ensure_lock() {
        if (_InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) {
            KeInitializeSpinLock(&g_canary_lock);
        }
    }

    __forceinline UINT64 va_to_pa_for_pid(ULONG pid, UINT64 va) {
        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc)) || !proc) {
            return 0;
        }

        UINT64 dtb = 0;
        __try {
            dtb = *reinterpret_cast<UINT64*>(reinterpret_cast<UCHAR*>(proc) + 0x28);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            dtb = 0;
        }
        ObDereferenceObject(proc);
        if (!dtb) return 0;

        return strong::translate_virtual_address(dtb, va);
    }

    __forceinline BOOLEAN register_canary(UINT64 va, UINT64 size, ULONG owner_pid) {
        if (!va || !size || !owner_pid) return FALSE;
        ensure_lock();

        UINT64 pa = va_to_pa_for_pid(owner_pid, va);
        if (!pa) return FALSE;

        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);

        BOOLEAN ok = FALSE;
        for (ULONG i = 0; i < MAX_CANARIES; i++) {
            if (!g_canaries[i].active) {
                g_canaries[i].va        = va;
                g_canaries[i].pa        = pa & ~0xFFFULL;
                g_canaries[i].size      = size;
                g_canaries[i].owner_pid = owner_pid;
                g_canaries[i].active    = 1;
                if (i + 1 > g_canary_count) g_canary_count = i + 1;
                ok = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&g_canary_lock, old);
        return ok;
    }

    __forceinline BOOLEAN any_canary_matches_pa(UINT64 pa_page, UINT32* out_owner_pid,
                                                UINT64* out_va) {
        pa_page &= ~0xFFFULL;
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < g_canary_count && i < MAX_CANARIES; i++) {
            if (!g_canaries[i].active) continue;
            UINT64 start = g_canaries[i].pa;
            UINT64 end   = start + ((g_canaries[i].size + 0xFFF) & ~0xFFFULL);
            if (pa_page >= start && pa_page < end) {
                if (out_owner_pid) *out_owner_pid = g_canaries[i].owner_pid;
                if (out_va)        *out_va        = g_canaries[i].va;
                found = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        return found;
    }

    __forceinline BOOLEAN scan_one_process(ULONG pid, UINT32* out_canary_owner, UINT64* out_va) {
        if (pid == 0 || pid == 4) return FALSE;

        ULONG own_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));
        if (pid == own_pid) return FALSE;

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc)) || !proc) {
            return FALSE;
        }

        UINT64 dtb = 0;
        __try {
            dtb = *reinterpret_cast<UINT64*>(reinterpret_cast<UCHAR*>(proc) + 0x28);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            dtb = 0;
        }
        ObDereferenceObject(proc);
        if (!dtb) return FALSE;
        dtb &= 0x000FFFFFFFFFF000ULL;

        BOOLEAN hit = FALSE;

        for (ULONG pml4i = 0; pml4i < 256 && !hit; pml4i++) {
            UINT64 pml4e = 0;
            SIZE_T br = 0;
            if (!NT_SUCCESS(strong::read_physical(dtb + pml4i * 8, &pml4e, 8, &br)) || br != 8)
                continue;
            if (!(pml4e & 1)) continue;

            UINT64 pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;

            for (ULONG pdpti = 0; pdpti < 512 && !hit; pdpti++) {
                UINT64 pdpte = 0;
                if (!NT_SUCCESS(strong::read_physical(pdpt_pa + pdpti * 8, &pdpte, 8, &br)) || br != 8)
                    continue;
                if (!(pdpte & 1)) continue;

                if (pdpte & 0x80) {
                    UINT64 start_pa = pdpte & 0x000FFFFFC0000000ULL;
                    for (ULONG i = 0; i < MAX_CANARIES; i++) {
                        if (!g_canaries[i].active) continue;
                        UINT64 cp = g_canaries[i].pa;
                        if (cp >= start_pa && cp < start_pa + (1ULL << 30)) {
                            if (out_canary_owner) *out_canary_owner = g_canaries[i].owner_pid;
                            if (out_va)           *out_va           = g_canaries[i].va;
                            hit = TRUE;
                            break;
                        }
                    }
                    continue;
                }

                UINT64 pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
                for (ULONG pdi = 0; pdi < 512 && !hit; pdi++) {
                    UINT64 pde = 0;
                    if (!NT_SUCCESS(strong::read_physical(pd_pa + pdi * 8, &pde, 8, &br)) || br != 8)
                        continue;
                    if (!(pde & 1)) continue;

                    if (pde & 0x80) {
                        UINT64 start_pa = pde & 0x000FFFFFFFE00000ULL;
                        for (ULONG i = 0; i < MAX_CANARIES; i++) {
                            if (!g_canaries[i].active) continue;
                            UINT64 cp = g_canaries[i].pa;
                            if (cp >= start_pa && cp < start_pa + (2ULL * 1024 * 1024)) {
                                if (out_canary_owner) *out_canary_owner = g_canaries[i].owner_pid;
                                if (out_va)           *out_va           = g_canaries[i].va;
                                hit = TRUE;
                                break;
                            }
                        }
                        continue;
                    }

                    UINT64 pt_pa = pde & 0x000FFFFFFFFFF000ULL;
                    for (ULONG pti = 0; pti < 512 && !hit; pti++) {
                        UINT64 pte = 0;
                        if (!NT_SUCCESS(strong::read_physical(pt_pa + pti * 8, &pte, 8, &br)) || br != 8)
                            continue;
                        if (!(pte & 1)) continue;
                        UINT64 phys = pte & 0x000FFFFFFFFFF000ULL;
                        UINT32 owner = 0;
                        UINT64 va    = 0;
                        if (any_canary_matches_pa(phys, &owner, &va)) {
                            if (out_canary_owner) *out_canary_owner = owner;
                            if (out_va)           *out_va           = va;
                            hit = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        return hit;
    }

    __forceinline void do_scan_batch() {
        if (!caller_validation::g_registered_client_pid) return;
        if (g_canary_count == 0) return;

        ULONG pid_start = static_cast<ULONG>(
            _InterlockedCompareExchange(&g_scan_cursor_pid, 0, 0));
        if (pid_start < 4) pid_start = 4;

        ULONG own_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));

        ULONG scanned = 0;
        ULONG pid = pid_start;
        UINT32 hit_owner = 0;
        UINT64 hit_va    = 0;
        ULONG  hit_pid   = 0;

        while (scanned < SCAN_BATCH) {
            if (pid != own_pid && pid != 0 && pid != 4) {
                if (scan_one_process(pid, &hit_owner, &hit_va)) {
                    hit_pid = pid;
                    break;
                }
            }
            pid += 4;
            if (pid > 0x20000) pid = 4;
            scanned++;
        }

        _InterlockedExchange(&g_scan_cursor_pid, static_cast<LONG>(pid + 4));

        if (hit_pid != 0) {
            LONG prev_pid = _InterlockedExchange(&g_strike_pid, static_cast<LONG>(hit_pid));
            LONG strikes  = (prev_pid == static_cast<LONG>(hit_pid))
                            ? _InterlockedIncrement(&g_strike_count)
                            : (_InterlockedExchange(&g_strike_count, 1), 1);

            sentinel_bridge::populate_evidence_blob(
                0x40u,
                sentinel_bridge::RE_REASON_DMA_CANARY,
                95,
                hit_pid,
                hit_va,
                0,
                static_cast<UINT64>(hit_owner));

            ULONG cmd   = sentinel_bridge::BRIDGE_CMD_CANARY_FOREIGN_PT;
            ULONG param = hit_pid;
            sentinel_bridge::bridge_encrypt_cmd(cmd, param);
            _InterlockedExchange(
                reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                static_cast<LONG>(cmd));
            _InterlockedExchange(
                reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                static_cast<LONG>(param));

            if (strikes >= PERSIST_STRIKE) {
                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_DMA_CANARY,
                    hit_va,
                    static_cast<UINT64>(hit_pid),
                    static_cast<UINT64>(hit_owner),
                    0
                );
            }
        } else {
            _InterlockedExchange(&g_strike_count, 0);
            _InterlockedExchange(&g_strike_pid, 0);
        }
    }

    static VOID NTAPI work_routine(PVOID) {
        __try {
            do_scan_batch();
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        _InterlockedExchange(&g_work_queued, 0);
    }

    static VOID NTAPI dpc_routine(_KDPC*, PVOID, PVOID, PVOID) {
        WW_LOG("dma_canary::dpc_routine: ENTRY running=%ld", g_running);
        if (!_InterlockedCompareExchange(&g_running, 0, 0)) return;
        if (_InterlockedCompareExchange(&g_work_queued, 1, 0) != 0) return;
        ExInitializeWorkItem(&g_work, work_routine, nullptr);
        ExQueueWorkItem(&g_work, DelayedWorkQueue);
    }

    __forceinline VOID init_timer() {
        WW_LOG("dma_canary::init_timer: ENTRY");
        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) return;
        ensure_lock();
        KeInitializeTimerEx(&g_timer, SynchronizationTimer);
        KeInitializeDpc(&g_dpc, dpc_routine, nullptr);
        LARGE_INTEGER due;
        due.QuadPart = -10000000LL;
        KeSetTimerEx(&g_timer, due, static_cast<LONG>(PERIOD_MS), &g_dpc);
        WW_LOG("dma_canary::init_timer: timer armed, period=%lldms", PERIOD_MS);
    }

    __forceinline VOID stop_timer() {
        if (_InterlockedCompareExchange(&g_running, 0, 1) != 1) return;
        KeCancelTimer(&g_timer);
        KeFlushQueuedDpcs();
    }

    __forceinline BOOLEAN query_tier_a_preloaded() {
        return sentinel_bridge::g_bridge.sentinel_cmd == sentinel_bridge::BRIDGE_CMD_TIER_A_PRE_LOADED ||
               sentinel_bridge::g_bridge.sentinel_cmd ==
                   (sentinel_bridge::BRIDGE_CMD_TIER_A_PRE_LOADED ^
                    static_cast<ULONG>(sentinel_bridge::g_bridge_crypt_key & 0xFFFFFFFF));
    }
}
