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
    constexpr ULONG PROCESS_NAME_CHARS = 15;

    struct canary_t {
        UINT64 va;
        UINT64 pa;
        UINT64 size;
        UINT32 owner_pid;
        UINT32 active;
    };

    struct scan_hit_t {
        UINT32 owner_pid;
        UINT32 target_pid;
        UINT64 owner_va;
        UINT64 canary_pa;
        UINT64 mapped_pa;
        UINT64 dtb;
        UINT64 entry_value;
        ULONG pml4_index;
        ULONG pdpt_index;
        ULONG pd_index;
        ULONG pt_index;
        ULONG page_size;
        char target_name[16];
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
    inline volatile LONG64 g_scan_batch_id = 0;

    __forceinline void capture_process_name(PEPROCESS proc, scan_hit_t* out_hit) {
        if (!out_hit) return;
        RtlZeroMemory(out_hit->target_name, sizeof(out_hit->target_name));
        if (!proc) return;

        __try {
            UCHAR* image_name = PsGetProcessImageFileName(proc);
            if (image_name) {
                for (ULONG name_index = 0; name_index < PROCESS_NAME_CHARS; name_index++) {
                    char name_char = static_cast<char>(image_name[name_index]);
                    out_hit->target_name[name_index] = name_char;
                    if (name_char == 0)
                        break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out_hit->target_name[0] = 0;
        }

        if (out_hit->target_name[0] == 0) {
            out_hit->target_name[0] = '?';
            out_hit->target_name[1] = 0;
        }
    }

    __forceinline void fill_scan_hit(scan_hit_t* out_hit,
                                     ULONG target_pid,
                                     PEPROCESS proc,
                                     UINT32 owner_pid,
                                     UINT64 owner_va,
                                     UINT64 canary_pa,
                                     UINT64 mapped_pa,
                                     UINT64 dtb,
                                     UINT64 entry_value,
                                     ULONG pml4_index,
                                     ULONG pdpt_index,
                                     ULONG pd_index,
                                     ULONG pt_index,
                                     ULONG page_size) {
        if (!out_hit) return;
        RtlZeroMemory(out_hit, sizeof(*out_hit));
        out_hit->owner_pid = owner_pid;
        out_hit->target_pid = target_pid;
        out_hit->owner_va = owner_va;
        out_hit->canary_pa = canary_pa;
        out_hit->mapped_pa = mapped_pa;
        out_hit->dtb = dtb;
        out_hit->entry_value = entry_value;
        out_hit->pml4_index = pml4_index;
        out_hit->pdpt_index = pdpt_index;
        out_hit->pd_index = pd_index;
        out_hit->pt_index = pt_index;
        out_hit->page_size = page_size;
        capture_process_name(proc, out_hit);
    }

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
        if (!va || !size || !owner_pid) {
            WW_LOG("dma_canary::register_reject invalid_input va=0x%llx size=0x%llx owner=%lu",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                owner_pid);
            return FALSE;
        }
        if (size > 0x1000ULL) {
            WW_LOG("dma_canary::register_reject size_too_large va=0x%llx size=0x%llx owner=%lu",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                owner_pid);
            return FALSE;
        }
        UINT64 page_offset = va & 0xFFFULL;
        if (page_offset > 0x1000ULL - size) {
            WW_LOG("dma_canary::register_reject crosses_page va=0x%llx size=0x%llx offset=0x%llx owner=%lu",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(page_offset),
                owner_pid);
            return FALSE;
        }
        ensure_lock();

        UINT64 pa = va_to_pa_for_pid(owner_pid, va);
        if (!pa) {
            WW_LOG("dma_canary::register_reject translate_failed va=0x%llx size=0x%llx owner=%lu",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                owner_pid);
            return FALSE;
        }

        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);

        BOOLEAN ok = FALSE;
        ULONG slot = MAX_CANARIES;
        for (ULONG i = 0; i < MAX_CANARIES; i++) {
            if (!g_canaries[i].active) {
                g_canaries[i].va        = va;
                g_canaries[i].pa        = pa & ~0xFFFULL;
                g_canaries[i].size      = 0x1000ULL;
                g_canaries[i].owner_pid = owner_pid;
                g_canaries[i].active    = 1;
                if (i + 1 > g_canary_count) g_canary_count = i + 1;
                slot = i;
                ok = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&g_canary_lock, old);

        if (ok) {
            WW_LOG("dma_canary::register_ok slot=%lu owner=%lu va=0x%llx size=0x%llx pa=0x%llx page_pa=0x%llx count=%lu",
                slot,
                owner_pid,
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(pa),
                static_cast<unsigned long long>(pa & ~0xFFFULL),
                g_canary_count);
        } else {
            WW_LOG("dma_canary::register_reject no_slots owner=%lu va=0x%llx size=0x%llx pa=0x%llx count=%lu",
                owner_pid,
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(pa),
                g_canary_count);
        }
        return ok;
    }

    __forceinline BOOLEAN any_canary_matches_pa(UINT64 pa_page, UINT32* out_owner_pid,
                                                UINT64* out_va, UINT64* out_canary_pa) {
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
                if (out_canary_pa) *out_canary_pa = g_canaries[i].pa;
                found = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        return found;
    }

    __forceinline BOOLEAN scan_one_process(ULONG pid, scan_hit_t* out_hit) {
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
        if (!dtb) {
            ObDereferenceObject(proc);
            return FALSE;
        }
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
                            fill_scan_hit(out_hit, pid, proc, g_canaries[i].owner_pid,
                                g_canaries[i].va, cp, start_pa, dtb, pdpte,
                                pml4i, pdpti, 0xFFFFFFFFul, 0xFFFFFFFFul,
                                static_cast<ULONG>(1ULL << 30));
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
                                fill_scan_hit(out_hit, pid, proc, g_canaries[i].owner_pid,
                                    g_canaries[i].va, cp, start_pa, dtb, pde,
                                    pml4i, pdpti, pdi, 0xFFFFFFFFul,
                                    static_cast<ULONG>(2ULL * 1024 * 1024));
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
                        UINT64 canary_pa = 0;
                        if (any_canary_matches_pa(phys, &owner, &va, &canary_pa)) {
                            fill_scan_hit(out_hit, pid, proc, owner, va, canary_pa,
                                phys, dtb, pte, pml4i, pdpti, pdi, pti, 0x1000ul);
                            hit = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        ObDereferenceObject(proc);
        return hit;
    }

    __forceinline void do_scan_batch() {
        if (!caller_validation::g_registered_client_pid) return;
        if (g_canary_count == 0) return;

        LONG64 batch_id = _InterlockedIncrement64(&g_scan_batch_id);

        ULONG own_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));

        ULONG  hit_pid   = 0;
        scan_hit_t hit_info = {};

        LONG pending_strike_pid = _InterlockedCompareExchange(&g_strike_pid, 0, 0);
        LONG pending_strike_count = _InterlockedCompareExchange(&g_strike_count, 0, 0);
        LONG cursor_snapshot = _InterlockedCompareExchange(&g_scan_cursor_pid, 0, 0);
        WW_LOG("dma_canary::batch_start id=%lld own=%lu canaries=%lu cursor=%ld pending_pid=%ld pending_strikes=%ld bridge_raw=0x%lx",
            batch_id,
            own_pid,
            g_canary_count,
            cursor_snapshot,
            pending_strike_pid,
            pending_strike_count,
            sentinel_bridge::g_bridge.sentinel_cmd);

        if (pending_strike_pid > 4 &&
            static_cast<ULONG>(pending_strike_pid) != own_pid) {
            scan_hit_t confirm_info = {};
            if (scan_one_process(static_cast<ULONG>(pending_strike_pid), &confirm_info)) {
                hit_pid   = static_cast<ULONG>(pending_strike_pid);
                hit_info  = confirm_info;
                WW_LOG("dma_canary::pending_confirmed id=%lld pid=%lu name=%.15s owner=%u va=0x%llx canary_pa=0x%llx mapped_pa=0x%llx page=0x%lx",
                    batch_id,
                    hit_pid,
                    hit_info.target_name,
                    hit_info.owner_pid,
                    static_cast<unsigned long long>(hit_info.owner_va),
                    static_cast<unsigned long long>(hit_info.canary_pa),
                    static_cast<unsigned long long>(hit_info.mapped_pa),
                    hit_info.page_size);
            } else {
                _InterlockedExchange(&g_strike_pid, 0);
                _InterlockedExchange(&g_strike_count, 0);
                WW_LOG("dma_canary::pending_cleared id=%lld pid=%ld reason=rescan_no_hit",
                    batch_id,
                    pending_strike_pid);
            }
        }

        ULONG scanned = 0;
        ULONG pid_start = 0;
        ULONG pid = 0;
        if (hit_pid == 0) {
            pid_start = static_cast<ULONG>(
                _InterlockedCompareExchange(&g_scan_cursor_pid, 0, 0));
            if (pid_start < 4) pid_start = 4;

            pid = pid_start;

            while (scanned < SCAN_BATCH) {
                if (pid != own_pid && pid != 0 && pid != 4 &&
                    pid != static_cast<ULONG>(pending_strike_pid)) {
                    if (scan_one_process(pid, &hit_info)) {
                        hit_pid = pid;
                        WW_LOG("dma_canary::cursor_hit id=%lld scanned=%lu cursor_start=%lu pid=%lu name=%.15s owner=%u va=0x%llx canary_pa=0x%llx mapped_pa=0x%llx page=0x%lx",
                            batch_id,
                            scanned,
                            pid_start,
                            hit_pid,
                            hit_info.target_name,
                            hit_info.owner_pid,
                            static_cast<unsigned long long>(hit_info.owner_va),
                            static_cast<unsigned long long>(hit_info.canary_pa),
                            static_cast<unsigned long long>(hit_info.mapped_pa),
                            hit_info.page_size);
                        break;
                    }
                }
                pid += 4;
                if (pid > 0x20000) pid = 4;
                scanned++;
            }

            _InterlockedExchange(&g_scan_cursor_pid, static_cast<LONG>(pid + 4));
        }

        if (hit_pid == 0) {
            WW_LOG("dma_canary::batch_no_hit id=%lld scanned=%lu cursor_start=%lu cursor_next=%ld canaries=%lu",
                batch_id,
                scanned,
                pid_start,
                _InterlockedCompareExchange(&g_scan_cursor_pid, 0, 0),
                g_canary_count);
        }

        if (hit_pid != 0) {
            LONG prev_pid = _InterlockedExchange(&g_strike_pid, static_cast<LONG>(hit_pid));
            LONG strikes;
            if (prev_pid == static_cast<LONG>(hit_pid)) {
                strikes = _InterlockedIncrement(&g_strike_count);
            } else {
                _InterlockedExchange(&g_strike_count, 1);
                strikes = 1;
            }

            WW_LOG("dma_canary::hit id=%lld pid=%lu name=%.15s owner=%u va=0x%llx canary_pa=0x%llx mapped_pa=0x%llx dtb=0x%llx entry=0x%llx page=0x%lx idx=%lu/%lu/%lu/%lu prev_pid=%ld strikes=%ld threshold=%lu",
                batch_id,
                hit_pid,
                hit_info.target_name,
                hit_info.owner_pid,
                static_cast<unsigned long long>(hit_info.owner_va),
                static_cast<unsigned long long>(hit_info.canary_pa),
                static_cast<unsigned long long>(hit_info.mapped_pa),
                static_cast<unsigned long long>(hit_info.dtb),
                static_cast<unsigned long long>(hit_info.entry_value),
                hit_info.page_size,
                hit_info.pml4_index,
                hit_info.pdpt_index,
                hit_info.pd_index,
                hit_info.pt_index,
                prev_pid,
                strikes,
                PERSIST_STRIKE);

            sentinel_bridge::populate_evidence_blob(
                0x40u,
                sentinel_bridge::RE_REASON_DMA_CANARY,
                95,
                hit_pid,
                hit_info.owner_va,
                0,
                static_cast<UINT64>(hit_info.owner_pid));
            WW_LOG("dma_canary::evidence_written id=%lld pid=%lu owner=%u va=0x%llx strikes=%ld",
                batch_id,
                hit_pid,
                hit_info.owner_pid,
                static_cast<unsigned long long>(hit_info.owner_va),
                strikes);

            if (strikes >= PERSIST_STRIKE) {
                ULONG cmd   = sentinel_bridge::BRIDGE_CMD_CANARY_FOREIGN_PT;
                ULONG param = hit_pid;
                ULONG plain_cmd = cmd;
                ULONG plain_param = param;
                sentinel_bridge::bridge_encrypt_cmd(cmd, param);
                _InterlockedExchange(
                    reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd),
                    static_cast<LONG>(cmd));
                _InterlockedExchange(
                    reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param),
                    static_cast<LONG>(param));

                WW_LOG("dma_canary::bridge_armed id=%lld plain_cmd=%lu plain_param_pid=%lu enc_cmd=0x%lx enc_param=0x%lx bridge=%p key=0x%llx",
                    batch_id,
                    plain_cmd,
                    plain_param,
                    cmd,
                    param,
                    &sentinel_bridge::g_bridge,
                    static_cast<unsigned long long>(sentinel_bridge::g_bridge_crypt_key));

                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_DMA_CANARY,
                    hit_info.owner_va,
                    static_cast<UINT64>(hit_pid),
                    static_cast<UINT64>(hit_info.owner_pid),
                    0
                );
            } else {
                WW_LOG("dma_canary::bridge_not_armed id=%lld pid=%lu strikes=%ld threshold=%lu",
                    batch_id,
                    hit_pid,
                    strikes,
                    PERSIST_STRIKE);
            }
        }
    }

    static VOID NTAPI work_routine(PVOID) {
        __try {
            do_scan_batch();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("dma_canary::work_exception");
        }
        _InterlockedExchange(&g_work_queued, 0);
    }

    static VOID NTAPI dpc_routine(_KDPC*, PVOID, PVOID, PVOID) {
        WW_LOG("dma_canary::dpc_routine: ENTRY running=%ld", g_running);
        if (!_InterlockedCompareExchange(&g_running, 0, 0)) {
            WW_LOG("dma_canary::dpc_skip not_running");
            return;
        }
        if (_InterlockedCompareExchange(&g_work_queued, 1, 0) != 0) {
            WW_LOG("dma_canary::dpc_skip work_already_queued");
            return;
        }
        ExInitializeWorkItem(&g_work, work_routine, nullptr);
        ExQueueWorkItem(&g_work, DelayedWorkQueue);
        WW_LOG("dma_canary::dpc_queued_work");
    }

    __forceinline VOID init_timer() {
        WW_LOG("dma_canary::init_timer: ENTRY");
        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) return;

        RtlZeroMemory(g_canaries, sizeof(g_canaries));
        g_canary_count = 0;
        g_work_queued = 0;
        g_scan_cursor_pid = 4;
        g_strike_pid = 0;
        g_strike_count = 0;
        g_scan_batch_id = 0;
        RtlZeroMemory(&g_timer, sizeof(g_timer));
        RtlZeroMemory(&g_dpc, sizeof(g_dpc));
        RtlZeroMemory(&g_work, sizeof(g_work));

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
