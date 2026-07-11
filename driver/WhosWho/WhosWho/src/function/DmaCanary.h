#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include <function/CoreSecurity.h>
#include <function/SentinelBridge.h>
#include <function/impl/driver/Strong.h>
#include <function/TargetingLatch.h>
#include <function/DmaDefense.h>

namespace anti_dma_canary {

    constexpr ULONG POOL_TAG       = 'aCiA';
    constexpr ULONG MAX_CANARIES   = 32;
    constexpr ULONG SCAN_BATCH     = 16;
    constexpr ULONG READ_BUDGET_PER_PROCESS = 1024;
    constexpr ULONG READ_BUDGET_PER_BATCH = 4096;
    constexpr ULONG PERSIST_STRIKE = 2;
    constexpr LONG64 PERIOD_MS     = 5000;
    constexpr LONG64 STARTUP_WARMUP_100NS = 30LL * 1000LL * 1000LL * 10LL;
    constexpr ULONG PROCESS_NAME_CHARS = 15;

    struct canary_t {
        UINT64 va;
        UINT64 pa;
        UINT64 size;
        PMDL mdl;
        UINT32 owner_pid;
        UINT32 active;
    };

    struct canary_poison_t {
        UINT64 poison_signature;
        UINT64 original_value;
        UINT32 poisoned;
        UINT32 pad;
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
    inline volatile LONG  g_work_running = 0;
    inline KEVENT         g_work_done = {};
    inline volatile LONG  g_work_sync_initialized = 0;
    inline volatile LONG  g_timer_initialized = 0;
    inline volatile LONG  g_scan_cursor_pid = 4;
    inline volatile LONG  g_strike_pid = 0;
    inline volatile LONG  g_strike_count = 0;
    inline volatile LONG64 g_scan_batch_id = 0;
    inline volatile LONG64 g_first_canary_time = 0;
    inline volatile LONG g_warmup_logged = 0;

    inline canary_poison_t g_canary_poisons[MAX_CANARIES] = {};
    inline volatile LONG g_scan_cycle_since_refresh = 0;
    inline volatile ULONG g_canary_crc_hits = 0;
    inline volatile ULONG g_canary_accessed_hits = 0;
    inline volatile ULONG g_canary_refresh_count = 0;

    __forceinline ULONG elapsed_us_from_100ns(ULONGLONG start_100ns, ULONGLONG end_100ns) {
        return end_100ns >= start_100ns
            ? static_cast<ULONG>((end_100ns - start_100ns) / 10ULL)
            : 0;
    }

    __forceinline void ensure_work_sync_initialized() {
        if (_InterlockedCompareExchange(&g_work_sync_initialized, 1, 0) == 0)
            KeInitializeEvent(&g_work_done, NotificationEvent, TRUE);
    }

    __forceinline UINT32 current_registered_client_pid() {
        return static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));
    }

    __forceinline VOID init_timer(const char* reason = "manual", UINT32 client_pid = 0);
    __forceinline VOID stop_timer(const char* reason = "manual", UINT32 client_pid = 0, BOOLEAN wait_for_work = TRUE);

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

    __forceinline BOOLEAN is_pid_alive(UINT32 pid) {
        if (pid == 0 || pid == 4) return TRUE;
        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc);
        if (!NT_SUCCESS(st) || !proc) return FALSE;
        ObDereferenceObject(proc);
        return TRUE;
    }

    __forceinline void release_locked_mdl(PMDL mdl) {
        if (!mdl) return;
        ULONG exception_code = 0;
        __try {
            if (_MmUnlockPages)
                _MmUnlockPages(mdl);
        } __except ((exception_code = GetExceptionInformation()->ExceptionRecord->ExceptionCode), EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("dma_canary::mdl_unlock_exception mdl=%p code=0x%08lx",
                mdl,
                exception_code);
        }
        if (_IoFreeMdl)
            _IoFreeMdl(mdl);
    }

    __forceinline BOOLEAN lock_user_page_pa_for_pid(ULONG pid, UINT64 va, PMDL* out_mdl, UINT64* out_pa) {
        if (out_mdl) *out_mdl = nullptr;
        if (out_pa) *out_pa = 0;
        if (!pid || !va || !out_pa ||
            !_PsLookupProcessByProcessId || !_ObfDereferenceObject ||
            !_IoAllocateMdl || !_IoFreeMdl || !_MmProbeAndLockPages ||
            !_MmUnlockPages || !_KeStackAttachProcess || !_KeUnstackDetachProcess) {
            WW_LOG("dma_canary::lock_user_page_reject missing_prereq pid=%lu va=0x%llx",
                pid,
                static_cast<unsigned long long>(va));
            return FALSE;
        }
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            WW_LOG("dma_canary::lock_user_page_reject irql=%lu pid=%lu va=0x%llx",
                static_cast<ULONG>(KeGetCurrentIrql()),
                pid,
                static_cast<unsigned long long>(va));
            return FALSE;
        }

        PEPROCESS proc = nullptr;
        NTSTATUS lookup = _PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc);
        if (!NT_SUCCESS(lookup) || !proc) {
            WW_LOG("dma_canary::lock_user_page_reject lookup=0x%08lx pid=%lu va=0x%llx",
                lookup,
                pid,
                static_cast<unsigned long long>(va));
            return FALSE;
        }

        PVOID page_va = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(va & ~0xFFFULL));
        PMDL mdl = _IoAllocateMdl(page_va, 0x1000, FALSE, FALSE, nullptr);
        if (!mdl) {
            _ObfDereferenceObject(proc);
            WW_LOG("dma_canary::lock_user_page_reject mdl_alloc pid=%lu va=0x%llx page_va=%p",
                pid,
                static_cast<unsigned long long>(va),
                page_va);
            return FALSE;
        }

        KAPC_STATE apc{};
        BOOLEAN attached = FALSE;
        BOOLEAN locked = FALSE;
        ULONG exception_code = 0;
        UINT64 pa = 0;
        __try {
            _KeStackAttachProcess(proc, &apc);
            attached = TRUE;
            _MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            locked = TRUE;
            PPFN_NUMBER pfns = MmGetMdlPfnArray(mdl);
            if (pfns && pfns[0] != 0)
                pa = (static_cast<UINT64>(pfns[0]) << 12) | (va & 0xFFFULL);
        } __except ((exception_code = GetExceptionInformation()->ExceptionRecord->ExceptionCode), EXCEPTION_EXECUTE_HANDLER) {
        }

        if (attached)
            _KeUnstackDetachProcess(&apc);
        _ObfDereferenceObject(proc);

        if (!locked || pa == 0) {
            if (locked)
                release_locked_mdl(mdl);
            else
                _IoFreeMdl(mdl);
            WW_LOG("dma_canary::lock_user_page_reject lock_failed pid=%lu va=0x%llx page_va=%p locked=%u pa=0x%llx seh=0x%08lx",
                pid,
                static_cast<unsigned long long>(va),
                page_va,
                locked ? 1u : 0u,
                static_cast<unsigned long long>(pa),
                exception_code);
            return FALSE;
        }

        *out_pa = pa;
        if (out_mdl)
            *out_mdl = mdl;
        else
            release_locked_mdl(mdl);
        WW_LOG("dma_canary::lock_user_page_ok pid=%lu va=0x%llx page_va=%p pa=0x%llx keep_mdl=%u",
            pid,
            static_cast<unsigned long long>(va),
            page_va,
            static_cast<unsigned long long>(pa),
            out_mdl ? 1u : 0u);
        return TRUE;
    }

    __forceinline ULONG cleanup_for_pid(UINT32 owner_pid) {
        if (owner_pid == 0) return 0;
        ensure_lock();
        PMDL release_mdls[MAX_CANARIES] = {};
        ULONG release_count = 0;
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        ULONG cleared = 0;
        ULONG new_count = g_canary_count;
        for (ULONG i = 0; i < MAX_CANARIES; i++) {
            if (g_canaries[i].active && g_canaries[i].owner_pid == owner_pid) {
                g_canaries[i].active    = 0;
                g_canaries[i].pa        = 0;
                g_canaries[i].va        = 0;
                g_canaries[i].size      = 0;
                if (g_canaries[i].mdl && release_count < MAX_CANARIES)
                    release_mdls[release_count++] = g_canaries[i].mdl;
                g_canaries[i].mdl       = nullptr;
                g_canaries[i].owner_pid = 0;
                cleared++;
            }
        }
        if (cleared) {
            new_count = 0;
            for (ULONG i = 0; i < MAX_CANARIES; i++) {
                if (g_canaries[i].active) new_count = i + 1;
            }
            g_canary_count = new_count;
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        for (ULONG i = 0; i < release_count; ++i)
            release_locked_mdl(release_mdls[i]);
        if (cleared) {
            WW_LOG("dma_canary::cleanup_for_pid pid=%lu cleared=%lu count=%lu running=%ld queued=%ld work_running=%ld",
                owner_pid,
                cleared,
                new_count,
                _InterlockedCompareExchange(&g_running, 0, 0),
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            if (new_count == 0) {
                _InterlockedExchange64(&g_first_canary_time, 0);
                _InterlockedExchange(&g_warmup_logged, 0);
                stop_timer("cleanup_last_canary", owner_pid, FALSE);
            }
        }
        return cleared;
    }

    __forceinline ULONG cleanup_dead_owners() {
        ensure_lock();
        UINT32 candidates[MAX_CANARIES];
        ULONG candidate_count = 0;
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        for (ULONG i = 0; i < MAX_CANARIES; i++) {
            if (!g_canaries[i].active) continue;
            UINT32 owner = g_canaries[i].owner_pid;
            if (owner == 0) continue;
            BOOLEAN duplicate = FALSE;
            for (ULONG j = 0; j < candidate_count; j++) {
                if (candidates[j] == owner) { duplicate = TRUE; break; }
            }
            if (!duplicate) candidates[candidate_count++] = owner;
        }
        KeReleaseSpinLock(&g_canary_lock, old);

        ULONG total_cleared = 0;
        UINT32 registered = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(
            caller_validation::g_registered_client_pid));
        for (ULONG i = 0; i < candidate_count; i++) {
            UINT32 pid = candidates[i];
            if (pid == registered && registered != 0) continue;
            if (!is_pid_alive(pid)) {
                ULONG cleared = cleanup_for_pid(pid);
                if (cleared) {
                    WW_LOG("dma_canary::cleanup_dead_owner pid=%lu cleared=%lu", pid, cleared);
                }
                total_cleared += cleared;
            }
        }
        return total_cleared;
    }

    __forceinline UINT64 va_to_pa_for_pid(ULONG pid, UINT64 va) {
        UINT64 pa = 0;
        if (lock_user_page_pa_for_pid(pid, va, nullptr, &pa))
            return pa;
        return 0;
    }

    __forceinline BOOLEAN canary_still_valid_for(UINT32 owner_pid, UINT64 owner_va, UINT64 canary_pa) {
        if (owner_pid == 0) return FALSE;
        UINT64 current_pa = va_to_pa_for_pid(static_cast<ULONG>(owner_pid), owner_va);
        if (current_pa == 0) return FALSE;
        return ((current_pa & ~0xFFFULL) == (canary_pa & ~0xFFFULL));
    }

    __forceinline ULONG snapshot_canaries(canary_t* snapshot, ULONG capacity) {
        if (!snapshot || capacity == 0) return 0;
        ensure_lock();
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        ULONG copied = 0;
        for (ULONG i = 0; i < g_canary_count && i < MAX_CANARIES && copied < capacity; i++) {
            if (!g_canaries[i].active) continue;
            snapshot[copied++] = g_canaries[i];
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        return copied;
    }

    __forceinline BOOLEAN snapshot_matches_pa(const canary_t* snapshot, ULONG snapshot_count,
                                              UINT64 pa_page, UINT32* out_owner_pid,
                                              UINT64* out_va, UINT64* out_canary_pa) {
        if (!snapshot || snapshot_count == 0) return FALSE;
        pa_page &= ~0xFFFULL;
        for (ULONG i = 0; i < snapshot_count && i < MAX_CANARIES; i++) {
            if (!snapshot[i].active) continue;
            UINT64 start = snapshot[i].pa;
            UINT64 end = start + ((snapshot[i].size + 0xFFF) & ~0xFFFULL);
            if (pa_page >= start && pa_page < end) {
                if (out_owner_pid) *out_owner_pid = snapshot[i].owner_pid;
                if (out_va) *out_va = snapshot[i].va;
                if (out_canary_pa) *out_canary_pa = snapshot[i].pa;
                return TRUE;
            }
        }
        return FALSE;
    }

    __forceinline BOOLEAN read_phys_qword_budgeted(UINT64 pa, UINT64* value, ULONG* budget) {
        if (!value || !budget || *budget == 0) return FALSE;
        *value = 0;
        (*budget)--;
        SIZE_T br = 0;
        return NT_SUCCESS(strong::read_physical(pa, value, sizeof(*value), &br)) && br == sizeof(*value);
    }

    __forceinline BOOLEAN register_canary(UINT64 va, UINT64 size, ULONG owner_pid) {
        ULONG build = strong::get_windows_version();
        WW_LOG("dma_canary::register_entry build=%lu va=0x%llx size=0x%llx owner=%lu registered=%u count=%lu running=%ld queued=%ld work_running=%ld irql=%lu",
            build,
            static_cast<unsigned long long>(va),
            static_cast<unsigned long long>(size),
            owner_pid,
            current_registered_client_pid(),
            g_canary_count,
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            static_cast<ULONG>(KeGetCurrentIrql()));
        UINT32 registered_pid = current_registered_client_pid();
        if (registered_pid == 0 || owner_pid != registered_pid || !is_pid_alive(owner_pid)) {
            WW_LOG("dma_canary::register_reject no_live_registered_client va=0x%llx size=0x%llx owner=%lu registered=%u running=%ld queued=%ld",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                owner_pid,
                registered_pid,
                _InterlockedCompareExchange(&g_running, 0, 0),
                _InterlockedCompareExchange(&g_work_queued, 0, 0));
            return FALSE;
        }
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

        PMDL locked_mdl = nullptr;
        UINT64 pa = 0;
        if (!lock_user_page_pa_for_pid(owner_pid, va, &locked_mdl, &pa)) {
            WW_LOG("dma_canary::register_reject translate_failed va=0x%llx size=0x%llx owner=%lu",
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                owner_pid);
            return FALSE;
        }
        if (!pa) {
            release_locked_mdl(locked_mdl);
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
                g_canaries[i].mdl       = locked_mdl;
                g_canaries[i].owner_pid = owner_pid;
                g_canaries[i].active    = 1;
                if (i + 1 > g_canary_count) g_canary_count = i + 1;
                slot = i;
                ok = TRUE;
                locked_mdl = nullptr;
                break;
            }
        }

        KeReleaseSpinLock(&g_canary_lock, old);
        if (locked_mdl)
            release_locked_mdl(locked_mdl);

        if (ok) {
            LONG64 now = static_cast<LONG64>(KeQueryInterruptTime());
            _InterlockedCompareExchange64(&g_first_canary_time, now, 0);
            refresh_canary_slot(slot);
            WW_LOG("dma_canary::register_ok slot=%lu owner=%lu va=0x%llx size=0x%llx pa=0x%llx page_pa=0x%llx count=%lu",
                slot,
                owner_pid,
                static_cast<unsigned long long>(va),
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(pa),
                static_cast<unsigned long long>(pa & ~0xFFFULL),
                g_canary_count);
            init_timer("register_canary", owner_pid);
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

    __forceinline BOOLEAN scan_one_process(ULONG pid, const canary_t* snapshot,
                                           ULONG snapshot_count, ULONG* batch_budget,
                                           scan_hit_t* out_hit, BOOLEAN* out_budget_exhausted) {
        if (out_budget_exhausted) *out_budget_exhausted = FALSE;
        if (pid == 0 || pid == 4) return FALSE;
        if (!snapshot || snapshot_count == 0 || !batch_budget || *batch_budget == 0) return FALSE;

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
        ULONG local_budget = (*batch_budget < READ_BUDGET_PER_PROCESS) ? *batch_budget : READ_BUDGET_PER_PROCESS;
        ULONG starting_budget = local_budget;

        for (ULONG pml4i = 0; pml4i < 256 && !hit && local_budget > 0; pml4i++) {
            UINT64 pml4e = 0;
            if (!read_phys_qword_budgeted(dtb + pml4i * 8, &pml4e, &local_budget))
                continue;
            if (!(pml4e & 1)) continue;

            UINT64 pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;

            for (ULONG pdpti = 0; pdpti < 512 && !hit && local_budget > 0; pdpti++) {
                UINT64 pdpte = 0;
                if (!read_phys_qword_budgeted(pdpt_pa + pdpti * 8, &pdpte, &local_budget))
                    continue;
                if (!(pdpte & 1)) continue;

                if (pdpte & 0x80) {
                    UINT64 start_pa = pdpte & 0x000FFFFFC0000000ULL;
                    for (ULONG i = 0; i < snapshot_count && i < MAX_CANARIES; i++) {
                        if (!snapshot[i].active) continue;
                        UINT64 cp = snapshot[i].pa;
                        if (cp >= start_pa && cp < start_pa + (1ULL << 30)) {
                            fill_scan_hit(out_hit, pid, proc, snapshot[i].owner_pid,
                                snapshot[i].va, cp, start_pa, dtb, pdpte,
                                pml4i, pdpti, 0xFFFFFFFFul, 0xFFFFFFFFul,
                                static_cast<ULONG>(1ULL << 30));
                            hit = TRUE;
                            break;
                        }
                    }
                    continue;
                }

                UINT64 pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
                for (ULONG pdi = 0; pdi < 512 && !hit && local_budget > 0; pdi++) {
                    UINT64 pde = 0;
                    if (!read_phys_qword_budgeted(pd_pa + pdi * 8, &pde, &local_budget))
                        continue;
                    if (!(pde & 1)) continue;

                    if (pde & 0x80) {
                        UINT64 start_pa = pde & 0x000FFFFFFFE00000ULL;
                        for (ULONG i = 0; i < snapshot_count && i < MAX_CANARIES; i++) {
                            if (!snapshot[i].active) continue;
                            UINT64 cp = snapshot[i].pa;
                            if (cp >= start_pa && cp < start_pa + (2ULL * 1024 * 1024)) {
                                fill_scan_hit(out_hit, pid, proc, snapshot[i].owner_pid,
                                    snapshot[i].va, cp, start_pa, dtb, pde,
                                    pml4i, pdpti, pdi, 0xFFFFFFFFul,
                                    static_cast<ULONG>(2ULL * 1024 * 1024));
                                hit = TRUE;
                                break;
                            }
                        }
                        continue;
                    }

                    UINT64 pt_pa = pde & 0x000FFFFFFFFFF000ULL;
                    for (ULONG pti = 0; pti < 512 && !hit && local_budget > 0; pti++) {
                        UINT64 pte = 0;
                        if (!read_phys_qword_budgeted(pt_pa + pti * 8, &pte, &local_budget))
                            continue;
                        if (!(pte & 1)) continue;
                        UINT64 phys = pte & 0x000FFFFFFFFFF000ULL;
                        UINT32 owner = 0;
                        UINT64 va    = 0;
                        UINT64 canary_pa = 0;
                        if (snapshot_matches_pa(snapshot, snapshot_count, phys, &owner, &va, &canary_pa)) {
                            fill_scan_hit(out_hit, pid, proc, owner, va, canary_pa,
                                phys, dtb, pte, pml4i, pdpti, pdi, pti, 0x1000ul);
                            hit = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        ULONG consumed = starting_budget - local_budget;
        if (*batch_budget >= consumed)
            *batch_budget -= consumed;
        else
            *batch_budget = 0;
        if (!hit && local_budget == 0 && out_budget_exhausted)
            *out_budget_exhausted = TRUE;

        ObDereferenceObject(proc);
        return hit;
    }

    __forceinline void write_canary_signature(UINT64 canary_pa, UINT64* sig1_out, UINT64* sig2_out) {
        if (!canary_pa) return;
        UINT8 payload[16] = {};
        UINT64 r1 = anti_dma::xorshift128p();
        UINT64 r2 = anti_dma::xorshift128p();
        RtlCopyMemory(payload, &r1, 8);
        RtlCopyMemory(payload + 8, &r2, 8);
        UINT32 crc = anti_dma::compute_crc32(payload, 16);
        UINT8 block[20] = {};
        RtlCopyMemory(block, payload, 16);
        RtlCopyMemory(block + 16, &crc, 4);
        SIZE_T bw = 0;
        strong::write_physical(reinterpret_cast<PVOID>(canary_pa), block, 20, &bw);
        if (sig1_out) *sig1_out = r1;
        if (sig2_out) *sig2_out = r2;
    }

    __forceinline void refresh_canary_slot(ULONG slot) {
        if (slot >= MAX_CANARIES) return;
        if (!g_canaries[slot].active || !g_canaries[slot].pa) return;
        UINT64 s1 = 0, s2 = 0;
        write_canary_signature(g_canaries[slot].pa, &s1, &s2);
        g_canary_poisons[slot].poison_signature = s1;
        g_canary_poisons[slot].original_value = s2;
    }

    __forceinline void refresh_all_canaries() {
        ensure_lock();
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        ULONG refreshed = 0;
        for (ULONG i = 0; i < g_canary_count && i < MAX_CANARIES; i++) {
            if (g_canaries[i].active && g_canaries[i].pa) {
                refresh_canary_slot(i);
                refreshed++;
            }
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        _InterlockedExchange(&g_scan_cycle_since_refresh, 0);
        _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_canary_refresh_count));
        WW_LOG("dma_canary::refresh_all refreshed=%lu total_refreshes=%lu",
            refreshed,
            _InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&g_canary_refresh_count), 0, 0));
    }

    __forceinline void corrupt_canaries() {
        ensure_lock();
        KIRQL old;
        KeAcquireSpinLock(&g_canary_lock, &old);
        ULONG corrupted = 0;
        UINT8 garbage[20] = {};
        for (ULONG i = 0; i < 16; i++) garbage[i] = 0xDE;
        for (ULONG i = 16; i < 20; i++) garbage[i] = 0xAD;
        for (ULONG i = 0; i < g_canary_count && i < MAX_CANARIES; i++) {
            if (g_canaries[i].active && g_canaries[i].pa) {
                SIZE_T bw = 0;
                strong::write_physical(reinterpret_cast<PVOID>(g_canaries[i].pa), garbage, 20, &bw);
                g_canary_poisons[i].poisoned = 0;
                g_canary_poisons[i].original_value = 0;
                corrupted++;
            }
        }
        KeReleaseSpinLock(&g_canary_lock, old);
        WW_LOG("dma_canary::corrupt_canaries corrupted=%lu", corrupted);
    }

    __forceinline void do_scan_batch() {
        UINT32 registered_pid = current_registered_client_pid();
        if (!registered_pid) {
            WW_LOG("dma_canary::batch_quiesce reason=no_registered_client count=%lu running=%ld queued=%ld work_running=%ld",
                g_canary_count,
                _InterlockedCompareExchange(&g_running, 0, 0),
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            stop_timer("batch_no_registered_client", 0, FALSE);
            return;
        }

        LONG64 first_canary_time = _InterlockedCompareExchange64(&g_first_canary_time, 0, 0);
        if (first_canary_time != 0) {
            LONG64 now = static_cast<LONG64>(KeQueryInterruptTime());
            LONG64 elapsed = now - first_canary_time;
            if (elapsed >= 0 && elapsed < STARTUP_WARMUP_100NS) {
                if (_InterlockedCompareExchange(&g_warmup_logged, 1, 0) == 0) {
                    WW_LOG("dma_canary::batch_deferred warmup_remaining_100ns=%lld",
                        STARTUP_WARMUP_100NS - elapsed);
                }
                return;
            }
        }

        cleanup_dead_owners();

        LONG cycles = _InterlockedIncrement(&g_scan_cycle_since_refresh);
        if (cycles >= 12) {
            refresh_all_canaries();
        }

        if (g_canary_count == 0) {
            WW_LOG("dma_canary::batch_quiesce reason=no_canaries client=%u running=%ld queued=%ld work_running=%ld",
                registered_pid,
                _InterlockedCompareExchange(&g_running, 0, 0),
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            stop_timer("batch_no_canaries", registered_pid, FALSE);
            return;
        }

        canary_t snapshot[MAX_CANARIES] = {};
        ULONG snapshot_count = snapshot_canaries(snapshot, MAX_CANARIES);
        if (snapshot_count == 0) {
            WW_LOG("dma_canary::batch_quiesce reason=empty_snapshot client=%u count=%lu running=%ld queued=%ld work_running=%ld",
                registered_pid,
                g_canary_count,
                _InterlockedCompareExchange(&g_running, 0, 0),
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            stop_timer("batch_empty_snapshot", registered_pid, FALSE);
            return;
        }

        for (ULONG ci = 0; ci < snapshot_count && ci < MAX_CANARIES; ci++) {
            if (!snapshot[ci].active || !snapshot[ci].pa) continue;
            UINT8 canary_block[20] = {};
            SIZE_T br = 0;
            if (!NT_SUCCESS(strong::read_physical(snapshot[ci].pa, canary_block, 20, &br)) || br != 20)
                continue;
            ULONG slot = MAX_CANARIES;
            for (ULONG si = 0; si < MAX_CANARIES; si++) {
                if (g_canaries[si].active && g_canaries[si].pa == snapshot[ci].pa) {
                    slot = si;
                    break;
                }
            }
            UINT32 stored_crc = 0;
            RtlCopyMemory(&stored_crc, canary_block + 16, 4);
            UINT32 computed_crc = anti_dma::compute_crc32(canary_block, 16);
            if (stored_crc != computed_crc) {
                WW_LOG("dma_canary::crc_mismatch pa=0x%llx stored=0x%08x computed=0x%08x refreshing",
                    snapshot[ci].pa, stored_crc, computed_crc);
                if (slot < MAX_CANARIES) refresh_canary_slot(slot);
                else { UINT64 s1, s2; write_canary_signature(snapshot[ci].pa, &s1, &s2); }
                continue;
            }
            UINT64 r1 = 0, r2 = 0;
            RtlCopyMemory(&r1, canary_block, 8);
            RtlCopyMemory(&r2, canary_block + 8, 8);
            if (r1 == 0 && r2 == 0) {
                WW_LOG("dma_canary::crc_valid_zeroed pa=0x%llx refreshing", snapshot[ci].pa);
                if (slot < MAX_CANARIES) refresh_canary_slot(slot);
                else { UINT64 s1, s2; write_canary_signature(snapshot[ci].pa, &s1, &s2); }
                continue;
            }
            if (slot < MAX_CANARIES && g_canary_poisons[slot].poison_signature != 0) {
                if (r1 != g_canary_poisons[slot].poison_signature ||
                    r2 != g_canary_poisons[slot].original_value) {
                    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_canary_crc_hits));
                    UINT64 evidence_hash = r1 ^ r2 ^ snapshot[ci].pa ^ __rdtsc();
                    WW_LOG("dma_canary::dma_attack_canary_disturbed pa=0x%llx r1=0x%llx r2=0x%llx expected_s1=0x%llx expected_s2=0x%llx",
                        snapshot[ci].pa, r1, r2,
                        g_canary_poisons[slot].poison_signature,
                        g_canary_poisons[slot].original_value);
                    anti_dma::countermeasure::trigger_bsod(0x01, snapshot[ci].pa, 0, evidence_hash);
                }
            }
        }

        LONG64 batch_id = _InterlockedIncrement64(&g_scan_batch_id);
        ULONG batch_budget = READ_BUDGET_PER_BATCH;

        ULONG own_pid = registered_pid;

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
            BOOLEAN exhausted = FALSE;
            if (scan_one_process(static_cast<ULONG>(pending_strike_pid), snapshot,
                                 snapshot_count, &batch_budget, &confirm_info, &exhausted)) {
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
                if (exhausted) {
                    WW_LOG("dma_canary::pending_rescan_budget_exhausted id=%lld pid=%ld budget_left=%lu",
                        batch_id,
                        pending_strike_pid,
                        batch_budget);
                } else {
                    _InterlockedExchange(&g_strike_pid, 0);
                    _InterlockedExchange(&g_strike_count, 0);
                    WW_LOG("dma_canary::pending_cleared id=%lld pid=%ld reason=rescan_no_hit",
                        batch_id,
                        pending_strike_pid);
                }
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

            while (scanned < SCAN_BATCH && batch_budget > 0) {
                if (pid != own_pid && pid != 0 && pid != 4 &&
                    pid != static_cast<ULONG>(pending_strike_pid)) {
                    BOOLEAN exhausted = FALSE;
                    if (scan_one_process(pid, snapshot, snapshot_count, &batch_budget,
                                         &hit_info, &exhausted)) {
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
                    if (exhausted && batch_budget == 0)
                        break;
                }
                pid += 4;
                if (pid > 0x20000) pid = 4;
                scanned++;
            }

            _InterlockedExchange(&g_scan_cursor_pid, static_cast<LONG>(pid + 4));
        }

        if (hit_pid == 0) {
            WW_LOG("dma_canary::batch_no_hit id=%lld scanned=%lu cursor_start=%lu cursor_next=%ld canaries=%lu budget_left=%lu",
                batch_id,
                scanned,
                pid_start,
                _InterlockedCompareExchange(&g_scan_cursor_pid, 0, 0),
                snapshot_count,
                batch_budget);
        }

        if (g_scan_cycle_since_refresh > 1) {
            ULONG accessed_hits = 0;
            if (anti_dma::accessed_bit::check_canary_accessed_bits(snapshot, snapshot_count, &accessed_hits)) {
                _InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&g_canary_accessed_hits), accessed_hits);
                UINT64 evidence_hash = __rdtsc() ^ snapshot[0].pa;
                WW_LOG("dma_canary::accessed_bit_dma_attack detected_hits=%lu", accessed_hits);
                anti_dma::countermeasure::trigger_bsod(0x03, snapshot[0].pa, 0, evidence_hash);
            }
        }

        for (ULONG ai = 0; ai < snapshot_count && ai < MAX_CANARIES; ai++) {
            if (!snapshot[ai].active || !snapshot[ai].owner_pid) continue;
            UINT64 owner_cr3 = anti_dma::get_process_dtb(snapshot[ai].owner_pid);
            if (!owner_cr3) continue;
            UINT64 pte_phys = anti_dma::accessed_bit::get_pte_phys_addr(owner_cr3, snapshot[ai].va);
            if (!pte_phys) continue;
            SIZE_T bw = 0;
            UINT64 cur_pte = 0;
            if (!NT_SUCCESS(strong::read_physical(pte_phys, &cur_pte, 8, &bw)) || bw != 8) continue;
            if (cur_pte & 0x20) {
                UINT64 cleared = cur_pte & ~0x20ULL;
                strong::write_physical(reinterpret_cast<PVOID>(pte_phys), &cleared, sizeof(cleared), &bw);
            }
        }

        if (hit_pid != 0) {
            if (!canary_still_valid_for(hit_info.owner_pid, hit_info.owner_va, hit_info.canary_pa)) {
                ULONG cleared = cleanup_for_pid(hit_info.owner_pid);
                _InterlockedExchange(&g_strike_pid, 0);
                _InterlockedExchange(&g_strike_count, 0);
                WW_LOG("dma_canary::stale_canary_evicted id=%lld owner=%u va=0x%llx canary_pa=0x%llx mapped_pa=0x%llx offender_pid=%lu cleared=%lu",
                    batch_id,
                    hit_info.owner_pid,
                    static_cast<unsigned long long>(hit_info.owner_va),
                    static_cast<unsigned long long>(hit_info.canary_pa),
                    static_cast<unsigned long long>(hit_info.mapped_pa),
                    hit_pid,
                    cleared);
                return;
            }

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
                BOOLEAN owner_alive    = is_pid_alive(hit_info.owner_pid);
                BOOLEAN offender_alive = is_pid_alive(hit_pid);

                if (!owner_alive) {
                    cleanup_for_pid(hit_info.owner_pid);
                    _InterlockedExchange(&g_strike_pid, 0);
                    _InterlockedExchange(&g_strike_count, 0);
                    WW_LOG("dma_canary::arm_aborted reason=owner_dead id=%lld pid=%lu owner=%u strikes=%ld",
                        batch_id,
                        hit_pid,
                        hit_info.owner_pid,
                        strikes);
                } else if (!offender_alive) {
                    _InterlockedExchange(&g_strike_pid, 0);
                    _InterlockedExchange(&g_strike_count, 0);
                    WW_LOG("dma_canary::arm_aborted reason=offender_dead id=%lld pid=%lu owner=%u strikes=%ld",
                        batch_id,
                        hit_pid,
                        hit_info.owner_pid,
                        strikes);
                } else {
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
                }
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
        ULONGLONG start_time = KeQueryInterruptTime();
        _InterlockedExchange(&g_work_running, 1);
        UINT32 client_pid = current_registered_client_pid();
        WW_LOG("dma_canary::work_entry running=%ld queued=%ld work_running=%ld count=%lu client=%u irql=%lu",
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            g_canary_count,
            client_pid,
            static_cast<ULONG>(KeGetCurrentIrql()));
        __try {
            do_scan_batch();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("dma_canary::work_exception");
        }
        _InterlockedExchange(&g_work_running, 0);
        _InterlockedExchange(&g_work_queued, 0);
        KeSetEvent(&g_work_done, IO_NO_INCREMENT, FALSE);
        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("dma_canary::work_exit elapsed_us=%lu running=%ld queued=%ld work_running=%ld count=%lu client=%u",
            elapsed_us_from_100ns(start_time, end_time),
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            g_canary_count,
            current_registered_client_pid());
    }

    static VOID NTAPI dpc_routine(_KDPC*, PVOID, PVOID, PVOID) {
        UINT32 client_pid = current_registered_client_pid();
        LONG running = _InterlockedCompareExchange(&g_running, 0, 0);
        WW_LOG("dma_canary::dpc_entry running=%ld queued=%ld work_running=%ld count=%lu client=%u irql=%lu",
            running,
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            g_canary_count,
            client_pid,
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (!running) {
            WW_LOG("dma_canary::dpc_skip not_running queued=%ld work_running=%ld",
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            return;
        }
        if (client_pid == 0) {
            stop_timer("dpc_no_registered_client", 0, FALSE);
            return;
        }
        if (g_canary_count == 0) {
            stop_timer("dpc_no_canaries", client_pid, FALSE);
            return;
        }
        if (_InterlockedCompareExchange(&g_work_running, 0, 0) != 0) {
            WW_LOG("dma_canary::dpc_skip work_running client=%u count=%lu queued=%ld",
                client_pid,
                g_canary_count,
                _InterlockedCompareExchange(&g_work_queued, 0, 0));
            return;
        }
        if (_InterlockedCompareExchange(&g_work_queued, 1, 0) != 0) {
            WW_LOG("dma_canary::dpc_skip work_already_queued client=%u count=%lu work_running=%ld",
                client_pid,
                g_canary_count,
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            return;
        }
        ensure_work_sync_initialized();
        KeClearEvent(&g_work_done);
        ExInitializeWorkItem(&g_work, work_routine, nullptr);
        ExQueueWorkItem(&g_work, DelayedWorkQueue);
        WW_LOG("dma_canary::dpc_queued_work client=%u count=%lu queued=%ld work_running=%ld",
            client_pid,
            g_canary_count,
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0));
    }

    __forceinline VOID init_timer(const char* reason, UINT32 client_pid) {
        ULONGLONG start_time = KeQueryInterruptTime();
        UINT32 registered_pid = current_registered_client_pid();
        if (client_pid == 0)
            client_pid = registered_pid;
        WW_LOG("dma_canary::timer_start_entry reason=%s client=%u registered=%u count=%lu running=%ld queued=%ld work_running=%ld timer_init=%ld irql=%lu",
            reason ? reason : "unknown",
            client_pid,
            registered_pid,
            g_canary_count,
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            _InterlockedCompareExchange(&g_timer_initialized, 0, 0),
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (client_pid == 0 || registered_pid == 0 || client_pid != registered_pid || g_canary_count == 0) {
            WW_LOG("dma_canary::timer_start_reject reason=%s client=%u registered=%u count=%lu",
                reason ? reason : "unknown",
                client_pid,
                registered_pid,
                g_canary_count);
            return;
        }
        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) {
            WW_LOG("dma_canary::timer_start_noop reason=%s client=%u count=%lu queued=%ld work_running=%ld",
                reason ? reason : "unknown",
                client_pid,
                g_canary_count,
                _InterlockedCompareExchange(&g_work_queued, 0, 0),
                _InterlockedCompareExchange(&g_work_running, 0, 0));
            return;
        }

        ensure_work_sync_initialized();
        if (_InterlockedCompareExchange(&g_work_queued, 0, 0) != 0 ||
            _InterlockedCompareExchange(&g_work_running, 0, 0) != 0) {
            NTSTATUS wait_status = STATUS_NOT_SUPPORTED;
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -50'000'000LL;
                wait_status = KeWaitForSingleObject(&g_work_done, Executive, KernelMode, FALSE, &timeout);
            }
            if (_InterlockedCompareExchange(&g_work_queued, 0, 0) != 0 ||
                _InterlockedCompareExchange(&g_work_running, 0, 0) != 0) {
                WW_LOG("dma_canary::timer_start_pending_work reason=%s client=%u registered=%u count=%lu wait_status=0x%08lx queued=%ld work_running=%ld",
                    reason ? reason : "unknown",
                    client_pid,
                    registered_pid,
                    g_canary_count,
                    wait_status,
                    _InterlockedCompareExchange(&g_work_queued, 0, 0),
                    _InterlockedCompareExchange(&g_work_running, 0, 0));
                _InterlockedExchange(&g_running, 0);
                return;
            }
        }
        KeSetEvent(&g_work_done, IO_NO_INCREMENT, FALSE);
        _InterlockedExchange(&g_scan_cursor_pid, 4);
        _InterlockedExchange(&g_strike_pid, 0);
        _InterlockedExchange(&g_strike_count, 0);
        _InterlockedExchange64(&g_scan_batch_id, 0);
        _InterlockedExchange(&g_warmup_logged, 0);
        ensure_lock();
        KeInitializeTimerEx(&g_timer, SynchronizationTimer);
        KeInitializeDpc(&g_dpc, dpc_routine, nullptr);
        _InterlockedExchange(&g_timer_initialized, 1);
        LARGE_INTEGER due;
        due.QuadPart = -10000000LL;
        KeSetTimerEx(&g_timer, due, static_cast<LONG>(PERIOD_MS), &g_dpc);
        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("dma_canary::timer_start_exit reason=%s client=%u registered=%u count=%lu running=%ld queued=%ld work_running=%ld period=%lldms elapsed_us=%lu",
            reason ? reason : "unknown",
            client_pid,
            registered_pid,
            g_canary_count,
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            PERIOD_MS,
            elapsed_us_from_100ns(start_time, end_time));
    }

    __forceinline VOID stop_timer(const char* reason, UINT32 client_pid, BOOLEAN wait_for_work) {
        ULONGLONG start_time = KeQueryInterruptTime();
        UINT32 registered_pid = current_registered_client_pid();
        LONG running_before = _InterlockedExchange(&g_running, 0);
        LONG queued_before = _InterlockedCompareExchange(&g_work_queued, 0, 0);
        LONG work_running_before = _InterlockedCompareExchange(&g_work_running, 0, 0);
        LONG timer_initialized = _InterlockedCompareExchange(&g_timer_initialized, 0, 0);
        WW_LOG("dma_canary::timer_stop_entry reason=%s client=%u registered=%u count=%lu running_before=%ld queued_before=%ld work_running_before=%ld timer_init=%ld wait=%u irql=%lu",
            reason ? reason : "unknown",
            client_pid,
            registered_pid,
            g_canary_count,
            running_before,
            queued_before,
            work_running_before,
            timer_initialized,
            wait_for_work ? 1u : 0u,
            static_cast<ULONG>(KeGetCurrentIrql()));
        if (timer_initialized != 0) {
            KeCancelTimer(&g_timer);
            _InterlockedExchange(&g_timer_initialized, 0);
        }
        if (_KeFlushQueuedDpcs && KeGetCurrentIrql() < DISPATCH_LEVEL)
            _KeFlushQueuedDpcs();
        ensure_work_sync_initialized();
        NTSTATUS wait_status = STATUS_NOT_SUPPORTED;
        if (wait_for_work && KeGetCurrentIrql() == PASSIVE_LEVEL &&
            (_InterlockedCompareExchange(&g_work_queued, 0, 0) != 0 ||
             _InterlockedCompareExchange(&g_work_running, 0, 0) != 0)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50'000'000LL;
            wait_status = KeWaitForSingleObject(&g_work_done, Executive, KernelMode, FALSE, &timeout);
        }
        ULONGLONG end_time = KeQueryInterruptTime();
        WW_LOG("dma_canary::timer_stop_exit reason=%s client=%u registered=%u count=%lu running=%ld queued=%ld work_running=%ld wait_status=0x%08lx elapsed_us=%lu",
            reason ? reason : "unknown",
            client_pid,
            current_registered_client_pid(),
            g_canary_count,
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0),
            wait_status,
            elapsed_us_from_100ns(start_time, end_time));
    }

    __forceinline BOOLEAN query_tier_a_preloaded() {
        ULONG raw_cmd = static_cast<ULONG>(sentinel_bridge::g_bridge.sentinel_cmd);
        ULONG plain_cmd = sentinel_bridge::BRIDGE_CMD_TIER_A_PRE_LOADED;
        ULONG encoded_cmd = sentinel_bridge::BRIDGE_CMD_TIER_A_PRE_LOADED ^
            static_cast<ULONG>(sentinel_bridge::g_bridge_crypt_key & 0xFFFFFFFF);
        BOOLEAN present = raw_cmd == plain_cmd || raw_cmd == encoded_cmd;
        WW_LOG("dma_canary::query_tier_a_preloaded raw_cmd=0x%08lx plain_match=%u encoded_match=%u present=%u bridge=%p whoswho_tsc=%lld sentinel_tsc=%lld canary_count=%lu running=%ld queued=%ld work_running=%ld",
            raw_cmd,
            raw_cmd == plain_cmd ? 1u : 0u,
            raw_cmd == encoded_cmd ? 1u : 0u,
            present ? 1u : 0u,
            &sentinel_bridge::g_bridge,
            sentinel_bridge::g_bridge.whoswho_tsc,
            sentinel_bridge::g_bridge.sentinel_tsc,
            g_canary_count,
            _InterlockedCompareExchange(&g_running, 0, 0),
            _InterlockedCompareExchange(&g_work_queued, 0, 0),
            _InterlockedCompareExchange(&g_work_running, 0, 0));
        return present;
    }
}
