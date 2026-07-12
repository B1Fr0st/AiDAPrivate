#pragma once
#include <core/SelfProtect.h>
#include <core/Integrity.h>
#include <core/DispatchGuard.h>
#include <core/ThreadGuard.h>
#include <core/Heartbeat.h>
#include <core/EtwDisable.h>
#include <core/CallbackScanner.h>
#include <core/PoolScrub.h>
#include <core/ObjectGuard.h>
#include <core/ProcessNotify.h>
#include <core/HyperVAllowList.h>
#include <core/DebugPortTrap.h>
#include <core/VadTextGuard.h>
#include <core/WskTransport.h>
#include <core/ModuleCrossCheck.h>
#include <core/Attestation.h>


namespace guardian {

    constexpr ULONG MSR_LBR_TOS         = 0x1C9u;
    constexpr ULONG MSR_DEBUGCTL         = 0x1D9u;
    constexpr ULONG MSR_APERF            = 0xE8u;
    constexpr ULONG MSR_MPERF            = 0xE7u;

    inline volatile LONG g_lbr_baseline_captured = 0;
    inline volatile LONG g_lbr_baseline_available = 0;
    inline volatile LONG g_aperf_baseline_captured = 0;
    inline volatile UINT64 g_aperf_ratio_baseline = 0;
    inline volatile UINT64 g_aperf_last_ratio = 0;
    inline volatile UINT64 g_aperf_last_deviation = 0;
    inline volatile UINT64 g_aperf_last_threshold = 0;
    inline volatile LONG g_aperf_consecutive_anomalies = 0;
    inline volatile LONG g_hv_gate_logged = 0;

    constexpr LONG APERF_WARMUP_CYCLES = 30;
    constexpr LONG APERF_SAMPLE_COUNT = 7;
    inline volatile LONG g_aperf_warmup_done = 0;
    inline volatile LONG g_aperf_sample_index = 0;
    inline UINT64 g_aperf_samples[APERF_SAMPLE_COUNT] = {};

    __forceinline bool detect_lbr_interception()
    {
        if (!_InterlockedCompareExchange(&g_lbr_baseline_available, 0, 0))
        {
            __try {
                UINT64 debugctl = __readmsr(MSR_DEBUGCTL);
                (void)debugctl;
                _InterlockedExchange(&g_lbr_baseline_available, 1);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
            return false;
        }

        __try {
            UINT64 debugctl_before = __readmsr(MSR_DEBUGCTL);
            UINT64 modified = debugctl_before | 1ULL;
            __writemsr(MSR_DEBUGCTL, modified);
            UINT64 debugctl_after = __readmsr(MSR_DEBUGCTL);
            __writemsr(MSR_DEBUGCTL, debugctl_before);

            if ((debugctl_after & 1ULL) == 0 && (modified & 1ULL) != 0)
                return true;

            UINT64 lbr_tos = __readmsr(MSR_LBR_TOS);
            (void)lbr_tos;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true;
        }

        return false;
    }

    __forceinline UINT64 aperf_median_of_samples() {
        UINT64 sorted[APERF_SAMPLE_COUNT];
        for (int i = 0; i < APERF_SAMPLE_COUNT; i++)
            sorted[i] = g_aperf_samples[i];
        for (int i = 0; i < APERF_SAMPLE_COUNT - 1; i++) {
            for (int j = i + 1; j < APERF_SAMPLE_COUNT; j++) {
                if (sorted[j] < sorted[i]) {
                    UINT64 tmp = sorted[i];
                    sorted[i] = sorted[j];
                    sorted[j] = tmp;
                }
            }
        }
        return sorted[APERF_SAMPLE_COUNT / 2];
    }

    __forceinline bool detect_aperf_anomaly()
    {
        __try {
            UINT64 aperf1 = __readmsr(MSR_APERF);
            UINT64 mperf1 = __readmsr(MSR_MPERF);

            KeStallExecutionProcessor(50);

            UINT64 aperf2 = __readmsr(MSR_APERF);
            UINT64 mperf2 = __readmsr(MSR_MPERF);

            UINT64 aperf_delta = aperf2 - aperf1;
            UINT64 mperf_delta = mperf2 - mperf1;

            if (mperf_delta == 0)
                return false;

            UINT64 ratio = (aperf_delta * 1000) / mperf_delta;

            if (!_InterlockedCompareExchange(&g_aperf_warmup_done, 0, 0))
                return false;

            if (!_InterlockedCompareExchange(&g_aperf_baseline_captured, 0, 0))
            {
                LONG idx = _InterlockedIncrement(&g_aperf_sample_index) - 1;
                if (idx < APERF_SAMPLE_COUNT) {
                    g_aperf_samples[idx] = ratio;
                    return false;
                }
                UINT64 median = aperf_median_of_samples();
                _InterlockedExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_ratio_baseline),
                    static_cast<LONG64>(median));
                _InterlockedExchange(&g_aperf_baseline_captured, 1);
                return false;
            }

            UINT64 baseline = static_cast<UINT64>(
                _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_ratio_baseline), 0, 0));

            if (baseline == 0)
                return false;

            UINT64 deviation = (ratio > baseline) ? (ratio - baseline) : (baseline - ratio);
            UINT64 threshold = baseline / 3;
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_aperf_last_ratio),
                static_cast<LONG64>(ratio));
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_aperf_last_deviation),
                static_cast<LONG64>(deviation));
            _InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&g_aperf_last_threshold),
                static_cast<LONG64>(threshold));

            return deviation > threshold;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }


    constexpr LONG64 CHECK_INTERVAL = -100'000'000LL;

    inline KTIMER       g_timer = {};
    inline KDPC         g_dpc = {};
    inline WORK_QUEUE_ITEM g_work_item = {};
    inline volatile LONG g_cycle_count = 0;
    inline volatile LONG g_running = 0;
    inline volatile LONG g_timer_active = 0;
    inline volatile LONG g_work_item_queued = 0;
    inline volatile LONG g_idle_backoff_count = 0;

    struct perf_stamp_t {
        LARGE_INTEGER counter;
        LARGE_INTEGER freq;
    };

    struct session_state_t {
        BOOLEAN initialized;
        BOOLEAN bridge_valid;
        BOOLEAN first_heartbeat_seen;
        BOOLEAN heartbeat_fresh;
        BOOLEAN active;
        HANDLE object_protected_pid;
        HANDLE notify_protected_pid;
        UINT64 whoswho_tsc;
        UINT64 last_whoswho_tsc;
        UINT64 last_check_tsc;
        UINT64 elapsed_tsc;
    };

    __forceinline perf_stamp_t perf_mark()
    {
        perf_stamp_t mark = {};
        mark.counter = KeQueryPerformanceCounter(&mark.freq);
        return mark;
    }

    __forceinline ULONG perf_elapsed_us(perf_stamp_t mark)
    {
        LARGE_INTEGER end = KeQueryPerformanceCounter(nullptr);
        if (mark.freq.QuadPart <= 0 || end.QuadPart < mark.counter.QuadPart)
            return 0;
        ULONGLONG delta = static_cast<ULONGLONG>(end.QuadPart - mark.counter.QuadPart);
        return static_cast<ULONG>((delta * 1000000ULL) / static_cast<ULONGLONG>(mark.freq.QuadPart));
    }

    __forceinline session_state_t snapshot_session_state()
    {
        session_state_t state = {};
        state.initialized = _InterlockedCompareExchange(&heartbeat::g_initialized, 1, 1) ? TRUE : FALSE;
        state.first_heartbeat_seen = _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0) ? TRUE : FALSE;
        state.object_protected_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid), 0, 0));
        state.notify_protected_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));
        state.last_whoswho_tsc = heartbeat::g_last_whoswho_tsc;
        state.last_check_tsc = heartbeat::g_last_check_tsc;

        if (heartbeat::g_bridge && (!_MmIsAddressValid || _MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge))))) {
            state.bridge_valid = TRUE;
            __try {
                state.whoswho_tsc = static_cast<UINT64>(heartbeat::g_bridge->whoswho_tsc);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                state.bridge_valid = FALSE;
                state.whoswho_tsc = 0;
            }
        }

        UINT64 now = __rdtsc();
        if (state.last_check_tsc != 0 && now >= state.last_check_tsc)
            state.elapsed_tsc = now - state.last_check_tsc;
        if (state.first_heartbeat_seen && state.bridge_valid && state.whoswho_tsc != 0 &&
            state.last_check_tsc != 0 && state.elapsed_tsc <= heartbeat::HEARTBEAT_TIMEOUT_TSC) {
            state.heartbeat_fresh = TRUE;
        }
        state.active = (state.object_protected_pid || state.notify_protected_pid) ? TRUE : FALSE;
        return state;
    }

    static void NTAPI work_item_callback(PVOID)
    {
        if (!_InterlockedCompareExchange(&g_timer_active, 1, 1)) {
            _InterlockedExchange(&g_work_item_queued, 0);
            return;
        }

        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) {
            SN_LOG("guardian::work: SKIP (already running)");
            _InterlockedExchange(&g_work_item_queued, 0);
            return;
        }

        LONG cycle = 0;
        perf_stamp_t cycle_mark = perf_mark();
        session_state_t session = {};
        __try {
        cycle = _InterlockedIncrement(&g_cycle_count);

        perf_stamp_t step = perf_mark();
        bool heartbeat_ok = heartbeat::update_and_check();
        ULONG step_us = perf_elapsed_us(step);
        session = snapshot_session_state();
        if (!heartbeat_ok || !session.bridge_valid || !session.heartbeat_fresh) {
            SN_LOG("guardian::step cycle=%ld name=heartbeat elapsed_us=%lu result=%u init=%u bridge_valid=%u first_seen=%u heartbeat_fresh=%u bridge=%p whoswho_tsc=%llu last_whoswho_tsc=%llu last_check_tsc=%llu elapsed_tsc=%llu",
                cycle,
                step_us,
                heartbeat_ok ? 1u : 0u,
                session.initialized ? 1u : 0u,
                session.bridge_valid ? 1u : 0u,
                session.first_heartbeat_seen ? 1u : 0u,
                session.heartbeat_fresh ? 1u : 0u,
                heartbeat::g_bridge,
                static_cast<unsigned long long>(session.whoswho_tsc),
                static_cast<unsigned long long>(session.last_whoswho_tsc),
                static_cast<unsigned long long>(session.last_check_tsc),
                static_cast<unsigned long long>(session.elapsed_tsc));
        }

        if (!session.active) {
            _InterlockedIncrement(&g_idle_backoff_count);
        } else {
        _InterlockedExchange(&g_idle_backoff_count, 0);

        step = perf_mark();
        etw_disable::monitor_reenablement();
        BOOLEAN etw_reactivated = FALSE;
        if (etw_disable::g_provider_handle && _MmIsAddressValid((PVOID)etw_disable::g_provider_handle)) {
            __try {
                volatile UINT64 val = *static_cast<volatile UINT64*>((PVOID)etw_disable::g_provider_handle);
                if (val != 0) {
                    etw_reactivated = TRUE;
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_ETW_REACTIVATED, 0);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        SN_LOG("guardian::step cycle=%ld name=etw elapsed_us=%lu provider=%p reactivated=%u",
            cycle,
            perf_elapsed_us(step),
            (PVOID)etw_disable::g_provider_handle,
            etw_reactivated ? 1u : 0u);

        step = perf_mark();
        BOOLEAN integrity_fail_sent = FALSE;
        SN_LOG("guardian::step cycle=%ld name=integrity_strikes elapsed_us=%lu sent=%u",
            cycle,
            perf_elapsed_us(step),
            integrity_fail_sent ? 1u : 0u);

        step = perf_mark();
        bool self_ok = self_protect::verify_own_integrity();
        SN_LOG("guardian::step cycle=%ld name=self_protect elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            self_ok ? 1u : 0u);

        step = perf_mark();
        bool ssdt_ok = self_protect::ssdt_verify();
        SN_LOG("guardian::step cycle=%ld name=ssdt_verify elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            ssdt_ok ? 1u : 0u);

        step = perf_mark();
        bool integrity_ok = integrity::verify();
        SN_LOG("guardian::step cycle=%ld name=integrity elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            integrity_ok ? 1u : 0u);

        step = perf_mark();
        bool dispatch_ok = dispatch_guard::verify();
        SN_LOG("guardian::step cycle=%ld name=dispatch_guard elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            dispatch_ok ? 1u : 0u);

        if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
            UINT8 dg_hook = 0;
            UINT64 dg_target = 0;
            dispatch_guard::query_status(dg_hook, dg_target);
            const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->dispatch_hook_detected = dg_hook;
            const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->dispatch_hook_target = dg_target;
        }

        step = perf_mark();
        thread_guard::check_and_clear_current_cpu();
        SN_LOG("guardian::step cycle=%ld name=thread_guard elapsed_us=%lu",
            cycle,
            perf_elapsed_us(step));

        step = perf_mark();
        bool callback_ok = callback_scanner::verify();
        SN_LOG("guardian::step cycle=%ld name=callback_scanner elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            callback_ok ? 1u : 0u);

        if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
            const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->hostile_drivers =
                callback_scanner::g_hostile_driver_loads > 0 ? 1 : 0;
            const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->modified_callbacks =
                callback_ok ? 0 : 1;
        }

        step = perf_mark();
        pool_scrub::periodic_scrub();
        SN_LOG("guardian::step cycle=%ld name=pool_scrub elapsed_us=%lu",
            cycle,
            perf_elapsed_us(step));

        if ((cycle % 30) == 0 && session.active) {
            step = perf_mark();
            process_notify::detect_ce_driver();
            SN_LOG("guardian::step cycle=%ld name=ce_driver_scan elapsed_us=%lu",
                cycle,
                perf_elapsed_us(step));
        }

        HANDLE protected_pid = session.object_protected_pid ? session.object_protected_pid : session.notify_protected_pid;

        step = perf_mark();
        debug_port_trap::check(protected_pid);
        SN_LOG("guardian::step cycle=%ld name=debug_port_trap elapsed_us=%lu protected_pid=%llu",
            cycle,
            perf_elapsed_us(step),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));

        step = perf_mark();
        vad_text_guard::check_with_content(protected_pid);
        SN_LOG("guardian::step cycle=%ld name=vad_text_guard_with_content elapsed_us=%lu protected_pid=%llu",
            cycle,
            perf_elapsed_us(step),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));

        if ((cycle % 5) == 0 && session.active) {
            step = perf_mark();
            vad_text_guard::check_header_region_intact(protected_pid);
            SN_LOG("guardian::step cycle=%ld name=header_region_intact elapsed_us=%lu protected_pid=%llu",
                cycle,
                perf_elapsed_us(step),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));
        }

        if ((cycle % 10) == 0 && session.active) {
            step = perf_mark();
            vad_text_guard::monitor_text_page_access(protected_pid);
            SN_LOG("guardian::step cycle=%ld name=monitor_text_page_access elapsed_us=%lu protected_pid=%llu",
                cycle,
                perf_elapsed_us(step),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));
        }

        step = perf_mark();
        bool module_present = heartbeat::verify_module_presence();
        if (!module_present) {
            SN_LOG("guardian::dpc: WhosWho UNLOADED from module list!");
        }
        SN_LOG("guardian::step cycle=%ld name=module_presence elapsed_us=%lu result=%u",
            cycle,
            perf_elapsed_us(step),
            module_present ? 1u : 0u);

        step = perf_mark();
        heartbeat::verify_challenge_response();
        SN_LOG("guardian::step cycle=%ld name=challenge_verify elapsed_us=%lu",
            cycle,
            perf_elapsed_us(step));
        step = perf_mark();
        heartbeat::process_reverse_challenge();
        SN_LOG("guardian::step cycle=%ld name=reverse_challenge elapsed_us=%lu",
            cycle,
            perf_elapsed_us(step));
        step = perf_mark();
        heartbeat::issue_challenge();
        SN_LOG("guardian::step cycle=%ld name=challenge_issue elapsed_us=%lu",
            cycle,
            perf_elapsed_us(step));

        step = perf_mark();
        BOOLEAN ms_hv_root = hv_allow_list::is_microsoft_hyperv_root();
        BOOLEAN vbs_hvci = hv_allow_list::has_vbs_or_hvci();
        BOOLEAN lbr_detected = FALSE;
        BOOLEAN aperf_detected = FALSE;
        LONG aperf_consecutive = _InterlockedCompareExchange(&g_aperf_consecutive_anomalies, 0, 0);
        if (!ms_hv_root && !vbs_hvci) {
            if (detect_lbr_interception()) {
                lbr_detected = TRUE;
                SN_LOG("guardian::dpc: LBR interception detected - hostile HV");
                heartbeat::send_command(heartbeat::BRIDGE_CMD_RE_EVIDENCE, 0x0000AE01u);
            }

            if (!_InterlockedCompareExchange(&g_aperf_warmup_done, 0, 0)) {
                if (cycle >= APERF_WARMUP_CYCLES)
                    _InterlockedExchange(&g_aperf_warmup_done, 1);
            } else if (detect_aperf_anomaly()) {
                LONG consecutive = _InterlockedIncrement(&g_aperf_consecutive_anomalies);
                aperf_detected = TRUE;
                aperf_consecutive = consecutive;
                UINT64 ratio = static_cast<UINT64>(_InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_last_ratio), 0, 0));
                UINT64 baseline = static_cast<UINT64>(_InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_ratio_baseline), 0, 0));
                UINT64 deviation = static_cast<UINT64>(_InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_last_deviation), 0, 0));
                UINT64 threshold = static_cast<UINT64>(_InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_aperf_last_threshold), 0, 0));
                SN_LOG("guardian::dpc: APERF/MPERF anomaly cycle=%ld consecutive=%ld ratio=%llu baseline=%llu deviation=%llu threshold=%llu ms_hv_root=%d vbs_hvci=%d",
                    cycle,
                    consecutive,
                    static_cast<unsigned long long>(ratio),
                    static_cast<unsigned long long>(baseline),
                    static_cast<unsigned long long>(deviation),
                    static_cast<unsigned long long>(threshold),
                    (int)ms_hv_root,
                    (int)vbs_hvci);
                if (consecutive >= 3) {
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_RE_EVIDENCE, 0x0000AE02u);
                }
            } else {
                _InterlockedExchange(&g_aperf_consecutive_anomalies, 0);
                aperf_consecutive = 0;
            }
        } else if (cycle == APERF_WARMUP_CYCLES || cycle == APERF_WARMUP_CYCLES + 1) {
            SN_LOG("guardian::dpc: side-channel HV detectors gated ms_hv_root=%d vbs_hvci=%d", (int)ms_hv_root, (int)vbs_hvci);
        }
        SN_LOG("guardian::step cycle=%ld name=sidechannel elapsed_us=%lu ms_hv_root=%d vbs_hvci=%d lbr=%u aperf=%u aperf_consecutive=%ld warmup=%ld",
            cycle,
            perf_elapsed_us(step),
            (int)ms_hv_root,
            (int)vbs_hvci,
            lbr_detected ? 1u : 0u,
            aperf_detected ? 1u : 0u,
            aperf_consecutive,
            _InterlockedCompareExchange(&g_aperf_warmup_done, 0, 0));

        step = perf_mark();
        BOOLEAN dma_cmd_processed = FALSE;
        if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
            __try {
                ULONG raw_dma_cmd = _InterlockedCompareExchange(
                    (volatile LONG*)&heartbeat::g_bridge->sentinel_cmd, 0, 0);
                ULONG raw_dma_param = _InterlockedCompareExchange(
                    (volatile LONG*)&heartbeat::g_bridge->sentinel_cmd_param, 0, 0);
                if (raw_dma_cmd != 0) {
                    ULONG dma_cmd = raw_dma_cmd;
                    ULONG dma_param = raw_dma_param;
                    heartbeat::bridge_encrypt_cmd(dma_cmd, dma_param);
                    if (dma_cmd == heartbeat::BRIDGE_CMD_DMA_KEY_SCRUB ||
                        dma_cmd == heartbeat::BRIDGE_CMD_DMA_BSOD ||
                        dma_cmd == heartbeat::BRIDGE_CMD_DMA_ATTACK_REPORT ||
                        dma_cmd == heartbeat::BRIDGE_CMD_CANARY_FOREIGN_PT) {

                        SN_LOG("guardian::dpc: DMA bridge command cmd=0x%lx param=0x%lx cycle=%ld",
                            dma_cmd, dma_param, cycle);

                        _InterlockedExchange(&heartbeat::g_dma_tier1_refused, 1);
                        _InterlockedIncrement(&heartbeat::g_dma_canary_hits);

                        wsk_transport::queue_dma_report(dma_cmd, dma_param);
                        dma_cmd_processed = TRUE;

                        if (dma_cmd == heartbeat::BRIDGE_CMD_DMA_BSOD ||
                            dma_cmd == heartbeat::BRIDGE_CMD_CANARY_FOREIGN_PT) {
                            SN_LOG("guardian::dpc: DMA_BSOD triggered cmd=0x%lx param=0x%lx - KeBugCheckEx NOW",
                                dma_cmd, dma_param);
                            if (_KeBugCheckEx)
                                _KeBugCheckEx(heartbeat::BUGCHECK_DMA_ATTACK, dma_param, 0, 0, 0);
                        }
                    }

                    if (dma_cmd == heartbeat::BRIDGE_CMD_UPDATE_CE_HASHES) {
                        ULONG ce_count = dma_param;
                        if (ce_count > 32) ce_count = 32;
                        SN_LOG("guardian::dpc: UPDATE_CE_HASHES count=%lu cycle=%ld", ce_count, cycle);
                        if (ce_count > 0) {
                            process_notify::update_ce_driver_hashes(
                                const_cast<PUCHAR>(
                                    reinterpret_cast<const UCHAR*>(
                                        heartbeat::g_bridge->ce_driver_hash_data)),
                                ce_count);
                        }
                        _InterlockedExchange(
                            (volatile LONG*)&heartbeat::g_bridge->sentinel_cmd,
                            heartbeat::BRIDGE_CMD_NONE);
                        _InterlockedExchange(
                            (volatile LONG*)&heartbeat::g_bridge->sentinel_cmd_param,
                            0);
                        dma_cmd_processed = TRUE;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                SN_LOG("guardian::work: DMA bridge check EXCEPTION");
            }
        }
        SN_LOG("guardian::step cycle=%ld name=dma_bridge elapsed_us=%lu processed=%u",
            cycle,
            perf_elapsed_us(step),
            dma_cmd_processed ? 1u : 0u);

        step = perf_mark();
        if ((cycle % 60) == 0 && session.active) {
            attestation::attest_with_integrity_t attest = {};
            NTSTATUS attest_st = attestation::compute_attest_with_integrity(attest);
            if (NT_SUCCESS(attest_st)) {
                wsk_transport::send_attestation(&attest, sizeof(attest));
                SN_LOG("guardian::step cycle=%ld name=attestation elapsed_us=%lu status=0x%08lx",
                    cycle, perf_elapsed_us(step), attest_st);
            } else {
                SN_LOG("guardian::step cycle=%ld name=attestation elapsed_us=%lu status=0x%08lx FAILED",
                    cycle, perf_elapsed_us(step), attest_st);
            }
        }

        if ((cycle % 30) == 0 && session.active) {
            step = perf_mark();
            BOOLEAN wm_has_expected = FALSE;
            if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                    const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
                __try {
                    volatile UINT8 exp[16];
                    BOOLEAN any_nonzero = FALSE;
                    for (int i = 0; i < 16; ++i) {
                        exp[i] = heartbeat::g_bridge->expected_watermark[i];
                        if (exp[i] != 0) any_nonzero = TRUE;
                    }
                    wm_has_expected = any_nonzero;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    SN_LOG("guardian::step cycle=%ld name=watermark_verify elapsed_us=%lu result=bridge_read_exception",
                        cycle, perf_elapsed_us(step));
                }
            }

            if (wm_has_expected) {
                HANDLE protected_pid = session.object_protected_pid ?
                    session.object_protected_pid : session.notify_protected_pid;
                if (protected_pid && (ULONG_PTR)protected_pid > 4) {
                    PEPROCESS proc = nullptr;
                    NTSTATUS lookup_st = PsLookupProcessByProcessId(protected_pid, &proc);
                    if (NT_SUCCESS(lookup_st) && proc) {
                        UINT8 expected_wm[16];
                        if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
                            for (int i = 0; i < 16; ++i)
                                expected_wm[i] = heartbeat::g_bridge->expected_watermark[i];
                        } else {
                            RtlZeroMemory(expected_wm, 16);
                        }

                        BOOLEAN wm_match = attestation::verify_watermark(proc, expected_wm);

                        if (heartbeat::g_bridge && _MmIsAddressValid(reinterpret_cast<PVOID>(
                                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)))) {
                            __try {
                                for (int i = 0; i < 16; ++i)
                                    const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->actual_watermark[i] =
                                        attestation::g_watermark_state.actual_watermark[i];
                                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge)->watermark_verified = wm_match;
                            } __except (EXCEPTION_EXECUTE_HANDLER) {}
                        }

                        _ObfDereferenceObject(proc);

                        SN_LOG("guardian::step cycle=%ld name=watermark_verify elapsed_us=%lu match=%u pid=%llu",
                            cycle, perf_elapsed_us(step), wm_match ? 1u : 0u,
                            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));

                        if (!wm_match) {
                            SN_LOG("guardian::watermark_mismatch: BSOD pid=%llu magic=0x%08lx",
                                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)),
                                static_cast<ULONG>(AIDA_WATERMARK_MAGIC));
#ifndef AIDA_DEV_MODE
                            if (_KeBugCheckEx)
                                _KeBugCheckEx(static_cast<ULONG>(BUGCHECK_MODULE_CROSSCHECK),
                                    (ULONG_PTR)protected_pid,
                                    (ULONG_PTR)AIDA_WATERMARK_MAGIC,
                                    0, 0);
#endif
                        }
                    } else {
                        SN_LOG("guardian::step cycle=%ld name=watermark_verify elapsed_us=%lu result=lookup_failed status=0x%08lx pid=%llu",
                            cycle, perf_elapsed_us(step), lookup_st,
                            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(protected_pid)));
                    }
                }
            } else {
                SN_LOG("guardian::step cycle=%ld name=watermark_verify elapsed_us=%lu result=no_expected_watermark",
                    cycle, perf_elapsed_us(step));
            }
        }
        }

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("guardian::work: EXCEPTION");
        }

        _InterlockedExchange(&g_running, 0);
        _InterlockedExchange(&g_work_item_queued, 0);
        ULONG total_us = perf_elapsed_us(cycle_mark);
        if (cycle != 0 && (session.active || total_us >= 5000))
            SN_LOG("guardian::dpc: cycle=%ld done total_us=%lu active=%u idle_backoff=%ld",
                cycle,
                total_us,
                session.active ? 1u : 0u,
                _InterlockedCompareExchange(&g_idle_backoff_count, 0, 0));
    }

    static void NTAPI dpc_callback(
        PKDPC ,
        PVOID ,
        PVOID ,
        PVOID )
    {
        if (!_InterlockedCompareExchange(&g_timer_active, 1, 1))
            return;
        if (_InterlockedCompareExchange(&g_work_item_queued, 1, 0) != 0)
            return;

        ExInitializeWorkItem(&g_work_item, work_item_callback, nullptr);
        if (_ExQueueWorkItem)
            _ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
        else
            ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
    }


    __forceinline bool start() {
        SN_LOG("guardian::start: checking function pointers");
        if (!_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx) {
            SN_LOG("guardian::start: FAIL - missing function pointers: dpc=%p timer=%p settimer=%p",
                _KeInitializeDpc, _KeInitializeTimerEx, _KeSetTimerEx);
            return false;
        }

        if (!_InterlockedCompareExchange(&g_hv_gate_logged, 1, 0)) {
            BOOLEAN ms_hv = hv_allow_list::is_microsoft_hyperv_root();
            BOOLEAN vbs_hvci = hv_allow_list::has_vbs_or_hvci();
            SN_LOG("guardian::start: MS Hyper-V root=%d VBS/HVCI=%d (side-channel HV detectors %s)",
                (int)ms_hv, (int)vbs_hvci, (ms_hv || vbs_hvci) ? "GATED" : "ACTIVE");
        }


        _KeInitializeTimerEx(&g_timer, NotificationTimer);
        _KeInitializeDpc(&g_dpc, dpc_callback, nullptr);

        targeting_latch::init();

        self_protect::ssdt_snapshot();

        LARGE_INTEGER due_time;
        due_time.QuadPart = CHECK_INTERVAL;


        _KeSetTimerEx(&g_timer, due_time, 10000, &g_dpc);

        _InterlockedExchange(&g_timer_active, 1);
        _InterlockedExchange(&heartbeat::g_dma_tier2_bsod_armed, 1);

        module_cross_check::start();

        SN_LOG("guardian::start: SUCCESS - timer active, interval=%lld period=10000ms", CHECK_INTERVAL);
        return true;
    }


    __forceinline void stop() {
        if (!_InterlockedCompareExchange(&g_timer_active, 0, 1))
            return;

        module_cross_check::stop();

        if (_KeCancelTimer)
            _KeCancelTimer(&g_timer);


        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
    }
}
