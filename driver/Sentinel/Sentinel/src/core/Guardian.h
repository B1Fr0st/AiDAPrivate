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
#include <core/HyperVAllowList.h>
#include <core/DebugPortTrap.h>
#include <core/VadTextGuard.h>


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
        __try {
        cycle = _InterlockedIncrement(&g_cycle_count);
        SN_LOG("guardian::dpc: cycle=%ld", cycle);


        SN_LOG("guardian::dpc: calling heartbeat::update_and_check (bridge=%p init=%ld)",
            heartbeat::g_bridge, heartbeat::g_initialized);
        heartbeat::update_and_check();


        etw_disable::monitor_reenablement();
        if (etw_disable::g_provider_handle && _MmIsAddressValid((PVOID)etw_disable::g_provider_handle)) {
            __try {
                volatile UINT64 val = *static_cast<volatile UINT64*>((PVOID)etw_disable::g_provider_handle);
                if (val != 0) {
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_ETW_REACTIVATED, 0);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (integrity::g_integrity_strikes >= integrity::INTEGRITY_STRIKE_THRESHOLD) {
            heartbeat::send_command(heartbeat::BRIDGE_CMD_INTEGRITY_FAIL,
                static_cast<ULONG>(integrity::g_integrity_strikes));
        }

        self_protect::verify_own_integrity();

        integrity::verify();

        dispatch_guard::verify();

        SN_LOG("guardian::dpc: local debug register clear (cycle %ld)", cycle);
        thread_guard::check_and_clear_current_cpu();

        callback_scanner::verify();

        pool_scrub::periodic_scrub();

        debug_port_trap::check(reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid), 0, 0)));

        vad_text_guard::check(reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid), 0, 0)));

        if (!heartbeat::verify_module_presence()) {
            SN_LOG("guardian::dpc: WhosWho UNLOADED from module list!");
        }

        heartbeat::verify_challenge_response();
        heartbeat::issue_challenge();

        BOOLEAN ms_hv_root = hv_allow_list::is_microsoft_hyperv_root();
        BOOLEAN vbs_hvci = hv_allow_list::has_vbs_or_hvci();
        if (!ms_hv_root && !vbs_hvci) {
            if (detect_lbr_interception()) {
                SN_LOG("guardian::dpc: LBR interception detected - hostile HV");
                heartbeat::send_command(heartbeat::BRIDGE_CMD_RE_EVIDENCE, 0x0000AE01u);
            }

            if (!_InterlockedCompareExchange(&g_aperf_warmup_done, 0, 0)) {
                if (cycle >= APERF_WARMUP_CYCLES)
                    _InterlockedExchange(&g_aperf_warmup_done, 1);
            } else if (detect_aperf_anomaly()) {
                LONG consecutive = _InterlockedIncrement(&g_aperf_consecutive_anomalies);
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
            }
        } else if (cycle == APERF_WARMUP_CYCLES || cycle == APERF_WARMUP_CYCLES + 1) {
            SN_LOG("guardian::dpc: side-channel HV detectors gated ms_hv_root=%d vbs_hvci=%d", (int)ms_hv_root, (int)vbs_hvci);
        }

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("guardian::work: EXCEPTION");
        }

        _InterlockedExchange(&g_running, 0);
        _InterlockedExchange(&g_work_item_queued, 0);
        if (cycle != 0)
            SN_LOG("guardian::dpc: cycle=%ld done", cycle);
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

        LARGE_INTEGER due_time;
        due_time.QuadPart = CHECK_INTERVAL;


        _KeSetTimerEx(&g_timer, due_time, 10000, &g_dpc);

        _InterlockedExchange(&g_timer_active, 1);
        SN_LOG("guardian::start: SUCCESS - timer active, interval=%lld period=10000ms", CHECK_INTERVAL);
        return true;
    }


    __forceinline void stop() {
        if (!_InterlockedCompareExchange(&g_timer_active, 0, 1))
            return;

        if (_KeCancelTimer)
            _KeCancelTimer(&g_timer);


        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
    }
}
