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

            volatile ULONG dummy = 0;
            for (volatile int i = 0; i < 10000; ++i)
                dummy += i;

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

            return deviation > threshold;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }


    constexpr LONG64 CHECK_INTERVAL = -100'000'000LL;

    inline KTIMER       g_timer = {};
    inline KDPC         g_dpc = {};
    inline volatile LONG g_cycle_count = 0;
    inline volatile LONG g_running = 0;
    inline volatile LONG g_timer_active = 0;


    static void NTAPI dpc_callback(
        PKDPC ,
        PVOID ,
        PVOID ,
        PVOID )
    {


        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) {
            SN_LOG("guardian::dpc: SKIP (already running)");
            return;
        }

        LONG cycle = _InterlockedIncrement(&g_cycle_count);
        SN_LOG("guardian::dpc: cycle=%ld", cycle);


        self_protect::verify_own_integrity();


        integrity::verify();
        if (integrity::g_integrity_strikes >= integrity::INTEGRITY_STRIKE_THRESHOLD) {
            heartbeat::send_command(heartbeat::BRIDGE_CMD_INTEGRITY_FAIL,
                static_cast<ULONG>(integrity::g_integrity_strikes));
        }


        dispatch_guard::verify();


        if ((cycle % 5) == 0) {
            SN_LOG("guardian::dpc: IPI clear (cycle %ld)", cycle);
            thread_guard::ipi_clear_all_cpus();
        }


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


        if ((cycle % 5) == 0) {
            callback_scanner::verify();
        }


        if ((cycle % 10) == 0) {
            pool_scrub::periodic_scrub();
        }

        if ((cycle % 3) == 0) {
            debug_port_trap::check(reinterpret_cast<HANDLE>(
                _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid), 0, 0)));
        }

        if ((cycle % 2) == 0) {
            vad_text_guard::check(reinterpret_cast<HANDLE>(
                _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&object_guard::g_protected_pid), 0, 0)));
        }

        if ((cycle % 7) == 0) {
            if (!heartbeat::verify_module_presence()) {
                SN_LOG("guardian::dpc: WhosWho UNLOADED from module list!");
            }
        }

        if ((cycle % 6) == 0) {
            heartbeat::verify_challenge_response();
            heartbeat::issue_challenge();
        }

        if ((cycle % 4) == 0) {
            if (!hv_allow_list::is_microsoft_hyperv_root()) {
                if (detect_lbr_interception()) {
                    SN_LOG("guardian::dpc: LBR interception detected - hostile HV");
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_RE_EVIDENCE, 0x0000AE01u);
                }
            }
        }

        if ((cycle % 8) == 0) {
            if (!hv_allow_list::is_microsoft_hyperv_root()) {
                if (!_InterlockedCompareExchange(&g_aperf_warmup_done, 0, 0)) {
                    if (cycle >= APERF_WARMUP_CYCLES)
                        _InterlockedExchange(&g_aperf_warmup_done, 1);
                } else if (detect_aperf_anomaly()) {
                    SN_LOG("guardian::dpc: APERF/MPERF anomaly detected - possible HV");
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_RE_EVIDENCE, 0x0000AE02u);
                }
            }
        }

        _InterlockedExchange(&g_running, 0);
        SN_LOG("guardian::dpc: cycle=%ld done", cycle);
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
            SN_LOG("guardian::start: MS Hyper-V root=%d (side-channel HV detectors %s)",
                (int)ms_hv, ms_hv ? "GATED" : "ACTIVE");
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
