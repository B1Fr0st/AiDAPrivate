#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#include "../../helpers/diag_log.hpp"
#include "../../infra/win_thread.hpp"
#include "../runtime/manual_map_tls.hpp"
#include "metadata_ring.hpp"
#include "wer_correlation.hpp"

namespace aida::diagnostics::observer {

struct observer_config_t {
    std::uint32_t poll_interval_ms = 5000;
    std::uint32_t hung_threshold_ms = 5000;
    std::uint32_t max_lifetime_ms = 600000;
    std::uint32_t wm_null_timeout_ms = 200;
    bool enabled = true;
};

struct observer_state_t {
    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};
    std::atomic<std::uint64_t> poll_count{0};
    std::atomic<std::uint64_t> hang_detected_count{0};
    std::atomic<std::uint64_t> wer_correlation_count{0};
    std::atomic<std::uint64_t> heartbeat_tick_ms{0};
    std::atomic<DWORD> observed_pid{0};
    std::atomic<HWND> observed_hwnd{nullptr};
    std::atomic<std::uint64_t> start_ms{0};
    std::mutex mtx;
    observer_config_t config;
};

inline observer_state_t& state() {
    static observer_state_t s;
    return s;
}

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

struct observer_hang_record_t {
    std::uint64_t timestamp_ms;
    DWORD pid;
    HWND hwnd;
    BOOL is_hung;
    BOOL send_wm_null_ok;
    DWORD send_wm_null_gle;
    DWORD_PTR send_wm_null_lresult;
    BOOL process_alive;
    DWORD exit_code;
    std::uint64_t heartbeat_age_ms;
    std::uint64_t poll_index;
};

inline void log_observer_start(DWORD pid, HWND hwnd) {
    diag::log_tagged_critical_fmt("diag",
        "OBSERVER-START pid=%lu hwnd=0x%llX observer_tid=%lu poll_interval_ms=%u hung_threshold_ms=%u max_lifetime_ms=%u",
        static_cast<unsigned long>(pid),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long>(GetCurrentThreadId()),
        state().config.poll_interval_ms,
        state().config.hung_threshold_ms,
        state().config.max_lifetime_ms);

    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::observer;
    opts.label = "observer_start";
    opts.reason = "out_of_process_diagnostics_observer_started";
    opts.owner_subsystem = "diagnostics_observer";
    opts.force = true;
    metadata_ring::emit(std::move(opts));
}

inline void log_observer_heartbeat(std::uint64_t poll_index, DWORD pid, HWND hwnd, bool process_alive, bool hwnd_responsive) {
    diag::log_tagged_fmt("diag",
        "OBSERVER-HEARTBEAT poll=%llu pid=%lu hwnd=0x%llX process_alive=%d hwnd_responsive=%d heartbeat_age_ms=%llu",
        static_cast<unsigned long long>(poll_index),
        static_cast<unsigned long>(pid),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        process_alive ? 1 : 0,
        hwnd_responsive ? 1 : 0,
        static_cast<unsigned long long>(now_ms() - state().heartbeat_tick_ms.load(std::memory_order_acquire)));
}

inline void log_observer_hang(const observer_hang_record_t& rec) {
    diag::log_tagged_critical_fmt("diag",
        "OBSERVER-HANG poll=%llu pid=%lu hwnd=0x%llX is_hung=%d send_wm_null_ok=%d send_wm_null_gle=%lu send_wm_null_lresult=0x%llX process_alive=%d exit_code=0x%08lX heartbeat_age_ms=%llu timestamp_ms=%llu",
        static_cast<unsigned long long>(rec.poll_index),
        static_cast<unsigned long>(rec.pid),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rec.hwnd)),
        rec.is_hung ? 1 : 0,
        rec.send_wm_null_ok ? 1 : 0,
        static_cast<unsigned long>(rec.send_wm_null_gle),
        static_cast<unsigned long long>(rec.send_wm_null_lresult),
        rec.process_alive ? 1 : 0,
        static_cast<unsigned long>(rec.exit_code),
        static_cast<unsigned long long>(rec.heartbeat_age_ms),
        static_cast<unsigned long long>(rec.timestamp_ms));

    wer::log_wer_correlation("observer_hang");

    const std::string log_paths = wer::known_log_paths_summary();
    diag::log_tagged_critical_fmt("diag",
        "OBSERVER-HANG-LOG-PATHS pid=%lu log_paths=%s",
        static_cast<unsigned long>(rec.pid),
        log_paths.c_str());

    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::observer;
    opts.label = "observer_hang_detected";
    opts.reason = "ui_thread_unresponsive";
    opts.owner_subsystem = "diagnostics_observer";
    opts.force = true;
    metadata_ring::emit(std::move(opts));
}

inline void log_observer_stop() {
    diag::log_tagged_critical_fmt("diag",
        "OBSERVER-STOP pid=%lu polls=%llu hangs_detected=%llu wer_correlations=%llu uptime_ms=%llu",
        static_cast<unsigned long>(state().observed_pid.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(state().poll_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(state().hang_detected_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(state().wer_correlation_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(now_ms() - state().start_ms.load(std::memory_order_acquire)));

    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::observer;
    opts.label = "observer_stop";
    opts.reason = "out_of_process_diagnostics_observer_stopped";
    opts.owner_subsystem = "diagnostics_observer";
    opts.force = true;
    metadata_ring::emit(std::move(opts));
}

inline void observer_loop(DWORD pid, HWND hwnd) {
    aida::manual_map_tls::ensure_current_thread();

    auto& s = state();
    s.observed_pid.store(pid, std::memory_order_release);
    s.observed_hwnd.store(hwnd, std::memory_order_release);
    s.start_ms.store(now_ms(), std::memory_order_release);
    s.heartbeat_tick_ms.store(now_ms(), std::memory_order_release);

    log_observer_start(pid, hwnd);

    while (!s.stop_requested.load(std::memory_order_acquire)) {
        const std::uint64_t elapsed = now_ms() - s.start_ms.load(std::memory_order_acquire);
        if (elapsed >= s.config.max_lifetime_ms) {
            diag::log_tagged_fmt("diag",
                "OBSERVER-LIFETIME-EXCEEDED elapsed_ms=%llu max_lifetime_ms=%u",
                static_cast<unsigned long long>(elapsed),
                s.config.max_lifetime_ms);
            break;
        }

        const std::uint64_t poll_index = s.poll_count.fetch_add(1, std::memory_order_acq_rel) + 1;

        bool process_alive = false;
        DWORD exit_code = 0;
        HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hproc) {
            BOOL ok = GetExitCodeProcess(hproc, &exit_code);
            process_alive = ok && (exit_code == STILL_ACTIVE);
            CloseHandle(hproc);
        }

        if (!process_alive) {
            diag::log_tagged_fmt("diag",
                "OBSERVER-PROCESS-EXIT poll=%llu pid=%lu exit_code=0x%08lX",
                static_cast<unsigned long long>(poll_index),
                static_cast<unsigned long>(pid),
                static_cast<unsigned long>(exit_code));

            wer::log_wer_correlation("observer_process_exit");
            s.wer_correlation_count.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        observer_hang_record_t rec{};
        rec.timestamp_ms = now_ms();
        rec.poll_index = poll_index;
        rec.pid = pid;
        rec.hwnd = hwnd;
        rec.process_alive = process_alive;
        rec.exit_code = exit_code;
        rec.heartbeat_age_ms = rec.timestamp_ms - s.heartbeat_tick_ms.load(std::memory_order_acquire);

        if (hwnd && ::IsWindow(hwnd)) {
            rec.is_hung = ::IsHungAppWindow(hwnd);
            ::SetLastError(0);
            rec.send_wm_null_ok = ::SendMessageTimeoutW(hwnd, WM_NULL, 0, 0,
                SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
                s.config.wm_null_timeout_ms,
                &rec.send_wm_null_lresult);
            rec.send_wm_null_gle = rec.send_wm_null_ok ? 0 : ::GetLastError();
        }

        const bool hwnd_responsive = rec.send_wm_null_ok && rec.send_wm_null_gle == 0;
        const bool hang_detected = rec.is_hung || (!rec.send_wm_null_ok && rec.send_wm_null_gle != 0);

        if (hang_detected) {
            s.hang_detected_count.fetch_add(1, std::memory_order_relaxed);
            log_observer_hang(rec);
        }

        log_observer_heartbeat(poll_index, pid, hwnd, process_alive, hwnd_responsive);
        s.heartbeat_tick_ms.store(now_ms(), std::memory_order_release);

        for (std::uint32_t slept = 0; slept < s.config.poll_interval_ms / 100; ++slept) {
            if (s.stop_requested.load(std::memory_order_acquire))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    log_observer_stop();
    s.running.store(false, std::memory_order_release);
}

inline bool start(DWORD pid, HWND hwnd, const observer_config_t& cfg = {}) {
    auto& s = state();
    if (s.running.load(std::memory_order_acquire))
        return true;
    if (!cfg.enabled)
        return false;

    bool expected = false;
    if (!s.running.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return true;

    s.config = cfg;
    s.stop_requested.store(false, std::memory_order_release);
    s.poll_count.store(0, std::memory_order_release);
    s.hang_detected_count.store(0, std::memory_order_release);
    s.wer_correlation_count.store(0, std::memory_order_release);

    aida::infra::win_thread::joinable_thread_t worker;
    std::string err;
    const bool started = worker.start(
        [pid, hwnd]() { observer_loop(pid, hwnd); },
        &err, aida::infra::win_thread::default_stack_reserve, "diag_observer");

    if (!started) {
        s.running.store(false, std::memory_order_release);
        diag::log_tagged_fmt("diag",
            "OBSERVER-START-FAILED pid=%lu hwnd=0x%llX err=%s",
            static_cast<unsigned long>(pid),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            err.empty() ? "<none>" : err.c_str());
        return false;
    }

    worker.detach();
    return true;
}

inline void stop() {
    auto& s = state();
    s.stop_requested.store(true, std::memory_order_release);
}

inline bool is_running() {
    return state().running.load(std::memory_order_acquire);
}

inline std::string status_string() {
    auto& s = state();
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "running=%d pid=%lu polls=%llu hangs=%llu wer_correlations=%llu uptime_ms=%llu",
        s.running.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(s.observed_pid.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(s.poll_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(s.hang_detected_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(s.wer_correlation_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(now_ms() - s.start_ms.load(std::memory_order_acquire)));
    return std::string(buf);
}

}
