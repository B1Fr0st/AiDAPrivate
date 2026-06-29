#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "../runtime/manual_map_tls.hpp"
#include "win_thread.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace critical_work_queue {

inline constexpr int POOL_SIZE = 24;

namespace detail {

struct task_t {
    std::function<void()> fn;
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
};

struct active_task_t {
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    DWORD tid = 0;
};

struct pool_t {
    std::vector<aida::infra::win_thread::joinable_thread_t> workers;
    std::queue<task_t> tasks;
    std::vector<active_task_t>        active_snapshots;
    std::mutex                        mtx;
    std::condition_variable           cv;
    std::atomic<bool>                 alive{false};
    std::atomic<bool>                 shutting_down{false};
    std::atomic<bool>                 shutdown_called{false};
    std::atomic<std::uint32_t>        active_tasks{0};
    std::atomic<std::uint64_t>        post_attempts{0};
    std::atomic<std::uint64_t>        posted_tasks{0};
    std::atomic<std::uint64_t>        rejected_tasks{0};
    std::atomic<std::uint64_t>        started_tasks{0};
    std::atomic<std::uint64_t>        finished_tasks{0};
    std::atomic<std::uint64_t>        next_task_id{0};
};

inline pool_t g_pool;

}

struct stats_t {
    bool alive = false;
    bool shutting_down = false;
    int pool_size = 0;
    std::size_t workers = 0;
    std::size_t pending = 0;
    std::uint32_t active = 0;
    std::uint64_t post_attempts = 0;
    std::uint64_t posted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t started = 0;
    std::uint64_t finished = 0;
    std::uint64_t oldest_active_ms = 0;
    std::uint32_t active_label_count = 0;
    std::string active_labels;
};

inline void shutdown(std::uint32_t timeout_ms = 15000);

inline stats_t stats() {
    auto& p = detail::g_pool;
    stats_t s;
    s.alive = p.alive.load(std::memory_order_acquire);
    s.shutting_down = p.shutting_down.load(std::memory_order_acquire);
    s.pool_size = POOL_SIZE;
    s.active = p.active_tasks.load(std::memory_order_acquire);
    s.post_attempts = p.post_attempts.load(std::memory_order_acquire);
    s.posted = p.posted_tasks.load(std::memory_order_acquire);
    s.rejected = p.rejected_tasks.load(std::memory_order_acquire);
    s.started = p.started_tasks.load(std::memory_order_acquire);
    s.finished = p.finished_tasks.load(std::memory_order_acquire);
    {
        std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
        if (!lk.owns_lock()) {
            s.active_labels = "<stats_lock_busy>";
            return s;
        }
        s.workers = p.workers.size();
        s.pending = p.tasks.size();
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        for (const auto& active : p.active_snapshots) {
            if (active.id == 0)
                continue;
            const std::uint64_t age_ms = now >= active.started_ms ? now - active.started_ms : 0;
            if (s.oldest_active_ms < age_ms)
                s.oldest_active_ms = age_ms;
            ++s.active_label_count;
            if (s.active_labels.size() < 900) {
                char item[256];
                _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s#%llu:%s:tid=%lu:age_ms=%llu:queued_ms=%llu",
                    s.active_labels.empty() ? "" : ";",
                    static_cast<unsigned long long>(active.id),
                    active.label.empty() ? "<unnamed>" : active.label.c_str(),
                    static_cast<unsigned long>(active.tid),
                    static_cast<unsigned long long>(age_ms),
                    static_cast<unsigned long long>(active.queued_ms));
                s.active_labels += item;
            }
        }
    }
    return s;
}

struct stuck_worker_diag_t {
    std::uint64_t task_id = 0;
    std::string label;
    DWORD tid = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t active_ms = 0;
    std::size_t worker_index = 0;
};

inline std::vector<stuck_worker_diag_t> stuck_workers(std::uint64_t threshold_ms) {
    std::vector<stuck_worker_diag_t> result;
    auto& p = detail::g_pool;
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
    if (!lk.owns_lock())
        return result;
    for (std::size_t i = 0; i < p.active_snapshots.size(); ++i) {
        const auto& active = p.active_snapshots[i];
        if (active.id == 0)
            continue;
        const std::uint64_t age_ms = now >= active.started_ms ? now - active.started_ms : 0;
        if (age_ms >= threshold_ms) {
            stuck_worker_diag_t d;
            d.task_id = active.id;
            d.label = active.label;
            d.tid = active.tid;
            d.queued_ms = active.queued_ms;
            d.started_ms = active.started_ms;
            d.active_ms = age_ms;
            d.worker_index = i;
            result.push_back(std::move(d));
        }
    }
    return result;
}

inline void log_stuck_workers(std::uint64_t threshold_ms) {
    auto stuck = stuck_workers(threshold_ms);
    if (stuck.empty())
        return;
    for (const auto& s : stuck) {
        diag::log_tagged_fmt("critical_work_queue",
            "stuck_worker task_id=%llu label=%s worker_index=%zu tid=%lu active_ms=%llu queued_ms=%llu threshold_ms=%llu",
            static_cast<unsigned long long>(s.task_id),
            s.label.empty() ? "<unnamed>" : s.label.c_str(),
            s.worker_index,
            static_cast<unsigned long>(s.tid),
            static_cast<unsigned long long>(s.active_ms),
            static_cast<unsigned long long>(s.queued_ms),
            static_cast<unsigned long long>(threshold_ms));
    }
}

inline void initialize() {
    auto& p = detail::g_pool;
    if (p.shutting_down.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!p.alive.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (p.shutting_down.load(std::memory_order_acquire)) {
            p.alive.store(false, std::memory_order_release);
            return;
        }
        try {
            p.workers.reserve(POOL_SIZE);
            p.active_snapshots.assign(static_cast<std::size_t>(POOL_SIZE), {});
            for (int i = 0; i < POOL_SIZE; ++i) {
                aida::infra::win_thread::joinable_thread_t worker;
                std::string err;
                const std::size_t worker_index = static_cast<std::size_t>(i);
                const bool started = worker.start([&p, worker_index]() {
                    bool thread_tls_ready = aida::manual_map_tls::ensure_current_thread();
                    if (!thread_tls_ready) {
                        diag::log_tagged_fmt("critical_work_queue",
                            "worker_tls_unavailable phase=thread_start tid=%lu",
                            static_cast<unsigned long>(GetCurrentThreadId()));
                    }
                    while (true) {
                        detail::task_t task;
                        {
                            std::unique_lock<std::mutex> lk(p.mtx);
                            p.cv.wait(lk, [&p]() { return !p.tasks.empty() || !p.alive.load(); });
                            if (!p.alive.load() && p.tasks.empty()) return;
                            task = std::move(p.tasks.front());
                            p.tasks.pop();
                            const std::uint64_t task_started_ms = static_cast<std::uint64_t>(GetTickCount64());
                            if (worker_index < p.active_snapshots.size()) {
                                auto& active = p.active_snapshots[worker_index];
                                active.label = task.label;
                                active.id = task.id;
                                active.queued_ms = task.queued_ms;
                                active.started_ms = task_started_ms;
                                active.tid = GetCurrentThreadId();
                            }
                        }
                        p.active_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        p.started_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        const bool task_tls_ready = aida::manual_map_tls::ensure_current_thread();
                        if (!task_tls_ready) {
                            diag::log_tagged_fmt("critical_work_queue",
                                "worker_tls_unavailable phase=task_start tid=%lu started=%llu finished=%llu",
                                static_cast<unsigned long>(GetCurrentThreadId()),
                                static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
                                static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)));
                        }
                        DWORD task_seh = 0;
                        try {
                            task_seh = aida::infra::win_thread::run_function_seh_guarded(task.fn);
                        } catch (const std::exception& ex) {
                            diag::log_tagged_fmt("critical_work_queue",
                                "worker_task_exception id=%llu label=%s worker_index=%zu tid=%lu err=%s",
                                static_cast<unsigned long long>(task.id),
                                task.label.empty() ? "<unnamed>" : task.label.c_str(),
                                worker_index,
                                static_cast<unsigned long>(GetCurrentThreadId()),
                                ex.what());
                        } catch (...) {
                            diag::log_tagged_fmt("critical_work_queue",
                                "worker_task_exception id=%llu label=%s worker_index=%zu tid=%lu err=unknown",
                                static_cast<unsigned long long>(task.id),
                                task.label.empty() ? "<unnamed>" : task.label.c_str(),
                                worker_index,
                                static_cast<unsigned long>(GetCurrentThreadId()));
                        }
                        if (task_seh != 0) {
                            const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
                            const std::uint64_t age_ms = task.queued_ms != 0 && now_ms >= task.queued_ms ? now_ms - task.queued_ms : 0;
                            diag::log_tagged_fmt("critical_work_queue",
                                "worker_task_seh id=%llu label=%s worker_index=%zu tid=%lu code=0x%08lX age_ms=%llu active=%u started=%llu finished=%llu shutting_down=%d",
                                static_cast<unsigned long long>(task.id),
                                task.label.empty() ? "<unnamed>" : task.label.c_str(),
                                worker_index,
                                static_cast<unsigned long>(GetCurrentThreadId()),
                                static_cast<unsigned long>(task_seh),
                                static_cast<unsigned long long>(age_ms),
                                static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
                                static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
                                static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
                                p.shutting_down.load(std::memory_order_acquire) ? 1 : 0);
                        }
                        {
                            std::lock_guard<std::mutex> lk(p.mtx);
                            if (worker_index < p.active_snapshots.size())
                                p.active_snapshots[worker_index] = {};
                        }
                        p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        p.active_tasks.fetch_sub(1u, std::memory_order_acq_rel);
                    }
                }, &err, aida::infra::win_thread::default_stack_reserve, "critical_work_queue");
                if (started) {
                    p.workers.emplace_back(std::move(worker));
                } else {
                    diag::log_tagged_fmt("critical_work_queue",
                        "worker_start_failed index=%d err=%s",
                        i,
                        err.empty() ? "<none>" : err.c_str());
                }
            }
        } catch (...) {
            if (p.workers.empty()) {
                p.alive.store(false, std::memory_order_release);
                p.cv.notify_all();
            }
        }
    }
}

inline bool post_labeled(const char* label, std::function<void()> f) {
    auto& p = detail::g_pool;
    p.post_attempts.fetch_add(1u, std::memory_order_acq_rel);
    if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) {
        p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) {
            p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
            return false;
        }
        try {
            detail::task_t task;
            task.fn = std::move(f);
            task.label = (label && *label) ? label : "critical_work_queue.task";
            task.id = p.next_task_id.fetch_add(1u, std::memory_order_acq_rel) + 1u;
            task.queued_ms = static_cast<std::uint64_t>(GetTickCount64());
            p.tasks.push(std::move(task));
            p.posted_tasks.fetch_add(1u, std::memory_order_acq_rel);
        } catch (...) {
            p.rejected_tasks.fetch_add(1u, std::memory_order_acq_rel);
            return false;
        }
    }
    p.cv.notify_one();
    return true;
}

inline bool post(std::function<void()> f) {
    return post_labeled("critical_work_queue.task", std::move(f));
}

inline void shutdown(std::uint32_t timeout_ms) {
    auto& p = detail::g_pool;
    bool expected = false;
    if (!p.shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    p.shutting_down.store(true, std::memory_order_release);
    p.alive.store(false, std::memory_order_release);
    std::vector<aida::infra::win_thread::joinable_thread_t> to_join;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        to_join = std::move(p.workers);
        p.workers.clear();
        p.cv.notify_all();
    }
#ifdef _WIN32
    const ULONGLONG deadline = timeout_ms == INFINITE ? 0 : GetTickCount64() + timeout_ms;
#endif
    for (auto& w : to_join) {
        if (!w.joinable())
            continue;
#ifdef _WIN32
        DWORD wait_ms = INFINITE;
        if (timeout_ms != INFINITE) {
            const ULONGLONG now = GetTickCount64();
            wait_ms = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
        }
        if (w.join_for(wait_ms))
            continue;
        std::size_t pending = 0;
        {
            std::lock_guard<std::mutex> lk(p.mtx);
            pending = p.tasks.size();
        }
        diag::log_tagged_fmt("critical_work_queue",
            "shutdown_join_timeout timeout_ms=%lu active=%u pending=%zu started=%llu finished=%llu",
            static_cast<unsigned long>(wait_ms),
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            pending,
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)));
        w.detach();
#else
        w.join();
#endif
    }
}

struct shutdown_guard_t {
    ~shutdown_guard_t() { ::critical_work_queue::shutdown(); }
};

inline shutdown_guard_t g_shutdown_guard;

}
