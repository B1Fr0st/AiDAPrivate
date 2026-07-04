#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "../runtime/manual_map_tls.hpp"
#include "win_thread.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace work_queue {

inline const int POOL_SIZE = []() {
    unsigned int hc = std::thread::hardware_concurrency();
    if (hc == 0u)
        hc = 32u;
    unsigned int base = hc;
    if (base < 32u)
        base = 32u;
    if (base > 64u)
        base = 64u;
    return static_cast<int>(base);
}();

inline const int SERVICE_POOL_SIZE = []() {
    unsigned int hc = std::thread::hardware_concurrency();
    if (hc == 0u)
        hc = 16u;
    unsigned int base = hc;
    if (base < 16u)
        base = 16u;
    if (base > 32u)
        base = 32u;
    return static_cast<int>(base);
}();

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
    std::uint64_t last_cpu_100ns = 0;
    std::uint64_t last_cpu_sample_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    DWORD thread_query_gle = 0;
    DWORD exit_code = 0;
    DWORD tid = 0;
    bool thread_alive = false;
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
inline pool_t g_service_pool;

}

inline std::uint64_t filetime_to_100ns(const FILETIME& ft)
{
    ULARGE_INTEGER v{};
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    return v.QuadPart;
}

inline bool sample_thread_cpu_100ns(DWORD tid, std::uint64_t& cpu_100ns, DWORD& gle, DWORD& exit_code)
{
    cpu_100ns = 0;
    gle = 0;
    exit_code = 0;
    if (tid == 0) {
        gle = ERROR_INVALID_PARAMETER;
        return false;
    }
    HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!th) {
        gle = GetLastError();
        return false;
    }
    FILETIME create_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    SetLastError(0);
    const BOOL exit_ok = GetExitCodeThread(th, &exit_code);
    const DWORD exit_gle = exit_ok ? 0UL : GetLastError();
    SetLastError(0);
    const BOOL times_ok = GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time);
    gle = times_ok ? 0UL : GetLastError();
    CloseHandle(th);
    if (!exit_ok) {
        gle = exit_gle;
        return false;
    }
    if (!times_ok)
        return false;
    cpu_100ns = filetime_to_100ns(kernel_time) + filetime_to_100ns(user_time);
    return exit_code == STILL_ACTIVE;
}

inline const char* classify_worker_label(const std::string& label) {
    if (label.find("full_test") != std::string::npos || label.find("test_all") != std::string::npos)
        return "full_test";
    if (label.find("heartbeat") != std::string::npos || label.find("session_health") != std::string::npos)
        return "heartbeat";
    if (label.find("mcp") != std::string::npos || label.find("http") != std::string::npos || label.find("sse") != std::string::npos)
        return "mcp_or_http";
    if (label.find("camoufox") != std::string::npos || label.find("browser") != std::string::npos)
        return "camoufox";
    if (label.find("driver") != std::string::npos || label.find("kernel") != std::string::npos || label.find("tctx") != std::string::npos)
        return "driver";
    if (label.find("scanner") != std::string::npos || label.find("scan") != std::string::npos)
        return "scanner";
    if (label.find("ui") != std::string::npos || label.find("render") != std::string::npos || label.find("dialog") != std::string::npos)
        return "ui_adjacent";
    if (label.find("service") != std::string::npos || label.find("listener") != std::string::npos || label.find("watch") != std::string::npos)
        return "long_lived_service";
    return "general";
}

inline bool worker_label_long_lived_hint(const char* label_class) {
    return label_class &&
        (std::strcmp(label_class, "heartbeat") == 0 ||
         std::strcmp(label_class, "mcp_or_http") == 0 ||
         std::strcmp(label_class, "camoufox") == 0 ||
         std::strcmp(label_class, "driver") == 0 ||
         std::strcmp(label_class, "long_lived_service") == 0);
}

inline const char* worker_lifetime_label(const char* pool_name, const char* label_class)
{
    const bool service_pool = pool_name && std::strcmp(pool_name, "service") == 0;
    if (service_pool && worker_label_long_lived_hint(label_class))
        return "intentional_service";
    if (service_pool)
        return "service_task";
    if (worker_label_long_lived_hint(label_class))
        return "long_lived_hint";
    return "bounded_task";
}

inline const char* worker_health_label(const char* lifetime, bool thread_alive, std::uint32_t cpu_pct_x100, std::size_t pending, bool shutting_down)
{
    if (!thread_alive)
        return "thread_not_queryable";
    if (shutting_down)
        return "shutdown_waiting";
    if (cpu_pct_x100 >= 2500)
        return "hot_cpu";
    if (lifetime && std::strcmp(lifetime, "intentional_service") == 0 && pending == 0)
        return "healthy_long_lived";
    if (lifetime && std::strcmp(lifetime, "intentional_service") == 0)
        return "service_backlog";
    return "needs_progress";
}

inline void refresh_active_thread_sample(detail::active_task_t& active, std::uint64_t now_ms)
{
    std::uint64_t cpu_100ns = 0;
    DWORD gle = 0;
    DWORD exit_code = 0;
    const bool alive = sample_thread_cpu_100ns(active.tid, cpu_100ns, gle, exit_code);
    active.thread_query_gle = gle;
    active.exit_code = exit_code;
    active.thread_alive = alive;
    if (active.last_cpu_sample_ms != 0 && now_ms > active.last_cpu_sample_ms && cpu_100ns >= active.last_cpu_100ns) {
        active.cpu_delta_100ns = cpu_100ns - active.last_cpu_100ns;
        const std::uint64_t wall_100ns = (now_ms - active.last_cpu_sample_ms) * 10000ULL;
        active.cpu_pct_x100 = wall_100ns != 0 ? static_cast<std::uint32_t>((active.cpu_delta_100ns * 10000ULL) / wall_100ns) : 0U;
        if (active.cpu_pct_x100 > 10000U)
            active.cpu_pct_x100 = 10000U;
    } else {
        active.cpu_delta_100ns = 0;
        active.cpu_pct_x100 = 0;
    }
    active.last_cpu_100ns = cpu_100ns;
    active.last_cpu_sample_ms = now_ms;
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
    std::uint32_t healthy_long_lived = 0;
    std::uint32_t hot_workers = 0;
    std::uint32_t not_queryable_workers = 0;
    std::string active_labels;
    std::string top_cpu_labels;
};

inline void shutdown(std::uint32_t timeout_ms = 5000);

inline stats_t stats_for(detail::pool_t& p, int pool_size, const char* pool_name) {
    stats_t s;
    s.alive = p.alive.load(std::memory_order_acquire);
    s.shutting_down = p.shutting_down.load(std::memory_order_acquire);
    s.pool_size = pool_size;
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
            s.top_cpu_labels = "<stats_lock_busy>";
            return s;
        }
        s.workers = p.workers.size();
        s.pending = p.tasks.size();
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        struct top_cpu_item_t {
            std::uint64_t task_id = 0;
            std::string label;
            const char* label_class = "general";
            const char* health = "needs_progress";
            std::uint64_t cpu_delta_100ns = 0;
            std::uint32_t cpu_pct_x100 = 0;
        };
        top_cpu_item_t top_cpu[4];
        std::size_t top_cpu_count = 0;
        for (auto& active : p.active_snapshots) {
            if (active.id == 0)
                continue;
            refresh_active_thread_sample(active, now);
            const char* cls = classify_worker_label(active.label);
            const char* lifetime = worker_lifetime_label(pool_name, cls);
            const char* health = worker_health_label(lifetime, active.thread_alive, active.cpu_pct_x100, s.pending, s.shutting_down);
            if (std::strcmp(health, "healthy_long_lived") == 0)
                ++s.healthy_long_lived;
            if (std::strcmp(health, "hot_cpu") == 0)
                ++s.hot_workers;
            if (!active.thread_alive)
                ++s.not_queryable_workers;
            const std::uint64_t age_ms = now >= active.started_ms ? now - active.started_ms : 0;
            if (s.oldest_active_ms < age_ms)
                s.oldest_active_ms = age_ms;
            ++s.active_label_count;
            const std::uint64_t queued_age_ms = active.queued_ms != 0 && now >= active.queued_ms ? now - active.queued_ms : 0;
            if (active.cpu_delta_100ns != 0) {
                std::size_t pos = top_cpu_count;
                while (pos > 0 && active.cpu_delta_100ns > top_cpu[pos - 1].cpu_delta_100ns)
                    --pos;
                if (pos < 4) {
                    if (top_cpu_count < 4)
                        ++top_cpu_count;
                    for (std::size_t j = top_cpu_count - 1; j > pos; --j)
                        top_cpu[j] = std::move(top_cpu[j - 1]);
                    top_cpu[pos].task_id = active.id;
                    top_cpu[pos].label = active.label;
                    top_cpu[pos].label_class = cls;
                    top_cpu[pos].health = health;
                    top_cpu[pos].cpu_delta_100ns = active.cpu_delta_100ns;
                    top_cpu[pos].cpu_pct_x100 = active.cpu_pct_x100;
                }
            }
            if (s.active_labels.size() < 900) {
                char item[360];
                _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s#%llu:%s:class=%s:life=%s:health=%s:tid=%lu:age_ms=%llu:queued_age_ms=%llu:cpu_delta_100ns=%llu:cpu_pct_x100=%u:alive=%d:gle=%lu",
                    s.active_labels.empty() ? "" : ";",
                    static_cast<unsigned long long>(active.id),
                    active.label.empty() ? "<unnamed>" : active.label.c_str(),
                    cls,
                    lifetime,
                    health,
                    static_cast<unsigned long>(active.tid),
                    static_cast<unsigned long long>(age_ms),
                    static_cast<unsigned long long>(queued_age_ms),
                    static_cast<unsigned long long>(active.cpu_delta_100ns),
                    static_cast<unsigned>(active.cpu_pct_x100),
                    active.thread_alive ? 1 : 0,
                    static_cast<unsigned long>(active.thread_query_gle));
                s.active_labels += item;
            }
        }
        for (std::size_t i = 0; i < top_cpu_count; ++i) {
            char item[260];
            _snprintf_s(item, sizeof(item), _TRUNCATE,
                "%s#%llu:%s:class=%s:cpu_delta_100ns=%llu:cpu_pct_x100=%u:health=%s",
                s.top_cpu_labels.empty() ? "" : ";",
                static_cast<unsigned long long>(top_cpu[i].task_id),
                top_cpu[i].label.empty() ? "<unnamed>" : top_cpu[i].label.c_str(),
                top_cpu[i].label_class,
                static_cast<unsigned long long>(top_cpu[i].cpu_delta_100ns),
                static_cast<unsigned>(top_cpu[i].cpu_pct_x100),
                top_cpu[i].health);
            s.top_cpu_labels += item;
        }
    }
    return s;
}

inline stats_t stats() {
    return stats_for(detail::g_pool, POOL_SIZE, "general");
}

inline stats_t service_stats() {
    return stats_for(detail::g_service_pool, SERVICE_POOL_SIZE, "service");
}

struct stuck_worker_diag_t {
    std::uint64_t task_id = 0;
    std::string label;
    const char* label_class = "general";
    const char* lifetime = "bounded_task";
    const char* health = "needs_progress";
    DWORD tid = 0;
    DWORD thread_query_gle = 0;
    DWORD exit_code = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t active_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    std::size_t worker_index = 0;
    bool thread_alive = false;
};

inline std::vector<stuck_worker_diag_t> stuck_workers_for(detail::pool_t& p, const char* pool_name, std::uint64_t threshold_ms, std::size_t max_records) {
    std::vector<stuck_worker_diag_t> result;
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
    if (!lk.owns_lock())
        return result;
    for (std::size_t i = 0; i < p.active_snapshots.size(); ++i) {
        if (max_records != 0 && result.size() >= max_records)
            break;
        auto& active = p.active_snapshots[i];
        if (active.id == 0)
            continue;
        refresh_active_thread_sample(active, now);
        const std::uint64_t age_ms = now >= active.started_ms ? now - active.started_ms : 0;
        if (age_ms < threshold_ms)
            continue;
        const char* cls = classify_worker_label(active.label);
        const char* lifetime = worker_lifetime_label(pool_name, cls);
        stuck_worker_diag_t d;
        d.task_id = active.id;
        d.label = active.label;
        d.label_class = cls;
        d.lifetime = lifetime;
        d.health = worker_health_label(lifetime, active.thread_alive, active.cpu_pct_x100, p.tasks.size(), p.shutting_down.load(std::memory_order_acquire));
        d.tid = active.tid;
        d.thread_query_gle = active.thread_query_gle;
        d.exit_code = active.exit_code;
        d.queued_ms = active.queued_ms;
        d.started_ms = active.started_ms;
        d.active_ms = age_ms;
        d.cpu_delta_100ns = active.cpu_delta_100ns;
        d.cpu_pct_x100 = active.cpu_pct_x100;
        d.worker_index = i;
        d.thread_alive = active.thread_alive;
        result.push_back(std::move(d));
    }
    return result;
}

inline void log_stuck_workers_for(detail::pool_t& p, const char* pool_name, std::uint64_t threshold_ms, std::size_t max_records) {
    auto stuck = stuck_workers_for(p, pool_name, threshold_ms, max_records);
    if (stuck.empty())
        return;
    std::size_t pending = 0;
    bool lock_busy = false;
    {
        std::unique_lock<std::mutex> lk(p.mtx, std::try_to_lock);
        if (lk.owns_lock())
            pending = p.tasks.size();
        else
            lock_busy = true;
    }
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    for (const auto& s : stuck) {
        const std::uint64_t queued_age_ms = s.queued_ms != 0 && now >= s.queued_ms ? now - s.queued_ms : 0;
        diag::log_tagged_fmt("work_queue",
            "stuck_worker pool=%s task_id=%llu label=%s class=%s lifetime=%s health=%s long_lived_hint=%d worker_index=%zu tid=%lu thread_alive=%d thread_gle=%lu exit_code=0x%08lX active_ms=%llu queued_age_ms=%llu threshold_ms=%llu cpu_delta_100ns=%llu cpu_pct_x100=%u cancellation=%s active=%u pending=%zu pending_lock_busy=%d post_attempts=%llu posted=%llu rejected=%llu started=%llu finished=%llu shutting_down=%d",
            pool_name ? pool_name : "<unnamed>",
            static_cast<unsigned long long>(s.task_id),
            s.label.empty() ? "<unnamed>" : s.label.c_str(),
            s.label_class,
            s.lifetime,
            s.health,
            worker_label_long_lived_hint(s.label_class) ? 1 : 0,
            s.worker_index,
            static_cast<unsigned long>(s.tid),
            s.thread_alive ? 1 : 0,
            static_cast<unsigned long>(s.thread_query_gle),
            static_cast<unsigned long>(s.exit_code),
            static_cast<unsigned long long>(s.active_ms),
            static_cast<unsigned long long>(queued_age_ms),
            static_cast<unsigned long long>(threshold_ms),
            static_cast<unsigned long long>(s.cpu_delta_100ns),
            static_cast<unsigned>(s.cpu_pct_x100),
            p.shutting_down.load(std::memory_order_acquire) ? "shutdown_requested" : "not_requested",
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            pending,
            lock_busy ? 1 : 0,
            static_cast<unsigned long long>(p.post_attempts.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.posted_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.rejected_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)),
            p.shutting_down.load(std::memory_order_acquire) ? 1 : 0);
    }
}

inline void log_stuck_workers(std::uint64_t threshold_ms, std::size_t max_records = 8) {
    log_stuck_workers_for(detail::g_pool, "general", threshold_ms, max_records);
}

inline void log_service_stuck_workers(std::uint64_t threshold_ms, std::size_t max_records = 8) {
    log_stuck_workers_for(detail::g_service_pool, "service", threshold_ms, max_records);
}

inline void initialize_pool(detail::pool_t& p, int pool_size) {
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
            p.workers.reserve(static_cast<std::size_t>(pool_size));
            p.active_snapshots.assign(static_cast<std::size_t>(pool_size), {});
            for (int i = 0; i < pool_size; ++i) {
                aida::infra::win_thread::joinable_thread_t worker;
                std::string err;
                const std::size_t worker_index = static_cast<std::size_t>(i);
                const bool started = worker.start([&p, worker_index]() {
                    bool thread_tls_ready = aida::manual_map_tls::ensure_current_thread();
                    if (!thread_tls_ready) {
                        diag::log_tagged_fmt("work_queue",
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
                            diag::log_tagged_fmt("work_queue",
                                "worker_tls_unavailable phase=task_start tid=%lu started=%llu finished=%llu",
                                static_cast<unsigned long>(GetCurrentThreadId()),
                                static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
                                static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)));
                        }
                        DWORD task_seh = 0;
                        try {
                            task_seh = aida::infra::win_thread::run_function_seh_guarded(task.fn);
                        } catch (const std::exception& ex) {
                            diag::log_tagged_fmt("work_queue",
                                "worker_task_exception id=%llu label=%s worker_index=%zu tid=%lu err=%s",
                                static_cast<unsigned long long>(task.id),
                                task.label.empty() ? "<unnamed>" : task.label.c_str(),
                                worker_index,
                                static_cast<unsigned long>(GetCurrentThreadId()),
                                ex.what());
                        } catch (...) {
                            diag::log_tagged_fmt("work_queue",
                                "worker_task_exception id=%llu label=%s worker_index=%zu tid=%lu err=unknown",
                                static_cast<unsigned long long>(task.id),
                                task.label.empty() ? "<unnamed>" : task.label.c_str(),
                                worker_index,
                                static_cast<unsigned long>(GetCurrentThreadId()));
                        }
                        if (task_seh != 0) {
                            const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
                            const std::uint64_t age_ms = task.queued_ms != 0 && now_ms >= task.queued_ms ? now_ms - task.queued_ms : 0;
                            diag::log_tagged_fmt("work_queue",
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
                }, &err, aida::infra::win_thread::default_stack_reserve, "work_queue");
                if (started) {
                    p.workers.emplace_back(std::move(worker));
                } else {
                    diag::log_tagged_fmt("work_queue",
                        "worker_start_failed index=%d pool_size=%d err=%s",
                        i,
                        pool_size,
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

inline void initialize() {
    initialize_pool(detail::g_pool, POOL_SIZE);
}

inline void initialize_services() {
    initialize_pool(detail::g_service_pool, SERVICE_POOL_SIZE);
}

inline bool post_to(detail::pool_t& p, int pool_size, std::function<void()> f, const char* label) {
    p.post_attempts.fetch_add(1u, std::memory_order_acq_rel);
    if (!p.alive.load(std::memory_order_acquire)) initialize_pool(p, pool_size);
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
            task.label = (label && *label) ? label : "<unnamed>";
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
    return post_to(detail::g_pool, POOL_SIZE, std::move(f), "work_queue.task");
}

inline bool post_service(std::function<void()> f) {
    return post_to(detail::g_service_pool, SERVICE_POOL_SIZE, std::move(f), "work_queue.service_task");
}

inline bool post_labeled(const char* label, std::function<void()> f) {
    return post_to(detail::g_pool, POOL_SIZE, std::move(f), label);
}

inline bool post_service_labeled(const char* label, std::function<void()> f) {
    return post_to(detail::g_service_pool, SERVICE_POOL_SIZE, std::move(f), label);
}

inline void shutdown_pool(detail::pool_t& p, const char* name, std::uint32_t timeout_ms) {
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
    const ULONGLONG deadline = timeout_ms == INFINITE ? 0 : GetTickCount64() + timeout_ms;
    for (auto& w : to_join) {
        if (!w.joinable())
            continue;
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
        diag::log_tagged_fmt("work_queue",
            "shutdown_join_timeout pool=%s wait_ms=%lu active=%u pending=%zu started=%llu finished=%llu",
            name ? name : "<unnamed>",
            static_cast<unsigned long>(wait_ms),
            static_cast<unsigned>(p.active_tasks.load(std::memory_order_acquire)),
            pending,
            static_cast<unsigned long long>(p.started_tasks.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(p.finished_tasks.load(std::memory_order_acquire)));
        log_stuck_workers_for(p, name, 0ULL, 16);
        w.detach();
    }
}

inline void shutdown(std::uint32_t timeout_ms) {
    shutdown_pool(detail::g_pool, "general", timeout_ms);
    shutdown_pool(detail::g_service_pool, "service", timeout_ms);
}

struct work_queue_shutdown_guard_t {
    ~work_queue_shutdown_guard_t() { ::work_queue::shutdown(); }
};

inline work_queue_shutdown_guard_t g_work_queue_shutdown_guard;

}
