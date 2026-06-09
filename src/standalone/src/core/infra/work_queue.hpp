#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "../runtime/manual_map_tls.hpp"

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

struct pool_t {
    std::vector<std::thread>          workers;
    std::queue<std::function<void()>> tasks;
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
};

inline pool_t g_pool;
inline pool_t g_service_pool;

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
};

inline void shutdown();

inline stats_t stats_for(detail::pool_t& p, int pool_size) {
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
        std::lock_guard<std::mutex> lk(p.mtx);
        s.workers = p.workers.size();
        s.pending = p.tasks.size();
    }
    return s;
}

inline stats_t stats() {
    return stats_for(detail::g_pool, POOL_SIZE);
}

inline stats_t service_stats() {
    return stats_for(detail::g_service_pool, SERVICE_POOL_SIZE);
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
            for (int i = 0; i < pool_size; ++i) {
                p.workers.emplace_back([&p]() {
                    aida::manual_map_tls::ensure_current_thread();
                    while (true) {
                        std::function<void()> task;
                        {
                            std::unique_lock<std::mutex> lk(p.mtx);
                            p.cv.wait(lk, [&p]() { return !p.tasks.empty() || !p.alive.load(); });
                            if (!p.alive.load() && p.tasks.empty()) return;
                            task = std::move(p.tasks.front());
                            p.tasks.pop();
                        }
                        p.active_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        p.started_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        try { task(); } catch (...) {}
                        p.finished_tasks.fetch_add(1u, std::memory_order_acq_rel);
                        p.active_tasks.fetch_sub(1u, std::memory_order_acq_rel);
                    }
                });
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

inline bool post_to(detail::pool_t& p, int pool_size, std::function<void()> f) {
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
            p.tasks.push(std::move(f));
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
    return post_to(detail::g_pool, POOL_SIZE, std::move(f));
}

inline bool post_service(std::function<void()> f) {
    return post_to(detail::g_service_pool, SERVICE_POOL_SIZE, std::move(f));
}

inline void shutdown_pool(detail::pool_t& p) {
    bool expected = false;
    if (!p.shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    p.shutting_down.store(true, std::memory_order_release);
    p.alive.store(false, std::memory_order_release);
    std::vector<std::thread> to_join;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        to_join = std::move(p.workers);
        p.workers.clear();
        p.cv.notify_all();
    }
    for (auto& w : to_join) if (w.joinable()) w.join();
}

inline void shutdown() {
    shutdown_pool(detail::g_pool);
    shutdown_pool(detail::g_service_pool);
}

struct work_queue_shutdown_guard_t {
    ~work_queue_shutdown_guard_t() { ::work_queue::shutdown(); }
};

inline work_queue_shutdown_guard_t g_work_queue_shutdown_guard;

}
