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
        std::lock_guard<std::mutex> lk(p.mtx);
        s.workers = p.workers.size();
        s.pending = p.tasks.size();
    }
    return s;
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
            for (int i = 0; i < POOL_SIZE; ++i) {
                p.workers.emplace_back([&p]() {
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

inline bool post(std::function<void()> f) {
    auto& p = detail::g_pool;
    p.post_attempts.fetch_add(1u, std::memory_order_acq_rel);
    if (!p.alive.load(std::memory_order_acquire)) initialize();
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

inline void shutdown() {
    auto& p = detail::g_pool;
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

struct work_queue_shutdown_guard_t {
    ~work_queue_shutdown_guard_t() { ::work_queue::shutdown(); }
};

inline work_queue_shutdown_guard_t g_work_queue_shutdown_guard;

}
