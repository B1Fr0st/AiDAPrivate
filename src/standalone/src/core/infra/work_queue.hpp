#pragma once

#include <atomic>
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace work_queue {

inline const int POOL_SIZE = []() {
    unsigned int hc = std::thread::hardware_concurrency();
    unsigned int base = (hc < 4u) ? 4u : (hc - 2u);
    constexpr unsigned int kPersistentLoopFloor = 32u;
    return static_cast<int>(base > kPersistentLoopFloor ? base : kPersistentLoopFloor);
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
};

inline pool_t g_pool;

}

inline void shutdown();

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
                        try { task(); } catch (...) {}
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
    if (!p.alive.load(std::memory_order_acquire)) initialize();
    if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) return false;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) return false;
        try {
            p.tasks.push(std::move(f));
        } catch (...) {
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
