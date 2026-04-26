#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace work_queue {

inline constexpr int POOL_SIZE = 12;

namespace detail {

struct pool_t {
    std::vector<std::thread>          workers;
    std::queue<std::function<void()>> tasks;
    std::mutex                        mtx;
    std::condition_variable           cv;
    std::atomic<bool>                 alive{false};
    std::atomic<bool>                 shutting_down{false};
};

inline pool_t g_pool;

}

inline void initialize() {
    auto& p = detail::g_pool;
    if (p.shutting_down.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!p.alive.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
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
}

inline void post(std::function<void()> f) {
    auto& p = detail::g_pool;
    if (!p.alive.load(std::memory_order_acquire)) initialize();
    if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) return;
    {
        std::lock_guard<std::mutex> lk(p.mtx);
        if (!p.alive.load(std::memory_order_acquire) || p.shutting_down.load(std::memory_order_acquire)) return;
        p.tasks.push(std::move(f));
    }
    p.cv.notify_one();
}

inline void shutdown() {
    auto& p = detail::g_pool;
    p.shutting_down.store(true, std::memory_order_release);
    p.alive.store(false, std::memory_order_release);
    p.cv.notify_all();
    for (auto& w : p.workers) if (w.joinable()) w.join();
    p.workers.clear();
}

}
