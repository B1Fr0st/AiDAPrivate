#pragma once

#include "taskflow_runtime.hpp"
#include "win_thread.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::infra::cancellation_watchdog {

inline constexpr std::uint32_t watch_capacity = 4096;
inline constexpr std::uint64_t sweep_interval_ms = 25;

struct watch_id_t {
    std::uint32_t slot = 0;
    std::uint32_t generation = 0;
    constexpr bool valid() const noexcept { return generation != 0; }
};

struct watch_descriptor_t {
    std::uint64_t deadline_ms = 0;
    std::shared_ptr<taskflow_runtime::cancellation_token_t> source_token;
    std::atomic<bool>* external_flag = nullptr;
    std::function<void()> on_fire;
};

namespace detail {

struct watch_slot_t {
    std::atomic<std::uint32_t> generation{0};
    std::uint64_t deadline_ms = 0;
    std::shared_ptr<taskflow_runtime::cancellation_token_t> source_token;
    std::atomic<bool>* external_flag = nullptr;
    std::function<void()> on_fire;
};

struct watch_registry_t {
    watch_registry_t() {
        free_slots.reserve(watch_capacity);
        for (std::uint32_t slot_index = watch_capacity; slot_index > 0; --slot_index)
            free_slots.push_back(slot_index - 1u);
    }

    watch_slot_t slots[watch_capacity];
    std::mutex free_mtx;
    std::vector<std::uint32_t> free_slots;
    std::atomic<std::uint32_t> next_generation{0};
    std::atomic<std::uint64_t> registered_count{0};
    std::atomic<std::uint64_t> fired_count{0};
    std::atomic<std::uint64_t> rejected_count{0};
    std::atomic<std::uint64_t> last_sweep_tick_ms{0};
    std::atomic<std::uint64_t> last_sweep_lag_ms{0};
    std::atomic<std::uint64_t> last_sweep_duration_ms{0};
    std::atomic<bool> sweeper_started{false};
};

inline watch_registry_t& registry() noexcept {
    static watch_registry_t* instance = new watch_registry_t();
    return *instance;
}

inline void invoke_on_fire_guarded(std::function<void()>& fn, std::uint32_t slot, std::uint32_t generation) noexcept {
    if (!fn)
        return;
    DWORD seh = 0;
    try {
        const std::function<void()> guarded = [&]() { fn(); };
        seh = aida::infra::win_thread::run_function_seh_guarded(guarded);
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("watchdog",
            "watchdog_fire_exception slot=%lu generation=%lu err=%s tid=%lu",
            static_cast<unsigned long>(slot),
            static_cast<unsigned long>(generation),
            ex.what(),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    } catch (...) {
        diag::log_tagged_fmt("watchdog",
            "watchdog_fire_exception slot=%lu generation=%lu err=unknown tid=%lu",
            static_cast<unsigned long>(slot),
            static_cast<unsigned long>(generation),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    }
    if (seh != 0) {
        diag::log_tagged_fmt("watchdog",
            "watchdog_fire_seh slot=%lu generation=%lu seh=0x%08lX tid=%lu",
            static_cast<unsigned long>(slot),
            static_cast<unsigned long>(generation),
            static_cast<unsigned long>(seh),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
}

inline bool claim_slot(watch_registry_t& reg, std::uint32_t slot_index, std::uint32_t generation) {
    watch_slot_t& slot = reg.slots[slot_index];
    std::uint32_t expected = generation;
    if (!slot.generation.compare_exchange_strong(expected, 0u,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return false;
    std::function<void()> on_fire = std::move(slot.on_fire);
    slot.on_fire = nullptr;
    slot.source_token.reset();
    slot.external_flag = nullptr;
    slot.deadline_ms = 0;
    {
        std::lock_guard<std::mutex> lk(reg.free_mtx);
        reg.free_slots.push_back(slot_index);
    }
    reg.registered_count.fetch_sub(1u, std::memory_order_acq_rel);
    if (on_fire) {
        reg.fired_count.fetch_add(1u, std::memory_order_acq_rel);
        invoke_on_fire_guarded(on_fire, slot_index, generation);
    }
    return true;
}

inline void sweep_once() noexcept {
    watch_registry_t& reg = registry();
    const std::uint64_t start = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t previous = reg.last_sweep_tick_ms.exchange(start, std::memory_order_acq_rel);
    if (previous != 0 && start >= previous + sweep_interval_ms)
        reg.last_sweep_lag_ms.store(start - previous - sweep_interval_ms, std::memory_order_release);
    else
        reg.last_sweep_lag_ms.store(0, std::memory_order_release);
    for (std::uint32_t slot_index = 0; slot_index < watch_capacity; ++slot_index) {
    detail::watch_slot_t& slot = reg.slots[slot_index];
        const std::uint32_t generation = slot.generation.load(std::memory_order_acquire);
        if (generation == 0)
            continue;
        bool fire = false;
        if (slot.deadline_ms != 0 && start >= slot.deadline_ms) {
            fire = true;
        } else if (slot.source_token &&
                   slot.source_token->requested.load(std::memory_order_acquire)) {
            fire = true;
        } else if (slot.external_flag &&
                   slot.external_flag->load(std::memory_order_acquire)) {
            fire = true;
        }
        if (fire)
            claim_slot(reg, slot_index, generation);
    }
    const std::uint64_t end = static_cast<std::uint64_t>(GetTickCount64());
    reg.last_sweep_duration_ms.store(end >= start ? end - start : 0, std::memory_order_release);
}

inline void sweeper_tick() {
    sweep_once();
    if (taskflow_runtime::g_shutdown_requested.load(std::memory_order_acquire) ||
        taskflow_runtime::g_stop_accepting.load(std::memory_order_acquire))
        return;
    taskflow_runtime::task_descriptor_t desc;
    desc.domain = taskflow_runtime::executor_domain_t::diagnostics;
    desc.owner_subsystem = "cancellation_watchdog";
    desc.label = "watchdog.sweeper";
    desc.priority = 7;
    desc.shutdown_policy = "cancel_pending";
    desc.cancellable_body = [](const taskflow_runtime::cancellation_token_t& token) {
        for (int slice = 0; slice < 5; ++slice) {
            if (token.requested.load(std::memory_order_acquire))
                return;
            Sleep(5);
        }
        sweeper_tick();
    };
    static_cast<void>(taskflow_runtime::submit(std::move(desc)));
}

inline void ensure_started() noexcept {
    watch_registry_t& reg = registry();
    bool expected = false;
    if (!reg.sweeper_started.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return;
    try {
        sweeper_tick();
    } catch (...) {
    }
}

}

watch_id_t register_watch(watch_descriptor_t desc) noexcept {
    watch_id_t id;
    if (!desc.on_fire)
        return id;
    detail::watch_registry_t& reg = detail::registry();
    std::uint32_t slot_index = 0;
    {
        std::lock_guard<std::mutex> lk(reg.free_mtx);
        if (reg.free_slots.empty()) {
            reg.rejected_count.fetch_add(1u, std::memory_order_acq_rel);
            diag::log_tagged_fmt("watchdog",
                "watchdog_register_rejected reason=registry_full capacity=%u registered=%llu fired=%llu rejected=%llu tid=%lu",
                static_cast<unsigned>(watch_capacity),
                static_cast<unsigned long long>(reg.registered_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(reg.fired_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(reg.rejected_count.load(std::memory_order_acquire)),
                static_cast<unsigned long>(GetCurrentThreadId()));
            return id;
        }
        slot_index = reg.free_slots.back();
        reg.free_slots.pop_back();
    }
    std::uint32_t generation = reg.next_generation.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    if (generation == 0)
        generation = reg.next_generation.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    watch_slot_t& slot = reg.slots[slot_index];
    slot.deadline_ms = desc.deadline_ms;
    slot.source_token = std::move(desc.source_token);
    slot.external_flag = desc.external_flag;
    slot.on_fire = std::move(desc.on_fire);
    slot.generation.store(generation, std::memory_order_release);
    reg.registered_count.fetch_add(1u, std::memory_order_acq_rel);
    id.slot = slot_index;
    id.generation = generation;
    detail::ensure_started();
    return id;
}

bool unregister_watch(watch_id_t id) noexcept {
    if (!id.valid() || id.slot >= watch_capacity)
        return false;
    detail::watch_registry_t& reg = detail::registry();
    detail::watch_slot_t& slot = reg.slots[id.slot];
    std::uint32_t expected = id.generation;
    if (!slot.generation.compare_exchange_strong(expected, 0u,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return false;
    slot.on_fire = nullptr;
    slot.source_token.reset();
    slot.external_flag = nullptr;
    slot.deadline_ms = 0;
    {
        std::lock_guard<std::mutex> lk(reg.free_mtx);
        reg.free_slots.push_back(id.slot);
    }
    reg.registered_count.fetch_sub(1u, std::memory_order_acq_rel);
    return true;
}

std::uint64_t last_sweep_lag_ms() noexcept {
    return detail::registry().last_sweep_lag_ms.load(std::memory_order_acquire);
}

std::uint64_t last_sweep_duration_ms() noexcept {
    return detail::registry().last_sweep_duration_ms.load(std::memory_order_acquire);
}

std::uint64_t registered_watch_count() noexcept {
    return detail::registry().registered_count.load(std::memory_order_acquire);
}

std::uint64_t fired_watch_count() noexcept {
    return detail::registry().fired_count.load(std::memory_order_acquire);
}

}
