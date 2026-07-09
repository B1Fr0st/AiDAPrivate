#pragma once

#include "standalone_driver.hpp"
#include "../infra/executor.hpp"
#include "helpers/diag_log.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace driver_bridge {
std::vector<captured_packet_t> get_captured_packets_bounded(uint32_t max_packets, uint32_t deadline_ms);
void cancel_inflight_capture();
}

namespace network_view {


struct stream_key_t {
    uint32_t src_ip4  = 0;
    uint32_t dst_ip4  = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  proto    = 0;
    uint8_t  pad[3]   = {};

    bool operator==(const stream_key_t& o) const noexcept {
        return src_ip4 == o.src_ip4 && dst_ip4 == o.dst_ip4 &&
               src_port == o.src_port && dst_port == o.dst_port &&
               proto    == o.proto;
    }
};

struct stream_key_hash_t {
    size_t operator()(const stream_key_t& k) const noexcept {

        constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME  = 1099511628211ULL;
        uint64_t h = FNV_OFFSET;
        auto fnv_byte = [&](uint8_t b) { h ^= b; h *= FNV_PRIME; };
        auto fnv32 = [&](uint32_t v) {
            fnv_byte(static_cast<uint8_t>(v));
            fnv_byte(static_cast<uint8_t>(v >> 8));
            fnv_byte(static_cast<uint8_t>(v >> 16));
            fnv_byte(static_cast<uint8_t>(v >> 24));
        };
        auto fnv16 = [&](uint16_t v) {
            fnv_byte(static_cast<uint8_t>(v));
            fnv_byte(static_cast<uint8_t>(v >> 8));
        };
        fnv32(k.src_ip4);
        fnv32(k.dst_ip4);
        fnv16(k.src_port);
        fnv16(k.dst_port);
        fnv_byte(k.proto);
        return static_cast<size_t>(h);
    }
};


struct half_stream_state_t {
    std::vector<uint8_t> assembled;
    uint64_t             total_bytes   = 0;
    uint64_t             total_packets = 0;
};

struct stream_state_t {
    bool                 syn_seen       = false;
    bool                 fin_seen       = false;
    std::vector<uint8_t> assembled;
    uint64_t             last_activity_ns = 0;
    uint64_t             total_bytes    = 0;
    uint64_t             total_packets  = 0;
    half_stream_state_t  c2s;
    half_stream_state_t  s2c;
};


struct stream_snapshot_t {
    stream_key_t         key;
    std::vector<uint8_t> assembled;
    uint64_t             total_bytes    = 0;
    uint64_t             total_packets  = 0;
    uint64_t             last_activity_ns = 0;
    bool                 syn_seen       = false;
    bool                 fin_seen       = false;
};


class tcp_stream_tracker_t {
    struct worker_state_t {
        mutable std::mutex streams_mutex;
        std::unordered_map<stream_key_t, stream_state_t, stream_key_hash_t> streams;
        std::atomic<bool> running{false};
        uint32_t filter_pid = 0;
        uint32_t evict_counter = 0;
        std::mutex worker_mutex;
        std::condition_variable worker_cv;
        bool worker_active = false;
        std::atomic<bool> worker_entered{false};
        std::atomic<bool> stop_timed_out{false};
    };

public:
    tcp_stream_tracker_t()
        : state_(std::make_shared<worker_state_t>()) {}
    ~tcp_stream_tracker_t() { stop(); }

    tcp_stream_tracker_t(const tcp_stream_tracker_t&)            = delete;
    tcp_stream_tracker_t& operator=(const tcp_stream_tracker_t&) = delete;

    void start(uint32_t filter_pid = 0) {
        auto state = std::make_shared<worker_state_t>();
        state->filter_pid = filter_pid;
        state->running.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(state->worker_mutex);
            state->worker_active = true;
        }
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (state_ && state_->running.load(std::memory_order_acquire))
                return;
            state_ = state;
        }
        diag::log_tagged_fmt("tcp_tracker", "start this=%p state=%p filter_pid=%u", this, state.get(), filter_pid);
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "network.tcp_tracker";
        sub.label = "tcp_tracker.poll_loop";
        sub.thread_class = "service_loop";
        sub.domain = aida::infra::executor::domain_t::service;
        sub.priority = 4;
        sub.target_pid = filter_pid;
        sub.body = [state]() {
            state->worker_entered.store(true, std::memory_order_release);
            diag::log_tagged_fmt("tcp_tracker", "worker_enter state=%p tid=%lu", state.get(), static_cast<unsigned long>(GetCurrentThreadId()));
            poll_loop(state);
            {
                std::lock_guard<std::mutex> lk(state->worker_mutex);
                state->worker_active = false;
            }
            state->worker_cv.notify_all();
            diag::log_tagged_fmt("tcp_tracker", "worker_exit state=%p tid=%lu timed_out=%d", state.get(), static_cast<unsigned long>(GetCurrentThreadId()),
                state->stop_timed_out.load(std::memory_order_acquire) ? 1 : 0);
        };
        if (!aida::infra::executor::submit(std::move(sub)).submitted) {
            state->running.store(false, std::memory_order_release);
            {
                std::lock_guard<std::mutex> lk(state->worker_mutex);
                state->worker_active = false;
            }
            state->worker_cv.notify_all();
            diag::log_tagged_fmt("tcp_tracker", "start_post_failed this=%p state=%p", this, state.get());
        }
    }

    bool stop(uint32_t timeout_ms = 2000) {
        auto state = current_state();
        if (!state)
            return true;
        state->running.store(false, std::memory_order_release);
        driver_bridge::cancel_inflight_capture();
        const uint64_t t0 = static_cast<uint64_t>(GetTickCount64());
        std::unique_lock<std::mutex> lk(state->worker_mutex);
        const bool stopped = state->worker_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [state]() { return !state->worker_active; });
        const uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - t0;
        if (!stopped) {
            state->stop_timed_out.store(true, std::memory_order_release);
            diag::log_tagged_fmt("tcp_tracker",
                "stop_timeout this=%p state=%p timeout_ms=%u elapsed_ms=%llu worker_active=%d worker_entered=%d",
                this,
                state.get(),
                timeout_ms,
                static_cast<unsigned long long>(elapsed),
                state->worker_active ? 1 : 0,
                state->worker_entered.load(std::memory_order_acquire) ? 1 : 0);
            return false;
        }
        diag::log_tagged_fmt("tcp_tracker", "stop this=%p state=%p elapsed_ms=%llu worker_active=%d worker_entered=%d",
            this,
            state.get(),
            static_cast<unsigned long long>(elapsed),
            state->worker_active ? 1 : 0,
            state->worker_entered.load(std::memory_order_acquire) ? 1 : 0);
        return true;
    }

    bool is_running() const noexcept {
        auto state = current_state();
        return state && state->running.load(std::memory_order_acquire);
    }


    void feed(const driver_bridge::captured_packet_t& pkt) {
        auto state = current_state();
        if (state)
            feed_packet(*state, pkt);
    }


    std::optional<stream_snapshot_t> get_stream(const stream_key_t& key) const {
        auto state = current_state();
        if (!state)
            return std::nullopt;
        std::lock_guard<std::mutex> lk(state->streams_mutex);
        auto it = state->streams.find(key);
        if (it == state->streams.end()) return std::nullopt;
        return make_snapshot(key, it->second);
    }


    std::vector<stream_snapshot_t> get_all() const {
        auto state = current_state();
        if (!state)
            return {};
        std::lock_guard<std::mutex> lk(state->streams_mutex);
        std::vector<stream_snapshot_t> out;
        out.reserve(state->streams.size());
        for (auto& [k, v] : state->streams)
            out.push_back(make_snapshot(k, v));
        return out;
    }


    void evict_stale(uint64_t age_ns = 30'000'000'000ULL) {
        auto state = current_state();
        if (state)
            evict_stale_state(*state, age_ns);
    }

    void clear() {
        auto state = current_state();
        if (!state)
            return;
        std::lock_guard<std::mutex> lk(state->streams_mutex);
        state->streams.clear();
    }

    size_t stream_count() const {
        auto state = current_state();
        if (!state)
            return 0;
        std::lock_guard<std::mutex> lk(state->streams_mutex);
        return state->streams.size();
    }

private:
    std::shared_ptr<worker_state_t> current_state() const noexcept {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return state_;
    }

    static stream_snapshot_t make_snapshot(const stream_key_t& key,
                                            const stream_state_t& st) {
        stream_snapshot_t snap;
        snap.key              = key;
        snap.assembled        = st.assembled;
        snap.total_bytes      = st.total_bytes;
        snap.total_packets    = st.total_packets;
        snap.last_activity_ns = st.last_activity_ns;
        snap.syn_seen         = st.syn_seen;
        snap.fin_seen         = st.fin_seen;
        return snap;
    }

    static void feed_packet(worker_state_t& state, const driver_bridge::captured_packet_t& pkt) {
        if (pkt.protocol != 6) return;
        if (pkt.payload.empty()) return;

        stream_key_t key;

        if (pkt.direction == 0) {
            key.src_ip4  = *reinterpret_cast<const uint32_t*>(pkt.remote_addr);
            key.dst_ip4  = *reinterpret_cast<const uint32_t*>(pkt.local_addr);
            key.src_port = static_cast<uint16_t>(pkt.remote_port);
            key.dst_port = static_cast<uint16_t>(pkt.local_port);
        } else {
            key.src_ip4  = *reinterpret_cast<const uint32_t*>(pkt.local_addr);
            key.dst_ip4  = *reinterpret_cast<const uint32_t*>(pkt.remote_addr);
            key.src_port = static_cast<uint16_t>(pkt.local_port);
            key.dst_port = static_cast<uint16_t>(pkt.remote_port);
        }
        key.proto = 6;

        uint64_t now_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        std::lock_guard<std::mutex> lk(state.streams_mutex);

        auto& st = state.streams[key];
        st.last_activity_ns = now_ns;
        st.total_packets++;
        st.total_bytes += pkt.payload.size();
        st.syn_seen = true;

        half_stream_state_t& half = (pkt.direction == 0) ? st.s2c : st.c2s;
        half.total_packets++;
        half.total_bytes += pkt.payload.size();
        half.assembled.insert(half.assembled.end(), pkt.payload.begin(), pkt.payload.end());

        st.assembled.insert(st.assembled.end(), pkt.payload.begin(), pkt.payload.end());
    }

    static void evict_stale_state(worker_state_t& state, uint64_t age_ns) {
        uint64_t now_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        std::lock_guard<std::mutex> lk(state.streams_mutex);
        for (auto it = state.streams.begin(); it != state.streams.end(); ) {
            if (now_ns - it->second.last_activity_ns > age_ns)
                it = state.streams.erase(it);
            else
                ++it;
        }
    }

    static void poll_loop(const std::shared_ptr<worker_state_t>& state) {
        diag::log_tagged_fmt("tcp_tracker", "poll_loop_enter state=%p tid=%lu running=%d",
            state.get(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            state->running.load(std::memory_order_acquire) ? 1 : 0);
        while (state->running.load(std::memory_order_acquire)) {
            if (driver_bridge::using_kernel_driver()) {
                diag::log_tagged_fmt("tcp_tracker", "poll_pre tid=%lu state=%p running=%d",
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    state.get(),
                    state->running.load(std::memory_order_acquire) ? 1 : 0);
                auto packets = driver_bridge::get_captured_packets_bounded(32, 500);
                diag::log_tagged_fmt("tcp_tracker", "poll_post tid=%lu state=%p running=%d packets=%zu",
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    state.get(),
                    state->running.load(std::memory_order_acquire) ? 1 : 0,
                    packets.size());
                if (!state->running.load(std::memory_order_acquire))
                    break;
                for (auto& pkt : packets) {
                    if (state->filter_pid == 0 || pkt.pid == state->filter_pid)
                        feed_packet(*state, pkt);
                    if (!state->running.load(std::memory_order_acquire))
                        break;
                }
            }

            if (!state->running.load(std::memory_order_acquire))
                break;

            state->evict_counter++;
            if (state->evict_counter >= 12000) {
                evict_stale_state(*state, 30'000'000'000ULL);
                state->evict_counter = 0;
            }


            if (state->running.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        diag::log_tagged_fmt("tcp_tracker", "poll_loop_exit state=%p tid=%lu",
            state.get(),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }

    mutable std::mutex state_mutex_;
    std::shared_ptr<worker_state_t> state_;
};

inline tcp_stream_tracker_t g_stream_tracker;

}
