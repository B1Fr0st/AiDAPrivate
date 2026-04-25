#pragma once

#include "standalone_driver.hpp"
#include "work_queue.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

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


struct stream_state_t {
    uint32_t                              expected_seq   = 0;
    bool                                  syn_seen       = false;
    bool                                  fin_seen       = false;
    std::map<uint32_t, std::vector<uint8_t>> ooo_buffer;
    std::vector<uint8_t>                  assembled;
    uint64_t                              last_activity_ns = 0;
    uint64_t                              total_bytes    = 0;
    uint64_t                              total_packets  = 0;
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
public:
    tcp_stream_tracker_t() = default;
    ~tcp_stream_tracker_t() { stop(); }

    tcp_stream_tracker_t(const tcp_stream_tracker_t&)            = delete;
    tcp_stream_tracker_t& operator=(const tcp_stream_tracker_t&) = delete;

    void start(uint32_t filter_pid = 0) {
        if (running_.load()) return;
        filter_pid_ = filter_pid;
        running_.store(true);
        {
            std::lock_guard<std::mutex> lk(streams_mutex_);
            streams_.clear();
        }
        poll_thread_ = {};
        work_queue::post([this]() { poll_loop(); });
    }

    void stop() {
        if (!running_.load()) return;
        running_.store(false);
        if (poll_thread_.joinable()) poll_thread_.join();
    }

    bool is_running() const noexcept { return running_.load(); }


    void feed(const driver_bridge::captured_packet_t& pkt) {
        if (pkt.protocol != 6) return;
        if (pkt.payload.empty())        return;


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

        std::lock_guard<std::mutex> lk(streams_mutex_);

        auto& st = streams_[key];
        st.last_activity_ns = now_ns;
        st.total_packets++;
        st.total_bytes += pkt.payload.size();


        st.assembled.insert(st.assembled.end(),
                             pkt.payload.begin(), pkt.payload.end());
        st.syn_seen = true;
    }


    std::optional<stream_snapshot_t> get_stream(const stream_key_t& key) const {
        std::lock_guard<std::mutex> lk(streams_mutex_);
        auto it = streams_.find(key);
        if (it == streams_.end()) return std::nullopt;
        return make_snapshot(key, it->second);
    }


    std::vector<stream_snapshot_t> get_all() const {
        std::lock_guard<std::mutex> lk(streams_mutex_);
        std::vector<stream_snapshot_t> out;
        out.reserve(streams_.size());
        for (auto& [k, v] : streams_)
            out.push_back(make_snapshot(k, v));
        return out;
    }


    void evict_stale(uint64_t age_ns = 30'000'000'000ULL) {
        uint64_t now_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        std::lock_guard<std::mutex> lk(streams_mutex_);
        for (auto it = streams_.begin(); it != streams_.end(); ) {
            if (now_ns - it->second.last_activity_ns > age_ns)
                it = streams_.erase(it);
            else
                ++it;
        }
    }

    void clear() {
        std::lock_guard<std::mutex> lk(streams_mutex_);
        streams_.clear();
    }

    size_t stream_count() const {
        std::lock_guard<std::mutex> lk(streams_mutex_);
        return streams_.size();
    }

private:
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

    void poll_loop() {
        while (running_.load()) {
            if (driver_bridge::using_kernel_driver()) {
                auto packets = driver_bridge::get_captured_packets(32);
                for (auto& pkt : packets) {
                    if (filter_pid_ == 0 || pkt.pid == filter_pid_)
                        feed(pkt);
                }
            }

            // Evict stale streams every ~60 seconds (12000 * 5ms loops)
            evict_counter_++;
            if (evict_counter_ >= 12000) {
                evict_stale(30'000'000'000ULL);
                evict_counter_ = 0;
            }


            for (int i = 0; i < 5 && running_.load(); i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    mutable std::mutex streams_mutex_;
    std::unordered_map<stream_key_t, stream_state_t, stream_key_hash_t> streams_;
    std::thread  poll_thread_;
    std::atomic<bool>     running_{false};
    uint32_t              filter_pid_     = 0;
    uint32_t              evict_counter_  = 0;
};

inline tcp_stream_tracker_t g_stream_tracker;

}
