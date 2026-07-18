#pragma once

#include "network_preview_adapter.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ssl_keylog {

struct keylog_entry {
    std::string label;
    std::string client_random_hex;
    std::string secret_hex;
    uint64_t timestamp = 0;
};

struct retained_set_token {
    uint64_t generation = 0;
    size_t count = 0;
};

struct state_t {
    std::string keylog_path;
    std::atomic<bool> watching{false};
    std::mutex entries_mutex;
    std::deque<keylog_entry> entries;
    size_t max_entries = 8192;
    std::unordered_map<std::string, std::vector<keylog_entry>> by_client_random;
    uint64_t retained_generation = 1;
    size_t file_pos = 0;
    bool fixture_seeded = false;
};

inline state_t g_state;

inline void advance_retained_generation_locked() {
    ++g_state.retained_generation;
    if (g_state.retained_generation == 0) ++g_state.retained_generation;
}

inline void rebuild_client_random_index_locked() {
    g_state.by_client_random.clear();
    for (const auto& entry : g_state.entries)
        g_state.by_client_random[entry.client_random_hex].push_back(entry);
}

struct launch_result {
    bool success = false;
    uint32_t pid = 0;
    std::string error;
    std::string keylog_path;
};

inline void seed_entries() {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    if (g_state.fixture_seeded) return;
    g_state.fixture_seeded = true;
    g_state.entries.push_back({
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "9f2914d26c2379a1c3b12e70d5d66304515776e2b42587d5cbf468eddbd67b20",
        "3a18c27901af9e44f892ce16f35ccf7d50a948c1925d1d6234aa7c258d8fa54a",
        aida::preview::network::monotonic_ms()
    });
    g_state.entries.push_back({
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "9f2914d26c2379a1c3b12e70d5d66304515776e2b42587d5cbf468eddbd67b20",
        "81ad09d082dc262ff12e9537eb9ea67bd5df249335fd27f44d245f72b52b6e10",
        aida::preview::network::monotonic_ms()
    });
    g_state.entries.push_back({
        "CLIENT_TRAFFIC_SECRET_0",
        "9f2914d26c2379a1c3b12e70d5d66304515776e2b42587d5cbf468eddbd67b20",
        "66a811d98ef376e04fc994a8ea80eef631e4cead7559c4e945116d075ff7c492",
        aida::preview::network::monotonic_ms()
    });
    rebuild_client_random_index_locked();
    advance_retained_generation_locked();
}

inline launch_result launch_with_keylog(const std::string& exe_path,
                                        const std::string&,
                                        const std::string& keylog_path = {}) {
    launch_result result;
    result.success = !exe_path.empty();
    result.pid = result.success ? 12064 : 0;
    result.error = result.success ? std::string() : "Select an executable";
    result.keylog_path = keylog_path.empty() ? "/aida-preview/captures/sslkeys.log" : keylog_path;
    if (result.success) {
        g_state.keylog_path = result.keylog_path;
        g_state.watching.store(true, std::memory_order_release);
        seed_entries();
        aida::preview::network::record_receipt("SSL key log launch", exe_path);
    }
    return result;
}

inline void start_watching(const std::string& keylog_path) {
    g_state.keylog_path = keylog_path.empty() ? "/aida-preview/captures/sslkeys.log" : keylog_path;
    g_state.watching.store(true, std::memory_order_release);
    seed_entries();
    aida::preview::network::record_receipt("SSL key log watch", g_state.keylog_path);
}

inline void stop_watching() {
    g_state.watching.store(false, std::memory_order_release);
    aida::preview::network::record_receipt("SSL key log watch", "stopped");
}

inline bool is_watching() {
    return g_state.watching.load(std::memory_order_acquire);
}

inline std::vector<keylog_entry> get_entries(size_t max_count = 0) {
    seed_entries();
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    const size_t count = max_count == 0 ? g_state.entries.size() : std::min(max_count, g_state.entries.size());
    return std::vector<keylog_entry>(g_state.entries.end() - static_cast<ptrdiff_t>(count), g_state.entries.end());
}

inline size_t entry_count() {
    seed_entries();
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    return g_state.entries.size();
}

inline retained_set_token retained_token() {
    seed_entries();
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    return {g_state.retained_generation, g_state.entries.size()};
}

inline void clear_entries() {
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    if (g_state.entries.empty()) return;
    g_state.entries.clear();
    g_state.by_client_random.clear();
    advance_retained_generation_locked();
    aida::preview::network::record_receipt("SSL key log", "entries cleared");
}

inline bool clear_entries_if_exact(retained_set_token reviewed) {
    seed_entries();
    std::lock_guard<std::mutex> lock(g_state.entries_mutex);
    if (g_state.retained_generation != reviewed.generation ||
        g_state.entries.size() != reviewed.count)
        return false;
    g_state.entries.clear();
    g_state.by_client_random.clear();
    advance_retained_generation_locked();
    aida::preview::network::record_receipt("SSL key log", "reviewed entries cleared");
    return true;
}

}
