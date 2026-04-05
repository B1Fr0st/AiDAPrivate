#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "protocol_parser.hpp"

namespace mitm_proxy {

// ─── Types ────────────────────────────────────────────────────────

enum class intercept_action { forward, drop, modify };

struct http_exchange {
    uint64_t    id = 0;
    uint64_t    timestamp = 0;           // GetTickCount64
    std::string client_addr;
    uint16_t    client_port = 0;
    std::string target_host;             // from CONNECT or Host header
    uint16_t    target_port = 0;

    // Raw bytes
    std::vector<uint8_t> raw_request;
    std::vector<uint8_t> raw_response;

    // Parsed (if applicable)
    protocol_parser::http_request  request;
    protocol_parser::http_response response;

    // TLS info
    bool        is_tls = false;
    std::string tls_sni;
    std::string tls_version_str;

    // State
    enum class state_t { pending, forwarding, complete, dropped, error };
    state_t     state = state_t::pending;
    std::string error_msg;

    // Timing
    uint64_t    request_time = 0;
    uint64_t    response_time = 0;
    uint64_t    latency_ms = 0;

    // Size summaries
    size_t      request_size = 0;
    size_t      response_size = 0;
};

struct proxy_config {
    std::string bind_addr = "127.0.0.1";
    uint16_t    bind_port = 8443;
    bool        intercept_enabled = false;   // hold requests for user action
    bool        decode_tls = true;           // perform MITM TLS interception
    size_t      max_history = 4096;
    size_t      max_body_size = 16 * 1024 * 1024; // 16 MB
};

// Intercept callback: called when a request is intercepted
// Return intercept_action::forward to pass through, drop to discard, modify to use modified_data
using intercept_callback_t = std::function<intercept_action(http_exchange& exchange)>;

// ─── Proxy State ──────────────────────────────────────────────────

struct state_t {
    proxy_config       config;
    std::atomic<bool>  running{false};
    std::thread        listener_thread;

    // Exchange history
    std::mutex                 history_mutex;
    std::deque<http_exchange>  history;
    uint64_t                   next_id = 1;

    // Held exchanges (when intercept is enabled)
    std::mutex                          held_mutex;
    std::vector<http_exchange*>         held_exchanges;

    // Stats
    std::atomic<uint64_t>  total_requests{0};
    std::atomic<uint64_t>  total_bytes_in{0};
    std::atomic<uint64_t>  total_bytes_out{0};
    std::atomic<uint32_t>  active_connections{0};

    // Socket
    uintptr_t  listen_socket = ~static_cast<uintptr_t>(0);

    // Intercept callback
    intercept_callback_t intercept_cb;
};

inline state_t g_state;

// ─── Control ──────────────────────────────────────────────────────

bool start(const proxy_config& config = {});
void stop();
bool is_running();

// ─── History ──────────────────────────────────────────────────────

std::vector<http_exchange> get_history(size_t max_count = 0);
const http_exchange* find_exchange(uint64_t id);
void clear_history();
size_t history_count();

// ─── Intercept ────────────────────────────────────────────────────

void set_intercept_enabled(bool enabled);
bool is_intercept_enabled();
void set_intercept_callback(intercept_callback_t cb);

// Forward a held exchange
void forward_exchange(uint64_t id);
// Forward with modifications
void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request);
// Drop a held exchange
void drop_exchange(uint64_t id);
// Forward all held exchanges
void forward_all();
// Drop all held exchanges
void drop_all();

// ─── Repeater ─────────────────────────────────────────────────────

struct repeat_result {
    bool success = false;
    http_exchange exchange;
    std::string error;
};

// Replay a request to the target host
repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls,
                             const std::vector<uint8_t>& raw_request);

// ─── Stats ────────────────────────────────────────────────────────

struct proxy_stats {
    bool     running = false;
    uint64_t total_requests = 0;
    uint64_t total_bytes_in = 0;
    uint64_t total_bytes_out = 0;
    uint32_t active_connections = 0;
    size_t   history_size = 0;
    size_t   held_count = 0;
};

proxy_stats get_stats();

} // namespace mitm_proxy
