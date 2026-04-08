#pragma once


#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "protocol_parser.hpp"

namespace mitm_proxy {


enum class intercept_action { forward, drop, modify };

struct http_exchange {
    uint64_t    id = 0;
    uint64_t    timestamp = 0;
    std::string client_addr;
    uint16_t    client_port = 0;
    std::string target_host;
    uint16_t    target_port = 0;


    std::vector<uint8_t> raw_request;
    std::vector<uint8_t> raw_response;


    protocol_parser::http_request  request;
    protocol_parser::http_response response;


    bool        is_tls = false;
    std::string tls_sni;
    std::string tls_version_str;
    std::string alpn_protocol;


    bool        is_websocket = false;
    uint32_t    ws_frames_sent = 0;
    uint32_t    ws_frames_recv = 0;


    struct ws_frame_entry {
        uint64_t    timestamp = 0;
        bool        outbound = false;
        protocol_parser::ws_opcode opcode = protocol_parser::ws_opcode::text;
        std::vector<uint8_t> payload;
    };
    std::vector<ws_frame_entry> ws_frames;


    bool        is_h2 = false;
    int32_t     h2_stream_id = 0;


    enum class state_t { pending, forwarding, complete, dropped, error };
    state_t     state = state_t::pending;
    std::string error_msg;


    uint64_t    request_time = 0;
    uint64_t    response_time = 0;
    uint64_t    latency_ms = 0;


    size_t      request_size = 0;
    size_t      response_size = 0;
};


struct upstream_proxy_config {
    enum class type_t { none, http_connect, socks5 };
    type_t      type = type_t::none;
    std::string host;
    uint16_t    port = 0;
    std::string username;
    std::string password;
};

struct proxy_config {
    std::string bind_addr = "127.0.0.1";
    uint16_t    bind_port = 8443;
    bool        intercept_enabled = false;
    bool        decode_tls = true;
    bool        enable_h2 = true;
    bool        enable_websocket = true;
    size_t      max_history = 4096;
    size_t      max_body_size = 16 * 1024 * 1024;


    upstream_proxy_config upstream;


    bool        use_wfp_redirect = false;
    uint16_t    redirect_target_port = 443;
    uint32_t    wfp_rule_id = 0;
};


using intercept_callback_t = std::function<intercept_action(http_exchange& exchange)>;


static constexpr uint32_t WORKER_POOL_SIZE = 4;

struct work_item {
    uintptr_t   client_socket;
    uint32_t    client_ip;
    uint16_t    client_port;
};

struct state_t {
    proxy_config       config;
    std::atomic<bool>  running{false};
    std::thread        listener_thread;


    std::vector<std::thread>      worker_threads;
    std::queue<work_item>         work_queue;
    std::mutex                    work_mutex;
    std::condition_variable       work_cv;


    std::mutex                 history_mutex;
    std::deque<http_exchange>  history;
    uint64_t                   next_id = 1;


    std::mutex                          held_mutex;
    std::vector<http_exchange*>         held_exchanges;


    std::atomic<uint64_t>  total_requests{0};
    std::atomic<uint64_t>  total_bytes_in{0};
    std::atomic<uint64_t>  total_bytes_out{0};
    std::atomic<uint32_t>  active_connections{0};


    uintptr_t  listen_socket = ~static_cast<uintptr_t>(0);


    intercept_callback_t intercept_cb;
};

inline state_t g_state;


bool start(const proxy_config& config = {});
void stop();
bool is_running();


std::vector<http_exchange> get_history(size_t max_count = 0);
const http_exchange* find_exchange(uint64_t id);
void clear_history();
size_t history_count();


void set_intercept_enabled(bool enabled);
bool is_intercept_enabled();
void set_intercept_callback(intercept_callback_t cb);


void forward_exchange(uint64_t id);

void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request);

void drop_exchange(uint64_t id);

void forward_all();

void drop_all();


std::vector<http_exchange> get_held_exchanges();


struct repeat_result {
    bool success = false;
    http_exchange exchange;
    std::string error;
};


repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls,
                             const std::vector<uint8_t>& raw_request);


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

}
