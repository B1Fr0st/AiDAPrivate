#pragma once


#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "protocol_parser.hpp"

namespace mitm_proxy {


enum class intercept_action { forward, drop, modify };

enum class hold_decision_t { pending, forward, drop, modified };

enum class proxy_mode_t { regular, reverse, transparent, socks5 };

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
    std::vector<std::string> tags;
    std::string notes;
};

enum class tls_observation_kind_t {
    http_tls,
    client_handshake_failed,
    upstream_handshake_failed,
    upstream_pin_mismatch,
    sni_authority_mismatch,
    non_http_tls,
    tunnel_passthrough
};

struct tls_observation_t {
    uint64_t timestamp = 0;
    tls_observation_kind_t kind = tls_observation_kind_t::http_tls;
    std::string client_addr;
    uint16_t client_port = 0;
    std::string target_host;
    uint16_t target_port = 0;
    std::string sni;
    std::string alpn;
    std::string detail;
};

struct held_wait_t {
    std::mutex                mtx;
    std::condition_variable   cv;
    hold_decision_t           decision = hold_decision_t::pending;
    std::vector<uint8_t>      modified_request;
    bool                      released = false;
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
    proxy_mode_t mode = proxy_mode_t::regular;
    std::string bind_addr = "127.0.0.1";
    uint16_t    bind_port = 8443;
    bool        intercept_enabled = false;
    bool        decode_tls = true;
    bool        enable_h2 = true;
    bool        enable_websocket = true;
    size_t      max_history = 4096;
    size_t      max_body_size = 16 * 1024 * 1024;


    upstream_proxy_config upstream;

    std::string reverse_target_host;
    uint16_t    reverse_target_port = 0;
    bool        reverse_target_tls = true;

    bool        require_proxy_auth = false;
    std::string proxy_auth_realm = "AiDA Proxy";
    std::string proxy_auth_username;
    std::string proxy_auth_password;

    bool        enable_sticky_sessions = false;
    uint64_t    sticky_session_rule_id = 0;

    bool        enable_pac = false;
    std::string pac_script;
    bool        pac_fail_closed = true;

    bool        enable_connection_pool = false;
    size_t      connection_pool_max_idle_total = 32;
    size_t      connection_pool_max_idle_per_key = 4;
    uint64_t    connection_pool_idle_timeout_ms = 30000;
    uint64_t    connection_pool_max_age_ms = 300000;


    bool        use_wfp_redirect = false;
    uint16_t    redirect_target_port = 443;
    uint32_t    wfp_rule_id = 0;
};


using intercept_callback_t = std::function<intercept_action(http_exchange& exchange)>;

struct ws_frame_observed_t {
    uint64_t                            timestamp = 0;
    uint64_t                            exchange_id = 0;
    std::string                         host;
    uint16_t                            port = 0;
    bool                                is_outbound = false;
    bool                                is_text = false;
    uint8_t                             opcode = 0;
    std::vector<uint8_t>                payload;
};

using ws_frame_callback_t = std::function<void(const ws_frame_observed_t& frame)>;


static constexpr uint32_t WORKER_POOL_SIZE = 4;

struct work_item {
    uintptr_t   client_socket;
    uint32_t    client_ip;
    uint16_t    client_port;
    uint64_t    listener_id = 0;
    proxy_config config;
};

struct state_t {
    proxy_config       config;
    std::atomic<bool>  running{false};
    std::atomic<bool>  proxy_alive{false};
    std::mutex         proxy_start_mtx;
    std::condition_variable proxy_start_cv;
    std::atomic<bool>  listener_done{true};


    std::atomic<uint32_t>         active_worker_count{0};
    std::queue<work_item>         work_queue;
    std::mutex                    work_mutex;
    std::condition_variable       work_cv;


    std::mutex                                  history_mutex;
    std::deque<std::shared_ptr<http_exchange>>  history;
    std::atomic<uint64_t>                       next_id{1};

    std::mutex                                  tls_observation_mutex;
    std::deque<tls_observation_t>               tls_observations;


    std::mutex                                                           held_mutex;
    std::condition_variable                                              held_cv;
    std::list<http_exchange>                                             held_storage;
    std::vector<http_exchange*>                                          held_exchanges;
    std::unordered_map<uint64_t, std::shared_ptr<held_wait_t>>           held_waits;


    std::atomic<uint64_t>  total_requests{0};
    std::atomic<uint64_t>  total_bytes_in{0};
    std::atomic<uint64_t>  total_bytes_out{0};
    std::atomic<uint32_t>  active_connections{0};


    uintptr_t  listen_socket = ~static_cast<uintptr_t>(0);


    intercept_callback_t intercept_cb;

    std::mutex           ws_observer_mutex;
    ws_frame_callback_t  ws_observer_cb;
};

inline state_t g_state;


bool start(const proxy_config& config = {});
void stop();
bool start_listener(const proxy_config& config, uint64_t* listener_id = nullptr);
bool stop_listener(uint64_t listener_id);
void pre_initialize();
void shutdown();
bool is_running();
proxy_config get_config();
bool set_config(const proxy_config& config);

struct listener_snapshot {
    uint64_t id = 0;
    proxy_config config;
    bool running = false;
    uint64_t accepted = 0;
};

std::vector<listener_snapshot> get_listeners();


std::vector<http_exchange> get_history(size_t max_count = 0);
std::vector<http_exchange> get_history_by_ids(const std::vector<uint64_t>& ids);
const http_exchange* find_exchange(uint64_t id);
void clear_history();
size_t history_count();
bool append_history(const std::vector<http_exchange>& exchanges, bool preserve_ids = true);
bool set_exchange_tags(uint64_t id, const std::vector<std::string>& tags);
bool add_exchange_tag(uint64_t id, const std::string& tag);
bool remove_exchange_tag(uint64_t id, const std::string& tag);
bool set_exchange_notes(uint64_t id, const std::string& notes);

std::vector<tls_observation_t> get_tls_observations(size_t max_count = 0);
void clear_tls_observations();
const char* to_string(tls_observation_kind_t kind);


void set_intercept_enabled(bool enabled);
bool is_intercept_enabled();
void set_intercept_callback(intercept_callback_t cb);

void set_ws_frame_callback(ws_frame_callback_t cb);
void publish_ws_frame(const ws_frame_observed_t& frame);


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
