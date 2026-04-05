#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Forward declarations for driver types
namespace voyager { class device_t; }

namespace network_view {

// ─── Sub-tabs ─────────────────────────────────────────────────────

enum class sub_tab_t : int {
    connections = 0,
    capture,
    intercept,
    proxy,
    dns,
    filters,
    bandwidth,
    repeater,
    keylog,
    COUNT
};

// ─── Cached connection info ───────────────────────────────────────

struct connection_entry {
    uint32_t pid = 0;
    uint8_t  protocol = 0;   // 6=TCP, 17=UDP
    uint8_t  state = 0;
    uint16_t local_port = 0;
    uint16_t remote_port = 0;
    uint8_t  address_family = 0;
    uint8_t  local_addr[16] = {};
    uint8_t  remote_addr[16] = {};
    std::string process_name;
};

// ─── Cached captured packet ───────────────────────────────────────

struct packet_entry {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint8_t     protocol = 0;
    uint8_t     direction = 0; // 0=in, 1=out
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint8_t     src_addr[16] = {};
    uint8_t     dst_addr[16] = {};
    uint32_t    payload_size = 0;
    std::vector<uint8_t> payload;
    std::string protocol_label;  // detected protocol
    std::string summary;         // short summary of content
};

// ─── DNS entry ────────────────────────────────────────────────────

struct dns_entry {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint16_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
};

// ─── Filter rule ──────────────────────────────────────────────────

struct filter_entry {
    uint32_t rule_id = 0;
    uint8_t  action = 0;    // 0=block, 1=allow
    uint8_t  direction = 0; // 0=in, 1=out, 2=both
    uint8_t  protocol = 0;
    uint32_t pid = 0;
    uint16_t port = 0;
    std::string ip_addr;
    bool     active = true;
};

// ─── Bandwidth entry ──────────────────────────────────────────────

struct bw_entry {
    uint32_t    pid = 0;
    std::string process_name;
    uint64_t    bytes_in = 0;
    uint64_t    bytes_out = 0;
    float       rate_in = 0.f;   // bytes/sec
    float       rate_out = 0.f;
};

// ─── Repeater state ───────────────────────────────────────────────

struct repeater_entry {
    std::string host;
    uint16_t    port = 443;
    bool        use_tls = true;
    std::string raw_request;    // editable
    std::string raw_response;   // readonly
    int         status_code = 0;
    uint64_t    latency_ms = 0;
    bool        in_progress = false;
};

// ─── Main state ───────────────────────────────────────────────────

struct state_t {
    bool active = false;

    sub_tab_t active_tab = sub_tab_t::connections;

    // ── Connections tab ──
    std::mutex                    conn_mutex;
    std::vector<connection_entry> connections;
    int                           conn_selected = -1;
    uint32_t                      conn_filter_pid = 0;
    uint8_t                       conn_filter_protocol = 0; // 0=all
    char                          conn_filter_text[128] = {};
    bool                          conn_auto_refresh = true;
    std::thread                   conn_thread;
    std::atomic<bool>             conn_polling{false};

    // ── Capture tab ──
    std::mutex                    cap_mutex;
    std::deque<packet_entry>      captured_packets;
    size_t                        cap_max_packets = 8192;
    int                           cap_selected = -1;
    bool                          cap_running = false;
    uint32_t                      cap_filter_pid = 0;
    uint16_t                      cap_filter_port = 0;
    uint8_t                       cap_filter_protocol = 0;
    char                          cap_filter_text[128] = {};
    bool                          cap_auto_scroll = true;
    std::thread                   cap_thread;
    std::atomic<bool>             cap_polling{false};

    // ── Intercept tab ──
    bool                          intercept_enabled = false;
    int                           intercept_selected = -1;

    // ── Proxy tab ──
    char                          proxy_bind_addr[64] = "127.0.0.1";
    int                           proxy_port = 8443;
    bool                          proxy_decode_tls = true;
    int                           proxy_selected = -1;
    char                          proxy_filter_text[128] = {};

    // ── DNS tab ──
    std::mutex                    dns_mutex;
    std::vector<dns_entry>        dns_entries;
    int                           dns_selected = -1;
    uint32_t                      dns_filter_pid = 0;
    char                          dns_filter_text[128] = {};
    std::thread                   dns_thread;
    std::atomic<bool>             dns_polling{false};

    // ── Filters tab ──
    std::vector<filter_entry>     filters;
    int                           filter_selected = -1;
    // New filter editor
    int   nf_action = 0;     // 0=block, 1=allow
    int   nf_direction = 2;  // 0=in, 1=out, 2=both
    int   nf_protocol = 0;   // 0=any, 6=TCP, 17=UDP
    char  nf_pid[16] = {};
    char  nf_port[16] = {};
    char  nf_ip[64] = {};

    // ── Bandwidth tab ──
    std::mutex                    bw_mutex;
    std::vector<bw_entry>         bw_entries;
    bool                          bw_monitoring = false;
    std::thread                   bw_thread;
    std::atomic<bool>             bw_polling{false};

    // ── Repeater tab ──
    std::vector<repeater_entry>   repeater_entries;
    int                           repeater_selected = 0;
    char                          rep_host[256] = {};
    int                           rep_port = 443;
    bool                          rep_use_tls = true;

    // ── Keylog tab ──
    char                          kl_exe_path[512] = {};
    char                          kl_args[512] = {};
    int                           kl_selected = -1;
    bool                          kl_auto_scroll = true;

    // ── Detail panel ──
    bool                          show_detail = true;
    float                         detail_ratio = 0.65f; // top panel = 65%

    // ── Animation ──
    float tab_anim[static_cast<int>(sub_tab_t::COUNT)] = {};
};

inline state_t g_state;

// ─── Control ──────────────────────────────────────────────────────

void initialize();
void shutdown();

// ─── Render ───────────────────────────────────────────────────────

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

} // namespace network_view
