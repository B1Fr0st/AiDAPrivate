#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


namespace voyager { class device_t; }

namespace network_view {


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
    pcap_export,
    fuzzer,
    offensive,
    websocket,
    scripting,
    decoder,
    sitemap,
    scope,
    cookies,
    scanner,
    recon,
    intruder,
    collab,
    sequencer,
    comparer,
    jwt,
    mr,
    session,
    api,
    ws_edit,
    h2_edit,
    logger,
    csp,
    upstream,
    browser,
    reports,
    headless,
    COUNT
};


struct connection_entry_t {
    uint32_t pid = 0;
    uint8_t  protocol = 0;
    uint8_t  state = 0;
    uint16_t local_port = 0;
    uint16_t remote_port = 0;
    uint8_t  address_family = 0;
    uint8_t  local_addr[16] = {};
    uint8_t  remote_addr[16] = {};
    std::string process_name;
};


struct packet_entry_t {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint8_t     protocol = 0;
    uint8_t     direction = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint8_t     src_addr[16] = {};
    uint8_t     dst_addr[16] = {};
    uint32_t    payload_size = 0;
    std::vector<uint8_t> payload;
    std::string protocol_label;
    std::string summary;
};


struct dns_entry_t {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint16_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
};


struct filter_entry_t {
    uint32_t rule_id = 0;
    uint8_t  action = 0;
    uint8_t  direction = 0;
    uint8_t  protocol = 0;
    uint32_t pid = 0;
    uint16_t port = 0;
    std::string ip_addr;
    bool     active = true;
};


struct bw_entry_t {
    uint32_t    pid = 0;
    std::string process_name;
    uint64_t    bytes_in = 0;
    uint64_t    bytes_out = 0;
    float       rate_in = 0.f;
    float       rate_out = 0.f;
    float       rate_history[64] = {};
    int         history_index = 0;
};


struct repeater_entry_t {
    std::string       host;
    uint16_t          port = 443;
    bool              use_tls = true;
    std::string       raw_request;
    std::string       raw_response;
    int               status_code = 0;
    uint64_t          latency_ms = 0;
    std::atomic<bool> in_progress{false};
};

enum class fuzzer_attack_mode_t : int {
    sniper      = 0,
    pitchfork   = 1,
    clusterbomb = 2,
};


struct payload_set_t {
    std::string              name;
    std::string              source;
    int                      type = 0;
    std::vector<std::string> entries;
    char                     grep_regex[256]  = {};
    char                     grep_group[32]   = "1";
};


struct state_t {
    bool active = false;
    std::atomic<uint64_t> last_render_tick_ms{0};

    sub_tab_t active_tab = sub_tab_t::connections;


    std::mutex                    conn_mutex;
    std::vector<connection_entry_t> connections;
    int                           conn_selected = -1;
    uint32_t                      conn_filter_pid = 0;
    uint8_t                       conn_filter_protocol = 0;
    char                          conn_filter_text[128] = {};
    bool                          conn_auto_refresh = true;
    std::atomic<bool>             conn_auto_refresh_enabled{true};
    std::atomic<bool>             conn_thread_done{true};
    std::atomic<bool>             conn_polling{false};
    std::mutex                    conn_cv_mutex;
    std::condition_variable       conn_cv;


    std::mutex                    cap_mutex;
    std::deque<packet_entry_t>    captured_packets;
    size_t                        cap_max_packets = 8192;
    int                           cap_selected = -1;
    std::atomic<bool>             cap_running{false};
    std::atomic<bool>             cap_start_pending{false};
    std::atomic<bool>             cap_stop_pending{false};
    uint32_t                      cap_filter_pid = 0;
    uint16_t                      cap_filter_port = 0;
    uint8_t                       cap_filter_protocol = 0;
    char                          cap_filter_text[128] = {};
    bool                          cap_auto_scroll = true;
    std::atomic<bool>             cap_thread_done{true};
    std::atomic<bool>             cap_polling{false};
    std::mutex                    cap_cv_mutex;
    std::condition_variable       cap_cv;
    std::atomic<bool>             cap_thread_alive{false};


    bool                          intercept_enabled = false;
    int                           intercept_selected = -1;


    char                          proxy_bind_addr[64] = "127.0.0.1";
    int                           proxy_port = 8443;
    bool                          proxy_decode_tls = true;
    int                           proxy_selected = -1;
    char                          proxy_filter_text[128] = {};


    std::mutex                    dns_mutex;
    std::deque<dns_entry_t>       dns_entries;
    size_t                        dns_max_entries = 8192;
    int                           dns_selected = -1;
    uint32_t                      dns_filter_pid = 0;
    char                          dns_filter_text[128] = {};
    bool                          dns_auto_scroll = true;
    std::atomic<bool>             dns_thread_done{true};
    std::atomic<bool>             dns_polling{false};
    std::mutex                    dns_cv_mutex;
    std::condition_variable       dns_cv;
    std::atomic<bool>             dns_thread_alive{false};


    std::vector<filter_entry_t>   filters;
    int                           filter_selected = -1;

    int   nf_action = 0;
    int   nf_direction = 2;
    int   nf_protocol = 0;
    char  nf_pid[16] = {};
    char  nf_port[16] = {};
    char  nf_ip[64] = {};


    std::mutex                    bw_mutex;
    std::vector<bw_entry_t>       bw_entries;
    bool                          bw_monitoring = false;
    int                           bw_selected = -1;
    std::atomic<bool>             bw_thread_done{true};
    std::atomic<bool>             bw_polling{false};
    std::mutex                    bw_cv_mutex;
    std::condition_variable       bw_cv;
    std::atomic<bool>             bw_thread_alive{false};


    std::vector<std::shared_ptr<repeater_entry_t>> repeater_entries;
    int                                            repeater_selected = 0;
    char                          rep_host[256] = {};
    int                           rep_port = 443;
    bool                          rep_use_tls = true;


    char                          kl_exe_path[512] = {};
    char                          kl_args[512] = {};
    char                          kl_watch_path[512] = {};
    int                           kl_selected = -1;
    bool                          kl_auto_scroll = true;


    char                          pcap_path[512] = {};
    std::atomic<bool>             pcap_writing{false};
    std::atomic<uint32_t>         pcap_written_count{0};
    uint32_t                      pcap_filter_pid = 0;
    uint8_t                       pcap_filter_protocol = 0;
    std::string                   pcap_last_error;
    std::mutex                    pcap_error_mutex;


    struct fuzzer_entry_t {
        std::string host;
        uint16_t    port = 443;
        bool        use_tls = true;
        std::string base_request;
        std::string payload_source;
        int         payload_type = 0;
        int         thread_count = 4;
        int         delay_ms = 0;
        int         match_status = 0;
        std::string match_body;
        int         match_size_op = 0;
        int         match_size = 0;
        bool        stop_on_match = false;
        fuzzer_attack_mode_t    attack_mode = fuzzer_attack_mode_t::sniper;
        std::vector<payload_set_t> payload_sets;
    };

    struct fuzzer_result_t {
        int         index = 0;
        std::string payload;
        int         status_code = 0;
        size_t      response_len = 0;
        uint64_t    latency_ms = 0;
        bool        match = false;
        std::string response_preview;
        std::vector<std::string> payloads;
        std::string extracted_value;
    };

    fuzzer_entry_t                fuzz_config;
    std::mutex                    fuzz_mutex;
    std::vector<fuzzer_result_t>  fuzz_results;
    std::atomic<bool>             fuzz_running{false};
    std::atomic<int>              fuzz_progress{0};
    std::atomic<int>              fuzz_total{0};
    std::atomic<bool>             fuzz_thread_done{true};
    std::mutex                    fuzz_cv_mutex;
    std::condition_variable       fuzz_cv;
    std::atomic<bool>             fuzz_thread_alive{false};
    int                           fuzz_selected = -1;

    char                          off_target_url[1024] = {};
    char                          off_target_param[128] = {};
    char                          off_payload_json[8192] = "{}";
    char                          off_raw_request[32768] = {};
    int                           off_workflow = 0;
    int                           off_timeout_ms = 15000;
    int                           off_max_payloads = 16;
    int                           off_max_requests = 32;
    bool                          off_scope_only = true;
    std::atomic<bool>             off_running{false};
    std::atomic<bool>             off_cancel_requested{false};
    std::atomic<uint64_t>         off_run_id{0};
    std::atomic<uint64_t>         off_active_fuzz_job_id{0};
    std::mutex                    off_mutex;
    std::string                   off_status = "Idle";
    std::string                   off_result;


    struct ws_frame_entry_t {
        uint64_t    timestamp = 0;
        uint64_t    exchange_id = 0;
        std::string host;
        uint16_t    port = 0;
        bool        is_outbound = false;
        bool        is_text = false;
        uint8_t     opcode = 0;
        std::vector<uint8_t> payload;
        std::string preview;
    };
    std::mutex                    ws_mutex;
    std::deque<ws_frame_entry_t> ws_frames;
    size_t                        ws_max_frames = 4096;
    int                           ws_selected = -1;
    bool                          ws_auto_scroll = true;
    char                          ws_filter_text[128] = {};


    struct script_entry_t {
        std::string name;
        std::string path;
        bool        enabled = true;
        bool        loaded = false;
    };
    std::vector<script_entry_t>   scripts;
    int                           script_selected = -1;
    char                          script_editor_buf[32768] = {};
    char                          script_console_buf[512] = {};
    std::mutex                    script_log_mutex;
    std::deque<std::string>       script_log;
    size_t                        script_log_max = 2048;
    bool                          script_log_auto_scroll = true;


    struct decoder_step_t {
        std::string transform_name;
        std::vector<std::pair<std::string, std::string>> params;
    };
    std::vector<decoder_step_t>   decoder_pipeline;
    char                          decoder_input[16384] = {};
    std::string                   decoder_output;
    int                           decoder_selected_step = -1;
    int                           decoder_add_transform = 0;


    bool                          show_detail = true;
    float                         detail_ratio = 0.65f;


    float tab_anim[static_cast<int>(sub_tab_t::COUNT)] = {};

    float tab_scroll_x = 0.f;
    float tab_target_scroll_x = 0.f;
    int   tab_last_ensured = -1;
    float underline_x = 0.f;
    float underline_w = 0.f;
    float underline_vel = 0.f;
    float content_fade = 1.f;
    sub_tab_t prev_tab = sub_tab_t::connections;
};

inline state_t g_state;


void initialize();
void shutdown();


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
