#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
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
    websocket,
    scripting,
    decoder,
    COUNT
};


struct connection_entry {
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


struct packet_entry {
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


struct dns_entry {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint16_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
};


struct filter_entry {
    uint32_t rule_id = 0;
    uint8_t  action = 0;
    uint8_t  direction = 0;
    uint8_t  protocol = 0;
    uint32_t pid = 0;
    uint16_t port = 0;
    std::string ip_addr;
    bool     active = true;
};


struct bw_entry {
    uint32_t    pid = 0;
    std::string process_name;
    uint64_t    bytes_in = 0;
    uint64_t    bytes_out = 0;
    float       rate_in = 0.f;
    float       rate_out = 0.f;
    float       rate_history[64] = {};
    int         history_index = 0;
};


struct repeater_entry {
    std::string host;
    uint16_t    port = 443;
    bool        use_tls = true;
    std::string raw_request;
    std::string raw_response;
    int         status_code = 0;
    uint64_t    latency_ms = 0;
    bool        in_progress = false;
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

    sub_tab_t active_tab = sub_tab_t::connections;


    std::mutex                    conn_mutex;
    std::vector<connection_entry> connections;
    int                           conn_selected = -1;
    uint32_t                      conn_filter_pid = 0;
    uint8_t                       conn_filter_protocol = 0;
    char                          conn_filter_text[128] = {};
    bool                          conn_auto_refresh = true;
    std::thread                   conn_thread;
    std::atomic<bool>             conn_polling{false};


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


    bool                          intercept_enabled = false;
    int                           intercept_selected = -1;


    char                          proxy_bind_addr[64] = "127.0.0.1";
    int                           proxy_port = 8443;
    bool                          proxy_decode_tls = true;
    int                           proxy_selected = -1;
    char                          proxy_filter_text[128] = {};


    std::mutex                    dns_mutex;
    std::vector<dns_entry>        dns_entries;
    int                           dns_selected = -1;
    uint32_t                      dns_filter_pid = 0;
    char                          dns_filter_text[128] = {};
    std::thread                   dns_thread;
    std::atomic<bool>             dns_polling{false};


    std::vector<filter_entry>     filters;
    int                           filter_selected = -1;

    int   nf_action = 0;
    int   nf_direction = 2;
    int   nf_protocol = 0;
    char  nf_pid[16] = {};
    char  nf_port[16] = {};
    char  nf_ip[64] = {};


    std::mutex                    bw_mutex;
    std::vector<bw_entry>         bw_entries;
    bool                          bw_monitoring = false;
    std::thread                   bw_thread;
    std::atomic<bool>             bw_polling{false};


    std::vector<repeater_entry>   repeater_entries;
    int                           repeater_selected = 0;
    char                          rep_host[256] = {};
    int                           rep_port = 443;
    bool                          rep_use_tls = true;


    char                          kl_exe_path[512] = {};
    char                          kl_args[512] = {};
    int                           kl_selected = -1;
    bool                          kl_auto_scroll = true;


    char                          pcap_path[512] = {};
    bool                          pcap_writing = false;
    uint32_t                      pcap_written_count = 0;
    uint32_t                      pcap_filter_pid = 0;
    uint8_t                       pcap_filter_protocol = 0;


    struct fuzzer_entry {
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

    struct fuzzer_result {
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

    fuzzer_entry                  fuzz_config;
    std::mutex                    fuzz_mutex;
    std::vector<fuzzer_result>    fuzz_results;
    std::atomic<bool>             fuzz_running{false};
    std::atomic<int>              fuzz_progress{0};
    std::atomic<int>              fuzz_total{0};
    std::thread                   fuzz_thread;
    int                           fuzz_selected = -1;


    struct ws_frame_entry {
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
    std::deque<ws_frame_entry>    ws_frames;
    size_t                        ws_max_frames = 4096;
    int                           ws_selected = -1;
    bool                          ws_auto_scroll = true;
    char                          ws_filter_text[128] = {};


    struct script_entry {
        std::string name;
        std::string path;
        bool        enabled = true;
        bool        loaded = false;
    };
    std::vector<script_entry>     scripts;
    int                           script_selected = -1;
    char                          script_editor_buf[32768] = {};
    char                          script_console_buf[512] = {};
    std::mutex                    script_log_mutex;
    std::deque<std::string>       script_log;
    size_t                        script_log_max = 2048;
    bool                          script_log_auto_scroll = true;


    struct decoder_step {
        std::string transform_name;
        std::vector<std::pair<std::string, std::string>> params;
    };
    std::vector<decoder_step>     decoder_pipeline;
    char                          decoder_input[16384] = {};
    std::string                   decoder_output;
    int                           decoder_selected_step = -1;
    int                           decoder_add_transform = 0;


    bool                          show_detail = true;
    float                         detail_ratio = 0.65f;


    float tab_anim[static_cast<int>(sub_tab_t::COUNT)] = {};
};

inline state_t g_state;


void initialize();
void shutdown();


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
