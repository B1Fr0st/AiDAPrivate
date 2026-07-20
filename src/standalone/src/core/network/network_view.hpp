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

enum class intercept_command_t : std::uint8_t {
    forward_selected,
    drop_selected,
    forward_all,
    drop_all,
    forward_modified
};

struct intercept_command_capability_t {
    bool enabled = false;
    std::string disabled_reason;
};

intercept_command_capability_t intercept_command_capability(intercept_command_t command);
bool execute_intercept_command(intercept_command_t command, std::string* error = nullptr);

enum class operational_command_t : std::uint8_t {
    capture_start,
    capture_stop,
    proxy_start,
    proxy_stop,
    proxy_history_clear,
    proxy_ca_trust_repair,
    filter_add,
    filter_remove_selected,
    filter_clear,
    intercept_toggle,
    keylog_launch,
    keylog_watch,
    keylog_stop,
    keylog_clear
};

struct operational_command_capability_t {
    bool enabled = false;
    bool checked = false;
    std::string disabled_reason;
    std::string target_summary;
};

operational_command_capability_t operational_command_capability(
    operational_command_t command);
bool prepare_operational_command_confirmation(operational_command_t command,
                                              std::string* error = nullptr);
void cancel_operational_command_confirmation(operational_command_t command) noexcept;
bool execute_operational_command(operational_command_t command,
                                 std::string* error = nullptr);


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
    std::uint64_t       id = 0;
    std::string         source_artifact_id;
    std::string         source_session_id;
    std::uint64_t       request_revision = 1;
    std::uint64_t       request_hash = 0;
    std::uint64_t       response_hash = 0;
    std::uint64_t       response_timestamp = 0;
    std::uint64_t       reviewed_source_hash = 0;
    std::string         review_provenance;
    std::string       host;
    uint16_t          port = 443;
    bool              use_tls = true;
    std::string       raw_request;
    std::string       raw_response;
    int               status_code = 0;
    uint64_t          latency_ms = 0;
    bool              reviewed_draft = false;
    std::atomic<bool> in_progress{false};
};

enum class fuzzer_attack_mode_t : int {
    sniper      = 0,
    pitchfork   = 1,
    clusterbomb = 2,
};

enum class artifact_kind_t : std::uint8_t {
    packet = 0,
    exchange,
    request,
    response,
    websocket_frame,
    repeater_request,
    repeater_response,
    sitemap_request,
    sitemap_response,
    api_request,
    api_response,
    websocket_editor_frame,
    http2_request,
    http2_response,
    intruder_response,
    scanner_request,
    scanner_response,
    intercept_request
};

enum class exchange_context_origin_t : std::uint8_t {
    pointer = 0,
    menu_key,
    shift_f10
};

struct artifact_identity_t {
    std::string id;
    std::string parent_id;
    std::string source_view_id;
    std::string session_id;
    artifact_kind_t kind = artifact_kind_t::packet;
    std::uint64_t source_id = 0;
    std::uint64_t timestamp = 0;
    std::uint64_t revision = 0;
    std::uint64_t content_hash = 0;
    std::size_t content_size = 0;
    std::string label;
    std::string target_host;
    std::uint16_t target_port = 0;
    bool use_tls = false;
    bool raw_protocol = false;

    bool valid() const noexcept {
        return !id.empty() && !source_view_id.empty() && content_hash != 0;
    }
};

struct artifact_snapshot_t {
    artifact_identity_t identity;
    std::vector<std::uint8_t> bytes;
};

bool resolve_artifact(const artifact_identity_t& identity,
                      artifact_snapshot_t& snapshot,
                      std::string& unavailable_reason);
bool validate_reviewed_request(const artifact_identity_t& source,
                               const std::vector<std::uint8_t>& reviewed_request,
                               artifact_identity_t& canonical_source,
                               std::string& unavailable_reason);
bool stage_validated_reviewed_request(const artifact_identity_t& canonical_source,
                                      const std::vector<std::uint8_t>& reviewed_request,
                                      const std::string& provenance,
                                      artifact_identity_t& staged_identity,
                                      std::string& unavailable_reason);
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
    std::shared_ptr<const std::vector<connection_entry_t>> connection_snapshot;
    int                           conn_selected = -1;
    uint32_t                      conn_filter_pid = 0;
    uint8_t                       conn_filter_protocol = 0;
    char                          conn_filter_text[128] = {};
    bool                          conn_auto_refresh = true;
    std::atomic<bool>             conn_auto_refresh_enabled{true};
    std::atomic<bool>             conn_thread_done{true};
    std::atomic<bool>             conn_polling{false};
    std::atomic<bool>             conn_refresh_pending{false};
    std::atomic<std::uint64_t>    conn_refresh_serial{0};
    std::mutex                    conn_cv_mutex;
    std::condition_variable       conn_cv;


    std::mutex                    cap_mutex;
    std::deque<packet_entry_t>    captured_packets;
    std::shared_ptr<const std::vector<packet_entry_t>> capture_snapshot;
    size_t                        cap_max_packets = 8192;
    std::atomic<int>              cap_selected{-1};
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
    std::shared_ptr<const std::vector<dns_entry_t>> dns_snapshot;
    size_t                        dns_max_entries = 8192;
    int                           dns_selected = -1;
    uint32_t                      dns_filter_pid = 0;
    char                          dns_filter_text[128] = {};
    bool                          dns_auto_scroll = true;
    std::atomic<bool>             dns_thread_done{true};
    std::atomic<bool>             dns_polling{false};
    std::atomic<bool>             dns_refresh_pending{false};
    std::atomic<std::uint64_t>    dns_refresh_serial{0};
    std::mutex                    dns_cv_mutex;
    std::condition_variable       dns_cv;
    std::atomic<bool>             dns_thread_alive{false};


    std::vector<filter_entry_t>   filters;
    int                           filter_selected = -1;
    std::atomic<bool>             filter_mutation_pending{false};
    std::atomic<std::uint64_t>    filter_mutation_serial{0};

    int   nf_action = 0;
    int   nf_direction = 2;
    int   nf_protocol = 0;
    char  nf_pid[16] = {};
    char  nf_port[16] = {};
    char  nf_ip[64] = {};


    std::mutex                    bw_mutex;
    std::vector<bw_entry_t>       bw_entries;
    std::shared_ptr<const std::vector<bw_entry_t>> bandwidth_snapshot;
    bool                          bw_monitoring = false;
    int                           bw_selected = -1;
    std::atomic<bool>             bw_thread_done{true};
    std::atomic<bool>             bw_polling{false};
    std::atomic<bool>             bw_control_pending{false};
    std::atomic<std::uint64_t>    bw_control_serial{0};
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
    std::string                   pcap_last_path;
    std::string                   pcap_last_error;
    std::mutex                    pcap_error_mutex;
    std::atomic<bool>             har_writing{false};
    std::atomic<std::uint32_t>    har_written_count{0};
    std::string                   har_last_path;
    std::string                   har_last_error;
    std::mutex                    har_status_mutex;


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
    std::uint64_t                 fuzz_request_revision = 1;
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
    std::atomic<bool>             script_operation_pending{false};
    std::atomic<bool>             script_open_pending{false};
    std::atomic<std::uint64_t>    script_operation_serial{0};
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
    std::size_t                   decoder_input_size = 0;
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

const char* tab_name(sub_tab_t tab) noexcept;
void render_pane(sub_tab_t tab, float pos_x, float pos_y, float width, float height,
                 float alpha, float accent_r, float accent_g, float accent_b);

bool resolve_artifact(const artifact_identity_t& identity, artifact_snapshot_t& snapshot,
                      std::string& unavailable_reason);
std::uint64_t artifact_content_hash(const std::vector<std::uint8_t>& bytes);
bool send_artifact_to_repeater(const artifact_identity_t& identity, std::string& unavailable_reason);
bool send_artifact_to_comparer(const artifact_identity_t& identity, std::string& unavailable_reason);
bool add_artifact_to_chat(const artifact_identity_t& identity, std::string& unavailable_reason);
bool assign_artifact_to_agent(const artifact_identity_t& identity, std::string& unavailable_reason);
bool make_sitemap_artifact(std::uint64_t exchange_id, artifact_kind_t kind,
                           artifact_identity_t& identity, std::string& unavailable_reason);
void open_exchange_context(artifact_identity_t primary, artifact_identity_t related,
                           exchange_context_origin_t origin,
                           bool include_intercept_actions = false);
void render_exchange_context();

}
