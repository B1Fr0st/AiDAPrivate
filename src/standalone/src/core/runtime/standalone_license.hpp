#pragma once

#include <cstdint>
#include <string>

struct settings_sa_t;
struct arc_comm_vtable_t;
struct arc_heartbeat_result_t;

namespace standalone_license
{
    void set_run_correlation_id(const std::string& id);
    std::string run_correlation_id();
    std::string runtime_state_snapshot();
    bool initialize(settings_sa_t& settings);
    bool startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out);
    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out);
    bool is_valid();
    std::string plan();
    std::string last_error();
    void stop_background_workers(const char* reason = nullptr, uint32_t timeout_ms = 5000);
    void shutdown_after_worker_quiesce(const char* reason = nullptr);
    void shutdown();
    void invalidate_for_enforcement(const char* reason);


    bool check_subscription_tier();
    bool verify_entitlement_state();
    bool confirm_session_integrity();


    double  inline_proof_check_a();


    bool    inline_proof_check_b();


    bool    inline_proof_check_c();


    bool    inline_proof_check_d();


    bool    snapshot_code_hashes();
    bool    verify_code_hashes();


    enum gate_slot_t : int {
        gate_chat_pre_agentic      = 0,
        gate_chat_tool_exec        = 1,
        gate_chat_post_response    = 2,
        gate_ai_chat_async         = 3,
        gate_ai_generate           = 4,
        gate_ai_stream_cb          = 5,
        gate_editor_ghost          = 6,
        gate_editor_save           = 7,
        gate_ui_bottom_panel       = 8,
        gate_ui_command_palette    = 9,
        gate_ui_render_loop        = 10,
        gate_mcp_tool_exec         = 11,
        gate_driver_attach         = 12,
        gate_driver_read_mem       = 13,
        gate_file_browser_open     = 14,
        gate_integrity_periodic    = 15,

        gate_coding_tool_exec      = 16,
        gate_marketplace_search    = 17,
        gate_marketplace_install   = 18,
        gate_native_tool_use       = 19,
        gate_agentic_loop_iter     = 20,
        gate_settings_save         = 21,
        gate_terminal_exec         = 22,
        gate_workspace_search      = 23,
        GATE_SLOT_COUNT            = 24
    };


    uint64_t inline_gate_check(gate_slot_t slot);

    bool    check_feature_allowed(gate_slot_t slot);

    double   verify_gate_token(gate_slot_t slot, uint64_t token);


    bool     cross_validation_sweep(int frame_counter);


    uint64_t compute_integrity_token(int frame_counter, int function_id);

    void     fold_integrity_token(uint64_t token);

    std::string decode_status_string(int string_id);


    enum status_string_id : int {
        str_session_revoked       = 0,
        str_integrity_violation   = 1,
        str_gate_stale            = 2,
        str_proof_mismatch        = 3,
        str_hwid_drift            = 4,
        str_heartbeat_expired     = 5,
        str_internal_error        = 6,
        str_model_routing         = 7,
    };


    bool is_arc_loaded();
    bool force_relay_now_blocking(uint32_t timeout_ms);
    void wake_kernel_session_relay_keepalive(const char* reason);
    bool peek_cached_relay_inputs(uint32_t* out_token_hash, uint64_t* out_server_nonce);
    bool request_immediate_relay(const char* reason);
    bool is_arc_download_in_progress();
    bool is_arc_transfer_in_progress();
    bool validate_arc_required_exports(std::string& missing_out);
    uint64_t activation_completed_at();
    uint64_t last_heartbeat_time();
    using arc_comm_bridge_callback_t = bool (*)(const arc_comm_vtable_t*, void*);
    bool with_arc_comm_bridge(arc_comm_bridge_callback_t callback, void* ctx);
    uint64_t arc_validate_tool(uint64_t tool_name_hash, uint64_t gate_token);
    bool verify_tool_runtime(gate_slot_t slot, uint64_t gate_token, const std::string& tool_name);
    arc_heartbeat_result_t arc_heartbeat();
    bool arc_unseal_feature_blocking(uint32_t feature_id,
                                     const uint8_t* nonce,
                                     uint32_t nonce_len,
                                     uint8_t* out,
                                     uint32_t* out_size,
                                     uint32_t out_cap);
    uint64_t get_server_nonce_hash();
    std::string get_session_token();
    std::string get_arc_bind_token();
    bool build_ida_plugin_auth_proof(const std::string& challenge_hex,
                                     uint32_t plugin_pid,
                                     uint32_t mcp_port,
                                     bool lifecycle_ready,
                                     bool exports_verified,
                                     std::string& out_json,
                                     std::string& error_out);

    bool compute_integrity_gated_hmac(
        const uint8_t* heartbeat_payload, size_t payload_len,
        const uint8_t* server_nonce, size_t nonce_len,
        uint8_t hmac_out[32]);

    std::string get_build_id();


    bool validate_server_response(const uint8_t* response, size_t response_len,
                                   uint64_t server_nonce_hash);
    bool check_kernel_attestation(uint64_t attestation_value);
    bool verify_gate_chain(uint64_t session_token);
    bool check_heartbeat_freshness(uint64_t heartbeat_time, uint64_t now);
    bool verify_session_epoch(uint64_t epoch);
    bool check_driver_bridge_active();
    bool verify_filesystem_baseline(uint64_t fs_hash);
    bool finalize_validation(bool* partial_results, size_t count);


    constexpr int REAL_VALIDATION_FUNC_COUNT = 12;
    constexpr int DECOY_VALIDATION_FUNC_COUNT = 8;
    constexpr int TOTAL_CALL_TARGETS = REAL_VALIDATION_FUNC_COUNT + DECOY_VALIDATION_FUNC_COUNT;
    constexpr int VALIDATION_BRANCHING = 3;
    constexpr int VALIDATION_DEPTH = 6;
    constexpr int VALIDATION_GRAPH_PATHS = 729;

    struct distributed_validation_node_t
    {
        int function_id;
        int next_nodes[3];
        bool is_decoy;
    };

    inline constexpr distributed_validation_node_t g_validation_graph[TOTAL_CALL_TARGETS] = {
        {0,  {1, 2, 9},  false},
        {1,  {3, 10, 4}, false},
        {2,  {5, 6, 11}, false},
        {3,  {7, 8, 12}, false},
        {4,  {13, 5, 14},false},
        {5,  {9, 15, 6}, false},
        {6,  {10, 7, 16},false},
        {7,  {11, 8, 17},false},
        {8,  {0, 1, 18}, false},
        {9,  {14, 15, 19},false},
        {10, {16, 17, 12},false},
        {11, {18, 19, 13},false},
        {12, {0, 3, 6},  true},
        {13, {1, 4, 7},  true},
        {14, {2, 5, 8},  true},
        {15, {0, 6, 9},  true},
        {16, {1, 7, 10}, true},
        {17, {2, 8, 11}, true},
        {18, {3, 9, 12}, true},
        {19, {4, 10, 13},true},
    };

    bool validate_with_environmental_resistance();

    void record_mcp_tool_call(const std::string& tool_name, const std::string& params_json);
}


#define VERIFY_LICENSE_INLINE(slot)                                          \
    ([&]() -> bool {                                                        \
        if (!standalone_license::check_feature_allowed(slot))               \
            return false;                                                   \
        uint64_t _vli_gt = standalone_license::inline_gate_check(slot);     \
        double _vli_v = standalone_license::verify_gate_token(slot, _vli_gt); \
        standalone_license::fold_integrity_token(_vli_gt);                  \
        return _vli_v >= 0.5;                                               \
    }())
