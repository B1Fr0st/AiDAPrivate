#pragma once

#include <cstdint>
#include <string>

struct settings_sa_t;
struct arc_comm_vtable_t;
struct arc_heartbeat_result_t;

namespace standalone_license
{
    bool initialize(settings_sa_t& settings);
    bool startup_ban_check(settings_sa_t& settings, std::string& reason_out, std::string& message_out);
    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out);
    bool is_valid();
    std::string plan();
    std::string last_error();
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
    bool is_arc_download_in_progress();
    bool is_arc_transfer_in_progress();
    bool validate_arc_required_exports(std::string& missing_out);
    uint64_t activation_completed_at();
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
