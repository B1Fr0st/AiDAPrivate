#pragma once

#include <atomic>
#include <cstdint>
#include <string>

struct settings_sa_t;
struct arc_comm_vtable_t;
struct arc_heartbeat_result_t;

namespace standalone_license
{
    bool initialize(settings_sa_t& settings);
    bool activate(settings_sa_t& settings, const std::string& key, std::string& error_out);
    bool is_valid();
    std::string plan();
    std::string last_error();
    void shutdown();


    bool check_subscription_tier();
    bool verify_entitlement_state();
    bool confirm_session_integrity();


    double  inline_proof_check_a();


    bool    inline_proof_check_b();


    bool    inline_proof_check_c();


    bool    inline_proof_check_d();


    double  compute_degradation_factor();


    void    snapshot_code_hashes();
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


    double   verify_gate_token(gate_slot_t slot, uint64_t token);


    bool     cross_validation_sweep(int frame_counter);


    uint64_t compute_integrity_token(int frame_counter, int function_id);


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

    // ── ARC (AiDA Runtime Core) accessors ──────────────────
    bool is_arc_loaded();
    const arc_comm_vtable_t* get_arc_comm_bridge();
    uint64_t arc_validate_tool(uint64_t tool_name_hash, uint64_t gate_token);
    arc_heartbeat_result_t arc_heartbeat();
}
