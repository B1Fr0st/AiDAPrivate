#pragma once

#include "license_state.hpp"

#include <cstdint>
#include <string>

namespace aida::gate_tokens
{
    enum slot_t : uint32_t
    {
        slot_chat_pre_agentic      = 0,
        slot_chat_tool_exec        = 1,
        slot_chat_post_response    = 2,
        slot_ai_chat_async         = 3,
        slot_ai_generate           = 4,
        slot_ai_stream_cb          = 5,
        slot_editor_ghost          = 6,
        slot_editor_save           = 7,
        slot_ui_bottom_panel       = 8,
        slot_ui_command_palette    = 9,
        slot_ui_render_loop        = 10,
        slot_mcp_tool_exec         = 11,
        slot_driver_attach         = 12,
        slot_driver_read_mem       = 13,
        slot_file_browser_open     = 14,
        slot_integrity_periodic    = 15,
        slot_coding_tool_exec      = 16,
        slot_marketplace_search    = 17,
        slot_marketplace_install   = 18,
        slot_native_tool_use       = 19,
        slot_agentic_loop_iter     = 20,
        slot_settings_save         = 21,
        slot_terminal_exec         = 22,
        slot_workspace_search      = 23,
        slot_count                 = 24
    };

    bool initialize_session(const uint8_t session_key[32],
                            const uint8_t gate_root_commitment[32],
                            std::string& last_error);

    uint64_t issue_token(uint32_t slot_index);

    bool verify_token(uint32_t slot_index, uint64_t token, std::string& last_error);

    void rotate_root(const uint8_t new_root[32]);

    void clear_session();

    bool is_session_active();

    bool current_slot_counter(uint32_t slot_index, uint64_t& out_counter);

    bool check_feature_allowed(uint32_t slot_index);

    void fold_integrity_token(uint64_t token);

    uint64_t current_proof_hash();
}

#define VERIFY_LICENSE_INLINE_V2(slot_value)                                            \
    ([](uint32_t _slot) -> bool {                                                       \
        if (!aida::license_state::is_valid_or_degraded()) return false;                 \
        if (!aida::gate_tokens::check_feature_allowed(_slot)) return false;             \
        uint64_t _vli_token = aida::gate_tokens::issue_token(_slot);                    \
        std::string _vli_err;                                                           \
        if (!aida::gate_tokens::verify_token(_slot, _vli_token, _vli_err))              \
        {                                                                               \
            __fastfail(0xA1DA0002u);                                                    \
        }                                                                               \
        aida::gate_tokens::fold_integrity_token(_vli_token);                            \
        return true;                                                                    \
    }(static_cast<uint32_t>(slot_value)))
