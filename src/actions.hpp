#pragma once

#include <kernwin.hpp>

class aida_plugin_t;

bool can_use_ai(aida_plugin_t* plugin);

struct action_handler : public action_handler_t
{
    using action_func_t = void (*)(action_activation_ctx_t*, aida_plugin_t*);
    action_func_t action_func;
    aida_plugin_t* plugin;

    action_handler(action_func_t func, aida_plugin_t* p) : action_handler_t(), action_func(func), plugin(p) {}

    int idaapi activate(action_activation_ctx_t* ctx) override;
    action_state_t idaapi update(action_update_ctx_t* ctx) override;
};

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_auto_comment(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_generate_hook(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_copy_context(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_scan_for_offsets(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_show_settings(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_rename_all(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_save_database_context(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_check_for_updates(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_open_chat(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_fix_analysis(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_cancel_request(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_toggle_mcp(action_activation_ctx_t* ctx, aida_plugin_t* plugin);

void handle_debug_analyze(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_debug_devirtualize(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_debug_trace_dispatch(action_activation_ctx_t* ctx, aida_plugin_t* plugin);

namespace action_helpers {
void handle_ai_response(const std::string& result, const qstring& title_prefix,
                        std::function<void(const std::string&)> success_action);
}

namespace tool_executor {
    struct tool_call_t {
        std::string type;
        std::string reasoning;
        nlohmann::json params;
    };

    std::vector<tool_call_t> parse_tool_calls(const std::string& json_response);
    qstring execute_tool_calls(ea_t func_ea, const std::vector<tool_call_t>& calls);
    std::string format_tool_calls_for_review(const std::vector<tool_call_t>& calls);
}

namespace analysis_fixer {
    bool install_hexrays_fixups();
    void uninstall_hexrays_fixups();
    void refresh_decompilation(ea_t func_ea);
}
