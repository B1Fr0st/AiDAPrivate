#pragma once

#include <kernwin.hpp>

class aida_plugin_t;

struct action_handler : public action_handler_t
{
    using action_func_t = void (*)(action_activation_ctx_t*, aida_plugin_t*);
    action_func_t action_func;
    aida_plugin_t* plugin;

    action_handler(action_func_t func, aida_plugin_t* p) : action_handler_t(), action_func(func), plugin(p) {}

    int idaapi activate(action_activation_ctx_t* ctx) override;
    action_state_t idaapi update(action_update_ctx_t* ctx) override;
};

void handle_copy_context(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_save_database_context(action_activation_ctx_t* ctx, aida_plugin_t* plugin);
void handle_fix_analysis(action_activation_ctx_t* ctx, aida_plugin_t* plugin);

namespace analysis_fixer {
    bool install_hexrays_fixups();
    void uninstall_hexrays_fixups();
    void refresh_decompilation(ea_t func_ea);
}
