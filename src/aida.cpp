#include "aida_pro.hpp"

#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"
#include "vuln/embedded_libz3.hpp"
#include "vuln/chain_verify_service.hpp"

#include <delayimp.h>

extern "C" {

static FARPROC WINAPI aida_plugin_delay_load_hook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify == dliNotePreLoadLibrary && pdli != nullptr && pdli->szDll != nullptr)
    {
        if (_stricmp(pdli->szDll, "libz3.dll") == 0)
        {
            aida::vuln::embedded_libz3::ensure_loaded();
            HMODULE m = aida::vuln::embedded_libz3::g_z3_module.load(std::memory_order_acquire);
            if (m != nullptr)
                return reinterpret_cast<FARPROC>(m);
        }
    }
    return nullptr;
}

const PfnDliHook __pfnDliNotifyHook2 = aida_plugin_delay_load_hook;

}

#ifdef __NT__
#include "aida_ipc.hpp"
#include <exception>
#include <thread>
#endif

#ifdef __NT__

namespace {

void join_plugin_thread(std::thread& worker, const char* name)
{
    if (!worker.joinable())
        return;
    const ULONGLONG started = GetTickCount64();
    aida_ipc::trace_breadcrumb("plugin_worker_join_begin name=%s", name ? name : "<unknown>");
    try
    {
        worker.join();
        aida_ipc::trace_breadcrumb("plugin_worker_join_done name=%s elapsed_ms=%llu",
                                   name ? name : "<unknown>",
                                   static_cast<unsigned long long>(GetTickCount64() - started));
    }
    catch (const std::exception& ex)
    {
        aida_ipc::trace_breadcrumb("plugin_worker_join_exception name=%s what=%s",
                                   name ? name : "<unknown>",
                                   ex.what());
    }
    catch (...)
    {
        aida_ipc::trace_breadcrumb("plugin_worker_join_unknown_exception name=%s", name ? name : "<unknown>");
    }
}

}
extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     fdwReason,
                                LPVOID    )
{
    aida_ipc::trace_breadcrumb("DllMain_enter fdwReason=%lu hinstDLL=%p", static_cast<unsigned long>(fdwReason), static_cast<void*>(hinstDLL));
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        aida_ipc::trace_breadcrumb("DllMain_before_DisableThreadLibraryCalls");
        DisableThreadLibraryCalls(hinstDLL);
        aida_ipc::trace_breadcrumb("DllMain_after_DisableThreadLibraryCalls");
    }
    aida_ipc::trace_breadcrumb("DllMain_exit_returning_TRUE");
    return TRUE;
}
#endif

extern "C" int __stdcall simpleline_place_t__compare2(
    const simpleline_place_t *a,
    const place_t *b,
    void *)
{
    return simpleline_place_t__compare(a, b);
}

extern "C" bool __stdcall simpleline_place_t__equals(
    const simpleline_place_t *a,
    const place_t *b,
    void *ud)
{
    return simpleline_place_t__compare2(a, b, ud) == 0;
}


static int idaapi finish_populating_widget_popup(
    TWidget* widget, TPopupMenu* popup_handle,
    const action_activation_ctx_t* ctx)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_enter ctx=%p", static_cast<void*>(const_cast<action_activation_ctx_t*>(ctx)));
#endif
    if (ctx == nullptr
        || (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("finish_populating_widget_popup_return_0 ctx_null=%d widget_type=%d", ctx == nullptr ? 1 : 0, ctx ? ctx->widget_type : -1);
#endif
        return 0;
    }

    static const char* const kept_actions[] = {
        "ai_assistant:copy_context",
        "ai_assistant:save_database_context",
        "ai_assistant:fix_analysis",
        "aida:chain_verify_open_panel",
        "aida:chain_verify_current_function_as_link",
        "aida:chain_verify_start",
        "aida:chain_verify_cancel",
        "aida:chain_verify_copy_result_json",
    };

    const std::string menu_root = std::string("AiDA/");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_before_attach_loop count=%d", static_cast<int>(sizeof(kept_actions)/sizeof(kept_actions[0])));
#endif
    for (const char* action_name : kept_actions)
    {
        attach_action_to_popup(widget, popup_handle, action_name,
                               menu_root.c_str(), 0);
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("finish_populating_widget_popup_return_0_after_attach");
#endif
    return 0;
}


ssize_t idaapi ui_event_listener_t::on_event(ssize_t code, va_list va)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ui_event_on_event_enter code=%zd", static_cast<ssize_t>(code));
#endif
    if (code == ui_finish_populating_widget_popup)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ui_event_on_event_finish_populating_widget_popup");
#endif
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ui_event_on_event_calling_finish_populating_widget_popup");
#endif
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ui_event_on_event_return_0");
#endif
    return 0;
}

class chain_verify_action_handler_t final : public action_handler_t
{
public:
    chain_verify_action_handler_t(aida::vuln::chain_verify_action_kind_t action_kind, aida_plugin_t* owner)
        : kind(action_kind), plugin(owner)
    {
    }

    int idaapi activate(action_activation_ctx_t* ctx) override
    {
        if (plugin != nullptr)
            plugin->activate_chain_verify_action(kind, ctx);
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t* ctx) override
    {
        if (plugin == nullptr)
            return AST_DISABLE;
        return plugin->update_chain_verify_action(kind, ctx);
    }

private:
    aida::vuln::chain_verify_action_kind_t kind;
    aida_plugin_t* plugin = nullptr;
};

aida_plugin_t::aida_plugin_t(bool standalone_verified, const std::string& standalone_failure)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_enter standalone_verified=%d", standalone_verified ? 1 : 0);
    aida_ipc::trace_breadcrumb("constructor_standalone_failure=%s", standalone_failure.empty() ? "(empty)" : standalone_failure.c_str());
#endif
    msg("--- Plugin Loading (v%s) ---\n", AIDA_VERSION);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_version_msg");
    aida_ipc::trace_breadcrumb("constructor_before_chain_verifier_service_create");
#endif
    chain_verifier_service = std::make_unique<aida::vuln::chain_verifier_service_t>();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_chain_verifier_service_create");
    aida_ipc::trace_breadcrumb("constructor_before_register_actions");
#endif
    register_actions();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("constructor_after_register_actions");
    aida_ipc::trace_breadcrumb("constructor_before_initialize_operational");
#endif
    if (!initialize_operational(true))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("constructor_initialize_operational_failed disabled_detail=%s", disabled_detail.c_str());
#endif
        msg("AiDA: plugin loaded in disabled mode. %s\n", disabled_detail.c_str());
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("constructor_initialize_operational_succeeded");
    }
    aida_ipc::trace_breadcrumb("constructor_exit");
#endif
}

void aida_plugin_t::set_disabled(const std::string& reason)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("set_disabled_enter reason=%s", reason.empty() ? "(empty)" : reason.c_str());
#endif
    disabled_detail = reason.empty() ? std::string("standalone verification failed") : reason;
    features_initialized = false;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("set_disabled_exit disabled_detail=%s features_initialized=0", disabled_detail.c_str());
#endif
}

bool aida_plugin_t::is_operational() const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("is_operational features_initialized=%d", features_initialized ? 1 : 0);
#endif
    return features_initialized;
}

const std::string& aida_plugin_t::disabled_reason() const
{
    return disabled_detail;
}

bool aida_plugin_t::ensure_operational(bool interactive)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ensure_operational_enter interactive=%d features_initialized=%d", interactive ? 1 : 0, features_initialized ? 1 : 0);
#endif
    if (features_initialized)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ensure_operational_already_initialized_returning_true");
#endif
        return true;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ensure_operational_calling_initialize_operational");
#endif
    return initialize_operational(interactive);
}

bool aida_plugin_t::initialize_operational(bool interactive)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_enter interactive=%d", interactive ? 1 : 0);
    aida_ipc::trace_breadcrumb("initialize_operational_before_settings_load_from_file");
#endif
    g_settings.load_from_file();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_settings_load_from_file");
    aida_ipc::trace_breadcrumb("initialize_operational_before_settings_load_this");
#endif
    g_settings.load(this);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_settings_load_this");
    aida_ipc::trace_breadcrumb("initialize_operational_before_analysis_db_load");
#endif
    aida_db::AnalysisDB::instance().load();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_analysis_db_load");
    aida_ipc::trace_breadcrumb("initialize_operational_before_agent_tools_init");
#endif
    agent_tools::initialize_all_tools();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_agent_tools_init");
    aida_ipc::trace_breadcrumb("initialize_operational_before_chain_verifier_check");
#endif

    if (!chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_creating_new");
#endif
        chain_verifier_service = std::make_unique<aida::vuln::chain_verifier_service_t>();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_created");
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_before_chain_verifier_start");
#endif
    if (!chain_verifier_service->start())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_start_failed");
#endif
        chain_verifier_service->stop(4000);
        set_disabled("Chain verifier service could not start");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_return_false_chain_verifier");
#endif
        return false;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_chain_verifier_start_ok");
    aida_ipc::trace_breadcrumb("initialize_operational_before_mcp_enabled_save");
#endif

    g_settings.mcp_enabled = true;
    g_settings.save();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_mcp_enabled_save");
    aida_ipc::trace_breadcrumb("initialize_operational_before_start_mcp_server");
#endif

    if (!start_mcp_server())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_start_mcp_server_failed");
#endif
        if (chain_verifier_service)
            chain_verifier_service->stop(4000);
        set_disabled("MCP server could not start");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_return_false_mcp_server");
#endif
        return false;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_start_mcp_server_ok");
    aida_ipc::trace_breadcrumb("initialize_operational_before_install_hexrays_fixups");
#endif

    analysis_fixer::install_hexrays_fixups();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_install_hexrays_fixups");
    aida_ipc::trace_breadcrumb("initialize_operational_before_hook_event_listener");
#endif
    if (hook_event_listener(HT_UI, &ui_listener))
    {
        ui_listener_hooked = true;
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_hook_event_listener_ok hooked=1");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("initialize_operational_hook_event_listener_failed hooked=0");
    }
    aida_ipc::trace_breadcrumb("initialize_operational_before_features_initialized_true");
#endif
    features_initialized = true;
    disabled_detail.clear();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_features_initialized_true");
#endif

    msg("--- Plugin Loaded Successfully ---\n");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_after_success_msg");
    aida_ipc::trace_breadcrumb("initialize_operational_before_graphrag_load");
#endif

    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("initialize_operational_bin_hash=%s", bin_hash.empty() ? "(empty)" : bin_hash.c_str());
#endif
    if (!bin_hash.empty())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("initialize_operational_before_graphrag_thread_create");
#endif
        try
        {
            graphrag_load_thread = std::thread([bin_hash]() {
                try
                {
                    graphrag::load_graph(bin_hash);
                }
                catch (const std::exception& ex)
                {
                    msg("AiDA GraphRAG load worker unavailable: %s\n", ex.what());
                }
                catch (...)
                {
                    msg("AiDA GraphRAG load worker unavailable.\n");
                }
            });
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_started");
#endif
        }
        catch (const std::exception& ex)
        {
            msg("AiDA GraphRAG load worker unavailable: %s\n", ex.what());
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_exception what=%s", ex.what());
#endif
        }
        catch (...)
        {
            msg("AiDA GraphRAG load worker unavailable.\n");
#ifdef __NT__
            aida_ipc::trace_breadcrumb("initialize_operational_graphrag_thread_unknown_exception");
#endif
        }
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("initialize_operational_no_bin_hash_skipping_graphrag");
    }
    aida_ipc::trace_breadcrumb("initialize_operational_return_true");
#endif

    return true;
}

aida_plugin_t::~aida_plugin_t()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_enter features_initialized=%d", features_initialized ? 1 : 0);
    aida_ipc::trace_breadcrumb("destructor_before_join_graphrag_load_thread");
    join_plugin_thread(graphrag_load_thread, "graphrag_load");
    aida_ipc::trace_breadcrumb("destructor_after_join_graphrag_load_thread");
#endif

    if (features_initialized)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_features_initialized_begin_cleanup");
#endif
        if (chain_verifier_service)
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_chain_verifier_stop");
#endif
            chain_verifier_service->stop(4000);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_chain_verifier_stop");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_get_binary_hash");
#endif
        std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
        if (!bin_hash.empty())
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_graphrag_save_graph hash=%s", bin_hash.c_str());
#endif
            graphrag::save_graph(bin_hash);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_graphrag_save_graph");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_analysis_db_save");
#endif
        aida_db::AnalysisDB::instance().save();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_analysis_db_save");
        aida_ipc::trace_breadcrumb("destructor_before_stop_mcp_server");
#endif
        stop_mcp_server();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_stop_mcp_server");
#endif
        if (ui_listener_hooked)
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_before_unhook_event_listener");
#endif
            ::unhook_event_listener(HT_UI, &ui_listener);
#ifdef __NT__
            aida_ipc::trace_breadcrumb("destructor_after_unhook_event_listener");
#endif
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_before_uninstall_hexrays_fixups");
#endif
        analysis_fixer::uninstall_hexrays_fixups();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("destructor_after_uninstall_hexrays_fixups");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("destructor_features_not_initialized_skipping_cleanup");
    }
    aida_ipc::trace_breadcrumb("destructor_before_unregister_actions");
#endif
    unregister_actions();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_after_unregister_actions");
    aida_ipc::trace_breadcrumb("destructor_before_chain_verifier_reset");
#endif
    chain_verifier_service.reset();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_after_chain_verifier_reset");
#endif
    msg("--- Plugin has been unloaded ---\n");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("destructor_exit");
#endif
}

bool idaapi aida_plugin_t::run(size_t)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_enter");
    aida_ipc::trace_breadcrumb("run_before_ensure_operational");
#endif
    if (!ensure_operational(true))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("run_ensure_operational_failed disabled_detail=%s", disabled_detail.c_str());
#endif
        warning("AiDA is loaded but disabled: %s", disabled_detail.c_str());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("run_return_false_disabled");
#endif
        return false;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_ensure_operational_succeeded");
#endif
    info("Plugin is active. Use the right-click context menu in a code view or the Tools menu.");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("run_return_true");
#endif
    return true;
}

void aida_plugin_t::activate_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, action_activation_ctx_t* ctx)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_enter");
#endif
    if (!is_operational() || !chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("activate_chain_verify_action_return_not_operational");
#endif
        return;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_calling_activate");
#endif
    chain_verifier_service->activate(kind, ctx);
#ifdef __NT__
    aida_ipc::trace_breadcrumb("activate_chain_verify_action_exit");
#endif
}

action_state_t aida_plugin_t::update_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, const action_update_ctx_t* ctx) const
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("update_chain_verify_action_enter");
#endif
    if (!is_operational() || !chain_verifier_service)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("update_chain_verify_action_return_ast_disable");
#endif
        return AST_DISABLE;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("update_chain_verify_action_calling_action_state");
#endif
    return chain_verifier_service->action_state(kind, ctx);
}

bool aida_plugin_t::start_mcp_server()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_enter");
#endif

    if (mcp_server && mcp_server->is_running())
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_already_running_returning_true");
#endif
        return true;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_before_make_unique mcp_port=%d", g_settings.mcp_port);
#endif
    mcp_server = std::make_unique<mcp_server_t>();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_after_make_unique");
    aida_ipc::trace_breadcrumb("start_mcp_server_before_start port=%d", g_settings.mcp_port);
#endif
    if (!mcp_server->start(g_settings.mcp_port))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_start_failed port=%d", g_settings.mcp_port);
#endif
        msg("MCP: Could not start server on port %d.\n", g_settings.mcp_port);
        mcp_server.reset();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("start_mcp_server_return_false");
#endif
        return false;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_start_succeeded");
    aida_ipc::trace_breadcrumb("start_mcp_server_before_write_configs");
#endif
    mcp_server->write_mcp_client_configs();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("start_mcp_server_after_write_configs");
    aida_ipc::trace_breadcrumb("start_mcp_server_return_true");
#endif
    return true;
}

void aida_plugin_t::stop_mcp_server()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("stop_mcp_server_enter");
#endif
    if (mcp_server)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_before_stop");
#endif
        mcp_server->stop();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_after_stop");
        aida_ipc::trace_breadcrumb("stop_mcp_server_before_reset");
#endif
        mcp_server.reset();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("stop_mcp_server_after_reset");
#endif
    }
#ifdef __NT__
    else
    {
        aida_ipc::trace_breadcrumb("stop_mcp_server_no_server");
    }
    aida_ipc::trace_breadcrumb("stop_mcp_server_exit");
#endif
}

void aida_plugin_t::register_actions()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_enter actions_registered=%d", actions_registered ? 1 : 0);
#endif
    if (actions_registered)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_actions_already_registered_returning");
#endif
        return;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_action_definitions");
#endif
    struct rt_action_def_t {
        std::string name;
        std::string label;
        action_handler::action_func_t handler;
        const char* shortcut;
    };

    const rt_action_def_t action_definitions[] = {
        {std::string("ai_assistant:copy_context"), std::string("Copy function contents"), handle_copy_context, "Ctrl+Alt+X"},
        {std::string("ai_assistant:save_database_context"), std::string("Save database context to file..."), handle_save_database_context, ""},
        {std::string("ai_assistant:fix_analysis"), std::string("Fix Analysis (Clean Decompilation)"), handle_fix_analysis, "Ctrl+Alt+F"},
    };

    const std::string menu_root = std::string("AiDA/");

#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_registering_rt_actions count=%d", static_cast<int>(sizeof(action_definitions)/sizeof(action_definitions[0])));
#endif
    for (const auto& def : action_definitions)
    {
        actions_list.push_back() = def.name.c_str();
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name.c_str(),
            def.label.c_str(),
            new action_handler(def.handler, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("register_action_failed name=%s", def.name.c_str());
#endif
            msg("Failed to register action %s\n", def.name.c_str());
            continue;
        }
        attach_action_to_menu(menu_root.c_str(), def.name.c_str(), SETMENU_APP);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_action_ok name=%s", def.name.c_str());
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_after_rt_actions");
    aida_ipc::trace_breadcrumb("register_actions_before_chain_action_definitions");
#endif

    struct chain_action_def_t {
        std::string name;
        std::string label;
        aida::vuln::chain_verify_action_kind_t kind;
        const char* shortcut;
    };

    const chain_action_def_t chain_action_definitions[] = {
        {std::string("aida:chain_verify_open_panel"), std::string("Open Chain Verify"), aida::vuln::chain_verify_action_kind_t::open_panel, ""},
        {std::string("aida:chain_verify_current_function_as_link"), std::string("Current Function As Chain Link"), aida::vuln::chain_verify_action_kind_t::current_function_as_link, "Ctrl+Alt+L"},
        {std::string("aida:chain_verify_start"), std::string("Start Chain Verification"), aida::vuln::chain_verify_action_kind_t::start, "Ctrl+Alt+V"},
        {std::string("aida:chain_verify_cancel"), std::string("Cancel Chain Verification"), aida::vuln::chain_verify_action_kind_t::cancel, ""},
        {std::string("aida:chain_verify_copy_result_json"), std::string("Copy Chain Result JSON"), aida::vuln::chain_verify_action_kind_t::copy_result_json, ""},
    };

    const std::string chain_menu_root = menu_root + std::string("Chain Verify/");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_before_registering_chain_actions count=%d", static_cast<int>(sizeof(chain_action_definitions)/sizeof(chain_action_definitions[0])));
#endif
    for (const auto& def : chain_action_definitions)
    {
        actions_list.push_back() = def.name.c_str();
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name.c_str(),
            def.label.c_str(),
            new chain_verify_action_handler_t(def.kind, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("register_chain_action_failed name=%s", def.name.c_str());
#endif
            msg("Failed to register action %s\n", def.name.c_str());
            continue;
        }
        attach_action_to_menu(chain_menu_root.c_str(), def.name.c_str(), SETMENU_APP);
#ifdef __NT__
        aida_ipc::trace_breadcrumb("register_chain_action_ok name=%s", def.name.c_str());
#endif
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_after_chain_actions");
#endif
    actions_registered = true;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("register_actions_exit actions_registered=1");
#endif
}

void aida_plugin_t::unregister_actions()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_enter actions_registered=%d", actions_registered ? 1 : 0);
#endif
    if (!actions_registered)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("unregister_actions_not_registered_returning");
#endif
        return;
    }

#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_before_loop count=%d", static_cast<int>(actions_list.size()));
#endif
    for (const auto& action_name : actions_list)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("unregister_actions_unregistering name=%s", action_name.c_str());
#endif
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
    actions_registered = false;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("unregister_actions_exit actions_registered=0");
#endif
}

static plugmod_t* idaapi init_core()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_core_enter");
#endif
    std::string standalone_failure;
    bool standalone_verified = true;
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_core_vars_initialized standalone_verified=%d", standalone_verified ? 1 : 0);
    aida_ipc::trace_breadcrumb("init_core_before_new_aida_plugin_t");
#endif
    return new aida_plugin_t(standalone_verified, standalone_failure);
}

static plugmod_t* idaapi init_seh_wrapper()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_seh_wrapper_enter");
#endif
    plugmod_t* result = nullptr;
    DWORD seh_code = 0;
    __try
    {
        result = init_core();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_seh_wrapper_core_returned result=%p", static_cast<void*>(result));
#endif
    }
    __except (seh_code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_seh_wrapper_exception code=0x%08lX", seh_code);
#endif
        result = PLUGIN_SKIP;
    }
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_seh_wrapper_exit result=%p", static_cast<void*>(result));
#endif
    return result;
}

static plugmod_t* idaapi init()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("init_enter FIRST_BREADCRUMB");

    HMODULE plugin_module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&init), &plugin_module);
    aida_ipc::trace_breadcrumb("init_diag plugin_module_base=%p", static_cast<void*>(plugin_module));

    HMODULE ida_dll = GetModuleHandleW(L"ida.dll");
    aida_ipc::trace_breadcrumb("init_diag ida_dll_loaded=%d ida_dll_handle=%p", ida_dll ? 1 : 0, static_cast<void*>(ida_dll));

    aida_ipc::trace_breadcrumb("init_diag IDP_INTERFACE_VERSION=%d", IDP_INTERFACE_VERSION);

    aida_ipc::trace_breadcrumb("init_before_try_catch");
#endif

    try
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_try_enter calling_init_seh_wrapper");
#endif
        plugmod_t* result = init_seh_wrapper();
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_try_exit result=%p", static_cast<void*>(result));
#endif
        return result;
    }
    catch (const std::exception& ex)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_cxx_exception what=%s", ex.what());
#endif
        return PLUGIN_SKIP;
    }
    catch (...)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("init_cxx_unknown_exception");
#endif
        return PLUGIN_SKIP;
    }
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "AiDA MCP Server for IDA Pro",
  "Exposes IDA analysis tools via MCP protocol",
  "AiDA",
  ""
};
