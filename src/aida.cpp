#include "aida_pro.hpp"

#include "anti_re.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"

#ifdef __NT__
#include "driver_loader.hpp"
#endif

#ifdef __NT__
extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                                DWORD     fdwReason,
                                LPVOID    )
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}
#endif

#ifdef __NT__
static bool has_expected_plugin_filename()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&has_expected_plugin_filename),
            &module) || module == nullptr)
    {
        return false;
    }

    wchar_t module_path[MAX_PATH] = {};
    if (GetModuleFileNameW(module, module_path, MAX_PATH) == 0)
        return false;

    const wchar_t* base_name = module_path;
    for (const wchar_t* p = module_path; *p != L'\0'; ++p)
    {
        if (*p == L'\\' || *p == L'/')
            base_name = p + 1;
    }

    return wcscmp(base_name, L"AiDA.dll") == 0;
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


static bool show_eula_dialog()
{
    int choice = ask_yn(ASKBTN_NO,
        "AiDA - End User License Agreement\n"
        "\n"
        "By clicking YES you acknowledge that you have read, understood,\n"
        "and agreed to the AiDA End User License Agreement.\n"
        "\n"
        "Key points:\n"
        "  - You may only use AiDA on targets you are legally authorized to analyze.\n"
        "  - The software contains anti-reverse-engineering self-defense mechanisms.\n"
        "  - Telemetry data (HWID, IP, Discord ID) is collected for license enforcement.\n"
        "  - AI provider endpoints are volatile and may change without notice.\n"
        "  - The kernel driver operates at Ring 0; system instability may occur.\n"
        "  - The software is provided AS-IS with no warranty.\n"
        "\n"
        "Do you accept the EULA?");
    return choice == ASKBTN_YES;
}


static int idaapi finish_populating_widget_popup(
    TWidget* widget, TPopupMenu* popup_handle,
    const action_activation_ctx_t* ctx)
{
    if (ctx == nullptr
        || (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM))
        return 0;

    static const char* const kept_actions[] = {
        "ai_assistant:copy_context",
        "ai_assistant:save_database_context",
        "ai_assistant:fix_analysis",
        "ai_assistant:toggle_mcp",
    };

    const std::string menu_root = OBFSTR("AiDA/");
    for (const char* action_name : kept_actions)
    {
        attach_action_to_popup(widget, popup_handle, action_name,
                               menu_root.c_str(), 0);
    }
    return 0;
}


ssize_t idaapi ui_event_listener_t::on_event(ssize_t code, va_list va)
{
#ifdef __NT__
    if (code == ui_ready_to_run)
        anti_re::initialize();
#endif

    if (code == ui_finish_populating_widget_popup)
    {
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
    return 0;
}

ssize_t idaapi dbg_event_listener_t::on_event(ssize_t code, va_list va)
{
    dbg_event_record_t rec;
    rec.timestamp_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    rec.notification = static_cast<dbg_notification_t>(code);
    rec.ea  = BADADDR;
    rec.pid = 0;
    rec.tid = 0;

    switch (static_cast<dbg_notification_t>(code))
    {
    case dbg_process_start:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const char* name = event->modinfo().name.c_str();
        rec.detail = OBFSTR("process_start: ") + std::string(name[0] ? name : "unknown");
        break;
    }
    case dbg_process_exit:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        char buf[128];
        qsnprintf(buf, sizeof(buf), "process_exit: code=%d", event->exit_code());
        rec.detail = buf;
        break;
    }
    case dbg_process_attach:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const char* name = event->modinfo().name.c_str();
        rec.detail = OBFSTR("process_attach: ") + std::string(name[0] ? name : "unknown");
        break;
    }
    case dbg_process_detach:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.detail = OBFSTR("process_detach");
        break;
    }
    case dbg_thread_start:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const char* tname = event->info().c_str();
        char buf[256];
        qsnprintf(buf, sizeof(buf), "thread_start: tid=%d ea=0x%llX name=%s",
                  event->tid, static_cast<unsigned long long>(event->ea),
                  tname[0] ? tname : "");
        rec.detail = buf;
        break;
    }
    case dbg_thread_exit:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        char buf[128];
        qsnprintf(buf, sizeof(buf), "thread_exit: tid=%d code=%d",
                  event->tid, event->exit_code());
        rec.detail = buf;
        break;
    }
    case dbg_library_load:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const char* name = event->modinfo().name.c_str();
        rec.detail = OBFSTR("library_load: ") + std::string(name[0] ? name : "unknown");
        break;
    }
    case dbg_library_unload:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const char* name = event->info().c_str();
        rec.detail = OBFSTR("library_unload: ") + std::string(name[0] ? name : "unknown");
        break;
    }
    case dbg_information:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        rec.detail = OBFSTR("info: ") + std::string(event->info().c_str());
        break;
    }
    case dbg_exception:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
         va_arg(va, int*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        const excinfo_t& exc = event->exc();
        char buf[512];
        qsnprintf(buf, sizeof(buf), "exception: code=0x%X ea=0x%llX can_cont=%d info=%s",
                  exc.code, static_cast<unsigned long long>(exc.ea),
                  exc.can_cont ? 1 : 0, exc.info.c_str());
        rec.detail = buf;
        break;
    }
    case dbg_suspend_process:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        rec.detail = OBFSTR("suspend_process");
        break;
    }
    case dbg_bpt:
    {
        thid_t tid = va_arg(va, thid_t);
        ea_t bptea = va_arg(va, ea_t);
        rec.tid = tid;
        rec.ea  = bptea;
        qstring fname;
        if (get_func_name(&fname, bptea) > 0)
        {
            char buf[512];
            qsnprintf(buf, sizeof(buf), "breakpoint_hit: ea=0x%llX func=%s tid=%d",
                      static_cast<unsigned long long>(bptea), fname.c_str(), tid);
            rec.detail = buf;
        }
        else
        {
            char buf[256];
            qsnprintf(buf, sizeof(buf), "breakpoint_hit: ea=0x%llX tid=%d",
                      static_cast<unsigned long long>(bptea), tid);
            rec.detail = buf;
        }
        break;
    }
    case dbg_trace:
    {
        thid_t tid = va_arg(va, thid_t);
        ea_t ip = va_arg(va, ea_t);
        rec.tid = tid;
        rec.ea  = ip;
        char buf[128];
        qsnprintf(buf, sizeof(buf), "trace: ip=0x%llX tid=%d",
                  static_cast<unsigned long long>(ip), tid);
        rec.detail = buf;
        break;
    }
    case dbg_step_into:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        rec.detail = OBFSTR("step_into_complete");
        break;
    }
    case dbg_step_over:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        rec.detail = OBFSTR("step_over_complete");
        break;
    }
    case dbg_step_until_ret:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        rec.detail = OBFSTR("step_until_ret_complete");
        break;
    }
    case dbg_run_to:
    {
        const debug_event_t* event = va_arg(va, const debug_event_t*);
        rec.pid = event->pid;
        rec.tid = event->tid;
        rec.ea  = event->ea;
        char buf[128];
        qsnprintf(buf, sizeof(buf), "run_to: ea=0x%llX",
                  static_cast<unsigned long long>(event->ea));
        rec.detail = buf;
        break;
    }
    default:
    {
        char buf[64];
        qsnprintf(buf, sizeof(buf), "dbg_event_%d", static_cast<int>(code));
        rec.detail = buf;
        break;
    }
    }

    g_dbg_event_log.push(std::move(rec));
    return 0;
}

static int idaapi self_analysis_watchdog(void *)
{
    static bool s_self_target_checked = false;
    static bool s_is_self_target      = false;

    if (!s_self_target_checked)
    {
        s_is_self_target      = ida_utils::is_self_target_database();
        s_self_target_checked = true;
    }

    if (s_is_self_target)
        return -1;

#ifdef __NT__
    if (!anti_re::guard())
    {
        anti_re::latch_self_analysis_violation("self_analysis_watchdog");
        anti_re::sync_latched_violation_with_server();
        anti_re::arm_destructive_enforcement();
        anti_re::enforce_self_analysis_violation();
        return -1;
    }
#endif

    return 30000;
}

aida_plugin_t::aida_plugin_t()
{
    ida_utils::compute_self_identity();

    if (license_manager_t::instance().get_runtime_nonce() == 0)
    {
    }

    msg(OBFSTR_C("--- Plugin Loading (v%s) ---\n"), AIDA_VERSION);

#ifdef __NT__
    if (!driver_loader::is_driver_loaded())
        msg(OBFSTR_C("AiDA Driver: Warning - kernel driver trust state was lost after initialization.\n"));
#endif

    g_settings.load(this);
    aida_db::AnalysisDB::instance().load();
    agent_tools::initialize_all_tools();
    analysis_fixer::install_hexrays_fixups();
    register_actions();
    hook_event_listener(HT_UI, &ui_listener);
    hook_event_listener(HT_DBG, &dbg_listener);

    if (g_settings.mcp_enabled)
        start_mcp_server();

    msg(OBFSTR_C("--- Plugin Loaded Successfully ---\n"));


    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!bin_hash.empty())
    {
        std::thread([bin_hash]() {
            graphrag::load_graph(bin_hash);
        }).detach();
    }
}

aida_plugin_t::~aida_plugin_t()
{

    std::string bin_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!bin_hash.empty())
        graphrag::save_graph(bin_hash);
    aida_db::AnalysisDB::instance().save();

    stop_mcp_server();
    ::unhook_event_listener(HT_DBG, &dbg_listener);
    ::unhook_event_listener(HT_UI, &ui_listener);
    analysis_fixer::uninstall_hexrays_fixups();
    unregister_actions();
    g_dbg_event_log.clear();
    msg(OBFSTR_C("--- Plugin has been unloaded ---\n"));
}

bool idaapi aida_plugin_t::run(size_t)
{
    auto& license = license_manager_t::instance();
    if (!license.is_valid() || license.get_runtime_nonce() == 0)
    {
        warning(OBFSTR_C("License validation failed. Please restart IDA and enter a valid license key."));
        return false;
    }

    if (license.get_runtime_nonce() == 0xDEADBEEFCAFEBABEULL
        || license.get_runtime_nonce() == 0xFFFFFFFFFFFFFFFFULL)
    {
    }

    info(OBFSTR_C("Plugin is active. Use the right-click context menu in a code view or the Tools menu."));
    return true;
}

void aida_plugin_t::start_mcp_server()
{
    if (!g_settings.mcp_enabled)
        return;

    if (ida_utils::is_self_target_database())
    {
        msg(OBFSTR_C("MCP: disabled while AiDA itself is the active analysis target.\n"));
        return;
    }

    if (mcp_server && mcp_server->is_running())
        return;

    mcp_server = std::make_unique<mcp_server_t>();
    if (!mcp_server->start(g_settings.mcp_port))
    {
        msg(OBFSTR_C("MCP: Could not start server on port %d.\n"), g_settings.mcp_port);
        mcp_server.reset();
        return;
    }

    mcp_server->write_mcp_client_configs();
}

void aida_plugin_t::stop_mcp_server()
{
    if (mcp_server)
    {
        mcp_server->stop();
        mcp_server.reset();
    }
}

void aida_plugin_t::toggle_mcp_server()
{
    if (mcp_server && mcp_server->is_running())
    {
        stop_mcp_server();
        g_settings.mcp_enabled = false;
        g_settings.save();
        msg(OBFSTR_C("MCP: Server stopped and disabled.\n"));
    }
    else
    {
        g_settings.mcp_enabled = true;
        g_settings.save();
        start_mcp_server();
    }
}

void aida_plugin_t::register_actions()
{
    struct rt_action_def_t {
        std::string name;
        std::string label;
        action_handler::action_func_t handler;
        const char* shortcut;
    };

    const rt_action_def_t action_definitions[] = {
        {OBFSTR("ai_assistant:copy_context"), OBFSTR("Copy function contents"), handle_copy_context, "Ctrl+Alt+X"},
        {OBFSTR("ai_assistant:save_database_context"), OBFSTR("Save database context to file..."), handle_save_database_context, ""},
        {OBFSTR("ai_assistant:fix_analysis"), OBFSTR("Fix Analysis (Clean Decompilation)"), handle_fix_analysis, "Ctrl+Alt+F"},
        {OBFSTR("ai_assistant:toggle_mcp"), OBFSTR("Start MCP Server"), handle_toggle_mcp, ""},
    };

    const std::string menu_root = OBFSTR("AiDA/");

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
            msg(OBFSTR_C("Failed to register action %s\n"), def.name.c_str());
            continue;
        }
        attach_action_to_menu(menu_root.c_str(), def.name.c_str(), SETMENU_APP);
    }
}

void aida_plugin_t::unregister_actions()
{
    for (const auto& action_name : actions_list)
    {
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
}

static plugmod_t* idaapi init()
{
#ifdef __NT__
    if (!has_expected_plugin_filename())
    {
        msg(OBFSTR_C("AiDA: plugin filename mismatch. Expected exact name: AiDA.dll\n"));
        return PLUGIN_SKIP;
    }
#endif

    g_settings.load_from_file();

    if (!g_settings.eula_accepted)
    {
        if (!show_eula_dialog())
        {
            msg(OBFSTR_C("AiDA: End User License Agreement was declined. Plugin will not load.\n"));
            return PLUGIN_SKIP;
        }
        g_settings.eula_accepted = true;
        g_settings.save();
    }

#ifdef __NT__
    if (!driver_loader::initialize_and_load())
    {
        msg(OBFSTR_C("AiDA: kernel driver attestation is required and could not be initialized.\n"));
        return PLUGIN_SKIP;
    }

    if (!anti_re::initialize())
        msg(OBFSTR_C("AiDA: kernel-backed runtime attestation warm-up failed; runtime checks will retry on demand.\n"));
#endif


    ida_utils::compute_self_identity();
    if (ida_utils::is_self_target_database())
        return PLUGIN_SKIP;


    std::thread([]() { discord_webhook::get_public_ip(); }).detach();

    register_timer(10000, self_analysis_watchdog, nullptr);

    auto& license = license_manager_t::instance();

    bool license_ok = license.validate();

    if (!license_ok || !license.is_valid())
    {
        bool activated = false;
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            if (license.show_activation_dialog())
            {
                activated = true;
                break;
            }

            if (attempt < 2)
            {
                int choice = ask_yn(ASKBTN_YES,
                    OBFSTR_C("License validation failed. Try again?"));
                if (choice != ASKBTN_YES)
                    break;
            }
        }

        if (!activated || !license.is_valid())
        {
            msg(OBFSTR_C("Plugin requires a valid license to operate.\n"));
            return PLUGIN_SKIP;
        }
    }

    license.start_revalidation_timer();

    license.snapshot_function_prologues();

#ifdef __NT__
    anti_re::start_pipe_monitor();
    {
        uint8_t self_sha[32] = {};
        if (ida_utils::get_self_sha256(self_sha))
            anti_re::start_process_hash_scanner(self_sha, 32);
    }
    anti_re::start_driver_tamper_monitor();
    anti_re::arm_destructive_enforcement();
#endif

    return new aida_plugin_t();
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
