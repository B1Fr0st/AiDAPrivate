#include "aida_pro.hpp"

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

aida_plugin_t::aida_plugin_t()
{
    msg(OBFSTR_C("--- Plugin Loading (v%s) ---\n"), AIDA_VERSION);
    g_settings.load(this);
    agent_tools::initialize_all_tools();
    register_actions();
    hook_event_listener(HT_UI, &ui_listener);

    if (g_settings.mcp_enabled)
        start_mcp_server();

    reinit_ai_client();
    msg(OBFSTR_C("--- Plugin Loaded Successfully ---\n"));

    if (g_settings.check_for_updates)
    {
        check_for_updates();
    }
}

aida_plugin_t::~aida_plugin_t()
{
    stop_copilot_proxy();
    stop_mcp_server();
    ::unhook_event_listener(HT_UI, &ui_listener);
    unregister_actions();
    msg(OBFSTR_C("--- Plugin has been unloaded ---\n"));
}

void aida_plugin_t::reinit_ai_client()
{
    m_stale_clients.erase(
        std::remove_if(m_stale_clients.begin(), m_stale_clients.end(),
            [](const std::unique_ptr<AIClient>& c) { return c->_task_done.load(); }),
        m_stale_clients.end());

    if (ai_client && !ai_client->_task_done.load())
    {
        m_stale_clients.push_back(std::move(ai_client));
    }

    stop_copilot_proxy();

    ai_client = get_ai_client(g_settings);

    qstring provider = ida_utils::qstring_tolower(g_settings.api_provider.c_str());
    if (provider == "copilot")
        start_copilot_proxy();

    if (!ai_client || !ai_client->is_available())
    {
        msg(OBFSTR_C("No AI client is available. AI features will be limited.\n"));
    }
}

void aida_plugin_t::start_copilot_proxy()
{
#ifdef __NT__
    if (m_copilot_process != nullptr)
        return;

    if (g_settings.copilot_proxy_address.empty())
    {
        g_settings.copilot_proxy_address = "http://127.0.0.1:4141";
        g_settings.save();
    }

    bool already_running = false;
    try
    {
        httplib::Client probe(g_settings.copilot_proxy_address);
        probe.set_connection_timeout(0, 500000);
        probe.set_read_timeout(0, 500000);
        auto res = probe.Get("/v1/models");
        if (res)
            already_running = true;
    }
    catch (...) {}

    if (already_running)
    {
        msg(OBFSTR_C("Copilot API proxy is already running at %s\n"),
            g_settings.copilot_proxy_address.c_str());
        return;
    }

    m_copilot_job = CreateJobObject(nullptr, nullptr);
    if (m_copilot_job != nullptr)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(m_copilot_job,
            JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    wchar_t cmdline[] = L"cmd.exe /c npx copilot-api@latest start";

    DWORD flags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;
    if (!CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
        flags, nullptr, nullptr, &si, &pi))
    {
        DWORD err = GetLastError();
        msg(OBFSTR_C("Failed to launch copilot-api (error %lu). "
            "Ensure Node.js and npx are installed and in your PATH.\n"),
            static_cast<unsigned long>(err));
        if (m_copilot_job != nullptr)
        {
            CloseHandle(m_copilot_job);
            m_copilot_job = nullptr;
        }
        return;
    }

    CloseHandle(pi.hThread);
    m_copilot_process = pi.hProcess;

    if (m_copilot_job != nullptr)
        AssignProcessToJobObject(m_copilot_job, pi.hProcess);

    if (WaitForSingleObject(m_copilot_process, 1500) == WAIT_OBJECT_0)
    {
        DWORD exit_code = 0;
        GetExitCodeProcess(m_copilot_process, &exit_code);
        CloseHandle(m_copilot_process);
        m_copilot_process = nullptr;
        if (m_copilot_job != nullptr)
        {
            CloseHandle(m_copilot_job);
            m_copilot_job = nullptr;
        }
        msg(OBFSTR_C("copilot-api exited immediately (code %lu). "
            "Is Node.js/npx installed and in your PATH?\n"),
            static_cast<unsigned long>(exit_code));
        return;
    }

    msg(OBFSTR_C("Copilot API proxy starting (pid %lu), please wait...\n"),
        static_cast<unsigned long>(pi.dwProcessId));

    std::string proxy_addr = g_settings.copilot_proxy_address;
    std::thread([proxy_addr]() {
        for (int attempt = 0; attempt < 120; ++attempt)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            try
            {
                httplib::Client probe(proxy_addr);
                probe.set_connection_timeout(1);
                probe.set_read_timeout(2);
                auto res = probe.Get("/v1/models");
                if (res)
                {
                    struct ready_notify_t : public exec_request_t
                    {
                        std::string addr;
                        ssize_t idaapi execute() override
                        {
                            msg("AiDA: Copilot API proxy is ready at %s\n",
                                addr.c_str());
                            delete this;
                            return 0;
                        }
                    };
                    auto* n = new ready_notify_t();
                    n->addr = proxy_addr;
                    execute_sync(*n, MFF_NOWAIT);
                    return;
                }
            }
            catch (...) {}
        }

        struct timeout_notify_t : public exec_request_t
        {
            ssize_t idaapi execute() override
            {
                msg(OBFSTR_C("Copilot API proxy did not become ready "
                    "within 120 seconds. Check your Node.js installation.\n"));
                delete this;
                return 0;
            }
        };
        execute_sync(*(new timeout_notify_t()), MFF_NOWAIT);
    }).detach();
#endif
}

void aida_plugin_t::stop_copilot_proxy()
{
#ifdef __NT__
    if (m_copilot_job != nullptr)
    {
        CloseHandle(m_copilot_job);
        m_copilot_job = nullptr;
    }
    if (m_copilot_process != nullptr)
    {
        TerminateProcess(m_copilot_process, 0);
        CloseHandle(m_copilot_process);
        m_copilot_process = nullptr;
        msg(OBFSTR_C("Copilot API proxy stopped.\n"));
    }
#endif
}

static int compare_versions(const std::string& a, const std::string& b)
{
    auto parse_parts = [](const std::string& ver) -> std::vector<int> {
        std::vector<int> parts;
        std::stringstream ss(ver);
        std::string token;
        while (std::getline(ss, token, '.'))
        {
            try { parts.push_back(std::stoi(token)); }
            catch (...) { parts.push_back(0); }
        }
        while (parts.size() < 3) parts.push_back(0);
        return parts;
    };

    auto pa = parse_parts(a);
    auto pb = parse_parts(b);

    for (size_t i = 0; i < 3; ++i)
    {
        if (pa[i] < pb[i]) return -1;
        if (pa[i] > pb[i]) return 1;
    }
    return 0;
}

void aida_plugin_t::check_for_updates()
{
    std::thread([]() {
        try
        {
            httplib::Client cli("https://api.github.com");
            cli.set_read_timeout(15);
            cli.set_connection_timeout(10);
            cli.set_default_headers({
                {"User-Agent", OBFSTR("AiDA-UpdateChecker/") + AIDA_VERSION},
                {"Accept", "application/vnd.github.v3+json"}
            });

            auto res = cli.Get((OBFSTR("/repos/") + AIDA_GITHUB_REPO + OBFSTR("/releases/latest")).c_str());
            if (!res || res->status != 200)
                return;

            auto j = nlohmann::json::parse(res->body);
            std::string latest_tag = j.value("tag_name", "");
            if (latest_tag.empty())
                return;

            std::string latest_version = latest_tag;
            if (!latest_version.empty() && (latest_version[0] == 'v' || latest_version[0] == 'V'))
                latest_version = latest_version.substr(1);

            std::string current_version = AIDA_VERSION;

            if (compare_versions(latest_version, current_version) > 0)
            {
                std::string html_url = j.value("html_url",
                    OBFSTR("https://github.com/") + AIDA_GITHUB_REPO + OBFSTR("/releases"));

                struct update_notify_t : public exec_request_t
                {
                    std::string version;
                    std::string url;
                    ssize_t idaapi execute() override
                    {
                        msg(OBFSTR_C("Update available! Current: v%s, Latest: v%s\n"),
                            AIDA_VERSION, version.c_str());
                        msg(OBFSTR_C("Download at: %s\n"), url.c_str());
                        info(OBFSTR_C("Update Available!\n\n"
                             "A new version (v%s) is available.\n"
                             "You are running v%s.\n\n"
                             "Visit the releases page to download:\n%s"),
                             version.c_str(), AIDA_VERSION, url.c_str());
                        delete this;
                        return 0;
                    }
                };
                auto* req = new update_notify_t();
                req->version = latest_version;
                req->url = html_url;
                execute_sync(*req, MFF_NOWAIT);
            }
            else
            {
                msg(OBFSTR_C("Plugin is up to date (v%s).\n"), AIDA_VERSION);
            }
        }
        catch (...)
        {
        }
    }).detach();
}

bool idaapi aida_plugin_t::run(size_t)
{
    info(OBFSTR_C("Plugin is active. Use the right-click context menu in a code view or the Tools menu."));
    return true;
}

void aida_plugin_t::start_mcp_server()
{
    if (!g_settings.mcp_enabled)
        return;

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
        {OBFSTR("ai_assistant:analyze"), OBFSTR("Analyze function..."), handle_analyze_function, "Ctrl+Alt+A"},
        {OBFSTR("ai_assistant:comment"), OBFSTR("Add AI-generated comments"), handle_auto_comment, "Ctrl+Alt+C"},
        {OBFSTR("ai_assistant:gen_struct"), OBFSTR("Generate struct from function"), handle_generate_struct, "Ctrl+Alt+G"},
        {OBFSTR("ai_assistant:gen_hook"), OBFSTR("Generate MinHook C++ snippet"), handle_generate_hook, "Ctrl+Alt+H"},
        {OBFSTR("ai_assistant:copy_context"), OBFSTR("Copy Context"), handle_copy_context, "Ctrl+Alt+X"},
        {OBFSTR("ai_assistant:rename_all"), OBFSTR("Rename variables/functions..."), handle_rename_all, "Ctrl+Alt+R"},
        {OBFSTR("ai_assistant:scan_for_offsets"), OBFSTR("Scan for Engine Pointers (Coming Soon!)"), handle_scan_for_offsets, ""},
        {OBFSTR("ai_assistant:save_database_context"), OBFSTR("Save database context to file..."), handle_save_database_context, ""},
        {OBFSTR("ai_assistant:open_chat"), OBFSTR("Open Chat..."), handle_open_chat, "Ctrl+Alt+I"},
        {OBFSTR("ai_assistant:fix_analysis"), OBFSTR("Fix Analysis (Clean Decompilation)"), handle_fix_analysis, "Ctrl+Alt+F"},
        {OBFSTR("ai_assistant:cancel"), OBFSTR("Cancel AI Request"), handle_cancel_request, "Ctrl+Alt+Z"},
        {OBFSTR("ai_assistant:check_for_updates"), OBFSTR("Check for updates..."), handle_check_for_updates, ""},
        {OBFSTR("ai_assistant:toggle_mcp"), OBFSTR("Start MCP Server"), handle_toggle_mcp, ""},
        {OBFSTR("ai_assistant:settings"), OBFSTR("Settings..."), handle_show_settings, "Ctrl+Alt+O"},
    };

    const std::string menu_root = OBFSTR("AI Assistant/");

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
    g_settings.load_from_file();

    auto& license = license_manager_t::instance();

    if (!license.validate())
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

        if (!activated)
        {
            msg(OBFSTR_C("Plugin requires a valid license to operate.\n"));
            return PLUGIN_SKIP;
        }
    }

    return new aida_plugin_t();
}

static const std::string _p_comment = OBFSTR("AI-powered game reversing assistant");
static const std::string _p_help    = OBFSTR("Right-click in code views or use the menu");
static const std::string _p_name    = OBFSTR("AI Assistant");

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  _p_comment.c_str(),
  _p_help.c_str(),
  _p_name.c_str(),
  ""
};