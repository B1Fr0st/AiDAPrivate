#include "burp_module.hpp"

#include "scope.hpp"
#include "cookie_jar.hpp"
#include "issue.hpp"
#include "site_map.hpp"

#include "passive_scanner.hpp"
#include "active_scanner.hpp"
#include "dom_xss_engine.hpp"

#include "payload_library.hpp"
#include "crawler.hpp"
#include "content_discovery.hpp"
#include "subdomain_enum.hpp"

#include "auth_lab.hpp"
#include "jwt_lab.hpp"
#include "match_replace.hpp"
#include "session_handler.hpp"

#include "api_definition.hpp"
#include "ws_editor.hpp"
#include "burp_logger.hpp"

#include "browser_launch.hpp"
#include "csp_analyzer.hpp"
#include "upstream_chain.hpp"
#include "tech_fingerprint.hpp"

#include "camoufox_install.hpp"
#include "camoufox_bridge.hpp"
#include "headless_view.hpp"

#include "../../../helpers/diag_log.hpp"
#include "../../infra/work_queue.hpp"

#include <atomic>
#include <exception>

namespace aida {
namespace burp {

namespace target          { void register_target_tools(mcp_standalone::server_t&); }
namespace collaborator_mcp{ void register_collaborator_tools(mcp_standalone::server_t&); }
namespace sequencer_mcp   { void register_sequencer_tools(mcp_standalone::server_t&); }
namespace comparer_mcp    { void register_comparer_tools(mcp_standalone::server_t&); }
namespace api_mcp         { void register_api_tools(mcp_standalone::server_t&); }
namespace bambda          { void register_bambda_tools(mcp_standalone::server_t&); }
namespace csp             { void register_csp_tools(mcp_standalone::server_t&); }
namespace upstream        { void register_upstream_tools(mcp_standalone::server_t&); }
namespace tech            { void register_tech_tools(mcp_standalone::server_t&); }
void register_scanner_tools(mcp_standalone::server_t&);
void register_recon_tools(mcp_standalone::server_t&);
void register_intruder_tools(mcp_standalone::server_t&);
void register_jwt_tools(mcp_standalone::server_t&);
void register_auth_tools(mcp_standalone::server_t&);
void register_match_replace_tools(mcp_standalone::server_t&);
void register_session_tools(mcp_standalone::server_t&);
void register_dom_xss_tools(mcp_standalone::server_t&);
void register_camoufox_tools(mcp_standalone::server_t&);

namespace {

std::atomic<bool>& initialized_flag()
{
    static std::atomic<bool> f{false};
    return f;
}

template <typename Fn>
void run_init_phase(const char* name, Fn&& fn)
{
    diag::log_tagged_fmt("burp_module", "init_phase_begin name=%s", name ? name : "?");
    try
    {
        fn();
        diag::log_tagged_fmt("burp_module", "init_phase_ok name=%s", name ? name : "?");
    }
    catch (const std::exception& e)
    {
        diag::log_tagged_fmt("burp_module", "init_phase_cpp_exception name=%s what=%s",
            name ? name : "?", e.what());
        throw;
    }
    catch (...)
    {
        diag::log_tagged_fmt("burp_module", "init_phase_unknown_exception name=%s", name ? name : "?");
        throw;
    }
}

}

bool initialize()
{
    bool expected = false;
    if (!initialized_flag().compare_exchange_strong(expected, true)) return true;

    try
    {
        run_init_phase("scope", []() { (void)scope::initialize(); });
        run_init_phase("issue_store", []() { (void)issue_store::initialize(); });
        run_init_phase("cookie_jar", []() { (void)cookie_jar::initialize(); });
        run_init_phase("payloads", []() { (void)payloads::initialize(); });
        run_init_phase("sitemap", []() { (void)sitemap::initialize(); });

        run_init_phase("passive_scanner", []() { (void)passive_scanner::initialize(); });
        run_init_phase("active_scanner", []() { (void)active_scanner::initialize(); });
        run_init_phase("dom_xss", []() { (void)dom_xss::initialize(); });

        run_init_phase("crawler", []() { (void)crawler::initialize(); });
        run_init_phase("content_discovery", []() { (void)content_discovery::initialize(); });
        run_init_phase("subdomain_enum", []() { (void)subdomain_enum::initialize(); });

        run_init_phase("auth_lab", []() { (void)auth_lab::initialize(); });
        run_init_phase("jwt_lab", []() { (void)jwt_lab::initialize(); });
        run_init_phase("match_replace", []() { (void)match_replace::initialize(); });
        run_init_phase("session_handler", []() { (void)session_handler::initialize(); });

        run_init_phase("api_definition", []() { (void)api_definition::initialize(); });
        run_init_phase("ws_editor", []() { (void)ws_editor::initialize(); });
        run_init_phase("logger", []() { (void)logger::initialize(); });

        run_init_phase("browser", []() { (void)browser::initialize(); });
        run_init_phase("csp", []() { (void)csp::initialize(); });
        run_init_phase("tech", []() { (void)tech::initialize(); });
        run_init_phase("upstream", []() { (void)upstream::initialize(); });

        run_init_phase("camoufox_install", []() {
            const bool posted = work_queue::post([]() {
                (void)camoufox::install::initialize();
            });
            diag::log_tagged_fmt("burp_module", "camoufox_install async_offload posted=%d", posted ? 1 : 0);
            if (!posted) {
                (void)camoufox::install::initialize();
            }
        });
        run_init_phase("headless_view", []() { (void)headless_view::initialize(); });

        diag::log_tagged("burp_module", "initialized");
        return true;
    }
    catch (...)
    {
        diag::log_tagged("burp_module", "initialize_failed_unwinding");
        try
        {
            shutdown();
        }
        catch (...)
        {
            initialized_flag().store(false);
            diag::log_tagged("burp_module", "initialize_unwind_exception");
        }
        initialized_flag().store(false);
        throw;
    }
}

void shutdown()
{
    if (!initialized_flag().exchange(false)) return;

    try
    {
        camoufox::force_cleanup("burp_module.shutdown");
    }
    catch (...)
    {
        diag::log_tagged("burp_module", "camoufox_force_cleanup_exception");
    }
    headless_view::shutdown();
    camoufox::install::shutdown();

    upstream::shutdown();
    tech::shutdown();
    csp::shutdown();
    browser::shutdown();

    logger::shutdown();
    ws_editor::shutdown();
    api_definition::shutdown();

    session_handler::shutdown();
    match_replace::shutdown();
    jwt_lab::shutdown();
    auth_lab::shutdown();

    subdomain_enum::shutdown();
    content_discovery::shutdown();
    crawler::shutdown();

    dom_xss::shutdown();
    active_scanner::shutdown();
    passive_scanner::shutdown();

    sitemap::shutdown();
    payloads::shutdown();
    cookie_jar::shutdown();
    issue_store::shutdown();
    scope::shutdown();
}

void register_all_tools(mcp_standalone::server_t& srv)
{
    target::register_target_tools(srv);
    register_scanner_tools(srv);
    register_dom_xss_tools(srv);
    register_recon_tools(srv);
    collaborator_mcp::register_collaborator_tools(srv);
    sequencer_mcp::register_sequencer_tools(srv);
    comparer_mcp::register_comparer_tools(srv);
    register_intruder_tools(srv);
    register_jwt_tools(srv);
    register_auth_tools(srv);
    register_match_replace_tools(srv);
    register_session_tools(srv);
    api_mcp::register_api_tools(srv);
    bambda::register_bambda_tools(srv);
    csp::register_csp_tools(srv);
    upstream::register_upstream_tools(srv);
    tech::register_tech_tools(srv);
    register_camoufox_tools(srv);
}

}
}
