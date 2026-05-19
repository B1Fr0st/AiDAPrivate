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
#include "headless_view.hpp"

#include "../../../helpers/diag_log.hpp"

#include <atomic>

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
namespace browser         { void register_browser_tools(mcp_standalone::server_t&); }
void register_scanner_tools(mcp_standalone::server_t&);
void register_recon_tools(mcp_standalone::server_t&);
void register_intruder_tools(mcp_standalone::server_t&);
void register_jwt_tools(mcp_standalone::server_t&);
void register_auth_tools(mcp_standalone::server_t&);
void register_match_replace_tools(mcp_standalone::server_t&);
void register_session_tools(mcp_standalone::server_t&);
void register_dom_xss_tools(mcp_standalone::server_t&);
void register_camoufox_tools(mcp_standalone::server_t&);
void register_headless_view_tools(mcp_standalone::server_t&);

namespace {

std::atomic<bool>& initialized_flag()
{
    static std::atomic<bool> f{false};
    return f;
}

}

bool initialize()
{
    bool expected = false;
    if (!initialized_flag().compare_exchange_strong(expected, true)) return true;

    scope::initialize();
    issue_store::initialize();
    cookie_jar::initialize();
    payloads::initialize();
    sitemap::initialize();

    passive_scanner::initialize();
    active_scanner::initialize();
    dom_xss::initialize();

    crawler::initialize();
    content_discovery::initialize();
    subdomain_enum::initialize();

    auth_lab::initialize();
    jwt_lab::initialize();
    match_replace::initialize();
    session_handler::initialize();

    api_definition::initialize();
    ws_editor::initialize();
    logger::initialize();

    browser::initialize();
    csp::initialize();
    tech::initialize();
    upstream::initialize();

    camoufox::install::initialize();
    headless_view::initialize();

    diag::log_tagged("burp_module", "initialized");
    return true;
}

void shutdown()
{
    if (!initialized_flag().exchange(false)) return;

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
    browser::register_browser_tools(srv);
    register_camoufox_tools(srv);
    register_headless_view_tools(srv);
}

}
}
