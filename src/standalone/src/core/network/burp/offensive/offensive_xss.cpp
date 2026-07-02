#include "offensive_xss.hpp"

#include "xss_engine.hpp"

#include "../csp_analyzer.hpp"
#include "../dom_xss_engine.hpp"

#include "../../../settings/standalone_compat.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <string>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t to_tool_result(const xss::engine_result_t& r)
{
    if (r.ok) return tool_result_t::ok(r.message, r.data);
    if (!r.code.empty()) return tool_result_t::error(r.message, r.code, r.data);
    return tool_result_t::error(r.message, r.data);
}

}

void register_xss_tools(mcp_standalone::server_t& srv)
{
    dom_xss::initialize();
    csp::initialize();

    register_compat(srv, {
        "aida_offensive_xss_manage", "offensive.xss",
        "XSS detection, context-aware payload generation, CSP bypass analysis, DOM analysis, and stored XSS verification. Actions: detect, generate_payloads, test_csp_bypass, dom_analyze, stored_scan, context_probe, get_status, get_results.",
        {
            {"action", "string", "detect|generate_payloads|test_csp_bypass|dom_analyze|stored_scan|context_probe|get_status|get_results", true},
            {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
            {"url", "string", "Target URL.", false},
            {"method", "string", "HTTP method for synthesized requests.", false},
            {"params", "object", "Request parameter map for synthesized requests.", false},
            {"headers", "object|array|string", "Request headers for synthesized requests.", false},
            {"body", "string", "Text request body for synthesized requests.", false},
            {"param_target", "string", "Specific insertion point name to test.", false},
            {"xss_types", "array", "reflected|stored|dom|all.", false},
            {"use_browser", "boolean", "Use existing Camoufox DOM-XSS execution hooks when practical.", false},
            {"context", "string", "html|attribute|script|url|css|unknown for generate_payloads.", false},
            {"encoding", "string", "none|html_entities|url|base64|double_url|unicode.", false},
            {"payload_filter", "string", "all|waf_bypass|csp_bypass|short|event_handler|script_src.", false},
            {"marker", "string", "Custom marker for generated payloads.", false},
            {"max_payloads", "number", "Maximum generated payload count.", false},
            {"csp_header", "string", "CSP header value for test_csp_bypass; fetched from url when omitted.", false},
            {"verify_url", "string", "Clean verification URL for stored_scan.", false},
            {"session_id", "string", "Session id returned by detect or stored_scan.", false},
            {"timeout_ms", "number", "Request timeout in milliseconds.", false},
            {"scope_only", "boolean", "Keep active requests constrained to Burp scope; default true.", false}
        },
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            diag::log_tagged_fmt("offensive_xss", "dispatch action=%s", action.c_str());
            if (action == "detect") return to_tool_result(xss::detect(p));
            if (action == "generate_payloads") return to_tool_result(xss::generate_payloads(p));
            if (action == "test_csp_bypass") return to_tool_result(xss::test_csp_bypass(p));
            if (action == "dom_analyze") return to_tool_result(xss::dom_analyze(p));
            if (action == "stored_scan") return to_tool_result(xss::stored_scan(p));
            if (action == "context_probe") return to_tool_result(xss::context_probe(p));
            if (action == "get_status") return to_tool_result(xss::get_status(p));
            if (action == "get_results") return to_tool_result(xss::get_results(p));
            return compat_unknown_action("aida_offensive_xss_manage", action);
        },
        false
    });
}

}
}
}
