#include "offensive_js_analysis.hpp"

#include "js_analysis_engine.hpp"
#include "../../../settings/standalone_compat.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <string>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using mcp_standalone::tool_result_t;

tool_result_t result_from_json(const json& out)
{
    if (out.is_object() && out.value("ok", true) == false)
        return tool_result_t::error(out.value("error", std::string("js_analysis_failed")), out);
    return tool_result_t::ok(out);
}

tool_result_t handle_manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("mcp_burp", "offensive_js_analysis action=%s", action.c_str());
    if (action == "extract_endpoints") return result_from_json(js_analysis::extract_endpoints(p));
    if (action == "extract_secrets") return result_from_json(js_analysis::extract_secrets(p));
    if (action == "source_map_analyze") return result_from_json(js_analysis::source_map_analyze(p));
    if (action == "deobfuscate") return result_from_json(js_analysis::deobfuscate(p));
    if (action == "framework_detect") return result_from_json(js_analysis::framework_detect(p));
    if (action == "dependency_audit") return result_from_json(js_analysis::dependency_audit(p));
    if (action == "get_status") return result_from_json(js_analysis::get_status(p));
    if (action == "get_results") return result_from_json(js_analysis::get_results(p));
    return compat_unknown_action("aida_offensive_js_analysis_manage", action);
}

}

void register_js_analysis_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    srv.register_tool({
        "aida_offensive_js_analysis_manage",
        "JavaScript reversing and exposure analysis. Actions: extract_endpoints, extract_secrets, source_map_analyze, deobfuscate, framework_detect, dependency_audit, get_status, get_results.",
        {p{"action", "string", "extract_endpoints|extract_secrets|source_map_analyze|deobfuscate|framework_detect|dependency_audit|get_status|get_results", true},
         p{"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
         p{"url", "string", "JavaScript URL to fetch.", false},
         p{"urls", "array", "JavaScript URLs to fetch, bounded by max_urls.", false},
         p{"source", "string", "Inline JavaScript source.", false},
         p{"source_name", "string", "Label for inline source.", false},
         p{"headers", "object", "Optional request headers; secret-like values are never returned.", false},
         p{"target_domain", "string", "Target domain used for report context filtering.", false},
         p{"max_results", "number", "Maximum findings to return.", false},
         p{"timeout_ms", "number", "Bounded fetch timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound fetches by default.", false}},
        false,
        handle_manage,
        mcp_standalone::tool_visibility_t::external_visible
    });
}

}
}
}
