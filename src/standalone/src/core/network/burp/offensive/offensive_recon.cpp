#include "offensive_recon.hpp"

#include "recon_engine.hpp"
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
        return tool_result_t::error(out.value("error", std::string("recon_failed")), out);
    return tool_result_t::ok(out);
}

tool_result_t handle_manage(const json& params)
{
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    diag::log_tagged_fmt("mcp_burp", "offensive_recon action=%s", action.c_str());
    if (action == "fingerprint") return result_from_json(recon::fingerprint(p));
    if (action == "waf_detect") return result_from_json(recon::waf_detect(p));
    if (action == "dns_enum") return result_from_json(recon::dns_enum(p));
    if (action == "s3_discovery") return result_from_json(recon::s3_discovery(p));
    if (action == "cloud_metadata_test") return result_from_json(recon::cloud_metadata_test(p));
    if (action == "port_scan") return result_from_json(recon::port_scan(p));
    if (action == "full_recon") return result_from_json(recon::full_recon(p));
    if (action == "get_status") return result_from_json(recon::get_status(p));
    return compat_unknown_action("aida_offensive_recon_manage", action);
}

}

void register_recon_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    srv.register_tool({
        "aida_offensive_recon_manage",
        "Cloud and infrastructure reconnaissance. Actions: fingerprint, waf_detect, dns_enum, s3_discovery, cloud_metadata_test, port_scan, full_recon, get_status.",
        {p{"action", "string", "fingerprint|waf_detect|dns_enum|s3_discovery|cloud_metadata_test|port_scan|full_recon|get_status", true},
         p{"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
         p{"url", "string", "Target URL for fingerprint, WAF, or cloud metadata tests.", false},
         p{"domain", "string", "Target domain for DNS, S3, and full recon.", false},
         p{"host", "string", "Host for connect port scan.", false},
         p{"target_domain", "string", "Target domain used for report context filtering.", false},
         p{"timeout_ms", "number", "Bounded timeout for network operations.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound HTTP probes by default.", false},
         p{"ports", "array", "Explicit TCP ports for connect scan.", false},
         p{"port_range", "string", "Bounded TCP port range such as 1-1024.", false}},
        false,
        handle_manage,
        mcp_standalone::tool_visibility_t::external_visible
    });
}

}
}
}
