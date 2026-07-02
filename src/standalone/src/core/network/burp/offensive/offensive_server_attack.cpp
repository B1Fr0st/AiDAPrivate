#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "offensive_server_attack.hpp"

#include "server_attack_engine.hpp"
#include "../../../settings/standalone_compat.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t to_tool_result(const server_attack::action_result_t& r)
{
    if (r.success) return tool_result_t::ok(r.message, r.data);
    return tool_result_t::error(r.message, r.code.empty() ? "offensive_server_attack_error" : r.code, r.data);
}

}

void register_server_attack_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_server_attack_manage",
        "offensive_server_attack",
        "Server-side attack exploitation toolkit. Actions: ssrf_exploit, ssti_exploit, cmdi_exploit, path_traversal_exploit, xxe_exploit, lfi_exploit, deserialize_exploit, smuggle_exploit, cloud_metadata_test, oob_confirm, get_status, get_results.",
        {{"action", "string", "ssrf_exploit|ssti_exploit|cmdi_exploit|path_traversal_exploit|xxe_exploit|lfi_exploit|deserialize_exploit|smuggle_exploit|cloud_metadata_test|oob_confirm|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
         {"url", "string", "Target URL for bounded HTTP delivery.", false},
         {"method", "string", "HTTP method for the synthesized request.", false},
         {"param", "string", "Preferred query or body parameter insertion point.", false},
         {"scope_only", "boolean", "Enforce the existing Burp scope before dispatching requests.", false},
         {"timeout_ms", "number", "Per-action deadline in milliseconds.", false},
         {"max_payloads", "number", "Maximum payload attempts for payload-driven actions.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json payload = compat_action_payload(params);
            return to_tool_result(server_attack::handle_action(action, payload));
        },
        false});
}

}
}
}
