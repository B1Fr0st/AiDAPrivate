#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "offensive_auth_attack.hpp"

#include "auth_attack_engine.hpp"
#include "../../../mcp/mcp_standalone.hpp"
#include "../../../settings/standalone_compat.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t to_tool_result(const auth_attack::result_t& r)
{
    if (r.success) return tool_result_t::ok(r.message, r.data);
    return tool_result_t::error(r.message, r.error_code.empty() ? "offensive_auth_error" : r.error_code, r.data);
}

}

void register_auth_attack_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_auth_attack_manage",
        "offensive_auth_attack",
        "Authentication and authorization testing toolkit. Actions: brute_force, credential_stuffing, session_analysis, idor_test, bola_test, password_policy, mfa_bypass_check, get_status, get_results.",
        {{"action", "string", "brute_force|credential_stuffing|session_analysis|idor_test|bola_test|password_policy|mfa_bypass_check|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json payload = compat_action_payload(params);
            return to_tool_result(auth_attack::handle_action(action, payload));
        },
        false});
}

}
}
}
