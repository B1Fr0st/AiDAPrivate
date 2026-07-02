#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "offensive_business_logic.hpp"

#include "business_logic_engine.hpp"
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

tool_result_t to_tool_result(const business_logic::result_t& r)
{
    if (r.success) return tool_result_t::ok(r.message, r.data);
    return tool_result_t::error(r.message, r.error_code.empty() ? "offensive_business_logic_error" : r.error_code, r.data);
}

}

void register_business_logic_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_business_logic_manage",
        "offensive_business_logic",
        "Business logic abuse and workflow testing toolkit. Actions: race_test, price_tamper, coupon_abuse, workflow_bypass, quantity_tamper, role_escalation, get_status, get_results.",
        {{"action", "string", "race_test|price_tamper|coupon_abuse|workflow_bypass|quantity_tamper|role_escalation|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json payload = compat_action_payload(params);
            return to_tool_result(business_logic::handle_action(action, payload));
        },
        false});
}

}
}
}
