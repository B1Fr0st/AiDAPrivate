#include "offensive_api_rest.hpp"

#include "api_security_engine.hpp"
#include "offensive_graphql.hpp"

#include "../../../settings/standalone_compat.hpp"
#include "../../../../helpers/diag_log.hpp"

namespace aida {
namespace burp {
namespace offensive {

void register_api_rest_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_api_rest_manage", "offensive_api",
        "Manage REST API offensive security checks. Actions: discover, param_fuzz, mass_assignment, authz_matrix, rate_limit_test, schema_diff, get_status, get_results.",
        {{"action", "string", "discover|param_fuzz|mass_assignment|authz_matrix|rate_limit_test|schema_diff|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const nlohmann::json& params) -> mcp_standalone::tool_result_t {
            const std::string action = compat_action_name(params);
            const nlohmann::json p = compat_action_payload(params);
            if (action == "discover" || action == "enumerate_endpoints") return api_security::discover(p);
            if (action == "param_fuzz" || action == "fuzz_params") return api_security::param_fuzz(p);
            if (action == "mass_assignment" || action == "mass_assignment_test") return api_security::mass_assignment(p);
            if (action == "authz_matrix" || action == "authorization_matrix") return api_security::authz_matrix(p);
            if (action == "rate_limit_test" || action == "rate_limit_bypass") return api_security::rate_limit_test(p);
            if (action == "schema_diff") return api_security::schema_diff(p);
            if (action == "get_status" || action == "status") return api_security::get_status(p);
            if (action == "get_results" || action == "results") return api_security::get_results(p);
            return compat_unknown_action("aida_offensive_api_rest_manage", action);
        },
        false
    });
    diag::log_tagged("off_api_rest", "registered aida_offensive_api_rest_manage");
}

void register_api_security_tools(mcp_standalone::server_t& srv)
{
    register_api_graphql_tools(srv);
    register_api_rest_tools(srv);
}

}
}
}
