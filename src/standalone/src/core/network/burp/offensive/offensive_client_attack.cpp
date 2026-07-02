#include "offensive_client_attack.hpp"

#include "client_attack_engine.hpp"

#include "../../../settings/standalone_compat.hpp"
#include "../../../../helpers/diag_log.hpp"

namespace aida {
namespace burp {
namespace offensive {

void register_client_attack_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_client_attack_manage", "offensive_client",
        "Manage client-side offensive checks. Actions: csrf_test, clickjacking_test, postmessage_scan, prototype_pollution, dom_clobbering, cors_exploit, get_status, get_results.",
        {{"action", "string", "csrf_test|clickjacking_test|postmessage_scan|prototype_pollution|dom_clobbering|cors_exploit|get_status|get_results", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const nlohmann::json& params) -> mcp_standalone::tool_result_t {
            const std::string action = compat_action_name(params);
            const nlohmann::json p = compat_action_payload(params);
            if (action == "csrf_test") return client_attack::csrf_test(p);
            if (action == "clickjacking_test" || action == "clickjack_test") return client_attack::clickjacking_test(p);
            if (action == "postmessage_scan" || action == "postmessage_test") return client_attack::postmessage_scan(p);
            if (action == "prototype_pollution" || action == "proto_pollution_test") return client_attack::prototype_pollution(p);
            if (action == "dom_clobbering" || action == "dom_clobber_test") return client_attack::dom_clobbering(p);
            if (action == "cors_exploit" || action == "cors_test") return client_attack::cors_exploit(p);
            if (action == "get_status" || action == "status") return client_attack::get_status(p);
            if (action == "get_results" || action == "results") return client_attack::get_results(p);
            return compat_unknown_action("aida_offensive_client_attack_manage", action);
        },
        false
    });
    diag::log_tagged("off_client", "registered aida_offensive_client_attack_manage");
}

}
}
}
