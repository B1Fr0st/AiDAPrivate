#include "offensive_fuzzing.hpp"

#include "fuzzing_engine.hpp"

#include "../../../settings/standalone_compat.hpp"
#include "../../../../helpers/diag_log.hpp"

namespace aida {
namespace burp {
namespace offensive {

void register_fuzzing_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_fuzzing_manage", "offensive_fuzzing",
        "Manage bounded fuzzing jobs and corpus mutation. Actions: start, stop, status, results, mutate, corpus_add, anomaly_analyze.",
        {{"action", "string", "start|stop|status|results|mutate|corpus_add|anomaly_analyze", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const nlohmann::json& params) -> mcp_standalone::tool_result_t {
            const std::string action = compat_action_name(params);
            const nlohmann::json p = compat_action_payload(params);
            if (action == "start" || action == "start_fuzz") return fuzzing::start(p);
            if (action == "stop") return fuzzing::stop(p);
            if (action == "status" || action == "get_status") return fuzzing::status(p);
            if (action == "results" || action == "get_results") return fuzzing::results(p);
            if (action == "mutate" || action == "mutation_fuzz") return fuzzing::mutate(p);
            if (action == "corpus_add") return fuzzing::corpus_add(p);
            if (action == "anomaly_analyze" || action == "analyze_results") return fuzzing::anomaly_analyze(p);
            return compat_unknown_action("aida_offensive_fuzzing_manage", action);
        },
        false
    });
    diag::log_tagged("off_fuzz", "registered aida_offensive_fuzzing_manage");
}

}
}
}
