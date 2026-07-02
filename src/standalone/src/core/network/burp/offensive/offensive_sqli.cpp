#include "offensive_sqli.hpp"

#include "sqli_engine.hpp"

#include "../../../settings/standalone_compat.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <string>

namespace aida {
namespace burp {
namespace offensive {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t to_tool_result(const sqli::engine_result_t& r)
{
    if (r.ok) return tool_result_t::ok(r.message, r.data);
    if (!r.code.empty()) return tool_result_t::error(r.message, r.code, r.data);
    return tool_result_t::error(r.message, r.data);
}

}

void register_sqli_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "aida_offensive_sqli_manage", "offensive.sqli",
        "SQL injection detection and exploitation toolkit. Actions: detect, enumerate_schemas, enumerate_tables, enumerate_columns, extract_data, os_command, waf_identify, waf_bypass, fingerprint_db, get_status, get_results.",
        {
            {"action", "string", "detect|enumerate_schemas|enumerate_tables|enumerate_columns|extract_data|os_command|waf_identify|waf_bypass|fingerprint_db|get_status|get_results", true},
            {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
            {"url", "string", "Target URL for detect or waf_identify.", false},
            {"method", "string", "HTTP method for synthesized requests.", false},
            {"params", "object", "Request parameter map for synthesized requests.", false},
            {"headers", "object|array|string", "Request headers for synthesized requests.", false},
            {"body", "string", "Text request body for synthesized requests.", false},
            {"param_target", "string", "Specific insertion point name to test.", false},
            {"techniques", "array", "SQLi techniques: error, boolean, time, union, waf_bypass, fingerprint, all.", false},
            {"dbms", "string", "mysql|mssql|postgres|oracle|sqlite|auto.", false},
            {"session_id", "string", "Session id returned by detect.", false},
            {"schema", "string", "Schema/catalog name for enumeration or extraction.", false},
            {"table", "string", "Table name for column enumeration or data extraction.", false},
            {"columns", "array", "Column names for bounded data extraction.", false},
            {"where_clause", "string", "Optional bounded WHERE clause for extraction.", false},
            {"command", "string", "OS command for output-marker proof attempts.", false},
            {"timeout_ms", "number", "Request timeout in milliseconds.", false},
            {"level", "number", "Probe depth 1-5.", false},
            {"risk", "number", "Reserved SQLi risk level 1-3.", false},
            {"scope_only", "boolean", "Keep active requests constrained to Burp scope; default true.", false}
        },
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            diag::log_tagged_fmt("offensive_sqli", "dispatch action=%s", action.c_str());
            if (action == "detect") return to_tool_result(sqli::detect(p));
            if (action == "enumerate_schemas") return to_tool_result(sqli::enumerate_schemas(p));
            if (action == "enumerate_tables") return to_tool_result(sqli::enumerate_tables(p));
            if (action == "enumerate_columns") return to_tool_result(sqli::enumerate_columns(p));
            if (action == "extract_data") return to_tool_result(sqli::extract_data(p));
            if (action == "os_command") return to_tool_result(sqli::os_command(p));
            if (action == "waf_identify") return to_tool_result(sqli::waf_identify(p));
            if (action == "waf_bypass") return to_tool_result(sqli::waf_bypass(p));
            if (action == "fingerprint_db") return to_tool_result(sqli::fingerprint_db(p));
            if (action == "get_status") return to_tool_result(sqli::get_status(p));
            if (action == "get_results") return to_tool_result(sqli::get_results(p));
            return compat_unknown_action("aida_offensive_sqli_manage", action);
        },
        false
    });
}

}
}
}
