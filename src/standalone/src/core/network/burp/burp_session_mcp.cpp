#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_session_mcp.hpp"
#include "session_handler.hpp"
#include "auth_lab.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

json step_to_json(const session_handler::macro_step_t& s_in)
{
    json j;
    j["label"] = s_in.label;
    j["scheme"] = s_in.scheme;
    j["host"] = s_in.host;
    j["port"] = s_in.port;
    j["raw_request_b64"] = auth_lab::base64_encode_std(s_in.raw_request.data(), s_in.raw_request.size());
    j["timeout_ms"] = s_in.timeout_ms;
    json extracts = json::array();
    for (const auto& e : s_in.extracts) {
        json je;
        je["name"]  = e.name;
        je["from"]  = e.from;
        je["regex"] = e.regex;
        je["group"] = e.group;
        extracts.push_back(je);
    }
    j["extracts"] = extracts;
    return j;
}

bool step_from_json(const json& j, session_handler::macro_step_t& out)
{
    if (!j.is_object()) return false;
    out.label = j.value("label", std::string());
    out.scheme = j.value("scheme", std::string("https"));
    out.host = j.value("host", std::string());
    out.port = static_cast<uint16_t>(j.value("port", 443));
    out.timeout_ms = j.value("timeout_ms", 15000);
    if (j.contains("raw_request_b64") && j["raw_request_b64"].is_string()) {
        std::string raw;
        if (auth_lab::base64_decode_std(j["raw_request_b64"].get<std::string>(), raw))
            out.raw_request.assign(raw.begin(), raw.end());
    } else if (j.contains("raw_request") && j["raw_request"].is_string()) {
        const std::string r = j["raw_request"].get<std::string>();
        out.raw_request.assign(r.begin(), r.end());
    }
    out.extracts.clear();
    if (j.contains("extracts") && j["extracts"].is_array()) {
        for (const auto& je : j["extracts"]) {
            session_handler::extract_t e;
            e.name  = je.value("name", std::string());
            e.from  = je.value("from", std::string("resp_body"));
            e.regex = je.value("regex", std::string());
            e.group = je.value("group", 1);
            out.extracts.push_back(e);
        }
    }
    return true;
}

json macro_to_json(const session_handler::macro_t& m)
{
    json j;
    j["id"] = m.id;
    j["name"] = m.name;
    json arr = json::array();
    for (const auto& s_in : m.steps) arr.push_back(step_to_json(s_in));
    j["steps"] = arr;
    json kv = json::object();
    for (const auto& e : m.last_extracted_values) kv[e.first] = e.second;
    j["last_extracted_values"] = kv;
    j["last_run_ms"] = m.last_run_ms;
    j["ok_last_run"] = m.ok_last_run;
    return j;
}

tool_result_t handle_macro_add(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "macro_add name=%s", params.value("name", std::string()).c_str());
    session_handler::macro_t m;
    m.name = params.value("name", std::string());
    if (params.contains("steps") && params["steps"].is_array()) {
        for (const auto& js : params["steps"]) {
            session_handler::macro_step_t st;
            if (step_from_json(js, st)) m.steps.push_back(st);
        }
    }
    diag::log_tagged_fmt("mcp_burp", "macro_add steps=%zu", m.steps.size());
    const uint64_t id = session_handler::add_macro(m);
    diag::log_tagged_fmt("mcp_burp", "macro_add ok macro_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["macro_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t handle_macro_run(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("macro_id", 0));
    diag::log_tagged_fmt("mcp_burp", "macro_run macro_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "macro_run missing macro_id");
        return tool_result_t::error("missing macro_id");
    }
    std::map<std::string, std::string> values;
    const bool ok = session_handler::run_macro(id, values);
    diag::log_tagged_fmt("mcp_burp", "macro_run ok macro_id=%llu success=%d extracted=%zu", static_cast<unsigned long long>(id), (int)ok, values.size());
    json out;
    out["ok"] = ok;
    json vj = json::object();
    for (const auto& kv : values) vj[kv.first] = kv.second;
    out["values"] = vj;
    return tool_result_t::ok(out);
}

tool_result_t handle_macro_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "macro_list entry");
    auto items = session_handler::list_macros();
    json arr = json::array();
    for (const auto& m : items) arr.push_back(macro_to_json(m));
    diag::log_tagged_fmt("mcp_burp", "macro_list ok count=%zu", items.size());
    json out;
    out["count"] = arr.size();
    out["macros"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t handle_macro_remove(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("macro_id", 0));
    diag::log_tagged_fmt("mcp_burp", "macro_remove macro_id=%llu", static_cast<unsigned long long>(id));
    const bool removed = session_handler::remove_macro(id);
    diag::log_tagged_fmt("mcp_burp", "macro_remove ok macro_id=%llu removed=%d", static_cast<unsigned long long>(id), (int)removed);
    json out;
    out["removed"] = removed;
    return tool_result_t::ok(out);
}

tool_result_t handle_macro_update(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("macro_id", 0));
    diag::log_tagged_fmt("mcp_burp", "macro_update macro_id=%llu", static_cast<unsigned long long>(id));
    if (id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "macro_update missing macro_id");
        return tool_result_t::error("missing macro_id");
    }
    session_handler::macro_t cur;
    if (!session_handler::get_macro(id, cur))
    {
        diag::log_tagged_fmt("mcp_burp", "macro_update not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("macro not found");
    }
    if (params.contains("fields") && params["fields"].is_object()) {
        const auto& f = params["fields"];
        if (f.contains("name")) cur.name = f.value("name", cur.name);
        if (f.contains("steps") && f["steps"].is_array()) {
            cur.steps.clear();
            for (const auto& js : f["steps"]) {
                session_handler::macro_step_t st;
                if (step_from_json(js, st)) cur.steps.push_back(st);
            }
        }
    }
    if (!session_handler::update_macro(cur))
    {
        diag::log_tagged_fmt("mcp_burp", "macro_update backend_failed id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("update failed");
    }
    diag::log_tagged_fmt("mcp_burp", "macro_update ok macro_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["macro"] = macro_to_json(cur);
    return tool_result_t::ok(out);
}

tool_result_t handle_rule_add(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "session_rule_add name=%s match=%s", params.value("name", std::string()).c_str(), params.value("match", std::string("url_regex")).c_str());
    session_handler::session_rule_t r;
    r.name = params.value("name", std::string());
    session_handler::sh_match_t m;
    if (!session_handler::parse_match(params.value("match", std::string("url_regex")), m))
    {
        diag::log_tagged_fmt("mcp_burp", "session_rule_add invalid_match match=%s", params.value("match", std::string()).c_str());
        return tool_result_t::error("invalid 'match'");
    }
    r.match = m;
    r.match_pattern = params.value("pattern", std::string());
    r.match_status = params.value("status", 0);
    r.macro_id = static_cast<uint64_t>(params.value("macro_id", 0));
    r.replace_in_url = params.value("replace_in_url", true);
    r.replace_in_headers = params.value("replace_in_headers", true);
    r.replace_in_body = params.value("replace_in_body", true);
    r.active = params.value("active", true);
    if (r.macro_id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "session_rule_add missing macro_id");
        return tool_result_t::error("macro_id is required");
    }
    const uint64_t id = session_handler::add_rule(r);
    diag::log_tagged_fmt("mcp_burp", "session_rule_add ok rule_id=%llu macro_id=%llu", static_cast<unsigned long long>(id), static_cast<unsigned long long>(r.macro_id));
    json out;
    out["rule_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t handle_rule_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "session_rule_list entry");
    auto rules = session_handler::list_rules();
    json arr = json::array();
    for (const auto& r : rules) {
        json j;
        j["id"]                 = r.id;
        j["name"]               = r.name;
        j["match"]              = session_handler::match_label(r.match);
        j["match_pattern"]      = r.match_pattern;
        j["match_status"]       = r.match_status;
        j["macro_id"]           = r.macro_id;
        j["replace_in_url"]     = r.replace_in_url;
        j["replace_in_headers"] = r.replace_in_headers;
        j["replace_in_body"]    = r.replace_in_body;
        j["active"]             = r.active;
        arr.push_back(j);
    }
    diag::log_tagged_fmt("mcp_burp", "session_rule_list ok count=%zu", rules.size());
    json out;
    out["count"] = arr.size();
    out["rules"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t handle_rule_remove(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("rule_id", 0));
    diag::log_tagged_fmt("mcp_burp", "session_rule_remove rule_id=%llu", static_cast<unsigned long long>(id));
    const bool removed = session_handler::remove_rule(id);
    diag::log_tagged_fmt("mcp_burp", "session_rule_remove ok rule_id=%llu removed=%d", static_cast<unsigned long long>(id), (int)removed);
    json out;
    out["removed"] = removed;
    return tool_result_t::ok(out);
}

}

void register_session_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_macro_add",
        "Create a Burp-style request macro. 'steps' is an array of {label, scheme, host, port, raw_request_b64, timeout_ms, extracts[{name, from, regex, group}]}. 'from' must be one of resp_body | resp_headers | resp_url.",
        {{"name", "string", "Macro name", false},
         {"steps", "array", "List of macro steps", true}},
        false, handle_macro_add
    });

    srv.register_tool({
        "burp_macro_run",
        "Run a macro now and return the extracted values map.",
        {{"macro_id", "number", "Macro id", true}},
        false, handle_macro_run
    });

    srv.register_tool({
        "burp_macro_list",
        "List all macros and their last-run state.",
        {},
        true, handle_macro_list
    });

    srv.register_tool({
        "burp_macro_remove",
        "Remove a macro by id.",
        {{"macro_id", "number", "Macro id", true}},
        false, handle_macro_remove
    });

    srv.register_tool({
        "burp_macro_update",
        "Update a macro by id (fields may overwrite 'name' and 'steps').",
        {{"macro_id", "number", "Macro id", true},
         {"fields", "object", "Partial fields", true}},
        false, handle_macro_update
    });

    srv.register_tool({
        "burp_session_rule_add",
        "Add a session-handler rule. When an exchange matches, the associated macro runs and the extracted values are substituted as {{name}} tokens in the outgoing request.",
        {{"name", "string", "Rule name", false},
         {"match", "string", "url_regex | response_status | response_regex", true},
         {"pattern", "string", "Regex (for url_regex/response_regex)", false},
         {"status", "number", "HTTP status (for response_status)", false},
         {"macro_id", "number", "Macro to run", true},
         {"replace_in_url", "boolean", "Substitute tokens in URL line (default true)", false},
         {"replace_in_headers", "boolean", "Substitute tokens in headers (default true)", false},
         {"replace_in_body", "boolean", "Substitute tokens in body (default true)", false},
         {"active", "boolean", "Active (default true)", false}},
        false, handle_rule_add
    });

    srv.register_tool({
        "burp_session_rule_list",
        "List all session rules.",
        {},
        true, handle_rule_list
    });

    srv.register_tool({
        "burp_session_rule_remove",
        "Remove a session rule by id.",
        {{"rule_id", "number", "Rule id", true}},
        false, handle_rule_remove
    });
}

}
}
