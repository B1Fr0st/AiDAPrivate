#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_mr_mcp.hpp"
#include "match_replace.hpp"
#include "auth_lab.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

json rule_to_json(const match_replace::rule_t& r)
{
    json j;
    j["id"]              = r.id;
    j["label"]           = r.label;
    j["target"]          = match_replace::target_label(r.target);
    j["match_regex"]     = r.match_regex;
    j["replacement"]     = r.replacement;
    j["regex"]           = r.regex;
    j["case_insensitive"]= r.case_insensitive;
    j["active"]          = r.active;
    j["host_filter"]     = r.host_filter;
    j["scheme_filter"]   = r.scheme_filter;
    j["hit_count"]       = r.hit_count;
    return j;
}

tool_result_t handle_add(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_add target=%s label=%s", params.value("target", std::string("request_url")).c_str(), params.value("label", std::string()).c_str());
    match_replace::rule_t r;
    r.label = params.value("label", std::string());
    {
        match_replace::match_kind_t target;
        if (!match_replace::parse_target(params.value("target", std::string("request_url")), target))
            return tool_result_t::error("invalid 'target'");
        r.target = target;
    }
    r.match_regex = params.value("match_regex", std::string());
    r.replacement = params.value("replacement", std::string());
    r.regex = params.value("regex", true);
    r.case_insensitive = params.value("case_insensitive", false);
    r.active = params.value("active", true);
    r.host_filter = params.value("host_filter", std::string());
    r.scheme_filter = params.value("scheme_filter", std::string());
    const uint64_t id = match_replace::add(r);
    diag::log_tagged_fmt("mcp_burp", "match_replace_add ok rule_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["rule_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t handle_update(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_update entry");
    if (!params.contains("rule_id"))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_update missing rule_id");
        return tool_result_t::error("missing 'rule_id'");
    }
    const uint64_t id = static_cast<uint64_t>(params["rule_id"].get<uint64_t>());
    diag::log_tagged_fmt("mcp_burp", "match_replace_update rule_id=%llu", static_cast<unsigned long long>(id));
    auto rules = match_replace::list();
    match_replace::rule_t r;
    bool found = false;
    for (const auto& cur : rules) { if (cur.id == id) { r = cur; found = true; break; } }
    if (!found)
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_update rule_not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("rule not found");
    }
    if (params.contains("fields") && params["fields"].is_object()) {
        const auto& f = params["fields"];
        if (f.contains("label")) r.label = f.value("label", r.label);
        if (f.contains("target")) {
            match_replace::match_kind_t t;
            if (match_replace::parse_target(f["target"].get<std::string>(), t)) r.target = t;
        }
        if (f.contains("match_regex")) r.match_regex = f.value("match_regex", r.match_regex);
        if (f.contains("replacement")) r.replacement = f.value("replacement", r.replacement);
        if (f.contains("regex")) r.regex = f.value("regex", r.regex);
        if (f.contains("case_insensitive")) r.case_insensitive = f.value("case_insensitive", r.case_insensitive);
        if (f.contains("active")) r.active = f.value("active", r.active);
        if (f.contains("host_filter")) r.host_filter = f.value("host_filter", r.host_filter);
        if (f.contains("scheme_filter")) r.scheme_filter = f.value("scheme_filter", r.scheme_filter);
    }
    if (!match_replace::update(r))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_update backend_failed id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("update failed");
    }
    diag::log_tagged_fmt("mcp_burp", "match_replace_update ok id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["rule"] = rule_to_json(r);
    return tool_result_t::ok(out);
}

tool_result_t handle_remove(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_remove entry");
    if (!params.contains("rule_id"))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_remove missing rule_id");
        return tool_result_t::error("missing 'rule_id'");
    }
    const uint64_t id = static_cast<uint64_t>(params["rule_id"].get<uint64_t>());
    diag::log_tagged_fmt("mcp_burp", "match_replace_remove rule_id=%llu", static_cast<unsigned long long>(id));
    const bool ok = match_replace::remove(id);
    diag::log_tagged_fmt("mcp_burp", "match_replace_remove ok id=%llu removed=%d", static_cast<unsigned long long>(id), (int)ok);
    json out;
    out["removed"] = ok;
    return tool_result_t::ok(out);
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_list entry");
    auto rules = match_replace::list();
    json arr = json::array();
    for (const auto& r : rules) arr.push_back(rule_to_json(r));
    diag::log_tagged_fmt("mcp_burp", "match_replace_list ok count=%zu", rules.size());
    json out;
    out["count"] = arr.size();
    out["rules"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t handle_clear(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_clear entry");
    match_replace::clear();
    diag::log_tagged_fmt("mcp_burp", "match_replace_clear ok");
    json out;
    out["cleared"] = true;
    return tool_result_t::ok(out);
}

tool_result_t handle_test(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "match_replace_test entry");
    if (!params.contains("target"))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test missing target");
        return tool_result_t::error("missing 'target'");
    }
    if (!params.contains("sample_b64"))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test missing sample_b64");
        return tool_result_t::error("missing 'sample_b64'");
    }
    if (!params.contains("rule_id"))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test missing rule_id");
        return tool_result_t::error("missing 'rule_id'");
    }
    std::string sample;
    if (!auth_lab::base64_decode_std(params["sample_b64"].get<std::string>(), sample))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test invalid_base64");
        return tool_result_t::error("sample_b64 not valid base64");
    }
    const uint64_t id = static_cast<uint64_t>(params["rule_id"].get<uint64_t>());
    diag::log_tagged_fmt("mcp_burp", "match_replace_test rule_id=%llu target=%s", static_cast<unsigned long long>(id), params.value("target", std::string()).c_str());
    auto rules = match_replace::list();
    match_replace::rule_t r;
    bool found = false;
    for (const auto& cur : rules) { if (cur.id == id) { r = cur; found = true; break; } }
    if (!found)
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test rule_not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("rule not found");
    }
    std::string mod;
    if (!match_replace::test_rule(r, sample, mod))
    {
        diag::log_tagged_fmt("mcp_burp", "match_replace_test test_rule_failed err=%s", match_replace::last_error().c_str());
        return tool_result_t::error(std::string("test_rule failed: ") + match_replace::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "match_replace_test ok id=%llu mod_len=%zu", static_cast<unsigned long long>(id), mod.size());
    json out;
    out["modified"] = mod;
    out["modified_b64"] = auth_lab::base64_encode_std(
        reinterpret_cast<const uint8_t*>(mod.data()), mod.size());
    return tool_result_t::ok(out);
}

}

void register_match_replace_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_match_replace_add",
        "Add a match-and-replace rule applied to in-flight proxy exchanges. Target: request_url|request_headers|request_body|response_headers|response_body|all.",
        {{"label", "string", "Rule label", false},
         {"target", "string", "Match target", true},
         {"match_regex", "string", "Regex or literal", true},
         {"replacement", "string", "Replacement", false},
         {"regex", "boolean", "Treat match as regex (default true)", false},
         {"case_insensitive", "boolean", "Case insensitive (default false)", false},
         {"host_filter", "string", "Optional host regex", false},
         {"scheme_filter", "string", "Optional 'http' / 'https'", false}},
        false, handle_add
    });

    srv.register_tool({
        "burp_match_replace_update",
        "Update an existing match-replace rule by id. 'fields' is a partial object of fields to overwrite.",
        {{"rule_id", "number", "Rule id", true},
         {"fields", "object", "Partial fields to update", true}},
        false, handle_update
    });

    srv.register_tool({
        "burp_match_replace_remove",
        "Remove a match-replace rule by id.",
        {{"rule_id", "number", "Rule id", true}},
        false, handle_remove
    });

    srv.register_tool({
        "burp_match_replace_list",
        "List all match-replace rules.",
        {},
        true, handle_list
    });

    srv.register_tool({
        "burp_match_replace_clear",
        "Remove all match-replace rules.",
        {},
        false, handle_clear
    });

    srv.register_tool({
        "burp_match_replace_test",
        "Apply a rule to a base64-encoded sample and return the modified text.",
        {{"target", "string", "Match target (kept for parity)", true},
         {"sample_b64", "string", "Base64 sample", true},
         {"rule_id", "number", "Rule id to test", true}},
        true, handle_test
    });
}

}
}
