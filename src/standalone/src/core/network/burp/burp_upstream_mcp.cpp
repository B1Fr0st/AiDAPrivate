#include "burp_upstream_mcp.hpp"
#include "upstream_chain.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace upstream {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

json hop_json(const upstream_hop_t& h)
{
    json j;
    j["type"]     = h.type;
    j["host"]     = h.host;
    j["port"]     = h.port;
    j["username"] = h.username;
    return j;
}

json chain_json(const upstream_chain_t& c)
{
    json j;
    j["id"]     = c.id;
    j["label"]  = c.label;
    j["active"] = c.active;
    json arr = json::array();
    for (const auto& h : c.hops) arr.push_back(hop_json(h));
    j["hops"]   = arr;
    return j;
}

bool json_u64(const json& j, uint64_t& out)
{
    if (j.is_number_unsigned())
    {
        out = j.get<uint64_t>();
        return true;
    }
    if (j.is_number_integer())
    {
        int64_t v = j.get<int64_t>();
        if (v >= 0)
        {
            out = static_cast<uint64_t>(v);
            return true;
        }
    }
    return false;
}

bool json_u32(const json& j, uint32_t& out)
{
    uint64_t v = 0;
    if (!json_u64(j, v) || v > 0xFFFFFFFFull)
        return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool parse_hops(const json& src, std::vector<upstream_hop_t>& out, std::string& err)
{
    if (!src.is_array()) { err = "hops_not_array"; return false; }
    for (const auto& j : src) {
        if (!j.is_object()) { err = "hop_not_object"; return false; }
        upstream_hop_t h;
        if (!j.contains("type") || !j["type"].is_string()) { err = "hop_missing_type"; return false; }
        h.type = j["type"].get<std::string>();
        if (h.type != "http_connect" && h.type != "socks5") { err = "hop_unsupported_type"; return false; }
        if (!j.contains("host") || !j["host"].is_string()) { err = "hop_missing_host"; return false; }
        h.host = j["host"].get<std::string>();
        uint32_t p = 0;
        if (!j.contains("port") || !json_u32(j["port"], p)) { err = "hop_missing_port"; return false; }
        if (p == 0 || p > 65535) { err = "hop_bad_port"; return false; }
        h.port = static_cast<uint16_t>(p);
        if (j.contains("username") && j["username"].is_string()) h.username = j["username"].get<std::string>();
        if (j.contains("password") && j["password"].is_string()) h.password = j["password"].get<std::string>();
        out.push_back(h);
    }
    return !out.empty();
}

tool_result_t tool_add(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "upstream_add entry");
    if (!params.is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_add invalid_params");
        return tool_result_t::error("params_must_be_object");
    }
    upstream_chain_t c;
    if (params.contains("label") && params["label"].is_string()) c.label = params["label"].get<std::string>();
    std::string err;
    if (!params.contains("hops") || !parse_hops(params["hops"], c.hops, err))
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_add parse_hops_failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("missing_hops") : err);
    }
    uint64_t id = add_chain(c);
    diag::log_tagged_fmt("mcp_burp", "upstream_add ok id=%llu label=%s hops=%zu", static_cast<unsigned long long>(id), c.label.c_str(), c.hops.size());
    json j;
    j["id"]    = id;
    j["label"] = c.label;
    j["hops_count"] = c.hops.size();
    return tool_result_t::ok(j);
}

tool_result_t tool_remove(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "upstream_remove entry");
    uint64_t id = 0;
    if (!params.is_object() || !params.contains("id") || !json_u64(params["id"], id))
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_remove missing_id");
        return tool_result_t::error("missing_id");
    }
    diag::log_tagged_fmt("mcp_burp", "upstream_remove id=%llu", static_cast<unsigned long long>(id));
    bool ok = remove_chain(id);
    diag::log_tagged_fmt("mcp_burp", "upstream_remove ok id=%llu removed=%d", static_cast<unsigned long long>(id), (int)ok);
    json j;
    j["id"] = id;
    j["removed"] = ok;
    return tool_result_t::ok(j);
}

tool_result_t tool_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "upstream_list entry");
    auto chains = list_chains();
    json arr = json::array();
    for (const auto& c : chains) arr.push_back(chain_json(c));
    const uint64_t active = get_active_chain_id();
    diag::log_tagged_fmt("mcp_burp", "upstream_list ok count=%zu active_id=%llu", chains.size(), static_cast<unsigned long long>(active));
    json out;
    out["chains"]    = arr;
    out["active_id"] = active;
    return tool_result_t::ok(out);
}

tool_result_t tool_set_active(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "upstream_set_active entry");
    uint64_t id = 0;
    if (!params.is_object() || !params.contains("id") || !json_u64(params["id"], id))
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_set_active missing_id");
        return tool_result_t::error("missing_id");
    }
    diag::log_tagged_fmt("mcp_burp", "upstream_set_active id=%llu", static_cast<unsigned long long>(id));
    bool ok = set_active_chain(id);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_set_active failed id=%llu err=%s", static_cast<unsigned long long>(id), last_error().c_str());
        return tool_result_t::error(last_error().empty() ? std::string("set_active_failed") : last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "upstream_set_active ok active_id=%llu", static_cast<unsigned long long>(id));
    json j;
    j["active_id"] = id;
    j["ok"]        = ok;
    return tool_result_t::ok(j);
}

tool_result_t tool_get_active(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "upstream_get_active entry");
    const uint64_t active = get_active_chain_id();
    diag::log_tagged_fmt("mcp_burp", "upstream_get_active ok active_id=%llu", static_cast<unsigned long long>(active));
    json j;
    j["active_id"] = active;
    return tool_result_t::ok(j);
}

tool_result_t tool_test(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "upstream_test entry");
    uint64_t id = 0;
    uint32_t port = 0;
    if (!params.is_object() ||
        !params.contains("id") || !json_u64(params["id"], id) ||
        !params.contains("target_host") || !params["target_host"].is_string() ||
        !params.contains("target_port") || !json_u32(params["target_port"], port))
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_test missing_params");
        return tool_result_t::error("missing_id_target_host_or_target_port");
    }
    std::string host = params["target_host"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "upstream_test id=%llu host=%s port=%u", static_cast<unsigned long long>(id), host.c_str(), port);
    if (port == 0 || port > 65535)
    {
        diag::log_tagged_fmt("mcp_burp", "upstream_test bad_port port=%u", port);
        return tool_result_t::error("bad_port");
    }
    std::string err;
    bool ok = test_chain(id, host, static_cast<uint16_t>(port), err);
    diag::log_tagged_fmt("mcp_burp", "upstream_test ok id=%llu success=%d err=%s", static_cast<unsigned long long>(id), (int)ok, err.c_str());
    json j;
    j["ok"]    = ok;
    j["error"] = err;
    j["id"]    = id;
    j["target_host"] = host;
    j["target_port"] = port;
    return tool_result_t::ok(j);
}

}

void register_upstream_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_upstream_add_chain";
        t.description = "Create a new upstream proxy chain with one or more hops. Each hop has type "
                        "('http_connect' or 'socks5'), host, port, and optional username/password.";
        t.params = {
            {"label", "string", "Friendly label for the chain", false},
            {"hops",  "array",  "Array of {type, host, port, username, password}", true},
        };
        t.read_only = false;
        t.handler = tool_add;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_upstream_remove_chain";
        t.description = "Remove a saved upstream chain by id.";
        t.params = { {"id", "number", "Chain id", true} };
        t.read_only = false;
        t.handler = tool_remove;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_upstream_list_chains";
        t.description = "List every saved upstream chain plus the currently-active chain id.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_list;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_upstream_set_active";
        t.description = "Set the currently-active upstream chain. Pass id=0 to deactivate.";
        t.params = { {"id", "number", "Chain id (0 = none)", true} };
        t.read_only = false;
        t.handler = tool_set_active;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_upstream_get_active";
        t.description = "Return the currently-active upstream chain id.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_get_active;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_upstream_test_chain";
        t.description = "Walk the chain end-to-end to (target_host:target_port). Returns ok=true/false + error.";
        t.params = {
            {"id",          "number", "Chain id",    true},
            {"target_host", "string", "Target host", true},
            {"target_port", "number", "Target port", true},
        };
        t.read_only = true;
        t.handler = tool_test;
        srv.register_tool(std::move(t));
    }
}

}
}
}
