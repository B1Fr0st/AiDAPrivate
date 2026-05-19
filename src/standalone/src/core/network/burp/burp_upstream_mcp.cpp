#include "burp_upstream_mcp.hpp"
#include "upstream_chain.hpp"

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
        if (!j.contains("port") || !j["port"].is_number_unsigned()) { err = "hop_missing_port"; return false; }
        uint32_t p = j["port"].get<uint32_t>();
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
    if (!params.is_object()) return tool_result_t::error("params_must_be_object");
    upstream_chain_t c;
    if (params.contains("label") && params["label"].is_string()) c.label = params["label"].get<std::string>();
    std::string err;
    if (!params.contains("hops") || !parse_hops(params["hops"], c.hops, err))
        return tool_result_t::error(err.empty() ? std::string("missing_hops") : err);
    uint64_t id = add_chain(c);
    json j;
    j["id"]    = id;
    j["label"] = c.label;
    j["hops_count"] = c.hops.size();
    return tool_result_t::ok(j);
}

tool_result_t tool_remove(const json& params)
{
    if (!params.is_object() || !params.contains("id") || !params["id"].is_number_unsigned())
        return tool_result_t::error("missing_id");
    uint64_t id = params["id"].get<uint64_t>();
    bool ok = remove_chain(id);
    json j;
    j["id"] = id;
    j["removed"] = ok;
    return tool_result_t::ok(j);
}

tool_result_t tool_list(const json& params)
{
    (void)params;
    auto chains = list_chains();
    json arr = json::array();
    for (const auto& c : chains) arr.push_back(chain_json(c));
    json out;
    out["chains"]    = arr;
    out["active_id"] = get_active_chain_id();
    return tool_result_t::ok(out);
}

tool_result_t tool_set_active(const json& params)
{
    if (!params.is_object() || !params.contains("id") || !params["id"].is_number_unsigned())
        return tool_result_t::error("missing_id");
    uint64_t id = params["id"].get<uint64_t>();
    bool ok = set_active_chain(id);
    json j;
    j["active_id"] = id;
    j["ok"]        = ok;
    return ok ? tool_result_t::ok(j) : tool_result_t::error(last_error().empty() ? std::string("set_active_failed") : last_error());
}

tool_result_t tool_get_active(const json& params)
{
    (void)params;
    json j;
    j["active_id"] = get_active_chain_id();
    return tool_result_t::ok(j);
}

tool_result_t tool_test(const json& params)
{
    if (!params.is_object() ||
        !params.contains("id") || !params["id"].is_number_unsigned() ||
        !params.contains("target_host") || !params["target_host"].is_string() ||
        !params.contains("target_port") || !params["target_port"].is_number_unsigned()) {
        return tool_result_t::error("missing_id_target_host_or_target_port");
    }
    uint64_t id = params["id"].get<uint64_t>();
    std::string host = params["target_host"].get<std::string>();
    uint32_t port = params["target_port"].get<uint32_t>();
    if (port == 0 || port > 65535) return tool_result_t::error("bad_port");
    std::string err;
    bool ok = test_chain(id, host, static_cast<uint16_t>(port), err);
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
