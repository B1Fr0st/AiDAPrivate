#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_target_mcp.hpp"
#include "burp_events.hpp"
#include "site_map.hpp"
#include "scope.hpp"
#include "cookie_jar.hpp"

#include "../../settings/standalone_compat.hpp"

#ifdef small
#undef small
#endif

#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace target {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

std::string trim_lower(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    for (size_t i = b; i < e; ++i) {
        const char c = s[i];
        r.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
    }
    return r;
}

tool_result_t sitemap_list_hosts(const json& args)
{
    const bool scope_only = args.value("scope_only", false);
    const auto hosts = sitemap::list_hosts(scope_only);
    json arr = json::array();
    for (const auto& h : hosts) {
        json j;
        j["host"]           = h.host;
        j["port"]           = h.port;
        j["tls"]            = h.tls;
        j["in_scope"]       = h.in_scope;
        j["total_requests"] = h.total_requests;
        j["issue_count"]    = h.issue_count;
        arr.push_back(j);
    }
    json r;
    r["hosts"] = arr;
    r["count"] = hosts.size();
    return tool_result_t::ok(std::to_string(hosts.size()) + " hosts in site map", r);
}

tool_result_t sitemap_list_paths(const json& args)
{
    if (!args.contains("host") || !args["host"].is_string()) {
        return tool_result_t::error("Missing 'host' parameter");
    }
    const std::string host = args["host"].get<std::string>();
    const int port = args.value("port", 0);
    const auto paths = sitemap::list_paths(host, static_cast<uint16_t>(port));
    json arr = json::array();
    for (const auto& p : paths) arr.push_back(p);
    json r;
    r["host"]  = host;
    r["port"]  = port;
    r["paths"] = arr;
    r["count"] = paths.size();
    return tool_result_t::ok(std::to_string(paths.size()) + " paths for " + host, r);
}

tool_result_t sitemap_get_exchange(const json& args)
{
    if (!args.contains("exchange_id") || !args["exchange_id"].is_number_unsigned()) {
        return tool_result_t::error("Missing or invalid 'exchange_id' parameter");
    }
    const uint64_t id = args["exchange_id"].get<uint64_t>();
    exchange_observed_t e;
    if (!sitemap::find_exchange(id, e)) {
        return tool_result_t::error("Exchange id not found");
    }
    const bool include_bodies = args.value("include_bodies", true);
    json j = sitemap::exchange_to_json(e, include_bodies);
    return tool_result_t::ok("Exchange " + std::to_string(id), j);
}

tool_result_t sitemap_send_to(const json& args)
{
    if (!args.contains("exchange_id") || !args["exchange_id"].is_number_unsigned()) {
        return tool_result_t::error("Missing or invalid 'exchange_id' parameter");
    }
    if (!args.contains("target") || !args["target"].is_string()) {
        return tool_result_t::error("Missing 'target' parameter");
    }
    const std::string tgt = trim_lower(args["target"].get<std::string>());
    static const char* allowed[] = {"repeater", "intruder", "comparer", "scanner", "decoder"};
    bool ok = false;
    for (const char* a : allowed) { if (tgt == a) { ok = true; break; } }
    if (!ok) {
        return tool_result_t::error("Invalid 'target'. Allowed: repeater|intruder|comparer|scanner|decoder");
    }
    const uint64_t id = args["exchange_id"].get<uint64_t>();
    exchange_observed_t e;
    if (!sitemap::find_exchange(id, e)) {
        return tool_result_t::error("Exchange id not found");
    }
    sitemap::send_to(id, tgt, "mcp");
    json r;
    r["exchange_id"] = id;
    r["target"]      = tgt;
    return tool_result_t::ok("Dispatched exchange " + std::to_string(id) + " to " + tgt, r);
}

tool_result_t scope_add(const json& args)
{
    scope::rule_t r;
    if (!scope::rule_from_json(args, r)) {
        return tool_result_t::error("Invalid rule payload");
    }
    if (r.host_pattern.empty()) {
        return tool_result_t::error("'host_pattern' required");
    }
    const uint64_t id = scope::add_rule(r);
    json out;
    out["rule_id"] = id;
    return tool_result_t::ok("Scope rule added id=" + std::to_string(id), out);
}

tool_result_t scope_remove(const json& args)
{
    if (!args.contains("rule_id") || !args["rule_id"].is_number_unsigned()) {
        return tool_result_t::error("Missing 'rule_id'");
    }
    const uint64_t id = args["rule_id"].get<uint64_t>();
    if (!scope::remove_rule(id)) {
        return tool_result_t::error("rule_id not found");
    }
    return tool_result_t::ok("Scope rule " + std::to_string(id) + " removed");
}

tool_result_t scope_list(const json&)
{
    const auto rules = scope::list_rules();
    json arr = json::array();
    for (const auto& r : rules) arr.push_back(scope::rule_to_json(r));
    json out;
    out["rules"] = arr;
    out["count"] = rules.size();
    return tool_result_t::ok(std::to_string(rules.size()) + " scope rules", out);
}

tool_result_t scope_check(const json& args)
{
    if (!args.contains("url") || !args["url"].is_string()) {
        return tool_result_t::error("Missing 'url'");
    }
    const std::string url = args["url"].get<std::string>();
    const bool ok = scope::in_scope(url);
    json out;
    out["url"]      = url;
    out["in_scope"] = ok;
    return tool_result_t::ok(ok ? "in scope" : "out of scope", out);
}

tool_result_t cookie_list(const json& args)
{
    std::vector<cookie_jar::parsed_cookie_t> cookies;
    if (args.contains("host") && args["host"].is_string()) {
        cookies = cookie_jar::list_for_host(args["host"].get<std::string>());
    } else {
        cookies = cookie_jar::list_all();
    }
    json arr = json::array();
    for (const auto& c : cookies) {
        json j;
        j["name"]            = c.name;
        j["value"]           = c.value;
        j["domain"]          = c.domain;
        j["path"]            = c.path;
        j["expires_unix_ms"] = c.expires_unix_ms;
        j["has_expires"]     = c.has_expires;
        j["secure"]          = c.secure;
        j["http_only"]       = c.http_only;
        j["host_only"]       = c.host_only;
        j["same_site"]       = cookie_jar::same_site_str(c.same_site);
        arr.push_back(j);
    }
    json out;
    out["cookies"] = arr;
    out["count"]   = cookies.size();
    return tool_result_t::ok(std::to_string(cookies.size()) + " cookies", out);
}

tool_result_t cookie_set(const json& args)
{
    if (!args.contains("host") || !args["host"].is_string()) {
        return tool_result_t::error("Missing 'host'");
    }
    if (!args.contains("name") || !args["name"].is_string()) {
        return tool_result_t::error("Missing 'name'");
    }
    const std::string host = args["host"].get<std::string>();
    cookie_jar::parsed_cookie_t c;
    c.name     = args["name"].get<std::string>();
    c.value    = args.value("value", std::string());
    c.domain   = args.value("domain", host);
    c.path     = args.value("path", std::string("/"));
    c.secure   = args.value("secure", false);
    c.http_only = args.value("http_only", false);
    if (args.contains("same_site") && args["same_site"].is_string()) {
        c.same_site = cookie_jar::parse_same_site(args["same_site"].get<std::string>());
    }
    if (args.contains("expires_unix_ms") && args["expires_unix_ms"].is_number_integer()) {
        c.has_expires = true;
        c.expires_unix_ms = args["expires_unix_ms"].get<int64_t>();
    }
    cookie_jar::set_cookie(host, c);
    json out;
    out["host"] = host;
    out["name"] = c.name;
    return tool_result_t::ok("Cookie set", out);
}

tool_result_t cookie_delete(const json& args)
{
    if (!args.contains("host") || !args["host"].is_string()) {
        return tool_result_t::error("Missing 'host'");
    }
    if (!args.contains("name") || !args["name"].is_string()) {
        return tool_result_t::error("Missing 'name'");
    }
    const std::string host = args["host"].get<std::string>();
    const std::string name = args["name"].get<std::string>();
    const std::string path = args.value("path", std::string());
    if (!cookie_jar::delete_cookie(host, name, path)) {
        return tool_result_t::error("Cookie not found");
    }
    return tool_result_t::ok("Cookie deleted");
}

tool_result_t cookie_export_netscape(const json& args)
{
    if (!args.contains("file_path") || !args["file_path"].is_string()) {
        return tool_result_t::error("Missing 'file_path'");
    }
    const std::string path = args["file_path"].get<std::string>();
    if (!cookie_jar::export_netscape(path)) {
        return tool_result_t::error("Export failed: " + cookie_jar::last_error());
    }
    json out;
    out["file_path"] = path;
    return tool_result_t::ok("Cookies exported to " + path, out);
}

}

void register_target_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_sitemap_list_hosts", "burp",
        "List all hosts observed in the Burp site map. Returns host, port, scheme (TLS), scope state, total_requests and issue_count.",
        {
            {"scope_only", "boolean", "If true, only return hosts that pass the active scope rules.", false}
        },
        sitemap_list_hosts, true});

    register_compat(srv, {
        "burp_sitemap_list_paths", "burp",
        "Enumerate all observed URL paths for a host:port pair.",
        {
            {"host", "string", "Hostname (case-sensitive)", true},
            {"port", "number", "Port number", false}
        },
        sitemap_list_paths, true});

    register_compat(srv, {
        "burp_sitemap_get_exchange", "burp",
        "Fetch a captured HTTP/WebSocket exchange by id. Returns full request and response headers and base64-encoded bodies.",
        {
            {"exchange_id",     "number",  "Numeric exchange id returned by other burp tools",                      true},
            {"include_bodies",  "boolean", "Include request and response body bytes encoded as base64 (default true)", false}
        },
        sitemap_get_exchange, true});

    register_compat(srv, {
        "burp_sitemap_send_to", "burp",
        "Dispatch an exchange to another Burp tool (repeater, intruder, comparer, scanner, decoder). Publishes a burp.send_to_action event the subsystem subscribes to.",
        {
            {"exchange_id", "number", "Exchange id to dispatch", true},
            {"target",      "string", "One of: repeater, intruder, comparer, scanner, decoder", true}
        },
        sitemap_send_to, false});

    register_compat(srv, {
        "burp_scope_add", "burp",
        "Add a scope rule. Body is the rule object with kind ('include'|'exclude'), protocol, host_pattern (literal/regex/suffix), port (0=any), path_prefix, enabled.",
        {
            {"kind",         "string", "'include' or 'exclude'",      false},
            {"protocol",     "string", "https/http/*",                false},
            {"host_pattern", "string", ".example.com or regex",       true},
            {"port",         "number", "0=any",                       false},
            {"path_prefix",  "string", "/api/",                       false},
            {"enabled",      "boolean","Initial enabled state",       false}
        },
        scope_add, false});

    register_compat(srv, {
        "burp_scope_remove", "burp",
        "Remove a scope rule by numeric id.",
        {
            {"rule_id", "number", "Rule id returned by burp_scope_add or burp_scope_list", true}
        },
        scope_remove, false});

    register_compat(srv, {
        "burp_scope_list", "burp",
        "List all configured scope rules.",
        {},
        scope_list, true});

    register_compat(srv, {
        "burp_scope_check", "burp",
        "Test whether a URL is currently in scope.",
        {
            {"url", "string", "Absolute URL to test, e.g. https://example.com/api/v1", true}
        },
        scope_check, true});

    register_compat(srv, {
        "burp_cookie_list", "burp",
        "List cookies in the cookie jar. If 'host' is omitted, lists all cookies across all hosts.",
        {
            {"host", "string", "Filter to one host (optional)", false}
        },
        cookie_list, true});

    register_compat(srv, {
        "burp_cookie_set", "burp",
        "Set or update a cookie in the jar.",
        {
            {"host",            "string", "Host this cookie belongs to",                       true},
            {"name",            "string", "Cookie name",                                       true},
            {"value",           "string", "Cookie value",                                      false},
            {"domain",          "string", "Domain attribute (default = host)",                 false},
            {"path",            "string", "Path attribute (default /)",                        false},
            {"secure",          "boolean","Secure flag",                                       false},
            {"http_only",       "boolean","HttpOnly flag",                                     false},
            {"same_site",       "string", "Lax|Strict|None|Unset",                             false},
            {"expires_unix_ms", "number", "Unix epoch milliseconds (omit for session cookie)", false}
        },
        cookie_set, false});

    register_compat(srv, {
        "burp_cookie_delete", "burp",
        "Delete a cookie by host and name (and optionally path).",
        {
            {"host", "string", "Host",       true},
            {"name", "string", "Cookie name",true},
            {"path", "string", "Match path", false}
        },
        cookie_delete, false});

    register_compat(srv, {
        "burp_cookie_export_netscape", "burp",
        "Export the cookie jar as a Netscape-format cookies.txt file (curl-compatible).",
        {
            {"file_path", "string", "Absolute path to the output cookies.txt file", true}
        },
        cookie_export_netscape, false});

    diag::log_tagged("burp", "target_mcp_tools_registered");
}

}
}
}
