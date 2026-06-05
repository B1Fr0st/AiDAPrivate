#include "burp_tech_mcp.hpp"
#include "tech_fingerprint.hpp"
#include "audit_http.hpp"
#include "burp_events.hpp"
#include "../../infra/event_bus.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace tech {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

std::vector<uint8_t> build_get_request(const std::string& host, const std::string& path)
{
    std::string s;
    s += "GET "; s += path.empty() ? std::string("/") : path; s += " HTTP/1.1\r\n";
    s += "Host: "; s += host; s += "\r\n";
    s += "User-Agent: AiDA-Burp/1.0\r\n";
    s += "Accept: */*\r\n";
    s += "Connection: close\r\n\r\n";
    return std::vector<uint8_t>(s.begin(), s.end());
}

json tech_to_json(const tech_t& t)
{
    json j;
    j["name"]             = t.name;
    j["category"]         = t.category;
    j["version"]          = t.version;
    j["confidence_label"] = t.confidence_label;
    return j;
}

tool_result_t tool_fingerprint(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint entry");
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint missing_url");
        return tool_result_t::error("missing_url");
    }
    std::string url = params["url"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint url=%s", url.c_str());
    initialize();
    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint invalid_url url=%s", url.c_str());
        json data;
        data["error"] = "invalid_url";
        data["url"] = url;
        data["status"] = "parse_failed";
        return error_with_data("invalid_url", data);
    }
    bool tls = (scheme == "https");
    audit_http::send_options_t opt;
    opt.timeout_ms = 15000;
    opt.follow_redirects = true;
    opt.enforce_scope = false;
    auto req = build_get_request(host, path);
    auto resp = audit_http::send(req, host, port, tls, opt);
    if (!resp.has_value())
    {
        std::string err = audit_http::last_error();
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint send_failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["url"] = url;
        data["scheme"] = scheme;
        data["host"] = host;
        data["port"] = port;
        data["path"] = path;
        data["tls"] = tls;
        data["status"] = "send_failed";
        return error_with_data(std::string("send_failed: ") + err, data);
    }
    auto items = fingerprint(resp->resp_headers, resp->resp_body, url);
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint ok url=%s status=%d techs=%zu", url.c_str(), resp->status_code, items.size());
    exchange_observed_t ex;
    ex.id = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    ex.timestamp_ms = ex.id;
    ex.method = "GET";
    ex.scheme = scheme;
    ex.host = host;
    ex.port = port;
    ex.path = path.empty() ? std::string("/") : path;
    ex.req_headers = {{"Host", host}, {"User-Agent", "AiDA-Burp/1.0"}};
    ex.status_code = resp->status_code;
    ex.reason_phrase = "OK";
    ex.resp_headers = resp->resp_headers;
    ex.resp_body = resp->resp_body;
    ex.latency_ms = resp->latency_ms;
    aida::events::publish(kExchangeObservedEvent, ex);
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint published_exchange id=%llu host=%s path=%s headers=%zu body=%zu",
        static_cast<unsigned long long>(ex.id), ex.host.c_str(), ex.path.c_str(), ex.resp_headers.size(), ex.resp_body.size());
    json arr = json::array();
    for (const auto& t : items) arr.push_back(tech_to_json(t));
    json out;
    out["url"]          = url;
    out["status_code"]  = resp->status_code;
    out["technologies"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t tool_inventory(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "tech_inventory entry");
    auto items = inventory();
    json arr = json::array();
    for (const auto& h : items) {
        json techs = json::array();
        for (const auto& t : h.technologies) techs.push_back(tech_to_json(t));
        json h_obj;
        h_obj["host"]         = h.host;
        h_obj["technologies"] = techs;
        arr.push_back(h_obj);
    }
    diag::log_tagged_fmt("mcp_burp", "tech_inventory ok hosts=%zu", items.size());
    json out;
    out["host_count"] = arr.size();
    out["hosts"]      = arr;
    if (items.empty()) {
        out["status"] = "empty";
        out["error"] = "no_technology_fingerprints_recorded";
    }
    return tool_result_t::ok(out);
}

tool_result_t tool_clear(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "tech_clear entry");
    clear_inventory();
    diag::log_tagged_fmt("mcp_burp", "tech_clear ok");
    json j;
    j["ok"] = true;
    return tool_result_t::ok(j);
}

}

void register_tech_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_tech_fingerprint";
        t.description = "Fetch a URL and identify the underlying technology stack (web server, framework, CMS, "
                        "front-end library, CDN, analytics, auth) using header + body regex rules.";
        t.params = { {"url", "string", "Full URL", true} };
        t.read_only = true;
        t.handler = tool_fingerprint;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_tech_inventory";
        t.description = "Return the deduped inventory of technologies detected across every host observed during this session.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_inventory;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_tech_clear";
        t.description = "Clear the tech-fingerprint inventory.";
        t.params = {};
        t.read_only = false;
        t.handler = tool_clear;
        srv.register_tool(std::move(t));
    }
}

}
}
}
