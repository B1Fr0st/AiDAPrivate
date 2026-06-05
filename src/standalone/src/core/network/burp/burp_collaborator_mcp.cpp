#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_collaborator_mcp.hpp"
#include "collaborator.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace collaborator_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

json interaction_to_json(const aida::burp::collaborator::interaction_t& it)
{
    json out;
    out["id"] = static_cast<uint64_t>(it.id);
    out["timestamp_ms"] = static_cast<uint64_t>(it.timestamp_ms);
    out["kind"] = it.kind;
    out["client_ip"] = it.client_ip;
    out["client_port"] = static_cast<uint32_t>(it.client_port);
    out["subdomain"] = it.subdomain;
    out["payload_token"] = it.payload_token;
    out["raw"] = it.raw;
    json details = json::object();
    for (const auto& kv : it.details) details[kv.first] = kv.second;
    out["details"] = std::move(details);
    return out;
}

json status_to_json(const aida::burp::collaborator::status_t& s)
{
    json out;
    out["running"] = s.running;
    out["http_alive"] = s.http_alive;
    out["dns_alive"]  = s.dns_alive;
    out["smtp_alive"] = s.smtp_alive;
    out["bind_ip"]    = s.bind_ip;
    out["http_port"]  = static_cast<uint32_t>(s.http_port);
    out["dns_port"]   = static_cast<uint32_t>(s.dns_port);
    out["smtp_port"]  = static_cast<uint32_t>(s.smtp_port);
    out["public_host"] = s.public_host;
    out["public_ip"]   = s.public_ip;
    out["interaction_count"] = static_cast<uint64_t>(s.interaction_count);
    out["token_count"] = static_cast<uint64_t>(s.token_count);
    out["started_ms"]  = static_cast<uint64_t>(s.started_ms);
    return out;
}

tool_result_t handle_status(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_status entry");
    auto s = aida::burp::collaborator::status();
    diag::log_tagged_fmt("mcp_burp", "collaborator_status ok running=%d interactions=%llu", (int)s.running, static_cast<unsigned long long>(s.interaction_count));
    return tool_result_t::ok("collaborator status running=" + std::to_string(s.running ? 1 : 0) + " interactions=" + std::to_string(s.interaction_count) + " tokens=" + std::to_string(s.token_count), status_to_json(s));
}

tool_result_t handle_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_start entry");
    aida::burp::collaborator::collaborator_config_t cfg;
    if (p.contains("bind_ip") && p["bind_ip"].is_string()) cfg.bind_ip = p["bind_ip"].get<std::string>();
    if (p.contains("http_port") && p["http_port"].is_number()) cfg.http_port = static_cast<uint16_t>(p["http_port"].get<int>());
    if (p.contains("dns_port")  && p["dns_port"].is_number())  cfg.dns_port  = static_cast<uint16_t>(p["dns_port"].get<int>());
    if (p.contains("smtp_port") && p["smtp_port"].is_number()) cfg.smtp_port = static_cast<uint16_t>(p["smtp_port"].get<int>());
    if (p.contains("public_host") && p["public_host"].is_string()) cfg.public_host = p["public_host"].get<std::string>();
    if (p.contains("public_ip")   && p["public_ip"].is_string())   cfg.public_ip   = p["public_ip"].get<std::string>();
    if (p.contains("enable_http") && p["enable_http"].is_boolean()) cfg.enable_http = p["enable_http"].get<bool>();
    if (p.contains("enable_dns")  && p["enable_dns"].is_boolean())  cfg.enable_dns  = p["enable_dns"].get<bool>();
    if (p.contains("enable_smtp") && p["enable_smtp"].is_boolean()) cfg.enable_smtp = p["enable_smtp"].get<bool>();
    if (p.contains("canned_body") && p["canned_body"].is_string()) cfg.canned_body = p["canned_body"].get<std::string>();
    if (p.contains("canned_content_type") && p["canned_content_type"].is_string()) cfg.canned_content_type = p["canned_content_type"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "collaborator_start public_host=%s http=%d dns=%d smtp=%d", cfg.public_host.c_str(), (int)cfg.enable_http, (int)cfg.enable_dns, (int)cfg.enable_smtp);

    bool ok = aida::burp::collaborator::start(cfg);
    if (!ok)
    {
        std::string err = aida::burp::collaborator::last_error();
        diag::log_tagged_fmt("mcp_burp", "collaborator_start failed err=%s", err.c_str());
        json data = status_to_json(aida::burp::collaborator::status());
        data["error"] = err;
        data["requested_enable_http"] = cfg.enable_http;
        data["requested_enable_dns"] = cfg.enable_dns;
        data["requested_enable_smtp"] = cfg.enable_smtp;
        data["requested_http_port"] = cfg.http_port;
        data["requested_dns_port"] = cfg.dns_port;
        data["requested_smtp_port"] = cfg.smtp_port;
        data["status"] = "start_failed";
        return error_with_data("collaborator start failed: " + err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_start ok");
    auto s = aida::burp::collaborator::status();
    return tool_result_t::ok("collaborator started http_port=" + std::to_string(s.http_port), status_to_json(s));
}

tool_result_t handle_stop(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_stop entry");
    aida::burp::collaborator::stop();
    diag::log_tagged_fmt("mcp_burp", "collaborator_stop ok");
    auto s = aida::burp::collaborator::status();
    return tool_result_t::ok("collaborator stopped running=" + std::to_string(s.running ? 1 : 0), status_to_json(s));
}

tool_result_t handle_generate_token(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token entry");
    if (!aida::burp::collaborator::is_running())
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token not_running");
        return tool_result_t::error("collaborator not running");
    }
    auto cfg = aida::burp::collaborator::current_config();
    std::string tok = aida::burp::collaborator::generate_token();
    diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token ok token=%s host=%s", tok.c_str(), cfg.public_host.c_str());
    json out;
    out["token"] = tok;
    out["full_domain"] = tok + "." + cfg.public_host;
    out["public_host"] = cfg.public_host;
    return tool_result_t::ok("token generated len=" + std::to_string(tok.size()), out);
}

tool_result_t handle_poll(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_poll entry");
    json out = json::array();
    size_t count = 0;
    if (p.contains("token") && p["token"].is_string() && !p["token"].get<std::string>().empty()) {
        const std::string tok = p["token"].get<std::string>();
        diag::log_tagged_fmt("mcp_burp", "collaborator_poll by_token token=%s", tok.c_str());
        auto list = aida::burp::collaborator::poll_by_token(tok);
        for (const auto& it : list) out.push_back(interaction_to_json(it));
        count = list.size();
    } else {
        uint64_t since = 0;
        if (p.contains("since_ms") && p["since_ms"].is_number_unsigned()) since = p["since_ms"].get<uint64_t>();
        diag::log_tagged_fmt("mcp_burp", "collaborator_poll since_ms=%llu", static_cast<unsigned long long>(since));
        auto list = aida::burp::collaborator::poll_since(since);
        for (const auto& it : list) out.push_back(interaction_to_json(it));
        count = list.size();
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_poll ok count=%zu", count);
    json result;
    result["interactions"] = std::move(out);
    return tool_result_t::ok("collaborator interactions count=" + std::to_string(count), result);
}

tool_result_t handle_get_interaction(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction entry");
    if (!p.contains("id") || !p["id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction missing_id");
        return tool_result_t::error("id parameter required");
    }
    uint64_t id = p["id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction id=%llu", static_cast<unsigned long long>(id));
    aida::burp::collaborator::interaction_t it;
    if (!aida::burp::collaborator::get_interaction(id, it))
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("interaction not found");
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction ok id=%llu kind=%s", static_cast<unsigned long long>(id), it.kind.c_str());
    return tool_result_t::ok("interaction", interaction_to_json(it));
}

tool_result_t handle_clear(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_clear entry");
    aida::burp::collaborator::clear();
    diag::log_tagged_fmt("mcp_burp", "collaborator_clear ok");
    return tool_result_t::ok("cleared", status_to_json(aida::burp::collaborator::status()));
}

tool_result_t handle_list_tokens(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_list_tokens entry");
    auto toks = aida::burp::collaborator::list_tokens();
    json arr = json::array();
    for (const auto& t : toks) {
        json e;
        e["token"]             = t.token;
        e["full_domain"]       = t.full_domain;
        e["issued_ms"]         = static_cast<uint64_t>(t.issued_ms);
        e["last_seen_ms"]      = static_cast<uint64_t>(t.last_seen_ms);
        e["interaction_count"] = static_cast<uint64_t>(t.interaction_count);
        arr.push_back(std::move(e));
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_list_tokens ok count=%zu", toks.size());
    json r;
    r["tokens"] = std::move(arr);
    return tool_result_t::ok("tokens count=" + std::to_string(toks.size()), r);
}

}

void register_collaborator_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_collaborator_status", "burp",
        "Get the current state of the Burp-style out-of-band Collaborator server: "
        "running flag, HTTP/DNS/SMTP listener health, ports, public host/IP, interaction count, token count.",
        {},
        handle_status, true
    });

    register_compat(srv, {
        "burp_collaborator_start", "burp",
        "Start the out-of-band Collaborator server. Listens on HTTP (default 8444), DNS (UDP, default 5353), and SMTP (default 2525). "
        "Every inbound HTTP request, DNS query, or SMTP envelope is captured and timestamped, with the embedded token "
        "extracted from the subdomain/path. Use this to detect blind injection (SSRF, XXE, RCE, SQLi out-of-band).",
        {{"bind_ip",      "string",  "Interface to bind (default '0.0.0.0')", false},
         {"http_port",    "number",  "HTTP listener port (default 8444)", false},
         {"dns_port",     "number",  "DNS UDP port (default 5353)", false},
         {"smtp_port",    "number",  "SMTP TCP port (default 2525)", false},
         {"public_host",  "string",  "Public hostname victims will resolve (default 'aidacollab.local')", false},
         {"public_ip",    "string",  "Public IPv4 the DNS server returns as A record (default '127.0.0.1')", false},
         {"enable_http",  "boolean", "Enable HTTP listener (default true)", false},
         {"enable_dns",   "boolean", "Enable DNS listener (default true)", false},
         {"enable_smtp",  "boolean", "Enable SMTP listener (default true)", false},
         {"canned_body",  "string",  "Optional response body returned for every HTTP hit", false},
         {"canned_content_type", "string", "Content-Type for canned body (default 'text/plain')", false}},
        handle_start, false
    });

    register_compat(srv, {
        "burp_collaborator_stop", "burp",
        "Stop the Collaborator server and tear down all three listener sockets. Interactions captured prior to stop are kept.",
        {},
        handle_stop, false
    });

    register_compat(srv, {
        "burp_collaborator_generate_token", "burp",
        "Generate a fresh 16-letter lowercase token and bind it to the configured public host. "
        "Returns the bare token and the full callback domain (e.g. 'abcdefghijklmnop.aidacollab.local'). "
        "Inject this domain into target inputs to detect out-of-band callbacks.",
        {},
        handle_generate_token, false
    });

    register_compat(srv, {
        "burp_collaborator_poll", "burp",
        "Poll captured interactions. Filter by exact token, or by timestamp (interactions with timestamp_ms >= since_ms).",
        {{"since_ms", "number", "Inclusive lower bound on interaction timestamp (ms)", false},
         {"token",    "string", "Exact token to filter by", false}},
        handle_poll, true
    });

    register_compat(srv, {
        "burp_collaborator_get_interaction", "burp",
        "Retrieve a single interaction record by its numeric id (raw request, decoded details, client ip, token).",
        {{"id", "number", "Numeric interaction id", true}},
        handle_get_interaction, true
    });

    register_compat(srv, {
        "burp_collaborator_clear", "burp",
        "Clear the captured interaction history. Issued tokens are retained but their counters reset.",
        {},
        handle_clear, false
    });

    register_compat(srv, {
        "burp_collaborator_list_tokens", "burp",
        "Enumerate all tokens that have been issued by the Collaborator with per-token interaction counters and last-seen timestamps.",
        {},
        handle_list_tokens, true
    });
}

}
}
}
