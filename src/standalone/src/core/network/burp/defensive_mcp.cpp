#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "defensive_mcp.hpp"

#include "content_scanner.hpp"
#include "security_headers.hpp"
#include "site_map.hpp"
#include "tls_analyzer.hpp"

#include "../../../helpers/diag_log.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace defensive {

namespace {

using json = nlohmann::json;
using tool_def_t = mcp_standalone::tool_def_t;
using tool_result_t = mcp_standalone::tool_result_t;

bool json_u64(const json& value, std::uint64_t& out)
{
    if (value.is_number_unsigned()) {
        out = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value >= 0) {
            out = static_cast<std::uint64_t>(signed_value);
            return true;
        }
    }
    return false;
}

bool json_u16(const json& value, std::uint16_t& out)
{
    std::uint64_t tmp = 0;
    if (!json_u64(value, tmp) || tmp == 0 || tmp > 65535)
        return false;
    out = static_cast<std::uint16_t>(tmp);
    return true;
}

std::vector<std::string> category_list(const json& params)
{
    std::vector<std::string> out;
    if (!params.contains("check_categories") || !params["check_categories"].is_array())
        return out;
    for (const auto& item : params["check_categories"]) {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

std::string redact_url(std::string url)
{
    const std::size_t scheme = url.find("://");
    const std::size_t authority_start = scheme == std::string::npos ? 0 : scheme + 3;
    const std::size_t path_start = url.find_first_of("/?#", authority_start);
    const std::size_t authority_end = path_start == std::string::npos ? url.size() : path_start;
    const std::size_t at = url.find('@', authority_start);
    if (at != std::string::npos && at < authority_end)
        url.replace(authority_start, at - authority_start, "[REDACTED]");
    const std::size_t query = url.find('?', authority_start);
    if (query != std::string::npos)
        url.erase(query + 1).append("[REDACTED]");
    const std::size_t fragment = url.find('#', authority_start);
    if (fragment != std::string::npos)
        url.erase(fragment + 1).append("[REDACTED]");
    return url;
}

tool_result_t error_with_data(const std::string& message, const std::string& code, json data = json::object())
{
    data["success"] = false;
    data["code"] = code;
    return tool_result_t::error(message, code, data);
}

tool_result_t security_headers_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "security_headers entry");
    if (!params.is_object())
        return error_with_data("Parameters must be an object", "invalid_params");
    if (params.contains("exchange_id")) {
        std::uint64_t id = 0;
        if (!json_u64(params["exchange_id"], id))
            return error_with_data("exchange_id must be a positive integer", "invalid_exchange_id");
        exchange_observed_t exchange;
        if (!sitemap::find_exchange(id, exchange)) {
            json data;
            data["exchange_id"] = id;
            return error_with_data("Exchange id not found", "exchange_not_found", data);
        }
        auto result = security_headers::analyze_exchange(exchange, true);
        return tool_result_t::ok("Security header analysis complete", result);
    }
    if (!params.contains("target_url") || !params["target_url"].is_string())
        return error_with_data("target_url or exchange_id is required", "missing_target");
    std::string error;
    auto result = security_headers::analyze_url(params["target_url"].get<std::string>(),
                                                params.value("check_all_paths", false),
                                                true,
                                                error);
    if (!error.empty()) {
        json data;
        data["target_url"] = redact_url(params["target_url"].get<std::string>());
        data["error"] = error;
        return error_with_data("Security header request failed", "request_failed", data);
    }
    return tool_result_t::ok("Security header analysis complete", result);
}

tool_result_t tls_analyze_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "tls_analyze entry");
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return error_with_data("host is required", "missing_host");
    std::uint16_t port = 443;
    if (params.contains("port") && !json_u16(params["port"], port))
        return error_with_data("port must be 1..65535", "invalid_port");
    std::string error;
    auto result = tls_analyzer::analyze_host(params["host"].get<std::string>(),
                                             port,
                                             params.value("check_chain", true),
                                             params.value("check_ct_logs", true),
                                             true,
                                             error);
    if (!error.empty()) {
        json data;
        data["host"] = redact_url(params["host"].get<std::string>());
        data["port"] = port;
        data["error"] = error;
        return error_with_data("TLS analysis failed", error, data);
    }
    return tool_result_t::ok("TLS analysis complete", result);
}

tool_result_t cookie_audit_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "cookie_audit entry");
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return error_with_data("host is required", "missing_host");
    std::string error;
    auto result = security_headers::audit_cookies_for_host(params["host"].get<std::string>(),
                                                           params.value("scan_all_paths", true),
                                                           true,
                                                           error);
    if (!error.empty()) {
        json data;
        data["host"] = redact_url(params["host"].get<std::string>());
        data["error"] = error;
        return error_with_data("Cookie audit failed", error, data);
    }
    return tool_result_t::ok("Cookie audit complete", result);
}

tool_result_t content_scan_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "content_scan entry");
    if (!params.is_object())
        return error_with_data("Parameters must be an object", "invalid_params");
    const auto categories = category_list(params);
    if (params.value("scan_all_captured", false)) {
        auto result = content_scanner::scan_captured(params.value("host_filter", std::string()), categories, true);
        return tool_result_t::ok("Captured content scan complete", result);
    }
    if (params.contains("exchange_id")) {
        std::uint64_t id = 0;
        if (!json_u64(params["exchange_id"], id))
            return error_with_data("exchange_id must be a positive integer", "invalid_exchange_id");
        exchange_observed_t exchange;
        if (!sitemap::find_exchange(id, exchange)) {
            json data;
            data["exchange_id"] = id;
            return error_with_data("Exchange id not found", "exchange_not_found", data);
        }
        auto result = content_scanner::scan_exchange(exchange, categories, true);
        return tool_result_t::ok("Content scan complete", result);
    }
    if (!params.contains("target_url") || !params["target_url"].is_string())
        return error_with_data("target_url, exchange_id, or scan_all_captured is required", "missing_target");
    std::string error;
    auto result = content_scanner::scan_url(params["target_url"].get<std::string>(), categories, true, error);
    if (!error.empty()) {
        json data;
        data["target_url"] = redact_url(params["target_url"].get<std::string>());
        data["error"] = error;
        return error_with_data("Content scan request failed", error, data);
    }
    return tool_result_t::ok("Content scan complete", result);
}

tool_result_t backup_detect_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "backup_detect entry");
    if (!params.is_object() || !params.contains("target_url") || !params["target_url"].is_string())
        return error_with_data("target_url is required", "missing_target_url");
    const std::uint32_t max_probes = params.value("max_probes", 32u);
    std::string error;
    auto result = content_scanner::detect_backups(params["target_url"].get<std::string>(), max_probes, true, error);
    if (!error.empty()) {
        json data;
        data["target_url"] = redact_url(params["target_url"].get<std::string>());
        data["error"] = error;
        return error_with_data("Backup detection failed", error, data);
    }
    return tool_result_t::ok("Backup detection complete", result);
}

tool_result_t source_exposure_tool(const json& params)
{
    diag::log_tagged("defensive_mcp", "source_exposure entry");
    if (!params.is_object() || !params.contains("target_url") || !params["target_url"].is_string())
        return error_with_data("target_url is required", "missing_target_url");
    const std::uint32_t max_probes = params.value("max_probes", 32u);
    std::string error;
    auto result = content_scanner::detect_source_exposure(params["target_url"].get<std::string>(), max_probes, true, error);
    if (!error.empty()) {
        json data;
        data["target_url"] = redact_url(params["target_url"].get<std::string>());
        data["error"] = error;
        return error_with_data("Source exposure detection failed", error, data);
    }
    return tool_result_t::ok("Source exposure detection complete", result);
}

void register_tool(mcp_standalone::server_t& srv,
                   std::string name,
                   std::string description,
                   std::vector<mcp_standalone::tool_param_t> params,
                   bool read_only,
                   std::function<tool_result_t(const json&)> handler)
{
    tool_def_t tool;
    tool.name = std::move(name);
    tool.description = std::move(description);
    tool.params = std::move(params);
    tool.read_only = read_only;
    tool.handler = std::move(handler);
    srv.register_tool(std::move(tool));
}

}

void register_defensive_tools(mcp_standalone::server_t& srv)
{
    register_tool(srv,
                  "aida.web.defensive.security_headers",
                  "Analyze HTTP security headers and cookie flags for a captured exchange or fetched URL. URL mode may send bounded requests.",
                  {
                      {"target_url", "string", "Full URL to fetch and analyze", false},
                      {"exchange_id", "number", "Captured exchange id to analyze without network traffic", false},
                      {"check_all_paths", "boolean", "Also check common paths such as /login and /.well-known/security.txt", false}
                  },
                  false,
                  security_headers_tool);

    register_tool(srv,
                  "aida.web.defensive.tls_analyze",
                  "Analyze TLS protocol, cipher, certificate chain, HSTS, OCSP, and SCT evidence with safe bounded probes.",
                  {
                      {"host", "string", "TLS server hostname or address", true},
                      {"port", "number", "TLS port, default 443", false},
                      {"check_chain", "boolean", "Validate certificate chain with Windows CryptoAPI cache-only revocation evidence", false},
                      {"check_ct_logs", "boolean", "Report SCT certificate extension evidence where present", false}
                  },
                  false,
                  tls_analyze_tool);

    register_tool(srv,
                  "aida.web.defensive.cookie_audit",
                  "Audit cookies for Secure, HttpOnly, SameSite, expiration, scope, and prefix compliance. Path scan mode sends bounded requests.",
                  {
                      {"host", "string", "Hostname or URL whose cookies should be audited", true},
                      {"scan_all_paths", "boolean", "Request common paths to observe Set-Cookie headers", false}
                  },
                  false,
                  cookie_audit_tool);

    register_tool(srv,
                  "aida.web.defensive.content_scan",
                  "Scan captured or fetched HTTP content for PII, payment cards, API keys, internal IPs, errors, debug links, backup references, source exposure, directory listings, secrets, and comment leaks. Evidence is redacted.",
                  {
                      {"exchange_id", "number", "Captured exchange id to scan without network traffic", false},
                      {"target_url", "string", "Full URL to fetch and scan", false},
                      {"scan_all_captured", "boolean", "Scan bounded captured exchanges instead of one target", false},
                      {"host_filter", "string", "Optional host substring for captured scans", false},
                      {"check_categories", "array", "Optional categories to run", false}
                  },
                  false,
                  content_scan_tool);

    register_tool(srv,
                  "aida.web.defensive.backup_detect",
                  "Run scope-aware bounded probes for backup, dump, archive, editor-swap, and environment files.",
                  {
                      {"target_url", "string", "In-scope base URL to probe", true},
                      {"max_probes", "number", "Maximum probes, clamped to 1..64", false}
                  },
                  false,
                  backup_detect_tool);

    register_tool(srv,
                  "aida.web.defensive.source_exposure",
                  "Run scope-aware bounded probes for repository metadata, source files, deployment manifests, and source-like directories.",
                  {
                      {"target_url", "string", "In-scope base URL to probe", true},
                      {"max_probes", "number", "Maximum probes, clamped to 1..64", false}
                  },
                  false,
                  source_exposure_tool);

    diag::log_tagged("defensive_mcp", "defensive_tools_registered");
}

}
}
}
