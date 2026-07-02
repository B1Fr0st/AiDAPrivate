#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "security_headers.hpp"

#include "audit_http.hpp"
#include "cookie_jar.hpp"
#include "csp_analyzer.hpp"
#include "findings_db.hpp"
#include "issue.hpp"
#include "scope.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace security_headers {

namespace {

using json = nlohmann::json;

std::string lower_ascii(std::string v)
{
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v;
}

std::string trim_copy(std::string v)
{
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front())))
        v.erase(v.begin());
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
        v.pop_back();
    return v;
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

std::uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::uint64_t fnv1a64(const std::string& value)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : value) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex64(std::uint64_t value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = kHex[value & 0x0f];
        value >>= 4;
    }
    return out;
}

std::map<std::string, std::vector<std::string>> header_map(const std::vector<std::pair<std::string, std::string>>& headers)
{
    std::map<std::string, std::vector<std::string>> out;
    for (const auto& h : headers)
        out[lower_ascii(trim_copy(h.first))].push_back(trim_copy(h.second));
    return out;
}

std::string first_header(const std::map<std::string, std::vector<std::string>>& headers, const std::string& name)
{
    const auto it = headers.find(lower_ascii(name));
    if (it == headers.end() || it->second.empty())
        return {};
    return it->second.front();
}

std::string sanitize_header_value(const std::string& value)
{
    std::string out = value;
    const std::string low = lower_ascii(out);
    std::size_t pos = low.find("'nonce-");
    while (pos != std::string::npos) {
        const std::size_t end = out.find('\'', pos + 7);
        if (end == std::string::npos)
            break;
        out.replace(pos, end - pos + 1, "'nonce-[REDACTED]'");
        const std::string refreshed = lower_ascii(out);
        pos = refreshed.find("'nonce-", pos + 18);
    }
    return out;
}

json status_json(bool present,
                 const std::string& value,
                 const std::string& status,
                 const std::vector<std::string>& issues,
                 const std::string& recommendation)
{
    json out;
    out["present"] = present;
    if (present)
        out["value"] = sanitize_header_value(value);
    out["status"] = status;
    if (!issues.empty())
        out["issues"] = issues;
    if (!recommendation.empty())
        out["recommendation"] = recommendation;
    return out;
}

void count_status(const json& item, int& passed, int& warnings, int& failed, int& info)
{
    const std::string status = item.value("status", std::string());
    if (status == "pass")
        ++passed;
    else if (status == "warn")
        ++warnings;
    else if (status == "fail")
        ++failed;
    else
        ++info;
}

bool contains_token(const std::string& value, const std::string& token)
{
    return lower_ascii(value).find(lower_ascii(token)) != std::string::npos;
}

long long parse_hsts_max_age(const std::string& value)
{
    const std::string lower = lower_ascii(value);
    const std::string marker = "max-age=";
    const std::size_t pos = lower.find(marker);
    if (pos == std::string::npos)
        return -1;
    std::size_t p = pos + marker.size();
    long long out = 0;
    bool any = false;
    while (p < lower.size() && std::isdigit(static_cast<unsigned char>(lower[p]))) {
        any = true;
        out = out * 10 + (lower[p] - '0');
        ++p;
    }
    return any ? out : -1;
}

int cookie_score(const cookie_jar::parsed_cookie_t& cookie, bool tls, std::vector<json>& issue_items)
{
    int score = 100;
    const std::string name_l = lower_ascii(cookie.name);
    const bool session_like = name_l.find("session") != std::string::npos ||
        name_l.find("sid") != std::string::npos ||
        name_l.find("token") != std::string::npos ||
        name_l.find("auth") != std::string::npos ||
        name_l.find("jwt") != std::string::npos;

    auto add = [&](const char* severity, const char* text, const char* cwe, int penalty) {
        json item;
        item["severity"] = severity;
        item["issue"] = text;
        if (cwe && cwe[0])
            item["cwe"] = cwe;
        issue_items.push_back(std::move(item));
        score -= penalty;
    };

    if (tls && !cookie.secure)
        add("high", "Missing Secure flag", "CWE-614", 30);
    if (session_like && !cookie.http_only)
        add("medium", "Session-like cookie is missing HttpOnly", "CWE-1004", 20);
    else if (!cookie.http_only)
        add("low", "Cookie is missing HttpOnly", "CWE-1004", 10);
    if (cookie.same_site == cookie_jar::same_site_t::unset)
        add(session_like ? "medium" : "low", "SameSite attribute is not set", "CWE-1275", session_like ? 18 : 10);
    if (cookie.same_site == cookie_jar::same_site_t::none && !cookie.secure)
        add("high", "SameSite=None cookie is missing Secure", "CWE-1275", 30);
    if (!cookie.host_only && !cookie.domain.empty())
        add("low", "Domain attribute permits subdomain scope", "", 8);
    if (cookie.path.empty() || cookie.path == "/")
        add("info", "Cookie path is broad", "", 3);
    if (cookie.name.rfind("__Host-", 0) == 0) {
        if (!cookie.secure)
            add("high", "__Host- cookie is missing Secure", "CWE-614", 30);
        if (!cookie.host_only)
            add("medium", "__Host- cookie must not set Domain", "", 20);
        if (cookie.path != "/")
            add("medium", "__Host- cookie path must be /", "", 20);
    }
    if (cookie.name.rfind("__Secure-", 0) == 0 && !cookie.secure)
        add("high", "__Secure- cookie is missing Secure", "CWE-614", 30);

    return std::max(0, score);
}

json cookie_to_json(const cookie_jar::parsed_cookie_t& cookie, bool tls)
{
    std::vector<json> issues;
    const int score = cookie_score(cookie, tls, issues);
    json out;
    out["name"] = cookie.name;
    out["domain"] = cookie.domain;
    out["path"] = cookie.path;
    out["secure"] = cookie.secure;
    out["http_only"] = cookie.http_only;
    out["host_only"] = cookie.host_only;
    out["same_site"] = cookie_jar::same_site_str(cookie.same_site);
    out["has_expires"] = cookie.has_expires;
    out["expires_unix_ms"] = cookie.expires_unix_ms;
    out["value_redacted"] = true;
    out["value_length"] = static_cast<std::uint64_t>(cookie.value.size());
    out["value_hash64"] = hex64(fnv1a64(cookie.value));
    out["score"] = score;
    out["issues"] = issues;
    std::string severity = "info";
    for (const auto& issue : issues) {
        const std::string sev = issue.value("severity", "info");
        if (sev == "high") {
            severity = "high";
            break;
        }
        if (sev == "medium" && severity != "high")
            severity = "medium";
        if (sev == "low" && severity == "info")
            severity = "low";
    }
    out["severity"] = severity;
    return out;
}

std::vector<cookie_jar::parsed_cookie_t> parse_response_cookies(const exchange_observed_t& exchange)
{
    std::vector<cookie_jar::parsed_cookie_t> cookies;
    for (const auto& h : exchange.resp_headers) {
        if (lower_ascii(h.first) != "set-cookie")
            continue;
        cookie_jar::parsed_cookie_t cookie;
        if (cookie_jar::parse_set_cookie(h.second, exchange.host, cookie))
            cookies.push_back(std::move(cookie));
    }
    return cookies;
}

severity_t issue_severity_from_status(const std::string& status, const std::string& key)
{
    if (status == "fail") {
        if (key.find("hsts") != std::string::npos || key.find("cookie") != std::string::npos)
            return severity_t::high;
        return severity_t::medium;
    }
    if (status == "warn")
        return severity_t::low;
    return severity_t::info;
}

void persist_issue(const std::string& type_key,
                   const std::string& name,
                   const std::string& description,
                   const std::string& remediation,
                   severity_t severity,
                   const exchange_observed_t& exchange,
                   const std::string& marker)
{
    if (type_key.empty())
        return;
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.description = description;
    issue.remediation = remediation;
    issue.severity = severity;
    issue.confidence = confidence_t::firm;
    issue.scheme = exchange.scheme;
    issue.host = exchange.host;
    issue.port = exchange.port;
    issue.path = exchange.path.empty() ? "/" : exchange.path;
    issue.src_exchange_id = exchange.id;
    issue.seen_ms = now_ms();
    evidence_t ev;
    ev.marker = marker;
    ev.response_raw = marker;
    issue.evidence.push_back(std::move(ev));
    issue_t db_issue = issue;
    db_issue.id = 0;
    findings_db::upsert(std::move(db_issue));
    issue_store::add(std::move(issue));
}

std::vector<std::uint8_t> build_request(const std::string& method, const std::string& host, std::uint16_t port, bool tls, const std::string& path)
{
    const bool default_port = (tls && port == 443) || (!tls && port == 80);
    std::string authority = host;
    if (!default_port)
        authority += ":" + std::to_string(port);
    std::string request_path = path.empty() ? "/" : path;
    std::string raw;
    raw += method;
    raw += " ";
    raw += request_path;
    raw += " HTTP/1.1\r\nHost: ";
    raw += authority;
    raw += "\r\nUser-Agent: AiDA-Defensive/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

bool fetch_url(const std::string& url, const std::string& method, exchange_observed_t& out, std::string& error, bool enforce_scope)
{
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "invalid_url";
        return false;
    }
    if (enforce_scope && !scope::in_scope_components(scheme, host, port, path)) {
        error = "blocked_by_scope";
        return false;
    }
    const bool tls = scheme == "https";
    audit_http::send_options_t opt;
    opt.timeout_ms = 10000;
    opt.follow_redirects = true;
    opt.max_redirects = 2;
    opt.enforce_scope = enforce_scope;
    opt.publish_exchange = false;
    opt.exchange_source = "defensive";
    auto request = build_request(method, host, port, tls, path);
    auto response = audit_http::send(request, host, port, tls, opt);
    if (!response.has_value() && method == "HEAD") {
        request = build_request("GET", host, port, tls, path);
        response = audit_http::send(request, host, port, tls, opt);
    }
    if (!response.has_value()) {
        error = audit_http::last_error();
        return false;
    }
    out = std::move(*response);
    return true;
}

json analyze_single(const exchange_observed_t& exchange, bool persist_findings)
{
    const auto headers = header_map(exchange.resp_headers);
    const bool tls = lower_ascii(exchange.scheme) == "https" || exchange.port == 443;
    json result;
    result["url"] = exchange.scheme + "://" + exchange.host + (exchange.path.empty() ? "/" : exchange.path);
    result["host"] = exchange.host;
    result["port"] = exchange.port;
    result["status_code"] = exchange.status_code;
    result["exchange_id"] = exchange.id;

    json header_results = json::object();
    int score = 0;

    const std::string hsts = first_header(headers, "strict-transport-security");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        std::string recommendation;
        int points = 15;
        if (tls && hsts.empty()) {
            status = "fail";
            issues.push_back("Missing Strict-Transport-Security on HTTPS response");
            recommendation = "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
            points = 0;
        } else if (!hsts.empty()) {
            const long long max_age = parse_hsts_max_age(hsts);
            if (max_age < 31536000) {
                status = "warn";
                issues.push_back("HSTS max-age is below one year");
                recommendation = "Use max-age=31536000 or higher after validating HTTPS coverage";
                points = 9;
            }
            if (!contains_token(hsts, "includesubdomains")) {
                if (status == "pass")
                    status = "warn";
                issues.push_back("HSTS includeSubDomains is absent");
                points = std::min(points, 11);
            }
        } else if (!tls) {
            status = "info";
        }
        header_results["strict_transport_security"] = status_json(!hsts.empty(), hsts, status, issues, recommendation);
        score += points;
    }

    const auto csp_result = csp::analyze_for_response(exchange.resp_headers);
    {
        std::vector<std::string> issues;
        for (const auto& finding : csp_result.findings)
            issues.push_back(finding.title);
        std::string value = first_header(headers, "content-security-policy");
        if (value.empty())
            value = first_header(headers, "content-security-policy-report-only");
        std::string status = "pass";
        if (!csp_result.has_csp)
            status = "fail";
        else if (csp_result.score < 80 || csp_result.is_report_only)
            status = "warn";
        std::string recommendation;
        if (!csp_result.has_csp)
            recommendation = "Add a restrictive Content-Security-Policy with default-src 'self' and explicit script/style sources";
        else if (csp_result.score < 100)
            recommendation = "Tighten CSP directives flagged by the CSP analyzer";
        json csp_json = status_json(csp_result.has_csp, value, status, issues, recommendation);
        csp_json["score"] = csp_result.score;
        csp_json["report_only"] = csp_result.is_report_only;
        header_results["content_security_policy"] = csp_json;
        score += static_cast<int>((std::max(0, csp_result.score) * 20) / 100);
    }

    const std::string xfo = first_header(headers, "x-frame-options");
    {
        const std::string lxfo = lower_ascii(xfo);
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 10;
        std::string recommendation;
        if (xfo.empty()) {
            status = "fail";
            issues.push_back("Missing X-Frame-Options");
            recommendation = "Add X-Frame-Options: DENY or frame-ancestors in CSP";
            points = 0;
        } else if (!(lxfo == "deny" || lxfo == "sameorigin")) {
            status = "warn";
            issues.push_back("X-Frame-Options value is not DENY or SAMEORIGIN");
            recommendation = "Use DENY or SAMEORIGIN, or enforce frame-ancestors in CSP";
            points = 5;
        }
        header_results["x_frame_options"] = status_json(!xfo.empty(), xfo, status, issues, recommendation);
        score += points;
    }

    const std::string xcto = first_header(headers, "x-content-type-options");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (lower_ascii(xcto) != "nosniff") {
            status = "fail";
            issues.push_back(xcto.empty() ? "Missing X-Content-Type-Options" : "X-Content-Type-Options is not nosniff");
            points = 0;
        }
        header_results["x_content_type_options"] = status_json(!xcto.empty(), xcto, status, issues, "Add X-Content-Type-Options: nosniff");
        score += points;
    }

    const std::string referrer = first_header(headers, "referrer-policy");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (referrer.empty()) {
            status = "warn";
            issues.push_back("Missing Referrer-Policy");
            points = 3;
        } else if (contains_token(referrer, "unsafe-url")) {
            status = "fail";
            issues.push_back("Referrer-Policy unsafe-url leaks full URLs cross-origin");
            points = 0;
        }
        header_results["referrer_policy"] = status_json(!referrer.empty(), referrer, status, issues, "Add Referrer-Policy: strict-origin-when-cross-origin");
        score += points;
    }

    const std::string permissions = first_header(headers, "permissions-policy");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (permissions.empty()) {
            status = "info";
            issues.push_back("Permissions-Policy is absent");
            points = 3;
        } else if (permissions.find('*') != std::string::npos) {
            status = "warn";
            issues.push_back("Permissions-Policy contains wildcard access");
            points = 2;
        }
        header_results["permissions_policy"] = status_json(!permissions.empty(), permissions, status, issues, "Add Permissions-Policy with denied defaults for unused browser features");
        score += points;
    }

    const std::string coop = first_header(headers, "cross-origin-opener-policy");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (coop.empty()) {
            status = "warn";
            issues.push_back("Cross-Origin-Opener-Policy is absent");
            points = 2;
        } else if (!contains_token(coop, "same-origin")) {
            status = "warn";
            issues.push_back("COOP is not same-origin based");
            points = 3;
        }
        header_results["cross_origin_opener_policy"] = status_json(!coop.empty(), coop, status, issues, "Use Cross-Origin-Opener-Policy: same-origin where compatible");
        score += points;
    }

    const std::string coep = first_header(headers, "cross-origin-embedder-policy");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (coep.empty()) {
            status = "info";
            issues.push_back("Cross-Origin-Embedder-Policy is absent");
            points = 3;
        } else if (!contains_token(coep, "require-corp") && !contains_token(coep, "credentialless")) {
            status = "warn";
            issues.push_back("COEP does not require-corp or credentialless");
            points = 2;
        }
        header_results["cross_origin_embedder_policy"] = status_json(!coep.empty(), coep, status, issues, "Use Cross-Origin-Embedder-Policy: require-corp where compatible");
        score += points;
    }

    const std::string corp = first_header(headers, "cross-origin-resource-policy");
    {
        std::vector<std::string> issues;
        std::string status = "pass";
        int points = 5;
        if (corp.empty()) {
            status = "info";
            issues.push_back("Cross-Origin-Resource-Policy is absent");
            points = 3;
        }
        header_results["cross_origin_resource_policy"] = status_json(!corp.empty(), corp, status, issues, "Add Cross-Origin-Resource-Policy: same-origin for non-public resources");
        score += points;
    }

    const auto cookies = parse_response_cookies(exchange);
    json cookie_arr = json::array();
    int cookie_score_total = 0;
    for (const auto& cookie : cookies) {
        json c = cookie_to_json(cookie, tls);
        cookie_score_total += c.value("score", 100);
        cookie_arr.push_back(std::move(c));
    }
    if (cookies.empty())
        score += 25;
    else
        score += static_cast<int>((cookie_score_total / static_cast<int>(cookies.size())) * 25 / 100);

    int passed = 0;
    int warnings = 0;
    int failed = 0;
    int info = 0;
    for (auto it = header_results.begin(); it != header_results.end(); ++it)
        count_status(it.value(), passed, warnings, failed, info);

    for (const auto& c : cookie_arr) {
        const auto issue_count = c.contains("issues") && c["issues"].is_array() ? c["issues"].size() : 0;
        if (issue_count == 0)
            ++passed;
        else if (c.value("severity", "info") == "high" || c.value("severity", "info") == "medium")
            ++failed;
        else
            ++warnings;
    }

    result["headers"] = header_results;
    result["cookies"] = cookie_arr;
    result["score"] = std::max(0, std::min(100, score));
    result["grade"] = grade_for_score(result["score"].get<int>());
    result["summary"] = {
        {"total_checks", passed + warnings + failed + info},
        {"passed", passed},
        {"warnings", warnings},
        {"failed", failed},
        {"info", info}
    };

    if (persist_findings) {
        for (auto it = header_results.begin(); it != header_results.end(); ++it) {
            const std::string status = it.value().value("status", "pass");
            if (status == "pass" || status == "info")
                continue;
            const std::string type_key = "defensive.security_headers." + it.key();
            std::string description = it.key() + " status=" + status;
            if (it.value().contains("issues") && it.value()["issues"].is_array() && !it.value()["issues"].empty())
                description = it.value()["issues"].front().get<std::string>();
            persist_issue(type_key, "Security header finding", description,
                          it.value().value("recommendation", std::string()),
                          issue_severity_from_status(status, type_key), exchange, type_key + ":" + status);
        }
        for (const auto& c : cookie_arr) {
            if (!c.contains("issues") || !c["issues"].is_array() || c["issues"].empty())
                continue;
            const std::string cookie_name = c.value("name", std::string());
            persist_issue("defensive.security_headers.cookie_flags",
                          "Cookie security flag finding",
                          "Cookie " + cookie_name + " has security attribute findings",
                          "Set Secure, HttpOnly, SameSite, narrow Domain/Path, and enforce prefix contracts where applicable",
                          c.value("severity", "info") == "high" ? severity_t::high : severity_t::medium,
                          exchange,
                          "cookie:" + cookie_name + ":value_hash64=" + c.value("value_hash64", std::string()));
        }
    }

    return result;
}

std::string url_for_path(const std::string& scheme, const std::string& host, std::uint16_t port, const std::string& path)
{
    const bool tls = scheme == "https";
    const bool default_port = (tls && port == 443) || (!tls && port == 80);
    std::string url = scheme + "://" + host;
    if (!default_port)
        url += ":" + std::to_string(port);
    if (path.empty() || path[0] != '/')
        url += "/";
    url += path.empty() ? std::string() : path;
    return url;
}

std::vector<cookie_jar::parsed_cookie_t> collect_remote_cookies(const std::string& scheme,
                                                                 const std::string& host,
                                                                 std::uint16_t port,
                                                                 const std::vector<std::string>& paths,
                                                                 json& probes)
{
    std::vector<cookie_jar::parsed_cookie_t> out;
    std::set<std::string> seen;
    for (const auto& path : paths) {
        const std::string url = url_for_path(scheme, host, port, path);
        json probe;
        probe["url"] = url;
        if (!scope::in_scope_components(scheme, host, port, path)) {
            probe["status"] = "blocked_by_scope";
            probes.push_back(std::move(probe));
            continue;
        }
        exchange_observed_t exchange;
        std::string error;
        if (!fetch_url(url, "GET", exchange, error, true)) {
            probe["status"] = "send_failed";
            probe["error"] = error;
            probes.push_back(std::move(probe));
            continue;
        }
        probe["status"] = "ok";
        probe["http_status"] = exchange.status_code;
        const auto cookies = parse_response_cookies(exchange);
        probe["set_cookie_count"] = static_cast<std::uint64_t>(cookies.size());
        for (const auto& cookie : cookies) {
            const std::string key = lower_ascii(cookie.name + "|" + cookie.domain + "|" + cookie.path);
            if (seen.insert(key).second)
                out.push_back(cookie);
        }
        probes.push_back(std::move(probe));
    }
    return out;
}

json cookie_audit_json(const std::string& host,
                       bool tls,
                       const std::vector<cookie_jar::parsed_cookie_t>& cookies,
                       bool persist_findings,
                       const exchange_observed_t* source_exchange)
{
    json findings = json::array();
    int total = 0;
    for (const auto& cookie : cookies) {
        json c = cookie_to_json(cookie, tls);
        total += c.value("score", 100);
        findings.push_back(std::move(c));
    }
    const int score = cookies.empty() ? 100 : std::max(0, std::min(100, total / static_cast<int>(cookies.size())));
    json out;
    out["host"] = host;
    out["total_cookies"] = static_cast<std::uint64_t>(cookies.size());
    out["audit_findings"] = findings;
    out["score"] = score;
    out["grade"] = grade_for_score(score);

    if (persist_findings && source_exchange) {
        for (const auto& item : findings) {
            if (!item.contains("issues") || !item["issues"].is_array() || item["issues"].empty())
                continue;
            persist_issue("defensive.cookie_audit.flags",
                          "Cookie audit finding",
                          "Cookie " + item.value("name", std::string()) + " has security attribute findings",
                          "Use Secure, HttpOnly, SameSite, narrow scope, and compliant cookie prefixes",
                          item.value("severity", "info") == "high" ? severity_t::high : severity_t::medium,
                          *source_exchange,
                          "cookie:" + item.value("name", std::string()) + ":value_hash64=" + item.value("value_hash64", std::string()));
        }
    }
    return out;
}

}

std::string grade_for_score(int score)
{
    if (score >= 90)
        return "A";
    if (score >= 70)
        return "B";
    if (score >= 50)
        return "C";
    if (score >= 30)
        return "D";
    return "F";
}

nlohmann::json analyze_exchange(const exchange_observed_t& exchange, bool persist_findings)
{
    diag::log_tagged_fmt("defensive", "security_headers analyze_exchange id=%llu host=%s status=%d",
        static_cast<unsigned long long>(exchange.id), exchange.host.c_str(), exchange.status_code);
    return analyze_single(exchange, persist_findings);
}

nlohmann::json analyze_url(const std::string& target_url, bool check_all_paths, bool persist_findings, std::string& error)
{
    diag::log_tagged_fmt("defensive", "security_headers analyze_url url=%s check_all_paths=%d",
        redact_url(target_url).c_str(), check_all_paths ? 1 : 0);
    exchange_observed_t exchange;
    if (!fetch_url(target_url, "GET", exchange, error, false))
        return json::object();
    json result = analyze_single(exchange, persist_findings);
    if (check_all_paths) {
        std::string scheme;
        std::string host;
        std::string path;
        std::uint16_t port = 0;
        audit_http::parse_url(target_url, scheme, host, port, path);
        const std::vector<std::string> paths = {"/login", "/admin", "/api", "/robots.txt", "/.well-known/security.txt"};
        json path_results = json::array();
        for (const auto& p : paths) {
            exchange_observed_t path_exchange;
            std::string path_error;
            json item;
            item["url"] = url_for_path(scheme, host, port, p);
            if (fetch_url(item["url"].get<std::string>(), "HEAD", path_exchange, path_error, false)) {
                item["status"] = "ok";
                item["http_status"] = path_exchange.status_code;
                item["grade"] = analyze_single(path_exchange, persist_findings).value("grade", std::string("F"));
            } else {
                item["status"] = "send_failed";
                item["error"] = path_error;
            }
            path_results.push_back(std::move(item));
        }
        result["path_checks"] = path_results;
    }
    return result;
}

nlohmann::json audit_cookies_for_host(const std::string& host_input, bool scan_all_paths, bool persist_findings, std::string& error)
{
    diag::log_tagged_fmt("defensive", "cookie_audit host=%s scan_all_paths=%d", redact_url(host_input).c_str(), scan_all_paths ? 1 : 0);
    std::string scheme = "https";
    std::string host = host_input;
    std::string path = "/";
    std::uint16_t port = 443;
    if (host_input.find("://") != std::string::npos) {
        if (!audit_http::parse_url(host_input, scheme, host, port, path)) {
            error = "invalid_host_or_url";
            return json::object();
        }
    }
    std::vector<cookie_jar::parsed_cookie_t> cookies = cookie_jar::list_for_host(host);
    json probes = json::array();
    exchange_observed_t source;
    bool have_source = false;
    if (scan_all_paths) {
        const std::vector<std::string> paths = {"/", "/login", "/admin", "/api", "/dashboard"};
        auto remote = collect_remote_cookies(scheme, host, port, paths, probes);
        std::set<std::string> seen;
        for (const auto& cookie : cookies)
            seen.insert(lower_ascii(cookie.name + "|" + cookie.domain + "|" + cookie.path));
        for (const auto& cookie : remote) {
            const std::string key = lower_ascii(cookie.name + "|" + cookie.domain + "|" + cookie.path);
            if (seen.insert(key).second)
                cookies.push_back(cookie);
        }
        const std::string source_url = url_for_path(scheme, host, port, "/");
        std::string fetch_error;
        if (fetch_url(source_url, "GET", source, fetch_error, true))
            have_source = true;
    }
    json result = cookie_audit_json(host, scheme == "https", cookies, persist_findings, have_source ? &source : nullptr);
    result["scan_all_paths"] = scan_all_paths;
    result["path_probes"] = probes;
    return result;
}

}
}
}
