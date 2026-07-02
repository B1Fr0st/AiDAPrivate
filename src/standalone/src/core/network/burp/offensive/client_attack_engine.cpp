#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "client_attack_engine.hpp"

#include "../audit_http.hpp"
#include "../camoufox_bridge.hpp"
#include "../issue.hpp"
#include "../scope.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace client_attack {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct client_job_t
{
    std::uint64_t id = 0;
    std::string action;
    std::string target;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    bool running = false;
    bool cancelled = false;
    std::size_t requests_sent = 0;
    std::size_t requests_failed = 0;
    std::size_t issues_created = 0;
    json result = json::object();
};

std::atomic<std::uint64_t>& next_job_id()
{
    static std::atomic<std::uint64_t> v{1};
    return v;
}

std::mutex& jobs_mtx()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::uint64_t, client_job_t>& jobs()
{
    static std::unordered_map<std::uint64_t, client_job_t> j;
    return j;
}

std::uint64_t wall_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bool call_cancelled()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
}

int bounded_timeout_ms(const json& params, int fallback, int max_ms)
{
    int value = params.value("timeout_ms", fallback);
    value = std::max(250, std::min(value, max_ms));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline <= now)
            return 1;
        value = static_cast<int>(std::min<std::uint64_t>(static_cast<std::uint64_t>(value), deadline - now));
    }
    return std::max(1, value);
}

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string upper_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool contains_ci(const std::string& text, const std::string& needle)
{
    if (needle.empty() || text.size() < needle.size())
        return false;
    return lower_copy(text).find(lower_copy(needle)) != std::string::npos;
}

std::string html_escape(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string body_to_string(const std::vector<std::uint8_t>& body)
{
    if (body.empty())
        return {};
    return std::string(reinterpret_cast<const char*>(body.data()), body.size());
}

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80))
        return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

std::vector<std::pair<std::string, std::string>> headers_from_json(const json& src)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (!src.is_object())
        return out;
    for (auto it = src.begin(); it != src.end(); ++it) {
        if (!it.value().is_string())
            continue;
        const std::string name = it.key();
        const std::string value = it.value().get<std::string>();
        if (name.find('\r') != std::string::npos || name.find('\n') != std::string::npos)
            continue;
        if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos)
            continue;
        const std::string lname = lower_copy(name);
        if (lname == "host" || lname == "content-length" || lname == "connection")
            continue;
        out.emplace_back(name, value);
    }
    return out;
}

std::string form_encode_component(const std::string& value)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else if (c == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0x0F]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

std::string params_to_form(const json& params)
{
    if (!params.is_object())
        return {};
    std::string body;
    bool first = true;
    for (auto it = params.begin(); it != params.end(); ++it) {
        if (!first)
            body += "&";
        first = false;
        body += form_encode_component(it.key());
        body += "=";
        if (it.value().is_string())
            body += form_encode_component(it.value().get<std::string>());
        else
            body += form_encode_component(it.value().dump());
    }
    return body;
}

std::vector<std::uint8_t> build_request(const std::string& method,
                                        const std::string& url,
                                        const json& headers_json,
                                        const std::string& body,
                                        const std::string& content_type,
                                        std::string& host,
                                        std::uint16_t& port,
                                        bool& tls,
                                        std::string& error)
{
    std::string scheme;
    std::string path;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "url parse failed";
        return {};
    }
    tls = scheme == "https";
    std::ostringstream req;
    req << upper_copy(method.empty() ? std::string("GET") : method) << " " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    bool has_accept = false;
    bool has_content_type = false;
    for (const auto& h : headers_from_json(headers_json)) {
        if (lower_copy(h.first) == "accept")
            has_accept = true;
        if (lower_copy(h.first) == "content-type")
            has_content_type = true;
        req << h.first << ": " << h.second << "\r\n";
    }
    if (!has_accept)
        req << "Accept: text/html,application/xhtml+xml,application/json,text/plain,*/*\r\n";
    if (!body.empty() && !has_content_type && !content_type.empty())
        req << "Content-Type: " << content_type << "\r\n";
    req << "User-Agent: AiDA-Client-Offensive/1.0\r\n";
    if (!body.empty())
        req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body;
    const std::string raw = req.str();
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

std::optional<exchange_observed_t> send_request(const std::string& method,
                                                const std::string& url,
                                                const json& headers,
                                                const std::string& body,
                                                const std::string& content_type,
                                                int timeout_ms,
                                                bool enforce_scope,
                                                std::string& error)
{
    if (enforce_scope && !scope::in_scope(url)) {
        error = "target out of scope";
        return std::nullopt;
    }
    std::string host;
    std::uint16_t port = 0;
    bool tls = false;
    std::vector<std::uint8_t> raw = build_request(method, url, headers, body, content_type, host, port, tls, error);
    if (raw.empty())
        return std::nullopt;
    audit_http::send_options_t opts;
    opts.timeout_ms = timeout_ms;
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = "offensive_client";
    auto resp = audit_http::send(raw, host, port, tls, opts);
    if (!resp.has_value())
        error = audit_http::last_error();
    return resp;
}

std::string response_header(const exchange_observed_t& ex, const std::string& name)
{
    const std::string lname = lower_copy(name);
    for (const auto& h : ex.resp_headers) {
        if (lower_copy(h.first) == lname)
            return h.second;
    }
    return {};
}

json exchange_summary(const exchange_observed_t& ex)
{
    const std::string body = body_to_string(ex.resp_body);
    json out;
    out["status"] = ex.status_code;
    out["latency_ms"] = ex.latency_ms;
    out["body_length"] = static_cast<std::uint64_t>(ex.resp_body.size());
    out["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(body);
    out["content_type"] = response_header(ex, "Content-Type");
    out["location"] = aida::network::js_analysis_tools::redact_url_for_output(response_header(ex, "Location"));
    out["set_cookie_count"] = 0;
    for (const auto& h : ex.resp_headers) {
        if (lower_copy(h.first) == "set-cookie")
            out["set_cookie_count"] = out["set_cookie_count"].get<int>() + 1;
    }
    return out;
}

client_job_t begin_job(const std::string& action, const std::string& target)
{
    client_job_t job;
    job.id = next_job_id().fetch_add(1);
    job.action = action;
    job.target = target;
    job.started_ms = wall_ms();
    job.running = true;
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
    return job;
}

void finish_job(client_job_t& job, json result)
{
    job.finished_ms = wall_ms();
    job.running = false;
    job.cancelled = call_cancelled() || job.cancelled;
    job.result = std::move(result);
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
}

bool get_job(std::uint64_t id, client_job_t& out)
{
    std::lock_guard<std::mutex> lk(jobs_mtx());
    auto it = jobs().find(id);
    if (it == jobs().end())
        return false;
    out = it->second;
    return true;
}

json job_status_json(const client_job_t& job)
{
    json out;
    out["job_id"] = job.id;
    out["action"] = job.action;
    out["target"] = aida::network::js_analysis_tools::redact_url_for_output(job.target);
    out["started_ms"] = job.started_ms;
    out["finished_ms"] = job.finished_ms;
    out["running"] = job.running;
    out["cancelled"] = job.cancelled;
    out["requests_sent"] = static_cast<std::uint64_t>(job.requests_sent);
    out["requests_failed"] = static_cast<std::uint64_t>(job.requests_failed);
    out["issues_created"] = static_cast<std::uint64_t>(job.issues_created);
    return out;
}

std::uint64_t add_issue(const std::string& type_key,
                        const std::string& name,
                        severity_t severity,
                        confidence_t confidence,
                        const std::string& url,
                        const std::string& parameter,
                        const std::string& description,
                        const json& summary)
{
    issue_store::initialize();
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    audit_http::parse_url(url, scheme, host, port, path);
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.severity = severity;
    issue.confidence = confidence;
    issue.scheme = scheme;
    issue.host = host;
    issue.port = port;
    issue.path = path.empty() ? "/" : path;
    issue.parameter = parameter;
    issue.insertion_point = parameter.empty() ? "client" : "client:" + parameter;
    issue.description = description;
    issue.remediation = "Enforce browser security headers, strict origin validation, CSRF tokens, SameSite cookie policy, and safe client-side parsing for untrusted data.";
    issue.seen_ms = wall_ms();
    evidence_t evidence;
    evidence.request_raw = "url=" + aida::network::js_analysis_tools::redact_url_for_output(url) + " parameter=" + parameter;
    evidence.response_raw = summary.dump();
    evidence.marker = description;
    issue.evidence.push_back(std::move(evidence));
    return issue_store::add(std::move(issue));
}

std::string append_query_param(const std::string& url, const std::string& name, const std::string& value)
{
    std::string out = url;
    const std::size_t hash = out.find('#');
    std::string fragment;
    if (hash != std::string::npos) {
        fragment = out.substr(hash);
        out.erase(hash);
    }
    out += out.find('?') == std::string::npos ? "?" : "&";
    out += form_encode_component(name);
    out += "=";
    out += form_encode_component(value);
    out += fragment;
    return out;
}

bool browser_ready_or_error(json& out)
{
    if (camoufox::ensure_ready())
        return true;
    const auto st = camoufox::get_status();
    out["camoufox_ready"] = false;
    out["bridge_state"] = static_cast<int>(st.state);
    out["child_alive"] = st.child_alive;
    out["browser_open"] = st.browser_open;
    out["page_verified"] = st.page_verified;
    out["last_error"] = st.last_error.empty() ? camoufox::last_error() : st.last_error;
    return false;
}

json status_payload(std::uint64_t job_id)
{
    json out;
    if (job_id != 0) {
        client_job_t job;
        if (!get_job(job_id, job)) {
            out["found"] = false;
            out["job_id"] = job_id;
            return out;
        }
        out["found"] = true;
        out["job"] = job_status_json(job);
        return out;
    }
    json arr = json::array();
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        for (const auto& kv : jobs())
            arr.push_back(job_status_json(kv.second));
    }
    out["count"] = arr.size();
    out["jobs"] = std::move(arr);
    return out;
}

}

tool_result_t csrf_test(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const std::string method = params.value("method", std::string("POST"));
    const bool enforce_scope = params.value("enforce_scope", true);
    json form_params = params.value("params", json::object());
    if (!form_params.is_object())
        form_params = json::object();
    client_job_t job = begin_job("csrf_test", url);
    std::string baseline_body = upper_copy(method) == "GET" ? std::string() : params_to_form(form_params);
    std::string error;
    auto baseline = send_request(method, url, params.value("headers", json::object()), baseline_body,
                                 baseline_body.empty() ? std::string() : std::string("application/x-www-form-urlencoded"),
                                 bounded_timeout_ms(params, 15000, 60000), enforce_scope, error);
    ++job.requests_sent;
    if (!baseline.has_value()) {
        ++job.requests_failed;
        json out{{"job_id", job.id}, {"error", error}};
        finish_job(job, out);
        return tool_result_t::error("baseline request failed", out);
    }
    const std::string token_field = params.value("csrf_token_field", std::string());
    json results = json::array();
    json variants = json::array({"no_referer", "cross_origin_referer", "get_method"});
    if (!token_field.empty()) {
        variants.push_back("remove_token");
        variants.push_back("empty_token");
    }
    int accepted = 0;
    for (const auto& v : variants) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        std::string variant = v.get<std::string>();
        json headers = params.value("headers", json::object());
        json variant_params = form_params;
        std::string variant_method = method;
        if (variant == "cross_origin_referer") {
            headers["Origin"] = "https://attacker.invalid";
            headers["Referer"] = "https://attacker.invalid/";
        } else if (variant == "remove_token" && !token_field.empty()) {
            variant_params.erase(token_field);
        } else if (variant == "empty_token" && !token_field.empty()) {
            variant_params[token_field] = "";
        } else if (variant == "get_method") {
            variant_method = "GET";
        }
        std::string body = upper_copy(variant_method) == "GET" ? std::string() : params_to_form(variant_params);
        std::string send_error;
        auto resp = send_request(variant_method, url, headers, body,
                                 body.empty() ? std::string() : std::string("application/x-www-form-urlencoded"),
                                 bounded_timeout_ms(params, 15000, 60000), enforce_scope, send_error);
        ++job.requests_sent;
        json row;
        row["test_type"] = variant;
        row["ok"] = resp.has_value();
        if (!resp.has_value()) {
            ++job.requests_failed;
            row["error"] = send_error;
        } else {
            row["summary"] = exchange_summary(*resp);
            const bool accepted_like_baseline = resp->status_code >= 200 && resp->status_code < 400 &&
                baseline->status_code >= 200 && baseline->status_code < 400;
            row["accepted_like_baseline"] = accepted_like_baseline;
            if (accepted_like_baseline)
                ++accepted;
        }
        results.push_back(std::move(row));
    }
    json issues = json::array();
    if (accepted > 0) {
        std::uint64_t issue_id = add_issue("client.csrf.accepted-variant",
                                           "Potential CSRF protection weakness",
                                           severity_t::high,
                                           confidence_t::tentative,
                                           url,
                                           token_field,
                                           "One or more CSRF variants produced a successful response comparable to the baseline state-changing request.",
                                           exchange_summary(*baseline));
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["vulnerable"] = accepted > 0;
    out["baseline"] = exchange_summary(*baseline);
    out["test_results"] = std::move(results);
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t clickjacking_test(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const bool enforce_scope = params.value("enforce_scope", true);
    client_job_t job = begin_job("clickjacking_test", url);
    std::string error;
    auto resp = send_request("GET", url, params.value("headers", json::object()), {}, {},
                             bounded_timeout_ms(params, 10000, 45000), enforce_scope, error);
    ++job.requests_sent;
    if (!resp.has_value()) {
        ++job.requests_failed;
        json out{{"job_id", job.id}, {"error", error}};
        finish_job(job, out);
        return tool_result_t::error("request failed", out);
    }
    const std::string xfo = response_header(*resp, "X-Frame-Options");
    const std::string csp = response_header(*resp, "Content-Security-Policy");
    const bool xfo_protects = contains_ci(xfo, "deny") || contains_ci(xfo, "sameorigin");
    const bool csp_has_frame_ancestors = contains_ci(csp, "frame-ancestors");
    const bool csp_protects = csp_has_frame_ancestors && (contains_ci(csp, "'none'") || contains_ci(csp, "'self'") || contains_ci(csp, "https://"));
    const bool vulnerable = !xfo_protects && !csp_protects;
    json issues = json::array();
    if (vulnerable) {
        std::uint64_t issue_id = add_issue("client.clickjacking.missing-frame-policy",
                                           "Clickjacking frame policy missing",
                                           severity_t::medium,
                                           confidence_t::firm,
                                           url,
                                           "headers",
                                           "The response did not include an effective X-Frame-Options or CSP frame-ancestors policy.",
                                           exchange_summary(*resp));
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    const std::string redacted = aida::network::js_analysis_tools::redact_url_for_output(url);
    json out;
    out["job_id"] = job.id;
    out["url"] = redacted;
    out["vulnerable"] = vulnerable;
    out["x_frame_options"] = xfo.empty() ? json(nullptr) : json(xfo);
    out["csp_frame_ancestors_present"] = csp_has_frame_ancestors;
    out["summary"] = exchange_summary(*resp);
    out["issues_created"] = std::move(issues);
    if (params.value("generate_poc", true)) {
        std::ostringstream poc;
        poc << "<!doctype html><meta charset=\"utf-8\"><title>AiDA Clickjacking PoC</title><style>iframe{position:absolute;inset:0;width:100%;height:100%;opacity:.15}button{position:absolute;top:40%;left:40%;z-index:2}</style><iframe src=\""
            << html_escape(redacted) << "\"></iframe><button>Continue</button>";
        out["poc_html"] = poc.str();
        out["poc_target_redacted"] = true;
    }
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t postmessage_scan(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    if (params.value("enforce_scope", true) && !scope::in_scope(url))
        return tool_result_t::error("target out of scope");
    client_job_t job = begin_job("postmessage_scan", url);
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    if (!browser_ready_or_error(out)) {
        finish_job(job, out);
        return tool_result_t::error("Camoufox bridge not ready", out);
    }
    const char* hook_js =
        "(() => {"
        "if (!window.__aidaPmLog) {"
        "window.__aidaPmLog = [];"
        "const original = EventTarget.prototype.addEventListener;"
        "EventTarget.prototype.addEventListener = function(type, listener, options) {"
        "if (type === 'message') {"
        "let source = '';"
        "try { source = String(listener); } catch (e) {}"
        "window.__aidaPmLog.push({length: source.length, origin_check: /origin|isTrusted|source/.test(source), sinks: {location: /location\\s*[.=]/.test(source), eval: /\\beval\\s*\\(/.test(source), html: /innerHTML|outerHTML|insertAdjacentHTML/.test(source), fetch: /\\bfetch\\s*\\(/.test(source), storage: /localStorage|sessionStorage/.test(source)}});"
        "}"
        "return original.apply(this, arguments);"
        "};"
        "}"
        "return true;"
        "})()";
    camoufox::add_init_script(hook_js);
    const bool nav = camoufox::navigate(url, "domcontentloaded", bounded_timeout_ms(params, 30000, 60000));
    if (!nav) {
        out["error"] = camoufox::last_error();
        finish_job(job, out);
        return tool_result_t::error("Camoufox navigation failed", out);
    }
    if (params.value("inject_payloads", true)) {
        camoufox::evaluate_js("window.postMessage({aida:'probe',url:'javascript:alert(1)',html:'<img src=x onerror=alert(1)>'}, '*')", true);
    }
    auto observed = camoufox::evaluate_js("(() => window.__aidaPmLog || [])()", true);
    json listeners = observed.ok ? observed.data : json::array();
    bool vulnerable = false;
    if (listeners.is_array()) {
        for (const auto& item : listeners) {
            if (!item.is_object())
                continue;
            const bool origin_check = item.value("origin_check", false);
            const json sinks = item.value("sinks", json::object());
            if (!origin_check && sinks.is_object()) {
                for (auto it = sinks.begin(); it != sinks.end(); ++it) {
                    if (it.value().is_boolean() && it.value().get<bool>())
                        vulnerable = true;
                }
            }
        }
    }
    json issues = json::array();
    if (vulnerable) {
        std::uint64_t issue_id = add_issue("client.postmessage.missing-origin-check",
                                           "postMessage listener lacks origin validation",
                                           severity_t::high,
                                           confidence_t::tentative,
                                           url,
                                           "postMessage",
                                           "Camoufox observed message listeners with sensitive sinks and no origin validation indicators.",
                                           json{{"listeners", listeners}});
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    out["listeners_found"] = listeners.is_array() ? listeners : json::array();
    out["vulnerable"] = vulnerable;
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t prototype_pollution(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    if (params.value("enforce_scope", true) && !scope::in_scope(url))
        return tool_result_t::error("target out of scope");
    client_job_t job = begin_job("prototype_pollution", url);
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    if (!browser_ready_or_error(out)) {
        finish_job(job, out);
        return tool_result_t::error("Camoufox bridge not ready", out);
    }
    const std::string marker = "aida_polluted_" + std::to_string(job.id);
    std::vector<std::string> payload_urls = {
        append_query_param(url, "__proto__[aidaPolluted]", marker),
        append_query_param(url, "constructor[prototype][aidaPolluted]", marker),
        append_query_param(url, "__proto__.aidaPolluted", marker)
    };
    json attempts = json::array();
    bool verified = false;
    for (const std::string& probe_url : payload_urls) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        const bool nav = camoufox::navigate(probe_url, "domcontentloaded", bounded_timeout_ms(params, 30000, 60000));
        json row;
        row["url"] = aida::network::js_analysis_tools::redact_url_for_output(probe_url);
        row["navigated"] = nav;
        if (nav) {
            auto eval = camoufox::evaluate_js("(() => String(({}).aidaPolluted || Object.prototype.aidaPolluted || ''))()", true);
            row["eval_ok"] = eval.ok;
            row["verified"] = eval.ok && eval.data.is_string() && eval.data.get<std::string>() == marker;
            if (row["verified"].get<bool>())
                verified = true;
        } else {
            row["error"] = camoufox::last_error();
        }
        attempts.push_back(std::move(row));
        if (verified)
            break;
    }
    json issues = json::array();
    if (verified) {
        std::uint64_t issue_id = add_issue("client.prototype-pollution.verified",
                                           "Client-side prototype pollution verified",
                                           severity_t::high,
                                           confidence_t::firm,
                                           url,
                                           "prototype",
                                           "Camoufox verified Object prototype pollution after URL parameter injection.",
                                           json{{"marker_sha256", aida::network::js_analysis_tools::sha256_hex(marker)}});
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    out["verified_via_browser"] = verified;
    out["attempts"] = std::move(attempts);
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t dom_clobbering(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    if (params.value("enforce_scope", true) && !scope::in_scope(url))
        return tool_result_t::error("target out of scope");
    client_job_t job = begin_job("dom_clobbering", url);
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    if (!browser_ready_or_error(out)) {
        finish_job(job, out);
        return tool_result_t::error("Camoufox bridge not ready", out);
    }
    const bool nav = camoufox::navigate(url, "domcontentloaded", bounded_timeout_ms(params, 15000, 60000));
    if (!nav) {
        out["error"] = camoufox::last_error();
        finish_job(job, out);
        return tool_result_t::error("Camoufox navigation failed", out);
    }
    const char* js =
        "(() => {"
        "const risky = new Set(['location','name','onload','constructor','prototype','submit','action','contentWindow','frames','parent','top']);"
        "const counts = {};"
        "const findings = [];"
        "for (const el of Array.from(document.querySelectorAll('[id],[name]')).slice(0,1000)) {"
        "const vals = [];"
        "if (el.id) vals.push(['id', el.id]);"
        "if (el.getAttribute('name')) vals.push(['name', el.getAttribute('name')]);"
        "for (const pair of vals) {"
        "const key = String(pair[1]);"
        "counts[key] = (counts[key] || 0) + 1;"
        "if (risky.has(key) || counts[key] > 1) findings.push({attribute: pair[0], name: key, tag: el.tagName.toLowerCase(), duplicate_count: counts[key], risky_name: risky.has(key)});"
        "}"
        "}"
        "return {checked: Object.keys(counts).length, findings: findings.slice(0,64)};"
        "})()";
    auto eval = camoufox::evaluate_js(js, true);
    if (!eval.ok) {
        out["error"] = eval.error.empty() ? eval.text : eval.error;
        finish_job(job, out);
        return tool_result_t::error("DOM clobbering analysis failed", out);
    }
    json data = eval.data.is_object() ? eval.data : json::object();
    const bool vulnerable = data.contains("findings") && data["findings"].is_array() && !data["findings"].empty();
    json issues = json::array();
    if (vulnerable) {
        std::uint64_t issue_id = add_issue("client.dom-clobbering.candidates",
                                           "DOM clobbering candidates observed",
                                           severity_t::medium,
                                           confidence_t::tentative,
                                           url,
                                           "dom",
                                           "Camoufox observed duplicate or risky id/name attributes that may clobber DOM globals.",
                                           data);
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    out["vulnerable"] = vulnerable;
    out["analysis"] = data;
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t cors_exploit(const json& params)
{
    const std::string url = params.value("url", std::string());
    if (url.empty())
        return tool_result_t::error("url required");
    const bool enforce_scope = params.value("enforce_scope", true);
    client_job_t job = begin_job("cors_exploit", url);
    std::vector<std::string> origins = {"https://attacker.invalid", "null", "https://sub.attacker.invalid"};
    const auto custom = params.value("origins", json::array());
    if (custom.is_array()) {
        origins.clear();
        for (const auto& item : custom) {
            if (item.is_string() && origins.size() < 12)
                origins.push_back(item.get<std::string>());
        }
    }
    json results = json::array();
    bool vulnerable = false;
    for (const std::string& origin : origins) {
        if (call_cancelled()) {
            job.cancelled = true;
            break;
        }
        json headers = params.value("headers", json::object());
        headers["Origin"] = origin;
        std::string error;
        auto resp = send_request(params.value("method", std::string("GET")), url, headers, params.value("body", std::string()),
                                 params.value("content_type", std::string()), bounded_timeout_ms(params, 15000, 60000),
                                 enforce_scope, error);
        ++job.requests_sent;
        json row;
        row["origin"] = origin == "null" ? json("null") : json(aida::network::js_analysis_tools::redact_url_for_output(origin));
        row["ok"] = resp.has_value();
        if (!resp.has_value()) {
            ++job.requests_failed;
            row["error"] = error;
        } else {
            const std::string acao = response_header(*resp, "Access-Control-Allow-Origin");
            const std::string acac = response_header(*resp, "Access-Control-Allow-Credentials");
            const bool reflected = lower_copy(acao) == lower_copy(origin) || (acao == "*" && lower_copy(acac) == "true");
            row["access_control_allow_origin"] = acao.empty() ? json(nullptr) : json(acao);
            row["access_control_allow_credentials"] = acac.empty() ? json(nullptr) : json(acac);
            row["reflected_or_wildcard_credentialed"] = reflected;
            row["summary"] = exchange_summary(*resp);
            if (reflected)
                vulnerable = true;
        }
        results.push_back(std::move(row));
    }
    json issues = json::array();
    if (vulnerable) {
        std::uint64_t issue_id = add_issue("client.cors.exploitable-policy",
                                           "Potentially exploitable CORS policy",
                                           severity_t::high,
                                           confidence_t::firm,
                                           url,
                                           "Origin",
                                           "The endpoint reflected an arbitrary Origin or combined wildcard ACAO with credentials.",
                                           json{{"results", results}});
        issues.push_back(issue_id);
        job.issues_created = 1;
    }
    json out;
    out["job_id"] = job.id;
    out["url"] = aida::network::js_analysis_tools::redact_url_for_output(url);
    out["vulnerable"] = vulnerable;
    out["test_results"] = std::move(results);
    out["issues_created"] = std::move(issues);
    finish_job(job, out);
    return tool_result_t::ok(out);
}

tool_result_t get_status(const json& params)
{
    return tool_result_t::ok(status_payload(params.value("job_id", 0ull)));
}

tool_result_t get_results(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    client_job_t job;
    if (!get_job(job_id, job))
        return tool_result_t::error("job not found");
    json out = job.result;
    out["job"] = job_status_json(job);
    return tool_result_t::ok(out);
}

}
}
}
}
