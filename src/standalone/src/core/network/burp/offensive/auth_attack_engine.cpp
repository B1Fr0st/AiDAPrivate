#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "auth_attack_engine.hpp"

#include "../audit_http.hpp"
#include "../auth_lab.hpp"
#include "../cookie_jar.hpp"
#include "../issue.hpp"
#include "../payload_library.hpp"
#include "../../../mcp/mcp_standalone.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <numeric>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace auth_attack {

namespace {

using json = nlohmann::json;

constexpr size_t kMaxAuthAttempts = 10000;
constexpr size_t kMaxCredentialPairs = 10000;
constexpr size_t kMaxSessionSamples = 1000;
constexpr size_t kMaxIdTests = 250;
constexpr size_t kMaxPolicyTests = 64;
constexpr int kDefaultRequestTimeoutMs = 15000;

struct target_t
{
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;
    bool tls = false;
};

struct send_result_t
{
    bool ok = false;
    exchange_observed_t exchange;
    std::string error;
};

struct job_record_t
{
    std::string id;
    std::string action;
    uint64_t started_ms = 0;
    uint64_t finished_ms = 0;
    size_t total = 0;
    size_t completed = 0;
    bool running = false;
    bool cancelled = false;
    bool error = false;
    std::string error_message;
    json result = json::object();
};

std::mutex& jobs_mutex()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, job_record_t>& jobs()
{
    static std::unordered_map<std::string, job_record_t> v;
    return v;
}

uint64_t now_unix_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bool call_cancelled()
{
    const uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return mcp_standalone::current_call_cancelled() || (deadline != 0 && GetTickCount64() >= deadline);
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim_ascii(const std::string& s)
{
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

bool equals_ci(const std::string& a, const std::string& b)
{
    return lower_ascii(a) == lower_ascii(b);
}

bool contains_ci(const std::string& h, const std::string& n)
{
    if (n.empty() || h.size() < n.size()) return false;
    return lower_ascii(h).find(lower_ascii(n)) != std::string::npos;
}

uint64_t fnv1a(const uint8_t* data, size_t len)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t fnv1a_string(const std::string& s)
{
    return fnv1a(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string hex64(uint64_t v)
{
    std::ostringstream os;
    os << std::hex << std::setfill('0') << std::setw(16) << v;
    return os.str();
}

json secret_summary(const std::string& value)
{
    json out;
    out["redacted"] = true;
    out["length"] = value.size();
    out["fingerprint"] = hex64(fnv1a_string(value));
    return out;
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    for (const auto& h : headers) {
        if (equals_ci(h.first, name)) return h.second;
    }
    return {};
}

std::string body_text(const std::vector<uint8_t>& body, size_t limit = 65536)
{
    const size_t n = std::min(body.size(), limit);
    return std::string(reinterpret_cast<const char*>(body.data()), n);
}

std::vector<std::string> set_cookie_names(const exchange_observed_t& e)
{
    std::vector<std::string> out;
    for (const auto& h : e.resp_headers) {
        if (!equals_ci(h.first, "Set-Cookie")) continue;
        const size_t eq = h.second.find('=');
        if (eq == std::string::npos) continue;
        const std::string name = trim_ascii(h.second.substr(0, eq));
        if (!name.empty()) out.push_back(name);
    }
    return out;
}

json response_summary(const exchange_observed_t& e)
{
    json out;
    out["status_code"] = e.status_code;
    out["latency_ms"] = e.latency_ms;
    out["body_length"] = e.resp_body.size();
    out["body_fingerprint"] = hex64(fnv1a(e.resp_body.data(), e.resp_body.size()));
    out["set_cookie_names"] = set_cookie_names(e);
    const std::string location = header_value(e.resp_headers, "Location");
    if (!location.empty()) {
        out["location_length"] = location.size();
        out["location_fingerprint"] = hex64(fnv1a_string(location));
    }
    return out;
}

json ok_data(json data)
{
    data["success"] = true;
    return data;
}

result_t ok_result(const std::string& message, json data)
{
    return result_t{true, message, ok_data(std::move(data)), {}};
}

result_t error_result(const std::string& message, const std::string& code = "invalid_param", json data = json::object())
{
    data["success"] = false;
    data["code"] = code;
    return result_t{false, message, std::move(data), code};
}

std::string json_string_value(const json& v)
{
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_integer()) return std::to_string(v.get<long long>());
    if (v.is_number_unsigned()) return std::to_string(v.get<unsigned long long>());
    if (v.is_number_float()) {
        std::ostringstream os;
        os << v.get<double>();
        return os.str();
    }
    if (v.is_null()) return "null";
    return v.dump();
}

std::string get_string(const json& p, const char* key, const std::string& def = {})
{
    if (!p.contains(key)) return def;
    if (p[key].is_string()) return p[key].get<std::string>();
    return json_string_value(p[key]);
}

bool get_bool(const json& p, const char* key, bool def)
{
    if (!p.contains(key)) return def;
    if (p[key].is_boolean()) return p[key].get<bool>();
    if (p[key].is_number_integer()) return p[key].get<int>() != 0;
    if (p[key].is_string()) {
        const std::string v = lower_ascii(p[key].get<std::string>());
        return v == "1" || v == "true" || v == "yes";
    }
    return def;
}

size_t get_size(const json& p, const char* key, size_t def, size_t min_v, size_t max_v)
{
    if (!p.contains(key) || !p[key].is_number()) return def;
    long long v = p[key].get<long long>();
    if (v < static_cast<long long>(min_v)) v = static_cast<long long>(min_v);
    if (v > static_cast<long long>(max_v)) v = static_cast<long long>(max_v);
    return static_cast<size_t>(v);
}

int get_int(const json& p, const char* key, int def, int min_v, int max_v)
{
    if (!p.contains(key) || !p[key].is_number()) return def;
    int v = p[key].get<int>();
    if (v < min_v) v = min_v;
    if (v > max_v) v = max_v;
    return v;
}

std::vector<std::string> string_array(const json& p, const char* key)
{
    std::vector<std::string> out;
    if (!p.contains(key) || !p[key].is_array()) return out;
    for (const auto& v : p[key]) {
        std::string s = json_string_value(v);
        if (!s.empty()) out.push_back(std::move(s));
    }
    return out;
}

std::map<std::string, std::string> string_map_from_object(const json& obj)
{
    std::map<std::string, std::string> out;
    if (!obj.is_object()) return out;
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        out[it.key()] = json_string_value(it.value());
    }
    return out;
}

std::map<std::string, std::string> extra_params(const json& p)
{
    std::map<std::string, std::string> out;
    if (p.contains("extra_params") && p["extra_params"].is_object()) {
        out = string_map_from_object(p["extra_params"]);
    }
    if (p.contains("params") && p["params"].is_object()) {
        auto more = string_map_from_object(p["params"]);
        out.insert(more.begin(), more.end());
    }
    return out;
}

std::string percent_encode(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else if (c == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string form_body(const std::map<std::string, std::string>& params)
{
    std::string body;
    bool first = true;
    for (const auto& kv : params) {
        if (!first) body.push_back('&');
        first = false;
        body += percent_encode(kv.first);
        body.push_back('=');
        body += percent_encode(kv.second);
    }
    return body;
}

std::string json_body(const std::map<std::string, std::string>& params)
{
    json j = json::object();
    for (const auto& kv : params) j[kv.first] = kv.second;
    return j.dump();
}

std::string authority(const target_t& t)
{
    std::string out = t.host;
    const bool default_port = (t.tls && t.port == 443) || (!t.tls && t.port == 80);
    if (!default_port) {
        out.push_back(':');
        out += std::to_string(static_cast<unsigned>(t.port));
    }
    return out;
}

bool parse_target(const std::string& url, target_t& out, std::string& err)
{
    if (!audit_http::parse_url(url, out.scheme, out.host, out.port, out.path)) {
        err = "invalid url";
        return false;
    }
    if (out.scheme != "http" && out.scheme != "https") {
        err = "only http and https URLs are supported";
        return false;
    }
    out.tls = out.scheme == "https";
    if (out.path.empty()) out.path = "/";
    return true;
}

void add_or_replace_query_param(std::string& path, const std::string& key, const std::string& value)
{
    std::string fragment;
    const size_t hash = path.find('#');
    if (hash != std::string::npos) {
        fragment = path.substr(hash);
        path.erase(hash);
    }
    const std::string enc_key = percent_encode(key);
    const std::string enc_value = percent_encode(value);
    size_t q = path.find('?');
    if (q == std::string::npos) {
        path.push_back('?');
        path += enc_key;
        path.push_back('=');
        path += enc_value;
        path += fragment;
        return;
    }
    std::string base = path.substr(0, q + 1);
    std::string query = path.substr(q + 1);
    std::vector<std::string> parts;
    size_t pos = 0;
    bool replaced = false;
    while (pos <= query.size()) {
        const size_t amp = query.find('&', pos);
        std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        const size_t eq = part.find('=');
        const std::string name = eq == std::string::npos ? part : part.substr(0, eq);
        if (name == enc_key || name == key) {
            parts.push_back(enc_key + "=" + enc_value);
            replaced = true;
        } else if (!part.empty()) {
            parts.push_back(part);
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    if (!replaced) parts.push_back(enc_key + "=" + enc_value);
    path = base;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) path.push_back('&');
        path += parts[i];
    }
    path += fragment;
}

std::string with_target_param_path(const std::string& path, const std::string& param, const std::string& value)
{
    std::string out = path.empty() ? "/" : path;
    const std::string braced = "{" + param + "}";
    const std::string colon = ":" + param;
    size_t p = out.find(braced);
    if (p != std::string::npos) {
        out.replace(p, braced.size(), percent_encode(value));
        return out;
    }
    p = out.find(colon);
    if (p != std::string::npos) {
        out.replace(p, colon.size(), percent_encode(value));
        return out;
    }
    add_or_replace_query_param(out, param, value);
    return out;
}

std::map<std::string, std::string> header_map_from_json(const json& p)
{
    std::map<std::string, std::string> headers;
    if (!p.contains("headers") || !p["headers"].is_object()) return headers;
    for (auto it = p["headers"].begin(); it != p["headers"].end(); ++it) {
        std::string name = it.key();
        std::string value = json_string_value(it.value());
        name.erase(std::remove_if(name.begin(), name.end(), [](char c) { return c == '\r' || c == '\n' || c == ':'; }), name.end());
        value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
        value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
        if (!name.empty()) headers[name] = value;
    }
    return headers;
}

std::vector<uint8_t> build_request(const target_t& target,
                                   const std::string& method_in,
                                   std::string path,
                                   std::map<std::string, std::string> params,
                                   const std::string& body_mode,
                                   std::map<std::string, std::string> headers,
                                   const std::string& authorization,
                                   bool include_cookie_jar)
{
    std::string method = method_in.empty() ? "GET" : method_in;
    std::transform(method.begin(), method.end(), method.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    std::string body;
    std::string content_type;
    if (method == "GET" || method == "HEAD") {
        for (const auto& kv : params) add_or_replace_query_param(path, kv.first, kv.second);
    } else if (body_mode == "json" || body_mode == "jwt") {
        body = json_body(params);
        content_type = "application/json";
    } else {
        body = form_body(params);
        content_type = "application/x-www-form-urlencoded";
    }
    std::ostringstream req;
    req << method << ' ' << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << authority(target) << "\r\n";
    req << "User-Agent: AiDA-Offensive-Auth\r\n";
    req << "Accept: */*\r\n";
    if (!authorization.empty()) req << "Authorization: " << authorization << "\r\n";
    if (include_cookie_jar) {
        const std::string cookies = cookie_jar::build_cookie_header(target.host, target.path, target.tls);
        if (!cookies.empty()) req << "Cookie: " << cookies << "\r\n";
    }
    for (const auto& h : headers) req << h.first << ": " << h.second << "\r\n";
    if (!body.empty() || (method != "GET" && method != "HEAD")) {
        if (!content_type.empty() && headers.find("Content-Type") == headers.end()) req << "Content-Type: " << content_type << "\r\n";
        req << "Content-Length: " << body.size() << "\r\n";
    }
    req << "Connection: close\r\n\r\n";
    req << body;
    const std::string raw = req.str();
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

send_result_t send_raw_request(const target_t& target,
                               const std::vector<uint8_t>& raw,
                               int timeout_ms,
                               bool follow_redirects = false)
{
    audit_http::send_options_t options;
    options.timeout_ms = timeout_ms;
    options.follow_redirects = follow_redirects;
    options.max_redirects = 3;
    options.enforce_scope = true;
    options.publish_exchange = false;
    options.exchange_source = "offensive_auth";
    auto sent = audit_http::send(raw, target.host, target.port, target.tls, options);
    if (!sent) {
        return send_result_t{false, {}, audit_http::last_error()};
    }
    cookie_jar::ingest_set_cookie_headers(target.host, sent->resp_headers);
    return send_result_t{true, *sent, {}};
}

send_result_t send_param_request(const std::string& url,
                                 const std::string& method,
                                 const std::map<std::string, std::string>& params,
                                 const std::string& body_mode,
                                 const std::map<std::string, std::string>& headers,
                                 const std::string& bearer_or_authorization,
                                 int timeout_ms)
{
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return send_result_t{false, {}, err};
    std::string authz;
    if (!bearer_or_authorization.empty()) {
        authz = bearer_or_authorization.rfind("Bearer ", 0) == 0 || bearer_or_authorization.rfind("Basic ", 0) == 0
              ? bearer_or_authorization
              : auth_lab::bearer_header(bearer_or_authorization);
    }
    const auto raw = build_request(target, method, target.path, params, body_mode, headers, authz, true);
    return send_raw_request(target, raw, timeout_ms, false);
}

std::string build_attempt_authorization(const std::string& auth_type,
                                        const std::string& username,
                                        const std::string& password,
                                        const json& p)
{
    if (auth_type == "basic") return "Basic " + auth_lab::basic_encode(username, password);
    if (auth_type == "bearer") {
        const std::string token = get_string(p, "token");
        if (!token.empty()) return auth_lab::bearer_header(token);
    }
    return {};
}

bool indicator_matches(const json& indicator, const exchange_observed_t& e)
{
    if (!indicator.is_object()) return false;
    const std::string type = lower_ascii(get_string(indicator, "type"));
    const std::string value = get_string(indicator, "value");
    if (type == "status_code") {
        int expected = 0;
        try { expected = std::stoi(value); } catch (...) { return false; }
        return e.status_code == expected;
    }
    if (type == "redirect") {
        if (e.status_code < 300 || e.status_code >= 400) return false;
        const std::string loc = header_value(e.resp_headers, "Location");
        return value.empty() || contains_ci(loc, value);
    }
    if (type == "body_contains") {
        return contains_ci(body_text(e.resp_body), value);
    }
    if (type == "body_not_contains") {
        return !contains_ci(body_text(e.resp_body), value);
    }
    if (type == "cookie_set") {
        const auto names = set_cookie_names(e);
        if (value.empty()) return !names.empty();
        for (const auto& name : names) {
            if (equals_ci(name, value)) return true;
        }
        return false;
    }
    if (type == "response_size") {
        if (value.empty()) return false;
        const size_t size = e.resp_body.size();
        try {
            if (value[0] == '>') return size > static_cast<size_t>(std::stoull(value.substr(1)));
            if (value[0] == '<') return size < static_cast<size_t>(std::stoull(value.substr(1)));
            return size == static_cast<size_t>(std::stoull(value));
        } catch (...) {
            return false;
        }
    }
    return false;
}

bool body_has_auth_failure_terms(const exchange_observed_t& e)
{
    const std::string b = lower_ascii(body_text(e.resp_body));
    static const char* terms[] = {
        "invalid", "incorrect", "failed", "failure", "denied", "unauthorized",
        "forbidden", "locked", "captcha", "rate limit", "too many", "mfa",
        "two-factor", "2fa", "otp", "verification code"
    };
    for (const char* term : terms) {
        if (b.find(term) != std::string::npos) return true;
    }
    return false;
}

bool likely_auth_success(const exchange_observed_t& e, const json& success_indicator, const json& failure_indicator)
{
    if (failure_indicator.is_object() && indicator_matches(failure_indicator, e)) return false;
    if (success_indicator.is_object()) return indicator_matches(success_indicator, e);
    if (e.status_code == 401 || e.status_code == 403 || e.status_code == 429) return false;
    if (e.status_code >= 300 && e.status_code < 400) return true;
    if (e.status_code >= 200 && e.status_code < 300 && !body_has_auth_failure_terms(e)) {
        const auto names = set_cookie_names(e);
        for (const auto& name : names) {
            const std::string n = lower_ascii(name);
            if (n.find("session") != std::string::npos || n.find("auth") != std::string::npos || n.find("token") != std::string::npos) return true;
        }
        return e.resp_body.size() > 0;
    }
    return false;
}

std::string start_job(const std::string& action, size_t total)
{
    static std::atomic<uint64_t> next_id{1};
    const uint64_t n = next_id.fetch_add(1);
    std::string id = "auth_" + std::to_string(now_unix_ms()) + "_" + std::to_string(n);
    job_record_t rec;
    rec.id = id;
    rec.action = action;
    rec.started_ms = now_unix_ms();
    rec.total = total;
    rec.running = true;
    {
        std::lock_guard<std::mutex> lk(jobs_mutex());
        auto& m = jobs();
        if (m.size() > 64) {
            std::vector<std::string> keys;
            keys.reserve(m.size());
            for (const auto& kv : m) keys.push_back(kv.first);
            std::sort(keys.begin(), keys.end());
            for (size_t i = 0; i < keys.size() && m.size() > 48; ++i) m.erase(keys[i]);
        }
        m[id] = std::move(rec);
    }
    return id;
}

void update_job_progress(const std::string& id, size_t completed)
{
    std::lock_guard<std::mutex> lk(jobs_mutex());
    auto it = jobs().find(id);
    if (it != jobs().end()) it->second.completed = completed;
}

void finish_job(const std::string& id, json result, size_t completed, bool cancelled, const std::string& error)
{
    std::lock_guard<std::mutex> lk(jobs_mutex());
    auto it = jobs().find(id);
    if (it == jobs().end()) return;
    it->second.completed = completed;
    it->second.running = false;
    it->second.cancelled = cancelled;
    it->second.error = !error.empty();
    it->second.error_message = error;
    it->second.finished_ms = now_unix_ms();
    it->second.result = std::move(result);
}

json job_status_json(const job_record_t& rec)
{
    json out;
    out["task_id"] = rec.id;
    out["action"] = rec.action;
    out["running"] = rec.running;
    out["cancelled"] = rec.cancelled;
    out["error"] = rec.error;
    out["error_message"] = rec.error_message;
    out["started_ms"] = rec.started_ms;
    out["finished_ms"] = rec.finished_ms;
    out["total"] = rec.total;
    out["completed"] = rec.completed;
    return out;
}

json all_status_json()
{
    json arr = json::array();
    std::lock_guard<std::mutex> lk(jobs_mutex());
    for (const auto& kv : jobs()) arr.push_back(job_status_json(kv.second));
    return arr;
}

std::vector<std::string> payload_entries_with_fallback(const std::string& primary,
                                                       const std::string& fallback,
                                                       size_t max_count)
{
    payloads::initialize();
    std::vector<std::string> out = payloads::entries(primary, max_count);
    if (out.empty() && primary != fallback) out = payloads::entries(fallback, max_count);
    if (out.size() > max_count) out.resize(max_count);
    return out;
}

std::vector<std::pair<std::string, std::string>> credential_pairs_from_payload(const json& p, size_t max_count)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (p.contains("credential_pairs") && p["credential_pairs"].is_array()) {
        for (const auto& item : p["credential_pairs"]) {
            if (!item.is_object()) continue;
            std::string u = get_string(item, "username");
            std::string pw = get_string(item, "password");
            if (u.empty() && item.contains("user")) u = get_string(item, "user");
            if (u.empty() || pw.empty()) continue;
            out.emplace_back(std::move(u), std::move(pw));
            if (out.size() >= max_count) return out;
        }
    }
    if (p.contains("credential_file_b64") && p["credential_file_b64"].is_string() && out.size() < max_count) {
        std::string decoded;
        if (auth_lab::base64_decode_std(p["credential_file_b64"].get<std::string>(), decoded)) {
            std::istringstream is(decoded);
            std::string line;
            while (std::getline(is, line) && out.size() < max_count) {
                line = trim_ascii(line);
                if (line.empty()) continue;
                const size_t sep = line.find(':');
                if (sep == std::string::npos) continue;
                std::string u = line.substr(0, sep);
                std::string pw = line.substr(sep + 1);
                if (!u.empty() && !pw.empty()) out.emplace_back(std::move(u), std::move(pw));
            }
        }
    }
    return out;
}

bool refresh_csrf_token(const json& p, const std::string& login_url, const std::string& field, std::string& token)
{
    if (field.empty()) return true;
    const std::string token_url = get_string(p, "csrf_token_url", login_url);
    target_t target;
    std::string err;
    if (!parse_target(token_url, target, err)) return false;
    std::map<std::string, std::string> headers = header_map_from_json(p);
    const auto raw = build_request(target, "GET", target.path, {}, "form", headers, {}, true);
    auto sent = send_raw_request(target, raw, get_int(p, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000), false);
    if (!sent.ok) return false;
    const std::string body = body_text(sent.exchange.resp_body, 262144);
    const std::string escaped = std::regex_replace(field, std::regex(R"([.^$|()\\[\]{}*+?])"), R"(\\$&)");
    const std::regex value_re("name=[\"']" + escaped + "[\"'][^>]*value=[\"']([^\"']+)[\"']", std::regex::icase);
    std::smatch m;
    if (std::regex_search(body, m, value_re) && m.size() > 1) {
        token = m[1].str();
        return true;
    }
    const auto cookies = cookie_jar::list_for_host(target.host);
    for (const auto& c : cookies) {
        if (equals_ci(c.name, field)) {
            token = c.value;
            return true;
        }
    }
    return false;
}

uint64_t add_issue(const std::string& type_key,
                   const std::string& name,
                   severity_t severity,
                   confidence_t confidence,
                   const target_t& target,
                   const std::string& path,
                   const std::string& parameter,
                   const std::string& description,
                   const std::string& remediation,
                   const std::vector<std::string>& cwe,
                   const std::string& evidence)
{
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.severity = severity;
    iss.confidence = confidence;
    iss.scheme = target.scheme;
    iss.host = target.host;
    iss.port = target.port;
    iss.path = path;
    iss.parameter = parameter;
    iss.description = description;
    iss.remediation = remediation;
    iss.cwe = cwe;
    evidence_t ev;
    ev.marker = evidence;
    ev.request_raw = "sanitized offensive auth evidence";
    ev.response_raw = evidence;
    iss.evidence.push_back(std::move(ev));
    return issue_store::add(std::move(iss));
}

std::string auth_type_from_payload(const json& p)
{
    std::string auth_type = lower_ascii(get_string(p, "auth_type", "form"));
    if (auth_type != "form" && auth_type != "basic" && auth_type != "json" && auth_type != "jwt" && auth_type != "bearer") auth_type = "form";
    return auth_type;
}

send_result_t send_login_attempt(const json& p,
                                 const std::string& username,
                                 const std::string& password,
                                 const std::string& csrf_token)
{
    target_t target;
    std::string err;
    const std::string url = get_string(p, "url");
    if (!parse_target(url, target, err)) return send_result_t{false, {}, err};
    std::string method = get_string(p, "method", "POST");
    std::map<std::string, std::string> params = extra_params(p);
    const std::string auth_type = auth_type_from_payload(p);
    if (auth_type != "basic") {
        const std::string username_field = get_string(p, "username_field", "username");
        const std::string password_field = get_string(p, "password_field", "password");
        if (!username_field.empty()) params[username_field] = username;
        if (!password_field.empty()) params[password_field] = password;
    }
    const std::string csrf_field = get_string(p, "csrf_token_field");
    if (!csrf_field.empty() && !csrf_token.empty()) params[csrf_field] = csrf_token;
    std::map<std::string, std::string> headers = header_map_from_json(p);
    const std::string authz = build_attempt_authorization(auth_type, username, password, p);
    const std::string body_mode = (auth_type == "json" || auth_type == "jwt") ? "json" : "form";
    const auto raw = build_request(target, method, target.path, params, body_mode, headers, authz, true);
    return send_raw_request(target, raw, get_int(p, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000), false);
}

json credential_hit_json(const std::string& username,
                         const std::string& password,
                         size_t attempt_number,
                         const exchange_observed_t& e)
{
    json hit;
    hit["username_summary"] = secret_summary(username);
    hit["password_summary"] = secret_summary(password);
    hit["attempt_number"] = attempt_number;
    hit["response"] = response_summary(e);
    return hit;
}

result_t run_credential_attempts(const std::string& action,
                                 const json& p,
                                 const std::vector<std::pair<std::string, std::string>>& pairs,
                                 size_t requested_total)
{
    if (get_string(p, "url").empty()) return error_result("Missing url", "missing_param");
    const size_t total = std::min(requested_total, pairs.size());
    if (total == 0) return error_result("No credential attempts available after applying bounds", "empty_input");
    const std::string task_id = start_job(action, total);
    const json success_indicator = p.contains("success_indicator") ? p["success_indicator"] : json();
    const json failure_indicator = p.contains("failure_indicator") ? p["failure_indicator"] : json();
    const bool stop_on_first = get_bool(p, "stop_on_first_success", action == "brute_force");
    const int requested_rate = get_int(p, "rate_limit_ms", action == "credential_stuffing" ? 100 : 50, 0, 60000);
    const int effective_rate = total > 20 ? std::max(requested_rate, 50) : requested_rate;
    const std::string csrf_field = get_string(p, "csrf_token_field");
    json successes = json::array();
    json attempts = json::array();
    bool rate_limited = false;
    bool cancelled = false;
    size_t completed = 0;
    for (size_t i = 0; i < total; ++i) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::string csrf_token;
        if (!csrf_field.empty() && !refresh_csrf_token(p, get_string(p, "url"), csrf_field, csrf_token)) {
            json miss;
            miss["attempt_number"] = completed + 1;
            miss["status"] = "csrf_refresh_failed";
            attempts.push_back(std::move(miss));
            ++completed;
            update_job_progress(task_id, completed);
            continue;
        }
        const auto sent = send_login_attempt(p, pairs[i].first, pairs[i].second, csrf_token);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok) {
            json item;
            item["attempt_number"] = completed;
            item["transport_error"] = sent.error;
            attempts.push_back(std::move(item));
        } else {
            if (sent.exchange.status_code == 429) rate_limited = true;
            const bool success = likely_auth_success(sent.exchange, success_indicator, failure_indicator);
            if (success) successes.push_back(credential_hit_json(pairs[i].first, pairs[i].second, completed, sent.exchange));
            if (attempts.size() < 25) {
                json item;
                item["attempt_number"] = completed;
                item["status_code"] = sent.exchange.status_code;
                item["body_length"] = sent.exchange.resp_body.size();
                item["body_fingerprint"] = hex64(fnv1a(sent.exchange.resp_body.data(), sent.exchange.resp_body.size()));
                item["success_indicator_matched"] = success;
                attempts.push_back(std::move(item));
            }
            if (success && stop_on_first) break;
        }
        if (effective_rate > 0 && i + 1 < total) std::this_thread::sleep_for(std::chrono::milliseconds(effective_rate));
    }
    target_t target;
    std::string err;
    parse_target(get_string(p, "url"), target, err);
    json issue_ids = json::array();
    if (!successes.empty() && !target.host.empty()) {
        const std::string evidence = "credential attempts=" + std::to_string(completed) + "; successes=" + std::to_string(successes.size()) + "; credentials redacted";
        uint64_t issue_id = add_issue(action == "brute_force" ? "auth.bruteforce.valid-credential" : "auth.credential-stuffing.valid-credential",
                                      action == "brute_force" ? "Valid credential found during bounded brute force" : "Valid credential found during bounded credential stuffing",
                                      severity_t::high, confidence_t::firm, target, target.path, get_string(p, "username_field", "username"),
                                      "The authentication endpoint accepted at least one credential attempt during a bounded offensive auth test. Credential values are intentionally redacted in evidence.",
                                      "Enforce strong credential hygiene, MFA, throttling, lockout controls, breached-password screening, and anomaly detection on authentication attempts.",
                                      {"CWE-307", "CWE-521"}, evidence);
        issue_ids.push_back(issue_id);
    }
    json data;
    data["task_id"] = task_id;
    data["action"] = action;
    data["total_attempts"] = total;
    data["completed"] = completed;
    data["success_count"] = successes.size();
    data["successful_credentials"] = successes;
    data["rate_limited"] = rate_limited;
    data["cancelled"] = cancelled;
    data["effective_rate_limit_ms"] = effective_rate;
    data["effective_concurrency"] = 1;
    data["attempt_summaries"] = attempts;
    data["issues_created"] = issue_ids;
    data["secret_handling"] = "credential values are redacted and represented only by length plus fingerprint";
    finish_job(task_id, data, completed, cancelled, {});
    const std::string message = action + " completed attempts=" + std::to_string(completed) + " successes=" + std::to_string(successes.size());
    return ok_result(message, std::move(data));
}

std::vector<std::pair<std::string, std::string>> brute_force_pairs(const json& p, size_t max_attempts)
{
    std::vector<std::string> usernames = string_array(p, "usernames");
    std::vector<std::string> passwords = string_array(p, "passwords");
    if (usernames.empty()) {
        const std::string id = get_string(p, "username_wordlist_id", "auth/usernames_common_expanded");
        usernames = payload_entries_with_fallback(id, "auth/usernames-top1000", max_attempts);
    }
    if (passwords.empty()) {
        const std::string id = get_string(p, "password_wordlist_id", "auth/passwords_common_expanded");
        passwords = payload_entries_with_fallback(id, "auth/passwords-top1000", max_attempts);
    }
    std::vector<std::pair<std::string, std::string>> pairs;
    pairs.reserve(max_attempts);
    for (const auto& u : usernames) {
        for (const auto& pw : passwords) {
            if (u.empty() || pw.empty()) continue;
            pairs.emplace_back(u, pw);
            if (pairs.size() >= max_attempts) return pairs;
        }
    }
    return pairs;
}

bool extract_cookie_token(const exchange_observed_t& e, const std::string& token_name, std::string& out)
{
    for (const auto& h : e.resp_headers) {
        if (!equals_ci(h.first, "Set-Cookie")) continue;
        cookie_jar::parsed_cookie_t c;
        if (cookie_jar::parse_set_cookie(h.second, e.host, c)) {
            if (token_name.empty() || equals_ci(c.name, token_name)) {
                out = c.value;
                return !out.empty();
            }
        }
    }
    return false;
}

bool extract_named_token(const exchange_observed_t& e, const std::string& location, const std::string& token_name, std::string& out)
{
    const std::string loc = lower_ascii(location);
    if (loc == "cookie") return extract_cookie_token(e, token_name, out);
    if (loc == "header") {
        out = token_name.empty() ? std::string() : header_value(e.resp_headers, token_name);
        return !out.empty();
    }
    if (loc == "body") {
        const std::string text = body_text(e.resp_body, 262144);
        if (!token_name.empty()) {
            const std::string escaped = std::regex_replace(token_name, std::regex(R"([.^$|()\\[\]{}*+?])"), R"(\\$&)");
            const std::regex json_re("[\"']" + escaped + "[\"']\\s*[:=]\\s*[\"']([^\"']+)[\"']", std::regex::icase);
            std::smatch m;
            if (std::regex_search(text, m, json_re) && m.size() > 1) {
                out = m[1].str();
                return true;
            }
        }
        const std::regex generic_re(R"(([A-Za-z0-9._~+/=-]{16,}))");
        std::smatch m;
        if (std::regex_search(text, m, generic_re)) {
            out = m[1].str();
            return true;
        }
        return false;
    }
    if (loc == "url_param") {
        const std::string header = header_value(e.resp_headers, "Location");
        if (header.empty() || token_name.empty()) return false;
        const std::string needle = token_name + "=";
        const size_t pos = header.find(needle);
        if (pos == std::string::npos) return false;
        const size_t start = pos + needle.size();
        const size_t end = header.find_first_of("&#", start);
        out = header.substr(start, end == std::string::npos ? std::string::npos : end - start);
        return !out.empty();
    }
    return false;
}

json token_entropy_analysis(const std::vector<std::string>& samples)
{
    json out;
    out["samples_collected"] = samples.size();
    if (samples.empty()) return out;
    size_t min_len = std::numeric_limits<size_t>::max();
    size_t max_len = 0;
    size_t total_len = 0;
    std::array<size_t, 256> freq{};
    bool all_numeric = true;
    std::vector<unsigned long long> numeric_values;
    for (const auto& s : samples) {
        min_len = std::min(min_len, s.size());
        max_len = std::max(max_len, s.size());
        total_len += s.size();
        bool numeric = !s.empty();
        for (unsigned char c : s) {
            ++freq[c];
            if (c < '0' || c > '9') numeric = false;
        }
        if (!numeric) all_numeric = false;
        if (numeric) {
            try { numeric_values.push_back(std::stoull(s)); } catch (...) { all_numeric = false; }
        }
    }
    size_t charset = 0;
    for (size_t f : freq) {
        if (f) ++charset;
    }
    const double total_chars = static_cast<double>(total_len);
    double entropy_per_char = 0.0;
    if (total_chars > 0.0) {
        for (size_t f : freq) {
            if (!f) continue;
            const double p = static_cast<double>(f) / total_chars;
            entropy_per_char -= p * std::log2(p);
        }
    }
    bool monotonic = all_numeric && numeric_values.size() >= 3;
    if (monotonic) {
        bool inc = true;
        for (size_t i = 1; i < numeric_values.size(); ++i) {
            if (numeric_values[i] <= numeric_values[i - 1]) {
                inc = false;
                break;
            }
        }
        monotonic = inc;
    }
    size_t common_prefix = samples.front().size();
    for (const auto& s : samples) {
        size_t i = 0;
        while (i < common_prefix && i < s.size() && s[i] == samples.front()[i]) ++i;
        common_prefix = i;
    }
    const double mean_len = static_cast<double>(total_len) / static_cast<double>(samples.size());
    const double total_entropy = entropy_per_char * mean_len;
    std::string rating = "weak";
    if (total_entropy >= 128.0 && !monotonic) rating = "excellent";
    else if (total_entropy >= 96.0 && !monotonic) rating = "good";
    else if (total_entropy >= 64.0 && !monotonic) rating = "moderate";
    out["token_length"] = {{"min", min_len}, {"max", max_len}, {"mean", mean_len}};
    out["charset_size"] = charset;
    out["shannon_entropy_bits_per_char"] = entropy_per_char;
    out["estimated_total_entropy_bits"] = total_entropy;
    out["entropy_rating"] = rating;
    out["sequence_detected"] = monotonic;
    out["common_prefix_length"] = common_prefix;
    out["predictability_score"] = monotonic ? 0.95 : (common_prefix >= min_len / 2 && min_len >= 8 ? 0.35 : 0.05);
    out["predictability_rating"] = monotonic ? "high" : (out["predictability_score"].get<double>() > 0.25 ? "moderate" : "very_low");
    json sample_summaries = json::array();
    for (size_t i = 0; i < samples.size() && i < 8; ++i) sample_summaries.push_back(secret_summary(samples[i]));
    out["sample_summaries"] = sample_summaries;
    return out;
}

std::vector<std::string> ids_from_payload(const json& p)
{
    std::vector<std::string> ids = string_array(p, "id_list");
    const size_t max_ids = get_size(p, "max_ids", 100, 1, kMaxIdTests);
    if (!ids.empty()) {
        if (ids.size() > max_ids) ids.resize(max_ids);
        return ids;
    }
    if (p.contains("id_range_start") && p.contains("id_range_end") && p["id_range_start"].is_number_integer() && p["id_range_end"].is_number_integer()) {
        long long start = p["id_range_start"].get<long long>();
        long long end = p["id_range_end"].get<long long>();
        if (end < start) std::swap(start, end);
        for (long long v = start; v <= end && ids.size() < max_ids; ++v) ids.push_back(std::to_string(v));
    }
    return ids;
}

bool body_has_sensitive_markers(const exchange_observed_t& e)
{
    const std::string b = lower_ascii(body_text(e.resp_body, 65536));
    static const char* markers[] = {"email", "account", "user", "owner", "balance", "amount", "role", "address", "phone", "profile", "invoice", "order"};
    for (const char* marker : markers) {
        if (b.find(marker) != std::string::npos) return true;
    }
    return false;
}

std::string target_url_with_path(const target_t& t, const std::string& path)
{
    std::string out = t.scheme + "://" + authority(t);
    out += path.empty() ? "/" : path;
    return out;
}

std::string original_param_value(const target_t& target, const json& p, const std::string& param)
{
    if (p.contains("params") && p["params"].is_object() && p["params"].contains(param)) return json_string_value(p["params"][param]);
    const std::string needle = param + "=";
    const size_t q = target.path.find('?');
    if (q != std::string::npos) {
        const size_t pos = target.path.find(needle, q + 1);
        if (pos != std::string::npos) {
            const size_t start = pos + needle.size();
            const size_t end = target.path.find_first_of("&#", start);
            return target.path.substr(start, end == std::string::npos ? std::string::npos : end - start);
        }
    }
    return get_string(p, "original_id");
}

bool weak_password_shape(const std::string& s, json& summary)
{
    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;
    bool has_symbol = false;
    for (unsigned char c : s) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_symbol = true;
    }
    const std::string lc = lower_ascii(s);
    static const char* common[] = {"password", "admin", "qwerty", "letmein", "welcome", "changeme", "123456"};
    bool common_term = false;
    for (const char* c : common) {
        if (lc.find(c) != std::string::npos) common_term = true;
    }
    const bool weak = s.size() < 12 || !(has_lower && has_upper && has_digit && has_symbol) || common_term;
    summary = secret_summary(s);
    summary["length_ok"] = s.size() >= 12;
    summary["has_lower"] = has_lower;
    summary["has_upper"] = has_upper;
    summary["has_digit"] = has_digit;
    summary["has_symbol"] = has_symbol;
    summary["common_pattern"] = common_term;
    summary["weak"] = weak;
    return weak;
}

}

result_t brute_force(const json& payload)
{
    const size_t max_attempts = get_size(payload, "max_attempts", kMaxAuthAttempts, 1, kMaxAuthAttempts);
    auto pairs = brute_force_pairs(payload, max_attempts);
    if (pairs.size() > max_attempts) pairs.resize(max_attempts);
    return run_credential_attempts("brute_force", payload, pairs, max_attempts);
}

result_t credential_stuffing(const json& payload)
{
    const size_t max_attempts = get_size(payload, "max_attempts", kMaxCredentialPairs, 1, kMaxCredentialPairs);
    auto pairs = credential_pairs_from_payload(payload, max_attempts);
    return run_credential_attempts("credential_stuffing", payload, pairs, max_attempts);
}

result_t session_analysis(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    const size_t sample_count = get_size(payload, "sample_count", 500, 2, kMaxSessionSamples);
    const std::string task_id = start_job("session_analysis", sample_count);
    std::map<std::string, std::string> params = extra_params(payload);
    std::map<std::string, std::string> headers = header_map_from_json(payload);
    const std::string method = get_string(payload, "method", "GET");
    const std::string token_location = lower_ascii(get_string(payload, "token_location", "cookie"));
    const std::string token_name = get_string(payload, "token_name");
    const int timeout_ms = get_int(payload, "per_request_timeout_ms", 5000, 1000, 60000);
    std::vector<std::string> samples;
    samples.reserve(sample_count);
    json misses = json::array();
    bool cancelled = false;
    for (size_t i = 0; i < sample_count; ++i) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        const auto raw = build_request(target, method, target.path, params, "form", headers, {}, true);
        auto sent = send_raw_request(target, raw, timeout_ms, false);
        if (!sent.ok) {
            if (misses.size() < 16) misses.push_back({{"sample_number", i + 1}, {"transport_error", sent.error}});
        } else {
            std::string token;
            if (extract_named_token(sent.exchange, token_location, token_name, token)) samples.push_back(token);
            else if (misses.size() < 16) misses.push_back({{"sample_number", i + 1}, {"status_code", sent.exchange.status_code}, {"token_extracted", false}});
        }
        update_job_progress(task_id, i + 1);
        if (get_int(payload, "rate_limit_ms", 20, 0, 60000) > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(get_int(payload, "rate_limit_ms", 20, 0, 60000)));
        }
    }
    json analysis = token_entropy_analysis(samples);
    json issue_ids = json::array();
    const bool weak = samples.size() >= 2 && (analysis.value("sequence_detected", false) || analysis.value("estimated_total_entropy_bits", 0.0) < 64.0);
    if (weak) {
        const std::string evidence = "samples=" + std::to_string(samples.size()) + "; token values redacted; entropy_bits=" + std::to_string(analysis.value("estimated_total_entropy_bits", 0.0));
        uint64_t id = add_issue("auth.session-token.weak-randomness",
                                "Weak or predictable session token evidence",
                                severity_t::high, confidence_t::tentative, target, target.path, token_name,
                                "Collected session token samples showed low entropy, repeated structure, or monotonic sequence behavior. Token values are redacted in evidence.",
                                "Generate session identifiers with a cryptographically secure random source, rotate on authentication, and reject client-supplied session IDs.",
                                {"CWE-330", "CWE-384"}, evidence);
        issue_ids.push_back(id);
    }
    analysis["task_id"] = task_id;
    analysis["cancelled"] = cancelled;
    analysis["token_location"] = token_location;
    analysis["token_name"] = token_name.empty() ? json(nullptr) : json(token_name);
    analysis["extraction_misses"] = misses;
    analysis["issues_created"] = issue_ids;
    analysis["recommendation"] = weak ? "Session tokens require manual confirmation and likely stronger generation or rotation controls." : "No low-entropy or monotonic sequence evidence was observed in the collected samples.";
    finish_job(task_id, analysis, samples.size(), cancelled, {});
    return ok_result("session_analysis collected=" + std::to_string(samples.size()), std::move(analysis));
}

result_t idor_test(const json& payload)
{
    const std::string url = get_string(payload, "url");
    const std::string param = get_string(payload, "param_target");
    if (url.empty()) return error_result("Missing url", "missing_param");
    if (param.empty()) return error_result("Missing param_target", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    std::vector<std::string> ids = ids_from_payload(payload);
    if (ids.empty()) return error_result("No IDs to test", "empty_input");
    const std::string method = get_string(payload, "method", "GET");
    const int timeout_ms = get_int(payload, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000);
    std::map<std::string, std::string> base_params = extra_params(payload);
    std::map<std::string, std::string> headers = header_map_from_json(payload);
    const std::string token = get_string(payload, "session_token");
    const bool compare_baseline = get_bool(payload, "compare_baseline", true);
    const std::string original = original_param_value(target, payload, param);
    const std::string task_id = start_job("idor_test", ids.size());
    send_result_t baseline;
    if (compare_baseline) {
        std::map<std::string, std::string> p = base_params;
        std::string path = target.path;
        if (!original.empty()) p[param] = original;
        else path = with_target_param_path(path, param, ids.front());
        std::string baseline_url = target_url_with_path(target, path);
        baseline = send_param_request(baseline_url, method, p, get_string(payload, "body_mode", "form"), headers, token, timeout_ms);
    }
    json accessible = json::array();
    bool cancelled = false;
    size_t completed = 0;
    for (const auto& id_value : ids) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        if (!original.empty() && id_value == original) continue;
        std::map<std::string, std::string> p = base_params;
        std::string path = target.path;
        if (p.find(param) != p.end()) p[param] = id_value;
        else path = with_target_param_path(path, param, id_value);
        auto sent = send_param_request(target_url_with_path(target, path), method, p, get_string(payload, "body_mode", "form"), headers, token, timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok) continue;
        const bool baseline_diff = !baseline.ok || baseline.exchange.status_code != sent.exchange.status_code ||
                                   baseline.exchange.resp_body.size() != sent.exchange.resp_body.size() ||
                                   fnv1a(baseline.exchange.resp_body.data(), baseline.exchange.resp_body.size()) != fnv1a(sent.exchange.resp_body.data(), sent.exchange.resp_body.size());
        const bool accessible_status = sent.exchange.status_code >= 200 && sent.exchange.status_code < 300;
        const bool leak = accessible_status && baseline_diff && body_has_sensitive_markers(sent.exchange);
        if (accessible_status && (leak || !compare_baseline)) {
            json item;
            item["id"] = id_value;
            item["status_code"] = sent.exchange.status_code;
            item["data_leaked"] = leak;
            item["body_length"] = sent.exchange.resp_body.size();
            item["body_fingerprint"] = hex64(fnv1a(sent.exchange.resp_body.data(), sent.exchange.resp_body.size()));
            accessible.push_back(std::move(item));
        }
    }
    json issue_ids = json::array();
    if (!accessible.empty()) {
        const std::string evidence = "tested=" + std::to_string(completed) + "; accessible=" + std::to_string(accessible.size()) + "; response bodies not stored";
        uint64_t id = add_issue("authz.idor.object-access",
                                "Possible insecure direct object reference",
                                severity_t::high, confidence_t::tentative, target, target.path, param,
                                "Changing an object identifier produced successful responses with differential content consistent with unauthorized object access.",
                                "Authorize every object access on the server side and avoid exposing predictable direct object references.",
                                {"CWE-639", "CWE-285"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = !accessible.empty();
    data["parameter"] = param;
    data["tested_count"] = completed;
    data["accessible_count"] = accessible.size();
    data["accessible_ids"] = accessible;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    return ok_result("idor_test completed accessible=" + std::to_string(accessible.size()), std::move(data));
}

result_t bola_test(const json& payload)
{
    const std::string url = get_string(payload, "url");
    const std::string param = get_string(payload, "param_target");
    const std::string token_a = get_string(payload, "auth_token_user_a");
    const std::string token_b = get_string(payload, "auth_token_user_b");
    if (url.empty()) return error_result("Missing url", "missing_param");
    if (param.empty()) return error_result("Missing param_target", "missing_param");
    if (token_a.empty() || token_b.empty()) return error_result("Missing cross-user auth tokens", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    std::vector<std::string> a_ids = string_array(payload, "object_ids_user_a");
    std::vector<std::string> b_ids = string_array(payload, "object_ids_user_b");
    if (a_ids.size() > kMaxIdTests) a_ids.resize(kMaxIdTests);
    if (b_ids.size() > kMaxIdTests) b_ids.resize(kMaxIdTests);
    const size_t total = a_ids.size() + b_ids.size();
    if (total == 0) return error_result("No cross-user object IDs supplied", "empty_input");
    const std::string task_id = start_job("bola_test", total);
    const std::string method = get_string(payload, "method", "GET");
    const int timeout_ms = get_int(payload, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000);
    std::map<std::string, std::string> base_params = extra_params(payload);
    std::map<std::string, std::string> headers = header_map_from_json(payload);
    json user_a_accessed_b = json::array();
    json user_b_accessed_a = json::array();
    size_t completed = 0;
    bool cancelled = false;
    auto run_one = [&](const std::string& token, const std::string& id_value, const char* direction, json& bucket) {
        std::map<std::string, std::string> p = base_params;
        std::string path = target.path;
        if (p.find(param) != p.end()) p[param] = id_value;
        else path = with_target_param_path(path, param, id_value);
        auto sent = send_param_request(target_url_with_path(target, path), method, p, get_string(payload, "body_mode", "form"), headers, token, timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok) return;
        if (sent.exchange.status_code >= 200 && sent.exchange.status_code < 300 && !body_has_auth_failure_terms(sent.exchange)) {
            json item;
            item["object_id"] = id_value;
            item["direction"] = direction;
            item["status_code"] = sent.exchange.status_code;
            item["body_length"] = sent.exchange.resp_body.size();
            item["body_fingerprint"] = hex64(fnv1a(sent.exchange.resp_body.data(), sent.exchange.resp_body.size()));
            bucket.push_back(std::move(item));
        }
    };
    for (const auto& id : b_ids) {
        if (call_cancelled()) { cancelled = true; break; }
        run_one(token_a, id, "user_a_accessed_user_b_object", user_a_accessed_b);
    }
    for (const auto& id : a_ids) {
        if (call_cancelled()) { cancelled = true; break; }
        run_one(token_b, id, "user_b_accessed_user_a_object", user_b_accessed_a);
    }
    json issue_ids = json::array();
    const bool confirmed = !user_a_accessed_b.empty() || !user_b_accessed_a.empty();
    if (confirmed) {
        const std::string evidence = "cross-user object access count=" + std::to_string(user_a_accessed_b.size() + user_b_accessed_a.size()) + "; tokens redacted";
        uint64_t id = add_issue("authz.bola.cross-user-object-access",
                                "Broken object level authorization",
                                severity_t::critical, confidence_t::firm, target, target.path, param,
                                "A token for one user successfully accessed objects supplied as belonging to another user. Authorization tokens are intentionally redacted.",
                                "Perform object ownership checks inside every API handler and resolver, independent of client-supplied identifiers.",
                                {"CWE-639", "CWE-862"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["bola_confirmed"] = confirmed;
    data["parameter"] = param;
    data["tested_count"] = completed;
    data["user_a_accessed_b_objects"] = user_a_accessed_b;
    data["user_b_accessed_a_objects"] = user_b_accessed_a;
    data["auth_token_user_a_summary"] = secret_summary(token_a);
    data["auth_token_user_b_summary"] = secret_summary(token_b);
    data["issues_created"] = issue_ids;
    data["cancelled"] = cancelled;
    finish_job(task_id, data, completed, cancelled, {});
    return ok_result("bola_test completed confirmed=" + std::to_string(confirmed ? 1 : 0), std::move(data));
}

result_t password_policy(const json& payload)
{
    std::vector<std::string> candidates = string_array(payload, "test_values");
    if (candidates.empty()) {
        candidates = {"password", "Password1", "Password123", "admin123", "qwerty123", "Welcome1", "Summer2026", "12345678", "P@ssw0rd"};
    }
    if (candidates.size() > kMaxPolicyTests) candidates.resize(kMaxPolicyTests);
    json assessed = json::array();
    for (const auto& c : candidates) {
        json s;
        weak_password_shape(c, s);
        assessed.push_back(std::move(s));
    }
    const std::string url = get_string(payload, "url");
    if (url.empty()) {
        json data;
        data["mode"] = "local_policy_assessment";
        data["checked_count"] = candidates.size();
        data["candidate_summaries"] = assessed;
        data["issues_created"] = json::array();
        return ok_result("password_policy local assessment completed", std::move(data));
    }
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    const std::string field = get_string(payload, "password_field", "password");
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000);
    const json success_indicator = payload.contains("success_indicator") ? payload["success_indicator"] : json();
    const json failure_indicator = payload.contains("failure_indicator") ? payload["failure_indicator"] : json();
    const std::string task_id = start_job("password_policy", candidates.size());
    json accepted = json::array();
    size_t completed = 0;
    bool cancelled = false;
    for (const auto& c : candidates) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::map<std::string, std::string> params = extra_params(payload);
        params[field] = c;
        auto sent = send_param_request(url, method, params, get_string(payload, "body_mode", "form"), header_map_from_json(payload), get_string(payload, "auth_token"), timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok) continue;
        json summary;
        const bool weak = weak_password_shape(c, summary);
        const bool accepted_by_endpoint = likely_auth_success(sent.exchange, success_indicator, failure_indicator);
        if (weak && accepted_by_endpoint) {
            summary["response"] = response_summary(sent.exchange);
            accepted.push_back(std::move(summary));
        }
    }
    json issue_ids = json::array();
    if (!accepted.empty()) {
        const std::string evidence = "weak_passwords_accepted=" + std::to_string(accepted.size()) + "; password values redacted";
        uint64_t id = add_issue("auth.password-policy.weak-password-accepted",
                                "Weak password accepted",
                                severity_t::medium, confidence_t::firm, target, target.path, field,
                                "The password policy endpoint accepted one or more weak password candidates. Candidate values are redacted in evidence.",
                                "Require length, complexity, breached-password screening, and server-side policy enforcement on all password creation and reset flows.",
                                {"CWE-521"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["checked_count"] = completed;
    data["weak_accepted_count"] = accepted.size();
    data["accepted_weak_passwords"] = accepted;
    data["candidate_summaries"] = assessed;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    return ok_result("password_policy endpoint assessment completed", std::move(data));
}

result_t mfa_bypass_check(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    std::vector<std::string> values = string_array(payload, "test_values");
    if (values.empty()) values = {"", "000000", "0000000", "111111", "123456", "999999", "null", "true", "false"};
    if (values.size() > kMaxPolicyTests) values.resize(kMaxPolicyTests);
    const std::string field = get_string(payload, "mfa_field", get_string(payload, "otp_field", "otp"));
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "per_request_timeout_ms", kDefaultRequestTimeoutMs, 1000, 60000);
    const json success_indicator = payload.contains("success_indicator") ? payload["success_indicator"] : json();
    const json failure_indicator = payload.contains("failure_indicator") ? payload["failure_indicator"] : json();
    const std::string task_id = start_job("mfa_bypass_check", values.size());
    json accepted = json::array();
    size_t completed = 0;
    bool cancelled = false;
    for (const auto& value : values) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::map<std::string, std::string> params = extra_params(payload);
        params[field] = value;
        auto sent = send_param_request(url, method, params, get_string(payload, "body_mode", "form"), header_map_from_json(payload), get_string(payload, "auth_token"), timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok) continue;
        const bool accepted_by_endpoint = likely_auth_success(sent.exchange, success_indicator, failure_indicator);
        if (accepted_by_endpoint) {
            json item;
            item["mfa_value_summary"] = secret_summary(value);
            item["response"] = response_summary(sent.exchange);
            accepted.push_back(std::move(item));
        }
    }
    json issue_ids = json::array();
    if (!accepted.empty()) {
        const std::string evidence = "accepted_mfa_bypass_values=" + std::to_string(accepted.size()) + "; submitted values redacted";
        uint64_t id = add_issue("auth.mfa.bypass-candidate",
                                "Possible MFA bypass",
                                severity_t::critical, confidence_t::tentative, target, target.path, field,
                                "The MFA endpoint accepted one or more bypass-style OTP values or missing-value attempts. Submitted values are redacted in evidence.",
                                "Bind MFA verification to the authenticated login transaction, reject missing or malformed codes, enforce replay protection, and rate-limit verification attempts.",
                                {"CWE-287", "CWE-307"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["tested_count"] = completed;
    data["accepted_count"] = accepted.size();
    data["accepted_values"] = accepted;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    return ok_result("mfa_bypass_check completed accepted=" + std::to_string(accepted.size()), std::move(data));
}

result_t get_status(const json& payload)
{
    const std::string task_id = get_string(payload, "task_id");
    if (task_id.empty()) {
        json data;
        data["jobs"] = all_status_json();
        return ok_result("auth attack job status list", std::move(data));
    }
    std::lock_guard<std::mutex> lk(jobs_mutex());
    auto it = jobs().find(task_id);
    if (it == jobs().end()) return error_result("Unknown task_id", "not_found");
    return ok_result("auth attack job status", job_status_json(it->second));
}

result_t get_results(const json& payload)
{
    const std::string task_id = get_string(payload, "task_id");
    if (task_id.empty()) return error_result("Missing task_id", "missing_param");
    std::lock_guard<std::mutex> lk(jobs_mutex());
    auto it = jobs().find(task_id);
    if (it == jobs().end()) return error_result("Unknown task_id", "not_found");
    json data = it->second.result;
    data["status"] = job_status_json(it->second);
    return ok_result("auth attack job results", std::move(data));
}

result_t handle_action(const std::string& action_raw, const json& payload)
{
    const std::string action = lower_ascii(action_raw);
    if (action == "brute_force") return brute_force(payload);
    if (action == "credential_stuffing") return credential_stuffing(payload);
    if (action == "session_analysis") return session_analysis(payload);
    if (action == "idor_test") return idor_test(payload);
    if (action == "bola_test") return bola_test(payload);
    if (action == "password_policy") return password_policy(payload);
    if (action == "mfa_bypass_check") return mfa_bypass_check(payload);
    if (action == "get_status" || action == "status") return get_status(payload);
    if (action == "get_results" || action == "results") return get_results(payload);
    return error_result("aida_offensive_auth_attack_manage unknown action: " + action_raw, "unknown_action");
}

}
}
}
}
