#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "business_logic_engine.hpp"

#include "../audit_http.hpp"
#include "../auth_lab.hpp"
#include "../cookie_jar.hpp"
#include "../intruder_engine.hpp"
#include "../issue.hpp"
#include "../../../mcp/mcp_standalone.hpp"
#include "../../../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace business_logic {

namespace {

using json = nlohmann::json;

constexpr size_t kMaxConcurrentRequests = 50;
constexpr size_t kMaxRepeatCount = 10;
constexpr size_t kMaxTamperValues = 64;
constexpr int kDefaultTimeoutMs = 15000;

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

bool equals_ci(const std::string& a, const std::string& b)
{
    return lower_ascii(a) == lower_ascii(b);
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

uint64_t fnv1a_string(const std::string& value)
{
    return fnv1a(reinterpret_cast<const uint8_t*>(value.data()), value.size());
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

int get_int(const json& p, const char* key, int def, int min_v, int max_v)
{
    if (!p.contains(key) || !p[key].is_number()) return def;
    int v = p[key].get<int>();
    if (v < min_v) v = min_v;
    if (v > max_v) v = max_v;
    return v;
}

size_t get_size(const json& p, const char* key, size_t def, size_t min_v, size_t max_v)
{
    if (!p.contains(key) || !p[key].is_number()) return def;
    long long v = p[key].get<long long>();
    if (v < static_cast<long long>(min_v)) v = static_cast<long long>(min_v);
    if (v > static_cast<long long>(max_v)) v = static_cast<long long>(max_v);
    return static_cast<size_t>(v);
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
    for (auto it = obj.begin(); it != obj.end(); ++it) out[it.key()] = json_string_value(it.value());
    return out;
}

std::map<std::string, std::string> params_from_payload(const json& p)
{
    if (p.contains("params") && p["params"].is_object()) return string_map_from_object(p["params"]);
    return {};
}

std::map<std::string, std::string> headers_from_payload(const json& p)
{
    std::map<std::string, std::string> out;
    if (!p.contains("headers") || !p["headers"].is_object()) return out;
    for (auto it = p["headers"].begin(); it != p["headers"].end(); ++it) {
        std::string name = it.key();
        std::string value = json_string_value(it.value());
        name.erase(std::remove_if(name.begin(), name.end(), [](char c) { return c == '\r' || c == '\n' || c == ':'; }), name.end());
        value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
        value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
        if (!name.empty()) out[name] = value;
    }
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

bool body_has_failure_terms(const exchange_observed_t& e)
{
    const std::string b = lower_ascii(body_text(e.resp_body));
    static const char* terms[] = {
        "error", "invalid", "failed", "denied", "unauthorized", "forbidden",
        "insufficient", "expired", "not allowed", "cannot", "blocked", "limit"
    };
    for (const char* term : terms) {
        if (b.find(term) != std::string::npos) return true;
    }
    return false;
}

bool body_has_success_terms(const exchange_observed_t& e)
{
    const std::string b = lower_ascii(body_text(e.resp_body));
    static const char* terms[] = {
        "success", "complete", "completed", "accepted", "applied", "created",
        "order", "checkout", "confirmed", "balance", "total", "discount"
    };
    for (const char* term : terms) {
        if (b.find(term) != std::string::npos) return true;
    }
    return false;
}

json response_summary(const exchange_observed_t& e)
{
    json out;
    out["status_code"] = e.status_code;
    out["latency_ms"] = e.latency_ms;
    out["body_length"] = e.resp_body.size();
    out["body_fingerprint"] = hex64(fnv1a(e.resp_body.data(), e.resp_body.size()));
    const std::string loc = header_value(e.resp_headers, "Location");
    if (!loc.empty()) {
        out["location_length"] = loc.size();
        out["location_fingerprint"] = hex64(fnv1a_string(loc));
    }
    return out;
}

result_t ok_result(const std::string& message, json data)
{
    data["success"] = true;
    return result_t{true, message, std::move(data), {}};
}

result_t error_result(const std::string& message, const std::string& code = "invalid_param", json data = json::object())
{
    data["success"] = false;
    data["code"] = code;
    return result_t{false, message, std::move(data), code};
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
    json out = json::object();
    for (const auto& kv : params) out[kv.first] = kv.second;
    return out.dump();
}

std::string authority(const target_t& target)
{
    std::string out = target.host;
    const bool default_port = (target.tls && target.port == 443) || (!target.tls && target.port == 80);
    if (!default_port) {
        out.push_back(':');
        out += std::to_string(static_cast<unsigned>(target.port));
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
    const size_t q = path.find('?');
    if (q == std::string::npos) {
        path.push_back('?');
        path += enc_key + "=" + enc_value + fragment;
        return;
    }
    std::string base = path.substr(0, q + 1);
    std::string query = path.substr(q + 1);
    std::vector<std::string> parts;
    bool replaced = false;
    size_t pos = 0;
    while (pos <= query.size()) {
        const size_t amp = query.find('&', pos);
        std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        const size_t eq = part.find('=');
        const std::string name = eq == std::string::npos ? part : part.substr(0, eq);
        if (name == key || name == enc_key) {
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

std::vector<uint8_t> build_request(const target_t& target,
                                   const std::string& method_in,
                                   std::string path,
                                   const std::map<std::string, std::string>& params,
                                   const std::string& body_mode,
                                   const std::map<std::string, std::string>& headers,
                                   const std::string& auth_token)
{
    std::string method = method_in.empty() ? "POST" : method_in;
    std::transform(method.begin(), method.end(), method.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    std::string body;
    std::string content_type;
    if (method == "GET" || method == "HEAD") {
        for (const auto& kv : params) add_or_replace_query_param(path, kv.first, kv.second);
    } else if (body_mode == "json") {
        body = json_body(params);
        content_type = "application/json";
    } else {
        body = form_body(params);
        content_type = "application/x-www-form-urlencoded";
    }
    std::ostringstream req;
    req << method << ' ' << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << authority(target) << "\r\n";
    req << "User-Agent: AiDA-Offensive-BusinessLogic\r\n";
    req << "Accept: */*\r\n";
    if (!auth_token.empty()) {
        const std::string authz = auth_token.rfind("Bearer ", 0) == 0 || auth_token.rfind("Basic ", 0) == 0 ? auth_token : auth_lab::bearer_header(auth_token);
        req << "Authorization: " << authz << "\r\n";
    }
    const std::string cookies = cookie_jar::build_cookie_header(target.host, target.path, target.tls);
    if (!cookies.empty()) req << "Cookie: " << cookies << "\r\n";
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

send_result_t send_raw_request(const target_t& target, const std::vector<uint8_t>& raw, int timeout_ms)
{
    audit_http::send_options_t options;
    options.timeout_ms = timeout_ms;
    options.follow_redirects = false;
    options.max_redirects = 2;
    options.enforce_scope = true;
    options.publish_exchange = false;
    options.exchange_source = "offensive_business_logic";
    auto sent = audit_http::send(raw, target.host, target.port, target.tls, options);
    if (!sent) return send_result_t{false, {}, audit_http::last_error()};
    cookie_jar::ingest_set_cookie_headers(target.host, sent->resp_headers);
    return send_result_t{true, *sent, {}};
}

send_result_t send_param_request(const target_t& target,
                                 const std::string& method,
                                 const std::map<std::string, std::string>& params,
                                 const json& payload,
                                 int timeout_ms)
{
    const auto raw = build_request(target,
                                   method,
                                   target.path,
                                   params,
                                   get_string(payload, "body_mode", "form"),
                                   headers_from_payload(payload),
                                   get_string(payload, "auth_token"));
    return send_raw_request(target, raw, timeout_ms);
}

bool success_like(const exchange_observed_t& e)
{
    if (e.status_code == 401 || e.status_code == 403 || e.status_code == 429) return false;
    if (body_has_failure_terms(e)) return false;
    if (e.status_code >= 200 && e.status_code < 300) return true;
    if (e.status_code >= 300 && e.status_code < 400) return true;
    return body_has_success_terms(e);
}

std::string start_job(const std::string& action, size_t total)
{
    static std::atomic<uint64_t> next_id{1};
    const uint64_t n = next_id.fetch_add(1);
    std::string id = "biz_" + std::to_string(now_unix_ms()) + "_" + std::to_string(n);
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

mcp_standalone::downstream::scoped_admission_t acquire_biz_admission(const std::string& action, const std::string& domain)
{
    mcp_standalone::downstream::producer_identity_t id;
    id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
    id.tool_name = "business_logic." + action;
    id.domain = domain;
    return mcp_standalone::downstream::scoped_admission_t::acquire(id);
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

uint64_t add_issue(const std::string& type_key,
                   const std::string& name,
                   severity_t severity,
                   confidence_t confidence,
                   const target_t& target,
                   const std::string& parameter,
                   const std::string& description,
                   const std::string& remediation,
                   const std::vector<std::string>& cwe,
                   const std::string& evidence)
{
    issue_t iss;
    iss.type_key = type_key;
    iss.name = name;
    iss.description = description;
    iss.remediation = remediation;
    iss.cwe = cwe;
    iss.severity = severity;
    iss.confidence = confidence;
    iss.scheme = target.scheme;
    iss.host = target.host;
    iss.port = target.port;
    iss.path = target.path;
    iss.parameter = parameter;
    evidence_t ev;
    ev.marker = evidence;
    ev.request_raw = "sanitized offensive business logic evidence";
    ev.response_raw = evidence;
    iss.evidence.push_back(std::move(ev));
    return issue_store::add(std::move(iss));
}

std::vector<send_result_t> concurrent_send(const target_t& target,
                                           const std::vector<uint8_t>& raw,
                                           size_t count,
                                           int timeout_ms)
{
    count = std::min(count, kMaxConcurrentRequests);
    const size_t capped_count = std::min(count,
        mcp_standalone::downstream::default_quotas().burp_network_worker_group_size);
    std::vector<send_result_t> results(count);
    std::vector<aida::infra::win_thread::joinable_thread_t> threads;
    threads.reserve(capped_count);
    for (size_t i = 0; i < capped_count; ++i) {
        aida::infra::win_thread::joinable_thread_t wt;
        std::string err;
        const std::string label = "biz_logic.concurrent_send." + std::to_string(i);
        const bool started = wt.start([&, i]() {
            results[i] = send_raw_request(target, raw, timeout_ms);
        }, &err, aida::infra::win_thread::default_stack_reserve, label.c_str());
        if (started)
            threads.push_back(std::move(wt));
    }
    for (auto& t : threads) {
        t.join();
    }
    return results;
}

std::string detect_field(const std::map<std::string, std::string>& params,
                         const std::vector<std::string>& candidates,
                         const std::string& fallback)
{
    for (const auto& c : candidates) {
        for (const auto& kv : params) {
            if (equals_ci(kv.first, c) || lower_ascii(kv.first).find(lower_ascii(c)) != std::string::npos) return kv.first;
        }
    }
    return fallback;
}

json all_status_json()
{
    json arr = json::array();
    std::lock_guard<std::mutex> lk(jobs_mutex());
    for (const auto& kv : jobs()) arr.push_back(job_status_json(kv.second));
    return arr;
}

}

result_t race_test(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("race_test", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=race_test host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=race_test host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    const size_t concurrent = get_size(payload, "concurrent_requests", 20, 2, kMaxConcurrentRequests);
    const size_t repeat_count = get_size(payload, "repeat_count", 5, 1, kMaxRepeatCount);
    const size_t total_expected = concurrent * repeat_count;
    const std::string task_id = start_job("race_test", total_expected);
    const int timeout_ms = get_int(payload, "timeout_ms", 60000, 2000, 300000);
    const std::string method = get_string(payload, "method", "POST");
    std::map<std::string, std::string> params = params_from_payload(payload);
    const auto raw = build_request(target, method, target.path, params, get_string(payload, "body_mode", "form"), headers_from_payload(payload), get_string(payload, "auth_token"));
    json batches = json::array();
    size_t completed = 0;
    size_t successful_2xx = 0;
    size_t divergent_batches = 0;
    bool cancelled = false;
    for (size_t batch = 0; batch < repeat_count; ++batch) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        intruder::config_t cfg;
        cfg.scheme = target.scheme;
        cfg.host = target.host;
        cfg.port = target.port;
        cfg.base_request = raw;
        cfg.attack_mode = intruder::attack_mode_t::race;
        cfg.engine_mode = get_bool(payload, "use_single_packet", true) && target.tls ? intruder::engine_mode_t::http2_single_packet : intruder::engine_mode_t::http1_pipelined;
        cfg.concurrency = concurrent;
        cfg.total_requests_cap = concurrent;
        cfg.race_gate_size = concurrent;
        cfg.race_warmup_count = 0;
        cfg.timeout_ms = std::max(2000, timeout_ms / static_cast<int>(repeat_count));
        cfg.record_history = false;
        cfg.max_response_body_bytes = 32768;
        cfg.payload_sets.push_back(std::vector<std::string>(concurrent, std::string()));
        cfg.positions.push_back({raw.size(), 0});
        const uint64_t intruder_job = intruder::start(cfg);
        json batch_json;
        batch_json["batch"] = batch + 1;
        batch_json["intruder_job_id"] = intruder_job;
        if (intruder_job == 0) {
            batch_json["error"] = intruder::last_error();
            batches.push_back(std::move(batch_json));
            continue;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg.timeout_ms * 3);
        while (std::chrono::steady_clock::now() < deadline) {
            if (call_cancelled()) {
                cancelled = true;
                intruder::stop(intruder_job);
                break;
            }
            auto st = intruder::status(intruder_job);
            if (!st.running && (st.sent >= st.total || st.total == 0)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        auto results = intruder::results(intruder_job, 0, concurrent + 16);
        intruder::clear(intruder_job);
        size_t twoxx = 0;
        size_t errors = 0;
        std::map<int, size_t> statuses;
        std::vector<size_t> sizes;
        json result_summaries = json::array();
        for (const auto& r : results) {
            if (r.error) {
                ++errors;
                continue;
            }
            if (r.status_code >= 200 && r.status_code < 300) ++twoxx;
            ++statuses[r.status_code];
            sizes.push_back(r.response_size);
            if (result_summaries.size() < 12) {
                result_summaries.push_back({{"status_code", r.status_code}, {"response_size", r.response_size}, {"latency_ms", r.latency_ms}, {"error", r.error}});
            }
        }
        completed += results.size();
        update_job_progress(task_id, completed);
        successful_2xx += twoxx;
        bool size_divergence = false;
        if (!sizes.empty()) {
            std::sort(sizes.begin(), sizes.end());
            const size_t median = sizes[sizes.size() / 2];
            for (size_t s : sizes) {
                const size_t hi = std::max(s, median);
                const size_t lo = std::min(s, median);
                if (median > 0 && ((hi - lo) * 100 / median) > 15) {
                    size_divergence = true;
                    break;
                }
            }
        }
        const bool status_divergence = statuses.size() > 1;
        const bool multi_success = twoxx >= 2;
        if (size_divergence || status_divergence || multi_success) ++divergent_batches;
        batch_json["sent"] = results.size();
        batch_json["twoxx"] = twoxx;
        batch_json["errors"] = errors;
        batch_json["status_divergence"] = status_divergence;
        batch_json["size_divergence"] = size_divergence;
        batch_json["multi_success"] = multi_success;
        batch_json["result_summaries"] = result_summaries;
        batches.push_back(std::move(batch_json));
        const int delay = get_int(payload, "delay_between_batches_ms", 500, 0, 30000);
        if (delay > 0 && batch + 1 < repeat_count) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }
    json issue_ids = json::array();
    const bool vulnerable = divergent_batches > 0 && successful_2xx >= 2;
    if (vulnerable) {
        const std::string evidence = "race batches=" + std::to_string(repeat_count) + "; concurrent=" + std::to_string(concurrent) + "; divergent_batches=" + std::to_string(divergent_batches);
        uint64_t issue = add_issue("business.race-condition.concurrent-state-change",
                                   "Possible business logic race condition",
                                   severity_t::high, confidence_t::tentative, target, "",
                                   "Bounded concurrent state-changing requests produced multiple successful or divergent responses, consistent with a race condition candidate.",
                                   "Serialize critical state transitions with transactional locks, idempotency keys, and database uniqueness constraints.",
                                   {"CWE-362", "CWE-367"}, evidence);
        issue_ids.push_back(issue);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = vulnerable;
    data["race_condition_confirmed"] = vulnerable;
    data["concurrent_requests"] = concurrent;
    data["repeat_count"] = repeat_count;
    data["successful_exploitations"] = successful_2xx;
    data["divergent_batches"] = divergent_batches;
    data["batches"] = batches;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=race_test host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("race_test completed divergent_batches=" + std::to_string(divergent_batches), std::move(data));
}

result_t price_tamper(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("price_tamper", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=price_tamper host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=price_tamper host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    std::map<std::string, std::string> params = params_from_payload(payload);
    const std::string field = get_string(payload, "price_field", detect_field(params, {"price", "amount", "total", "subtotal", "cost"}, "price"));
    std::vector<std::string> values = string_array(payload, "test_values");
    if (values.empty()) values = {"0", "-1", "0.01", "0.001", "null", "NaN", "1e-10", "999999999"};
    if (values.size() > kMaxTamperValues) values.resize(kMaxTamperValues);
    const std::string task_id = start_job("price_tamper", values.size());
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "timeout_ms", 30000, 1000, 300000);
    auto baseline = send_param_request(target, method, params, payload, timeout_ms);
    json accepted = json::array();
    size_t completed = 0;
    bool cancelled = false;
    for (const auto& value : values) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::map<std::string, std::string> mutated = params;
        mutated[field] = value;
        auto sent = send_param_request(target, method, mutated, payload, timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (!sent.ok || !success_like(sent.exchange)) continue;
        const bool differs = !baseline.ok ||
                             sent.exchange.status_code != baseline.exchange.status_code ||
                             sent.exchange.resp_body.size() != baseline.exchange.resp_body.size() ||
                             fnv1a(sent.exchange.resp_body.data(), sent.exchange.resp_body.size()) != fnv1a(baseline.exchange.resp_body.data(), baseline.exchange.resp_body.size());
        if (differs || body_has_success_terms(sent.exchange)) {
            accepted.push_back({{"value", value}, {"response", response_summary(sent.exchange)}});
        }
    }
    json issue_ids = json::array();
    if (!accepted.empty()) {
        const std::string evidence = "field=" + field + "; accepted_values=" + std::to_string(accepted.size()) + "; bodies not stored";
        uint64_t id = add_issue("business.price-tamper.accepted",
                                "Possible price tampering accepted",
                                severity_t::high, confidence_t::tentative, target, field,
                                "The endpoint accepted one or more manipulated price values with successful or differential responses.",
                                "Derive prices server-side from immutable product/catalog data and reject client-controlled totals, discounts, taxes, and balances.",
                                {"CWE-840", "CWE-642"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = !accepted.empty();
    data["field"] = field;
    data["tested_count"] = completed;
    data["accepted_values"] = accepted;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=price_tamper host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("price_tamper completed accepted=" + std::to_string(accepted.size()), std::move(data));
}

result_t coupon_abuse(const json& payload)
{
    const std::string url = get_string(payload, "url");
    const std::string field = get_string(payload, "coupon_field");
    const std::string coupon_value = get_string(payload, "coupon_value");
    if (url.empty()) return error_result("Missing url", "missing_param");
    if (field.empty()) return error_result("Missing coupon_field", "missing_param");
    if (coupon_value.empty()) return error_result("Missing coupon_value", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("coupon_abuse", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=coupon_abuse host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=coupon_abuse host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    const bool test_reuse = get_bool(payload, "test_reuse", true);
    const bool test_stacking = get_bool(payload, "test_stacking", true);
    const bool test_expired = get_bool(payload, "test_expired", true);
    const bool test_concurrent = get_bool(payload, "test_concurrent", true);
    const size_t total = (test_reuse ? 3 : 0) + (test_stacking ? 2 : 0) + (test_expired ? 2 : 0) + (test_concurrent ? get_size(payload, "concurrent_requests", 8, 2, 25) : 0);
    const std::string task_id = start_job("coupon_abuse", total == 0 ? 1 : total);
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "timeout_ms", 30000, 1000, 300000);
    std::map<std::string, std::string> base = params_from_payload(payload);
    base[field] = coupon_value;
    json reuse = json::array();
    json stacking = json::array();
    json expired = json::array();
    json concurrent_results = json::array();
    size_t completed = 0;
    bool cancelled = false;
    if (test_reuse) {
        for (int i = 0; i < 3; ++i) {
            if (call_cancelled()) { cancelled = true; break; }
            auto sent = send_param_request(target, method, base, payload, timeout_ms);
            ++completed;
            update_job_progress(task_id, completed);
            if (sent.ok && success_like(sent.exchange)) reuse.push_back({{"application_number", i + 1}, {"response", response_summary(sent.exchange)}});
        }
    }
    if (!cancelled && test_stacking) {
        std::vector<std::string> variants = {coupon_value + "," + coupon_value, coupon_value + "&" + coupon_value};
        for (const auto& variant : variants) {
            if (call_cancelled()) { cancelled = true; break; }
            std::map<std::string, std::string> params = params_from_payload(payload);
            params[field] = variant;
            auto sent = send_param_request(target, method, params, payload, timeout_ms);
            ++completed;
            update_job_progress(task_id, completed);
            if (sent.ok && success_like(sent.exchange)) stacking.push_back({{"coupon_summary", secret_summary(variant)}, {"response", response_summary(sent.exchange)}});
        }
    }
    if (!cancelled && test_expired) {
        std::vector<std::string> variants = {"EXPIRED-" + coupon_value, coupon_value + "-EXPIRED"};
        for (const auto& variant : variants) {
            if (call_cancelled()) { cancelled = true; break; }
            std::map<std::string, std::string> params = params_from_payload(payload);
            params[field] = variant;
            auto sent = send_param_request(target, method, params, payload, timeout_ms);
            ++completed;
            update_job_progress(task_id, completed);
            if (sent.ok && success_like(sent.exchange)) expired.push_back({{"coupon_summary", secret_summary(variant)}, {"response", response_summary(sent.exchange)}});
        }
    }
    if (!cancelled && test_concurrent) {
        const size_t concurrent = get_size(payload, "concurrent_requests", 8, 2, 25);
        const auto raw = build_request(target, method, target.path, base, get_string(payload, "body_mode", "form"), headers_from_payload(payload), get_string(payload, "auth_token"));
        auto results = concurrent_send(target, raw, concurrent, timeout_ms);
        for (size_t i = 0; i < results.size(); ++i) {
            ++completed;
            if (results[i].ok && success_like(results[i].exchange)) concurrent_results.push_back({{"request_number", i + 1}, {"response", response_summary(results[i].exchange)}});
        }
        update_job_progress(task_id, completed);
    }
    const bool reuse_vulnerable = reuse.size() > 1;
    const bool stacking_vulnerable = !stacking.empty();
    const bool expired_vulnerable = !expired.empty();
    const bool concurrent_vulnerable = concurrent_results.size() > 1;
    json issue_ids = json::array();
    if (reuse_vulnerable || stacking_vulnerable || expired_vulnerable || concurrent_vulnerable) {
        const std::string evidence = "reuse=" + std::to_string(reuse.size()) + "; stacking=" + std::to_string(stacking.size()) + "; expired=" + std::to_string(expired.size()) + "; concurrent=" + std::to_string(concurrent_results.size()) + "; coupon values redacted";
        uint64_t id = add_issue("business.coupon-abuse.accepted",
                                "Possible coupon abuse",
                                severity_t::high, confidence_t::tentative, target, field,
                                "Coupon reuse, stacking, expired-coupon, or concurrent application attempts produced successful responses.",
                                "Enforce coupon validity, single-use constraints, per-order uniqueness, and atomic redemption server-side.",
                                {"CWE-840", "CWE-362"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["coupon_value_summary"] = secret_summary(coupon_value);
    data["reuse_vulnerable"] = reuse_vulnerable;
    data["stacking_vulnerable"] = stacking_vulnerable;
    data["expired_vulnerable"] = expired_vulnerable;
    data["concurrent_vulnerable"] = concurrent_vulnerable;
    data["reuse_evidence"] = reuse;
    data["stacking_evidence"] = stacking;
    data["expired_evidence"] = expired;
    data["concurrent_evidence"] = concurrent_results;
    data["max_applications"] = std::max(reuse.size(), concurrent_results.size());
    data["tested_count"] = completed;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=coupon_abuse host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("coupon_abuse completed", std::move(data));
}

result_t workflow_bypass(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("workflow_bypass", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=workflow_bypass host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=workflow_bypass host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    const std::string task_id = start_job("workflow_bypass", 1);
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "timeout_ms", 15000, 1000, 300000);
    auto sent = send_param_request(target, method, params_from_payload(payload), payload, timeout_ms);
    update_job_progress(task_id, 1);
    json skipped = json::array();
    if (payload.contains("steps_to_skip") && payload["steps_to_skip"].is_array()) {
        size_t step_index = 0;
        for (const auto& s : payload["steps_to_skip"]) {
            ++step_index;
            json item;
            if (s.is_object()) {
                const std::string name = get_string(s, "name", "step_" + std::to_string(step_index));
                const std::string step_url = get_string(s, "url");
                item["name"] = name;
                if (!step_url.empty()) item["url_summary"] = secret_summary(step_url);
            } else {
                item["name"] = "step_" + std::to_string(step_index);
                item["value_summary"] = secret_summary(json_string_value(s));
            }
            skipped.push_back(std::move(item));
        }
    }
    const bool vulnerable = sent.ok && success_like(sent.exchange);
    json issue_ids = json::array();
    if (vulnerable) {
        const std::string evidence = "final step accepted without declared prerequisites; skipped_steps=" + std::to_string(skipped.size());
        uint64_t id = add_issue("business.workflow-bypass.final-step-accepted",
                                "Possible workflow bypass",
                                severity_t::high, confidence_t::tentative, target, "",
                                "A final or privileged workflow endpoint returned a successful response when called directly without completing declared prerequisite steps.",
                                "Validate workflow state server-side before every step transition and make finalization endpoints idempotent and state-bound.",
                                {"CWE-840", "CWE-862"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = vulnerable;
    data["steps_skipped"] = skipped;
    data["final_step_completed"] = vulnerable;
    if (sent.ok) data["response"] = response_summary(sent.exchange);
    else data["transport_error"] = sent.error;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, 1, false, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=workflow_bypass host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("workflow_bypass completed", std::move(data));
}

result_t quantity_tamper(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("quantity_tamper", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=quantity_tamper host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=quantity_tamper host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    std::map<std::string, std::string> params = params_from_payload(payload);
    const std::string field = get_string(payload, "quantity_field", get_string(payload, "param_target", detect_field(params, {"quantity", "qty", "count", "units", "amount"}, "quantity")));
    std::vector<std::string> values = string_array(payload, "test_values");
    if (values.empty()) values = {"-1", "-100", "-999999", "-0.01", "0", "2147483647", "2147483648", "4294967295", "9223372036854775807"};
    if (values.size() > kMaxTamperValues) values.resize(kMaxTamperValues);
    const std::string task_id = start_job("quantity_tamper", values.size());
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "timeout_ms", 15000, 1000, 300000);
    json accepted = json::array();
    size_t completed = 0;
    bool cancelled = false;
    for (const auto& value : values) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::map<std::string, std::string> mutated = params;
        mutated[field] = value;
        auto sent = send_param_request(target, method, mutated, payload, timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (sent.ok && success_like(sent.exchange)) accepted.push_back({{"value", value}, {"response", response_summary(sent.exchange)}});
    }
    json issue_ids = json::array();
    if (!accepted.empty()) {
        const std::string evidence = "field=" + field + "; accepted_values=" + std::to_string(accepted.size());
        uint64_t id = add_issue("business.quantity-tamper.accepted",
                                "Possible quantity tampering accepted",
                                severity_t::high, confidence_t::tentative, target, field,
                                "The endpoint accepted negative, zero, fractional, or boundary quantity values with successful responses.",
                                "Validate numeric business inputs server-side, use safe integer ranges, and recompute totals from server-side state.",
                                {"CWE-190", "CWE-1284", "CWE-840"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = !accepted.empty();
    data["field"] = field;
    data["tested_count"] = completed;
    data["accepted_values"] = accepted;
    data["cancelled"] = cancelled;
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=quantity_tamper host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("quantity_tamper completed accepted=" + std::to_string(accepted.size()), std::move(data));
}

result_t role_escalation(const json& payload)
{
    const std::string url = get_string(payload, "url");
    if (url.empty()) return error_result("Missing url", "missing_param");
    target_t target;
    std::string err;
    if (!parse_target(url, target, err)) return error_result(err, "invalid_url");
    auto admission = acquire_biz_admission("role_escalation", target.host);
    if (!admission.active()) {
        diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-REJECT action=role_escalation host=%s reason=%s quota=%s observed=%zu limit=%zu",
            target.host.c_str(),
            admission.result().reason.c_str(),
            admission.result().quota_name.c_str(),
            admission.result().observed, admission.result().limit);
        return error_result("Downstream capacity exhausted", "downstream_capacity_reject");
    }
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-ADMIT action=role_escalation host=%s token=%llu",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    std::map<std::string, std::string> params = params_from_payload(payload);
    const std::string field = get_string(payload, "role_field", get_string(payload, "param_target", detect_field(params, {"role", "is_admin", "admin", "permission", "scope", "tier"}, "role")));
    std::vector<std::string> values = string_array(payload, "test_values");
    if (values.empty()) values = {"admin", "administrator", "superuser", "owner", "true", "1", "all", "root"};
    if (values.size() > kMaxTamperValues) values.resize(kMaxTamperValues);
    const std::string task_id = start_job("role_escalation", values.size());
    const std::string method = get_string(payload, "method", "POST");
    const int timeout_ms = get_int(payload, "timeout_ms", 15000, 1000, 300000);
    json accepted = json::array();
    size_t completed = 0;
    bool cancelled = false;
    for (const auto& value : values) {
        if (call_cancelled()) {
            cancelled = true;
            break;
        }
        std::map<std::string, std::string> mutated = params;
        mutated[field] = value;
        auto sent = send_param_request(target, method, mutated, payload, timeout_ms);
        ++completed;
        update_job_progress(task_id, completed);
        if (sent.ok && success_like(sent.exchange)) accepted.push_back({{"role_value_summary", secret_summary(value)}, {"response", response_summary(sent.exchange)}});
    }
    json issue_ids = json::array();
    if (!accepted.empty()) {
        const std::string evidence = "field=" + field + "; accepted_role_values=" + std::to_string(accepted.size()) + "; values redacted";
        uint64_t id = add_issue("business.role-escalation.accepted",
                                "Possible role escalation via client-controlled field",
                                severity_t::critical, confidence_t::tentative, target, field,
                                "The endpoint accepted client-controlled role or privilege values with successful responses.",
                                "Ignore client-supplied roles and permissions; derive authorization from server-side identity and policy state.",
                                {"CWE-266", "CWE-269", "CWE-862"}, evidence);
        issue_ids.push_back(id);
    }
    json data;
    data["task_id"] = task_id;
    data["vulnerable"] = !accepted.empty();
    data["field"] = field;
    data["tested_count"] = completed;
    data["accepted_values"] = accepted;
    data["cancelled"] = cancelled;
    data["auth_token_summary"] = secret_summary(get_string(payload, "auth_token"));
    data["issues_created"] = issue_ids;
    finish_job(task_id, data, completed, cancelled, {});
    diag::log_tagged_fmt("biz_logic", "BURP-NETWORK-WORKER-RELEASE action=role_escalation host=%s token=%llu reason=completed",
        target.host.c_str(), static_cast<unsigned long long>(admission.token()));
    return ok_result("role_escalation completed accepted=" + std::to_string(accepted.size()), std::move(data));
}

result_t get_status(const json& payload)
{
    const std::string task_id = get_string(payload, "task_id");
    if (task_id.empty()) {
        json data;
        data["jobs"] = all_status_json();
        return ok_result("business logic job status list", std::move(data));
    }
    std::lock_guard<std::mutex> lk(jobs_mutex());
    auto it = jobs().find(task_id);
    if (it == jobs().end()) return error_result("Unknown task_id", "not_found");
    return ok_result("business logic job status", job_status_json(it->second));
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
    return ok_result("business logic job results", std::move(data));
}

result_t handle_action(const std::string& action_raw, const json& payload)
{
    const std::string action = lower_ascii(action_raw);
    if (action == "race_test") return race_test(payload);
    if (action == "price_tamper" || action == "price_manipulation") return price_tamper(payload);
    if (action == "coupon_abuse") return coupon_abuse(payload);
    if (action == "workflow_bypass" || action == "step_skip") return workflow_bypass(payload);
    if (action == "quantity_tamper" || action == "integer_overflow_test" || action == "negative_value_test") return quantity_tamper(payload);
    if (action == "role_escalation" || action == "privilege_escalation") return role_escalation(payload);
    if (action == "get_status" || action == "status") return get_status(payload);
    if (action == "get_results" || action == "results") return get_results(payload);
    return error_result("aida_offensive_business_logic_manage unknown action: " + action_raw, "unknown_action");
}

}
}
}
}
