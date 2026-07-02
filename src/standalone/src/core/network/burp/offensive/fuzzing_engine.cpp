#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "fuzzing_engine.hpp"

#include "../audit_http.hpp"
#include "../intruder_engine.hpp"
#include "../issue.hpp"
#include "../payload_library.hpp"
#include "../scope.hpp"
#include "../../js_analysis_tools_standalone.hpp"
#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace offensive {
namespace fuzzing {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct fuzz_job_t
{
    std::uint64_t id = 0;
    std::uint64_t intruder_job_id = 0;
    std::string target;
    std::uint64_t started_ms = 0;
    json baseline = json::object();
    bool detect_anomalies = true;
    bool accepted = false;
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

std::unordered_map<std::uint64_t, fuzz_job_t>& jobs()
{
    static std::unordered_map<std::uint64_t, fuzz_job_t> j;
    return j;
}

std::mutex& corpus_mtx()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, std::vector<std::string>>& corpora()
{
    static std::unordered_map<std::string, std::vector<std::string>> c;
    return c;
}

std::uint64_t wall_ms()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
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

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80))
        return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

std::string body_to_string(const std::vector<std::uint8_t>& body)
{
    if (body.empty())
        return {};
    return std::string(reinterpret_cast<const char*>(body.data()), body.size());
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

std::string url_encode(const std::string& value)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0x0F]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
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
    out += url_encode(name);
    out += "=";
    out += url_encode(value);
    out += fragment;
    return out;
}

std::vector<std::uint8_t> build_request(const std::string& method,
                                        const std::string& url,
                                        const json& headers_json,
                                        const std::string& body,
                                        const std::string& content_type,
                                        std::string& scheme,
                                        std::string& host,
                                        std::uint16_t& port,
                                        std::string& path,
                                        std::string& error)
{
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        error = "url parse failed";
        return {};
    }
    const bool tls = scheme == "https";
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
        req << "Accept: application/json,text/html,text/plain,*/*\r\n";
    if (!body.empty() && !has_content_type && !content_type.empty())
        req << "Content-Type: " << content_type << "\r\n";
    req << "User-Agent: AiDA-Fuzzer/1.0\r\n";
    if (!body.empty())
        req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body;
    const std::string raw = req.str();
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

std::optional<exchange_observed_t> send_baseline(const std::string& method,
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
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    std::vector<std::uint8_t> req = build_request(method, url, headers, body, content_type, scheme, host, port, path, error);
    if (req.empty())
        return std::nullopt;
    audit_http::send_options_t opts;
    opts.timeout_ms = timeout_ms;
    opts.enforce_scope = enforce_scope;
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.exchange_source = "offensive_fuzzing_baseline";
    auto resp = audit_http::send(req, host, port, scheme == "https", opts);
    if (!resp.has_value())
        error = audit_http::last_error();
    return resp;
}

json exchange_summary(const exchange_observed_t& ex)
{
    const std::string body = body_to_string(ex.resp_body);
    json out;
    out["status"] = ex.status_code;
    out["latency_ms"] = ex.latency_ms;
    out["body_length"] = static_cast<std::uint64_t>(ex.resp_body.size());
    out["body_sha256"] = aida::network::js_analysis_tools::sha256_hex(body);
    return out;
}

std::vector<std::string> strings_from_json(const json& src, std::size_t max_count)
{
    std::vector<std::string> out;
    if (!src.is_array())
        return out;
    for (const auto& item : src) {
        if (out.size() >= max_count)
            break;
        if (!item.is_string())
            continue;
        std::string text = item.get<std::string>();
        if (!text.empty())
            out.push_back(std::move(text));
    }
    return out;
}

std::vector<std::string> payloads_from_position(const json& position, const json& params)
{
    std::vector<std::string> out = strings_from_json(position.value("custom_payloads", json::array()), 1024);
    if (!out.empty())
        return out;
    if (position.contains("payload_set_id") && position["payload_set_id"].is_string()) {
        payloads::initialize();
        out = payloads::entries(position["payload_set_id"].get<std::string>(), static_cast<std::size_t>(std::max(1, std::min(params.value("max_payloads_per_set", 128), 2048))));
        if (!out.empty())
            return out;
    }
    if (params.contains("payload_sets") && params["payload_sets"].is_array()) {
        payloads::initialize();
        for (const auto& id : params["payload_sets"]) {
            if (!id.is_string())
                continue;
            auto rows = payloads::entries(id.get<std::string>(), static_cast<std::size_t>(std::max(1, std::min(params.value("max_payloads_per_set", 128), 2048))));
            out.insert(out.end(), rows.begin(), rows.end());
            if (out.size() >= 2048)
                break;
        }
        if (!out.empty())
            return out;
    }
    return {"aida_probe", "' OR '1'='1", "\"><svg/onload=alert(1)>", "../../etc/passwd", "{{7*7}}", "%s%s%s%s"};
}

bool parse_numeric_positions(const json& positions, std::vector<std::pair<std::size_t, std::size_t>>& out)
{
    if (!positions.is_array())
        return false;
    for (const auto& item : positions) {
        if (!item.is_array() || item.size() < 2)
            continue;
        if (!item[0].is_number() || !item[1].is_number())
            continue;
        out.emplace_back(item[0].get<std::size_t>(), item[1].get<std::size_t>());
    }
    return !out.empty();
}

std::string raw_request_target(const std::string& raw)
{
    const std::size_t eol = raw.find("\r\n");
    const std::size_t line_end = eol == std::string::npos ? raw.find('\n') : eol;
    const std::string first_line = raw.substr(0, line_end == std::string::npos ? raw.size() : line_end);
    std::istringstream iss(first_line);
    std::string method;
    std::string target;
    iss >> method >> target;
    return target.empty() ? std::string("/") : target;
}

std::string scoped_url_from_parts(const std::string& scheme, const std::string& host, std::uint16_t port, const std::string& target)
{
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0)
        return target;
    std::string url = scheme.empty() ? std::string("https://") : scheme + "://";
    url += host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        url += ":" + std::to_string(static_cast<unsigned>(port));
    if (target.empty() || target.front() != '/')
        url += "/";
    url += target.empty() ? std::string() : target;
    return url;
}

std::string request_target_path(const std::string& target)
{
    if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
        std::string scheme;
        std::string host;
        std::string path;
        std::uint16_t port = 0;
        if (audit_http::parse_url(target, scheme, host, port, path))
            return path.empty() ? std::string("/") : path;
    }
    return target.empty() ? std::string("/") : target;
}

bool build_marked_request(const json& params,
                          intruder::config_t& cfg,
                          json& position_summary,
                          std::string& error)
{
    if (params.contains("raw_request") && params["raw_request"].is_string()) {
        const std::string raw = params["raw_request"].get<std::string>();
        cfg.base_request.assign(raw.begin(), raw.end());
        if (!params.contains("host") || !params["host"].is_string()) {
            error = "host required when raw_request is supplied";
            return false;
        }
        cfg.host = params["host"].get<std::string>();
        cfg.scheme = params.value("scheme", std::string("https"));
        cfg.port = static_cast<std::uint16_t>(params.value("port", cfg.scheme == "https" ? 443 : 80));
        if (params.value("enforce_scope", true)) {
            const std::string target = raw_request_target(raw);
            const std::string declared_url = scoped_url_from_parts(cfg.scheme, cfg.host, cfg.port, target);
            const std::string transport_url = scoped_url_from_parts(cfg.scheme, cfg.host, cfg.port, request_target_path(target));
            if (!scope::in_scope(declared_url) || !scope::in_scope(transport_url)) {
                error = "target out of scope";
                return false;
            }
        }
        if (!parse_numeric_positions(params.value("positions", json::array()), cfg.positions)) {
            error = "numeric positions required when raw_request is supplied";
            return false;
        }
        std::vector<std::string> payload_set = strings_from_json(params.value("custom_payloads", json::array()), 2048);
        if (payload_set.empty() && params.contains("payload_set_id") && params["payload_set_id"].is_string()) {
            payloads::initialize();
            payload_set = payloads::entries(params["payload_set_id"].get<std::string>(), static_cast<std::size_t>(std::max(1, std::min(params.value("max_payloads_per_set", 128), 2048))));
        }
        if (payload_set.empty())
            payload_set = {"aida_probe"};
        for (std::size_t i = 0; i < cfg.positions.size(); ++i)
            cfg.payload_sets.push_back(payload_set);
        position_summary.push_back(json{{"source", "raw_request"}, {"count", static_cast<std::uint64_t>(cfg.positions.size())}});
        return true;
    }

    const std::string url = params.value("url", std::string());
    if (url.empty()) {
        error = "url required";
        return false;
    }
    if (params.value("enforce_scope", true) && !scope::in_scope(url)) {
        error = "target out of scope";
        return false;
    }
    const std::string method = params.value("method", std::string("GET"));
    const std::string content_type = params.value("content_type", params.contains("body_json") ? std::string("application/json") : std::string("text/plain"));
    std::string body = params.value("body", std::string());
    if (params.contains("body_json"))
        body = params["body_json"].dump();
    std::string marked_url = url;
    json headers = params.value("headers", json::object());
    json positions = params.value("positions", json::array());
    if (!positions.is_array() || positions.empty()) {
        positions = json::array({json{{"location", "query"}, {"param_name", "aida_fuzz"}, {"payload_set_id", params.value("wordlist_id", std::string("fuzz/common_params"))}}});
    }

    struct marker_t
    {
        std::string token;
        std::vector<std::string> payloads;
        json summary;
    };
    std::vector<marker_t> markers;
    int index = 0;
    for (const auto& pos : positions) {
        if (!pos.is_object())
            continue;
        const std::string token = "AIDA_FUZZ_MARKER_" + std::to_string(index++);
        const std::string location = lower_copy(pos.value("location", std::string("query")));
        const std::string name = pos.value("param_name", pos.value("name", std::string("aida_fuzz")));
        if (location == "query") {
            marked_url = append_query_param(marked_url, name, token);
        } else if (location == "header") {
            headers[name.empty() ? std::string("X-AiDA-Fuzz") : name] = token;
        } else if (location == "cookie") {
            headers["Cookie"] = (name.empty() ? std::string("aida_fuzz") : name) + "=" + token;
        } else if (location == "body" || location == "json_field") {
            if (body.empty() || location == "json_field") {
                json body_json = params.contains("body_json") && params["body_json"].is_object() ? params["body_json"] : json::object();
                body_json[name.empty() ? std::string("aida_fuzz") : name] = token;
                body = body_json.dump();
            } else {
                body += token;
            }
        } else if (location == "path") {
            marked_url = append_query_param(marked_url, name.empty() ? std::string("aida_path") : name, token);
        } else {
            continue;
        }
        marker_t marker;
        marker.token = token;
        marker.payloads = payloads_from_position(pos, params);
        marker.summary = json{{"location", location}, {"name", name}, {"payload_count", static_cast<std::uint64_t>(marker.payloads.size())}};
        markers.push_back(std::move(marker));
    }

    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    cfg.base_request = build_request(method, marked_url, headers, body, content_type, scheme, host, port, path, error);
    if (cfg.base_request.empty())
        return false;
    cfg.scheme = scheme;
    cfg.host = host;
    cfg.port = port;
    const std::string raw_text(reinterpret_cast<const char*>(cfg.base_request.data()), cfg.base_request.size());
    for (const marker_t& marker : markers) {
        const std::size_t off = raw_text.find(marker.token);
        if (off == std::string::npos)
            continue;
        cfg.positions.emplace_back(off, marker.token.size());
        cfg.payload_sets.push_back(marker.payloads);
        position_summary.push_back(marker.summary);
    }
    if (cfg.positions.empty()) {
        error = "no injection positions resolved";
        return false;
    }
    return true;
}

json intruder_status_json(const intruder::status_t& st)
{
    json out;
    out["intruder_job_id"] = st.job_id;
    out["total"] = static_cast<std::uint64_t>(st.total);
    out["sent"] = static_cast<std::uint64_t>(st.sent);
    out["errors"] = static_cast<std::uint64_t>(st.errors);
    out["running"] = st.running;
    out["current_rps"] = st.current_rps;
    out["started_unix_ms"] = st.started_unix_ms;
    out["finished_unix_ms"] = st.finished_unix_ms;
    return out;
}

json payloads_summary(const std::vector<std::string>& payloads)
{
    json arr = json::array();
    for (const std::string& payload : payloads) {
        json p;
        p["sha256"] = aida::network::js_analysis_tools::sha256_hex(payload);
        p["length"] = static_cast<std::uint64_t>(payload.size());
        p["preview"] = aida::network::js_analysis_tools::redact_sensitive_values(payload.size() > 120 ? payload.substr(0, 120) + "..." : payload);
        arr.push_back(std::move(p));
    }
    return arr;
}

json result_row_json(const intruder::result_t& r)
{
    json row;
    row["index"] = static_cast<std::uint64_t>(r.index);
    row["status_code"] = r.status_code;
    row["response_size"] = static_cast<std::uint64_t>(r.response_size);
    row["latency_ms"] = r.latency_ms;
    row["error"] = r.error;
    row["error_msg"] = r.error_msg;
    row["payloads"] = payloads_summary(r.payloads);
    row["response_preview"] = aida::network::js_analysis_tools::redact_sensitive_values(r.response_preview);
    return row;
}

bool find_job(std::uint64_t id, fuzz_job_t& out)
{
    std::lock_guard<std::mutex> lk(jobs_mtx());
    auto it = jobs().find(id);
    if (it == jobs().end())
        return false;
    out = it->second;
    return true;
}

json job_json(const fuzz_job_t& job)
{
    json out;
    out["job_id"] = job.id;
    out["intruder_job_id"] = job.intruder_job_id;
    out["target"] = aida::network::js_analysis_tools::redact_url_for_output(job.target);
    out["started_ms"] = job.started_ms;
    out["accepted"] = job.accepted;
    out["detect_anomalies"] = job.detect_anomalies;
    out["baseline"] = job.baseline;
    out["intruder_status"] = intruder_status_json(intruder::status(job.intruder_job_id));
    return out;
}

std::uint64_t add_issue(const std::string& url, const json& anomaly_summary)
{
    issue_store::initialize();
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    audit_http::parse_url(url, scheme, host, port, path);
    issue_t issue;
    issue.type_key = "fuzzing.response-anomalies";
    issue.name = "Fuzzing response anomalies observed";
    issue.severity = severity_t::medium;
    issue.confidence = confidence_t::tentative;
    issue.scheme = scheme;
    issue.host = host;
    issue.port = port;
    issue.path = path.empty() ? "/" : path;
    issue.parameter = "fuzzing";
    issue.insertion_point = "fuzzing";
    issue.description = "Fuzzed requests produced status, length, latency, error, or content anomaly signals compared with baseline.";
    issue.remediation = "Review anomalous inputs, enforce strict parser validation, and normalize error handling for malformed client-controlled data.";
    issue.seen_ms = wall_ms();
    evidence_t evidence;
    evidence.request_raw = "url=" + aida::network::js_analysis_tools::redact_url_for_output(url);
    evidence.response_raw = anomaly_summary.dump();
    evidence.marker = "fuzzing_anomaly";
    issue.evidence.push_back(std::move(evidence));
    return issue_store::add(std::move(issue));
}

std::vector<std::string> mutation_strategies(const json& params)
{
    auto strategies = strings_from_json(params.value("mutation_strategies", json::array()), 32);
    if (strategies.empty())
        strategies = {"special_chars", "unicode", "null_bytes", "format_strings", "long_strings", "boundary_values", "case_flip"};
    if (std::find(strategies.begin(), strategies.end(), "all") != strategies.end())
        strategies = {"special_chars", "unicode", "null_bytes", "format_strings", "long_strings", "boundary_values", "case_flip", "byte_insert", "byte_delete"};
    return strategies;
}

void append_unique(std::vector<std::string>& out, const std::string& value, std::size_t max_count)
{
    if (out.size() >= max_count)
        return;
    if (std::find(out.begin(), out.end(), value) == out.end())
        out.push_back(value);
}

std::vector<std::string> mutate_seed(const std::string& seed, const std::vector<std::string>& strategies, std::size_t max_count)
{
    std::vector<std::string> out;
    for (const std::string& strategy : strategies) {
        if (out.size() >= max_count)
            break;
        if (strategy == "special_chars") {
            for (const char* s : {"'", "\"", "<>", "../", "{{7*7}}", "$()", "`id`", "\r\nX-AiDA: probe"})
                append_unique(out, seed + s, max_count);
        } else if (strategy == "unicode") {
            append_unique(out, seed + "\xE2\x80\xAE", max_count);
            append_unique(out, seed + "\xF0\x9F\x92\xA5", max_count);
        } else if (strategy == "null_bytes") {
            append_unique(out, seed + std::string("%00"), max_count);
            append_unique(out, seed + std::string("\0", 1), max_count);
        } else if (strategy == "format_strings") {
            append_unique(out, seed + "%s%s%s%s", max_count);
            append_unique(out, seed + "%x%x%x%x", max_count);
            append_unique(out, seed + "%n%n", max_count);
        } else if (strategy == "long_strings") {
            append_unique(out, seed + std::string(1024, 'A'), max_count);
            append_unique(out, std::string(4096, 'B'), max_count);
        } else if (strategy == "boundary_values") {
            append_unique(out, "0", max_count);
            append_unique(out, "-1", max_count);
            append_unique(out, "2147483647", max_count);
            append_unique(out, "-2147483648", max_count);
            append_unique(out, "9223372036854775807", max_count);
        } else if (strategy == "case_flip") {
            std::string flipped = seed;
            for (std::size_t i = 0; i < flipped.size(); ++i) {
                if (i % 2 == 0)
                    flipped[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(flipped[i])));
                else
                    flipped[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(flipped[i])));
            }
            append_unique(out, flipped, max_count);
        } else if (strategy == "byte_insert") {
            append_unique(out, seed + "AAAA", max_count);
            append_unique(out, "AAAA" + seed, max_count);
        } else if (strategy == "byte_delete") {
            if (!seed.empty())
                append_unique(out, seed.substr(0, seed.size() / 2), max_count);
        }
    }
    return out;
}

}

tool_result_t start(const json& params)
{
    intruder::config_t cfg;
    json position_summary = json::array();
    std::string error;
    if (!build_marked_request(params, cfg, position_summary, error))
        return tool_result_t::error(error);
    intruder::attack_mode_t attack_mode = intruder::attack_mode_t::sniper;
    intruder::engine_mode_t engine_mode = intruder::engine_mode_t::http1_pooled;
    if (!intruder::parse_attack_mode(params.value("attack_mode", std::string("sniper")), attack_mode))
        return tool_result_t::error("invalid attack_mode");
    if (!intruder::parse_engine_mode(params.value("engine_mode", std::string("http1_pooled")), engine_mode))
        return tool_result_t::error("invalid engine_mode");
    cfg.attack_mode = attack_mode;
    cfg.engine_mode = engine_mode;
    cfg.concurrency = static_cast<std::size_t>(std::max(1, std::min(params.value("concurrency", 16), 128)));
    cfg.requests_per_second_cap = static_cast<std::size_t>(std::max(0, std::min(params.value("rate_limit_rps", 0), 10000)));
    cfg.total_requests_cap = static_cast<std::size_t>(std::max(0, std::min(params.value("max_requests", 0), 100000)));
    cfg.timeout_ms = bounded_timeout_ms(params, 15000, 120000);
    cfg.follow_redirects = params.value("follow_redirects", false) ? 1 : 0;
    cfg.max_response_body_bytes = static_cast<std::size_t>(std::max(1024, std::min(params.value("max_response_body_bytes", 65536), 1048576)));

    json baseline = json::object();
    std::string baseline_error;
    const std::string original_url = params.value("url", std::string());
    if (!original_url.empty() && params.value("baseline_requests", 1) > 0) {
        auto base = send_baseline(params.value("method", std::string("GET")), original_url, params.value("headers", json::object()),
                                  params.value("body", std::string()), params.value("content_type", std::string()),
                                  bounded_timeout_ms(params, 15000, 60000), params.value("enforce_scope", true), baseline_error);
        if (base.has_value())
            baseline = exchange_summary(*base);
        else
            baseline["error"] = baseline_error;
    }

    const std::uint64_t intruder_id = intruder::start(cfg);
    if (intruder_id == 0)
        return tool_result_t::error(std::string("intruder start failed: ") + intruder::last_error());

    fuzz_job_t job;
    job.id = next_job_id().fetch_add(1);
    job.intruder_job_id = intruder_id;
    job.target = original_url.empty() ? cfg.host : original_url;
    job.started_ms = wall_ms();
    job.baseline = baseline;
    job.detect_anomalies = params.value("detect_anomalies", true);
    job.accepted = true;
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        jobs()[job.id] = job;
    }
    json out;
    out["job_id"] = job.id;
    out["intruder_job_id"] = intruder_id;
    out["positions_count"] = static_cast<std::uint64_t>(cfg.positions.size());
    out["positions"] = std::move(position_summary);
    out["attack_mode"] = intruder::attack_mode_name(cfg.attack_mode);
    out["engine_mode"] = intruder::engine_mode_name(cfg.engine_mode);
    out["baseline"] = baseline;
    out["status"] = intruder_status_json(intruder::status(intruder_id));
    return tool_result_t::ok("fuzzing job started", out);
}

tool_result_t stop(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    fuzz_job_t job;
    if (!find_job(job_id, job))
        return tool_result_t::error("job not found");
    const bool stopped = intruder::stop(job.intruder_job_id);
    json out;
    out["job_id"] = job_id;
    out["intruder_job_id"] = job.intruder_job_id;
    out["stopped"] = stopped;
    out["status"] = intruder_status_json(intruder::status(job.intruder_job_id));
    return stopped ? tool_result_t::ok("fuzzing job stopped", out) : tool_result_t::error("intruder job not found", out);
}

tool_result_t status(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id != 0) {
        fuzz_job_t job;
        if (!find_job(job_id, job))
            return tool_result_t::error("job not found");
        return tool_result_t::ok(job_json(job));
    }
    json arr = json::array();
    {
        std::lock_guard<std::mutex> lk(jobs_mtx());
        for (const auto& kv : jobs())
            arr.push_back(job_json(kv.second));
    }
    return tool_result_t::ok(json{{"count", arr.size()}, {"jobs", arr}});
}

tool_result_t results(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    fuzz_job_t job;
    if (!find_job(job_id, job))
        return tool_result_t::error("job not found");
    const std::size_t start_idx = static_cast<std::size_t>(params.value("start", 0u));
    const std::size_t max_rows = static_cast<std::size_t>(std::max(1, std::min(params.value("max", 256), 2048)));
    auto rows = intruder::results(job.intruder_job_id, start_idx, max_rows);
    json arr = json::array();
    for (const auto& row : rows)
        arr.push_back(result_row_json(row));
    json out;
    out["job"] = job_json(job);
    out["count"] = arr.size();
    out["window_start"] = static_cast<std::uint64_t>(start_idx);
    out["results"] = std::move(arr);
    return tool_result_t::ok(out);
}

tool_result_t mutate(const json& params)
{
    std::vector<std::string> seeds = strings_from_json(params.value("seeds", json::array()), 256);
    if (seeds.empty() && params.contains("seed") && params["seed"].is_string())
        seeds.push_back(params["seed"].get<std::string>());
    if (seeds.empty() && params.contains("params") && params["params"].is_object()) {
        for (auto it = params["params"].begin(); it != params["params"].end(); ++it) {
            if (seeds.size() >= 64)
                break;
            seeds.push_back(it.value().is_string() ? it.value().get<std::string>() : it.value().dump());
        }
    }
    if (seeds.empty())
        seeds = {"aida"};
    const std::size_t max_outputs = static_cast<std::size_t>(std::max(1, std::min(params.value("max_outputs", 128), 1024)));
    const auto strategies = mutation_strategies(params);
    std::vector<std::string> mutated;
    for (const std::string& seed : seeds) {
        auto rows = mutate_seed(seed, strategies, max_outputs);
        for (const std::string& row : rows) {
            append_unique(mutated, row, max_outputs);
            if (mutated.size() >= max_outputs)
                break;
        }
        if (mutated.size() >= max_outputs)
            break;
    }
    json arr = json::array();
    for (const std::string& payload : mutated) {
        json row;
        row["payload"] = aida::network::js_analysis_tools::redact_sensitive_values(payload);
        row["sha256"] = aida::network::js_analysis_tools::sha256_hex(payload);
        row["length"] = static_cast<std::uint64_t>(payload.size());
        arr.push_back(std::move(row));
    }
    json out;
    out["count"] = arr.size();
    out["strategies"] = strategies;
    out["payloads"] = std::move(arr);
    return tool_result_t::ok(out);
}

tool_result_t corpus_add(const json& params)
{
    std::string corpus_id = params.value("corpus_id", params.value("id", std::string("default")));
    if (corpus_id.empty())
        corpus_id = "default";
    for (char& c : corpus_id) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '/'))
            c = '_';
    }
    std::vector<std::string> corpus_payloads = strings_from_json(params.value("payloads", json::array()), 10000);
    if (corpus_payloads.empty())
        return tool_result_t::error("payloads array required");
    const std::string payload_set_id = corpus_id.find('/') == std::string::npos ? "offensive/fuzz/" + corpus_id : corpus_id;
    {
        std::lock_guard<std::mutex> lk(corpus_mtx());
        auto& existing = corpora()[payload_set_id];
        for (const std::string& payload : corpus_payloads)
            append_unique(existing, payload, 100000);
        corpus_payloads = existing;
    }
    payloads::initialize();
    const bool added = payloads::add_custom_set(payload_set_id, payload_set_id, "AiDA offensive fuzzing corpus", corpus_payloads);
    json out;
    out["corpus_id"] = payload_set_id;
    out["payload_count"] = static_cast<std::uint64_t>(corpus_payloads.size());
    out["payload_library_registered"] = added;
    out["raw_payloads_returned"] = false;
    out["payload_hashes"] = json::array();
    for (std::size_t i = 0; i < corpus_payloads.size() && i < 256; ++i)
        out["payload_hashes"].push_back(aida::network::js_analysis_tools::sha256_hex(corpus_payloads[i]));
    return added ? tool_result_t::ok(out) : tool_result_t::error(payloads::last_error(), out);
}

tool_result_t anomaly_analyze(const json& params)
{
    const std::uint64_t job_id = params.value("job_id", 0ull);
    if (job_id == 0)
        return tool_result_t::error("job_id required");
    fuzz_job_t job;
    if (!find_job(job_id, job))
        return tool_result_t::error("job not found");
    const double threshold = std::max(0.01, std::min(params.value("threshold", 0.10), 1.0));
    const std::size_t max_rows = static_cast<std::size_t>(std::max(1, std::min(params.value("max_results", 2048), 10000)));
    auto rows = intruder::results(job.intruder_job_id, 0, max_rows);
    const int baseline_status = job.baseline.value("status", 0);
    const std::uint64_t baseline_len = job.baseline.value("body_length", 0ull);
    const std::uint64_t baseline_latency = job.baseline.value("latency_ms", 0ull);
    json anomalies = json::array();
    for (const auto& row : rows) {
        bool anomaly = row.error;
        json reasons = json::array();
        if (row.error) {
            reasons.push_back("transport_error");
        }
        if (baseline_status != 0 && row.status_code != baseline_status) {
            anomaly = true;
            reasons.push_back("status_diff");
        }
        if (baseline_len != 0) {
            const double delta = std::abs(static_cast<double>(row.response_size) - static_cast<double>(baseline_len)) / static_cast<double>(baseline_len);
            if (delta >= threshold) {
                anomaly = true;
                reasons.push_back("length_diff");
            }
        }
        if (baseline_latency != 0 && row.latency_ms > baseline_latency * 2 + 500) {
            anomaly = true;
            reasons.push_back("time_diff");
        }
        const std::string preview_lc = lower_copy(row.response_preview);
        if (preview_lc.find("exception") != std::string::npos || preview_lc.find("traceback") != std::string::npos ||
            preview_lc.find("sql syntax") != std::string::npos || preview_lc.find("warning:") != std::string::npos) {
            anomaly = true;
            reasons.push_back("error_content");
        }
        if (!anomaly)
            continue;
        json item = result_row_json(row);
        item["anomaly_reasons"] = std::move(reasons);
        anomalies.push_back(std::move(item));
        if (anomalies.size() >= 256)
            break;
    }
    json issues = json::array();
    if (!anomalies.empty() && params.value("create_issue", true)) {
        issues.push_back(add_issue(job.target, json{{"anomaly_count", anomalies.size()}, {"baseline", job.baseline}}));
    }
    json out;
    out["job_id"] = job.id;
    out["intruder_job_id"] = job.intruder_job_id;
    out["baseline"] = job.baseline;
    out["total_results_examined"] = static_cast<std::uint64_t>(rows.size());
    out["total_anomalies"] = anomalies.size();
    out["anomalies"] = std::move(anomalies);
    out["issues_created"] = std::move(issues);
    return tool_result_t::ok(out);
}

}
}
}
}
