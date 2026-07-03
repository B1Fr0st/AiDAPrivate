#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "obfuscation.hpp"
#include "helpers/diag_log.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "burp/audit_http.hpp"
#include "burp/cookie_jar.hpp"
#include "burp/repeater.hpp"
#include "burp/site_map.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace network_tools
{
namespace
{

struct parsed_url_t
{
    std::string scheme;
    std::string host;
    std::uint16_t port = 0;
    std::string target;
    bool tls = false;
};

struct request_spec_t
{
    std::string method = "GET";
    std::string url;
    parsed_url_t parsed;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
    bool body_present = false;
    bool use_cookie_jar = false;
    bool store_cookies = false;
    bool publish_exchange = true;
    bool enforce_scope = false;
    int timeout_ms = 15000;
    std::string sni_override;
};

struct response_value_t
{
    int status = 0;
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
    bool preview_only = false;
};

std::uint64_t now_steady_ms()
{
    return static_cast<std::uint64_t>(GetTickCount64());
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

std::string trim_ascii(const std::string& s)
{
    std::size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    std::size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return s.substr(b, e - b);
}

bool is_sensitive_name(const std::string& name)
{
    const std::string k = lower_ascii(name);
    return k.find("authorization") != std::string::npos ||
           k.find("cookie") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("secret") != std::string::npos ||
           k.find("password") != std::string::npos ||
           k.find("passwd") != std::string::npos ||
           k.find("api-key") != std::string::npos ||
           k.find("apikey") != std::string::npos ||
           k.find("api_key") != std::string::npos ||
           k.find("private-key") != std::string::npos ||
           k.find("private_key") != std::string::npos ||
           k.find("license") != std::string::npos ||
           k.find("session") != std::string::npos;
}

std::uint64_t fnv1a64_bytes(const std::uint8_t* data, std::size_t size)
{
    std::uint64_t h = 1469598103934665603ULL;
    for (std::size_t i = 0; i < size; ++i) {
        h ^= static_cast<std::uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

std::string hex_u64(std::uint64_t v)
{
    std::ostringstream os;
    os << std::hex << std::setw(16) << std::setfill('0') << v;
    return os.str();
}

std::string hash_bytes(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.empty())
        return "0000000000000000";
    return hex_u64(fnv1a64_bytes(bytes.data(), bytes.size()));
}

std::string hash_string(const std::string& s)
{
    if (s.empty())
        return "0000000000000000";
    return hex_u64(fnv1a64_bytes(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
}

std::string redact_summary(const std::string& value)
{
    return "<redacted len=" + std::to_string(value.size()) + " fnv1a64=" + hash_string(value) + ">";
}

std::string redact_cookie_header_value(const std::string& value)
{
    std::string first = value;
    const std::size_t semi = first.find(';');
    if (semi != std::string::npos)
        first.resize(semi);
    const std::size_t eq = first.find('=');
    std::string name = eq == std::string::npos ? trim_ascii(first) : trim_ascii(first.substr(0, eq));
    if (name.empty())
        name = "cookie";
    return "<redacted-cookie name=" + name + " len=" + std::to_string(value.size()) + " fnv1a64=" + hash_string(value) + ">";
}

bool token_like_segment(const std::string& segment)
{
    if (segment.size() < 24)
        return false;
    std::size_t token_chars = 0;
    for (unsigned char c : segment) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '=' || c == '%')
            ++token_chars;
    }
    return token_chars * 100 >= segment.size() * 85;
}

std::string redact_url_prefix_path(const std::string& prefix)
{
    std::string work = prefix;
    const std::size_t scheme = work.find("://");
    const std::size_t auth_start = scheme == std::string::npos ? 0 : scheme + 3;
    const std::size_t path_start = work.find('/', auth_start);
    const std::size_t auth_end = path_start == std::string::npos ? work.size() : path_start;
    const std::size_t at = work.find('@', auth_start);
    if (at != std::string::npos && at < auth_end) {
        const std::string userinfo = work.substr(auth_start, at - auth_start);
        work = work.substr(0, auth_start) + redact_summary(userinfo) + work.substr(at);
    }
    const std::size_t redacted_path_start = work.find('/', auth_start);
    if (redacted_path_start == std::string::npos)
        return work;
    std::string out = work.substr(0, redacted_path_start);
    std::size_t pos = redacted_path_start;
    while (pos < work.size()) {
        const std::size_t next = work.find('/', pos + 1);
        const std::string sep = "/";
        const std::string segment = work.substr(pos + 1, next == std::string::npos ? std::string::npos : next - pos - 1);
        out += sep;
        const std::string lc = lower_ascii(segment);
        if (token_like_segment(segment) || lc.find("token") != std::string::npos || lc.find("secret") != std::string::npos || lc.find("password") != std::string::npos || lc.find("license") != std::string::npos)
            out += redact_summary(segment);
        else
            out += segment;
        if (next == std::string::npos)
            break;
        pos = next;
    }
    return out;
}

std::string redact_param_values(const std::string& params)
{
    std::ostringstream out;
    std::size_t pos = 0;
    bool first = true;
    while (pos <= params.size()) {
        const std::size_t amp = params.find('&', pos);
        const std::string part = params.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (!first)
            out << '&';
        first = false;
        const std::size_t eq = part.find('=');
        if (eq == std::string::npos) {
            const std::string lc = lower_ascii(part);
            if (token_like_segment(part) || lc.find("token") != std::string::npos || lc.find("secret") != std::string::npos || lc.find("password") != std::string::npos || lc.find("license") != std::string::npos)
                out << redact_summary(part);
            else
                out << part;
        } else {
            out << part.substr(0, eq + 1) << redact_summary(part.substr(eq + 1));
        }
        if (amp == std::string::npos)
            break;
        pos = amp + 1;
    }
    return out.str();
}

std::string redact_query_values(const std::string& url)
{
    const std::size_t q = url.find('?');
    if (q == std::string::npos) {
        const std::size_t hash = url.find('#');
        if (hash != std::string::npos)
            return redact_url_prefix_path(url.substr(0, hash)) + "#" + redact_param_values(url.substr(hash + 1));
        return redact_url_prefix_path(url);
    }
    const std::size_t hash = url.find('#', q + 1);
    const std::string prefix = redact_url_prefix_path(url.substr(0, q)) + "?";
    const std::string query = hash == std::string::npos ? url.substr(q + 1) : url.substr(q + 1, hash - q - 1);
    const std::string suffix = hash == std::string::npos ? std::string() : "#" + redact_param_values(url.substr(hash + 1));
    std::ostringstream out;
    out << prefix << redact_param_values(query);
    out << suffix;
    return out.str();
}

std::string redact_header_value(const std::string& name, const std::string& value)
{
    const std::string lc = lower_ascii(name);
    if (lc == "set-cookie" || lc == "cookie")
        return redact_cookie_header_value(value);
    if (is_sensitive_name(name))
        return redact_summary(value);
    if (lc == "location" || lc == "content-location")
        return redact_query_values(value);
    return value;
}

std::string redact_sensitive_text(std::string text)
{
    try {
        static const std::regex key_value(
            R"((\"?(?:password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|private[_-]?key|license[_-]?key|authorization|cookie|session[_-]?id)\"?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^&\s,}]+))",
            std::regex_constants::icase);
        text = std::regex_replace(text, key_value, "$1<redacted>");
        static const std::regex bearer(R"(\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,})", std::regex_constants::icase);
        text = std::regex_replace(text, bearer, "$1 <redacted>");
        static const std::regex private_key(R"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)", std::regex_constants::icase);
        text = std::regex_replace(text, private_key, "<redacted-private-key>");
        static const std::regex aida_key(R"(\bAIDA-[A-Za-z0-9-]{8,}\b)", std::regex_constants::icase);
        text = std::regex_replace(text, aida_key, "<redacted-license-key>");
    } catch (...) {
        if (text.size() > 256)
            text.resize(256);
    }
    return text;
}

bool text_looks_sensitive(const std::string& text)
{
    const std::string lc = lower_ascii(text);
    return lc.find("-----begin") != std::string::npos ||
           lc.find("private key") != std::string::npos ||
           lc.find("access_token") != std::string::npos ||
           lc.find("refresh_token") != std::string::npos ||
           lc.find("api_key") != std::string::npos ||
           lc.find("apikey") != std::string::npos ||
           lc.find("authorization") != std::string::npos ||
           lc.find("license_key") != std::string::npos ||
           lc.find("password") != std::string::npos;
}

std::string preview_bytes(const std::vector<std::uint8_t>& bytes, std::size_t max_len)
{
    const std::size_t n = std::min(bytes.size(), max_len);
    std::string out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char c = bytes[i];
        if (c == '\r' || c == '\n' || c == '\t' || (c >= 32 && c < 127))
            out.push_back(static_cast<char>(c));
        else
            out.push_back('.');
    }
    return redact_sensitive_text(out);
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(digits[(b >> 4) & 0xF]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

bool hex_to_bytes(const std::string& in, std::vector<std::uint8_t>& out, std::string& err)
{
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (!std::isspace(static_cast<unsigned char>(c)))
            s.push_back(c);
    }
    if ((s.size() & 1U) != 0) {
        err = "hex input has odd length";
        return false;
    }
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        const int hi = hexval(s[i]);
        const int lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) {
            err = "hex input contains non-hex characters";
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool is_safe_header_name(const std::string& name)
{
    if (name.empty())
        return false;
    for (char c : name) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc <= 32 || uc >= 127 || c == ':' || c == '\r' || c == '\n')
            return false;
    }
    return true;
}

bool is_safe_header_value(const std::string& value)
{
    return value.find('\r') == std::string::npos && value.find('\n') == std::string::npos;
}

bool has_header(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string want = lower_ascii(name);
    for (const auto& h : headers) {
        if (lower_ascii(h.first) == want)
            return true;
    }
    return false;
}

void remove_header(std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string want = lower_ascii(name);
    headers.erase(std::remove_if(headers.begin(), headers.end(), [&](const auto& h) {
        return lower_ascii(h.first) == want;
    }), headers.end());
}

bool headers_from_json(const json& value, std::vector<std::pair<std::string, std::string>>& out, std::string& err)
{
    if (value.is_null())
        return true;
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            const std::string name = it.key();
            std::string v;
            if (it.value().is_string())
                v = it.value().get<std::string>();
            else if (it.value().is_number_integer() || it.value().is_number_unsigned() || it.value().is_number_float() || it.value().is_boolean())
                v = it.value().dump();
            else {
                err = "header values must be strings or scalars";
                return false;
            }
            if (!is_safe_header_name(name) || !is_safe_header_value(v)) {
                err = "header contains unsafe characters";
                return false;
            }
            out.emplace_back(name, v);
        }
        return true;
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            if (item.is_array() && item.size() >= 2 && item[0].is_string() && item[1].is_string()) {
                const std::string name = item[0].get<std::string>();
                const std::string v = item[1].get<std::string>();
                if (!is_safe_header_name(name) || !is_safe_header_value(v)) {
                    err = "header contains unsafe characters";
                    return false;
                }
                out.emplace_back(name, v);
                continue;
            }
            if (item.is_object() && item.contains("name") && item.contains("value") && item["name"].is_string() && item["value"].is_string()) {
                const std::string name = item["name"].get<std::string>();
                const std::string v = item["value"].get<std::string>();
                if (!is_safe_header_name(name) || !is_safe_header_value(v)) {
                    err = "header contains unsafe characters";
                    return false;
                }
                out.emplace_back(name, v);
                continue;
            }
            err = "headers array entries must be [name,value] or {name,value}";
            return false;
        }
        return true;
    }
    err = "headers must be an object or array";
    return false;
}

bool parse_url_silent(const std::string& url, parsed_url_t& out, std::string& err)
{
    const std::string u = trim_ascii(url);
    const std::size_t sep = u.find("://");
    if (sep == std::string::npos) {
        err = "url must include http:// or https://";
        return false;
    }
    out.scheme = lower_ascii(u.substr(0, sep));
    out.tls = out.scheme == "https";
    if (out.scheme != "http" && out.scheme != "https") {
        err = "only http and https URLs are supported";
        return false;
    }
    const std::size_t authority_start = sep + 3;
    std::size_t path_start = u.find_first_of("/?#", authority_start);
    std::string authority = path_start == std::string::npos ? u.substr(authority_start) : u.substr(authority_start, path_start - authority_start);
    if (authority.find('@') != std::string::npos) {
        err = "URL userinfo is not accepted";
        return false;
    }
    const std::size_t fragment = path_start == std::string::npos ? std::string::npos : u.find('#', path_start);
    std::string target = path_start == std::string::npos ? "/" : u.substr(path_start, fragment == std::string::npos ? std::string::npos : fragment - path_start);
    if (target.empty() || target[0] == '?')
        target = "/" + target;
    std::size_t colon = authority.rfind(':');
    if (!authority.empty() && authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            err = "invalid IPv6 authority";
            return false;
        }
        out.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                err = "invalid authority after IPv6 host";
                return false;
            }
            colon = close + 1;
        } else {
            colon = std::string::npos;
        }
    } else if (colon != std::string::npos && authority.find(':') == colon) {
        out.host = authority.substr(0, colon);
    } else {
        colon = std::string::npos;
        out.host = authority;
    }
    if (out.host.empty()) {
        err = "url host is empty";
        return false;
    }
    if (colon == std::string::npos) {
        out.port = out.tls ? 443 : 80;
    } else {
        const std::string port_s = authority.substr(colon + 1);
        if (port_s.empty()) {
            err = "url port is empty";
            return false;
        }
        unsigned long p = 0;
        try {
            p = std::stoul(port_s);
        } catch (...) {
            err = "url port is invalid";
            return false;
        }
        if (p == 0 || p > 65535) {
            err = "url port is out of range";
            return false;
        }
        out.port = static_cast<std::uint16_t>(p);
    }
    out.target = target;
    return true;
}

int bounded_timeout_ms(const json& params)
{
    int timeout_ms = 15000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = params["timeout_ms"].get<int>();
    if (params.contains("timeout") && params["timeout"].is_number_integer())
        timeout_ms = params["timeout"].get<int>();
    timeout_ms = std::max(250, std::min(timeout_ms, 120000));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = now_steady_ms();
        if (deadline <= now + 25)
            return 1;
        const std::uint64_t remain = deadline - now - 25;
        timeout_ms = static_cast<int>(std::min<std::uint64_t>(static_cast<std::uint64_t>(timeout_ms), remain));
    }
    return std::max(1, timeout_ms);
}

bool deadline_expired()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && now_steady_ms() >= deadline;
}

bool body_from_params(const json& params, std::vector<std::uint8_t>& out, bool& present, std::string& err)
{
    out.clear();
    present = false;
    if (params.contains("body_hex") && params["body_hex"].is_string()) {
        present = true;
        return hex_to_bytes(params["body_hex"].get<std::string>(), out, err);
    }
    if (params.contains("body") && params["body"].is_string()) {
        present = true;
        const std::string body = params["body"].get<std::string>();
        out.assign(body.begin(), body.end());
        return true;
    }
    if (params.contains("json_body")) {
        present = true;
        const std::string body = params["json_body"].dump();
        out.assign(body.begin(), body.end());
        return true;
    }
    return true;
}

bool parse_request_spec(const json& params, request_spec_t& spec, std::string& err)
{
    if (!params.is_object()) {
        err = "params must be an object";
        return false;
    }
    if (!params.contains("url") || !params["url"].is_string()) {
        err = "url is required";
        return false;
    }
    spec.url = params["url"].get<std::string>();
    if (params.contains("method") && params["method"].is_string())
        spec.method = upper_ascii(trim_ascii(params["method"].get<std::string>()));
    if (spec.method.empty())
        spec.method = "GET";
    for (char c : spec.method) {
        if (!std::isalpha(static_cast<unsigned char>(c))) {
            err = "method contains invalid characters";
            return false;
        }
    }
    if (!parse_url_silent(spec.url, spec.parsed, err))
        return false;
    if (params.contains("headers") && !headers_from_json(params["headers"], spec.headers, err))
        return false;
    if (!body_from_params(params, spec.body, spec.body_present, err))
        return false;
    spec.use_cookie_jar = params.value("use_cookie_jar", params.value("cookie_jar", false));
    spec.store_cookies = params.value("store_cookies", spec.use_cookie_jar);
    spec.publish_exchange = params.value("publish_exchange", true);
    spec.enforce_scope = params.value("enforce_scope", false);
    spec.timeout_ms = bounded_timeout_ms(params);
    if (params.contains("sni_override") && params["sni_override"].is_string())
        spec.sni_override = params["sni_override"].get<std::string>();
    return true;
}

std::vector<std::uint8_t> build_raw_request(const request_spec_t& spec)
{
    std::vector<std::pair<std::string, std::string>> headers = spec.headers;
    remove_header(headers, "Content-Length");
    if (!has_header(headers, "User-Agent"))
        headers.emplace_back("User-Agent", "AiDA-HTTP/1.0");
    if (!has_header(headers, "Accept"))
        headers.emplace_back("Accept", "*/*");
    if (!has_header(headers, "Connection"))
        headers.emplace_back("Connection", "close");
    if (spec.use_cookie_jar && !has_header(headers, "Cookie")) {
        std::string cookie_path = spec.parsed.target;
        const std::size_t q = cookie_path.find('?');
        if (q != std::string::npos)
            cookie_path.resize(q);
        const std::string cookies = aida::burp::cookie_jar::build_cookie_header(spec.parsed.host, cookie_path, spec.parsed.tls);
        if (!cookies.empty())
            headers.emplace_back("Cookie", cookies);
    }
    if (spec.body_present && !has_header(headers, "Content-Length"))
        headers.emplace_back("Content-Length", std::to_string(spec.body.size()));
    std::ostringstream req;
    req << spec.method << ' ' << spec.parsed.target << " HTTP/1.1\r\n";
    for (const auto& h : headers)
        req << h.first << ": " << h.second << "\r\n";
    req << "\r\n";
    std::string head = req.str();
    std::vector<std::uint8_t> raw(head.begin(), head.end());
    raw.insert(raw.end(), spec.body.begin(), spec.body.end());
    return raw;
}

json headers_to_json(const std::vector<std::pair<std::string, std::string>>& headers)
{
    json arr = json::array();
    for (const auto& h : headers)
        arr.push_back({{"name", h.first}, {"value", redact_header_value(h.first, h.second)}});
    return arr;
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string want = lower_ascii(name);
    for (const auto& h : headers) {
        if (lower_ascii(h.first) == want)
            return h.second;
    }
    return {};
}

bool is_redirect_status(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

std::string authority_for_url(const parsed_url_t& u)
{
    std::string out = u.host;
    if ((u.tls && u.port != 443) || (!u.tls && u.port != 80))
        out += ":" + std::to_string(u.port);
    return out;
}

std::string absolute_redirect_url(const parsed_url_t& base, const std::string& location)
{
    const std::string loc = trim_ascii(location);
    if (loc.find("://") != std::string::npos)
        return loc;
    if (loc.rfind("//", 0) == 0)
        return base.scheme + ":" + loc;
    const std::string root = base.scheme + "://" + authority_for_url(base);
    if (loc.empty())
        return root + base.target;
    if (loc[0] == '/')
        return root + loc;
    std::string path = base.target;
    const std::size_t q = path.find('?');
    if (q != std::string::npos)
        path.resize(q);
    const std::size_t slash = path.rfind('/');
    if (slash == std::string::npos)
        path = "/";
    else
        path.resize(slash + 1);
    return root + path + loc;
}

json exchange_summary_json(const aida::burp::exchange_observed_t& ex, std::size_t preview_len)
{
    json out;
    out["ok"] = true;
    out["status"] = ex.status_code;
    out["reason"] = ex.reason_phrase;
    out["headers"] = headers_to_json(ex.resp_headers);
    out["body_hash_algorithm"] = "fnv1a64";
    out["body_hash"] = hash_bytes(ex.resp_body);
    out["body_preview"] = preview_bytes(ex.resp_body, preview_len);
    out["body_preview_truncated"] = ex.resp_body.size() > preview_len;
    out["body_length"] = static_cast<std::uint64_t>(ex.resp_body.size());
    out["elapsed_ms"] = static_cast<std::uint64_t>(ex.latency_ms);
    out["exchange_id"] = static_cast<std::uint64_t>(ex.id);
    out["method"] = ex.method;
    out["scheme"] = ex.scheme;
    out["host"] = ex.host;
    out["port"] = ex.port;
    out["path"] = ex.path;
    out["query_present"] = !ex.query.empty();
    out["query_length"] = static_cast<std::uint64_t>(ex.query.size());
    out["errors"] = json::array();
    std::uint64_t set_cookie_count = 0;
    for (const auto& h : ex.resp_headers) {
        if (lower_ascii(h.first) == "set-cookie")
            ++set_cookie_count;
    }
    out["set_cookie_count"] = set_cookie_count;
    return out;
}

tool_result_t error_result(const std::string& msg, json data = json::object())
{
    if (!data.is_object())
        data = json::object();
    data["ok"] = false;
    data["errors"] = json::array({redact_sensitive_text(msg)});
    return tool_result_t::error(redact_sensitive_text(msg), data);
}

std::optional<aida::burp::exchange_observed_t> send_once(const request_spec_t& spec, std::string& err)
{
    if (deadline_expired()) {
        err = mcp_standalone::current_call_cancelled() ? "call cancelled before HTTP request" : "call deadline expired before HTTP request";
        return std::nullopt;
    }
    aida::burp::audit_http::send_options_t opts;
    opts.timeout_ms = spec.timeout_ms;
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.return_first_redirect = true;
    opts.enforce_scope = spec.enforce_scope;
    opts.publish_exchange = spec.publish_exchange;
    opts.exchange_source = "aida.http";
    opts.sni_override = spec.sni_override;
    const auto raw = build_raw_request(spec);
    diag::log_tagged_fmt("http_tools", "send_once method=%s host=%s port=%u tls=%d target_len=%zu body_len=%zu timeout_ms=%d cookie_jar=%d store_cookies=%d publish=%d",
        spec.method.c_str(),
        spec.parsed.host.c_str(),
        static_cast<unsigned>(spec.parsed.port),
        spec.parsed.tls ? 1 : 0,
        spec.parsed.target.size(),
        spec.body.size(),
        spec.timeout_ms,
        spec.use_cookie_jar ? 1 : 0,
        spec.store_cookies ? 1 : 0,
        spec.publish_exchange ? 1 : 0);
    auto ex = aida::burp::audit_http::send(raw, spec.parsed.host, spec.parsed.port, spec.parsed.tls, opts);
    if (!ex.has_value()) {
        err = aida::burp::audit_http::last_error();
        if (err.empty())
            err = "HTTP transport failed";
        return std::nullopt;
    }
    if (spec.store_cookies)
        aida::burp::cookie_jar::ingest_set_cookie_headers(spec.parsed.host, ex->resp_headers);
    if (deadline_expired()) {
        err = mcp_standalone::current_call_cancelled() ? "call cancelled after HTTP request" : "call deadline expired after HTTP request";
        return std::nullopt;
    }
    return ex;
}

request_spec_t redirect_request_from(const request_spec_t& prior, const std::string& next_url, int status, std::string& err)
{
    request_spec_t next = prior;
    next.url = next_url;
    if (!parse_url_silent(next_url, next.parsed, err))
        return next;
    if (lower_ascii(next.parsed.host) != lower_ascii(prior.parsed.host) ||
        next.parsed.port != prior.parsed.port ||
        next.parsed.tls != prior.parsed.tls) {
        remove_header(next.headers, "Authorization");
        remove_header(next.headers, "Proxy-Authorization");
        remove_header(next.headers, "Cookie");
    }
    if (status == 301 || status == 302 || status == 303) {
        if (next.method != "HEAD") {
            next.method = "GET";
            next.body.clear();
            next.body_present = false;
            remove_header(next.headers, "Content-Type");
        }
    }
    remove_header(next.headers, "Host");
    remove_header(next.headers, "Content-Length");
    if (!next.body.empty())
        next.body_present = true;
    return next;
}

tool_result_t perform_http_request(const json& params, bool force_follow, bool chain_only)
{
    request_spec_t spec;
    std::string err;
    if (!parse_request_spec(params, spec, err))
        return error_result(err);
    const std::size_t preview_len = static_cast<std::size_t>(std::max(0, std::min(params.value("body_preview_bytes", 1024), 8192)));
    std::string redirect_policy = lower_ascii(params.value("redirect_policy", std::string()));
    if (redirect_policy.empty())
        redirect_policy = (params.value("follow_redirects", false) || force_follow) ? "follow" : "manual";
    const bool follow = force_follow || redirect_policy == "follow";
    const int max_redirects = std::max(0, std::min(params.value("max_redirects", chain_only ? 10 : 5), 10));
    json chain = json::array();
    std::optional<aida::burp::exchange_observed_t> final_ex;
    request_spec_t current = spec;
    for (int hop = 0; hop <= max_redirects; ++hop) {
        auto ex = send_once(current, err);
        if (!ex.has_value()) {
            json data;
            data["redirect_chain"] = chain;
            data["hop"] = hop;
            return error_result(err, data);
        }
        json item = exchange_summary_json(*ex, preview_len);
        item["hop"] = hop;
        item["request_url"] = redact_query_values(current.parsed.scheme + "://" + authority_for_url(current.parsed) + current.parsed.target);
        const std::string location = header_value(ex->resp_headers, "Location");
        if (!location.empty())
            item["location"] = redact_query_values(location);
        chain.push_back(item);
        final_ex = ex;
        if (!follow || !is_redirect_status(ex->status_code) || location.empty() || hop == max_redirects)
            break;
        const std::string next_url = absolute_redirect_url(current.parsed, location);
        current = redirect_request_from(current, next_url, ex->status_code, err);
        if (!err.empty()) {
            json data;
            data["redirect_chain"] = chain;
            return error_result("redirect target rejected: " + err, data);
        }
    }
    if (!final_ex.has_value())
        return error_result("HTTP request produced no response");
    json out = exchange_summary_json(*final_ex, preview_len);
    out["redirect_policy"] = redirect_policy;
    out["redirect_chain"] = chain;
    out["redirect_count"] = chain.empty() ? 0 : static_cast<int>(chain.size()) - 1;
    if (chain.empty())
        out["final_url"] = nullptr;
    else
        out["final_url"] = chain.back().value("request_url", std::string());
    if (chain_only)
        return tool_result_t::ok("HTTP redirect chain complete.", out);
    return tool_result_t::ok("HTTP request complete.", out);
}

std::string percent_encode(const std::string& s, bool space_plus)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else if (c == ' ' && space_plus) {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

bool append_urlencoded_pairs(const json& params, std::vector<std::pair<std::string, std::string>>& pairs, bool& sensitive, std::string& err)
{
    if (params.is_object()) {
        for (auto it = params.begin(); it != params.end(); ++it) {
            if (deadline_expired()) {
                err = "urlencoded build cancelled";
                return false;
            }
            std::string v;
            if (it.value().is_string())
                v = it.value().get<std::string>();
            else if (it.value().is_number() || it.value().is_boolean())
                v = it.value().dump();
            else {
                err = "urlencoded object values must be strings or scalars";
                return false;
            }
            sensitive = sensitive || is_sensitive_name(it.key()) || text_looks_sensitive(v);
            pairs.emplace_back(it.key(), v);
        }
        return true;
    }
    if (params.is_array()) {
        for (const auto& item : params) {
            if (deadline_expired()) {
                err = "urlencoded build cancelled";
                return false;
            }
            if (!item.is_object() || !item.contains("name") || !item.contains("value") || !item["name"].is_string()) {
                err = "urlencoded array entries must be objects with name and value";
                return false;
            }
            std::string v;
            if (item["value"].is_string())
                v = item["value"].get<std::string>();
            else if (item["value"].is_number() || item["value"].is_boolean())
                v = item["value"].dump();
            else {
                err = "urlencoded values must be strings or scalars";
                return false;
            }
            const std::string n = item["name"].get<std::string>();
            sensitive = sensitive || is_sensitive_name(n) || text_looks_sensitive(v);
            pairs.emplace_back(n, v);
        }
        return true;
    }
    err = "params must be an object or array";
    return false;
}

tool_result_t tool_build_urlencoded(const json& params)
{
    if (deadline_expired())
        return error_result("call cancelled before urlencoded build");
    const json* src = nullptr;
    if (params.contains("params"))
        src = &params["params"];
    else if (params.contains("fields"))
        src = &params["fields"];
    if (!src)
        return error_result("params or fields is required");
    std::vector<std::pair<std::string, std::string>> pairs;
    bool sensitive = false;
    std::string err;
    if (!append_urlencoded_pairs(*src, pairs, sensitive, err))
        return error_result(err);
    const bool space_plus = params.value("space_as_plus", true);
    std::ostringstream body;
    for (std::size_t i = 0; i < pairs.size(); ++i) {
        if (i)
            body << '&';
        body << percent_encode(pairs[i].first, space_plus) << '=' << percent_encode(pairs[i].second, space_plus);
    }
    const std::string s = body.str();
    std::vector<std::uint8_t> bytes(s.begin(), s.end());
    json out;
    out["content_type"] = "application/x-www-form-urlencoded";
    out["body_length"] = static_cast<std::uint64_t>(bytes.size());
    out["body_hash_algorithm"] = "fnv1a64";
    out["body_hash"] = hash_bytes(bytes);
    out["body_preview"] = preview_bytes(bytes, 1024);
    out["sensitive_redacted"] = sensitive;
    out["field_count"] = static_cast<std::uint64_t>(pairs.size());
    if (!sensitive)
        out["body"] = s;
    return tool_result_t::ok("URL-encoded body built.", out);
}

std::string generated_boundary()
{
    static std::atomic<std::uint64_t> counter{0};
    const std::uint64_t id = counter.fetch_add(1, std::memory_order_relaxed) + 1;
    return "----AiDAFormBoundary" + hex_u64(now_steady_ms()) + hex_u64(id);
}

bool valid_boundary(const std::string& b)
{
    if (b.size() < 8 || b.size() > 70)
        return false;
    for (char c : b) {
        if (c == '\r' || c == '\n')
            return false;
    }
    return true;
}

bool json_scalar_to_string(const json& v, std::string& out)
{
    if (v.is_string()) {
        out = v.get<std::string>();
        return true;
    }
    if (v.is_number() || v.is_boolean()) {
        out = v.dump();
        return true;
    }
    return false;
}

bool append_multipart_part(std::vector<std::uint8_t>& body,
                           const std::string& boundary,
                           const std::string& name,
                           const std::string& filename,
                           const std::string& content_type,
                           const std::vector<std::uint8_t>& content,
                           bool& sensitive,
                           std::string& err)
{
    if (!is_safe_header_value(name) || !is_safe_header_value(filename) || !is_safe_header_value(content_type)) {
        err = "multipart part metadata contains unsafe characters";
        return false;
    }
    sensitive = sensitive || is_sensitive_name(name) || text_looks_sensitive(std::string(content.begin(), content.end()));
    std::ostringstream head;
    head << "--" << boundary << "\r\n";
    head << "Content-Disposition: form-data; name=\"" << name << "\"";
    if (!filename.empty())
        head << "; filename=\"" << filename << "\"";
    head << "\r\n";
    if (!content_type.empty())
        head << "Content-Type: " << content_type << "\r\n";
    head << "\r\n";
    const std::string h = head.str();
    body.insert(body.end(), h.begin(), h.end());
    body.insert(body.end(), content.begin(), content.end());
    body.insert(body.end(), {'\r', '\n'});
    return true;
}

bool append_multipart_collection(const json& collection,
                                 bool files,
                                 const std::string& boundary,
                                 std::vector<std::uint8_t>& body,
                                 bool& sensitive,
                                 std::string& err)
{
    if (collection.is_object() && !files) {
        for (auto it = collection.begin(); it != collection.end(); ++it) {
            if (deadline_expired()) {
                err = "multipart build cancelled";
                return false;
            }
            std::string v;
            if (!json_scalar_to_string(it.value(), v)) {
                err = "multipart field values must be strings or scalars";
                return false;
            }
            std::vector<std::uint8_t> bytes(v.begin(), v.end());
            if (!append_multipart_part(body, boundary, it.key(), std::string(), std::string(), bytes, sensitive, err))
                return false;
        }
        return true;
    }
    if (!collection.is_array()) {
        err = files ? "files must be an array" : "fields must be an object or array";
        return false;
    }
    for (const auto& item : collection) {
        if (deadline_expired()) {
            err = "multipart build cancelled";
            return false;
        }
        if (!item.is_object() || !item.contains("name") || !item["name"].is_string()) {
            err = "multipart entries require a string name";
            return false;
        }
        const std::string name = item["name"].get<std::string>();
        std::string filename;
        std::string content_type;
        if (item.contains("filename") && item["filename"].is_string())
            filename = item["filename"].get<std::string>();
        if (item.contains("content_type") && item["content_type"].is_string())
            content_type = item["content_type"].get<std::string>();
        std::vector<std::uint8_t> bytes;
        if (item.contains("content_hex") && item["content_hex"].is_string()) {
            if (!hex_to_bytes(item["content_hex"].get<std::string>(), bytes, err))
                return false;
        } else {
            std::string value;
            if (item.contains("content") && json_scalar_to_string(item["content"], value)) {
                bytes.assign(value.begin(), value.end());
            } else if (item.contains("value") && json_scalar_to_string(item["value"], value)) {
                bytes.assign(value.begin(), value.end());
            } else {
                err = "multipart entries require value, content, or content_hex";
                return false;
            }
        }
        if (!append_multipart_part(body, boundary, name, filename, content_type, bytes, sensitive, err))
            return false;
    }
    return true;
}

bool is_printable_body(const std::vector<std::uint8_t>& bytes)
{
    for (std::uint8_t b : bytes) {
        if (b == '\r' || b == '\n' || b == '\t')
            continue;
        if (b < 32 || b >= 127)
            return false;
    }
    return true;
}

tool_result_t tool_build_multipart(const json& params)
{
    if (deadline_expired())
        return error_result("call cancelled before multipart build");
    std::string boundary = params.value("boundary", std::string());
    if (boundary.empty())
        boundary = generated_boundary();
    if (!valid_boundary(boundary))
        return error_result("boundary is invalid");
    std::vector<std::uint8_t> body;
    bool sensitive = false;
    std::string err;
    if (params.contains("fields") && !append_multipart_collection(params["fields"], false, boundary, body, sensitive, err))
        return error_result(err);
    if (params.contains("files") && !append_multipart_collection(params["files"], true, boundary, body, sensitive, err))
        return error_result(err);
    if (!params.contains("fields") && !params.contains("files"))
        return error_result("fields or files is required");
    const std::string tail = "--" + boundary + "--\r\n";
    body.insert(body.end(), tail.begin(), tail.end());
    if (body.size() > 2 * 1024 * 1024)
        return error_result("multipart body exceeds the 2 MiB MCP builder limit");
    json out;
    out["content_type"] = "multipart/form-data; boundary=" + boundary;
    out["boundary"] = boundary;
    out["body_length"] = static_cast<std::uint64_t>(body.size());
    out["body_hash_algorithm"] = "fnv1a64";
    out["body_hash"] = hash_bytes(body);
    out["body_preview"] = preview_bytes(body, 2048);
    out["sensitive_redacted"] = sensitive;
    if (!sensitive) {
        if (is_printable_body(body))
            out["body"] = std::string(body.begin(), body.end());
        else
            out["body_hex"] = bytes_to_hex(body);
    }
    return tool_result_t::ok("Multipart body built.", out);
}

response_value_t response_from_exchange(const aida::burp::exchange_observed_t& ex)
{
    response_value_t r;
    r.status = ex.status_code;
    r.reason = ex.reason_phrase;
    r.headers = ex.resp_headers;
    r.body = ex.resp_body;
    return r;
}

bool supplied_response_from_json(const json& src, response_value_t& out, std::string& err)
{
    if (!src.is_object()) {
        err = "response object must be an object";
        return false;
    }
    out.status = src.value("status", src.value("status_code", 0));
    out.reason = src.value("reason", std::string());
    if (src.contains("headers") && !headers_from_json(src["headers"], out.headers, err))
        return false;
    if (src.contains("body_hex") && src["body_hex"].is_string()) {
        return hex_to_bytes(src["body_hex"].get<std::string>(), out.body, err);
    }
    if (src.contains("body") && src["body"].is_string()) {
        const std::string b = src["body"].get<std::string>();
        out.body.assign(b.begin(), b.end());
        return true;
    }
    if (src.contains("body_preview") && src["body_preview"].is_string()) {
        const std::string b = src["body_preview"].get<std::string>();
        out.body.assign(b.begin(), b.end());
        out.preview_only = true;
        return true;
    }
    return true;
}

json header_diff(const response_value_t& a, const response_value_t& b)
{
    std::map<std::string, std::string> ma;
    std::map<std::string, std::string> mb;
    for (const auto& h : a.headers)
        ma[lower_ascii(h.first)] = redact_header_value(h.first, h.second);
    for (const auto& h : b.headers)
        mb[lower_ascii(h.first)] = redact_header_value(h.first, h.second);
    json added = json::array();
    json removed = json::array();
    json changed = json::array();
    for (const auto& kv : mb) {
        if (!ma.count(kv.first))
            added.push_back(kv.first);
    }
    for (const auto& kv : ma) {
        if (!mb.count(kv.first))
            removed.push_back(kv.first);
        else if (mb[kv.first] != kv.second)
            changed.push_back({{"name", kv.first}, {"a", kv.second}, {"b", mb[kv.first]}});
    }
    return {{"added", added}, {"removed", removed}, {"changed", changed}};
}

json text_diff_summary(const response_value_t& a, const response_value_t& b)
{
    const std::string as(a.body.begin(), a.body.end());
    const std::string bs(b.body.begin(), b.body.end());
    std::size_t first = 0;
    const std::size_t min_len = std::min(as.size(), bs.size());
    while (first < min_len && as[first] == bs[first])
        ++first;
    json out;
    out["same"] = as == bs;
    out["first_diff_offset"] = as == bs ? json() : json(static_cast<std::uint64_t>(first));
    out["a_length"] = static_cast<std::uint64_t>(as.size());
    out["b_length"] = static_cast<std::uint64_t>(bs.size());
    out["a_hash"] = hash_bytes(a.body);
    out["b_hash"] = hash_bytes(b.body);
    const std::size_t ctx_start = first > 80 ? first - 80 : 0;
    if (as != bs) {
        const std::string a_ctx = as.substr(ctx_start, std::min<std::size_t>(160, as.size() - ctx_start));
        const std::string b_ctx = bs.substr(ctx_start, std::min<std::size_t>(160, bs.size() - ctx_start));
        out["a_context"] = redact_sensitive_text(a_ctx);
        out["b_context"] = redact_sensitive_text(b_ctx);
    }
    return out;
}

void collect_json_shape(const json& j, const std::string& path, json& out, std::size_t& count)
{
    if (count >= 512)
        return;
    ++count;
    std::string type = j.type_name();
    out.push_back({{"path", path.empty() ? "$" : path}, {"type", type}});
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it)
            collect_json_shape(it.value(), path + "." + it.key(), out, count);
    } else if (j.is_array()) {
        const std::size_t n = std::min<std::size_t>(j.size(), 8);
        for (std::size_t i = 0; i < n; ++i)
            collect_json_shape(j[i], path + "[" + std::to_string(i) + "]", out, count);
    }
}

json json_diff_summary(const response_value_t& a, const response_value_t& b)
{
    json out;
    try {
        const auto ja = json::parse(std::string(a.body.begin(), a.body.end()));
        const auto jb = json::parse(std::string(b.body.begin(), b.body.end()));
        json sa = json::array();
        json sb = json::array();
        std::size_t ca = 0;
        std::size_t cb = 0;
        collect_json_shape(ja, "$", sa, ca);
        collect_json_shape(jb, "$", sb, cb);
        out["parse_ok"] = true;
        out["a_shape"] = sa;
        out["b_shape"] = sb;
        out["same_json"] = ja == jb;
        out["a_node_count"] = static_cast<std::uint64_t>(ca);
        out["b_node_count"] = static_cast<std::uint64_t>(cb);
    } catch (const std::exception& e) {
        out["parse_ok"] = false;
        out["error"] = redact_sensitive_text(e.what());
    }
    return out;
}

json structure_diff_summary(const response_value_t& a, const response_value_t& b)
{
    json out;
    out["status_changed"] = a.status != b.status;
    out["status_a"] = a.status;
    out["status_b"] = b.status;
    out["body_length_changed"] = a.body.size() != b.body.size();
    out["body_hash_changed"] = hash_bytes(a.body) != hash_bytes(b.body);
    out["headers"] = header_diff(a, b);
    out["a_preview_only"] = a.preview_only;
    out["b_preview_only"] = b.preview_only;
    out["json"] = json_diff_summary(a, b);
    return out;
}

bool response_for_diff(const json& params, const char* req_key, const char* resp_key, response_value_t& out, json& summary, std::string& err)
{
    if (params.contains(resp_key)) {
        if (!supplied_response_from_json(params[resp_key], out, err))
            return false;
        summary = {
            {"status", out.status},
            {"headers", headers_to_json(out.headers)},
            {"body_hash_algorithm", "fnv1a64"},
            {"body_hash", hash_bytes(out.body)},
            {"body_length", static_cast<std::uint64_t>(out.body.size())},
            {"body_preview", preview_bytes(out.body, 512)},
            {"preview_only", out.preview_only}
        };
        return true;
    }
    if (!params.contains(req_key) || !params[req_key].is_object()) {
        err = std::string(req_key) + " or " + resp_key + " is required";
        return false;
    }
    request_spec_t spec;
    if (!parse_request_spec(params[req_key], spec, err))
        return false;
    auto ex = send_once(spec, err);
    if (!ex.has_value())
        return false;
    out = response_from_exchange(*ex);
    summary = exchange_summary_json(*ex, 512);
    return true;
}

tool_result_t tool_diff_responses(const json& params)
{
    if (deadline_expired())
        return error_result("call cancelled before response diff");
    response_value_t a;
    response_value_t b;
    json a_summary;
    json b_summary;
    std::string err;
    if (!response_for_diff(params, "request_a", "response_a", a, a_summary, err))
        return error_result(err);
    if (deadline_expired())
        return error_result("call cancelled before second response");
    if (!response_for_diff(params, "request_b", "response_b", b, b_summary, err))
        return error_result(err);
    const std::string mode = lower_ascii(params.value("diff_mode", std::string("structure")));
    json diff;
    if (mode == "text")
        diff = text_diff_summary(a, b);
    else if (mode == "json")
        diff = json_diff_summary(a, b);
    else
        diff = structure_diff_summary(a, b);
    json out;
    out["mode"] = mode;
    out["response_a"] = a_summary;
    out["response_b"] = b_summary;
    out["diff"] = diff;
    return tool_result_t::ok("Response diff complete.", out);
}

tool_result_t tool_repeater(const json& params)
{
    if (deadline_expired())
        return error_result("call cancelled before repeater send");
    const std::string action = lower_ascii(compat_action_name(params));
    if (action == "send_from_exchange" || (params.contains("exchange_id") && !params.contains("raw_request") && !params.contains("url"))) {
        const std::uint64_t id = params.value("exchange_id", static_cast<std::uint64_t>(0));
        if (id == 0)
            return error_result("exchange_id is required");
        aida::burp::exchange_observed_t ex;
        if (!aida::burp::sitemap::find_exchange(id, ex))
            return error_result("exchange not found");
        if (ex.host.empty())
            return error_result("exchange has no target host");
        request_spec_t spec;
        spec.method = ex.method.empty() ? "GET" : ex.method;
        spec.parsed.scheme = lower_ascii(ex.scheme.empty() ? std::string("https") : ex.scheme);
        spec.parsed.host = ex.host;
        spec.parsed.port = ex.port != 0 ? ex.port : (spec.parsed.scheme == "https" ? 443 : 80);
        spec.parsed.tls = spec.parsed.scheme == "https";
        spec.parsed.target = ex.path.empty() ? "/" : ex.path;
        if (!ex.query.empty())
            spec.parsed.target += "?" + ex.query;
        spec.headers = ex.req_headers;
        spec.body = ex.req_body;
        spec.body_present = !ex.req_body.empty();
        const auto raw_request = build_raw_request(spec);
        aida::burp::audit_http::send_options_t opts;
        opts.timeout_ms = bounded_timeout_ms(params);
        opts.follow_redirects = params.value("follow_redirects", false);
        opts.max_redirects = std::max(0, std::min(params.value("max_redirects", 3), 10));
        opts.enforce_scope = params.value("enforce_scope", false);
        opts.publish_exchange = params.value("publish_exchange", false);
        opts.exchange_source = "aida.http.repeater";
        const auto sent = aida::burp::audit_http::send(raw_request, spec.parsed.host, spec.parsed.port, spec.parsed.tls, opts);
        if (!sent.has_value())
            return error_result(aida::burp::audit_http::last_error().empty() ? "repeater send failed" : aida::burp::audit_http::last_error());
        json out = exchange_summary_json(*sent, static_cast<std::size_t>(std::max(0, std::min(params.value("body_preview_bytes", 1024), 8192))));
        out["source_exchange_id"] = id;
        return tool_result_t::ok("Repeater exchange sent.", out);
    }
    if (params.contains("raw_request") && params["raw_request"].is_string()) {
        std::string host = params.value("host", std::string());
        std::uint16_t port = static_cast<std::uint16_t>(std::max(0, std::min(params.value("port", 0), 65535)));
        bool use_tls = params.value("use_tls", true);
        if (host.empty() && params.contains("url") && params["url"].is_string()) {
            parsed_url_t u;
            std::string err;
            if (!parse_url_silent(params["url"].get<std::string>(), u, err))
                return error_result(err);
            host = u.host;
            port = u.port;
            use_tls = u.tls;
        }
        if (host.empty() || port == 0)
            return error_result("host and port are required for raw_request repeater sends");
        std::vector<std::uint8_t> raw_request;
        const std::string raw_text = params["raw_request"].get<std::string>();
        raw_request.assign(raw_text.begin(), raw_text.end());
        aida::burp::audit_http::send_options_t opts;
        opts.timeout_ms = bounded_timeout_ms(params);
        opts.follow_redirects = params.value("follow_redirects", false);
        opts.max_redirects = std::max(0, std::min(params.value("max_redirects", 3), 10));
        opts.enforce_scope = params.value("enforce_scope", false);
        opts.publish_exchange = params.value("publish_exchange", false);
        opts.exchange_source = "aida.http.repeater";
        const auto sent = aida::burp::audit_http::send(raw_request, host, port, use_tls, opts);
        if (!sent.has_value())
            return error_result(aida::burp::audit_http::last_error().empty() ? "repeater raw request failed" : aida::burp::audit_http::last_error());
        json out = exchange_summary_json(*sent, static_cast<std::size_t>(std::max(0, std::min(params.value("body_preview_bytes", 1024), 8192))));
        return tool_result_t::ok("Repeater raw request sent.", out);
    }
    return perform_http_request(params, false, false);
}

}

void register_http_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged("http_tools", "register_http_tools entry");
    srv.register_tool({
        "aida.http.send_request",
        "Send a bounded HTTP/1.x request using AiDA's audit HTTP transport and return redacted response evidence.",
        {{"method", "string", "HTTP method; defaults to GET.", false},
         {"url", "string", "Absolute http:// or https:// URL.", true},
         {"headers", "object", "Request headers as an object or array; sensitive values are not returned.", false},
         {"body", "string", "Request body text.", false},
         {"body_hex", "string", "Request body bytes encoded as hex.", false},
         {"timeout_ms", "number", "Request timeout in milliseconds, bounded by the MCP call deadline.", false},
         {"redirect_policy", "string", "manual, none, or follow.", false},
         {"follow_redirects", "boolean", "Follow redirects when true.", false},
         {"max_redirects", "number", "Maximum redirects, capped at 10.", false},
         {"use_cookie_jar", "boolean", "Attach matching cookies from AiDA's cookie jar.", false},
         {"store_cookies", "boolean", "Store Set-Cookie headers into AiDA's cookie jar.", false},
         {"enforce_scope", "boolean", "Require the target to be in Burp scope.", false},
         {"publish_exchange", "boolean", "Publish the exchange to AiDA's Burp event bus; defaults true.", false},
         {"body_preview_bytes", "number", "Maximum redacted response preview bytes, capped at 8192.", false}},
        false,
        [](const json& params) -> tool_result_t { return perform_http_request(params, false, false); }
    });
    srv.register_tool({
        "aida.http.repeater",
        "Send a raw, sitemap-derived, or structured request through AiDA's repeater-safe HTTP transport.",
        {{"url", "string", "Absolute URL for structured sends or target inference.", false},
         {"method", "string", "HTTP method for structured sends.", false},
         {"headers", "object", "Request headers.", false},
         {"body", "string", "Request body text.", false},
         {"body_hex", "string", "Request body bytes encoded as hex.", false},
         {"raw_request", "string", "Raw HTTP/1.x request for repeater send_raw.", false},
         {"exchange_id", "number", "Observed sitemap exchange id for send_from_exchange.", false},
         {"host", "string", "Target host for raw_request.", false},
         {"port", "number", "Target port for raw_request.", false},
         {"use_tls", "boolean", "Use TLS for raw_request.", false},
         {"timeout_ms", "number", "Bounded send timeout.", false},
         {"follow_redirects", "boolean", "Follow redirects for the send.", false},
         {"max_redirects", "number", "Maximum redirects, capped at 10.", false},
         {"body_preview_bytes", "number", "Maximum redacted response preview bytes.", false}},
        false,
        [](const json& params) -> tool_result_t { return tool_repeater(params); }
    });
    srv.register_tool({
        "aida.http.build_multipart",
        "Build a multipart/form-data body with content type, length, hash, and redacted preview.",
        {{"fields", "object", "Form fields as object or array of {name,value}.", false},
         {"files", "array", "File-like parts with name, filename, content/content_hex, and content_type.", false},
         {"boundary", "string", "Optional multipart boundary.", false}},
        true,
        [](const json& params) -> tool_result_t { return tool_build_multipart(params); }
    });
    srv.register_tool({
        "aida.http.build_urlencoded",
        "Build an application/x-www-form-urlencoded body with length, hash, and redacted preview.",
        {{"params", "object", "Parameters as object or array of {name,value}.", false},
         {"fields", "object", "Alias for params.", false},
         {"space_as_plus", "boolean", "Encode spaces as '+', default true.", false}},
        true,
        [](const json& params) -> tool_result_t { return tool_build_urlencoded(params); }
    });
    srv.register_tool({
        "aida.http.follow_redirect_chain",
        "Follow a bounded HTTP redirect chain and return redacted evidence for each hop.",
        {{"method", "string", "HTTP method; defaults to GET.", false},
         {"url", "string", "Absolute http:// or https:// URL.", true},
         {"headers", "object", "Request headers.", false},
         {"body", "string", "Request body text.", false},
         {"body_hex", "string", "Request body bytes encoded as hex.", false},
         {"timeout_ms", "number", "Per-hop timeout bounded by MCP deadline.", false},
         {"max_redirects", "number", "Maximum redirects, capped at 10.", false},
         {"use_cookie_jar", "boolean", "Attach matching cookies from AiDA's cookie jar.", false},
         {"store_cookies", "boolean", "Store Set-Cookie headers into AiDA's cookie jar.", false},
         {"body_preview_bytes", "number", "Maximum redacted response preview bytes.", false}},
        false,
        [](const json& params) -> tool_result_t { return perform_http_request(params, true, true); }
    });
    srv.register_tool({
        "aida.diff.responses",
        "Diff two supplied response objects or two bounded HTTP responses from request_a and request_b.",
        {{"request_a", "object", "First HTTP request object.", false},
         {"request_b", "object", "Second HTTP request object.", false},
         {"response_a", "object", "First supplied response object with status, headers, body/body_hex/body_preview.", false},
         {"response_b", "object", "Second supplied response object with status, headers, body/body_hex/body_preview.", false},
         {"diff_mode", "string", "structure, text, or json.", false}},
        false,
        [](const json& params) -> tool_result_t { return tool_diff_responses(params); }
    });
    diag::log_tagged("http_tools", "register_http_tools complete");
}

}
