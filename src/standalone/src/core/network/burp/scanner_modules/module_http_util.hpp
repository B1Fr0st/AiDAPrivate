#pragma once

#include "../scanner_module.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {
namespace module_http {

struct parsed_request_t
{
    std::string request_line;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool valid = false;
};

inline std::string lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline bool contains_ci(const std::string& haystack, const std::string& needle)
{
    if (needle.empty() || haystack.size() < needle.size()) return false;
    const std::string h = lower(haystack);
    const std::string n = lower(needle);
    return h.find(n) != std::string::npos;
}

inline bool body_contains_ci_bytes(const std::vector<uint8_t>& body, const std::string& needle)
{
    if (needle.empty() || body.empty() || body.size() < needle.size()) return false;
    std::string text(reinterpret_cast<const char*>(body.data()), body.size());
    return contains_ci(text, needle);
}

inline parsed_request_t parse(const std::string& raw)
{
    parsed_request_t out;
    const size_t first = raw.find("\r\n");
    if (first == std::string::npos) return out;
    out.request_line = raw.substr(0, first);
    const size_t hdr_end = raw.find("\r\n\r\n", first + 2);
    const size_t headers_stop = hdr_end == std::string::npos ? raw.size() : hdr_end;
    size_t pos = first + 2;
    while (pos < headers_stop) {
        const size_t nl = raw.find("\r\n", pos);
        const size_t end = nl == std::string::npos || nl > headers_stop ? headers_stop : nl;
        std::string line = raw.substr(pos, end - pos);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            size_t vs = colon + 1;
            while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) ++vs;
            out.headers.emplace_back(std::move(name), line.substr(vs));
        }
        if (nl == std::string::npos || nl >= headers_stop) break;
        pos = nl + 2;
    }
    if (hdr_end != std::string::npos) out.body = raw.substr(hdr_end + 4);
    out.valid = true;
    return out;
}

inline std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    const std::string lname = lower(name);
    for (const auto& h : headers) {
        if (lower(h.first) == lname) return h.second;
    }
    return {};
}

inline void remove_header(parsed_request_t& req, const std::string& name)
{
    const std::string lname = lower(name);
    req.headers.erase(std::remove_if(req.headers.begin(), req.headers.end(), [&](const auto& h) {
        return lower(h.first) == lname;
    }), req.headers.end());
}

inline void set_header(parsed_request_t& req, const std::string& name, const std::string& value)
{
    const std::string lname = lower(name);
    for (auto& h : req.headers) {
        if (lower(h.first) == lname) {
            h.first = name;
            h.second = value;
            return;
        }
    }
    req.headers.emplace_back(name, value);
}

inline void add_header(parsed_request_t& req, const std::string& name, const std::string& value)
{
    req.headers.emplace_back(name, value);
}

inline std::string render(const parsed_request_t& req)
{
    std::ostringstream os;
    os << req.request_line << "\r\n";
    for (const auto& h : req.headers) os << h.first << ": " << h.second << "\r\n";
    os << "\r\n" << req.body;
    return os.str();
}

inline std::vector<uint8_t> render_bytes(const parsed_request_t& req)
{
    std::string raw = render(req);
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

inline bool split_request_line(const std::string& line, std::string& method, std::string& target, std::string& version)
{
    std::istringstream is(line);
    return static_cast<bool>(is >> method >> target >> version);
}

inline void set_request_target(parsed_request_t& req, const std::string& target)
{
    std::string method;
    std::string old_target;
    std::string version;
    if (!split_request_line(req.request_line, method, old_target, version)) return;
    req.request_line = method + " " + target + " " + version;
}

inline void set_method_target(parsed_request_t& req, const std::string& method, const std::string& target)
{
    std::string old_method;
    std::string old_target;
    std::string version;
    if (!split_request_line(req.request_line, old_method, old_target, version)) version = "HTTP/1.1";
    req.request_line = method + " " + target + " " + version;
}

inline std::string request_target(const std::string& raw)
{
    auto req = parse(raw);
    std::string method;
    std::string target;
    std::string version;
    if (!req.valid || !split_request_line(req.request_line, method, target, version)) return "/";
    return target.empty() ? std::string("/") : target;
}

inline std::string with_query_param(const std::string& target, const std::string& name, const std::string& value)
{
    std::string out = target.empty() ? std::string("/") : target;
    const size_t hash = out.find('#');
    std::string fragment;
    if (hash != std::string::npos) {
        fragment = out.substr(hash);
        out.erase(hash);
    }
    out += out.find('?') == std::string::npos ? "?" : "&";
    out += name;
    out += "=";
    out += value;
    out += fragment;
    return out;
}

inline std::string body_text(const exchange_observed_t& resp, size_t limit = 65536)
{
    const size_t n = std::min(resp.resp_body.size(), limit);
    return std::string(reinterpret_cast<const char*>(resp.resp_body.data()), n);
}

inline bool response_header_contains(const exchange_observed_t& resp, const std::string& name, const std::string& needle)
{
    return contains_ci(header_value(resp.resp_headers, name), needle);
}

inline bool response_is_cacheable(const exchange_observed_t& resp)
{
    const std::string cc = lower(header_value(resp.resp_headers, "Cache-Control"));
    const std::string age = header_value(resp.resp_headers, "Age");
    const std::string xcache = lower(header_value(resp.resp_headers, "X-Cache"));
    const std::string via = header_value(resp.resp_headers, "Via");
    if (!age.empty() || !via.empty() || contains_ci(xcache, "hit") || contains_ci(xcache, "miss")) return true;
    return cc.find("public") != std::string::npos ||
           cc.find("s-maxage") != std::string::npos ||
           cc.find("max-age") != std::string::npos;
}

inline bool response_content_type_is_html_or_json(const exchange_observed_t& resp)
{
    const std::string ct = lower(header_value(resp.resp_headers, "Content-Type"));
    return ct.find("text/html") != std::string::npos ||
           ct.find("application/json") != std::string::npos ||
           ct.find("text/plain") != std::string::npos ||
           ct.empty();
}

inline bool response_has_sql_error(const exchange_observed_t& resp)
{
    const std::string body = lower(body_text(resp));
    return body.find("sql syntax") != std::string::npos ||
           body.find("mysql") != std::string::npos ||
           body.find("postgresql") != std::string::npos ||
           body.find("sqlite") != std::string::npos ||
           body.find("ora-") != std::string::npos ||
           body.find("odbc") != std::string::npos ||
           body.find("unterminated quoted string") != std::string::npos;
}

inline exchange_observed_t synthetic_baseline(const module_context_t& ctx)
{
    exchange_observed_t synthetic;
    synthetic.method = "GET";
    synthetic.scheme = ctx.tls ? std::string("https") : std::string("http");
    synthetic.host = ctx.host;
    synthetic.port = ctx.port;
    synthetic.resp_headers = ctx.baseline_response_headers;
    synthetic.resp_body = ctx.baseline_response_body;
    synthetic.status_code = ctx.baseline_status_code;
    return synthetic;
}

}
}
}
}
