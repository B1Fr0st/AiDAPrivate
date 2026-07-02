#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "js_analysis_tools_standalone.hpp"

#include "burp/audit_http.hpp"
#include "burp/camoufox_bridge.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace network {
namespace js_analysis_tools {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct fetch_result_t
{
    bool        ok = false;
    std::string body;
    int         status = 0;
    std::string content_type;
    std::string error;
    bool        truncated = false;
};

struct secret_pattern_t
{
    std::string name;
    std::string provider;
    std::string type;
    std::regex  pattern;
    std::size_t group = 0;
    double      confidence = 0.80;
};

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

bool starts_with_ci(const std::string& s, const std::string& prefix)
{
    if (s.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

bool contains_ci(const std::string& s, const std::string& needle)
{
    return lower_copy(s).find(lower_copy(needle)) != std::string::npos;
}

bool is_sensitive_key(const std::string& key)
{
    const std::string k = lower_copy(key);
    static const char* needles[] = {
        "token", "secret", "key", "password", "passwd", "pwd", "auth", "session", "license", "bearer", "credential"
    };
    for (const char* needle : needles) {
        if (k.find(needle) != std::string::npos) return true;
    }
    return false;
}

std::string hex_encode(const std::uint8_t* data, std::size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2] = hex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[data[i] & 0xF];
    }
    return out;
}

std::string fallback_hash_hex(const std::string& value)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : value) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    std::ostringstream os;
    os << "fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << h;
    return os.str();
}

std::pair<std::size_t, std::size_t> line_col_for_offset(const std::string& source, std::size_t offset)
{
    std::size_t line = 1;
    std::size_t col = 1;
    const std::size_t capped = std::min(offset, source.size());
    for (std::size_t i = 0; i < capped; ++i) {
        if (source[i] == '\n') {
            ++line;
            col = 1;
        } else {
            ++col;
        }
    }
    return {line, col};
}

std::vector<std::pair<std::string, std::string>> headers_from_json(const json& j)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (!j.is_object()) return out;
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (!it.value().is_string()) continue;
        const std::string name = it.key();
        const std::string value = it.value().get<std::string>();
        if (name.find('\r') != std::string::npos || name.find('\n') != std::string::npos) continue;
        if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) continue;
        const std::string lname = lower_copy(name);
        if (lname == "host" || lname == "connection" || lname == "content-length") continue;
        out.emplace_back(name, value);
    }
    return out;
}

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80)) return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

bool call_expired()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
}

int bounded_timeout_ms(int requested, int fallback, int min_ms, int max_ms)
{
    int value = requested <= 0 ? fallback : requested;
    value = std::max(min_ms, std::min(value, max_ms));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline <= now)
            return 1;
        value = static_cast<int>(std::min<std::uint64_t>(static_cast<std::uint64_t>(value), deadline - now));
    }
    return std::max(1, value);
}

fetch_result_t fetch_text_url(const std::string& url,
                              const json& headers,
                              int timeout_ms,
                              bool enforce_scope,
                              std::size_t max_bytes)
{
    fetch_result_t out;
    if (call_expired()) {
        out.error = "cancelled";
        return out;
    }
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!burp::audit_http::parse_url(url, scheme, host, port, path)) {
        out.error = "url parse failed";
        return out;
    }
    const bool tls = scheme == "https";
    std::ostringstream req;
    req << "GET " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    req << "User-Agent: AiDA-JS-Analysis/1.0\r\n";
    req << "Accept: application/javascript, text/javascript, application/json, text/plain, */*\r\n";
    for (const auto& h : headers_from_json(headers))
        req << h.first << ": " << h.second << "\r\n";
    req << "Connection: close\r\n\r\n";

    const std::string raw = req.str();
    std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
    burp::audit_http::send_options_t opts;
    opts.timeout_ms = bounded_timeout_ms(timeout_ms, 15000, 250, 45000);
    opts.follow_redirects = true;
    opts.max_redirects = 4;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = "js_analysis";
    auto ex = burp::audit_http::send(bytes, host, port, tls, opts);
    if (!ex.has_value()) {
        out.error = burp::audit_http::last_error();
        return out;
    }
    out.status = ex->status_code;
    for (const auto& h : ex->resp_headers) {
        if (lower_copy(h.first) == "content-type") {
            out.content_type = h.second;
            break;
        }
    }
    if (ex->status_code < 200 || ex->status_code >= 300) {
        out.error = "HTTP " + std::to_string(ex->status_code);
        return out;
    }
    const std::size_t n = max_bytes == 0 ? ex->resp_body.size() : std::min(max_bytes, ex->resp_body.size());
    out.body.assign(reinterpret_cast<const char*>(ex->resp_body.data()), n);
    out.truncated = n < ex->resp_body.size();
    out.ok = true;
    return out;
}

std::string truncate_text(const std::string& s, std::size_t max_len)
{
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len);
}

std::string query_redacted(const std::string& query)
{
    std::string out;
    std::size_t pos = 0;
    bool first = true;
    while (pos <= query.size()) {
        std::size_t amp = query.find('&', pos);
        std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (!first) out.push_back('&');
        first = false;
        std::size_t eq = part.find('=');
        if (eq == std::string::npos) {
            out += part;
        } else {
            out += part.substr(0, eq + 1);
            out += "[redacted]";
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return out;
}

std::string redact_context(const std::string& source, std::size_t start, std::size_t len)
{
    const std::size_t left = start > 80 ? start - 80 : 0;
    const std::size_t right = std::min(source.size(), start + len + 80);
    std::string ctx = source.substr(left, right - left);
    const std::size_t rel = start - left;
    if (rel <= ctx.size()) {
        ctx.replace(rel, std::min(len, ctx.size() - rel), "[REDACTED]");
    }
    return truncate_text(redact_sensitive_values(ctx), 240);
}

std::vector<secret_pattern_t> built_in_patterns()
{
    std::vector<secret_pattern_t> p;
    p.push_back({"aws_access_key", "aws", "access_key_id", std::regex(R"re(\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b)re"), 1, 0.98});
    p.push_back({"google_api_key", "google", "api_key", std::regex(R"re(\b(AIza[0-9A-Za-z_-]{35})\b)re"), 1, 0.98});
    p.push_back({"github_token", "github", "token", std::regex(R"re(\b(gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b)re"), 1, 0.96});
    p.push_back({"slack_token", "slack", "token", std::regex(R"re(\b(xox[baprs]-[A-Za-z0-9-]{10,255})\b)re"), 1, 0.96});
    p.push_back({"stripe_secret_key", "stripe", "secret_key", std::regex(R"re(\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})\b)re"), 1, 0.95});
    p.push_back({"stripe_publishable_key", "stripe", "publishable_key", std::regex(R"re(\b(pk_(?:live|test)_[A-Za-z0-9]{16,255})\b)re"), 1, 0.86});
    p.push_back({"jwt", "jwt", "token", std::regex(R"re(\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})\b)re"), 1, 0.88});
    p.push_back({"bearer_token", "http", "bearer_token", std::regex(R"re(\bBearer\s+([A-Za-z0-9._~+/=-]{16,4096})\b)re", std::regex_constants::icase), 1, 0.78});
    p.push_back({"private_key", "pem", "private_key", std::regex(R"re((-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{64,12000}?-----END [A-Z0-9 ]*PRIVATE KEY-----))re"), 1, 0.99});
    p.push_back({"assignment_secret", "javascript", "assigned_secret", std::regex(R"re((api[_-]?key|apikey|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|private[_-]?key|password)\s*[:=]\s*["'`]([^"'`\r\n]{8,4096})["'`])re", std::regex_constants::icase), 2, 0.70});
    return p;
}

bool looks_like_low_value_secret(const std::string& value)
{
    if (value.size() < 8) return true;
    const std::string lower = lower_copy(value);
    static const char* weak[] = {
        "undefined", "null", "false", "true", "password", "changeme", "example", "localhost", "token", "secret", "apikey"
    };
    for (const char* w : weak) {
        if (lower == w) return true;
    }
    std::size_t classes = 0;
    bool has_lower = false, has_upper = false, has_digit = false, has_symbol = false;
    for (unsigned char c : value) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_symbol = true;
    }
    if (has_lower) ++classes;
    if (has_upper) ++classes;
    if (has_digit) ++classes;
    if (has_symbol) ++classes;
    return value.size() < 20 && classes < 2;
}

json finding_to_json(const std::string& source,
                     const std::string& source_label,
                     const secret_pattern_t& pattern,
                     const std::string& value,
                     std::size_t offset,
                     std::size_t match_len)
{
    const auto lc = line_col_for_offset(source, offset);
    json item;
    item["provider"] = pattern.provider;
    item["type"] = pattern.type;
    item["pattern"] = pattern.name;
    item["source"] = source_label;
    item["sha256"] = sha256_hex(value);
    item["length"] = static_cast<std::uint64_t>(value.size());
    item["line"] = static_cast<std::uint64_t>(lc.first);
    item["column"] = static_cast<std::uint64_t>(lc.second);
    item["confidence"] = pattern.confidence;
    item["context"] = redact_context(source, offset, match_len);
    item["redacted"] = true;
    return item;
}

std::string endpoint_source_kind(const std::string& label)
{
    if (starts_with_ci(label, "http://") || starts_with_ci(label, "https://")) return "static_js_url";
    if (label.empty()) return "static_js_source";
    return label;
}

bool is_probable_endpoint(const std::string& candidate, bool include_relative)
{
    if (candidate.empty() || candidate.size() > 2048) return false;
    if (candidate.find('\r') != std::string::npos || candidate.find('\n') != std::string::npos) return false;
    const std::string lower = lower_copy(candidate);
    if (lower.find("javascript:") == 0 || lower.find("data:") == 0 || lower.find("mailto:") == 0) return false;
    if (!include_relative && !(starts_with_ci(candidate, "http://") || starts_with_ci(candidate, "https://") || candidate.rfind("//", 0) == 0))
        return false;
    static const char* static_ext[] = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ttf", ".ico", ".map"};
    bool static_asset = false;
    for (const char* ext : static_ext) {
        if (lower.find(ext) != std::string::npos) {
            static_asset = true;
            break;
        }
    }
    const bool apiish = lower.find("/api") != std::string::npos || lower.find("graphql") != std::string::npos ||
        lower.find("/v1") != std::string::npos || lower.find("/v2") != std::string::npos ||
        lower.find("/rest") != std::string::npos || lower.find("/rpc") != std::string::npos ||
        lower.find("/oauth") != std::string::npos || lower.find("/auth") != std::string::npos;
    if (static_asset && !apiish) return false;
    if (starts_with_ci(candidate, "http://") || starts_with_ci(candidate, "https://") || candidate.rfind("//", 0) == 0)
        return candidate.find('.') != std::string::npos || apiish;
    return include_relative && (candidate[0] == '/' || lower.find("api/") == 0 || lower.find("v1/") == 0 || lower.find("v2/") == 0 || lower.find("graphql") == 0);
}

std::string redact_endpoint_path(std::string endpoint)
{
    std::size_t fragment = endpoint.find('#');
    std::string hash;
    if (fragment != std::string::npos) {
        hash = endpoint.substr(fragment);
        endpoint.erase(fragment);
    }
    std::size_t query = endpoint.find('?');
    if (query == std::string::npos) return endpoint + hash;
    return endpoint.substr(0, query + 1) + query_redacted(endpoint.substr(query + 1)) + hash;
}

void push_endpoint(json& arr,
                   std::set<std::string>& seen,
                   const std::string& method,
                   const std::string& endpoint,
                   const std::string& source,
                   double confidence,
                   const std::string& source_label,
                   const std::string& js_source,
                   std::size_t offset)
{
    if (!is_probable_endpoint(endpoint, true)) return;
    const std::string path = redact_endpoint_path(endpoint);
    const std::string m = method.empty() ? "UNKNOWN" : upper_copy(method);
    const std::string key = m + "\n" + path + "\n" + source;
    if (!seen.insert(key).second) return;
    const auto lc = line_col_for_offset(js_source, offset);
    json item;
    item["method"] = m;
    item["path"] = path;
    item["source"] = source;
    item["source_label"] = redact_url_for_output(source_label);
    item["confidence"] = confidence;
    item["line"] = static_cast<std::uint64_t>(lc.first);
    item["column"] = static_cast<std::uint64_t>(lc.second);
    item["context"] = truncate_text(redact_sensitive_values(js_source.substr(offset > 80 ? offset - 80 : 0, std::min<std::size_t>(180, js_source.size() - (offset > 80 ? offset - 80 : 0)))), 220);
    arr.push_back(std::move(item));
}

std::string infer_fetch_method(const std::string& source, std::size_t offset)
{
    const std::size_t end = std::min(source.size(), offset + 360);
    const std::string ctx = lower_copy(source.substr(offset, end - offset));
    std::regex method_re(R"re(method\s*:\s*["'`](get|post|put|patch|delete|head|options)["'`])re", std::regex_constants::icase);
    std::smatch m;
    if (std::regex_search(ctx, m, method_re) && m.size() > 1)
        return m[1].str();
    return "GET";
}

bool append_utf8(std::string& out, std::uint32_t cp)
{
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
        return true;
    }
    if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        return true;
    }
    if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        return true;
    }
    if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        return true;
    }
    return false;
}

int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

std::string decode_js_escapes(const std::string& in, std::size_t& replaced)
{
    replaced = 0;
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\' || i + 1 >= in.size()) {
            out.push_back(in[i]);
            continue;
        }
        const char n = in[i + 1];
        if (n == 'x' && i + 3 < in.size()) {
            const int a = hex_value(in[i + 2]);
            const int b = hex_value(in[i + 3]);
            if (a >= 0 && b >= 0) {
                out.push_back(static_cast<char>((a << 4) | b));
                i += 3;
                ++replaced;
                continue;
            }
        }
        if (n == 'u' && i + 5 < in.size()) {
            std::uint32_t cp = 0;
            bool ok = true;
            for (std::size_t k = 0; k < 4; ++k) {
                const int hv = hex_value(in[i + 2 + k]);
                if (hv < 0) {
                    ok = false;
                    break;
                }
                cp = (cp << 4) | static_cast<std::uint32_t>(hv);
            }
            if (ok && append_utf8(out, cp)) {
                i += 5;
                ++replaced;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

std::string beautify_js(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + in.size() / 8);
    int indent = 0;
    bool in_string = false;
    char quote = 0;
    bool escaped = false;
    auto newline = [&]() {
        while (!out.empty() && (out.back() == ' ' || out.back() == '\t')) out.pop_back();
        if (out.empty() || out.back() != '\n') out.push_back('\n');
        for (int i = 0; i < indent; ++i) out.append("  ");
    };
    for (char c : in) {
        if (in_string) {
            out.push_back(c);
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == quote) in_string = false;
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') {
            in_string = true;
            quote = c;
            out.push_back(c);
            continue;
        }
        if (c == '{' || c == '[') {
            out.push_back(c);
            ++indent;
            newline();
            continue;
        }
        if (c == '}' || c == ']') {
            indent = std::max(0, indent - 1);
            newline();
            out.push_back(c);
            continue;
        }
        if (c == ';') {
            out.push_back(c);
            newline();
            continue;
        }
        if (c == ',') {
            out.push_back(c);
            if (out.size() > 120) newline();
            else out.push_back(' ');
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!out.empty() && !std::isspace(static_cast<unsigned char>(out.back()))) out.push_back(' ');
            continue;
        }
        out.push_back(c);
    }
    return out;
}

json extract_string_arrays(const std::string& source)
{
    json arrays = json::array();
    std::regex re(R"re((?:var|let|const)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[((?:\s*["'`][\s\S]{0,4096}?["'`]\s*,?){2,128})\])re");
    auto begin = std::sregex_iterator(source.begin(), source.end(), re);
    auto end = std::sregex_iterator();
    std::size_t array_count = 0;
    for (auto it = begin; it != end && array_count < 16; ++it, ++array_count) {
        const std::smatch& m = *it;
        json arr;
        arr["name"] = m[1].str();
        arr["offset"] = static_cast<std::uint64_t>(m.position(0));
        arr["strings"] = json::array();
        const std::string body = m[2].str();
        std::regex str_re(R"re(["'`]([^"'`]{0,2048})["'`])re");
        auto sb = std::sregex_iterator(body.begin(), body.end(), str_re);
        auto se = std::sregex_iterator();
        std::size_t idx = 0;
        for (auto sit = sb; sit != se && idx < 64; ++sit, ++idx) {
            std::string value = (*sit)[1].str();
            const std::string redacted = redact_sensitive_values(value);
            json item;
            item["index"] = static_cast<std::uint64_t>(idx);
            item["length"] = static_cast<std::uint64_t>(value.size());
            item["sha256"] = sha256_hex(value);
            item["value"] = truncate_text(redacted, 240);
            item["redacted"] = redacted != value;
            arr["strings"].push_back(std::move(item));
        }
        arr["count"] = arr["strings"].size();
        arrays.push_back(std::move(arr));
    }
    return arrays;
}

std::vector<std::uint8_t> base64_decode_bytes(const std::string& in)
{
    static const signed char table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,0,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
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
    std::vector<std::uint8_t> out;
    out.reserve((in.size() * 3) / 4 + 3);
    std::uint32_t val = 0;
    int bits = 0;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == '\t' || c == ' ') continue;
        const int v = table[c];
        if (v < 0) continue;
        val = (val << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((val >> bits) & 0xFF));
        }
    }
    return out;
}

std::string source_map_url_from_source(const std::string& source)
{
    std::regex re(R"re(sourceMappingURL\s*=\s*([^\s*]+))re");
    std::smatch m;
    if (std::regex_search(source, m, re) && m.size() > 1)
        return m[1].str();
    return {};
}

std::string resolve_url(const std::string& base_url, const std::string& ref)
{
    if (ref.empty()) return {};
    if (starts_with_ci(ref, "http://") || starts_with_ci(ref, "https://")) return ref;
    std::string scheme, host, path;
    std::uint16_t port = 0;
    if (!burp::audit_http::parse_url(base_url, scheme, host, port, path)) return ref;
    std::string origin = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        origin += ":" + std::to_string(static_cast<unsigned>(port));
    if (ref.rfind("//", 0) == 0) return scheme + ":" + ref;
    if (!ref.empty() && ref[0] == '/') return origin + ref;
    std::size_t slash = path.rfind('/');
    std::string dir = slash == std::string::npos ? "/" : path.substr(0, slash + 1);
    return origin + dir + ref;
}

bool decode_inline_source_map(const std::string& url, std::string& out)
{
    if (url.rfind("data:", 0) != 0) return false;
    const std::size_t comma = url.find(',');
    if (comma == std::string::npos) return false;
    const std::string meta = lower_copy(url.substr(0, comma));
    const std::string payload = url.substr(comma + 1);
    if (meta.find(";base64") != std::string::npos) {
        const auto bytes = base64_decode_bytes(payload);
        out.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return !out.empty();
    }
    out = payload;
    return !out.empty();
}

tool_result_t load_source_from_params(const json& params,
                                      const char* diag_tag,
                                      std::string& source,
                                      std::string& source_label,
                                      json& fetch_meta)
{
    if (params.contains("source") && params["source"].is_string()) {
        source = params["source"].get<std::string>();
        source_label = params.value("source_name", std::string("inline_source"));
        fetch_meta["source_kind"] = "inline";
        return tool_result_t::ok("source loaded");
    }
    if (params.contains("url") && params["url"].is_string()) {
        const std::string url = params["url"].get<std::string>();
        const int timeout_ms = params.value("timeout_ms", 15000);
        const bool enforce_scope = params.value("enforce_scope", false);
        const std::size_t max_bytes = static_cast<std::size_t>(std::max(65536, std::min(params.value("max_source_bytes", 4194304), 16777216)));
        diag::log_tagged_fmt(diag_tag, "fetch url=%s max_bytes=%zu", redact_url_for_output(url).c_str(), max_bytes);
        fetch_result_t fetched = fetch_text_url(url, params.value("headers", json::object()), timeout_ms, enforce_scope, max_bytes);
        fetch_meta["source_kind"] = "url";
        fetch_meta["url"] = redact_url_for_output(url);
        fetch_meta["status"] = fetched.status;
        fetch_meta["content_type"] = fetched.content_type;
        fetch_meta["truncated"] = fetched.truncated;
        if (!fetched.ok) {
            fetch_meta["error"] = fetched.error;
            return tool_result_t::error("source fetch failed", fetch_meta);
        }
        source = std::move(fetched.body);
        source_label = url;
        return tool_result_t::ok("source loaded");
    }
    return tool_result_t::error("source or url is required");
}

tool_result_t tool_extract_secrets(const json& params)
{
    diag::log_tagged_fmt("js_analysis", "extract_secrets entry has_url=%d has_source=%d",
        params.contains("url") ? 1 : 0, params.contains("source") ? 1 : 0);
    std::string source;
    std::string label;
    json fetch_meta;
    tool_result_t loaded = load_source_from_params(params, "js_analysis", source, label, fetch_meta);
    if (!loaded.success) return loaded;
    if (call_expired())
        return tool_result_t::error("cancelled");
    const double min_confidence = params.value("min_confidence", 0.50);
    const std::size_t max_results = static_cast<std::size_t>(std::max(1, std::min(params.value("max_results", 256), 2048)));
    json findings = extract_redacted_secrets_from_source(source, label, min_confidence, max_results, params.value("patterns", json::array()));
    json out;
    out["source"] = redact_url_for_output(label);
    out["source_sha256"] = sha256_hex(source);
    out["source_bytes"] = static_cast<std::uint64_t>(source.size());
    out["fetch"] = std::move(fetch_meta);
    out["count"] = findings.size();
    out["findings"] = std::move(findings);
    diag::log_tagged_fmt("js_analysis", "extract_secrets done count=%zu source_len=%zu", out["count"].get<std::size_t>(), source.size());
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_extract_endpoints(const json& params)
{
    diag::log_tagged_fmt("js_analysis", "extract_endpoints entry has_url=%d has_source=%d",
        params.contains("url") ? 1 : 0, params.contains("source") ? 1 : 0);
    std::string source;
    std::string label;
    json fetch_meta;
    tool_result_t loaded = load_source_from_params(params, "js_analysis", source, label, fetch_meta);
    if (!loaded.success) return loaded;
    const bool include_relative = params.value("include_relative", true);
    const std::size_t max_results = static_cast<std::size_t>(std::max(1, std::min(params.value("max_results", 512), 4096)));
    json endpoints = extract_endpoints_from_source(source, label, include_relative, max_results);
    json out;
    out["source"] = redact_url_for_output(label);
    out["source_sha256"] = sha256_hex(source);
    out["source_bytes"] = static_cast<std::uint64_t>(source.size());
    out["fetch"] = std::move(fetch_meta);
    out["count"] = endpoints.size();
    out["endpoints"] = std::move(endpoints);
    diag::log_tagged_fmt("js_analysis", "extract_endpoints done count=%zu source_len=%zu", out["count"].get<std::size_t>(), source.size());
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_analyze_source_map(const json& params)
{
    diag::log_tagged_fmt("js_analysis", "analyze_source_map entry has_url=%d has_source_map=%d",
        params.contains("url") ? 1 : 0, params.contains("source_map") ? 1 : 0);
    std::string map_text;
    std::string map_label = "inline_source_map";
    json fetch_meta = json::object();

    if (params.contains("source_map") && params["source_map"].is_string()) {
        map_text = params["source_map"].get<std::string>();
    } else {
        std::string map_url = params.value("source_map_url", std::string());
        std::string js_source;
        std::string js_label;
        if (map_url.empty()) {
            json source_fetch;
            tool_result_t loaded = load_source_from_params(params, "js_analysis", js_source, js_label, source_fetch);
            if (!loaded.success) return loaded;
            map_url = source_map_url_from_source(js_source);
            fetch_meta["javascript"] = source_fetch;
            if (map_url.empty())
                return tool_result_t::error("source map marker not found", fetch_meta);
            if (decode_inline_source_map(map_url, map_text)) {
                map_label = "inline_data_source_map";
            } else if (!params.value("fetch_external", true)) {
                json err = fetch_meta;
                err["source_map_url"] = redact_url_for_output(resolve_url(js_label, map_url));
                return tool_result_t::error("external source map fetch disabled", err);
            } else {
                map_url = resolve_url(js_label, map_url);
            }
        }
        if (map_text.empty()) {
            const int timeout_ms = params.value("timeout_ms", 15000);
            const std::size_t max_bytes = static_cast<std::size_t>(std::max(65536, std::min(params.value("max_source_bytes", 8388608), 33554432)));
            fetch_result_t fetched = fetch_text_url(map_url, params.value("headers", json::object()), timeout_ms, params.value("enforce_scope", false), max_bytes);
            fetch_meta["source_map_url"] = redact_url_for_output(map_url);
            fetch_meta["source_map_status"] = fetched.status;
            fetch_meta["source_map_truncated"] = fetched.truncated;
            if (!fetched.ok) {
                fetch_meta["error"] = fetched.error;
                return tool_result_t::error("source map fetch failed", fetch_meta);
            }
            map_text = std::move(fetched.body);
            map_label = map_url;
        }
    }

    json doc = json::parse(map_text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        json err;
        err["source_map"] = redact_url_for_output(map_label);
        err["bytes"] = static_cast<std::uint64_t>(map_text.size());
        return tool_result_t::error("source map JSON parse failed", err);
    }

    json sources = json::array();
    json endpoints = json::array();
    json secrets = json::array();
    const json empty_array = json::array();
    const json& source_names = doc.contains("sources") && doc["sources"].is_array() ? doc["sources"] : empty_array;
    const json& source_contents = doc.contains("sourcesContent") && doc["sourcesContent"].is_array() ? doc["sourcesContent"] : empty_array;
    std::set<std::string> seen_endpoint;
    for (std::size_t i = 0; i < source_names.size(); ++i) {
        if (call_expired())
            return tool_result_t::error("cancelled");
        std::string name = source_names[i].is_string() ? source_names[i].get<std::string>() : std::string();
        std::string content;
        if (i < source_contents.size() && source_contents[i].is_string())
            content = source_contents[i].get<std::string>();
        json src;
        src["index"] = static_cast<std::uint64_t>(i);
        src["source"] = redact_url_for_output(name);
        src["has_content"] = !content.empty();
        src["content_length"] = static_cast<std::uint64_t>(content.size());
        if (!content.empty()) src["content_sha256"] = sha256_hex(content);
        sources.push_back(std::move(src));
        if (!content.empty()) {
            json eps = extract_endpoints_from_source(content, name, true, 256);
            for (const auto& ep : eps) {
                std::string key = ep.value("method", std::string()) + "\n" + ep.value("path", std::string());
                if (seen_endpoint.insert(key).second) endpoints.push_back(ep);
            }
            json sec = extract_redacted_secrets_from_source(content, name, 0.50, 128, json::array());
            for (const auto& s : sec) secrets.push_back(s);
        }
    }

    json out;
    out["source_map"] = redact_url_for_output(map_label);
    out["source_map_sha256"] = sha256_hex(map_text);
    out["source_map_bytes"] = static_cast<std::uint64_t>(map_text.size());
    out["fetch"] = std::move(fetch_meta);
    out["version"] = doc.value("version", 0);
    out["file"] = redact_url_for_output(doc.value("file", std::string()));
    out["sources_count"] = sources.size();
    out["sources"] = std::move(sources);
    out["names_count"] = doc.contains("names") && doc["names"].is_array() ? doc["names"].size() : 0;
    out["mappings_length"] = doc.contains("mappings") && doc["mappings"].is_string() ? static_cast<std::uint64_t>(doc["mappings"].get<std::string>().size()) : 0;
    out["hidden_endpoint_count"] = endpoints.size();
    out["hidden_endpoints"] = std::move(endpoints);
    out["secret_count"] = secrets.size();
    out["secrets"] = std::move(secrets);
    diag::log_tagged_fmt("js_analysis", "analyze_source_map done sources=%zu endpoints=%zu secrets=%zu", out["sources_count"].get<std::size_t>(), out["hidden_endpoint_count"].get<std::size_t>(), out["secret_count"].get<std::size_t>());
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_deobfuscate(const json& params)
{
    if (!params.contains("source") || !params["source"].is_string())
        return tool_result_t::error("source is required");
    const std::string source = params["source"].get<std::string>();
    const std::string requested = lower_copy(params.value("deobfuscator", std::string("auto")));
    const std::size_t max_output = static_cast<std::size_t>(std::max(4096, std::min(params.value("max_output_bytes", 262144), 1048576)));
    diag::log_tagged_fmt("js_analysis", "deobfuscate entry source_len=%zu requested=%s", source.size(), requested.c_str());

    std::size_t escape_count = 0;
    std::string transformed = decode_js_escapes(source, escape_count);
    json transforms = json::array();
    if (escape_count > 0) transforms.push_back(json{{"name", "unicode_hex_escape_decode"}, {"replacements", static_cast<std::uint64_t>(escape_count)}});
    json arrays = extract_string_arrays(transformed);
    if (!arrays.empty()) transforms.push_back(json{{"name", "string_array_extract"}, {"arrays", arrays.size()}});
    transformed = beautify_js(transformed);
    transforms.push_back(json{{"name", "beautify"}, {"style", "built_in"}});

    json eval_evidence = json::array();
    const std::string lower = lower_copy(transformed);
    if (lower.find("eval(") != std::string::npos) eval_evidence.push_back("eval_call_present");
    if (lower.find("function(p,a,c,k,e,d)") != std::string::npos || lower.find("eval(function(p,a,c,k,e,d)") != std::string::npos) eval_evidence.push_back("packer_signature_present");
    if (lower.find("function(") != std::string::npos && lower.find("constructor") != std::string::npos) eval_evidence.push_back("function_constructor_present");
    if (lower.find("atob(") != std::string::npos) eval_evidence.push_back("base64_runtime_decode_present");

    json unsupported = json::array();
    if (!(requested.empty() || requested == "auto" || requested == "built_in" || requested == "builtin" || requested == "unicode" || requested == "beautify"))
        unsupported.push_back(json{{"requested", requested}, {"reason", "external JavaScript deobfuscators are not embedded in this build path"}});
    if (!eval_evidence.empty())
        unsupported.push_back(json{{"transform", "dynamic_eval_unpack"}, {"reason", "dynamic evaluation is reported as evidence but not executed inside the MCP process"}});

    const std::string redacted = redact_sensitive_values(transformed);
    const bool truncated = redacted.size() > max_output;
    json endpoints = extract_endpoints_from_source(redacted, "deobfuscated_source", true, 512);
    json secrets = extract_redacted_secrets_from_source(transformed, "deobfuscated_source", 0.50, 256, json::array());

    json out;
    out["source_sha256"] = sha256_hex(source);
    out["deobfuscated_sha256"] = sha256_hex(transformed);
    out["source_bytes"] = static_cast<std::uint64_t>(source.size());
    out["deobfuscated_bytes"] = static_cast<std::uint64_t>(transformed.size());
    out["output_truncated"] = truncated;
    out["transforms_applied"] = std::move(transforms);
    out["unsupported_transforms"] = std::move(unsupported);
    out["string_arrays"] = std::move(arrays);
    out["eval_unpack_evidence"] = std::move(eval_evidence);
    out["endpoints"] = std::move(endpoints);
    out["secrets"] = std::move(secrets);
    out["deobfuscated_source"] = truncate_text(redacted, max_output);
    diag::log_tagged_fmt("js_analysis", "deobfuscate done output_len=%zu truncated=%d", redacted.size(), truncated ? 1 : 0);
    return tool_result_t::ok(out.dump(2), out);
}

}

std::string sha256_hex(const std::string& value)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD obj_len = 0;
    DWORD data_len = 0;
    DWORD hash_len = 0;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return fallback_hash_hex(value);
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &data_len, 0)) ||
        !BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &data_len, 0)) ||
        hash_len == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return fallback_hash_hex(value);
    }
    std::vector<UCHAR> obj(obj_len);
    std::vector<UCHAR> digest(hash_len);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, obj.data(), obj_len, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return fallback_hash_hex(value);
    }
    const PUCHAR data = value.empty() ? nullptr : reinterpret_cast<PUCHAR>(const_cast<char*>(value.data()));
    const ULONG len = static_cast<ULONG>(std::min<std::size_t>(value.size(), static_cast<std::size_t>(0xFFFFFFFFu)));
    bool ok = BCRYPT_SUCCESS(BCryptHashData(hash, data, len, 0)) &&
        BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), hash_len, 0));
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok ? hex_encode(digest.data(), digest.size()) : fallback_hash_hex(value);
}

std::string redact_url_for_output(const std::string& url)
{
    std::size_t query = url.find('?');
    if (query == std::string::npos) return url;
    std::size_t fragment = url.find('#', query + 1);
    const std::string before = url.substr(0, query + 1);
    const std::string q = url.substr(query + 1, fragment == std::string::npos ? std::string::npos : fragment - query - 1);
    const std::string after = fragment == std::string::npos ? std::string() : url.substr(fragment);
    return before + query_redacted(q) + after;
}

std::string redact_sensitive_values(const std::string& text)
{
    if (text.empty()) return text;
    std::string out = text;
    try {
        out = std::regex_replace(out, std::regex(R"re(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{16,12000}?-----END [A-Z0-9 ]*PRIVATE KEY-----)re"), "[REDACTED_PRIVATE_KEY]");
        out = std::regex_replace(out, std::regex(R"re(\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})\b)re"), "[REDACTED_SECRET]");
        out = std::regex_replace(out, std::regex(R"re((api[_-]?key|apikey|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|private[_-]?key|password)\s*[:=]\s*["'`])[^"'`\r\n]{8,4096}(["'`])re", std::regex_constants::icase), "$1[REDACTED]$2");
        out = std::regex_replace(out, std::regex(R"re((Bearer\s+)[A-Za-z0-9._~+/=-]{16,4096})re", std::regex_constants::icase), "$1[REDACTED]");
    } catch (...) {
        return "[REDACTION_FAILED]";
    }
    return out;
}

nlohmann::json extract_redacted_secrets_from_source(const std::string& source,
                                                    const std::string& source_label,
                                                    double min_confidence,
                                                    std::size_t max_results,
                                                    const nlohmann::json& custom_patterns)
{
    json out = json::array();
    std::vector<secret_pattern_t> patterns = built_in_patterns();
    if (custom_patterns.is_array()) {
        for (const auto& item : custom_patterns) {
            if (patterns.size() >= 64) break;
            try {
                if (item.is_string()) {
                    std::string pat = item.get<std::string>();
                    if (!pat.empty() && pat.size() <= 512)
                        patterns.push_back({"custom", "custom", "custom_secret", std::regex(pat), 0, 0.60});
                } else if (item.is_object() && item.contains("regex") && item["regex"].is_string()) {
                    std::string pat = item["regex"].get<std::string>();
                    if (!pat.empty() && pat.size() <= 512) {
                        secret_pattern_t p{
                            item.value("name", std::string("custom")),
                            item.value("provider", std::string("custom")),
                            item.value("type", std::string("custom_secret")),
                            std::regex(pat),
                            static_cast<std::size_t>(std::max(0, item.value("secret_group", 0))),
                            item.value("confidence", 0.60)
                        };
                        patterns.push_back(std::move(p));
                    }
                }
            } catch (...) {
            }
        }
    }

    std::set<std::string> seen;
    const std::size_t scan_len = std::min<std::size_t>(source.size(), 4194304);
    const std::string scan = source.substr(0, scan_len);
    for (const auto& p : patterns) {
        if (out.size() >= max_results) break;
        if (p.confidence < min_confidence) continue;
        try {
            auto begin = std::sregex_iterator(scan.begin(), scan.end(), p.pattern);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end && out.size() < max_results; ++it) {
                if (call_expired()) return out;
                const std::smatch& m = *it;
                if (m.empty() || p.group >= m.size()) continue;
                std::string value = m[p.group].str();
                if (value.empty() || looks_like_low_value_secret(value)) continue;
                const std::size_t offset = static_cast<std::size_t>(m.position(p.group));
                const std::string key = p.type + "\n" + sha256_hex(value) + "\n" + source_label;
                if (!seen.insert(key).second) continue;
                out.push_back(finding_to_json(scan, redact_url_for_output(source_label), p, value, offset, value.size()));
            }
        } catch (...) {
        }
    }
    return out;
}

nlohmann::json extract_endpoints_from_source(const std::string& source,
                                             const std::string& source_label,
                                             bool include_relative,
                                             std::size_t max_results)
{
    json out = json::array();
    std::set<std::string> seen;
    const std::size_t scan_len = std::min<std::size_t>(source.size(), 4194304);
    const std::string scan = source.substr(0, scan_len);
    const std::string source_kind = endpoint_source_kind(source_label);

    try {
        std::regex fetch_re(R"re(\bfetch\s*\(\s*["'`]([^"'`]{1,2048})["'`])re");
        for (auto it = std::sregex_iterator(scan.begin(), scan.end(), fetch_re), end = std::sregex_iterator(); it != end && out.size() < max_results; ++it) {
            const std::smatch& m = *it;
            const std::string endpoint = m[1].str();
            if (!is_probable_endpoint(endpoint, include_relative)) continue;
            push_endpoint(out, seen, infer_fetch_method(scan, static_cast<std::size_t>(m.position(0))), endpoint, source_kind, 0.88, source_label, scan, static_cast<std::size_t>(m.position(1)));
        }
    } catch (...) {
    }

    try {
        std::regex axios_re(R"re(\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`]{1,2048})["'`])re", std::regex_constants::icase);
        for (auto it = std::sregex_iterator(scan.begin(), scan.end(), axios_re), end = std::sregex_iterator(); it != end && out.size() < max_results; ++it) {
            const std::smatch& m = *it;
            const std::string endpoint = m[2].str();
            if (!is_probable_endpoint(endpoint, include_relative)) continue;
            push_endpoint(out, seen, m[1].str(), endpoint, source_kind, 0.90, source_label, scan, static_cast<std::size_t>(m.position(2)));
        }
    } catch (...) {
    }

    try {
        std::regex method_re(R"re(\.(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`]{1,2048})["'`])re", std::regex_constants::icase);
        for (auto it = std::sregex_iterator(scan.begin(), scan.end(), method_re), end = std::sregex_iterator(); it != end && out.size() < max_results; ++it) {
            const std::smatch& m = *it;
            const std::string endpoint = m[2].str();
            if (!is_probable_endpoint(endpoint, include_relative)) continue;
            push_endpoint(out, seen, m[1].str(), endpoint, source_kind, 0.78, source_label, scan, static_cast<std::size_t>(m.position(2)));
        }
    } catch (...) {
    }

    try {
        std::regex string_re(R"re(["'`]((?:https?:)?//[^"'`\s<>{}|\\^]{4,2048}|/(?:api|v[0-9]+|graphql|rest|rpc|auth|oauth|users?|admin)[^"'`\s<>{}|\\^]{0,2048}|(?:api|v[0-9]+|graphql|rest|rpc|auth|oauth)/[^"'`\s<>{}|\\^]{1,2048})["'`])re", std::regex_constants::icase);
        for (auto it = std::sregex_iterator(scan.begin(), scan.end(), string_re), end = std::sregex_iterator(); it != end && out.size() < max_results; ++it) {
            if (call_expired()) return out;
            const std::smatch& m = *it;
            const std::string endpoint = m[1].str();
            if (!is_probable_endpoint(endpoint, include_relative)) continue;
            push_endpoint(out, seen, "UNKNOWN", endpoint, source_kind, 0.62, source_label, scan, static_cast<std::size_t>(m.position(1)));
        }
    } catch (...) {
    }

    return out;
}

void register_js_analysis_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    srv.register_tool({
        "aida.js.extract_secrets",
        "Extract likely JavaScript secrets and return redacted evidence with provider, type, hash, length, source, confidence, and masked context.",
        {p{"url", "string", "JavaScript URL to fetch.", false},
         p{"source", "string", "Inline JavaScript source to analyze.", false},
         p{"source_name", "string", "Label for inline source.", false},
         p{"headers", "object", "Optional request headers for URL fetch.", false},
         p{"patterns", "array", "Optional bounded custom regex patterns; values are redacted.", false},
         p{"min_confidence", "number", "Minimum confidence from 0.0 to 1.0.", false},
         p{"max_results", "number", "Maximum findings to return.", false},
         p{"timeout_ms", "number", "URL fetch timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound fetch.", false}},
        false,
        tool_extract_secrets
    });

    srv.register_tool({
        "aida.js.extract_endpoints",
        "Extract absolute, protocol-relative, and relative API endpoints from JavaScript source.",
        {p{"url", "string", "JavaScript URL to fetch.", false},
         p{"source", "string", "Inline JavaScript source to analyze.", false},
         p{"source_name", "string", "Label for inline source.", false},
         p{"headers", "object", "Optional request headers for URL fetch.", false},
         p{"include_relative", "boolean", "Include relative API paths.", false},
         p{"max_results", "number", "Maximum endpoints to return.", false},
         p{"timeout_ms", "number", "URL fetch timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound fetch.", false}},
        false,
        tool_extract_endpoints
    });

    srv.register_tool({
        "aida.js.analyze_source_map",
        "Analyze inline, supplied, or fetched JavaScript source maps for original sources, hidden endpoints, and redacted secrets.",
        {p{"url", "string", "JavaScript URL containing a sourceMappingURL marker.", false},
         p{"source", "string", "Inline JavaScript source containing a sourceMappingURL marker.", false},
         p{"source_map", "string", "Inline source map JSON.", false},
         p{"source_map_url", "string", "External source map URL.", false},
         p{"headers", "object", "Optional request headers for URL fetches.", false},
         p{"fetch_external", "boolean", "Allow fetching external source map URLs.", false},
         p{"timeout_ms", "number", "URL fetch timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound fetch.", false}},
        false,
        tool_analyze_source_map
    });

    srv.register_tool({
        "aida.js.deobfuscate",
        "Apply built-in JavaScript deobfuscation transforms and return redacted transformed source plus evidence for unsupported dynamic transforms.",
        {p{"source", "string", "JavaScript source to deobfuscate.", true},
         p{"deobfuscator", "string", "auto|built_in|unicode|beautify; external deobfuscators are reported as unsupported.", false},
         p{"max_output_bytes", "number", "Maximum transformed source bytes to return.", false}},
        true,
        tool_deobfuscate
    });
}

}
}
}
