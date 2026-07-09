#include "passive_scanner.hpp"

#include "burp_events.hpp"
#include "issue.hpp"

#include "../../infra/event_bus.hpp"
#include "../../infra/executor.hpp"
#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <utility>

namespace aida {
namespace burp {
namespace passive_scanner {

namespace {

struct passive_state_t
{
    std::atomic<bool>                              initialized{false};
    std::atomic<bool>                              enabled{true};
    aida::events::subscription_handle_t            sub;
    std::atomic<uint64_t>                          exchanges{0};
    std::atomic<uint64_t>                          issues{0};
    std::atomic<uint64_t>                          last_scan_ms{0};
    std::mutex                                     err_mtx;
    std::string                                    err_slot;
};

passive_state_t& state()
{
    static passive_state_t s;
    return s;
}

void set_err(const std::string& m)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.err_slot = m;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string lc_string(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string find_header(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name_lc)
{
    for (const auto& h : headers) {
        if (lc_string(h.first) == name_lc) return h.second;
    }
    return std::string();
}

bool has_header(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name_lc)
{
    for (const auto& h : headers) {
        if (lc_string(h.first) == name_lc) return true;
    }
    return false;
}

std::string body_text(const exchange_observed_t& ex, size_t cap = 8192)
{
    size_t n = std::min(ex.resp_body.size(), cap);
    return std::string(reinterpret_cast<const char*>(ex.resp_body.data()), n);
}

issue_t base_issue(const exchange_observed_t& ex)
{
    issue_t iss;
    iss.scheme = ex.scheme;
    iss.host = ex.host;
    iss.port = ex.port;
    iss.path = ex.path;
    iss.src_exchange_id = ex.id;
    iss.seen_ms = now_ms();
    iss.insertion_point = "response";
    return iss;
}

void emit(issue_t iss)
{
    auto& s = state();
    issue_store::add(std::move(iss));
    s.issues.fetch_add(1);
}

std::string trim_ascii(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

bool is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

std::string url_decode_local(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') out.push_back(' ');
        else if (s[i] == '%' && i + 2 < s.size() && is_hex(s[i + 1]) && is_hex(s[i + 2])) {
            out.push_back(static_cast<char>((hex_val(s[i + 1]) << 4) | hex_val(s[i + 2])));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

std::vector<uint8_t> base64_decode_local(std::string s)
{
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4 != 0)
        s.push_back('=');
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = tbl[c];
        if (v == -1) return {};
        if (v == -2) break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

bool printable_text(const std::vector<uint8_t>& data)
{
    if (data.empty())
        return false;
    size_t printable = 0;
    for (uint8_t b : data) {
        if (b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b < 0x7f))
            ++printable;
    }
    return printable * 100 / data.size() >= 85;
}

bool looks_base64_token(const std::string& s)
{
    if (s.size() < 12)
        return false;
    size_t b64 = 0;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '-' || c == '_' || c == '=')
            ++b64;
    }
    return b64 == s.size();
}

void collect_json_keys(const nlohmann::json& j, const std::string& prefix, std::vector<std::string>& keys)
{
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            std::string path = prefix.empty() ? it.key() : prefix + "." + it.key();
            keys.push_back(path);
            collect_json_keys(it.value(), path, keys);
        }
    } else if (j.is_array()) {
        for (size_t i = 0; i < j.size(); ++i)
            collect_json_keys(j[i], prefix + "[" + std::to_string(i) + "]", keys);
    }
}

void collect_kv_keys(const std::string& s, std::vector<std::string>& keys)
{
    size_t p = 0;
    while (p < s.size()) {
        size_t end = s.find_first_of("&;\n\r", p);
        if (end == std::string::npos) end = s.size();
        size_t eq = s.find_first_of("=:", p);
        if (eq != std::string::npos && eq < end) {
            std::string key = trim_ascii(s.substr(p, eq - p));
            if (!key.empty() && key.size() <= 64)
                keys.push_back(key);
        }
        if (end >= s.size()) break;
        p = end + 1;
    }
}

bool sensitive_key_name(const std::string& key)
{
    std::string k = lc_string(key);
    static const char* names[] = {
        "altoroaccounts", "account", "acct", "customer", "user", "username",
        "email", "role", "admin", "balance", "amount", "password", "passwd",
        "pwd", "token", "session", "auth", "jwt", "ssn"
    };
    for (const char* n : names) {
        if (k.find(n) != std::string::npos)
            return true;
    }
    return false;
}

std::string join_limited(const std::vector<std::string>& items, size_t max_items)
{
    std::ostringstream os;
    const size_t n = std::min(items.size(), max_items);
    for (size_t i = 0; i < n; ++i) {
        if (i) os << ",";
        os << items[i];
    }
    if (items.size() > n)
        os << ",...";
    return os.str();
}

struct decoded_payload_t
{
    std::string label;
    std::string text;
};

std::vector<decoded_payload_t> decoded_views(const std::string& value)
{
    std::vector<decoded_payload_t> views;
    views.push_back({ "raw", value });
    std::string cur = value;
    for (int i = 0; i < 3; ++i) {
        std::string dec = url_decode_local(cur);
        if (dec == cur)
            break;
        views.push_back({ std::string("url") + std::to_string(i + 1), dec });
        cur = dec;
    }
    const size_t initial = views.size();
    for (size_t i = 0; i < initial; ++i) {
        if (!looks_base64_token(views[i].text))
            continue;
        auto bytes = base64_decode_local(views[i].text);
        if (!printable_text(bytes))
            continue;
        views.push_back({ views[i].label + ".base64", std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()) });
    }
    return views;
}

struct payload_analysis_t
{
    bool structured = false;
    bool sensitive = false;
    std::vector<std::string> keys;
    std::string source;
};

payload_analysis_t analyze_payload_text(const std::string& text)
{
    payload_analysis_t out;
    try {
        auto j = nlohmann::json::parse(text);
        out.structured = j.is_object() || j.is_array();
        if (out.structured) {
            collect_json_keys(j, "", out.keys);
            out.source = "json";
        }
    } catch (...) {}
    if (out.keys.empty()) {
        collect_kv_keys(text, out.keys);
        if (!out.keys.empty()) {
            out.structured = true;
            out.source = "key_value";
        }
    }
    for (const auto& key : out.keys) {
        if (sensitive_key_name(key)) {
            out.sensitive = true;
            break;
        }
    }
    return out;
}

void emit_plaintext_cookie(const exchange_observed_t& ex, const std::string& direction,
                           const std::string& cookie_name, const payload_analysis_t& analysis,
                           const std::string& decode_label)
{
    auto iss = base_issue(ex);
    iss.type_key = "cookie.plaintext-sensitive";
    iss.name = "Plaintext sensitive cookie payload";
    iss.description = std::string("A ") + direction + " cookie named '" + cookie_name +
        "' contains readable sensitive fields after " + decode_label + " decoding.";
    iss.remediation = "Store only opaque, server-side session identifiers in cookies. Protect structured client cookies with authenticated encryption and integrity checks.";
    iss.cwe.push_back("CWE-312");
    iss.cwe.push_back("CWE-565");
    iss.severity = severity_t::medium;
    iss.confidence = sensitive_key_name(cookie_name) ? confidence_t::certain : confidence_t::firm;
    iss.parameter = cookie_name;
    iss.insertion_point = direction == "request" ? "request.cookie" : "response.set-cookie";
    evidence_t ev;
    ev.marker = "cookie=" + cookie_name + "; decoded_as=" + decode_label + "; keys=" + join_limited(analysis.keys, 8);
    if (direction == "request") ev.request_raw = "Cookie: " + cookie_name + "=<redacted>";
    else ev.response_raw = "Set-Cookie: " + cookie_name + "=<redacted>";
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

std::vector<std::pair<std::string, std::string>> parse_cookie_header_pairs(const std::string& value)
{
    std::vector<std::pair<std::string, std::string>> out;
    size_t p = 0;
    while (p < value.size()) {
        size_t end = value.find(';', p);
        if (end == std::string::npos) end = value.size();
        std::string part = trim_ascii(value.substr(p, end - p));
        size_t eq = part.find('=');
        if (eq != std::string::npos) {
            std::string name = trim_ascii(part.substr(0, eq));
            std::string val = trim_ascii(part.substr(eq + 1));
            if (!name.empty())
                out.emplace_back(std::move(name), std::move(val));
        }
        if (end >= value.size()) break;
        p = end + 1;
    }
    return out;
}

std::pair<std::string, std::string> parse_set_cookie_name_value(const std::string& value)
{
    size_t semi = value.find(';');
    std::string first = trim_ascii(value.substr(0, semi == std::string::npos ? value.size() : semi));
    size_t eq = first.find('=');
    if (eq == std::string::npos)
        return {};
    return { trim_ascii(first.substr(0, eq)), trim_ascii(first.substr(eq + 1)) };
}

void inspect_cookie_payload(const exchange_observed_t& ex, const std::string& direction,
                            const std::string& cookie_name, const std::string& cookie_value)
{
    if (cookie_name.empty() || cookie_value.empty())
        return;
    const bool sensitive_name = sensitive_key_name(cookie_name);
    for (const auto& view : decoded_views(cookie_value)) {
        auto analysis = analyze_payload_text(view.text);
        if ((analysis.structured && analysis.sensitive) || (sensitive_name && analysis.structured)) {
            diag::log_tagged_fmt("passive", "cookie_plaintext_sensitive direction=%s name=%s decoded_as=%s key_count=%zu",
                direction.c_str(), cookie_name.c_str(), view.label.c_str(), analysis.keys.size());
            emit_plaintext_cookie(ex, direction, cookie_name, analysis, view.label);
            return;
        }
    }
    if (lc_string(cookie_name).find("altoroaccounts") != std::string::npos) {
        payload_analysis_t analysis;
        analysis.structured = true;
        analysis.sensitive = true;
        analysis.source = "name";
        analysis.keys.push_back("AltoroAccounts");
        emit_plaintext_cookie(ex, direction, cookie_name, analysis, "name");
    }
}

std::vector<std::string> split_dot(const std::string& s)
{
    std::vector<std::string> out;
    size_t p = 0;
    while (p <= s.size()) {
        size_t q = s.find('.', p);
        if (q == std::string::npos) q = s.size();
        out.push_back(s.substr(p, q - p));
        if (q >= s.size()) break;
        p = q + 1;
    }
    return out;
}

bool decode_base64_json(const std::string& s, nlohmann::json& out)
{
    auto bytes = base64_decode_local(s);
    if (!printable_text(bytes))
        return false;
    try {
        out = nlohmann::json::parse(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        return out.is_object() || out.is_array();
    } catch (...) {
        return false;
    }
}

struct jwt_analysis_t
{
    bool is_jwt = false;
    bool unsigned_jwt = false;
    bool missing_exp = false;
    bool plaintext_claims = false;
    std::string alg;
    std::vector<std::string> claim_keys;
};

jwt_analysis_t analyze_jwt_token(const std::string& token)
{
    jwt_analysis_t out;
    auto parts = split_dot(token);
    if (parts.size() != 2 && parts.size() != 3)
        return out;
    nlohmann::json header;
    nlohmann::json payload;
    if (!decode_base64_json(parts[0], header) || !decode_base64_json(parts[1], payload))
        return out;
    out.is_jwt = true;
    if (header.is_object() && header.contains("alg") && header["alg"].is_string())
        out.alg = header["alg"].get<std::string>();
    out.unsigned_jwt = parts.size() == 2 || (parts.size() == 3 && parts[2].empty()) || lc_string(out.alg) == "none";
    out.missing_exp = payload.is_object() && !payload.contains("exp");
    collect_json_keys(payload, "", out.claim_keys);
    for (const auto& key : out.claim_keys) {
        if (sensitive_key_name(key)) {
            out.plaintext_claims = true;
            break;
        }
    }
    return out;
}

bool static_looking_bearer(const std::string& token)
{
    if (token.empty())
        return false;
    std::string lc = lc_string(token);
    static const char* words[] = { "static", "sample", "example", "debug", "test", "admin", "password", "changeme", "secret" };
    for (const char* w : words) {
        if (lc.find(w) != std::string::npos)
            return true;
    }
    std::set<char> uniq;
    for (char c : token) uniq.insert(c);
    if (token.size() >= 8 && token.size() < 24)
        return true;
    if (token.size() >= 16 && uniq.size() <= 5)
        return true;
    if (token.find('.') == std::string::npos && token.find('-') == std::string::npos && token.find('_') == std::string::npos && token.size() < 32)
        return true;
    return false;
}

void emit_token_issue(const exchange_observed_t& ex, const std::string& type_key,
                      const std::string& name, severity_t sev, confidence_t conf,
                      const std::string& where, const std::string& marker)
{
    auto iss = base_issue(ex);
    iss.type_key = type_key;
    iss.name = name;
    iss.description = marker;
    iss.remediation = "Use short-lived, signed tokens with explicit expiry and transmit them only over HTTPS in Authorization headers or HttpOnly Secure cookies.";
    iss.cwe.push_back("CWE-319");
    iss.severity = sev;
    iss.confidence = conf;
    iss.insertion_point = where;
    evidence_t ev;
    ev.marker = where + "; " + marker;
    if (where.find("response") != std::string::npos) ev.response_raw = where + ": <redacted>";
    else ev.request_raw = where + ": <redacted>";
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void inspect_token_value(const exchange_observed_t& ex, const std::string& where,
                         const std::string& token, bool bearer_context)
{
    if (token.size() < 6)
        return;
    if (ex.scheme != "https") {
        emit_token_issue(ex, "token.http-exposure", "Token transmitted over cleartext HTTP",
                         severity_t::high, confidence_t::firm, where,
                         "token observed on non-HTTPS transport");
    }
    auto jwt = analyze_jwt_token(token);
    if (jwt.is_jwt) {
        if (jwt.unsigned_jwt) {
            emit_token_issue(ex, "jwt.unsigned", "Unsigned JWT accepted or transmitted",
                             severity_t::high, confidence_t::firm, where,
                             "JWT alg=" + (jwt.alg.empty() ? std::string("<missing>") : jwt.alg) + " has no effective signature");
        }
        if (jwt.missing_exp) {
            emit_token_issue(ex, "jwt.missing-exp", "JWT missing expiry claim",
                             severity_t::medium, confidence_t::firm, where,
                             "JWT payload has no exp claim; claims=" + join_limited(jwt.claim_keys, 8));
        }
        if (jwt.plaintext_claims) {
            emit_token_issue(ex, "jwt.plaintext-claims", "JWT exposes readable sensitive claims",
                             severity_t::low, confidence_t::firm, where,
                             "JWT payload contains readable claims: " + join_limited(jwt.claim_keys, 8));
        }
        return;
    }
    for (const auto& view : decoded_views(token)) {
        if (view.label == "raw")
            continue;
        auto analysis = analyze_payload_text(view.text);
        if (analysis.structured && analysis.sensitive) {
            emit_token_issue(ex, bearer_context ? "bearer.base64-claims" : "token.base64-claims",
                             bearer_context ? "Bearer token exposes base64/plaintext claims" : "Token field exposes base64/plaintext claims",
                             severity_t::high, confidence_t::firm, where,
                             "decoded_as=" + view.label + "; keys=" + join_limited(analysis.keys, 8));
            return;
        }
    }
    if (bearer_context && static_looking_bearer(token)) {
        emit_token_issue(ex, "bearer.static-looking", "Static-looking Bearer token",
                         severity_t::medium, confidence_t::tentative, where,
                         "bearer token has low-entropy or environment-style structure");
    }
}

bool token_field_name(const std::string& key)
{
    std::string k = lc_string(key);
    static const char* exact[] = {
        "token", "access_token", "refresh_token", "id_token", "jwt",
        "bearer", "bearer_token", "auth_token", "session_token"
    };
    for (const char* e : exact) {
        if (k == e)
            return true;
    }
    return k.size() > 5 && k.find("token") != std::string::npos;
}

void collect_json_token_values(const nlohmann::json& j, const std::string& path,
                               std::vector<std::pair<std::string, std::string>>& out)
{
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            std::string next = path.empty() ? it.key() : path + "." + it.key();
            if (it.value().is_string() && token_field_name(it.key()))
                out.emplace_back(next, it.value().get<std::string>());
            collect_json_token_values(it.value(), next, out);
        }
    } else if (j.is_array()) {
        for (size_t i = 0; i < j.size(); ++i)
            collect_json_token_values(j[i], path + "[" + std::to_string(i) + "]", out);
    }
}

void inspect_json_token_fields(const exchange_observed_t& ex, const std::string& where,
                               const std::vector<uint8_t>& body)
{
    if (body.empty() || body.size() > 1024 * 1024)
        return;
    try {
        auto j = nlohmann::json::parse(std::string(reinterpret_cast<const char*>(body.data()), body.size()));
        std::vector<std::pair<std::string, std::string>> tokens;
        collect_json_token_values(j, "", tokens);
        diag::log_tagged_fmt("passive", "json_token_fields where=%s count=%zu", where.c_str(), tokens.size());
        for (const auto& tv : tokens)
            inspect_token_value(ex, where + "." + tv.first, tv.second, false);
    } catch (...) {}
}

void check_security_headers(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_security_headers host=%s path=%s status=%d",
        ex.host.c_str(), ex.path.c_str(), ex.status_code);
    if (ex.status_code <= 0) {
        diag::log_tagged_fmt("passive", "check_security_headers skipped status=%d", ex.status_code);
        return;
    }
    auto ct = lc_string(find_header(ex.resp_headers, "content-type"));
    bool is_html = (ct.find("text/html") != std::string::npos);
    diag::log_tagged_fmt("passive", "check_security_headers content_type=%s is_html=%d is_https=%d",
        ct.c_str(), is_html ? 1 : 0, (ex.scheme == "https") ? 1 : 0);

    auto check = [&](const char* name_lc, const char* canonical, const char* desc, severity_t sev,
                     bool only_html) {
        if (only_html && !is_html) return;
        if (!has_header(ex.resp_headers, name_lc)) {
            auto iss = base_issue(ex);
            iss.type_key = std::string("missing-header.") + name_lc;
            iss.name = std::string("Missing security header: ") + canonical;
            iss.description = std::string("The response does not include the ") + canonical + " header. " + desc;
            iss.remediation = std::string("Configure the application or web server to emit the ") + canonical + " header on every response.";
            iss.cwe.push_back("CWE-693");
            iss.severity = sev;
            iss.confidence = confidence_t::firm;
            evidence_t ev;
            ev.response_raw = std::string("HTTP/1.1 ") + std::to_string(ex.status_code) + " " + ex.reason_phrase + "\r\n";
            for (const auto& h : ex.resp_headers) ev.response_raw += h.first + ": " + h.second + "\r\n";
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
    };

    bool is_https = (ex.scheme == "https");
    if (is_https) check("strict-transport-security", "Strict-Transport-Security",
                        "HSTS instructs browsers to only contact this origin over HTTPS for a configured time window.",
                        severity_t::low, false);
    check("content-security-policy", "Content-Security-Policy",
          "CSP restricts script execution, framing, and other resource sources, reducing the impact of XSS.",
          severity_t::medium, true);
    check("x-frame-options", "X-Frame-Options",
          "X-Frame-Options blocks framing of the page by other origins (clickjacking).",
          severity_t::low, true);
    check("x-content-type-options", "X-Content-Type-Options",
          "X-Content-Type-Options: nosniff prevents MIME-sniffing-based attacks.",
          severity_t::low, false);
    check("referrer-policy", "Referrer-Policy",
          "Referrer-Policy controls the Referer header to limit leakage of sensitive URL components.",
          severity_t::info, true);
    check("permissions-policy", "Permissions-Policy",
          "Permissions-Policy restricts powerful browser features (camera, geolocation, etc).",
          severity_t::info, true);
}

void check_server_disclosure(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_server_disclosure host=%s path=%s", ex.host.c_str(), ex.path.c_str());
    auto v = find_header(ex.resp_headers, "server");
    auto p = find_header(ex.resp_headers, "x-powered-by");
    diag::log_tagged_fmt("passive", "check_server_disclosure server='%s' x-powered-by='%s'", v.c_str(), p.c_str());
    if (!v.empty()) {
        auto iss = base_issue(ex);
        iss.type_key = "info-disclosure.server-banner";
        iss.name = "Server banner disclosed";
        iss.description = std::string("The Server response header reveals software identification: '") + v + "'.";
        iss.remediation = "Strip or sanitize the Server header in the reverse-proxy or application configuration.";
        iss.cwe.push_back("CWE-200");
        iss.severity = severity_t::info;
        iss.confidence = confidence_t::certain;
        evidence_t ev; ev.response_raw = "Server: " + v;
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    }
    if (!p.empty()) {
        auto iss = base_issue(ex);
        iss.type_key = "info-disclosure.x-powered-by";
        iss.name = "X-Powered-By disclosed";
        iss.description = std::string("The X-Powered-By header reveals the application stack: '") + p + "'.";
        iss.remediation = "Disable or remove the X-Powered-By header at the application or proxy layer.";
        iss.cwe.push_back("CWE-200");
        iss.severity = severity_t::info;
        iss.confidence = confidence_t::certain;
        evidence_t ev; ev.response_raw = "X-Powered-By: " + p;
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    }
}

void check_cookies(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_cookies host=%s path=%s scheme=%s", ex.host.c_str(), ex.path.c_str(), ex.scheme.c_str());
    for (const auto& h : ex.req_headers) {
        if (lc_string(h.first) != "cookie") continue;
        auto pairs = parse_cookie_header_pairs(h.second);
        diag::log_tagged_fmt("passive", "check_cookies request_cookie pairs=%zu", pairs.size());
        for (const auto& kv : pairs)
            inspect_cookie_payload(ex, "request", kv.first, kv.second);
    }
    for (const auto& h : ex.resp_headers) {
        if (lc_string(h.first) != "set-cookie") continue;
        diag::log_tagged_fmt("passive", "check_cookies found Set-Cookie value_len=%zu", h.second.size());
        const std::string& v = h.second;
        auto set_pair = parse_set_cookie_name_value(v);
        inspect_cookie_payload(ex, "response", set_pair.first, set_pair.second);
        std::string lc = lc_string(v);
        bool secure = lc.find("; secure") != std::string::npos || lc.find(";secure") != std::string::npos;
        bool httponly = lc.find("httponly") != std::string::npos;
        bool samesite = lc.find("samesite") != std::string::npos;
        if (!secure && ex.scheme == "https") {
            auto iss = base_issue(ex);
            iss.type_key = "cookie.missing-secure";
            iss.name = "Cookie set without Secure flag over HTTPS";
            iss.description = "A Set-Cookie was issued over HTTPS without the Secure attribute, allowing the cookie to be sent over cleartext HTTP.";
            iss.remediation = "Add the Secure attribute to all session and authentication cookies.";
            iss.cwe.push_back("CWE-614");
            iss.severity = severity_t::low;
            iss.confidence = confidence_t::firm;
            evidence_t ev; ev.response_raw = "Set-Cookie: " + v;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
        if (!httponly) {
            auto iss = base_issue(ex);
            iss.type_key = "cookie.missing-httponly";
            iss.name = "Cookie set without HttpOnly flag";
            iss.description = "A Set-Cookie was issued without HttpOnly, exposing the cookie to JavaScript and increasing XSS impact.";
            iss.remediation = "Add HttpOnly to all session and authentication cookies.";
            iss.cwe.push_back("CWE-1004");
            iss.severity = severity_t::low;
            iss.confidence = confidence_t::firm;
            evidence_t ev; ev.response_raw = "Set-Cookie: " + v;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
        if (!samesite) {
            auto iss = base_issue(ex);
            iss.type_key = "cookie.missing-samesite";
            iss.name = "Cookie set without SameSite attribute";
            iss.description = "A Set-Cookie was issued without SameSite, enabling cross-site request inclusion (CSRF risk).";
            iss.remediation = "Set SameSite=Lax or SameSite=Strict on all authentication and session cookies.";
            iss.cwe.push_back("CWE-352");
            iss.severity = severity_t::low;
            iss.confidence = confidence_t::firm;
            evidence_t ev; ev.response_raw = "Set-Cookie: " + v;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
    }
}

void check_session_id_in_url(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_session_id_in_url host=%s path=%s query_len=%zu", ex.host.c_str(), ex.path.c_str(), ex.query.size());
    if (ex.query.empty()) {
        diag::log_tagged_fmt("passive", "check_session_id_in_url skipped empty_query");
        return;
    }
    std::string lq = lc_string(ex.query);
    static const char* kNames[] = { "sessionid=", "session_id=", "jsessionid=", "phpsessid=", "asp.net_sessionid=", "token=", "auth=" };
    for (const char* n : kNames) {
        if (lq.find(n) != std::string::npos) {
            auto iss = base_issue(ex);
            iss.type_key = "session.in-url";
            iss.name = "Session identifier in URL query";
            iss.description = std::string("The URL query string contains a session-like parameter (") + n + "). URL contents leak via Referer and proxy logs.";
            iss.remediation = "Move session identifiers to HttpOnly Secure cookies; never accept them via URL parameters.";
            iss.cwe.push_back("CWE-598");
            iss.severity = severity_t::medium;
            iss.confidence = confidence_t::firm;
            evidence_t ev; ev.request_raw = ex.method + " " + ex.path + "?" + ex.query;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
            return;
        }
    }
}

void check_csrf_form_post(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_csrf_form_post host=%s path=%s method=%s", ex.host.c_str(), ex.path.c_str(), ex.method.c_str());
    if (ex.method != "POST") {
        diag::log_tagged_fmt("passive", "check_csrf_form_post skipped method=%s", ex.method.c_str());
        return;
    }
    bool has_token = false;
    std::string body(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size());
    std::string lc = lc_string(body);
    static const char* kNames[] = { "csrf", "_csrf", "csrftoken", "authenticity_token", "xsrf", "anti-csrf", "request_token" };
    for (const char* n : kNames) if (lc.find(n) != std::string::npos) { has_token = true; break; }
    if (has_token) return;
    auto iss = base_issue(ex);
    iss.type_key = "csrf.missing-token";
    iss.name = "POST without anti-CSRF token";
    iss.description = "A state-changing POST request was observed without an apparent anti-CSRF token in the body.";
    iss.remediation = "Use a per-session synchronizer token or SameSite=Lax/Strict cookies, and require token verification on every state-changing request.";
    iss.cwe.push_back("CWE-352");
    iss.severity = severity_t::low;
    iss.confidence = confidence_t::tentative;
    evidence_t ev;
    ev.request_raw = ex.method + " " + ex.path;
    if (!ex.req_body.empty()) ev.request_raw += "\r\n\r\n" + body.substr(0, std::min<size_t>(body.size(), 256));
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void check_mixed_content(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_mixed_content host=%s path=%s scheme=%s", ex.host.c_str(), ex.path.c_str(), ex.scheme.c_str());
    if (ex.scheme != "https") {
        diag::log_tagged_fmt("passive", "check_mixed_content skipped scheme=%s", ex.scheme.c_str());
        return;
    }
    auto ct = lc_string(find_header(ex.resp_headers, "content-type"));
    if (ct.find("text/html") == std::string::npos) return;
    std::string text = body_text(ex, 16384);
    static const std::regex re(R"((src|href)\s*=\s*['\"]http://[^'\"]+)",
                               std::regex::ECMAScript | std::regex::icase);
    auto begin = std::sregex_iterator(text.begin(), text.end(), re);
    auto end = std::sregex_iterator();
    if (begin == end) return;
    auto iss = base_issue(ex);
    iss.type_key = "mixed-content.cleartext";
    iss.name = "Mixed content: cleartext resource referenced from HTTPS page";
    iss.description = "An HTTPS HTML page references one or more HTTP resources (src=/href= http://). Browsers block or downgrade these.";
    iss.remediation = "Migrate every subresource to HTTPS or use protocol-relative URLs.";
    iss.cwe.push_back("CWE-311");
    iss.severity = severity_t::low;
    iss.confidence = confidence_t::firm;
    evidence_t ev; ev.response_raw = begin->str();
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void check_verbose_errors(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_verbose_errors host=%s path=%s body_len=%zu", ex.host.c_str(), ex.path.c_str(), ex.resp_body.size());
    static const std::regex re(
        R"((SQLSTATE\[\w+\]|ORA-\d{5}|PostgreSQL[^\n]{0,80}ERROR|MySQL[^\n]{0,80}error|SQLite3?::SQL|System\.Data\.SqlClient\.|"
        R"(Microsoft OLE DB Provider for SQL|Stack trace:|at\s+[a-zA-Z_][\w.]+\([^)]*\)\s+in\s+|Exception in thread|Traceback \(most recent call last\)))",
        std::regex::ECMAScript);
    std::string text = body_text(ex, 16384);
    if (!std::regex_search(text, re)) return;
    auto iss = base_issue(ex);
    iss.type_key = "info-disclosure.verbose-error";
    iss.name = "Verbose error page disclosed";
    iss.description = "The response body contains backend error text (SQL error or stack trace), revealing implementation details.";
    iss.remediation = "Return a generic error page in production; log full diagnostics server-side only.";
    iss.cwe.push_back("CWE-209");
    iss.severity = severity_t::medium;
    iss.confidence = confidence_t::firm;
    evidence_t ev; ev.response_raw = text.substr(0, std::min<size_t>(text.size(), 1024));
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void check_reflected_input(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_reflected_input host=%s path=%s query_len=%zu body_len=%zu",
        ex.host.c_str(), ex.path.c_str(), ex.query.size(), ex.req_body.size());
    if (ex.query.empty() && ex.req_body.empty()) {
        diag::log_tagged_fmt("passive", "check_reflected_input skipped no_query_no_body");
        return;
    }
    auto extract_params = [](const std::string& s, std::vector<std::pair<std::string, std::string>>& out) {
        size_t p = 0;
        while (p < s.size()) {
            size_t amp = s.find('&', p);
            size_t end = (amp == std::string::npos) ? s.size() : amp;
            size_t eq = s.find('=', p);
            if (eq != std::string::npos && eq < end) {
                std::string k = s.substr(p, eq - p);
                std::string v = s.substr(eq + 1, end - eq - 1);
                if (v.size() >= 4) out.emplace_back(std::move(k), std::move(v));
            }
            if (amp == std::string::npos) break;
            p = amp + 1;
        }
    };
    std::vector<std::pair<std::string, std::string>> params;
    extract_params(ex.query, params);
    if (!ex.req_body.empty()) {
        std::string body(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size());
        extract_params(body, params);
    }
    std::string text = body_text(ex, 16384);
    for (const auto& kv : params) {
        if (kv.second.size() < 4) continue;
        if (kv.second.find_first_not_of("0123456789") == std::string::npos) continue;
        if (text.find(kv.second) != std::string::npos) {
            auto iss = base_issue(ex);
            iss.type_key = "xss.reflected-heuristic";
            iss.name = "Request parameter reflected in response";
            iss.description = std::string("The value of parameter '") + kv.first + "' was reflected verbatim in the response body. This is not proof of XSS but warrants investigation.";
            iss.remediation = "Context-aware output encoding; consider Content-Security-Policy.";
            iss.cwe.push_back("CWE-79");
            iss.severity = severity_t::low;
            iss.confidence = confidence_t::tentative;
            iss.parameter = kv.first;
            iss.insertion_point = "parameter";
            evidence_t ev;
            ev.marker = kv.second;
            ev.request_raw = ex.method + " " + ex.path + "?" + ex.query;
            ev.response_raw = text.substr(0, std::min<size_t>(text.size(), 512));
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
            return;
        }
    }
}

void check_cleartext_password(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_cleartext_password host=%s path=%s scheme=%s method=%s", ex.host.c_str(), ex.path.c_str(), ex.scheme.c_str(), ex.method.c_str());
    if (ex.scheme == "https") {
        diag::log_tagged_fmt("passive", "check_cleartext_password skipped scheme=https");
        return;
    }
    auto has_password_param = [](const std::string& s) {
        std::string lc = lc_string(s);
        return lc.find("password=") != std::string::npos || lc.find("passwd=") != std::string::npos || lc.find("pwd=") != std::string::npos;
    };
    if (has_password_param(ex.query) ||
        has_password_param(std::string(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size()))) {
        auto iss = base_issue(ex);
        iss.type_key = "auth.cleartext-password";
        iss.name = "Password submitted over cleartext HTTP";
        iss.description = "A request containing a password-like parameter was sent over plaintext HTTP, exposing credentials on the wire.";
        iss.remediation = "Force HTTPS via HSTS and redirect plaintext requests; never accept credentials over HTTP.";
        iss.cwe.push_back("CWE-319");
        iss.severity = severity_t::high;
        iss.confidence = confidence_t::firm;
        evidence_t ev; ev.request_raw = ex.method + " " + ex.path + "?" + ex.query;
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    }
}

void check_cloud_bucket_pointer(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_cloud_bucket_pointer host=%s path=%s body_len=%zu", ex.host.c_str(), ex.path.c_str(), ex.resp_body.size());
    std::string text = body_text(ex, 16384);
    static const std::regex re(
        R"((https?://[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com|https?://storage\.googleapis\.com/[a-z0-9._-]+|https?://[a-z0-9.-]+\.blob\.core\.windows\.net))",
        std::regex::ECMAScript | std::regex::icase);
    std::smatch m;
    if (!std::regex_search(text, m, re)) return;
    auto iss = base_issue(ex);
    iss.type_key = "info-disclosure.cloud-bucket-ref";
    iss.name = "Cloud storage URL referenced in response";
    iss.description = std::string("The response references a cloud-storage URL: '") + m[0].str() + "'. Verify ACLs (public-read often unintended).";
    iss.remediation = "Audit bucket ACLs and use signed URLs where appropriate.";
    iss.cwe.push_back("CWE-200");
    iss.severity = severity_t::info;
    iss.confidence = confidence_t::firm;
    evidence_t ev; ev.response_raw = m[0].str();
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void check_pii_leak(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_pii_leak host=%s path=%s body_len=%zu", ex.host.c_str(), ex.path.c_str(), ex.resp_body.size());
    std::string text = body_text(ex, 16384);
    static const std::regex email_re(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", std::regex::ECMAScript);
    static const std::regex ipv4_internal_re(R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b)", std::regex::ECMAScript);
    std::smatch m;
    if (std::regex_search(text, m, ipv4_internal_re)) {
        auto iss = base_issue(ex);
        iss.type_key = "info-disclosure.internal-ip";
        iss.name = "Internal RFC1918 address leaked in response";
        iss.description = std::string("The response contains a private IPv4 address (") + m[0].str() + "), suggesting an internal hostname or routing table leak.";
        iss.remediation = "Sanitize error responses and outbound headers; avoid embedding internal addresses in client-facing payloads.";
        iss.cwe.push_back("CWE-200");
        iss.severity = severity_t::low;
        iss.confidence = confidence_t::firm;
        evidence_t ev; ev.response_raw = m[0].str();
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    }
    if (std::regex_search(text, m, email_re)) {
        std::string addr = m[0].str();
        if (addr.find("@example.com") == std::string::npos &&
            addr.find("@example.org") == std::string::npos) {
            auto iss = base_issue(ex);
            iss.type_key = "info-disclosure.email";
            iss.name = "Email address exposed in response body";
            iss.description = std::string("The response body contains an email address: '") + addr + "'. Confirm whether this is intentional.";
            iss.remediation = "Avoid exposing personal contact addresses; consider replacing with a contact form.";
            iss.cwe.push_back("CWE-359");
            iss.severity = severity_t::info;
            iss.confidence = confidence_t::tentative;
            evidence_t ev; ev.response_raw = addr;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
    }
}

void check_jwt(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_jwt host=%s path=%s query_len=%zu body_len=%zu req_header_count=%zu",
        ex.host.c_str(), ex.path.c_str(), ex.query.size(), ex.req_body.size(), ex.req_headers.size());
    static const std::regex jwt_re(R"(\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?)", std::regex::ECMAScript);
    static const std::regex bearer_re(R"(\bBearer\s+([A-Za-z0-9._~+/\-=]{6,4096})\b)", std::regex::ECMAScript | std::regex::icase);
    auto scan_string = [&](const std::string& where, const std::string& s) {
        std::smatch m;
        if (std::regex_search(s, m, jwt_re)) {
            auto iss = base_issue(ex);
            iss.type_key = std::string("info-disclosure.jwt-in-") + where;
            iss.name = std::string("JSON Web Token observed in ") + where;
            iss.description = std::string("A JWT was observed in the ") + where + ". Verify it is not transmitted via URL, body, or non-secured channels.";
            iss.remediation = "Transmit JWTs via Authorization: Bearer headers over HTTPS only. Never embed them in URLs.";
            iss.cwe.push_back("CWE-319");
            iss.severity = (where == "query" || where == "body") ? severity_t::medium : severity_t::info;
            iss.confidence = confidence_t::firm;
            evidence_t ev; ev.marker = "JWT observed in " + where;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
            inspect_token_value(ex, where, m[0].str(), false);
        }
        if (std::regex_search(s, m, bearer_re)) {
            inspect_token_value(ex, where + ".bearer", m[1].str(), true);
        }
    };
    scan_string("query", ex.query);
    scan_string("body", std::string(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size()));
    for (const auto& h : ex.req_headers) {
        std::string where = std::string("header.") + lc_string(h.first);
        scan_string(where, h.second);
    }
    inspect_json_token_fields(ex, "request.json", ex.req_body);
    inspect_json_token_fields(ex, "response.json", ex.resp_body);
}

void check_cors(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_cors host=%s path=%s", ex.host.c_str(), ex.path.c_str());
    auto acao = find_header(ex.resp_headers, "access-control-allow-origin");
    auto acac = lc_string(find_header(ex.resp_headers, "access-control-allow-credentials"));
    if (acao.empty()) return;
    if (acao == "*" && acac == "true") {
        auto iss = base_issue(ex);
        iss.type_key = "cors.wildcard-with-credentials";
        iss.name = "CORS allows wildcard origin with credentials";
        iss.description = "Access-Control-Allow-Origin: * combined with Allow-Credentials: true is a hard misconfiguration; browsers refuse, but a misbehaving client could trust the response.";
        iss.remediation = "Echo the requesting Origin against an allow-list; never combine '*' with credentials.";
        iss.cwe.push_back("CWE-942");
        iss.severity = severity_t::high;
        iss.confidence = confidence_t::certain;
        evidence_t ev; ev.response_raw = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true";
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    } else if (acao == "null") {
        auto iss = base_issue(ex);
        iss.type_key = "cors.null-origin";
        iss.name = "CORS allows null origin";
        iss.description = "Access-Control-Allow-Origin: null can be spoofed by sandboxed/iframe documents.";
        iss.remediation = "Reject null origins; echo only known origins.";
        iss.cwe.push_back("CWE-942");
        iss.severity = severity_t::medium;
        iss.confidence = confidence_t::firm;
        evidence_t ev; ev.response_raw = "Access-Control-Allow-Origin: null";
        iss.evidence.push_back(std::move(ev));
        emit(std::move(iss));
    } else if (!acao.empty() && acao != "*") {
        const std::string& origin_req = find_header(ex.req_headers, "origin");
        if (!origin_req.empty() && origin_req != acao && acac == "true") {
            auto iss = base_issue(ex);
            iss.type_key = "cors.reflected-origin-with-credentials";
            iss.name = "CORS reflects arbitrary Origin with credentials";
            iss.description = std::string("The Allow-Origin in the response (") + acao + ") matches the request Origin (" + origin_req + "), and credentials are allowed. Verify the application validates origin against an allow-list.";
            iss.remediation = "Validate Origin against a strict allow-list before reflecting it.";
            iss.cwe.push_back("CWE-942");
            iss.severity = severity_t::medium;
            iss.confidence = confidence_t::tentative;
            evidence_t ev; ev.response_raw = "Access-Control-Allow-Origin: " + acao + "\r\nAccess-Control-Allow-Credentials: " + acac;
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
    }
}

void check_numeric_id_idor(const exchange_observed_t& ex)
{
    diag::log_tagged_fmt("passive", "check_numeric_id_idor host=%s path=%s", ex.host.c_str(), ex.path.c_str());
    static const std::regex re(R"((/users/|/accounts/|/orders/|/invoice/|/profile/|/document/|/id/)(\d+)\b)",
                               std::regex::ECMAScript | std::regex::icase);
    std::smatch m;
    if (!std::regex_search(ex.path, m, re)) return;
    auto iss = base_issue(ex);
    iss.type_key = "idor.numeric-id-in-path";
    iss.name = "Numeric resource identifier in path";
    iss.description = std::string("The path contains a numeric identifier ('") + m[0].str() + "'). Verify that authorization checks prevent horizontal access.";
    iss.remediation = "Enforce object-level authorization on every read; consider opaque identifiers.";
    iss.cwe.push_back("CWE-639");
    iss.severity = severity_t::info;
    iss.confidence = confidence_t::tentative;
    evidence_t ev; ev.request_raw = ex.method + " " + ex.path;
    iss.evidence.push_back(std::move(ev));
    emit(std::move(iss));
}

void scan_one(const exchange_observed_t& ex)
{
    auto& s = state();
    if (!s.enabled.load()) {
        diag::log_tagged_fmt("passive", "scan_one skipped disabled host=%s path=%s", ex.host.c_str(), ex.path.c_str());
        return;
    }
    uint64_t n = s.exchanges.fetch_add(1) + 1;
    s.last_scan_ms.store(now_ms());
    diag::log_tagged_fmt("passive", "scan_one start host=%s path=%s method=%s status=%d body_len=%zu exchange_count=%llu",
        ex.host.c_str(), ex.path.c_str(), ex.method.c_str(), ex.status_code, ex.resp_body.size(),
        static_cast<unsigned long long>(n));
    check_security_headers(ex);
    check_server_disclosure(ex);
    check_cookies(ex);
    check_session_id_in_url(ex);
    check_csrf_form_post(ex);
    check_mixed_content(ex);
    check_verbose_errors(ex);
    check_reflected_input(ex);
    check_cleartext_password(ex);
    check_cloud_bucket_pointer(ex);
    check_pii_leak(ex);
    check_jwt(ex);
    check_cors(ex);
    check_numeric_id_idor(ex);
    diag::log_tagged_fmt("passive", "scan_one done host=%s path=%s total_issues=%llu",
        ex.host.c_str(), ex.path.c_str(), static_cast<unsigned long long>(s.issues.load()));
}

}

bool initialize()
{
    diag::log_tagged_fmt("passive", "initialize called");
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("passive", "initialize already_initialized");
        return true;
    }
    issue_store::initialize();
    s.sub = aida::events::subscribe(kExchangeObservedEvent,
                                    [](const exchange_observed_t& ex) {
                                        exchange_observed_t copy = ex;
                                        {
                                            ::aida::infra::executor::submission_t sub;
                                            sub.owner_subsystem = "burp.passive_scanner";
                                            sub.label = "passive.scan_exchange";
                                            sub.thread_class = "bounded_task";
                                            sub.domain = aida::infra::executor::domain_t::feature_worker;
                                            sub.priority = 3;
                                            sub.body = [copy]() {
                                            scan_one(copy);
                                        };
                                            (void)::aida::infra::executor::submit(std::move(sub));
                                        }
                                    });
    if (!s.sub.valid()) {
        diag::log_tagged_fmt("passive", "initialize failed subscription_invalid");
        set_err("passive_scanner.initialize: event subscription failed");
        s.initialized.store(false);
        return false;
    }
    diag::log_tagged("burp", "passive_scanner initialized");
    diag::log_tagged_fmt("passive", "initialize success sub_valid=1");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("passive", "shutdown called");
    auto& s = state();
    if (!s.initialized.load()) {
        diag::log_tagged_fmt("passive", "shutdown skipped not_initialized");
        return;
    }
    if (s.sub.valid()) aida::events::unsubscribe(s.sub);
    s.initialized.store(false);
    diag::log_tagged_fmt("passive", "shutdown complete exchanges=%llu issues=%llu",
        static_cast<unsigned long long>(s.exchanges.load()),
        static_cast<unsigned long long>(s.issues.load()));
}

bool is_enabled() {
    bool e = state().enabled.load();
    diag::log_tagged_fmt("passive", "is_enabled=%d", e ? 1 : 0);
    return e;
}
void set_enabled(bool e) {
    diag::log_tagged_fmt("passive", "set_enabled=%d", e ? 1 : 0);
    state().enabled.store(e);
}

stats_t get_stats()
{
    auto& s = state();
    stats_t st;
    st.exchanges_scanned = s.exchanges.load();
    st.issues_found = s.issues.load();
    st.last_scan_ms = s.last_scan_ms.load();
    diag::log_tagged_fmt("passive", "get_stats exchanges=%llu issues=%llu last_scan_ms=%llu",
        static_cast<unsigned long long>(st.exchanges_scanned),
        static_cast<unsigned long long>(st.issues_found),
        static_cast<unsigned long long>(st.last_scan_ms));
    return st;
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.err_slot;
}

}
}
}
