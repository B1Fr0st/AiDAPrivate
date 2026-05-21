#include "passive_scanner.hpp"

#include "burp_events.hpp"
#include "issue.hpp"

#include "../../infra/event_bus.hpp"
#include "../../infra/work_queue.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <mutex>
#include <regex>
#include <set>
#include <string>

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
    for (const auto& h : ex.resp_headers) {
        if (lc_string(h.first) != "set-cookie") continue;
        diag::log_tagged_fmt("passive", "check_cookies found Set-Cookie value_len=%zu", h.second.size());
        const std::string& v = h.second;
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
    static const std::regex jwt_re(R"(\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b)", std::regex::ECMAScript);
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
            evidence_t ev; ev.marker = m[0].str();
            iss.evidence.push_back(std::move(ev));
            emit(std::move(iss));
        }
    };
    scan_string("query", ex.query);
    scan_string("body", std::string(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size()));
    for (const auto& h : ex.req_headers) {
        scan_string(std::string("header.") + lc_string(h.first), h.second);
    }
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
                                        work_queue::post([copy]() {
                                            scan_one(copy);
                                        });
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
