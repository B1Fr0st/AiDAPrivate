#include "csp_analyzer.hpp"
#include "burp_events.hpp"
#include "issue.hpp"
#include "../../infra/event_bus.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace aida {
namespace burp {
namespace csp {

namespace {

std::mutex& err_mtx()
{
    static std::mutex m;
    return m;
}

std::string& err_slot()
{
    static std::string e;
    return e;
}

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

std::atomic<bool>& initialized_flag()
{
    static std::atomic<bool> f{false};
    return f;
}

aida::events::subscription_handle_t& subscription_handle()
{
    static aida::events::subscription_handle_t h;
    return h;
}

std::mutex& seen_mtx()
{
    static std::mutex m;
    return m;
}

std::unordered_set<std::string>& seen_keys()
{
    static std::unordered_set<std::string> s;
    return s;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string to_lower(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    for (char c : s) r.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return r;
}

std::string trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split_ws(const std::string& s)
{
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool list_contains_ci(const std::vector<std::string>& v, const std::string& needle)
{
    std::string lc = to_lower(needle);
    for (const auto& s : v) if (to_lower(s) == lc) return true;
    return false;
}

bool any_value_matches_ci(const std::vector<std::string>& v, const std::string& token)
{
    std::string lc = to_lower(token);
    for (const auto& s : v) {
        if (to_lower(s).find(lc) != std::string::npos) return true;
    }
    return false;
}

const csp_directive_t* find_directive(const std::vector<csp_directive_t>& d, const std::string& name)
{
    std::string lc = to_lower(name);
    for (const auto& x : d) if (to_lower(x.name) == lc) return &x;
    return nullptr;
}

void push_finding(csp_result_t& out, const char* id, const char* title, const char* sev,
                  const std::string& desc, const std::string& evidence, int score_delta)
{
    csp_finding_t f;
    f.id = id; f.title = title; f.severity = sev; f.description = desc; f.evidence = evidence;
    out.findings.push_back(std::move(f));
    out.score += score_delta;
}

severity_t severity_from_str(const std::string& s)
{
    if (s == "high")   return severity_t::high;
    if (s == "medium") return severity_t::medium;
    if (s == "low")    return severity_t::low;
    return severity_t::info;
}

void handle_exchange(const exchange_observed_t& e)
{
    if (!initialized_flag().load()) {
        diag::log_tagged_fmt("csp", "handle_exchange skipped not_initialized");
        return;
    }
    diag::log_tagged_fmt("csp", "handle_exchange entry host=%s path=%s exchange_id=%llu",
        e.host.c_str(), e.path.c_str(), static_cast<unsigned long long>(e.id));
    std::string csp_value;
    bool report_only = false;
    for (const auto& h : e.resp_headers) {
        std::string lc = to_lower(h.first);
        if (lc == "content-security-policy") { csp_value = h.second; break; }
    }
    if (csp_value.empty()) {
        for (const auto& h : e.resp_headers) {
            std::string lc = to_lower(h.first);
            if (lc == "content-security-policy-report-only") {
                csp_value = h.second;
                report_only = true;
                break;
            }
        }
    }
    diag::log_tagged_fmt("csp", "handle_exchange csp_found=%d report_only=%d csp_len=%zu",
        static_cast<int>(!csp_value.empty()), static_cast<int>(report_only), csp_value.size());
    auto res = analyze(csp_value, report_only);
    if (res.findings.empty() && res.has_csp) {
        diag::log_tagged_fmt("csp", "handle_exchange no_findings has_csp=true host=%s", e.host.c_str());
        return;
    }
    diag::log_tagged_fmt("csp", "handle_exchange findings=%zu has_csp=%d host=%s",
        res.findings.size(), static_cast<int>(res.has_csp), e.host.c_str());

    std::string key_base = e.host + "|";
    if (!res.has_csp) {
        std::string dedupe_key = "csp.missing|" + e.host;
        {
            std::lock_guard<std::mutex> lk(seen_mtx());
            if (seen_keys().count(dedupe_key)) {
                diag::log_tagged_fmt("csp", "handle_exchange missing_csp already_issued host=%s", e.host.c_str());
                return;
            }
            seen_keys().insert(dedupe_key);
        }
        diag::log_tagged_fmt("csp", "handle_exchange adding_missing_csp_issue host=%s", e.host.c_str());
        issue_t iss;
        iss.type_key = "csp_missing";
        iss.name = "Missing Content-Security-Policy header";
        iss.severity = severity_t::low;
        iss.confidence = confidence_t::certain;
        iss.host = e.host;
        iss.port = e.port;
        iss.scheme = e.scheme;
        iss.path = e.path;
        iss.src_exchange_id = e.id;
        iss.seen_ms = now_ms();
        iss.description = "The response does not specify a Content-Security-Policy header. "
                          "Without CSP, the browser has no script-source restriction policy and may be more susceptible to XSS.";
        iss.remediation = "Configure a strict CSP policy with at minimum: default-src 'self'; object-src 'none'; base-uri 'self'.";
        iss.cwe.push_back("CWE-1021");
        issue_store::add(std::move(iss));
        return;
    }

    for (const auto& f : res.findings) {
        std::string dedupe_key = key_base + f.id;
        {
            std::lock_guard<std::mutex> lk(seen_mtx());
            if (seen_keys().count(dedupe_key)) {
                diag::log_tagged_fmt("csp", "handle_exchange finding_already_issued id=%s host=%s",
                    f.id.c_str(), e.host.c_str());
                continue;
            }
            seen_keys().insert(dedupe_key);
        }
        diag::log_tagged_fmt("csp", "handle_exchange adding_finding id=%s sev=%s host=%s",
            f.id.c_str(), f.severity.c_str(), e.host.c_str());
        issue_t iss;
        iss.type_key = "csp." + f.id;
        iss.name = f.title;
        iss.severity = severity_from_str(f.severity);
        iss.confidence = confidence_t::firm;
        iss.host = e.host;
        iss.port = e.port;
        iss.scheme = e.scheme;
        iss.path = e.path;
        iss.src_exchange_id = e.id;
        iss.seen_ms = now_ms();
        iss.description = f.description + (report_only ? " (report-only mode)" : std::string());
        iss.remediation = "Tighten the Content-Security-Policy: remove 'unsafe-inline'/'unsafe-eval', avoid wildcards, "
                          "and add object-src 'none', base-uri 'self', frame-ancestors 'self'.";
        evidence_t ev;
        ev.marker = f.evidence;
        iss.evidence.push_back(std::move(ev));
        iss.cwe.push_back("CWE-1021");
        issue_store::add(std::move(iss));
    }
    diag::log_tagged_fmt("csp", "handle_exchange done host=%s findings_processed=%zu",
        e.host.c_str(), res.findings.size());
}

}

bool initialize()
{
    diag::log_tagged_fmt("csp", "initialize entry");
    bool expected = false;
    if (!initialized_flag().compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("csp", "initialize already_initialized");
        return true;
    }
    subscription_handle() = aida::events::subscribe(kExchangeObservedEvent, [](const exchange_observed_t& e) {
        handle_exchange(e);
    });
    diag::log_tagged("burp_csp", "initialized");
    diag::log_tagged_fmt("csp", "initialize done subscribed");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("csp", "shutdown entry");
    if (!initialized_flag().exchange(false)) {
        diag::log_tagged_fmt("csp", "shutdown not_initialized skipping");
        return;
    }
    aida::events::unsubscribe(subscription_handle());
    subscription_handle() = aida::events::subscription_handle_t{};
    std::lock_guard<std::mutex> lk(seen_mtx());
    size_t n = seen_keys().size();
    seen_keys().clear();
    diag::log_tagged_fmt("csp", "shutdown done cleared_seen=%zu", n);
}

csp_result_t analyze(const std::string& csp_header_value, bool is_report_only)
{
    diag::log_tagged_fmt("csp", "analyze entry csp_len=%zu report_only=%d",
        csp_header_value.size(), static_cast<int>(is_report_only));
    csp_result_t out;
    out.score = 100;
    out.is_report_only = is_report_only;

    std::string raw = trim(csp_header_value);
    if (raw.empty()) {
        diag::log_tagged_fmt("csp", "analyze no_csp_header returning missing");
        out.has_csp = false;
        push_finding(out, "missing", "No Content-Security-Policy header", "low",
                     "No CSP header was present in the response.", "(no header)", -25);
        out.score = 0;
        return out;
    }
    out.has_csp = true;
    diag::log_tagged_fmt("csp", "analyze csp_present raw_len=%zu", raw.size());

    {
        std::string buf;
        bool last_ws = false;
        for (char c : raw) {
            if (c == '\r' || c == '\n' || c == '\t') c = ' ';
            if (c == ' ') {
                if (!last_ws) buf.push_back(' ');
                last_ws = true;
            } else {
                buf.push_back(c);
                last_ws = false;
            }
        }
        raw = trim(buf);
    }

    std::vector<std::string> parts;
    {
        std::string cur;
        for (char c : raw) {
            if (c == ';') {
                std::string t = trim(cur);
                if (!t.empty()) parts.push_back(t);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        std::string t = trim(cur);
        if (!t.empty()) parts.push_back(t);
    }

    for (const auto& p : parts) {
        auto tokens = split_ws(p);
        if (tokens.empty()) continue;
        csp_directive_t d;
        d.name = to_lower(tokens.front());
        for (size_t i = 1; i < tokens.size(); ++i) d.values.push_back(tokens[i]);
        out.directives.push_back(std::move(d));
    }

    auto script_src      = find_directive(out.directives, "script-src");
    auto default_src     = find_directive(out.directives, "default-src");
    auto object_src      = find_directive(out.directives, "object-src");
    auto base_uri        = find_directive(out.directives, "base-uri");
    auto style_src       = find_directive(out.directives, "style-src");
    auto img_src         = find_directive(out.directives, "img-src");
    auto frame_anc       = find_directive(out.directives, "frame-ancestors");
    auto report_uri      = find_directive(out.directives, "report-uri");

    auto inspect_unsafe = [&out](const char* dir_name, const csp_directive_t* d) {
        if (!d) return;
        if (list_contains_ci(d->values, "'unsafe-inline'")) {
            std::string desc = std::string("Directive ") + dir_name + " allows 'unsafe-inline', which permits inline scripts/styles to execute. This defeats the primary XSS mitigation provided by CSP.";
            push_finding(out, (std::string("unsafe_inline_") + dir_name).c_str(),
                         (std::string("unsafe-inline in ") + dir_name).c_str(),
                         (std::string(dir_name) == "script-src" ? "high" : "medium"),
                         desc, dir_name + std::string(": 'unsafe-inline'"),
                         std::string(dir_name) == "script-src" ? -30 : -15);
        }
        if (list_contains_ci(d->values, "'unsafe-eval'")) {
            std::string desc = std::string("Directive ") + dir_name + " allows 'unsafe-eval', enabling eval()/Function()/setTimeout(string). Bypasses script restrictions.";
            push_finding(out, (std::string("unsafe_eval_") + dir_name).c_str(),
                         (std::string("unsafe-eval in ") + dir_name).c_str(),
                         "high",
                         desc, dir_name + std::string(": 'unsafe-eval'"),
                         -25);
        }
        if (list_contains_ci(d->values, "'unsafe-hashes'")) {
            std::string desc = std::string("Directive ") + dir_name + " allows 'unsafe-hashes', which permits inline event handlers matching the listed hashes.";
            push_finding(out, (std::string("unsafe_hashes_") + dir_name).c_str(),
                         (std::string("unsafe-hashes in ") + dir_name).c_str(),
                         "medium",
                         desc, dir_name + std::string(": 'unsafe-hashes'"),
                         -10);
        }
        if (list_contains_ci(d->values, "*")) {
            std::string sev = (std::string(dir_name) == "script-src" || std::string(dir_name) == "default-src") ? "high" : "medium";
            push_finding(out, (std::string("wildcard_") + dir_name).c_str(),
                         (std::string("Wildcard '*' in ") + dir_name).c_str(),
                         sev.c_str(),
                         std::string("Directive ") + dir_name + " uses the wildcard '*', which allows resources from any origin.",
                         dir_name + std::string(": *"),
                         std::string(dir_name) == "script-src" ? -30 : -10);
        }
        if (list_contains_ci(d->values, "data:") ||
            list_contains_ci(d->values, "data")) {
            if (std::string(dir_name) == "script-src" || std::string(dir_name) == "default-src") {
                push_finding(out, (std::string("data_scheme_") + dir_name).c_str(),
                             (std::string("data: scheme in ") + dir_name).c_str(),
                             "high",
                             std::string(dir_name) + " allows data: URIs as a script source. This permits XSS via attacker-controlled data: URIs.",
                             dir_name + std::string(": data:"),
                             -25);
            }
        }
        if (any_value_matches_ci(d->values, "http://")) {
            if (std::string(dir_name) == "script-src" || std::string(dir_name) == "style-src" || std::string(dir_name) == "img-src" || std::string(dir_name) == "default-src") {
                push_finding(out, (std::string("mixed_http_") + dir_name).c_str(),
                             (std::string("http: scheme in ") + dir_name).c_str(),
                             "medium",
                             std::string(dir_name) + " contains http:// sources, allowing mixed content / passive MITM injection.",
                             dir_name + std::string(": http://..."),
                             -10);
            }
        }
        if (list_contains_ci(d->values, "https:") || list_contains_ci(d->values, "https")) {
            if (std::string(dir_name) == "script-src") {
                push_finding(out, "https_scheme_script_src",
                             "https: scheme used in script-src",
                             "medium",
                             "script-src allows the entire https: scheme, which is equivalent to a TLS-wide wildcard.",
                             "script-src: https:",
                             -10);
            }
        }
    };

    inspect_unsafe("script-src", script_src);
    inspect_unsafe("default-src", default_src);
    inspect_unsafe("style-src", style_src);
    inspect_unsafe("img-src", img_src);

    if (!script_src) {
        push_finding(out, "missing_script_src", "Missing script-src directive", "medium",
                     "No script-src is declared. Without script-src the policy falls back to default-src, which may not be restrictive enough.",
                     "(no script-src)", -15);
    }
    if (!object_src) {
        push_finding(out, "missing_object_src", "Missing object-src directive", "medium",
                     "object-src controls <object>, <embed>, <applet> sources. Without it, plugin-based XSS vectors remain open.",
                     "(no object-src)", -10);
    } else if (!list_contains_ci(object_src->values, "'none'")) {
        push_finding(out, "weak_object_src", "object-src is not 'none'", "low",
                     "Best practice is object-src 'none' to fully disable plugin contexts.",
                     "object-src: " + (object_src->values.empty() ? std::string("(empty)") : object_src->values.front()),
                     -5);
    }
    if (!base_uri) {
        push_finding(out, "missing_base_uri", "Missing base-uri directive", "medium",
                     "base-uri prevents <base> hijacking. Without it, an injected <base href> can change script-source resolution.",
                     "(no base-uri)", -8);
    }
    if (!frame_anc) {
        push_finding(out, "missing_frame_ancestors", "Missing frame-ancestors directive", "low",
                     "frame-ancestors controls who may embed the resource. Without it, clickjacking via <iframe> remains possible (X-Frame-Options is the legacy fallback).",
                     "(no frame-ancestors)", -5);
    } else if (list_contains_ci(frame_anc->values, "*")) {
        push_finding(out, "wildcard_frame_ancestors", "frame-ancestors '*' permits any embedding", "medium",
                     "frame-ancestors uses the wildcard '*', which permits the resource to be framed by any origin. This is a clickjacking risk.",
                     "frame-ancestors: *", -10);
    }
    if (!default_src) {
        push_finding(out, "missing_default_src", "Missing default-src directive", "low",
                     "default-src acts as the fallback for every -src directive. Without it, every directive must be specified individually.",
                     "(no default-src)", -5);
    }
    if (report_uri) {
        push_finding(out, "deprecated_report_uri", "report-uri is deprecated", "info",
                     "report-uri is deprecated in favor of report-to. Prefer the Reporting API.",
                     "report-uri present", -2);
    }

    if (script_src && list_contains_ci(script_src->values, "'self'")) {
        for (const auto& v : script_src->values) {
            std::string lc = to_lower(v);
            if (lc.find("googleapis.com") != std::string::npos || lc.find("cloudflare.com") != std::string::npos ||
                lc.find("jsdelivr.net") != std::string::npos || lc.find("unpkg.com") != std::string::npos) {
                if (list_contains_ci(script_src->values, "'unsafe-inline'")) {
                    push_finding(out, "cdn_plus_unsafe_inline", "Known-bypass CDN allowed alongside 'unsafe-inline'", "high",
                                 "script-src allows a CDN known to host arbitrary scripts together with 'unsafe-inline'. Attackers can frequently craft a JSONP or wildcard endpoint to host XSS payloads.",
                                 "script-src: " + v + " + 'unsafe-inline'", -10);
                }
            }
        }
    }

    if (out.score < 0) out.score = 0;
    if (out.score > 100) out.score = 100;
    diag::log_tagged_fmt("csp", "analyze done score=%d findings=%zu directives=%zu",
        out.score, out.findings.size(), out.directives.size());
    return out;
}

csp_result_t analyze_for_response(const std::vector<std::pair<std::string, std::string>>& response_headers)
{
    diag::log_tagged_fmt("csp", "analyze_for_response entry headers=%zu", response_headers.size());
    std::string value;
    bool report_only = false;
    for (const auto& h : response_headers) {
        std::string lc = to_lower(h.first);
        if (lc == "content-security-policy") { value = h.second; break; }
    }
    if (value.empty()) {
        for (const auto& h : response_headers) {
            std::string lc = to_lower(h.first);
            if (lc == "content-security-policy-report-only") {
                value = h.second;
                report_only = true;
                break;
            }
        }
    }
    diag::log_tagged_fmt("csp", "analyze_for_response csp_found=%d report_only=%d",
        static_cast<int>(!value.empty()), static_cast<int>(report_only));
    return analyze(value, report_only);
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("csp", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
