#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string lc(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

bool is_state_changing(const std::string& base_request)
{
    auto sp = base_request.find(' ');
    if (sp == std::string::npos) return false;
    std::string method = lc(base_request.substr(0, sp));
    return method == "post" || method == "put" || method == "delete" || method == "patch";
}

bool request_carries_session_cookie(const std::string& base_request)
{
    auto pos = base_request.find("\r\n\r\n");
    if (pos == std::string::npos) pos = base_request.size();
    std::string headers = base_request.substr(0, pos);
    std::string hl = lc(headers);
    if (hl.find("\ncookie:") == std::string::npos && hl.find("\r\ncookie:") == std::string::npos) return false;
    return true;
}

bool request_has_csrf_token(const std::string& base_request)
{
    std::string hl = lc(base_request);
    static const std::string toks[] = {
        "csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
        "requestverificationtoken", "x-csrf-token", "x-xsrf-token", "x-requested-with"
    };
    for (auto& t : toks) if (hl.find(t) != std::string::npos) return true;
    return false;
}

bool response_set_cookies_have_samesite_protective(const exchange_observed_t& baseline)
{
    for (auto& h : baseline.resp_headers)
    {
        if (lc(h.first) != "set-cookie") continue;
        std::string v = lc(h.second);
        if (v.find("samesite=strict") != std::string::npos) return true;
        if (v.find("samesite=lax") != std::string::npos) return true;
    }
    return false;
}

std::vector<uint8_t> strip_referer_and_origin(const std::string& base)
{
    auto eol = base.find("\r\n");
    if (eol == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string out = base.substr(0, eol + 2);
    size_t pos = eol + 2;
    auto header_end = base.find("\r\n\r\n", pos);
    std::string headers_section;
    std::string body_section;
    if (header_end == std::string::npos)
    {
        headers_section = base.substr(pos);
    }
    else
    {
        headers_section = base.substr(pos, header_end - pos);
        body_section = base.substr(header_end);
    }
    size_t i = 0;
    while (i < headers_section.size())
    {
        auto nl = headers_section.find("\r\n", i);
        if (nl == std::string::npos)
        {
            std::string line = headers_section.substr(i);
            if (!line.empty())
            {
                std::string name;
                auto colon = line.find(':');
                if (colon != std::string::npos) name = lc(line.substr(0, colon));
                if (name != "referer" && name != "origin") { out += line; out += "\r\n"; }
            }
            break;
        }
        std::string line = headers_section.substr(i, nl - i);
        std::string name;
        auto colon = line.find(':');
        if (colon != std::string::npos) name = lc(line.substr(0, colon));
        if (name != "referer" && name != "origin")
        {
            out += line;
            out += "\r\n";
        }
        i = nl + 2;
    }
    out += body_section;
    return std::vector<uint8_t>(out.begin(), out.end());
}

void csrf_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_csrf", "csrf_run entry ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
    if (ip.kind != "header") {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip not header kind=%s", ip.kind.c_str());
        return;
    }
    if (lc(ip.name) != "host") {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip not host header name=%s", ip.name.c_str());
        return;
    }
    if (!is_state_changing(ip.base_request)) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip not state-changing method");
        return;
    }
    if (!request_carries_session_cookie(ip.base_request)) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip no session cookie");
        return;
    }
    if (request_has_csrf_token(ip.base_request)) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip has csrf token");
        return;
    }
    if (ctx.baseline_status_code < 200 || ctx.baseline_status_code >= 400) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip bad baseline status=%d", ctx.baseline_status_code);
        return;
    }

    exchange_observed_t baseline_facade;
    baseline_facade.resp_headers = ctx.baseline_response_headers;
    baseline_facade.status_code = ctx.baseline_status_code;
    if (response_set_cookies_have_samesite_protective(baseline_facade)) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run skip samesite protective cookie");
        return;
    }
    diag::log_tagged_fmt("mod_csrf", "csrf_run all checks passed sending csrf replay probe host=%s", ctx.host.c_str());

    std::vector<uint8_t> raw = strip_referer_and_origin(ip.base_request);
    probe_t p;
    p.payload = "<no-referer-no-origin>";
    p.marker = "<csrf-replay>";
    p.variant = "strip-referer-origin";
    auto resp = send(raw, p);
    if (!resp.has_value()) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run no response for replay probe");
        return;
    }
    diag::log_tagged_fmt("mod_csrf", "csrf_run replay response status=%d baseline=%d", resp->status_code, ctx.baseline_status_code);
    if (resp->status_code != ctx.baseline_status_code) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run status mismatch probe=%d baseline=%d", resp->status_code, ctx.baseline_status_code);
        return;
    }
    if (resp->status_code < 200 || resp->status_code >= 400) {
        diag::log_tagged_fmt("mod_csrf", "csrf_run non-2xx replay status=%d", resp->status_code);
        return;
    }

    diag::log_tagged_fmt("mod_csrf", "csrf_run FINDING missing-token host=%s baseline=%d replay=%d",
                         ctx.host.c_str(), ctx.baseline_status_code, resp->status_code);
    auto iss = make_issue("csrf.missing-token",
                          "Cross-Site Request Forgery (CSRF)",
                          severity_t::high, confidence_t::firm, ip, p, *resp, ctx,
                          std::string("State-changing ") + (ip.base_request.substr(0, ip.base_request.find(' '))) +
                          " accepted without CSRF token or referer/origin validation");
    std::ostringstream desc;
    desc << "A state-changing request authenticated via cookies was processed without a CSRF token, "
         << "without a protective SameSite cookie attribute, and after stripping both the Referer and Origin headers. "
         << "Baseline status: " << ctx.baseline_status_code << "; replay status: " << resp->status_code << ".";
    iss.description = desc.str();
    iss.remediation = "Implement synchronizer-token-pattern CSRF tokens validated server-side. Set SameSite=Lax/Strict on session cookies. Validate Origin/Referer for state-changing endpoints.";
    iss.cwe.push_back("CWE-352");
    issue_store::add(std::move(iss));
}

bool register_self()
{
    module_t m;
    m.id = "csrf";
    m.name = "Cross-Site Request Forgery (CSRF)";
    m.category = "Session Handling";
    m.max_probes_per_point = 1;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = csrf_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
