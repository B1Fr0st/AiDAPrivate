#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> redirect_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_redirect", "redirect_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    out.push_back({"http://aida-redir-canary.invalid/",          "aida-redir-canary.invalid", "absolute-http"});
    out.push_back({"https://aida-redir-canary.invalid/",         "aida-redir-canary.invalid", "absolute-https"});
    out.push_back({"//aida-redir-canary.invalid/",               "aida-redir-canary.invalid", "scheme-relative"});
    out.push_back({"/\\aida-redir-canary.invalid/",              "aida-redir-canary.invalid", "backslash-trick"});
    out.push_back({"@aida-redir-canary.invalid/",                "aida-redir-canary.invalid", "userinfo-trick"});
    (void)ip;
    diag::log_tagged_fmt("mod_redirect", "redirect_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

bool redirect_target_has_canary(const exchange_observed_t& resp, const std::string& marker)
{
    if (resp.status_code < 300 || resp.status_code >= 400) return false;
    for (const auto& h : resp.resp_headers) {
        std::string lc = h.first;
        std::transform(lc.begin(), lc.end(), lc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lc != "location") continue;
        std::string v_lc = h.second;
        std::transform(v_lc.begin(), v_lc.end(), v_lc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (v_lc.find(marker) != std::string::npos) return true;
    }
    return false;
}

std::optional<issue_t> redirect_detect(const insertion_point_t& ip, const probe_t& probe,
                                       const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_redirect", "redirect_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (redirect_target_has_canary(resp, probe.marker)) {
        diag::log_tagged_fmt("mod_redirect", "redirect_detect FINDING location-header ip=%s:%s variant=%s",
                             ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        auto iss = make_issue("open-redirect.location", "Open Redirect via Location header",
                              severity_t::medium, confidence_t::firm, ip, probe, resp, ctx,
                              std::string("Location header reflects attacker-supplied host: ") + probe.payload);
        iss.description = "The application accepted a user-supplied URL and emitted it in the Location header without validation, enabling phishing redirects.";
        iss.remediation = "Validate redirect targets against an allow-list of hosts; reject scheme-relative ('//evil') and backslash variants before redirecting.";
        iss.cwe.push_back("CWE-601");
        return iss;
    }
    if (body_contains_ci(resp, probe.marker)) {
        std::string lc;
        size_t cap = std::min(resp.resp_body.size(), static_cast<size_t>(8192));
        lc.reserve(cap);
        for (size_t i = 0; i < cap; ++i) lc.push_back(static_cast<char>(std::tolower(resp.resp_body[i])));
        if (lc.find(std::string("window.location") ) != std::string::npos ||
            lc.find(std::string("location.href")  ) != std::string::npos ||
            lc.find(std::string("meta http-equiv=\"refresh\"")) != std::string::npos) {
            diag::log_tagged_fmt("mod_redirect", "redirect_detect FINDING body-redirect ip=%s:%s variant=%s",
                                 ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
            auto iss = make_issue("open-redirect.body", "Open Redirect via response body",
                                  severity_t::low, confidence_t::tentative, ip, probe, resp, ctx,
                                  std::string("Response body references redirect canary: ") + probe.marker);
            iss.description = "The application reflected the attacker-supplied URL inside a window.location / meta-refresh expression in the response.";
            iss.remediation = "Validate redirect targets against an allow-list; never reflect raw user input into a redirect expression.";
            iss.cwe.push_back("CWE-601");
            return iss;
        }
    }
    diag::log_tagged_fmt("mod_redirect", "redirect_detect no finding ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
    return std::nullopt;
}

bool register_self()
{
    module_t m;
    m.id = "open-redirect";
    m.name = "Open Redirect";
    m.category = "Redirects";
    m.max_probes_per_point = 5;
    m.probes = redirect_probes;
    m.detect = redirect_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
