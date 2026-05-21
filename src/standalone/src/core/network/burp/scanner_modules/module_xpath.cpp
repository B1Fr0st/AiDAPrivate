#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

bool body_contains_xpath_error(const exchange_observed_t& resp)
{
    if (body_contains_ci(resp, "xpathexception")) return true;
    if (body_contains_ci(resp, "javax.xml.xpath")) return true;
    if (body_contains_ci(resp, "system.xml.xpath")) return true;
    if (body_contains_ci(resp, "xpath_eval")) return true;
    if (body_contains_ci(resp, "msxml")) return true;
    if (body_contains_ci(resp, "xmlxpathexception")) return true;
    if (body_contains_ci(resp, "expected token") && body_contains_ci(resp, "xpath")) return true;
    return false;
}

std::vector<probe_t> xpath_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_xpath", "xpath_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    out.push_back({ "' or '1'='1",          "_AIDA_XPATH", "always-true-single" });
    out.push_back({ "\" or \"1\"=\"1",      "_AIDA_XPATH", "always-true-double" });
    out.push_back({ "' and '1'='2",         "_AIDA_XPATH", "always-false" });
    out.push_back({ "'] | //* | //[",       "_AIDA_XPATH", "union-xpath" });
    out.push_back({ "*[1]",                 "_AIDA_XPATH", "wildcard-node" });
    out.push_back({ "'",                    "_AIDA_XPATH", "broken-quote" });
    out.push_back({ "(",                    "_AIDA_XPATH", "broken-paren" });
    out.push_back({ "1] | //user[contains(@*, ''",  "_AIDA_XPATH", "predicate-break" });
    diag::log_tagged_fmt("mod_xpath", "xpath_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> xpath_detect(const insertion_point_t& ip, const probe_t& probe,
                                    const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_xpath", "xpath_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (probe.marker != "_AIDA_XPATH") return std::nullopt;
    bool err = body_contains_xpath_error(resp);
    bool differential = false;
    if (resp.status_code != ctx.baseline_status_code) differential = true;
    else
    {
        size_t mx = std::max(resp.resp_body.size(), ctx.baseline_response_body.size());
        size_t mn = std::min(resp.resp_body.size(), ctx.baseline_response_body.size());
        if (mx > 0 && (mx - mn) * 10 > mx) differential = true;
    }
    diag::log_tagged_fmt("mod_xpath", "xpath_detect err=%d differential=%d variant=%s", err ? 1 : 0, differential ? 1 : 0, probe.variant.c_str());
    if (!err && !differential) {
        diag::log_tagged_fmt("mod_xpath", "xpath_detect no finding ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }
    diag::log_tagged_fmt("mod_xpath", "xpath_detect FINDING injection ip=%s:%s variant=%s err=%d differential=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), err ? 1 : 0, differential ? 1 : 0);
    confidence_t conf = err ? confidence_t::firm : confidence_t::tentative;
    auto iss = make_issue("xpath.injection",
                          std::string("Possible XPath Injection (") + probe.variant + ")",
                          severity_t::high, conf, ip, probe, resp, ctx,
                          std::string("probe=") + probe.payload
                          + "; baseline_status=" + std::to_string(ctx.baseline_status_code)
                          + "; probe_status=" + std::to_string(resp.status_code));
    iss.description = std::string("Replacing the parameter with an XPath-injection payload (variant '") + probe.variant +
        "') produced " + (err ? "an XPath/XML error signature in the response" : "a substantively different response than the baseline") +
        ". This indicates that user input flows into an XPath expression via string concatenation.";
    iss.remediation = "Use precompiled XPath expressions with variable bindings instead of string concatenation. Escape XPath metacharacters in user input.";
    iss.cwe.push_back("CWE-643");
    iss.cwe.push_back("CWE-91");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "xpath-injection";
    m.name = "XPath Injection";
    m.category = "Injection";
    m.max_probes_per_point = 8;
    m.probes = xpath_probes;
    m.detect = xpath_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
