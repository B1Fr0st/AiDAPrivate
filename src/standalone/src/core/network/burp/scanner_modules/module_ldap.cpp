#include "../scanner_module.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

bool body_contains_ldap_error(const exchange_observed_t& resp)
{
    if (body_contains_ci(resp, "ldap_search")) return true;
    if (body_contains_ci(resp, "javax.naming.directory")) return true;
    if (body_contains_ci(resp, "javax.naming.namingexception")) return true;
    if (body_contains_ci(resp, "ldapexception")) return true;
    if (body_contains_ci(resp, "invalid dn syntax")) return true;
    if (body_contains_ci(resp, "filter parsing")) return true;
    if (body_contains_ci(resp, "ldap_err2string")) return true;
    if (body_contains_ci(resp, "supplied argument is not a valid ldap")) return true;
    return false;
}

std::vector<probe_t> ldap_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    std::string base = ip.original_value;
    out.push_back({ "*",                        "_AIDA_LDAP", "wildcard-filter" });
    out.push_back({ "*)(uid=*))(|(uid=*",       "_AIDA_LDAP", "or-bypass" });
    out.push_back({ base + ")(cn=*",            "_AIDA_LDAP", "appended-cn" });
    out.push_back({ base + "*)(|(cn=*",         "_AIDA_LDAP", "balanced-or" });
    out.push_back({ "*)(!(objectClass=foo)",    "_AIDA_LDAP", "blind-bool-true" });
    out.push_back({ "*)(!(objectClass=*)",      "_AIDA_LDAP", "blind-bool-false" });
    out.push_back({ "(",                        "_AIDA_LDAP", "broken-paren" });
    out.push_back({ "&",                        "_AIDA_LDAP", "broken-amp" });
    return out;
}

std::optional<issue_t> ldap_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (probe.marker != "_AIDA_LDAP") return std::nullopt;
    bool err = body_contains_ldap_error(resp);
    bool differential = false;
    if (resp.status_code != ctx.baseline_status_code) differential = true;
    else
    {
        size_t mx = std::max(resp.resp_body.size(), ctx.baseline_response_body.size());
        size_t mn = std::min(resp.resp_body.size(), ctx.baseline_response_body.size());
        if (mx > 0 && (mx - mn) * 10 > mx) differential = true;
    }
    if (!err && !differential) return std::nullopt;
    confidence_t conf = err ? confidence_t::firm : confidence_t::tentative;
    auto iss = make_issue("ldap.injection",
                          std::string("Possible LDAP Injection (") + probe.variant + ")",
                          severity_t::high, conf, ip, probe, resp, ctx,
                          std::string("probe=") + probe.payload
                          + "; baseline_status=" + std::to_string(ctx.baseline_status_code)
                          + "; probe_status=" + std::to_string(resp.status_code));
    iss.description = std::string("Replacing the parameter with LDAP-filter-injection payload (variant '") + probe.variant +
        "') produced " + (err ? "an LDAP error signature in the response" : "a substantively different response than the baseline") +
        ". This indicates that user input flows into an LDAP search filter.";
    iss.remediation = "Escape LDAP filter metacharacters (* ( ) \\ NUL) per RFC 4515 in all user-supplied filter components. Use parameterized search APIs.";
    iss.cwe.push_back("CWE-90");
    iss.cwe.push_back("CWE-77");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "ldap-injection";
    m.name = "LDAP Injection";
    m.category = "Injection";
    m.max_probes_per_point = 8;
    m.probes = ldap_probes;
    m.detect = ldap_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
