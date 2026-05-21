#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> ssti_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_ssti", "ssti_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    out.push_back({"aida{{7*7}}aida",       "aida49aida", "jinja2"});
    out.push_back({"aida<%=7*7%>aida",      "aida49aida", "erb"});
    out.push_back({"aida${7*7}aida",        "aida49aida", "freemarker_jsp_el"});
    out.push_back({"aida#{7*7}aida",        "aida49aida", "ruby_haml"});
    out.push_back({"aida<%=7*'7'%>aida",    "aida7777777aida", "twig_compat"});
    out.push_back({"aida{%24*4}aida",       std::string(), "smarty_curl"});
    out.push_back({"aida[[7*7]]aida",       "aida49aida", "django"});
    diag::log_tagged_fmt("mod_ssti", "ssti_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> ssti_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_ssti", "ssti_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (probe.marker.empty()) {
        diag::log_tagged_fmt("mod_ssti", "ssti_detect skip empty marker ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }
    if (!body_contains(resp, probe.marker)) {
        diag::log_tagged_fmt("mod_ssti", "ssti_detect marker not reflected ip=%s:%s variant=%s expected=%s",
                             ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
        return std::nullopt;
    }
    diag::log_tagged_fmt("mod_ssti", "ssti_detect FINDING template-eval ip=%s:%s variant=%s marker=%s",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
    auto iss = make_issue("ssti.template-evaluation", "Server-Side Template Injection",
                          severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                          std::string("Template-language expression evaluated to ") + probe.marker);
    iss.description = std::string("Injecting a template expression for engine '") + probe.variant +
        "' caused the server to render the evaluated result in the response. SSTI typically leads to RCE.";
    iss.remediation = "Never pass untrusted input to a template engine; if templates must be user-driven, use a sandboxed mode with no expression evaluation.";
    iss.cwe.push_back("CWE-1336");
    iss.cwe.push_back("CWE-94");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "ssti";
    m.name = "Server-Side Template Injection";
    m.category = "Injection";
    m.max_probes_per_point = 7;
    m.probes = ssti_probes;
    m.detect = ssti_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
