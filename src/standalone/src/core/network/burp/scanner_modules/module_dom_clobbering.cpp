#include "../scanner_module.hpp"
#include "module_http_util.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> dom_clobbering_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_dom_clobber", "probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") return out;
    const std::string marker = random_marker("aidadomclobber");
    out.push_back({ "<form id=\"" + marker + "\" name=\"location\"></form>", marker, "form-location" });
    out.push_back({ "<a id=\"" + marker + "\" name=\"constructor\" href=\"//example.invalid\"></a>", marker, "anchor-constructor" });
    out.push_back({ "<iframe name=\"" + marker + "\" srcdoc=\"clobber\"></iframe>", marker, "iframe-window-name" });
    out.push_back({ "<input id=\"__proto__\" name=\"" + marker + "\" value=\"clobber\">", marker, "proto-id-input" });
    return out;
}

bool reflected_unencoded(const exchange_observed_t& resp, const probe_t& probe)
{
    const std::string body = module_http::body_text(resp);
    return body.find(probe.payload) != std::string::npos ||
           (body.find(probe.marker) != std::string::npos &&
            (body.find("<form") != std::string::npos || body.find("<a ") != std::string::npos ||
             body.find("<iframe") != std::string::npos || body.find("<input") != std::string::npos));
}

std::optional<issue_t> dom_clobbering_detect(const insertion_point_t& ip, const probe_t& probe,
                                             const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_dom_clobber", "detect variant=%s status=%d", probe.variant.c_str(), resp.status_code);
    if (!module_http::response_content_type_is_html_or_json(resp)) return std::nullopt;
    if (!reflected_unencoded(resp, probe)) return std::nullopt;
    const std::string body_lc = module_http::lower(module_http::body_text(resp));
    const bool has_script = body_lc.find("<script") != std::string::npos ||
                            body_lc.find("document.") != std::string::npos ||
                            body_lc.find("window.") != std::string::npos;
    auto iss = make_issue("dom-clobbering.unencoded-html-reflection",
                          "Potential DOM clobbering via unencoded HTML reflection",
                          has_script ? severity_t::medium : severity_t::low,
                          has_script ? confidence_t::firm : confidence_t::tentative,
                          ip, probe, resp, ctx,
                          "DOM clobbering element reflected with marker " + probe.marker);
    iss.description = "A DOM clobbering HTML element was reflected without encoding. If page scripts read clobberable globals or DOM collections, this can alter client-side control flow.";
    iss.remediation = "HTML-encode reflected input and avoid resolving security-sensitive objects through clobberable global names such as window.location, document.forms, or named elements.";
    iss.cwe.push_back("CWE-79");
    iss.cwe.push_back("CWE-94");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "dom-clobbering";
    m.name = "DOM Clobbering";
    m.category = "Client-side";
    m.max_probes_per_point = 4;
    m.probes = dom_clobbering_probes;
    m.detect = dom_clobbering_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
