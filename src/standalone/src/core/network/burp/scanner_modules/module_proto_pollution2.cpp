#include "../scanner_module.hpp"
#include "module_http_util.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> client_gadget_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") return out;
    const std::string marker = random_marker("aidaprotogadget");
    out.push_back({ std::string("__proto__[") + marker + "]=polluted_" + marker + "&__proto__[srcdoc]=<script>window." + marker + "=1</script>", marker, "srcdoc-gadget" });
    out.push_back({ std::string("constructor[prototype][") + marker + "]=polluted_" + marker + "&constructor[prototype][innerHTML]=<img src=x onerror=window." + marker + "=1>", marker, "innerhtml-gadget" });
    out.push_back({ std::string("{\"__proto__\":{\"") + marker + "\":\"polluted_" + marker + "\",\"href\":\"javascript:window." + marker + "=1\"}}", marker, "json-href-gadget" });
    out.push_back({ std::string("{\"constructor\":{\"prototype\":{\"") + marker + "\":\"polluted_" + marker + "\",\"isAdmin\":true,\"template\":\"<svg onload=window." + marker + "=1>\"}}}", marker, "json-template-gadget" });
    return out;
}

std::optional<issue_t> client_gadget_detect(const insertion_point_t& ip,
                                            const probe_t& probe,
                                            const exchange_observed_t& resp,
                                            const module_context_t& ctx)
{
    if (!module_http::response_content_type_is_html_or_json(resp)) return std::nullopt;
    const std::string body = module_http::body_text(resp);
    const std::string body_lc = module_http::lower(body);
    const bool marker_seen = body.find(probe.marker) != std::string::npos || body.find("polluted_" + probe.marker) != std::string::npos;
    if (!marker_seen) return std::nullopt;
    const bool sink_seen =
        body_lc.find("innerhtml") != std::string::npos ||
        body_lc.find("srcdoc") != std::string::npos ||
        body_lc.find("javascript:") != std::string::npos ||
        body_lc.find("onerror") != std::string::npos ||
        body_lc.find("onload") != std::string::npos ||
        body_lc.find("template") != std::string::npos ||
        body_lc.find("isadmin") != std::string::npos ||
        body_lc.find("object.assign") != std::string::npos ||
        body_lc.find("merge(") != std::string::npos ||
        body_lc.find("extend(") != std::string::npos;
    if (!sink_seen) return std::nullopt;
    auto iss = make_issue("proto-pol.client-side-gadget",
                          "Prototype Pollution: client-side gadget candidate",
                          severity_t::high,
                          confidence_t::firm,
                          ip,
                          probe,
                          resp,
                          ctx,
                          std::string("marker=") + probe.marker + "; variant=" + probe.variant);
    iss.description = "A prototype-pollution payload was reflected with a marker and client-side gadget sink indicators, making browser-side exploitation plausible when the page merges attacker-controlled objects into trusted objects.";
    iss.remediation = "Filter prototype keys before object merges, freeze sensitive prototypes where practical, and remove DOM sinks that consume inherited properties for href, srcdoc, template, or HTML assignment.";
    iss.cwe.push_back("CWE-1321");
    iss.cwe.push_back("CWE-79");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "proto-pol-client-gadget";
    m.name = "Prototype Pollution Client Gadget";
    m.category = "Client-side";
    m.max_probes_per_point = 4;
    m.probes = client_gadget_probes;
    m.detect = client_gadget_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
