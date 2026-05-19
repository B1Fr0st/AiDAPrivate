#include "../scanner_module.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> protopol_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") return out;
    std::string canary = random_marker("aidaproto");
    out.push_back({ std::string("__proto__[") + canary + "]=polluted_" + canary,           canary, "query-proto" });
    out.push_back({ std::string("constructor[prototype][") + canary + "]=polluted_" + canary, canary, "query-constructor" });
    out.push_back({ std::string("__proto__.") + canary + "=polluted_" + canary,             canary, "query-dot-proto" });
    out.push_back({ std::string("constructor.prototype.") + canary + "=polluted_" + canary, canary, "query-dot-constructor" });
    out.push_back({ std::string("{\"__proto__\":{\"") + canary + "\":\"polluted_" + canary + "\"}}", canary, "json-proto" });
    out.push_back({ std::string("{\"constructor\":{\"prototype\":{\"") + canary + "\":\"polluted_" + canary + "\"}}}", canary, "json-constructor" });
    return out;
}

std::optional<issue_t> protopol_detect(const insertion_point_t& ip, const probe_t& probe,
                                       const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (probe.marker.empty()) return std::nullopt;
    bool key_in_response = body_contains(resp, probe.marker);
    bool value_in_response = body_contains(resp, std::string("polluted_") + probe.marker);
    if (!key_in_response || !value_in_response)
    {
        if (resp.status_code >= 500 && ctx.baseline_status_code < 500)
        {
            auto iss = make_issue("proto-pol.server-exception",
                                  "Prototype Pollution: payload triggered server exception",
                                  severity_t::medium, confidence_t::tentative, ip, probe, resp, ctx,
                                  std::string("baseline_status=") + std::to_string(ctx.baseline_status_code)
                                  + "; probe_status=" + std::to_string(resp.status_code));
            iss.description = "A prototype-pollution payload produced an HTTP 5xx where baseline was healthy. Confirm with a reflective canary on a different endpoint.";
            iss.remediation = "Use Object.create(null) for incoming containers, or reject keys named __proto__, constructor, prototype in recursive merges.";
            iss.cwe.push_back("CWE-1321");
            return iss;
        }
        return std::nullopt;
    }
    auto iss = make_issue("proto-pol.canary-reflected",
                          "Prototype Pollution: canary reflected in response",
                          severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                          std::string("marker=") + probe.marker + "; variant=" + probe.variant);
    iss.description = std::string("Variant '") + probe.variant + "' injected a payload polluting Object.prototype with key '"
        + probe.marker + "'. The polluted key and value appeared in the response body, indicating the server-side merge writes inherited properties.";
    iss.remediation = "Use Object.create(null) for incoming containers, or reject keys named __proto__, constructor, prototype. Recursive merge libraries must filter these keys.";
    iss.cwe.push_back("CWE-1321");
    iss.cwe.push_back("CWE-915");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "proto-pol";
    m.name = "Prototype Pollution";
    m.category = "Injection";
    m.max_probes_per_point = 6;
    m.probes = protopol_probes;
    m.detect = protopol_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
