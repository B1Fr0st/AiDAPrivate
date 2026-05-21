#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

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
    diag::log_tagged_fmt("mod_proto", "protopol_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") {
        diag::log_tagged_fmt("mod_proto", "protopol_probes skip kind=%s", ip.kind.c_str());
        return out;
    }
    std::string canary = random_marker("aidaproto");
    out.push_back({ std::string("__proto__[") + canary + "]=polluted_" + canary,           canary, "query-proto" });
    out.push_back({ std::string("constructor[prototype][") + canary + "]=polluted_" + canary, canary, "query-constructor" });
    out.push_back({ std::string("__proto__.") + canary + "=polluted_" + canary,             canary, "query-dot-proto" });
    out.push_back({ std::string("constructor.prototype.") + canary + "=polluted_" + canary, canary, "query-dot-constructor" });
    out.push_back({ std::string("{\"__proto__\":{\"") + canary + "\":\"polluted_" + canary + "\"}}", canary, "json-proto" });
    out.push_back({ std::string("{\"constructor\":{\"prototype\":{\"") + canary + "\":\"polluted_" + canary + "\"}}}", canary, "json-constructor" });
    diag::log_tagged_fmt("mod_proto", "protopol_probes built %zu probes canary=%s ip=%s:%s",
                         out.size(), canary.c_str(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> protopol_detect(const insertion_point_t& ip, const probe_t& probe,
                                       const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_proto", "protopol_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (probe.marker.empty()) return std::nullopt;
    bool key_in_response = body_contains(resp, probe.marker);
    bool value_in_response = body_contains(resp, std::string("polluted_") + probe.marker);
    diag::log_tagged_fmt("mod_proto", "protopol_detect key_in_resp=%d value_in_resp=%d variant=%s",
                         key_in_response ? 1 : 0, value_in_response ? 1 : 0, probe.variant.c_str());
    if (!key_in_response || !value_in_response)
    {
        if (resp.status_code >= 500 && ctx.baseline_status_code < 500)
        {
            diag::log_tagged_fmt("mod_proto", "protopol_detect FINDING server-exception ip=%s:%s variant=%s baseline=%d probe=%d",
                                 ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), ctx.baseline_status_code, resp.status_code);
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
        diag::log_tagged_fmt("mod_proto", "protopol_detect no finding ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }
    diag::log_tagged_fmt("mod_proto", "protopol_detect FINDING canary-reflected ip=%s:%s variant=%s marker=%s",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
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
