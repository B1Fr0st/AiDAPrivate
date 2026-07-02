#include "../scanner_module.hpp"
#include "module_http_util.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<uint8_t> build_header_probe(const insertion_point_t& ip, const std::string& header, const std::string& value, const std::string& buster)
{
    auto req = module_http::parse(ip.base_request);
    if (!req.valid) return std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
    module_http::set_request_target(req, module_http::with_query_param(module_http::request_target(ip.base_request), "aida_cache_bust", buster));
    module_http::set_header(req, "Cache-Control", "no-cache");
    module_http::set_header(req, "Pragma", "no-cache");
    module_http::add_header(req, header, value);
    return module_http::render_bytes(req);
}

bool response_refs_canary(const exchange_observed_t& resp, const std::string& canary)
{
    if (module_http::body_contains_ci_bytes(resp.resp_body, canary)) return true;
    for (const auto& h : resp.resp_headers) {
        if (module_http::contains_ci(h.second, canary)) return true;
    }
    return false;
}

void cache_poisoning_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_cache_poison", "run entry ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
    if (ip.value_offset > 64 && ip.kind != "header") return;
    const std::string canary = random_marker("aidacache");
    const std::string attacker_host = canary + ".cache-poison.invalid";
    struct probe_def_t { std::string header; std::string value; std::string variant; };
    std::vector<probe_def_t> probes = {
        { "X-Forwarded-Host", attacker_host, "x-forwarded-host" },
        { "X-Host", attacker_host, "x-host" },
        { "X-Forwarded-Scheme", "https://" + attacker_host, "x-forwarded-scheme" },
        { "Forwarded", "host=" + attacker_host + ";proto=https", "forwarded-host" }
    };

    for (const auto& pd : probes) {
        if (ctx.cancelled && ctx.cancelled()) return;
        probe_t p;
        p.payload = pd.header + ": " + pd.value;
        p.marker = canary;
        p.variant = pd.variant;
        auto resp = send(build_header_probe(ip, pd.header, pd.value, canary), p);
        if (!resp.has_value()) continue;
        const auto diff = compare_response_to_baseline(*resp, ctx, {}, {{"cache canary", canary}});
        diag::log_tagged_fmt("mod_cache_poison", "variant=%s status=%d cacheable=%d refs=%d diff=%s",
                             pd.variant.c_str(), resp->status_code, module_http::response_is_cacheable(*resp) ? 1 : 0,
                             response_refs_canary(*resp, canary) ? 1 : 0, diff.evidence.c_str());
        if (response_refs_canary(*resp, canary)) {
            severity_t sev = module_http::response_is_cacheable(*resp) ? severity_t::high : severity_t::medium;
            auto iss = make_issue("cache-poisoning.unkeyed-header-gadget",
                                  "Web cache poisoning header gadget",
                                  sev, confidence_t::firm, ip, p, *resp, ctx,
                                  std::string("Header ") + pd.header + " influenced cacheable response with canary " + canary);
            std::ostringstream desc;
            desc << "A unique request containing " << pd.header << " caused attacker-controlled host material to appear in the response.";
            if (module_http::response_is_cacheable(*resp)) desc << " Cache-related headers indicate the response may be stored by an intermediary.";
            iss.description = desc.str();
            iss.remediation = "Do not build absolute URLs from untrusted forwarding headers. Configure the cache key to include every trusted input that changes the response, and strip untrusted host override headers at the edge.";
            iss.cwe.push_back("CWE-444");
            iss.cwe.push_back("CWE-20");
            issue_store::add(std::move(iss));
            return;
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "cache-poisoning";
    m.name = "Web Cache Poisoning";
    m.category = "Cache";
    m.max_probes_per_point = 4;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = cache_poisoning_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
