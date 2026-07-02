#include "../scanner_module.hpp"
#include "../collaborator.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string collaborator_host_for_token(const std::string& token)
{
    auto cfg = collaborator::current_config();
    if (cfg.public_host.empty()) return token + ".invalid";
    return token + "." + cfg.public_host;
}

std::vector<probe_t> blind_ssrf_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_blind_ssrf", "probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    if (ip.kind != "query" && ip.kind != "body" && ip.kind != "json") return out;
    const std::string token = collaborator::generate_token();
    if (token.empty()) return out;
    const std::string host = collaborator_host_for_token(token);
    out.push_back({ "http://" + host + "/aida-ssrf", token, "http-url" });
    out.push_back({ "https://" + host + "/aida-ssrf", token, "https-url" });
    out.push_back({ "http://127.0.0.1:80@" + host + "/aida-ssrf", token, "userinfo-bypass" });
    out.push_back({ "http://" + host + "#@169.254.169.254/latest/meta-data/", token, "fragment-confusion" });
    return out;
}

std::optional<issue_t> blind_ssrf_detect(const insertion_point_t& ip, const probe_t& probe,
                                         const exchange_observed_t& resp, const module_context_t& ctx)
{
    const auto interactions = collaborator::poll_by_token(probe.marker);
    diag::log_tagged_fmt("mod_blind_ssrf", "detect variant=%s token_len=%zu interactions=%zu",
        probe.variant.c_str(), probe.marker.size(), interactions.size());
    if (interactions.empty()) return std::nullopt;
    std::string kinds;
    for (const auto& it : interactions) {
        if (!kinds.empty()) kinds += ",";
        kinds += it.kind;
    }
    auto iss = make_issue("blind-ssrf.collaborator-interaction",
                          "Blind SSRF confirmed by collaborator interaction",
                          severity_t::critical, confidence_t::certain, ip, probe, resp, ctx,
                          "Collaborator token received " + std::to_string(interactions.size()) + " interaction(s): " + kinds);
    iss.description = "The application made an outbound request to a scanner-controlled collaborator token after the parameter was set to an external URL.";
    iss.remediation = "Allow-list outbound destinations, block cloud metadata and loopback/private ranges at egress, and proxy server-side fetches through a hardened fetch service.";
    iss.cwe.push_back("CWE-918");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "blind-ssrf";
    m.name = "Blind SSRF";
    m.category = "Out-of-band";
    m.max_probes_per_point = 4;
    m.probes = blind_ssrf_probes;
    m.detect = blind_ssrf_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
