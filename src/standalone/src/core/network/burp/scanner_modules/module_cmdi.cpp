#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> cmdi_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_cmdi", "cmdi_probes entry ip=%s:%s orig=%s",
                         ip.kind.c_str(), ip.name.c_str(), ip.original_value.c_str());
    std::vector<probe_t> out;
    auto base = ip.original_value;
    out.push_back({base + "; sleep 8 ; ",       "_AIDA_SLEEP", "unix-semicolon"});
    out.push_back({base + "$(sleep 8)",         "_AIDA_SLEEP", "unix-dollar"});
    out.push_back({base + "`sleep 8`",          "_AIDA_SLEEP", "unix-backtick"});
    out.push_back({base + "&& ping -n 9 127.0.0.1 &&", "_AIDA_SLEEP", "win-ping"});
    out.push_back({base + " | sleep 8",         "_AIDA_SLEEP", "unix-pipe"});
    out.push_back({base + "%0Aid",              "uid=", "newline-id"});
    out.push_back({base + ";uname -a",          "Linux", "uname"});
    out.push_back({base + ";echo aida_cmdi_marker_zxq", "aida_cmdi_marker_zxq", "echo-marker"});
    diag::log_tagged_fmt("mod_cmdi", "cmdi_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> cmdi_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_cmdi", "cmdi_detect entry ip=%s:%s variant=%s status=%d latency=%llums",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                         resp.status_code, static_cast<unsigned long long>(resp.latency_ms));
    if (probe.marker == "_AIDA_SLEEP") {
        if (ctx.baseline_latency_ms == 0) {
            diag::log_tagged_fmt("mod_cmdi", "cmdi_detect sleep skip no baseline ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
            return std::nullopt;
        }
        if (resp.latency_ms >= ctx.baseline_latency_ms + 7000) {
            diag::log_tagged_fmt("mod_cmdi", "cmdi_detect FINDING time-based ip=%s:%s variant=%s baseline=%llums response=%llums",
                                 ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                                 static_cast<unsigned long long>(ctx.baseline_latency_ms),
                                 static_cast<unsigned long long>(resp.latency_ms));
            auto iss = make_issue("cmdi.time-based", "Command Injection (time-based)",
                                  severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("Latency increased: baseline=")
                                      + std::to_string(ctx.baseline_latency_ms) + "ms response="
                                      + std::to_string(resp.latency_ms) + "ms");
            iss.description = std::string("Injecting a shell payload ('") + probe.variant +
                "') caused a measurable server delay matching the injected sleep, indicating the input is passed to a shell or process invocation.";
            iss.remediation = "Avoid invoking shells with user input; use parameterized exec APIs (execve-family, ProcessBuilder with argv arrays). Validate input against a strict allow-list.";
            iss.cwe.push_back("CWE-78");
            return iss;
        }
        diag::log_tagged_fmt("mod_cmdi", "cmdi_detect sleep latency insufficient baseline=%llums response=%llums",
                             static_cast<unsigned long long>(ctx.baseline_latency_ms),
                             static_cast<unsigned long long>(resp.latency_ms));
        return std::nullopt;
    }
    if (probe.marker == "Linux" || probe.marker.rfind("uid=", 0) == 0) {
        if (body_contains_ci(resp, probe.marker)) {
            diag::log_tagged_fmt("mod_cmdi", "cmdi_detect FINDING output-leak ip=%s:%s variant=%s marker=%s",
                                 ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
            auto iss = make_issue("cmdi.output-leak", "Command Injection (output leak)",
                                  severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("Command output reflected: ") + probe.marker);
            iss.description = "The parameter was concatenated into a shell invocation and the command output ('uname'/'id') was reflected in the response body.";
            iss.remediation = "Never invoke a shell with untrusted input. Use exec arrays and strict input validation.";
            iss.cwe.push_back("CWE-78");
            return iss;
        }
        diag::log_tagged_fmt("mod_cmdi", "cmdi_detect output-leak marker not in body ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }
    if (!probe.marker.empty() && body_contains(resp, probe.marker)) {
        diag::log_tagged_fmt("mod_cmdi", "cmdi_detect FINDING echo-marker ip=%s:%s variant=%s marker=%s",
                             ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
        auto iss = make_issue("cmdi.echo-marker", "Command Injection (echo marker)",
                              severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                              std::string("Echo marker observed: ") + probe.marker);
        iss.description = "A unique marker produced by a shell echo command appeared in the response, confirming command execution.";
        iss.remediation = "Never invoke a shell with untrusted input. Use exec arrays and strict input validation.";
        iss.cwe.push_back("CWE-78");
        return iss;
    }
    diag::log_tagged_fmt("mod_cmdi", "cmdi_detect no finding ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
    return std::nullopt;
}

bool register_self()
{
    module_t m;
    m.id = "cmdi";
    m.name = "OS Command Injection";
    m.category = "Injection";
    m.max_probes_per_point = 8;
    m.probes = cmdi_probes;
    m.detect = cmdi_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
