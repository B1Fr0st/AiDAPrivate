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

std::vector<probe_t> ssrf_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_ssrf", "ssrf_probes entry ip=%s:%s orig=%s",
                         ip.kind.c_str(), ip.name.c_str(), ip.original_value.c_str());
    std::vector<probe_t> out;
    out.push_back({"http://169.254.169.254/latest/meta-data/", "instance-id", "aws-imds"});
    out.push_back({"http://metadata.google.internal/computeMetadata/v1/instance/id", "computeMetadata", "gcp-imds"});
    out.push_back({"http://127.0.0.1/", "localhost", "localhost-http"});
    out.push_back({"http://localhost:80/", "localhost", "localhost-named"});
    out.push_back({"file:///etc/hostname", std::string(), "file-uri-unix"});
    out.push_back({"file:///c:/windows/win.ini", "[fonts]", "file-uri-win"});
    out.push_back({"gopher://127.0.0.1:25/", std::string(), "gopher-smtp"});
    (void)ip;
    diag::log_tagged_fmt("mod_ssrf", "ssrf_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> ssrf_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_ssrf", "ssrf_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (!probe.marker.empty()) {
        if (body_contains_ci(resp, probe.marker)) {
            diag::log_tagged_fmt("mod_ssrf", "ssrf_detect FINDING metadata-or-local ip=%s:%s variant=%s marker=%s",
                                 ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
            auto iss = make_issue("ssrf.metadata-or-local", "Server-Side Request Forgery (likely)",
                                  severity_t::critical, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("Marker '") + probe.marker + "' returned by SSRF target");
            iss.description = std::string("The parameter '") + ip.name +
                "' caused the server to issue an outbound request to an attacker-controlled URL ('" + probe.payload + "') and reflect the response.";
            iss.remediation = "Validate and allow-list outbound destinations; never fetch arbitrary URLs from request input. Block cloud metadata IPs at egress.";
            iss.cwe.push_back("CWE-918");
            return iss;
        }
        diag::log_tagged_fmt("mod_ssrf", "ssrf_detect marker not in body ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }

    if (probe.variant == "file-uri-unix" && body_contains(resp, "127.0.0.1")) {
        diag::log_tagged_fmt("mod_ssrf", "ssrf_detect FINDING file-scheme ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        auto iss = make_issue("ssrf.file-scheme", "SSRF via file:// scheme",
                              severity_t::high, confidence_t::tentative, ip, probe, resp, ctx,
                              "file:// payload changed response");
        iss.description = "The parameter accepted a file:// URI; depending on backend behavior, this may permit local file disclosure.";
        iss.remediation = "Strip non-http/https schemes from URL parameters at the application layer.";
        iss.cwe.push_back("CWE-918");
        return iss;
    }
    diag::log_tagged_fmt("mod_ssrf", "ssrf_detect no finding ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
    return std::nullopt;
}

bool register_self()
{
    module_t m;
    m.id = "ssrf";
    m.name = "Server-Side Request Forgery";
    m.category = "Injection";
    m.max_probes_per_point = 7;
    m.probes = ssrf_probes;
    m.detect = ssrf_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
