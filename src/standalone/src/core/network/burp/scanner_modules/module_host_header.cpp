#include "../scanner_module.hpp"
#include "../audit_http.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<uint8_t> rebuild_with_injected_headers(const std::string& base, const std::vector<std::pair<std::string, std::string>>& extras)
{
    auto eol = base.find("\r\n");
    if (eol == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string out = base.substr(0, eol + 2);
    for (const auto& h : extras) {
        out += h.first; out += ": "; out += h.second; out += "\r\n";
    }
    out += base.substr(eol + 2);
    return std::vector<uint8_t>(out.begin(), out.end());
}

void host_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    if (ip.kind != "query" && ip.kind != "header") return;
    if (ip.kind == "header") {
        std::string lc = ip.name;
        std::transform(lc.begin(), lc.end(), lc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lc != "host") return;
    } else {
        return;
    }

    std::string canary = "aida-host-canary.invalid";
    std::vector<std::pair<std::string, std::string>> probes_def = {
        {"Host", canary},
        {"X-Forwarded-Host", canary},
        {"X-Original-URL", "/"},
        {"X-Rewrite-URL", "/"},
        {"X-Forwarded-Server", canary}
    };
    for (const auto& pr : probes_def) {
        std::vector<std::pair<std::string, std::string>> ex;
        if (pr.first == "Host") {
            std::string body = ip.base_request;
            auto host_pos = body.find("\r\nHost:");
            if (host_pos != std::string::npos) {
                size_t vs = host_pos + 7;
                while (vs < body.size() && (body[vs] == ' ' || body[vs] == '\t')) ++vs;
                size_t ve = body.find("\r\n", vs);
                if (ve != std::string::npos) {
                    body = body.substr(0, vs) + canary + body.substr(ve);
                }
            }
            std::vector<uint8_t> raw(body.begin(), body.end());
            probe_t p; p.payload = canary; p.marker = canary; p.variant = "host-override";
            auto resp = send(raw, p);
            if (!resp.has_value()) continue;
            if (body_contains_ci(*resp, canary)) {
                auto iss = make_issue("host-header.injection", "Host header injection reflected",
                                      severity_t::medium, confidence_t::firm, ip, p, *resp, ctx,
                                      std::string("Canary host '") + canary + "' reflected in response body");
                iss.description = "Modifying the Host header caused the application to reflect the attacker-supplied host in the response, enabling cache poisoning and password-reset abuse.";
                iss.remediation = "Validate the Host header against an allow-list of expected virtual hosts before building URLs or links.";
                iss.cwe.push_back("CWE-644");
                iss.cwe.push_back("CWE-20");
                issue_store::add(std::move(iss));
                return;
            }
            continue;
        }
        std::vector<std::pair<std::string, std::string>> extras = { pr };
        std::vector<uint8_t> raw = rebuild_with_injected_headers(ip.base_request, extras);
        probe_t p; p.payload = canary; p.marker = canary; p.variant = std::string("hdr-") + pr.first;
        auto resp = send(raw, p);
        if (!resp.has_value()) continue;
        if (body_contains_ci(*resp, canary)) {
            auto iss = make_issue("host-header.smuggled-via-x-forwarded",
                                  std::string("Reflected '") + pr.first + "' header",
                                  severity_t::medium, confidence_t::firm, ip, p, *resp, ctx,
                                  std::string("Header '") + pr.first + "' reflected in response body");
            iss.description = std::string("The application honored '") + pr.first +
                "' from the request and reflected its value in the response, enabling cache poisoning and routing-based attacks.";
            iss.remediation = "Strip overriding host-like headers at the edge or validate against an allow-list before use.";
            iss.cwe.push_back("CWE-644");
            issue_store::add(std::move(iss));
            return;
        }
        if (resp->status_code >= 300 && resp->status_code < 400) {
            for (const auto& h : resp->resp_headers) {
                std::string lc = h.first;
                std::transform(lc.begin(), lc.end(), lc.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lc != "location") continue;
                std::string vlc = h.second;
                std::transform(vlc.begin(), vlc.end(), vlc.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (vlc.find(canary) != std::string::npos) {
                    auto iss = make_issue("host-header.redirect-injection",
                                          std::string("Header '") + pr.first + "' poisoned redirect",
                                          severity_t::high, confidence_t::firm, ip, p, *resp, ctx,
                                          std::string("Header '") + pr.first + "' steered the Location header to attacker host");
                    iss.description = std::string("The application honored '") + pr.first +
                        "' from the request when building the Location redirect target.";
                    iss.remediation = "Build redirect targets from a server-side configured canonical hostname, not from request headers.";
                    iss.cwe.push_back("CWE-644");
                    iss.cwe.push_back("CWE-601");
                    issue_store::add(std::move(iss));
                    return;
                }
            }
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "host-header";
    m.name = "Host Header Injection";
    m.category = "Injection";
    m.max_probes_per_point = 5;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = host_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
