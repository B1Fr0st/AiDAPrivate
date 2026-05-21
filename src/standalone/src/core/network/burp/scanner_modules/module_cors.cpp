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

std::string lc(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string find_header_value(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name)
{
    std::string lname = lc(name);
    for (const auto& h : headers) if (lc(h.first) == lname) return h.second;
    return std::string();
}

std::vector<uint8_t> rebuild_with_origin(const std::string& base, const std::string& origin_value)
{
    auto eol = base.find("\r\n");
    if (eol == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string out = base.substr(0, eol + 2);
    size_t pos = eol + 2;
    auto header_end = base.find("\r\n\r\n", pos);
    std::string headers_section;
    std::string body_section;
    if (header_end == std::string::npos)
    {
        headers_section = base.substr(pos);
    }
    else
    {
        headers_section = base.substr(pos, header_end - pos);
        body_section = base.substr(header_end);
    }
    size_t i = 0;
    while (i < headers_section.size())
    {
        auto nl = headers_section.find("\r\n", i);
        if (nl == std::string::npos)
        {
            std::string line = headers_section.substr(i);
            if (!line.empty())
            {
                std::string name;
                auto colon = line.find(':');
                if (colon != std::string::npos) name = lc(line.substr(0, colon));
                if (name != "origin") { out += line; out += "\r\n"; }
            }
            break;
        }
        std::string line = headers_section.substr(i, nl - i);
        std::string name;
        auto colon = line.find(':');
        if (colon != std::string::npos) name = lc(line.substr(0, colon));
        if (name != "origin")
        {
            out += line;
            out += "\r\n";
        }
        i = nl + 2;
    }
    out += "Origin: ";
    out += origin_value;
    out += "\r\n";
    out += body_section;
    return std::vector<uint8_t>(out.begin(), out.end());
}

void cors_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_cors", "cors_run entry ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
    if (ip.kind != "header") {
        diag::log_tagged_fmt("mod_cors", "cors_run skip not header kind=%s", ip.kind.c_str());
        return;
    }
    if (lc(ip.name) != "host") {
        diag::log_tagged_fmt("mod_cors", "cors_run skip not host header name=%s", ip.name.c_str());
        return;
    }

    std::string tag = random_marker("aidacors");
    diag::log_tagged_fmt("mod_cors", "cors_run testing CORS origins tag=%s host=%s", tag.c_str(), ctx.host.c_str());
    std::string attacker_origin    = std::string("https://attacker-") + tag + ".example";
    std::string null_origin        = "null";
    std::string suffix_origin      = std::string("https://") + ctx.host + ".attacker-" + tag + ".example";
    std::string prefix_origin      = std::string("https://attacker") + ctx.host;
    std::string subdomain_misconf  = std::string("https://") + ctx.host + ".evil-" + tag + ".example";

    struct probe_def_t { std::string origin; std::string variant; };
    std::vector<probe_def_t> probes_def = {
        { attacker_origin, "arbitrary-origin" },
        { null_origin,     "null-origin" },
        { suffix_origin,   "suffix-match-bypass" },
        { prefix_origin,   "prefix-match-bypass" },
        { subdomain_misconf, "subdomain-wildcard-bypass" },
    };

    for (auto& pd : probes_def)
    {
        diag::log_tagged_fmt("mod_cors", "cors_run probing variant=%s origin=%s", pd.variant.c_str(), pd.origin.c_str());
        std::vector<uint8_t> raw = rebuild_with_origin(ip.base_request, pd.origin);
        probe_t p;
        p.payload = pd.origin;
        p.marker = pd.origin;
        p.variant = pd.variant;

        auto resp = send(raw, p);
        if (!resp.has_value()) {
            diag::log_tagged_fmt("mod_cors", "cors_run no response variant=%s", pd.variant.c_str());
            continue;
        }

        std::string acao = find_header_value(resp->resp_headers, "Access-Control-Allow-Origin");
        std::string acac = find_header_value(resp->resp_headers, "Access-Control-Allow-Credentials");
        diag::log_tagged_fmt("mod_cors", "cors_run variant=%s status=%d ACAO=%s ACAC=%s",
                             pd.variant.c_str(), resp->status_code, acao.c_str(), acac.c_str());
        if (acao.empty()) {
            diag::log_tagged_fmt("mod_cors", "cors_run no ACAO header variant=%s", pd.variant.c_str());
            continue;
        }

        bool reflects = (acao == pd.origin) || lc(acao) == lc(pd.origin);
        if (!reflects && acao == "*" && lc(acac) == "true") reflects = true;
        if (!reflects) {
            diag::log_tagged_fmt("mod_cors", "cors_run origin not reflected variant=%s acao=%s", pd.variant.c_str(), acao.c_str());
            continue;
        }

        bool credentials = !acac.empty() && lc(acac) == "true";
        severity_t sev = credentials ? severity_t::high : severity_t::medium;
        confidence_t conf = confidence_t::firm;

        diag::log_tagged_fmt("mod_cors", "cors_run FINDING origin-reflection variant=%s origin=%s credentials=%d",
                             pd.variant.c_str(), pd.origin.c_str(), credentials ? 1 : 0);
        auto iss = make_issue("cors.origin-reflection",
                              std::string("CORS Misconfiguration (") + pd.variant + ")",
                              sev, conf, ip, p, *resp, ctx,
                              std::string("Origin '") + pd.origin + "' was reflected in Access-Control-Allow-Origin: " + acao
                              + (credentials ? "; Access-Control-Allow-Credentials: true" : ""));
        std::ostringstream desc;
        desc << "Variant '" << pd.variant << "': injecting Origin '" << pd.origin
             << "' caused the server to reflect it in Access-Control-Allow-Origin ('" << acao << "').";
        if (credentials) desc << " Access-Control-Allow-Credentials is true, allowing authenticated cross-origin reads.";
        iss.description = desc.str();
        iss.remediation = "Reject untrusted Origin values. Use an exact-match allowlist; never combine reflected Origin with Access-Control-Allow-Credentials: true.";
        iss.cwe.push_back("CWE-942");
        iss.cwe.push_back("CWE-346");
        issue_store::add(std::move(iss));
        return;
    }
    diag::log_tagged_fmt("mod_cors", "cors_run complete no findings ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
}

bool register_self()
{
    module_t m;
    m.id = "cors";
    m.name = "CORS Misconfiguration";
    m.category = "Configuration";
    m.max_probes_per_point = 5;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = cors_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
