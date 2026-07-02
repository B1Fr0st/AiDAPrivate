#include "../scanner_module.hpp"
#include "module_http_util.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

struct takeover_fingerprint_t
{
    const char* service;
    const char* marker;
};

const takeover_fingerprint_t kFingerprints[] = {
    { "AWS S3", "The specified bucket does not exist" },
    { "AWS S3", "NoSuchBucket" },
    { "GitHub Pages", "There isn't a GitHub Pages site here" },
    { "Heroku", "No such app" },
    { "Heroku", "herokucdn.com/error-pages/no-such-app.html" },
    { "Fastly", "Fastly error: unknown domain" },
    { "Pantheon", "The gods are wise" },
    { "Tumblr", "Whatever you were looking for doesn't currently exist" },
    { "Shopify", "Sorry, this shop is currently unavailable" },
    { "Azure", "404 Web Site not found" },
    { "Azure", "This Azure Web App is not available" },
    { "Readme.io", "Project doesnt exist" },
    { "Zendesk", "Help Center Closed" },
    { "Unbounce", "The requested URL was not found on this server" },
    { "Surge", "project not found" },
    { "Netlify", "Not Found - Request ID" },
    { "Vercel", "DEPLOYMENT_NOT_FOUND" }
};

void subdomain_takeover_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t&)
{
    diag::log_tagged_fmt("mod_takeover", "run entry ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
    if (ip.value_offset > 64) return;
    exchange_observed_t synthetic = module_http::synthetic_baseline(ctx);
    const std::string body = module_http::body_text(synthetic);
    if (body.empty()) return;
    for (const auto& fp : kFingerprints) {
        if (!module_http::contains_ci(body, fp.marker)) continue;
        probe_t p;
        p.payload = ctx.host;
        p.marker = fp.marker;
        p.variant = fp.service;
        diag::log_tagged_fmt("mod_takeover", "FINDING service=%s marker=%s host=%s", fp.service, fp.marker, ctx.host.c_str());
        auto iss = make_issue("subdomain-takeover.provider-fingerprint",
                              std::string("Possible subdomain takeover: ") + fp.service,
                              severity_t::high, confidence_t::firm, ip, p, synthetic, ctx,
                              std::string("Provider unclaimed-resource marker observed: ") + fp.marker);
        iss.description = std::string("The current host response contains an unclaimed-resource fingerprint associated with ") + fp.service + ". This commonly indicates a dangling DNS record pointing at a deprovisioned third-party service.";
        iss.remediation = "Remove the dangling DNS record or claim the resource in the third-party provider account before exposing the hostname.";
        iss.cwe.push_back("CWE-350");
        iss.cwe.push_back("CWE-404");
        issue_store::add(std::move(iss));
        return;
    }
}

bool register_self()
{
    module_t m;
    m.id = "subdomain-takeover";
    m.name = "Subdomain Takeover";
    m.category = "Cloud";
    m.max_probes_per_point = 1;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = subdomain_takeover_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
