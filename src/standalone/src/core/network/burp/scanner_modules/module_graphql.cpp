#include "../scanner_module.hpp"
#include "module_http_util.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<uint8_t> build_graphql_request(const insertion_point_t& ip, const module_context_t& ctx, const std::string& body, const std::string& variant)
{
    auto req = module_http::parse(ip.base_request);
    if (!req.valid) return std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
    std::string target = module_http::request_target(ip.base_request);
    if (variant == "get-typename") {
        module_http::set_method_target(req, "GET", module_http::with_query_param(target, "query", "%7B__typename%7D"));
        req.body.clear();
        module_http::remove_header(req, "Content-Length");
        return module_http::render_bytes(req);
    }
    module_http::set_method_target(req, "POST", target.empty() ? std::string("/") : target);
    module_http::set_header(req, "Host", ctx.host);
    module_http::set_header(req, "Content-Type", "application/json");
    module_http::set_header(req, "Accept", "application/json");
    req.body = body;
    module_http::set_header(req, "Content-Length", std::to_string(req.body.size()));
    return module_http::render_bytes(req);
}

bool looks_graphql(const exchange_observed_t& resp)
{
    const std::string body = module_http::lower(module_http::body_text(resp));
    return body.find("\"data\"") != std::string::npos && body.find("__typename") != std::string::npos ||
           body.find("\"errors\"") != std::string::npos && body.find("graphql") != std::string::npos ||
           body.find("cannot query field") != std::string::npos ||
           body.find("must provide query string") != std::string::npos;
}

bool has_introspection(const exchange_observed_t& resp)
{
    const std::string body = module_http::lower(module_http::body_text(resp));
    return body.find("\"__schema\"") != std::string::npos &&
           (body.find("\"querytype\"") != std::string::npos || body.find("\"types\"") != std::string::npos);
}

void graphql_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_graphql", "graphql_run entry ip=%s:%s url=%s", ip.kind.c_str(), ip.name.c_str(), ctx.url.c_str());
    if (ip.value_offset > 64) return;
    const std::string target = module_http::lower(module_http::request_target(ip.base_request));
    const std::string ctype = module_http::lower(module_http::header_value(module_http::parse(ip.base_request).headers, "Content-Type"));
    if (target.find("graphql") == std::string::npos && ctype.find("graphql") == std::string::npos && ctype.find("json") == std::string::npos) {
        diag::log_tagged_fmt("mod_graphql", "graphql_run skip target=%s content_type=%s", target.c_str(), ctype.c_str());
        return;
    }

    struct probe_def_t { std::string body; std::string variant; };
    const std::string marker = random_marker("aidagql");
    std::vector<probe_def_t> probes = {
        { "{\"query\":\"query " + marker + "{__typename}\"}", "post-typename" },
        { "{\"query\":\"query " + marker + "{__schema{queryType{name} types{name kind}}}\"}", "introspection" },
        { "[{\"query\":\"query " + marker + "A{__typename}\"},{\"query\":\"query " + marker + "B{__typename}\"}]", "batch-array" },
        { std::string(), "get-typename" }
    };

    for (const auto& pd : probes) {
        if (ctx.cancelled && ctx.cancelled()) return;
        probe_t p;
        p.payload = pd.body.empty() ? "{__typename}" : pd.body;
        p.marker = marker;
        p.variant = pd.variant;
        auto resp = send(build_graphql_request(ip, ctx, pd.body, pd.variant), p);
        if (!resp.has_value()) continue;
        diag::log_tagged_fmt("mod_graphql", "graphql_run variant=%s status=%d body=%zu", pd.variant.c_str(), resp->status_code, resp->resp_body.size());
        if (pd.variant == "introspection" && has_introspection(*resp)) {
            auto iss = make_issue("graphql.introspection-enabled", "GraphQL introspection enabled",
                                  severity_t::medium, confidence_t::firm, ip, p, *resp, ctx,
                                  "Introspection query returned __schema metadata");
            iss.description = "The GraphQL endpoint returned schema metadata for an unauthenticated scanner introspection query.";
            iss.remediation = "Disable introspection in production or require authorization before returning schema metadata.";
            iss.cwe.push_back("CWE-200");
            issue_store::add(std::move(iss));
            return;
        }
        if (pd.variant == "batch-array" && module_http::body_contains_ci_bytes(resp->resp_body, "__typename") &&
            module_http::body_text(*resp).find('[') != std::string::npos) {
            auto iss = make_issue("graphql.batch-enabled", "GraphQL batching enabled",
                                  severity_t::low, confidence_t::firm, ip, p, *resp, ctx,
                                  "Array batch query returned GraphQL data");
            iss.description = "The GraphQL endpoint accepted multiple operations in one JSON array, which can amplify brute-force, authorization, and rate-limit bypass testing.";
            iss.remediation = "Disable JSON array batching unless it is explicitly required and individually rate-limited.";
            iss.cwe.push_back("CWE-770");
            issue_store::add(std::move(iss));
            return;
        }
        if (looks_graphql(*resp)) {
            auto iss = make_issue("graphql.endpoint-detected", "GraphQL endpoint detected",
                                  severity_t::info, confidence_t::firm, ip, p, *resp, ctx,
                                  "GraphQL query semantics observed in response");
            iss.description = "The endpoint responds to GraphQL query probes. Review authorization, complexity limits, introspection, batching, and resolver error disclosure.";
            iss.remediation = "Enforce query depth and complexity limits, rate-limit operations, and verify authorization inside every resolver.";
            iss.cwe.push_back("CWE-20");
            issue_store::add(std::move(iss));
            return;
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "graphql";
    m.name = "GraphQL Endpoint Checks";
    m.category = "API";
    m.max_probes_per_point = 4;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = graphql_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
