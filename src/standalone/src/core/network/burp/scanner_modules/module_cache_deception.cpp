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

std::string deception_target(const std::string& original, const std::string& suffix)
{
    std::string target = original.empty() ? std::string("/") : original;
    const size_t q = target.find('?');
    std::string path = q == std::string::npos ? target : target.substr(0, q);
    std::string query = q == std::string::npos ? std::string() : target.substr(q);
    if (!path.empty() && path.back() == '/') path.pop_back();
    if (path.empty()) path = "/";
    if (path == "/" && !suffix.empty() && suffix.front() == '/') return suffix + query;
    return path + suffix + query;
}

std::vector<uint8_t> build_deception_probe(const insertion_point_t& ip, const std::string& target, const std::string& buster)
{
    auto req = module_http::parse(ip.base_request);
    if (!req.valid) return std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
    module_http::set_request_target(req, module_http::with_query_param(target, "aida_deception_bust", buster));
    module_http::set_header(req, "Cache-Control", "no-cache");
    module_http::set_header(req, "Pragma", "no-cache");
    return module_http::render_bytes(req);
}

void cache_deception_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_cache_deception", "run entry ip=%s:%s url=%s", ip.kind.c_str(), ip.name.c_str(), ctx.url.c_str());
    if (ip.value_offset > 64) return;
    if (ctx.baseline_status_code < 200 || ctx.baseline_status_code >= 400) return;
    if (!module_http::response_content_type_is_html_or_json(module_http::synthetic_baseline(ctx))) return;

    const std::string buster = random_marker("aidadeception");
    const std::string original = module_http::request_target(ip.base_request);
    struct probe_def_t { std::string suffix; std::string variant; };
    std::vector<probe_def_t> probes = {
        { "/.." + buster + ".css", "path-info-css" },
        { "%2f" + buster + ".js", "encoded-slash-js" },
        { ";" + buster + ".css", "matrix-param-css" },
        { "/" + buster + ".ico", "static-extension-ico" }
    };

    for (const auto& pd : probes) {
        if (ctx.cancelled && ctx.cancelled()) return;
        const std::string target = deception_target(original, pd.suffix);
        probe_t p;
        p.payload = target;
        p.marker = buster;
        p.variant = pd.variant;
        auto resp = send(build_deception_probe(ip, target, buster), p);
        if (!resp.has_value()) continue;
        const auto diff = compare_response_to_baseline(*resp, ctx);
        const bool same_page = resp->status_code == ctx.baseline_status_code && diff.body_length_ratio >= 0.85 && module_http::response_content_type_is_html_or_json(*resp);
        const bool cacheable = module_http::response_is_cacheable(*resp);
        diag::log_tagged_fmt("mod_cache_deception", "variant=%s target=%s status=%d same_page=%d cacheable=%d diff=%s",
                             pd.variant.c_str(), target.c_str(), resp->status_code, same_page ? 1 : 0, cacheable ? 1 : 0, diff.evidence.c_str());
        if (same_page && cacheable) {
            auto iss = make_issue("cache-deception.static-suffix",
                                  "Web cache deception via static-looking path",
                                  severity_t::high, confidence_t::firm, ip, p, *resp, ctx,
                                  "Static-looking URL returned baseline-like dynamic content with cache headers");
            iss.description = "A static-looking path variant returned the same dynamic content as the original request and carried cache-related headers. A shared cache may store private content under the crafted URL.";
            iss.remediation = "Configure caches to key and store only explicit static asset routes. Reject encoded path separators and path-info suffixes on authenticated dynamic routes.";
            iss.cwe.push_back("CWE-524");
            iss.cwe.push_back("CWE-525");
            issue_store::add(std::move(iss));
            return;
        }
    }
}

bool register_self()
{
    module_t m;
    m.id = "cache-deception";
    m.name = "Web Cache Deception";
    m.category = "Cache";
    m.max_probes_per_point = 4;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = cache_deception_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
