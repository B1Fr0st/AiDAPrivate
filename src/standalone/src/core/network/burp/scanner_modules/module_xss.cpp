#include "../scanner_module.hpp"
#include "../insertion_points.hpp"
#include "../camoufox_bridge.hpp"
#include "../dom_xss_engine.hpp"
#include "../scope.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> xss_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_xss", "xss_probes entry ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    std::vector<probe_t> out;
    std::string marker = random_marker("aidaxss");
    std::string m1 = std::string("<svg/onload=alert('") + marker + "')>";
    std::string m2 = std::string("\"><script>/*") + marker + "*/</script>";
    std::string m3 = std::string("javascript:alert('") + marker + "')";
    std::string m4 = std::string("' onmouseover='alert(\"") + marker + "\")";
    std::string m5 = std::string("</textarea><img src=x onerror=alert('") + marker + "')>";
    std::string m6 = std::string("--></style><script>") + marker + "</script>";
    out.push_back({m1, marker, "svg-onload"});
    out.push_back({m2, marker, "script-tag"});
    out.push_back({m3, marker, "js-uri"});
    out.push_back({m4, marker, "attr-break"});
    out.push_back({m5, marker, "textarea-break"});
    out.push_back({m6, marker, "style-break"});
    (void)ip;
    diag::log_tagged_fmt("mod_xss", "xss_probes built %zu probes marker=%s", out.size(), marker.c_str());
    return out;
}

std::optional<issue_t> xss_detect(const insertion_point_t& ip, const probe_t& probe,
                                  const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_xss", "xss_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (probe.marker.empty()) {
        diag::log_tagged_fmt("mod_xss", "xss_detect skip empty marker ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return std::nullopt;
    }
    if (!body_contains(resp, probe.marker)) {
        diag::log_tagged_fmt("mod_xss", "xss_detect marker not in body ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }

    bool full_payload_present = body_contains(resp, probe.payload);
    confidence_t conf = full_payload_present ? confidence_t::firm : confidence_t::tentative;
    severity_t sev = full_payload_present ? severity_t::high : severity_t::medium;
    diag::log_tagged_fmt("mod_xss", "xss_detect FINDING reflected ip=%s:%s variant=%s full_payload=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), full_payload_present ? 1 : 0);
    auto iss = make_issue("xss.reflected", "Cross-Site Scripting (reflected)",
                          sev, conf, ip, probe, resp, ctx,
                          std::string("Marker found in response: ") + probe.marker);
    iss.description = std::string(
        "A payload containing a unique marker was injected into the '") + ip.name +
        "' parameter and the marker appeared in the response body" +
        (full_payload_present ? " unfiltered, indicating reflected XSS." : " (partially encoded), worth manual confirmation.");
    iss.remediation = "Apply context-aware output encoding; deploy a strict Content-Security-Policy.";
    iss.cwe.push_back("CWE-79");
    return iss;
}

void xss_browser_confirm_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_xss", "xss_browser_confirm_run entry ip=%s:%s url=%s",
                         ip.kind.c_str(), ip.name.c_str(), ctx.url.c_str());
    (void)send;
    if (!camoufox::ensure_ready()) {
        diag::log_tagged_fmt("mod_xss", "xss_browser_confirm_run skip camoufox not ready ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return;
    }
    if (!scope::in_scope(ctx.url)) {
        diag::log_tagged_fmt("mod_xss", "xss_browser_confirm_run skip out-of-scope url=%s", ctx.url.c_str());
        return;
    }

    dom_xss::scan_options_t opts;
    opts.include_polyglot       = true;
    opts.include_standard       = true;
    opts.include_dom_only       = false;
    opts.capture_screenshots    = false;
    opts.per_payload_timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms / 2 : 8000;
    if (opts.per_payload_timeout_ms < 3000)  opts.per_payload_timeout_ms = 3000;
    if (opts.per_payload_timeout_ms > 15000) opts.per_payload_timeout_ms = 15000;
    opts.max_payloads_per_point = 6;
    opts.audit_id               = ctx.audit_id;
    opts.scheme                 = ctx.tls ? std::string("https") : std::string("http");
    opts.host                   = ctx.host;
    opts.port                   = ctx.port;

    using namespace std::chrono;
    uint64_t t0 = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    size_t emitted = dom_xss::scan_insertion_point(ip, opts);
    uint64_t t1 = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    diag::log_tagged_fmt("xss",
                         "module_xss custom_run browser_confirm ip=%s:%s emitted=%zu elapsed=%llums",
                         ip.kind.c_str(), ip.name.c_str(), emitted,
                         static_cast<unsigned long long>(t1 - t0));
}

bool register_self()
{
    module_t m;
    m.id = "xss";
    m.name = "Reflected XSS";
    m.category = "Injection";
    m.max_probes_per_point = 6;
    m.probes = xss_probes;
    m.detect = xss_detect;
    m.custom_run = xss_browser_confirm_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
