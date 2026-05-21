#include "../scanner_module.hpp"
#include "../insertion_points.hpp"
#include "../camoufox_bridge.hpp"
#include "../dom_xss_engine.hpp"
#include "../scope.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

void dom_xss_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_dom_xss", "dom_xss_run entry ip=%s:%s url=%s", ip.kind.c_str(), ip.name.c_str(), ctx.url.c_str());
    (void)send;
    if (!camoufox::ensure_ready()) {
        diag::log_tagged_fmt("mod_dom_xss", "dom_xss_run skip camoufox not ready ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return;
    }
    if (!scope::in_scope(ctx.url)) {
        diag::log_tagged_fmt("mod_dom_xss", "dom_xss_run skip out-of-scope url=%s", ctx.url.c_str());
        return;
    }
    diag::log_tagged_fmt("mod_dom_xss", "dom_xss_run camoufox ready scanning ip=%s:%s", ip.kind.c_str(), ip.name.c_str());

    dom_xss::scan_options_t opts;
    opts.include_polyglot       = true;
    opts.include_standard       = true;
    opts.include_dom_only       = true;
    opts.capture_screenshots    = false;
    opts.per_payload_timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms / 2 : 8000;
    if (opts.per_payload_timeout_ms < 3000) opts.per_payload_timeout_ms = 3000;
    if (opts.per_payload_timeout_ms > 20000) opts.per_payload_timeout_ms = 20000;
    opts.max_payloads_per_point = 8;
    opts.audit_id               = ctx.audit_id;
    opts.scheme                 = ctx.tls ? std::string("https") : std::string("http");
    opts.host                   = ctx.host;
    opts.port                   = ctx.port;

    using namespace std::chrono;
    uint64_t t0 = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    size_t emitted = dom_xss::scan_insertion_point(ip, opts);
    uint64_t t1 = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    diag::log_tagged_fmt("dom_xss", "module sweep ip=%s:%s emitted=%zu elapsed=%llums",
                         ip.kind.c_str(), ip.name.c_str(), emitted,
                         static_cast<unsigned long long>(t1 - t0));
}

std::vector<probe_t> dom_xss_probes(const insertion_point_t&, const module_context_t&)
{
    return {};
}

bool register_self()
{
    module_t m;
    m.id = "xss.dom";
    m.name = "DOM-Based XSS (Camoufox)";
    m.category = "client_side";
    m.max_probes_per_point = 0;
    m.probes = dom_xss_probes;
    m.custom_run = dom_xss_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
