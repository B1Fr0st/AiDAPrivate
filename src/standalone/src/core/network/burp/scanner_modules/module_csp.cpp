#include "../scanner_module.hpp"
#include "../csp_analyzer.hpp"
#include "../issue.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::atomic<bool>& registered_flag()
{
    static std::atomic<bool> f{false};
    return f;
}

severity_t severity_from_str(const std::string& s)
{
    if (s == "high")   return severity_t::high;
    if (s == "medium") return severity_t::medium;
    if (s == "low")    return severity_t::low;
    return severity_t::info;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void run_csp_analysis(const insertion_point_t& ip,
                      const module_context_t& ctx,
                      const send_fn_t& send_fn)
{
    (void)ip;
    (void)send_fn;
    if (ctx.baseline_response_headers.empty()) return;
    auto res = csp::analyze_for_response(ctx.baseline_response_headers);
    if (!res.has_csp) {
        issue_t iss;
        iss.type_key = "csp_missing";
        iss.name = "Missing Content-Security-Policy header";
        iss.severity = severity_t::low;
        iss.confidence = confidence_t::certain;
        iss.host = ctx.host;
        iss.port = ctx.port;
        iss.scheme = ctx.tls ? "https" : "http";
        iss.audit_id = ctx.audit_id;
        iss.seen_ms = now_ms();
        iss.description = "Response does not carry a Content-Security-Policy header.";
        iss.remediation = "Add a strict CSP: default-src 'self'; object-src 'none'; base-uri 'self'.";
        iss.cwe.push_back("CWE-1021");
        issue_store::add(std::move(iss));
        return;
    }
    for (const auto& f : res.findings) {
        issue_t iss;
        iss.type_key = "csp." + f.id;
        iss.name = f.title;
        iss.severity = severity_from_str(f.severity);
        iss.confidence = confidence_t::firm;
        iss.host = ctx.host;
        iss.port = ctx.port;
        iss.scheme = ctx.tls ? "https" : "http";
        iss.audit_id = ctx.audit_id;
        iss.seen_ms = now_ms();
        iss.description = f.description;
        iss.remediation = "Tighten the CSP directive: avoid 'unsafe-inline'/'unsafe-eval', avoid wildcards, set object-src 'none'.";
        evidence_t ev;
        ev.marker = f.evidence;
        iss.evidence.push_back(std::move(ev));
        iss.cwe.push_back("CWE-1021");
        issue_store::add(std::move(iss));
    }
}

struct auto_register_t
{
    auto_register_t()
    {
        bool expected = false;
        if (!registered_flag().compare_exchange_strong(expected, true)) return;
        module_t m;
        m.id = "csp.passive";
        m.name = "Content-Security-Policy analyzer (passive)";
        m.category = "passive";
        m.max_probes_per_point = 1;
        m.custom_run = [](const insertion_point_t& ip,
                          const module_context_t& ctx,
                          const send_fn_t& send_fn) {
            run_csp_analysis(ip, ctx, send_fn);
        };
        register_module(std::move(m));
    }
};

auto_register_t g_register_csp_module;

}

}
}
}
