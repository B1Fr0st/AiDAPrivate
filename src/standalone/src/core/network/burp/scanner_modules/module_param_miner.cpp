#include "../scanner_module.hpp"
#include "../audit_http.hpp"
#include "../param_miner.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

static bool insertion_point_is_request_line(const insertion_point_t& ip)
{
    return ip.value_offset < 64;
}

static void run_one_location(const insertion_point_t& ip, const module_context_t& ctx,
                             aida::burp::param_miner::location_t loc, const std::string& label)
{
    aida::burp::param_miner::config_t cfg;
    cfg.target_url = ctx.url;
    cfg.location = loc;
    cfg.wordlist_id = "params/common";
    cfg.concurrency = 6;
    cfg.throttle_ms = 25;
    cfg.timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms : 10000;
    cfg.baseline_count = 5;
    cfg.diff_sigma_threshold = 3.0;
    cfg.report_as_issues = true;

    uint64_t id = aida::burp::param_miner::start(std::move(cfg));
    if (id == 0) return;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    while (std::chrono::steady_clock::now() < deadline) {
        auto s = aida::burp::param_miner::status(id);
        if (!s.running && s.tried >= s.total) break;
        if (!s.running && s.total == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    auto hits = aida::burp::param_miner::results(id);
    aida::burp::param_miner::clear(id);

    if (!hits.empty()) {
        probe_t p;
        p.variant = std::string("param-miner-") + label;
        p.payload = std::string("Hidden parameter discovery on ") + label;
        p.marker = "param-miner";
        audit_http::send_options_t opt;
        opt.timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms : 10000;
        auto resp = audit_http::send(std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end()),
                                     ctx.host, ctx.port, ctx.tls, opt);
        if (!resp.has_value()) return;
        std::string summary = "Detected " + std::to_string(hits.size())
                            + " unrecognized parameters in '" + label + "': ";
        size_t shown = 0;
        for (auto& h : hits) {
            if (shown >= 8) { summary += "..."; break; }
            if (shown > 0) summary += ", ";
            summary += h.param_name;
            ++shown;
        }
        auto iss = make_issue("param-miner.summary",
                              "Hidden parameters discovered in " + label,
                              severity_t::info, confidence_t::firm,
                              ip, p, *resp, ctx, summary);
        iss.description = "ParamMiner enumerated common parameter names and " + std::to_string(hits.size())
                        + " of them produced a measurable response difference. Individual hits are also logged as separate issues.";
        iss.remediation = "Document and review the parameters discovered. Ensure that no hidden parameter bypasses access control, payment, or feature-flag logic.";
        iss.cwe.push_back("CWE-1230");
        issue_store::add(std::move(iss));
    }
}

void param_miner_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    (void)send;
    if (!insertion_point_is_request_line(ip)) return;
    if (ctx.url.empty()) return;

    run_one_location(ip, ctx, aida::burp::param_miner::location_t::query, "query");
    run_one_location(ip, ctx, aida::burp::param_miner::location_t::header, "header");
}

bool register_self()
{
    module_t m;
    m.id = "param_miner";
    m.name = "Hidden parameter discovery";
    m.category = "Discovery";
    m.max_probes_per_point = 1;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = param_miner_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
