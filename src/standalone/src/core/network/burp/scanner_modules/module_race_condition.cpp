#include "../scanner_module.hpp"
#include "../audit_http.hpp"
#include "../intruder_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

static std::string extract_method(const std::string& base_request)
{
    size_t sp = base_request.find(' ');
    if (sp == std::string::npos) return std::string();
    return base_request.substr(0, sp);
}

static bool is_state_changing_method(const std::string& method)
{
    return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE";
}

static bool insertion_point_is_request_line(const insertion_point_t& ip)
{
    return ip.value_offset < 64;
}

static double median_size(std::vector<size_t> sizes)
{
    if (sizes.empty()) return 0.0;
    std::sort(sizes.begin(), sizes.end());
    size_t mid = sizes.size() / 2;
    if (sizes.size() & 1) return static_cast<double>(sizes[mid]);
    return (static_cast<double>(sizes[mid - 1]) + static_cast<double>(sizes[mid])) * 0.5;
}

void race_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    if (!insertion_point_is_request_line(ip)) return;
    if (ip.base_request.empty()) return;

    std::string method = extract_method(ip.base_request);
    if (!is_state_changing_method(method)) return;

    audit_http::send_options_t opt;
    opt.timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms : 12000;
    opt.follow_redirects = false;

    std::vector<uint8_t> raw_req(ip.base_request.begin(), ip.base_request.end());
    auto baseline = audit_http::send(raw_req, ctx.host, ctx.port, ctx.tls, opt);
    if (!baseline.has_value()) return;

    intruder::config_t cfg;
    cfg.scheme = ctx.tls ? "https" : "http";
    cfg.host = ctx.host;
    cfg.port = ctx.port;
    cfg.base_request = raw_req;
    cfg.attack_mode = intruder::attack_mode_t::race;
    cfg.engine_mode = ctx.tls ? intruder::engine_mode_t::http2_single_packet
                              : intruder::engine_mode_t::http1_pipelined;
    cfg.concurrency = 20;
    cfg.race_gate_size = 20;
    cfg.race_warmup_count = 0;
    cfg.total_requests_cap = 20;
    cfg.timeout_ms = opt.timeout_ms;
    cfg.payload_sets.push_back(std::vector<std::string>(20, std::string()));
    cfg.positions.push_back({ raw_req.size(), 0 });
    cfg.max_response_body_bytes = 16384;

    uint64_t job_id = intruder::start(cfg);
    if (job_id == 0) return;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(opt.timeout_ms * 3);
    while (std::chrono::steady_clock::now() < deadline) {
        auto s = intruder::status(job_id);
        if (!s.running && s.sent >= s.total) break;
        if (!s.running && s.total == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    auto results = intruder::results(job_id, 0, 256);
    intruder::clear(job_id);
    if (results.empty()) return;

    int twoxx_count = 0;
    int fourxx_count = 0;
    int fivexx_count = 0;
    int other_count = 0;
    std::vector<size_t> all_sizes;
    std::unordered_map<int, int> status_distribution;
    for (auto& r : results) {
        if (r.error) continue;
        if (r.status_code >= 200 && r.status_code < 300) ++twoxx_count;
        else if (r.status_code >= 400 && r.status_code < 500) ++fourxx_count;
        else if (r.status_code >= 500 && r.status_code < 600) ++fivexx_count;
        else ++other_count;
        all_sizes.push_back(r.response_size);
        ++status_distribution[r.status_code];
    }
    if (all_sizes.empty()) return;

    double med = median_size(all_sizes);
    size_t deviant = 0;
    for (auto sz : all_sizes) {
        double d = static_cast<double>(sz) - med;
        if (d < 0) d = -d;
        if (med > 0 && d / med > 0.15) ++deviant;
    }

    bool multi_success = twoxx_count >= 2;
    bool size_divergence = deviant >= 2;
    bool status_divergence = status_distribution.size() >= 2;

    if (!multi_success && !size_divergence && !status_divergence) return;

    severity_t sev = severity_t::medium;
    confidence_t conf = confidence_t::tentative;
    if (multi_success && size_divergence) {
        sev = severity_t::high;
        conf = confidence_t::tentative;
    } else if (multi_success || size_divergence) {
        sev = severity_t::medium;
    } else {
        sev = severity_t::low;
    }

    probe_t pb;
    pb.variant = "race-single-packet";
    pb.payload = std::string("20x ") + method + " single-packet race";
    pb.marker = "race";

    std::string ev;
    ev.reserve(256);
    ev += "Race attack fired " + std::to_string(all_sizes.size()) + " concurrent "
        + method + " requests. Outcomes: 2xx=" + std::to_string(twoxx_count)
        + " 4xx=" + std::to_string(fourxx_count)
        + " 5xx=" + std::to_string(fivexx_count)
        + " other=" + std::to_string(other_count)
        + ". Median size=" + std::to_string(static_cast<uint64_t>(med))
        + ", deviant responses=" + std::to_string(deviant) + ".";

    auto iss = make_issue("race.single-packet", "Possible race condition (single-packet attack)",
                          sev, conf, ip, pb, *baseline, ctx, ev);
    iss.description = "20 identical state-changing requests were fired in a single TLS write (HTTP/2 single-packet attack) and the server returned divergent responses (multiple 2xx or significantly different response sizes). This is consistent with a TOCTOU race condition on " + method + " " + ip.kind + ".";
    iss.remediation = "Wrap state-changing operations in transactional locks or use database-level uniqueness constraints. Audit endpoints that perform critical state changes (account creation, voucher redemption, balance transfer) for atomicity.";
    iss.cwe.push_back("CWE-362");
    iss.cwe.push_back("CWE-367");
    issue_store::add(std::move(iss));
}

bool register_self()
{
    module_t m;
    m.id = "race_condition";
    m.name = "Race condition (single-packet)";
    m.category = "Logic";
    m.max_probes_per_point = 1;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = race_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
