#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "insertion_points.hpp"
#include "issue.hpp"
#include "scope.hpp"

#include "../../infra/work_queue.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace aida {
namespace burp {
namespace active_scanner {

namespace {

struct audit_runtime_t
{
    audit_status_t              status;
    audit_config_t              config;
    std::vector<uint8_t>        raw_request;
    std::atomic<bool>           cancel_flag{false};
    std::atomic<size_t>         in_flight{0};
    std::atomic<size_t>         module_request_count{0};
    std::map<std::string, std::atomic<size_t>> per_module_count;
    std::mutex                  pmc_mtx;
    std::mutex                  status_mtx;
    std::condition_variable     cancel_cv;
};

struct state_t
{
    std::mutex                                                            audits_mtx;
    std::unordered_map<uint64_t, std::shared_ptr<audit_runtime_t>>        audits;
    std::atomic<uint64_t>                                                 next_id{1};
    std::atomic<size_t>                                                   global_in_flight{0};
    std::atomic<bool>                                                     initialized{false};
    std::mutex                                                            err_mtx;
    std::string                                                           last_error;
};

state_t& state()
{
    static state_t s;
    return s;
}

void set_err(const std::string& msg)
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

size_t increment_pmc(audit_runtime_t& rt, const std::string& mod_id)
{
    std::lock_guard<std::mutex> lk(rt.pmc_mtx);
    auto it = rt.per_module_count.find(mod_id);
    if (it == rt.per_module_count.end()) {
        rt.per_module_count[mod_id].store(0);
        it = rt.per_module_count.find(mod_id);
    }
    return it->second.fetch_add(1) + 1;
}

bool wait_for_inflight_slot(audit_runtime_t& rt, size_t cap)
{
    while (true) {
        if (rt.cancel_flag.load()) return false;
        size_t cur = rt.in_flight.load();
        if (cur < cap) {
            if (rt.in_flight.compare_exchange_weak(cur, cur + 1)) return true;
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void release_inflight(audit_runtime_t& rt)
{
    rt.in_flight.fetch_sub(1);
}

scanner::send_fn_t make_send_fn(std::shared_ptr<audit_runtime_t> rt_ptr,
                                const std::string& mod_id)
{
    return [rt_ptr, mod_id](const std::vector<uint8_t>& raw_req, const scanner::probe_t& probe) -> std::optional<exchange_observed_t> {
        (void)probe;
        if (rt_ptr->cancel_flag.load()) return std::nullopt;
        if (rt_ptr->config.per_module_request_cap > 0 &&
            increment_pmc(*rt_ptr, mod_id) > rt_ptr->config.per_module_request_cap) return std::nullopt;
        if (rt_ptr->config.request_throttle_ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(rt_ptr->config.request_throttle_ms));
        audit_http::send_options_t opt;
        opt.timeout_ms = rt_ptr->config.timeout_ms;
        opt.follow_redirects = rt_ptr->config.follow_redirects;
        opt.enforce_scope = rt_ptr->config.scope_only;
        return audit_http::send(raw_req, rt_ptr->status.host, rt_ptr->status.port,
                                rt_ptr->status.tls, opt);
    };
}

void emit_issue_safe(std::shared_ptr<audit_runtime_t> rt_ptr, issue_t iss)
{
    iss.audit_id = rt_ptr->status.id;
    iss.host = rt_ptr->status.host;
    iss.port = rt_ptr->status.port;
    iss.scheme = rt_ptr->status.tls ? "https" : "http";
    issue_store::add(std::move(iss));
    std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
    rt_ptr->status.issues_found++;
}

void run_module_for_point(std::shared_ptr<audit_runtime_t> rt_ptr,
                          const scanner::module_t& mod,
                          const insertion_point_t& ip)
{
    diag::log_tagged_fmt("scanner", "run_module_for_point audit=%llu module=%s ip_kind=%s ip_name=%s",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), ip.kind.c_str(), ip.name.c_str());
    if (rt_ptr->cancel_flag.load()) {
        diag::log_tagged_fmt("scanner", "run_module_for_point cancelled early audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        return;
    }

    scanner::module_context_t ctx;
    ctx.audit_id = rt_ptr->status.id;
    ctx.host = rt_ptr->status.host;
    ctx.port = rt_ptr->status.port;
    ctx.tls = rt_ptr->status.tls;
    ctx.url = rt_ptr->status.url;
    ctx.timeout_ms = rt_ptr->config.timeout_ms;
    ctx.follow_redirects = rt_ptr->config.follow_redirects;

    audit_http::send_options_t base_opt;
    base_opt.timeout_ms = rt_ptr->config.timeout_ms;
    base_opt.follow_redirects = rt_ptr->config.follow_redirects;
    base_opt.enforce_scope = rt_ptr->config.scope_only;
    auto baseline = audit_http::send(rt_ptr->raw_request, rt_ptr->status.host,
                                     rt_ptr->status.port, rt_ptr->status.tls, base_opt);
    if (baseline.has_value()) {
        ctx.baseline_latency_ms = baseline->latency_ms;
        ctx.baseline_response_body = baseline->resp_body;
        ctx.baseline_response_headers = baseline->resp_headers;
        ctx.baseline_status_code = baseline->status_code;
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline audit=%llu module=%s status=%d latency=%llu body=%zu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(),
            baseline->status_code, static_cast<unsigned long long>(baseline->latency_ms), baseline->resp_body.size());
    } else {
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline_failed audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
    }

    auto send_fn = make_send_fn(rt_ptr, mod.id);

    if (mod.custom_run) {
        diag::log_tagged_fmt("scanner", "run_module_for_point custom_run audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        mod.custom_run(ip, ctx, send_fn);
        if (!mod.probes || !mod.detect) return;
    }

    if (!mod.probes || !mod.detect) {
        diag::log_tagged_fmt("scanner", "run_module_for_point no_probes_or_detect audit=%llu module=%s", static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        return;
    }
    auto probes = mod.probes(ip, ctx);
    int probe_cap = mod.max_probes_per_point > 0 ? mod.max_probes_per_point : 6;
    diag::log_tagged_fmt("scanner", "run_module_for_point probes_generated audit=%llu module=%s ip=%s/%s probe_count=%zu cap=%d",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(),
        ip.kind.c_str(), ip.name.c_str(), probes.size(), probe_cap);
    int issued = 0;
    for (const auto& p : probes) {
        if (rt_ptr->cancel_flag.load()) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_loop cancelled audit=%llu module=%s issued=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued);
            return;
        }
        if (issued >= probe_cap) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_cap_reached audit=%llu module=%s cap=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), probe_cap);
            break;
        }
        if (!wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests)) {
            diag::log_tagged_fmt("scanner", "run_module_for_point inflight_wait_failed audit=%llu module=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
            return;
        }

        diag::log_tagged_fmt("scanner", "run_module_for_point sending_probe audit=%llu module=%s probe_idx=%d payload_len=%zu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued, p.payload.size());
        auto built = ip.build ? ip.build(p.payload) : std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
        auto resp = send_fn(built, p);
        release_inflight(*rt_ptr);
        {
            std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
            rt_ptr->status.completed_probes++;
        }
        ++issued;
        if (!resp.has_value()) {
            diag::log_tagged_fmt("scanner", "run_module_for_point probe_no_response audit=%llu module=%s probe_idx=%d",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued - 1);
            continue;
        }
        diag::log_tagged_fmt("scanner", "run_module_for_point probe_response audit=%llu module=%s probe_idx=%d status=%d body=%zu latency=%llu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), issued - 1,
            resp->status_code, resp->resp_body.size(), static_cast<unsigned long long>(resp->latency_ms));
        auto maybe = mod.detect(ip, p, *resp, ctx);
        if (maybe.has_value()) {
            diag::log_tagged_fmt("scanner", "run_module_for_point issue_found audit=%llu module=%s type=%s",
                static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), maybe->type_key.c_str());
            emit_issue_safe(rt_ptr, *maybe);
            break;
        }
    }
    diag::log_tagged_fmt("scanner", "run_module_for_point done audit=%llu module=%s ip=%s/%s issued=%d",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), ip.kind.c_str(), ip.name.c_str(), issued);
}

void run_audit(std::shared_ptr<audit_runtime_t> rt_ptr)
{
    auto modules_all = scanner::all_modules();
    std::vector<scanner::module_t> enabled;
    if (rt_ptr->config.enabled_modules.empty()) {
        enabled = std::move(modules_all);
    } else {
        for (auto& m : modules_all) {
            if (std::find(rt_ptr->config.enabled_modules.begin(),
                          rt_ptr->config.enabled_modules.end(),
                          m.id) != rt_ptr->config.enabled_modules.end()) {
                enabled.push_back(std::move(m));
            }
        }
    }

    auto points = insertion_points::analyze(rt_ptr->raw_request, rt_ptr->status.url);
    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.total_points = points.size();
        rt_ptr->status.total_probes = points.size() * enabled.size();
    }

    diag::log_tagged_fmt("burp", "active_scanner audit_start id=%llu points=%zu modules=%zu url=%s",
        static_cast<unsigned long long>(rt_ptr->status.id),
        points.size(), enabled.size(), rt_ptr->status.url.c_str());

    for (const auto& ip : points) {
        if (rt_ptr->cancel_flag.load()) break;
        for (const auto& mod : enabled) {
            if (rt_ptr->cancel_flag.load()) break;
            std::shared_ptr<audit_runtime_t> captured = rt_ptr;
            scanner::module_t mod_copy = mod;
            insertion_point_t ip_copy = ip;
            work_queue::post([captured, mod_copy, ip_copy]() {
                run_module_for_point(captured, mod_copy, ip_copy);
            });
        }
    }

    while (true) {
        if (rt_ptr->cancel_flag.load()) break;
        size_t completed;
        size_t total;
        {
            std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
            completed = rt_ptr->status.completed_probes;
            total = rt_ptr->status.total_probes;
        }
        if (rt_ptr->in_flight.load() == 0 && (total == 0 || completed >= total)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.running = false;
        rt_ptr->status.cancelled = rt_ptr->cancel_flag.load();
        rt_ptr->status.ended_ms = now_ms();
    }
    diag::log_tagged_fmt("burp", "active_scanner audit_end id=%llu issues=%zu cancelled=%d",
        static_cast<unsigned long long>(rt_ptr->status.id),
        rt_ptr->status.issues_found,
        rt_ptr->status.cancelled ? 1 : 0);
}

}

bool initialize()
{
    diag::log_tagged_fmt("scanner", "active_scanner initialize called");
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("scanner", "active_scanner already_initialized");
        return true;
    }
    diag::log_tagged_fmt("scanner", "active_scanner initialize success");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("scanner", "active_scanner shutdown called");
    auto& s = state();
    if (!s.initialized.load()) {
        diag::log_tagged_fmt("scanner", "active_scanner shutdown skipped not_initialized");
        return;
    }
    std::vector<std::shared_ptr<audit_runtime_t>> alive;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        for (auto& kv : s.audits) alive.push_back(kv.second);
    }
    diag::log_tagged_fmt("scanner", "active_scanner shutdown cancelling %zu audits", alive.size());
    for (auto& rt : alive) rt->cancel_flag.store(true);
    auto t0 = std::chrono::steady_clock::now();
    while (true) {
        bool all_done = true;
        for (auto& rt : alive) {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            if (rt->status.running) { all_done = false; break; }
        }
        if (all_done) break;
        if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(5)) {
            diag::log_tagged_fmt("scanner", "active_scanner shutdown timeout waiting for audits");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    diag::log_tagged_fmt("scanner", "active_scanner shutdown complete");
}

uint64_t enqueue_target(const std::vector<uint8_t>& raw_request,
                        const std::string& url,
                        const audit_config_t& cfg)
{
    diag::log_tagged_fmt("scanner", "enqueue_target url=%s req_len=%zu scope_only=%d timeout=%d modules=%zu",
        url.c_str(), raw_request.size(), cfg.scope_only ? 1 : 0, cfg.timeout_ms, cfg.enabled_modules.size());
    auto& s = state();
    if (!s.initialized.load()) initialize();
    if (raw_request.empty() || url.empty()) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected empty_request=%d empty_url=%d",
            raw_request.empty() ? 1 : 0, url.empty() ? 1 : 0);
        set_err("active_scanner.enqueue: empty request or url");
        return 0;
    }

    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected invalid_url=%s", url.c_str());
        set_err("active_scanner.enqueue: invalid url");
        return 0;
    }
    if (cfg.scope_only && !scope::in_scope(url)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected out_of_scope url=%s", url.c_str());
        set_err("active_scanner.enqueue: target out of scope");
        return 0;
    }
    auto rt = std::make_shared<audit_runtime_t>();
    rt->config = cfg;
    rt->raw_request = raw_request;
    rt->status.id = s.next_id.fetch_add(1);
    rt->status.url = url;
    rt->status.host = host;
    rt->status.port = port;
    rt->status.tls = (scheme == "https");
    rt->status.running = true;
    rt->status.started_ms = now_ms();
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        s.audits[rt->status.id] = rt;
    }

    diag::log_tagged_fmt("scanner", "enqueue_target queued audit_id=%llu host=%s port=%u tls=%d",
        static_cast<unsigned long long>(rt->status.id), host.c_str(), port, rt->status.tls ? 1 : 0);

    std::shared_ptr<audit_runtime_t> captured = rt;
    work_queue::post([captured]() { run_audit(captured); });

    return rt->status.id;
}

bool cancel_audit(uint64_t audit_id)
{
    diag::log_tagged_fmt("scanner", "cancel_audit id=%llu", static_cast<unsigned long long>(audit_id));
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "cancel_audit id=%llu not_found", static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }
    rt->cancel_flag.store(true);
    rt->cancel_cv.notify_all();
    diag::log_tagged_fmt("scanner", "cancel_audit id=%llu cancel_flag_set", static_cast<unsigned long long>(audit_id));
    return true;
}

std::vector<audit_status_t> list_audits()
{
    auto& s = state();
    std::vector<audit_status_t> out;
    std::vector<std::shared_ptr<audit_runtime_t>> alive;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        for (auto& kv : s.audits) alive.push_back(kv.second);
    }
    for (auto& rt : alive) {
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        out.push_back(rt->status);
    }
    std::sort(out.begin(), out.end(), [](const audit_status_t& a, const audit_status_t& b) {
        return a.started_ms > b.started_ms;
    });
    return out;
}

bool get_status(uint64_t audit_id, audit_status_t& out)
{
    diag::log_tagged_fmt("scanner", "get_status id=%llu", static_cast<unsigned long long>(audit_id));
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "get_status id=%llu not_found", static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }
    std::lock_guard<std::mutex> lk(rt->status_mtx);
    out = rt->status;
    diag::log_tagged_fmt("scanner", "get_status id=%llu running=%d issues=%zu completed=%zu total=%zu",
        static_cast<unsigned long long>(audit_id), out.running ? 1 : 0,
        out.issues_found, out.completed_probes, out.total_probes);
    return true;
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error;
}

}
}
}
