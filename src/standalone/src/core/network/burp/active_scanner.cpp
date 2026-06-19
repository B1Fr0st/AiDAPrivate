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
#include <exception>
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

constexpr size_t kMaxActiveAudits = 2;
constexpr size_t kMaxGlobalInFlightRequests = 16;
constexpr size_t kMaxPerAuditInFlightRequests = 8;

struct audit_runtime_t
{
    audit_status_t              status;
    audit_config_t              config;
    std::vector<uint8_t>        raw_request;
    std::atomic<bool>           cancel_flag{false};
    std::atomic<size_t>         in_flight{0};
    std::atomic<size_t>         active_workers{0};
    std::atomic<size_t>         queued_workers{0};
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
    std::atomic<bool>                                                     shutting_down{false};
    std::mutex                                                            err_mtx;
    std::string                                                           last_error;
    std::string                                                           last_error_code;
};

state_t& state()
{
    static state_t* s = new state_t();
    return *s;
}

void set_err(const std::string& msg, const std::string& code = std::string())
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    s.last_error = msg;
    s.last_error_code = code;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

scanner_load_t collect_load_snapshot()
{
    auto& s = state();
    scanner_load_t load;
    load.max_active_audits = kMaxActiveAudits;
    load.shutting_down = s.shutting_down.load(std::memory_order_acquire);
    load.in_flight_requests = s.global_in_flight.load(std::memory_order_acquire);
    std::lock_guard<std::mutex> lk(s.audits_mtx);
    load.active_audits = s.audits.size();
    for (auto& kv : s.audits) {
        const auto& rt = kv.second;
        if (!rt)
            continue;
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        load.active_workers += active_workers;
        load.queue_depth += active_workers;
        {
            std::lock_guard<std::mutex> st_lk(rt->status_mtx);
            if (rt->status.running)
                ++load.running_audits;
        }
    }
    return load;
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
    auto& s = state();
    const size_t per_audit_cap = (std::max)(static_cast<size_t>(1), (std::min)(cap, kMaxPerAuditInFlightRequests));
    while (true) {
        if (rt.cancel_flag.load() || s.shutting_down.load(std::memory_order_acquire)) return false;
        size_t cur = rt.in_flight.load();
        size_t global_cur = s.global_in_flight.load(std::memory_order_acquire);
        if (cur < per_audit_cap && global_cur < kMaxGlobalInFlightRequests) {
            if (!rt.in_flight.compare_exchange_weak(cur, cur + 1))
                continue;
            while (true) {
                global_cur = s.global_in_flight.load(std::memory_order_acquire);
                if (global_cur >= kMaxGlobalInFlightRequests) {
                    rt.in_flight.fetch_sub(1, std::memory_order_acq_rel);
                    break;
                }
                if (s.global_in_flight.compare_exchange_weak(global_cur, global_cur + 1, std::memory_order_acq_rel))
                    return true;
            }
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void release_inflight(audit_runtime_t& rt)
{
    rt.in_flight.fetch_sub(1, std::memory_order_acq_rel);
    state().global_in_flight.fetch_sub(1, std::memory_order_acq_rel);
}

scanner::send_fn_t make_send_fn(std::shared_ptr<audit_runtime_t> rt_ptr,
                                const std::string& mod_id,
                                bool count_completed,
                                bool acquire_slot)
{
    return [rt_ptr, mod_id, count_completed, acquire_slot](const std::vector<uint8_t>& raw_req, const scanner::probe_t& probe) -> std::optional<exchange_observed_t> {
        (void)probe;
        if (rt_ptr->cancel_flag.load()) return std::nullopt;
        if (rt_ptr->config.per_module_request_cap > 0 &&
            increment_pmc(*rt_ptr, mod_id) > rt_ptr->config.per_module_request_cap) return std::nullopt;
        if (rt_ptr->config.request_throttle_ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(rt_ptr->config.request_throttle_ms));
        bool slot_acquired = false;
        if (acquire_slot) {
            slot_acquired = wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests);
            if (!slot_acquired) {
                diag::log_tagged_fmt("scanner", "send_fn slot_wait_failed audit=%llu module=%s req_len=%zu tid=%lu",
                    static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(), static_cast<unsigned long>(GetCurrentThreadId()));
                return std::nullopt;
            }
        }
        audit_http::send_options_t opt;
        opt.timeout_ms = rt_ptr->config.timeout_ms;
        opt.follow_redirects = rt_ptr->config.follow_redirects;
        opt.enforce_scope = rt_ptr->config.scope_only;
        const uint64_t started = now_ms();
        const auto before = collect_load_snapshot();
        diag::log_tagged_fmt("scanner", "send_fn begin audit=%llu module=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(),
            before.active_audits, before.running_audits, before.queue_depth, before.in_flight_requests,
            static_cast<unsigned long>(GetCurrentThreadId()));
        auto observed = audit_http::send(raw_req, rt_ptr->status.host, rt_ptr->status.port,
                                         rt_ptr->status.tls, opt);
        const uint64_t elapsed = now_ms() - started;
        if (observed.has_value()) {
            diag::log_tagged_fmt("scanner", "send_fn done audit=%llu module=%s status=%d body=%zu elapsed_ms=%llu tid=%lu",
                static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), observed->status_code, observed->resp_body.size(),
                static_cast<unsigned long long>(elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
        } else {
            const std::string socket_error = audit_http::last_error();
            diag::log_tagged_fmt("scanner", "send_fn failed audit=%llu module=%s req_len=%zu socket_error=%s elapsed_ms=%llu tid=%lu",
                static_cast<unsigned long long>(rt_ptr->status.id), mod_id.c_str(), raw_req.size(), socket_error.c_str(),
                static_cast<unsigned long long>(elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
        }
        if (slot_acquired)
            release_inflight(*rt_ptr);
        if (count_completed) {
            std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
            rt_ptr->status.completed_probes++;
        }
        return observed;
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
    ctx.cancelled = [rt_ptr]() {
        return rt_ptr->cancel_flag.load(std::memory_order_acquire);
    };

    audit_http::send_options_t base_opt;
    base_opt.timeout_ms = rt_ptr->config.timeout_ms;
    base_opt.follow_redirects = rt_ptr->config.follow_redirects;
    base_opt.enforce_scope = rt_ptr->config.scope_only;
    if (!wait_for_inflight_slot(*rt_ptr, rt_ptr->config.max_concurrent_requests)) {
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline_slot_wait_failed audit=%llu module=%s req_len=%zu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), rt_ptr->raw_request.size(), static_cast<unsigned long>(GetCurrentThreadId()));
        return;
    }
    const uint64_t baseline_started = now_ms();
    const auto baseline_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "run_module_for_point baseline_begin audit=%llu module=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), rt_ptr->raw_request.size(),
        baseline_load.active_audits, baseline_load.running_audits, baseline_load.queue_depth, baseline_load.in_flight_requests,
        static_cast<unsigned long>(GetCurrentThreadId()));
    auto baseline = audit_http::send(rt_ptr->raw_request, rt_ptr->status.host,
                                     rt_ptr->status.port, rt_ptr->status.tls, base_opt);
    release_inflight(*rt_ptr);
    const uint64_t baseline_elapsed = now_ms() - baseline_started;
    if (baseline.has_value()) {
        ctx.baseline_latency_ms = baseline->latency_ms;
        ctx.baseline_response_body = baseline->resp_body;
        ctx.baseline_response_headers = baseline->resp_headers;
        ctx.baseline_status_code = baseline->status_code;
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline audit=%llu module=%s status=%d latency=%llu body=%zu elapsed_ms=%llu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(),
            baseline->status_code, static_cast<unsigned long long>(baseline->latency_ms), baseline->resp_body.size(),
            static_cast<unsigned long long>(baseline_elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
    } else {
        const std::string socket_error = audit_http::last_error();
        diag::log_tagged_fmt("scanner", "run_module_for_point baseline_failed audit=%llu module=%s socket_error=%s elapsed_ms=%llu tid=%lu",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str(), socket_error.c_str(),
            static_cast<unsigned long long>(baseline_elapsed), static_cast<unsigned long>(GetCurrentThreadId()));
    }

    auto send_fn = make_send_fn(rt_ptr, mod.id, false, false);

    if (mod.custom_run) {
        diag::log_tagged_fmt("scanner", "run_module_for_point custom_run audit=%llu module=%s",
            static_cast<unsigned long long>(rt_ptr->status.id), mod.id.c_str());
        auto custom_send_fn = make_send_fn(rt_ptr, mod.id, true, true);
        mod.custom_run(ip, ctx, custom_send_fn);
        if (rt_ptr->cancel_flag.load()) return;
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

    const auto start_load = collect_load_snapshot();
    diag::log_tagged_fmt("burp", "active_scanner audit_start id=%llu points=%zu modules=%zu url=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id),
        points.size(), enabled.size(), rt_ptr->status.url.c_str(), rt_ptr->raw_request.size(),
        start_load.active_audits, start_load.running_audits, start_load.queue_depth, start_load.in_flight_requests,
        static_cast<unsigned long>(GetCurrentThreadId()));

    for (const auto& ip : points) {
        if (rt_ptr->cancel_flag.load()) break;
        for (const auto& mod : enabled) {
            if (rt_ptr->cancel_flag.load()) break;
            std::shared_ptr<audit_runtime_t> captured = rt_ptr;
            scanner::module_t mod_copy = mod;
            insertion_point_t ip_copy = ip;
            rt_ptr->queued_workers.fetch_add(1, std::memory_order_relaxed);
            rt_ptr->active_workers.fetch_add(1, std::memory_order_relaxed);
            const bool posted = work_queue::post([captured, mod_copy, ip_copy]() {
                struct worker_guard_t
                {
                    std::shared_ptr<audit_runtime_t> rt;
                    ~worker_guard_t()
                    {
                        rt->active_workers.fetch_sub(1, std::memory_order_acq_rel);
                        rt->cancel_cv.notify_all();
                    }
                } guard{captured};
                run_module_for_point(captured, mod_copy, ip_copy);
            });
            if (!posted) {
                rt_ptr->active_workers.fetch_sub(1, std::memory_order_acq_rel);
                rt_ptr->cancel_cv.notify_all();
                diag::log_tagged_fmt("burp", "active_scanner worker_post_failed id=%llu module=%s ip=%s/%s",
                    static_cast<unsigned long long>(rt_ptr->status.id),
                    mod.id.c_str(),
                    ip.kind.c_str(),
                    ip.name.c_str());
                {
                    std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
                    if (rt_ptr->status.completed_probes < rt_ptr->status.total_probes)
                        rt_ptr->status.completed_probes++;
                }
            }
        }
    }

    auto cancel_wait_started = std::chrono::steady_clock::time_point{};
    while (true) {
        const size_t active_workers = rt_ptr->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt_ptr->in_flight.load(std::memory_order_acquire);
        if (active_workers == 0 && in_flight == 0) break;
        if (rt_ptr->cancel_flag.load(std::memory_order_acquire)) {
            if (cancel_wait_started == std::chrono::steady_clock::time_point{})
                cancel_wait_started = std::chrono::steady_clock::now();
            if (std::chrono::steady_clock::now() - cancel_wait_started > std::chrono::seconds(15)) {
                diag::log_tagged_fmt("burp", "active_scanner cancel_drain_timeout id=%llu active_workers=%zu in_flight=%zu",
                    static_cast<unsigned long long>(rt_ptr->status.id), active_workers, in_flight);
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    {
        std::lock_guard<std::mutex> lk(rt_ptr->status_mtx);
        rt_ptr->status.running = false;
        const bool cancel_requested = rt_ptr->cancel_flag.load();
        rt_ptr->status.cancel_requested = rt_ptr->status.cancel_requested || cancel_requested;
        rt_ptr->status.cancelled = cancel_requested;
        rt_ptr->status.drained = rt_ptr->active_workers.load(std::memory_order_acquire) == 0 &&
                                 rt_ptr->in_flight.load(std::memory_order_acquire) == 0;
        rt_ptr->status.ended_ms = now_ms();
    }
    rt_ptr->cancel_cv.notify_all();
    const auto end_load = collect_load_snapshot();
    diag::log_tagged_fmt("burp", "active_scanner audit_end id=%llu issues=%zu cancelled=%d cancel_requested=%d drained=%d active_workers=%zu in_flight=%zu active_audits=%zu running_audits=%zu queue_depth=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(rt_ptr->status.id),
        rt_ptr->status.issues_found,
        rt_ptr->status.cancelled ? 1 : 0,
        rt_ptr->status.cancel_requested ? 1 : 0,
        rt_ptr->status.drained ? 1 : 0,
        rt_ptr->active_workers.load(std::memory_order_acquire),
        rt_ptr->in_flight.load(std::memory_order_acquire),
        end_load.active_audits,
        end_load.running_audits,
        end_load.queue_depth,
        static_cast<unsigned long long>(rt_ptr->status.ended_ms > rt_ptr->status.started_ms ? rt_ptr->status.ended_ms - rt_ptr->status.started_ms : 0),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

}

bool initialize()
{
    diag::log_tagged_fmt("scanner", "active_scanner initialize called");
    auto& s = state();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) {
        const bool stopping = s.shutting_down.load(std::memory_order_acquire);
        diag::log_tagged_fmt("scanner", "active_scanner already_initialized shutting_down=%d", stopping ? 1 : 0);
        return !stopping;
    }
    s.shutting_down.store(false, std::memory_order_release);
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
    bool expected = false;
    if (!s.shutting_down.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged_fmt("scanner", "active_scanner shutdown skipped already_shutting_down");
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
    bool all_done = false;
    while (true) {
        all_done = true;
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
    if (all_done) {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        s.audits.clear();
        s.initialized.store(false, std::memory_order_release);
        s.shutting_down.store(false, std::memory_order_release);
    } else {
        diag::log_tagged_fmt("scanner", "active_scanner shutdown incomplete audits=%zu", alive.size());
    }
    diag::log_tagged_fmt("scanner", "active_scanner shutdown complete");
}

uint64_t enqueue_target(const std::vector<uint8_t>& raw_request,
                        const std::string& url,
                        const audit_config_t& cfg)
{
    const uint64_t enqueue_started = now_ms();
    const auto entry_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "enqueue_target url=%s req_len=%zu scope_only=%d timeout=%d modules=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu max_active=%zu tid=%lu",
        url.c_str(), raw_request.size(), cfg.scope_only ? 1 : 0, cfg.timeout_ms, cfg.enabled_modules.size(),
        entry_load.active_audits, entry_load.running_audits, entry_load.queue_depth, entry_load.in_flight_requests, entry_load.max_active_audits,
        static_cast<unsigned long>(GetCurrentThreadId()));
    auto& s = state();
    if (!s.initialized.load() && !initialize()) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected initialize_failed");
        set_err("active_scanner.enqueue: initialization failed");
        return 0;
    }
    if (s.shutting_down.load(std::memory_order_acquire)) {
        diag::log_tagged_fmt("scanner", "enqueue_target rejected shutting_down");
        set_err("active_scanner.enqueue: scanner is shutting down");
        return 0;
    }
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
    audit_config_t normalized_cfg = cfg;
    normalized_cfg.max_concurrent_requests = (std::max)(static_cast<size_t>(1), (std::min)(normalized_cfg.max_concurrent_requests, kMaxPerAuditInFlightRequests));
    auto rt = std::make_shared<audit_runtime_t>();
    rt->config = normalized_cfg;
    rt->raw_request = raw_request;
    rt->status.id = s.next_id.fetch_add(1);
    rt->status.url = url;
    rt->status.host = host;
    rt->status.port = port;
    rt->status.tls = (scheme == "https");
    rt->status.running = true;
    rt->status.started_ms = now_ms();
    rt->status.request_length = raw_request.size();
    try {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        size_t running_audits = 0;
        size_t active_workers = 0;
        size_t in_flight = s.global_in_flight.load(std::memory_order_acquire);
        for (auto& kv : s.audits) {
            const auto& existing = kv.second;
            if (!existing)
                continue;
            active_workers += existing->active_workers.load(std::memory_order_acquire);
            std::lock_guard<std::mutex> st_lk(existing->status_mtx);
            if (existing->status.running)
                ++running_audits;
        }
        if (running_audits >= kMaxActiveAudits) {
            diag::log_tagged_fmt("scanner", "enqueue_target rejected busy url=%s req_len=%zu running_audits=%zu active_audits=%zu queue_depth=%zu in_flight=%zu max_active=%zu elapsed_ms=%llu tid=%lu",
                url.c_str(), raw_request.size(), running_audits, s.audits.size(), active_workers, in_flight, kMaxActiveAudits,
                static_cast<unsigned long long>(now_ms() - enqueue_started), static_cast<unsigned long>(GetCurrentThreadId()));
            set_err("active_scanner.enqueue: scanner busy", "scanner_busy");
            return 0;
        }
        auto inserted = s.audits.emplace(rt->status.id, rt);
        if (!inserted.second) {
            diag::log_tagged_fmt("scanner", "enqueue_target rejected duplicate_id=%llu", static_cast<unsigned long long>(rt->status.id));
            set_err("active_scanner.enqueue: duplicate audit id");
            return 0;
        }
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("scanner", "enqueue_target audit_map_insert_exception id=%llu err=%s",
            static_cast<unsigned long long>(rt->status.id), ex.what());
        set_err("active_scanner.enqueue: audit registration failed");
        return 0;
    } catch (...) {
        diag::log_tagged_fmt("scanner", "enqueue_target audit_map_insert_exception id=%llu err=unknown",
            static_cast<unsigned long long>(rt->status.id));
        set_err("active_scanner.enqueue: audit registration failed");
        return 0;
    }

    const auto queued_load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "enqueue_target queued audit_id=%llu host=%s port=%u tls=%d req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(rt->status.id), host.c_str(), port, rt->status.tls ? 1 : 0, raw_request.size(),
        queued_load.active_audits, queued_load.running_audits, queued_load.queue_depth, queued_load.in_flight_requests,
        static_cast<unsigned long long>(now_ms() - enqueue_started), static_cast<unsigned long>(GetCurrentThreadId()));

    std::shared_ptr<audit_runtime_t> captured = rt;
    const bool posted = work_queue::post([captured]() { run_audit(captured); });
    if (!posted) {
        {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            rt->status.running = false;
            rt->status.cancelled = true;
            rt->status.cancel_requested = true;
            rt->status.drained = true;
            rt->status.ended_ms = now_ms();
        }
        rt->cancel_flag.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(s.audits_mtx);
            s.audits.erase(rt->status.id);
        }
        diag::log_tagged_fmt("scanner", "enqueue_target worker_post_failed audit_id=%llu",
            static_cast<unsigned long long>(rt->status.id));
        set_err("active_scanner.enqueue: worker queue unavailable");
        return 0;
    }

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
    {
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        rt->status.cancel_requested = true;
    }
    rt->cancel_cv.notify_all();
    diag::log_tagged_fmt("scanner", "cancel_audit id=%llu cancel_flag_set", static_cast<unsigned long long>(audit_id));
    return true;
}

bool wait_for_audit_idle(uint64_t audit_id, uint32_t timeout_ms)
{
    diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu timeout_ms=%u",
        static_cast<unsigned long long>(audit_id),
        timeout_ms);
    auto& s = state();
    std::shared_ptr<audit_runtime_t> rt;
    {
        std::lock_guard<std::mutex> lk(s.audits_mtx);
        auto it = s.audits.find(audit_id);
        if (it == s.audits.end()) {
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu not_found",
                static_cast<unsigned long long>(audit_id));
            return false;
        }
        rt = it->second;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
        bool running = false;
        {
            std::lock_guard<std::mutex> lk(rt->status_mtx);
            running = rt->status.running;
        }
        if (!running && active_workers == 0 && in_flight == 0) {
            {
                std::lock_guard<std::mutex> lk(rt->status_mtx);
                rt->status.drained = true;
            }
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu idle",
                static_cast<unsigned long long>(audit_id));
            return true;
        }
        if (timeout_ms == 0 || std::chrono::steady_clock::now() >= deadline) {
            diag::log_tagged_fmt("scanner", "wait_for_audit_idle id=%llu timeout running=%d active_workers=%zu in_flight=%zu",
                static_cast<unsigned long long>(audit_id),
                running ? 1 : 0,
                active_workers,
                in_flight);
            return false;
        }
        std::unique_lock<std::mutex> lk(rt->status_mtx);
        rt->cancel_cv.wait_for(lk, std::chrono::milliseconds(50));
    }
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
        const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
        const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
        const size_t queued_workers = rt->queued_workers.load(std::memory_order_acquire);
        std::lock_guard<std::mutex> lk(rt->status_mtx);
        audit_status_t st = rt->status;
        st.cancel_requested = st.cancel_requested || rt->cancel_flag.load(std::memory_order_acquire);
        st.drained = !st.running && active_workers == 0 && in_flight == 0;
        st.active_workers = active_workers;
        st.queued_workers = queued_workers;
        st.in_flight_requests = in_flight;
        if (st.cancel_requested)
            rt->status.cancel_requested = true;
        if (st.drained)
            rt->status.drained = true;
        out.push_back(std::move(st));
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
    const size_t active_workers = rt->active_workers.load(std::memory_order_acquire);
    const size_t in_flight = rt->in_flight.load(std::memory_order_acquire);
    const size_t queued_workers = rt->queued_workers.load(std::memory_order_acquire);
    std::lock_guard<std::mutex> lk(rt->status_mtx);
    out = rt->status;
    out.cancel_requested = out.cancel_requested || rt->cancel_flag.load(std::memory_order_acquire);
    out.drained = !out.running && active_workers == 0 && in_flight == 0;
    out.active_workers = active_workers;
    out.queued_workers = queued_workers;
    out.in_flight_requests = in_flight;
    if (out.drained)
        rt->status.drained = true;
    if (out.cancel_requested)
        rt->status.cancel_requested = true;
    diag::log_tagged_fmt("scanner", "get_status id=%llu running=%d issues=%zu completed=%zu total=%zu cancel_requested=%d drained=%d req_len=%zu queued_workers=%zu active_workers=%zu in_flight=%zu tid=%lu",
        static_cast<unsigned long long>(audit_id), out.running ? 1 : 0,
        out.issues_found, out.completed_probes, out.total_probes,
        out.cancel_requested ? 1 : 0,
        out.drained ? 1 : 0,
        out.request_length,
        queued_workers,
        active_workers,
        in_flight,
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

scanner_load_t load_snapshot()
{
    const auto load = collect_load_snapshot();
    diag::log_tagged_fmt("scanner", "load_snapshot active_audits=%zu running_audits=%zu queue_depth=%zu active_workers=%zu in_flight=%zu max_active=%zu shutting_down=%d tid=%lu",
        load.active_audits,
        load.running_audits,
        load.queue_depth,
        load.active_workers,
        load.in_flight_requests,
        load.max_active_audits,
        load.shutting_down ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()));
    return load;
}

std::string last_error()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error;
}

std::string last_error_code()
{
    auto& s = state();
    std::lock_guard<std::mutex> lk(s.err_mtx);
    return s.last_error_code;
}

}
}
}
