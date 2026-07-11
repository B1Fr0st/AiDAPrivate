#pragma once

#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>

namespace aida::network::executor_status {

namespace runtime = ::aida::infra::taskflow_runtime;
namespace executor = ::aida::infra::executor;

struct aggregate_stats_t {
    bool alive = false;
    bool shutting_down = false;
    int pool_size = 0;
    std::size_t workers = 0;
    std::uint64_t pending = 0;
    std::uint32_t active = 0;
    std::uint64_t post_attempts = 0;
    std::uint64_t posted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t started = 0;
    std::uint64_t finished = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t failed = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t oldest_active_ms = 0;
    std::uint32_t active_label_count = 0;
    std::string active_labels;
    nlohmann::json domains = nlohmann::json::array();
};

inline void merge_stats(aggregate_stats_t& out, const runtime::stats_t& s, runtime::executor_domain_t domain)
{
    out.alive = out.alive || s.alive;
    out.shutting_down = out.shutting_down || s.shutting_down;
    out.pool_size += s.pool_size;
    out.workers += s.workers;
    out.pending += static_cast<std::uint64_t>(s.pending);
    out.active += s.active;
    out.post_attempts += s.post_attempts;
    out.posted += s.posted;
    out.rejected += s.rejected;
    out.started += s.started;
    out.finished += s.finished;
    out.cancelled += s.cancelled;
    out.failed += s.failed;
    out.timed_out += s.timed_out;
    if (s.oldest_active_ms > out.oldest_active_ms)
        out.oldest_active_ms = s.oldest_active_ms;
    out.active_label_count += s.active_label_count;
    if (!s.active_labels.empty()) {
        if (!out.active_labels.empty())
            out.active_labels += ";";
        out.active_labels += s.active_labels;
    }
    out.domains.push_back({
        {"name", runtime::domain_name(domain)},
        {"alive", s.alive},
        {"shutting_down", s.shutting_down},
        {"pool_size", s.pool_size},
        {"workers", static_cast<std::uint64_t>(s.workers)},
        {"pending", static_cast<std::uint64_t>(s.pending)},
        {"active", s.active},
        {"post_attempts", s.post_attempts},
        {"posted", s.posted},
        {"rejected", s.rejected},
        {"started", s.started},
        {"finished", s.finished},
        {"cancelled", s.cancelled},
        {"failed", s.failed},
        {"timed_out", s.timed_out},
        {"oldest_active_ms", s.oldest_active_ms},
        {"active_label_count", s.active_label_count},
        {"active_labels", s.active_labels}
    });
}

inline aggregate_stats_t aggregate(std::initializer_list<runtime::executor_domain_t> domains)
{
    aggregate_stats_t out;
    for (runtime::executor_domain_t domain : domains)
        merge_stats(out, runtime::domain_stats(domain), domain);
    return out;
}

inline nlohmann::json to_json(const aggregate_stats_t& s)
{
    const auto exec = executor::active_snapshot();
    const auto rt = runtime::active_snapshot(32);
    nlohmann::json j;
    j["alive"] = s.alive;
    j["shutting_down"] = s.shutting_down;
    j["pool_size"] = s.pool_size;
    j["workers"] = static_cast<std::uint64_t>(s.workers);
    j["pending"] = s.pending;
    j["active"] = s.active;
    j["post_attempts"] = s.post_attempts;
    j["posted"] = s.posted;
    j["rejected"] = s.rejected;
    j["started"] = s.started;
    j["finished"] = s.finished;
    j["cancelled"] = s.cancelled;
    j["failed"] = s.failed;
    j["timed_out"] = s.timed_out;
    j["oldest_active_ms"] = s.oldest_active_ms;
    j["active_label_count"] = s.active_label_count;
    j["active_labels"] = s.active_labels;
    j["domains"] = s.domains;
    j["executor_total_active"] = exec.total_active;
    j["executor_oldest_active_ms"] = exec.oldest_active_ms;
    j["executor_labels_under_pressure"] = exec.labels_under_pressure;
    j["runtime_total_submitted"] = rt.total_submitted;
    j["runtime_total_rejected"] = rt.total_rejected;
    j["runtime_total_cancelled"] = rt.total_cancelled;
    j["runtime_total_failed"] = rt.total_failed;
    j["runtime_total_timed_out"] = rt.total_timed_out;
    j["runtime_accepting"] = rt.accepting;
    return j;
}

inline aggregate_stats_t work_stats()
{
    return aggregate({
        runtime::executor_domain_t::general,
        runtime::executor_domain_t::ui_dispatch,
        runtime::executor_domain_t::external_tool,
        runtime::executor_domain_t::feature_worker,
        runtime::executor_domain_t::diagnostics
    });
}

inline aggregate_stats_t service_stats()
{
    return aggregate({
        runtime::executor_domain_t::service,
        runtime::executor_domain_t::long_running
    });
}

inline aggregate_stats_t critical_stats()
{
    return aggregate({
        runtime::executor_domain_t::critical,
        runtime::executor_domain_t::security_liveness
    });
}

inline nlohmann::json work_json()
{
    return to_json(work_stats());
}

inline nlohmann::json service_json()
{
    return to_json(service_stats());
}

inline nlohmann::json critical_json()
{
    return to_json(critical_stats());
}

inline void attach_executor_snapshots(nlohmann::json& j)
{
    j["executor_work"] = work_json();
    j["executor_service"] = service_json();
    j["executor_critical"] = critical_json();
}

inline std::uint64_t work_pending()
{
    return work_stats().pending;
}

inline std::uint32_t work_active()
{
    return work_stats().active;
}

inline std::uint64_t service_pending()
{
    return service_stats().pending;
}

inline std::uint32_t service_active()
{
    return service_stats().active;
}

inline std::uint64_t critical_pending()
{
    return critical_stats().pending;
}

inline std::uint32_t critical_active()
{
    return critical_stats().active;
}

}
