#include "working_set_governor.hpp"

#include "fact_page_cache.hpp"
#include "../../helpers/diag_log.hpp"

namespace aida::analysis {

namespace {

constexpr std::uint64_t kGovernorYellowPercent = 85ULL;
constexpr std::uint64_t kGovernorRedPercent = 95ULL;

std::uint64_t governor_steady_now_ns() noexcept {
    return analysis_metrics_t::steady_now_ns();
}

}

const char* governor_zone_name(governor_zone_t zone) noexcept {
    switch (zone) {
    case governor_zone_t::green:
        return "green";
    case governor_zone_t::yellow:
        return "yellow";
    case governor_zone_t::red:
        return "red";
    }
    return "unknown";
}

working_set_governor_t& working_set_governor_t::instance() noexcept {
    static working_set_governor_t governor;
    return governor;
}

working_set_governor_t::working_set_governor_t()
    : budgets_(governor_subsystem_budget_fields(host_memory_envelope())) {
    auto& ledger = working_set_metrics::process_subsystem_ledger();
    ledger.set(working_set_metrics::subsystem_t::sqlite_caches,
               budgets_.sqlite_caches_bytes);
    ledger.set(working_set_metrics::subsystem_t::ui_misc,
               budgets_.ui_misc_bytes);
    zone_entered_steady_ns_.store(governor_steady_now_ns(),
                                  std::memory_order_release);
    ::diag::log_tagged_fmt("memory_governor",
        "governor_budgets usable=%llu mapped=%llu page_cache=%llu resident=%llu staging=%llu decode=%llu search=%llu decompiler=%llu worker=%llu xref=%llu sqlite=%llu ui=%llu",
        static_cast<unsigned long long>(budgets_.process_budget_bytes),
        static_cast<unsigned long long>(budgets_.mapped_windows_bytes),
        static_cast<unsigned long long>(budgets_.fact_page_cache_bytes),
        static_cast<unsigned long long>(budgets_.resident_facts_bytes),
        static_cast<unsigned long long>(budgets_.persistence_staging_bytes),
        static_cast<unsigned long long>(budgets_.decode_transient_bytes),
        static_cast<unsigned long long>(budgets_.search_index_bytes),
        static_cast<unsigned long long>(budgets_.decompiler_memory_bytes),
        static_cast<unsigned long long>(budgets_.worker_snapshots_bytes),
        static_cast<unsigned long long>(budgets_.xref_arenas_bytes),
        static_cast<unsigned long long>(budgets_.sqlite_caches_bytes),
        static_cast<unsigned long long>(budgets_.ui_misc_bytes));
}

std::uint64_t working_set_governor_t::subsystem_budget(
    working_set_metrics::subsystem_t subsystem) const noexcept {
    switch (subsystem) {
    case working_set_metrics::subsystem_t::mapped_windows:
        return budgets_.mapped_windows_bytes;
    case working_set_metrics::subsystem_t::fact_page_cache:
        return budgets_.fact_page_cache_bytes;
    case working_set_metrics::subsystem_t::resident_facts:
        return budgets_.resident_facts_bytes;
    case working_set_metrics::subsystem_t::persistence_staging:
        return budgets_.persistence_staging_bytes;
    case working_set_metrics::subsystem_t::decode_transient:
        return budgets_.decode_transient_bytes;
    case working_set_metrics::subsystem_t::search_index:
        return budgets_.search_index_bytes;
    case working_set_metrics::subsystem_t::decompiler_memory:
        return budgets_.decompiler_memory_bytes;
    case working_set_metrics::subsystem_t::worker_snapshots:
        return budgets_.worker_snapshots_bytes;
    case working_set_metrics::subsystem_t::xref_arenas:
        return budgets_.xref_arenas_bytes;
    case working_set_metrics::subsystem_t::sqlite_caches:
        return budgets_.sqlite_caches_bytes;
    case working_set_metrics::subsystem_t::ui_misc:
        return budgets_.ui_misc_bytes;
    case working_set_metrics::subsystem_t::count:
        break;
    }
    return 0;
}

std::uint64_t working_set_governor_t::process_budget_bytes() const noexcept {
    return budgets_.process_budget_bytes;
}

governor_zone_t working_set_governor_t::zone() const noexcept {
    const auto value = zone_value_.load(std::memory_order_acquire);
    return static_cast<governor_zone_t>(value > 2 ? 2 : value);
}

governor_zone_t working_set_governor_t::compute_zone(
    std::uint64_t ledger_total) const noexcept {
    const std::uint64_t budget = budgets_.process_budget_bytes;
    if (budget == 0)
        return governor_zone_t::green;
    if (ledger_total >= (budget / 100ULL) * kGovernorRedPercent +
            ((budget % 100ULL) * kGovernorRedPercent) / 100ULL)
        return governor_zone_t::red;
    if (ledger_total >= (budget / 100ULL) * kGovernorYellowPercent +
            ((budget % 100ULL) * kGovernorYellowPercent) / 100ULL)
        return governor_zone_t::yellow;
    return governor_zone_t::green;
}

governor_zone_t working_set_governor_t::refresh() noexcept {
    const std::uint64_t total =
        working_set_metrics::process_subsystem_ledger().total();
    std::uint64_t peak = ledger_peak_bytes_.load(std::memory_order_relaxed);
    while (peak < total &&
           !ledger_peak_bytes_.compare_exchange_weak(
               peak, total, std::memory_order_release,
               std::memory_order_relaxed)) {
    }
    const governor_zone_t computed = compute_zone(total);
    apply_zone(computed);
    return zone();
}

void working_set_governor_t::apply_zone(governor_zone_t zone) noexcept {
    const auto target = static_cast<std::uint64_t>(zone);
    std::uint64_t current = zone_value_.load(std::memory_order_acquire);
    if (current == target) {
        workspace_io_metrics().set(workspace_io_metric_t::governor_zone, target);
        return;
    }
    std::lock_guard<std::mutex> lock(transition_mutex_);
    current = zone_value_.load(std::memory_order_acquire);
    if (current == target)
        return;
    zone_value_.store(target, std::memory_order_release);
    zone_transitions_.fetch_add(1, std::memory_order_relaxed);
    zone_entered_steady_ns_.store(governor_steady_now_ns(),
                                  std::memory_order_release);
    apply_zone_transition(static_cast<governor_zone_t>(current), zone);
}

void working_set_governor_t::apply_zone_transition(
    governor_zone_t from, governor_zone_t to) noexcept {
    workspace_io_metrics().set(workspace_io_metric_t::governor_zone,
                               static_cast<std::uint64_t>(to));
    auto& page_cache = fact_page_cache_t::instance();
    switch (to) {
    case governor_zone_t::green:
        page_cache.set_ceiling(budgets_.fact_page_cache_bytes);
        break;
    case governor_zone_t::yellow:
        page_cache.set_ceiling(budgets_.fact_page_cache_bytes / 2ULL);
        break;
    case governor_zone_t::red:
        page_cache.set_ceiling(0);
        page_cache.trim();
        break;
    }
    ::diag::log_tagged_fmt("memory_governor",
        "governor_zone_transition from=%s to=%s ledger_total=%llu budget=%llu transitions=%llu",
        governor_zone_name(from), governor_zone_name(to),
        static_cast<unsigned long long>(
            working_set_metrics::process_subsystem_ledger().total()),
        static_cast<unsigned long long>(budgets_.process_budget_bytes),
        static_cast<unsigned long long>(
            zone_transitions_.load(std::memory_order_relaxed)));
}

bool working_set_governor_t::check(
    working_set_metrics::subsystem_t subsystem, std::uint64_t bytes) noexcept {
    const std::uint64_t budget = subsystem_budget(subsystem);
    const std::uint64_t current =
        working_set_metrics::process_subsystem_ledger().value(subsystem);
    if (bytes <= budget && current <= budget - bytes)
        return true;
    rejections_.fetch_add(1, std::memory_order_relaxed);
    workspace_io_metrics().add(workspace_io_metric_t::governor_rejections, 1);
    ::diag::log_tagged_fmt("memory_governor",
        "governor_admission_rejected subsystem=%s current=%llu requested=%llu budget=%llu zone=%s",
        working_set_metrics::subsystem_name(subsystem),
        static_cast<unsigned long long>(current),
        static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(budget),
        governor_zone_name(zone()));
    return false;
}

bool working_set_governor_t::admit(
    working_set_metrics::subsystem_t subsystem, std::uint64_t bytes) noexcept {
    if (!check(subsystem, bytes))
        return false;
    working_set_metrics::process_subsystem_ledger().add(
        subsystem, static_cast<std::int64_t>(bytes));
    return true;
}

void working_set_governor_t::charge(
    working_set_metrics::subsystem_t subsystem,
    std::int64_t delta_bytes) noexcept {
    working_set_metrics::process_subsystem_ledger().add(subsystem, delta_bytes);
}

void working_set_governor_t::note(
    working_set_metrics::subsystem_t subsystem, std::uint64_t bytes) noexcept {
    working_set_metrics::process_subsystem_ledger().set(subsystem, bytes);
}

std::uint64_t working_set_governor_t::search_index_budget_bytes() const noexcept {
    return budgets_.search_index_bytes;
}

governor_snapshot_t working_set_governor_t::snapshot() const noexcept {
    governor_snapshot_t result;
    result.zone = zone();
    result.ledger_total_bytes =
        working_set_metrics::process_subsystem_ledger().total();
    result.process_budget_bytes = budgets_.process_budget_bytes;
    result.ledger_peak_bytes = ledger_peak_bytes_.load(std::memory_order_relaxed);
    result.zone_transitions = zone_transitions_.load(std::memory_order_relaxed);
    result.rejections = rejections_.load(std::memory_order_relaxed);
    result.zone_entered_steady_ns =
        zone_entered_steady_ns_.load(std::memory_order_relaxed);
    return result;
}

}
