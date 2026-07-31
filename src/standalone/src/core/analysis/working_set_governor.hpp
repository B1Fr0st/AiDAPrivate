#pragma once

#include "analysis_budget.hpp"
#include "working_set_metrics.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>

namespace aida::analysis {

enum class governor_zone_t : std::uint8_t {
    green = 0,
    yellow = 1,
    red = 2
};

const char* governor_zone_name(governor_zone_t zone) noexcept;

struct governor_snapshot_t final {
    governor_zone_t zone = governor_zone_t::green;
    std::uint64_t ledger_total_bytes = 0;
    std::uint64_t process_budget_bytes = 0;
    std::uint64_t ledger_peak_bytes = 0;
    std::uint64_t zone_transitions = 0;
    std::uint64_t rejections = 0;
    std::uint64_t zone_entered_steady_ns = 0;
};

class working_set_governor_t final {
public:
    static working_set_governor_t& instance() noexcept;

    working_set_governor_t(const working_set_governor_t&) = delete;
    working_set_governor_t& operator=(const working_set_governor_t&) = delete;

    std::uint64_t subsystem_budget(
        working_set_metrics::subsystem_t subsystem) const noexcept;
    std::uint64_t process_budget_bytes() const noexcept;
    governor_zone_t zone() const noexcept;
    governor_zone_t refresh() noexcept;
    bool check(working_set_metrics::subsystem_t subsystem,
               std::uint64_t bytes) noexcept;
    bool admit(working_set_metrics::subsystem_t subsystem,
               std::uint64_t bytes) noexcept;
    void charge(working_set_metrics::subsystem_t subsystem,
                std::int64_t delta_bytes) noexcept;
    void note(working_set_metrics::subsystem_t subsystem,
              std::uint64_t bytes) noexcept;
    std::uint64_t search_index_budget_bytes() const noexcept;
    governor_snapshot_t snapshot() const noexcept;

private:
    working_set_governor_t();

    governor_zone_t compute_zone(std::uint64_t ledger_total) const noexcept;
    void apply_zone(governor_zone_t zone) noexcept;
    void apply_zone_transition(governor_zone_t from,
                               governor_zone_t to) noexcept;

    governor_subsystem_budget_fields_t budgets_;
    std::atomic<std::uint64_t> zone_value_{0};
    std::atomic<std::uint64_t> zone_entered_steady_ns_{0};
    std::atomic<std::uint64_t> zone_transitions_{0};
    std::atomic<std::uint64_t> rejections_{0};
    std::atomic<std::uint64_t> ledger_peak_bytes_{0};
    std::mutex transition_mutex_;
};

}
