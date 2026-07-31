#pragma once

#include "analysis_resource_metrics.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace aida::analysis {

inline constexpr std::uint32_t analysis_fabric_metrics_schema_version = 1;
inline constexpr std::size_t analysis_fabric_domain_count = 9;
inline constexpr std::size_t analysis_fabric_priority_lane_count = 8;

struct analysis_fabric_domain_snapshot_t final {
    std::uint64_t queue_depth = 0;
    std::uint64_t in_flight = 0;
    std::uint64_t busy_worker_ms = 0;
    std::uint64_t posted = 0;
    std::uint64_t started = 0;
    std::uint64_t finished = 0;
    std::uint64_t rejected = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t failed = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t active = 0;
    std::uint64_t workers = 0;
    std::uint64_t oldest_active_ms = 0;
    std::uint64_t fairness_wait_ns_total = 0;
    std::array<std::uint64_t, analysis_fabric_priority_lane_count> lane_depth{};
    std::array<std::uint64_t, analysis_fabric_priority_lane_count> lane_admitted{};
};

struct analysis_fabric_metrics_snapshot_t final {
    std::uint32_t schema_version = analysis_fabric_metrics_schema_version;
    std::uint64_t generation = 0;
    std::uint64_t sample_sequence = 0;
    std::uint64_t sampler_running = 0;
    std::uint64_t watchdog_lag_ms = 0;
    std::uint64_t watchdog_registered = 0;
    std::uint64_t watchdog_fired = 0;
    std::array<analysis_fabric_domain_snapshot_t, analysis_fabric_domain_count> domains{};

    std::string to_json() const;
};

class analysis_fabric_metrics_t final {
public:
    static analysis_fabric_metrics_t& instance() noexcept;

    analysis_fabric_metrics_t(const analysis_fabric_metrics_t&) = delete;
    analysis_fabric_metrics_t& operator=(const analysis_fabric_metrics_t&) = delete;
    analysis_fabric_metrics_t(analysis_fabric_metrics_t&&) = delete;
    analysis_fabric_metrics_t& operator=(analysis_fabric_metrics_t&&) = delete;

    void ensure_sampler_started() noexcept;
    bool sampler_running() const noexcept;
    void stop_sampler() noexcept;
    analysis_fabric_metrics_snapshot_t snapshot() const noexcept;
    std::shared_ptr<analysis_resource_metrics_t> resource_metrics() const noexcept;

private:
    analysis_fabric_metrics_t() = default;
    ~analysis_fabric_metrics_t() = default;
};

analysis_fabric_metrics_snapshot_t analysis_fabric_metrics_snapshot() noexcept;

}
