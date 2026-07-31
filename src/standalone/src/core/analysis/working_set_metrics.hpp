#pragma once

#include "workspace/analysis_metrics.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace aida::analysis::working_set_metrics {

struct process_sample_t {
    std::uint64_t working_set_bytes = 0;
    std::uint64_t peak_working_set_bytes = 0;
    std::uint64_t private_bytes = 0;
    std::uint64_t peak_private_bytes = 0;
    std::uint64_t pagefile_bytes = 0;
    std::uint64_t peak_pagefile_bytes = 0;
    std::uint64_t sampled_steady_ns = 0;
};

process_sample_t sample_process_memory() noexcept;

enum class subsystem_t : std::uint8_t {
    mapped_windows = 0,
    fact_page_cache,
    resident_facts,
    persistence_staging,
    decode_transient,
    search_index,
    decompiler_memory,
    worker_snapshots,
    xref_arenas,
    sqlite_caches,
    ui_misc,
    count
};

inline constexpr std::size_t subsystem_count =
    static_cast<std::size_t>(subsystem_t::count);

const char* subsystem_name(subsystem_t subsystem) noexcept;

struct subsystem_ledger_snapshot_t {
    std::array<std::uint64_t, subsystem_count> bytes{};
    std::array<std::uint64_t, subsystem_count> peak_bytes{};
    std::uint64_t total_bytes = 0;
};

class subsystem_ledger_t final {
public:
    void add(subsystem_t subsystem, std::int64_t delta_bytes) noexcept;
    void set(subsystem_t subsystem, std::uint64_t bytes) noexcept;
    std::uint64_t value(subsystem_t subsystem) const noexcept;
    std::uint64_t peak(subsystem_t subsystem) const noexcept;
    std::uint64_t total() const noexcept;
    subsystem_ledger_snapshot_t snapshot() const noexcept;
    void reset() noexcept;

private:
    struct alignas(64) slot_t {
        std::atomic<std::uint64_t> bytes{0};
        std::atomic<std::uint64_t> peak_bytes{0};
    };

    static void publish_peak(slot_t& slot, std::uint64_t bytes) noexcept;

    std::array<slot_t, subsystem_count> slots_{};
};

subsystem_ledger_t& process_subsystem_ledger() noexcept;

struct commit_lag_snapshot_t {
    std::uint64_t samples = 0;
    std::uint64_t total_ns = 0;
    std::uint64_t max_ns = 0;
    std::uint64_t last_ns = 0;
};

void record_commit_lag(std::uint64_t lag_ns) noexcept;
commit_lag_snapshot_t commit_lag() noexcept;
void reset_commit_lag() noexcept;

class sampler_t final {
public:
    explicit sampler_t(
        std::chrono::milliseconds interval = std::chrono::milliseconds{250});
    ~sampler_t();

    sampler_t(const sampler_t&) = delete;
    sampler_t& operator=(const sampler_t&) = delete;

    workspace_result_t<void> start();
    void stop() noexcept;
    bool running() const noexcept;
    process_sample_t latest() const noexcept;
    process_sample_t sample_now() noexcept;
    void attach_metrics(std::shared_ptr<analysis_metrics_t> metrics) noexcept;
    std::chrono::milliseconds interval() const noexcept;

private:
    struct state_t;

    static void run(const std::shared_ptr<state_t>& state) noexcept;

    std::shared_ptr<state_t> state_;
};

sampler_t& process_sampler() noexcept;

}
