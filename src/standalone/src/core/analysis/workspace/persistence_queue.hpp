#pragma once

#include "analysis_workspace.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <string>

namespace aida::analysis {

class workspace_persistence_candidate_t;

struct persistence_queue_limits_t {
    std::size_t max_pending_operations = 1024;
    std::uint64_t max_pending_bytes = 1ULL << 30;
    std::size_t max_operations_per_drain = 64;
    std::chrono::milliseconds max_drain_wall_time{25};
};

using persistence_operation_t =
    std::function<workspace_result_t<void>(const cancellation_token_t&)>;

struct persistence_commit_metrics_t {
    std::uint64_t logical_bytes = 0;
    std::uint64_t rows = 0;
    std::uint64_t page_write_bytes = 0;
    std::uint64_t elapsed_us = 0;
};

struct persistence_ticket_t {
    std::uint64_t sequence = 0;
    bool accepted = false;
    std::shared_future<workspace_result_t<void>> completion;
    std::shared_ptr<const persistence_commit_metrics_t> commit_metrics;
    std::shared_ptr<const workspace_persistence_candidate_t> snapshot_candidate;
};

struct persistence_queue_snapshot_t {
    std::uint64_t submitted = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t rejected = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t drain_tasks = 0;
    std::size_t pending = 0;
    std::uint64_t pending_bytes = 0;
    std::uint64_t active_bytes = 0;
    bool accepting = false;
    bool drain_active = false;
};

class persistence_queue_t final : public workspace_lifecycle_participant_t,
                                  public std::enable_shared_from_this<persistence_queue_t> {
public:
    struct state_t;

    static workspace_result_t<std::shared_ptr<persistence_queue_t>>
        create(binary_id_t workspace_id, persistence_queue_limits_t limits = {});

    ~persistence_queue_t() override;
    persistence_queue_t(const persistence_queue_t&) = delete;
    persistence_queue_t& operator=(const persistence_queue_t&) = delete;

    persistence_ticket_t enqueue(std::string label, persistence_operation_t operation,
                                 cancellation_token_t cancel = {},
                                 std::uint64_t reservation_bytes = 0);
    persistence_queue_snapshot_t snapshot() const;
    bool idle() const;

    void request_cancel() noexcept override;
    workspace_result_t<void>
        drain(std::chrono::steady_clock::time_point deadline) override;

private:
    explicit persistence_queue_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
