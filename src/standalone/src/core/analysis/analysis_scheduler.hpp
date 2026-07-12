#pragma once

#include "analysis_budget.hpp"
#include "analysis_resource_metrics.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis {

inline constexpr std::size_t analysis_execution_domain_count = 5;
inline constexpr std::size_t max_analysis_task_label_bytes = 128;

enum class analysis_execution_domain_t : std::uint8_t {
    control = 0,
    interactive = 1,
    foreground = 2,
    background = 3,
    maintenance = 4
};

enum class analysis_priority_t : std::uint8_t {
    control = 0,
    interactive = 1,
    foreground = 2,
    background = 3,
    maintenance = 4
};

enum class analysis_task_state_t : std::uint8_t {
    queued = 1,
    dispatched = 2,
    running = 3,
    completed = 4,
    cancelled = 5,
    failed = 6
};

enum class analysis_task_completion_t : std::uint8_t {
    completed = 1,
    cancelled = 2,
    failed = 3
};

enum class analysis_scheduler_error_code_t : std::uint16_t {
    none = 0,
    invalid_scheduler_configuration = 1,
    invalid_clock = 2,
    invalid_domain = 3,
    missing_task_body = 4,
    task_label_too_long = 5,
    scheduler_stopped = 6,
    task_id_exhausted = 7,
    resource_rejected = 8,
    task_not_found = 9,
    task_not_queued = 10,
    task_not_active = 11,
    task_terminal = 12,
    dispatch_not_owned = 13,
    checkpoint_interval_exceeded = 14,
    clock_regressed = 15,
    priority_policy_violation = 16,
    internal_invariant_violation = 17
};

struct analysis_priority_reservation_policy_t final {
    bool strict_priority = true;
    bool no_priority_inversion = true;
    bool control_capacity_reserved = true;
    bool control_capacity_borrowing = false;
    std::uint32_t reserved_control_worker_slots = 0;
};

struct analysis_scheduler_error_t final {
    analysis_scheduler_error_code_t code = analysis_scheduler_error_code_t::none;
    std::string_view stable_code = "ok";
    analysis_task_id_t task_id = 0;
    analysis_resource_error_t resource_error;

    constexpr bool ok() const noexcept { return code == analysis_scheduler_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

std::string_view analysis_execution_domain_name(analysis_execution_domain_t domain) noexcept;
std::string_view analysis_task_state_name(analysis_task_state_t state) noexcept;
std::string_view analysis_scheduler_error_code_name(analysis_scheduler_error_code_t code) noexcept;
bool is_valid_analysis_execution_domain(analysis_execution_domain_t domain) noexcept;
analysis_priority_t analysis_priority_for_domain(analysis_execution_domain_t domain) noexcept;
analysis_priority_reservation_policy_t analysis_priority_reservation_policy(const analysis_budget_t& budget) noexcept;
analysis_task_id_t make_analysis_task_id(std::uint32_t scheduler_id, std::uint32_t ordinal) noexcept;

class analysis_clock_t {
public:
    virtual ~analysis_clock_t() = default;
    virtual std::uint64_t now_milliseconds() const noexcept = 0;
};

struct analysis_scheduler_configuration_t final {
    std::uint32_t scheduler_id = 0;
    std::uint32_t max_retained_terminal_tasks = 2048;
    analysis_budget_t budget;
};

struct analysis_task_context_state_t;
struct analysis_task_dispatch_state_t;
struct analysis_scheduler_state_t;

struct analysis_checkpoint_result_t final {
    bool cancellation_requested = false;
    bool interval_exceeded = false;
    analysis_scheduler_error_t error;
};

class analysis_task_context_t final {
public:
    analysis_task_context_t() = default;

    analysis_task_id_t task_id() const noexcept;
    bool cancellation_requested() const noexcept;
    analysis_checkpoint_result_t checkpoint() const noexcept;
    bool valid() const noexcept;

private:
    explicit analysis_task_context_t(std::shared_ptr<analysis_task_context_state_t> state);

    std::shared_ptr<analysis_task_context_state_t> state_;

    friend class analysis_scheduler_t;
};

using analysis_task_body_t = std::function<void(const analysis_task_context_t&)>;

struct analysis_task_request_t final {
    analysis_execution_domain_t domain = analysis_execution_domain_t::background;
    analysis_resource_demand_t resources;
    std::string label;
    analysis_task_body_t body;
};

class analysis_task_dispatch_t final {
public:
    analysis_task_dispatch_t() = default;

    analysis_task_id_t task_id() const noexcept;
    analysis_execution_domain_t domain() const noexcept;
    analysis_priority_t priority() const noexcept;
    bool valid() const noexcept;
    std::function<void()> taskflow_callable() const;

private:
    explicit analysis_task_dispatch_t(std::shared_ptr<analysis_task_dispatch_state_t> state);

    std::shared_ptr<analysis_task_dispatch_state_t> state_;

    friend class analysis_scheduler_t;
};

struct analysis_submit_result_t final {
    analysis_task_id_t task_id = 0;
    analysis_scheduler_error_t error;

    constexpr bool accepted() const noexcept { return error.ok() && task_id != 0; }
};

struct analysis_dispatch_result_t final {
    analysis_task_dispatch_t dispatch;
    analysis_scheduler_error_t error;

    bool available() const noexcept;
};

struct analysis_cancellation_result_t final {
    std::uint32_t queued_cancelled = 0;
    std::uint32_t active_signalled = 0;
    analysis_scheduler_error_t error;
};

struct analysis_task_snapshot_t final {
    analysis_task_id_t task_id = 0;
    analysis_execution_domain_t domain = analysis_execution_domain_t::background;
    analysis_priority_t priority = analysis_priority_t::background;
    analysis_task_state_t state = analysis_task_state_t::queued;
    bool cancellation_requested = false;
    std::uint64_t submitted_milliseconds = 0;
    std::uint64_t dispatched_milliseconds = 0;
    std::uint64_t started_milliseconds = 0;
    std::uint64_t last_checkpoint_milliseconds = 0;
    std::uint64_t completed_milliseconds = 0;
    analysis_resource_demand_t resources;
    std::string label;
};

struct analysis_task_snapshot_result_t final {
    analysis_task_snapshot_t task;
    analysis_scheduler_error_t error;

    constexpr bool found() const noexcept { return error.ok() && task.task_id != 0; }
};

struct analysis_scheduler_snapshot_t final {
    bool accepting = false;
    analysis_priority_reservation_policy_t policy;
    analysis_budget_snapshot_t budget;
    std::array<std::uint32_t, analysis_execution_domain_count> queued_per_domain{};
    std::array<std::uint32_t, analysis_execution_domain_count> active_per_domain{};
    std::uint32_t overdue_checkpoint_count = 0;
    std::uint32_t retained_terminal_tasks = 0;
    std::uint32_t next_task_ordinal = 0;
};

class analysis_scheduler_t final {
public:
    analysis_scheduler_t(analysis_scheduler_configuration_t configuration,
        std::shared_ptr<analysis_clock_t> clock,
        std::shared_ptr<analysis_resource_metrics_t> metrics = {});
    ~analysis_scheduler_t();

    analysis_scheduler_t(const analysis_scheduler_t&) = delete;
    analysis_scheduler_t& operator=(const analysis_scheduler_t&) = delete;
    analysis_scheduler_t(analysis_scheduler_t&&) = delete;
    analysis_scheduler_t& operator=(analysis_scheduler_t&&) = delete;

    analysis_scheduler_error_t configuration_error() const noexcept;
    analysis_submit_result_t submit(analysis_task_request_t request);
    analysis_dispatch_result_t acquire_next();
    analysis_scheduler_error_t requeue(const analysis_task_dispatch_t& dispatch);
    analysis_cancellation_result_t cancel_task(analysis_task_id_t task_id);
    analysis_cancellation_result_t cancel_domain(analysis_execution_domain_t domain);
    analysis_cancellation_result_t shutdown();
    void stop_accepting() noexcept;
    analysis_task_snapshot_result_t task_snapshot(analysis_task_id_t task_id) const;
    analysis_scheduler_snapshot_t snapshot() const;
    analysis_resource_metrics_snapshot_t metrics_snapshot() const noexcept;
    std::vector<analysis_task_id_t> overdue_checkpoint_tasks() const;
    analysis_scheduler_error_t verify_invariants() const;

private:
    std::shared_ptr<analysis_scheduler_state_t> state_;
};

}
