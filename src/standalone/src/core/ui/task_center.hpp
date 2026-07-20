#pragma once

#include "view_registry.hpp"
#include "../analysis/analysis_scheduler.hpp"
#include "../infra/taskflow_runtime.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace aida::ui::task_center {

enum class task_state_t : std::uint8_t {
    queued,
    running,
    cancellation_requested,
    completed,
    partial,
    cancelled,
    failed,
    timed_out,
    interrupted
};

enum class diagnostic_severity_t : std::uint8_t {
    information,
    warning,
    error,
    security
};

struct task_snapshot_t {
    std::string id;
    std::string source;
    std::string owner;
    std::string owner_view;
    std::string owner_action;
    std::string project;
    std::string session;
    std::string target;
    std::string label;
    std::string stage;
    std::string result_summary;
    std::string diagnostic_id;
    std::string log_link;
    std::string affected_entity;
    task_state_t state = task_state_t::queued;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t ended_ms = 0;
    std::uint64_t elapsed_ms = 0;
    float progress = -1.0f;
    bool cancellable = false;
    bool retryable = false;
    bool focusable = false;
    bool log_available = false;
    bool acknowledged = false;
    bool security_critical = false;
};

struct diagnostic_snapshot_t {
    std::string id;
    std::string task_id;
    std::string owner;
    std::string target;
    std::string summary;
    std::string details;
    std::string log_link;
    diagnostic_severity_t severity = diagnostic_severity_t::error;
    std::uint64_t raised_ms = 0;
    bool acknowledged = false;
    bool retryable = false;
    bool focusable = false;
    bool log_available = false;
};

struct status_summary_t {
    std::uint32_t queued = 0;
    std::uint32_t running = 0;
    std::uint32_t cancellation_requested = 0;
    std::uint32_t failures = 0;
    std::uint32_t interrupted = 0;
    std::uint32_t partial = 0;
    std::uint32_t unacknowledged_diagnostics = 0;
    std::uint64_t oldest_active_ms = 0;
    std::uint64_t generation = 0;
};

struct immutable_snapshot_t {
    std::vector<task_snapshot_t> tasks;
    std::vector<diagnostic_snapshot_t> diagnostics;
    status_summary_t status;
    std::uint64_t captured_ms = 0;
    std::uint64_t generation = 0;
};

using immutable_snapshot_ptr = std::shared_ptr<const immutable_snapshot_t>;

struct task_callbacks_t {
    std::function<bool()> cancel;
    std::function<bool()> retry;
    std::function<void()> focus;
    std::function<void()> open_log;
};

struct task_registration_t {
    std::string id;
    std::string source;
    std::string owner;
    std::string owner_view;
    std::string owner_action;
    std::string project;
    std::string session;
    std::string target;
    std::string label;
    std::string stage;
    std::string affected_entity;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    float progress = -1.0f;
    bool cancellation_is_safe = false;
    bool security_critical = false;
    task_callbacks_t callbacks;
};

struct diagnostic_registration_t {
    std::string id;
    std::string task_id;
    std::string owner;
    std::string target;
    std::string summary;
    std::string details;
    std::string log_link;
    diagnostic_severity_t severity = diagnostic_severity_t::error;
    std::uint64_t raised_ms = 0;
    task_callbacks_t callbacks;
};

bool register_task(task_registration_t registration);
bool register_taskflow_job(aida::infra::taskflow_runtime::job_handle_t handle,
                           task_registration_t registration);
bool register_executor_job(std::uint64_t task_id, task_registration_t registration);
bool try_register_executor_job(std::uint64_t task_id, task_registration_t registration);
bool register_analysis_task(std::shared_ptr<aida::analysis::analysis_scheduler_t> scheduler,
                            aida::analysis::analysis_task_id_t task_id,
                            task_registration_t registration);
bool update_task(const std::string& id, task_state_t state, float progress,
                 std::string stage, std::string result_summary = {},
                 std::string diagnostic_id = {}, std::string log_link = {});
bool raise_diagnostic(diagnostic_registration_t registration);
bool acknowledge_diagnostic(const std::string& id);
bool retry_diagnostic(const std::string& id);
bool focus_diagnostic(const std::string& id);
bool open_diagnostic_log(const std::string& id);
bool request_cancel(const std::string& task_id);
bool retry(const std::string& task_id);
bool focus(const std::string& task_id);
bool open_log(const std::string& task_id);
void refresh();
immutable_snapshot_ptr snapshot();
status_summary_t status_summary();
void clear_memory_history();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
void clear_preview_state();
#endif
void register_views(view_registry_t& registry);
void render_tasks_view(const view_render_context_t& context);
void render_diagnostics_view(const view_render_context_t& context);

}
