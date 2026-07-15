#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace aida::infra::taskflow_runtime {

enum class pool_family_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2
};

enum class executor_domain_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2,
    ui_dispatch = 3,
    external_tool = 4,
    long_running = 5,
    security_liveness = 6,
    feature_worker = 7,
    diagnostics = 8
};

inline constexpr std::size_t executor_domain_count = 9;

enum class job_state_t : std::uint8_t {
    queued = 0,
    not_started = 1,
    running = 2,
    completed = 3,
    cancelled = 4,
    failed = 5,
    timed_out = 6
};

struct cancellation_token_t {
    std::atomic<bool> requested{false};
};

struct job_handle_t {
    std::uint64_t id = 0;
    bool valid() const noexcept { return id != 0; }
};

struct task_descriptor_t {
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
    std::function<void()> cancel_hook;
    executor_domain_t domain = executor_domain_t::general;
    const char* owner_subsystem = nullptr;
    const char* label = nullptr;
    const char* thread_class = nullptr;
    const char* session_id = nullptr;
    const char* target_id = nullptr;
    const char* diagnostic_id = nullptr;
    const char* request_id = nullptr;
    const char* ui_access_policy = "none";
    const char* failure_policy = "reject_not_started";
    const char* shutdown_policy = "drain";
    const char* no_capacity_reason = nullptr;
    int priority = 3;
    std::uint32_t target_pid = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
};

struct graph_node_descriptor_t {
    std::uint64_t node_id = 0;
    const char* label = nullptr;
    std::vector<std::uint64_t> depends_on;
    std::function<void()> body;
    std::function<void(const cancellation_token_t&)> cancellable_body;
};

struct graph_descriptor_t {
    executor_domain_t domain = executor_domain_t::general;
    const char* owner_subsystem = nullptr;
    const char* label = nullptr;
    const char* phase = nullptr;
    const char* session_id = nullptr;
    const char* target_id = nullptr;
    const char* diagnostic_id = nullptr;
    const char* request_id = nullptr;
    std::function<void()> cancel_hook;
    int priority = 3;
    std::uint32_t target_pid = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t generation = 0;
    std::vector<graph_node_descriptor_t> nodes;
};

struct submit_result_t {
    bool submitted = false;
    job_handle_t handle;
    std::string reject_reason;
};

struct wait_result_t {
    bool completed = false;
    bool timed_out = false;
    bool rejected = false;
    bool cancelled = false;
    bool failed = false;
};

struct task_t {
    std::function<void()> fn;
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
};

struct active_task_t {
    std::string label;
    std::uint64_t id = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t last_cpu_100ns = 0;
    std::uint64_t last_cpu_sample_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    std::uint32_t thread_query_gle = 0;
    std::uint32_t exit_code = 0;
    std::uint32_t tid = 0;
    bool thread_alive = false;
};

struct stats_t {
    bool alive = false;
    bool shutting_down = false;
    int pool_size = 0;
    std::size_t workers = 0;
    std::size_t pending = 0;
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
    std::uint32_t healthy_long_lived = 0;
    std::uint32_t hot_workers = 0;
    std::uint32_t not_queryable_workers = 0;
    std::string active_labels;
    std::string top_cpu_labels;
};

struct stuck_worker_diag_t {
    std::uint64_t task_id = 0;
    std::string label;
    const char* label_class = "general";
    const char* lifetime = "bounded_task";
    const char* health = "needs_progress";
    std::uint32_t tid = 0;
    std::uint32_t thread_query_gle = 0;
    std::uint32_t exit_code = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t active_ms = 0;
    std::uint64_t cpu_delta_100ns = 0;
    std::uint32_t cpu_pct_x100 = 0;
    std::size_t worker_index = 0;
    bool thread_alive = false;
};

struct active_job_snapshot_t {
    std::uint64_t job_id = 0;
    executor_domain_t domain = executor_domain_t::general;
    job_state_t state = job_state_t::queued;
    std::string label;
    std::string owner_subsystem;
    std::string exception_text;
    std::string target_id;
    int priority = 3;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    std::uint64_t queued_ns = 0;
    std::uint64_t started_ns = 0;
    std::uint64_t fairness_wait_ns = 0;
    std::uint64_t service_units = 0;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    std::uint64_t active_ms = 0;
    std::uint32_t node_count = 0;
    bool graph = false;
    bool cancellation_requested = false;
};

struct runtime_snapshot_t {
    std::uint64_t total_submitted = 0;
    std::uint64_t total_rejected = 0;
    std::uint64_t total_cancelled = 0;
    std::uint64_t total_failed = 0;
    std::uint64_t total_timed_out = 0;
    std::uint32_t total_active = 0;
    std::uint32_t active_per_domain[executor_domain_count] = {};
    std::uint64_t oldest_active_ms = 0;
    std::uint64_t work_queue_pending = 0;
    std::uint64_t service_queue_pending = 0;
    std::uint64_t critical_queue_pending = 0;
    std::uint32_t work_queue_active = 0;
    std::uint32_t service_queue_active = 0;
    std::uint32_t critical_queue_active = 0;
    bool accepting = true;
    bool shutting_down = false;
    std::string labels_under_pressure;
    std::vector<active_job_snapshot_t> active_jobs;
};

struct pool_t {
    const char* pool_name = nullptr;
    const char* log_tag = nullptr;
    const char* default_label = nullptr;
    pool_family_t family = pool_family_t::general;
    int configured_pool_size = 0;
    std::atomic<bool> alive{true};
    std::atomic<bool> shutting_down{false};
    std::atomic<bool> stop_accepting{false};
    std::atomic<std::uint32_t> active_tasks{0};
    std::atomic<std::uint64_t> pending_tasks{0};
    std::atomic<std::uint64_t> post_attempts{0};
    std::atomic<std::uint64_t> posted_tasks{0};
    std::atomic<std::uint64_t> rejected_tasks{0};
    std::atomic<std::uint64_t> started_tasks{0};
    std::atomic<std::uint64_t> finished_tasks{0};
    std::atomic<std::uint64_t> cancelled_tasks{0};
    std::atomic<std::uint64_t> failed_tasks{0};
    std::atomic<std::uint64_t> timed_out_tasks{0};
    std::atomic<std::size_t> worker_count{1};

    pool_t(const char* name, const char* tag, const char* label,
           pool_family_t family_value, int size) noexcept
        : pool_name(name), log_tag(tag), default_label(label), family(family_value),
          configured_pool_size(size) {}
};

struct preview_job_t {
    active_job_snapshot_t snapshot;
    std::shared_ptr<cancellation_token_t> cancellation;
    std::function<void()> cancel_hook;
    bool timed_out_requested = false;
    bool cancel_hook_invoked = false;
};

inline std::atomic<std::uint64_t> g_next_job_id{0};
inline std::atomic<std::uint64_t> g_total_submitted{0};
inline std::atomic<std::uint64_t> g_total_rejected{0};
inline std::atomic<std::uint64_t> g_total_cancelled{0};
inline std::atomic<std::uint64_t> g_total_failed{0};
inline std::atomic<std::uint64_t> g_total_timed_out{0};
inline std::atomic<bool> g_stop_accepting{false};
inline std::atomic<bool> g_shutdown_requested{false};
inline std::mutex g_jobs_mutex;
inline std::map<std::uint64_t, preview_job_t> g_jobs;

inline const char* domain_name(executor_domain_t domain) {
    switch (domain) {
    case executor_domain_t::general: return "general";
    case executor_domain_t::service: return "service";
    case executor_domain_t::critical: return "critical";
    case executor_domain_t::ui_dispatch: return "ui_dispatch";
    case executor_domain_t::external_tool: return "external_tool";
    case executor_domain_t::long_running: return "long_running";
    case executor_domain_t::security_liveness: return "security_liveness";
    case executor_domain_t::feature_worker: return "feature_worker";
    case executor_domain_t::diagnostics: return "diagnostics";
    }
    return "general";
}

inline const char* job_state_name(job_state_t state) {
    switch (state) {
    case job_state_t::queued: return "queued";
    case job_state_t::not_started: return "not_started";
    case job_state_t::running: return "running";
    case job_state_t::completed: return "completed";
    case job_state_t::cancelled: return "cancelled";
    case job_state_t::failed: return "failed";
    case job_state_t::timed_out: return "timed_out";
    }
    return "not_started";
}

inline std::uint64_t preview_now_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline std::uint64_t preview_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline int general_pool_size() { return 1; }
inline int service_pool_size() { return 1; }

inline pool_t& domain_pool(executor_domain_t domain) {
    static std::array<pool_t, executor_domain_count> pools{{
        {"runtime.general", "taskflow_runtime", "runtime.general", pool_family_t::general, 1},
        {"runtime.service", "taskflow_runtime", "runtime.service", pool_family_t::service, 1},
        {"runtime.critical", "taskflow_runtime", "runtime.critical", pool_family_t::critical, 1},
        {"runtime.ui_dispatch", "taskflow_runtime", "runtime.ui_dispatch", pool_family_t::general, 1},
        {"runtime.external_tool", "taskflow_runtime", "runtime.external_tool", pool_family_t::general, 1},
        {"runtime.long_running", "taskflow_runtime", "runtime.long_running", pool_family_t::service, 1},
        {"runtime.security_liveness", "taskflow_runtime", "runtime.security_liveness", pool_family_t::critical, 1},
        {"runtime.feature_worker", "taskflow_runtime", "runtime.feature_worker", pool_family_t::general, 1},
        {"runtime.diagnostics", "taskflow_runtime", "runtime.diagnostics", pool_family_t::general, 1}
    }};
    const auto index = static_cast<std::size_t>(domain);
    return pools[index < pools.size() ? index : 0];
}

inline void initialize() {
    g_stop_accepting.store(false);
    g_shutdown_requested.store(false);
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        auto& pool = domain_pool(static_cast<executor_domain_t>(index));
        pool.alive.store(true);
        pool.shutting_down.store(false);
        pool.stop_accepting.store(false);
    }
}

inline bool preview_terminal_state(job_state_t state) {
    return state == job_state_t::completed || state == job_state_t::cancelled ||
        state == job_state_t::failed || state == job_state_t::timed_out;
}

inline void preview_prune_jobs_locked() {
    constexpr std::size_t retained_jobs = 256;
    auto iterator = g_jobs.begin();
    while (g_jobs.size() >= retained_jobs && iterator != g_jobs.end()) {
        if (preview_terminal_state(iterator->second.snapshot.state))
            iterator = g_jobs.erase(iterator);
        else
            ++iterator;
    }
}

inline void preview_invoke_cancel_hook(std::function<void()>& hook) noexcept {
    if (!hook)
        return;
    try {
        hook();
    } catch (...) {
    }
}

inline submit_result_t preview_submit(task_descriptor_t&& descriptor, bool graph,
                                      std::uint32_t node_count) {
    auto& pool = domain_pool(descriptor.domain);
    pool.post_attempts.fetch_add(1);
    if (g_stop_accepting.load() || pool.stop_accepting.load()) {
        pool.rejected_tasks.fetch_add(1);
        g_total_rejected.fetch_add(1);
        return {false, {}, "Preview runtime is not accepting work"};
    }
    if (!descriptor.owner_subsystem || !*descriptor.owner_subsystem) {
        pool.rejected_tasks.fetch_add(1);
        g_total_rejected.fetch_add(1);
        return {false, {}, "missing_owner_subsystem"};
    }
    if (!descriptor.label || !*descriptor.label) {
        pool.rejected_tasks.fetch_add(1);
        g_total_rejected.fetch_add(1);
        return {false, {}, "missing_label"};
    }
    if (!descriptor.body && !descriptor.cancellable_body) {
        pool.rejected_tasks.fetch_add(1);
        g_total_rejected.fetch_add(1);
        return {false, {}, "missing_body"};
    }

    const std::uint64_t id = g_next_job_id.fetch_add(1) + 1;
    const std::uint64_t queued_ms = preview_now_ms();
    preview_job_t job;
    job.snapshot.job_id = id;
    job.snapshot.domain = descriptor.domain;
    job.snapshot.state = job_state_t::queued;
    job.snapshot.label = descriptor.label ? descriptor.label : pool.default_label;
    job.snapshot.owner_subsystem = descriptor.owner_subsystem ? descriptor.owner_subsystem : "taskflow_runtime";
    job.snapshot.target_id = descriptor.target_id ? descriptor.target_id : "";
    job.snapshot.priority = descriptor.priority;
    job.snapshot.queued_ms = queued_ms;
    job.snapshot.queued_ns = preview_now_ns();
    job.snapshot.deadline_ms = descriptor.deadline_ms;
    job.snapshot.capacity_lease = descriptor.capacity_lease;
    job.snapshot.graph = graph;
    job.snapshot.node_count = node_count;
    job.cancellation = std::make_shared<cancellation_token_t>();
    job.cancel_hook = std::move(descriptor.cancel_hook);
    {
        std::lock_guard<std::mutex> lock(g_jobs_mutex);
        preview_prune_jobs_locked();
        auto inserted = g_jobs.emplace(id, std::move(job));
        inserted.first->second.snapshot.state = job_state_t::running;
        inserted.first->second.snapshot.started_ms = preview_now_ms();
        inserted.first->second.snapshot.started_ns = preview_now_ns();
    }

    pool.posted_tasks.fetch_add(1);
    pool.started_tasks.fetch_add(1);
    pool.active_tasks.fetch_add(1);
    g_total_submitted.fetch_add(1);
    job_state_t final_state = job_state_t::completed;
    std::string exception_text;
    std::shared_ptr<cancellation_token_t> cancellation;
    {
        std::lock_guard<std::mutex> lock(g_jobs_mutex);
        cancellation = g_jobs.at(id).cancellation;
    }
    try {
        if (descriptor.deadline_ms != 0 && preview_now_ms() >= descriptor.deadline_ms) {
            std::lock_guard<std::mutex> lock(g_jobs_mutex);
            auto& stored = g_jobs.at(id);
            stored.timed_out_requested = true;
            stored.cancellation->requested.store(true);
        }
        if (descriptor.cancellable_body)
            descriptor.cancellable_body(*cancellation);
        else if (!cancellation->requested.load())
            descriptor.body();
    } catch (const std::exception& exception) {
        final_state = job_state_t::failed;
        exception_text = exception.what();
    } catch (...) {
        final_state = job_state_t::failed;
        exception_text = "Unknown preview task failure";
    }

    std::function<void()> timeout_hook;
    {
        std::lock_guard<std::mutex> lock(g_jobs_mutex);
        auto found = g_jobs.find(id);
        if (found != g_jobs.end()) {
            if (final_state != job_state_t::failed) {
                if (found->second.timed_out_requested ||
                    (descriptor.deadline_ms != 0 && preview_now_ms() >= descriptor.deadline_ms)) {
                    final_state = job_state_t::timed_out;
                    found->second.timed_out_requested = true;
                    found->second.cancellation->requested.store(true);
                    if (!found->second.cancel_hook_invoked && found->second.cancel_hook) {
                        found->second.cancel_hook_invoked = true;
                        timeout_hook = found->second.cancel_hook;
                    }
                } else if (found->second.cancellation->requested.load()) {
                    final_state = job_state_t::cancelled;
                }
            }
            found->second.snapshot.state = final_state;
            found->second.snapshot.finished_ms = preview_now_ms();
            found->second.snapshot.exception_text = std::move(exception_text);
            found->second.snapshot.cancellation_requested = found->second.cancellation->requested.load();
        }
    }
    preview_invoke_cancel_hook(timeout_hook);
    pool.active_tasks.fetch_sub(1);
    pool.finished_tasks.fetch_add(1);
    if (final_state == job_state_t::cancelled) {
        pool.cancelled_tasks.fetch_add(1);
        g_total_cancelled.fetch_add(1);
    } else if (final_state == job_state_t::failed) {
        pool.failed_tasks.fetch_add(1);
        g_total_failed.fetch_add(1);
    } else if (final_state == job_state_t::timed_out) {
        pool.timed_out_tasks.fetch_add(1);
        g_total_timed_out.fetch_add(1);
    }
    return {true, {id}, {}};
}

inline submit_result_t submit(task_descriptor_t&& descriptor) {
    return preview_submit(std::move(descriptor), false, 0);
}

inline submit_result_t submit_graph(graph_descriptor_t&& graph) {
    auto& pool = domain_pool(graph.domain);
    const auto reject = [&](const char* reason) {
        pool.post_attempts.fetch_add(1);
        pool.rejected_tasks.fetch_add(1);
        g_total_rejected.fetch_add(1);
        return submit_result_t{false, {}, reason};
    };
    if (!graph.owner_subsystem || !*graph.owner_subsystem)
        return reject("missing_owner_subsystem");
    if (!graph.label || !*graph.label)
        return reject("missing_label");
    if (graph.nodes.empty())
        return reject("missing_graph_nodes");
    std::vector<std::uint64_t> node_ids;
    node_ids.reserve(graph.nodes.size());
    for (const auto& node : graph.nodes) {
        if (node.node_id == 0 || (!node.body && !node.cancellable_body))
            return reject("invalid_graph_node");
        if (std::find(node_ids.begin(), node_ids.end(), node.node_id) != node_ids.end())
            return reject("duplicate_graph_node");
        node_ids.push_back(node.node_id);
    }
    for (const auto& node : graph.nodes) {
        for (const auto dependency : node.depends_on) {
            if (std::find(node_ids.begin(), node_ids.end(), dependency) == node_ids.end())
                return reject("missing_graph_dependency");
        }
    }
    std::vector<bool> schedulable(graph.nodes.size(), false);
    std::size_t schedulable_count = 0;
    while (schedulable_count < graph.nodes.size()) {
        bool progressed = false;
        for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
            if (schedulable[index])
                continue;
            bool ready = true;
            for (const auto dependency : graph.nodes[index].depends_on) {
                const auto found = std::find(node_ids.begin(), node_ids.end(), dependency);
                const auto dependency_index = static_cast<std::size_t>(
                    std::distance(node_ids.begin(), found));
                if (!schedulable[dependency_index]) {
                    ready = false;
                    break;
                }
            }
            if (!ready)
                continue;
            schedulable[index] = true;
            ++schedulable_count;
            progressed = true;
        }
        if (!progressed)
            return reject("cyclic_graph_dependency");
    }
    task_descriptor_t descriptor;
    descriptor.domain = graph.domain;
    descriptor.owner_subsystem = graph.owner_subsystem;
    descriptor.label = graph.label;
    descriptor.target_id = graph.target_id;
    descriptor.priority = graph.priority;
    descriptor.target_pid = graph.target_pid;
    descriptor.deadline_ms = graph.deadline_ms;
    descriptor.generation = graph.generation;
    descriptor.cancel_hook = std::move(graph.cancel_hook);
    const auto node_count = graph.nodes.size();
    auto nodes = std::move(graph.nodes);
    descriptor.cancellable_body = [nodes = std::move(nodes)](const cancellation_token_t& token) mutable {
        std::vector<bool> complete(nodes.size(), false);
        std::size_t completed = 0;
        while (completed < nodes.size() && !token.requested.load()) {
            bool progressed = false;
            for (std::size_t index = 0; index < nodes.size(); ++index) {
                if (complete[index]) continue;
                bool ready = true;
                for (const std::uint64_t dependency : nodes[index].depends_on) {
                    const auto found = std::find_if(nodes.begin(), nodes.end(),
                        [dependency](const graph_node_descriptor_t& candidate) {
                            return candidate.node_id == dependency;
                        });
                    if (found == nodes.end()) {
                        ready = false;
                        break;
                    }
                    const auto dependency_index = static_cast<std::size_t>(std::distance(nodes.begin(), found));
                    if (!complete[dependency_index]) {
                        ready = false;
                        break;
                    }
                }
                if (!ready) continue;
                if (nodes[index].cancellable_body)
                    nodes[index].cancellable_body(token);
                else if (nodes[index].body)
                    nodes[index].body();
                complete[index] = true;
                ++completed;
                progressed = true;
            }
            if (!progressed) break;
        }
    };
    const auto bounded_node_count = static_cast<std::uint32_t>((std::min)(
        node_count, static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())));
    return preview_submit(std::move(descriptor), true, bounded_node_count);
}

inline bool cancel(job_handle_t handle) {
    std::function<void()> cancel_hook;
    {
        std::lock_guard<std::mutex> lock(g_jobs_mutex);
        auto found = g_jobs.find(handle.id);
        if (found == g_jobs.end()) return false;
        if (preview_terminal_state(found->second.snapshot.state))
            return false;
        found->second.cancellation->requested.store(true);
        found->second.snapshot.cancellation_requested = true;
        if (!found->second.cancel_hook_invoked) {
            cancel_hook = found->second.cancel_hook;
            found->second.cancel_hook_invoked = true;
        }
    }
    preview_invoke_cancel_hook(cancel_hook);
    return true;
}

inline bool cancel(std::uint64_t job_id) { return cancel(job_handle_t{job_id}); }

inline bool cooperative_cancel_requested(job_handle_t handle) {
    std::lock_guard<std::mutex> lock(g_jobs_mutex);
    const auto found = g_jobs.find(handle.id);
    return found != g_jobs.end() && found->second.cancellation->requested.load();
}

inline wait_result_t wait_for(job_handle_t handle, std::uint32_t) {
    if (!handle.valid())
        return {true, false, false, false, false};
    std::lock_guard<std::mutex> lock(g_jobs_mutex);
    const auto found = g_jobs.find(handle.id);
    if (found == g_jobs.end()) return {true, false, false, false, false};
    const auto state = found->second.snapshot.state;
    return {
        state == job_state_t::completed,
        state == job_state_t::timed_out,
        false,
        state == job_state_t::cancelled,
        state == job_state_t::failed
    };
}

inline wait_result_t wait_for(std::uint64_t job_id, std::uint32_t timeout_ms) {
    return wait_for(job_handle_t{job_id}, timeout_ms);
}

inline void check_deadlines() {
    const auto current = preview_now_ms();
    std::vector<std::function<void()>> cancel_hooks;
    {
        std::lock_guard<std::mutex> lock(g_jobs_mutex);
        for (auto& entry : g_jobs) {
            auto& job = entry.second;
            if (preview_terminal_state(job.snapshot.state) || job.snapshot.deadline_ms == 0 ||
                current < job.snapshot.deadline_ms)
                continue;
            job.timed_out_requested = true;
            job.cancellation->requested.store(true);
            job.snapshot.cancellation_requested = true;
            if (!job.cancel_hook_invoked && job.cancel_hook) {
                job.cancel_hook_invoked = true;
                cancel_hooks.push_back(job.cancel_hook);
            }
        }
    }
    for (auto& hook : cancel_hooks)
        preview_invoke_cancel_hook(hook);
}

inline stats_t stats_for(pool_t& pool, int pool_size, const char*) {
    stats_t result;
    result.alive = pool.alive.load();
    result.shutting_down = pool.shutting_down.load();
    result.pool_size = pool_size;
    result.workers = pool.worker_count.load();
    result.pending = static_cast<std::size_t>(pool.pending_tasks.load());
    result.active = pool.active_tasks.load();
    result.post_attempts = pool.post_attempts.load();
    result.posted = pool.posted_tasks.load();
    result.rejected = pool.rejected_tasks.load();
    result.started = pool.started_tasks.load();
    result.finished = pool.finished_tasks.load();
    result.cancelled = pool.cancelled_tasks.load();
    result.failed = pool.failed_tasks.load();
    result.timed_out = pool.timed_out_tasks.load();
    return result;
}

inline stats_t domain_stats(executor_domain_t domain) {
    auto& pool = domain_pool(domain);
    return stats_for(pool, pool.configured_pool_size, pool.pool_name);
}

inline std::vector<stuck_worker_diag_t> stuck_workers(std::uint64_t, std::size_t) { return {}; }
inline void log_stuck_workers(std::uint64_t, std::size_t) {}

inline bool post_to(pool_t& pool, int, std::function<void()> body, const char* label) {
    task_descriptor_t descriptor;
    descriptor.owner_subsystem = pool.pool_name ? pool.pool_name : "taskflow_runtime";
    descriptor.label = label && *label ? label :
        (pool.default_label && *pool.default_label ? pool.default_label : "taskflow.task");
    descriptor.body = std::move(body);
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        if (&domain_pool(static_cast<executor_domain_t>(index)) == &pool) {
            descriptor.domain = static_cast<executor_domain_t>(index);
            break;
        }
    }
    return submit(std::move(descriptor)).submitted;
}

inline bool all_pools_quiescent() {
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        const auto& pool = domain_pool(static_cast<executor_domain_t>(index));
        if (pool.active_tasks.load() != 0 || pool.pending_tasks.load() != 0) return false;
    }
    return true;
}

inline runtime_snapshot_t active_snapshot(std::size_t max_jobs = 64) {
    runtime_snapshot_t result;
    result.total_submitted = g_total_submitted.load();
    result.total_rejected = g_total_rejected.load();
    result.total_cancelled = g_total_cancelled.load();
    result.total_failed = g_total_failed.load();
    result.total_timed_out = g_total_timed_out.load();
    result.accepting = !g_stop_accepting.load();
    result.shutting_down = g_shutdown_requested.load();
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        const auto domain = static_cast<executor_domain_t>(index);
        const auto stats = domain_stats(domain);
        result.active_per_domain[index] = stats.active;
        result.total_active += stats.active;
        if (domain == executor_domain_t::general || domain == executor_domain_t::ui_dispatch ||
            domain == executor_domain_t::external_tool || domain == executor_domain_t::feature_worker ||
            domain == executor_domain_t::diagnostics) {
            result.work_queue_pending += static_cast<std::uint64_t>(stats.pending);
            result.work_queue_active += stats.active;
        } else if (domain == executor_domain_t::service || domain == executor_domain_t::long_running) {
            result.service_queue_pending += static_cast<std::uint64_t>(stats.pending);
            result.service_queue_active += stats.active;
        } else {
            result.critical_queue_pending += static_cast<std::uint64_t>(stats.pending);
            result.critical_queue_active += stats.active;
        }
    }
    std::lock_guard<std::mutex> lock(g_jobs_mutex);
    const auto current = preview_now_ms();
    for (auto iterator = g_jobs.rbegin(); iterator != g_jobs.rend(); ++iterator) {
        if (preview_terminal_state(iterator->second.snapshot.state))
            continue;
        auto snapshot = iterator->second.snapshot;
        snapshot.active_ms = current >= snapshot.queued_ms ? current - snapshot.queued_ms : 0;
        if (snapshot.active_ms > result.oldest_active_ms)
            result.oldest_active_ms = snapshot.active_ms;
        if (!result.labels_under_pressure.empty())
            result.labels_under_pressure += ";";
        result.labels_under_pressure += snapshot.label;
        if (result.active_jobs.size() < max_jobs)
            result.active_jobs.push_back(std::move(snapshot));
    }
    return result;
}

inline std::string snapshot_json_string() {
    const auto snapshot = active_snapshot(32);
    return std::string("{\"accepting\":") + (snapshot.accepting ? "true" : "false") +
        ",\"shutting_down\":" + (snapshot.shutting_down ? "true" : "false") +
        ",\"total_submitted\":" + std::to_string(snapshot.total_submitted) +
        ",\"total_active\":" + std::to_string(snapshot.total_active) + "}";
}

inline void shutdown(std::uint32_t = 15000) {
    g_stop_accepting.store(true);
    g_shutdown_requested.store(true);
    for (std::size_t index = 0; index < executor_domain_count; ++index) {
        auto& pool = domain_pool(static_cast<executor_domain_t>(index));
        pool.stop_accepting.store(true);
        pool.shutting_down.store(true);
        pool.alive.store(false);
    }
}

}
