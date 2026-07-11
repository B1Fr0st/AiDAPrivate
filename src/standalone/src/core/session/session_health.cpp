#include "session_health.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/diag_log.hpp"

namespace session_health {

namespace {

struct health_entry_t {
    bool current = false;
    aida::analysis::workspace_error_t error;
};

struct state_t {
    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};
    std::mutex mutex;
    std::unordered_map<std::string, health_entry_t> workspaces;
};

state_t& state()
{
    static state_t value;
    return value;
}

health_entry_t validate(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    health_entry_t result;
    if (!workspace || workspace->closing() || workspace->closed()) {
        result.error = aida::analysis::make_workspace_error(
            aida::analysis::workspace_error_code_t::target_stale,
            "Workspace is closing or closed", "session_health.validate");
        return result;
    }
    if (workspace->target_kind() != aida::analysis::target_kind_t::live_snapshot) {
        result.current = true;
        return result;
    }
    auto provider = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
        workspace->provider_handle());
    if (!provider) {
        result.error = aida::analysis::make_workspace_error(
            aida::analysis::workspace_error_code_t::provider_unavailable,
            "Live workspace is not backed by an immutable live snapshot provider",
            "session_health.validate");
        return result;
    }
    auto current = provider->validate_current_identity();
    if (!current) {
        result.error = current.error();
        return result;
    }
    result.current = true;
    return result;
}

void watcher_loop()
{
    auto& shared = state();
    diag::log_tagged("session_health", "thread_entry");
    while (!shared.stop_requested.load(std::memory_order_acquire)) {
        auto workspaces = aida::analysis::workspace_registry().list();
        std::unordered_set<std::string> observed;
        std::size_t current_count = 0;
        std::size_t stale_count = 0;
        for (const auto& workspace : workspaces) {
            if (!workspace || workspace->target_kind() !=
                    aida::analysis::target_kind_t::live_snapshot)
                continue;
            const std::string id = workspace->identity().binary_id().to_hex();
            observed.insert(id);
            auto entry = validate(workspace);
            bool transitioned_to_stale = false;
            {
                std::lock_guard<std::mutex> lock(shared.mutex);
                auto found = shared.workspaces.find(id);
                transitioned_to_stale = found != shared.workspaces.end() &&
                    found->second.current && !entry.current;
                shared.workspaces[id] = entry;
            }
            if (entry.current) ++current_count;
            else ++stale_count;
            if (transitioned_to_stale) {
                const auto process = workspace->identity().process();
                diag::log_tagged_fmt("session_health",
                    "workspace_stale binary_id=%s pid=%u creation=%llu code=%s",
                    id.c_str(), process ? process->pid : 0,
                    static_cast<unsigned long long>(process
                        ? process->creation_time_100ns : 0),
                    entry.error.stable_code().c_str());
            }
        }
        {
            std::lock_guard<std::mutex> lock(shared.mutex);
            for (auto iterator = shared.workspaces.begin();
                 iterator != shared.workspaces.end();) {
                if (observed.find(iterator->first) == observed.end())
                    iterator = shared.workspaces.erase(iterator);
                else
                    ++iterator;
            }
        }
        diag::log_tagged_fmt("session_health",
            "tick current=%llu stale=%llu tracked=%llu",
            static_cast<unsigned long long>(current_count),
            static_cast<unsigned long long>(stale_count),
            static_cast<unsigned long long>(observed.size()));
        for (int interval = 0; interval < 20; ++interval) {
            if (shared.stop_requested.load(std::memory_order_acquire)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    shared.running.store(false, std::memory_order_release);
    diag::log_tagged("session_health", "thread_exit");
}

}

bool initialize()
{
    auto& shared = state();
    bool expected = false;
    if (!shared.running.compare_exchange_strong(expected, true)) return true;
    shared.stop_requested.store(false, std::memory_order_release);
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "session_health";
    submission.label = "session_health.watcher_loop";
    submission.thread_class = "long_lived_service";
    submission.domain = aida::infra::executor::domain_t::service;
    submission.priority = 3;
    submission.body = []() { watcher_loop(); };
    const auto result = aida::infra::executor::submit(std::move(submission));
    if (!result.submitted) {
        shared.running.store(false, std::memory_order_release);
        diag::log_tagged_fmt("session_health",
            "initialize_failed executor_submit_failed reason=%s",
            result.reject_reason.empty() ? "<none>" : result.reject_reason.c_str());
        return false;
    }
    diag::log_tagged("session_health", "initialize_ok");
    return true;
}

void shutdown()
{
    (void)shutdown_and_wait(0);
}

bool shutdown_and_wait(uint32_t timeout_ms)
{
    auto& shared = state();
    const std::uint64_t started = GetTickCount64();
    shared.stop_requested.store(true, std::memory_order_release);
    while (shared.running.load(std::memory_order_acquire) &&
           GetTickCount64() - started < timeout_ms) {
        Sleep(25);
    }
    const bool stopped = !shared.running.load(std::memory_order_acquire);
    if (stopped) {
        std::lock_guard<std::mutex> lock(shared.mutex);
        shared.workspaces.clear();
    }
    diag::log_tagged_fmt("session_health",
        "shutdown_done stopped=%d elapsed_ms=%llu",
        stopped ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started));
    return stopped;
}

bool is_alive(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    if (!workspace) return false;
    if (workspace->target_kind() != aida::analysis::target_kind_t::live_snapshot)
        return !workspace->closing() && !workspace->closed();
    const std::string id = workspace->identity().binary_id().to_hex();
    {
        auto& shared = state();
        std::lock_guard<std::mutex> lock(shared.mutex);
        const auto found = shared.workspaces.find(id);
        if (found != shared.workspaces.end()) return found->second.current;
    }
    return validate(workspace).current;
}

bool is_alive(uint32_t pid)
{
    if (pid == 0) return false;
    return is_alive(aida::analysis::workspace_registry().find_by_pid(pid));
}

session_health_t query_health(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    session_health_t health;
    if (!workspace) return health;
    health.closed = workspace->closed();
    health.closing = workspace->closing();
    health.alive = !health.closed && !health.closing;
    const auto progress = workspace->progress();
    health.readiness = progress.readiness;
    health.phase = progress.phase;
    health.error = progress.error;
    health.generation = workspace->generation();
    const auto publication = workspace->analysis_publication();
    health.analysis_revision = publication ? publication->analysis_revision : 0;
    health.overlay_revision = workspace->overlay_revision();
    health.ready = progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
        progress.readiness == aida::analysis::workspace_readiness_t::partial;
    health.failed = progress.readiness == aida::analysis::workspace_readiness_t::failed;
    if (progress.total_units != 0)
        health.progress_fraction = static_cast<float>(
            static_cast<double>(progress.completed_units) /
            static_cast<double>(progress.total_units));
    else if (progress.total_bytes != 0)
        health.progress_fraction = static_cast<float>(
            static_cast<double>(progress.completed_bytes) /
            static_cast<double>(progress.total_bytes));
    else if (health.ready)
        health.progress_fraction = 1.0f;
    health.binary_id = workspace->identity().binary_id().to_hex();
    health.bin_name = workspace->identity().bin_name();
    if (const auto process = workspace->identity().process()) {
        health.pid = process->pid;
        health.process_creation_time_100ns = process->creation_time_100ns;
    }
    if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        auto provider = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
            workspace->provider_handle());
        if (provider) {
            auto current = provider->validate_current_identity();
            if (!current) {
                health.alive = false;
                health.error = current.error();
            }
        } else {
            health.alive = false;
            health.error = aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::provider_unavailable,
                "Live workspace is not backed by an immutable live snapshot provider",
                "session_health.query_health");
        }
    }
    return health;
}

}
