#include "core/settings/settings_persistence_service.hpp"

#include "core/settings/standalone_settings.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "preview/shell_preview_platform.hpp"
#include "preview/shell_preview.hpp"
#else
#include "core/infra/executor.hpp"
#include "core/ui/task_center.hpp"
#include "core/ui/ui_thread_dispatcher.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <optional>
#endif

#include <utility>

namespace aida::settings_persistence {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

request_result_t request_save(const settings_sa_t&, std::uint64_t* generation) noexcept
{
    if (generation)
        *generation = 1;
    aida::preview::record(aida::preview::shell_action_t::save_file, "settings");
    return request_result_t::preview_recorded;
}

bool commit_lifecycle(const settings_sa_t&, std::string& error) noexcept
{
    error.clear();
    aida::preview::record(aida::preview::shell_action_t::save_file, "settings.lifecycle");
    return true;
}

bool shutdown_commit(const settings_sa_t& settings, std::string& error) noexcept
{
    return commit_lifecycle(settings, error);
}

status_t status() noexcept
{
    return {};
}

#else
namespace {

struct runtime_t {
    std::mutex mutex;
    std::mutex write_mutex;
    std::uint64_t next_generation = 0;
    std::uint64_t latest_generation = 0;
    std::uint64_t committed_generation = 0;
    std::uint64_t authoritative_generation = 0;
    bool worker_active = false;
    bool accepting = true;
    std::shared_ptr<const settings_sa_t> latest_snapshot;
    std::shared_ptr<const settings_sa_t> failed_snapshot;
    std::string active_task_id;
    std::string failed_task_id;
    status_t ui_status;
    std::optional<status_t> deferred_status;
};

runtime_t& runtime() noexcept
{
    static runtime_t value;
    return value;
}

void publish_ui(std::uint64_t generation, std::uint64_t committed,
    bool pending, bool failed, std::string stage, std::string error) noexcept
{
    status_t publication;
    publication.generation = generation;
    publication.committed_generation = committed;
    publication.pending = pending;
    publication.failed = failed;
    publication.stage = std::move(stage);
    publication.error = std::move(error);
    aida::ui_thread::post_options_t options;
    options.subsystem = "settings_persistence";
    options.label = "settings.persistence.result";
    options.phase = "worker_result";
    options.owner = "Settings";
    options.priority = aida::ui_thread::priority_t::normal;
    const auto posted = aida::ui_thread::post(
        [publication]() mutable {
            runtime_t& current = runtime();
            std::lock_guard<std::mutex> lock(current.mutex);
            if (publication.generation < current.ui_status.generation)
                return;
            current.ui_status.generation = publication.generation;
            current.ui_status.committed_generation = (std::max)(
                current.ui_status.committed_generation,
                publication.committed_generation);
            current.ui_status.pending = publication.pending;
            current.ui_status.failed = publication.failed;
            current.ui_status.stage = std::move(publication.stage);
            current.ui_status.error = std::move(publication.error);
        }, std::move(options));
    if (posted != aida::ui_thread::enqueue_result_t::accepted) {
        runtime_t& current = runtime();
        std::lock_guard<std::mutex> lock(current.mutex);
        if (!current.deferred_status ||
            current.deferred_status->generation <= publication.generation)
            current.deferred_status = std::move(publication);
    }
}

bool retry_task(const std::string& task_id) noexcept;

bool register_task(const std::string& task_id)
{
    aida::ui::task_center::task_registration_t registration;
    registration.id = task_id;
    registration.source = "settings_persistence";
    registration.owner = "Settings";
    registration.owner_view = "view.settings";
    registration.owner_action = "Persist settings";
    registration.target = "AiDA standalone settings";
    registration.label = "Persist settings";
    registration.stage = "Queued immutable settings snapshot";
    registration.affected_entity = "settings.schema.v1";
    registration.callbacks.retry = [task_id] {
        return retry_task(task_id);
    };
    return aida::ui::task_center::register_task(std::move(registration));
}

bool submit_worker(std::uint64_t generation, const std::string& task_id)
{
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "settings_persistence";
    submission.label = "settings.persistence";
    submission.thread_class = "blocking_file_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 2;
    submission.generation = generation;
    submission.diagnostic_id = "settings.persistence";
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_last_known_good";
    submission.shutdown_policy = "drain";
    submission.body = [task_id] {
        runtime_t& current = runtime();
        for (;;) {
            std::shared_ptr<const settings_sa_t> snapshot;
            std::uint64_t candidate_generation = 0;
            {
                std::lock_guard<std::mutex> lock(current.mutex);
                snapshot = std::move(current.latest_snapshot);
                candidate_generation = current.latest_generation;
            }
            if (!snapshot)
                break;

            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::running, 0.35f,
                "Serializing immutable settings snapshot"));

            bool committed = false;
            bool superseded = false;
            std::string error;
            {
                std::lock_guard<std::mutex> write_lock(current.write_mutex);
                {
                    std::lock_guard<std::mutex> lock(current.mutex);
                    superseded = candidate_generation < current.authoritative_generation;
                }
                if (!superseded) {
                    settings_sa_t writable = *snapshot;
                    committed = writable.save();
                    if (!committed)
                        error = settings_sa_t::last_error();
                }
            }

            bool has_newer = false;
            {
                std::lock_guard<std::mutex> lock(current.mutex);
                if (committed) {
                    current.committed_generation = (std::max)(
                        current.committed_generation, candidate_generation);
                    current.authoritative_generation = (std::max)(
                        current.authoritative_generation, candidate_generation);
                    current.failed_snapshot.reset();
                    current.failed_task_id.clear();
                } else if (!superseded) {
                    current.failed_snapshot = snapshot;
                    current.failed_task_id = task_id;
                }
                has_newer = current.latest_snapshot &&
                    current.latest_generation > candidate_generation;
                if (!has_newer) {
                    current.worker_active = false;
                    current.active_task_id.clear();
                }
            }

            if (has_newer) {
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::running, 0.65f,
                    "Coalesced a newer settings generation"));
                continue;
            }

            if (committed || superseded) {
                const std::uint64_t committed_value = [&] {
                    std::lock_guard<std::mutex> lock(current.mutex);
                    return current.committed_generation;
                }();
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::completed, 1.0f,
                    superseded ? "Superseded by a newer durable settings commit" :
                        "Settings committed atomically"));
                publish_ui(candidate_generation, committed_value, false, false,
                    superseded ? "Superseded by a newer durable commit" :
                        "Settings saved", {});
            } else {
                if (error.empty())
                    error = "Settings persistence failed without a diagnostic.";
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::failed, 1.0f,
                    "Settings persistence failed", error));
                publish_ui(candidate_generation, 0, false, true,
                    "Settings persistence failed", error);
            }
            return;
        }
        {
            std::lock_guard<std::mutex> lock(current.mutex);
            current.worker_active = false;
            current.active_task_id.clear();
        }
    };
    return aida::infra::executor::submit(std::move(submission)).submitted;
}

request_result_t submit_snapshot(std::shared_ptr<const settings_sa_t> snapshot,
    bool retry, std::uint64_t* generation_out = nullptr)
{
    runtime_t& current = runtime();
    std::uint64_t generation = 0;
    std::string task_id;
    bool coalesced = false;
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (!current.accepting)
            return request_result_t::rejected;
        generation = ++current.next_generation;
        if (generation_out)
            *generation_out = generation;
        current.latest_generation = generation;
        current.latest_snapshot = std::move(snapshot);
        current.ui_status.generation = generation;
        current.ui_status.pending = true;
        current.ui_status.failed = false;
        current.ui_status.error.clear();
        current.ui_status.stage = retry ? "Retry queued" : "Settings save queued";
        if (current.worker_active) {
            coalesced = true;
            task_id = current.active_task_id;
        } else {
            current.worker_active = true;
            task_id = "settings.persistence." + std::to_string(generation);
            current.active_task_id = task_id;
        }
    }

    if (coalesced) {
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::running, 0.2f,
            "Coalesced newer immutable settings generation"));
        return request_result_t::coalesced;
    }

    if (!register_task(task_id) || !submit_worker(generation, task_id)) {
        {
            std::lock_guard<std::mutex> lock(current.mutex);
            current.worker_active = false;
            current.failed_snapshot = current.latest_snapshot;
            current.failed_task_id = task_id;
            current.latest_snapshot.reset();
            current.active_task_id.clear();
            current.ui_status.pending = false;
            current.ui_status.failed = true;
            current.ui_status.stage = "Settings persistence scheduling failed";
            current.ui_status.error = "The settings persistence worker could not be scheduled.";
        }
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Settings persistence scheduling failed"));
        return request_result_t::rejected;
    }
    return request_result_t::queued;
}

bool retry_task(const std::string& task_id) noexcept
{
    if (!aida::ui_thread::is_owner_thread())
        return false;
    runtime_t& current = runtime();
    std::shared_ptr<const settings_sa_t> snapshot;
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (current.worker_active || current.failed_task_id != task_id ||
            !current.failed_snapshot || !current.accepting)
            return false;
        snapshot = current.failed_snapshot;
    }
    try {
        const request_result_t result = submit_snapshot(std::move(snapshot), true);
        return result == request_result_t::queued || result == request_result_t::coalesced;
    } catch (...) {
        return false;
    }
}

}

request_result_t request_save(const settings_sa_t& settings,
    std::uint64_t* generation) noexcept
{
    if (!aida::ui_thread::is_owner_thread()) {
        runtime_t& current = runtime();
        std::lock_guard<std::mutex> lock(current.mutex);
        status_t rejected = current.ui_status;
        rejected.pending = false;
        rejected.failed = true;
        rejected.stage = "Settings snapshot capture rejected";
        rejected.error = "Settings snapshots must be captured on the owning UI thread.";
        current.deferred_status = std::move(rejected);
        return request_result_t::rejected;
    }
    try {
        return submit_snapshot(std::make_shared<const settings_sa_t>(settings), false,
            generation);
    } catch (...) {
        runtime_t& current = runtime();
        std::lock_guard<std::mutex> lock(current.mutex);
        current.ui_status.pending = false;
        current.ui_status.failed = true;
        current.ui_status.stage = "Settings snapshot capture failed";
        current.ui_status.error = "The immutable settings snapshot could not be captured.";
        return request_result_t::capture_failed;
    }
}

bool commit_lifecycle(const settings_sa_t& settings, std::string& error) noexcept
{
    error.clear();
    try {
        auto snapshot = std::make_shared<const settings_sa_t>(settings);
        runtime_t& current = runtime();
        std::uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(current.mutex);
            generation = ++current.next_generation;
            current.authoritative_generation = generation;
            current.latest_snapshot.reset();
            current.latest_generation = generation;
        }
        bool committed = false;
        {
            std::lock_guard<std::mutex> write_lock(current.write_mutex);
            settings_sa_t writable = *snapshot;
            committed = writable.save();
            if (!committed)
                error = settings_sa_t::last_error();
        }
        {
            std::lock_guard<std::mutex> lock(current.mutex);
            if (committed) {
                current.committed_generation = generation;
                current.failed_snapshot.reset();
                current.failed_task_id.clear();
            } else {
                current.failed_snapshot = snapshot;
                current.failed_task_id.clear();
            }
            current.ui_status.generation = generation;
            current.ui_status.committed_generation = current.committed_generation;
            current.ui_status.pending = false;
            current.ui_status.failed = !committed;
            current.ui_status.stage = committed ? "Lifecycle settings commit completed" :
                "Lifecycle settings commit failed";
            current.ui_status.error = error;
        }
        return committed;
    } catch (...) {
        error = "The lifecycle settings snapshot could not be captured or committed.";
        runtime_t& current = runtime();
        std::lock_guard<std::mutex> lock(current.mutex);
        current.ui_status.pending = false;
        current.ui_status.failed = true;
        current.ui_status.stage = "Lifecycle settings commit failed";
        current.ui_status.error = error;
        return false;
    }
}

bool shutdown_commit(const settings_sa_t& settings, std::string& error) noexcept
{
    {
        runtime_t& current = runtime();
        std::lock_guard<std::mutex> lock(current.mutex);
        current.accepting = false;
    }
    return commit_lifecycle(settings, error);
}

status_t status() noexcept
{
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    if (current.deferred_status &&
        current.deferred_status->generation >= current.ui_status.generation) {
        current.ui_status = std::move(*current.deferred_status);
        current.deferred_status.reset();
    }
    return current.ui_status;
}

#endif

}
