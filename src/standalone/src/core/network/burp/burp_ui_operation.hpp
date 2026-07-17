#pragma once

#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif
#include "../../ui/task_center.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <exception>
#include <utility>

namespace aida::burp::ui_operation {

struct result_t {
    bool success = false;
    bool partial = false;
    std::string message;
};

struct request_t {
    std::string owner;
    std::string owner_view;
    std::string owner_action;
    std::string label;
    std::string target;
    std::string affected_entity;
    aida::infra::executor::domain_t domain = aida::infra::executor::domain_t::external_tool;
    int priority = 3;
    std::function<result_t()> execute;
};

struct completion_t {
    std::uint64_t generation = 0;
    result_t result;
};

class state_t {
public:
    bool submit(request_t request) {
        if (!request.execute || request.owner.empty() || request.label.empty())
            return false;
        bool expected = false;
        if (!pending_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
            return false;
        const std::uint64_t generation = generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            last_request_ = request;
            completion_.reset();
        }
        const std::string task_id = "burp.ui." + request.owner + "." +
            std::to_string(generation) + "." +
            std::to_string(aida::infra::executor::now_ms());
        aida::ui::task_center::task_registration_t registration;
        registration.id = task_id;
        registration.source = "burp_ui";
        registration.owner = request.owner;
        registration.owner_view = request.owner_view;
        registration.owner_action = request.owner_action;
        registration.target = request.target;
        registration.label = request.label;
        registration.stage = "Queued";
        registration.affected_entity = request.affected_entity;
        registration.progress = 0.0f;
        registration.callbacks.retry = [this]() { return retry(); };
        if (!aida::ui::task_center::register_task(std::move(registration))) {
            pending_.store(false, std::memory_order_release);
            return false;
        }
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = request.owner.c_str();
        submission.label = request.label.c_str();
        submission.thread_class = "bounded_task";
        submission.domain = request.domain;
        submission.priority = request.priority;
        submission.body = [this, generation, task_id, execute = std::move(request.execute)]() mutable {
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::running, 0.1f, "Running"));
            result_t result;
            try {
                result = execute();
            } catch (const std::exception& exception) {
                result.message = exception.what();
            } catch (...) {
                result.message = "The operation failed with an unknown exception.";
            }
            if (result.message.empty())
                result.message = result.success ? "Operation completed." : "Operation failed.";
            auto completion = std::make_shared<completion_t>();
            completion->generation = generation;
            completion->result = result;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                completion_ = std::move(completion);
            }
            pending_.store(false, std::memory_order_release);
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                result.success
                    ? result.partial ? aida::ui::task_center::task_state_t::partial
                                     : aida::ui::task_center::task_state_t::completed
                    : aida::ui::task_center::task_state_t::failed,
                1.0f, result.success ? "Completed" : "Failed", result.message));
        };
        if (!aida::infra::executor::submit(std::move(submission)).submitted) {
            pending_.store(false, std::memory_order_release);
            result_t result;
            result.message = "The bounded operation queue rejected the request.";
            auto completion = std::make_shared<completion_t>();
            completion->generation = generation;
            completion->result = result;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                completion_ = std::move(completion);
            }
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "Submission rejected", result.message));
            return false;
        }
        return true;
    }

    bool retry() {
        request_t request;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!last_request_ || pending_.load(std::memory_order_acquire))
                return false;
            request = *last_request_;
        }
        return submit(std::move(request));
    }

    bool pending() const noexcept {
        return pending_.load(std::memory_order_acquire);
    }

    std::shared_ptr<const completion_t> completion() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return completion_;
    }

private:
    std::atomic<bool> pending_{false};
    std::atomic<std::uint64_t> generation_{0};
    mutable std::mutex mutex_;
    std::shared_ptr<const completion_t> completion_;
    std::optional<request_t> last_request_;
};

}
