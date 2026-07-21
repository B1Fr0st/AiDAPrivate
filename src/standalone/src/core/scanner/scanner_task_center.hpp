#pragma once

#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace scanner_task_center {

inline std::string executor_task_id(std::uint64_t task_id) {
	return "scanner.executor." + std::to_string(task_id);
}

inline bool update_executor_task(std::uint64_t task_id,
	aida::ui::task_center::task_state_t state, float progress,
	std::string stage, std::string result = {}) {
	if (task_id == 0)
		return false;
	return aida::ui::task_center::update_task(executor_task_id(task_id), state,
		progress, std::move(stage), std::move(result));
}

inline bool register_executor_task(
	const aida::infra::executor::submit_result_t& submitted,
	const char* owner_view, const char* owner_action, const char* label,
	std::uint32_t target_pid, bool cancellable = false,
	std::function<bool()> cancel = {}) {
	if (!submitted.submitted || submitted.task_id == 0)
		return false;
	aida::ui::task_center::task_registration_t registration;
	registration.id = executor_task_id(submitted.task_id);
	registration.owner = "scanner";
	registration.owner_view = owner_view ? owner_view : "";
	registration.owner_action = owner_action ? owner_action : "";
	registration.target = target_pid == 0 ? std::string{} : "PID " + std::to_string(target_pid);
	registration.label = label ? label : "Scanner task";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.cancellation_is_safe = cancellable;
	if (cancellable) {
		registration.callbacks.cancel = [task_id = submitted.task_id,
			owner_cancel = std::move(cancel)]() mutable {
			const bool owner_accepted = owner_cancel && owner_cancel();
			const bool runtime_accepted = aida::infra::executor::cancel(task_id);
			return owner_accepted || runtime_accepted;
		};
	}
	return aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration));
}

}
