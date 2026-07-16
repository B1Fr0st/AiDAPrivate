#pragma once

#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace scanner_task_center {

inline void register_executor_task(
	const aida::infra::executor::submit_result_t& submitted,
	const char* owner_view, const char* owner_action, const char* label,
	std::uint32_t target_pid, bool cancellable = false,
	std::function<bool()> cancel = {}) {
	if (!submitted.submitted || submitted.task_id == 0)
		return;
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "scanner";
	registration.owner_view = owner_view ? owner_view : "";
	registration.owner_action = owner_action ? owner_action : "";
	registration.target = target_pid == 0 ? std::string{} : "PID " + std::to_string(target_pid);
	registration.label = label ? label : "Scanner task";
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.cancellation_is_safe = cancellable;
	registration.callbacks.cancel = std::move(cancel);
	static_cast<void>(aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration)));
}

}
