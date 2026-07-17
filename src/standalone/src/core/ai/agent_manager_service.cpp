#include "agent_manager_service.hpp"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"
#include "../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <functional>
#include <mutex>
#include <stdexcept>

namespace aida::agent_manager_service {
namespace {

struct runtime_t {
	std::shared_ptr<const snapshot_t> publication;
	std::atomic<std::uint64_t> generation{1};
	std::atomic<std::uint64_t> request_generation{1};
	std::atomic<bool> pending{false};
	std::atomic<bool> initialized{false};
};

runtime_t& runtime()
{
	static runtime_t value;
	static std::once_flag once;
	std::call_once(once, [&]() {
		auto initial = std::make_shared<snapshot_t>();
		initial->generation = 1;
		std::atomic_store_explicit(&value.publication,
			std::shared_ptr<const snapshot_t>(std::move(initial)),
			std::memory_order_release);
	});
	return value;
}

std::vector<aida::agent::agent_info_t> combined_catalog()
{
	const auto& all = aida::agent::list();
	return {all.begin(), all.end()};
}

std::shared_ptr<snapshot_t> make_snapshot(operation_state_t state,
	std::string operation, std::string detail)
{
	auto result = std::make_shared<snapshot_t>();
	result->generation = runtime().generation.fetch_add(1,
		std::memory_order_acq_rel) + 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const auto current = std::atomic_load_explicit(&runtime().publication,
		std::memory_order_acquire);
	result->catalog_generation = current ? current->catalog_generation : 1;
#else
	result->catalog_generation = aida::agent::custom_catalog_snapshot().generation;
#endif
	result->state = state;
	result->operation = std::move(operation);
	result->detail = std::move(detail);
	result->agents = combined_catalog();
	return result;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
struct pending_lifecycle_t {
	explicit pending_lifecycle_t(std::atomic<bool>& value) noexcept : pending(value) {}

	template <typename Publisher>
	bool finish(Publisher&& publisher) noexcept
	{
		bool expected = false;
		if (!finished.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel))
			return false;
		try { publisher(); }
		catch (...) {}
		pending.store(false, std::memory_order_release);
		return true;
	}

	bool release() noexcept
	{
		return finish([]() noexcept {});
	}

	std::atomic<bool>& pending;
	std::atomic<bool> finished{false};
};

struct pending_scope_t {
	explicit pending_scope_t(std::shared_ptr<pending_lifecycle_t> value) noexcept
		: lifecycle(std::move(value)) {}
	~pending_scope_t() { if (active && lifecycle) lifecycle->release(); }
	void dismiss() noexcept { active = false; }

	std::shared_ptr<pending_lifecycle_t> lifecycle;
	bool active = true;
};

void publish_terminal(std::shared_ptr<snapshot_t> terminal)
{
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(terminal)),
		std::memory_order_release);
}

using operation_t = std::function<void(const std::shared_ptr<std::atomic<bool>>&)>;

bool submit(const char* label, const char* action, bool cancellable,
	operation_t operation, std::string* error)
{
	auto& rt = runtime();
	const auto lifecycle = std::make_shared<pending_lifecycle_t>(rt.pending);
	bool expected = false;
	if (!rt.pending.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) {
		if (error) *error = "Another Agent Manager operation is already running";
		return false;
	}
	pending_scope_t setup_scope(lifecycle);
	std::shared_ptr<std::atomic<bool>> cancelled;
	std::uint64_t submitted_task_id = 0;
	try {
		auto loading = make_snapshot(operation_state_t::loading, label, {});
		const auto current = snapshot();
		loading->agents = current ? current->agents : combined_catalog();
		std::atomic_store_explicit(&rt.publication,
			std::shared_ptr<const snapshot_t>(std::move(loading)),
			std::memory_order_release);
		cancelled = std::make_shared<std::atomic<bool>>(false);
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "agent_manager";
		submission.label = label;
		submission.thread_class = "settings_persistence";
		submission.domain = aida::infra::executor::domain_t::feature_worker;
		submission.priority = 4;
		submission.generation = rt.request_generation.fetch_add(1,
			std::memory_order_acq_rel);
		submission.cancel_hook = [cancelled]() {
			cancelled->store(true, std::memory_order_release);
		};
		submission.body = [cancelled, lifecycle, operation = std::move(operation),
			label = std::string(label)]() mutable {
			pending_scope_t worker_scope(lifecycle);
			operation_state_t state = operation_state_t::succeeded;
			std::string detail;
			try {
				detail = label + " completed";
				operation(cancelled);
				if (cancelled->load(std::memory_order_acquire)) {
					state = operation_state_t::cancelled;
					detail = label + " was cancelled";
				}
			} catch (const std::exception& exception) {
				state = operation_state_t::failed;
				try { detail = exception.what(); }
				catch (...) { detail.clear(); }
			} catch (...) {
				state = operation_state_t::failed;
				try { detail = "Agent Manager operation failed"; }
				catch (...) { detail.clear(); }
			}
			const bool terminal_owner = worker_scope.lifecycle->finish([&]() {
				try {
					publish_terminal(make_snapshot(state, label, detail));
				} catch (...) {
					state = operation_state_t::failed;
					try {
						detail = "Agent Manager could not publish the operation result";
						publish_terminal(make_snapshot(state, label, detail));
					} catch (...) {}
				}
			});
			worker_scope.dismiss();
			if (!terminal_owner) return;
			if (state == operation_state_t::failed)
				throw std::runtime_error(detail.empty()
					? "Agent Manager operation failed" : detail);
		};
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (!submitted.submitted) {
			const std::string detail = submitted.reject_reason.empty()
				? "Agent Manager executor rejected the operation"
				: submitted.reject_reason;
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(make_snapshot(operation_state_t::failed, label, detail));
			}));
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		submitted_task_id = submitted.task_id;
		aida::ui::task_center::task_registration_t registration;
		registration.id = "agent.manager." + std::to_string(submitted.task_id);
		registration.source = "Agent Manager";
		registration.owner = "agent_manager";
		registration.owner_view = "view.ai.agents";
		registration.owner_action = action;
		registration.label = label;
		registration.stage = "Queued";
		registration.affected_entity = "custom agent catalog";
		registration.cancellation_is_safe = cancellable;
		if (cancellable) {
			registration.callbacks.cancel = [cancelled, task_id = submitted.task_id]() {
				cancelled->store(true, std::memory_order_release);
				return aida::infra::executor::cancel(task_id);
			};
		}
		if (!aida::ui::task_center::try_register_executor_job(submitted.task_id,
			std::move(registration))) {
			cancelled->store(true, std::memory_order_release);
			static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
			const std::string detail = "Task Center rejected Agent Manager ownership";
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(make_snapshot(operation_state_t::failed, label, detail));
			}));
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		setup_scope.dismiss();
		return true;
	} catch (const std::exception& exception) {
		if (cancelled) cancelled->store(true, std::memory_order_release);
		if (submitted_task_id != 0) {
			try { static_cast<void>(aida::infra::executor::cancel(submitted_task_id)); }
			catch (...) {}
		}
		std::string detail;
		try { detail = exception.what(); }
		catch (...) {
			try { detail = "Agent Manager setup failed"; } catch (...) {}
		}
		static_cast<void>(lifecycle->finish([&]() {
			publish_terminal(make_snapshot(operation_state_t::failed, label, detail));
		}));
		setup_scope.dismiss();
		if (error) {
			try { *error = detail; } catch (...) {}
		}
		return false;
	} catch (...) {
		if (cancelled) cancelled->store(true, std::memory_order_release);
		if (submitted_task_id != 0) {
			try { static_cast<void>(aida::infra::executor::cancel(submitted_task_id)); }
			catch (...) {}
		}
		try {
			const std::string detail = "Agent Manager setup failed";
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(make_snapshot(operation_state_t::failed, label, detail));
			}));
			if (error) *error = detail;
		} catch (...) {}
		static_cast<void>(lifecycle->release());
		setup_scope.dismiss();
		return false;
	}
}

#endif

}

snapshot_ptr snapshot()
{
	return std::atomic_load_explicit(&runtime().publication,
		std::memory_order_acquire);
}

const aida::agent::agent_info_t* find(const snapshot_ptr& publication,
	const std::string& identity)
{
	if (!publication) return nullptr;
	const auto found = std::find_if(publication->agents.begin(), publication->agents.end(),
		[&](const auto& agent) { return agent.name == identity; });
	return found == publication->agents.end() ? nullptr : &*found;
}

void begin_frame()
{
	auto& rt = runtime();
	bool expected = false;
	if (!rt.initialized.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto publication = make_snapshot(operation_state_t::succeeded,
		"Preview Agent Catalog", "Deterministic in-memory Agent Manager preview");
	std::atomic_store_explicit(&rt.publication,
		std::shared_ptr<const snapshot_t>(std::move(publication)),
		std::memory_order_release);
#else
	auto initial = make_snapshot(operation_state_t::idle, {}, {});
	std::atomic_store_explicit(&rt.publication,
		std::shared_ptr<const snapshot_t>(std::move(initial)),
		std::memory_order_release);
	std::string ignored;
	static_cast<void>(request_reload(&ignored));
#endif
}

bool request_reload(std::string* error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(error);
	return true;
#else
	const auto expected = aida::agent::custom_catalog_snapshot().generation;
	return submit("Reload custom agents", "agent.manager.reload", true,
		[expected](const std::shared_ptr<std::atomic<bool>>& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			std::string failure;
			if (!aida::agent::reload_custom_catalog(expected, failure))
				throw std::runtime_error(failure);
		}, error);
#endif
}

bool request_upsert(const aida::agent::agent_info_t& definition,
	const std::string& replaced_identity, std::uint64_t expected_catalog_generation,
	std::string* error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto current = snapshot();
	auto next = current ? std::make_shared<snapshot_t>(*current)
		: std::make_shared<snapshot_t>();
	next->generation = runtime().generation.fetch_add(1) + 1;
	auto found = std::find_if(next->agents.begin(), next->agents.end(),
		[&](const auto& agent) { return agent.name == replaced_identity; });
	if (found != next->agents.end() && !found->native) *found = definition;
	else next->agents.push_back(definition);
	next->state = operation_state_t::succeeded;
	next->detail = "Deterministic preview agent update";
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)),
		std::memory_order_release);
	static_cast<void>(expected_catalog_generation);
	static_cast<void>(error);
	return true;
#else
	return submit("Save custom agent", "agent.manager.save", false,
		[definition, replaced_identity, expected_catalog_generation](const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			auto catalog = aida::agent::custom_catalog_snapshot();
			if (catalog.generation != expected_catalog_generation)
				throw std::runtime_error("Custom agent catalog changed; reload before saving");
			auto found = std::find_if(catalog.agents.begin(), catalog.agents.end(),
				[&](const auto& agent) { return agent.name == replaced_identity; });
			if (!replaced_identity.empty() && found == catalog.agents.end())
				throw std::runtime_error("The edited custom agent no longer exists");
			if (found != catalog.agents.end()) catalog.agents.erase(found);
			if (std::any_of(catalog.agents.begin(), catalog.agents.end(),
				[&](const auto& agent) { return agent.name == definition.name; }))
				throw std::runtime_error("A custom agent with that name already exists");
			catalog.agents.push_back(definition);
			if (cancelled->load(std::memory_order_acquire)) return;
			std::string failure;
			if (!aida::agent::commit_custom_catalog(expected_catalog_generation,
				catalog.agents, failure)) throw std::runtime_error(failure);
		}, error);
#endif
}

bool request_duplicate(const std::string& source_identity,
	const std::string& new_identity, std::uint64_t expected_catalog_generation,
	std::string* error)
{
	const auto publication = snapshot();
	const auto* source = find(publication, source_identity);
	if (!source) {
		if (error) *error = "The source agent no longer exists";
		return false;
	}
	auto duplicate = *source;
	duplicate.name = new_identity;
	duplicate.native = false;
	return request_upsert(duplicate, {}, expected_catalog_generation, error);
}

bool request_delete(const std::string& identity,
	std::uint64_t expected_catalog_generation, std::string* error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto current = snapshot();
	const auto* selected = find(current, identity);
	if (!selected || selected->native) {
		if (error) *error = "Only a current custom agent can be deleted";
		return false;
	}
	auto next = std::make_shared<snapshot_t>(*current);
	next->agents.erase(std::remove_if(next->agents.begin(), next->agents.end(),
		[&](const auto& agent) { return agent.name == identity; }), next->agents.end());
	next->generation = runtime().generation.fetch_add(1) + 1;
	next->state = operation_state_t::succeeded;
	next->detail = "Deterministic preview agent deletion";
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)),
		std::memory_order_release);
	static_cast<void>(expected_catalog_generation);
	return true;
#else
	return submit("Delete custom agent", "agent.manager.delete", false,
		[identity, expected_catalog_generation](const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			auto catalog = aida::agent::custom_catalog_snapshot();
			if (catalog.generation != expected_catalog_generation)
				throw std::runtime_error("Custom agent catalog changed; review deletion again");
			const auto found = std::find_if(catalog.agents.begin(), catalog.agents.end(),
				[&](const auto& agent) { return agent.name == identity; });
			if (found == catalog.agents.end())
				throw std::runtime_error("The reviewed custom agent no longer exists");
			catalog.agents.erase(found);
			if (cancelled->load(std::memory_order_acquire)) return;
			std::string failure;
			if (!aida::agent::commit_custom_catalog(expected_catalog_generation,
				catalog.agents, failure)) throw std::runtime_error(failure);
		}, error);
#endif
}

}
