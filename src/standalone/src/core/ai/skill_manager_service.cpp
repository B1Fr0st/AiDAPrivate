#include "skill_manager_service.hpp"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <functional>
#include <mutex>
#include <stdexcept>

namespace aida::skill_manager_service {
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

std::shared_ptr<snapshot_t> copy_publication(operation_state_t state,
	std::string operation, std::string detail)
{
	auto current = std::atomic_load_explicit(&runtime().publication,
		std::memory_order_acquire);
	auto next = current ? std::make_shared<snapshot_t>(*current)
		: std::make_shared<snapshot_t>();
	next->generation = runtime().generation.fetch_add(1,
		std::memory_order_acq_rel) + 1;
	next->state = state;
	next->operation = std::move(operation);
	next->detail = std::move(detail);
	return next;
}

void refresh_catalog(snapshot_t& next)
{
	next.skills = aida::skills::all();
	next.remote_urls = aida::skills::list_remote_urls();
	next.disabled.clear();
	for (const auto& name : aida::skills::list_disabled())
		next.disabled.insert(name);
	if (!next.resolved_name.empty() && std::none_of(next.skills.begin(), next.skills.end(),
		[&](const auto& skill) { return skill.name == next.resolved_name; })) {
		next.resolved_name.clear();
		next.resolved_body.clear();
		next.resolved_hints.clear();
	}
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

using operation_t = std::function<void(snapshot_t&,
	const std::shared_ptr<std::atomic<bool>>&)>;

bool submit(const char* label, const char* action,
	aida::infra::executor::domain_t domain, operation_t operation,
	std::string* error)
{
	auto& rt = runtime();
	const auto lifecycle = std::make_shared<pending_lifecycle_t>(rt.pending);
	bool expected = false;
	if (!rt.pending.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) {
		if (error) *error = "Another Skills operation is already running";
		return false;
	}
	pending_scope_t setup_scope(lifecycle);
	std::shared_ptr<std::atomic<bool>> cancelled;
	std::uint64_t submitted_task_id = 0;
	try {
		auto loading = copy_publication(operation_state_t::loading, label, {});
		std::atomic_store_explicit(&rt.publication,
			std::shared_ptr<const snapshot_t>(std::move(loading)),
			std::memory_order_release);
		cancelled = std::make_shared<std::atomic<bool>>(false);
		aida::infra::executor::submission_t submission;
		submission.owner_subsystem = "ai_skill_manager";
		submission.label = label;
		submission.thread_class = "bounded_task";
		submission.domain = domain;
		submission.priority = 3;
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
			std::shared_ptr<snapshot_t> next;
			try {
				detail = label + " completed";
				next = copy_publication(state, label, detail);
				if (cancelled->load(std::memory_order_acquire)) {
					state = operation_state_t::cancelled;
					detail = label + " was cancelled";
				} else {
					operation(*next, cancelled);
					if (cancelled->load(std::memory_order_acquire)) {
						state = operation_state_t::cancelled;
						detail = label + " was cancelled";
					}
				}
			} catch (const std::exception& exception) {
				state = operation_state_t::failed;
				try { detail = exception.what(); }
				catch (...) { detail.clear(); }
			} catch (...) {
				state = operation_state_t::failed;
				try { detail = "Skills operation failed"; }
				catch (...) { detail.clear(); }
			}
			const bool terminal_owner = worker_scope.lifecycle->finish([&]() {
				try {
					if (!next) next = copy_publication(state, label, detail);
					next->state = state;
					next->operation = label;
					next->detail = detail;
					publish_terminal(std::move(next));
				} catch (...) {
					state = operation_state_t::failed;
					try {
						detail = "Skills Manager could not publish the operation result";
						auto failure = copy_publication(state, label, detail);
						publish_terminal(std::move(failure));
					} catch (...) {}
				}
			});
			worker_scope.dismiss();
			if (!terminal_owner) return;
			if (state == operation_state_t::failed)
				throw std::runtime_error(detail.empty()
					? "Skills operation failed" : detail);
		};
		const auto submitted = aida::infra::executor::submit(std::move(submission));
		if (!submitted.submitted) {
			const std::string detail = submitted.reject_reason.empty()
				? "Skills executor rejected the operation" : submitted.reject_reason;
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(copy_publication(operation_state_t::failed, label, detail));
			}));
			setup_scope.dismiss();
			if (error) *error = detail;
			return false;
		}
		submitted_task_id = submitted.task_id;
		aida::ui::task_center::task_registration_t registration;
		registration.id = "skills.manager." + std::to_string(submitted.task_id);
		registration.source = "Skills";
		registration.owner = "ai_skill_manager";
		registration.owner_view = "view.ai.skills";
		registration.owner_action = action;
		registration.label = label;
		registration.stage = "Queued";
		registration.affected_entity = "skill catalog";
		registration.cancellation_is_safe = true;
		registration.callbacks.cancel = [cancelled, task_id = submitted.task_id]() {
			cancelled->store(true, std::memory_order_release);
			return aida::infra::executor::cancel(task_id);
		};
		if (!aida::ui::task_center::try_register_executor_job(submitted.task_id,
			std::move(registration))) {
			cancelled->store(true, std::memory_order_release);
			static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
			const std::string detail = "Task Center rejected Skills ownership";
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(copy_publication(operation_state_t::failed, label, detail));
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
			try { detail = "Skills Manager setup failed"; } catch (...) {}
		}
		static_cast<void>(lifecycle->finish([&]() {
			publish_terminal(copy_publication(operation_state_t::failed, label, detail));
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
			const std::string detail = "Skills Manager setup failed";
			static_cast<void>(lifecycle->finish([&]() {
				publish_terminal(copy_publication(operation_state_t::failed, label, detail));
			}));
			if (error) *error = detail;
		} catch (...) {}
		static_cast<void>(lifecycle->release());
		setup_scope.dismiss();
		return false;
	}
}

#endif

bool reject_empty(const std::string& value, const char* label, std::string* error)
{
	if (!value.empty()) return false;
	if (error) *error = std::string(label) + " is required";
	return true;
}

}

snapshot_ptr snapshot()
{
	return std::atomic_load_explicit(&runtime().publication,
		std::memory_order_acquire);
}

const aida::skills::skill_metadata_t* find(const snapshot_ptr& publication,
	const std::string& name)
{
	if (!publication) return nullptr;
	const auto found = std::find_if(publication->skills.begin(), publication->skills.end(),
		[&](const auto& skill) { return skill.name == name; });
	return found == publication->skills.end() ? nullptr : &*found;
}

void begin_frame()
{
	auto& rt = runtime();
	bool expected = false;
	if (!rt.initialized.compare_exchange_strong(expected, true,
		std::memory_order_acq_rel)) return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto initial = copy_publication(operation_state_t::succeeded,
		"Preview skill catalog", "Deterministic in-memory Skills preview");
	refresh_catalog(*initial);
	std::atomic_store_explicit(&rt.publication,
		std::shared_ptr<const snapshot_t>(std::move(initial)),
		std::memory_order_release);
#else
	std::string ignored;
	static_cast<void>(request_reindex(&ignored));
#endif
}

bool request_reindex(std::string* error)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = copy_publication(operation_state_t::succeeded,
		"Reindex skills", "Preview skill catalog refreshed");
	refresh_catalog(*next);
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	static_cast<void>(error);
	return true;
#else
	return submit("Reindex skills", "skills.reindex",
		aida::infra::executor::domain_t::general,
		[](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			if (!aida::skills::reindex())
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
		}, error);
#endif
}

bool request_resolve(const std::string& name, std::string* error)
{
	if (reject_empty(name, "Skill name", error)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = copy_publication(operation_state_t::succeeded,
		"Resolve skill", "Preview skill resolved");
	const auto content = aida::skills::resolve(name);
	next->resolved_name = name;
	next->resolved_body = content.instructions;
	next->resolved_hints = aida::skills::placeholder_hints_for(content.instructions);
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	return true;
#else
	return submit("Resolve skill", "skills.resolve",
		aida::infra::executor::domain_t::general,
		[name](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			const auto content = aida::skills::resolve(name);
			if (content.name.empty() && content.instructions.empty())
				throw std::runtime_error("The selected skill could not be resolved");
			next.resolved_name = name;
			next.resolved_body = content.instructions;
			next.resolved_hints = aida::skills::placeholder_hints_for(content.instructions);
		}, error);
#endif
}

bool request_set_enabled(const std::string& name, bool enabled, std::string* error)
{
	if (reject_empty(name, "Skill name", error)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = copy_publication(operation_state_t::succeeded,
		"Update skill availability", "Preview skill availability updated");
	if (enabled) next->disabled.erase(name); else next->disabled.insert(name);
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	return true;
#else
	return submit("Update skill availability", "skills.set_enabled",
		aida::infra::executor::domain_t::feature_worker,
		[name, enabled](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			if (!aida::skills::set_enabled(name, enabled))
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
		}, error);
#endif
}

bool request_add_remote_url(const std::string& url, std::string* error)
{
	if (reject_empty(url, "Remote URL", error)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = copy_publication(operation_state_t::succeeded,
		"Add remote skill source", "Preview remote source added");
	if (std::find(next->remote_urls.begin(), next->remote_urls.end(), url) == next->remote_urls.end())
		next->remote_urls.push_back(url);
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	return true;
#else
	return submit("Add remote skill source", "skills.remote.add",
		aida::infra::executor::domain_t::external_tool,
		[url](snapshot_t& next, const auto& cancelled) {
			if (!aida::skills::add_remote_url(url))
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
			if (cancelled->load(std::memory_order_acquire)) return;
			aida::skills::remote_index_t index;
			if (!aida::skills::fetch_remote_index(url, index, 10000))
				throw std::runtime_error(aida::skills::last_error());
			next.remote_indices[url] = std::move(index);
		}, error);
#endif
}

bool request_remove_remote_url(const std::string& url, std::string* error)
{
	if (reject_empty(url, "Remote URL", error)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = copy_publication(operation_state_t::succeeded,
		"Remove remote skill source", "Preview remote source removed");
	next->remote_urls.erase(std::remove(next->remote_urls.begin(),
		next->remote_urls.end(), url), next->remote_urls.end());
	next->remote_indices.erase(url);
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	return true;
#else
	return submit("Remove remote skill source", "skills.remote.remove",
		aida::infra::executor::domain_t::feature_worker,
		[url](snapshot_t& next, const auto&) {
			if (!aida::skills::remove_remote_url(url))
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
			next.remote_indices.erase(url);
		}, error);
#endif
}

bool request_fetch_remote(const std::string& url, std::string* error)
{
	if (reject_empty(url, "Remote URL", error)) return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(error);
	return true;
#else
	return submit("Fetch remote skill index", "skills.remote.fetch",
		aida::infra::executor::domain_t::external_tool,
		[url](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			aida::skills::remote_index_t index;
			if (!aida::skills::fetch_remote_index(url, index, 10000))
				throw std::runtime_error(aida::skills::last_error());
			next.remote_indices[url] = std::move(index);
		}, error);
#endif
}

bool request_install(const std::string& url, const std::string& name, std::string* error)
{
	if (reject_empty(url, "Remote URL", error) || reject_empty(name, "Skill name", error))
		return false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(error);
	return true;
#else
	return submit("Install remote skill", "skills.remote.install",
		aida::infra::executor::domain_t::external_tool,
		[url, name](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			if (!aida::skills::install_remote_skill(url, name))
				throw std::runtime_error(aida::skills::last_error());
			if (!aida::skills::reindex())
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
		}, error);
#endif
}

bool request_uninstall(const std::string& name, std::uint64_t reviewed_generation,
	std::string* error)
{
	if (reject_empty(name, "Skill name", error)) return false;
	const auto reviewed = snapshot();
	const auto* skill = find(reviewed, name);
	if (!reviewed || reviewed->generation != reviewed_generation || !skill ||
		skill->source != "remote") {
		if (error) *error = "The reviewed remote skill changed; review deletion again";
		return false;
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	auto next = std::make_shared<snapshot_t>(*reviewed);
	next->generation = runtime().generation.fetch_add(1) + 1;
	next->skills.erase(std::remove_if(next->skills.begin(), next->skills.end(),
		[&](const auto& candidate) { return candidate.name == name; }), next->skills.end());
	next->state = operation_state_t::succeeded;
	next->operation = "Uninstall remote skill";
	next->detail = "Preview remote skill uninstalled";
	std::atomic_store_explicit(&runtime().publication,
		std::shared_ptr<const snapshot_t>(std::move(next)), std::memory_order_release);
	return true;
#else
	return submit("Uninstall remote skill", "skills.remote.uninstall",
		aida::infra::executor::domain_t::feature_worker,
		[name](snapshot_t& next, const auto& cancelled) {
			if (cancelled->load(std::memory_order_acquire)) return;
			if (!aida::skills::uninstall_remote_skill(name))
				throw std::runtime_error(aida::skills::last_error());
			if (!aida::skills::reindex())
				throw std::runtime_error(aida::skills::last_error());
			refresh_catalog(next);
		}, error);
#endif
}

}
