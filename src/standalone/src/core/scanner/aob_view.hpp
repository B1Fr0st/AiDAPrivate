#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <atomic>

#include "imgui.h"
#include "aob_generator.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "ui_anim.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../anti-tamper/webhook.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../ui/task_center.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "scanner_async_io.hpp"
#endif
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../ui/responsive.hpp"
#include "../ui/toast_notification.hpp"

namespace aob_view {

enum class format_tab_t : int {
	standard = 0,
	ida_style,
	code_pattern,
	x64dbg,
	COUNT
};

enum class operation_terminal_t : std::uint8_t {
	idle,
	queued,
	running,
	succeeded,
	failed,
	cancelled,
	stale
};

struct operation_status_t {
	operation_terminal_t terminal = operation_terminal_t::idle;
	std::string message;
	std::string path;
};

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_saved = -1;
	std::uint64_t context_address = 0;
	std::string context_name;
	format_tab_t active_format = format_tab_t::standard;
	std::mutex operation_mutex;
	operation_status_t export_status;
	operation_status_t catalog_status;
	operation_status_t comparison_status;
	std::atomic<bool> export_pending{false};
	std::atomic<bool> catalog_pending{false};
	std::atomic<bool> comparison_pending{false};
	std::atomic<bool> export_dispatch_failed{false};
	std::atomic<bool> catalog_dispatch_failed{false};
	std::atomic<bool> comparison_dispatch_failed{false};
	std::atomic<std::uint64_t> export_serial{0};
	std::atomic<std::uint64_t> catalog_serial{0};
	std::atomic<std::uint64_t> comparison_serial{0};
	aob_generator::export_format_t last_export_format = aob_generator::export_format_t::json;
	std::string last_export_path;
	bool last_catalog_save = true;
};

inline state_t g_state;

inline bool context_key_pressed()
{
	return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		(ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

inline std::mutex& workspace_view_states_mutex()
{
	static std::mutex mutex;
	return mutex;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& workspace_view_states()
{
	static std::unordered_map<std::string, std::shared_ptr<state_t>> states;
	return states;
}

inline std::shared_ptr<state_t> view_state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(workspace_view_states_mutex());
	auto& state = workspace_view_states()[key];
	if (!state) {
		state = std::make_shared<state_t>();
	}
	return state;
}

namespace detail {

inline aida::ui::components::pill_kind_t grade_pill_kind(float qs) {
	if (qs >= 0.85f) return aida::ui::components::pill_kind_t::success;
	if (qs >= 0.7f)  return aida::ui::components::pill_kind_t::info;
	if (qs >= 0.5f)  return aida::ui::components::pill_kind_t::warning;
	return aida::ui::components::pill_kind_t::error;
}

inline ImU32 grade_color(float qs) {
	const auto& t = aida::ui::resolved();
	if (qs >= 0.85f) return t.success;
	if (qs >= 0.7f)  return t.info;
	if (qs >= 0.5f)  return t.warning;
	return t.error;
}

inline void open_saved_in_hex(const disasm_view::workspace_context_t& context,
	std::uint64_t address)
{
	if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
		hex_view::request_live_memory(context, address, 256);
		return;
	}
	hex_view::activate(context);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	aida::preview::scan::record("aob.open_hex", std::to_string(address));
#endif
}

inline std::string format_for_tab(const aob_generator::signature_t& sig, format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return aob_generator::format_signature(sig);
	case format_tab_t::ida_style:    return aob_generator::format_ida_signature(sig);
	case format_tab_t::code_pattern: return aob_generator::format_code_signature(sig);
	case format_tab_t::x64dbg:       return aob_generator::format_x64dbg_signature(sig);
	default: return aob_generator::format_signature(sig);
	}
}

inline bool signature_bytes_equal(const std::vector<aob_generator::aob_byte_t>& lhs,
	const std::vector<aob_generator::aob_byte_t>& rhs)
{
	return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin(),
		[](const auto& left, const auto& right) {
			return left.value == right.value && left.wildcard == right.wildcard;
		});
}

inline const char* tab_name(format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return "Standard";
	case format_tab_t::ida_style:    return "IDA";
	case format_tab_t::code_pattern: return "Code";
	case format_tab_t::x64dbg:       return "x64dbg";
	default: return "Standard";
	}
}

inline void render_format_segmented(float x, float y, float& width_used, format_tab_t& active) {
	const auto& t = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float pad_x = 4.f;
	float h = 26.f;
	float total_w = pad_x * 2.f;
	constexpr int format_count = static_cast<int>(format_tab_t::COUNT);
	float seg_w[format_count];
	for (int i = 0; i < format_count; ++i) {
		const char* nm = tab_name(static_cast<format_tab_t>(i));
		ImVec2 sz = ImGui::CalcTextSize(nm);
		seg_w[i] = sz.x + 18.f;
		total_w += seg_w[i];
	}
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.panel_header, 1.f), h * 0.5f);
	dl->AddRect(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.border_subtle, 1.f), h * 0.5f, 0, 1.f);

	float cx = x + pad_x;
	for (int i = 0; i < format_count; ++i) {
		ImGui::PushID(i);
		ImGui::SetCursorScreenPos(ImVec2(cx, y));
		ImGui::InvisibleButton("##seg", ImVec2(seg_w[i], h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		bool act = (active == static_cast<format_tab_t>(i));
		if (clk) active = static_cast<format_tab_t>(i);

		if (act) {
			ImVec2 a(cx + 2.f, y + 2.f);
			ImVec2 b(cx + seg_w[i] - 2.f, y + h - 2.f);
			float seg_radius = (h - 4.f) * 0.5f;
			dl->AddRectFilled(a, b,
				aida::ui::mix(t.accent_grad_top, t.accent_grad_bot, 0.45f),
				seg_radius);
		} else if (hov) {
			dl->AddRectFilled(ImVec2(cx + 2.f, y + 2.f),
				ImVec2(cx + seg_w[i] - 2.f, y + h - 2.f),
				aida::ui::with_alpha(t.hover_wash, 1.f), (h - 4.f) * 0.5f);
		}

		const char* nm = tab_name(static_cast<format_tab_t>(i));
		ImVec2 ts = ImGui::CalcTextSize(nm);
		ImU32 tc = act ? IM_COL32(255, 255, 255, 240) : t.text_secondary;
		dl->AddText(ImVec2(cx + (seg_w[i] - ts.x) * 0.5f, y + (h - ts.y) * 0.5f), tc, nm);

		cx += seg_w[i];
		ImGui::PopID();
	}
	width_used = total_w;
}

inline void set_operation_status(const std::shared_ptr<state_t>& state,
	operation_status_t state_t::* member, operation_terminal_t terminal,
	std::string message, std::string path = {})
{
	if (!state) return;
	std::lock_guard<std::mutex> lock(state->operation_mutex);
	auto& status = state.get()->*member;
	status.terminal = terminal;
	status.message = std::move(message);
	status.path = std::move(path);
}

inline bool workspace_matches(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
	const std::string& binary_id, std::uint64_t workspace_generation,
	std::uint64_t publication_generation, std::uint32_t pid)
{
	if (!workspace || workspace->closing() || workspace->closed() ||
		workspace->identity().binary_id().to_hex() != binary_id ||
		workspace->generation() != workspace_generation) return false;
	const auto publication = workspace->analysis_publication();
	if (!publication || publication->generation != publication_generation) return false;
	const auto process = workspace->identity().process();
	return pid == 0 ? !process : process && process->pid == pid;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::atomic<std::uint64_t> operation_sequence{1};

inline std::string register_operation(const char* action, const char* label,
	const std::string& target, const std::shared_ptr<std::atomic<bool>>& cancellation,
	const std::shared_ptr<std::atomic<std::uint8_t>>& commit_gate = {})
{
	const std::string id = "scanner.aob.operation." +
		std::to_string(operation_sequence.fetch_add(1, std::memory_order_acq_rel));
	aida::ui::task_center::task_registration_t registration;
	registration.id = id;
	registration.source = "human";
	registration.owner = "AOB Generator";
	registration.owner_view = "view.memory.aob";
	registration.owner_action = action;
	registration.target = target;
	registration.label = label;
	registration.stage = "Queued";
	registration.progress = -1.0f;
	registration.cancellation_is_safe = static_cast<bool>(cancellation);
	if (cancellation) registration.callbacks.cancel = [cancellation, commit_gate] {
		if (commit_gate) {
			std::uint8_t expected_gate = scanner_async_io::operation_reversible;
			if (!commit_gate->compare_exchange_strong(expected_gate,
				scanner_async_io::operation_cancelled, std::memory_order_acq_rel,
				std::memory_order_acquire)) return false;
		}
		bool expected = false;
		return cancellation->compare_exchange_strong(expected, true, std::memory_order_acq_rel);
	};
	registration.callbacks.focus = [] {
		static_cast<void>(aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.memory.aob")));
	};
	return aida::ui::task_center::register_task(std::move(registration)) ? id : std::string();
}

inline void finish_operation(const std::string& task_id, operation_terminal_t terminal,
	const std::string& stage, const std::string& summary)
{
	if (task_id.empty()) return;
	auto task_state = aida::ui::task_center::task_state_t::failed;
	if (terminal == operation_terminal_t::succeeded)
		task_state = aida::ui::task_center::task_state_t::completed;
	else if (terminal == operation_terminal_t::cancelled || terminal == operation_terminal_t::stale)
		task_state = aida::ui::task_center::task_state_t::cancelled;
	static_cast<void>(aida::ui::task_center::update_task(task_id, task_state, 1.0f,
		stage, summary));
}
#endif

inline void reconcile_dispatch_failures(const std::shared_ptr<state_t>& state)
{
	if (!state) return;
	if (state->export_dispatch_failed.exchange(false, std::memory_order_acq_rel))
		set_operation_status(state, &state_t::export_status, operation_terminal_t::failed,
			"UI dispatcher rejected AOB export completion");
	if (state->catalog_dispatch_failed.exchange(false, std::memory_order_acq_rel))
		set_operation_status(state, &state_t::catalog_status, operation_terminal_t::failed,
			"UI dispatcher rejected AOB catalog completion");
	if (state->comparison_dispatch_failed.exchange(false, std::memory_order_acq_rel))
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			"UI dispatcher rejected AOB comparison completion");
}

inline void request_export(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<aob_generator::state_t>& generator,
	const std::shared_ptr<state_t>& state, aob_generator::export_format_t format,
	std::string requested_path)
{
	if (!context.workspace || !context.publication || !generator || !state) return;
	bool expected = false;
	if (!state->export_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	const std::uint64_t serial = state->export_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
	std::vector<aob_generator::signature_t> signatures;
	std::uint64_t catalog_generation = 0;
	{
		std::lock_guard<std::mutex> lock(generator->mutex);
		signatures = generator->saved_signatures;
		catalog_generation = generator->catalog_generation.load(std::memory_order_acquire);
	}
	state->last_export_format = format;
	state->last_export_path = requested_path;
	set_operation_status(state, &state_t::export_status, operation_terminal_t::queued,
		"Queued immutable AOB export", requested_path);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(serial);
	static_cast<void>(catalog_generation);
	const char* receipt = format == aob_generator::export_format_t::json ? "aob.export.json" :
		format == aob_generator::export_format_t::yara ? "aob.export.yara" : "aob.export.header";
	aida::preview::scan::record(receipt, context.workspace->identity().binary_id().to_hex() + ":" +
		std::to_string(signatures.size()));
	set_operation_status(state, &state_t::export_status, operation_terminal_t::succeeded,
		"Studio receipt recorded for immutable AOB export", requested_path);
	state->export_pending.store(false, std::memory_order_release);
#else
	const auto workspace = context.workspace;
	const std::string binary_id = workspace->identity().binary_id().to_hex();
	const std::uint64_t workspace_generation = workspace->generation();
	const std::uint64_t publication_generation = context.publication->generation;
	const auto process = workspace->identity().process();
	const std::uint32_t pid = process ? process->pid : 0;
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto commit_gate = std::make_shared<std::atomic<std::uint8_t>>(
		scanner_async_io::operation_reversible);
	const std::string task_id = register_operation("scanner.aob.export", "Export AOB signatures",
		binary_id, cancellation, commit_gate);
	if (task_id.empty()) {
		state->export_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::export_status, operation_terminal_t::failed,
			"Task Center rejected AOB export ownership", requested_path);
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner.aob";
	submission.label = "scanner.aob.export";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.target_pid = pid;
	submission.generation = publication_generation;
	submission.cancel_hook = [cancellation, commit_gate] {
		std::uint8_t expected_gate = scanner_async_io::operation_reversible;
		if (commit_gate->compare_exchange_strong(expected_gate, scanner_async_io::operation_cancelled,
			std::memory_order_acq_rel, std::memory_order_acquire))
			cancellation->store(true, std::memory_order_release);
	};
	submission.body = [workspace, generator, state, signatures = std::move(signatures), format,
		requested_path = std::move(requested_path), cancellation, task_id, binary_id,
		workspace_generation, publication_generation, pid, catalog_generation, serial,
		commit_gate]() mutable {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.1f, "Serializing bounded AOB catalog"));
		static_cast<void>(aida::ui_thread::post([state, serial] {
			if (state->export_serial.load(std::memory_order_acquire) == serial &&
				state->export_pending.load(std::memory_order_acquire))
				set_operation_status(state, &state_t::export_status, operation_terminal_t::running,
					"Serializing bounded AOB export");
		}, "scanner.aob", "publish_export_running", "worker_progress"));
		std::string output;
		std::string error;
		bool serialized = aob_generator::serialize_catalog(signatures, format, output, error, cancellation);
		std::string path = requested_path;
		if (serialized && path.empty()) {
			const std::string cache = aob_generator::get_aob_cache_dir();
			if (!cache.empty()) {
				const std::string extension = format == aob_generator::export_format_t::json ? ".json" :
					format == aob_generator::export_format_t::yara ? ".yar" : ".hpp";
				path = (std::filesystem::path(cache).parent_path() /
					("aob_export" + extension)).string();
			}
			if (path.empty()) { serialized = false; error = "APPDATA is unavailable for AOB export"; }
		}
		auto current = [workspace, generator, binary_id, workspace_generation,
			publication_generation, pid, catalog_generation] {
			return workspace_matches(workspace, binary_id, workspace_generation,
				publication_generation, pid) &&
				generator->catalog_generation.load(std::memory_order_acquire) == catalog_generation;
		};
		scanner_async_io::result_t write;
		if (serialized && current())
			write = scanner_async_io::atomic_replace(path, output, true, cancellation, current, commit_gate);
		else if (serialized)
			write.error = "AOB workspace, target, publication, or catalog generation changed";
		const bool cancelled = scanner_async_io::cancellation_requested(cancellation) || write.cancelled;
		const bool stale = !cancelled && !current();
		const bool success = serialized && write.success && !stale;
		if (!success && error.empty()) error = write.error;
		const operation_terminal_t terminal = success ? operation_terminal_t::succeeded :
			cancelled ? operation_terminal_t::cancelled : stale ? operation_terminal_t::stale :
			operation_terminal_t::failed;
		auto publish = [state, serial, terminal, error = std::move(error), path]() mutable {
			if (state->export_serial.load(std::memory_order_acquire) != serial) return;
			set_operation_status(state, &state_t::export_status, terminal,
				terminal == operation_terminal_t::succeeded ? "AOB export committed atomically" : error, path);
			state->export_pending.store(false, std::memory_order_release);
		};
		finish_operation(task_id, terminal, success ? "AOB export complete" : "AOB export did not commit",
			success ? path : error);
		if (!aida::ui_thread::post(std::move(publish), "scanner.aob", "publish_export", "worker_completion")) {
			state->export_pending.store(false, std::memory_order_release);
			state->export_dispatch_failed.store(true, std::memory_order_release);
			finish_operation(task_id, operation_terminal_t::failed, "UI publication rejected",
				"AOB export completion was not published");
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		state->export_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::export_status, operation_terminal_t::failed,
			"Worker queue rejected AOB export: " + submitted.reject_reason, state->last_export_path);
		finish_operation(task_id, operation_terminal_t::failed, "Worker queue rejected", submitted.reject_reason);
	}
#endif
}

inline void request_catalog(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<aob_generator::state_t>& generator,
	const std::shared_ptr<state_t>& state, bool save)
{
	if (!context.workspace || !context.publication || !generator || !state) return;
	bool expected = false;
	if (!state->catalog_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	const std::uint64_t serial = state->catalog_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
	state->last_catalog_save = save;
	std::vector<aob_generator::signature_t> signatures;
	std::uint64_t catalog_generation = 0;
	{
		std::lock_guard<std::mutex> lock(generator->mutex);
		signatures = generator->saved_signatures;
		catalog_generation = generator->catalog_generation.load(std::memory_order_acquire);
	}
	set_operation_status(state, &state_t::catalog_status, operation_terminal_t::queued,
		save ? "Queued saved-signature catalog commit" : "Queued saved-signature catalog load");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(serial);
	static_cast<void>(catalog_generation);
	if (!save && signatures.empty()) {
		std::lock_guard<std::mutex> lock(generator->mutex);
		if (!generator->current.bytes.empty()) generator->saved_signatures.push_back(generator->current);
		generator->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
	}
	aida::preview::scan::record(save ? "aob.catalog.save" : "aob.catalog.load",
		context.workspace->identity().binary_id().to_hex());
	set_operation_status(state, &state_t::catalog_status, operation_terminal_t::succeeded,
		save ? "Studio saved-catalog receipt recorded" : "Studio catalog fixture published");
	state->catalog_pending.store(false, std::memory_order_release);
#else
	const auto workspace = context.workspace;
	const std::string binary_id = workspace->identity().binary_id().to_hex();
	const std::uint64_t workspace_generation = workspace->generation();
	const std::uint64_t publication_generation = context.publication->generation;
	const auto process = workspace->identity().process();
	const std::uint32_t pid = process ? process->pid : 0;
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto commit_gate = std::make_shared<std::atomic<std::uint8_t>>(
		scanner_async_io::operation_reversible);
	const std::string task_id = register_operation(save ? "scanner.aob.catalog.save" : "scanner.aob.catalog.load",
		save ? "Save AOB signature catalog" : "Load AOB signature catalog", binary_id,
		cancellation, commit_gate);
	if (task_id.empty()) {
		state->catalog_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::catalog_status, operation_terminal_t::failed,
			"Task Center rejected AOB catalog ownership");
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner.aob";
	submission.label = save ? "scanner.aob.catalog.save" : "scanner.aob.catalog.load";
	submission.thread_class = "bounded_task";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.target_pid = pid;
	submission.generation = publication_generation;
	submission.cancel_hook = [cancellation, commit_gate] {
		std::uint8_t expected_gate = scanner_async_io::operation_reversible;
		if (commit_gate->compare_exchange_strong(expected_gate, scanner_async_io::operation_cancelled,
			std::memory_order_acq_rel, std::memory_order_acquire))
			cancellation->store(true, std::memory_order_release);
	};
	submission.body = [workspace, generator, state, signatures = std::move(signatures), save,
		cancellation, task_id, binary_id, workspace_generation, publication_generation,
		pid, catalog_generation, serial, commit_gate]() mutable {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.1f,
			save ? "Serializing saved AOB catalog" : "Reading and validating saved AOB catalog"));
		static_cast<void>(aida::ui_thread::post([state, serial, save] {
			if (state->catalog_serial.load(std::memory_order_acquire) == serial &&
				state->catalog_pending.load(std::memory_order_acquire))
				set_operation_status(state, &state_t::catalog_status, operation_terminal_t::running,
					save ? "Serializing saved AOB catalog" : "Reading and validating saved AOB catalog");
		}, "scanner.aob", "publish_catalog_running", "worker_progress"));
		const std::string directory = aob_generator::get_aob_cache_dir();
		const std::string path = directory.empty() ? std::string() :
			(directory + "\\" + binary_id + ".json");
		auto current = [workspace, generator, binary_id, workspace_generation,
			publication_generation, pid, catalog_generation] {
			return workspace_matches(workspace, binary_id, workspace_generation,
				publication_generation, pid) &&
				generator->catalog_generation.load(std::memory_order_acquire) == catalog_generation;
		};
		std::string error;
		bool success = false;
		bool cancelled = false;
		std::vector<aob_generator::signature_t> staged;
		std::uint64_t maximum_id = 0;
		if (path.empty()) {
			error = "APPDATA is unavailable for the AOB saved catalog";
		} else if (save) {
			std::string output;
			if (aob_generator::serialize_catalog(signatures, aob_generator::export_format_t::json,
				output, error, cancellation) && current()) {
				auto write = scanner_async_io::atomic_replace(path, output, true, cancellation, current, commit_gate);
				success = write.success;
				cancelled = write.cancelled;
				if (!success && error.empty()) error = write.error;
			} else if (error.empty()) {
				error = "AOB catalog changed before saved-catalog commit";
			}
		} else {
			std::string input;
			auto read = scanner_async_io::read_bounded(path, aob_generator::max_catalog_file_bytes,
				cancellation, input);
			cancelled = read.cancelled;
			if (read.success && current())
				success = aob_generator::parse_catalog(input, staged, maximum_id, error, cancellation);
			else if (!read.success) error = read.error;
			else error = "AOB catalog changed before saved-catalog validation";
		}
		cancelled = cancelled || scanner_async_io::cancellation_requested(cancellation);
		const bool stale = !cancelled && !current();
		if (stale) { success = false; error = "AOB workspace, target, publication, or catalog generation changed"; }
		const operation_terminal_t terminal = success ? operation_terminal_t::succeeded :
			cancelled ? operation_terminal_t::cancelled : stale ? operation_terminal_t::stale :
			operation_terminal_t::failed;
		auto publish = [workspace, generator, state, save, staged = std::move(staged), maximum_id,
			task_id, binary_id, workspace_generation, publication_generation, pid,
			catalog_generation, serial, terminal, error = std::move(error), path, commit_gate]() mutable {
			if (state->catalog_serial.load(std::memory_order_acquire) != serial) return;
			operation_terminal_t final_terminal = terminal;
			std::string final_error = error;
			if (terminal == operation_terminal_t::succeeded && !save) {
				std::uint8_t expected_gate = scanner_async_io::operation_reversible;
				if (!commit_gate->compare_exchange_strong(expected_gate,
					scanner_async_io::operation_committing, std::memory_order_acq_rel,
					std::memory_order_acquire)) {
					final_terminal = expected_gate == scanner_async_io::operation_cancelled
						? operation_terminal_t::cancelled : operation_terminal_t::failed;
					final_error = "AOB catalog load was cancelled before publication";
				} else if (!workspace_matches(workspace, binary_id, workspace_generation,
					publication_generation, pid) ||
					generator->catalog_generation.load(std::memory_order_acquire) != catalog_generation) {
					final_terminal = operation_terminal_t::stale;
					final_error = "AOB catalog changed before atomic publication";
				} else {
					std::lock_guard<std::mutex> lock(generator->mutex);
					generator->saved_signatures = std::move(staged);
					generator->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
					std::uint64_t next = aob_generator::g_next_signature_id.load(std::memory_order_acquire);
					while (maximum_id >= next && !aob_generator::g_next_signature_id.compare_exchange_weak(
						next, maximum_id + 1, std::memory_order_acq_rel)) {}
				}
			}
			set_operation_status(state, &state_t::catalog_status, final_terminal,
				final_terminal == operation_terminal_t::succeeded
					? (save ? "Saved-signature catalog committed atomically" :
						"Validated saved-signature catalog published atomically") : final_error, path);
			state->catalog_pending.store(false, std::memory_order_release);
			finish_operation(task_id, final_terminal,
				final_terminal == operation_terminal_t::succeeded ? "AOB catalog complete" : "AOB catalog failed",
				final_terminal == operation_terminal_t::succeeded ? path : final_error);
		};
		if (!aida::ui_thread::post(std::move(publish), "scanner.aob", "publish_catalog", "worker_completion")) {
			state->catalog_pending.store(false, std::memory_order_release);
			state->catalog_dispatch_failed.store(true, std::memory_order_release);
			finish_operation(task_id, operation_terminal_t::failed, "UI publication rejected",
				"AOB catalog completion was not published");
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		state->catalog_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::catalog_status, operation_terminal_t::failed,
			"Worker queue rejected AOB catalog operation: " + submitted.reject_reason);
		finish_operation(task_id, operation_terminal_t::failed, "Worker queue rejected", submitted.reject_reason);
	}
#endif
}

inline void request_comparison(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<aob_generator::state_t>& generator,
	const std::shared_ptr<state_t>& state)
{
	if (!context.workspace || !context.publication || !generator || !state) return;
	const auto process = context.workspace->identity().process();
	if (!process || process->pid == 0) {
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			"Attach a live process before comparing signatures");
		return;
	}
	bool expected = false;
	if (!state->comparison_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
	const std::uint64_t serial = state->comparison_serial.fetch_add(1, std::memory_order_acq_rel) + 1;
	std::vector<aob_generator::signature_t> signatures;
	std::uint64_t catalog_generation = 0;
	{
		std::lock_guard<std::mutex> lock(generator->mutex);
		signatures = generator->saved_signatures;
		catalog_generation = generator->catalog_generation.load(std::memory_order_acquire);
	}
	if (signatures.empty()) {
		state->comparison_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			"Save at least one signature before comparing");
		return;
	}
	set_operation_status(state, &state_t::comparison_status, operation_terminal_t::queued,
		"Queued immutable AOB comparison");
	const auto workspace = context.workspace;
	const std::string binary_id = workspace->identity().binary_id().to_hex();
	const std::uint64_t workspace_generation = workspace->generation();
	const std::uint64_t publication_generation = context.publication->generation;
	const std::uint32_t pid = process->pid;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	static_cast<void>(serial);
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto current = [workspace, generator, binary_id, workspace_generation,
		publication_generation, pid, catalog_generation] {
		return workspace_matches(workspace, binary_id, workspace_generation,
			publication_generation, pid) &&
			generator->catalog_generation.load(std::memory_order_acquire) == catalog_generation;
	};
	std::string error;
	auto results = aob_generator::compare_signatures_against_process(
		pid, signatures, cancellation, current, error);
	if (current() && results.size() == signatures.size()) {
		std::lock_guard<std::mutex> lock(generator->mutex);
		for (std::size_t index = 0; index < results.size(); ++index) {
			auto found = std::find_if(generator->saved_signatures.begin(), generator->saved_signatures.end(),
				[id = signatures[index].id](const auto& item) { return item.id == id; });
			if (found == generator->saved_signatures.end()) continue;
			found->unique = results[index].still_found;
			found->uniqueness_count = results[index].match_count;
			found->quality_score = aob_generator::compute_quality_score(*found);
		}
		generator->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
		aida::preview::scan::record("aob.compare", binary_id + ":" + std::to_string(results.size()));
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::succeeded,
			"Studio comparison fixture published");
	} else {
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			error.empty() ? "Studio comparison fixture was rejected" : error);
	}
	state->comparison_pending.store(false, std::memory_order_release);
#else
	auto cancellation = std::make_shared<std::atomic<bool>>(false);
	auto commit_gate = std::make_shared<std::atomic<std::uint8_t>>(
		scanner_async_io::operation_reversible);
	const std::string task_id = register_operation("scanner.aob.compare", "Compare AOB signatures",
		binary_id, cancellation, commit_gate);
	if (task_id.empty()) {
		state->comparison_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			"Task Center rejected AOB comparison ownership");
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "scanner.aob";
	submission.label = "scanner.aob.compare";
	submission.thread_class = "scanner_sweep";
	submission.domain = aida::infra::executor::domain_t::long_running;
	submission.priority = 2;
	submission.target_pid = pid;
	submission.generation = publication_generation;
	submission.cancel_hook = [cancellation, commit_gate] {
		std::uint8_t expected_gate = scanner_async_io::operation_reversible;
		if (commit_gate->compare_exchange_strong(expected_gate, scanner_async_io::operation_cancelled,
			std::memory_order_acq_rel, std::memory_order_acquire))
			cancellation->store(true, std::memory_order_release);
	};
	submission.body = [workspace, generator, state, signatures = std::move(signatures), cancellation,
		task_id, binary_id, workspace_generation, publication_generation, pid,
		catalog_generation, serial, commit_gate]() mutable {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, -1.0f, "Comparing signatures against live memory"));
		static_cast<void>(aida::ui_thread::post([state, serial] {
			if (state->comparison_serial.load(std::memory_order_acquire) == serial &&
				state->comparison_pending.load(std::memory_order_acquire))
				set_operation_status(state, &state_t::comparison_status, operation_terminal_t::running,
					"Comparing signatures against live memory");
		}, "scanner.aob", "publish_comparison_running", "worker_progress"));
		auto current = [workspace, generator, binary_id, workspace_generation,
			publication_generation, pid, catalog_generation] {
			return workspace_matches(workspace, binary_id, workspace_generation,
				publication_generation, pid) &&
				generator->catalog_generation.load(std::memory_order_acquire) == catalog_generation;
		};
		std::string error;
		auto results = aob_generator::compare_signatures_against_process(
			pid, signatures, cancellation, current, error);
		const bool cancelled = scanner_async_io::cancellation_requested(cancellation);
		const bool stale = !cancelled && !current();
		const bool success = !stale && !cancelled && error.empty() && results.size() == signatures.size();
		const operation_terminal_t terminal = success ? operation_terminal_t::succeeded :
			cancelled ? operation_terminal_t::cancelled : stale ? operation_terminal_t::stale :
			operation_terminal_t::failed;
		auto publish = [workspace, generator, state, signatures = std::move(signatures),
			results = std::move(results), task_id, binary_id, workspace_generation,
			publication_generation, pid, catalog_generation, serial, terminal,
			error = std::move(error), commit_gate]() mutable {
			if (state->comparison_serial.load(std::memory_order_acquire) != serial) return;
			operation_terminal_t final_terminal = terminal;
			std::string final_error = error;
			if (terminal == operation_terminal_t::succeeded) {
				std::uint8_t expected_gate = scanner_async_io::operation_reversible;
				if (!commit_gate->compare_exchange_strong(expected_gate,
					scanner_async_io::operation_committing, std::memory_order_acq_rel,
					std::memory_order_acquire)) {
					final_terminal = expected_gate == scanner_async_io::operation_cancelled
						? operation_terminal_t::cancelled : operation_terminal_t::failed;
					final_error = "AOB comparison was cancelled before publication";
				} else if (!workspace_matches(workspace, binary_id, workspace_generation,
					publication_generation, pid) ||
					generator->catalog_generation.load(std::memory_order_acquire) != catalog_generation) {
					final_terminal = operation_terminal_t::stale;
					final_error = "AOB comparison target or catalog changed before publication";
				} else {
					std::lock_guard<std::mutex> lock(generator->mutex);
					for (std::size_t index = 0; index < results.size(); ++index) {
						auto found = std::find_if(generator->saved_signatures.begin(), generator->saved_signatures.end(),
							[id = signatures[index].id](const auto& item) { return item.id == id; });
						if (found == generator->saved_signatures.end()) continue;
						found->unique = results[index].still_found;
						found->uniqueness_count = results[index].match_count;
						found->quality_score = aob_generator::compute_quality_score(*found);
					}
					generator->catalog_generation.fetch_add(1, std::memory_order_acq_rel);
				}
			}
			set_operation_status(state, &state_t::comparison_status, final_terminal,
				final_terminal == operation_terminal_t::succeeded
					? "AOB comparison published atomically" : final_error);
			state->comparison_pending.store(false, std::memory_order_release);
			finish_operation(task_id, final_terminal,
				final_terminal == operation_terminal_t::succeeded ? "AOB comparison complete" : "AOB comparison failed",
				final_terminal == operation_terminal_t::succeeded ? binary_id : final_error);
		};
		if (!aida::ui_thread::post(std::move(publish), "scanner.aob", "publish_comparison", "worker_completion")) {
			state->comparison_pending.store(false, std::memory_order_release);
			state->comparison_dispatch_failed.store(true, std::memory_order_release);
			finish_operation(task_id, operation_terminal_t::failed, "UI publication rejected",
				"AOB comparison completion was not published");
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		state->comparison_pending.store(false, std::memory_order_release);
		set_operation_status(state, &state_t::comparison_status, operation_terminal_t::failed,
			"Worker queue rejected AOB comparison: " + submitted.reject_reason);
		finish_operation(task_id, operation_terminal_t::failed, "Worker queue rejected", submitted.reject_reason);
	}
#endif
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float,
				   const disasm_view::workspace_context_t& context)
{
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##aob_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	const auto view_state = view_state_for(context);
	const auto generator_state = aob_generator::state_for(context);
	if (!view_state || !generator_state) {
		aida::ui::empty_state::config_t config;
		config.glyph = aida::ui::empty_state::glyph_t::binary_file;
		config.title = "No analysis target";
		config.body = "Open a binary or attach a live target to generate signatures.";
		aida::ui::empty_state::render(ImGui::GetWindowPos(), ImGui::GetWindowSize(), config);
		ImGui::EndChild();
		return;
	}
	detail::reconcile_dispatch_failures(view_state);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	if (generator_state->last_request_addr == 0) {
		std::snprintf(generator_state->name_input, sizeof(generator_state->name_input), "%s", "decrypt_dispatch");
		const std::uint64_t address = context.workspace->identity().image_base() + 0x16A0;
		aob_generator::generate_from_address(context, address, generator_state->instruction_count,
			generator_state->auto_wildcard);
		aob_generator::save_current(generator_state);
	}
#endif
	{
		std::string pending_clip;
		if (aob_generator::take_pending_clipboard(generator_state, pending_clip)) {
			ImGui::SetClipboardText(pending_clip.c_str());
		}
	}

	auto* dl = ImGui::GetWindowDrawList();
	auto& st = *view_state;
	auto& gen = *generator_state;
	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	const float body_font_size = aida::ui::fonts::size_or(body_font, ImGui::GetFontSize());
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_font_size = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = ImGui::GetWindowSize().x;
	float h = ImGui::GetWindowSize().y;

	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, alpha));

	const float kAobMinW = 520.f;
	if (w < kAobMinW) {
		static bool s_logged_aob_narrow = false;
		if (!s_logged_aob_narrow) {
			s_logged_aob_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"aob_view clamp_overlay width=%.0f min=%.0f", w, kAobMinW);
		}
		aida::ui::responsive::draw_clamp_overlay(
			ImVec2(ox, oy), ImVec2(w, h),
			"Widen the panel to use the AOB generator");
		ImGui::EndChild();
		return;
	}

	float left_w = w * 0.55f;
	float right_w = w - left_w - 8.f;

	float cx = ox + 16.f;
	float cy = oy + 12.f;

	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(cx, cy),
		aida::ui::with_alpha(t.text_primary, alpha),
		"AOB Signature Generator");
	cy += 22.f;

	{
		const bool live = context.workspace->target_kind() ==
			aida::analysis::target_kind_t::live_snapshot;
		const bool pe = context.workspace->target_kind() ==
			aida::analysis::target_kind_t::static_file && static_cast<bool>(context.image);
		if (!live && !pe) {
			ui_anim::render_inline_callout(dl, cx, cy, left_w - 24.f, 22.f,
				"Generate needs a live process attach or an open PE.",
				ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, alpha);
			cy += 26.f;
		}
	}

	{
		float input_h = 32.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		aida::ui::input_text("##aob_addr", gen.address_input, sizeof(gen.address_input),
			"Address (hex)", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 178.f, cy));
		aida::ui::input_text("##aob_name", gen.name_input, sizeof(gen.name_input),
			"Signature name", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 356.f, cy + 2.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushItemWidth(80.f);
		ImGui::InputInt("##aob_count", &gen.instruction_count, 1, 4);
		if (gen.instruction_count < 1) gen.instruction_count = 1;
		if (gen.instruction_count > 128) gen.instruction_count = 128;
		ImGui::PopItemWidth();
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
	}
	cy += 38.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool aw = gen.auto_wildcard;
		aida::ui::toggle_switch("##aw", &aw, aida::ui::size_t_::sm);
		gen.auto_wildcard = aw;
		ImFont* lbl_fn = body_font;
		float lbl_fs = body_font_size;
		float toggle_w = ImGui::GetItemRectSize().x;
		float aw_lbl_x = cx + toggle_w + 14.f;
		ImVec2 aw_ts = ImGui::CalcTextSize("Auto-wildcard");
		dl->AddText(lbl_fn, lbl_fs,
			ImVec2(aw_lbl_x, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Auto-wildcard");

		float vu_x = aw_lbl_x + aw_ts.x + 30.f;
		ImGui::SetCursorScreenPos(ImVec2(vu_x, cy));
		bool vu = gen.validate_uniqueness;
		aida::ui::toggle_switch("##vu", &vu, aida::ui::size_t_::sm);
		gen.validate_uniqueness = vu;
		float vu_toggle_w = ImGui::GetItemRectSize().x;
		dl->AddText(lbl_fn, lbl_fs,
			ImVec2(vu_x + vu_toggle_w + 14.f, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Validate uniqueness");
	}
	cy += 32.f;

	{
		bool generating = gen.generating.load();
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Generate", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), generating, nullptr, generating)) {
			diag::log_tagged_fmt("aob",
				"view generate_button_clicked input='%s' count=%d auto_wildcard=%d generating=%d",
				gen.address_input, gen.instruction_count,
				static_cast<int>(gen.auto_wildcard),
				static_cast<int>(generating));
			anti_tamper::webhook::write_log("aob", "generate button clicked");
			toast_notification::push("AOB: Generating signature...",
				toast_notification::toast_type_t::info, 1.5f);
			uint64_t addr = 0;
			if (gen.address_input[0]) {
				const char* p = gen.address_input;
				if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
				addr = std::strtoull(p, nullptr, 16);
			}
			if (addr == 0) {
				uint64_t fallback = 0;
				{
					std::lock_guard<std::mutex> lk(gen.mutex);
					fallback = gen.last_request_addr;
					if (fallback == 0 && gen.current.address != 0)
						fallback = gen.current.address;
				}
				if (fallback != 0) {
					diag::log_tagged_fmt("aob",
						"view generate using_fallback_address va=0x%llX",
						static_cast<unsigned long long>(fallback));
					addr = fallback;
					std::snprintf(gen.address_input, sizeof(gen.address_input),
						"%llX", static_cast<unsigned long long>(addr));
				}
			}
			if (addr != 0) {
				diag::log_tagged_fmt("aob",
					"view generate dispatching addr=0x%llX count=%d",
					static_cast<unsigned long long>(addr), gen.instruction_count);
				aob_generator::generate_from_address(context, addr, gen.instruction_count, gen.auto_wildcard);
			} else {
				const bool live = context.workspace->target_kind() ==
					aida::analysis::target_kind_t::live_snapshot;
				const bool pe = context.workspace->target_kind() ==
					aida::analysis::target_kind_t::static_file && static_cast<bool>(context.image);
				diag::log_tagged_fmt("aob",
					"view generate refused parse_failed input='%s' live=%d pe=%d",
					gen.address_input, live ? 1 : 0, pe ? 1 : 0);
				anti_tamper::webhook::write_log("aob", "generate refused parse_failed");
				toast_notification::push(
					"AOB: Enter a hex address (e.g. 7FF6A1B20040) or click an instruction in the disassembly first.",
					toast_notification::toast_type_t::warning, 5.0f);
				std::lock_guard<std::mutex> lk(gen.mutex);
				if (!live && !pe) {
					gen.last_error =
						"No data source attached. Open a PE file or attach a process before generating signatures.";
				} else {
					gen.last_error =
						"Address is empty or invalid. Enter a hexadecimal address (e.g. 7FF6A1B20040) or click an instruction in the disassembly first.";
				}
				gen.show_no_address_modal = true;
			}
		}
		float btn_gap = 14.f;
		float run_x = ImGui::GetItemRectMax().x + btn_gap;

		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Regenerate", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), generating, nullptr, generating)) {
			aob_generator::regenerate_last(context, generator_state);
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap;

		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Save", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			aob_generator::save_current(generator_state);
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap;

		const auto process = context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
			? context.workspace->identity().process() : std::nullopt;
		const std::uint32_t live_pid = process ? process->pid : 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		bool attached_live = live_pid != 0;
#else
		bool attached_live = driver_bridge::is_loaded() && live_pid != 0;
#endif
		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Optimize", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !attached_live)) {
			aob_generator::signature_t to_optimize;
			{
				std::lock_guard<std::mutex> lk(gen.mutex);
				to_optimize = gen.current;
			}
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] aob optimize invoked");
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			aob_generator::optimize_signature(live_pid, to_optimize);
			std::lock_guard<std::mutex> lk(generator_state->mutex);
			generator_state->current = std::move(to_optimize);
#else
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "scanner";
			sub.label = "scanner.aob_optimize";
			sub.thread_class = "scanner_sweep";
			sub.domain = aida::infra::executor::domain_t::long_running;
			sub.priority = 2;
			sub.target_pid = live_pid;
			sub.body = [live_pid, to_optimize, generator_state]() mutable {
				aob_generator::optimize_signature(live_pid, to_optimize);
				std::lock_guard<std::mutex> lk(generator_state->mutex);
				if (generator_state->current.id == to_optimize.id)
					generator_state->current = std::move(to_optimize);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				diag::log_tagged("aob", "optimize worker_queue_rejected");
#endif
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap + 6.f;

		bool batch_running = gen.batch_generating.load();
		if (batch_running) {
			char batch_buf[32];
			std::snprintf(batch_buf, sizeof(batch_buf), "Batch %d/%d",
			              gen.batch_done.load(), gen.batch_total.load());
			ImGui::SetCursorScreenPos(ImVec2(run_x, cy + 4.f));
			aida::ui::pill_kind(batch_buf, aida::ui::components::pill_kind_t::accent,
				aida::ui::size_t_::sm, true);
		}
	}
	cy += 42.f;

	aob_generator::signature_t current_copy;
	std::string error_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		current_copy = gen.current;
		error_copy = gen.last_error;
	}

	if (!error_copy.empty()) {
		float err_x = cx - 4.f;
		float err_w = ox + left_w - err_x - 12.f;
		float err_h = 30.f;
		ImU32 err_col = aida::ui::with_alpha(t.error, alpha);
		dl->AddRectFilled(ImVec2(err_x, cy),
			ImVec2(err_x + err_w, cy + err_h),
			aida::ui::with_alpha(t.error, 0.10f * alpha), 8.f);
		dl->AddRect(ImVec2(err_x, cy),
			ImVec2(err_x + err_w, cy + err_h),
			aida::ui::with_alpha(t.error, 0.55f * alpha), 8.f, 0, 1.f);
		dl->AddText(aida::ui::fonts::body_em(), 12.f,
			ImVec2(err_x + 12.f, cy + (err_h - 12.f) * 0.5f),
			err_col, "Last error:");
		ImVec2 lbl_sz = ImGui::CalcTextSize("Last error:");
		ImGui::PushClipRect(ImVec2(err_x + 12.f + lbl_sz.x + 8.f, cy),
			ImVec2(err_x + err_w - 12.f, cy + err_h), true);
		dl->AddText(body_font, body_font_size,
			ImVec2(err_x + 12.f + lbl_sz.x + 8.f, cy + (err_h - 11.f) * 0.5f),
			err_col, error_copy.c_str());
		ImGui::PopClipRect();
		cy += err_h + 10.f;
	}

	if (!current_copy.bytes.empty()) {
		float card_x = cx - 4.f;
		float card_w = ox + left_w - card_x - 12.f;
		float card_h = 36.f;
		dl->AddRectFilled(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 10.f);
		dl->AddRect(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);

		char info_buf[160];
		std::snprintf(info_buf, sizeof(info_buf), "0x%llX  |  %s  |  %zu bytes  |  %.0f%%",
		              static_cast<unsigned long long>(current_copy.address),
		              current_copy.module_name.empty() ? "<unknown>" : current_copy.module_name.c_str(),
		              current_copy.bytes.size(),
		              current_copy.quality_score * 100.f);
		dl->AddText(body_font, body_font_size,
			ImVec2(card_x + 12.f, cy + (card_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, alpha), info_buf);

		{
			const char* grade_str = aob_generator::score_grade(current_copy.quality_score);
			ImU32 gc = detail::grade_color(current_copy.quality_score);
			const char* lbl = "Grade";
			ImVec2 ts_lbl = ImGui::CalcTextSize(lbl);
			float ph = 22.f;
			float pw = ts_lbl.x + 36.f;
			float gx = card_x + card_w - pw - 12.f;
			float gy = cy + (card_h - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.18f), ph * 0.5f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.55f), ph * 0.5f, 0, 1.f);
			float dot_cx = gx + 12.f;
			float dot_cy = gy + ph * 0.5f;
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 8.f,
				aida::ui::with_alpha(gc, 0.85f), 18);
			ImVec2 g_ts = ImGui::CalcTextSize(grade_str);
			dl->AddText(aida::ui::fonts::body_em(), 13.f,
				ImVec2(dot_cx - g_ts.x * 0.5f, dot_cy - 6.f),
				IM_COL32(255, 255, 255, 245), grade_str);
			dl->AddText(body_font, body_font_size,
				ImVec2(dot_cx + 12.f, gy + (ph - 11.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), lbl);
		}
		cy += card_h + 10.f;

		float byte_x = cx;
		float byte_y = cy;
		const float byte_w = 24.f;
		const float byte_h = 18.f;
		const float max_x = ox + left_w - 20.f;

		ImU32 wild_col = aida::ui::with_alpha(t.error, alpha);
		ImU32 fixed_col = aida::ui::with_alpha(t.info, alpha);

		for (std::size_t i = 0; i < current_copy.bytes.size(); ++i) {
			if (byte_x + byte_w > max_x) {
				byte_x = cx;
				byte_y += byte_h + 2.f;
			}
			char hex[4];
			if (current_copy.bytes[i].wildcard) {
				hex[0] = '?'; hex[1] = '?'; hex[2] = 0;
				dl->AddText(code_font, code_font_size,
					ImVec2(byte_x, byte_y), wild_col, hex);
			} else {
				std::snprintf(hex, sizeof(hex), "%02X", current_copy.bytes[i].value);
				dl->AddText(code_font, code_font_size,
					ImVec2(byte_x, byte_y), fixed_col, hex);
			}
			byte_x += byte_w;
		}
		cy = byte_y + byte_h + 14.f;

		float seg_w_used = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		detail::render_format_segmented(cx, cy, seg_w_used, st.active_format);
		cy += 32.f;

		std::string fmt = detail::format_for_tab(current_copy, st.active_format);
		float code_h = 30.f;
		dl->AddRectFilled(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 8.f);
		dl->AddRect(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 8.f, 0, 1.f);
		ImGui::PushClipRect(ImVec2(cx, cy), ImVec2(ox + left_w - 16.f, cy + code_h), true);
		dl->AddText(code_font, code_font_size,
			ImVec2(cx + 4.f, cy + (code_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha), fmt.c_str());
		ImGui::PopClipRect();
		cy += code_h + 10.f;

		{
			ImGui::SetCursorScreenPos(ImVec2(cx, cy));
			char copy_lbl[24];
			std::snprintf(copy_lbl, sizeof(copy_lbl), "Copy %s", detail::tab_name(st.active_format));
			if (aida::ui::button(copy_lbl, aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				ImGui::SetClipboardText(fmt.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(cx + 110.f, cy));
			if (aida::ui::button("Copy signature", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm)) {
				std::string std_fmt = aob_generator::format_signature(current_copy);
				ImGui::SetClipboardText(std_fmt.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(cx + 232.f, cy));
			if (aida::ui::button("Copy YARA", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string yara = aob_generator::format_yara_rule(current_copy);
				ImGui::SetClipboardText(yara.c_str());
			}
		}
		cy += 30.f;

		{
			float bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			const bool export_pending = st.export_pending.load(std::memory_order_acquire);
			if (aida::ui::button("Export JSON", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f), export_pending))
				detail::request_export(context, generator_state, view_state,
					aob_generator::export_format_t::json, {});
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export YARA", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f), export_pending))
				detail::request_export(context, generator_state, view_state,
					aob_generator::export_format_t::yara, {});
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export Header", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f), export_pending))
				detail::request_export(context, generator_state, view_state,
					aob_generator::export_format_t::header, {});
			cy += 30.f;

			bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			const auto compare_process =
				context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
				? context.workspace->identity().process() : std::nullopt;
			const std::uint32_t compare_pid = compare_process ? compare_process->pid : 0;
			const bool compare_pending = st.comparison_pending.load(std::memory_order_acquire);
			bool attached_cmp = compare_pid != 0;
			if (aida::ui::button("Compare", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f), !attached_cmp || compare_pending)) {
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob compare invoked");
				detail::request_comparison(context, generator_state, view_state);
			}
			bx += 90.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Save Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f),
					st.catalog_pending.load(std::memory_order_acquire)))
				detail::request_catalog(context, generator_state, view_state, true);
			bx += 96.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Load Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f),
					st.catalog_pending.load(std::memory_order_acquire)))
				detail::request_catalog(context, generator_state, view_state, false);
			cy += 28.f;
			operation_status_t export_status;
			operation_status_t catalog_status;
			operation_status_t comparison_status;
			{
				std::lock_guard<std::mutex> lock(st.operation_mutex);
				export_status = st.export_status;
				catalog_status = st.catalog_status;
				comparison_status = st.comparison_status;
			}
			const operation_status_t* visible_status = comparison_status.terminal != operation_terminal_t::idle
				? &comparison_status : catalog_status.terminal != operation_terminal_t::idle
				? &catalog_status : export_status.terminal != operation_terminal_t::idle ? &export_status : nullptr;
			if (visible_status) {
				ImGui::SetCursorScreenPos(ImVec2(cx, cy));
				ImGui::TextDisabled("%s", visible_status->message.c_str());
				const bool retryable = visible_status->terminal == operation_terminal_t::failed ||
					visible_status->terminal == operation_terminal_t::cancelled ||
					visible_status->terminal == operation_terminal_t::stale;
				if (retryable) {
					ImGui::SetCursorScreenPos(ImVec2(ox + left_w - 72.f, cy - 4.f));
					if (aida::ui::button("Retry", aida::ui::button_kind_t::secondary,
							aida::ui::size_t_::sm)) {
						if (visible_status == &comparison_status)
							detail::request_comparison(context, generator_state, view_state);
						else if (visible_status == &catalog_status)
							detail::request_catalog(context, generator_state, view_state, st.last_catalog_save);
						else
							detail::request_export(context, generator_state, view_state,
								st.last_export_format, st.last_export_path);
					}
				}
			}
		}
	} else {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
		cfg.title = "No signature yet";
		cfg.body = "Enter an address and click Generate to extract an AOB pattern.";
		aida::ui::empty_state::render(ImVec2(ox, cy), ImVec2(left_w, 220.f), cfg);
	}

	float rx = ox + left_w + 6.f;
	float ry = oy + 12.f;
	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(rx, ry),
		aida::ui::with_alpha(t.text_primary, alpha),
		"Saved Signatures");
	ry += 22.f;

	std::vector<aob_generator::signature_t> saved_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		saved_copy = gen.saved_signatures;
	}

	float saved_h = oy + h - ry - 12.f;
	float row_h = 28.f;
	float content_h = static_cast<float>(saved_copy.size()) * row_h;

	float dt = aida::ui::clock::dt();
	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - saved_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, dt);

	bool ctx_saved_open = false;
	auto ctx_saved_origin = aida::ui::context_menu_open_origin_t::pointer;

	ImGui::PushClipRect(ImVec2(rx, ry), ImVec2(rx + right_w, oy + h - 8.f), true);

	static float saved_anim_time = 0.f;
	saved_anim_time += dt;

	for (std::size_t i = 0; i < saved_copy.size(); ++i) {
		float row_y = ry + static_cast<float>(i) * row_h - st.scroll_y;
		if (row_y + row_h < ry || row_y > oy + h) continue;

		ImVec2 rmin(rx, row_y);
		ImVec2 rmax(rx + right_w, row_y + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_saved == static_cast<int>(i));
		float entrance = ui_anim::render_row_entrance(static_cast<int>(i), saved_anim_time, 0.012f);

		if (selected) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.selection, alpha * entrance), 6.f);
			dl->AddRectFilled(rmin, ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(t.accent_u32, alpha * entrance));
		} else if (hovered) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.hover_wash, alpha * entrance), 6.f);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_saved = (selected ? -1 : static_cast<int>(i));
			if (!selected) {
				st.context_address = saved_copy[i].address;
				st.context_name = saved_copy[i].name;
			}
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			ctx_saved_open = true;
			st.selected_saved = static_cast<int>(i);
			st.context_address = saved_copy[i].address;
			st.context_name = saved_copy[i].name;
		}

		auto& sig = saved_copy[i];
		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(sig.address));

		{
			float gx = rx + 8.f;
			float gy = row_y + (row_h - 20.f) * 0.5f;
			ImU32 gc = detail::grade_color(sig.quality_score);
			const char* g_str = aob_generator::score_grade(sig.quality_score);
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.22f), 5.f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.55f), 5.f, 0, 1.f);
			ImVec2 g_ts = ImGui::CalcTextSize(g_str);
			dl->AddText(aida::ui::fonts::body_em(), 14.f,
				ImVec2(gx + (22.f - g_ts.x) * 0.5f, gy + (20.f - 12.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), g_str);
		}

		dl->AddText(body_font, body_font_size,
			ImVec2(rx + 38.f, row_y + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha * entrance), sig.name.c_str());

		float mid_x = rx + right_w * 0.42f;
		dl->AddText(code_font, code_font_size,
			ImVec2(mid_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, alpha * entrance), addr_buf);

		float end_x = rx + right_w * 0.65f;
		char sz_buf[16];
		std::snprintf(sz_buf, sizeof(sz_buf), "%zu B", sig.bytes.size());
		dl->AddText(body_font, body_font_size,
			ImVec2(end_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha * entrance), sz_buf);

		if (sig.uniqueness_count > 0) {
			float u_x = rx + right_w - 76.f;
			ImGui::SetCursorScreenPos(ImVec2(u_x, row_y + (row_h - 18.f) * 0.5f));
			ImGui::PushID(static_cast<int>(i) + 4096);
			aida::ui::pill_kind(sig.unique ? "unique" : "non-unique",
				sig.unique ? aida::ui::components::pill_kind_t::success
				           : aida::ui::components::pill_kind_t::warning,
				aida::ui::size_t_::sm, true);
			ImGui::PopID();
		}
	}
	if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && context_key_pressed() &&
		st.selected_saved >= 0) {
		ctx_saved_open = true;
		ctx_saved_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10;
	}

	ImGui::PopClipRect();

	if (ctx_saved_open) {
		const auto current_signature = std::find_if(saved_copy.begin(), saved_copy.end(), [&](const auto& signature) {
			return signature.address == st.context_address && signature.name == st.context_name;
		});
		if (current_signature != saved_copy.end()) {
			const auto signature = *current_signature;
			const auto workspace = context.workspace;
			const auto generation = context.publication ? context.publication->generation : 0;
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "memory.aob.saved";
			retained.entity_id = signature.name + "@" + std::to_string(signature.address);
			retained.entity_generation = generation;
			retained.active_view = aida::ui::stable_view_id_t("view.memory.aob");
			retained.validate_identity = [workspace, generator_state, generation, signature]() {
				if (!workspace) return aida::ui::capability_state_t::unavailable("The AOB workspace was closed.");
				const auto publication = workspace->analysis_publication();
				if (!publication || publication->generation != generation)
					return aida::ui::capability_state_t::unavailable("The analysis publication changed; reopen the menu.");
				std::lock_guard<std::mutex> lock(generator_state->mutex);
				const bool current = std::any_of(generator_state->saved_signatures.begin(),
					generator_state->saved_signatures.end(), [&](const auto& item) {
						return item.address == signature.address && item.name == signature.name &&
							detail::signature_bytes_equal(item.bytes, signature.bytes);
					});
				return current ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable("The selected signature changed or was removed.");
			};
			auto add = [&](const char* id, bool enabled, const char* reason, auto invoke) {
				retained.actions.push_back({id, enabled ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(reason), invoke});
			};
			add("memory.entity.open_disassembly", signature.address != 0,
				"The saved signature has no mapped address.", [signature, context]() {
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
					disasm_view::goto_address(signature.address, context);
					anti_tamper::webhook::write_log("scan_audit", "[scan_audit] aob saved ctx open_disasm");
					return aida::ui::action_handler_result_t::completed();
				});
			add("memory.entity.open_hex", signature.address != 0,
				"The saved signature has no mapped address.", [signature, context]() {
					detail::open_saved_in_hex(context, signature.address);
					aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.hex"));
					anti_tamper::webhook::write_log("scan_audit", "[scan_audit] aob saved ctx open_hex");
					return aida::ui::action_handler_result_t::completed();
				});
			add("memory.aob.copy_pattern", !signature.bytes.empty(),
				"The saved signature has no retained pattern bytes.", [signature]() {
					const std::string text = aob_generator::format_signature(signature);
					ImGui::SetClipboardText(text.c_str());
					anti_tamper::webhook::write_log("scan_audit", "[scan_audit] aob saved ctx copy_pattern");
					return aida::ui::action_handler_result_t::completed();
				});
			add("memory.aob.copy_ida_pattern", !signature.bytes.empty(),
				"The saved signature has no retained pattern bytes.", [signature]() {
					const std::string text = aob_generator::format_ida_signature(signature);
					ImGui::SetClipboardText(text.c_str());
					anti_tamper::webhook::write_log("scan_audit", "[scan_audit] aob saved ctx copy_ida");
					return aida::ui::action_handler_result_t::completed();
				});
			add("memory.entity.copy_address", signature.address != 0,
				"The saved signature has no mapped address.", [signature]() {
					char address[24]{};
					std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(signature.address));
					ImGui::SetClipboardText(address);
					anti_tamper::webhook::write_log("scan_audit", "[scan_audit] aob saved ctx copy_address");
					return aida::ui::action_handler_result_t::completed();
				});
			char evidence_address[24]{};
			std::snprintf(evidence_address, sizeof(evidence_address), "0x%016llX",
				static_cast<unsigned long long>(signature.address));
			constexpr std::size_t k_evidence_pattern_bytes = 1024U;
			const std::size_t evidence_byte_count = (std::min)(signature.bytes.size(),
				k_evidence_pattern_bytes);
			std::string evidence_pattern;
			evidence_pattern.reserve(evidence_byte_count * 3U);
			char encoded_byte[4]{};
			for (std::size_t index = 0; index < evidence_byte_count; ++index) {
				if (index != 0) evidence_pattern.push_back(' ');
				if (signature.bytes[index].wildcard) evidence_pattern += "??";
				else {
					std::snprintf(encoded_byte, sizeof(encoded_byte), "%02X",
						signature.bytes[index].value);
					evidence_pattern += encoded_byte;
				}
			}
			std::uint64_t signature_identity_hash = 1469598103934665603ULL;
			for (const auto& byte : signature.bytes) {
				signature_identity_hash ^= byte.value;
				signature_identity_hash *= 1099511628211ULL;
				signature_identity_hash ^= byte.wildcard ? 1U : 0U;
				signature_identity_hash *= 1099511628211ULL;
			}
			const auto signature_id = signature.id;
			const auto signature_address = signature.address;
			const auto signature_name = signature.name;
			aida::automation_ui::entity_evidence::snapshot_t evidence;
			evidence.workspace_id = workspace->identity().binary_id().to_hex();
			evidence.source_view_id = "view.memory.aob";
			evidence.source_kind = "aob_signature";
			evidence.entity_id = retained.entity_id;
			evidence.display_label = signature.name;
			evidence.excerpt = "Name: " + signature.name + "\nAddress: " +
				evidence_address + "\nPattern: " + evidence_pattern +
				"\nByte count: " + std::to_string(signature.bytes.size()) +
				"\nUniqueness count: " + std::to_string(signature.uniqueness_count);
			evidence.address = signature.address;
			evidence.revision = generation;
			evidence.generation = generation;
			evidence.truncated = evidence_byte_count != signature.bytes.size();
			evidence.return_to_source = [workspace, generator_state, view_state,
				generation, signature_id, signature_address, signature_name,
				signature_identity_hash](std::string& reason) {
			const auto publication = workspace ? workspace->analysis_publication() : nullptr;
			if (!publication || publication->generation != generation) {
				reason = "The AOB analysis publication changed; capture the signature again.";
				return false;
			}
			{
				std::lock_guard<std::mutex> lock(generator_state->mutex);
				const auto found = std::find_if(generator_state->saved_signatures.begin(),
					generator_state->saved_signatures.end(), [&](const auto& item) {
						if (item.id != signature_id || item.address != signature_address ||
							item.name != signature_name) return false;
						std::uint64_t current_hash = 1469598103934665603ULL;
						for (const auto& byte : item.bytes) {
							current_hash ^= byte.value;
							current_hash *= 1099511628211ULL;
							current_hash ^= byte.wildcard ? 1U : 0U;
							current_hash *= 1099511628211ULL;
						}
						return current_hash == signature_identity_hash;
					});
				if (found == generator_state->saved_signatures.end()) {
					reason = "The retained AOB signature changed or was removed; capture it again.";
					return false;
				}
				view_state->selected_saved = static_cast<int>(
					std::distance(generator_state->saved_signatures.begin(), found));
				view_state->context_address = signature_address;
				view_state->context_name = signature_name;
			}
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.memory.aob"));
			if (!opened.ok()) {
				reason = opened.detail;
				return false;
			}
			reason.clear();
			return true;
		};
			aida::automation_ui::entity_evidence::append_actions(retained,
				std::move(evidence), !signature.bytes.empty()
					? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(
						"The retained AOB signature has no pattern bytes."));
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), ctx_saved_origin);
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu("memory.aob.saved");

	if (saved_copy.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Nothing saved yet";
		cfg.body = "Generated signatures appear here once you click Save.";
		aida::ui::empty_state::render(ImVec2(rx, ry), ImVec2(right_w, saved_h), cfg);
	}

	if (content_h > saved_h) {
		ui_anim::render_custom_scrollbar(dl, rx + right_w - 12.f, ry, 8.f, saved_h,
		                                  st.scroll_y, content_h, saved_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (gen.show_no_address_modal) {
		ImGui::OpenPopup("AOB Generation Refused##aob_no_address_modal");
		gen.show_no_address_modal = false;
	}
	ImVec2 modal_center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(modal_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSize(ImVec2(420.f, 0.f), ImGuiCond_Appearing);
	if (ImGui::BeginPopupModal("AOB Generation Refused##aob_no_address_modal",
		nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
		std::string modal_msg;
		{
			std::lock_guard<std::mutex> lk(gen.mutex);
			modal_msg = gen.last_error.empty()
				? std::string("No address selected - click an instruction first.")
				: gen.last_error;
		}
		ImGui::TextColored(ImVec4(1.f, 0.55f, 0.55f, 1.f), "Cannot generate signature");
		ImGui::Separator();
		ImGui::TextWrapped("%s", modal_msg.c_str());
		ImGui::Spacing();
		float modal_w = ImGui::GetContentRegionAvail().x;
		float btn_w = 120.f;
		ImGui::SetCursorPosX((modal_w - btn_w) * 0.5f + ImGui::GetCursorPosX());
		if (ImGui::Button("OK", ImVec2(btn_w, 0.f))) {
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}

	ImGui::EndChild();
}

inline void render(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b)
{
	render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
		disasm_view::capture_selected_workspace());
}

}
