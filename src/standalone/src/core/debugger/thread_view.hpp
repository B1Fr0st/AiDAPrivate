#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "debugger_interaction_context.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/task_center.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"

namespace thread_view {

struct thread_entry_t {
	uint32_t    tid = 0;
	int         priority = 0;
	std::string state_text;
	uint64_t    rip = 0;
	uint64_t    rsp = 0;
	std::string module_name;
	uint64_t    entry_point = 0;
	bool        suspended = false;
};

struct ui_state_t {
	std::shared_ptr<const std::vector<thread_entry_t>> threads =
		std::make_shared<const std::vector<thread_entry_t>>();
	std::shared_ptr<const std::vector<thread_entry_t>> visible_threads;
	std::string                 last_error;
	int                         visible_running = 0;
	int                         visible_waiting = 0;
	int                         visible_suspended = 0;
	int                         selected = -1;
	float                       scroll_y = 0.f;
	float                       target_scroll_y = 0.f;
	std::mutex                  threads_mutex;
	std::atomic<bool>           refreshing{false};
	float                       last_refresh = 0.f;
	bool                        scrollbar_dragging = false;
	float                       scrollbar_drag_offset = 0.f;
	int                         context_idx = -1;
};

inline ui_state_t g_ui;

inline void register_task(const aida::infra::executor::submit_result_t& submitted,
	const char* action, const char* label) {
	if (!submitted.submitted || submitted.task_id == 0) return;
	aida::ui::task_center::task_registration_t registration;
	registration.owner = "debugger";
	registration.owner_view = "view.debug.threads";
	registration.owner_action = action;
	registration.label = label;
	registration.stage = "Queued";
	registration.progress = -1.f;
	registration.target = driver_bridge::attached_pid() == 0 ? std::string{} :
		"PID " + std::to_string(driver_bridge::attached_pid());
	registration.cancellation_is_safe = false;
	registration.callbacks.focus = []() {
		static_cast<void>(aida::ui_thread::post([]() {
			aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.debug.threads"));
		}, "thread_view", "task_focus", "task_center_callback"));
	};
	static_cast<void>(aida::ui::task_center::register_executor_job(
		submitted.task_id, std::move(registration)));
}

inline aida::ui::action_handler_result_t request_thread_control(
	thread_entry_t thread, int target_idx,
	const debugger_interaction::context_t& context, bool suspend) {
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = suspend ? "debugger.thread_suspend" : "debugger.thread_resume";
	submission.thread_class = "debugger_thread_control";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 3;
	submission.target_pid = context.target_pid;
	submission.generation = context.stop_generation;
	submission.body = [thread, target_idx, context, suspend]() {
		auto fail = [](const char* message) {
			{
				std::lock_guard<std::mutex> lock(g_ui.threads_mutex);
				g_ui.last_error = message;
			}
			throw std::runtime_error(message);
		};
		if (driver_bridge::attached_pid() != context.target_pid ||
			debugger_interaction::current_stop_generation() != context.stop_generation)
			fail("The target changed before thread control started");
		const bool controlled = suspend
			? driver_bridge::suspend_thread(thread.tid, nullptr)
			: driver_bridge::resume_thread(thread.tid, nullptr);
		if (!controlled)
			fail(suspend ? "The driver rejected thread suspension"
				: "The driver rejected thread resume");
		std::lock_guard<std::mutex> lock(g_ui.threads_mutex);
		g_ui.last_error.clear();
		if (g_ui.threads && target_idx >= 0 && target_idx < static_cast<int>(g_ui.threads->size()) &&
			(*g_ui.threads)[static_cast<std::size_t>(target_idx)].tid == thread.tid) {
			auto updated = std::make_shared<std::vector<thread_entry_t>>(*g_ui.threads);
			(*updated)[static_cast<std::size_t>(target_idx)].suspended = suspend;
			(*updated)[static_cast<std::size_t>(target_idx)].state_text = suspend ? "Suspended" : "Running";
			g_ui.threads = std::move(updated);
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		diag::log_tagged("threads", suspend ? "thread_suspend_post_failed" : "thread_resume_post_failed");
		std::unique_lock<std::mutex> lock(g_ui.threads_mutex, std::try_to_lock);
		if (lock.owns_lock())
			g_ui.last_error = "Thread control could not be queued: " + submitted.reject_reason;
		return aida::ui::action_handler_result_t::failed(
			submitted.reject_reason.empty() ? "Thread control could not be queued." : submitted.reject_reason);
	}
	register_task(submitted, suspend ? "debugger.thread_suspend" : "debugger.thread_resume",
		suspend ? "Suspend target thread" : "Resume target thread");
	return aida::ui::action_handler_result_t::completed();
}

inline void refresh()
{
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0)
		return;

	bool expected = false;
	if (!g_ui.refreshing.compare_exchange_strong(expected, true))
		return;

	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "debugger";
	sub.label = "debugger.threads_refresh";
	sub.thread_class = "debugger_refresh";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 3;
	const std::uint32_t target_pid = driver_bridge::attached_pid();
	const std::uint64_t target_generation = debugger_interaction::current_stop_generation();
	sub.target_pid = target_pid;
	sub.generation = target_generation;
	sub.body = [target_pid, target_generation]() {
		try {
			if (driver_bridge::attached_pid() != target_pid ||
				debugger_interaction::current_stop_generation() != target_generation) {
				g_ui.refreshing.store(false);
				return;
			}
			auto raw_threads = driver_bridge::enumerate_threads();
			auto modules = driver_bridge::enumerate_modules();

			std::vector<thread_entry_t> entries;
			entries.reserve(raw_threads.size());

			for (auto& t : raw_threads) {
			thread_entry_t e;
			e.tid = t.tid;
			e.priority = t.priority;


			e.rip = t.rip;
			e.rsp = 0;
			e.entry_point = 0;

			if (t.state == 5)
				e.state_text = "Waiting";
			else if (t.state == 2)
				e.state_text = "Running";
			else if (t.state == 1)
				e.state_text = "Ready";
			else if (t.state == 0)
				e.state_text = "Initialized";
			else if (t.state == 3)
				e.state_text = "Standby";
			else if (t.state == 4)
				e.state_text = "Terminated";
			else if (t.state == 6)
				e.state_text = "Transition";
			else
				e.state_text = "Unknown";

			uint32_t prev_count = 0;
			bool we_suspended = driver_bridge::suspend_thread(t.tid, &prev_count);
			if (we_suspended) {
				driver_bridge::thread_context_t ctx{};
				if (driver_bridge::get_thread_context(t.tid, ctx)) {
					if (e.rip == 0)
						e.rip = ctx.rip;
					e.rsp = ctx.rsp;
				}
				driver_bridge::resume_thread(t.tid, nullptr);
			}
			e.suspended = (prev_count > 0);
			if (e.suspended)
				e.state_text = "Suspended";


			for (auto& m : modules) {
				if (e.rip >= m.base && e.rip < m.base + m.size) {
					e.module_name = m.name;
					break;
				}
			}

				entries.push_back(std::move(e));
			}

			if (driver_bridge::attached_pid() == target_pid &&
				debugger_interaction::current_stop_generation() == target_generation) {
				std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
				g_ui.threads = std::make_shared<const std::vector<thread_entry_t>>(
					std::move(entries));
				g_ui.last_error.clear();
			}
			g_ui.refreshing.store(false);
		} catch (const std::exception& exception) {
			{
				std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
				g_ui.last_error = std::string("Thread refresh failed: ") + exception.what();
			}
			g_ui.refreshing.store(false);
			throw;
		} catch (...) {
			{
				std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
				g_ui.last_error = "Thread refresh failed with an unknown error.";
			}
			g_ui.refreshing.store(false);
			throw;
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(sub));
	if (!submitted.submitted) {
		diag::log_tagged("threads", "threads_refresh_post_failed");
		std::unique_lock<std::mutex> lock(g_ui.threads_mutex, std::try_to_lock);
		if (lock.owns_lock())
			g_ui.last_error = "Thread refresh could not be queued: " + submitted.reject_reason;
		g_ui.refreshing.store(false);
	} else register_task(submitted, "debugger.threads_refresh", "Refresh target threads");
}

namespace detail {

inline ImU32 state_color(const std::string& state, float alpha)
{
	if (state == "Running")   return aida::ui::with_alpha(aida::ui::resolved().success, alpha);
	if (state == "Waiting")   return aida::ui::with_alpha(aida::ui::resolved().warning, alpha);
	if (state == "Suspended") return aida::ui::with_alpha(aida::ui::darken(aida::ui::resolved().warning, 20), alpha);
	return aida::ui::with_alpha(aida::ui::resolved().text_secondary, alpha);
}

inline ImU32 priority_color(int prio, float alpha)
{
	if (prio > 0) return aida::ui::with_alpha(aida::ui::resolved().warning, alpha);
	if (prio < 0) return aida::ui::with_alpha(aida::ui::resolved().info, alpha);
	return aida::ui::with_alpha(aida::ui::resolved().text_secondary, alpha);
}

}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float ar, float ag, float ab)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = ImGui::GetIO().DeltaTime;
	const auto& _t = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
	};

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  _ta(_t.bg_base));

	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, width, header_h, ar, ag, ab, alpha);
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				_ta(_t.text_primary), "Threads");
	std::shared_ptr<const std::vector<thread_entry_t>> snapshot_handle;
	static std::string error_snapshot;
	std::unique_lock<std::mutex> threads_lock(g_ui.threads_mutex, std::try_to_lock);
	if (threads_lock.owns_lock()) {
		snapshot_handle = g_ui.threads;
		error_snapshot = g_ui.last_error;
	}
	if (threads_lock.owns_lock()) threads_lock.unlock();
	if (!snapshot_handle)
		snapshot_handle = g_ui.visible_threads ? g_ui.visible_threads :
			std::make_shared<const std::vector<thread_entry_t>>();
	if (g_ui.visible_threads != snapshot_handle) {
		g_ui.visible_threads = snapshot_handle;
		g_ui.visible_running = 0;
		g_ui.visible_waiting = 0;
		g_ui.visible_suspended = 0;
		for (const auto& thread : *snapshot_handle) {
			if (thread.state_text == "Running") ++g_ui.visible_running;
			else if (thread.state_text == "Suspended") ++g_ui.visible_suspended;
			else ++g_ui.visible_waiting;
		}
	}
	const auto& snapshot = *snapshot_handle;

	int thread_count = static_cast<int>(snapshot.size());

	char count_buf[16];
	snprintf(count_buf, sizeof(count_buf), "%d", thread_count);
	ui_anim::render_badge(dl, count_buf, pos_x + 75.f, pos_y + 9.f,
						  IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
								   static_cast<int>(ab * 255), static_cast<int>(160 * alpha)),
						  IM_COL32(255, 255, 255, static_cast<int>(220 * alpha)));

	float refresh_x = pos_x + 120.f;
	float refresh_y = pos_y + 4.f;
	ImVec2 btn_min(refresh_x, refresh_y);
	ImVec2 btn_max(refresh_x + 60.f, refresh_y + 22.f);
	bool btn_hover = ImGui::IsMouseHoveringRect(btn_min, btn_max, false);
	dl->AddRectFilled(btn_min, btn_max,
					  btn_hover ? _ta(ui_anim::lighten(_t.panel_header, 14))
								: _ta(_t.panel_header), 3.f);
	dl->AddText(ImVec2(refresh_x + 8.f, refresh_y + 3.f),
				_ta(_t.text_secondary), "Refresh");
	if (btn_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
		refresh();

	float strip_y = pos_y + header_h;
	const float strip_h = 44.f;
	{
		const int running = g_ui.visible_running;
		const int waiting = g_ui.visible_waiting;
		const int suspended = g_ui.visible_suspended;
		char tot_buf[16];
		char run_buf[16];
		char wait_buf[16];
		char susp_buf[16];
		std::snprintf(tot_buf, sizeof(tot_buf), "%d", thread_count);
		std::snprintf(run_buf, sizeof(run_buf), "%d", running);
		std::snprintf(wait_buf, sizeof(wait_buf), "%d", waiting);
		std::snprintf(susp_buf, sizeof(susp_buf), "%d", suspended);

		ImU32 run_col  = aida::ui::resolved().success;
		ImU32 wait_col = aida::ui::resolved().warning;
		ImU32 susp_col = suspended > 0 ? aida::ui::darken(aida::ui::resolved().warning, 20) : aida::ui::resolved().text_secondary;

		ui_anim::stat_strip_item_t items[4];
		items[0] = { "Threads",   tot_buf,  nullptr, 0, nullptr, 0, 0 };
		items[1] = { "Running",   run_buf,  nullptr, 0, nullptr, 0, run_col };
		items[2] = { "Waiting",   wait_buf, nullptr, 0, nullptr, 0, wait_col };
		items[3] = { "Suspended", susp_buf, nullptr, 0, nullptr, 0, susp_col };
		ui_anim::render_stat_strip(dl, pos_x + 6.f, strip_y + 4.f, width - 12.f, strip_h - 8.f,
			items, 4, ar, ag, ab, alpha);
	}

	float table_y = strip_y + strip_h;

	float col_tid = pos_x + width * 0.01f;
	float col_entry = pos_x + width * 0.08f;
	float col_rip = pos_x + width * 0.25f;
	float col_rsp = pos_x + width * 0.44f;
	float col_module = pos_x + width * 0.62f;
	float col_prio = pos_x + width * 0.78f;
	float col_state = pos_x + width * 0.87f;

	{
		ui_anim::table_col_t cols[] = {{"TID", 70.f}, {"Entry", 140.f}, {"RIP", 160.f}, {"RSP", 150.f}, {"Module", 130.f}, {"Priority", 70.f}, {"State", 80.f}};
		ui_anim::render_table_header(dl, pos_x, table_y, width, col_header_h, cols, 7, ar, ag, ab, alpha);
	}

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - strip_h - col_header_h;
	if (list_h <= 0.f) return;

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	float content_h = static_cast<float>(snapshot.size()) * row_h;
	float max_scroll = content_h - list_h;
	if (max_scroll < 0.f) max_scroll = 0.f;

	if (ImGui::IsMouseHoveringRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), false))
		ui_anim::handle_scroll_input(g_ui.target_scroll_y, 0.f, max_scroll, row_h);
	ui_anim::clamp_scroll(g_ui.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(g_ui.scroll_y, g_ui.target_scroll_y, 15.f, dt);

	int first_visible = static_cast<int>(g_ui.scroll_y / row_h);
	if (first_visible < 0) first_visible = 0;
	int visible_count = static_cast<int>(list_h / row_h) + 2;

	if (snapshot.empty() && !g_ui.refreshing.load()) {
		ui_anim::render_empty_state(dl, pos_x, list_y, width, list_h,
			error_snapshot.empty() ? "No threads found" : error_snapshot.c_str(),
			ar, ag, ab, alpha, static_cast<float>(ImGui::GetTime()));
		dl->PopClipRect();

		float scrollbar_w = 8.f;
		ui_anim::render_custom_scrollbar(dl, pos_x + width - scrollbar_w - 2.f, list_y, scrollbar_w, list_h,
										 g_ui.scroll_y, content_h, list_h, alpha,
										 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);
		return;
	}

	if (g_ui.refreshing.load()) {
		ui_anim::render_spinner(dl, pos_x + width * 0.5f, list_y + list_h * 0.5f, 10.f, 2.f,
								IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
										 static_cast<int>(ab * 255), static_cast<int>(alpha * 255)),
								static_cast<float>(ImGui::GetTime()));
	}

	bool open_thread_context = false;
	auto thread_context_origin = aida::ui::context_menu_open_origin_t::pointer;
	for (int vi = 0; vi < visible_count; ++vi) {
		int idx = first_visible + vi;
		if (idx >= static_cast<int>(snapshot.size())) break;

		auto& t = snapshot[idx];
		float ry = list_y + idx * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		float row_alpha = ui_anim::render_row_entrance(idx, static_cast<float>(first_visible), dt, alpha);
		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, row_alpha, ar, ag, ab);

		char tid_buf[16];
		snprintf(tid_buf, sizeof(tid_buf), "%u", t.tid);
		dl->AddText(ImVec2(col_tid, ry + 2.f),
					_ta(_t.text_primary), tid_buf);

		char entry_buf[24];
		snprintf(entry_buf, sizeof(entry_buf), "%016llX", static_cast<unsigned long long>(t.entry_point));
		dl->AddText(ImVec2(col_entry, ry + 2.f),
					_ta(_t.text_secondary), entry_buf);

		char rip_buf[24];
		snprintf(rip_buf, sizeof(rip_buf), "%016llX", static_cast<unsigned long long>(t.rip));
		dl->AddText(ImVec2(col_rip, ry + 2.f),
					_ta(_t.text_primary), rip_buf);

		char rsp_buf[24];
		snprintf(rsp_buf, sizeof(rsp_buf), "%016llX", static_cast<unsigned long long>(t.rsp));
		dl->AddText(ImVec2(col_rsp, ry + 2.f),
					_ta(_t.text_secondary), rsp_buf);

		dl->AddText(ImVec2(col_module, ry + 2.f),
					_ta(_t.text_secondary), t.module_name.c_str());

		char prio_buf[16];
		snprintf(prio_buf, sizeof(prio_buf), "%d", t.priority);
		dl->AddText(ImVec2(col_prio, ry + 2.f), detail::priority_color(t.priority, alpha), prio_buf);

		ui_anim::render_status_pill(dl, col_state, ry + 1.f, t.state_text.c_str(),
			detail::state_color(t.state_text, 1.f), alpha,
			static_cast<float>(ImGui::GetTime()), t.state_text == "Running");

		if (idx == g_ui.selected && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			g_ui.context_idx = idx;
			open_thread_context = true;
		}
	}

	dl->PopClipRect();

	float scrollbar_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + width - scrollbar_w - 2.f, list_y, scrollbar_w, list_h,
									 g_ui.scroll_y, content_h, list_h, alpha,
									 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);

	if (g_ui.selected >= 0 && ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
		(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		 (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)))) {
		g_ui.context_idx = g_ui.selected;
		open_thread_context = true;
		thread_context_origin = ImGui::IsKeyPressed(ImGuiKey_Menu, false)
			? aida::ui::context_menu_open_origin_t::menu_key
			: aida::ui::context_menu_open_origin_t::shift_f10;
	}
	if (open_thread_context) {
		if (g_ui.context_idx >= 0 && g_ui.context_idx < static_cast<int>(snapshot.size())) {
			const auto thread = snapshot[static_cast<std::size_t>(g_ui.context_idx)];
			const int thread_index = g_ui.context_idx;
			const auto context = debugger_interaction::capture(
				debugger_interaction::kind_t::thread, thread.rip, 0, thread_index, thread.tid);
			aida::ui::application_ui::retained_entity_context_t retained;
			retained.owner_id = "debugger.thread.list";
			retained.entity_id = std::to_string(thread.tid);
			retained.entity_generation = context.stop_generation;
			retained.active_view = aida::ui::stable_view_id_t("view.debug.threads");
			retained.validate_identity = [thread, context]() {
				if (!debugger_interaction::is_current(context))
					return aida::ui::capability_state_t::unavailable("The target or debugger stop generation changed.");
				std::lock_guard<std::mutex> lock(g_ui.threads_mutex);
				const bool exists = g_ui.threads && std::any_of(g_ui.threads->begin(), g_ui.threads->end(),
					[&](const auto& item) { return item.tid == thread.tid; });
				return exists ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable("The selected thread is no longer published.");
			};
			auto capability = [&](debugger_interaction::capability_t requested) {
				const auto result = debugger_interaction::evaluate(requested, context);
				return result.enabled ? aida::ui::capability_state_t::available()
					: aida::ui::capability_state_t::unavailable(result.disabled_reason ? result.disabled_reason : "The thread action is unavailable.");
			};
			retained.actions.push_back({"debugger.thread.suspend",
				capability(debugger_interaction::capability_t::suspend_thread),
				[thread, thread_index, context]() { return request_thread_control(thread, thread_index, context, true); }});
			retained.actions.push_back({"debugger.thread.resume",
				capability(debugger_interaction::capability_t::resume_thread),
				[thread, thread_index, context]() { return request_thread_control(thread, thread_index, context, false); }});
			retained.actions.push_back({"debugger.thread.switch",
				capability(debugger_interaction::capability_t::switch_thread), [thread]() {
					debugger_engine::g_state.active_tid = thread.tid;
					debugger_engine::invalidate_cache();
					return aida::ui::action_handler_result_t::completed();
				}});
			retained.actions.push_back({"debugger.thread.follow_rip", thread.rip != 0
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable("The retained thread has no instruction pointer."), [thread]() {
				aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
				disasm_view::goto_address(thread.rip,
					disasm_view::capture_selected_workspace());
					return aida::ui::action_handler_result_t::completed();
				}});
			aida::ui::application_ui::open_retained_entity_context_menu(
				std::move(retained), thread_context_origin);
		}
	}
	aida::ui::application_ui::render_retained_entity_context_menu("debugger.thread.list");
}

}
