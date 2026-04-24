#pragma once

#include <atomic>
#include "work_queue.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

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
	std::vector<thread_entry_t> threads;
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

inline void refresh()
{
	if (g_ui.refreshing.load())
		return;
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0)
		return;
	g_ui.refreshing.store(true);

	work_queue::post([]() {
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


			bool was_already_suspended = (t.state == 5);
			e.suspended = was_already_suspended;

			if (t.state == 5)
				e.state_text = "Suspended";
			else if (t.state == 2)
				e.state_text = "Running";
			else if (t.state == 1)
				e.state_text = "Ready";
			else if (t.state == 0)
				e.state_text = "Initialized";
			else
				e.state_text = "Waiting";


			if (e.rip == 0 && !was_already_suspended) {
				if (driver_bridge::suspend_thread(t.tid, nullptr)) {
					driver_bridge::thread_context_t ctx{};
					if (driver_bridge::get_thread_context(t.tid, ctx)) {
						e.rip = ctx.rip;
						e.rsp = ctx.rsp;
					}
					driver_bridge::resume_thread(t.tid, nullptr);
				}
			} else if (was_already_suspended) {


				driver_bridge::thread_context_t ctx{};
				if (driver_bridge::get_thread_context(t.tid, ctx)) {
					if (e.rip == 0)
						e.rip = ctx.rip;
					e.rsp = ctx.rsp;
				}
			}


			for (auto& m : modules) {
				if (e.rip >= m.base && e.rip < m.base + m.size) {
					e.module_name = m.name;
					break;
				}
			}

			entries.push_back(std::move(e));
		}

		{
			std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
			g_ui.threads = std::move(entries);
		}
		g_ui.refreshing.store(false);
	});
}

namespace detail {

inline ImU32 state_color(const std::string& state, float alpha)
{
	if (state == "Running")   return IM_COL32(80, 200, 80, static_cast<int>(200 * alpha));
	if (state == "Waiting")   return IM_COL32(220, 200, 60, static_cast<int>(200 * alpha));
	if (state == "Suspended") return IM_COL32(220, 140, 40, static_cast<int>(200 * alpha));
	return IM_COL32(180, 180, 190, static_cast<int>(180 * alpha));
}

inline ImU32 priority_color(int prio, float alpha)
{
	if (prio > 0) return IM_COL32(220, 160, 60, static_cast<int>(200 * alpha));
	if (prio < 0) return IM_COL32(100, 140, 200, static_cast<int>(200 * alpha));
	return IM_COL32(180, 180, 190, static_cast<int>(200 * alpha));
}

}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float ar, float ag, float ab)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = ImGui::GetIO().DeltaTime;
	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  _ta(_t.bg_base));

	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, width, header_h, ar, ag, ab, alpha);
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				_ta(_t.text_primary), "Threads");

	int thread_count = 0;
	{
		std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
		thread_count = static_cast<int>(g_ui.threads.size());
	}

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
		int running = 0, waiting = 0, suspended = 0;
		{
			std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
			for (auto& t : g_ui.threads) {
				if (t.state_text == "Running") running++;
				else if (t.state_text == "Suspended") suspended++;
				else waiting++;
			}
		}
		char tot_buf[16];
		char run_buf[16];
		char wait_buf[16];
		char susp_buf[16];
		std::snprintf(tot_buf, sizeof(tot_buf), "%d", thread_count);
		std::snprintf(run_buf, sizeof(run_buf), "%d", running);
		std::snprintf(wait_buf, sizeof(wait_buf), "%d", waiting);
		std::snprintf(susp_buf, sizeof(susp_buf), "%d", suspended);

		ImU32 run_col  = IM_COL32(120, 200, 130, 255);
		ImU32 wait_col = IM_COL32(220, 200, 80, 255);
		ImU32 susp_col = suspended > 0 ? IM_COL32(230, 140, 80, 255) : IM_COL32(180, 185, 200, 255);

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

	std::vector<thread_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
		snapshot = g_ui.threads;
	}

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
			"No threads found", ar, ag, ab, alpha, static_cast<float>(ImGui::GetTime()));
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

	for (int vi = 0; vi < visible_count; ++vi) {
		int idx = first_visible + vi;
		if (idx >= static_cast<int>(snapshot.size())) break;

		auto& t = snapshot[idx];
		float ry = list_y + idx * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		float row_alpha = ui_anim::render_row_entrance(idx, first_visible, dt, alpha);
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
			ImGui::OpenPopup("##thread_ctx");
		}
	}

	dl->PopClipRect();

	float scrollbar_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + width - scrollbar_w - 2.f, list_y, scrollbar_w, list_h,
									 g_ui.scroll_y, content_h, list_h, alpha,
									 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);

	if (ImGui::BeginPopup("##thread_ctx")) {
		if (g_ui.context_idx >= 0 && g_ui.context_idx < static_cast<int>(snapshot.size())) {
			if (ImGui::MenuItem("Suspend")) {
				std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
				if (g_ui.context_idx < static_cast<int>(g_ui.threads.size()))
					g_ui.threads[g_ui.context_idx].suspended = true;
			}
			if (ImGui::MenuItem("Resume")) {
				std::lock_guard<std::mutex> lk(g_ui.threads_mutex);
				if (g_ui.context_idx < static_cast<int>(g_ui.threads.size()))
					g_ui.threads[g_ui.context_idx].suspended = false;
			}
			if (ImGui::MenuItem("Switch To")) {
				debugger_engine::g_state.active_tid = snapshot[g_ui.context_idx].tid;
			}
			if (ImGui::MenuItem("Go to RIP in Disasm")) {
			}
		}
		ImGui::EndPopup();
	}
}

}
