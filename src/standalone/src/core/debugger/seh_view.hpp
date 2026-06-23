#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include "work_queue.hpp"
#include <cstdio>
#include <cstring>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"

extern DisasmState g_disasm;

namespace seh_view {

struct seh_entry_t {
	uint64_t    handler_addr = 0;
	uint64_t    filter_addr = 0;
	uint64_t    frame_addr = 0;
	std::string module_name;
	std::string handler_name;
	int         index = 0;
};

struct ui_state_t {
	std::vector<seh_entry_t> entries;
	int                      selected = -1;
	float                    scroll_y = 0.f;
	float                    target_scroll_y = 0.f;
	std::mutex               mutex;
	std::atomic<bool>        refreshing{false};
	bool                     scrollbar_dragging = false;
	float                    scrollbar_drag_offset = 0.f;
};

inline ui_state_t g_ui;

inline void draw_clipped_text(ImDrawList* dl, ImVec2 pos, float width, float row_h, ImU32 color, const char* text)
{
	const char* value = (text && text[0]) ? text : "Unresolved";
	float clipped_w = std::max(4.f, width);
	ImVec2 a(pos.x, pos.y - 2.f);
	ImVec2 b(pos.x + clipped_w, pos.y + row_h);
	dl->PushClipRect(a, b, true);
	dl->AddText(pos, color, value);
	dl->PopClipRect();
	if (ImGui::IsMouseHoveringRect(a, b, false) && ImGui::CalcTextSize(value).x > clipped_w)
		ImGui::SetTooltip("%s", value);
}

inline uint64_t resolve_thread_teb(uint32_t tid)
{
	if (tid == 0)
		return 0;
	struct teb_basic_t {
		long      exit_status;
		void*     teb_base;
		void*     unique_process;
		void*     unique_thread;
		uintptr_t affinity_mask;
		long      priority;
		long      base_priority;
	};
	teb_basic_t tbi{};
	uint32_t returned = 0;
	if (!driver_bridge::query_thread_information(tid, 0, &tbi, sizeof(tbi), &returned))
		return 0;
	return reinterpret_cast<uint64_t>(tbi.teb_base);
}

inline void refresh()
{
	bool expected = false;
	if (!g_ui.refreshing.compare_exchange_strong(expected, true))
		return;
	diag::log_tagged_fmt("seh",
		"seh_refresh_request attached_pid=%u active_tid=%u",
		static_cast<unsigned>(driver_bridge::attached_pid()),
		static_cast<unsigned>(debugger_engine::g_state.active_tid));
	try {
		if (!work_queue::post([]() {
		try {
		std::vector<seh_entry_t> entries;

		auto modules = driver_bridge::enumerate_modules();
		auto regs = debugger_engine::get_registers();

		uint64_t teb_addr = resolve_thread_teb(debugger_engine::g_state.active_tid);
		uint64_t nt_tib_seh = 0;
		bool found_seh = false;

		if (teb_addr != 0) {
			std::vector<uint8_t> teb_buf;
			if (driver_bridge::read_memory(teb_addr, 8, teb_buf) && teb_buf.size() >= 8) {
				std::memcpy(&nt_tib_seh, teb_buf.data(), 8);
				found_seh = (nt_tib_seh != 0 && nt_tib_seh != 0xFFFFFFFFFFFFFFFFULL);
			}
		}

		if (!found_seh) {
			uint64_t rsp = regs.rsp;
			if (rsp != 0) {
				std::vector<uint8_t> stack_buf;
				size_t scan_size = 4096;
				if (driver_bridge::read_memory(rsp, scan_size, stack_buf) && stack_buf.size() >= 16) {
					for (size_t i = 8; i + 8 <= stack_buf.size(); i += 8) {
						uint64_t candidate = 0;
						std::memcpy(&candidate, stack_buf.data() + i, 8);
						if (candidate > 0x10000 && candidate < 0x7FFFFFFFFFFF) {
							for (auto& m : modules) {
								if (candidate >= m.base && candidate < m.base + m.size) {
									uint64_t potential_next = 0;
									std::memcpy(&potential_next, stack_buf.data() + i - 8, 8);
									if (potential_next > rsp && potential_next < rsp + 0x100000) {
										nt_tib_seh = rsp + i - 8;
										found_seh = true;
									}
									break;
								}
							}
						}
						if (found_seh) break;
					}
				}
			}
		}

		if (found_seh && nt_tib_seh != 0 && nt_tib_seh != 0xFFFFFFFFFFFFFFFFULL) {
			uint64_t current = nt_tib_seh;
			int idx = 0;
			const int max_chain = 256;

			while (current != 0 && current != 0xFFFFFFFFFFFFFFFFULL && idx < max_chain) {
				std::vector<uint8_t> rec_buf;
				bool read_ok = driver_bridge::read_memory(current, 16, rec_buf);
				if (!read_ok || rec_buf.size() < 16)
					break;

				seh_entry_t entry;
				entry.frame_addr = current;
				entry.index = idx;

				uint64_t next = 0;
				std::memcpy(&next, rec_buf.data(), 8);
				std::memcpy(&entry.handler_addr, rec_buf.data() + 8, 8);

				for (auto& m : modules) {
					if (entry.handler_addr >= m.base && entry.handler_addr < m.base + m.size) {
						entry.module_name = m.name;
						char off_buf[32];
						snprintf(off_buf, sizeof(off_buf), "+0x%llX",
								 static_cast<unsigned long long>(entry.handler_addr - m.base));
						entry.handler_name = m.name + off_buf;
						break;
					}
				}

				entries.push_back(std::move(entry));
				if (next == current || next == 0 || next == 0xFFFFFFFFFFFFFFFFULL)
					break;
				current = next;
				++idx;
			}
		}

		size_t n = entries.size();
		{
			std::lock_guard<std::mutex> lk(g_ui.mutex);
			g_ui.entries = std::move(entries);
		}
		diag::log_tagged_fmt("seh",
			"seh_refresh_done chain_depth=%zu", n);
		g_ui.refreshing.store(false);
		} catch (const std::exception& ex) {
			diag::log_tagged_fmt("seh", "seh_refresh_worker_exception err='%s'", ex.what());
			g_ui.refreshing.store(false);
		} catch (...) {
			diag::log_tagged("seh", "seh_refresh_worker_exception err='<unknown>'");
			g_ui.refreshing.store(false);
		}
	})) {
			diag::log_tagged("seh", "seh_refresh_worker_post_failed");
			g_ui.refreshing.store(false);
		}
	} catch (const std::exception& ex) {
		diag::log_tagged_fmt("seh", "seh_refresh_worker_create_failed err='%s'", ex.what());
		g_ui.refreshing.store(false);
	} catch (...) {
		diag::log_tagged("seh", "seh_refresh_worker_create_failed err='<unknown>'");
		g_ui.refreshing.store(false);
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
				_ta(_t.text_primary), "SEH Chain");

	float refresh_x = pos_x + 90.f;
	ImVec2 btn_min(refresh_x, pos_y + 4.f);
	ImVec2 btn_max(refresh_x + 60.f, pos_y + 26.f);
	bool btn_hover = ImGui::IsMouseHoveringRect(btn_min, btn_max, false);
	dl->AddRectFilled(btn_min, btn_max,
					  btn_hover ? _ta(ui_anim::lighten(_t.panel_header, 14))
								: _ta(_t.panel_header), 3.f);
	dl->AddText(ImVec2(refresh_x + 8.f, pos_y + 7.f),
				_ta(_t.text_secondary), "Refresh");
	if (btn_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
		refresh();

	float strip_y = pos_y + header_h;
	const float strip_h = 44.f;
	{
		int depth = 0;
		int unresolved = 0;
		int distinct_modules = 0;
		uint32_t active_tid = debugger_engine::g_state.active_tid;
		{
			std::lock_guard<std::mutex> lk(g_ui.mutex);
			depth = static_cast<int>(g_ui.entries.size());
			std::vector<std::string> seen_modules;
			seen_modules.reserve(g_ui.entries.size());
			for (auto& e : g_ui.entries) {
				if (e.module_name.empty()) unresolved++;
				else {
					bool already = false;
					for (auto& sm : seen_modules) {
						if (sm == e.module_name) { already = true; break; }
					}
					if (!already) seen_modules.push_back(e.module_name);
				}
			}
			distinct_modules = static_cast<int>(seen_modules.size());
		}
		char depth_buf[16];
		char tid_buf[16];
		char unres_buf[16];
		char mod_buf[16];
		std::snprintf(depth_buf, sizeof(depth_buf), "%d", depth);
		std::snprintf(tid_buf, sizeof(tid_buf), "%u", active_tid);
		std::snprintf(unres_buf, sizeof(unres_buf), "%d", unresolved);
		std::snprintf(mod_buf, sizeof(mod_buf), "%d", distinct_modules);

		ImU32 unres_col = unresolved > 0
			? _t.warning
			: _t.success;

		ui_anim::stat_strip_item_t items[4];
		items[0] = { "Chain Depth", depth_buf, nullptr, 0, nullptr, 0, 0 };
		items[1] = { "Active TID",   tid_buf,   nullptr, 0, nullptr, 0, 0 };
		items[2] = { "Unresolved",   unres_buf, nullptr, 0, nullptr, 0, unres_col };
		items[3] = { "Modules",      mod_buf,   nullptr, 0, nullptr, 0, 0 };
		ui_anim::render_stat_strip(dl, pos_x + 6.f, strip_y + 4.f, width - 12.f, strip_h - 8.f,
			items, 4, ar, ag, ab, alpha);
	}

	float table_y = strip_y + strip_h;

	const float table_pad = 10.f;
	float content_w = std::max(240.f, width - table_pad * 2.f);
	float idx_w = 44.f;
	float frame_w = std::min(172.f, std::max(126.f, content_w * 0.20f));
	float handler_w = std::min(180.f, std::max(132.f, content_w * 0.22f));
	float module_w = std::min(180.f, std::max(96.f, content_w * 0.18f));
	float name_w = content_w - idx_w - frame_w - handler_w - module_w;
	if (name_w < 96.f) {
		float deficit = 96.f - name_w;
		auto shrink = [](float& value, float min_value, float& amount) {
			float room = std::max(0.f, value - min_value);
			float cut = std::min(room, amount);
			value -= cut;
			amount -= cut;
		};
		shrink(module_w, 72.f, deficit);
		shrink(handler_w, 116.f, deficit);
		shrink(frame_w, 116.f, deficit);
		name_w = std::max(72.f, content_w - idx_w - frame_w - handler_w - module_w);
	}

	float col_idx = pos_x + table_pad;
	float col_frame = col_idx + idx_w;
	float col_handler = col_frame + frame_w;
	float col_module = col_handler + handler_w;
	float col_name = col_module + module_w;

	{
		ui_anim::table_col_t cols[] = {{"#", idx_w}, {"Frame Address", frame_w}, {"Handler Address", handler_w}, {"Module", module_w}, {"Name", name_w}};
		ui_anim::render_table_header(dl, pos_x, table_y, width, col_header_h, cols, 5, ar, ag, ab, alpha);
	}

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - strip_h - col_header_h;
	if (list_h <= 0.f) return;

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	std::vector<seh_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_ui.mutex);
		snapshot = g_ui.entries;
	}

	if (snapshot.empty()) {
		float cw = std::min(width - 40.f, 540.f);
		if (cw < 160.f) cw = std::max(160.f, width - 20.f);
		float cx = pos_x + (width - cw) * 0.5f;
		float cy = list_y + list_h * 0.5f - 34.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"No SEH chain found. Empty chains are normal for many x64 targets.",
			ui_anim::callout_kind_t::info, ar, ag, ab, alpha);
		const char* hint = "SEH is per active thread; switch threads and refresh when needed.";
		ImVec2 hint_sz = ImGui::CalcTextSize(hint);
		dl->AddText(ImVec2(pos_x + (width - hint_sz.x) * 0.5f, cy + 58.f),
			_ta(_t.text_secondary), hint);
		dl->PopClipRect();
		return;
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

	for (int vi = 0; vi < visible_count; ++vi) {
		int idx = first_visible + vi;
		if (idx >= static_cast<int>(snapshot.size())) break;

		auto& e = snapshot[idx];
		float ry = list_y + idx * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		float row_alpha = ui_anim::render_row_entrance(idx, static_cast<float>(first_visible), dt, alpha);
		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, row_alpha, ar, ag, ab);

		char idx_buf[8];
		snprintf(idx_buf, sizeof(idx_buf), "%d", e.index);
		draw_clipped_text(dl, ImVec2(col_idx, ry + 2.f), idx_w - 6.f, row_h,
			_ta(_t.text_secondary), idx_buf);

		char frame_buf[24];
		snprintf(frame_buf, sizeof(frame_buf), "%016llX", static_cast<unsigned long long>(e.frame_addr));
		draw_clipped_text(dl, ImVec2(col_frame, ry + 2.f), frame_w - 8.f, row_h,
			_ta(_t.text_primary), frame_buf);

		char handler_buf[24];
		snprintf(handler_buf, sizeof(handler_buf), "%016llX", static_cast<unsigned long long>(e.handler_addr));
		draw_clipped_text(dl, ImVec2(col_handler, ry + 2.f), handler_w - 8.f, row_h,
			_ta(_t.text_primary), handler_buf);

		draw_clipped_text(dl, ImVec2(col_module, ry + 2.f), module_w - 8.f, row_h,
			_ta(_t.text_secondary), e.module_name.c_str());

		draw_clipped_text(dl, ImVec2(col_name, ry + 2.f), name_w - 8.f, row_h,
			_ta(_t.text_primary), e.handler_name.c_str());

		if (idx == g_ui.selected && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
			ImGui::OpenPopup("##seh_ctx");
	}

	dl->PopClipRect();

	float sb_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + width - sb_w - 2.f, list_y, sb_w, list_h,
									 g_ui.scroll_y, content_h, list_h, alpha,
									 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);

	if (ImGui::BeginPopup("##seh_ctx")) {
		if (g_ui.selected >= 0 && g_ui.selected < static_cast<int>(snapshot.size())) {
			if (ImGui::MenuItem("Go to Handler")) {
				diag::log_tagged_fmt("seh",
					"seh_go_handler idx=%d handler=0x%llx",
					g_ui.selected,
					static_cast<unsigned long long>(snapshot[g_ui.selected].handler_addr));
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(snapshot[g_ui.selected].handler_addr, g_disasm);
			}
			if (ImGui::MenuItem("Copy Address")) {
				char abuf[24];
				snprintf(abuf, sizeof(abuf), "%016llX",
						 static_cast<unsigned long long>(snapshot[g_ui.selected].handler_addr));
				ImGui::SetClipboardText(abuf);
			}
		}
		ImGui::EndPopup();
	}
}

}
