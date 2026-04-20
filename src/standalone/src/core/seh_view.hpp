#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

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
	bool                     scrollbar_dragging = false;
	float                    scrollbar_drag_offset = 0.f;
};

inline ui_state_t g_ui;

inline void refresh()
{
	std::thread([]() {
		std::vector<seh_entry_t> entries;

		auto modules = driver_bridge::enumerate_modules();
		auto regs = debugger_engine::get_registers();

		uint64_t teb_addr = regs.gs;
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
					for (size_t i = 0; i + 16 <= stack_buf.size(); i += 8) {
						uint64_t candidate = 0;
						std::memcpy(&candidate, stack_buf.data() + i, 8);
						if (candidate > 0x10000 && candidate < 0x7FFFFFFFFFFF) {
							for (auto& m : modules) {
								if (candidate >= m.base && candidate < m.base + m.size) {
									uint64_t potential_next = 0;
									std::memcpy(&potential_next, stack_buf.data() + i - 8, 8);
									if (i >= 8 && potential_next > rsp && potential_next < rsp + 0x100000) {
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
				current = next;
				++idx;
			}
		}

		{
			std::lock_guard<std::mutex> lk(g_ui.mutex);
			g_ui.entries = std::move(entries);
		}
	}).detach();
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

	float table_y = pos_y + header_h;

	float col_idx = pos_x + width * 0.01f;
	float col_frame = pos_x + width * 0.06f;
	float col_handler = pos_x + width * 0.28f;
	float col_module = pos_x + width * 0.52f;
	float col_name = pos_x + width * 0.70f;

	{
		ui_anim::table_col_t cols[] = {{"#", 40.f}, {"Frame Address", 170.f}, {"Handler Address", 180.f}, {"Module", 140.f}, {"Name", 200.f}};
		ui_anim::render_table_header(dl, pos_x, table_y, width, col_header_h, cols, 5, ar, ag, ab, alpha);
	}

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - col_header_h;
	if (list_h <= 0.f) return;

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	std::vector<seh_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_ui.mutex);
		snapshot = g_ui.entries;
	}

	if (snapshot.empty()) {
		ui_anim::render_empty_state(dl, pos_x, list_y, width, list_h, "No SEH chain found",
			ar, ag, ab, alpha, static_cast<float>(ImGui::GetTime()));
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

		float row_alpha = ui_anim::render_row_entrance(idx, first_visible, dt, alpha);
		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, row_alpha, ar, ag, ab);

		char idx_buf[8];
		snprintf(idx_buf, sizeof(idx_buf), "%d", e.index);
		dl->AddText(ImVec2(col_idx, ry + 2.f),
					_ta(_t.text_secondary), idx_buf);

		char frame_buf[24];
		snprintf(frame_buf, sizeof(frame_buf), "%016llX", static_cast<unsigned long long>(e.frame_addr));
		dl->AddText(ImVec2(col_frame, ry + 2.f),
					_ta(_t.text_primary), frame_buf);

		char handler_buf[24];
		snprintf(handler_buf, sizeof(handler_buf), "%016llX", static_cast<unsigned long long>(e.handler_addr));
		dl->AddText(ImVec2(col_handler, ry + 2.f),
					_ta(_t.text_primary), handler_buf);

		dl->AddText(ImVec2(col_module, ry + 2.f),
					_ta(_t.text_secondary), e.module_name.c_str());

		dl->AddText(ImVec2(col_name, ry + 2.f),
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
