#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui/imgui.h"
#include "debugger_engine.hpp"
#include "ui_anim.hpp"

namespace memory_map_view {

struct ui_state_t {
	int                                        selected = -1;
	float                                      scroll_y = 0.f;
	float                                      target_scroll_y = 0.f;
	char                                       filter_buf[64] = {};
	float                                      last_refresh = 0.f;
	float                                      refresh_interval = 2.f;
	std::vector<debugger_engine::memory_region_t> regions;
	std::mutex                                 regions_mutex;
	std::atomic<bool>                          refreshing{false};
	bool                                       scrollbar_dragging = false;
	float                                      scrollbar_drag_offset = 0.f;
	uint64_t                                   context_addr = 0;
	bool                                       show_context = false;
};

inline ui_state_t g_ui;

inline void refresh()
{
	if (g_ui.refreshing.load())
		return;
	g_ui.refreshing.store(true);

	std::thread([]() {
		auto map = debugger_engine::get_memory_map();
		{
			std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
			g_ui.regions = std::move(map);
		}
		g_ui.refreshing.store(false);
	}).detach();
}

namespace detail {

inline std::string format_size(uint64_t bytes)
{
	char buf[32];
	if (bytes >= 1048576)
		snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / 1048576.0);
	else if (bytes >= 1024)
		snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
	else
		snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
	return buf;
}

inline std::string format_state(uint32_t state)
{
	if (state == 0x1000) return "COMMIT";
	if (state == 0x2000) return "RESERVE";
	if (state == 0x10000) return "FREE";
	char buf[16];
	snprintf(buf, sizeof(buf), "0x%X", state);
	return buf;
}

inline std::string format_type(uint32_t type)
{
	if (type == 0x1000000) return "IMAGE";
	if (type == 0x20000) return "PRIVATE";
	if (type == 0x40000) return "MAPPED";
	if (type == 0) return "";
	char buf[16];
	snprintf(buf, sizeof(buf), "0x%X", type);
	return buf;
}

inline ImU32 protect_color(uint32_t protect, float alpha)
{
	bool exec = (protect & 0xF0) != 0;
	bool write = (protect == 0x04) || (protect == 0x08) || (protect == 0x40) || (protect == 0x80);
	if (exec) return IM_COL32(220, 80, 80, static_cast<int>(200 * alpha));
	if (write) return IM_COL32(80, 200, 80, static_cast<int>(200 * alpha));
	return IM_COL32(80, 140, 220, static_cast<int>(200 * alpha));
}

inline ImU32 state_color(uint32_t state, float alpha)
{
	if (state == 0x1000) return IM_COL32(210, 210, 220, static_cast<int>(220 * alpha));
	if (state == 0x2000) return IM_COL32(120, 120, 130, static_cast<int>(150 * alpha));
	return IM_COL32(60, 60, 70, static_cast<int>(100 * alpha));
}

inline ImU32 type_color(uint32_t type, float alpha)
{
	if (type == 0x1000000) return IM_COL32(80, 140, 220, static_cast<int>(200 * alpha));
	if (type == 0x40000) return IM_COL32(80, 200, 80, static_cast<int>(200 * alpha));
	return IM_COL32(200, 200, 210, static_cast<int>(200 * alpha));
}

inline bool match_filter(const debugger_engine::memory_region_t& r, const char* filter)
{
	if (filter[0] == 0) return true;
	std::string lower_filter;
	for (const char* p = filter; *p; ++p)
		lower_filter.push_back(static_cast<char>((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p));
	std::string lower_mod;
	for (auto& c : r.module_name)
		lower_mod.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	std::string lower_info;
	for (auto& c : r.info)
		lower_info.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	if (lower_mod.find(lower_filter) != std::string::npos) return true;
	if (lower_info.find(lower_filter) != std::string::npos) return true;
	return false;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float ar, float ag, float ab)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = ImGui::GetIO().DeltaTime;

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  IM_COL32(18, 18, 24, static_cast<int>(240 * alpha)));

	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + header_h),
					  IM_COL32(25, 27, 35, static_cast<int>(240 * alpha)));
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				IM_COL32(200, 200, 210, static_cast<int>(220 * alpha)), "Memory Map");

	float refresh_x = pos_x + 100.f;
	float refresh_y = pos_y + 4.f;
	ImVec2 btn_min(refresh_x, refresh_y);
	ImVec2 btn_max(refresh_x + 60.f, refresh_y + 22.f);
	bool btn_hover = ImGui::IsMouseHoveringRect(btn_min, btn_max, false);
	dl->AddRectFilled(btn_min, btn_max,
					  btn_hover ? IM_COL32(50, 52, 60, static_cast<int>(200 * alpha))
								: IM_COL32(35, 37, 45, static_cast<int>(200 * alpha)), 3.f);
	dl->AddText(ImVec2(refresh_x + 8.f, refresh_y + 3.f),
				IM_COL32(180, 180, 190, static_cast<int>(200 * alpha)), "Refresh");
	if (btn_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
		refresh();

	if (g_ui.refreshing.load()) {
		dl->AddText(ImVec2(refresh_x + 70.f, refresh_y + 3.f),
					IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							 static_cast<int>(ab * 255), static_cast<int>(200 * alpha)), "...");
	}

	float filter_x = pos_x + width - 220.f;
	dl->AddText(ImVec2(filter_x - 40.f, pos_y + 8.f),
				IM_COL32(140, 140, 150, static_cast<int>(180 * alpha)), "Filter:");
	ImGui::SetCursorScreenPos(ImVec2(filter_x, pos_y + 5.f));
	ImGui::PushItemWidth(200.f);
	ImGui::PushID("##memmapfilter");
	ImGui::InputText("##f", g_ui.filter_buf, sizeof(g_ui.filter_buf));
	ImGui::PopID();
	ImGui::PopItemWidth();

	float table_y = pos_y + header_h;

	float col_addr = pos_x + 10.f;
	float col_size = pos_x + 160.f;
	float col_prot = pos_x + 250.f;
	float col_state = pos_x + 380.f;
	float col_type = pos_x + 470.f;
	float col_mod = pos_x + 560.f;
	float col_info = pos_x + 700.f;

	dl->AddRectFilled(ImVec2(pos_x, table_y), ImVec2(pos_x + width, table_y + col_header_h),
					  IM_COL32(30, 32, 40, static_cast<int>(220 * alpha)));
	ImU32 hdr_col = IM_COL32(160, 160, 175, static_cast<int>(200 * alpha));
	dl->AddText(ImVec2(col_addr, table_y + 3.f), hdr_col, "Address");
	dl->AddText(ImVec2(col_size, table_y + 3.f), hdr_col, "Size");
	dl->AddText(ImVec2(col_prot, table_y + 3.f), hdr_col, "Protection");
	dl->AddText(ImVec2(col_state, table_y + 3.f), hdr_col, "State");
	dl->AddText(ImVec2(col_type, table_y + 3.f), hdr_col, "Type");
	dl->AddText(ImVec2(col_mod, table_y + 3.f), hdr_col, "Module");
	dl->AddText(ImVec2(col_info, table_y + 3.f), hdr_col, "Info");

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - col_header_h;
	if (list_h <= 0.f)
		return;

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	std::vector<debugger_engine::memory_region_t> filtered;
	{
		std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
		for (auto& r : g_ui.regions) {
			if (detail::match_filter(r, g_ui.filter_buf))
				filtered.push_back(r);
		}
	}

	float content_h = static_cast<float>(filtered.size()) * row_h;
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
		if (idx >= static_cast<int>(filtered.size())) break;

		auto& r = filtered[idx];
		float ry = list_y + idx * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, alpha, ar, ag, ab);

		char addr_buf[24];
		snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(r.base));
		dl->AddText(ImVec2(col_addr, ry + 2.f),
					IM_COL32(180, 190, 210, static_cast<int>(210 * alpha)), addr_buf);

		std::string sz_str = detail::format_size(r.size);
		dl->AddText(ImVec2(col_size, ry + 2.f),
					IM_COL32(180, 180, 190, static_cast<int>(200 * alpha)), sz_str.c_str());

		std::string prot_str = debugger_engine::format_protect(r.protect);
		dl->AddText(ImVec2(col_prot, ry + 2.f), detail::protect_color(r.protect, alpha), prot_str.c_str());

		std::string state_str = detail::format_state(r.state);
		dl->AddText(ImVec2(col_state, ry + 2.f), detail::state_color(r.state, alpha), state_str.c_str());

		std::string type_str = detail::format_type(r.type);
		dl->AddText(ImVec2(col_type, ry + 2.f), detail::type_color(r.type, alpha), type_str.c_str());

		dl->AddText(ImVec2(col_mod, ry + 2.f),
					IM_COL32(160, 170, 200, static_cast<int>(200 * alpha)), r.module_name.c_str());
		dl->AddText(ImVec2(col_info, ry + 2.f),
					IM_COL32(140, 140, 150, static_cast<int>(170 * alpha)), r.info.c_str());

		if (idx == g_ui.selected && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			g_ui.context_addr = r.base;
			g_ui.show_context = true;
			ImGui::OpenPopup("##memmap_ctx");
		}
	}

	dl->PopClipRect();

	float scrollbar_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + width - scrollbar_w - 2.f, list_y, scrollbar_w, list_h,
									 g_ui.scroll_y, content_h, list_h, alpha,
									 g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);

	if (ImGui::BeginPopup("##memmap_ctx")) {
		if (ImGui::MenuItem("Go to Hex View"))
			g_ui.show_context = false;
		if (ImGui::MenuItem("Go to Disassembly"))
			g_ui.show_context = false;
		if (ImGui::MenuItem("Change Protection"))
			g_ui.show_context = false;
		if (ImGui::MenuItem("Dump Region"))
			g_ui.show_context = false;
		ImGui::EndPopup();
	}
}

}
