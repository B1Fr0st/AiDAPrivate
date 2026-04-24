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


	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0)
		return;
	g_ui.refreshing.store(true);

	work_queue::post([]() {
		auto map = debugger_engine::get_memory_map();
		{
			std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
			g_ui.regions = std::move(map);
		}
		g_ui.refreshing.store(false);
	});
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
	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 accent = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
								  static_cast<int>(ab * 255), static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
					  _ta(_t.bg_base));

	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, width, header_h, ar, ag, ab, alpha);
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				_ta(_t.text_primary), "Memory Map");

	float refresh_x = pos_x + 100.f;
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

	if (g_ui.refreshing.load()) {
		ui_anim::render_spinner(dl, refresh_x + 80.f, refresh_y + 11.f, 6.f, 1.5f,
								accent, static_cast<float>(ImGui::GetTime()));
	}

	float filter_x = pos_x + width - 220.f;
	ImGui::SetCursorScreenPos(ImVec2(filter_x, pos_y + 5.f));
	ImGui::PushID("##memmapfilter");
	ui_anim::render_filter_input_chip("##f", g_ui.filter_buf, sizeof(g_ui.filter_buf),
		"Filter modules or info...", 210.f, ar, ag, ab, alpha);
	ImGui::PopID();

	float strip_y = pos_y + header_h;
	const float strip_h = 44.f;
	{
		size_t n_regions = 0;
		uint64_t total_size = 0;
		int rwx_count = 0;
		{
			std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
			n_regions = g_ui.regions.size();
			for (auto& r : g_ui.regions) {
				if (r.state == 0x1000)
					total_size += r.size;
				bool exec = (r.protect & 0xF0) != 0;
				bool write = (r.protect == 0x04) || (r.protect == 0x08) || (r.protect == 0x40) || (r.protect == 0x80);
				if (exec && write) rwx_count++;
			}
		}
		char n_buf[24];
		char sz_buf[24];
		char rwx_buf[24];
		char pid_buf[24];
		std::snprintf(n_buf, sizeof(n_buf), "%zu", n_regions);
		if (total_size >= 1024ULL * 1024ULL * 1024ULL)
			std::snprintf(sz_buf, sizeof(sz_buf), "%.1f GB", static_cast<double>(total_size) / (1024.0 * 1024.0 * 1024.0));
		else
			std::snprintf(sz_buf, sizeof(sz_buf), "%.1f MB", static_cast<double>(total_size) / (1024.0 * 1024.0));
		std::snprintf(rwx_buf, sizeof(rwx_buf), "%d", rwx_count);
		uint32_t pid = driver_bridge::attached_pid();
		if (pid)
			std::snprintf(pid_buf, sizeof(pid_buf), "PID %u", pid);
		else
			std::snprintf(pid_buf, sizeof(pid_buf), "none");

		ImU32 rwx_col = rwx_count > 0
			? IM_COL32(230, 90, 90, 255)
			: IM_COL32(120, 200, 130, 255);

		ui_anim::stat_strip_item_t items[4];
		items[0] = { "Regions",   n_buf,   nullptr, 0, nullptr, 0, 0 };
		items[1] = { "Committed", sz_buf,  nullptr, 0, nullptr, 0, 0 };
		items[2] = { "RWX",       rwx_buf, nullptr, 0, nullptr, 0, rwx_col };
		items[3] = { "Attached",  pid_buf, nullptr, 0, nullptr, 0, 0 };
		ui_anim::render_stat_strip(dl, pos_x + 6.f, strip_y + 4.f, width - 12.f, strip_h - 8.f,
			items, 4, ar, ag, ab, alpha);
	}

	float table_y = strip_y + strip_h;

	float col_addr = pos_x + width * 0.01f;
	float col_size = pos_x + width * 0.18f;
	float col_prot = pos_x + width * 0.28f;
	float col_state = pos_x + width * 0.43f;
	float col_type = pos_x + width * 0.54f;
	float col_mod = pos_x + width * 0.64f;
	float col_info = pos_x + width * 0.80f;

	{
		ui_anim::table_col_t cols[] = {{"Address", 150.f}, {"Size", 90.f}, {"Protection", 130.f}, {"State", 90.f}, {"Type", 90.f}, {"Module", 140.f}, {"Info", 150.f}};
		ui_anim::render_table_header(dl, pos_x, table_y, width, col_header_h, cols, 7, ar, ag, ab, alpha);
	}

	float list_y = table_y + col_header_h;
	float list_h = height - header_h - strip_h - col_header_h;
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

	if (filtered.empty() && !g_ui.refreshing.load()) {
		ui_anim::render_empty_state(dl, pos_x, list_y, width, list_h,
			"No memory regions found", ar, ag, ab, alpha, static_cast<float>(ImGui::GetTime()));
		dl->PopClipRect();
		return;
	}

	for (int vi = 0; vi < visible_count; ++vi) {
		int idx = first_visible + vi;
		if (idx >= static_cast<int>(filtered.size())) break;

		auto& r = filtered[idx];
		float ry = list_y + idx * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		float row_alpha = ui_anim::render_row_entrance(idx, first_visible, dt, alpha);
		ui_anim::row_hover_select(dl, pos_x, ry, width - 12.f, row_h, idx, g_ui.selected, row_alpha, ar, ag, ab);

		char addr_buf[24];
		snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(r.base));
		dl->AddText(ImVec2(col_addr, ry + 2.f),
					_ta(_t.text_secondary), addr_buf);

		std::string sz_str = detail::format_size(r.size);
		dl->AddText(ImVec2(col_size, ry + 2.f),
					_ta(_t.text_secondary), sz_str.c_str());

		std::string prot_str = debugger_engine::format_protect(r.protect);
		dl->AddText(ImVec2(col_prot, ry + 2.f), detail::protect_color(r.protect, alpha), prot_str.c_str());

		std::string state_str = detail::format_state(r.state);
		dl->AddText(ImVec2(col_state, ry + 2.f), detail::state_color(r.state, alpha), state_str.c_str());

		std::string type_str = detail::format_type(r.type);
		dl->AddText(ImVec2(col_type, ry + 2.f), detail::type_color(r.type, alpha), type_str.c_str());

		dl->AddText(ImVec2(col_mod, ry + 2.f),
					_ta(_t.text_secondary), r.module_name.c_str());
		dl->AddText(ImVec2(col_info, ry + 2.f),
					_ta(_t.text_dim), r.info.c_str());

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
