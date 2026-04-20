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
#include "standalone_driver.hpp"
#include "pe_parser.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

namespace module_view {

struct ui_state_t {
	std::vector<driver_bridge::module_info_t> modules;
	int                                       selected_module = -1;
	int                                       active_sub = 0;
	std::vector<pe_parser::export_entry_t>    exports;
	std::vector<pe_parser::import_entry_t>    imports;
	float                                     module_scroll_y = 0.f;
	float                                     module_target_scroll_y = 0.f;
	float                                     detail_scroll_y = 0.f;
	float                                     detail_target_scroll_y = 0.f;
	char                                      filter_buf[128] = {};
	std::mutex                                modules_mutex;
	std::atomic<bool>                         loading{false};
	int                                       selected_detail = -1;
	bool                                      mod_scrollbar_dragging = false;
	float                                     mod_scrollbar_drag_offset = 0.f;
	bool                                      detail_scrollbar_dragging = false;
	float                                     detail_scrollbar_drag_offset = 0.f;
	float                                     sub_tab_anim[2] = {1.f, 0.f};
	uint64_t                                  navigate_to = 0;
};

inline ui_state_t g_ui;

inline void refresh()
{
	if (g_ui.loading.load())
		return;


	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0)
		return;
	g_ui.loading.store(true);

	std::thread([]() {
		auto mods = driver_bridge::enumerate_modules();
		{
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			g_ui.modules = std::move(mods);
		}
		g_ui.loading.store(false);
	}).detach();
}

inline void load_module_details(int index)
{
	if (g_ui.loading.load())
		return;

	uint64_t base = 0;
	{
		std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
		if (index < 0 || index >= static_cast<int>(g_ui.modules.size()))
			return;
		base = g_ui.modules[index].base;
	}

	g_ui.loading.store(true);

	std::thread([base]() {
		pe_parser::pe_info_t pe;
		pe_parser::parse(base, pe);
		{
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			g_ui.exports = std::move(pe.exports);
			g_ui.imports = std::move(pe.imports);
			g_ui.selected_detail = -1;
			g_ui.detail_scroll_y = 0.f;
			g_ui.detail_target_scroll_y = 0.f;
		}
		g_ui.loading.store(false);
	}).detach();
}

namespace detail {

inline bool match_filter(const std::string& name, const char* filter)
{
	if (filter[0] == 0) return true;
	std::string lower_name;
	for (auto c : name)
		lower_name.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	std::string lower_filter;
	for (const char* p = filter; *p; ++p)
		lower_filter.push_back(static_cast<char>((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p));
	return lower_name.find(lower_filter) != std::string::npos;
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

	float left_w = width * 0.4f;
	float right_w = width - left_w - 2.f;
	float header_h = 32.f;
	float row_h = 20.f;
	float col_header_h = 22.f;

	ui_anim::render_toolbar(dl, pos_x, pos_y, left_w, header_h, ar, ag, ab, alpha);
	dl->AddText(ImVec2(pos_x + 10.f, pos_y + 8.f),
				_ta(_t.text_primary), "Modules");

	float refresh_x = pos_x + 80.f;
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

	static char mod_list_filter[64] = {};
	float mlf_x = pos_x + left_w - 160.f;
	ImGui::SetCursorScreenPos(ImVec2(mlf_x, pos_y + 5.f));
	ImGui::PushItemWidth(140.f);
	ImGui::PushID("##modlistfilter");
	ImGui::InputText("##mlf", mod_list_filter, sizeof(mod_list_filter));
	ImGui::PopID();
	ImGui::PopItemWidth();

	float mod_col_name = pos_x + 10.f;
	float mod_col_base = pos_x + left_w * 0.45f;
	float mod_col_size = pos_x + left_w * 0.75f;

	float mod_table_y = pos_y + header_h;
	{
		ui_anim::table_col_t cols[] = {{"Name", left_w * 0.45f - 10.f}, {"Base", left_w * 0.3f}, {"Size", left_w * 0.25f}};
		ui_anim::render_table_header(dl, pos_x, mod_table_y, left_w, col_header_h, cols, 3, ar, ag, ab, alpha);
	}
	ImU32 hdr_col = _ta(_t.text_secondary);

	float mod_list_y = mod_table_y + col_header_h;
	float mod_list_h = height - header_h - col_header_h;
	if (mod_list_h <= 0.f) return;

	dl->PushClipRect(ImVec2(pos_x, mod_list_y), ImVec2(pos_x + left_w, mod_list_y + mod_list_h), true);

	std::vector<driver_bridge::module_info_t> mods_snapshot;
	{
		std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
		for (auto& m : g_ui.modules) {
			if (detail::match_filter(m.name, mod_list_filter))
				mods_snapshot.push_back(m);
		}
	}

	float mod_content_h = static_cast<float>(mods_snapshot.size()) * row_h;
	float mod_max_scroll = mod_content_h - mod_list_h;
	if (mod_max_scroll < 0.f) mod_max_scroll = 0.f;

	if (ImGui::IsMouseHoveringRect(ImVec2(pos_x, mod_list_y), ImVec2(pos_x + left_w, mod_list_y + mod_list_h), false))
		ui_anim::handle_scroll_input(g_ui.module_target_scroll_y, 0.f, mod_max_scroll, row_h);
	ui_anim::clamp_scroll(g_ui.module_target_scroll_y, 0.f, mod_max_scroll);
	ui_anim::smooth_scroll(g_ui.module_scroll_y, g_ui.module_target_scroll_y, 15.f, dt);

	int mod_first = static_cast<int>(g_ui.module_scroll_y / row_h);
	if (mod_first < 0) mod_first = 0;
	int mod_vis = static_cast<int>(mod_list_h / row_h) + 2;

	for (int vi = 0; vi < mod_vis; ++vi) {
		int idx = mod_first + vi;
		if (idx >= static_cast<int>(mods_snapshot.size())) break;

		auto& m = mods_snapshot[idx];
		float ry = mod_list_y + idx * row_h - g_ui.module_scroll_y;
		if (ry + row_h < mod_list_y || ry > mod_list_y + mod_list_h) continue;

		bool clicked = ui_anim::row_hover_select(dl, pos_x, ry, left_w - 12.f, row_h,
												  idx, g_ui.selected_module, alpha, ar, ag, ab);
		float mod_row_alpha = ui_anim::render_row_entrance(idx, mod_first, dt, alpha);
		(void)mod_row_alpha;
		if (clicked)
			load_module_details(idx);

		dl->AddText(ImVec2(mod_col_name, ry + 2.f),
					_ta(_t.text_primary), m.name.c_str());

		char base_buf[24];
		snprintf(base_buf, sizeof(base_buf), "%016llX", static_cast<unsigned long long>(m.base));
		dl->AddText(ImVec2(mod_col_base, ry + 2.f),
					_ta(_t.text_secondary), base_buf);

		char size_buf[16];
		snprintf(size_buf, sizeof(size_buf), "%08X", m.size);
		dl->AddText(ImVec2(mod_col_size, ry + 2.f),
					_ta(_t.text_secondary), size_buf);
	}

	dl->PopClipRect();

	float sb_w = 8.f;
	ui_anim::render_custom_scrollbar(dl, pos_x + left_w - sb_w - 2.f, mod_list_y, sb_w, mod_list_h,
									 g_ui.module_scroll_y, mod_content_h, mod_list_h, alpha,
									 g_ui.mod_scrollbar_dragging, g_ui.mod_scrollbar_drag_offset);

	dl->AddRectFilled(ImVec2(pos_x + left_w, pos_y),
					  ImVec2(pos_x + left_w + 2.f, pos_y + height),
					  _ta(ui_anim::lighten(_t.panel_bg, 12)));

	float right_x = pos_x + left_w + 2.f;

	ui_anim::render_toolbar(dl, right_x, pos_y, right_w, header_h, ar, ag, ab, alpha);

	const char* sub_labels[] = {"Exports", "Imports"};
	float tab_x = right_x + 10.f;
	for (int i = 0; i < 2; ++i) {
		ImVec2 tsz = ImGui::CalcTextSize(sub_labels[i]);
		float tw = tsz.x + 20.f;
		ImVec2 tmin(tab_x, pos_y + 4.f);
		ImVec2 tmax(tab_x + tw, pos_y + 26.f);
		bool tab_hover = ImGui::IsMouseHoveringRect(tmin, tmax, false);

		if (tab_hover && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_ui.active_sub = i;
			g_ui.selected_detail = -1;
			g_ui.detail_scroll_y = 0.f;
			g_ui.detail_target_scroll_y = 0.f;
		}

		ImU32 tab_text_col = (i == g_ui.active_sub)
			? _ta(_t.text_primary)
			: _ta(_t.text_dim);
		dl->AddText(ImVec2(tab_x + 10.f, pos_y + 7.f), tab_text_col, sub_labels[i]);
		ui_anim::render_tab_underline(dl, tab_x, pos_y + header_h - 2.f, tw,
									  g_ui.sub_tab_anim[i], i == g_ui.active_sub, dt, ar, ag, ab, alpha);
		tab_x += tw + 4.f;
	}

	float filter_x = right_x + right_w - 220.f;
	ImGui::SetCursorScreenPos(ImVec2(filter_x, pos_y + 5.f));
	ImGui::PushItemWidth(200.f);
	ImGui::PushID("##modfilter");
	ImGui::InputText("##mf", g_ui.filter_buf, sizeof(g_ui.filter_buf));
	ImGui::PopID();
	ImGui::PopItemWidth();

	float det_table_y = pos_y + header_h;

	if (g_ui.active_sub == 0) {
		float ec_ord = right_x + 10.f;
		float ec_name = right_x + 70.f;
		float ec_addr = right_x + right_w * 0.65f;

		{
			ui_anim::table_col_t cols[] = {{"Ordinal", 60.f}, {"Name", right_w * 0.55f}, {"Address", right_w * 0.3f}};
			ui_anim::render_table_header(dl, right_x, det_table_y, right_w, col_header_h, cols, 3, ar, ag, ab, alpha);
		}

		float det_list_y = det_table_y + col_header_h;
		float det_list_h = height - header_h - col_header_h;
		if (det_list_h <= 0.f) return;

		dl->PushClipRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), true);

		std::vector<pe_parser::export_entry_t> filtered;
		{
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			for (auto& e : g_ui.exports) {
				if (detail::match_filter(e.name, g_ui.filter_buf))
					filtered.push_back(e);
			}
		}

		float det_content_h = static_cast<float>(filtered.size()) * row_h;
		float det_max_scroll = det_content_h - det_list_h;
		if (det_max_scroll < 0.f) det_max_scroll = 0.f;

		if (ImGui::IsMouseHoveringRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), false))
			ui_anim::handle_scroll_input(g_ui.detail_target_scroll_y, 0.f, det_max_scroll, row_h);
		ui_anim::clamp_scroll(g_ui.detail_target_scroll_y, 0.f, det_max_scroll);
		ui_anim::smooth_scroll(g_ui.detail_scroll_y, g_ui.detail_target_scroll_y, 15.f, dt);

		int det_first = static_cast<int>(g_ui.detail_scroll_y / row_h);
		if (det_first < 0) det_first = 0;
		int det_vis = static_cast<int>(det_list_h / row_h) + 2;

		for (int vi = 0; vi < det_vis; ++vi) {
			int idx = det_first + vi;
			if (idx >= static_cast<int>(filtered.size())) break;

			auto& exp = filtered[idx];
			float ry = det_list_y + idx * row_h - g_ui.detail_scroll_y;
			if (ry + row_h < det_list_y || ry > det_list_y + det_list_h) continue;

			bool clicked = ui_anim::row_hover_select(dl, right_x, ry, right_w - 12.f, row_h,
													  idx, g_ui.selected_detail, alpha, ar, ag, ab);

			char ord_buf[8];
			snprintf(ord_buf, sizeof(ord_buf), "%u", exp.ordinal);
			dl->AddText(ImVec2(ec_ord, ry + 2.f),
						_ta(_t.text_secondary), ord_buf);

			ImU32 name_col = exp.is_forwarded
				? IM_COL32(200, 180, 80, static_cast<int>(alpha * 200))
				: _ta(_t.text_primary);
			dl->AddText(ImVec2(ec_name, ry + 2.f), name_col,
						exp.name.empty() ? "(unnamed)" : exp.name.c_str());

			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(exp.address));
			dl->AddText(ImVec2(ec_addr, ry + 2.f),
						_ta(_t.text_secondary), addr_buf);

			if (clicked && ui_anim::row_double_click(idx, g_ui.selected_detail))
				g_ui.navigate_to = exp.address;
		}

		dl->PopClipRect();
		ui_anim::render_custom_scrollbar(dl, right_x + right_w - sb_w - 2.f, det_list_y, sb_w, det_list_h,
										 g_ui.detail_scroll_y, det_content_h, det_list_h, alpha,
										 g_ui.detail_scrollbar_dragging, g_ui.detail_scrollbar_drag_offset);
	} else {
		float ic_mod = right_x + 10.f;
		float ic_func = right_x + right_w * 0.3f;
		float ic_addr = right_x + right_w * 0.7f;

		{
			ui_anim::table_col_t cols[] = {{"Module", right_w * 0.3f - 10.f}, {"Function", right_w * 0.4f}, {"Address", right_w * 0.3f}};
			ui_anim::render_table_header(dl, right_x, det_table_y, right_w, col_header_h, cols, 3, ar, ag, ab, alpha);
		}

		float det_list_y = det_table_y + col_header_h;
		float det_list_h = height - header_h - col_header_h;
		if (det_list_h <= 0.f) return;

		dl->PushClipRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), true);

		std::vector<pe_parser::import_entry_t> filtered;
		{
			std::lock_guard<std::mutex> lk(g_ui.modules_mutex);
			for (auto& imp : g_ui.imports) {
				if (detail::match_filter(imp.function_name, g_ui.filter_buf))
					filtered.push_back(imp);
			}
		}

		float det_content_h = static_cast<float>(filtered.size()) * row_h;
		float det_max_scroll = det_content_h - det_list_h;
		if (det_max_scroll < 0.f) det_max_scroll = 0.f;

		if (ImGui::IsMouseHoveringRect(ImVec2(right_x, det_list_y), ImVec2(right_x + right_w, det_list_y + det_list_h), false))
			ui_anim::handle_scroll_input(g_ui.detail_target_scroll_y, 0.f, det_max_scroll, row_h);
		ui_anim::clamp_scroll(g_ui.detail_target_scroll_y, 0.f, det_max_scroll);
		ui_anim::smooth_scroll(g_ui.detail_scroll_y, g_ui.detail_target_scroll_y, 15.f, dt);

		int det_first = static_cast<int>(g_ui.detail_scroll_y / row_h);
		if (det_first < 0) det_first = 0;
		int det_vis = static_cast<int>(det_list_h / row_h) + 2;

		for (int vi = 0; vi < det_vis; ++vi) {
			int idx = det_first + vi;
			if (idx >= static_cast<int>(filtered.size())) break;

			auto& imp = filtered[idx];
			float ry = det_list_y + idx * row_h - g_ui.detail_scroll_y;
			if (ry + row_h < det_list_y || ry > det_list_y + det_list_h) continue;

			bool clicked = ui_anim::row_hover_select(dl, right_x, ry, right_w - 12.f, row_h,
													  idx, g_ui.selected_detail, alpha, ar, ag, ab);

			dl->AddText(ImVec2(ic_mod, ry + 2.f),
						_ta(_t.text_secondary), imp.module_name.c_str());
			dl->AddText(ImVec2(ic_func, ry + 2.f),
						_ta(_t.text_primary), imp.function_name.c_str());

			char addr_buf[24];
			snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(imp.bound_address));
			dl->AddText(ImVec2(ic_addr, ry + 2.f),
						_ta(_t.text_secondary), addr_buf);

			if (clicked && ui_anim::row_double_click(idx, g_ui.selected_detail))
				g_ui.navigate_to = imp.bound_address;
		}

		dl->PopClipRect();
		ui_anim::render_custom_scrollbar(dl, right_x + right_w - sb_w - 2.f, det_list_y, sb_w, det_list_h,
										 g_ui.detail_scroll_y, det_content_h, det_list_h, alpha,
										 g_ui.detail_scrollbar_dragging, g_ui.detail_scrollbar_drag_offset);
	}

	if (g_ui.loading.load()) {
		float spinner_x = right_x + right_w * 0.5f;
		float spinner_y = pos_y + height * 0.5f;
		ui_anim::render_spinner(dl, spinner_x, spinner_y, 12.f, 2.f,
								IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
										 static_cast<int>(ab * 255), static_cast<int>(200 * alpha)),
								static_cast<float>(ImGui::GetTime()));
	}
}

}
