#include "memory_scanner_view.hpp"
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "ui_anim.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cinttypes>

namespace memory_scanner_view {


static bool row_hover(ImDrawList* dl, float x0, float y0, float x1, float y1,
					  float alpha, bool selected, float ar, float ag, float ab) {
	bool hov = ImGui::IsMouseHoveringRect(ImVec2(x0, y0), ImVec2(x1, y1), false);
	if (selected) {
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(30*alpha)), 3.f);
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + 3.f, y1),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(200*alpha)));
		for (int gi = 1; gi <= 3; ++gi) {
			float ga = (0.08f - static_cast<float>(gi) * 0.02f) * alpha;
			dl->AddRectFilled(ImVec2(x0, y0 - static_cast<float>(gi)),
				ImVec2(x1, y1 + static_cast<float>(gi)),
				IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
						 static_cast<int>(ab*255), static_cast<int>(ga * 255.f)), 2.f);
		}
	} else if (hov) {
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1),
			IM_COL32(255, 255, 255, static_cast<int>(10*alpha)), 3.f);
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + 2.f, y1),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(80*alpha)));
	}
	return hov;
}


static void render_toolbar(ImDrawList* dl, float ox, float oy, float w, float a,
						   float ar, float ag, float ab) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;

	ImU32 text_col  = IM_COL32(210, 215, 225, static_cast<int>(220*a));
	ImU32 dim_col   = IM_COL32(140, 145, 155, static_cast<int>(160*a));
	ImU32 ac_col    = IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
								static_cast<int>(ab*255), static_cast<int>(220*a));

	ui_anim::render_toolbar(dl, ox, oy, w, 34.f, a, ar, ag, ab);
	dl->AddLine(ImVec2(ox, oy + 34.f), ImVec2(ox + w, oy + 34.f),
		IM_COL32(60, 65, 75, static_cast<int>(80*a)));

	float pad = 8.f;
	float cy = oy + pad;
	float cx = ox + pad;


	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(90.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(180*a)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_col);
	ImGui::PushStyleColor(ImGuiCol_PopupBg, IM_COL32(25, 27, 35, static_cast<int>(240*a)));
	if (ImGui::BeginCombo("##vtype", memory_scanner::value_type_name(sc.config.value_type))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
			auto vt = static_cast<memory_scanner::value_type_t>(i);
			bool sel = (sc.config.value_type == vt);
			if (ImGui::Selectable(memory_scanner::value_type_name(vt), sel))
				sc.config.value_type = vt;
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleColor(3);
	ImGui::PopItemWidth();
	cx += 100.f;


	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(180*a)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_col);
	ImGui::PushStyleColor(ImGuiCol_PopupBg, IM_COL32(25, 27, 35, static_cast<int>(240*a)));
	if (ImGui::BeginCombo("##smode", memory_scanner::scan_mode_name(sc.config.scan_mode))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::scan_mode_t::COUNT); ++i) {
			auto sm = static_cast<memory_scanner::scan_mode_t>(i);
			bool sel = (sc.config.scan_mode == sm);
			if (ImGui::Selectable(memory_scanner::scan_mode_name(sm), sel))
				sc.config.scan_mode = sm;
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleColor(3);
	ImGui::PopItemWidth();
	cx += 130.f;


	bool needs_value = (sc.config.scan_mode != memory_scanner::scan_mode_t::changed &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::unchanged &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::increased &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::decreased &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::unknown_initial);

	if (needs_value) {
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		ImGui::PushItemWidth(140.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(180*a)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_col);
		ImGui::InputText("##val", ui.value_buf, sizeof(ui.value_buf));
		ImGui::PopStyleColor(2);
		ImGui::PopItemWidth();
		cx += 150.f;
	}

	if (sc.config.scan_mode == memory_scanner::scan_mode_t::value_between) {
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		dl->AddText(ImVec2(cx, cy + 2.f), dim_col, "to");
		cx += 22.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		ImGui::PushItemWidth(100.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(180*a)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_col);
		ImGui::InputText("##val2", ui.value_buf2, sizeof(ui.value_buf2));
		ImGui::PopStyleColor(2);
		ImGui::PopItemWidth();
		cx += 110.f;
	}


	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(180*a)));
	ImGui::PushStyleColor(ImGuiCol_CheckMark, ac_col);
	ImGui::Checkbox("Hex##shex", &sc.config.hex_input);
	ImGui::PopStyleColor(2);
	cx += 50.f;


	static float scan_btn_hover[4] = {};
	int scan_btn_idx = 0;
	float sdt = ImGui::GetIO().DeltaTime;
	auto scan_btn = [&](const char* label, bool enabled) -> bool {
		float bw = ui_anim::toolbar_button_width(label);
		int idx = scan_btn_idx++;
		if (idx >= 4) idx = 3;
		bool clicked = ui_anim::render_toolbar_button(dl, label, cx, cy,
			ar, ag, ab, a, scan_btn_hover[idx], sdt, false, !enabled);
		cx += bw + 6.f;
		return clicked;
	};

	bool scanning = sc.scanning.load();
	bool attached = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;

	if (!sc.has_initial_scan) {
		if (scan_btn("First Scan", attached && !scanning)) {
			sc.config.value_text = ui.value_buf;
			sc.config.value_text2 = ui.value_buf2;
			memory_scanner::first_scan(sc.config);
		}
	} else {
		if (scan_btn("Next Scan", !scanning)) {
			memory_scanner::next_scan(sc.config.scan_mode, std::string(ui.value_buf), std::string(ui.value_buf2));
		}
	}

	if (scan_btn("Undo", sc.has_initial_scan && !scanning))
		memory_scanner::undo_scan();

	if (scan_btn("Reset", !scanning))
		memory_scanner::reset_scan();


	if (scanning) {
		float prog = sc.scan_progress.load();
		float ring_r = 10.f;
		float ring_cx = cx + ring_r + 2.f;
		float ring_cy = cy + 11.f;
		ui_anim::render_progress_ring(dl, ring_cx, ring_cy, ring_r, 2.5f, prog,
			IM_COL32(30, 32, 40, static_cast<int>(120*a)), ac_col);
		char pct_buf[8];
		snprintf(pct_buf, sizeof(pct_buf), "%d%%", static_cast<int>(prog * 100.f));
		ImVec2 pct_sz = ImGui::CalcTextSize(pct_buf);
		dl->AddText(ImVec2(ring_cx - pct_sz.x * 0.5f, ring_cy - pct_sz.y * 0.5f),
			text_col, pct_buf);
		cx += ring_r * 2.f + 8.f;
		ui_anim::render_spinner(dl, cx + 8.f, cy + 11.f, 7.f, 2.f,
			ac_col, static_cast<float>(ImGui::GetTime()));
		cx += 24.f;
	}


	{
		char count_buf[64];
		snprintf(count_buf, sizeof(count_buf), "%zu found", sc.total_found);
		ImVec2 cts = ImGui::CalcTextSize(count_buf);
		dl->AddText(ImVec2(ox + w - pad - cts.x, cy + 2.f), dim_col, count_buf);
	}
}


static void render_results(ImDrawList* dl, float ox, float oy, float w, float h,
						   float a, float ar, float ag, float ab) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;

	ImU32 text_col  = IM_COL32(210, 215, 225, static_cast<int>(210*a));
	ImU32 dim_col   = IM_COL32(140, 145, 155, static_cast<int>(150*a));
	ImU32 addr_col  = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 val_col   = IM_COL32(180, 220, 160, static_cast<int>(220*a));
	ImU32 prev_col  = IM_COL32(180, 160, 130, static_cast<int>(180*a));

	float row_h = 20.f;
	float hdr_h = 22.f;

	float col_addr_w = 130.f;
	float col_val_w  = 120.f;
	float col_prev_w = 120.f;
	float col_mod_w  = w - col_addr_w - col_val_w - col_prev_w;
	if (col_mod_w < 40.f) col_mod_w = 40.f;

	ui_anim::table_col_t result_cols[] = {
		{"Address", col_addr_w}, {"Value", col_val_w},
		{"Previous", col_prev_w}, {"Module", col_mod_w}
	};
	ui_anim::render_table_header(dl, ox, oy, w, hdr_h, result_cols, 4, ar, ag, ab, a);

	{
		char count_buf[32];
		auto& sc2 = memory_scanner::g_state;
		snprintf(count_buf, sizeof(count_buf), "%zu", sc2.total_found);
		ImVec2 cs = ImGui::CalcTextSize(count_buf);
		float bx = ox + w - 10.f - cs.x - 12.f;
		ImU32 badge_bg = IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60),
								   static_cast<int>(ab*60), static_cast<int>(180*a));
		ImU32 badge_tc = IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
								   static_cast<int>(ab*255), static_cast<int>(220*a));
		ui_anim::render_badge(dl, count_buf, bx, oy + 3.f, badge_bg, badge_tc);
	}

	float body_y = oy + hdr_h;
	float body_h = h - hdr_h;
	int visible_rows = static_cast<int>(body_h / row_h);
	if (visible_rows < 1) visible_rows = 1;

	std::lock_guard<std::mutex> lk(sc.results_mutex);
	int total = static_cast<int>(sc.results.size());


	if (ImGui::IsMouseHoveringRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.result_target_scroll_y -= wheel * row_h * 3.f;
	}
	float max_scroll = std::max(0.f, static_cast<float>(total) * row_h - body_h);
	ui.result_target_scroll_y = std::clamp(ui.result_target_scroll_y, 0.f, max_scroll);
	float rdt = ImGui::GetIO().DeltaTime;
	ui.result_scroll_y += (ui.result_target_scroll_y - ui.result_scroll_y) * std::min(20.f * rdt, 1.f);
	if (std::abs(ui.result_target_scroll_y - ui.result_scroll_y) < 0.5f)
		ui.result_scroll_y = ui.result_target_scroll_y;

	int first_row = static_cast<int>(ui.result_scroll_y / row_h);
	int last_row = std::min(total, first_row + visible_rows + 2);

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	for (int i = first_row; i < last_row; ++i) {
		float ry = body_y + static_cast<float>(i) * row_h - ui.result_scroll_y;
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		bool sel = (ui.selected_result == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h), false);
		ui_anim::render_table_row(dl, ox, ry, w, row_h,
			{sel, hov, i, a, 1.f, ar, ag, ab});

		auto& r = sc.results[static_cast<size_t>(i)];

		char addr_buf[20];
		snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64, r.address);

		float rx = ox + 6.f;
		dl->AddText(ImVec2(rx, ry + 2.f), addr_col, addr_buf); rx += col_addr_w;

		std::string cur_str = memory_scanner::format_value(r.current_value, sc.config.value_type);
		ImU32 cur_color = val_col;
		if (!r.previous_value.empty() && !r.current_value.empty()) {
			int64_t cv = 0, pv = 0;
			std::memcpy(&cv, r.current_value.data(),
				std::min(r.current_value.size(), sizeof(int64_t)));
			std::memcpy(&pv, r.previous_value.data(),
				std::min(r.previous_value.size(), sizeof(int64_t)));
			cur_color = ui_anim::value_change_color(cv, pv, a);
		}
		dl->AddText(ImVec2(rx, ry + 2.f), cur_color, cur_str.c_str()); rx += col_val_w;

		if (!r.previous_value.empty()) {
			std::string prev_str = memory_scanner::format_value(r.previous_value, sc.config.value_type);
			dl->AddText(ImVec2(rx, ry + 2.f), prev_col, prev_str.c_str());
		}
		rx += col_prev_w;

		if (!r.module_name.empty()) {
			char mod_buf[128];
			snprintf(mod_buf, sizeof(mod_buf), "%s+0x%" PRIX64, r.module_name.c_str(), r.module_offset);
			dl->AddText(ImVec2(rx, ry + 2.f), dim_col, mod_buf);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.selected_result = i;

		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			memory_scanner::add_address(r.address, "", sc.config.value_type);
		}
	}

	ImGui::PopClipRect();


	if (total > visible_rows) {
		float sb_w = 6.f;
		float sb_x = ox + w - sb_w - 2.f;
		float content_total = static_cast<float>(total) * row_h;
		float ratio = body_h / content_total;
		float thumb_h = std::max(20.f, body_h * ratio);
		float track_h = body_h - thumb_h;
		float thumb_y = body_y + (max_scroll > 0.f ? (ui.result_scroll_y / max_scroll) * track_h : 0.f);
		dl->AddRectFilled(ImVec2(sb_x, body_y), ImVec2(sb_x + sb_w, body_y + body_h),
			IM_COL32(20, 22, 28, static_cast<int>(60*a)), 3.f);
		bool sb_hov = ImGui::IsMouseHoveringRect(ImVec2(sb_x, thumb_y), ImVec2(sb_x + sb_w, thumb_y + thumb_h));
		ImU32 sb_col = sb_hov
			? IM_COL32(static_cast<int>(ar*180), static_cast<int>(ag*180), static_cast<int>(ab*180), static_cast<int>(200*a))
			: IM_COL32(80, 85, 95, static_cast<int>(140*a));
		dl->AddRectFilled(ImVec2(sb_x, thumb_y), ImVec2(sb_x + sb_w, thumb_y + thumb_h),
			sb_col, 3.f);
	}

	if (total == 0) {
		float cx = ox + w * 0.5f;
		float cy = body_y + body_h * 0.5f;
		float t = static_cast<float>(ImGui::GetTime());
		float pulse = std::sin(t * 2.f) * 0.3f + 0.7f;
		ImU32 empty_col = IM_COL32(100, 100, 120, static_cast<int>(100 * a * pulse));
		const char* msg = sc.has_initial_scan ? "No results" : "Start a scan to find values";
		ImVec2 ts = ImGui::CalcTextSize(msg);
		dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f), empty_col, msg);
		if (!sc.has_initial_scan) {
			ui_anim::render_spinner(dl, cx, cy + 24.f, 6.f, 1.5f,
				IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
						 static_cast<int>(ab*255), static_cast<int>(60*a)), t);
		}
	}
}


static void render_address_list(ImDrawList* dl, float ox, float oy, float w, float h,
								float a, float ar, float ag, float ab) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;

	ImU32 text_col  = IM_COL32(210, 215, 225, static_cast<int>(210*a));
	ImU32 dim_col   = IM_COL32(140, 145, 155, static_cast<int>(150*a));
	ImU32 addr_col  = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 val_col   = IM_COL32(180, 220, 160, static_cast<int>(220*a));
	ImU32 freeze_col = IM_COL32(255, 140, 80, static_cast<int>(220*a));

	float row_h = 22.f;
	float hdr_h = 22.f;


	ui_anim::render_toolbar(dl, ox, oy, w, hdr_h, a, ar, ag, ab);
	dl->AddText(ImVec2(ox + 6.f, oy + 4.f), dim_col, "Address List");


	{
		const char* ar_label = ui.auto_refresh ? "Auto: ON" : "Auto: OFF";
		ImVec2 arts = ImGui::CalcTextSize(ar_label);
		float arx = ox + w - arts.x - 12.f;
		ImU32 arc = ui.auto_refresh
			? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					   static_cast<int>(ab*255), static_cast<int>(200*a))
			: dim_col;
		bool ar_hov = ImGui::IsMouseHoveringRect(ImVec2(arx, oy), ImVec2(arx + arts.x + 8.f, oy + hdr_h), false);
		dl->AddText(ImVec2(arx, oy + 3.f), ar_hov ? IM_COL32(255,255,255,static_cast<int>(230*a)) : arc, ar_label);
		if (ar_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.auto_refresh = !ui.auto_refresh;
	}

	float body_y = oy + hdr_h;
	float body_h = h - hdr_h;
	int visible_rows = static_cast<int>(body_h / row_h);
	if (visible_rows < 1) visible_rows = 1;

	int freeze_toggle_idx = -1;
	bool freeze_toggle_val = false;
	int delete_idx = -1;

	std::unique_lock<std::mutex> lk(sc.address_mutex);
	int total = static_cast<int>(sc.address_list.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.address_target_scroll_y -= wheel * row_h * 3.f;
	}
	float max_scroll = std::max(0.f, static_cast<float>(total) * row_h - body_h);
	ui.address_target_scroll_y = std::clamp(ui.address_target_scroll_y, 0.f, max_scroll);
	float adt = ImGui::GetIO().DeltaTime;
	ui.address_scroll_y += (ui.address_target_scroll_y - ui.address_scroll_y) * std::min(20.f * adt, 1.f);
	if (std::abs(ui.address_target_scroll_y - ui.address_scroll_y) < 0.5f)
		ui.address_scroll_y = ui.address_target_scroll_y;

	int first_row = static_cast<int>(ui.address_scroll_y / row_h);
	int last_row = std::min(total, first_row + visible_rows + 2);

	float col_freeze_w = 40.f;
	float col_desc_w   = 150.f;
	float col_addr_w   = 130.f;
	float col_type_w   = 80.f;
	float col_val_w    = w - col_freeze_w - col_desc_w - col_addr_w - col_type_w;
	if (col_val_w < 60.f) col_val_w = 60.f;

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	for (int i = first_row; i < last_row; ++i) {
		float ry = body_y + static_cast<float>(i) * row_h - ui.address_scroll_y;
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		bool sel = (ui.selected_address == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h), false);
		ui_anim::render_table_row(dl, ox, ry, w, row_h,
			{sel, hov, i, a, 1.f, ar, ag, ab});

		auto& e = sc.address_list[static_cast<size_t>(i)];
		float rx = ox + 6.f;


		{
			float cb_sz = 12.f;
			float cb_x = rx + (col_freeze_w - cb_sz) * 0.5f - 6.f;
			float cb_y = ry + (row_h - cb_sz) * 0.5f;
			dl->AddRect(ImVec2(cb_x, cb_y), ImVec2(cb_x + cb_sz, cb_y + cb_sz),
				e.frozen ? freeze_col : dim_col, 2.f);
			if (e.frozen) {
				dl->AddRectFilled(ImVec2(cb_x + 2, cb_y + 2), ImVec2(cb_x + cb_sz - 2, cb_y + cb_sz - 2),
					freeze_col, 1.f);
			}
			float dot_cx = cb_x + cb_sz + 7.f;
			float dot_cy = ry + row_h * 0.5f;
			if (e.frozen) {
				ui_anim::render_status_dot(dl, dot_cx, dot_cy, 3.f,
					IM_COL32(100, 180, 255, 255),
					static_cast<float>(ImGui::GetTime()) * 2.36f, true);
			} else {
				ui_anim::render_status_dot(dl, dot_cx, dot_cy, 3.f,
					IM_COL32(80, 80, 95, static_cast<int>(120*a)),
					0.f, false);
			}
			bool cb_hov = ImGui::IsMouseHoveringRect(ImVec2(cb_x - 2, cb_y - 2),
				ImVec2(cb_x + cb_sz + 2, cb_y + cb_sz + 2), false);
			if (cb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				freeze_toggle_idx = i;
				freeze_toggle_val = !e.frozen;
			}
		}
		rx += col_freeze_w;


		dl->AddText(ImVec2(rx, ry + 2.f), text_col,
			e.description.empty() ? "<no description>" : e.description.c_str());
		rx += col_desc_w;


		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, e.address);
		dl->AddText(ImVec2(rx, ry + 2.f), addr_col, abuf);
		rx += col_addr_w;


		dl->AddText(ImVec2(rx, ry + 2.f), dim_col,
			memory_scanner::value_type_name(e.value_type));
		rx += col_type_w;


		std::string val_str = memory_scanner::format_value(e.last_value, e.value_type);
		dl->AddText(ImVec2(rx, ry + 2.f), val_col, val_str.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.selected_address = i;


		if (sel && ImGui::IsKeyPressed(ImGuiKey_Delete, false)) {
			delete_idx = i;
			ui.selected_address = -1;
			break;
		}
	}

	ImGui::PopClipRect();

	if (total > visible_rows) {
		float sb_w = 6.f;
		float sb_x = ox + w - sb_w - 2.f;
		float content_total = static_cast<float>(total) * row_h;
		float ratio = body_h / content_total;
		float thumb_h = std::max(20.f, body_h * ratio);
		float track_h = body_h - thumb_h;
		float thumb_y = body_y + (max_scroll > 0.f ? (ui.address_scroll_y / max_scroll) * track_h : 0.f);
		dl->AddRectFilled(ImVec2(sb_x, body_y), ImVec2(sb_x + sb_w, body_y + body_h),
			IM_COL32(20, 22, 28, static_cast<int>(60*a)), 3.f);
		bool sb_hov = ImGui::IsMouseHoveringRect(ImVec2(sb_x, thumb_y), ImVec2(sb_x + sb_w, thumb_y + thumb_h));
		ImU32 sb_col = sb_hov
			? IM_COL32(static_cast<int>(ar*180), static_cast<int>(ag*180), static_cast<int>(ab*180), static_cast<int>(200*a))
			: IM_COL32(80, 85, 95, static_cast<int>(140*a));
		dl->AddRectFilled(ImVec2(sb_x, thumb_y), ImVec2(sb_x + sb_w, thumb_y + thumb_h),
			sb_col, 3.f);
	}

	if (total == 0) {
		float cx = ox + w * 0.5f;
		float cy = body_y + body_h * 0.5f - 8.f;
		float t = static_cast<float>(ImGui::GetTime());
		float pulse = std::sin(t * 1.8f) * 0.3f + 0.7f;
		dl->AddText(ImVec2(cx - 80.f, cy),
			IM_COL32(100, 100, 120, static_cast<int>(100*a*pulse)),
			"Double-click a result to add");
	}

	lk.unlock();

	if (freeze_toggle_idx >= 0)
		memory_scanner::freeze_address(static_cast<size_t>(freeze_toggle_idx), freeze_toggle_val);
	if (delete_idx >= 0)
		memory_scanner::remove_address(static_cast<size_t>(delete_idx));
}


void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b) {
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##scanner_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float a = alpha;


	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		IM_COL32(18, 20, 26, static_cast<int>(240*a)));


	auto& ui = g_ui;
	if (ui.auto_refresh) {
		ui.refresh_timer += ImGui::GetIO().DeltaTime;
		if (ui.refresh_timer >= ui.refresh_interval) {
			ui.refresh_timer = 0.f;
			memory_scanner::refresh_address_list();
		}
	}


	float toolbar_h = 34.f;
	float remaining = h - toolbar_h;
	float results_h = remaining * 0.6f;
	float address_h = remaining - results_h;

	render_toolbar(dl, ox, oy, w, a, accent_r, accent_g, accent_b);

	float results_y = oy + toolbar_h;
	render_results(dl, ox, results_y, w, results_h, a, accent_r, accent_g, accent_b);


	float split_y = results_y + results_h;
	float t = static_cast<float>(ImGui::GetTime());
	float glow = (std::sin(t * 1.5f) * 0.5f + 0.5f) * 0.3f + 0.5f;
	ImU32 split_col = IM_COL32(static_cast<int>(accent_r * 120 * glow),
		static_cast<int>(accent_g * 120 * glow),
		static_cast<int>(accent_b * 120 * glow),
		static_cast<int>(140 * a));
	dl->AddLine(ImVec2(ox + 8.f, split_y), ImVec2(ox + w - 8.f, split_y),
		split_col, 1.f);
	for (int gi = 1; gi <= 2; ++gi) {
		float ga = (0.06f - static_cast<float>(gi) * 0.02f) * a * glow;
		dl->AddRectFilled(ImVec2(ox + 8.f, split_y - static_cast<float>(gi)),
			ImVec2(ox + w - 8.f, split_y + static_cast<float>(gi) + 1.f),
			IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
					 static_cast<int>(accent_b * 255), static_cast<int>(ga * 255.f)));
	}

	render_address_list(dl, ox, split_y + 1.f, w, address_h - 1.f, a, accent_r, accent_g, accent_b);

	ImGui::EndChild();
}

}
