#pragma once

#include "decrypt_oracle.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace decrypt_oracle_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_row = -1;
	int   sort_column = -1;
	bool  sort_ascending = true;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	float anim_time = 0.f;
};

static local_state_t s_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImGui::BeginChild("##decrypt_oracle_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& oracle = decrypt_oracle::g_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float cx = wp.x;
	float cy = wp.y;

	st.anim_time += ImGui::GetIO().DeltaTime;
	float dt = ImGui::GetIO().DeltaTime;

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 bg        = _ta(_t.bg_base);
	const ImU32 text_col  = _ta(_t.text_primary);
	const ImU32 dim_col   = _ta(_t.text_dim);
	const ImU32 accent    = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg = _ta(_t.panel_header);
	const ImU32 row_even  = _ta(_t.panel_bg);
	const ImU32 row_odd   = _ta(ui_anim::lighten(_t.panel_bg, 8));
	const ImU32 row_hover = _ta(ui_anim::lighten(_t.panel_header, 14));
	const ImU32 sel_col   = _ta(ui_anim::lighten(_t.panel_header, 10));
	const ImU32 green_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 68.f;
	const float pad = 12.f;

	ui_anim::render_toolbar(dl, cx, cy, width, toolbar_h, accent_r, accent_g, accent_b, alpha);

	float tx = cx + pad;
	float ty = cy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(tx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(35, 37, 48, static_cast<int>(alpha * 220)));
	ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 65, 80, static_cast<int>(alpha * 120)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(210, 212, 220, static_cast<int>(alpha * 255)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

	ImGui::PushItemWidth(180.f);
	ImGui::InputTextWithHint("##do_addr", "Encrypted Region (hex)", oracle.address_input, sizeof(oracle.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(80.f);
	ImGui::InputTextWithHint("##do_size", "Size", oracle.size_input, sizeof(oracle.size_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();

	ImGui::PopStyleColor(3); ImGui::PopStyleVar(2);

	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140), static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180), static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 220)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100), static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, static_cast<int>(alpha * 255)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);

	bool scanning = oracle.scanning.load();

	if (!scanning) {
		if (ImGui::SmallButton("Scan & Decrypt")) {
			uint64_t addr = 0;
			uint64_t sz = 4096;
			if (oracle.address_input[0])
				addr = std::strtoull(oracle.address_input, nullptr, 16);
			if (oracle.size_input[0])
				sz = std::strtoull(oracle.size_input, nullptr, 0);
			if (addr != 0) {
				decrypt_oracle::scan_and_decrypt(addr, sz);
			}
		}
	} else {
		if (ImGui::SmallButton("Cancel")) {
			oracle.cancel.store(true);
		}
	}

	ImGui::PopStyleColor(4); ImGui::PopStyleVar();

	ty += 26.f;

	if (scanning) {
		float prog = oracle.progress.load();
		int done = oracle.processed_xrefs.load();
		int total = oracle.total_xrefs.load();

		float bar_x = cx + pad;
		float bar_w = width - pad * 2.f;
		float bar_h = 6.f;
		float bar_y = ty + 4.f;

		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w, bar_y + bar_h),
		                   IM_COL32(60, 60, 60, static_cast<int>(alpha * 255)), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w * prog, bar_y + bar_h),
		                   accent, 3.f);

		char prog_text[64];
		std::snprintf(prog_text, sizeof(prog_text), "%d / %d xrefs (%.0f%%)", done, total, prog * 100.f);
		ImVec2 pts = ImGui::CalcTextSize(prog_text);
		dl->AddText(ImVec2(bar_x + bar_w * 0.5f - pts.x * 0.5f, bar_y + bar_h + 2.f), dim_col, prog_text);
	} else {
		std::string status;
		{
			std::lock_guard<std::mutex> lk(oracle.mutex);
			status = oracle.status_text;
		}
		if (!status.empty()) {
			dl->AddText(ImVec2(cx + pad, ty + 2.f), dim_col, status.c_str());
		}
	}

	float table_top = cy + toolbar_h + 4.f;
	float table_h = height - toolbar_h - 4.f;

	const float col_func_w = 130.f;
	const float col_offset_w = 100.f;
	const float col_conf_w = 70.f;
	const float col_len_w = 50.f;
	const float col_string_w = width - col_func_w - col_offset_w - col_conf_w - col_len_w - pad * 2.f;

	float hx = cx + pad;
	float hy = table_top;
	const float row_h = 22.f;

	{
		ui_anim::table_col_t hdr_cols[] = {
			{"Source Func", col_func_w}, {"Enc Offset", col_offset_w},
			{"Decrypted String", col_string_w}, {"Conf", col_conf_w}, {"Len", col_len_w}
		};
		ui_anim::render_table_header(dl, hx, hy, width - pad * 2.f, row_h, hdr_cols, 5, accent_r, accent_g, accent_b, alpha);
	}

	float conf_x = hx + col_func_w + col_offset_w + col_string_w;
	hy += row_h;

	std::vector<decrypt_oracle::decrypted_string_t> results_copy;
	{
		std::lock_guard<std::mutex> lk(oracle.mutex);
		results_copy = oracle.results;
	}

	int visible_rows = static_cast<int>((table_h - row_h) / row_h);
	int total_rows = static_cast<int>(results_copy.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(cx, table_top), ImVec2(cx + width, cy + height))) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			st.target_scroll_y -= wheel * row_h * 3.f;
		}
	}

	float max_scroll = (std::max)(0.f, static_cast<float>(total_rows) * row_h - (table_h - row_h));
	ui_anim::clamp_scroll(st.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f, dt);
	ui_anim::clamp_scroll(st.scroll_y, 0.f, max_scroll);

	int start_row = static_cast<int>(st.scroll_y / row_h);
	if (start_row < 0) start_row = 0;

	for (int i = start_row; i < total_rows && i < start_row + visible_rows + 1; ++i) {
		float ry = hy + static_cast<float>(i - start_row) * row_h;
		if (ry > cy + height) break;

		auto& r = results_copy[static_cast<size_t>(i)];

		bool hovered = ImGui::IsMouseHoveringRect(
			ImVec2(hx, ry), ImVec2(hx + width - pad * 2.f, ry + row_h));
		bool selected = (st.selected_row == i);

		float row_a = ui_anim::render_row_entrance(i, 0.04f, alpha);
		ui_anim::table_row_style_t rs{};
		rs.selected = selected;
		rs.hovered = hovered;
		rs.index = i;
		rs.alpha = alpha;
		rs.entrance = row_a / alpha;
		rs.ar = accent_r; rs.ag = accent_g; rs.ab = accent_b;
		ui_anim::render_table_row(dl, hx, ry, width - pad * 2.f, row_h, rs);

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_row = i;
		}

		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
		}

		char func_buf[24];
		std::snprintf(func_buf, sizeof(func_buf), "0x%llX",
		              static_cast<unsigned long long>(r.source_function));
		dl->AddText(ImVec2(hx + 4.f, ry + 3.f), text_col, func_buf);

		char off_buf[24];
		std::snprintf(off_buf, sizeof(off_buf), "0x%llX",
		              static_cast<unsigned long long>(r.encrypted_offset));
		dl->AddText(ImVec2(hx + col_func_w + 4.f, ry + 3.f), dim_col, off_buf);

		float str_max_w = col_string_w - 8.f;
		std::string display_str = r.decrypted;
		if (display_str.size() > 80) {
			display_str = display_str.substr(0, 77) + "...";
		}
		dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
		            ImVec2(hx + col_func_w + col_offset_w + 4.f, ry + 3.f),
		            green_col, display_str.c_str(), display_str.c_str() + display_str.size(),
		            str_max_w);

		char conf_buf[16];
		std::snprintf(conf_buf, sizeof(conf_buf), "%.0f%%", r.confidence * 100.f);
		ImU32 conf_color = r.confidence > 0.9f ? green_col : (r.confidence > 0.7f ? text_col : dim_col);
		dl->AddText(ImVec2(conf_x + 4.f, ry + 3.f), conf_color, conf_buf);

		char len_buf[16];
		std::snprintf(len_buf, sizeof(len_buf), "%d", r.length);
		dl->AddText(ImVec2(conf_x + col_conf_w + 4.f, ry + 3.f), dim_col, len_buf);
	}

	if (total_rows == 0 && !scanning) {
		ui_anim::render_empty_state(dl, cx, table_top, width, table_h,
		    "Enter an encrypted region address and click Scan & Decrypt",
		    accent_r, accent_g, accent_b, alpha, static_cast<float>(ImGui::GetTime()));
	}

	ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, table_top + row_h, 6.f, table_h - row_h,
		st.scroll_y, static_cast<float>(total_rows) * row_h, table_h - row_h,
		alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);

	ImGui::EndChild();
}

}
