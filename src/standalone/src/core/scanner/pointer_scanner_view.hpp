#pragma once

#include "imgui/imgui.h"
#include "pointer_scanner.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

extern DisasmState g_disasm;

namespace pointer_scanner_view {

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;
	auto& st = pointer_scanner::g_state;

	static float row_anim_time = 0.f;
	row_anim_time += ImGui::GetIO().DeltaTime;

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};

	ImU32 bg = _ta(_t.bg_base);
	ImU32 panel_bg = _ta(_t.panel_bg);
	ImU32 hdr_bg = _ta(_t.panel_header);
	ImU32 text_main = _ta(_t.text_primary);
	ImU32 text_dim = _ta(_t.text_dim);
	ImU32 text_val = IM_COL32(100, 200, 150, static_cast<int>(220 * a));
	ImU32 text_inv = IM_COL32(220, 80, 80, static_cast<int>(220 * a));
	ImU32 accent_col = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(220 * a));
	ImU32 accent_dim = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(80 * a));
	ImU32 row_hover_col = _ta(_t.panel_header);
	ImU32 row_sel = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(30 * a));
	ImU32 sep_col = _ta(ui_anim::lighten(_t.panel_bg, 12));

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height), bg);

	float toolbar_h = 36.f;
	float config_panel_w = 260.f;
	float detail_panel_h = 160.f;
	float row_h = 22.f;

	ui_anim::render_toolbar(dl, x0, y0, width, toolbar_h, accent_r, accent_g, accent_b, a);

	ImGui::SetCursorPos(ImVec2(pos_x + 8.f, pos_y + 6.f));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::TextUnformatted("Pointer Chain Scanner");
	ImGui::PopStyleColor();

	{
		char status_buf[128] = {};
		std::lock_guard<std::mutex> lk(st.map_mutex);
		snprintf(status_buf, sizeof(status_buf), "Reverse Map: %zu entries | Results: %zu",
		         st.map_entry_count, st.results.size());
		float tw = ImGui::CalcTextSize(status_buf).x;
		ImGui::SetCursorPos(ImVec2(pos_x + width - tw - 12.f, pos_y + 6.f));
		ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
		ImGui::TextUnformatted(status_buf);
		ImGui::PopStyleColor();
	}

	float cfg_x = x0;
	float cfg_y = y0 + toolbar_h;
	float cfg_h = height - toolbar_h;

	ui_anim::render_panel_card(dl, cfg_x, cfg_y, config_panel_w, cfg_h, accent_r, accent_g, accent_b, a, 0.f, false);
	dl->AddLine(ImVec2(cfg_x + config_panel_w, cfg_y), ImVec2(cfg_x + config_panel_w, cfg_y + cfg_h), sep_col);

	ImGui::SetCursorPos(ImVec2(pos_x + 10.f, pos_y + toolbar_h + 10.f));
	ImGui::BeginChild("##ptr_cfg", ImVec2(config_panel_w - 20.f, cfg_h - 20.f), false,
	                   ImGuiWindowFlags_NoScrollbar);

	ImGui::PushStyleColor(ImGuiCol_Text, accent_col);
	ImGui::TextUnformatted("Configuration");
	ImGui::PopStyleColor();
	ImGui::Spacing();

	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
	ImGui::PushItemWidth(-1.f);

	ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
	ImGui::TextUnformatted("Target Address");
	ImGui::PopStyleColor();
	ImGui::InputTextWithHint("##ptr_addr", "e.g. 7FF60012A440", st.addr_buf, sizeof(st.addr_buf),
	                          ImGuiInputTextFlags_CharsHexadecimal);

	ImGui::Spacing();
	ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
	ImGui::TextUnformatted("Max Depth");
	ImGui::PopStyleColor();
	ImGui::SliderInt("##ptr_depth", &st.config.max_depth, 1, 7, "%d");

	ImGui::Spacing();
	ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
	ImGui::TextUnformatted("Max Offset");
	ImGui::PopStyleColor();
	int max_off = static_cast<int>(st.config.max_offset);
	ImGui::SliderInt("##ptr_maxoff", &max_off, 64, 16384, "%d");
	st.config.max_offset = max_off;

	ImGui::Spacing();
	ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
	ImGui::TextUnformatted("Struct Size");
	ImGui::PopStyleColor();
	int struct_sz = static_cast<int>(st.config.struct_size);
	ImGui::SliderInt("##ptr_struct", &struct_sz, 64, 16384, "%d");
	st.config.struct_size = struct_sz;

	ImGui::Spacing();
	ImGui::PushStyleColor(ImGuiCol_CheckMark, accent_col);
	ImGui::Checkbox("Negative Offsets##ptr", &st.config.negative_offsets);
	ImGui::Checkbox("Static Bases Only##ptr", &st.config.only_static_bases);
	ImGui::PopStyleColor();

	ImGui::PopItemWidth();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));

	bool building = st.map_building.load();
	bool scanning = st.scanning.load();

	if (building) {
		float prog = st.map_progress.load();
		ImGui::PushStyleColor(ImGuiCol_PlotHistogram, accent_col);
		ImGui::ProgressBar(prog, ImVec2(-1.f, 24.f), "Building reverse map...");
		ImGui::PopStyleColor();

		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(180, 60, 60, static_cast<int>(200 * a)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(220, 80, 80, static_cast<int>(200 * a)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_main);
		if (ImGui::Button("Cancel##map", ImVec2(-1.f, 0.f)))
			pointer_scanner::cancel_all();
		ImGui::PopStyleColor(3);
	} else {
		ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_main);
		if (ImGui::Button("Build Pointer Map##ptr", ImVec2(-1.f, 0.f)))
			pointer_scanner::build_reverse_map();
		ImGui::PopStyleColor(3);
	}

	ImGui::Spacing();

	if (scanning) {
		float prog = st.scan_progress.load();
		ImGui::PushStyleColor(ImGuiCol_PlotHistogram, accent_col);
		ImGui::ProgressBar(prog, ImVec2(-1.f, 24.f), "Scanning...");
		ImGui::PopStyleColor();

		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(180, 60, 60, static_cast<int>(200 * a)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(220, 80, 80, static_cast<int>(200 * a)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_main);
		if (ImGui::Button("Cancel##scan", ImVec2(-1.f, 0.f)))
			st.scan_cancel.store(true);
		ImGui::PopStyleColor(3);
	} else {
		bool can_scan = !building && st.map_entry_count > 0;
		ImGui::PushStyleColor(ImGuiCol_Button, can_scan
			? _ta(ui_anim::darken(_t.panel_header, 5))
			: _ta(_t.panel_bg));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, can_scan
			? _ta(ui_anim::lighten(_t.panel_header, 14))
			: _ta(_t.panel_bg));
		ImGui::PushStyleColor(ImGuiCol_Text, can_scan ? text_main : text_dim);
		if (ImGui::Button("Scan Chains##ptr", ImVec2(-1.f, 0.f)) && can_scan) {
			st.config.target_address = strtoull(st.addr_buf, nullptr, 16);
			pointer_scanner::start_scan();
		}
		ImGui::PopStyleColor(3);
	}

	ImGui::PopStyleVar(2);

	ImGui::Spacing();
	ImGui::Separator();
	ImGui::Spacing();

	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
	ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);

	if (ImGui::Button("Validate All##ptr", ImVec2(-1.f, 0.f)))
		pointer_scanner::validate_all_results();

	ImGui::Spacing();
	if (ImGui::Button("Clear Results##ptr", ImVec2(-1.f, 0.f)))
		pointer_scanner::clear_results();

	if (ImGui::Button("Clear Map##ptr", ImVec2(-1.f, 0.f)))
		pointer_scanner::clear_map();

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);

	ImGui::EndChild();

	float table_x = cfg_x + config_panel_w + 1.f;
	float table_y = cfg_y;
	float table_w = width - config_panel_w - 1.f;
	float table_h = cfg_h - detail_panel_h;

	float col_depth_w = 50.f;
	float col_module_w = 140.f;
	float col_base_w = 120.f;
	float col_status_w = 60.f;
	float col_chain_w = table_w - col_depth_w - col_module_w - col_base_w - col_status_w - 20.f;
	if (col_chain_w < 100.f) col_chain_w = 100.f;

	float hdr_h = 24.f;
	{
		ui_anim::table_col_t hdr_cols[] = {
			{"Depth", col_depth_w}, {"Module", col_module_w}, {"Base+Offset", col_base_w},
			{"Chain", col_chain_w}, {"Valid", col_status_w}
		};
		ui_anim::render_table_header(dl, table_x, table_y, table_w, hdr_h, hdr_cols, 5, accent_r, accent_g, accent_b, a);
	}

	float body_y = table_y + hdr_h;
	float body_h = table_h - hdr_h;

	ImGui::SetCursorPos(ImVec2(pos_x + config_panel_w + 1.f, pos_y + toolbar_h + hdr_h));

	ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
	ImGui::BeginChild("##ptr_results", ImVec2(table_w, body_h), false,
	                   ImGuiWindowFlags_NoScrollbar);

	std::lock_guard<std::mutex> lk(st.results_mutex);
	int visible_count = static_cast<int>(body_h / row_h);
	int total = static_cast<int>(st.results.size());

	float wheel = ImGui::GetIO().MouseWheel;
	ImVec2 mp = ImGui::GetMousePos();
	if (mp.x >= table_x && mp.x <= table_x + table_w && mp.y >= body_y && mp.y <= body_y + body_h) {
		st.target_scroll_y -= wheel * row_h * 3.f;
		if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
		float max_scroll = (total > visible_count) ? (total - visible_count) * row_h : 0.f;
		if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	}
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, ImGui::GetIO().DeltaTime);

	int start_row = static_cast<int>(st.scroll_y / row_h);
	if (start_row < 0) start_row = 0;

	for (int i = start_row; i < total && i < start_row + visible_count + 2; ++i) {
		auto& chain = st.results[i];
		float ry = body_y + (i - start_row) * row_h - (st.scroll_y - start_row * row_h);

		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		bool hovered = (mp.x >= table_x && mp.x <= table_x + table_w &&
		                mp.y >= ry && mp.y < ry + row_h);
		bool selected = (i == st.selected_result);

		float row_a = ui_anim::render_row_entrance(i, row_anim_time, 0.012f);
		ui_anim::table_row_style_t rs{};
		rs.selected = selected;
		rs.hovered = hovered;
		rs.index = i;
		rs.alpha = a;
		rs.entrance = row_a;
		rs.ar = accent_r; rs.ag = accent_g; rs.ab = accent_b;
		ui_anim::render_table_row(dl, table_x, ry, table_w, row_h, rs);

		if (hovered && ImGui::IsMouseClicked(0))
			st.selected_result = i;

		float rx = table_x + 6.f;
		char buf[32];

		snprintf(buf, sizeof(buf), "%d", chain.depth);
		dl->AddText(ImVec2(rx, ry + 3.f), text_main, buf);
		rx += col_depth_w;

		dl->AddText(ImVec2(rx, ry + 3.f),
		            chain.is_static ? accent_col : text_dim,
		            chain.module_name.empty() ? "dynamic" : chain.module_name.c_str());
		rx += col_module_w;

		snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(chain.base_offset));
		dl->AddText(ImVec2(rx, ry + 3.f), text_main, buf);
		rx += col_base_w;

		std::string chain_str;
		for (size_t j = 0; j < chain.offsets.size(); ++j) {
			if (j > 0) chain_str += " -> ";
			char ob[20];
			if (chain.offsets[j] >= 0)
				snprintf(ob, sizeof(ob), "+0x%llX", static_cast<unsigned long long>(chain.offsets[j]));
			else
				snprintf(ob, sizeof(ob), "-0x%llX", static_cast<unsigned long long>(-chain.offsets[j]));
			chain_str += ob;
		}

		float avail = col_chain_w - 4.f;
		ImVec2 chain_sz = ImGui::CalcTextSize(chain_str.c_str());
		if (chain_sz.x > avail) {
			size_t trunc = chain_str.size();
			while (trunc > 3) {
				--trunc;
				std::string test = chain_str.substr(0, trunc) + "...";
				if (ImGui::CalcTextSize(test.c_str()).x <= avail) {
					chain_str = test;
					break;
				}
			}
		}
		dl->AddText(ImVec2(rx, ry + 3.f), text_dim, chain_str.c_str());
		rx += col_chain_w;

		dl->AddText(ImVec2(rx, ry + 3.f),
		            chain.validated ? text_val : text_inv,
		            chain.validated ? "\xe2\x9c\x93" : "?");
		if (chain.validated) {
			ImVec2 badge_min(rx - 2.f, ry + 2.f);
			ImVec2 badge_max(rx + 14.f, ry + row_h - 2.f);
			dl->AddRectFilled(badge_min, badge_max, IM_COL32(
				(accent_col >> IM_COL32_R_SHIFT) & 0xFF,
				(accent_col >> IM_COL32_G_SHIFT) & 0xFF,
				(accent_col >> IM_COL32_B_SHIFT) & 0xFF,
				static_cast<int>(40 * row_a)), 4.f);
		}

		if (i < total - 1)
			dl->AddLine(ImVec2(table_x, ry + row_h), ImVec2(table_x + table_w, ry + row_h),
			            _ta(ui_anim::lighten(_t.panel_bg, 12)));
	}

	ImGui::EndChild();
	ImGui::PopStyleColor();

	float det_x = table_x;
	float det_y = cfg_y + table_h;
	float det_w = table_w;

	dl->AddLine(ImVec2(det_x, det_y), ImVec2(det_x + det_w, det_y), sep_col);
		ui_anim::render_panel_card(dl, det_x, det_y + 1.f, det_w, detail_panel_h - 1.f, accent_r, accent_g, accent_b, a, 0.f, true);
	if (st.selected_result >= 0 && st.selected_result < total) {
		auto& chain = st.results[st.selected_result];

		ImGui::SetCursorPos(ImVec2(pos_x + config_panel_w + 10.f, pos_y + toolbar_h + table_h + 6.f));
		ImGui::BeginChild("##ptr_detail", ImVec2(det_w - 20.f, detail_panel_h - 12.f), false);

		ImGui::PushStyleColor(ImGuiCol_Text, accent_col);
		ImGui::TextUnformatted("Chain Detail");
		ImGui::PopStyleColor();
		ImGui::SameLine(det_w - 300.f);

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 3.f));
		ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
		ImGui::PushStyleColor(ImGuiCol_Text, text_main);

		if (ImGui::Button("Copy Chain##ptr")) {
			std::string cs = pointer_scanner::chain_to_string(chain);
			ImGui::SetClipboardText(cs.c_str());
		}
		ImGui::SameLine();
		if (ImGui::Button("Copy C++##ptr")) {
			std::string cs = pointer_scanner::export_chain_cpp(chain);
			ImGui::SetClipboardText(cs.c_str());
		}
		ImGui::SameLine();
		if (ImGui::Button("Goto Base##ptr")) {
			uint64_t addr = 0;
			if (chain.is_static && chain.module_index >= 0 &&
			    chain.module_index < static_cast<int>(st.cached_modules.size()))
				addr = st.cached_modules[chain.module_index].base + chain.base_offset;
			else
				addr = chain.base_offset;
			if (addr != 0) {
				g_disasm.goto_address = addr;
				g_disasm.has_new_goto = true;
			}
		}

		ImGui::PopStyleColor(3);
		ImGui::PopStyleVar(2);

		ImGui::Spacing();

		ImGui::PushStyleColor(ImGuiCol_Text, text_main);
		std::string full_chain = pointer_scanner::chain_to_string(chain);
		ImGui::TextWrapped("%s", full_chain.c_str());
		ImGui::PopStyleColor();

		ImGui::Spacing();

		ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
		char info_buf[128];
		snprintf(info_buf, sizeof(info_buf), "Depth: %d | Static: %s | Validated: %s | Module: %s",
		         chain.depth, chain.is_static ? "Yes" : "No",
		         chain.validated ? "Yes" : "Not checked",
		         chain.module_name.empty() ? "N/A" : chain.module_name.c_str());
		ImGui::TextUnformatted(info_buf);
		ImGui::PopStyleColor();

		float diagram_y_start = ImGui::GetCursorPosY();
		float node_w = 90.f;
		float node_h = 20.f;
		float gap = 30.f;
		float dx = 10.f;

		ImVec2 cwp = ImGui::GetWindowPos();
		ImDrawList* ddl = ImGui::GetWindowDrawList();

		if (chain.is_static) {
			char lbl[64];
			snprintf(lbl, sizeof(lbl), "%s+0x%X",
			         chain.module_name.c_str(),
			         static_cast<unsigned>(chain.base_offset));
			ImVec2 ts = ImGui::CalcTextSize(lbl);
			float nw = ts.x + 12.f;
			ddl->AddRectFilled(ImVec2(cwp.x + dx, cwp.y + diagram_y_start),
			                   ImVec2(cwp.x + dx + nw, cwp.y + diagram_y_start + node_h),
			                   accent_dim, 4.f);
			ddl->AddText(ImVec2(cwp.x + dx + 6.f, cwp.y + diagram_y_start + 2.f), accent_col, lbl);
			dx += nw;
		}

		for (size_t j = 0; j < chain.offsets.size(); ++j) {
			float lx0 = cwp.x + dx;
			float ly0 = cwp.y + diagram_y_start + node_h / 2.f;
			float lx1 = cwp.x + dx + gap;
			float cp = gap * 0.4f;
			ddl->AddBezierCubic(
				ImVec2(lx0, ly0), ImVec2(lx0 + cp, ly0 - 6.f),
				ImVec2(lx1 - cp, ly0 + 6.f), ImVec2(lx1, ly0),
				accent_dim, 1.5f);
			ddl->AddTriangleFilled(
				ImVec2(lx1 - 6.f, ly0 - 4.f),
				ImVec2(lx1 - 6.f, ly0 + 4.f),
				ImVec2(lx1, ly0),
				accent_col);
			dx += gap;

			char ob[24];
			if (chain.offsets[j] >= 0)
				snprintf(ob, sizeof(ob), "+0x%llX", static_cast<unsigned long long>(chain.offsets[j]));
			else
				snprintf(ob, sizeof(ob), "-0x%llX", static_cast<unsigned long long>(-chain.offsets[j]));
			ImVec2 ots = ImGui::CalcTextSize(ob);
			float ow = ots.x + 12.f;
			ddl->AddRectFilled(ImVec2(cwp.x + dx, cwp.y + diagram_y_start),
			                   ImVec2(cwp.x + dx + ow, cwp.y + diagram_y_start + node_h),
			                   _ta(_t.panel_bg), 4.f);
			ddl->AddText(ImVec2(cwp.x + dx + 6.f, cwp.y + diagram_y_start + 2.f), text_main, ob);
			dx += ow;
		}

		ImGui::EndChild();
	} else {
		ImGui::SetCursorPos(ImVec2(pos_x + config_panel_w + 10.f, pos_y + toolbar_h + table_h + 6.f));
		ImGui::PushStyleColor(ImGuiCol_Text, text_dim);
		ImGui::TextUnformatted("Select a result to view chain details");
		ImGui::PopStyleColor();
	}
}

}
