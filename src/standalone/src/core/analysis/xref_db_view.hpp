#pragma once

#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "xref_db.hpp"
#include "ui_anim.hpp"

extern DisasmState g_disasm;

namespace xref_db_view {

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_row = -1;
	char  addr_buf[20] = {};
	char  filter_buf[128] = {};
	int   filter_type = -1;
	bool  show_to = true;
	bool  sb_dragging = false;
	float sb_drag_offset = 0.f;
};

inline state_t g_view;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;

	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 bg = _ta(_t.bg_base);
	ImU32 panel_bg = _ta(_t.panel_bg);
	ImU32 hdr_bg = _ta(_t.panel_header);
	ImU32 text_main = _ta(_t.text_primary);
	ImU32 text_dim = _ta(_t.text_dim);
	ImU32 text_sec = _ta(_t.text_secondary);
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
	float left_panel_w = std::max(180.f, width * 0.2f);

	ui_anim::render_toolbar(dl, x0, y0, width, toolbar_h, accent_r, accent_g, accent_b, a);
	dl->AddLine(ImVec2(x0, y0 + toolbar_h), ImVec2(x0 + width, y0 + toolbar_h), _ta(ui_anim::lighten(_t.panel_bg, 12)));

	ImGui::SetCursorPos(ImVec2(pos_x + 8.f, pos_y + 6.f));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::TextUnformatted("Cross-Reference Database");
	ImGui::PopStyleColor();

	ImGui::SetCursorPos(ImVec2(pos_x + 240.f, pos_y + 6.f));
	ImGui::PushItemWidth(140.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_header));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 4.f));
	ImGui::InputTextWithHint("##xref_addr", "Address (hex)", g_view.addr_buf, sizeof(g_view.addr_buf));
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
	ImGui::PopItemWidth();

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(ui_anim::lighten(_t.panel_header, 14)));
	ImGui::PushStyleColor(ImGuiCol_Text, text_main);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);

	if (ImGui::Button("XRefs To##xdb")) {
		uint64_t addr = strtoull(g_view.addr_buf, nullptr, 16);
		if (addr != 0) {
			g_view.show_to = true;
			xref_db::query_xrefs_to(addr);
			g_view.selected_row = -1;
			g_view.scroll_y = 0.f;
			g_view.target_scroll_y = 0.f;
		}
	}

	ImGui::SameLine();
	if (ImGui::Button("XRefs From##xdb")) {
		uint64_t addr = strtoull(g_view.addr_buf, nullptr, 16);
		if (addr != 0) {
			g_view.show_to = false;
			xref_db::query_xrefs_from(addr);
			g_view.selected_row = -1;
			g_view.scroll_y = 0.f;
			g_view.target_scroll_y = 0.f;
		}
	}

	ImGui::SameLine();
	ui_anim::render_filter_input_chip("##xref_filter", g_view.filter_buf, sizeof(g_view.filter_buf),
		"Filter address or disasm...", 180.f, accent_r, accent_g, accent_b, a);

	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);

	if (xref_db::g_state.building.load()) {
		float prog = xref_db::g_state.progress.load();
		float bar_w = 140.f;
		float bar_h = 8.f;
		float bx = x0 + width - bar_w - 60.f;
		float by = y0 + toolbar_h * 0.5f - bar_h * 0.5f;
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w, by + bar_h),
		                  _ta(_t.panel_header), 4.f);
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w * prog, by + bar_h),
		                  accent_col, 4.f);
		char pct[16];
		snprintf(pct, sizeof(pct), "%.0f%%", prog * 100.f);
		ImVec2 pt = ImGui::CalcTextSize(pct);
		dl->AddText(ImVec2(bx + bar_w + 6.f, by - pt.y * 0.5f + bar_h * 0.5f), text_sec, pct);
	} else {
		size_t total = xref_db::total_indexed_xrefs();
		if (total > 0) {
			char info[64];
			snprintf(info, sizeof(info), "%zu xrefs indexed", total);
			ImVec2 it = ImGui::CalcTextSize(info);
			dl->AddText(ImVec2(x0 + width - it.x - 12.f, y0 + toolbar_h * 0.5f - it.y * 0.5f),
			            text_dim, info);
		}
	}

	float content_y = y0 + toolbar_h;
	float content_h = height - toolbar_h;

	ui_anim::render_panel_card(dl, x0, content_y, left_panel_w, content_h, accent_r, accent_g, accent_b, a, 0.f, false);
	dl->AddLine(ImVec2(x0 + left_panel_w, content_y), ImVec2(x0 + left_panel_w, y0 + height), sep_col);

	dl->AddText(ImVec2(x0 + 10.f, content_y + 6.f), text_sec, "Modules");

	auto modules = xref_db::get_module_list();
	float my = content_y + 26.f;
	float row_h = 22.f;

	ImGui::SetCursorPos(ImVec2(pos_x + 2.f, pos_y + toolbar_h + 26.f));
	ImGui::BeginChild("##xref_mod_list", ImVec2(left_panel_w - 4.f, content_h - 26.f), false,
	                  ImGuiWindowFlags_NoBackground);

	for (size_t i = 0; i < modules.size(); ++i) {
		auto& m = modules[i];
		bool indexed = xref_db::is_module_indexed(m.name);
		ImVec2 cp = ImGui::GetCursorScreenPos();
		float lw = left_panel_w - 8.f;

		bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + lw, cp.y + row_h), true);
		if (hov)
			dl->AddRectFilled(cp, ImVec2(cp.x + lw, cp.y + row_h), row_hover_col, 3.f);

		ImU32 name_col = indexed ? accent_col : text_main;
		dl->AddText(ImVec2(cp.x + 4.f, cp.y + 3.f), name_col, m.name.c_str());

		if (indexed) {
			dl->AddCircleFilled(ImVec2(cp.x + lw - 10.f, cp.y + row_h * 0.5f), 4.f, accent_col);
		} else if (!xref_db::g_state.building.load()) {
			float bw = 44.f;
			float bx_off = lw - bw - 4.f;
			ImGui::SetCursorScreenPos(ImVec2(cp.x + bx_off, cp.y + 1.f));
			ImGui::PushID(static_cast<int>(i));
			ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, accent_dim);
			ImGui::PushStyleColor(ImGuiCol_Text, text_main);
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.f, 2.f));
			if (ImGui::Button("Index")) {
				xref_db::build_module_index(m.name, m.base, m.size);
			}
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(3);
			ImGui::PopID();
		}

		ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + row_h));
	}

	ImGui::EndChild();

	float table_x = x0 + left_panel_w + 2.f;
	float table_w = width - left_panel_w - 4.f;

	float col_dir_w = 48.f;
	float col_addr_w = 130.f;
	float col_type_w = 48.f;
	float col_disasm_w = table_w - col_dir_w - col_addr_w - col_type_w - 16.f;

	{
		ui_anim::table_col_t hdr_cols[] = {
			{"Dir", col_dir_w}, {"Address", col_addr_w}, {"Type", col_type_w}, {"Instruction", col_disasm_w}
		};
		ui_anim::render_table_header(dl, table_x, content_y, table_w, 24.f, hdr_cols, 4, accent_r, accent_g, accent_b, a);
	}

	float table_body_y = content_y + 24.f;
	float table_body_h = content_h - 24.f;

	ImGui::SetCursorPos(ImVec2(pos_x + left_panel_w + 2.f, pos_y + toolbar_h + 24.f));
	ImGui::BeginChild("##xref_results", ImVec2(table_w, table_body_h), false,
	                  ImGuiWindowFlags_NoBackground);

	std::vector<xref_db::xref_entry_t> filtered;
	{
		std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
		std::string ftext = g_view.filter_buf;
		for (auto& e : xref_db::g_state.query_results) {
			if (!ftext.empty()) {
				bool match = false;
				char addr_str[32];
				snprintf(addr_str, sizeof(addr_str), "%llX",
				         static_cast<unsigned long long>(g_view.show_to ? e.from_addr : e.to_addr));
				if (e.disasm_text.find(ftext) != std::string::npos) match = true;
				if (std::string(addr_str).find(ftext) != std::string::npos) match = true;
				if (!match) continue;
			}
			if (g_view.filter_type >= 0 && static_cast<int>(e.type) != g_view.filter_type)
				continue;
			filtered.push_back(e);
		}
	}

	static float xref_row_anim_time = 0.f;
	xref_row_anim_time += ImGui::GetIO().DeltaTime;

	float row_height = 20.f;
	for (int i = 0; i < static_cast<int>(filtered.size()); ++i) {
		auto& e = filtered[i];
		ImVec2 rp = ImGui::GetCursorScreenPos();

		float row_entrance = ui_anim::render_row_entrance(i, xref_row_anim_time, 0.015f);
		bool hov = ImGui::IsMouseHoveringRect(rp, ImVec2(rp.x + table_w, rp.y + row_height), true);
		bool sel = (g_view.selected_row == i);

		ui_anim::table_row_style_t rs{};
		rs.selected = sel;
		rs.hovered = hov;
		rs.index = i;
		rs.alpha = a;
		rs.entrance = row_entrance;
		rs.ar = accent_r; rs.ag = accent_g; rs.ab = accent_b;
		ui_anim::render_table_row(dl, rp.x, rp.y, table_w, row_height, rs);

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_view.selected_row = i;

		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			uint64_t nav_addr = g_view.show_to ? e.from_addr : e.to_addr;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(nav_addr, g_disasm);
		}

		const char* dir = g_view.show_to ? "<-" : "->";
		dl->AddText(ImVec2(rp.x + 4.f, rp.y + 2.f), text_dim, dir);

		uint64_t display_addr = g_view.show_to ? e.from_addr : e.to_addr;
		char addr_str[24];
		snprintf(addr_str, sizeof(addr_str), "0x%llX", static_cast<unsigned long long>(display_addr));
		dl->AddText(ImVec2(rp.x + col_dir_w + 4.f, rp.y + 2.f), accent_col, addr_str);

		std::string type_str = xref_engine::xref_type_name(e.type);
		ImU32 type_col = text_sec;
		if (e.type == xref_engine::xref_type_t::call)
			type_col = IM_COL32(100, 200, 255, static_cast<int>(220 * a));
		else if (e.type == xref_engine::xref_type_t::jump || e.type == xref_engine::xref_type_t::conditional_jump)
			type_col = IM_COL32(255, 200, 100, static_cast<int>(220 * a));
		{
			float tx = rp.x + col_dir_w + col_addr_w + 4.f;
			ImVec2 tts = ImGui::CalcTextSize(type_str.c_str());
			float pw = tts.x + 10.f;
			float ph = tts.y + 2.f;
			float py = rp.y + (row_height - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(tx, py), ImVec2(tx + pw, py + ph),
				IM_COL32((type_col >> IM_COL32_R_SHIFT) & 0xFF,
				         (type_col >> IM_COL32_G_SHIFT) & 0xFF,
				         (type_col >> IM_COL32_B_SHIFT) & 0xFF,
				         static_cast<int>(40 * a)), ph * 0.5f);
			dl->AddText(ImVec2(tx + 5.f, py + 1.f), type_col, type_str.c_str());
		}

		dl->AddText(ImVec2(rp.x + col_dir_w + col_addr_w + col_type_w + 4.f, rp.y + 2.f),
		            text_main, e.disasm_text.c_str());

		ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + row_height));
	}

	if (filtered.empty() && !xref_db::g_state.building.load()) {
		const char* empty_msg = xref_db::g_state.query_results.empty()
			? "Enter an address and click 'XRefs To' or 'XRefs From' to search."
			: "No results match the current filter.";
		ImVec2 cp = ImGui::GetCursorScreenPos();
		ui_anim::render_empty_state(dl, cp.x, cp.y, table_w, table_body_h * 0.6f,
			empty_msg, accent_r, accent_g, accent_b, a, static_cast<float>(ImGui::GetTime()));
	}

	ImGui::EndChild();

	{
		float content_total = static_cast<float>(filtered.size()) * row_height;
		if (content_total > table_body_h) {
			float sb_x = table_x + table_w - 8.f;
			ui_anim::render_custom_scrollbar(dl, sb_x, table_body_y, 6.f, table_body_h,
				g_view.scroll_y, content_total, table_body_h,
				a, g_view.sb_dragging, g_view.sb_drag_offset);
		}
	}

	char count_str[48];
	snprintf(count_str, sizeof(count_str), "%d results", static_cast<int>(filtered.size()));
	ImVec2 cs = ImGui::CalcTextSize(count_str);
	dl->AddText(ImVec2(x0 + width - cs.x - 10.f, y0 + height - 18.f), text_dim, count_str);
}

}
