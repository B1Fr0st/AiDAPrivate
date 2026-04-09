#pragma once

#include "struct_dissector.hpp"
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace struct_dissector_view {

struct ui_state_t {
	int   active_tab = 0;
	int   selected_field = -1;
	std::vector<bool> field_expand;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	float list_scroll_y = 0.f;
	float list_target_scroll_y = 0.f;
	char  name_buf[128] = {};
	char  field_name_buf[128] = {};
	char  offset_buf[32] = {};
	char  size_buf[32] = {};
	char  edit_value_buf[256] = {};
	char  addr_buf[20] = {};
	int   editing_field = -1;
	int   add_type = 0;
	int   selected_struct = -1;
	bool  sb_dragging = false;
	float sb_drag_offset = 0.f;
	bool  list_sb_dragging = false;
	float list_sb_drag_offset = 0.f;
};

inline ui_state_t g_ui;

inline ImU32 type_color(struct_dissector::field_type_t t, float alpha) {
	int a = static_cast<int>(220 * alpha);
	switch (t) {
	case struct_dissector::field_type_t::pointer:
		return IM_COL32(100, 160, 255, a);
	case struct_dissector::field_type_t::ascii_string:
	case struct_dissector::field_type_t::utf16_string:
		return IM_COL32(140, 220, 140, a);
	case struct_dissector::field_type_t::float32:
	case struct_dissector::field_type_t::float64:
		return IM_COL32(230, 180, 100, a);
	case struct_dissector::field_type_t::padding:
		return IM_COL32(100, 100, 100, a);
	case struct_dissector::field_type_t::nested_struct:
		return IM_COL32(200, 130, 220, a);
	default:
		return IM_COL32(210, 210, 230, a);
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b) {
	auto& ui = g_ui;
	auto& st = struct_dissector::g_state;
	const float dt = ImGui::GetIO().DeltaTime;
	const float line_h = 22.f;
	const float char_w = ImGui::CalcTextSize("0").x;
	const float top_bar_h = 32.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wpos = ImGui::GetWindowPos();
	float ox = wpos.x + pos_x;
	float oy = wpos.y + pos_y;

	ImU32 accent_col = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(220 * alpha));
	ImU32 accent_dim = IM_COL32(
		static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
		static_cast<int>(accent_b * 255), static_cast<int>(30 * alpha));
	ImU32 header_col = IM_COL32(160, 170, 200, static_cast<int>(200 * alpha));
	ImU32 text_col = IM_COL32(200, 200, 220, static_cast<int>(220 * alpha));
	ImU32 dim_col = IM_COL32(120, 120, 140, static_cast<int>(150 * alpha));
	ImU32 bg_alt = IM_COL32(255, 255, 255, static_cast<int>(3 * alpha));
	ImU32 separator_col = IM_COL32(255, 255, 255, static_cast<int>(10 * alpha));
	ImU32 changed_col = IM_COL32(255, 80, 80, static_cast<int>(200 * alpha));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + top_bar_h),
					  IM_COL32(18, 20, 26, static_cast<int>(200 * alpha)));
	dl->AddLine(ImVec2(ox, oy + top_bar_h), ImVec2(ox + width, oy + top_bar_h), separator_col);

	float bx = ox + 6.f;
	float by = oy + 6.f;

	dl->AddText(ImVec2(bx, by + 2.f), dim_col, "Base:");
	bx += ImGui::CalcTextSize("Base:").x + 6.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(200 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 220, 255));
	ImGui::PushItemWidth(char_w * 18.f);
	if (ImGui::InputText("##sd_addr", ui.addr_buf, sizeof(ui.addr_buf),
						 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.base_address = addr;
		}
	}
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(2);
	bx += char_w * 18.f + 12.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(40, 42, 52, static_cast<int>(200 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(55, 58, 70, static_cast<int>(200 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 220, 255));
	if (ImGui::SmallButton("Refresh##sd")) {
		struct_dissector::refresh_values();
	}
	bx += ImGui::CalcTextSize("Refresh").x + 20.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	{
		std::lock_guard<std::mutex> lk(st.mtx);
		if (ImGui::Checkbox("##sd_auto", &st.auto_refresh)) {}
	}
	bx += 22.f;
	dl->AddText(ImVec2(bx, by + 2.f), dim_col, "Auto");
	bx += ImGui::CalcTextSize("Auto").x + 16.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (ImGui::SmallButton("Export C##sd")) {
		int aidx = -1;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			aidx = st.active_struct;
		}
		if (aidx >= 0)
			struct_dissector::export_to_c(aidx);
	}
	ImGui::PopStyleColor(3);

	if (st.auto_refresh) {
		st.refresh_timer += dt;
		if (st.refresh_timer >= st.refresh_interval) {
			st.refresh_timer = 0.f;
			struct_dissector::refresh_values();
		}
	}

	float body_y = oy + top_bar_h + 1.f;
	float body_h = height - top_bar_h - 1.f;
	float left_w = std::floor(width * 0.3f);
	float right_w = width - left_w - 1.f;

	dl->AddLine(ImVec2(ox + left_w, body_y), ImVec2(ox + left_w, body_y + body_h), separator_col);

	{
		float lx = ox;
		float ly = body_y;
		float lw = left_w;
		float lh = body_h;

		dl->AddText(ImVec2(lx + 6.f, ly + 4.f), header_col, "Structures");
		float list_y = ly + line_h;
		float list_h = lh - line_h - line_h - 4.f;

		ui_anim::smooth_scroll(ui.list_scroll_y, ui.list_target_scroll_y, 20.f, dt);

		bool list_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h));
		if (list_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f)
				ui.list_target_scroll_y -= wheel * line_h * 3.f;
		}

		int struct_count = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			struct_count = static_cast<int>(st.structs.size());
		}

		float content_h = struct_count * line_h;
		ui_anim::clamp_scroll(ui.list_target_scroll_y, 0.f, std::max(0.f, content_h - list_h));

		ImGui::PushClipRect(ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h), true);
		for (int i = 0; i < struct_count; ++i) {
			float ry = list_y + i * line_h - ui.list_scroll_y;
			if (ry + line_h < list_y || ry > list_y + list_h) continue;

			int sel = st.active_struct;
			if (ui_anim::row_hover_select(dl, lx, ry, lw, line_h, i, sel, alpha,
										  accent_r, accent_g, accent_b)) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.active_struct = i;
				ui.selected_field = -1;
				ui.editing_field = -1;
			}

			std::string sname;
			uint32_t ssz = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (i < static_cast<int>(st.structs.size())) {
					sname = st.structs[i].name;
					ssz = st.structs[i].total_size;
				}
			}
			dl->AddText(ImVec2(lx + 8.f, ry + 2.f), text_col, sname.c_str());
			char sz_buf[32];
			std::snprintf(sz_buf, sizeof(sz_buf), "(%u)", ssz);
			dl->AddText(ImVec2(lx + lw - ImGui::CalcTextSize(sz_buf).x - 8.f, ry + 2.f),
						dim_col, sz_buf);
		}
		ImGui::PopClipRect();

		float btn_y = ly + lh - line_h;
		ImGui::SetCursorScreenPos(ImVec2(lx + 4.f, btn_y + 2.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 220, 255));
		ImGui::PushItemWidth(lw * 0.5f);
		ImGui::InputText("##sd_newname", ui.name_buf, sizeof(ui.name_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);

		ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(40, 80, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(50, 100, 50, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 220, 200, 255));
		if (ImGui::SmallButton("+##sd_add") && ui.name_buf[0] != '\0') {
			struct_dissector::create_struct(ui.name_buf);
			ui.name_buf[0] = '\0';
		}
		ImGui::PopStyleColor(3);

		ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(80, 40, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(100, 50, 50, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(220, 200, 200, 255));
		if (ImGui::SmallButton("-##sd_del")) {
			std::lock_guard<std::mutex> lk(st.mtx);
			if (st.active_struct >= 0 && st.active_struct < static_cast<int>(st.structs.size())) {
				st.structs.erase(st.structs.begin() + st.active_struct);
				if (st.active_struct >= static_cast<int>(st.structs.size()))
					st.active_struct = static_cast<int>(st.structs.size()) - 1;
				ui.selected_field = -1;
			}
		}
		ImGui::PopStyleColor(3);

		ui_anim::render_custom_scrollbar(dl, lx + lw - 6.f, list_y, 4.f, list_h,
										 ui.list_scroll_y, content_h, list_h,
										 alpha, ui.list_sb_dragging, ui.list_sb_drag_offset);
	}

	{
		float rx = ox + left_w + 1.f;
		float ry_start = body_y;
		float rw = right_w;
		float rh = body_h;

		int active_idx = -1;
		int field_count = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			active_idx = st.active_struct;
			if (active_idx >= 0 && active_idx < static_cast<int>(st.structs.size()))
				field_count = static_cast<int>(st.structs[active_idx].fields.size());
		}

		if (active_idx < 0) {
			dl->AddText(ImVec2(rx + rw * 0.5f - 60.f, ry_start + rh * 0.5f),
						dim_col, "No struct selected");
			return;
		}

		float col_offset_w = char_w * 8.f;
		float col_name_w = char_w * 20.f;
		float col_type_w = char_w * 14.f;
		float col_value_w = rw - col_offset_w - col_name_w - col_type_w - char_w * 14.f - 8.f;
		if (col_value_w < char_w * 10.f) col_value_w = char_w * 10.f;

		float hdr_y = ry_start;
		dl->AddRectFilled(ImVec2(rx, hdr_y), ImVec2(rx + rw, hdr_y + line_h),
						  IM_COL32(22, 24, 32, static_cast<int>(200 * alpha)));
		float cx = rx + 4.f;
		dl->AddText(ImVec2(cx, hdr_y + 2.f), header_col, "Offset");
		cx += col_offset_w;
		dl->AddText(ImVec2(cx, hdr_y + 2.f), header_col, "Name");
		cx += col_name_w;
		dl->AddText(ImVec2(cx, hdr_y + 2.f), header_col, "Type");
		cx += col_type_w;
		dl->AddText(ImVec2(cx, hdr_y + 2.f), header_col, "Value");
		cx += col_value_w;
		dl->AddText(ImVec2(cx, hdr_y + 2.f), header_col, "Description");

		float table_y = ry_start + line_h;
		float table_h = rh - line_h - line_h - 4.f;

		ui_anim::smooth_scroll(ui.scroll_y, ui.target_scroll_y, 20.f, dt);

		bool table_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h));
		if (table_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f)
				ui.target_scroll_y -= wheel * line_h * 3.f;
		}

		float content_h = field_count * line_h;
		ui_anim::clamp_scroll(ui.target_scroll_y, 0.f, std::max(0.f, content_h - table_h));

		ImGui::PushClipRect(ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h), true);
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (active_idx >= 0 && active_idx < static_cast<int>(st.structs.size())) {
				const auto& sd = st.structs[active_idx];
				for (int fi = 0; fi < static_cast<int>(sd.fields.size()); ++fi) {
					float row_y = table_y + fi * line_h - ui.scroll_y;
					if (row_y + line_h < table_y || row_y > table_y + table_h) continue;

					if (fi & 1)
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h), bg_alt);

					int sel = ui.selected_field;
					if (ui_anim::row_hover_select(dl, rx, row_y, rw, line_h, fi, sel, alpha,
												  accent_r, accent_g, accent_b)) {
						ui.selected_field = fi;
					}

					const auto& f = sd.fields[fi];
					float fx = rx + 4.f;

					char off_str[16];
					std::snprintf(off_str, sizeof(off_str), "+0x%03X", f.offset);
					dl->AddText(ImVec2(fx, row_y + 2.f),
								IM_COL32(75, 95, 155, static_cast<int>(170 * alpha)), off_str);
					fx += col_offset_w;

					dl->AddText(ImVec2(fx, row_y + 2.f), text_col, f.name.c_str());
					fx += col_name_w;

					dl->AddText(ImVec2(fx, row_y + 2.f), type_color(f.type, alpha),
								struct_dissector::field_type_name(f.type));
					fx += col_type_w;

					if (fi < static_cast<int>(st.cached_values.size())) {
						const auto& cv = st.cached_values[fi];
						ImU32 val_col = cv.changed ? changed_col : text_col;
						dl->AddText(ImVec2(fx, row_y + 2.f), val_col, cv.display_text.c_str());

						if (ui.editing_field == fi) {
							ImGui::SetCursorScreenPos(ImVec2(fx, row_y));
							ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(40, 42, 55, 230));
							ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, 255));
							ImGui::PushItemWidth(col_value_w - 4.f);
							bool committed = ImGui::InputText("##sd_edit_val", ui.edit_value_buf,
								sizeof(ui.edit_value_buf),
								ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
							ImGui::PopItemWidth();
							ImGui::PopStyleColor(2);
							if (committed) {
								uint64_t write_addr = st.base_address + f.offset;
								auto bytes = memory_scanner::parse_value(ui.edit_value_buf,
									static_cast<memory_scanner::value_type_t>(
										std::min(static_cast<int>(f.type),
												 static_cast<int>(memory_scanner::value_type_t::double_val))),
									false);
								if (!bytes.empty())
									driver_bridge::write_memory(write_addr, bytes);
								ui.editing_field = -1;
							}
							if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
								ui.editing_field = -1;
						}

						if (ui.selected_field == fi && ui.editing_field != fi &&
							ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							ImVec2 mp = ImGui::GetMousePos();
							if (mp.x >= fx && mp.x <= fx + col_value_w &&
								mp.y >= row_y && mp.y <= row_y + line_h) {
								ui.editing_field = fi;
								std::strncpy(ui.edit_value_buf, cv.display_text.c_str(),
											 sizeof(ui.edit_value_buf) - 1);
								ui.edit_value_buf[sizeof(ui.edit_value_buf) - 1] = '\0';
							}
						}
					}
					fx += col_value_w;

					if (!f.description.empty())
						dl->AddText(ImVec2(fx, row_y + 2.f), dim_col, f.description.c_str());
				}
			}
		}
		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, rx + rw - 6.f, table_y, 4.f, table_h,
										 ui.scroll_y, content_h, table_h,
										 alpha, ui.sb_dragging, ui.sb_drag_offset);

		float add_y = ry_start + rh - line_h - 2.f;
		ImGui::SetCursorScreenPos(ImVec2(rx + 4.f, add_y));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 32, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 220, 255));

		ImGui::PushItemWidth(char_w * 14.f);
		ImGui::InputText("##sd_fn", ui.field_name_buf, sizeof(ui.field_name_buf));
		ImGui::PopItemWidth();
		ImGui::SameLine();

		ImGui::PushItemWidth(char_w * 6.f);
		ImGui::InputText("##sd_fo", ui.offset_buf, sizeof(ui.offset_buf),
						 ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine();

		static const char* type_names[] = {
			"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
			"Int64", "UInt64", "Float", "Double", "Pointer",
			"ASCII", "UTF-16", "Bytes", "Padding", "Struct"
		};
		ImGui::PushItemWidth(char_w * 10.f);
		ImGui::Combo("##sd_ft", &ui.add_type, type_names,
					 static_cast<int>(struct_dissector::field_type_t::COUNT));
		ImGui::PopItemWidth();
		ImGui::SameLine();

		ImGui::PopStyleColor(2);

		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(40, 80, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(50, 100, 50, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 220, 200, 255));
		if (ImGui::SmallButton("Add##sd_af") && ui.field_name_buf[0] != '\0') {
			struct_dissector::field_def_t fd;
			fd.name = ui.field_name_buf;
			fd.type = static_cast<struct_dissector::field_type_t>(ui.add_type);
			uint32_t off = 0;
			std::sscanf(ui.offset_buf, "%x", &off);
			fd.offset = off;
			size_t ts = struct_dissector::field_type_size(fd.type);
			fd.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
			struct_dissector::add_field(active_idx, fd);
			ui.field_name_buf[0] = '\0';
			ui.offset_buf[0] = '\0';
		}
		ImGui::PopStyleColor(3);

		ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(80, 40, 40, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(100, 50, 50, static_cast<int>(200 * alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(220, 200, 200, 255));
		if (ImGui::SmallButton("Del##sd_df") && ui.selected_field >= 0) {
			struct_dissector::remove_field(active_idx, ui.selected_field);
			ui.selected_field = -1;
			ui.editing_field = -1;
		}
		ImGui::PopStyleColor(3);
	}
}

}
