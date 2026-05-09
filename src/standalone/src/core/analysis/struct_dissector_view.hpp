#pragma once

#include "struct_dissector.hpp"
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace struct_dissector_view {

struct field_anim_t {
	aida::ui::flash_t change_flash;
	aida::ui::flash_t write_success;
	std::vector<uint8_t> last_bytes;
	bool                  has_last = false;
	aida::ui::transition_t expand;
	bool                  expanded = false;
};

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
	float row_anim_time = 0.f;
	std::unordered_map<int, field_anim_t> field_anims;
	float edit_ring_phase = 0.f;
};

inline ui_state_t g_ui;

inline ImU32 type_color_token(struct_dissector::field_type_t tp, float alpha) {
	const auto& th = aida::ui::resolved();
	ImU32 base;
	switch (tp) {
		case struct_dissector::field_type_t::pointer:        base = th.syn_function; break;
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string:   base = th.syn_string;   break;
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64:        base = th.syn_number;   break;
		case struct_dissector::field_type_t::padding:        base = th.text_dim;     break;
		case struct_dissector::field_type_t::nested_struct:  base = th.syn_keyword;  break;
		case struct_dissector::field_type_t::byte_array:     base = th.warning;      break;
		case struct_dissector::field_type_t::int8:
		case struct_dissector::field_type_t::int16:
		case struct_dissector::field_type_t::int32:
		case struct_dissector::field_type_t::int64:
		case struct_dissector::field_type_t::uint8:
		case struct_dissector::field_type_t::uint16:
		case struct_dissector::field_type_t::uint32:
		case struct_dissector::field_type_t::uint64:         base = th.syn_number;   break;
		default:                                             base = th.text_primary; break;
	}
	return aida::ui::with_alpha(base, alpha);
}

inline void render_type_glyph(ImDrawList* dl, ImVec2 center,
                              struct_dissector::field_type_t tp, ImU32 color)
{
	switch (tp) {
		case struct_dissector::field_type_t::pointer: {
			dl->AddCircle(center, 5.f, color, 12, 1.2f);
			ImVec2 tip = ImVec2(center.x + 7.f, center.y);
			dl->AddLine(center, tip, color, 1.2f);
			dl->AddTriangleFilled(
				ImVec2(tip.x - 3.f, center.y - 3.f),
				ImVec2(tip.x + 1.f, center.y),
				ImVec2(tip.x - 3.f, center.y + 3.f), color);
			break;
		}
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string: {
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 1.f),
				ImVec2(center.x + 5.f, center.y + 1.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y + 3.f),
				ImVec2(center.x + 3.f, center.y + 5.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 5.f),
				ImVec2(center.x + 4.f, center.y - 3.f), color, 1.f);
			break;
		}
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64: {
			dl->AddText(ImGui::GetFont(), 10.f,
				ImVec2(center.x - 4.f, center.y - 5.f), color, "f");
			break;
		}
		case struct_dissector::field_type_t::nested_struct: {
			ImVec2 a = ImVec2(center.x - 5.f, center.y - 5.f);
			ImVec2 b = ImVec2(center.x + 5.f, center.y + 5.f);
			dl->AddRect(a, b, color, 1.5f, 0, 1.f);
			dl->AddLine(ImVec2(a.x + 2.f, center.y), ImVec2(b.x - 2.f, center.y), color, 1.f);
			break;
		}
		default: {
			dl->AddCircleFilled(center, 2.f, color, 12);
			break;
		}
	}
}

inline field_anim_t& fanim(int idx) { return g_ui.field_anims[idx]; }

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b) {
	(void)pos_x; (void)pos_y;
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##struct_dissector_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto& ui = g_ui;
	auto& st = struct_dissector::g_state;
	const float dt = aida::ui::clock::dt();
	const float line_h = 28.f;
	const float top_bar_h = 36.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wpos = ImGui::GetWindowPos();
	float ox = wpos.x;
	float oy = wpos.y;

	ui.row_anim_time += dt;
	ui.edit_ring_phase += dt;

	const auto& th = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + top_bar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + top_bar_h - 1.f), ImVec2(ox + width, oy + top_bar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float bx = ox + 12.f;
	float by = oy + 6.f;

	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		14.f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_secondary, alpha), "Base");
	bx += 36.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushItemWidth(170.f);
	if (ImGui::InputText("##sd_addr", ui.addr_buf, sizeof(ui.addr_buf),
						 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.base_address = addr;
		}
	}
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);
	bx += 180.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Refresh", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
		struct_dissector::refresh_values();
	}
	bx += 92.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	{
		bool auto_now = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto_now = st.auto_refresh;
		}
		if (aida::ui::toggle_switch("##sd_auto", &auto_now, aida::ui::size_t_::sm)) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.auto_refresh = auto_now;
		}
	}
	bx += 38.f;
	dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
		12.f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_dim, alpha), "Auto");
	bx += 40.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Export C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
		int aidx = -1;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			aidx = st.active_struct;
		}
		if (aidx >= 0) struct_dissector::export_to_c(aidx);
	}

	if (st.auto_refresh) {
		st.refresh_timer += dt;
		if (st.refresh_timer >= st.refresh_interval) {
			st.refresh_timer = 0.f;
			struct_dissector::refresh_values();
		}
	}

	float body_y = oy + top_bar_h + 1.f;
	float body_h = height - top_bar_h - 1.f;
	float left_w = std::floor(width * 0.28f);
	if (left_w < 200.f) left_w = 200.f;
	float right_w = width - left_w - 1.f;

	dl->AddLine(ImVec2(ox + left_w, body_y), ImVec2(ox + left_w, body_y + body_h),
		aida::ui::with_alpha(th.border_subtle, alpha));

	{
		float lx = ox;
		float ly = body_y;
		float lw = left_w;
		float lh = body_h;

		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			12.f, ImVec2(lx + 10.f, ly + 6.f),
			aida::ui::with_alpha(th.text_secondary, alpha), "Structures");
		float list_y = ly + 24.f;
		float list_h = lh - 24.f - line_h - 8.f;

		ui.list_scroll_y = aida::motion::smooth_lerp(ui.list_scroll_y,
			ui.list_target_scroll_y, 18.f, dt);

		bool list_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h));
		if (list_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.list_target_scroll_y -= wheel * line_h * 3.f;
		}

		int struct_count = 0;
		std::vector<std::pair<std::string, uint32_t>> entries;
		int active_struct_idx = -1;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			struct_count = static_cast<int>(st.structs.size());
			active_struct_idx = st.active_struct;
			entries.reserve(struct_count);
			for (auto& sd : st.structs) entries.emplace_back(sd.name, sd.total_size);
		}

		float content_h = struct_count * line_h;
		if (ui.list_target_scroll_y < 0.f) ui.list_target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - list_h);
		if (ui.list_target_scroll_y > ms) ui.list_target_scroll_y = ms;

		ImGui::PushClipRect(ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h), true);
		for (int i = 0; i < struct_count; ++i) {
			float ry = list_y + i * line_h - ui.list_scroll_y;
			if (ry + line_h < list_y || ry > list_y + list_h) continue;

			ImVec2 a = ImVec2(lx + 4.f, ry);
			ImVec2 b = ImVec2(lx + lw - 4.f, ry + line_h);
			bool hov = ImGui::IsMouseHoveringRect(a, b, true);
			bool sel = (active_struct_idx == i);

			ImU32 fill = sel
				? aida::ui::with_alpha(th.selection, alpha)
				: (hov ? aida::ui::with_alpha(th.hover_wash, alpha) : 0u);
			if ((fill & 0xFF000000) != 0) {
				dl->AddRectFilled(a, b, fill, 6.f);
			}
			if (sel) {
				dl->AddRectFilled(ImVec2(a.x, a.y),
					ImVec2(a.x + 3.f, b.y), aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
			}

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				std::lock_guard<std::mutex> lk(st.mtx);
				st.active_struct = i;
				ui.selected_field = -1;
				ui.editing_field = -1;
			}

			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				14.f, ImVec2(a.x + 10.f, ry + 5.f),
				aida::ui::with_alpha(th.text_primary, alpha),
				entries[static_cast<size_t>(i)].first.c_str());
			char sz_buf[32];
			std::snprintf(sz_buf, sizeof(sz_buf), "(%u)", entries[static_cast<size_t>(i)].second);
			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();
			ImVec2 sz = code_font->CalcTextSizeA(13.f, FLT_MAX, 0.f, sz_buf);
			dl->AddText(code_font, 13.f, ImVec2(b.x - sz.x - 8.f, ry + 6.f),
				aida::ui::with_alpha(th.text_dim, alpha), sz_buf);
		}
		ImGui::PopClipRect();

		float btn_y = ly + lh - line_h + 4.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, btn_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw * 0.5f);
		ImGui::InputTextWithHint("##sd_newname", "name", ui.name_buf, sizeof(ui.name_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		ImGui::SameLine();
		if (aida::ui::button("+", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			if (ui.name_buf[0] != '\0') {
				struct_dissector::create_struct(ui.name_buf);
				ui.name_buf[0] = '\0';
			}
		}
		ImGui::SameLine();
		if (aida::ui::button("-", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			std::lock_guard<std::mutex> lk(st.mtx);
			if (st.active_struct >= 0 && st.active_struct < static_cast<int>(st.structs.size())) {
				st.structs.erase(st.structs.begin() + st.active_struct);
				if (st.active_struct >= static_cast<int>(st.structs.size()))
					st.active_struct = static_cast<int>(st.structs.size()) - 1;
				ui.selected_field = -1;
			}
		}
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
			ImVec2 sz = ImVec2(rw, rh);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No struct selected";
			cfg.body = "Create or select a struct from the list to begin dissecting memory.";
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(ImVec2(rx, ry_start), sz, cfg);
			ImGui::EndChild();
			return;
		}

		const float col_offset_w = 70.f;
		const float col_glyph_w  = 22.f;
		const float col_name_w   = 200.f;
		const float col_type_w   = 110.f;
		const float col_value_w  = std::max(160.f, rw - col_offset_w - col_glyph_w
		                          - col_name_w - col_type_w - 140.f - 12.f);
		const float col_desc_w   = 140.f;

		float hdr_y = ry_start;
		ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
		dl->AddRectFilled(ImVec2(rx, hdr_y), ImVec2(rx + rw, hdr_y + line_h), hdr_bg, 6.f);
		dl->AddLine(ImVec2(rx, hdr_y + line_h - 1.f), ImVec2(rx + rw, hdr_y + line_h - 1.f),
			aida::ui::with_alpha(th.border_subtle, alpha));

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		float hx = rx + 8.f;
		dl->AddText(head_em, 13.f, ImVec2(hx, hdr_y + 7.f), hc, "Offset");
		hx += col_offset_w + col_glyph_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, hdr_y + 7.f), hc, "Name");
		hx += col_name_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, hdr_y + 7.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, hdr_y + 7.f), hc, "Value");
		hx += col_value_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, hdr_y + 7.f), hc, "Description");

		float table_y = ry_start + line_h;
		float table_h = rh - line_h - line_h - 8.f;

		ui.scroll_y = aida::motion::smooth_lerp(ui.scroll_y, ui.target_scroll_y, 18.f, dt);

		bool table_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h));
		if (table_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.target_scroll_y -= wheel * line_h * 3.f;
		}

		float content_h = field_count * line_h;
		if (ui.target_scroll_y < 0.f) ui.target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - table_h);
		if (ui.target_scroll_y > ms) ui.target_scroll_y = ms;

		ImGui::PushClipRect(ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h), true);
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (active_idx >= 0 && active_idx < static_cast<int>(st.structs.size())) {
				const auto& sd = st.structs[active_idx];
				for (int fi = 0; fi < static_cast<int>(sd.fields.size()); ++fi) {
					float row_y = table_y + fi * line_h - ui.scroll_y;
					if (row_y + line_h < table_y || row_y > table_y + table_h) continue;

					float entrance_delay = std::min(static_cast<float>(fi) * 0.008f, 0.240f);
					float entrance_t = (ui.row_anim_time - entrance_delay) / 0.32f;
					if (entrance_t < 0.f) entrance_t = 0.f;
					if (entrance_t > 1.f) entrance_t = 1.f;
					float entrance = aida::motion::ease::out_cubic(entrance_t);
					if (entrance < 0.01f) continue;

					bool row_sel = (ui.selected_field == fi);
					bool row_hov = ImGui::IsMouseHoveringRect(
						ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h), false);

					ImU32 row_fill;
					if (row_sel) row_fill = aida::ui::with_alpha(th.selection, alpha);
					else if (row_hov) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
					else row_fill = (fi & 1)
						? aida::ui::with_alpha(th.panel_bg, alpha * 0.55f * entrance)
						: 0u;
					if ((row_fill & 0xFF000000) != 0) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							row_fill, 4.f);
					}
					if (row_sel) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + 3.f, row_y + line_h),
							aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
					}

					auto& fa = fanim(fi);
					float change_v = fa.change_flash.tick(dt, 1.7f);
					if (change_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.error, alpha * change_v * 0.4f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}
					float write_v = fa.write_success.tick(dt, 2.0f);
					if (write_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.success_soft, alpha * write_v * 1.5f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}

					if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						ui.selected_field = fi;

					const auto& f = sd.fields[fi];
					float fx = rx + 8.f;
					ImFont* code_font = aida::ui::fonts::code();
					if (!code_font) code_font = ImGui::GetFont();

					char off_str[16];
					std::snprintf(off_str, sizeof(off_str), "+0x%03X", f.offset);
					dl->AddText(code_font, 13.f, ImVec2(fx, row_y + 7.f),
						aida::ui::with_alpha(th.text_address, alpha * entrance), off_str);
					fx += col_offset_w;

					ImU32 type_c = type_color_token(f.type, alpha * entrance);
					render_type_glyph(dl, ImVec2(fx + col_glyph_w * 0.5f, row_y + line_h * 0.5f),
						f.type, type_c);
					fx += col_glyph_w;

					dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
						14.f, ImVec2(fx, row_y + 7.f),
						aida::ui::with_alpha(th.text_primary, alpha * entrance), f.name.c_str());
					fx += col_name_w;

					dl->AddText(code_font, 13.f, ImVec2(fx, row_y + 7.f),
						type_c, struct_dissector::field_type_name(f.type));
					fx += col_type_w;

					if (fi < static_cast<int>(st.cached_values.size())) {
						const auto& cv = st.cached_values[fi];
						bool changed_now = cv.changed && fa.has_last && fa.last_bytes != cv.raw_bytes;
						if (changed_now) fa.change_flash.trigger();
						fa.last_bytes = cv.raw_bytes;
						fa.has_last = true;

						ImU32 val_col = aida::ui::with_alpha(th.text_primary, alpha * entrance);
						dl->AddText(code_font, 13.f, ImVec2(fx, row_y + 7.f),
							val_col, cv.display_text.c_str());

						if (ui.editing_field == fi) {
							float ring_pulse = sinf(ui.edit_ring_phase * 6.f) * 0.5f + 0.5f;
							ImU32 ring = aida::ui::with_alpha(th.accent_hover,
								alpha * (0.45f + ring_pulse * 0.45f));
							dl->AddRect(ImVec2(fx - 2.f, row_y + 1.f),
								ImVec2(fx + col_value_w - 4.f, row_y + line_h - 1.f),
								ring, 5.f, 0, 1.5f);

							ImGui::SetCursorScreenPos(ImVec2(fx, row_y + 1.f));
							ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.panel_header, alpha)));
							ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.text_primary, alpha)));
							ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
							ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 2.f));
							ImGui::PushItemWidth(col_value_w - 8.f);
							bool committed = ImGui::InputText("##sd_edit_val", ui.edit_value_buf,
								sizeof(ui.edit_value_buf),
								ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
							ImGui::PopItemWidth();
							ImGui::PopStyleVar(2);
							ImGui::PopStyleColor(2);
							if (committed) {
								uint64_t write_addr = st.base_address + f.offset;
								auto bytes = memory_scanner::parse_value(ui.edit_value_buf,
									static_cast<memory_scanner::value_type_t>(
										std::min(static_cast<int>(f.type),
												 static_cast<int>(memory_scanner::value_type_t::double_val))),
									false);
								if (!bytes.empty()) {
									if (driver_bridge::write_memory(write_addr, bytes)) {
										fa.write_success.trigger();
									}
								}
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

					if (!f.description.empty()) {
						dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
							13.f, ImVec2(fx, row_y + 7.f),
							aida::ui::with_alpha(th.text_dim, alpha * entrance),
							f.description.c_str());
					}
				}
			}
		}
		ImGui::PopClipRect();

		if (content_h > table_h && table_h > 0.f) {
			float bar_x = rx + rw - 10.f;
			float bar_y = table_y;
			float bar_h = table_h;
			float ratio = table_h / content_h;
			float thumb_h = std::max(bar_h * ratio, 24.f);
			float track = bar_h - thumb_h;
			float scroll_ratio = (content_h - table_h > 0.f) ? ui.scroll_y / (content_h - table_h) : 0.f;
			float thumb_y = bar_y + track * scroll_ratio;
			dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 5.f, bar_y + bar_h),
				aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 2.f);
			dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 5.f, thumb_y + thumb_h),
				aida::ui::with_alpha(th.accent_dim, alpha), 2.f);
		}

		float add_y = ry_start + rh - line_h - 2.f;
		ImGui::SetCursorScreenPos(ImVec2(rx + 4.f, add_y + 1.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));

		ImGui::PushItemWidth(170.f);
		ImGui::InputTextWithHint("##sd_fn", "field name", ui.field_name_buf, sizeof(ui.field_name_buf));
		ImGui::PopItemWidth();
		ImGui::SameLine();

		ImGui::PushItemWidth(80.f);
		ImGui::InputTextWithHint("##sd_fo", "+0x?", ui.offset_buf, sizeof(ui.offset_buf),
						 ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine();

		static const char* type_names[] = {
			"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
			"Int64", "UInt64", "Float", "Double", "Pointer",
			"ASCII", "UTF-16", "Bytes", "Padding", "Struct"
		};
		ImGui::PushItemWidth(110.f);
		ImGui::Combo("##sd_ft", &ui.add_type, type_names,
					 static_cast<int>(struct_dissector::field_type_t::COUNT));
		ImGui::PopItemWidth();
		ImGui::SameLine();

		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		if (aida::ui::button("Add", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(72.f, 28.f))) {
			if (ui.field_name_buf[0] != '\0') {
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
		}
		ImGui::SameLine();
		if (aida::ui::button("Del", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(64.f, 28.f))) {
			if (ui.selected_field >= 0) {
				struct_dissector::remove_field(active_idx, ui.selected_field);
				ui.selected_field = -1;
				ui.editing_field = -1;
			}
		}
	}

	ImGui::EndChild();
}

}
