#pragma once

#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "xref_db.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/brand.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

extern DisasmState g_disasm;

namespace xref_db_view {

struct module_anim_t {
	float dot_size = 0.f;
	float dot_target = 0.f;
	aida::ui::transition_t check_draw;
	bool  was_indexed = false;
};

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_row = -1;
	char  addr_buf[20] = {};
	char  filter_buf[128] = {};
	int   filter_type = -1;
	bool  show_to = true;
	bool  scroll_to_top = false;
	float row_anim_time = 0.f;
	int   prev_filtered_count = 0;
	std::string last_filter;
	aida::ui::transition_t list_crossfade;
	std::unordered_map<std::string, module_anim_t> module_anims;
};

inline state_t g_view;

inline aida::ui::pill_kind_t xref_pill(xref_engine::xref_type_t t)
{
	switch (t) {
		case xref_engine::xref_type_t::call: return aida::ui::pill_kind_t::info;
		case xref_engine::xref_type_t::jump:
		case xref_engine::xref_type_t::conditional_jump:
			return aida::ui::pill_kind_t::warning;
		default:
			return aida::ui::pill_kind_t::accent;
	}
}

inline ImU32 xref_color(xref_engine::xref_type_t tp, float alpha)
{
	const auto& th = aida::ui::resolved();
	switch (tp) {
		case xref_engine::xref_type_t::call:             return aida::ui::with_alpha(th.info, alpha);
		case xref_engine::xref_type_t::jump:
		case xref_engine::xref_type_t::conditional_jump: return aida::ui::with_alpha(th.warning, alpha);
		default:                                         return aida::ui::with_alpha(th.accent_u32, alpha);
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float a = alpha;

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
	g_view.row_anim_time += dt;

	float x0 = wp.x + pos_x;
	float y0 = wp.y + pos_y;

	dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + width, y0 + height),
		aida::ui::with_alpha(th.bg_base, a));

	const bool compact_toolbar = width < 900.f;
	const bool stacked_layout = width < 640.f;
	float toolbar_h = width < 420.f ? 148.f : (width < 660.f ? 116.f : (compact_toolbar ? 82.f : 44.f));
	float left_panel_w = stacked_layout
		? width
		: std::min(std::max(220.f, width * 0.22f), std::max(180.f, width - 360.f));

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, a * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, a * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(x0, y0), ImVec2(x0 + width, y0 + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(x0, y0 + toolbar_h - 1.f), ImVec2(x0 + width, y0 + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, a));

	ImGui::SetCursorPos(ImVec2(pos_x + 10.f, pos_y + 10.f));
	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	dl->AddText(head_em, 13.f, ImVec2(x0 + 10.f, y0 + 14.f),
		aida::ui::with_alpha(th.text_primary, a),
		"Cross-Reference Database");

	const float toolbar_left = compact_toolbar ? 10.f : 240.f;
	float toolbar_row_y = compact_toolbar ? 42.f : 12.f;
	auto place_next_toolbar_item = [&](float next_w)
	{
		const ImGuiStyle& style = ImGui::GetStyle();
		if (ImGui::GetItemRectMax().x + style.ItemSpacing.x + next_w <= x0 + width - 12.f) {
			ImGui::SameLine();
		} else {
			toolbar_row_y += 32.f;
			ImGui::SetCursorPos(ImVec2(pos_x + toolbar_left, pos_y + toolbar_row_y));
		}
	};

	ImGui::SetCursorPos(ImVec2(pos_x + toolbar_left, pos_y + toolbar_row_y));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, a)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, a)));
	ImGui::PushItemWidth(std::min(160.f, std::max(118.f, width - 24.f)));
	ImGui::InputTextWithHint("##xref_addr", "Address (hex)",
		g_view.addr_buf, sizeof(g_view.addr_buf));
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(2);
	ImGui::PopStyleVar(2);

	place_next_toolbar_item(102.f);
	if (aida::ui::button("XRefs To", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(102.f, 28.f))) {
		uint64_t addr = std::strtoull(g_view.addr_buf, nullptr, 16);
		if (addr != 0) {
			g_view.show_to = true;
			xref_db::query_xrefs_to(addr);
			g_view.selected_row = -1;
			g_view.scroll_y = 0.f;
			g_view.target_scroll_y = 0.f;
			g_view.scroll_to_top = true;
		}
	}
	place_next_toolbar_item(112.f);
	if (aida::ui::button("XRefs From", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(112.f, 28.f))) {
		uint64_t addr = std::strtoull(g_view.addr_buf, nullptr, 16);
		if (addr != 0) {
			g_view.show_to = false;
			xref_db::query_xrefs_from(addr);
			g_view.selected_row = -1;
			g_view.scroll_y = 0.f;
			g_view.target_scroll_y = 0.f;
			g_view.scroll_to_top = true;
		}
	}

	place_next_toolbar_item(std::min(200.f, std::max(120.f, width - 24.f)));
	ImGui::SetNextItemWidth(std::min(200.f, std::max(120.f, width - 24.f)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, a)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, a)));
	ImGui::InputTextWithHint("##xref_filter", "Filter address or disasm...",
		g_view.filter_buf, sizeof(g_view.filter_buf));
	ImGui::PopStyleColor(2);
	ImGui::PopStyleVar();

	std::string current_filter = g_view.filter_buf;
	if (current_filter != g_view.last_filter) {
		g_view.list_crossfade.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
		g_view.last_filter = current_filter;
	}
	g_view.list_crossfade.tick(dt);

	if (xref_db::g_state.building.load()) {
		float prog = xref_db::g_state.progress.load();
		float bar_w = 160.f;
		float bar_h = 8.f;
		float bx = x0 + width - bar_w - 80.f;
		float by = y0 + toolbar_h * 0.5f - bar_h * 0.5f;
		if (!compact_toolbar || width >= 430.f) {
			if (compact_toolbar) by = y0 + 20.f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w, by + bar_h),
				aida::ui::with_alpha(th.panel_header, a), 4.f);
			{
				ImU32 xref_prog_flat = aida::ui::mix(
					aida::ui::with_alpha(th.accent_grad_top, a),
					aida::ui::with_alpha(th.accent_grad_bot, a), 0.5f);
				dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w * prog, by + bar_h),
					xref_prog_flat, 4.f);
			}
			char pct[16];
			std::snprintf(pct, sizeof(pct), "%.0f%%", prog * 100.f);
			ImVec2 pt = ImGui::CalcTextSize(pct);
			dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
				11.f, ImVec2(bx + bar_w + 8.f, by - pt.y * 0.5f + bar_h * 0.5f),
				aida::ui::with_alpha(th.text_secondary, a), pct);
		}
	} else {
		size_t total = xref_db::total_indexed_xrefs();
		if (total > 0 && (!compact_toolbar || width >= 390.f)) {
			char info[64];
			std::snprintf(info, sizeof(info), "%zu xrefs indexed", total);
			ImVec2 it = ImGui::CalcTextSize(info);
			float info_y = compact_toolbar ? y0 + 14.f : y0 + toolbar_h * 0.5f - it.y * 0.5f;
			dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
				11.f, ImVec2(x0 + width - it.x - 12.f, info_y),
				aida::ui::with_alpha(th.text_dim, a), info);
		}
	}

	float content_y = y0 + toolbar_h;
	float content_h = std::max(80.f, height - toolbar_h);
	float modules_h = content_h;
	float result_y = content_y;
	float result_h = content_h;
	if (stacked_layout) {
		modules_h = std::min(176.f, std::max(88.f, content_h * 0.36f));
		if (content_h - modules_h - 6.f < 92.f)
			modules_h = std::max(56.f, content_h - 98.f);
		result_y = content_y + modules_h + 6.f;
		result_h = std::max(82.f, content_h - modules_h - 6.f);
	}

	ImVec2 lp_a = ImVec2(x0, content_y);
	ImVec2 lp_b = ImVec2(x0 + left_panel_w, content_y + modules_h);
	dl->AddRectFilled(lp_a, lp_b, aida::ui::with_alpha(th.panel_bg, a * 0.4f));
	if (stacked_layout) {
		dl->AddLine(ImVec2(x0, content_y + modules_h),
			ImVec2(x0 + width, content_y + modules_h),
			aida::ui::with_alpha(th.border_subtle, a));
	} else {
		dl->AddLine(ImVec2(x0 + left_panel_w, content_y),
			ImVec2(x0 + left_panel_w, y0 + height),
			aida::ui::with_alpha(th.border_subtle, a));
	}

	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		12.f, ImVec2(x0 + 12.f, content_y + 8.f),
		aida::ui::with_alpha(th.text_secondary, a), "Modules");

	auto modules = xref_db::get_module_list();
	float row_h = 28.f;

	ImGui::SetCursorPos(ImVec2(pos_x + 4.f, pos_y + toolbar_h + 30.f));
	ImGui::BeginChild("##xref_mod_list",
		ImVec2(std::max(80.f, left_panel_w - 4.f), std::max(44.f, modules_h - 30.f)), false,
		ImGuiWindowFlags_NoBackground);

	bool building = xref_db::g_state.building.load();
	if (building && modules.empty()) {
		ImVec2 cp = ImGui::GetCursorScreenPos();
		aida::ui::skeleton::render_table_rows(dl, ImVec2(cp.x + 4.f, cp.y),
			ImVec2(cp.x + left_panel_w - 12.f, cp.y + modules_h - 32.f),
			2, 6, row_h, 1.6f);
	}

	for (size_t i = 0; i < modules.size(); ++i) {
		auto& m = modules[i];
		bool indexed = xref_db::is_module_indexed(m.name);
		ImVec2 cp = ImGui::GetCursorScreenPos();
		float lw = left_panel_w - 8.f;

		bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + lw, cp.y + row_h), true);
		if (hov) {
			dl->AddRectFilled(cp, ImVec2(cp.x + lw, cp.y + row_h),
				aida::ui::with_alpha(th.hover_wash, a), 5.f);
		}

		auto& man = g_view.module_anims[m.name];
		if (indexed && !man.was_indexed) {
			man.check_draw.start(aida::motion::dur::md, aida::motion::ease::out_back);
			man.was_indexed = true;
		} else if (!indexed && man.was_indexed) {
			man.check_draw.reset();
			man.was_indexed = false;
		}
		man.check_draw.tick(dt);
		man.dot_target = indexed ? 1.f : 0.f;
		man.dot_size = aida::motion::smooth_lerp(man.dot_size, man.dot_target, 14.f, dt);

		ImU32 name_col = indexed
			? aida::ui::with_alpha(th.accent_u32, a)
			: aida::ui::with_alpha(th.text_primary, a);
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			12.f, ImVec2(cp.x + 6.f, cp.y + 5.f), name_col, m.name.c_str());

		if (indexed) {
			float dot_r = 4.f * man.dot_size;
			ImVec2 dot_c = ImVec2(cp.x + lw - 14.f, cp.y + row_h * 0.5f);
			dl->AddCircleFilled(dot_c, dot_r,
				aida::ui::with_alpha(th.accent_glow, a * 0.6f * man.dot_size), 16);
			dl->AddCircleFilled(dot_c, dot_r * 0.7f,
				aida::ui::with_alpha(th.accent_u32, a), 12);
			float check_p = man.check_draw.eased();
			if (check_p > 0.01f && check_p <= 1.f) {
				aida::ui::brand::render_check_drawn(dl,
					ImVec2(dot_c.x - 0.5f, dot_c.y), 6.f, check_p,
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), a), 1.5f);
			}
		} else if (!building) {
			float bw = 50.f;
			float bx_off = lw - bw - 6.f;
			ImGui::SetCursorScreenPos(ImVec2(cp.x + bx_off, cp.y + 1.f));
			ImGui::PushID(static_cast<int>(i));
			if (aida::ui::button("Index", aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm, ImVec2(bw, 20.f))) {
				xref_db::build_module_index(m.name, m.base, m.size);
			}
			ImGui::PopID();
		}

		ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + row_h));
	}

	ImGui::EndChild();

	float table_x = stacked_layout ? x0 : x0 + left_panel_w + 2.f;
	float table_w = std::max(160.f, stacked_layout ? width : width - left_panel_w - 4.f);

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	const float code_size = 13.f;
	float col_dir_w = 48.f;
	float col_addr_w = std::max(148.f,
		code_font->CalcTextSizeA(code_size, 1000000.f, 0.f, "0x0000000000000000").x + 14.f);
	float col_type_w = 90.f;
	float col_disasm_w = std::max(0.f, table_w - col_dir_w - col_addr_w - col_type_w - 16.f);

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, a * 0.9f);
	dl->AddRectFilled(ImVec2(table_x, result_y), ImVec2(table_x + table_w, result_y + 26.f),
		hdr_bg, 6.f);
	dl->AddLine(ImVec2(table_x, result_y + 25.f), ImVec2(table_x + table_w, result_y + 25.f),
		aida::ui::with_alpha(th.border_subtle, a));

	float hxx = table_x + 8.f;
	ImU32 hc = aida::ui::with_alpha(th.text_secondary, a);
	dl->AddText(head_em, 13.f, ImVec2(hxx, result_y + 8.f), hc, "Dir");
	hxx += col_dir_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, result_y + 8.f), hc, "Address");
	hxx += col_addr_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, result_y + 8.f), hc, "Type");
	hxx += col_type_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, result_y + 8.f), hc, "Instruction");

	float table_body_y = result_y + 26.f;
	float table_body_h = std::max(48.f, result_h - 26.f);

	ImGui::SetCursorPos(ImVec2(stacked_layout ? pos_x : pos_x + left_panel_w + 2.f,
		pos_y + toolbar_h + (stacked_layout ? modules_h + 6.f : 0.f) + 26.f));
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
				std::snprintf(addr_str, sizeof(addr_str), "%llX",
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

	float fade_in = g_view.list_crossfade.is_finished() ? 1.f : g_view.list_crossfade.eased();
	if (fade_in < 0.0001f) fade_in = 0.0001f;
	float final_alpha = a * fade_in;

	float row_height = 22.f;
	auto draw_clipped_text = [&](ImFont* font, float font_size, ImVec2 p,
		ImU32 col, const char* text, float clip_l, float clip_r)
	{
		if (!text || !*text || clip_r <= clip_l || p.x >= clip_r) return;
		ImVec4 clip(clip_l, table_body_y, clip_r, table_body_y + table_body_h);
		dl->AddText(font, font_size, p, col, text, nullptr, 0.f, &clip);
	};
	if (g_view.scroll_to_top)
		ImGui::SetScrollY(0.f);

	ImGuiListClipper clipper;
	clipper.Begin(static_cast<int>(filtered.size()), row_height);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			auto& e = filtered[static_cast<size_t>(i)];
			ImVec2 rp = ImGui::GetCursorScreenPos();

			float entrance_delay = std::min(static_cast<float>(i) * 0.012f, 0.240f);
			float entrance_t = (g_view.row_anim_time - entrance_delay) / 0.32f;
			if (entrance_t < 0.f) entrance_t = 0.f;
			if (entrance_t > 1.f) entrance_t = 1.f;
			float entrance = aida::motion::ease::out_cubic(entrance_t);

			bool hov = ImGui::IsMouseHoveringRect(rp, ImVec2(rp.x + table_w, rp.y + row_height), true);
			bool sel = (g_view.selected_row == i);

			ImU32 row_fill;
			if (sel) row_fill = aida::ui::with_alpha(th.selection, final_alpha);
			else if (hov) row_fill = aida::ui::with_alpha(th.hover_wash, final_alpha);
			else row_fill = (i & 1)
				? aida::ui::with_alpha(th.panel_bg, final_alpha * 0.45f * entrance)
				: 0u;
			if ((row_fill & 0xFF000000) != 0) {
				dl->AddRectFilled(rp, ImVec2(rp.x + table_w, rp.y + row_height), row_fill, 4.f);
			}
			if (sel) {
				dl->AddRectFilled(ImVec2(rp.x, rp.y), ImVec2(rp.x + 3.f, rp.y + row_height),
					aida::ui::with_alpha(th.accent_u32, final_alpha), 1.5f);
			}

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				g_view.selected_row = i;

			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
				uint64_t nav_addr = g_view.show_to ? e.from_addr : e.to_addr;
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(nav_addr, g_disasm);
			}

			const char* dir_str = g_view.show_to ? "<-" : "->";
			draw_clipped_text(code_font, code_size, ImVec2(rp.x + 8.f, rp.y + 7.f),
				aida::ui::with_alpha(th.text_dim, final_alpha * entrance), dir_str,
				rp.x, rp.x + col_dir_w - 2.f);

			uint64_t display_addr = g_view.show_to ? e.from_addr : e.to_addr;
			char addr_str[24];
			std::snprintf(addr_str, sizeof(addr_str), "0x%llX",
				static_cast<unsigned long long>(display_addr));
			draw_clipped_text(code_font, code_size, ImVec2(rp.x + col_dir_w + 4.f, rp.y + 7.f),
				aida::ui::with_alpha(th.text_address, final_alpha * entrance), addr_str,
				rp.x + col_dir_w, rp.x + col_dir_w + col_addr_w - 4.f);

			std::string type_str = xref_engine::xref_type_name(e.type);
			ImGui::SetCursorScreenPos(ImVec2(rp.x + col_dir_w + col_addr_w + 4.f, rp.y + 1.f));
			aida::ui::pill_kind(type_str.c_str(), xref_pill(e.type),
				aida::ui::size_t_::sm, false);

			draw_clipped_text(code_font, code_size,
				ImVec2(rp.x + col_dir_w + col_addr_w + col_type_w + 4.f, rp.y + 7.f),
				aida::ui::with_alpha(th.text_primary, final_alpha * entrance),
				e.disasm_text.c_str(),
				rp.x + col_dir_w + col_addr_w + col_type_w,
				rp.x + col_dir_w + col_addr_w + col_type_w + col_disasm_w);

			ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + row_height));
		}
	}
	g_view.scroll_y = ImGui::GetScrollY();
	g_view.target_scroll_y = g_view.scroll_y;
	if (g_view.scroll_to_top && g_view.scroll_y <= 0.5f)
		g_view.scroll_to_top = false;

	if (filtered.empty() && !building) {
		const char* empty_msg = xref_db::g_state.query_results.empty()
			? "Enter an address and click XRefs To or XRefs From to search."
			: "No results match the current filter.";
		ImVec2 cp = ImGui::GetCursorScreenPos();
		ImVec2 e_sz = ImVec2(table_w, table_body_h * 0.7f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::search;
		cfg.title = "No xrefs to show";
		cfg.body = empty_msg;
		cfg.max_width = 360.f;
		aida::ui::empty_state::render(cp, e_sz, cfg);
	}

	ImGui::EndChild();

	char count_str[48];
	std::snprintf(count_str, sizeof(count_str), "%d results",
		static_cast<int>(filtered.size()));
	ImVec2 cs = ImGui::CalcTextSize(count_str);
	dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
		11.f, ImVec2(x0 + width - cs.x - 12.f, y0 + height - 18.f),
		aida::ui::with_alpha(th.text_dim, a), count_str);
}

}
