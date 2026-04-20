#pragma once

#include "stealth_engine.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace stealth_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_finding = -1;
	int   category_filter = -1;
	int   severity_filter = -1;
	int   active_sub_tab = 0;
	char  pid_input[16] = {};
	bool  opt_peb = true;
	bool  opt_rdtsc = true;
	bool  opt_context = false;
	float anim_t = 0.f;
	float tab_underline_x = 0.f;
	float tab_underline_w = 0.f;
	float tab_underline_vel = 0.f;
	float content_crossfade = 1.f;
};

static local_state_t s_state;

inline ImU32 severity_color(stealth_engine::finding_severity_t s, float alpha)
{
	switch (s) {
	case stealth_engine::finding_severity_t::critical: return IM_COL32(220, 50, 50, static_cast<int>(alpha * 240));
	case stealth_engine::finding_severity_t::high:     return IM_COL32(220, 130, 50, static_cast<int>(alpha * 240));
	case stealth_engine::finding_severity_t::medium:   return IM_COL32(210, 190, 60, static_cast<int>(alpha * 220));
	case stealth_engine::finding_severity_t::low:      return IM_COL32(80, 160, 80, static_cast<int>(alpha * 220));
	case stealth_engine::finding_severity_t::info:     return IM_COL32(100, 140, 200, static_cast<int>(alpha * 200));
	}
	return IM_COL32(140, 140, 140, static_cast<int>(alpha * 200));
}

inline ImU32 severity_text_color(stealth_engine::finding_severity_t s, float alpha)
{
	const auto& _t = themes::resolved;
	switch (s) {
	case stealth_engine::finding_severity_t::critical: return ui_anim::theme_alpha(_t.text_primary, alpha);
	case stealth_engine::finding_severity_t::high:     return ui_anim::theme_alpha(_t.text_primary, alpha);
	case stealth_engine::finding_severity_t::medium:   return ui_anim::theme_alpha(_t.bg_base, alpha);
	case stealth_engine::finding_severity_t::low:      return ui_anim::theme_alpha(_t.text_primary, alpha);
	case stealth_engine::finding_severity_t::info:     return ui_anim::theme_alpha(_t.text_primary, alpha);
	}
	return ui_anim::theme_alpha(_t.text_primary, alpha);
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImGui::BeginChild("##protection_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;

	st.anim_t += ImGui::GetIO().DeltaTime;

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 bg         = _ta(_t.bg_base);
	const ImU32 text_col   = _ta(_t.text_primary);
	const ImU32 dim_col    = _ta(_t.text_dim);
	const ImU32 accent_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                   static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg  = _ta(_t.panel_header);
	const ImU32 row_even   = _ta(_t.panel_bg);
	const ImU32 row_odd    = _ta(ui_anim::lighten(_t.panel_bg, 8));
	const ImU32 row_hover  = _ta(ui_anim::lighten(_t.panel_header, 14));
	const ImU32 sel_col    = _ta(ui_anim::lighten(_t.panel_header, 10));
	const ImU32 green_col  = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 red_col    = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h), bg);

	const float pad = 12.f;
	float cx = ox + pad;
	float cy = oy + 6.f;

	const char* tab_names_arr[] = {"Protection Scan", "Stealth Controls"};
	float tab_x = cx;
	float dt = ImGui::GetIO().DeltaTime;

	dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + w, cy + 28.f),
		_ta(_t.bg_base));

	float target_ux = cx;
	float target_uw = 0.f;
	for (int ti = 0; ti < 2; ++ti) {
		ImVec2 tsz = ImGui::CalcTextSize(tab_names_arr[ti]);
		float tab_w = tsz.x + 24.f;
		if (ti == st.active_sub_tab) { target_ux = tab_x; target_uw = tab_w; }
		float text_alpha_val = (st.active_sub_tab == ti) ? 0.95f : 0.5f;

		ImGui::SetCursorScreenPos(ImVec2(tab_x, cy));
		ImGui::InvisibleButton(tab_names_arr[ti], ImVec2(tab_w, 26.f));
		bool hov = ImGui::IsItemHovered();
		if (hov) text_alpha_val = (st.active_sub_tab == ti) ? 0.95f : 0.72f;
		if (ImGui::IsItemClicked()) {
			if (st.active_sub_tab != ti) st.content_crossfade = 0.f;
			st.active_sub_tab = ti;
		}

		if (hov && st.active_sub_tab != ti) {
			dl->AddRectFilled(ImVec2(tab_x, cy), ImVec2(tab_x + tab_w, cy + 26.f),
				_ta(ui_anim::lighten(_t.panel_bg, 8)), 4.f, ImDrawFlags_RoundCornersTop);
		}

		dl->AddText(ImVec2(tab_x + 12.f, cy + 5.f),
			ui_anim::theme_alpha(_t.text_primary, text_alpha_val * alpha), tab_names_arr[ti]);

		tab_x += tab_w + 2.f;
	}

	if (st.tab_underline_w < 1.f) { st.tab_underline_x = target_ux; st.tab_underline_w = target_uw; }
	ui_anim::spring_interp(st.tab_underline_x, st.tab_underline_vel, target_ux, 280.f, 22.f, dt);
	float dummy_vel = 0.f;
	ui_anim::spring_interp(st.tab_underline_w, dummy_vel, target_uw, 280.f, 22.f, dt);

	dl->AddRectFilled(ImVec2(st.tab_underline_x + 2.f, cy + 25.f),
		ImVec2(st.tab_underline_x + st.tab_underline_w - 2.f, cy + 27.f),
		accent_col, 1.5f);

	st.content_crossfade = ui_anim::smooth_lerp(st.content_crossfade, 1.f, 10.f, dt);

	cy += 30.f;
	dl->AddLine(ImVec2(ox, cy - 1.f), ImVec2(ox + w, cy - 1.f),
		_ta(ui_anim::lighten(_t.panel_bg, 12)));
	cy += 4.f;

	if (st.active_sub_tab == 0) {
		float toolbar_top = cy;
		ui_anim::render_toolbar(dl, ox, cy, w, 34.f, accent_r, accent_g, accent_b, alpha);

		ImGui::SetCursorScreenPos(ImVec2(cx, cy + 5.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140),
			static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
			static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 240)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100),
			static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));

		bool scanning = stealth_engine::g_scan.scanning.load();

		if (!scanning) {
			if (ImGui::SmallButton("Scan")) {
				stealth_engine::run_protection_scan();
			}
		} else {
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.2f, 0.2f, 0.7f * alpha));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.2f, 0.2f, 0.9f * alpha));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.f, 0.2f, 0.2f, 1.f * alpha));
			if (ImGui::SmallButton("Stop"))
				stealth_engine::stop_protection_scan();
			ImGui::PopStyleColor(3);
		}

		ImGui::SameLine();
		if (ImGui::SmallButton("Clear")) {
			std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
			stealth_engine::g_scan.findings.clear();
			stealth_engine::g_scan.scan_status.clear();
			st.selected_finding = -1;
		}

		ImGui::PopStyleColor(4);
		ImGui::PopStyleVar();

		ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
		const char* sev_items[] = {"All Severity", "Critical", "High", "Medium", "Low", "Info"};
		ImGui::PushItemWidth(100.f);
		int sev_sel = st.severity_filter + 1;
		if (ImGui::Combo("##sev_combo", &sev_sel, sev_items, 6))
			st.severity_filter = sev_sel - 1;
		ImGui::PopItemWidth();

		ImGui::SameLine();
		const char* cat_items[] = {"All Categories", "AC Driver", "Memory Guard", "Suspicious Module",
		                           "Thread", "Debug State", "Hook", "WFP Callback"};
		ImGui::PushItemWidth(130.f);
		int cat_sel = st.category_filter + 1;
		if (ImGui::Combo("##cat_combo", &cat_sel, cat_items, 8))
			st.category_filter = cat_sel - 1;
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(3);
		ImGui::PopStyleVar(2);

		if (scanning) {
			ImGui::SameLine();
			float prog = stealth_engine::g_scan.progress.load();
			ui_anim::render_progress_ring(dl, ImGui::GetCursorScreenPos().x + 8.f,
				cy + 17.f, 7.f, 2.f, prog, _ta(ui_anim::lighten(_t.panel_bg, 12)), accent_col);
			ImGui::Dummy(ImVec2(24.f, 0.f));
			ImGui::SameLine();
			std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, alpha));
			ImGui::TextUnformatted(stealth_engine::g_scan.scan_status.c_str());
			ImGui::PopStyleColor();
		}

		cy += 38.f;

		std::vector<stealth_engine::finding_t> filtered;
		{
			std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
			for (auto& f : stealth_engine::g_scan.findings) {
				if (st.severity_filter >= 0 &&
				    static_cast<int>(f.severity) != (4 - st.severity_filter))
					continue;
				if (st.category_filter >= 0 &&
				    static_cast<int>(f.category) != st.category_filter)
					continue;
				filtered.push_back(f);
			}
		}

		const float row_h = 24.f;
		const float bottom_h = 56.f;
		const float table_top = cy;
		const float table_h = oy + h - cy - 8.f - bottom_h;

		float col_sev_w = 70.f;
		float col_cat_w = 120.f;
		float col_addr_w = 140.f;
		float col_title_w = w * 0.25f;
		float col_detail_w = w - col_sev_w - col_cat_w - col_addr_w - col_title_w - pad * 2.f - 14.f;
		if (col_detail_w < 60.f) col_detail_w = 60.f;

		float hx = cx;
		ui_anim::table_col_t finding_cols[] = {
			{ "Severity", col_sev_w }, { "Category", col_cat_w },
			{ "Address", col_addr_w }, { "Finding", col_title_w }, { "Details", col_detail_w }
		};
		ui_anim::render_table_header(dl, hx, cy, w - pad * 2.f, row_h,
			finding_cols, 5, accent_r, accent_g, accent_b, alpha * st.content_crossfade);

		cy += row_h + 1.f;

		float content_h = static_cast<float>(filtered.size()) * row_h;
		float visible_h = table_h - row_h - 1.f;
		if (visible_h < 0.f) visible_h = 0.f;

		ui_anim::handle_scroll_input(st.target_scroll_y, 0.f,
			std::max(0.f, content_h - visible_h), row_h);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

		ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + w - 14.f, oy + h - 8.f), true);

		int first_vis = static_cast<int>(st.scroll_y / row_h);
		int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
		if (first_vis < 0) first_vis = 0;
		if (last_vis > static_cast<int>(filtered.size()))
			last_vis = static_cast<int>(filtered.size());

		for (int i = first_vis; i < last_vis; ++i) {
			float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
			if (ry + row_h < cy || ry > oy + h) continue;

			auto& f = filtered[static_cast<size_t>(i)];

			ImVec2 rmin(cx, ry);
			ImVec2 rmax(ox + w - 14.f, ry + row_h);

			bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
			bool selected = (st.selected_finding == i);

			if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				st.selected_finding = selected ? -1 : i;

			if (selected) {
				ui_anim::render_glow_rect(dl, cx, ry, w - pad * 2.f - 14.f, row_h,
					accent_r, accent_g, accent_b, alpha, 0.5f);
			}
			dl->AddRectFilled(rmin, rmax,
				selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd)));

			if (selected) {
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + 3.f, ry + row_h),
					IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
							 static_cast<int>(accent_b * 255), static_cast<int>(alpha * 180)));
			}

			float row_anim = ui_anim::render_row_entrance(i - first_vis, st.anim_t > 1.f ? 1.f : st.anim_t);
			float row_alpha = alpha * row_anim;

			float rx = cx + 4.f;

			const char* sev_str = stealth_engine::severity_name(f.severity);
			ImVec2 sev_sz = ImGui::CalcTextSize(sev_str);
			float badge_w = sev_sz.x + 10.f;
			if (f.severity == stealth_engine::finding_severity_t::critical) {
				float glow_pulse = (std::sin(st.anim_t * 3.f + static_cast<float>(i) * 0.7f) + 1.f) * 0.5f;
				ImU32 crit_glow = IM_COL32(220, 50, 50, static_cast<int>(row_alpha * (15.f + glow_pulse * 20.f)));
				dl->AddRectFilled(ImVec2(rx - 3.f, ry + 1.f), ImVec2(rx + badge_w + 3.f, ry + row_h - 1.f),
					crit_glow, 5.f);
			}
			dl->AddRectFilled(ImVec2(rx, ry + 3.f), ImVec2(rx + badge_w, ry + row_h - 3.f),
				severity_color(f.severity, row_alpha), 3.f);
			dl->AddText(ImVec2(rx + 5.f, ry + 4.f),
				severity_text_color(f.severity, row_alpha), sev_str);
			rx = cx + col_sev_w + 4.f;

			dl->AddText(ImVec2(rx, ry + 4.f),
				ui_anim::theme_alpha(_t.text_secondary, row_alpha),
				stealth_engine::category_name(f.category));
			rx += col_cat_w;

			if (f.address != 0) {
				char addr_buf[20];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(f.address));
				dl->AddText(ImVec2(rx, ry + 4.f),
					ui_anim::theme_alpha(_t.text_secondary, row_alpha),
					addr_buf);
			}
			rx += col_addr_w;

			dl->AddText(ImVec2(rx, ry + 4.f),
				ui_anim::theme_alpha(_t.text_primary, row_alpha),
				f.title.c_str(),
				f.title.c_str() + std::min(f.title.size(), static_cast<size_t>(40)));
			rx += col_title_w;

			dl->AddText(ImVec2(rx, ry + 4.f),
				ui_anim::theme_alpha(_t.text_secondary, row_alpha),
				f.detail.c_str(),
				f.detail.c_str() + std::min(f.detail.size(), static_cast<size_t>(60)));
		}

		ImGui::PopClipRect();

		if (content_h > visible_h && visible_h > 0.f) {
			ui_anim::render_custom_scrollbar(dl, ox + w - 12.f, table_top + row_h + 1.f,
				10.f, visible_h, st.scroll_y, content_h, visible_h,
				alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
		}

		if (filtered.empty() && !scanning) {
			std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
			if (stealth_engine::g_scan.findings.empty()) {
				ui_anim::render_empty_state(dl, ox, table_top, w, table_h,
					"Click Scan to analyze the attached process for protection mechanisms",
					accent_r, accent_g, accent_b, alpha, st.anim_t);
			}
		}

		if (!scanning && !filtered.empty()) {
			int crit = 0, hi = 0, med = 0, lo = 0, inf = 0;
			for (auto& f : filtered) {
				switch (f.severity) {
				case stealth_engine::finding_severity_t::critical: ++crit; break;
				case stealth_engine::finding_severity_t::high:     ++hi; break;
				case stealth_engine::finding_severity_t::medium:   ++med; break;
				case stealth_engine::finding_severity_t::low:      ++lo; break;
				case stealth_engine::finding_severity_t::info:     ++inf; break;
				}
			}

			float card_y = oy + h - bottom_h;
			ui_anim::render_panel_card(dl, ox + 4.f, card_y, w - 8.f, bottom_h - 4.f,
				accent_r, accent_g, accent_b, alpha, 6.f, false);

			float donut_cx = ox + 32.f;
			float donut_cy = card_y + bottom_h * 0.5f - 2.f;
			float donut_r = 16.f;
			int total_f = static_cast<int>(filtered.size());
			if (total_f > 0) {
				int seg_counts[] = { crit, hi, med, lo, inf };
				ImU32 seg_colors[] = {
					IM_COL32(220, 50, 50, static_cast<int>(alpha * 240)),
					IM_COL32(220, 130, 50, static_cast<int>(alpha * 240)),
					IM_COL32(210, 190, 60, static_cast<int>(alpha * 220)),
					IM_COL32(80, 160, 80, static_cast<int>(alpha * 220)),
					IM_COL32(100, 140, 200, static_cast<int>(alpha * 200))
				};
				int valid_segs = 0;
				float valid_fracs[5];
				ImU32 valid_cols[5];
				for (int si = 0; si < 5; ++si) {
					if (seg_counts[si] > 0) {
						valid_fracs[valid_segs] = static_cast<float>(seg_counts[si]) / static_cast<float>(total_f);
						valid_cols[valid_segs] = seg_colors[si];
						++valid_segs;
					}
				}
				char t_buf[16];
				std::snprintf(t_buf, sizeof(t_buf), "%d", total_f);
				ui_anim::render_donut_chart(dl, donut_cx, donut_cy, donut_r, 5.f,
					valid_fracs, valid_cols, valid_segs, alpha, t_buf);
			}

			float card_w = (w - 80.f - 16.f) / 5.f;
			float sx = ox + 60.f;

			char b_total[16], b_crit[16], b_hi[16], b_med[16], b_lo[16];
			std::snprintf(b_total, sizeof(b_total), "%zu", filtered.size());
			std::snprintf(b_crit, sizeof(b_crit), "%d", crit);
			std::snprintf(b_hi, sizeof(b_hi), "%d", hi);
			std::snprintf(b_med, sizeof(b_med), "%d", med);
			std::snprintf(b_lo, sizeof(b_lo), "%d", lo);

			ui_anim::render_stat_card(dl, sx, card_y + 6.f, card_w, 40.f, "Findings", b_total,
				accent_r, accent_g, accent_b, alpha);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y + 6.f, card_w, 40.f, "Critical", b_crit,
				accent_r, accent_g, accent_b, alpha,
				IM_COL32(220, 50, 50, static_cast<int>(alpha * 255)));
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y + 6.f, card_w, 40.f, "High", b_hi,
				accent_r, accent_g, accent_b, alpha,
				IM_COL32(220, 130, 50, static_cast<int>(alpha * 255)));
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y + 6.f, card_w, 40.f, "Medium", b_med,
				accent_r, accent_g, accent_b, alpha,
				IM_COL32(210, 190, 60, static_cast<int>(alpha * 255)));
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y + 6.f, card_w, 40.f, "Low", b_lo,
				accent_r, accent_g, accent_b, alpha,
				IM_COL32(80, 160, 80, static_cast<int>(alpha * 255)));
		} else {
			float card_y = oy + h - bottom_h;
			ui_anim::render_panel_card(dl, ox + 4.f, card_y, w - 8.f, bottom_h - 4.f,
				accent_r, accent_g, accent_b, alpha * 0.4f, 6.f, false);
			ImVec2 ph_sz = ImGui::CalcTextSize("Run a scan to see summary");
			dl->AddText(ImVec2(ox + (w - ph_sz.x) * 0.5f, card_y + (bottom_h - ph_sz.y) * 0.5f - 2.f),
				_ta(ui_anim::lighten(_t.text_dim, 0)), "Run a scan to see summary");
		}
	}
	else {
		float toolbar_top = cy;
		ui_anim::render_toolbar(dl, ox, cy, w, 80.f, accent_r, accent_g, accent_b, alpha);

		float tx = cx;
		float ty = cy + 8.f;

		ImGui::SetCursorScreenPos(ImVec2(tx, ty));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
		ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::PushItemWidth(140.f);
		ImGui::InputTextWithHint("##stealth_pid", "Target PID (decimal)", st.pid_input, sizeof(st.pid_input),
			ImGuiInputTextFlags_CharsDecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);

		bool stealth_active = stealth_engine::is_active();

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140),
			static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
			static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 240)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100),
			static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));

		if (!stealth_active) {
			if (ImGui::SmallButton("Start Stealth")) {
				uint32_t pid = 0;
				if (st.pid_input[0])
					pid = static_cast<uint32_t>(std::strtoul(st.pid_input, nullptr, 10));
				if (pid == 0)
					pid = driver_bridge::attached_pid();
				if (pid != 0)
					stealth_engine::enable_stealth(pid);
			}
		} else {
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.2f, 0.2f, 0.7f * alpha));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.2f, 0.2f, 0.9f * alpha));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.f, 0.2f, 0.2f, 1.f * alpha));
			if (ImGui::SmallButton("Stop Stealth"))
				stealth_engine::disable_stealth();
			ImGui::PopStyleColor(3);
		}

		ImGui::PopStyleColor(4);
		ImGui::PopStyleVar();

		ty += 28.f;

		{
			std::string status_str = stealth_engine::get_status();
			if (!status_str.empty()) {
				ImU32 sc = stealth_active ? green_col : dim_col;
				dl->AddText(ImVec2(cx, ty), sc, status_str.c_str());
			}
		}

		ty += 18.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, ty));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
		ImGui::PushStyleColor(ImGuiCol_CheckMark, accent_col);
		ImGui::Checkbox("Spoof PEB Flags##stealth", &st.opt_peb);
		ImGui::SameLine();
		ImGui::Checkbox("Hook RDTSC##stealth", &st.opt_rdtsc);
		ImGui::SameLine();
		ImGui::Checkbox("Scrub Debug Context##stealth", &st.opt_context);
		ImGui::PopStyleColor(2);

		cy += 84.f;

		const float row_h = 22.f;
		float hx = cx;
		float hy = cy;

		std::vector<stealth_engine::hook_entry_t> hooks_copy;
		bool peb_ok = false;
		bool rdtsc_ok = false;
		uint32_t session_pid = 0;
		{
			std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
			hooks_copy = stealth_engine::g_state.session.hooks;
			peb_ok    = stealth_engine::g_state.session.peb_spoofed;
			rdtsc_ok  = stealth_engine::g_state.session.rdtsc_hooked;
			session_pid = stealth_engine::g_state.session.pid;
		}

		const float col_target_w  = 160.f;
		const float col_tramp_w   = 160.f;
		const float col_size_w    = 60.f;
		const float col_peb_w     = 60.f;
		const float col_active_w  = 70.f;

		ui_anim::table_col_t hook_cols[] = {
			{ "Target Address", col_target_w }, { "Trampoline", col_tramp_w },
			{ "Size", col_size_w }, { "PEB", col_peb_w }, { "Active", col_active_w }
		};
		ui_anim::render_table_header(dl, hx, hy, w - pad * 2.f, row_h,
			hook_cols, 5, accent_r, accent_g, accent_b, alpha * st.content_crossfade);

		hy += row_h;

		int total_rows = static_cast<int>(hooks_copy.size());

		if (total_rows == 0 && stealth_active) {
			float card_y = hy + 8.f;
			float card_w = (w - pad * 2.f - 8.f) / 3.f;
			float sx = hx;

			char b_pid[16];
			std::snprintf(b_pid, sizeof(b_pid), "%u", session_pid);

			ui_anim::render_stat_card(dl, sx, card_y, card_w, 40.f, "Target PID", b_pid,
				accent_r, accent_g, accent_b, alpha);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y, card_w, 40.f, "PEB Spoofed",
				peb_ok ? "Active" : "Inactive",
				accent_r, accent_g, accent_b, alpha, peb_ok ? green_col : red_col);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, card_y, card_w, 40.f, "RDTSC Hook",
				rdtsc_ok ? "Active" : "Inactive",
				accent_r, accent_g, accent_b, alpha, rdtsc_ok ? green_col : red_col);
		}

		for (int i = 0; i < total_rows; ++i) {
			float ry = hy + static_cast<float>(i) * row_h;
			if (ry > oy + h) break;

			auto& hook = hooks_copy[static_cast<size_t>(i)];
			float row_t = ui_anim::render_row_entrance(i, st.anim_t > 1.f ? 1.f : st.anim_t);

			bool hovered = ImGui::IsMouseHoveringRect(
				ImVec2(hx, ry), ImVec2(ox + w - pad, ry + row_h));

			dl->AddRectFilled(ImVec2(hx, ry), ImVec2(ox + w - pad, ry + row_h),
				ui_anim::theme_alpha(
					hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd), row_t));

			float rx = hx + 4.f;
			float yt = ry + (row_h - ImGui::GetTextLineHeight()) * 0.5f;

			char addr_buf[20];
			std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
				static_cast<unsigned long long>(hook.target_addr));
			dl->AddText(ImVec2(rx, yt),
				ui_anim::theme_alpha(_t.text_secondary, alpha * row_t), addr_buf);
			rx += col_target_w;

			char tramp_buf[20];
			std::snprintf(tramp_buf, sizeof(tramp_buf), "0x%llX",
				static_cast<unsigned long long>(hook.trampoline_addr));
			dl->AddText(ImVec2(rx, yt), dim_col, tramp_buf);
			rx += col_tramp_w;

			char size_buf[8];
			std::snprintf(size_buf, sizeof(size_buf), "%d", hook.hook_size);
			dl->AddText(ImVec2(rx, yt), text_col, size_buf);
			rx += col_size_w;

			dl->AddText(ImVec2(rx, yt), peb_ok ? green_col : red_col, peb_ok ? "yes" : "no");
			rx += col_peb_w;

			ui_anim::render_status_dot(dl, rx + 6.f, yt + ImGui::GetTextLineHeight() * 0.5f,
				3.f, hook.active ? green_col : red_col, st.anim_t, hook.active);
			dl->AddText(ImVec2(rx + 16.f, yt), hook.active ? green_col : red_col,
				hook.active ? "active" : "removed");
		}

		if (total_rows == 0 && !stealth_active) {
			float table_h = oy + h - cy - 8.f;
			ui_anim::render_empty_state(dl, ox, cy, w, table_h,
				"Attach a process and press Start Stealth to install anti-debug hooks",
				accent_r, accent_g, accent_b, alpha, st.anim_t);
		}
	}

	ImGui::EndChild();
}

}
