#pragma once

#include "stealth_engine.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/hub_strip.hpp"
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
	char  pid_input[16] = {};
	bool  opt_peb = true;
	bool  opt_rdtsc = true;
	bool  opt_context = false;
	float anim_t = 0.f;
	aida::ui::hub_strip::state_t strip;
};

static local_state_t s_state;

inline aida::ui::pill_kind_t severity_pill(stealth_engine::finding_severity_t s)
{
	switch (s) {
		case stealth_engine::finding_severity_t::critical: return aida::ui::pill_kind_t::error;
		case stealth_engine::finding_severity_t::high:     return aida::ui::pill_kind_t::warning;
		case stealth_engine::finding_severity_t::medium:   return aida::ui::pill_kind_t::warning;
		case stealth_engine::finding_severity_t::low:      return aida::ui::pill_kind_t::success;
		case stealth_engine::finding_severity_t::info:     return aida::ui::pill_kind_t::info;
	}
	return aida::ui::pill_kind_t::neutral;
}

inline ImU32 severity_token(stealth_engine::finding_severity_t s, float alpha)
{
	const auto& th = aida::ui::resolved();
	switch (s) {
		case stealth_engine::finding_severity_t::critical: return aida::ui::with_alpha(th.error,   alpha);
		case stealth_engine::finding_severity_t::high:     return aida::ui::with_alpha(th.warning, alpha);
		case stealth_engine::finding_severity_t::medium:   return aida::ui::with_alpha(th.warning, alpha * 0.85f);
		case stealth_engine::finding_severity_t::low:      return aida::ui::with_alpha(th.success, alpha);
		case stealth_engine::finding_severity_t::info:     return aida::ui::with_alpha(th.info,    alpha);
	}
	return aida::ui::with_alpha(th.text_dim, alpha);
}

inline constexpr aida::ui::hub_strip::tab_t s_subtabs[] = {
	{ "Protection Scan", "scan attached process" },
	{ "Stealth Controls", "anti-debug hook controls" },
};

inline void render_protection_scan(float pos_x, float pos_y, float w, float h,
                                    float alpha, ImDrawList* dl, ImVec2 wp)
{
	auto& st = s_state;
	const auto& th = aida::ui::resolved();
	float ox = wp.x;
	float oy = wp.y;
	const float pad = 12.f;
	const float dt = aida::ui::clock::dt();

	float cy = oy + pos_y + 6.f;
	float cx = ox + pos_x + pad;

	const float toolbar_h = 38.f;
	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox + pos_x, cy), ImVec2(ox + pos_x + w, cy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox + pos_x, cy + toolbar_h - 1.f), ImVec2(ox + pos_x + w, cy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	bool scanning = stealth_engine::g_scan.scanning.load();

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 8.f));
	if (!scanning) {
		if (aida::ui::button("Scan", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(76.f, 28.f))) {
			stealth_engine::run_protection_scan();
		}
	} else {
		if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(76.f, 28.f))) {
			stealth_engine::stop_protection_scan();
		}
	}
	ImGui::SameLine();
	if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(76.f, 28.f))) {
		std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
		stealth_engine::g_scan.findings.clear();
		stealth_engine::g_scan.scan_status.clear();
		st.selected_finding = -1;
	}
	ImGui::SameLine();
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	const char* sev_items[] = {"All Severity", "Critical", "High", "Medium", "Low", "Info"};
	ImGui::PushItemWidth(120.f);
	int sev_sel = st.severity_filter + 1;
	if (ImGui::Combo("##sev_combo", &sev_sel, sev_items, 6))
		st.severity_filter = sev_sel - 1;
	ImGui::PopItemWidth();
	ImGui::SameLine();
	const char* cat_items[] = {"All Categories", "AC Driver", "Memory Guard", "Suspicious Module",
							   "Thread", "Debug State", "Hook", "WFP Callback"};
	ImGui::PushItemWidth(150.f);
	int cat_sel = st.category_filter + 1;
	if (ImGui::Combo("##cat_combo", &cat_sel, cat_items, 8))
		st.category_filter = cat_sel - 1;
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(2);
	ImGui::PopStyleVar();

	if (scanning) {
		ImGui::SameLine();
		float prog = stealth_engine::g_scan.progress.load();
		ImVec2 cp = ImGui::GetCursorScreenPos();
		aida::ui::components::render_progress_ring(ImVec2(cp.x + 8.f, cy + 17.f), 9.f, 2.f, prog, false);
		ImGui::Dummy(ImVec2(28.f, 0.f));
		ImGui::SameLine();
		std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			11.f, ImVec2(ImGui::GetCursorScreenPos().x, cy + 13.f),
			aida::ui::with_alpha(th.text_dim, alpha),
			stealth_engine::g_scan.scan_status.c_str());
	}

	cy += toolbar_h + 6.f;

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

	const float row_h = 30.f;
	const float bottom_h = 64.f;
	const float table_top = cy;
	const float table_h = oy + pos_y + h - cy - 8.f - bottom_h;

	float col_sev_w = 76.f;
	float col_cat_w = 130.f;
	float col_addr_w = 144.f;
	float col_title_w = w * 0.25f;
	float col_detail_w = w - col_sev_w - col_cat_w - col_addr_w - col_title_w - pad * 2.f - 14.f;
	if (col_detail_w < 60.f) col_detail_w = 60.f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(ox + pos_x + w - pad, cy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(cx, cy + row_h - 1.f), ImVec2(ox + pos_x + w - pad, cy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
	float hx = cx + 6.f;
	dl->AddText(head_em, 13.f, ImVec2(hx, cy + 8.f), hc, "Severity");
	hx += col_sev_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, cy + 8.f), hc, "Category");
	hx += col_cat_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, cy + 8.f), hc, "Address");
	hx += col_addr_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, cy + 8.f), hc, "Finding");
	hx += col_title_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, cy + 8.f), hc, "Details");
	cy += row_h + 2.f;

	float content_h = static_cast<float>(filtered.size()) * row_h;
	float visible_h = table_h - row_h - 2.f;
	if (visible_h < 0.f) visible_h = 0.f;

	float wheel = 0.f;
	if (ImGui::IsMouseHoveringRect(ImVec2(cx, cy), ImVec2(ox + pos_x + w - pad, cy + visible_h))) {
		wheel = ImGui::GetIO().MouseWheel;
	}
	if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
	if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
	float ms = std::max(0.f, content_h - visible_h);
	if (st.target_scroll_y > ms) st.target_scroll_y = ms;
	st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

	ImGui::PushClipRect(ImVec2(ox + pos_x, cy), ImVec2(ox + pos_x + w - pad - 6.f, oy + pos_y + h - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(filtered.size())) last_vis = static_cast<int>(filtered.size());

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + pos_y + h) continue;

		auto& f = filtered[static_cast<size_t>(i)];
		ImVec2 rmin(cx, ry);
		ImVec2 rmax(ox + pos_x + w - pad, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_finding == i);

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			st.selected_finding = selected ? -1 : i;

		float entrance_delay = std::min(static_cast<float>(i - first_vis) * 0.012f, 0.240f);
		float entrance_t = (st.anim_t - entrance_delay) / 0.32f;
		if (entrance_t < 0.f) entrance_t = 0.f;
		if (entrance_t > 1.f) entrance_t = 1.f;
		float entrance = aida::motion::ease::out_cubic(entrance_t);

		ImU32 row_fill;
		if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
		else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
		else row_fill = (i & 1) ? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f * entrance) : 0u;
		if ((row_fill & 0xFF000000) != 0) {
			dl->AddRectFilled(rmin, rmax, row_fill, 4.f);
		}
		if (selected) {
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		}

		if (f.severity == stealth_engine::finding_severity_t::critical) {
			float pulse = (sinf(st.anim_t * 3.f + static_cast<float>(i) * 0.7f) + 1.f) * 0.5f;
			ImU32 glow = aida::ui::with_alpha(th.error, alpha * (0.18f + pulse * 0.22f));
			dl->AddRectFilled(rmin, rmax, glow, 4.f);
		} else if (f.severity == stealth_engine::finding_severity_t::high) {
			float pulse = (sinf(st.anim_t * 2.2f + static_cast<float>(i) * 0.5f) + 1.f) * 0.5f;
			ImU32 glow = aida::ui::with_alpha(th.warning, alpha * (0.08f + pulse * 0.12f));
			dl->AddRectFilled(rmin, rmax, glow, 4.f);
		}

		float rx = cx + 6.f;
		ImGui::SetCursorScreenPos(ImVec2(rx, ry + 3.f));
		aida::ui::pill_kind(stealth_engine::severity_name(f.severity), severity_pill(f.severity),
			aida::ui::size_t_::sm, true);
		rx = cx + col_sev_w + 4.f;

		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			13.f, ImVec2(rx, ry + 8.f),
			aida::ui::with_alpha(th.text_secondary, alpha * entrance),
			stealth_engine::category_name(f.category));
		rx += col_cat_w;

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		if (f.address != 0) {
			char addr_buf[24];
			std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
				static_cast<unsigned long long>(f.address));
			dl->AddText(code_font, 13.f, ImVec2(rx, ry + 8.f),
				aida::ui::with_alpha(th.text_address, alpha * entrance), addr_buf);
		}
		rx += col_addr_w;

		std::string title = f.title;
		if (title.size() > 40) title = title.substr(0, 38) + "..";
		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			13.f, ImVec2(rx, ry + 8.f),
			aida::ui::with_alpha(th.text_primary, alpha * entrance), title.c_str());
		rx += col_title_w;

		std::string det = f.detail;
		if (det.size() > 60) det = det.substr(0, 58) + "..";
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			13.f, ImVec2(rx, ry + 8.f),
			aida::ui::with_alpha(th.text_secondary, alpha * entrance), det.c_str());
	}

	ImGui::PopClipRect();

	if (content_h > visible_h && visible_h > 0.f) {
		float bar_x = ox + pos_x + w - pad - 8.f;
		float bar_y = cy;
		float bar_h = visible_h;
		float ratio = visible_h / content_h;
		float thumb_h = std::max(bar_h * ratio, 24.f);
		float track = bar_h - thumb_h;
		float scroll_ratio = (content_h - visible_h > 0.f) ? st.scroll_y / (content_h - visible_h) : 0.f;
		float thumb_y = bar_y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 6.f, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 6.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
	}

	if (filtered.empty() && !scanning) {
		std::lock_guard<std::mutex> lk(stealth_engine::g_scan.mutex);
		if (stealth_engine::g_scan.findings.empty()) {
			ImVec2 e_pos = ImVec2(ox + pos_x, table_top);
			ImVec2 e_sz = ImVec2(w, table_h);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "No findings yet";
			cfg.body = "Click Scan to analyze the attached process for protection mechanisms.";
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(e_pos, e_sz, cfg);
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

		float card_y = oy + pos_y + h - bottom_h;
		ImVec2 c_a = ImVec2(ox + pos_x + 8.f, card_y);
		ImVec2 c_b = ImVec2(ox + pos_x + w - 8.f, card_y + bottom_h - 8.f);
		aida::ui::blur::render_glass_fill(dl, c_a, c_b, 8.f, alpha);
		aida::ui::blur::render_glass_border(dl, c_a, c_b, 8.f, alpha, 1.f);

		float card_w = (w - 16.f) / 5.f;
		float sx = c_a.x + 4.f;
		float sy = c_a.y + 6.f;

		auto draw_count = [&](const char* label, int v, ImU32 col) {
			ImVec2 ba = ImVec2(sx, sy);
			ImVec2 bb = ImVec2(sx + card_w - 6.f, sy + bottom_h - 18.f);
			dl->AddRectFilled(ba, bb, aida::ui::with_alpha(th.panel_header, alpha * 0.45f), 6.f);
			dl->AddRect(ba, bb, aida::ui::with_alpha(th.border_subtle, alpha), 6.f, 0, 1.f);
			ImFont* num = aida::ui::fonts::body_strong();
			if (!num) num = ImGui::GetFont();
			char vbuf[16];
			std::snprintf(vbuf, sizeof(vbuf), "%d", v);
			dl->AddText(num, 18.f, ImVec2(ba.x + 10.f, ba.y + 4.f), col, vbuf);
			dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
				10.f, ImVec2(ba.x + 10.f, ba.y + 26.f),
				aida::ui::with_alpha(th.text_dim, alpha), label);
			sx += card_w;
		};

		int total = static_cast<int>(filtered.size());
		draw_count("Findings", total, aida::ui::with_alpha(th.text_primary, alpha));
		draw_count("Critical", crit, aida::ui::with_alpha(th.error, alpha));
		draw_count("High",     hi,   aida::ui::with_alpha(th.warning, alpha));
		draw_count("Medium",   med,  aida::ui::with_alpha(th.warning, alpha * 0.85f));
		draw_count("Low",      lo,   aida::ui::with_alpha(th.success, alpha));
	} else {
		float card_y = oy + pos_y + h - bottom_h;
		ImVec2 c_a = ImVec2(ox + pos_x + 8.f, card_y);
		ImVec2 c_b = ImVec2(ox + pos_x + w - 8.f, card_y + bottom_h - 8.f);
		aida::ui::blur::render_glass_fill(dl, c_a, c_b, 8.f, alpha * 0.5f);
		aida::ui::blur::render_glass_border(dl, c_a, c_b, 8.f, alpha * 0.5f, 1.f);
		ImFont* font = aida::ui::fonts::body();
		if (!font) font = ImGui::GetFont();
		const char* msg = "Run a scan to see summary";
		ImVec2 sz = font->CalcTextSizeA(12.f, FLT_MAX, 0.f, msg);
		dl->AddText(font, 13.f,
			ImVec2(c_a.x + (c_b.x - c_a.x - sz.x) * 0.5f,
				   c_a.y + (c_b.y - c_a.y - sz.y) * 0.5f),
			aida::ui::with_alpha(th.text_dim, alpha), msg);
	}
}

inline void render_stealth_controls(float pos_x, float pos_y, float w, float h,
                                     float alpha, ImDrawList* dl, ImVec2 wp)
{
	auto& st = s_state;
	const auto& th = aida::ui::resolved();
	float ox = wp.x;
	float oy = wp.y;
	const float pad = 12.f;

	float cy = oy + pos_y + 6.f;
	float cx = ox + pos_x + pad;

	const float toolbar_h = 86.f;
	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox + pos_x, cy), ImVec2(ox + pos_x + w, cy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox + pos_x, cy + toolbar_h - 1.f), ImVec2(ox + pos_x + w, cy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float ty = cy + 8.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushItemWidth(150.f);
	ImGui::InputTextWithHint("##stealth_pid", "Target PID", st.pid_input, sizeof(st.pid_input),
		ImGuiInputTextFlags_CharsDecimal);
	ImGui::PopItemWidth();
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);

	ImGui::SameLine();
	bool stealth_active = stealth_engine::is_active();

	if (!stealth_active) {
		if (aida::ui::button("Start Stealth", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(120.f, 28.f))) {
			uint32_t pid = 0;
			if (st.pid_input[0])
				pid = static_cast<uint32_t>(std::strtoul(st.pid_input, nullptr, 10));
			if (pid == 0) pid = driver_bridge::attached_pid();
			if (pid != 0) stealth_engine::enable_stealth(pid);
		}
	} else {
		if (aida::ui::button("Stop Stealth", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(120.f, 28.f))) {
			stealth_engine::disable_stealth();
		}
	}

	ty += 26.f;
	{
		std::string status_str = stealth_engine::get_status();
		if (!status_str.empty()) {
			ImU32 sc = stealth_active
				? aida::ui::with_alpha(th.success, alpha)
				: aida::ui::with_alpha(th.text_dim, alpha);
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				11.f, ImVec2(cx, ty), sc, status_str.c_str());
		}
	}

	ty += 18.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, ty));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.accent_u32, alpha)));
	ImGui::Checkbox("Spoof PEB Flags##stealth", &st.opt_peb);
	ImGui::SameLine();
	ImGui::Checkbox("Hook RDTSC##stealth", &st.opt_rdtsc);
	ImGui::SameLine();
	ImGui::Checkbox("Scrub Debug Context##stealth", &st.opt_context);
	ImGui::PopStyleColor(2);

	cy += toolbar_h + 6.f;
	float hy = cy;

	const float row_h = 28.f;
	std::vector<stealth_engine::hook_entry_t> hooks_copy;
	bool peb_ok = false;
	bool rdtsc_ok = false;
	uint32_t session_pid = 0;
	{
		std::lock_guard<std::mutex> lk(stealth_engine::g_state.mutex);
		hooks_copy = stealth_engine::g_state.session.hooks;
		peb_ok = stealth_engine::g_state.session.peb_spoofed;
		rdtsc_ok = stealth_engine::g_state.session.rdtsc_hooked;
		session_pid = stealth_engine::g_state.session.pid;
	}

	const float col_target_w = 170.f;
	const float col_tramp_w  = 170.f;
	const float col_size_w   = 70.f;
	const float col_peb_w    = 70.f;
	const float col_active_w = 80.f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(cx, hy), ImVec2(ox + pos_x + w - pad, hy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(cx, hy + row_h - 1.f), ImVec2(ox + pos_x + w - pad, hy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
	float hx = cx + 6.f;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Target Address");
	hx += col_target_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Trampoline");
	hx += col_tramp_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Size");
	hx += col_size_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "PEB");
	hx += col_peb_w;
	dl->AddText(head_em, 13.f, ImVec2(hx, hy + 7.f), hc, "Active");
	hy += row_h;

	int total_rows = static_cast<int>(hooks_copy.size());
	if (total_rows == 0 && stealth_active) {
		float card_y = hy + 8.f;
		float card_w = (w - pad * 2.f - 8.f) / 3.f;
		float sx = cx;

		auto draw_card = [&](const char* lbl, const char* val, ImU32 col) {
			ImVec2 ba = ImVec2(sx, card_y);
			ImVec2 bb = ImVec2(sx + card_w - 4.f, card_y + 44.f);
			aida::ui::blur::render_glass_fill(dl, ba, bb, 8.f, alpha);
			aida::ui::blur::render_glass_border(dl, ba, bb, 8.f, alpha, 1.f);
			ImFont* num = aida::ui::fonts::body_strong();
			if (!num) num = ImGui::GetFont();
			dl->AddText(num, 18.f, ImVec2(ba.x + 12.f, ba.y + 4.f), col, val);
			dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
				10.f, ImVec2(ba.x + 12.f, ba.y + 28.f),
				aida::ui::with_alpha(th.text_dim, alpha), lbl);
			sx += card_w;
		};

		char b_pid[16];
		std::snprintf(b_pid, sizeof(b_pid), "%u", session_pid);
		draw_card("Target PID", b_pid, aida::ui::with_alpha(th.accent_u32, alpha));
		draw_card("PEB Spoofed", peb_ok ? "Active" : "Inactive",
			peb_ok ? aida::ui::with_alpha(th.success, alpha) : aida::ui::with_alpha(th.error, alpha));
		draw_card("RDTSC Hook", rdtsc_ok ? "Active" : "Inactive",
			rdtsc_ok ? aida::ui::with_alpha(th.success, alpha) : aida::ui::with_alpha(th.error, alpha));
	}

	for (int i = 0; i < total_rows; ++i) {
		float ry = hy + static_cast<float>(i) * row_h;
		if (ry > oy + pos_y + h) break;

		auto& hook = hooks_copy[static_cast<size_t>(i)];
		bool hovered = ImGui::IsMouseHoveringRect(
			ImVec2(cx, ry), ImVec2(ox + pos_x + w - pad, ry + row_h));
		ImU32 row_fill = hovered
			? aida::ui::with_alpha(th.hover_wash, alpha)
			: ((i & 1) ? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f) : 0u);
		if ((row_fill & 0xFF000000) != 0) {
			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(ox + pos_x + w - pad, ry + row_h),
				row_fill, 4.f);
		}

		float rx = cx + 6.f;
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		char addr_buf[24];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
			static_cast<unsigned long long>(hook.target_addr));
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_address, alpha), addr_buf);
		rx += col_target_w;

		char tramp_buf[24];
		std::snprintf(tramp_buf, sizeof(tramp_buf), "0x%llX",
			static_cast<unsigned long long>(hook.trampoline_addr));
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha), tramp_buf);
		rx += col_tramp_w;

		char size_buf[8];
		std::snprintf(size_buf, sizeof(size_buf), "%d", hook.hook_size);
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_primary, alpha), size_buf);
		rx += col_size_w;

		ImU32 peb_col = peb_ok
			? aida::ui::with_alpha(th.success, alpha)
			: aida::ui::with_alpha(th.error, alpha);
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f), peb_col, peb_ok ? "yes" : "no");
		rx += col_peb_w;

		ImU32 dot_col = hook.active
			? aida::ui::with_alpha(th.success, alpha)
			: aida::ui::with_alpha(th.error, alpha);
		aida::ui::components::status_dot(ImVec2(rx + 6.f, ry + row_h * 0.5f), 3.f,
			dot_col, hook.active, 1.4f);
		dl->AddText(code_font, 13.f, ImVec2(rx + 18.f, ry + 7.f),
			dot_col, hook.active ? "active" : "removed");
		(void)col_active_w;
	}

	if (total_rows == 0 && !stealth_active) {
		ImVec2 e_pos = ImVec2(ox + pos_x, hy + 6.f);
		ImVec2 e_sz = ImVec2(w, oy + pos_y + h - hy - 14.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::shield;
		cfg.title = "Stealth idle";
		cfg.body = "Attach a process and press Start Stealth to install anti-debug hooks.";
		cfg.max_width = 360.f;
		aida::ui::empty_state::render(e_pos, e_sz, cfg);
	}
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##protection_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
	st.anim_t += dt;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(th.bg_base, alpha));

	const int subtab_count = static_cast<int>(sizeof(s_subtabs) / sizeof(s_subtabs[0]));
	aida::ui::hub_strip::render_strip(dl, wp, pos_x, pos_y, w,
		s_subtabs, subtab_count, st.strip, alpha);
	aida::ui::hub_strip::tick_swap(st.strip, dt);

	const float tab_h = 30.f;
	float content_pos_y = pos_y + tab_h + 2.f;
	float content_h = h - tab_h - 2.f;
	if (content_h < 1.f) {
		ImGui::EndChild();
		return;
	}

	int prev_idx = st.strip.prev;
	int new_idx  = st.strip.active;

	auto render_tab = [&](int idx) {
		if (idx == 0) render_protection_scan(pos_x, content_pos_y, w, content_h, alpha, dl, wp);
		else          render_stealth_controls(pos_x, content_pos_y, w, content_h, alpha, dl, wp);
	};

	if (!st.strip.swap_pending) {
		render_tab(new_idx);
	} else {
		float p = aida::ui::hub_strip::ease_out_cubic(st.strip.swap_progress);
		float slide = w * 0.06f * st.strip.direction_sign;
		float prev_off = -slide * p;
		float new_off  = slide * (1.f - p);

		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * (1.f - p));
		render_tab(prev_idx);
		ImGui::PopStyleVar();
		(void)prev_off; (void)new_off;
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * p);
		render_tab(new_idx);
		ImGui::PopStyleVar();
	}

	ImGui::EndChild();
}

}
