#pragma once

#include "stealth_engine.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
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
	switch (s) {
	case stealth_engine::finding_severity_t::critical: return IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
	case stealth_engine::finding_severity_t::high:     return IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
	case stealth_engine::finding_severity_t::medium:   return IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	case stealth_engine::finding_severity_t::low:      return IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
	case stealth_engine::finding_severity_t::info:     return IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
	}
	return IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
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

	const ImU32 bg         = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col   = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col    = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                   static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg  = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 row_even   = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd    = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover  = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 sel_col    = IM_COL32(60, 60, 80, static_cast<int>(alpha * 255));
	const ImU32 green_col  = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 red_col    = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h), bg);

	const float pad = 12.f;
	float cx = ox + pad;
	float cy = oy + 6.f;

	const char* tab_names[] = {"Protection Scan", "Stealth Controls"};
	float tab_x = cx;
	for (int ti = 0; ti < 2; ++ti) {
		ImVec2 tsz = ImGui::CalcTextSize(tab_names[ti]);
		float tab_w = tsz.x + 20.f;
		bool hovered = ImGui::IsMouseHoveringRect(ImVec2(tab_x, cy), ImVec2(tab_x + tab_w, cy + 24.f));
		bool active_tab = (st.active_sub_tab == ti);

		if (active_tab) {
			dl->AddRectFilled(ImVec2(tab_x, cy), ImVec2(tab_x + tab_w, cy + 24.f),
				IM_COL32(static_cast<int>(accent_r * 60), static_cast<int>(accent_g * 60),
				         static_cast<int>(accent_b * 60), static_cast<int>(alpha * 200)), 3.f);
			dl->AddLine(ImVec2(tab_x, cy + 23.f), ImVec2(tab_x + tab_w, cy + 23.f), accent_col, 2.f);
		} else if (hovered) {
			dl->AddRectFilled(ImVec2(tab_x, cy), ImVec2(tab_x + tab_w, cy + 24.f),
				IM_COL32(50, 50, 50, static_cast<int>(alpha * 150)), 3.f);
		}

		dl->AddText(ImVec2(tab_x + 10.f, cy + 4.f), active_tab ? accent_col : dim_col, tab_names[ti]);

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			st.active_sub_tab = ti;

		tab_x += tab_w + 4.f;
	}

	cy += 30.f;

	dl->AddLine(ImVec2(ox, cy), ImVec2(ox + w, cy), IM_COL32(60, 60, 60, static_cast<int>(alpha * 200)));
	cy += 4.f;

	if (st.active_sub_tab == 0) {
		float toolbar_top = cy;
		dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + w, cy + 34.f), header_bg);

		ImGui::SetCursorScreenPos(ImVec2(cx, cy + 5.f));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

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

		ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
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
		ImGui::PopStyleColor(2);

		if (scanning) {
			ImGui::SameLine();
			float prog = stealth_engine::g_scan.progress.load();
			ui_anim::render_progress_ring(dl, ImGui::GetCursorScreenPos().x + 8.f,
				cy + 17.f, 7.f, 2.f, accent_col, st.anim_t, prog);
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
		const float table_top = cy;
		const float table_h = oy + h - cy - 8.f;

		float col_sev_w = 70.f;
		float col_cat_w = 120.f;
		float col_addr_w = 140.f;
		float col_title_w = w * 0.25f;
		float col_detail_w = w - col_sev_w - col_cat_w - col_addr_w - col_title_w - pad * 2.f - 14.f;
		if (col_detail_w < 60.f) col_detail_w = 60.f;

		float hx = cx;
		dl->AddRectFilled(ImVec2(hx, cy), ImVec2(ox + w - pad, cy + row_h), header_bg);
		dl->AddText(ImVec2(hx + 4.f, cy + 4.f), text_col, "Severity");
		hx += col_sev_w;
		dl->AddText(ImVec2(hx + 4.f, cy + 4.f), text_col, "Category");
		hx += col_cat_w;
		dl->AddText(ImVec2(hx + 4.f, cy + 4.f), text_col, "Address");
		hx += col_addr_w;
		dl->AddText(ImVec2(hx + 4.f, cy + 4.f), text_col, "Finding");
		hx += col_title_w;
		dl->AddText(ImVec2(hx + 4.f, cy + 4.f), text_col, "Details");

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

			dl->AddRectFilled(rmin, rmax,
				selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd)));

			float row_anim = ui_anim::ease_out_cubic(
				std::min(1.f, (st.anim_t - static_cast<float>(i) * 0.02f) * 3.f));
			float row_alpha = alpha * std::max(0.f, std::min(1.f, row_anim));

			float rx = cx + 4.f;

			const char* sev_str = stealth_engine::severity_name(f.severity);
			ImVec2 sev_sz = ImGui::CalcTextSize(sev_str);
			float badge_w = sev_sz.x + 10.f;
			dl->AddRectFilled(ImVec2(rx, ry + 3.f), ImVec2(rx + badge_w, ry + row_h - 3.f),
				severity_color(f.severity, row_alpha), 3.f);
			dl->AddText(ImVec2(rx + 5.f, ry + 4.f),
				severity_text_color(f.severity, row_alpha), sev_str);
			rx = cx + col_sev_w + 4.f;

			dl->AddText(ImVec2(rx, ry + 4.f),
				IM_COL32(170, 170, 170, static_cast<int>(row_alpha * 255)),
				stealth_engine::category_name(f.category));
			rx += col_cat_w;

			if (f.address != 0) {
				char addr_buf[20];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(f.address));
				dl->AddText(ImVec2(rx, ry + 4.f),
					IM_COL32(229, 192, 123, static_cast<int>(row_alpha * 255)),
					addr_buf);
			}
			rx += col_addr_w;

			dl->AddText(ImVec2(rx, ry + 4.f),
				IM_COL32(212, 212, 212, static_cast<int>(row_alpha * 255)),
				f.title.c_str(),
				f.title.c_str() + std::min(f.title.size(), static_cast<size_t>(40)));
			rx += col_title_w;

			dl->AddText(ImVec2(rx, ry + 4.f),
				IM_COL32(140, 140, 140, static_cast<int>(row_alpha * 255)),
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
				const char* hint = "Click Scan to analyze the attached process for protection mechanisms.";
				ImVec2 hs = ImGui::CalcTextSize(hint);
				float hint_y = table_top + (table_h - ImGui::GetTextLineHeight()) * 0.5f;
				dl->AddText(ImVec2(ox + (w - hs.x) * 0.5f, hint_y), dim_col, hint);
			}
		}

		if (!scanning && !filtered.empty()) {
			int crit = 0, hi = 0, med = 0, lo = 0;
			for (auto& f : filtered) {
				switch (f.severity) {
				case stealth_engine::finding_severity_t::critical: ++crit; break;
				case stealth_engine::finding_severity_t::high:     ++hi; break;
				case stealth_engine::finding_severity_t::medium:   ++med; break;
				case stealth_engine::finding_severity_t::low:      ++lo; break;
				default: break;
				}
			}
			char summary[128];
			std::snprintf(summary, sizeof(summary), "%zu findings  |  %d critical  %d high  %d med  %d low",
				filtered.size(), crit, hi, med, lo);
			dl->AddText(ImVec2(ox + w - 350.f, oy + h - 18.f), dim_col, summary);
		}
	}
	else {
		float toolbar_top = cy;
		dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + w, cy + 80.f), header_bg);

		float tx = cx;
		float ty = cy + 8.f;

		ImGui::SetCursorScreenPos(ImVec2(tx, ty));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
		ImGui::PushItemWidth(140.f);
		ImGui::InputTextWithHint("##stealth_pid", "Target PID (decimal)", st.pid_input, sizeof(st.pid_input),
			ImGuiInputTextFlags_CharsDecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine();
		ImGui::PopStyleColor(2);

		bool stealth_active = stealth_engine::is_active();

		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

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
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
		ImGui::Checkbox("Spoof PEB Flags##stealth", &st.opt_peb);
		ImGui::SameLine();
		ImGui::Checkbox("Hook RDTSC##stealth", &st.opt_rdtsc);
		ImGui::SameLine();
		ImGui::Checkbox("Scrub Debug Context##stealth", &st.opt_context);
		ImGui::PopStyleColor();

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

		dl->AddRectFilled(ImVec2(hx, hy), ImVec2(ox + w - pad, hy + row_h), header_bg);
		float hdr_x = hx + 4.f;
		dl->AddText(ImVec2(hdr_x, hy + 3.f), text_col, "Target Address");
		hdr_x += col_target_w;
		dl->AddText(ImVec2(hdr_x, hy + 3.f), text_col, "Trampoline");
		hdr_x += col_tramp_w;
		dl->AddText(ImVec2(hdr_x, hy + 3.f), text_col, "Size");
		hdr_x += col_size_w;
		dl->AddText(ImVec2(hdr_x, hy + 3.f), text_col, "PEB");
		hdr_x += col_peb_w;
		dl->AddText(ImVec2(hdr_x, hy + 3.f), text_col, "Active");

		hy += row_h;

		int total_rows = static_cast<int>(hooks_copy.size());

		if (total_rows == 0 && stealth_active) {
			char summary[128];
			std::snprintf(summary, sizeof(summary),
				"PID: %u  |  PEB spoofed: %s  |  RDTSC hooks: %s",
				session_pid, peb_ok ? "yes" : "no", rdtsc_ok ? "yes" : "no");
			dl->AddText(ImVec2(hx + 4.f, hy + (row_h - ImGui::GetTextLineHeight()) * 0.5f),
				dim_col, summary);
		}

		for (int i = 0; i < total_rows; ++i) {
			float ry = hy + static_cast<float>(i) * row_h;
			if (ry > oy + h) break;

			auto& hook = hooks_copy[static_cast<size_t>(i)];

			bool hovered = ImGui::IsMouseHoveringRect(
				ImVec2(hx, ry), ImVec2(ox + w - pad, ry + row_h));

			dl->AddRectFilled(ImVec2(hx, ry), ImVec2(ox + w - pad, ry + row_h),
				hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd));

			float rx = hx + 4.f;
			float yt = ry + (row_h - ImGui::GetTextLineHeight()) * 0.5f;

			char addr_buf[20];
			std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
				static_cast<unsigned long long>(hook.target_addr));
			dl->AddText(ImVec2(rx, yt),
				IM_COL32(229, 192, 123, static_cast<int>(alpha * 255)), addr_buf);
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

			dl->AddText(ImVec2(rx, yt), hook.active ? green_col : red_col,
				hook.active ? "active" : "removed");
		}

		if (total_rows == 0 && !stealth_active) {
			const char* hint = "Attach a process and press Start Stealth to install anti-debug hooks.";
			ImVec2 hs = ImGui::CalcTextSize(hint);
			float table_h = oy + h - cy - 8.f;
			dl->AddText(ImVec2(ox + (w - hs.x) * 0.5f,
				cy + (table_h - ImGui::GetTextLineHeight()) * 0.5f), dim_col, hint);
		}
	}

	ImGui::EndChild();
}

}
