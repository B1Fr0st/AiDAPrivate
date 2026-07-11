#pragma once

#include "integrity_hunter.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "pseudocode_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "disasm_view.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace integrity_hunter_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_node = -1;
	uint64_t selected_rip = 0;
	bool  show_event_log = false;
	float log_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	float anim_time = 0.f;
};

inline local_state_t s_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	const auto workspace_context = disasm_view::capture_selected_workspace();
	ImGui::BeginChild("##integrity_hunter_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& ih = integrity_hunter::g_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float cx = wp.x;
	float cy = wp.y;

	st.anim_time += ImGui::GetIO().DeltaTime;
	float dt = ImGui::GetIO().DeltaTime;

	const auto& _t = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return aida::ui::with_alpha(c, alpha);
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
	const ImU32 red_col   = _ta(_t.error);
	const ImU32 green_col = _ta(_t.success);
	const ImU32 yellow_col = _ta(_t.warning);

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 68.f;
	const float pad = 12.f;

	ui_anim::render_toolbar(dl, cx, cy, width, toolbar_h, accent_r, accent_g, accent_b, alpha);

	float tx = cx + pad;
	float ty = cy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(tx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

	ImGui::PushItemWidth(180.f);
	ImGui::InputTextWithHint("##ih_addr", "Target Address (hex)", ih.address_input, sizeof(ih.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(80.f);
	ImGui::InputTextWithHint("##ih_size", "Size", ih.size_input, sizeof(ih.size_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();

	ImGui::PopStyleColor(3); ImGui::PopStyleVar(2);

	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140), static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180), static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 220)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100), static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, static_cast<int>(alpha * 255)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);

	bool hunting = ih.hunting.load();

	if (!hunting) {
		if (ImGui::SmallButton("Start Hunt")) {
			uint64_t addr = 0;
			uint64_t sz = 4096;
			if (ih.address_input[0])
				addr = std::strtoull(ih.address_input, nullptr, 16);
			if (ih.size_input[0])
				sz = std::strtoull(ih.size_input, nullptr, 0);
			if (addr != 0) {
				integrity_hunter::start_hunt(addr, sz);
			}
		}
	} else {
		if (ImGui::SmallButton("Stop Hunt")) {
			integrity_hunter::stop_hunt();
		}
	}

	ImGui::SameLine();

	bool log_toggle = st.show_event_log;
	if (ImGui::SmallButton(log_toggle ? "Hide Log" : "Show Log")) {
		st.show_event_log = !st.show_event_log;
	}

	ImGui::PopStyleColor(4); ImGui::PopStyleVar();

	ty += 26.f;

	{
		std::string status;
		{
			std::lock_guard<std::mutex> lk(ih.mutex);
			status = ih.status_text;
		}
		if (!status.empty()) {
			dl->AddText(ImVec2(cx + pad, ty + 2.f), dim_col, status.c_str());
		}

		if (hunting) {
			uint64_t reads = ih.total_reads.load();
			char rbuf[64];
			std::snprintf(rbuf, sizeof(rbuf), "Total reads: %llu",
			              static_cast<unsigned long long>(reads));
			ImVec2 rs = ImGui::CalcTextSize(rbuf);
			dl->AddText(ImVec2(cx + width - pad - rs.x, ty + 2.f), accent, rbuf);
		}
	}

	float strip_y = cy + toolbar_h + 2.f;
	const float strip_h = 64.f;
	{
		int found = 0, neutralized_c = 0, active_c = 0;
		double avg_rps = 0.0;
		{
			std::lock_guard<std::mutex> lk(ih.mutex);
			found = static_cast<int>(ih.nodes.size());
			for (auto& n : ih.nodes) {
				if (n.neutralized) neutralized_c++;
				else active_c++;
				avg_rps += n.reads_per_second;
			}
			if (found > 0) avg_rps /= static_cast<double>(found);
		}
		char found_buf[16];
		char active_buf[16];
		char neut_buf[16];
		char rps_buf[24];
		std::snprintf(found_buf, sizeof(found_buf), "%d", found);
		std::snprintf(active_buf, sizeof(active_buf), "%d", active_c);
		std::snprintf(neut_buf, sizeof(neut_buf), "%d", neutralized_c);
		std::snprintf(rps_buf, sizeof(rps_buf), "%.1f/s", avg_rps);

		ImU32 active_col = active_c > 0 ? _t.error : _t.success;
		ImU32 neut_col   = neutralized_c > 0 ? _t.success : _t.text_secondary;

		ui_anim::stat_strip_item_t items[4];
		items[0] = { "Checkers",    found_buf,  nullptr, 0, nullptr, 0, 0 };
		items[1] = { "Active",      active_buf, nullptr, 0, nullptr, 0, active_col };
		items[2] = { "Neutralized", neut_buf,   nullptr, 0, nullptr, 0, neut_col };
		items[3] = { "Avg Rate",    rps_buf,    nullptr, 0, nullptr, 0, 0 };
		ui_anim::render_stat_strip(dl, cx + 6.f, strip_y + 4.f, width - 12.f, strip_h - 8.f,
			items, 4, accent_r, accent_g, accent_b, alpha);
	}

	float table_top = cy + toolbar_h + strip_h + 4.f;
	float log_h = st.show_event_log ? 160.f : 0.f;
	float table_h = height - toolbar_h - strip_h - 4.f - log_h;
	if (table_h < 100.f) table_h = 100.f;

	const float row_h = 22.f;
	float hx = cx + pad;
	float hy = table_top;

	const float col_rip_w = 140.f;
	const float col_module_w = 200.f;
	const float col_compare_w = 120.f;
	const float col_reads_w = 80.f;
	const float col_rps_w = 70.f;
	const float col_status_w = 80.f;
	const float col_actions_w = (std::max)(0.f, width - col_rip_w - col_module_w - col_compare_w -
	                             col_reads_w - col_rps_w - col_status_w - pad * 2.f);

	{
		ui_anim::table_col_t hdr_cols[] = {
			{"Reader RIP", col_rip_w}, {"Module", col_module_w}, {"Compare Addr", col_compare_w},
			{"Reads", col_reads_w}, {"R/s", col_rps_w}, {"Status", col_status_w}
		};
		ui_anim::render_table_header(dl, hx, hy, width - pad * 2.f, row_h, hdr_cols, 6, accent_r, accent_g, accent_b, alpha);
	}

	hy += row_h;

	std::vector<integrity_hunter::integrity_node_t> nodes_copy;
	{
		std::lock_guard<std::mutex> lk(ih.mutex);
		nodes_copy = ih.nodes;
	}

	int visible_rows = static_cast<int>((table_h - row_h) / row_h);
	int total_rows = static_cast<int>(nodes_copy.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(cx, table_top), ImVec2(cx + width, table_top + table_h))) {
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
		if (ry > table_top + table_h) break;

		auto& node = nodes_copy[static_cast<size_t>(i)];

		bool hovered = ImGui::IsMouseHoveringRect(
			ImVec2(hx, ry), ImVec2(hx + width - pad * 2.f, ry + row_h));
		bool selected = (st.selected_node == i);

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
			st.selected_node = i;
			st.selected_rip = node.reader_rip;
		}

		float col_x = hx + 4.f;

		char rip_buf[24];
		std::snprintf(rip_buf, sizeof(rip_buf), "0x%llX",
		              static_cast<unsigned long long>(node.reader_rip));
		dl->AddText(ImVec2(col_x, ry + 3.f), text_col, rip_buf);
		col_x += col_rip_w;

		std::string mod_display = node.module_name;
		if (mod_display.size() > 30) mod_display = mod_display.substr(0, 27) + "...";
		dl->AddText(ImVec2(col_x, ry + 3.f), dim_col, mod_display.c_str());
		col_x += col_module_w;

		if (node.hash_compare_addr != 0) {
			char cmp_buf[24];
			std::snprintf(cmp_buf, sizeof(cmp_buf), "0x%llX",
			              static_cast<unsigned long long>(node.hash_compare_addr));
			dl->AddText(ImVec2(col_x, ry + 3.f), yellow_col, cmp_buf);
		} else {
			dl->AddText(ImVec2(col_x, ry + 3.f), dim_col, "N/A");
		}
		col_x += col_compare_w;

		char reads_buf[16];
		std::snprintf(reads_buf, sizeof(reads_buf), "%d", node.read_count);
		dl->AddText(ImVec2(col_x, ry + 3.f), text_col, reads_buf);
		col_x += col_reads_w;

		char rps_buf[16];
		std::snprintf(rps_buf, sizeof(rps_buf), "%.1f", node.reads_per_second);
		dl->AddText(ImVec2(col_x, ry + 3.f), dim_col, rps_buf);
		col_x += col_rps_w;

		if (node.neutralized) {
			dl->AddText(ImVec2(col_x, ry + 3.f), green_col, "Patched");
		} else {
			dl->AddText(ImVec2(col_x, ry + 3.f), red_col, "Active");
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.selected_node = i;
			st.selected_rip = node.reader_rip;
			ImGui::OpenPopup("##ih_ctx");
		}
	}

	if (ImGui::BeginPopup("##ih_ctx")) {
		int live_idx = -1;
		integrity_hunter::integrity_node_t sel_node{};
		bool have_sel = false;
		{
			std::lock_guard<std::mutex> lk(ih.mutex);
			for (size_t k = 0; k < ih.nodes.size(); ++k) {
				if (ih.nodes[k].reader_rip == st.selected_rip) {
					live_idx = static_cast<int>(k);
					sel_node = ih.nodes[k];
					have_sel = true;
					break;
				}
			}
		}

		if (have_sel) {
			if (!sel_node.neutralized) {
				if (ImGui::MenuItem("Neutralize")) {
					integrity_hunter::neutralize(live_idx);
				}
			} else {
				if (ImGui::MenuItem("Restore Original")) {
					integrity_hunter::restore(live_idx);
				}
			}

			if (ImGui::MenuItem("Go to Disassembly")) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(sel_node.reader_rip, workspace_context);
			}

			if (ImGui::MenuItem("Decompile Reader")) {
				uint64_t entry = disasm_view::enclosing_function_start(sel_node.reader_rip, workspace_context);
				if (entry == 0) entry = sel_node.reader_rip;
				diag::log_tagged_critical_fmt("dec_ui", "integrity_reader_dispatched addr=0x%llX entry=0x%llX",
					static_cast<unsigned long long>(sel_node.reader_rip),
					static_cast<unsigned long long>(entry));
				pseudocode_view::request_decompile(workspace_context, entry, false);
			}
		}
		ImGui::EndPopup();
	}

	if (total_rows == 0) {
		const char* empty_desc = hunting
			? "Monitoring for integrity checker reads — trigger the target's verification path."
			: "Enter a code address and click Start Hunt to locate integrity checkers.";
		float cw = std::min(width - 40.f, 620.f);
		if (cw < 160.f) cw = std::max(160.f, width - 20.f);
		float ccx = cx + (width - cw) * 0.5f;
		float ccy = table_top + table_h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, ccx, ccy, cw, 52.f,
		    empty_desc,
		    hunting ? ui_anim::callout_kind_t::warn : ui_anim::callout_kind_t::info,
		    accent_r, accent_g, accent_b, alpha);
	}

	if (st.show_event_log && log_h > 0.f) {
		float log_top = table_top + table_h + 2.f;
		ui_anim::render_panel_card(dl, cx, log_top, width, log_h, accent_r, accent_g, accent_b, alpha, 0.f, true);
		dl->AddText(ImVec2(cx + pad, log_top + 2.f), text_col, "Event Log");

		float log_content_top = log_top + 20.f;
		float log_content_h = log_h - 22.f;

		std::vector<integrity_hunter::capture_event_t> events;
		{
			std::lock_guard<std::mutex> lk(ih.mutex);
			size_t start_idx = ih.event_log.size() > 100 ? ih.event_log.size() - 100 : 0;
			events.assign(ih.event_log.begin() + static_cast<ptrdiff_t>(start_idx), ih.event_log.end());
		}

		float ey = log_content_top;
		const float log_row_h = 16.f;
		int visible_log = static_cast<int>(log_content_h / log_row_h);
		int start_log = (std::max)(0, static_cast<int>(events.size()) - visible_log);

		for (int i = start_log; i < static_cast<int>(events.size()); ++i) {
			if (ey > log_top + log_h) break;
			auto& evt = events[static_cast<size_t>(i)];
			char line[128];
			std::snprintf(line, sizeof(line), "[%s] RIP=0x%llX  Addr=0x%llX",
			              evt.access_type == 0 ? "R" : "W",
			              static_cast<unsigned long long>(evt.rip),
			              static_cast<unsigned long long>(evt.fault_addr));
			dl->AddText(ImGui::GetFont(), 14.f, ImVec2(cx + pad, ey), dim_col, line);
			ey += log_row_h;
		}
	}

	ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, table_top + row_h, 6.f, table_h - row_h,
		st.scroll_y, static_cast<float>(total_rows) * row_h, table_h - row_h,
		alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);

	ImGui::EndChild();
}

}
