#pragma once

#include "symbolic_engine.hpp"
#include "work_queue.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

extern DisasmState g_disasm;

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace taint_view {

struct taint_node_t {
	uint64_t address = 0;
	std::string disasm;
	std::string source_regs;
	std::string dest_regs;
	bool is_source = false;
	bool is_sink = false;
	bool is_propagation = false;
};

struct local_state_t {
	char addr_buf[64] = "0x";
	char end_addr_buf[64] = "";
	char taint_regs_buf[128] = "rcx";
	char taint_mem_buf[64] = "";
	int max_insns = 10000;
	int selected_row = -1;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	float anim_time = 0.f;
	int view_mode = 0;
	float mode_crossfade = 1.f;
};

static local_state_t s_state;

namespace detail {

inline std::vector<std::string> parse_list(const char* buf) {
	std::vector<std::string> items;
	std::string s(buf);
	size_t pos = 0;
	while (pos < s.size()) {
		size_t comma = s.find(',', pos);
		if (comma == std::string::npos) comma = s.size();
		std::string item = s.substr(pos, comma - pos);
		while (!item.empty() && item.front() == ' ') item.erase(item.begin());
		while (!item.empty() && item.back() == ' ') item.pop_back();
		if (!item.empty()) items.push_back(item);
		pos = comma + 1;
	}
	return items;
}

inline void start_taint_trace(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t end = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	auto regs = parse_list(st.taint_regs_buf);

	std::vector<std::pair<uint64_t, uint32_t>> mem_ranges;
	if (st.taint_mem_buf[0]) {
		uint64_t mem_addr = std::strtoull(st.taint_mem_buf, nullptr, 16);
		if (mem_addr != 0) {
			mem_ranges.push_back({mem_addr, 64});
		}
	}

	symbolic_engine::g_state.processing.store(true);
	work_queue::post([addr, end, max_i = static_cast<uint32_t>(st.max_insns), regs, mem_ranges]() {
		auto result = symbolic_engine::taint_trace(addr, end, max_i, regs, mem_ranges);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_taint = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	});
}

inline std::vector<taint_node_t> build_taint_flow(const symbolic_engine::taint_result_t& res,
                                                   const std::vector<std::string>& source_regs) {
	std::vector<taint_node_t> nodes;

	for (auto& insn : res.tainted_instructions) {
		taint_node_t node;
		node.address = insn.address;
		node.disasm = insn.disasm;

		for (auto& r : insn.read_regs) node.source_regs += r + " ";
		for (auto& r : insn.written_regs) node.dest_regs += r + " ";

		bool reads_source = false;
		for (auto& r : insn.read_regs) {
			std::string rl = r;
			std::transform(rl.begin(), rl.end(), rl.begin(), ::tolower);
			for (auto& s : source_regs) {
				std::string sl = s;
				std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
				if (rl == sl) { reads_source = true; break; }
			}
			if (reads_source) break;
		}

		if (reads_source && insn.written_regs.empty()) node.is_sink = true;
		else if (reads_source) node.is_source = true;
		else node.is_propagation = true;

		nodes.push_back(std::move(node));
	}

	return nodes;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImGui::BeginChild("##taint_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

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
	const ImU32 source_col = IM_COL32(86, 182, 194, static_cast<int>(alpha * 255));
	const ImU32 prop_col   = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
	const ImU32 sink_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 green_col  = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 72.f;
	const float pad = 10.f;
	const float row_h = 20.f;
	const float btn_h = 28.f;

	ui_anim::render_toolbar(dl, cx, cy, width, toolbar_h, accent_r, accent_g, accent_b, alpha);

	ImGui::PushItemWidth(140.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Start");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::InputText("##taint_addr", st.addr_buf, sizeof(st.addr_buf));

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("End");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::InputText("##taint_end", st.end_addr_buf, sizeof(st.end_addr_buf));

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Taint Regs");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::InputText("##taint_regs", st.taint_regs_buf, sizeof(st.taint_regs_buf));

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Mem");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::SetNextItemWidth(120.f);
	ImGui::InputText("##taint_mem", st.taint_mem_buf, sizeof(st.taint_mem_buf));

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
	ImGui::PopItemWidth();

	float btn_y = cy + pad + 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_y));

	bool busy = symbolic_engine::g_state.processing.load();

	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	if (busy) {
		ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, _ta(_t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, _ta(_t.panel_header));
	} else {
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140),
			static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
			static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 240)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100),
			static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
	}

	if (ImGui::Button("Start Trace", ImVec2(110.f, btn_h)) && !busy) {
		detail::start_taint_trace(st);
	}

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar();

	if (busy) {
		ImGui::SameLine();
		uint32_t cur = symbolic_engine::g_state.progress_current.load();
		uint32_t tot = symbolic_engine::g_state.progress_total.load();
		if (tot > 0) {
			float frac = static_cast<float>(cur) / static_cast<float>(tot);
			float pb_x = ImGui::GetCursorScreenPos().x;
			float pb_y = btn_y + 4.f;
			ui_anim::render_progress_bar_animated(dl, pb_x, pb_y, 200.f, 20.f, frac,
				accent_r, accent_g, accent_b, alpha, st.anim_time);
			ImGui::Dummy(ImVec2(200.f, 20.f));
		}
	}

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Max");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::SetNextItemWidth(100.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, accent);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::SliderInt("##taint_max", &st.max_insns, 100, 100000);
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(2);

	ImGui::SameLine();
	const char* modes[] = { "Table", "Flow" };
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	for (int i = 0; i < 2; ++i) {
		ImGui::SameLine();
		bool active = (st.view_mode == i);
		if (active) {
			ImGui::PushStyleColor(ImGuiCol_Button, accent);
		} else {
			ImGui::PushStyleColor(ImGuiCol_Button, _ta(_t.panel_header));
		}
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
			static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 200)));
		if (ImGui::Button(modes[i], ImVec2(60.f, btn_h))) {
			if (st.view_mode != i) st.mode_crossfade = 0.f;
			st.view_mode = i;
		}
		ImGui::PopStyleColor(2);
	}
	ImGui::PopStyleVar();

	st.mode_crossfade = ui_anim::smooth_lerp(st.mode_crossfade, 1.f, 10.f, dt);

	float content_y = cy + toolbar_h + 3.f;
	float content_h = height - toolbar_h - 3.f;

	std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
	auto& res = symbolic_engine::g_state.last_taint;

	if (!res.success && !res.error.empty()) {
		dl->AddText(ImVec2(cx + pad, content_y + pad), sink_col, res.error.c_str());
		ImGui::EndChild();
		return;
	}

	if (!res.success) {
		if (busy) {
			ui_anim::render_spinner(dl, cx + width * 0.5f, content_y + content_h * 0.4f, 14.f, 2.f, accent, st.anim_time);
			ImVec2 trsz = ImGui::CalcTextSize("Tracing...");
			dl->AddText(ImVec2(cx + (width - trsz.x) * 0.5f, content_y + content_h * 0.4f + 24.f), dim_col, "Tracing...");
		} else {
			ui_anim::render_empty_state(dl, cx, content_y, width, content_h,
				"Configure taint sources and click Start Trace", accent_r, accent_g, accent_b, alpha, st.anim_time);
		}
		ImGui::EndChild();
		return;
	}

	float card_h2 = 40.f;
	float card_w2 = (width - pad * 2.f - 12.f) / 4.f;
	float sx = cx + pad;
	float sy = content_y + 2.f;

	char b1[16], b2[16], b3[16], b4[16];
	std::snprintf(b1, sizeof(b1), "%u", res.total_processed);
	std::snprintf(b2, sizeof(b2), "%u", res.tainted_count);
	std::snprintf(b3, sizeof(b3), "%zu", res.tainted_registers.size());
	std::snprintf(b4, sizeof(b4), "%zu", res.tainted_memory_addresses.size());

	ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Processed", b1,
		accent_r, accent_g, accent_b, alpha);
	sx += card_w2 + 4.f;
	ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Tainted", b2,
		accent_r, accent_g, accent_b, alpha, prop_col);
	sx += card_w2 + 4.f;
	ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Taint Regs", b3,
		accent_r, accent_g, accent_b, alpha, source_col);
	sx += card_w2 + 4.f;
	ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Taint Addrs", b4,
		accent_r, accent_g, accent_b, alpha, sink_col);

	float legend_x = cx + width - 180.f;
	float legend_y = content_y + 6.f;
	dl->AddRectFilled(ImVec2(legend_x - 6.f, legend_y - 4.f), ImVec2(cx + width - 6.f, legend_y + 18.f),
		_ta(ui_anim::darken(_t.panel_bg, 10)), 4.f);
	dl->AddRect(ImVec2(legend_x - 6.f, legend_y - 4.f), ImVec2(cx + width - 6.f, legend_y + 18.f),
		_ta(ui_anim::lighten(_t.panel_bg, 12)), 4.f);
	const char* legend_labels[] = { "Source", "Propagation", "Sink" };
	const ImU32 legend_colors[] = { source_col, prop_col, sink_col };
	ui_anim::render_color_legend(dl, legend_x, legend_y, legend_labels, legend_colors, 3, alpha);

	float table_y = sy + card_h2 + 8.f;
	float table_h = content_h - (table_y - content_y);

	float mode_alpha = alpha * st.mode_crossfade;

	if (st.view_mode == 0) {
		const char* cols[] = { "Address", "Instruction", "Source Regs", "Dest Regs", "Flow" };
		float col_w[] = { 120.f, 220.f, 140.f, 140.f, 80.f };

		ui_anim::table_col_t taint_cols[] = {
			{ "Address", 120.f }, { "Instruction", 220.f },
			{ "Source Regs", 140.f }, { "Dest Regs", 140.f }, { "Flow", 80.f }
		};
		ui_anim::render_table_header(dl, cx, table_y, width, row_h,
			taint_cols, 5, accent_r, accent_g, accent_b, mode_alpha);

		float list_y = table_y + row_h;
		float list_h = table_h - row_h;
		int visible = static_cast<int>(list_h / row_h);

		auto source_regs = detail::parse_list(st.taint_regs_buf);
		auto nodes = detail::build_taint_flow(res, source_regs);
		int total = static_cast<int>(nodes.size());

		float max_scroll = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
		ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
		ImGui::InvisibleButton("##taint_scroll", ImVec2(width - 10.f, list_h));
		ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, max_scroll, row_h * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f, dt);
		ui_anim::clamp_scroll(st.scroll_y, 0.f, max_scroll);
		ui_anim::clamp_scroll(st.target_scroll_y, 0.f, max_scroll);

		int start = static_cast<int>(st.scroll_y / row_h);
		ImGui::PushClipRect(ImVec2(cx, list_y), ImVec2(cx + width, list_y + list_h), true);

		for (int i = start; i < total && i < start + visible + 1; ++i) {
			auto& n = nodes[i];
			float ry = list_y + static_cast<float>(i - start) * row_h
				- (st.scroll_y - static_cast<float>(start) * row_h);
			if (ry + row_h < list_y || ry > list_y + list_h) continue;

			ImU32 rbg = (i == st.selected_row) ? sel_col : (i % 2 == 0 ? row_even : row_odd);
			float row_t = ui_anim::render_row_entrance(i - start, st.anim_time > 1.f ? 1.f : st.anim_time);

			ImGui::SetCursorScreenPos(ImVec2(cx, ry));
			ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(), ImVec2(width, row_h));
			if (ImGui::IsItemHovered()) rbg = row_hover;
			if (ImGui::IsItemClicked()) st.selected_row = i;
			if (ImGui::IsItemClicked() && ImGui::IsMouseDoubleClicked(0)) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(n.address, g_disasm);
			}

			if (i == st.selected_row) {
				ui_anim::render_glow_rect(dl, cx, ry, width, row_h,
					accent_r, accent_g, accent_b, alpha * row_t, 0.5f);
			}
			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h),
				ui_anim::theme_alpha(rbg, row_t));

			if (i == st.selected_row) {
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + 3.f, ry + row_h),
					IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
							 static_cast<int>(accent_b * 255), static_cast<int>(180 * alpha * row_t)));
			}

			ImU32 flow_col = n.is_source ? source_col : (n.is_sink ? sink_col : prop_col);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(n.address));

			float rx = cx + 4.f;
			dl->AddText(ImVec2(rx, ry + 2.f), text_col, abuf);
			rx += col_w[0];
			dl->AddText(ImVec2(rx, ry + 2.f), text_col, n.disasm.c_str());
			rx += col_w[1];
			dl->AddText(ImVec2(rx, ry + 2.f), source_col, n.source_regs.c_str());
			rx += col_w[2];
			dl->AddText(ImVec2(rx, ry + 2.f), sink_col, n.dest_regs.c_str());
			rx += col_w[3];

			const char* flow_label = n.is_source ? "Source" : (n.is_sink ? "Sink" : "Prop");
			dl->AddText(ImVec2(rx, ry + 2.f), flow_col, flow_label);
		}

		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y, 6.f, list_h,
			st.scroll_y, static_cast<float>(total) * row_h, list_h,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	else if (st.view_mode == 1) {
		auto source_regs = detail::parse_list(st.taint_regs_buf);
		auto nodes = detail::build_taint_flow(res, source_regs);

		if (nodes.empty()) {
			ui_anim::render_empty_state(dl, cx, table_y, width, table_h,
				"No tainted instructions found in the trace",
				accent_r, accent_g, accent_b, alpha, st.anim_time);
			ImGui::EndChild();
			return;
		}

		float node_w = (std::min)(300.f, width * 0.4f);
		float node_h = 24.f;
		float node_spacing = 8.f;
		float flow_x = cx + pad;
		float flow_y = table_y + pad;
		float flow_w = width - pad * 2;

		ImGui::PushClipRect(ImVec2(cx, table_y), ImVec2(cx + width, cy + height), true);

		int max_vis = static_cast<int>((table_h - pad) / (node_h + node_spacing));
		int total = static_cast<int>(nodes.size());
		int start = 0;
		if (total > max_vis) {
			start = static_cast<int>(st.scroll_y / (node_h + node_spacing));
			if (start < 0) start = 0;
			if (start > total - max_vis) start = total - max_vis;
		}

		float max_s = static_cast<float>((std::max)(0, total - max_vis)) * (node_h + node_spacing);
		ImGui::SetCursorScreenPos(ImVec2(cx, table_y));
		ImGui::InvisibleButton("##flow_scroll", ImVec2(width - 10.f, table_h));
		ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, max_s, (node_h + node_spacing) * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f, dt);
		ui_anim::clamp_scroll(st.scroll_y, 0.f, max_s);
		ui_anim::clamp_scroll(st.target_scroll_y, 0.f, max_s);

		for (int i = start; i < total && i < start + max_vis; ++i) {
			auto& n = nodes[i];
			float ny = flow_y + static_cast<float>(i - start) * (node_h + node_spacing);

			ImU32 node_bg = n.is_source ? _ta(ui_anim::darken(_t.panel_bg, 8))
				: (n.is_sink ? _ta(ui_anim::darken(_t.panel_bg, 6))
				: _ta(ui_anim::darken(_t.panel_bg, 4)));

			ImU32 border = n.is_source ? source_col : (n.is_sink ? sink_col : prop_col);

			float nx = flow_x + (flow_w - node_w) * 0.5f;

			if (n.is_source || n.is_sink) {
				float pulse = (std::sin(st.anim_time * 3.f + static_cast<float>(i) * 0.5f) + 1.f) * 0.5f;
				ImU32 glow = (border & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(pulse * 25.f * alpha)) << 24);
				dl->AddRectFilled(ImVec2(nx - 3.f, ny - 3.f), ImVec2(nx + node_w + 3.f, ny + node_h + 3.f), glow, 6.f);
			}

			dl->AddRectFilled(ImVec2(nx, ny), ImVec2(nx + node_w, ny + node_h), node_bg, 4.f);
			dl->AddRect(ImVec2(nx, ny), ImVec2(nx + node_w, ny + node_h), border, 4.f);

			const char* type_label = n.is_source ? "SRC" : (n.is_sink ? "SINK" : "PROP");
			ImU32 type_bg = n.is_source ? ui_anim::theme_alpha(source_col, 0.5f * alpha)
				: (n.is_sink ? ui_anim::theme_alpha(sink_col, 0.5f * alpha)
				: ui_anim::theme_alpha(prop_col, 0.5f * alpha));
			ImVec2 type_sz = ImGui::CalcTextSize(type_label);
			float badge_w = type_sz.x + 8.f;
			dl->AddRectFilled(ImVec2(nx + 4.f, ny + 3.f), ImVec2(nx + 4.f + badge_w, ny + node_h - 3.f),
				type_bg, (node_h - 6.f) * 0.5f);
			dl->AddText(ImVec2(nx + 8.f, ny + 4.f), text_col, type_label);

			char label[128];
			std::snprintf(label, sizeof(label), "%llX  %s",
				static_cast<unsigned long long>(n.address), n.disasm.c_str());
			std::string lbl(label);
			if (lbl.size() > 40) lbl = lbl.substr(0, 37) + "...";
			dl->AddText(ImVec2(nx + 10.f + badge_w, ny + 4.f), text_col, lbl.c_str());

			if (i > start) {
				float prev_y = ny - node_spacing;
				float center_x = nx + node_w * 0.5f;

				ImVec2 p1(center_x, prev_y);
				ImVec2 p2(center_x, prev_y + node_spacing * 0.3f);
				ImVec2 p3(center_x, ny - node_spacing * 0.3f);
				ImVec2 p4(center_x, ny);
				ImU32 line_col = border;
				ImU32 line_glow = (line_col & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(20.f * alpha)) << 24);
				dl->AddBezierCubic(p1, p2, p3, p4, line_glow, 4.f);
				dl->AddBezierCubic(p1, p2, p3, p4, line_col, 1.5f);

				for (int pi = 0; pi < 2; ++pi) {
					float pt = std::fmod(st.anim_time * 0.8f + static_cast<float>(pi) * 0.5f + static_cast<float>(i) * 0.15f, 1.f);
					float u = 1.f - pt;
					float px = u*u*u*p1.x + 3.f*u*u*pt*p2.x + 3.f*u*pt*pt*p3.x + pt*pt*pt*p4.x;
					float py_v = u*u*u*p1.y + 3.f*u*u*pt*p2.y + 3.f*u*pt*pt*p3.y + pt*pt*pt*p4.y;
					float dot_a = std::sin(pt * 3.14159f) * alpha;
					ImU32 dot_col = (line_col & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(180.f * dot_a)) << 24);
					dl->AddCircleFilled(ImVec2(px, py_v), 2.5f, dot_col, 8);
				}

				float arrow_sz = 5.f;
				dl->AddTriangleFilled(
					ImVec2(center_x - arrow_sz, ny - arrow_sz - 1.f),
					ImVec2(center_x + arrow_sz, ny - arrow_sz - 1.f),
					ImVec2(center_x, ny),
					line_col);
			}
		}

		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, table_y, 6.f, table_h,
			st.scroll_y, static_cast<float>(total) * (node_h + node_spacing), table_h,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	ImGui::EndChild();
}

}
