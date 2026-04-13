#pragma once

#include "symbolic_engine.hpp"
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
	std::thread([addr, end, max_i = static_cast<uint32_t>(st.max_insns), regs, mem_ranges]() {
		auto result = symbolic_engine::taint_trace(addr, end, max_i, regs, mem_ranges);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_taint = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	}).detach();
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

	const ImU32 bg        = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col  = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col   = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent    = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 row_even  = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd   = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 sel_col   = IM_COL32(60, 60, 80, static_cast<int>(alpha * 255));
	const ImU32 source_col = IM_COL32(86, 182, 194, static_cast<int>(alpha * 255));
	const ImU32 prop_col   = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
	const ImU32 sink_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 green_col  = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 72.f;
	const float pad = 10.f;
	const float row_h = 20.f;
	const float btn_h = 28.f;

	ImGui::PushItemWidth(140.f);

	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Start");
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##taint_addr", st.addr_buf, sizeof(st.addr_buf));
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "End");
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##taint_end", st.end_addr_buf, sizeof(st.end_addr_buf));
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Taint Regs");
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##taint_regs", st.taint_regs_buf, sizeof(st.taint_regs_buf));
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Mem");
	ImGui::SameLine();
	ImGui::SetNextItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##taint_mem", st.taint_mem_buf, sizeof(st.taint_mem_buf));
	ImGui::PopStyleColor();

	ImGui::PopItemWidth();

	float btn_y = cy + pad + 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_y));

	bool busy = symbolic_engine::g_state.processing.load();

	ImGui::PushStyleColor(ImGuiCol_Button, busy ? IM_COL32(80, 80, 80, 200) : IM_COL32(50, 50, 70, static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(70, 70, 100, static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(40, 40, 60, static_cast<int>(alpha * 255)));

	if (ImGui::Button("Start Trace", ImVec2(110.f, btn_h)) && !busy) {
		detail::start_taint_trace(st);
	}

	ImGui::PopStyleColor(3);

	if (busy) {
		ImGui::SameLine();
		uint32_t cur = symbolic_engine::g_state.progress_current.load();
		uint32_t tot = symbolic_engine::g_state.progress_total.load();
		if (tot > 0) {
			ImGui::PushStyleColor(ImGuiCol_PlotHistogram, accent);
			ImGui::ProgressBar(static_cast<float>(cur) / static_cast<float>(tot), ImVec2(200.f, 20.f));
			ImGui::PopStyleColor();
		}
	}

	ImGui::SameLine();
	ImGui::SetNextItemWidth(100.f);
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Max");
	ImGui::SameLine();
	ImGui::SetNextItemWidth(100.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::SliderInt("##taint_max", &st.max_insns, 100, 100000);
	ImGui::PopStyleColor();

	ImGui::SameLine();
	const char* modes[] = { "Table", "Flow" };
	for (int i = 0; i < 2; ++i) {
		ImGui::SameLine();
		bool active = (st.view_mode == i);
		if (active) {
			ImGui::PushStyleColor(ImGuiCol_Button, accent);
		} else {
			ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 50, 50, static_cast<int>(alpha * 200)));
		}
		if (ImGui::Button(modes[i], ImVec2(60.f, btn_h))) st.view_mode = i;
		ImGui::PopStyleColor();
	}

	float content_y = cy + toolbar_h;
	float content_h = height - toolbar_h;

	std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
	auto& res = symbolic_engine::g_state.last_taint;

	if (!res.success && !res.error.empty()) {
		dl->AddText(ImVec2(cx + pad, content_y + pad), sink_col, res.error.c_str());
		ImGui::EndChild();
		return;
	}

	if (!res.success) {
		if (busy) {
			ui_anim::render_spinner(dl, cx + width * 0.5f, content_y + content_h * 0.4f, 14.f, accent, st.anim_time);
			dl->AddText(ImVec2(cx + width * 0.5f - 40.f, content_y + content_h * 0.4f + 24.f), dim_col, "Tracing...");
		} else {
			dl->AddText(ImVec2(cx + pad, content_y + pad), dim_col, "Configure taint sources and click Start Trace");
		}
		ImGui::EndChild();
		return;
	}

	char summary[256];
	std::snprintf(summary, sizeof(summary),
		"Processed: %u | Tainted: %u | Tainted regs: %zu | Tainted mem addrs: %zu",
		res.total_processed, res.tainted_count,
		res.tainted_registers.size(), res.tainted_memory_addresses.size());
	dl->AddText(ImVec2(cx + pad, content_y + 2.f), green_col, summary);

	float legend_x = cx + width - 300.f;
	dl->AddRectFilled(ImVec2(legend_x, content_y), ImVec2(legend_x + 12.f, content_y + 12.f), source_col);
	dl->AddText(ImVec2(legend_x + 16.f, content_y), text_col, "Source");
	dl->AddRectFilled(ImVec2(legend_x + 80.f, content_y), ImVec2(legend_x + 92.f, content_y + 12.f), prop_col);
	dl->AddText(ImVec2(legend_x + 96.f, content_y), text_col, "Propagation");
	dl->AddRectFilled(ImVec2(legend_x + 190.f, content_y), ImVec2(legend_x + 202.f, content_y + 12.f), sink_col);
	dl->AddText(ImVec2(legend_x + 206.f, content_y), text_col, "Sink");

	float table_y = content_y + 20.f;
	float table_h = content_h - 20.f;

	if (st.view_mode == 0) {
		const char* cols[] = { "Address", "Instruction", "Source Regs", "Dest Regs", "Flow" };
		float col_w[] = { 120.f, 220.f, 140.f, 140.f, 80.f };

		dl->AddRectFilled(ImVec2(cx, table_y), ImVec2(cx + width, table_y + row_h), header_bg);
		float hx = cx + 4.f;
		for (int c = 0; c < 5; ++c) {
			dl->AddText(ImVec2(hx, table_y + 2.f), accent, cols[c]);
			hx += col_w[c];
		}

		float list_y = table_y + row_h;
		float list_h = table_h - row_h;
		int visible = static_cast<int>(list_h / row_h);

		auto source_regs = detail::parse_list(st.taint_regs_buf);
		auto nodes = detail::build_taint_flow(res, source_regs);
		int total = static_cast<int>(nodes.size());

		float max_scroll = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
		ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
		ImGui::InvisibleButton("##taint_scroll", ImVec2(width - 10.f, list_h));
		ui_anim::handle_scroll_input(st.target_scroll_y, max_scroll, row_h * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, dt);
		ui_anim::clamp_scroll(st.scroll_y, max_scroll);
		ui_anim::clamp_scroll(st.target_scroll_y, max_scroll);

		int start = static_cast<int>(st.scroll_y / row_h);
		ImGui::PushClipRect(ImVec2(cx, list_y), ImVec2(cx + width, list_y + list_h), true);

		for (int i = start; i < total && i < start + visible + 1; ++i) {
			auto& n = nodes[i];
			float ry = list_y + static_cast<float>(i - start) * row_h
				- (st.scroll_y - static_cast<float>(start) * row_h);
			if (ry + row_h < list_y || ry > list_y + list_h) continue;

			ImU32 rbg = (i == st.selected_row) ? sel_col : (i % 2 == 0 ? row_even : row_odd);

			ImGui::SetCursorScreenPos(ImVec2(cx, ry));
			ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(), ImVec2(width, row_h));
			if (ImGui::IsItemHovered()) rbg = row_hover;
			if (ImGui::IsItemClicked()) st.selected_row = i;
			if (ImGui::IsItemClicked() && ImGui::IsMouseDoubleClicked(0)) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(n.address, g_disasm);
			}

			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), rbg);

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
			st.scroll_y, max_scroll, st.scrollbar_dragging, st.scrollbar_drag_offset,
			accent, IM_COL32(60, 60, 60, static_cast<int>(alpha * 150)));
	}

	else if (st.view_mode == 1) {
		auto source_regs = detail::parse_list(st.taint_regs_buf);
		auto nodes = detail::build_taint_flow(res, source_regs);

		if (nodes.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), dim_col, "No tainted instructions");
			ImGui::EndChild();
			return;
		}

		float node_w = 300.f;
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
		ui_anim::handle_scroll_input(st.target_scroll_y, max_s, (node_h + node_spacing) * 3.f);
		ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, dt);
		ui_anim::clamp_scroll(st.scroll_y, max_s);
		ui_anim::clamp_scroll(st.target_scroll_y, max_s);

		for (int i = start; i < total && i < start + max_vis; ++i) {
			auto& n = nodes[i];
			float ny = flow_y + static_cast<float>(i - start) * (node_h + node_spacing);

			ImU32 node_bg = n.is_source ? IM_COL32(40, 70, 75, static_cast<int>(alpha * 255))
				: (n.is_sink ? IM_COL32(75, 40, 45, static_cast<int>(alpha * 255))
				: IM_COL32(60, 55, 40, static_cast<int>(alpha * 255)));

			ImU32 border = n.is_source ? source_col : (n.is_sink ? sink_col : prop_col);

			float nx = flow_x + (flow_w - node_w) * 0.5f;
			dl->AddRectFilled(ImVec2(nx, ny), ImVec2(nx + node_w, ny + node_h), node_bg, 4.f);
			dl->AddRect(ImVec2(nx, ny), ImVec2(nx + node_w, ny + node_h), border, 4.f);

			char label[128];
			std::snprintf(label, sizeof(label), "%llX  %s",
				static_cast<unsigned long long>(n.address), n.disasm.c_str());
			std::string lbl(label);
			if (lbl.size() > 45) lbl = lbl.substr(0, 42) + "...";
			dl->AddText(ImVec2(nx + 6.f, ny + 4.f), text_col, lbl.c_str());

			if (i > start) {
				float prev_y = ny - node_spacing;
				float center_x = nx + node_w * 0.5f;
				dl->AddLine(ImVec2(center_x, prev_y), ImVec2(center_x, ny), dim_col, 1.f);

				float arrow_sz = 4.f;
				dl->AddTriangleFilled(
					ImVec2(center_x - arrow_sz, ny - arrow_sz),
					ImVec2(center_x + arrow_sz, ny - arrow_sz),
					ImVec2(center_x, ny),
					dim_col);
			}
		}

		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, table_y, 6.f, table_h,
			st.scroll_y, max_s, st.scrollbar_dragging, st.scrollbar_drag_offset,
			accent, IM_COL32(60, 60, 60, static_cast<int>(alpha * 150)));
	}

	ImGui::EndChild();
}

}
