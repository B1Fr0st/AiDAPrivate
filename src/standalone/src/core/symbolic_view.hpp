#pragma once

#include "symbolic_engine.hpp"
#include "deobfuscation_engine.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace symbolic_view {

struct local_state_t {
	char addr_buf[64] = "0x";
	char end_addr_buf[64] = "";
	char target_reg_buf[32] = "rax";
	char sym_regs_buf[128] = "rax,rbx,rcx,rdx";
	int max_insns = 10000;
	int selected_trace_row = -1;
	int selected_expr_row = -1;
	float trace_scroll_y = 0.f;
	float expr_scroll_y = 0.f;
	int active_tab = 0;
	bool show_junk = true;
	bool show_tainted_only = false;

	std::string expression_text;
	std::string simplified_text;
};

static local_state_t s_state;

namespace detail {

inline std::vector<std::string> parse_reg_list(const char* buf) {
	std::vector<std::string> regs;
	std::string s(buf);
	size_t pos = 0;
	while (pos < s.size()) {
		size_t comma = s.find(',', pos);
		if (comma == std::string::npos) comma = s.size();
		std::string reg = s.substr(pos, comma - pos);
		while (!reg.empty() && reg.front() == ' ') reg.erase(reg.begin());
		while (!reg.empty() && reg.back() == ' ') reg.pop_back();
		if (!reg.empty()) regs.push_back(reg);
		pos = comma + 1;
	}
	return regs;
}

inline void start_symbolic_exec(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t end = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	auto regs = parse_reg_list(st.sym_regs_buf);

	symbolic_engine::g_state.processing.store(true);
	std::thread([addr, end, max_i = static_cast<uint32_t>(st.max_insns), regs]() {
		auto result = symbolic_engine::execute_symbolic(addr, end, max_i, regs, {});
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_result = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	}).detach();
}

inline void start_deobfuscate(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);

	deobfuscation_engine::g_state.processing.store(true);
	std::thread([addr, max_i = static_cast<uint32_t>(st.max_insns)]() {
		auto result = deobfuscation_engine::deobfuscate_function(addr, max_i);
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		deobfuscation_engine::g_state.last_result = std::move(result);
		deobfuscation_engine::g_state.processing.store(false);
	}).detach();
}

inline void start_slice(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t end = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	std::string target(st.target_reg_buf);

	symbolic_engine::g_state.processing.store(true);
	std::thread([addr, end, max_i = static_cast<uint32_t>(st.max_insns), target]() {
		auto result = symbolic_engine::slice_to_register(addr, end, max_i, target);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_slice = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	}).detach();
}

inline void start_solve(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t target = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	auto regs = parse_reg_list(st.sym_regs_buf);

	symbolic_engine::g_state.processing.store(true);
	std::thread([addr, target, max_i = static_cast<uint32_t>(st.max_insns), regs]() {
		auto result = symbolic_engine::solve_for_path(addr, target, max_i, regs);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_solve = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	}).detach();
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;

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
	const ImU32 taint_col = IM_COL32(230, 180, 80, static_cast<int>(alpha * 255));
	const ImU32 junk_col  = IM_COL32(100, 100, 100, static_cast<int>(alpha * 120));
	const ImU32 opaque_col = IM_COL32(230, 80, 80, static_cast<int>(alpha * 255));
	const ImU32 green_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 warn_col  = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));

	ImVec2 wpos = ImGui::GetWindowPos();
	float cx = wpos.x + pos_x;
	float cy = wpos.y + pos_y;

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 100.f;
	const float pad = 10.f;
	const float row_h = 20.f;
	const float btn_w = 110.f;
	const float btn_h = 28.f;

	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));

	ImGui::PushItemWidth(160.f);
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Entry Addr");
	ImGui::SameLine();
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 85.f, cy + pad - 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##sym_addr", st.addr_buf, sizeof(st.addr_buf));
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "End/Target");
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##sym_end", st.end_addr_buf, sizeof(st.end_addr_buf));
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Target Reg");
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::SetNextItemWidth(80.f);
	ImGui::InputText("##sym_treg", st.target_reg_buf, sizeof(st.target_reg_buf));
	ImGui::PopStyleColor();

	ImGui::PopItemWidth();

	float btn_y = cy + pad + 26.f;

	ImGui::PushItemWidth(200.f);
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_y));
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Symbolic Regs");
	ImGui::SameLine();
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 100.f, btn_y - 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::InputText("##sym_regs", st.sym_regs_buf, sizeof(st.sym_regs_buf));
	ImGui::PopStyleColor();
	ImGui::PopItemWidth();

	ImGui::SameLine();
	ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "Max Insns");
	ImGui::SameLine();
	ImGui::SetNextItemWidth(100.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, static_cast<int>(alpha * 255)));
	ImGui::SliderInt("##sym_max", &st.max_insns, 100, 100000);
	ImGui::PopStyleColor();

	bool busy = symbolic_engine::g_state.processing.load() || deobfuscation_engine::g_state.processing.load();

	float btn_row_y = cy + pad + 54.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_row_y));

	if (busy) {
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(80, 80, 80, static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(80, 80, 80, static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(80, 80, 80, static_cast<int>(alpha * 200)));
	} else {
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(50, 50, 70, static_cast<int>(alpha * 255)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(70, 70, 100, static_cast<int>(alpha * 255)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(40, 40, 60, static_cast<int>(alpha * 255)));
	}

	if (ImGui::Button("Symbolize", ImVec2(btn_w, btn_h)) && !busy) {
		detail::start_symbolic_exec(st);
		st.active_tab = 0;
	}
	ImGui::SameLine();
	if (ImGui::Button("Deobfuscate", ImVec2(btn_w, btn_h)) && !busy) {
		detail::start_deobfuscate(st);
		st.active_tab = 1;
	}
	ImGui::SameLine();
	if (ImGui::Button("Slice", ImVec2(btn_w, btn_h)) && !busy) {
		detail::start_slice(st);
		st.active_tab = 2;
	}
	ImGui::SameLine();
	if (ImGui::Button("Solve Path", ImVec2(btn_w, btn_h)) && !busy) {
		detail::start_solve(st);
		st.active_tab = 3;
	}

	ImGui::PopStyleColor(3);

	if (busy) {
		ImGui::SameLine();
		uint32_t cur = symbolic_engine::g_state.progress_current.load();
		uint32_t tot = symbolic_engine::g_state.progress_total.load();
		if (tot == 0) {
			cur = deobfuscation_engine::g_state.progress_current.load();
			tot = deobfuscation_engine::g_state.progress_total.load();
		}
		if (tot > 0) {
			float frac = static_cast<float>(cur) / static_cast<float>(tot);
			ImGui::SetCursorScreenPos(ImVec2(cx + pad + btn_w * 4 + 60.f, btn_row_y + 4.f));
			ImGui::PushStyleColor(ImGuiCol_PlotHistogram, accent);
			ImGui::ProgressBar(frac, ImVec2(200.f, 20.f));
			ImGui::PopStyleColor();
		}
	}

	ImGui::SameLine();
	ImGui::Checkbox("Show Junk", &st.show_junk);
	ImGui::SameLine();
	ImGui::Checkbox("Tainted Only", &st.show_tainted_only);

	float content_y = cy + toolbar_h;
	float content_h = height - toolbar_h;

	const char* tab_labels[] = { "Trace", "Deobfuscation", "Slice", "Solver", "Expression" };
	float tab_x = cx + pad;
	float tab_btn_w = 100.f;

	for (int i = 0; i < 5; ++i) {
		bool active = (st.active_tab == i);
		ImU32 tab_bg = active ? accent : IM_COL32(50, 50, 50, static_cast<int>(alpha * 200));
		ImU32 tab_text = active ? IM_COL32(255, 255, 255, static_cast<int>(alpha * 255)) : dim_col;

		dl->AddRectFilled(ImVec2(tab_x, content_y), ImVec2(tab_x + tab_btn_w, content_y + 24.f), tab_bg, 4.f, ImDrawFlags_RoundCornersTop);
		dl->AddText(ImVec2(tab_x + 8.f, content_y + 4.f), tab_text, tab_labels[i]);

		ImGui::SetCursorScreenPos(ImVec2(tab_x, content_y));
		ImGui::InvisibleButton(tab_labels[i], ImVec2(tab_btn_w, 24.f));
		if (ImGui::IsItemClicked()) st.active_tab = i;
		tab_x += tab_btn_w + 4.f;
	}

	float table_y = content_y + 28.f;
	float table_h = content_h - 28.f;

	if (st.active_tab == 0) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_result;

		const char* cols[] = { "Address", "Instruction", "Symbolic State", "T", "J", "OP" };
		float col_w[] = { 120.f, 200.f, width - 120.f - 200.f - 80.f - 50.f, 24.f, 24.f, 26.f };

		dl->AddRectFilled(ImVec2(cx, table_y), ImVec2(cx + width, table_y + row_h), header_bg);
		float hx = cx + 4.f;
		for (int c = 0; c < 6; ++c) {
			dl->AddText(ImVec2(hx, table_y + 2.f), accent, cols[c]);
			hx += col_w[c];
		}

		float list_y = table_y + row_h;
		float list_h = table_h - row_h;
		int visible_rows = static_cast<int>(list_h / row_h);

		ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
		ImGui::InvisibleButton("##sym_trace_scroll", ImVec2(width, list_h));
		if (ImGui::IsItemHovered()) {
			st.trace_scroll_y -= ImGui::GetIO().MouseWheel * row_h * 3.f;
		}

		auto& trace = res.trace;
		int total = static_cast<int>(trace.size());
		if (st.trace_scroll_y < 0.f) st.trace_scroll_y = 0.f;
		float max_scroll = (std::max)(0.f, static_cast<float>(total - visible_rows) * row_h);
		if (st.trace_scroll_y > max_scroll) st.trace_scroll_y = max_scroll;

		int start_row = static_cast<int>(st.trace_scroll_y / row_h);
		ImGui::PushClipRect(ImVec2(cx, list_y), ImVec2(cx + width, list_y + list_h), true);

		for (int i = start_row; i < total && i < start_row + visible_rows + 1; ++i) {
			auto& t = trace[i];
			if (st.show_tainted_only && !t.is_tainted) continue;
			if (!st.show_junk && t.is_junk) continue;

			float ry = list_y + (static_cast<float>(i) - static_cast<float>(start_row)) * row_h
				- (st.trace_scroll_y - static_cast<float>(start_row) * row_h);

			if (ry + row_h < list_y || ry > list_y + list_h) continue;

			ImU32 rbg = (i == st.selected_trace_row) ? sel_col : (i % 2 == 0 ? row_even : row_odd);

			ImGui::SetCursorScreenPos(ImVec2(cx, ry));
			ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(), ImVec2(width, row_h));
			if (ImGui::IsItemHovered()) rbg = row_hover;
			if (ImGui::IsItemClicked()) {
				st.selected_trace_row = i;
				st.expression_text = t.symbolic_state;
				st.active_tab = 4;
			}

			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), rbg);

			ImU32 row_text = t.is_junk ? junk_col : (t.is_tainted ? taint_col : text_col);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(t.address));

			float rx = cx + 4.f;
			dl->AddText(ImVec2(rx, ry + 2.f), row_text, abuf);
			rx += col_w[0];
			dl->AddText(ImVec2(rx, ry + 2.f), row_text, t.disasm.c_str());
			rx += col_w[1];

			std::string sym_short = t.symbolic_state;
			if (sym_short.size() > 60) sym_short = sym_short.substr(0, 57) + "...";
			dl->AddText(ImVec2(rx, ry + 2.f), dim_col, sym_short.c_str());
			rx += col_w[2];

			if (t.is_tainted) dl->AddText(ImVec2(rx + 4.f, ry + 2.f), taint_col, "T");
			rx += col_w[3];
			if (t.is_junk) dl->AddText(ImVec2(rx + 4.f, ry + 2.f), junk_col, "J");
			rx += col_w[4];
			if (t.is_opaque_predicate) dl->AddText(ImVec2(rx + 2.f, ry + 2.f), opaque_col, "OP");
		}

		ImGui::PopClipRect();

		dl->AddText(ImVec2(cx + pad, list_y + list_h - 16.f), dim_col,
			(std::to_string(res.total_instructions) + " insns | " +
			 std::to_string(res.tainted_count) + " tainted | " +
			 std::to_string(res.opaque_count) + " opaque | " +
			 std::to_string(res.constants_count) + " constants").c_str());
	}

	else if (st.active_tab == 1) {
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		auto& res = deobfuscation_engine::g_state.last_result;

		if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			float stat_h = 80.f;
			char stats[512];
			std::snprintf(stats, sizeof(stats),
				"Original: %u | Clean: %u | Junk removed: %u (%.1f%%) | Opaques: %u | Constants: %u | States: %u",
				res.total_original, res.total_clean, res.removed_junk, res.junk_ratio * 100.f,
				res.opaque_predicates_found, res.constants_resolved, res.dispatcher_states_resolved);
			dl->AddText(ImVec2(cx + pad, table_y + 4.f), green_col, stats);

			const char* cols[] = { "Address", "Instruction", "Status" };
			float col_w[] = { 120.f, 300.f, width - 420.f - pad * 2 };

			float hdr_y = table_y + 24.f;
			dl->AddRectFilled(ImVec2(cx, hdr_y), ImVec2(cx + width, hdr_y + row_h), header_bg);
			float hx = cx + 4.f;
			for (int c = 0; c < 3; ++c) {
				dl->AddText(ImVec2(hx, hdr_y + 2.f), accent, cols[c]);
				hx += col_w[c];
			}

			float list_y2 = hdr_y + row_h;
			float list_h2 = table_h - 48.f;
			int visible = static_cast<int>(list_h2 / row_h);

			auto& insns = res.clean_instructions;
			int total = static_cast<int>(insns.size());

			ImGui::SetCursorScreenPos(ImVec2(cx, list_y2));
			ImGui::InvisibleButton("##deob_scroll", ImVec2(width, list_h2));
			if (ImGui::IsItemHovered()) {
				st.expr_scroll_y -= ImGui::GetIO().MouseWheel * row_h * 3.f;
			}
			if (st.expr_scroll_y < 0.f) st.expr_scroll_y = 0.f;
			float max_s = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
			if (st.expr_scroll_y > max_s) st.expr_scroll_y = max_s;

			int start = static_cast<int>(st.expr_scroll_y / row_h);
			ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + list_h2), true);

			for (int i = start; i < total && i < start + visible + 1; ++i) {
				auto& ci = insns[i];
				float ry = list_y2 + (static_cast<float>(i - start)) * row_h
					- (st.expr_scroll_y - static_cast<float>(start) * row_h);
				if (ry + row_h < list_y2 || ry > list_y2 + list_h2) continue;

				ImU32 rbg = ci.was_junk ? IM_COL32(50, 35, 35, static_cast<int>(alpha * 255)) : (i % 2 == 0 ? row_even : row_odd);
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), rbg);

				ImU32 txt = ci.was_junk ? junk_col : text_col;
				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(ci.address));

				float rx = cx + 4.f;
				dl->AddText(ImVec2(rx, ry + 2.f), txt, abuf);
				rx += col_w[0];
				dl->AddText(ImVec2(rx, ry + 2.f), txt, ci.disasm.c_str());
				rx += col_w[1];

				const char* status = ci.was_junk ? "JUNK" : (ci.was_opaque ? "OPAQUE" : (ci.was_constant_folded ? "CONST" : ""));
				ImU32 status_col = ci.was_junk ? opaque_col : (ci.was_opaque ? warn_col : green_col);
				if (status[0]) dl->AddText(ImVec2(rx, ry + 2.f), status_col, status);
			}

			ImGui::PopClipRect();
		}
	}

	else if (st.active_tab == 2) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_slice;

		if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			char stats[256];
			std::snprintf(stats, sizeof(stats), "Total: %u | Effective: %u | Removed: %u",
				res.total_instructions, res.effective_count, res.removed_count);
			dl->AddText(ImVec2(cx + pad, table_y + 4.f), green_col, stats);

			float hdr_y = table_y + 24.f;
			dl->AddRectFilled(ImVec2(cx, hdr_y), ImVec2(cx + width, hdr_y + row_h), header_bg);
			dl->AddText(ImVec2(cx + 4.f, hdr_y + 2.f), accent, "Address");
			dl->AddText(ImVec2(cx + 124.f, hdr_y + 2.f), accent, "Instruction");

			float list_y2 = hdr_y + row_h;
			auto& insns = res.effective_instructions;
			int total = static_cast<int>(insns.size());

			ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + table_h - 48.f), true);
			for (int i = 0; i < total; ++i) {
				float ry = list_y2 + static_cast<float>(i) * row_h;
				if (ry > list_y2 + table_h - 48.f) break;

				ImU32 rbg = (i % 2 == 0) ? row_even : row_odd;
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), rbg);

				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(insns[i].address));
				dl->AddText(ImVec2(cx + 4.f, ry + 2.f), text_col, abuf);
				dl->AddText(ImVec2(cx + 124.f, ry + 2.f), text_col, insns[i].disasm.c_str());
			}
			ImGui::PopClipRect();
		}
	}

	else if (st.active_tab == 3) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_solve;

		if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			float ty = table_y + pad;

			if (res.satisfiable) {
				dl->AddText(ImVec2(cx + pad, ty), green_col, "SATISFIABLE");
				ty += 20.f;

				char time_buf[64];
				std::snprintf(time_buf, sizeof(time_buf), "Solving time: %u ms", res.solving_time_ms);
				dl->AddText(ImVec2(cx + pad, ty), dim_col, time_buf);
				ty += 24.f;

				dl->AddText(ImVec2(cx + pad, ty), accent, "Variable Solutions:");
				ty += 20.f;

				for (auto& [name, val] : res.variable_values) {
					char vbuf[128];
					std::snprintf(vbuf, sizeof(vbuf), "  %s = 0x%llX (%llu)",
						name.c_str(), static_cast<unsigned long long>(val), static_cast<unsigned long long>(val));
					dl->AddText(ImVec2(cx + pad, ty), text_col, vbuf);
					ty += 18.f;
				}
			} else {
				dl->AddText(ImVec2(cx + pad, ty), opaque_col, "UNSATISFIABLE");
				ty += 20.f;
				dl->AddText(ImVec2(cx + pad, ty), dim_col, "No input values can reach the target address");
			}
		}
	}

	else if (st.active_tab == 4) {
		float ty = table_y + pad;
		dl->AddText(ImVec2(cx + pad, ty), accent, "Symbolic Expression:");
		ty += 20.f;

		if (!st.expression_text.empty()) {
			float wrap_w = width - pad * 2;
			ImGui::PushClipRect(ImVec2(cx, ty), ImVec2(cx + width, cy + height), true);
			dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(cx + pad, ty),
				text_col, st.expression_text.c_str(), nullptr, wrap_w);
			ImGui::PopClipRect();
		} else {
			dl->AddText(ImVec2(cx + pad, ty), dim_col, "Select an instruction from the Trace tab to view its symbolic state");
		}
	}
}

}
