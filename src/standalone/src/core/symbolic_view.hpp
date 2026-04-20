#pragma once

#include "symbolic_engine.hpp"
#include "deobfuscation_engine.hpp"
#include "ui_anim.hpp"
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
	float target_trace_scroll_y = 0.f;
	float expr_scroll_y = 0.f;
	float target_expr_scroll_y = 0.f;
	int active_tab = 0;
	int prev_tab = 0;
	bool scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	float anim_time = 0.f;
	bool show_junk = true;
	bool show_tainted_only = false;
	float tab_underline_x = 0.f;
	float tab_underline_w = 0.f;
	float tab_underline_vel = 0.f;
	float content_crossfade = 1.f;

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
	ImGui::BeginChild("##symbolic_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	auto& st = s_state;
	float dt = ImGui::GetIO().DeltaTime;
	st.anim_time += dt;

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
	const ImU32 taint_col = IM_COL32(230, 180, 80, static_cast<int>(alpha * 255));
	const ImU32 junk_col  = ui_anim::theme_alpha(_t.text_dim, 0.47f * alpha);
	const ImU32 opaque_col = IM_COL32(230, 80, 80, static_cast<int>(alpha * 255));
	const ImU32 green_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 warn_col  = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));

	float cx = ox;
	float cy = oy;

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 112.f;
	const float pad = 10.f;
	const float row_h = 20.f;
	const float btn_w = 110.f;
	const float btn_h = 28.f;

	ui_anim::render_toolbar(dl, cx, cy, width, toolbar_h, accent_r, accent_g, accent_b, alpha);

	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));

	ImGui::PushItemWidth(160.f);
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, cy + pad));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Entry Addr");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 85.f, cy + pad - 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::InputText("##sym_addr", st.addr_buf, sizeof(st.addr_buf));
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("End/Target");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::InputText("##sym_end", st.end_addr_buf, sizeof(st.end_addr_buf));
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Target Reg");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::SetNextItemWidth(80.f);
	ImGui::InputText("##sym_treg", st.target_reg_buf, sizeof(st.target_reg_buf));
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);

	ImGui::PopItemWidth();

	float btn_y = cy + pad + 26.f;

	ImGui::PushItemWidth(200.f);
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_y));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Symbolic Regs");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 100.f, btn_y - 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::InputText("##sym_regs", st.sym_regs_buf, sizeof(st.sym_regs_buf));
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
	ImGui::PopItemWidth();

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
	ImGui::TextUnformatted("Max Insns");
	ImGui::PopStyleColor();
	ImGui::SameLine();
	ImGui::SetNextItemWidth(100.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, accent);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::SliderInt("##sym_max", &st.max_insns, 100, 100000);
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(2);

	bool busy = symbolic_engine::g_state.processing.load() || deobfuscation_engine::g_state.processing.load();

	ui_anim::render_separator(dl, cx + pad, cy + pad + 50.f, width - pad * 2.f, accent_r, accent_g, accent_b, alpha);

	float btn_row_y = cy + pad + 56.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad, btn_row_y));

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
	ImGui::PopStyleVar();

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
			float pb_x = cx + pad + btn_w * 4 + 60.f;
			float pb_y = btn_row_y + 4.f;
			float pulse_a = (std::sin(st.anim_time * 4.f) + 1.f) * 0.5f;
			ImU32 glow_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), static_cast<int>(pulse_a * 30.f * alpha));
			dl->AddRectFilled(ImVec2(pb_x - 4.f, pb_y - 4.f), ImVec2(pb_x + 204.f, pb_y + 24.f), glow_col, 6.f);
			ui_anim::render_progress_bar_animated(dl, pb_x, pb_y, 200.f, 20.f, frac,
				accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else {
			float spin_x = cx + pad + btn_w * 4 + 70.f;
			float spin_y = btn_row_y + 14.f;
			float pulse_a = (std::sin(st.anim_time * 3.f) + 1.f) * 0.5f;
			ImU32 glow_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), static_cast<int>(pulse_a * 20.f * alpha));
			dl->AddCircleFilled(ImVec2(spin_x, spin_y), 14.f, glow_col, 16);
			ui_anim::render_spinner(dl, spin_x, spin_y, 7.f, 2.f, accent, st.anim_time);
		}
	}

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_CheckMark, accent);
	ImGui::Checkbox("Show Junk", &st.show_junk);
	ImGui::SameLine();
	ImGui::Checkbox("Tainted Only", &st.show_tainted_only);
	ImGui::PopStyleColor();

	float content_y = cy + toolbar_h + 3.f;
	float content_h = height - toolbar_h - 3.f;

	const char* tab_labels[] = { "Trace", "Deobfuscation", "Slice", "Solver", "Expression" };
	float tab_x = cx + pad;

	dl->AddRectFilled(ImVec2(cx, content_y), ImVec2(cx + width, content_y + 28.f),
		_ta(_t.bg_base));
	dl->AddLine(ImVec2(cx, content_y + 27.f), ImVec2(cx + width, content_y + 27.f),
		_ta(ui_anim::lighten(_t.panel_bg, 12)));

	float target_ux = cx + pad;
	float target_uw = 0.f;
	for (int i = 0; i < 5; ++i) {
		ImVec2 lsz = ImGui::CalcTextSize(tab_labels[i]);
		float tab_btn_w = lsz.x + 20.f;
		if (i == st.active_tab) { target_ux = tab_x; target_uw = tab_btn_w; }
		float text_alpha_val = (st.active_tab == i) ? 0.95f : 0.5f;

		ImGui::SetCursorScreenPos(ImVec2(tab_x, content_y));
		ImGui::InvisibleButton(tab_labels[i], ImVec2(tab_btn_w, 26.f));
		bool hov = ImGui::IsItemHovered();
		if (hov) text_alpha_val = (st.active_tab == i) ? 0.95f : 0.72f;
		if (ImGui::IsItemClicked()) {
			st.prev_tab = st.active_tab;
			st.active_tab = i;
			st.content_crossfade = 0.f;
		}

		if (hov && st.active_tab != i) {
			dl->AddRectFilled(ImVec2(tab_x, content_y), ImVec2(tab_x + tab_btn_w, content_y + 26.f),
				_ta(ui_anim::lighten(_t.panel_bg, 8)), 4.f, ImDrawFlags_RoundCornersTop);
		}

		dl->AddText(ImVec2(tab_x + 10.f, content_y + 5.f),
			ui_anim::theme_alpha(_t.text_primary, text_alpha_val * alpha), tab_labels[i]);

		tab_x += tab_btn_w + 2.f;
	}

	if (st.tab_underline_w < 1.f) { st.tab_underline_x = target_ux; st.tab_underline_w = target_uw; }
	ui_anim::spring_interp(st.tab_underline_x, st.tab_underline_vel, target_ux, 280.f, 22.f, dt);
	float dummy_vel = 0.f;
	ui_anim::spring_interp(st.tab_underline_w, dummy_vel, target_uw, 280.f, 22.f, dt);

	dl->AddRectFilled(ImVec2(st.tab_underline_x + 2.f, content_y + 25.f),
		ImVec2(st.tab_underline_x + st.tab_underline_w - 2.f, content_y + 27.f),
		accent, 1.5f);

	st.content_crossfade = ui_anim::smooth_lerp(st.content_crossfade, 1.f, 10.f, dt);
	float cf_alpha = alpha * st.content_crossfade;

	float table_y = content_y + 28.f;
	float table_h = content_h - 28.f;

	if (st.active_tab == 0) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_result;

		if (res.trace.empty()) {
			ui_anim::render_empty_state(dl, cx, table_y, width, table_h,
				"Run Symbolize to trace symbolic execution", accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else {
			const char* cols[] = { "Address", "Instruction", "Symbolic State", "T", "J", "OP" };
			float col_w[] = { 120.f, 200.f, width - 120.f - 200.f - 80.f - 50.f, 24.f, 24.f, 26.f };

			ui_anim::table_col_t hdr_cols[] = {
				{ "Address", 120.f }, { "Instruction", 200.f },
				{ "Symbolic State", width - 120.f - 200.f - 80.f - 50.f },
				{ "T", 24.f }, { "J", 24.f }, { "OP", 26.f }
			};
			ui_anim::render_table_header(dl, cx, table_y, width, row_h,
				hdr_cols, 6, accent_r, accent_g, accent_b, cf_alpha);

			float list_y = table_y + row_h;
			float list_h = table_h - row_h - 52.f;
			int visible_rows = static_cast<int>(list_h / row_h);

			ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
			ImGui::InvisibleButton("##sym_trace_scroll", ImVec2(width, list_h));

			auto& trace = res.trace;
			int total = static_cast<int>(trace.size());
			float max_scroll = (std::max)(0.f, static_cast<float>(total - visible_rows) * row_h);
			if (ImGui::IsItemHovered())
				ui_anim::handle_scroll_input(st.target_trace_scroll_y, 0.f, max_scroll, row_h);
			ui_anim::smooth_scroll(st.trace_scroll_y, st.target_trace_scroll_y, 12.f, dt);

			int start_row = static_cast<int>(st.trace_scroll_y / row_h);
			ImGui::PushClipRect(ImVec2(cx, list_y), ImVec2(cx + width, list_y + list_h), true);

			for (int i = start_row; i < total && i < start_row + visible_rows + 1; ++i) {
				auto& t = trace[i];
				if (st.show_tainted_only && !t.is_tainted) continue;
				if (!st.show_junk && t.is_junk) continue;

				float ry = list_y + (static_cast<float>(i) - static_cast<float>(start_row)) * row_h
					- (st.trace_scroll_y - static_cast<float>(start_row) * row_h);

				if (ry + row_h < list_y || ry > list_y + list_h) continue;

				float row_t = ui_anim::render_row_entrance(i - start_row, st.anim_time > 1.f ? 1.f : st.anim_time);
				float row_alpha = alpha * row_t;

				ImU32 rbg = (i == st.selected_trace_row) ? sel_col : (i % 2 == 0 ? row_even : row_odd);

				ImGui::SetCursorScreenPos(ImVec2(cx, ry));
				ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(), ImVec2(width, row_h));
				if (ImGui::IsItemHovered()) rbg = row_hover;
				if (ImGui::IsItemClicked()) {
					st.selected_trace_row = i;
					st.expression_text = t.symbolic_state;
					st.active_tab = 4;
				}

				if (i == st.selected_trace_row) {
					ui_anim::render_glow_rect(dl, cx, ry, width, row_h,
						accent_r, accent_g, accent_b, row_alpha, 0.6f);
				}
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), rbg);

				if (i == st.selected_trace_row) {
					dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + 3.f, ry + row_h),
						IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
								 static_cast<int>(accent_b * 255), static_cast<int>(180 * row_alpha)));
				}

				ImU32 row_text = ui_anim::theme_alpha(
					t.is_junk ? junk_col : (t.is_tainted ? taint_col : text_col), row_t);

				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(t.address));

				float rx = cx + 4.f;
				dl->AddText(ImVec2(rx, ry + 2.f), row_text, abuf);
				rx += col_w[0];
				dl->AddText(ImVec2(rx, ry + 2.f), row_text, t.disasm.c_str());
				rx += col_w[1];

				std::string sym_short = t.symbolic_state;
				if (sym_short.size() > 60) sym_short = sym_short.substr(0, 57) + "...";
				dl->AddText(ImVec2(rx, ry + 2.f), ui_anim::theme_alpha(dim_col, row_t), sym_short.c_str());
				rx += col_w[2];

				if (t.is_tainted) {
					ui_anim::render_badge(dl, "T", rx + 1.f, ry + 2.f,
						ui_anim::theme_alpha(taint_col, 0.14f * row_alpha),
						ui_anim::theme_alpha(taint_col, row_t));
				}
				rx += col_w[3];
				if (t.is_junk) {
					ui_anim::render_badge(dl, "J", rx + 1.f, ry + 2.f,
						ui_anim::theme_alpha(junk_col, 0.28f * row_alpha),
						ui_anim::theme_alpha(junk_col, row_t));
				}
				rx += col_w[4];
				if (t.is_opaque_predicate) {
					ui_anim::render_badge(dl, "OP", rx, ry + 2.f,
						ui_anim::theme_alpha(opaque_col, 0.14f * row_alpha),
						ui_anim::theme_alpha(opaque_col, row_t));
				}
			}

			ImGui::PopClipRect();

			ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y, 6.f, list_h,
				st.trace_scroll_y, static_cast<float>(total) * row_h, list_h,
				alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);

			float stats_y = list_y + list_h + 8.f;
			float card_w = (width - pad * 2.f - 12.f) / 4.f;
			float card_h = 40.f;
			float sx = cx + pad;

			char buf_insns[16], buf_taint[16], buf_opaque[16], buf_const[16];
			std::snprintf(buf_insns, sizeof(buf_insns), "%u", res.total_instructions);
			std::snprintf(buf_taint, sizeof(buf_taint), "%u", res.tainted_count);
			std::snprintf(buf_opaque, sizeof(buf_opaque), "%u", res.opaque_count);
			std::snprintf(buf_const, sizeof(buf_const), "%u", res.constants_count);

			ui_anim::render_stat_card(dl, sx, stats_y, card_w, card_h, "Instructions", buf_insns,
				accent_r, accent_g, accent_b, alpha);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, stats_y, card_w, card_h, "Tainted", buf_taint,
				accent_r, accent_g, accent_b, alpha, taint_col);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, stats_y, card_w, card_h, "Opaque", buf_opaque,
				accent_r, accent_g, accent_b, alpha, opaque_col);
			sx += card_w + 4.f;
			ui_anim::render_stat_card(dl, sx, stats_y, card_w, card_h, "Constants", buf_const,
				accent_r, accent_g, accent_b, alpha, green_col);
		}
	}

	else if (st.active_tab == 1) {
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		auto& res = deobfuscation_engine::g_state.last_result;

		if (!res.success && res.error.empty() && !deobfuscation_engine::g_state.processing.load()) {
			ui_anim::render_empty_state(dl, cx, table_y, width, table_h,
				"Run Deobfuscate to analyze and clean obfuscated code", accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			float card_h2 = 44.f;
			float card_w2 = (width - pad * 2.f - 20.f) / 6.f;
			float sx = cx + pad;
			float sy = table_y + 4.f;

			char b1[16], b2[16], b3[16], b4[16], b5[16], b6[16];
			std::snprintf(b1, sizeof(b1), "%u", res.total_original);
			std::snprintf(b2, sizeof(b2), "%u", res.total_clean);
			std::snprintf(b3, sizeof(b3), "%.1f%%", res.junk_ratio * 100.f);
			std::snprintf(b4, sizeof(b4), "%u", res.opaque_predicates_found);
			std::snprintf(b5, sizeof(b5), "%u", res.constants_resolved);
			std::snprintf(b6, sizeof(b6), "%u", res.dispatcher_states_resolved);

			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Original", b1,
				accent_r, accent_g, accent_b, alpha);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Clean", b2,
				accent_r, accent_g, accent_b, alpha, green_col);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Junk Removed", b3,
				accent_r, accent_g, accent_b, alpha, opaque_col);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Opaques", b4,
				accent_r, accent_g, accent_b, alpha, warn_col);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Constants", b5,
				accent_r, accent_g, accent_b, alpha, green_col);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "States", b6,
				accent_r, accent_g, accent_b, alpha,
				ui_anim::theme_alpha(ui_anim::lighten(_t.text_secondary, 20), alpha));

			const char* cols[] = { "Address", "Instruction", "Status" };
			float col_w[] = { 120.f, 300.f, width - 420.f - pad * 2 };

			float hdr_y = table_y + card_h2 + 12.f;
			ui_anim::table_col_t deob_cols[] = {
				{ "Address", 120.f }, { "Instruction", 300.f }, { "Status", width - 420.f - pad * 2 }
			};
			ui_anim::render_table_header(dl, cx, hdr_y, width, row_h,
				deob_cols, 3, accent_r, accent_g, accent_b, cf_alpha);

			float list_y2 = hdr_y + row_h;
			float list_h2 = table_h - card_h2 - 16.f - row_h;
			int visible = static_cast<int>(list_h2 / row_h);

			auto& insns = res.clean_instructions;
			int total = static_cast<int>(insns.size());

			ImGui::SetCursorScreenPos(ImVec2(cx, list_y2));
			ImGui::InvisibleButton("##deob_scroll", ImVec2(width, list_h2));
			float max_s = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
			if (ImGui::IsItemHovered())
				ui_anim::handle_scroll_input(st.target_expr_scroll_y, 0.f, max_s, row_h);
			ui_anim::smooth_scroll(st.expr_scroll_y, st.target_expr_scroll_y, 12.f, dt);

			int start = static_cast<int>(st.expr_scroll_y / row_h);
			ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + list_h2), true);

			for (int i = start; i < total && i < start + visible + 1; ++i) {
				auto& ci = insns[i];
				float ry = list_y2 + (static_cast<float>(i - start)) * row_h
					- (st.expr_scroll_y - static_cast<float>(start) * row_h);
				if (ry + row_h < list_y2 || ry > list_y2 + list_h2) continue;

				float row_t = ui_anim::render_row_entrance(i - start, st.anim_time > 1.f ? 1.f : st.anim_time);

				ImU32 rbg = ci.was_junk ? _ta(ui_anim::darken(_t.panel_bg, 5)) : (i % 2 == 0 ? row_even : row_odd);
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), ui_anim::theme_alpha(rbg, row_t));

				ImU32 txt = ui_anim::theme_alpha(ci.was_junk ? junk_col : text_col, row_t);
				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(ci.address));

				float rx = cx + 4.f;
				dl->AddText(ImVec2(rx, ry + 2.f), txt, abuf);
				rx += col_w[0];

				if (ci.was_junk) {
					ImVec2 ts = ImGui::CalcTextSize(ci.disasm.c_str());
					dl->AddText(ImVec2(rx, ry + 2.f), txt, ci.disasm.c_str());
					dl->AddLine(ImVec2(rx, ry + row_h * 0.5f), ImVec2(rx + ts.x, ry + row_h * 0.5f),
						ui_anim::theme_alpha(_t.text_dim, 0.4f * row_t));
				} else {
					dl->AddText(ImVec2(rx, ry + 2.f), txt, ci.disasm.c_str());
				}
				rx += col_w[1];

				const char* status = ci.was_junk ? "JUNK" : (ci.was_opaque ? "OPAQUE" : (ci.was_constant_folded ? "CONST" : ""));
				ImU32 status_col = ci.was_junk ? opaque_col : (ci.was_opaque ? warn_col : green_col);
				if (status[0]) {
					ui_anim::render_badge(dl, status, rx, ry + 2.f,
						ui_anim::theme_alpha(_t.panel_header, 0.63f * alpha * row_t),
						ui_anim::theme_alpha(status_col, row_t));
				}
			}

			ImGui::PopClipRect();

			ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y2, 6.f, list_h2,
				st.expr_scroll_y, static_cast<float>(total) * row_h, list_h2,
				alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
		}
	}

	else if (st.active_tab == 2) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_slice;

		if (!res.success && res.error.empty() && !symbolic_engine::g_state.processing.load()) {
			ui_anim::render_empty_state(dl, cx, table_y, width, table_h,
				"Run Slice to extract relevant instructions for a register", accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			float card_h2 = 44.f;
			float card_w2 = (width - pad * 2.f - 8.f) / 3.f;
			float sx = cx + pad;
			float sy = table_y + 4.f;

			char bt[16], be[16], br[16];
			std::snprintf(bt, sizeof(bt), "%u", res.total_instructions);
			std::snprintf(be, sizeof(be), "%u", res.effective_count);
			std::snprintf(br, sizeof(br), "%u", res.removed_count);

			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Total", bt,
				accent_r, accent_g, accent_b, alpha);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Effective", be,
				accent_r, accent_g, accent_b, alpha, green_col);
			sx += card_w2 + 4.f;
			ui_anim::render_stat_card(dl, sx, sy, card_w2, card_h2, "Removed", br,
				accent_r, accent_g, accent_b, alpha, opaque_col);

			float hdr_y = table_y + card_h2 + 12.f;
			ui_anim::table_col_t slice_cols[] = {
				{ "Address", 120.f }, { "Instruction", width - 120.f }
			};
			ui_anim::render_table_header(dl, cx, hdr_y, width, row_h,
				slice_cols, 2, accent_r, accent_g, accent_b, cf_alpha);

			float list_y2 = hdr_y + row_h;
			float list_h2 = table_h - card_h2 - 16.f - row_h;
			auto& insns = res.effective_instructions;
			int total = static_cast<int>(insns.size());
			int visible_slice = static_cast<int>(list_h2 / row_h);

			float max_slice_scroll = (std::max)(0.f, static_cast<float>(total - visible_slice) * row_h);
			ImGui::SetCursorScreenPos(ImVec2(cx, list_y2));
			ImGui::InvisibleButton("##slice_scroll_area", ImVec2(width - 10.f, list_h2));
			if (ImGui::IsItemHovered())
				ui_anim::handle_scroll_input(st.target_expr_scroll_y, 0.f, max_slice_scroll, row_h * 3.f);
			ui_anim::smooth_scroll(st.expr_scroll_y, st.target_expr_scroll_y, 12.f, dt);
			ui_anim::clamp_scroll(st.expr_scroll_y, 0.f, max_slice_scroll);
			ui_anim::clamp_scroll(st.target_expr_scroll_y, 0.f, max_slice_scroll);

			int slice_start = static_cast<int>(st.expr_scroll_y / row_h);
			if (slice_start < 0) slice_start = 0;

			ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + list_h2), true);
			for (int i = slice_start; i < total && i < slice_start + visible_slice + 1; ++i) {
				float ry = list_y2 + static_cast<float>(i - slice_start) * row_h
					- (st.expr_scroll_y - static_cast<float>(slice_start) * row_h);
				if (ry + row_h < list_y2 || ry > list_y2 + list_h2) continue;

				float row_t = ui_anim::render_row_entrance(i - slice_start, st.anim_time > 1.f ? 1.f : st.anim_time);

				ImU32 rbg = (i % 2 == 0) ? row_even : row_odd;
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h), ui_anim::theme_alpha(rbg, row_t));

				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(insns[i].address));
				dl->AddText(ImVec2(cx + 4.f, ry + 2.f), ui_anim::theme_alpha(text_col, row_t), abuf);
				dl->AddText(ImVec2(cx + 124.f, ry + 2.f), ui_anim::theme_alpha(text_col, row_t), insns[i].disasm.c_str());
			}
			ImGui::PopClipRect();

			if (max_slice_scroll > 0.f) {
				ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y2, 6.f, list_h2,
					st.expr_scroll_y, static_cast<float>(total) * row_h, list_h2,
					alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
			}
		}
	}

	else if (st.active_tab == 3) {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_solve;

		if (!res.success && res.error.empty() && !symbolic_engine::g_state.processing.load()) {
			ui_anim::render_empty_state(dl, cx, table_y, width, table_h,
				"Run Solve Path to find inputs that reach a target address", accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else if (!res.success && !res.error.empty()) {
			dl->AddText(ImVec2(cx + pad, table_y + pad), opaque_col, res.error.c_str());
		} else if (res.success) {
			float ty = table_y + pad;

			if (res.satisfiable) {
				ui_anim::render_badge(dl, "SATISFIABLE", cx + pad, ty,
					_ta(ui_anim::darken(_t.panel_bg, 12)), green_col);
				ty += 26.f;

				char time_buf[64];
				std::snprintf(time_buf, sizeof(time_buf), "Solving time: %u ms", res.solving_time_ms);
				dl->AddText(ImVec2(cx + pad, ty), dim_col, time_buf);
				ty += 28.f;

				ui_anim::render_section_header(dl, cx, ty, width, 22.f, "Variable Solutions",
					accent_r, accent_g, accent_b, alpha);
				ty += 26.f;

				int vi = 0;
				for (auto& [name, val] : res.variable_values) {
					float row_t = ui_anim::render_row_entrance(vi, st.anim_time > 0.5f ? 1.f : st.anim_time);

					ImU32 rbg2 = (vi % 2 == 0) ? row_even : row_odd;
					dl->AddRectFilled(ImVec2(cx + pad, ty), ImVec2(cx + width - pad, ty + 20.f),
						ui_anim::theme_alpha(rbg2, row_t), 3.f);

					dl->AddText(ImVec2(cx + pad + 8.f, ty + 2.f),
						ui_anim::theme_alpha(accent, row_t), name.c_str());

					char vbuf[64];
					std::snprintf(vbuf, sizeof(vbuf), "0x%llX (%llu)",
						static_cast<unsigned long long>(val), static_cast<unsigned long long>(val));
					dl->AddText(ImVec2(cx + pad + 120.f, ty + 2.f),
						ui_anim::theme_alpha(text_col, row_t), vbuf);

					ty += 22.f;
					++vi;
				}
			} else {
				ui_anim::render_badge(dl, "UNSATISFIABLE", cx + pad, ty,
					_ta(ui_anim::darken(_t.panel_bg, 12)), opaque_col);
				ty += 26.f;
				dl->AddText(ImVec2(cx + pad, ty), dim_col, "No input values can reach the target address");
			}
		}
	}

	else if (st.active_tab == 4) {
		float ty = table_y + 4.f;
		ui_anim::render_section_header(dl, cx, ty, width, 22.f, "Symbolic Expression",
			accent_r, accent_g, accent_b, alpha);
		ty += 26.f;

		if (!st.expression_text.empty()) {
			dl->AddRectFilled(ImVec2(cx + pad, ty), ImVec2(cx + width - pad, cy + height - pad),
				_ta(_t.panel_bg), 6.f);
			dl->AddRect(ImVec2(cx + pad, ty), ImVec2(cx + width - pad, cy + height - pad),
				_ta(ui_anim::lighten(_t.panel_bg, 12)), 6.f);

			float wrap_w = width - pad * 4;
			ImGui::PushClipRect(ImVec2(cx + pad + 4.f, ty + 4.f),
				ImVec2(cx + width - pad - 4.f, cy + height - pad - 4.f), true);
			dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(cx + pad + 8.f, ty + 8.f),
				text_col, st.expression_text.c_str(), nullptr, wrap_w);
			ImGui::PopClipRect();
		} else {
			ui_anim::render_empty_state(dl, cx, ty, width, height - (ty - oy) - pad,
				"Select an instruction from the Trace tab to view its symbolic state",
				accent_r, accent_g, accent_b, alpha, st.anim_time);
		}
	}
	ImGui::EndChild();
}

}
