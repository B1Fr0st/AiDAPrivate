#pragma once

#include "symbolic_engine.hpp"
#include "work_queue.hpp"
#include "deobfuscation_engine.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/brand.hpp"
#include "../ui/fonts.hpp"
#include "../ui/toast_notification.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace symbolic_view {

struct ast_node_t {
	std::string label;
	std::vector<std::shared_ptr<ast_node_t>> children;
	bool expanded = true;
	int kind = 0;
};

struct local_state_t {
	char addr_buf[64] = "0x";
	char end_addr_buf[64] = "";
	char target_reg_buf[32] = "rax";
	char sym_regs_buf[128] = "rax,rbx,rcx,rdx";
	int max_insns = 10000;
	int selected_trace_row = -1;
	int hovered_trace_row = -1;
	float trace_scroll_y = 0.f;
	float target_trace_scroll_y = 0.f;
	float expr_scroll_y = 0.f;
	float target_expr_scroll_y = 0.f;
	int active_tab = 0;
	int prev_tab = 0;
	bool scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	bool show_junk = true;
	bool show_tainted_only = false;

	float tab_underline_x = 0.f;
	float tab_underline_w = 0.f;
	float tab_underline_vel = 0.f;
	aida::ui::transition_t content_swap;

	std::string expression_text;
	std::string simplified_text;
	std::shared_ptr<ast_node_t> ast_root;
	bool simplifying = false;

	aida::ui::transition_t sat_celebration;
	float unsat_shake_v = 0.f;
	int unsat_shake_seed = 0;

	std::string hover_constraint_regs;
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
	work_queue::post([addr, end, max_i = static_cast<uint32_t>(st.max_insns), regs]() {
		auto result = symbolic_engine::execute_symbolic(addr, end, max_i, regs, {});
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_result = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	});
}

inline void start_deobfuscate(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);

	deobfuscation_engine::g_state.processing.store(true);
	work_queue::post([addr, max_i = static_cast<uint32_t>(st.max_insns)]() {
		auto result = deobfuscation_engine::deobfuscate_function(addr, max_i);
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		deobfuscation_engine::g_state.last_result = std::move(result);
		deobfuscation_engine::g_state.processing.store(false);
	});
}

inline void start_slice(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t end = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	std::string target(st.target_reg_buf);

	symbolic_engine::g_state.processing.store(true);
	work_queue::post([addr, end, max_i = static_cast<uint32_t>(st.max_insns), target]() {
		auto result = symbolic_engine::slice_to_register(addr, end, max_i, target);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_slice = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	});
}

inline void start_solve(local_state_t& st) {
	uint64_t addr = std::strtoull(st.addr_buf, nullptr, 16);
	uint64_t target = st.end_addr_buf[0] ? std::strtoull(st.end_addr_buf, nullptr, 16) : 0;
	auto regs = parse_reg_list(st.sym_regs_buf);

	symbolic_engine::g_state.processing.store(true);
	work_queue::post([addr, target, max_i = static_cast<uint32_t>(st.max_insns), regs]() {
		auto result = symbolic_engine::solve_for_path(addr, target, max_i, regs);
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		symbolic_engine::g_state.last_solve = std::move(result);
		symbolic_engine::g_state.processing.store(false);
	});
}

inline std::shared_ptr<ast_node_t> parse_ast(const std::string& expr) {
	auto root = std::make_shared<ast_node_t>();
	root->label = "trace";
	root->kind = 1;
	if (expr.empty()) {
		root->label = "<empty>";
		return root;
	}

	size_t pos = 0;
	auto skip_ws = [&]() {
		while (pos < expr.size() && (expr[pos] == ' ' || expr[pos] == '\n' ||
			expr[pos] == '\t' || expr[pos] == '\r' ||
			expr[pos] == ';' || expr[pos] == ',')) ++pos;
	};

	std::function<std::shared_ptr<ast_node_t>()> parse_one;
	parse_one = [&]() -> std::shared_ptr<ast_node_t> {
		skip_ws();
		if (pos >= expr.size()) return nullptr;
		auto node = std::make_shared<ast_node_t>();
		if (expr[pos] == '(') {
			++pos;
			skip_ws();
			std::string head;
			while (pos < expr.size() && expr[pos] != ' ' && expr[pos] != '(' &&
				   expr[pos] != ')' && expr[pos] != '\n' && expr[pos] != '\t') {
				head += expr[pos++];
			}
			node->label = head.empty() ? "expr" : head;
			node->kind = 1;
			while (pos < expr.size() && expr[pos] != ')') {
				skip_ws();
				if (pos >= expr.size() || expr[pos] == ')') break;
				auto child = parse_one();
				if (child) node->children.push_back(child);
				skip_ws();
			}
			if (pos < expr.size() && expr[pos] == ')') ++pos;
		} else {
			std::string atom;
			while (pos < expr.size() && expr[pos] != ' ' && expr[pos] != '(' &&
				   expr[pos] != ')' && expr[pos] != '\n' && expr[pos] != '\t' &&
				   expr[pos] != ';' && expr[pos] != ',') {
				atom += expr[pos++];
			}
			if (atom.empty()) {
				++pos;
				return nullptr;
			}
			if (atom == "=") {
				node->label = "=";
				node->kind = 1;
				skip_ws();
				if (pos < expr.size() && expr[pos] != ')' && expr[pos] != ';') {
					auto rhs = parse_one();
					if (rhs) node->children.push_back(rhs);
				}
				return node;
			}
			node->label = atom;
			node->kind = 0;
		}
		return node;
	};

	while (pos < expr.size()) {
		skip_ws();
		if (pos >= expr.size()) break;
		auto top = parse_one();
		if (!top) continue;
		if (top->label == "=" && !top->children.empty()) {
			root->children.push_back(top);
			continue;
		}
		if (pos < expr.size()) {
			skip_ws();
			if (pos < expr.size() && expr[pos] != ')' && expr[pos] != ';') {
				auto next_atom = parse_one();
				if (next_atom && next_atom->label == "=" && !next_atom->children.empty()) {
					next_atom->children.insert(next_atom->children.begin(), top);
					next_atom->label = "=";
					root->children.push_back(next_atom);
					continue;
				}
				if (next_atom) root->children.push_back(next_atom);
			}
		}
		root->children.push_back(top);
	}

	if (root->children.empty()) {
		root->label = expr.size() > 64 ? expr.substr(0, 60) + "..." : expr;
		root->kind = 0;
	} else if (root->children.size() == 1) {
		return root->children[0];
	}

	return root;
}

inline ImU32 ast_node_color(const aida::ui::theme_t& t, const ast_node_t& n) {
	if (n.kind == 0) {
		const std::string& s = n.label;
		if (!s.empty() && (s[0] == '#' || (s.size() > 2 && s[0] == '0' && s[1] == 'x')))
			return t.syn_number;
		if (s == "true" || s == "false") return t.syn_keyword;
		return t.syn_identifier;
	}
	if (n.label == "bvadd" || n.label == "bvsub" || n.label == "bvmul" ||
		n.label == "bvand" || n.label == "bvor"  || n.label == "bvxor" ||
		n.label == "bvshl" || n.label == "bvlshr" || n.label == "bvashr")
		return t.syn_operator;
	if (n.label == "ite" || n.label == "and" || n.label == "or" ||
		n.label == "not" || n.label == "=" || n.label == "bvult" || n.label == "bvslt")
		return t.syn_keyword;
	return t.syn_function;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y; (void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##symbolic_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	auto& st = s_state;
	float dt = aida::ui::clock::dt();

	const auto& t = aida::ui::resolved();
	const ImU32 row_even  = aida::ui::with_alpha(t.panel_bg, 0.45f * alpha);
	const ImU32 row_odd   = aida::ui::with_alpha(t.bg_elevated, 0.4f * alpha);
	const ImU32 row_hover = aida::ui::with_alpha(t.hover_wash, alpha);
	const ImU32 sel_col   = aida::ui::with_alpha(t.selection, alpha);
	const ImU32 taint_col = t.warning;
	const ImU32 junk_col  = aida::ui::with_alpha(t.text_dim, 0.47f);
	const ImU32 opaque_col = t.error;
	const ImU32 success_col = t.success;
	const ImU32 warn_col   = t.warning;

	float cx = ox;
	float cy = oy;

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height),
		aida::ui::with_alpha(t.bg_base, alpha));

	const float toolbar_h = 116.f;
	const float pad = 12.f;
	const float row_h = 22.f;

	ImVec2 toolbar_a(cx + 6.f, cy + 6.f);
	ImVec2 toolbar_b(cx + width - 6.f, cy + toolbar_h - 6.f);
	aida::ui::blur::render_drop_shadow(dl, toolbar_a, toolbar_b, 12.f, 4, 0.22f * alpha, ImVec2(0.f, 4.f));
	dl->AddRectFilled(toolbar_a, toolbar_b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), 12.f);
	dl->AddRectFilled(toolbar_a, toolbar_b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha), 12.f);
	dl->AddRect(toolbar_a, toolbar_b, aida::ui::with_alpha(t.border_subtle, alpha), 12.f, 0, 1.f);

	auto label_at = [&](float lx, float ly, const char* text) {
		ImGui::SetCursorScreenPos(ImVec2(lx, ly));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
		ImGui::TextUnformatted(text);
		ImGui::PopStyleColor();
	};

	auto input_at = [&](float ix, float iy, float w, const char* id, char* buf, size_t bufsz) {
		ImGui::SetCursorScreenPos(ImVec2(ix, iy));
		ImGui::SetNextItemWidth(w);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::PushFont(aida::ui::fonts::code());
		ImGui::InputText(id, buf, bufsz);
		ImGui::PopFont();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);
	};

	float row1_y = cy + 14.f;
	label_at(cx + pad + 8.f, row1_y + 6.f, "Entry");
	input_at(cx + pad + 60.f, row1_y, 150.f, "##sym_addr", st.addr_buf, sizeof(st.addr_buf));
	label_at(cx + pad + 224.f, row1_y + 6.f, "End/Target");
	input_at(cx + pad + 300.f, row1_y, 150.f, "##sym_end", st.end_addr_buf, sizeof(st.end_addr_buf));
	label_at(cx + pad + 462.f, row1_y + 6.f, "Target Reg");
	input_at(cx + pad + 540.f, row1_y, 90.f, "##sym_treg", st.target_reg_buf, sizeof(st.target_reg_buf));

	float row2_y = cy + 48.f;
	label_at(cx + pad + 8.f, row2_y + 6.f, "Symbolic Regs");
	input_at(cx + pad + 110.f, row2_y, 220.f, "##sym_regs", st.sym_regs_buf, sizeof(st.sym_regs_buf));
	label_at(cx + pad + 344.f, row2_y + 6.f, "Max");
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 388.f, row2_y + 2.f));
	ImGui::SetNextItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, alpha));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::SliderInt("##sym_max", &st.max_insns, 100, 100000, "");
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(2);

	{
		char vbuf[24];
		std::snprintf(vbuf, sizeof(vbuf), "%d", st.max_insns);
		ImGui::SetCursorScreenPos(ImVec2(cx + pad + 388.f + 128.f, row2_y + 6.f));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::TextUnformatted(vbuf);
		ImGui::PopStyleColor();
	}

	bool busy = symbolic_engine::g_state.processing.load() ||
		deobfuscation_engine::g_state.processing.load();

	float btn_y = cy + 80.f;
	float btn_x = cx + pad + 8.f;

	auto run_btn = [&](const char* label, int target_tab, void (*starter)(local_state_t&)) {
		ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
		bool clicked = aida::ui::components::button(label,
			busy ? aida::ui::components::button_kind_t::secondary
			     : aida::ui::components::button_kind_t::primary,
			aida::ui::components::size_t_::sm,
			ImVec2(108.f, 26.f), busy, nullptr, busy);
		if (clicked && !busy) {
			starter(st);
			st.prev_tab = st.active_tab;
			st.active_tab = target_tab;
			st.content_swap.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
		}
		btn_x += 116.f;
	};

	run_btn("Symbolize", 0, &detail::start_symbolic_exec);
	run_btn("Deobfuscate", 1, &detail::start_deobfuscate);
	run_btn("Slice", 2, &detail::start_slice);
	run_btn("Solve Path", 3, &detail::start_solve);

	if (busy) {
		uint32_t cur = symbolic_engine::g_state.progress_current.load();
		uint32_t tot = symbolic_engine::g_state.progress_total.load();
		if (tot == 0) {
			cur = deobfuscation_engine::g_state.progress_current.load();
			tot = deobfuscation_engine::g_state.progress_total.load();
		}
		float frac = (tot > 0) ? static_cast<float>(cur) / static_cast<float>(tot) : 0.f;
		float bar_x = btn_x + 8.f;
		float bar_y = btn_y + 9.f;
		float bar_w = (std::min)(220.f, cx + width - pad - 6.f - bar_x);
		if (bar_w > 24.f) {
			aida::ui::components::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 12.f, frac, tot == 0, true);
		}
	}

	float opt_x = cx + width - 280.f;
	ImGui::SetCursorScreenPos(ImVec2(opt_x, btn_y + 4.f));
	aida::ui::toggle_switch("Show junk##sym_junk", &st.show_junk, aida::ui::size_t_::sm);
	ImGui::SameLine(0.f, 14.f);
	aida::ui::toggle_switch("Tainted##sym_taint", &st.show_tainted_only, aida::ui::size_t_::sm);

	float content_y = cy + toolbar_h + 6.f;
	float content_h = height - toolbar_h - 12.f;

	const char* tab_labels[] = { "Trace", "Deobfuscation", "Slice", "Solver", "Constraints", "Expression" };
	const int tab_count = 6;
	float tab_x = cx + pad;
	float tab_strip_y = content_y;

	dl->AddRectFilled(ImVec2(cx + 6.f, tab_strip_y), ImVec2(cx + width - 6.f, tab_strip_y + 30.f),
		aida::ui::with_alpha(t.panel_bg, 0.7f * alpha), 8.f);
	dl->AddLine(ImVec2(cx + 6.f, tab_strip_y + 29.f), ImVec2(cx + width - 6.f, tab_strip_y + 29.f),
		aida::ui::with_alpha(t.border_subtle, alpha));

	float target_ux = cx + pad;
	float target_uw = 0.f;

	for (int i = 0; i < tab_count; ++i) {
		ImVec2 lsz = aida::ui::fonts::body()->CalcTextSizeA(13.f, FLT_MAX, 0.f, tab_labels[i]);
		float tab_btn_w = lsz.x + 24.f;
		if (i == st.active_tab) { target_ux = tab_x; target_uw = tab_btn_w; }

		ImGui::SetCursorScreenPos(ImVec2(tab_x, tab_strip_y));
		ImGui::InvisibleButton(tab_labels[i], ImVec2(tab_btn_w, 28.f));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		if (clicked) {
			st.prev_tab = st.active_tab;
			st.active_tab = i;
			st.content_swap.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
		}

		float text_alpha_val = (st.active_tab == i) ? 1.0f : (hov ? 0.85f : 0.55f);

		if (hov && st.active_tab != i) {
			dl->AddRectFilled(ImVec2(tab_x, tab_strip_y),
				ImVec2(tab_x + tab_btn_w, tab_strip_y + 28.f),
				aida::ui::with_alpha(t.hover_wash, alpha), 6.f, ImDrawFlags_RoundCornersTop);
		}

		dl->AddText(aida::ui::fonts::body_em(), 13.f,
			ImVec2(tab_x + 12.f, tab_strip_y + 7.f),
			aida::ui::with_alpha(t.text_primary, text_alpha_val * alpha), tab_labels[i]);

		tab_x += tab_btn_w + 4.f;
	}

	if (st.tab_underline_w < 1.f) {
		st.tab_underline_x = target_ux;
		st.tab_underline_w = target_uw;
	}
	st.tab_underline_x = aida::motion::spring_step(st.tab_underline_x, target_ux,
		st.tab_underline_vel, aida::motion::spring::balanced, dt);
	float dummy_v = 0.f;
	st.tab_underline_w = aida::motion::spring_step(st.tab_underline_w, target_uw,
		dummy_v, aida::motion::spring::balanced, dt);

	dl->AddRectFilledMultiColor(
		ImVec2(st.tab_underline_x + 4.f, tab_strip_y + 26.f),
		ImVec2(st.tab_underline_x + st.tab_underline_w - 4.f, tab_strip_y + 30.f),
		aida::ui::with_alpha(t.accent_grad_top, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha),
		aida::ui::with_alpha(t.accent_grad_top, alpha));

	st.content_swap.tick(dt);

	float table_y = content_y + 32.f;
	float table_h = content_h - 32.f;

	auto draw_trace_tab = [&]() {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_result;

		if (res.trace.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::flow;
			cfg.title = "Symbolic trace empty";
			cfg.body  = "Run Symbolize to step through with symbolic registers (e.g. rax, rcx).";
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}

		auto& trace = res.trace;
		int total = static_cast<int>(trace.size());

		struct col_t { const char* label; float w; };
		col_t cols[] = {
			{ "Address",        130.f },
			{ "Instruction",    240.f },
			{ "Symbolic State", width - 130.f - 240.f - 90.f - pad * 2.f },
			{ "T",               24.f },
			{ "J",               24.f },
			{ "OP",              26.f }
		};

		float hdr_y = table_y;
		dl->AddRectFilled(ImVec2(cx + pad, hdr_y), ImVec2(cx + width - pad, hdr_y + row_h),
			aida::ui::with_alpha(t.panel_header, 0.85f * alpha), 6.f);
		float hx = cx + pad + 12.f;
		for (auto& c : cols) {
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(hx, hdr_y + (row_h - 11.f) * 0.5f),
				aida::ui::with_alpha(t.text_dim, alpha), c.label);
			hx += c.w;
		}

		float list_y = hdr_y + row_h + 2.f;
		float list_h = table_h - row_h - 56.f;
		int visible_rows = static_cast<int>(list_h / row_h);

		ImGui::SetCursorScreenPos(ImVec2(cx, list_y));
		ImGui::InvisibleButton("##sym_trace_scroll", ImVec2(width, list_h));
		float max_scroll = (std::max)(0.f, static_cast<float>(total - visible_rows) * row_h);
		if (ImGui::IsItemHovered())
			ui_anim::handle_scroll_input(st.target_trace_scroll_y, 0.f, max_scroll, row_h);
		ui_anim::smooth_scroll(st.trace_scroll_y, st.target_trace_scroll_y, 12.f, dt);

		int start_row = static_cast<int>(st.trace_scroll_y / row_h);
		if (start_row < 0) start_row = 0;
		ImGui::PushClipRect(ImVec2(cx, list_y), ImVec2(cx + width, list_y + list_h), true);

		static float row_acc = 0.f;
		row_acc += dt;

		st.hovered_trace_row = -1;

		for (int i = start_row; i < total && i < start_row + visible_rows + 1; ++i) {
			auto& tr = trace[i];
			if (st.show_tainted_only && !tr.is_tainted) continue;
			if (!st.show_junk && tr.is_junk) continue;

			float ry = list_y + (static_cast<float>(i) - static_cast<float>(start_row)) * row_h
				- (st.trace_scroll_y - static_cast<float>(start_row) * row_h);
			if (ry + row_h < list_y || ry > list_y + list_h) continue;

			float row_t = ui_anim::render_row_entrance(i - start_row, row_acc, 0.012f);

			ImU32 rbg = (i == st.selected_trace_row) ? sel_col : (i % 2 == 0 ? row_even : row_odd);

			ImGui::SetCursorScreenPos(ImVec2(cx, ry));
			ImGui::InvisibleButton(("##trow" + std::to_string(i)).c_str(), ImVec2(width, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			if (hov) { rbg = row_hover; st.hovered_trace_row = i; }
			if (clicked) {
				st.selected_trace_row = i;
				st.expression_text = tr.symbolic_state;
				st.simplified_text.clear();
				st.ast_root = detail::parse_ast(tr.symbolic_state);
				st.prev_tab = st.active_tab;
				st.active_tab = 5;
				st.content_swap.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
			}

			if (!st.hover_constraint_regs.empty()) {
				bool affected = false;
				for (auto& wr : tr.written_regs) {
					if (st.hover_constraint_regs.find(wr) != std::string::npos) { affected = true; break; }
				}
				if (!affected) for (auto& rr : tr.read_regs) {
					if (st.hover_constraint_regs.find(rr) != std::string::npos) { affected = true; break; }
				}
				if (affected) rbg = aida::ui::with_alpha(t.accent_glow, alpha * 0.55f);
			}

			dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + width, ry + row_h),
				aida::ui::with_alpha(rbg, row_t), 4.f);

			if (i == st.selected_trace_row) {
				dl->AddRectFilled(ImVec2(cx, ry), ImVec2(cx + 3.f, ry + row_h),
					aida::ui::with_alpha(t.accent_u32, 0.85f * alpha * row_t), 4.f);
			}

			ImU32 row_text = aida::ui::with_alpha(
				tr.is_junk ? junk_col : (tr.is_tainted ? taint_col : t.text_primary),
				alpha * row_t);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(tr.address));

			float rx = cx + pad + 4.f;
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_address, alpha * row_t), abuf);
			rx += cols[0].w;

			std::string disp = tr.disasm;
			if (disp.size() > 36) disp = disp.substr(0, 33) + "...";
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f), row_text, disp.c_str());
			rx += cols[1].w;

			std::string sym_short = tr.symbolic_state;
			if (sym_short.size() > 90) sym_short = sym_short.substr(0, 87) + "...";
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_dim, alpha * row_t), sym_short.c_str());
			rx += cols[2].w;

			if (tr.is_tainted) {
				ImGui::SetCursorScreenPos(ImVec2(rx + 1.f, ry + 3.f));
				aida::ui::components::badge("T", aida::ui::with_alpha(taint_col, alpha * row_t), 4.f);
			}
			rx += cols[3].w;
			if (tr.is_junk) {
				ImGui::SetCursorScreenPos(ImVec2(rx + 1.f, ry + 3.f));
				aida::ui::components::badge("J", aida::ui::with_alpha(junk_col, alpha * row_t), 4.f);
			}
			rx += cols[4].w;
			if (tr.is_opaque_predicate) {
				ImGui::SetCursorScreenPos(ImVec2(rx, ry + 3.f));
				aida::ui::components::badge("OP", aida::ui::with_alpha(opaque_col, alpha * row_t), 4.f);
			}
		}

		ImGui::PopClipRect();
		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y, 6.f, list_h,
			st.trace_scroll_y, static_cast<float>(total) * row_h, list_h,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);

		float stats_y = list_y + list_h + 8.f;
		float card_w = (width - pad * 2.f - 18.f) / 4.f;
		float card_h = 44.f;
		float ssx = cx + pad;

		auto stat_chip = [&](const char* label, const char* value, ImU32 stripe) {
			ImVec2 a(ssx, stats_y);
			ImVec2 b(ssx + card_w, stats_y + card_h);
			aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 3, 0.18f * alpha);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), 10.f);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha), 10.f);
			dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);
			dl->AddRectFilled(a, ImVec2(a.x + 3.f, b.y),
				aida::ui::with_alpha(stripe, 0.85f * alpha), 10.f);
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(a.x + 12.f, a.y + 5.f),
				aida::ui::with_alpha(t.text_dim, alpha), label);
			dl->AddText(aida::ui::fonts::body_strong(), 18.f,
				ImVec2(a.x + 12.f, a.y + card_h - 22.f),
				aida::ui::with_alpha(t.text_primary, alpha), value);
			ssx += card_w + 6.f;
		};

		char b1[16], b2[16], b3[16], b4[16];
		std::snprintf(b1, sizeof(b1), "%u", res.total_instructions);
		std::snprintf(b2, sizeof(b2), "%u", res.tainted_count);
		std::snprintf(b3, sizeof(b3), "%u", res.opaque_count);
		std::snprintf(b4, sizeof(b4), "%u", res.constants_count);
		stat_chip("Instructions", b1, t.accent_u32);
		stat_chip("Tainted",      b2, taint_col);
		stat_chip("Opaque",       b3, opaque_col);
		stat_chip("Constants",    b4, success_col);
	};

	auto draw_deob_tab = [&]() {
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		auto& res = deobfuscation_engine::g_state.last_result;

		if (!res.success && res.error.empty() && !deobfuscation_engine::g_state.processing.load()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::flow;
			cfg.title = "Run Deobfuscate";
			cfg.body  = "Strip junk, fold constants, and resolve dispatcher states.";
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success && !res.error.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "Deobfuscation failed";
			cfg.body  = res.error;
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success) return;

		float card_w2 = (width - pad * 2.f - 30.f) / 6.f;
		float card_h2 = 44.f;
		float sx = cx + pad;
		float sy = table_y + 4.f;

		auto chip = [&](const char* label, const char* value, ImU32 stripe) {
			ImVec2 a(sx, sy);
			ImVec2 b(sx + card_w2, sy + card_h2);
			aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 3, 0.18f * alpha);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), 10.f);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha), 10.f);
			dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);
			dl->AddRectFilled(a, ImVec2(a.x + 3.f, b.y),
				aida::ui::with_alpha(stripe, 0.85f * alpha), 10.f);
			dl->AddText(aida::ui::fonts::caption(), 11.f, ImVec2(a.x + 10.f, a.y + 5.f),
				aida::ui::with_alpha(t.text_dim, alpha), label);
			dl->AddText(aida::ui::fonts::body_strong(), 17.f,
				ImVec2(a.x + 10.f, a.y + card_h2 - 22.f),
				aida::ui::with_alpha(t.text_primary, alpha), value);
			sx += card_w2 + 6.f;
		};

		char b1[16], b2[16], b3[16], b4[16], b5[16], b6[16];
		std::snprintf(b1, sizeof(b1), "%u", res.total_original);
		std::snprintf(b2, sizeof(b2), "%u", res.total_clean);
		std::snprintf(b3, sizeof(b3), "%.1f%%", res.junk_ratio * 100.f);
		std::snprintf(b4, sizeof(b4), "%u", res.opaque_predicates_found);
		std::snprintf(b5, sizeof(b5), "%u", res.constants_resolved);
		std::snprintf(b6, sizeof(b6), "%u", res.dispatcher_states_resolved);

		chip("Original",  b1, t.accent_u32);
		chip("Clean",     b2, success_col);
		chip("Junk",      b3, opaque_col);
		chip("Opaques",   b4, warn_col);
		chip("Constants", b5, success_col);
		chip("States",    b6, t.text_secondary);

		float hdr_y = table_y + card_h2 + 12.f;
		dl->AddRectFilled(ImVec2(cx + pad, hdr_y), ImVec2(cx + width - pad, hdr_y + row_h),
			aida::ui::with_alpha(t.panel_header, 0.85f * alpha), 6.f);
		float hxx = cx + pad + 12.f;
		const char* dcols[] = { "Address", "Instruction", "Status" };
		float dwid[] = { 130.f, width * 0.55f, 80.f };
		for (int i = 0; i < 3; ++i) {
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(hxx, hdr_y + (row_h - 11.f) * 0.5f),
				aida::ui::with_alpha(t.text_dim, alpha), dcols[i]);
			hxx += dwid[i];
		}

		float list_y2 = hdr_y + row_h + 2.f;
		float list_h2 = table_h - card_h2 - 16.f - row_h;

		auto& insns = res.clean_instructions;
		int total = static_cast<int>(insns.size());
		int visible = static_cast<int>(list_h2 / row_h);

		ImGui::SetCursorScreenPos(ImVec2(cx, list_y2));
		ImGui::InvisibleButton("##deob_scroll", ImVec2(width, list_h2));
		float max_s = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
		if (ImGui::IsItemHovered())
			ui_anim::handle_scroll_input(st.target_expr_scroll_y, 0.f, max_s, row_h);
		ui_anim::smooth_scroll(st.expr_scroll_y, st.target_expr_scroll_y, 12.f, dt);

		int start = static_cast<int>(st.expr_scroll_y / row_h);
		ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + list_h2), true);

		static float row_acc = 0.f;
		row_acc += dt;

		for (int i = start; i < total && i < start + visible + 1; ++i) {
			auto& ci = insns[i];
			float ry = list_y2 + (static_cast<float>(i - start)) * row_h
				- (st.expr_scroll_y - static_cast<float>(start) * row_h);
			if (ry + row_h < list_y2 || ry > list_y2 + list_h2) continue;

			float row_t = ui_anim::render_row_entrance(i - start, row_acc, 0.012f);

			ImU32 rbg = ci.was_junk
				? aida::ui::with_alpha(t.bg_overlay, 0.65f * alpha)
				: (i % 2 == 0 ? row_even : row_odd);
			dl->AddRectFilled(ImVec2(cx + pad, ry), ImVec2(cx + width - pad, ry + row_h),
				aida::ui::with_alpha(rbg, row_t), 4.f);

			ImU32 txt = aida::ui::with_alpha(ci.was_junk ? junk_col : t.text_primary, alpha * row_t);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(ci.address));
			float rx = cx + pad + 12.f;
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_address, alpha * row_t), abuf);
			rx += dwid[0];

			std::string disp = ci.disasm;
			if (disp.size() > 60) disp = disp.substr(0, 57) + "...";
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(rx, ry + (row_h - 12.f) * 0.5f), txt, disp.c_str());
			if (ci.was_junk) {
				float text_w = aida::ui::fonts::code()->CalcTextSizeA(12.f, FLT_MAX, 0.f, disp.c_str()).x;
				dl->AddLine(ImVec2(rx, ry + row_h * 0.5f),
					ImVec2(rx + text_w, ry + row_h * 0.5f),
					aida::ui::with_alpha(opaque_col, 0.7f * alpha * row_t), 1.4f);
			}
			rx += dwid[1];

			const char* status = ci.was_junk ? "JUNK"
				: (ci.was_opaque ? "OPAQUE"
				: (ci.was_constant_folded ? "CONST" : ""));
			ImU32 status_col = ci.was_junk ? opaque_col
				: (ci.was_opaque ? warn_col : success_col);
			if (status[0]) {
				ImGui::SetCursorScreenPos(ImVec2(rx, ry + 3.f));
				aida::ui::components::badge(status,
					aida::ui::with_alpha(status_col, alpha * row_t), 4.f);
			}
		}

		ImGui::PopClipRect();
		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y2, 6.f, list_h2,
			st.expr_scroll_y, static_cast<float>(total) * row_h, list_h2,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	};

	auto draw_slice_tab = [&]() {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_slice;

		if (!res.success && res.error.empty() && !symbolic_engine::g_state.processing.load()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::flow;
			cfg.title = "Run Slice";
			cfg.body  = "Extract instructions affecting a target register.";
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success && !res.error.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "Slice failed";
			cfg.body  = res.error;
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success) return;

		float card_h2 = 44.f;
		float card_w2 = (width - pad * 2.f - 12.f) / 3.f;
		float sx = cx + pad;
		float sy = table_y + 4.f;

		auto chip = [&](const char* label, const char* value, ImU32 stripe) {
			ImVec2 a(sx, sy);
			ImVec2 b(sx + card_w2, sy + card_h2);
			aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 3, 0.18f * alpha);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), 10.f);
			dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);
			dl->AddRectFilled(a, ImVec2(a.x + 3.f, b.y),
				aida::ui::with_alpha(stripe, 0.85f * alpha), 10.f);
			dl->AddText(aida::ui::fonts::caption(), 11.f, ImVec2(a.x + 12.f, a.y + 6.f),
				aida::ui::with_alpha(t.text_dim, alpha), label);
			dl->AddText(aida::ui::fonts::body_strong(), 18.f,
				ImVec2(a.x + 12.f, a.y + card_h2 - 22.f),
				aida::ui::with_alpha(t.text_primary, alpha), value);
			sx += card_w2 + 6.f;
		};

		char bt[16], be[16], br[16];
		std::snprintf(bt, sizeof(bt), "%u", res.total_instructions);
		std::snprintf(be, sizeof(be), "%u", res.effective_count);
		std::snprintf(br, sizeof(br), "%u", res.removed_count);
		chip("Total", bt, t.accent_u32);
		chip("Effective", be, success_col);
		chip("Removed", br, opaque_col);

		float hdr_y = table_y + card_h2 + 12.f;
		dl->AddRectFilled(ImVec2(cx + pad, hdr_y), ImVec2(cx + width - pad, hdr_y + row_h),
			aida::ui::with_alpha(t.panel_header, 0.85f * alpha), 6.f);
		dl->AddText(aida::ui::fonts::caption(), 11.f,
			ImVec2(cx + pad + 12.f, hdr_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), "Address");
		dl->AddText(aida::ui::fonts::caption(), 11.f,
			ImVec2(cx + pad + 142.f, hdr_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), "Instruction");

		float list_y2 = hdr_y + row_h + 2.f;
		float list_h2 = table_h - card_h2 - 16.f - row_h;

		auto& insns = res.effective_instructions;
		int total = static_cast<int>(insns.size());
		int visible = static_cast<int>(list_h2 / row_h);

		float max_s = (std::max)(0.f, static_cast<float>(total - visible) * row_h);
		ImGui::SetCursorScreenPos(ImVec2(cx, list_y2));
		ImGui::InvisibleButton("##slice_scroll_area", ImVec2(width - 10.f, list_h2));
		if (ImGui::IsItemHovered())
			ui_anim::handle_scroll_input(st.target_expr_scroll_y, 0.f, max_s, row_h * 3.f);
		ui_anim::smooth_scroll(st.expr_scroll_y, st.target_expr_scroll_y, 12.f, dt);
		ui_anim::clamp_scroll(st.expr_scroll_y, 0.f, max_s);
		ui_anim::clamp_scroll(st.target_expr_scroll_y, 0.f, max_s);

		int start = static_cast<int>(st.expr_scroll_y / row_h);
		if (start < 0) start = 0;

		ImGui::PushClipRect(ImVec2(cx, list_y2), ImVec2(cx + width, list_y2 + list_h2), true);

		static float row_acc = 0.f;
		row_acc += dt;

		for (int i = start; i < total && i < start + visible + 1; ++i) {
			float ry = list_y2 + static_cast<float>(i - start) * row_h
				- (st.expr_scroll_y - static_cast<float>(start) * row_h);
			if (ry + row_h < list_y2 || ry > list_y2 + list_h2) continue;

			float row_t = ui_anim::render_row_entrance(i - start, row_acc, 0.012f);
			ImU32 rbg = (i % 2 == 0) ? row_even : row_odd;
			dl->AddRectFilled(ImVec2(cx + pad, ry), ImVec2(cx + width - pad, ry + row_h),
				aida::ui::with_alpha(rbg, row_t), 4.f);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(insns[i].address));
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(cx + pad + 12.f, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_address, alpha * row_t), abuf);
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(cx + pad + 142.f, ry + (row_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_primary, alpha * row_t), insns[i].disasm.c_str());
		}
		ImGui::PopClipRect();
		ui_anim::render_custom_scrollbar(dl, cx + width - 8.f, list_y2, 6.f, list_h2,
			st.expr_scroll_y, static_cast<float>(total) * row_h, list_h2,
			alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	};

	auto draw_solver_tab = [&]() {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& res = symbolic_engine::g_state.last_solve;

		if (!res.success && res.error.empty() && !symbolic_engine::g_state.processing.load()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "Run Solve Path";
			cfg.body  = "Find inputs that drive execution to the target address.";
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success && !res.error.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "Solver failed";
			cfg.body  = res.error;
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}
		if (!res.success) return;

		static bool last_was_sat = false;
		static bool last_was_unsat = false;
		if (res.satisfiable && !last_was_sat) {
			st.sat_celebration.start(0.6f, aida::motion::ease::out_quint);
			last_was_sat = true;
			last_was_unsat = false;
		} else if (!res.satisfiable && !last_was_unsat) {
			st.unsat_shake_v = 1.f;
			st.unsat_shake_seed = static_cast<int>(aida::ui::clock::frame_index());
			last_was_unsat = true;
			last_was_sat = false;
		}
		st.sat_celebration.tick(dt);
		st.unsat_shake_v = (std::max)(0.f, st.unsat_shake_v - dt * 3.6f);

		float ty = table_y + 8.f;
		float shake_off = 0.f;
		if (st.unsat_shake_v > 0.f) {
			float p = aida::ui::clock::seconds() * 22.f + static_cast<float>(st.unsat_shake_seed);
			shake_off = std::sin(p) * 6.f * st.unsat_shake_v;
		}

		ImVec2 hdr_a(cx + pad + shake_off, ty);
		ImVec2 hdr_b(cx + pad + 220.f + shake_off, ty + 38.f);

		ImU32 banner_col = res.satisfiable ? success_col : opaque_col;
		dl->AddRectFilled(hdr_a, hdr_b, aida::ui::with_alpha(banner_col, 0.18f * alpha), 10.f);
		dl->AddRect(hdr_a, hdr_b, aida::ui::with_alpha(banner_col, 0.85f * alpha), 10.f, 0, 1.f);
		dl->AddText(aida::ui::fonts::body_strong(), 16.f,
			ImVec2(hdr_a.x + 14.f, hdr_a.y + 10.f),
			aida::ui::with_alpha(banner_col, alpha),
			res.satisfiable ? "SATISFIABLE" : "UNSATISFIABLE");

		if (res.satisfiable && st.sat_celebration.progress > 0.001f) {
			float p = st.sat_celebration.eased();
			ImVec2 cc(hdr_a.x + 110.f, hdr_a.y + 19.f);
			aida::ui::brand::render_sparkle_burst(dl, cc, p, 60.f,
				aida::ui::with_alpha(t.accent_u32, alpha), 10);
			aida::ui::brand::render_check_drawn(dl,
				ImVec2(hdr_b.x + 26.f, hdr_a.y + 19.f), 18.f, p,
				aida::ui::with_alpha(success_col, alpha), 2.5f);
		}

		ty += 50.f;

		if (res.satisfiable) {
			char tbuf[64];
			std::snprintf(tbuf, sizeof(tbuf), "Solved in %u ms", res.solving_time_ms);
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(cx + pad + 6.f, ty),
				aida::ui::with_alpha(t.text_dim, alpha), tbuf);
			ty += 16.f;

			dl->AddText(aida::ui::fonts::body_em(), 12.f,
				ImVec2(cx + pad + 6.f, ty),
				aida::ui::with_alpha(t.text_secondary, alpha), "VARIABLE ASSIGNMENTS");
			dl->AddLine(ImVec2(cx + pad, ty + 16.f),
				ImVec2(cx + width - pad, ty + 16.f),
				aida::ui::with_alpha(t.border_subtle, alpha));
			ty += 22.f;

			float card_w = 260.f;
			float card_h = 64.f;
			float gap = 10.f;
			int per_row = (std::max)(1, static_cast<int>((width - pad * 2.f) / (card_w + gap)));
			int idx = 0;
			float row_top = ty;

			static float entrance_acc = 0.f;
			entrance_acc += dt;

			for (auto& [name, val] : res.variable_values) {
				int col = idx % per_row;
				int row = idx / per_row;
				float vx = cx + pad + static_cast<float>(col) * (card_w + gap);
				float vy = row_top + static_cast<float>(row) * (card_h + gap);
				if (vy + card_h > cy + height - 8.f) break;

				float ent = ui_anim::render_row_entrance(idx, entrance_acc, 0.025f);
				float ent_off = (1.f - ent) * 8.f;

				ImVec2 a(vx, vy + ent_off);
				ImVec2 b(vx + card_w, vy + card_h + ent_off);
				aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 3, 0.18f * alpha * ent);
				dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha * ent), 10.f);
				dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha * ent), 10.f);
				dl->AddRect(a, b, aida::ui::with_alpha(t.accent_dim, 0.85f * alpha * ent), 10.f, 0, 1.f);
				dl->AddRectFilled(a, ImVec2(a.x + 3.f, b.y),
					aida::ui::with_alpha(t.accent_u32, 0.95f * alpha * ent), 10.f);

				dl->AddText(aida::ui::fonts::caption(), 11.f,
					ImVec2(a.x + 12.f, a.y + 6.f),
					aida::ui::with_alpha(t.text_dim, alpha * ent), "VARIABLE");
				dl->AddText(aida::ui::fonts::code_em(), 13.f,
					ImVec2(a.x + 12.f, a.y + 20.f),
					aida::ui::with_alpha(t.accent_u32, alpha * ent), name.c_str());

				char vbuf[64];
				std::snprintf(vbuf, sizeof(vbuf), "0x%llX",
					static_cast<unsigned long long>(val));
				dl->AddText(aida::ui::fonts::code(), 12.f,
					ImVec2(a.x + 12.f, a.y + 40.f),
					aida::ui::with_alpha(t.text_primary, alpha * ent), vbuf);
				char dbuf[40];
				std::snprintf(dbuf, sizeof(dbuf), "(%llu)",
					static_cast<unsigned long long>(val));
				dl->AddText(aida::ui::fonts::code(), 11.f,
					ImVec2(a.x + 110.f, a.y + 41.f),
					aida::ui::with_alpha(t.text_dim, alpha * ent), dbuf);
				++idx;
			}

			if (res.variable_values.empty()) {
				dl->AddText(aida::ui::fonts::body(), 13.f,
					ImVec2(cx + pad + 6.f, ty + 4.f),
					aida::ui::with_alpha(t.text_dim, alpha),
					"Path is reachable directly with current concrete state.");
			}
		} else {
			dl->AddText(aida::ui::fonts::body(), 13.f,
				ImVec2(cx + pad + 6.f, ty),
				aida::ui::with_alpha(t.text_dim, alpha),
				"No input values can drive execution to the target address.");
		}
	};

	auto draw_constraints_tab = [&]() {
		std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
		auto& sym = symbolic_engine::g_state.last_result;
		auto& solve = symbolic_engine::g_state.last_solve;

		std::vector<std::pair<std::string, ImU32>> rows;
		std::vector<std::string> row_regs;
		for (auto& op : sym.opaque_predicates) {
			char buf[200];
			std::snprintf(buf, sizeof(buf), "%llX  %s  ->  %s",
				static_cast<unsigned long long>(op.address),
				op.disasm.c_str(),
				op.simplified_ast.c_str());
			ImU32 col = op.always_taken ? success_col : opaque_col;
			rows.push_back({ std::string(buf), col });
			row_regs.push_back(op.disasm);
		}

		if (solve.satisfiable) {
			for (auto& [name, val] : solve.variable_values) {
				char buf[160];
				std::snprintf(buf, sizeof(buf), "%s  =  0x%llX",
					name.c_str(), static_cast<unsigned long long>(val));
				rows.push_back({ std::string(buf), t.accent_u32 });
				row_regs.push_back(name);
			}
		}

		if (rows.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "No constraints captured";
			cfg.body  = "Run Symbolize or Solve Path to populate path constraints.";
			aida::ui::empty_state::render(ImVec2(cx, table_y), ImVec2(width, table_h), cfg);
			return;
		}

		float ty = table_y + 8.f;
		dl->AddText(aida::ui::fonts::body_em(), 12.f,
			ImVec2(cx + pad + 6.f, ty),
			aida::ui::with_alpha(t.text_secondary, alpha), "PATH CONSTRAINTS");
		dl->AddLine(ImVec2(cx + pad, ty + 16.f),
			ImVec2(cx + width - pad, ty + 16.f),
			aida::ui::with_alpha(t.border_subtle, alpha));
		ty += 24.f;

		st.hover_constraint_regs.clear();

		float card_h = 38.f;
		static float entrance_acc = 0.f;
		entrance_acc += dt;

		for (size_t i = 0; i < rows.size(); ++i) {
			float vy = ty + static_cast<float>(i) * (card_h + 6.f);
			if (vy + card_h > cy + height - 8.f) break;

			float ent = ui_anim::render_row_entrance(static_cast<int>(i), entrance_acc, 0.025f);
			float ent_off = (1.f - ent) * 8.f;

			ImVec2 a(cx + pad, vy + ent_off);
			ImVec2 b(cx + width - pad, vy + card_h + ent_off);

			ImGui::SetCursorScreenPos(a);
			ImGui::InvisibleButton(("##cs" + std::to_string(i)).c_str(),
				ImVec2(b.x - a.x, b.y - a.y));
			bool hovered = ImGui::IsItemHovered();
			if (hovered) {
				st.hover_constraint_regs = row_regs[i];
			}

			aida::ui::blur::render_drop_shadow(dl, a, b, 8.f, 3, 0.18f * alpha * ent);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha * ent), 8.f);
			dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha * ent), 8.f);
			ImU32 border_col = hovered
				? aida::ui::with_alpha(t.accent_dim, 0.95f * alpha * ent)
				: aida::ui::with_alpha(t.border_subtle, alpha * ent);
			dl->AddRect(a, b, border_col, 8.f, 0, 1.f);

			dl->AddRectFilled(a, ImVec2(a.x + 4.f, b.y),
				aida::ui::with_alpha(rows[i].second, 0.85f * alpha * ent), 8.f);

			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(a.x + 14.f, a.y + (card_h - 12.f) * 0.5f),
				aida::ui::with_alpha(t.text_primary, alpha * ent), rows[i].first.c_str());
		}
	};

	auto draw_expression_tab = [&]() {
		float ty = table_y + 6.f;

		ImGui::SetCursorScreenPos(ImVec2(cx + pad, ty));
		bool simplify_clicked = aida::ui::components::button("Simplify",
			aida::ui::components::button_kind_t::secondary,
			aida::ui::components::size_t_::sm,
			ImVec2(0.f, 24.f), st.simplifying, nullptr, st.simplifying);
		if (simplify_clicked && !st.simplifying && !st.expression_text.empty()) {
			st.simplifying = true;
			std::string text_copy = st.expression_text;
			work_queue::post([text_copy]() {
				auto root = detail::parse_ast(text_copy);
				std::lock_guard<std::mutex> lk(symbolic_engine::g_state.mutex);
				s_state.ast_root = root;
				s_state.simplified_text = text_copy;
				s_state.simplifying = false;
			});
		}

		ImGui::SetCursorScreenPos(ImVec2(cx + pad + 110.f, ty));
		if (aida::ui::components::button("Copy",
			aida::ui::components::button_kind_t::ghost,
			aida::ui::components::size_t_::sm,
			ImVec2(0.f, 24.f))) {
			if (!st.expression_text.empty()) {
				ImGui::SetClipboardText(st.expression_text.c_str());
				toast_notification::push("Expression copied",
					toast_notification::toast_type_t::info, 2.0f);
			}
		}

		ty += 32.f;

		if (st.expression_text.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::dots;
			cfg.title = "No expression selected";
			cfg.body  = "Click an instruction in the Trace tab to view its symbolic AST.";
			aida::ui::empty_state::render(ImVec2(cx, ty), ImVec2(width, table_h - (ty - table_y)), cfg);
			return;
		}

		if (!st.ast_root) st.ast_root = detail::parse_ast(st.expression_text);

		float canvas_x = cx + pad;
		float canvas_y = ty;
		float canvas_w = width - pad * 2.f;
		float canvas_h = table_h - (ty - table_y) - 8.f;

		dl->AddRectFilled(ImVec2(canvas_x, canvas_y),
			ImVec2(canvas_x + canvas_w, canvas_y + canvas_h),
			aida::ui::with_alpha(t.panel_bg, 0.6f * alpha), 8.f);
		dl->AddRect(ImVec2(canvas_x, canvas_y),
			ImVec2(canvas_x + canvas_w, canvas_y + canvas_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 8.f, 0, 1.f);

		struct layout_node_t {
			std::shared_ptr<ast_node_t> n;
			int depth = 0;
			float center_x = 0.f;
			float y = 0.f;
			int parent_layout = -1;
		};

		std::vector<layout_node_t> layout;
		std::function<void(std::shared_ptr<ast_node_t>, int, int)> layout_pass;
		layout_pass = [&](std::shared_ptr<ast_node_t> node, int depth, int parent) {
			if (!node) return;
			layout_node_t ln;
			ln.n = node;
			ln.depth = depth;
			ln.parent_layout = parent;
			int idx = static_cast<int>(layout.size());
			layout.push_back(ln);
			if (node->expanded) {
				for (auto& ch : node->children) layout_pass(ch, depth + 1, idx);
			}
		};
		layout_pass(st.ast_root, 0, -1);

		std::unordered_map<int, std::vector<int>> indices_at_depth;
		for (size_t i = 0; i < layout.size(); ++i) {
			indices_at_depth[layout[i].depth].push_back(static_cast<int>(i));
		}

		int max_depth = 0;
		for (auto& kv : indices_at_depth) {
			if (kv.first > max_depth) max_depth = kv.first;
		}

		float node_w = 110.f;
		float node_h = 30.f;
		float h_gap = 14.f;
		float v_gap = 18.f;

		float row_y = canvas_y + 16.f;

		for (int d = 0; d <= max_depth; ++d) {
			auto& idxs = indices_at_depth[d];
			float total_w = static_cast<float>(idxs.size()) * (node_w + h_gap) - h_gap;
			float start_x = canvas_x + (canvas_w - total_w) * 0.5f;
			if (start_x < canvas_x + 8.f) start_x = canvas_x + 8.f;
			for (size_t k = 0; k < idxs.size(); ++k) {
				int li = idxs[k];
				layout[li].center_x = start_x + static_cast<float>(k) * (node_w + h_gap) + node_w * 0.5f;
				layout[li].y = row_y;
			}
			row_y += node_h + v_gap;
		}

		ImGui::PushClipRect(ImVec2(canvas_x + 1.f, canvas_y + 1.f),
			ImVec2(canvas_x + canvas_w - 1.f, canvas_y + canvas_h - 1.f), true);

		for (size_t i = 0; i < layout.size(); ++i) {
			if (layout[i].parent_layout < 0) continue;
			auto& parent = layout[static_cast<size_t>(layout[i].parent_layout)];
			auto& self = layout[i];
			ImVec2 p1(parent.center_x, parent.y + node_h);
			ImVec2 p4(self.center_x, self.y);
			ImVec2 p2(parent.center_x, parent.y + node_h + (self.y - parent.y - node_h) * 0.45f);
			ImVec2 p3(self.center_x, self.y - (self.y - parent.y - node_h) * 0.45f);

			ImU32 line_col = aida::ui::with_alpha(t.accent_dim, 0.85f * alpha);
			ImU32 line_glow = aida::ui::with_alpha(t.accent_glow, 0.45f * alpha);
			dl->AddBezierCubic(p1, p2, p3, p4, line_glow, 4.f);
			dl->AddBezierCubic(p1, p2, p3, p4, line_col, 1.4f);
		}

		for (size_t i = 0; i < layout.size(); ++i) {
			auto& ln = layout[i];
			if (!ln.n) continue;

			ImVec2 a(ln.center_x - node_w * 0.5f, ln.y);
			ImVec2 b(ln.center_x + node_w * 0.5f, ln.y + node_h);

			if (a.x < canvas_x || b.x > canvas_x + canvas_w) continue;
			if (a.y > canvas_y + canvas_h) continue;

			ImGui::SetCursorScreenPos(a);
			ImGui::InvisibleButton(("##astn" + std::to_string(i)).c_str(),
				ImVec2(node_w, node_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			if (clicked && !ln.n->children.empty()) ln.n->expanded = !ln.n->expanded;

			ImU32 nc = detail::ast_node_color(t, *ln.n);

			aida::ui::blur::render_glass_fill(dl, a, b, 8.f, alpha);
			ImU32 border_col = hov
				? aida::ui::with_alpha(t.accent_dim, 0.95f * alpha)
				: aida::ui::with_alpha(nc, 0.6f * alpha);
			dl->AddRect(a, b, border_col, 8.f, 0, hov ? 1.5f : 1.f);

			std::string label = ln.n->label;
			if (label.size() > 14) label = label.substr(0, 12) + "..";
			ImVec2 tsz = aida::ui::fonts::code()->CalcTextSizeA(12.f, FLT_MAX, 0.f, label.c_str());
			dl->AddText(aida::ui::fonts::code(), 12.f,
				ImVec2(ln.center_x - tsz.x * 0.5f, ln.y + (node_h - 12.f) * 0.5f),
				aida::ui::with_alpha(nc, alpha), label.c_str());

			if (!ln.n->children.empty()) {
				const char* mark = ln.n->expanded ? "-" : "+";
				dl->AddText(aida::ui::fonts::code_em(), 12.f,
					ImVec2(b.x - 14.f, ln.y + (node_h - 12.f) * 0.5f),
					aida::ui::with_alpha(t.text_dim, alpha), mark);
			}
		}

		ImGui::PopClipRect();
	};

	auto draw_active = [&]() {
		switch (st.active_tab) {
			case 0: draw_trace_tab(); break;
			case 1: draw_deob_tab(); break;
			case 2: draw_slice_tab(); break;
			case 3: draw_solver_tab(); break;
			case 4: draw_constraints_tab(); break;
			case 5: draw_expression_tab(); break;
		}
	};

	if (st.content_swap.active) {
		float p = st.content_swap.eased();
		float prev_alpha = alpha;
		alpha = alpha * p;
		draw_active();
		alpha = prev_alpha;
	} else {
		draw_active();
	}

	ImGui::EndChild();
}

}
