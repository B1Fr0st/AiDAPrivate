#pragma once

#include "deobfuscation_engine.hpp"
#include "work_queue.hpp"
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
#include <atomic>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace deobfuscation_view {

struct local_state_t {
	char addr_input[20] = {};
	int  max_instructions = 50000;

	float       code_scroll_y = 0.f;
	float       code_target_scroll = 0.f;
	int         selected_insn = -1;
	bool        code_scrollbar_dragging = false;
	float       code_scrollbar_drag_offset = 0.f;

	bool show_junk = false;
	bool show_compare = false;
	aida::ui::transition_t compare_swap;

	float donut_growth = 0.f;
	float donut_target = 0.f;
	bool  donut_seeded = false;
	uint64_t last_seen_origin_count = 0;

	std::unordered_map<int, aida::ui::transition_t> strikethrough;
};

static local_state_t s_state;

namespace detail {

inline void start_deobfuscate(local_state_t& st) {
	uint64_t addr = 0;
	if (st.addr_input[0])
		addr = std::strtoull(st.addr_input, nullptr, 16);
	if (addr == 0) {
		toast_notification::push("Enter a function address (hex)",
			toast_notification::toast_type_t::warning, 3.0f);
		return;
	}
	if (deobfuscation_engine::g_state.processing.load()) return;
	uint32_t max_insn = static_cast<uint32_t>(st.max_instructions);
	deobfuscation_engine::g_state.processing.store(true);
	deobfuscation_engine::g_state.progress_current.store(0);
	deobfuscation_engine::g_state.progress_total.store(5);
	work_queue::post([addr, max_insn]() {
		deobfuscation_engine::deobfuscated_result_t result;
		try {
			result = deobfuscation_engine::deobfuscate_function(addr, max_insn);
		} catch (const std::exception& ex) {
			result.success = false;
			result.error = std::string("Deobfuscation aborted: ") + ex.what();
		} catch (...) {
			result.success = false;
			result.error = "Deobfuscation aborted by unknown exception";
		}
		std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
		deobfuscation_engine::g_state.last_result = std::move(result);
		deobfuscation_engine::g_state.processing.store(false);
	});
}

inline void render_glass_panel(ImDrawList* dl, ImVec2 a, ImVec2 b, float radius,
                                float alpha, bool accent_border = false) {
	const auto& t = aida::ui::resolved();
	aida::ui::blur::render_drop_shadow(dl, a, b, radius, 4, 0.22f * alpha, ImVec2(0.f, 4.f));
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, 0.92f * alpha), radius);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, 0.55f * alpha), radius);
	ImU32 border_col = accent_border
		? aida::ui::with_alpha(t.accent_dim, 0.85f * alpha)
		: aida::ui::with_alpha(t.border_subtle, alpha);
	dl->AddRect(a, b, border_col, radius, 0, 1.f);
}

inline void render_stat_card(ImDrawList* dl, float x, float y, float w, float h,
                              const char* label, const char* value, ImU32 accent_token,
                              float alpha, float row_t = 1.f) {
	const auto& t = aida::ui::resolved();
	ImVec2 a(x, y);
	ImVec2 b(x + w, y + h);
	render_glass_panel(dl, a, b, 10.f, alpha * row_t);

	dl->AddRectFilled(ImVec2(a.x, a.y), ImVec2(a.x + 3.f, a.y + h),
		aida::ui::with_alpha(accent_token, 0.85f * alpha * row_t), 10.f);

	dl->AddText(aida::ui::fonts::caption(), 13.f, ImVec2(a.x + 12.f, a.y + 6.f),
		aida::ui::with_alpha(t.text_dim, alpha * row_t), label);
	dl->AddText(aida::ui::fonts::body_strong(), 18.f,
		ImVec2(a.x + 12.f, a.y + h - 22.f),
		aida::ui::with_alpha(t.text_primary, alpha * row_t), value);
}

inline std::string short_disasm(const std::string& src, size_t cap) {
	if (src.size() <= cap) return src;
	return src.substr(0, cap - 3) + "...";
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y; (void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##deobfuscation_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& eng = deobfuscation_engine::g_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float cx = wp.x;
	float cy = wp.y;

	float dt = aida::ui::clock::dt();
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height),
		aida::ui::with_alpha(t.bg_base, alpha));

	const float toolbar_h = 76.f;
	const float pad = 12.f;

	ImVec2 toolbar_a(cx + 6.f, cy + 6.f);
	ImVec2 toolbar_b(cx + width - 6.f, cy + toolbar_h - 6.f);
	detail::render_glass_panel(dl, toolbar_a, toolbar_b, 12.f, alpha);

	float input_y = cy + 14.f;

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 8.f, input_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
	ImGui::TextUnformatted("Function");
	ImGui::PopStyleColor();

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 78.f, input_y));
	ImGui::SetNextItemWidth(170.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, alpha));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushFont(aida::ui::fonts::code());
	ImGui::InputTextWithHint("##deob_addr", "0x...", st.addr_input, sizeof(st.addr_input));
	ImGui::PopFont();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);

	{
		char vbuf[32];
		std::snprintf(vbuf, sizeof(vbuf), "%d insns", st.max_instructions);
		ImGui::SetCursorScreenPos(ImVec2(cx + pad + 268.f, input_y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_secondary, alpha));
		ImGui::TextUnformatted("Max");
		ImGui::PopStyleColor();

		ImGui::SetCursorScreenPos(ImVec2(cx + pad + 304.f, input_y + 2.f));
		ImGui::SetNextItemWidth(140.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_SliderGrab, aida::ui::with_alpha(t.accent_u32, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::SliderInt("##deob_max", &st.max_instructions, 1000, 100000, "");
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);

		ImGui::SetCursorScreenPos(ImVec2(cx + pad + 304.f + 148.f, input_y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::TextUnformatted(vbuf);
		ImGui::PopStyleColor();
	}

	float btn_y = cy + 44.f;
	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 8.f, btn_y));

	bool processing = eng.processing.load();

	if (aida::ui::components::button("Deobfuscate",
		processing ? aida::ui::components::button_kind_t::secondary
		           : aida::ui::components::button_kind_t::primary,
		aida::ui::components::size_t_::sm,
		ImVec2(0.f, 26.f), processing, nullptr, processing)) {
		if (!processing) detail::start_deobfuscate(st);
	}

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 130.f, btn_y));
	if (aida::ui::components::button("Apply Clean",
		aida::ui::components::button_kind_t::accent_gradient,
		aida::ui::components::size_t_::sm,
		ImVec2(0.f, 26.f), processing)) {
		std::lock_guard<std::mutex> lk(eng.mutex);
		if (eng.last_result.success) {
			std::string text = deobfuscation_engine::export_clean_asm(eng.last_result);
			ImGui::SetClipboardText(text.c_str());
			char buf[96];
			std::snprintf(buf, sizeof(buf), "Applied %u clean instructions",
				eng.last_result.total_clean);
			toast_notification::push(buf, toast_notification::toast_type_t::success, 3.0f);
		} else {
			toast_notification::push("No deobfuscation result yet",
				toast_notification::toast_type_t::warning, 2.5f);
		}
	}

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 252.f, btn_y));
	if (aida::ui::components::button("Stats",
		aida::ui::components::button_kind_t::ghost,
		aida::ui::components::size_t_::sm,
		ImVec2(0.f, 26.f), processing)) {
		std::lock_guard<std::mutex> lk(eng.mutex);
		if (eng.last_result.success) {
			std::string text = deobfuscation_engine::export_statistics(eng.last_result);
			ImGui::SetClipboardText(text.c_str());
			toast_notification::push("Statistics copied to clipboard",
				toast_notification::toast_type_t::info, 2.5f);
		}
	}

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 332.f, btn_y));
	if (aida::ui::components::button(st.show_compare ? "Single" : "Compare",
		st.show_compare ? aida::ui::components::button_kind_t::primary
		                : aida::ui::components::button_kind_t::ghost,
		aida::ui::components::size_t_::sm,
		ImVec2(0.f, 26.f))) {
		st.show_compare = !st.show_compare;
		if (st.show_compare) st.compare_swap.start(aida::motion::dur::md, aida::motion::ease::out_cubic);
		else                 st.compare_swap.start_reverse(aida::motion::dur::md, aida::motion::ease::out_cubic);
	}
	st.compare_swap.tick(dt);

	ImGui::SetCursorScreenPos(ImVec2(cx + pad + 432.f, btn_y + 4.f));
	ImGui::PushStyleColor(ImGuiCol_CheckMark, aida::ui::with_alpha(t.accent_u32, alpha));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
	ImGui::Checkbox("Show junk##deob_junk", &st.show_junk);
	ImGui::PopStyleColor(2);

	if (processing) {
		uint32_t cur = eng.progress_current.load();
		uint32_t tot = eng.progress_total.load();
		float frac = (tot > 0) ? static_cast<float>(cur) / static_cast<float>(tot) : 0.f;
		float bar_x = cx + pad + 552.f;
		float bar_y = btn_y + 9.f;
		float bar_w = (std::min)(width - (bar_x - cx) - pad - 6.f, 180.f);
		if (bar_w > 24.f) {
			aida::ui::components::render_progress_bar(ImVec2(bar_x, bar_y), bar_w, 12.f, frac, tot == 0, true);
		}
	}

	float body_top = cy + toolbar_h + 6.f;
	float body_h = height - toolbar_h - 12.f;
	if (body_h < 100.f) body_h = 100.f;

	std::lock_guard<std::mutex> lk(eng.mutex);
	auto& res = eng.last_result;

	if (!res.success && !processing) {
		if (res.error.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::flow;
			cfg.title = "Deobfuscate a function";
			cfg.body  = "Enter a function address (e.g. 0x140001000) and press Deobfuscate to strip junk, fold constants, and resolve dispatcher states.";
			aida::ui::empty_state::render(ImVec2(cx, body_top), ImVec2(width, body_h), cfg);
		} else {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::shield;
			cfg.title = "Deobfuscation failed";
			cfg.body  = res.error;
			aida::ui::empty_state::render(ImVec2(cx, body_top), ImVec2(width, body_h), cfg);
		}
		ImGui::EndChild();
		return;
	}

	if (!res.success) {
		aida::ui::skeleton::render_table_rows(dl,
			ImVec2(cx + 14.f, body_top + 14.f),
			ImVec2(cx + width - 14.f, body_top + body_h - 14.f),
			3, 14, 22.f, 1.5f);
		ImGui::EndChild();
		return;
	}

	if (res.total_original > 0 &&
		(!st.donut_seeded || res.total_original != st.last_seen_origin_count)) {
		st.donut_target = res.junk_ratio;
		st.donut_growth = 0.f;
		st.donut_seeded = true;
		st.last_seen_origin_count = res.total_original;
		st.strikethrough.clear();
	}
	float donut_velocity = 0.f;
	st.donut_growth = aida::motion::spring_step(st.donut_growth, st.donut_target,
		donut_velocity, aida::motion::spring::balanced, dt);
	if (st.donut_growth > st.donut_target) st.donut_growth = st.donut_target;

	float code_w = width * 0.62f;
	float info_w = width - code_w - pad - 6.f;
	float code_x = cx + pad;
	float info_x = code_x + code_w + 6.f;

	std::vector<const deobfuscation_engine::clean_instruction_t*> all_insns;
	for (auto& block : res.clean_blocks) {
		for (auto& ci : block.instructions) all_insns.push_back(&ci);
	}
	if (all_insns.empty()) {
		for (auto& ci : res.clean_instructions) all_insns.push_back(&ci);
	}

	std::vector<const deobfuscation_engine::clean_instruction_t*> visible_left;
	std::vector<const deobfuscation_engine::clean_instruction_t*> visible_right;
	for (auto* ci : all_insns) {
		visible_left.push_back(ci);
		if (!ci->was_junk) visible_right.push_back(ci);
	}

	std::vector<const deobfuscation_engine::clean_instruction_t*> single_view;
	for (auto* ci : all_insns) {
		if (!st.show_junk && ci->was_junk) continue;
		single_view.push_back(ci);
	}

	float compare_p = st.compare_swap.eased();

	float code_panel_top = body_top;
	float code_panel_h = body_h;
	detail::render_glass_panel(dl, ImVec2(code_x, code_panel_top),
		ImVec2(code_x + code_w, code_panel_top + code_panel_h), 10.f, alpha);

	const float row_h = 22.f;
	float hdr_h = 26.f;

	auto draw_column_header = [&](float xs, float xe, const char* title, ImU32 stripe_col) {
		dl->AddRectFilled(ImVec2(xs, code_panel_top), ImVec2(xe, code_panel_top + hdr_h),
			aida::ui::with_alpha(t.panel_header, 0.85f * alpha), 10.f);
		dl->AddRectFilled(ImVec2(xs, code_panel_top + hdr_h - 2.f),
			ImVec2(xe, code_panel_top + hdr_h),
			aida::ui::with_alpha(stripe_col, 0.65f * alpha));
		dl->AddText(aida::ui::fonts::body_em(), 14.f,
			ImVec2(xs + 14.f, code_panel_top + 7.f),
			aida::ui::with_alpha(t.text_primary, alpha), title);
	};

	auto draw_row = [&](const deobfuscation_engine::clean_instruction_t* ci, int row_i,
	                     float xs, float xe, float ry, bool include_strikethrough) {
		if (!ci) return;
		bool is_junk = ci->was_junk;
		bool selected = (st.selected_insn == row_i);

		ImU32 rbg;
		if (is_junk) {
			rbg = aida::ui::with_alpha(t.bg_overlay, 0.7f * alpha);
		} else if (selected) {
			rbg = aida::ui::with_alpha(t.selection, alpha);
		} else if (row_i % 2 == 0) {
			rbg = aida::ui::with_alpha(t.panel_bg, 0.45f * alpha);
		} else {
			rbg = aida::ui::with_alpha(t.bg_elevated, 0.35f * alpha);
		}

		dl->AddRectFilled(ImVec2(xs, ry), ImVec2(xe, ry + row_h), rbg, 4.f);

		if (selected) {
			dl->AddRectFilled(ImVec2(xs, ry), ImVec2(xs + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, 0.85f * alpha), 4.f);
		}

		ImGui::SetCursorScreenPos(ImVec2(xs, ry));
		ImGui::InvisibleButton(("##drow" + std::to_string(row_i)).c_str(),
			ImVec2(xe - xs, row_h));
		if (ImGui::IsItemClicked()) st.selected_insn = row_i;

		char abuf[20];
		std::snprintf(abuf, sizeof(abuf), "%llX",
			static_cast<unsigned long long>(ci->address));

		ImU32 addr_col = is_junk
			? aida::ui::with_alpha(t.text_dim, alpha)
			: aida::ui::with_alpha(t.text_address, alpha);
		dl->AddText(aida::ui::fonts::code(), 13.f,
			ImVec2(xs + 8.f, ry + (row_h - 12.f) * 0.5f), addr_col, abuf);

		ImU32 disasm_col = is_junk
			? aida::ui::with_alpha(t.text_dim, alpha * 0.85f)
			: aida::ui::with_alpha(t.text_primary, alpha);
		std::string disp = detail::short_disasm(ci->disasm, 60);
		dl->AddText(aida::ui::fonts::code(), 13.f,
			ImVec2(xs + 130.f, ry + (row_h - 12.f) * 0.5f),
			disasm_col, disp.c_str());

		if (is_junk && include_strikethrough) {
			auto& tr = st.strikethrough[row_i];
			if (!tr.active && tr.progress < 0.001f) {
				tr.start(0.240f, aida::motion::ease::out_cubic);
			}
			tr.tick(dt);
			float p = tr.eased();
			float text_w = aida::ui::fonts::code()->CalcTextSizeA(12.f, FLT_MAX, 0.f, disp.c_str()).x;
			float line_y = ry + row_h * 0.5f;
			float line_x0 = xs + 130.f;
			float line_x1 = line_x0 + text_w * p;
			dl->AddLine(ImVec2(line_x0, line_y), ImVec2(line_x1, line_y),
				aida::ui::with_alpha(t.error, 0.75f * alpha), 1.4f);
		}

		ImU32 status_col = aida::ui::with_alpha(t.text_dim, alpha);
		const char* status = nullptr;
		if (is_junk) { status = "JUNK";   status_col = t.error; }
		else if (ci->was_opaque) { status = "OPAQUE"; status_col = t.warning; }
		else if (ci->was_constant_folded) { status = "CONST"; status_col = t.success; }

		if (status) {
			ImGui::SetCursorScreenPos(ImVec2(xe - 70.f, ry + 3.f));
			aida::ui::components::badge(status, aida::ui::with_alpha(status_col, alpha), 4.f);
		}
	};

	float list_y = code_panel_top + hdr_h + 4.f;
	float list_h = code_panel_h - hdr_h - 8.f;
	int visible_rows = static_cast<int>(list_h / row_h);

	auto compute_max_scroll = [&](size_t total) {
		float max_sc = (std::max)(0.f, static_cast<float>(total) * row_h - list_h);
		return max_sc;
	};

	float single_alpha = alpha * (1.f - compare_p);
	float compare_alpha = alpha * compare_p;

	if (compare_p < 0.99f) {
		float prev_alpha = alpha;
		alpha = single_alpha;
		draw_column_header(code_x, code_x + code_w, "Stream", t.accent_u32);

		ImGui::SetCursorScreenPos(ImVec2(code_x, list_y));
		ImGui::InvisibleButton("##deob_code_scroll", ImVec2(code_w - 14.f, list_h));
		float max_sc = compute_max_scroll(single_view.size());
		ui_anim::handle_scroll_input(st.code_target_scroll, 0.f, max_sc, row_h * 3.f);
		ui_anim::smooth_scroll(st.code_scroll_y, st.code_target_scroll, 15.f, dt);
		ui_anim::clamp_scroll(st.code_scroll_y, 0.f, max_sc);
		ui_anim::clamp_scroll(st.code_target_scroll, 0.f, max_sc);

		int start_row = static_cast<int>(st.code_scroll_y / row_h);
		if (start_row < 0) start_row = 0;

		ImGui::PushClipRect(ImVec2(code_x + 1.f, list_y),
			ImVec2(code_x + code_w - 1.f, list_y + list_h), true);

		for (int i = start_row;
			i < static_cast<int>(single_view.size()) && i < start_row + visible_rows + 1; ++i) {
			float ry = list_y + static_cast<float>(i - start_row) * row_h;
			if (ry > list_y + list_h) break;
			draw_row(single_view[i], i, code_x + 4.f, code_x + code_w - 4.f, ry, true);
		}

		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, code_x + code_w - 8.f, list_y, 6.f, list_h,
			st.code_scroll_y, static_cast<float>(single_view.size()) * row_h, list_h,
			alpha, st.code_scrollbar_dragging, st.code_scrollbar_drag_offset);

		alpha = prev_alpha;
	}

	if (compare_p > 0.01f) {
		float prev_alpha = alpha;
		alpha = compare_alpha;
		float split_x = code_x + code_w * 0.5f;

		draw_column_header(code_x, split_x - 1.f, "Original", t.text_dim);
		draw_column_header(split_x + 1.f, code_x + code_w, "Clean", t.success);

		dl->AddLine(ImVec2(split_x, code_panel_top + 2.f),
			ImVec2(split_x, code_panel_top + code_panel_h - 2.f),
			aida::ui::with_alpha(t.border_subtle, alpha), 1.f);

		ImGui::SetCursorScreenPos(ImVec2(code_x, list_y));
		ImGui::InvisibleButton("##deob_compare_scroll", ImVec2(code_w - 14.f, list_h));
		float max_sc = compute_max_scroll(visible_left.size());
		ui_anim::handle_scroll_input(st.code_target_scroll, 0.f, max_sc, row_h * 3.f);
		ui_anim::smooth_scroll(st.code_scroll_y, st.code_target_scroll, 15.f, dt);
		ui_anim::clamp_scroll(st.code_scroll_y, 0.f, max_sc);
		ui_anim::clamp_scroll(st.code_target_scroll, 0.f, max_sc);

		int start_row = static_cast<int>(st.code_scroll_y / row_h);
		if (start_row < 0) start_row = 0;

		ImGui::PushClipRect(ImVec2(code_x + 1.f, list_y),
			ImVec2(split_x - 2.f, list_y + list_h), true);
		for (int i = start_row;
			i < static_cast<int>(visible_left.size()) && i < start_row + visible_rows + 1; ++i) {
			float ry = list_y + static_cast<float>(i - start_row) * row_h;
			if (ry > list_y + list_h) break;
			draw_row(visible_left[i], i, code_x + 4.f, split_x - 4.f, ry, true);
		}
		ImGui::PopClipRect();

		ImGui::PushClipRect(ImVec2(split_x + 2.f, list_y),
			ImVec2(code_x + code_w - 1.f, list_y + list_h), true);
		for (int i = start_row;
			i < static_cast<int>(visible_right.size()) && i < start_row + visible_rows + 1; ++i) {
			float ry = list_y + static_cast<float>(i - start_row) * row_h;
			if (ry > list_y + list_h) break;
			draw_row(visible_right[i], i + 100000, split_x + 4.f,
				code_x + code_w - 4.f, ry, false);
		}
		ImGui::PopClipRect();

		ui_anim::render_custom_scrollbar(dl, code_x + code_w - 8.f, list_y, 6.f, list_h,
			st.code_scroll_y, static_cast<float>(visible_left.size()) * row_h, list_h,
			alpha, st.code_scrollbar_dragging, st.code_scrollbar_drag_offset);

		alpha = prev_alpha;
	}

	if (single_view.empty() && visible_left.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "No instructions";
		cfg.body  = "Deobfuscation produced an empty stream. Check the address.";
		aida::ui::empty_state::render(ImVec2(code_x, list_y),
			ImVec2(code_w, list_h), cfg);
	}

	detail::render_glass_panel(dl, ImVec2(info_x, body_top),
		ImVec2(info_x + info_w, body_top + body_h), 10.f, alpha);

	float iy = body_top + 12.f;
	float ix = info_x + 12.f;
	float iw = info_w - 24.f;

	{
		float card_h = 50.f;
		float card_w = (iw - 6.f) * 0.5f;
		char v_orig[16], v_clean[16], v_junk[16], v_pct[16];
		std::snprintf(v_orig, sizeof(v_orig), "%u", res.total_original);
		std::snprintf(v_clean, sizeof(v_clean), "%u", res.total_clean);
		std::snprintf(v_junk, sizeof(v_junk), "%u", res.removed_junk);
		float pct_val = res.total_original > 0
			? (1.f - static_cast<float>(res.total_clean) / static_cast<float>(res.total_original)) * 100.f
			: 0.f;
		std::snprintf(v_pct, sizeof(v_pct), "%.1f%%", pct_val);

		detail::render_stat_card(dl, ix, iy, card_w, card_h, "Original", v_orig,
			t.text_primary, alpha);
		detail::render_stat_card(dl, ix + card_w + 6.f, iy, card_w, card_h, "Clean", v_clean,
			t.success, alpha);
		iy += card_h + 6.f;
		detail::render_stat_card(dl, ix, iy, card_w, card_h, "Junk", v_junk,
			t.error, alpha);
		detail::render_stat_card(dl, ix + card_w + 6.f, iy, card_w, card_h, "Reduction", v_pct,
			t.warning, alpha);
		iy += card_h + 12.f;
	}

	if (res.total_original > 0) {
		float pct = res.junk_ratio * 100.f;
		char pct_buf[32];
		std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%%", pct);

		float ring_cx = ix + iw * 0.5f;
		float ring_cy = iy + 48.f;
		float ring_r = 38.f;

		float donut_pulse = aida::ui::clock::pulse(0.45f, 0.f, 1.f);
		ImU32 ring_glow_outer = aida::ui::with_alpha(t.accent_glow,
			(0.06f + 0.07f * donut_pulse) * alpha);
		dl->AddCircleFilled(ImVec2(ring_cx, ring_cy), ring_r + 14.f, ring_glow_outer, 32);
		dl->AddCircleFilled(ImVec2(ring_cx, ring_cy), ring_r + 8.f,
			aida::ui::with_alpha(t.accent_glow, 0.10f * alpha), 32);

		float anim_junk_ratio = st.donut_growth;
		float anim_clean_ratio = (st.donut_target > 0.001f)
			? (1.f - st.donut_target) * (st.donut_growth / st.donut_target)
			: (1.f - st.donut_growth);
		float remaining = 1.f - anim_junk_ratio - anim_clean_ratio;
		if (remaining < 0.f) remaining = 0.f;

		float fracs[3] = { anim_junk_ratio, anim_clean_ratio, remaining };
		ImU32 cols[3] = { t.error, t.success, aida::ui::with_alpha(t.border_strong, 0.6f) };
		ui_anim::render_donut_chart(dl, ring_cx, ring_cy, ring_r, 8.f,
			fracs, cols, 3, alpha, pct_buf);

		dl->AddText(aida::ui::fonts::caption(), 13.f,
			ImVec2(ring_cx - 14.f, ring_cy + ring_r + 6.f),
			aida::ui::with_alpha(t.text_dim, alpha), "junk");

		iy += 110.f;
	}

	float section_x = info_x + 8.f;
	float section_w = info_w - 16.f;

	if (!res.state_vars.empty() && iy < body_top + body_h - 80.f) {
		ImGui::SetCursorScreenPos(ImVec2(section_x, iy));
		ImGui::PushClipRect(ImVec2(info_x, iy), ImVec2(info_x + info_w, body_top + body_h), true);
		dl->AddText(aida::ui::fonts::body_em(), 14.f, ImVec2(section_x + 4.f, iy),
			aida::ui::with_alpha(t.text_secondary, alpha), "STATE MACHINE");
		dl->AddLine(ImVec2(section_x, iy + 16.f), ImVec2(section_x + section_w, iy + 16.f),
			aida::ui::with_alpha(t.border_subtle, alpha), 1.f);
		iy += 22.f;

		for (auto& sv : res.state_vars) {
			char dbuf[64];
			std::snprintf(dbuf, sizeof(dbuf), "Dispatcher: %llX",
				static_cast<unsigned long long>(sv.dispatcher_addr));
			dl->AddText(aida::ui::fonts::code(), 13.f, ImVec2(section_x + 4.f, iy),
				aida::ui::with_alpha(t.text_dim, alpha), dbuf);
			iy += 16.f;

			dl->AddText(aida::ui::fonts::caption(), 13.f, ImVec2(section_x + 4.f, iy),
				aida::ui::with_alpha(t.text_dim, alpha), "Register:");
			dl->AddText(aida::ui::fonts::code_em(), 13.f, ImVec2(section_x + 64.f, iy - 1.f),
				aida::ui::with_alpha(t.warning, alpha), sv.register_name.c_str());
			iy += 18.f;

			int sm_max = (int)((body_top + body_h - iy) / 16.f) - 1;
			int shown = 0;
			for (auto& [state_val, target] : sv.state_to_target) {
				if (shown >= sm_max) break;
				char sbuf[64];
				std::snprintf(sbuf, sizeof(sbuf), "  0x%llX -> 0x%llX",
					static_cast<unsigned long long>(state_val),
					static_cast<unsigned long long>(target));
				dl->AddText(aida::ui::fonts::code(), 13.f, ImVec2(section_x + 4.f, iy),
					aida::ui::with_alpha(t.info, alpha), sbuf);
				iy += 16.f;
				++shown;
				if (iy > body_top + body_h - 10.f) break;
			}
			iy += 4.f;
		}
		ImGui::PopClipRect();
	}

	if (!res.opaques.empty() && iy < body_top + body_h - 40.f) {
		dl->AddText(aida::ui::fonts::body_em(), 14.f, ImVec2(section_x + 4.f, iy),
			aida::ui::with_alpha(t.text_secondary, alpha), "OPAQUE PREDICATES");
		dl->AddLine(ImVec2(section_x, iy + 16.f), ImVec2(section_x + section_w, iy + 16.f),
			aida::ui::with_alpha(t.border_subtle, alpha), 1.f);
		iy += 22.f;

		ImGui::PushClipRect(ImVec2(info_x, iy), ImVec2(info_x + info_w, body_top + body_h), true);
		int max_show = static_cast<int>((body_top + body_h - iy) / 18.f) - 1;
		int show_count = (std::min)(static_cast<int>(res.opaques.size()), max_show);
		for (int i = 0; i < show_count; ++i) {
			auto& op = res.opaques[static_cast<size_t>(i)];
			char obuf[80];
			std::snprintf(obuf, sizeof(obuf), "%llX %s",
				static_cast<unsigned long long>(op.address),
				op.always_taken ? "always-T" : "never-T");
			dl->AddText(aida::ui::fonts::code(), 13.f, ImVec2(section_x + 4.f, iy),
				aida::ui::with_alpha(t.warning, alpha), obuf);
			iy += 16.f;
		}
		ImGui::PopClipRect();
	}

	if (!res.constants.empty() && iy < body_top + body_h - 40.f) {
		dl->AddText(aida::ui::fonts::body_em(), 14.f, ImVec2(section_x + 4.f, iy),
			aida::ui::with_alpha(t.text_secondary, alpha), "RESOLVED CONSTANTS");
		dl->AddLine(ImVec2(section_x, iy + 16.f), ImVec2(section_x + section_w, iy + 16.f),
			aida::ui::with_alpha(t.border_subtle, alpha), 1.f);
		iy += 22.f;

		ImGui::PushClipRect(ImVec2(info_x, iy), ImVec2(info_x + info_w, body_top + body_h), true);
		int max_show = static_cast<int>((body_top + body_h - iy) / 18.f) - 1;
		int show_count = (std::min)(static_cast<int>(res.constants.size()), max_show);
		for (int i = 0; i < show_count; ++i) {
			auto& c = res.constants[static_cast<size_t>(i)];
			char cbuf[96];
			std::snprintf(cbuf, sizeof(cbuf), "%llX %s = 0x%llX",
				static_cast<unsigned long long>(c.address),
				c.register_name.c_str(),
				static_cast<unsigned long long>(c.concrete_value));
			dl->AddText(aida::ui::fonts::code(), 13.f, ImVec2(section_x + 4.f, iy),
				aida::ui::with_alpha(t.success, alpha), cbuf);
			iy += 16.f;
		}
		ImGui::PopClipRect();
	}

	ImGui::EndChild();
}

}
