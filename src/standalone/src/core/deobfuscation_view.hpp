#pragma once

#include "deobfuscation_engine.hpp"
#include "work_queue.hpp"
#include "ui_anim.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace deobfuscation_view {

struct state_t {
	char addr_input[20] = {};
	int  max_instructions = 50000;

	float       code_scroll_y = 0.f;
	float       code_target_scroll = 0.f;
	int         selected_insn = -1;
	bool        code_scrollbar_dragging = false;
	float       code_scrollbar_drag_offset = 0.f;

	float       info_scroll_y = 0.f;
	float       info_target_scroll = 0.f;
	int         active_info_tab = 0;
	bool        info_scrollbar_dragging = false;
	float       info_scrollbar_drag_offset = 0.f;

	float       anim_time = 0.f;
	bool show_junk = false;
};

static state_t s_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	ImGui::BeginChild("##deobfuscation_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& eng = deobfuscation_engine::g_state;

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
	const ImU32 red_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 green_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 yellow_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
	const ImU32 cyan_col  = IM_COL32(86, 182, 194, static_cast<int>(alpha * 255));
	const ImU32 magenta_col = IM_COL32(198, 120, 221, static_cast<int>(alpha * 255));
	const ImU32 junk_col  = _ta(ui_anim::darken(_t.panel_bg, 10));
	const ImU32 junk_text = _ta(ui_anim::lighten(_t.text_dim, 10));

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 68.f;
	const float pad = 12.f;

	ui_anim::render_toolbar(dl, cx, cy, width, toolbar_h, accent_r, accent_g, accent_b, alpha);

	float tx = cx + pad;
	float ty = cy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(tx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, _ta(_t.panel_bg));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
	ImGui::PushStyleColor(ImGuiCol_Border, _ta(ui_anim::lighten(_t.panel_bg, 12)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##deob_addr", "Function Addr (hex)", st.addr_input, sizeof(st.addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(120.f);
	ImGui::PushStyleColor(ImGuiCol_SliderGrab, accent);
	ImGui::SliderInt("##deob_max", &st.max_instructions, 1000, 100000, "%d max");
	ImGui::PopStyleColor();
	ImGui::PopItemWidth();

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);

	ImGui::SameLine();

	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140),
		static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
		static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 240)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100),
		static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));

	bool processing = eng.processing.load();

	if (!processing) {
		if (ImGui::Button("Deobfuscate", ImVec2(100.f, 26.f))) {
			uint64_t addr = 0;
			if (st.addr_input[0])
				addr = std::strtoull(st.addr_input, nullptr, 16);
			if (addr != 0) {
				uint32_t max_insn = static_cast<uint32_t>(st.max_instructions);
				eng.processing.store(true);
				work_queue::post([addr, max_insn]() {
					auto result = deobfuscation_engine::deobfuscate_function(addr, max_insn);
					{
						std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
						deobfuscation_engine::g_state.last_result = std::move(result);
					}
					deobfuscation_engine::g_state.processing.store(false);
				});
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Export ASM", ImVec2(90.f, 26.f))) {
			std::lock_guard<std::mutex> lk(eng.mutex);
			if (eng.last_result.success) {
				std::string asm_text = deobfuscation_engine::export_clean_asm(eng.last_result);
				ImGui::SetClipboardText(asm_text.c_str());
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Export Stats", ImVec2(96.f, 26.f))) {
			std::lock_guard<std::mutex> lk(eng.mutex);
			if (eng.last_result.success) {
				std::string stats_text = deobfuscation_engine::export_statistics(eng.last_result);
				ImGui::SetClipboardText(stats_text.c_str());
			}
		}
	} else {
		ImGui::Button("Processing...", ImVec2(100.f, 26.f));
	}

	ImGui::SameLine();

	ImGui::PushStyleColor(ImGuiCol_CheckMark, accent);
	ImGui::Checkbox("Show Junk##deob_junk", &st.show_junk);
	ImGui::PopStyleColor();

	ImGui::PopStyleColor(4);
	ImGui::PopStyleVar();

	ty += 26.f;

	if (processing) {
		uint32_t cur = eng.progress_current.load();
		uint32_t tot = eng.progress_total.load();
		if (tot > 0) {
			float frac = static_cast<float>(cur) / static_cast<float>(tot);
			float bar_w = (std::min)(width - pad * 2.f, 400.f);
			float bar_h = 8.f;
			float bx = cx + pad;
			float by = ty + 2.f;
			ui_anim::render_progress_bar_animated(dl, bx, by, bar_w, bar_h, frac,
				accent_r, accent_g, accent_b, alpha, st.anim_time);
			char pbuf[32];
			std::snprintf(pbuf, sizeof(pbuf), "Phase %u / %u", cur, tot);
			dl->AddText(ImVec2(bx + bar_w + 8.f, ty), dim_col, pbuf);
		}
	}

	float body_top = cy + toolbar_h + 4.f;
	float body_h = height - toolbar_h - 4.f;
	if (body_h < 100.f) body_h = 100.f;

	std::lock_guard<std::mutex> lk(eng.mutex);
	auto& res = eng.last_result;

	if (!res.success && !processing) {
		if (res.error.empty()) {
			ui_anim::render_empty_state(dl, cx, body_top, width, body_h,
				"Enter a function address and click Deobfuscate",
				accent_r, accent_g, accent_b, alpha, st.anim_time);
		} else {
			dl->AddText(ImVec2(cx + pad, body_top + pad), red_col, res.error.c_str());
		}
		ImGui::EndChild();
		return;
	}

	if (!res.success) {
		ui_anim::render_spinner(dl, cx + width * 0.5f, body_top + body_h * 0.4f, 14.f, 2.f, accent, st.anim_time);
		dl->AddText(ImVec2(cx + width * 0.5f - 50.f, body_top + body_h * 0.4f + 24.f), dim_col, "Deobfuscating...");
		ImGui::EndChild();
		return;
	}

	float code_w = width * 0.62f;
	float info_w = width - code_w - pad;

	float code_x = cx + pad;
	float info_x = code_x + code_w + 4.f;

	{
		const float row_h = 20.f;
		float hdr_y = body_top;

		ui_anim::table_col_t code_cols[] = {
			{ "Address", 130.f }, { "Instruction", code_w - 200.f }, { "Status", 70.f }
		};
		ui_anim::render_table_header(dl, code_x, hdr_y, code_w, row_h,
			code_cols, 3, accent_r, accent_g, accent_b, alpha);

		hdr_y += row_h;

		std::vector<const deobfuscation_engine::clean_instruction_t*> display_insns;
		for (auto& block : res.clean_blocks) {
			for (auto& ci : block.instructions) {
				if (!st.show_junk && ci.was_junk) continue;
				display_insns.push_back(&ci);
			}
		}

		if (display_insns.empty()) {
			for (auto& ci : res.clean_instructions) {
				if (!st.show_junk && ci.was_junk) continue;
				display_insns.push_back(&ci);
			}
		}

		int total = static_cast<int>(display_insns.size());
		float avail_h = body_h - row_h;
		int visible = static_cast<int>(avail_h / row_h);

		float max_sc = (std::max)(0.f, static_cast<float>(total) * row_h - avail_h);
		ImGui::SetCursorScreenPos(ImVec2(code_x, body_top + row_h));
		ImGui::InvisibleButton("##deob_code_scroll", ImVec2(code_w - 10.f, avail_h));
		ui_anim::handle_scroll_input(st.code_target_scroll, 0.f, max_sc, row_h * 3.f);
		ui_anim::smooth_scroll(st.code_scroll_y, st.code_target_scroll, 15.f, dt);
		ui_anim::clamp_scroll(st.code_scroll_y, 0.f, max_sc);
		ui_anim::clamp_scroll(st.code_target_scroll, 0.f, max_sc);

		int start_row = static_cast<int>(st.code_scroll_y / row_h);
		if (start_row < 0) start_row = 0;

		for (int i = start_row; i < total && i < start_row + visible + 1; ++i) {
			float ry = hdr_y + static_cast<float>(i - start_row) * row_h;
			if (ry > body_top + body_h) break;

			auto* ci = display_insns[static_cast<size_t>(i)];
			float row_t = ui_anim::render_row_entrance(i - start_row, st.anim_time > 1.f ? 1.f : st.anim_time);

			bool hovered = ImGui::IsMouseHoveringRect(
				ImVec2(code_x, ry), ImVec2(code_x + code_w, ry + row_h));
			bool selected = (st.selected_insn == i);

			ImU32 rbg;
			if (ci->was_junk) {
				rbg = junk_col;
			} else {
				rbg = selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd));
			}

			if (selected && !ci->was_junk) {
				ui_anim::render_glow_rect(dl, code_x, ry, code_w, row_h,
					accent_r, accent_g, accent_b, alpha * row_t, 0.5f);
			}
			dl->AddRectFilled(ImVec2(code_x, ry), ImVec2(code_x + code_w, ry + row_h),
				ui_anim::theme_alpha(rbg, row_t));

			if (selected) {
				dl->AddRectFilled(ImVec2(code_x, ry), ImVec2(code_x + 3.f, ry + row_h),
					IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
							 static_cast<int>(accent_b * 255), static_cast<int>(180 * alpha * row_t)));
			}

			if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				st.selected_insn = i;

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%llX", static_cast<unsigned long long>(ci->address));
			dl->AddText(ImVec2(code_x + 4.f, ry + 2.f), ci->was_junk ? junk_text : cyan_col, abuf);

			std::string dtxt = ci->disasm;
			if (dtxt.size() > 55) dtxt = dtxt.substr(0, 52) + "...";
			ImU32 insn_col = ci->was_junk ? junk_text : text_col;
			dl->AddText(ImVec2(code_x + 134.f, ry + 2.f), insn_col, dtxt.c_str());

			if (ci->was_junk) {
				float line_y = ry + row_h * 0.5f;
				dl->AddLine(ImVec2(code_x + 134.f, line_y),
				            ImVec2(code_x + 134.f + ImGui::CalcTextSize(dtxt.c_str()).x, line_y),
				            _ta(ui_anim::lighten(_t.text_dim, 10)));
			}

			const char* status_label = nullptr;
			ImU32 status_color = dim_col;
			if (ci->was_junk) {
				status_label = "JUNK";
				status_color = red_col;
			} else if (ci->was_opaque) {
				status_label = "OPAQUE";
				status_color = yellow_col;
			} else if (ci->was_constant_folded) {
				status_label = "CONST";
				status_color = green_col;
			} else {
				status_label = "CLEAN";
				status_color = dim_col;
			}
			if (status_label && status_label[0] != 'C') {
				ui_anim::render_badge(dl, status_label, code_x + code_w - 66.f, ry + 2.f,
					ui_anim::theme_alpha(_t.panel_header, 0.63f * alpha * row_t),
					ui_anim::theme_alpha(status_color, row_t));
			} else {
				dl->AddText(ImVec2(code_x + code_w - 66.f, ry + 2.f),
					ui_anim::theme_alpha(status_color, row_t), status_label);
			}
		}

		if (total == 0) {
			ui_anim::render_empty_state(dl, code_x, hdr_y, code_w, body_h - 20.f,
				"No instructions after deobfuscation",
				accent_r, accent_g, accent_b, alpha, st.anim_time);
		}

		ui_anim::render_custom_scrollbar(dl, code_x + code_w - 8.f, body_top + row_h, 6.f, avail_h,
			st.code_scroll_y, static_cast<float>(total) * row_h, avail_h,
			alpha, st.code_scrollbar_dragging, st.code_scrollbar_drag_offset);
	}

	{
		ui_anim::render_panel_card(dl, info_x, body_top, info_w, body_h,
			accent_r, accent_g, accent_b, alpha, 4.f, false);

		float info_content_h = body_h - 8.f;
		ImGui::SetCursorScreenPos(ImVec2(info_x, body_top + 4.f));
		ImGui::BeginChild("##deob_info_panel", ImVec2(info_w, info_content_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
		auto* info_dl = ImGui::GetWindowDrawList();

		float iy = body_top + 4.f;
		float ix = info_x + 10.f;
		float iw = info_w - 20.f;

		{
			float card_h = 38.f;
			float card_w = (iw - 4.f) * 0.5f;
			char v_orig[16], v_clean[16], v_junk[16], v_pct[16];
			std::snprintf(v_orig, sizeof(v_orig), "%u", res.total_original);
			std::snprintf(v_clean, sizeof(v_clean), "%u", res.total_clean);
			std::snprintf(v_junk, sizeof(v_junk), "%u", res.removed_junk);
			float pct_val = res.total_original > 0 ? (1.f - static_cast<float>(res.total_clean) / static_cast<float>(res.total_original)) * 100.f : 0.f;
			std::snprintf(v_pct, sizeof(v_pct), "%.1f%%", pct_val);

			ui_anim::render_stat_card(dl, ix, iy, card_w, card_h, "Original", v_orig,
				accent_r, accent_g, accent_b, alpha);
			ui_anim::render_stat_card(dl, ix + card_w + 4.f, iy, card_w, card_h, "Clean", v_clean,
				accent_r, accent_g, accent_b, alpha, green_col);
			iy += card_h + 4.f;
			ui_anim::render_stat_card(dl, ix, iy, card_w, card_h, "Junk Removed", v_junk,
				accent_r, accent_g, accent_b, alpha, red_col);
			ui_anim::render_stat_card(dl, ix + card_w + 4.f, iy, card_w, card_h, "Reduction", v_pct,
				accent_r, accent_g, accent_b, alpha, yellow_col);
			iy += card_h + 8.f;
		}

		if (res.total_original > 0) {
			float pct = res.junk_ratio * 100.f;
			char pct_buf[32];
			std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%% junk", pct);

			float ring_cx = ix + iw * 0.5f;
			float ring_cy = iy + 40.f;
			float ring_r = 30.f;

			float donut_pulse = (std::sin(st.anim_time * 2.f) + 1.f) * 0.5f;
			ImU32 ring_glow_outer = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), static_cast<int>(alpha * (10.f + donut_pulse * 12.f)));
			dl->AddCircleFilled(ImVec2(ring_cx, ring_cy), ring_r + 12.f, ring_glow_outer, 32);
			ImU32 ring_glow = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), static_cast<int>(alpha * (18.f + donut_pulse * 10.f)));
			dl->AddCircleFilled(ImVec2(ring_cx, ring_cy), ring_r + 8.f, ring_glow, 32);

			float donut_fracs[] = { res.junk_ratio, 1.f - res.junk_ratio };
			ImU32 donut_cols[] = { red_col, green_col };
			ui_anim::render_donut_chart(dl, ring_cx, ring_cy, ring_r, 6.f,
				donut_fracs, donut_cols, 2, alpha, pct_buf);

			dl->AddText(ImVec2(ix, ring_cy + ring_r + 14.f), dim_col, "Opaques:");
			char op_buf[16];
			std::snprintf(op_buf, sizeof(op_buf), "%u", res.opaque_predicates_found);
			dl->AddText(ImVec2(ix + 60.f, ring_cy + ring_r + 14.f), yellow_col, op_buf);

			dl->AddText(ImVec2(ix + iw * 0.5f, ring_cy + ring_r + 14.f), dim_col, "Consts:");
			char cn_buf[16];
			std::snprintf(cn_buf, sizeof(cn_buf), "%u", res.constants_resolved);
			dl->AddText(ImVec2(ix + iw * 0.5f + 50.f, ring_cy + ring_r + 14.f), green_col, cn_buf);

			iy += 100.f;
		}

		if (!res.state_vars.empty()) {
			ui_anim::render_section_header(dl, info_x, iy, info_w, 22.f, "State Machine",
				accent_r, accent_g, accent_b, alpha);
			iy += 26.f;

			for (auto& sv : res.state_vars) {
				char dbuf[64];
				std::snprintf(dbuf, sizeof(dbuf), "Dispatcher: %llX",
				              static_cast<unsigned long long>(sv.dispatcher_addr));
				dl->AddText(ImVec2(ix, iy), dim_col, dbuf);
				iy += 16.f;

				dl->AddText(ImVec2(ix, iy), dim_col, "Register:");
				dl->AddText(ImVec2(ix + 70.f, iy), yellow_col, sv.register_name.c_str());
				iy += 16.f;

				for (auto& [state_val, target] : sv.state_to_target) {
					char sbuf[64];
					std::snprintf(sbuf, sizeof(sbuf), "  0x%llX -> 0x%llX",
					              static_cast<unsigned long long>(state_val),
					              static_cast<unsigned long long>(target));
					dl->AddText(ImVec2(ix, iy), cyan_col, sbuf);
					iy += 16.f;
					if (iy > body_top + body_h - 10.f) break;
				}
				iy += 4.f;
			}
		}

		if (!res.opaques.empty() && iy < body_top + body_h - 40.f) {
			ui_anim::render_section_header(dl, info_x, iy, info_w, 22.f, "Opaque Predicates",
				accent_r, accent_g, accent_b, alpha);
			iy += 26.f;

			int max_show = static_cast<int>((body_top + body_h - iy) / 16.f) - 1;
			int show_count = (std::min)(static_cast<int>(res.opaques.size()), max_show);

			for (int i = 0; i < show_count; ++i) {
				auto& op = res.opaques[static_cast<size_t>(i)];
				char obuf[80];
				std::snprintf(obuf, sizeof(obuf), "%llX: %s",
				              static_cast<unsigned long long>(op.address),
				              op.always_taken ? "always TAKEN" : "never TAKEN");
				dl->AddText(ImVec2(ix, iy), magenta_col, obuf);
				iy += 16.f;
			}
		}

		if (!res.constants.empty() && iy < body_top + body_h - 40.f) {
			ui_anim::render_section_header(dl, info_x, iy, info_w, 22.f, "Resolved Constants",
				accent_r, accent_g, accent_b, alpha);
			iy += 26.f;

			int max_show = static_cast<int>((body_top + body_h - iy) / 16.f) - 1;
			int show_count = (std::min)(static_cast<int>(res.constants.size()), max_show);

			for (int i = 0; i < show_count; ++i) {
				auto& c = res.constants[static_cast<size_t>(i)];
				char cbuf[80];
				std::snprintf(cbuf, sizeof(cbuf), "%llX: %s = 0x%llX",
				              static_cast<unsigned long long>(c.address),
				              c.register_name.c_str(),
				              static_cast<unsigned long long>(c.concrete_value));
				dl->AddText(ImVec2(ix, iy), green_col, cbuf);
				iy += 16.f;
			}
		}

		float info_scroll_content = iy - body_top;
		float info_scroll_visible = info_content_h;
		if (info_scroll_content > info_scroll_visible) {
			ui_anim::handle_scroll_input(st.info_target_scroll, 0.f,
				std::max(0.f, info_scroll_content - info_scroll_visible), 20.f);
			ui_anim::smooth_scroll(st.info_scroll_y, st.info_target_scroll, 12.f, dt);
		}
		ImGui::EndChild();
	}

	ImGui::EndChild();
}

}
