#pragma once

#include "deobfuscation_engine.hpp"
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

	float       info_scroll_y = 0.f;
	float       info_target_scroll = 0.f;
	int         active_info_tab = 0;

	bool show_junk = false;
};

static state_t s_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& eng = deobfuscation_engine::g_state;

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
	const ImU32 red_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 green_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 yellow_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
	const ImU32 cyan_col  = IM_COL32(86, 182, 194, static_cast<int>(alpha * 255));
	const ImU32 magenta_col = IM_COL32(198, 120, 221, static_cast<int>(alpha * 255));
	const ImU32 junk_col  = IM_COL32(100, 60, 60, static_cast<int>(alpha * 200));
	const ImU32 junk_text = IM_COL32(180, 100, 100, static_cast<int>(alpha * 180));

	ImVec2 wpos = ImGui::GetWindowPos();
	float cx = wpos.x + pos_x;
	float cy = wpos.y + pos_y;

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height), bg);

	const float toolbar_h = 68.f;
	const float pad = 12.f;

	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + toolbar_h), header_bg);

	float tx = cx + pad;
	float ty = cy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(tx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));

	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##deob_addr", "Function Addr (hex)", st.addr_input, sizeof(st.addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(120.f);
	ImGui::SliderInt("##deob_max", &st.max_instructions, 1000, 100000, "%d max");
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(2);

	ImGui::SameLine();

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

	bool processing = eng.processing.load();

	if (!processing) {
		if (ImGui::SmallButton("Deobfuscate")) {
			uint64_t addr = 0;
			if (st.addr_input[0])
				addr = std::strtoull(st.addr_input, nullptr, 16);
			if (addr != 0) {
				uint32_t max_insn = static_cast<uint32_t>(st.max_instructions);
				eng.processing.store(true);
				std::thread([addr, max_insn]() {
					auto result = deobfuscation_engine::deobfuscate_function(addr, max_insn);
					{
						std::lock_guard<std::mutex> lk(deobfuscation_engine::g_state.mutex);
						deobfuscation_engine::g_state.last_result = std::move(result);
					}
					deobfuscation_engine::g_state.processing.store(false);
				}).detach();
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Export ASM")) {
			std::lock_guard<std::mutex> lk(eng.mutex);
			if (eng.last_result.success) {
				std::string asm_text = deobfuscation_engine::export_clean_asm(eng.last_result);
				ImGui::SetClipboardText(asm_text.c_str());
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Export Stats")) {
			std::lock_guard<std::mutex> lk(eng.mutex);
			if (eng.last_result.success) {
				std::string stats_text = deobfuscation_engine::export_statistics(eng.last_result);
				ImGui::SetClipboardText(stats_text.c_str());
			}
		}
	} else {
		ImGui::SmallButton("Processing...");
	}

	ImGui::SameLine();

	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::Checkbox("Show Junk##deob_junk", &st.show_junk);
	ImGui::PopStyleColor();

	ImGui::PopStyleColor(4);

	ty += 26.f;

	if (processing) {
		uint32_t cur = eng.progress_current.load();
		uint32_t tot = eng.progress_total.load();
		if (tot > 0) {
			float frac = static_cast<float>(cur) / static_cast<float>(tot);
			float bar_w = (std::min)(width - pad * 2.f, 400.f);
			float bar_h = 6.f;
			float bx = cx + pad;
			float by = ty + 2.f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w, by + bar_h),
			                  IM_COL32(60, 60, 60, static_cast<int>(alpha * 255)));
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w * frac, by + bar_h), accent);
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
		const char* hint = res.error.empty()
			? "Enter a function address and click 'Deobfuscate'"
			: res.error.c_str();
		ImVec2 hs = ImGui::CalcTextSize(hint);
		dl->AddText(ImVec2(cx + width * 0.5f - hs.x * 0.5f, body_top + body_h * 0.4f),
		            res.error.empty() ? dim_col : red_col, hint);
		return;
	}

	if (!res.success) return;

	float code_w = width * 0.62f;
	float info_w = width - code_w - pad;

	float code_x = cx + pad;
	float info_x = code_x + code_w + 4.f;

	{
		const float row_h = 20.f;
		float hdr_y = body_top;

		dl->AddRectFilled(ImVec2(code_x, hdr_y), ImVec2(code_x + code_w, hdr_y + row_h), header_bg);
		dl->AddText(ImVec2(code_x + 4.f, hdr_y + 2.f), text_col, "Address");
		dl->AddText(ImVec2(code_x + 134.f, hdr_y + 2.f), text_col, "Instruction");
		dl->AddText(ImVec2(code_x + code_w - 70.f, hdr_y + 2.f), text_col, "Status");

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

		if (ImGui::IsMouseHoveringRect(ImVec2(code_x, body_top), ImVec2(code_x + code_w, body_top + body_h))) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) {
				st.code_target_scroll -= wheel * row_h * 3.f;
			}
		}

		float max_sc = (std::max)(0.f, static_cast<float>(total) * row_h - avail_h);
		if (st.code_target_scroll < 0.f) st.code_target_scroll = 0.f;
		if (st.code_target_scroll > max_sc) st.code_target_scroll = max_sc;
		st.code_scroll_y += (st.code_target_scroll - st.code_scroll_y) * 0.3f;

		int start_row = static_cast<int>(st.code_scroll_y / row_h);
		if (start_row < 0) start_row = 0;

		for (int i = start_row; i < total && i < start_row + visible + 1; ++i) {
			float ry = hdr_y + static_cast<float>(i - start_row) * row_h;
			if (ry > body_top + body_h) break;

			auto* ci = display_insns[static_cast<size_t>(i)];

			bool hovered = ImGui::IsMouseHoveringRect(
				ImVec2(code_x, ry), ImVec2(code_x + code_w, ry + row_h));
			bool selected = (st.selected_insn == i);

			ImU32 rbg;
			if (ci->was_junk) {
				rbg = junk_col;
			} else {
				rbg = selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd));
			}
			dl->AddRectFilled(ImVec2(code_x, ry), ImVec2(code_x + code_w, ry + row_h), rbg);

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
				            IM_COL32(180, 80, 80, static_cast<int>(alpha * 150)));
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
			dl->AddText(ImVec2(code_x + code_w - 66.f, ry + 2.f), status_color, status_label);
		}

		if (total == 0) {
			dl->AddText(ImVec2(code_x + 8.f, hdr_y + 8.f), dim_col, "No instructions");
		}
	}

	{
		dl->AddRectFilled(ImVec2(info_x, body_top), ImVec2(info_x + info_w, body_top + body_h), header_bg);

		float iy = body_top + 10.f;
		float ix = info_x + 10.f;
		float iw = info_w - 20.f;

		dl->AddText(ImVec2(ix, iy), accent, "Statistics");
		iy += 22.f;

		auto draw_stat = [&](const char* label, uint32_t value, ImU32 col) {
			char vbuf[32];
			std::snprintf(vbuf, sizeof(vbuf), "%u", value);
			dl->AddText(ImVec2(ix, iy), dim_col, label);
			ImVec2 vsz = ImGui::CalcTextSize(vbuf);
			dl->AddText(ImVec2(ix + iw - vsz.x, iy), col, vbuf);
			iy += 18.f;
		};

		draw_stat("Original Instructions", res.total_original, text_col);
		draw_stat("Clean Instructions", res.total_clean, green_col);
		draw_stat("Removed Junk", res.removed_junk, red_col);
		draw_stat("Opaque Predicates", res.opaque_predicates_found, yellow_col);
		draw_stat("Constants Resolved", res.constants_resolved, green_col);
		draw_stat("State Machine States", res.dispatcher_states_resolved, cyan_col);

		iy += 4.f;

		if (res.total_original > 0) {
			float pct = res.junk_ratio * 100.f;
			char pct_buf[32];
			std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%% junk", pct);

			float ring_cx = ix + iw * 0.5f;
			float ring_cy = iy + 40.f;
			float ring_r = 30.f;

			for (int seg = 0; seg < 64; ++seg) {
				float a0 = (static_cast<float>(seg) / 64.f) * 2.f * 3.14159f - 1.5708f;
				float a1 = (static_cast<float>(seg + 1) / 64.f) * 2.f * 3.14159f - 1.5708f;
				float frac = static_cast<float>(seg) / 64.f;
				ImU32 seg_col = (frac < res.junk_ratio) ? red_col : green_col;
				dl->AddLine(
					ImVec2(ring_cx + ring_r * std::cos(a0), ring_cy + ring_r * std::sin(a0)),
					ImVec2(ring_cx + ring_r * std::cos(a1), ring_cy + ring_r * std::sin(a1)),
					seg_col, 4.f);
			}

			ImVec2 pct_sz = ImGui::CalcTextSize(pct_buf);
			dl->AddText(ImVec2(ring_cx - pct_sz.x * 0.5f, ring_cy - pct_sz.y * 0.5f), text_col, pct_buf);
			iy += 86.f;
		}

		if (!res.state_vars.empty()) {
			dl->AddText(ImVec2(ix, iy), accent, "State Machine");
			iy += 20.f;

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
			dl->AddText(ImVec2(ix, iy), accent, "Opaque Predicates");
			iy += 20.f;

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
			dl->AddText(ImVec2(ix, iy), accent, "Resolved Constants");
			iy += 20.f;

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
	}
}

}
