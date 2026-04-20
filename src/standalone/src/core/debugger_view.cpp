#include "debugger_view.hpp"
#include "debugger_engine.hpp"
#include "standalone_driver.hpp"
#include "stealth_engine.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/globals.h"
#include "ui_anim.hpp"
#include "memory_map_view.hpp"
#include "thread_view.hpp"
#include "module_view.hpp"
#include "seh_view.hpp"
#include "cfg_view.hpp"
#include "code_patcher.hpp"

#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>

namespace debugger_view {


static constexpr float TAB_HEIGHT   = 30.f;
static constexpr float ROW_HEIGHT   = 20.f;
static constexpr float HEADER_H     = 24.f;


static bool draw_row(ImDrawList* dl, float x0, float y0, float x1, float y1,
					 float a, bool selected, float ar, float ag, float ab) {
	bool hov = ImGui::IsMouseHoveringRect(ImVec2(x0, y0), ImVec2(x1, y1), false);
	if (selected) {
		ImU32 sel_col = IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(30*a));
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), sel_col, 3.f);
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + 3.f, y1),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(180*a)));
		for (int g = 0; g < 3; ++g) {
			float gw = 6.f + static_cast<float>(g) * 4.f;
			float ga = (0.08f - static_cast<float>(g) * 0.025f) * a;
			dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + gw, y1),
				IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
						 static_cast<int>(ab*255), static_cast<int>(ga * 255.f)));
		}
	} else if (hov) {
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1),
			IM_COL32(255, 255, 255, static_cast<int>(10*a)), 3.f);
		dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + 2.f, y1),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(60*a)));
	}
	return hov;
}

static void render_column_header(ImDrawList* dl, float ox, float oy, float w,
								 float a, float ar, float ag, float ab) {
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + HEADER_H),
		_ta(_t.panel_header));
	ui_anim::render_gradient_header(dl, ox, oy, w, HEADER_H, ar, ag, ab, a * 0.3f);
	dl->AddLine(ImVec2(ox, oy + HEADER_H - 1.f), ImVec2(ox + w, oy + HEADER_H - 1.f),
		_ta(ui_anim::lighten(_t.panel_bg, 12)));
}


static void render_tab_bar(ImDrawList* dl, float ox, float oy, float w, float a,
						   float ar, float ag, float ab) {
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};
	auto& ui = g_ui;
	float dt = ImGui::GetIO().DeltaTime;

	static const char* tab_names[] = {
		"CPU", "Breakpoints", "Memory Map", "Call Stack", "Threads",
		"Watches", "Handles", "Trace", "Strings", "Bookmarks",
		"Modules", "Patches", "SEH", "CFG"
	};

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT),
		_ta(_t.bg_base));

	ui_anim::render_gradient_header(dl, ox, oy, w, TAB_HEIGHT, ar, ag, ab, a * 0.6f);

	int count = static_cast<int>(sub_tab_t::COUNT);
	float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
	float tab_positions[static_cast<int>(sub_tab_t::COUNT)];
	float total_tabs_w = 6.f;
	for (int i = 0; i < count; ++i) {
		tab_widths[i] = ImGui::CalcTextSize(tab_names[i]).x + 20.f;
		tab_positions[i] = total_tabs_w;
		total_tabs_w += tab_widths[i] + 3.f;
	}
	total_tabs_w += 6.f;

	bool tabs_overflow = total_tabs_w > w;

	if (tabs_overflow) {
		bool bar_hov = ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT), false);
		if (bar_hov) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f)
				ui.tab_target_scroll_x -= wheel * 60.f;
		}

		float max_scroll = std::max(0.f, total_tabs_w - w);
		ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
		ui.tab_scroll_x = ui_anim::smooth_lerp(ui.tab_scroll_x, ui.tab_target_scroll_x, 16.f, dt);
		if (std::abs(ui.tab_target_scroll_x - ui.tab_scroll_x) < 0.3f)
			ui.tab_scroll_x = ui.tab_target_scroll_x;

		int active_i = static_cast<int>(ui.active_tab);
		float active_left = tab_positions[active_i] - ui.tab_scroll_x + ox;
		float active_right = active_left + tab_widths[active_i];
		if (active_left < ox + 10.f)
			ui.tab_target_scroll_x = tab_positions[active_i] - 10.f;
		else if (active_right > ox + w - 10.f)
			ui.tab_target_scroll_x = tab_positions[active_i] + tab_widths[active_i] - w + 10.f;
		ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
	} else {
		ui.tab_scroll_x = 0.f;
		ui.tab_target_scroll_x = 0.f;
	}

	ImGui::PushClipRect(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT), true);

	int active_idx = static_cast<int>(ui.active_tab);
	float target_ul_x = ox + tab_positions[active_idx] - ui.tab_scroll_x + 4.f;
	float target_ul_w = tab_widths[active_idx] - 8.f;

	if (ui.underline_w < 0.01f) {
		ui.underline_x = target_ul_x;
		ui.underline_w = target_ul_w;
	}
	ui.underline_x = ui_anim::spring_interp(ui.underline_x, target_ul_x, ui.underline_vel, 280.f, 22.f, dt);
	ui.underline_w = ui_anim::smooth_lerp(ui.underline_w, target_ul_w, 14.f, dt);

	for (int i = 0; i < count; ++i) {
		auto tab = static_cast<sub_tab_t>(i);
		bool active = (ui.active_tab == tab);
		float tx = ox + tab_positions[i] - ui.tab_scroll_x;
		float tw = tab_widths[i];
		float ty = oy + 2.f;
		float th = TAB_HEIGHT - 5.f;

		if (tx + tw < ox || tx > ox + w) continue;

		bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx, ty), ImVec2(tx + tw, ty + th), false);

		float& tab_a = ui.tab_anim[i];
		float tab_target = active ? 1.f : (hov ? 0.5f : 0.f);
		tab_a = ui_anim::smooth_lerp(tab_a, tab_target, 12.f, dt);

		if (tab_a > 0.01f) {
			dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + tw, ty + th),
				IM_COL32(255, 255, 255, static_cast<int>(tab_a * 18.f * a)), 4.f);
		}

		ImVec2 ts = ImGui::CalcTextSize(tab_names[i]);
		float text_alpha = active ? 0.95f : (hov ? 0.8f : 0.5f);
		ImU32 col = active
			? IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					   static_cast<int>(ab*255), static_cast<int>(230*a))
			: ui_anim::theme_alpha(_t.text_primary, text_alpha * a);

		dl->AddText(ImVec2(tx + (tw - ts.x) * 0.5f, ty + (th - ts.y) * 0.5f), col, tab_names[i]);

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (ui.active_tab != tab) {
				ui.prev_tab = ui.active_tab;
				ui.content_fade = 0.f;
			}
			ui.active_tab = tab;
		}
	}

	if (ui.underline_w > 0.5f) {
		float ul_y = oy + TAB_HEIGHT - 3.f;

		for (int g = 0; g < 3; ++g) {
			float glow_spread = 2.f + static_cast<float>(g) * 2.f;
			float glow_a = (0.15f - static_cast<float>(g) * 0.04f) * a;
			dl->AddRectFilled(
				ImVec2(ui.underline_x - glow_spread, ul_y - glow_spread),
				ImVec2(ui.underline_x + ui.underline_w + glow_spread, ul_y + 2.f + glow_spread),
				IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
						 static_cast<int>(ab*255), static_cast<int>(glow_a * 255.f)),
				3.f + static_cast<float>(g));
		}

		dl->AddRectFilled(
			ImVec2(ui.underline_x, ul_y),
			ImVec2(ui.underline_x + ui.underline_w, ul_y + 2.f),
			IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
					 static_cast<int>(ab*255), static_cast<int>(230*a)),
			1.f);
	}

	ImGui::PopClipRect();

	if (tabs_overflow) {
		if (ui.tab_scroll_x > 1.f) {
			for (int f = 0; f < 30; ++f) {
				float fa = (1.f - static_cast<float>(f) / 30.f) * 0.9f * a;
				dl->AddRectFilled(
					ImVec2(ox + static_cast<float>(f), oy),
					ImVec2(ox + static_cast<float>(f) + 1.f, oy + TAB_HEIGHT),
					ui_anim::theme_alpha(_t.bg_base, fa));
			}
		}

		float max_scroll = total_tabs_w - w;
		if (ui.tab_scroll_x < max_scroll - 1.f) {
			for (int f = 0; f < 30; ++f) {
				float fa = (1.f - static_cast<float>(f) / 30.f) * 0.9f * a;
				dl->AddRectFilled(
					ImVec2(ox + w - static_cast<float>(f) - 1.f, oy),
					ImVec2(ox + w - static_cast<float>(f), oy + TAB_HEIGHT),
					ui_anim::theme_alpha(_t.bg_base, fa));
			}
		}
	}

	for (int si = 0; si < 3; ++si) {
		float sa = (1.f - static_cast<float>(si) / 3.f) * 0.3f * a;
		dl->AddRectFilled(
			ImVec2(ox, oy + TAB_HEIGHT + static_cast<float>(si)),
			ImVec2(ox + w, oy + TAB_HEIGHT + static_cast<float>(si) + 1.f),
			IM_COL32(0, 0, 0, static_cast<int>(sa * 255.f)));
	}

	{
		bool stealth_active = stealth_engine::is_active();
		const char* stealth_label = stealth_active ? "Stealth: ON" : "Stealth: OFF";
		ImVec2 stealth_sz = ImGui::CalcTextSize(stealth_label);
		float stealth_btn_w = stealth_sz.x + 16.f;
		float stealth_btn_h = 20.f;
		float stealth_x = ox + w - stealth_btn_w - 8.f;
		float stealth_y = oy + (TAB_HEIGHT - stealth_btn_h) * 0.5f;

		bool stealth_hov = ImGui::IsMouseHoveringRect(
			ImVec2(stealth_x, stealth_y),
			ImVec2(stealth_x + stealth_btn_w, stealth_y + stealth_btn_h), false);

		ImU32 stealth_bg = stealth_active
			? IM_COL32(static_cast<int>(ag*255), static_cast<int>(ag*255*0.8f), 0, static_cast<int>(120*a))
			: (stealth_hov
				? IM_COL32(255, 255, 255, static_cast<int>(15*a))
				: IM_COL32(255, 255, 255, static_cast<int>(8*a)));

		dl->AddRectFilled(ImVec2(stealth_x, stealth_y),
		                   ImVec2(stealth_x + stealth_btn_w, stealth_y + stealth_btn_h),
		                   stealth_bg, 4.f);

		ImU32 stealth_text_col = stealth_active
			? IM_COL32(152, 195, 121, static_cast<int>(230*a))
			: _ta(_t.text_secondary);
		dl->AddText(ImVec2(stealth_x + 8.f, stealth_y + (stealth_btn_h - stealth_sz.y) * 0.5f),
		            stealth_text_col, stealth_label);

		if (stealth_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (stealth_active) {
				stealth_engine::disable_stealth();
			} else {
				uint32_t pid = driver_bridge::attached_pid();
				if (pid != 0) {
					stealth_engine::enable_stealth(pid);
				}
			}
		}
	}
}


static void render_cpu(ImDrawList* dl, float ox, float oy, float w, float h,
					   float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	float dt = ImGui::GetIO().DeltaTime;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 text_col = _ta(_t.text_primary);
	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 mnem_col = IM_COL32(220, 180, 130, static_cast<int>(220*a));
	ImU32 reg_col  = IM_COL32(180, 220, 160, static_cast<int>(220*a));

	ui.panel_sep_phase += dt * 1.8f;
	if (ui.panel_sep_phase > 6.283185f) ui.panel_sep_phase -= 6.283185f;
	float sep_glow = (std::sin(ui.panel_sep_phase) * 0.5f + 0.5f) * 0.4f + 0.4f;

	float left_w = w * 0.65f;
	float right_w = w - left_w;
	float top_h = h * 0.6f;
	float bot_h = h - top_h;

	auto draw_panel_separator_v = [&](float sx, float sy, float sh) {
		ImU32 sep_col = IM_COL32(static_cast<int>(ar * 80 * sep_glow),
								  static_cast<int>(ag * 80 * sep_glow),
								  static_cast<int>(ab * 80 * sep_glow),
								  static_cast<int>(120 * a));
		dl->AddLine(ImVec2(sx, sy), ImVec2(sx, sy + sh), sep_col, 1.f);
		for (int gi = 1; gi <= 2; ++gi) {
			float ga = (0.08f - static_cast<float>(gi) * 0.03f) * a * sep_glow;
			dl->AddRectFilled(ImVec2(sx - static_cast<float>(gi), sy),
				ImVec2(sx + static_cast<float>(gi) + 1.f, sy + sh),
				IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						 static_cast<int>(ab * 255), static_cast<int>(ga * 255.f)));
		}
	};

	auto draw_panel_separator_h = [&](float sx, float sy, float sw) {
		ImU32 sep_col = IM_COL32(static_cast<int>(ar * 80 * sep_glow),
								  static_cast<int>(ag * 80 * sep_glow),
								  static_cast<int>(ab * 80 * sep_glow),
								  static_cast<int>(120 * a));
		dl->AddLine(ImVec2(sx, sy), ImVec2(sx + sw, sy), sep_col, 1.f);
		for (int gi = 1; gi <= 2; ++gi) {
			float ga = (0.08f - static_cast<float>(gi) * 0.03f) * a * sep_glow;
			dl->AddRectFilled(ImVec2(sx, sy - static_cast<float>(gi)),
				ImVec2(sx + sw, sy + static_cast<float>(gi) + 1.f),
				IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						 static_cast<int>(ab * 255), static_cast<int>(ga * 255.f)));
		}
	};

	auto draw_panel_header = [&](float px, float py, float pw, const char* label) {
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + HEADER_H),
			_ta(_t.panel_header));
		ui_anim::render_gradient_header(dl, px, py, pw, HEADER_H, ar, ag, ab, a * 0.35f);
		dl->AddLine(ImVec2(px, py + HEADER_H - 1.f), ImVec2(px + pw, py + HEADER_H - 1.f),
			IM_COL32(static_cast<int>(ar*60), static_cast<int>(ag*60),
					 static_cast<int>(ab*60), static_cast<int>(80*a)));
		dl->AddText(ImVec2(px + 8.f, py + 4.f), dim_col, label);
	};


	{
		float px = ox, py = oy, pw = left_w - 1.f, ph = top_h - 1.f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
			_ta(_t.bg_base));
		draw_panel_header(px, py, pw, "Disassembly");

		auto regs = debugger_engine::get_registers();
		uint64_t rip = regs.rip;

		if (rip != ui.prev_rip && rip != 0) {
			ui.rip_flash = 1.f;
			ui.prev_rip = rip;
		}
		ui_anim::decay_flash(ui.rip_flash, 3.f, dt);

		if (rip != 0) {
			std::vector<uint8_t> code;
			if (driver_bridge::read_memory(rip > 0x100 ? rip - 0x100 : 0, 0x400, code)) {
				uint64_t base = rip > 0x100 ? rip - 0x100 : 0;

				std::vector<AsmInstr> insns;
				{
					const uint8_t* data = code.data();
					int sz = static_cast<int>(code.size());
					int off = 0;
					while (off < sz && insns.size() < 128) {
						int remaining = sz - off;
						int avail = (remaining < 15) ? remaining : 15;
						insns.push_back(zydis_decode_one(data + off, avail, base + static_cast<uint64_t>(off)));
						off += insns.back().len;
					}
				}

				float dy = py + HEADER_H;
				ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

				for (size_t i = 0; i < insns.size(); ++i) {
					float ry = dy + static_cast<float>(i) * ROW_HEIGHT;
					if (ry + ROW_HEIGHT < dy || ry > py + ph) continue;

					bool is_rip = (insns[i].addr == rip);
					bool sel = (ui.disasm_selected == static_cast<int>(i));

					if (is_rip) {
						float rip_a = 20.f + ui.rip_flash * 25.f;
						dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT),
							IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
									 static_cast<int>(ab*255), static_cast<int>(rip_a*a)));

						float tri_glow = 0.8f + ui.rip_flash * 0.2f;
						dl->AddTriangleFilled(
							ImVec2(px + 4.f, ry + 4.f),
							ImVec2(px + 4.f, ry + ROW_HEIGHT - 4.f),
							ImVec2(px + 12.f, ry + ROW_HEIGHT * 0.5f),
							IM_COL32(static_cast<int>(ar*255*tri_glow), static_cast<int>(ag*255*tri_glow),
									 static_cast<int>(ab*255*tri_glow), static_cast<int>(230*a)));

						if (ui.rip_flash > 0.01f) {
							for (int fg = 0; fg < 2; ++fg) {
								float fga = ui.rip_flash * (0.12f - static_cast<float>(fg) * 0.05f) * a;
								dl->AddRectFilled(
									ImVec2(px, ry - static_cast<float>(fg + 1)),
									ImVec2(px + pw, ry + ROW_HEIGHT + static_cast<float>(fg + 1)),
									IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
											 static_cast<int>(ab*255), static_cast<int>(fga * 255.f)),
									2.f);
							}
						}

						ui_anim::render_status_dot(dl, px + 8.f, ry + ROW_HEIGHT * 0.5f, 2.f,
							IM_COL32(80, 220, 100, static_cast<int>(220 * a)),
							static_cast<float>(ImGui::GetTime()), true);
					}

					draw_row(dl, px, ry, px + pw, ry + ROW_HEIGHT, a, sel, ar, ag, ab);

					char abuf[20];
					snprintf(abuf, sizeof(abuf), "%016" PRIX64, insns[i].addr);
					dl->AddText(ImVec2(px + 16.f, ry + 1.f), addr_col, abuf);

					char textbuf[164];
					if (insns[i].ops[0])
						snprintf(textbuf, sizeof(textbuf), "%s %s", insns[i].mnem, insns[i].ops);
					else
						snprintf(textbuf, sizeof(textbuf), "%s", insns[i].mnem);
					dl->AddText(ImVec2(px + 160.f, ry + 1.f), mnem_col, textbuf);

					auto comment = debugger_engine::get_comment(insns[i].addr);
					if (!comment.empty()) {
						float cx = px + pw - ImGui::CalcTextSize(comment.c_str()).x - 8.f;
						dl->AddText(ImVec2(cx, ry + 1.f), dim_col, comment.c_str());
					}

					bool hov = ImGui::IsMouseHoveringRect(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT), false);
					if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
						ui.disasm_selected = static_cast<int>(i);
				}

				for (size_t bi = 0; bi < insns.size(); ++bi) {
					if (!insns[bi].is_branch && !insns[bi].is_call) continue;
					if (insns[bi].ops[0] != '0' || insns[bi].ops[1] != 'x') continue;
					uint64_t target = std::strtoull(insns[bi].ops, nullptr, 16);
					if (target == 0) continue;

					float from_y = dy + static_cast<float>(bi) * ROW_HEIGHT + ROW_HEIGHT * 0.5f;
					if (from_y < dy || from_y > py + ph) continue;

					bool found_target = false;
					float to_y = 0.f;
					for (size_t ti = 0; ti < insns.size(); ++ti) {
						if (insns[ti].addr == target) {
							to_y = dy + static_cast<float>(ti) * ROW_HEIGHT + ROW_HEIGHT * 0.5f;
							if (to_y >= dy && to_y <= py + ph) found_target = true;
							break;
						}
					}
					if (!found_target) continue;

					ImU32 arrow_col;
					if (insns[bi].is_call)
						arrow_col = IM_COL32(220, 80, 80, static_cast<int>(180 * a));
					else if (std::strcmp(insns[bi].mnem, "jmp") == 0)
						arrow_col = ui_anim::accent_col_u8(ar, ag, ab, static_cast<int>(180 * a));
					else
						arrow_col = IM_COL32(80, 220, 120, static_cast<int>(180 * a));

					ui_anim::render_branch_arrow(dl, px + 1.f, from_y, to_y, 13.f, arrow_col, 1.f);
				}

				ImGui::PopClipRect();
			}
		} else {
			dl->AddText(ImVec2(px + pw * 0.5f - 40.f, py + ph * 0.5f),
				_ta(_t.text_dim), "No target");
		}
	}


	draw_panel_separator_v(ox + left_w - 0.5f, oy, top_h);

	{
		float px = ox + left_w, py = oy, pw = right_w, ph = top_h - 1.f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
			_ta(_t.bg_base));
		draw_panel_header(px, py, pw, "Registers");

		auto regs = debugger_engine::get_registers();
		struct reg_info { const char* name; uint64_t val; int idx; };
		reg_info regs_list[] = {
			{"RAX", regs.rax, 0}, {"RBX", regs.rbx, 1}, {"RCX", regs.rcx, 2}, {"RDX", regs.rdx, 3},
			{"RSI", regs.rsi, 4}, {"RDI", regs.rdi, 5}, {"RBP", regs.rbp, 6}, {"RSP", regs.rsp, 7},
			{"R8",  regs.r8,  8}, {"R9",  regs.r9,  9}, {"R10", regs.r10, 10}, {"R11", regs.r11, 11},
			{"R12", regs.r12, 12}, {"R13", regs.r13, 13}, {"R14", regs.r14, 14}, {"R15", regs.r15, 15},
			{"RIP", regs.rip, 16}, {"RFLAGS", regs.rflags, 17},
		};

		float dt = ImGui::GetIO().DeltaTime;
		for (const auto& ri : regs_list) {
			if (ri.val != ui.prev_regs[ri.idx]) {
				ui.reg_flash[ri.idx] = 1.f;
				ui.prev_regs[ri.idx] = ri.val;
			}
			ui_anim::decay_flash(ui.reg_flash[ri.idx], 2.f, dt);
		}

		float ry = py + HEADER_H + 2.f;
		ImGui::PushClipRect(ImVec2(px, ry), ImVec2(px + pw, py + ph), true);

		for (const auto& ri : regs_list) {
			if (ry + ROW_HEIGHT > py + ph) break;

			char vbuf[20];
			snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, ri.val);

			dl->AddText(ImVec2(px + 6.f, ry + 1.f), dim_col, ri.name);

			float flash = ui.reg_flash[ri.idx];
			if (flash > 0.01f) {
				ImVec2 val_sz = ImGui::CalcTextSize(vbuf);
				dl->AddRectFilled(
					ImVec2(px + 58.f, ry),
					ImVec2(px + 62.f + val_sz.x, ry + ROW_HEIGHT),
					IM_COL32(255, 220, 80, static_cast<int>(flash * 180.f * a)));
			}
			ImU32 val_col = (flash > 0.01f)
				? IM_COL32(
					static_cast<int>(180 + 75.f * flash),
					static_cast<int>(220 - 120.f * flash),
					static_cast<int>(160 - 60.f * flash),
					static_cast<int>(220*a))
				: reg_col;
			dl->AddText(ImVec2(px + 60.f, ry + 1.f), val_col, vbuf);

			ry += ROW_HEIGHT;
		}


		if (ry + ROW_HEIGHT <= py + ph) {
			std::string flags = debugger_engine::format_flags(regs.rflags);
			dl->AddText(ImVec2(px + 6.f, ry + 1.f), dim_col, "Flags:");
			dl->AddText(ImVec2(px + 60.f, ry + 1.f),
				IM_COL32(200, 180, 140, static_cast<int>(200*a)), flags.c_str());
		}

		ImGui::PopClipRect();
	}


	draw_panel_separator_h(ox, oy + top_h - 0.5f, left_w);

	{
		float px = ox, py = oy + top_h, pw = left_w - 1.f, ph = bot_h;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
			_ta(_t.bg_base));
		draw_panel_header(px, py, pw, "Memory Dump");

		uint64_t dump_addr = ui.dump_address;
		if (dump_addr == 0) {
			auto regs = debugger_engine::get_registers();
			dump_addr = regs.rsp;
		}

		if (dump_addr != 0) {
			int rows = static_cast<int>((ph - HEADER_H) / ROW_HEIGHT);
			size_t bytes_per_row = 16;
			size_t total_bytes = static_cast<size_t>(rows) * bytes_per_row;

			std::vector<uint8_t> buf;
			driver_bridge::read_memory(dump_addr, total_bytes, buf);

			static std::vector<uint8_t> prev_dump;
			static std::vector<float> dump_byte_flash;
			static uint64_t prev_dump_addr = 0;

			float ddt = ImGui::GetIO().DeltaTime;
			if (prev_dump_addr != dump_addr || prev_dump.size() != buf.size()) {
				prev_dump = buf;
				prev_dump_addr = dump_addr;
				dump_byte_flash.assign(buf.size(), 0.f);
			} else {
				for (size_t di = 0; di < buf.size() && di < prev_dump.size(); ++di) {
					if (buf[di] != prev_dump[di]) {
						dump_byte_flash[di] = 1.f;
						prev_dump[di] = buf[di];
					}
					ui_anim::decay_flash(dump_byte_flash[di], 2.f, ddt);
				}
			}

			float dy = py + HEADER_H;
			ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

			{
				float hhx = px + 150.f;
				for (size_t c = 0; c < bytes_per_row; ++c) {
					char hc[4];
					snprintf(hc, sizeof(hc), "%X", static_cast<int>(c));
					dl->AddText(ImVec2(hhx + 4.f, dy + 1.f), dim_col, hc);
					hhx += 22.f;
					if (c == 7) hhx += 6.f;
				}
				dy += ROW_HEIGHT;
			}

			for (int r = 0; r < rows && r * static_cast<int>(bytes_per_row) < static_cast<int>(buf.size()); ++r) {
				float ry = dy + static_cast<float>(r) * ROW_HEIGHT;


				char abuf[20];
				snprintf(abuf, sizeof(abuf), "%016" PRIX64, dump_addr + static_cast<uint64_t>(r) * bytes_per_row);
				dl->AddText(ImVec2(px + 4.f, ry + 1.f), addr_col, abuf);


				float hx = px + 150.f;
				size_t off = static_cast<size_t>(r) * bytes_per_row;
				for (size_t b = 0; b < bytes_per_row && off + b < buf.size(); ++b) {
					size_t byte_idx = off + b;
					float bf = (byte_idx < dump_byte_flash.size()) ? dump_byte_flash[byte_idx] : 0.f;
					if (bf > 0.01f) {
						dl->AddRectFilled(
							ImVec2(hx - 1.f, ry),
							ImVec2(hx + 17.f, ry + ROW_HEIGHT),
							IM_COL32(220, 60, 60, static_cast<int>(bf * 120.f * a)));
					}
					char hbuf[4];
					snprintf(hbuf, sizeof(hbuf), "%02X", buf[off + b]);
					dl->AddText(ImVec2(hx, ry + 1.f), text_col, hbuf);
					hx += 22.f;
					if (b == 7) hx += 6.f;
				}


				float ax = hx + 10.f;
				for (size_t b = 0; b < bytes_per_row && off + b < buf.size(); ++b) {
					char ch = (buf[off + b] >= 0x20 && buf[off + b] <= 0x7e)
						? static_cast<char>(buf[off + b]) : '.';
					char cbuf[2] = {ch, 0};
					dl->AddText(ImVec2(ax, ry + 1.f),
						_ta(_t.text_secondary), cbuf);
					ax += 8.f;
				}
			}

			ImGui::PopClipRect();
		}
	}


	draw_panel_separator_h(ox + left_w, oy + top_h - 0.5f, right_w);
	draw_panel_separator_v(ox + left_w - 0.5f, oy + top_h, bot_h);

	{
		float px = ox + left_w, py = oy + top_h, pw = right_w, ph = bot_h;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
			_ta(_t.bg_base));
		draw_panel_header(px, py, pw, "Stack");
		auto regs = debugger_engine::get_registers();
		uint64_t rsp = regs.rsp;

		if (rsp != 0) {
			int rows = static_cast<int>((ph - HEADER_H) / ROW_HEIGHT);
			size_t total = static_cast<size_t>(rows) * 8;

			std::vector<uint8_t> buf;
			driver_bridge::read_memory(rsp, total, buf);

			float dy = py + HEADER_H;
			ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

			for (int r = 0; r < rows && static_cast<size_t>(r) * 8 + 8 <= buf.size(); ++r) {
				float ry = dy + static_cast<float>(r) * ROW_HEIGHT;

				uint64_t addr = rsp + static_cast<uint64_t>(r) * 8;
				uint64_t val;
				std::memcpy(&val, buf.data() + static_cast<size_t>(r) * 8, 8);

				char abuf[20], vbuf[20];
				snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
				snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, val);

				bool is_rsp = (r == 0);
				if (is_rsp) {
					dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT),
						IM_COL32(static_cast<int>(ar*255), static_cast<int>(ag*255),
								 static_cast<int>(ab*255), static_cast<int>(12*a)));
				}

				dl->AddText(ImVec2(px + 4.f, ry + 1.f), addr_col, abuf);
				dl->AddText(ImVec2(px + 150.f, ry + 1.f), text_col, vbuf);
			}

			ImGui::PopClipRect();
		}
	}
}


static void render_breakpoints(ImDrawList* dl, float ox, float oy, float w, float h,
							   float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 text_col = _ta(_t.text_primary);
	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 en_col   = IM_COL32(100, 220, 120, static_cast<int>(220*a));
	ImU32 dis_col  = IM_COL32(220, 100, 100, static_cast<int>(220*a));

	{
		ui_anim::table_col_t cols[] = {{"#", 22.f}, {"State", 60.f}, {"Address", 150.f}, {"Type", 80.f}, {"Name", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 5, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.bp_mutex);
	float ry = oy + HEADER_H;

	for (int i = 0; i < static_cast<int>(st.breakpoints.size()); ++i) {
		if (ry + ROW_HEIGHT > oy + h) break;
		auto& bp = st.breakpoints[static_cast<size_t>(i)];
		bool sel = (ui.list_selected == i);

		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		char ibuf[8];
		snprintf(ibuf, sizeof(ibuf), "%d", i);
		dl->AddText(ImVec2(ox + 6.f, ry + 2.f), dim_col, ibuf);

		bool enabled = (bp.state == debugger_engine::bp_state_t::enabled);
		ui_anim::render_status_dot(dl, ox + 40.f, ry + ROW_HEIGHT * 0.5f, 3.f,
			enabled ? en_col : dis_col, static_cast<float>(ImGui::GetTime()), enabled);
		{
			const char* state_str = enabled ? "ON" : "OFF";
			ImU32 pill_col = enabled ? en_col : dis_col;
			ImVec2 sts = ImGui::CalcTextSize(state_str);
			float pw = sts.x + 8.f;
			float ph = sts.y + 2.f;
			float py = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 48.f, py), ImVec2(ox + 48.f + pw, py + ph),
				IM_COL32((pill_col >> IM_COL32_R_SHIFT) & 0xFF, (pill_col >> IM_COL32_G_SHIFT) & 0xFF,
				         (pill_col >> IM_COL32_B_SHIFT) & 0xFF, static_cast<int>(35*a)), ph * 0.5f);
			dl->AddText(ImVec2(ox + 52.f, ry + 2.f), pill_col, state_str);
		}

		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, bp.address);
		dl->AddText(ImVec2(ox + 90.f, ry + 2.f), addr_col, abuf);

		static const char* type_names[] = {"SW", "HW_EXEC", "HW_WRITE", "HW_READ", "MEM"};
		ui_anim::render_badge(dl, type_names[static_cast<int>(bp.type)],
			ox + 240.f, ry + 2.f,
			_ta(_t.panel_bg), dim_col);

		if (!bp.name.empty())
			dl->AddText(ImVec2(ox + 320.f, ry + 2.f), text_col, bp.name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.list_selected = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
			debugger_engine::toggle_breakpoint(i);

		ry += ROW_HEIGHT;
	}

	float total_content = static_cast<float>(st.breakpoints.size()) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	if (total_content > visible_h) {
		static bool bp_scrollbar_dragging = false;
		static float bp_scrollbar_offset = 0.f;
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, oy + HEADER_H, 8.f, visible_h,
			ui.bp_scroll_y, total_content, visible_h, a, bp_scrollbar_dragging, bp_scrollbar_offset);
	}

	if (st.breakpoints.empty())
		ui_anim::render_empty_state(dl, ox, oy + HEADER_H, w, h - HEADER_H,
			"No breakpoints set. Double-click in disassembly to add.",
			ar, ag, ab, a, static_cast<float>(ImGui::GetTime()));
}


static void render_memmap(ImDrawList* dl, float ox, float oy, float w, float h,
						  float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"Base", 142.f}, {"Size", 90.f}, {"Protect", 140.f}, {"Module", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 4, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.memmap_mutex);

	int visible = static_cast<int>((h - HEADER_H) / ROW_HEIGHT);
	int total = static_cast<int>(st.memory_map.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, oy + HEADER_H), ImVec2(ox + w, oy + h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.memmap_target_scroll_y -= wheel * ROW_HEIGHT * 3.f;
	}
	float max_sc = std::max(0.f, static_cast<float>(total) * ROW_HEIGHT - (h - HEADER_H));
	ui.memmap_target_scroll_y = std::clamp(ui.memmap_target_scroll_y, 0.f, max_sc);
	ui.memmap_scroll_y += (ui.memmap_target_scroll_y - ui.memmap_scroll_y) * 0.25f;

	int first = static_cast<int>(ui.memmap_scroll_y / ROW_HEIGHT);
	int last = std::min(total, first + visible + 2);

	float body_y = oy + HEADER_H;
	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, oy + h), true);

	for (int i = first; i < last; ++i) {
		float ry = body_y + static_cast<float>(i) * ROW_HEIGHT - ui.memmap_scroll_y;
		if (ry + ROW_HEIGHT < body_y || ry > oy + h) continue;

		auto& r = st.memory_map[static_cast<size_t>(i)];
		bool sel = (ui.memmap_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, a, 1.f, ar, ag, ab});

		char buf[20];
		snprintf(buf, sizeof(buf), "%016" PRIX64, r.base);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), addr_col, buf);

		snprintf(buf, sizeof(buf), "%08" PRIX64, r.size);
		dl->AddText(ImVec2(ox + 150.f, ry + 1.f), text_col, buf);

		auto prot_str = debugger_engine::format_protect(r.protect);
		{
			ImU32 prot_col = dim_col;
			bool has_exec = (r.protect & 0xF0) != 0;
			bool has_write = (r.protect & 0x04) || (r.protect & 0x08) || (r.protect & 0x40) || (r.protect & 0x80);
			if (has_exec) prot_col = IM_COL32(240, 90, 90, static_cast<int>(220*a));
			else if (has_write) prot_col = IM_COL32(230, 195, 80, static_cast<int>(220*a));
			else prot_col = IM_COL32(90, 200, 130, static_cast<int>(200*a));
			ImVec2 pts = ImGui::CalcTextSize(prot_str.c_str());
			float pw = pts.x + 10.f;
			float ph = pts.y + 2.f;
			float py = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 238.f, py), ImVec2(ox + 238.f + pw, py + ph),
				IM_COL32((prot_col >> IM_COL32_R_SHIFT) & 0xFF, (prot_col >> IM_COL32_G_SHIFT) & 0xFF,
				         (prot_col >> IM_COL32_B_SHIFT) & 0xFF, static_cast<int>(35*a)), ph * 0.5f);
			dl->AddText(ImVec2(ox + 243.f, ry + 1.f), prot_col, prot_str.c_str());
		}

		if (!r.module_name.empty())
			dl->AddText(ImVec2(ox + 380.f, ry + 1.f), text_col, r.module_name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.memmap_selected = i;
	}

	ImGui::PopClipRect();
}


static void render_callstack(ImDrawList* dl, float ox, float oy, float w, float h,
							 float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"#", 22.f}, {"Address", 150.f}, {"Module", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 3, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.stack_mutex);
	float ry = oy + HEADER_H;

	for (int i = 0; i < static_cast<int>(st.call_stack.size()); ++i) {
		if (ry + ROW_HEIGHT > oy + h) break;
		auto& f = st.call_stack[static_cast<size_t>(i)];
		bool sel = (ui.list_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		char ibuf[8];
		snprintf(ibuf, sizeof(ibuf), "%d", i);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), dim_col, ibuf);

		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, f.address);
		dl->AddText(ImVec2(ox + 30.f, ry + 1.f), addr_col, abuf);

		std::string mod_info;
		if (!f.module_name.empty()) {
			char obuf[20];
			snprintf(obuf, sizeof(obuf), "+0x%" PRIX64, f.module_offset);
			mod_info = f.module_name + obuf;
		}
		dl->AddText(ImVec2(ox + 180.f, ry + 1.f), text_col, mod_info.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.list_selected = i;

		ry += ROW_HEIGHT;
	}

	float total_content = static_cast<float>(st.call_stack.size()) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	if (total_content > visible_h) {
		static bool cs_scrollbar_dragging = false;
		static float cs_scrollbar_offset = 0.f;
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, oy + HEADER_H, 8.f, visible_h,
			ui.callstack_scroll_y, total_content, visible_h, a, cs_scrollbar_dragging, cs_scrollbar_offset);
	}
}


static void render_watches(ImDrawList* dl, float ox, float oy, float w, float h,
						   float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 text_col = _ta(_t.text_primary);
	ImU32 val_col  = IM_COL32(180, 220, 160, static_cast<int>(220*a));

	{
		ui_anim::table_col_t cols[] = {{"Expression", 192.f}, {"Value", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 2, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.watch_mutex);
	float ry = oy + HEADER_H;

	for (int i = 0; i < static_cast<int>(st.watches.size()); ++i) {
		if (ry + ROW_HEIGHT > oy + h) break;
		auto& w_entry = st.watches[static_cast<size_t>(i)];
		bool sel = (ui.list_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), text_col, w_entry.expression.c_str());
		dl->AddText(ImVec2(ox + 200.f, ry + 1.f),
			w_entry.valid ? val_col : IM_COL32(220, 100, 100, static_cast<int>(200*a)),
			w_entry.value.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.list_selected = i;

		ry += ROW_HEIGHT;
	}

	float total_content = static_cast<float>(st.watches.size()) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	if (total_content > visible_h) {
		static bool watch_scrollbar_dragging = false;
		static float watch_scrollbar_offset = 0.f;
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, oy + HEADER_H, 8.f, visible_h,
			ui.watch_scroll_y, total_content, visible_h, a, watch_scrollbar_dragging, watch_scrollbar_offset);
	}
}


static void render_trace(ImDrawList* dl, float ox, float oy, float w, float h,
						 float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"#", 42.f}, {"Address", 150.f}, {"Instruction", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 3, ar, ag, ab, a);
	}

	bool tracing = st.tracing.load();
	const char* status = tracing ? "Recording..." : "Stopped";
	ImU32 sc = tracing ? IM_COL32(100, 220, 120, static_cast<int>(200*a))
					   : IM_COL32(180, 100, 100, static_cast<int>(200*a));
	{
		ImVec2 sts = ImGui::CalcTextSize(status);
		float pw = sts.x + 22.f;
		float ph = sts.y + 4.f;
		float px = ox + w - pw - 6.f;
		float py = oy + (HEADER_H - ph) * 0.5f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
			IM_COL32((sc >> IM_COL32_R_SHIFT) & 0xFF, (sc >> IM_COL32_G_SHIFT) & 0xFF,
			         (sc >> IM_COL32_B_SHIFT) & 0xFF, static_cast<int>(30*a)), ph * 0.5f);
		ui_anim::render_status_dot(dl, px + 8.f, py + ph * 0.5f, 3.f, sc,
			static_cast<float>(ImGui::GetTime()), tracing);
		dl->AddText(ImVec2(px + 16.f, py + 2.f), sc, status);
	}

	std::lock_guard<std::mutex> lk(st.trace_mutex);

	int visible = static_cast<int>((h - HEADER_H) / ROW_HEIGHT);
	int total = static_cast<int>(st.trace_log.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, oy + HEADER_H), ImVec2(ox + w, oy + h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.trace_target_scroll_y -= wheel * ROW_HEIGHT * 3.f;
	}
	float max_sc = std::max(0.f, static_cast<float>(total) * ROW_HEIGHT - (h - HEADER_H));
	ui.trace_target_scroll_y = std::clamp(ui.trace_target_scroll_y, 0.f, max_sc);
	ui.trace_scroll_y += (ui.trace_target_scroll_y - ui.trace_scroll_y) * 0.25f;

	int first = static_cast<int>(ui.trace_scroll_y / ROW_HEIGHT);
	int last = std::min(total, first + visible + 2);

	float body_y = oy + HEADER_H;
	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, oy + h), true);

	for (int i = first; i < last; ++i) {
		float ry = body_y + static_cast<float>(i) * ROW_HEIGHT - ui.trace_scroll_y;
		if (ry + ROW_HEIGHT < body_y || ry > oy + h) continue;

		auto& tr = st.trace_log[static_cast<size_t>(i)];
		bool sel = (ui.trace_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, first, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		char ibuf[12];
		snprintf(ibuf, sizeof(ibuf), "%d", tr.index);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), dim_col, ibuf);

		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, tr.address);
		dl->AddText(ImVec2(ox + 50.f, ry + 1.f), addr_col, abuf);
		dl->AddText(ImVec2(ox + 200.f, ry + 1.f), text_col, tr.disasm_text.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.trace_selected = i;
	}

	ImGui::PopClipRect();

	if (st.trace_log.empty() && !tracing)
		ui_anim::render_empty_state(dl, ox, oy + HEADER_H, w, h - HEADER_H,
			"No trace entries. Start recording to capture execution.",
			ar, ag, ab, a, static_cast<float>(ImGui::GetTime()));
}


static void render_strings(ImDrawList* dl, float ox, float oy, float w, float h,
						   float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"Address", 142.f}, {"String", 400.f}, {"Module", 100.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 3, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.strings_mutex);

	int visible = static_cast<int>((h - HEADER_H) / ROW_HEIGHT);
	int total = static_cast<int>(st.strings.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, oy + HEADER_H), ImVec2(ox + w, oy + h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.strings_target_scroll_y -= wheel * ROW_HEIGHT * 3.f;
	}
	float max_sc = std::max(0.f, static_cast<float>(total) * ROW_HEIGHT - (h - HEADER_H));
	ui.strings_target_scroll_y = std::clamp(ui.strings_target_scroll_y, 0.f, max_sc);
	ui.strings_scroll_y += (ui.strings_target_scroll_y - ui.strings_scroll_y) * 0.25f;

	int first = static_cast<int>(ui.strings_scroll_y / ROW_HEIGHT);
	int last = std::min(total, first + visible + 2);

	float body_y = oy + HEADER_H;
	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, oy + h), true);

	for (int i = first; i < last; ++i) {
		float ry = body_y + static_cast<float>(i) * ROW_HEIGHT - ui.strings_scroll_y;
		if (ry + ROW_HEIGHT < body_y || ry > oy + h) continue;

		auto& sr = st.strings[static_cast<size_t>(i)];
		bool sel = (ui.strings_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, first, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, sr.address);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), addr_col, abuf);


		std::string display = sr.value;
		if (display.size() > 80) display = display.substr(0, 80) + "...";
		dl->AddText(ImVec2(ox + 150.f, ry + 1.f), text_col, display.c_str());

		if (!sr.module_name.empty())
			dl->AddText(ImVec2(ox + w - 80.f, ry + 1.f), dim_col, sr.module_name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.strings_selected = i;
	}

	ImGui::PopClipRect();
}


static void render_threads(ImDrawList* dl, float ox, float oy, float w, float h,
						   float a, float ar, float ag, float ab) {
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"TID", 72.f}, {"Owner PID", 100.f}, {"Priority", 100.f}, {"State", 100.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 4, ar, ag, ab, a);
	}

	auto threads = driver_bridge::enumerate_threads();
	float body_y = oy + HEADER_H;
	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, oy + h), true);

	for (int ti = 0; ti < static_cast<int>(threads.size()); ++ti) {
		float ry = body_y + static_cast<float>(ti) * ROW_HEIGHT;
		if (ry + ROW_HEIGHT > oy + h) break;
		if (ry + ROW_HEIGHT < body_y) continue;

		auto& t = threads[ti];
		bool sel = (g_ui.list_selected == ti);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(ti, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, ti, row_a, 1.f, ar, ag, ab});

		char tbuf[12];
		snprintf(tbuf, sizeof(tbuf), "%u", t.tid);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), addr_col, tbuf);

		char pbuf[12];
		snprintf(pbuf, sizeof(pbuf), "%u", t.owner_pid);
		dl->AddText(ImVec2(ox + 80.f, ry + 1.f), text_col, pbuf);

		char prbuf[12];
		snprintf(prbuf, sizeof(prbuf), "%d", t.priority);
		dl->AddText(ImVec2(ox + 180.f, ry + 1.f), dim_col, prbuf);

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_ui.list_selected = ti;
	}

	ImGui::PopClipRect();
}


static void render_bookmarks(ImDrawList* dl, float ox, float oy, float w, float h,
							 float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 addr_col = IM_COL32(130, 170, 255, static_cast<int>(220*a));
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"#", 22.f}, {"Address", 150.f}, {"Label", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 3, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.anno_mutex);
	float ry = oy + HEADER_H;

	for (int i = 0; i < static_cast<int>(st.bookmarks.size()); ++i) {
		if (ry + ROW_HEIGHT > oy + h) break;
		uint64_t addr = st.bookmarks[static_cast<size_t>(i)];
		bool sel = (ui.list_selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, ar, ag, ab});

		char ibuf[8], abuf[20];
		snprintf(ibuf, sizeof(ibuf), "%d", i);
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), dim_col, ibuf);
		dl->AddText(ImVec2(ox + 30.f, ry + 1.f), addr_col, abuf);

		auto it = st.labels.find(addr);
		if (it != st.labels.end())
			dl->AddText(ImVec2(ox + 180.f, ry + 1.f), text_col, it->second.text.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.list_selected = i;

		ry += ROW_HEIGHT;
	}

	float total_content = static_cast<float>(st.bookmarks.size()) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	if (total_content > visible_h) {
		static bool bk_scrollbar_dragging = false;
		static float bk_scrollbar_offset = 0.f;
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, oy + HEADER_H, 8.f, visible_h,
			ui.bookmark_scroll_y, total_content, visible_h, a, bk_scrollbar_dragging, bk_scrollbar_offset);
	}
}


static void render_handles(ImDrawList* dl, float ox, float oy, float w, float h,
						   float a, float ar, float ag, float ab) {
	auto& st = debugger_engine::g_state;
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};

	ImU32 dim_col  = _ta(_t.text_secondary);
	ImU32 text_col = _ta(_t.text_primary);

	{
		ui_anim::table_col_t cols[] = {{"Handle", 72.f}, {"Type", 120.f}, {"Name", 200.f}};
		ui_anim::render_table_header(dl, ox, oy, w, HEADER_H, cols, 3, ar, ag, ab, a);
	}

	std::lock_guard<std::mutex> lk(st.handle_mutex);
	float body_y = oy + HEADER_H;
	int total = static_cast<int>(st.handles.size());
	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, oy + h), true);

	for (int hi = 0; hi < total; ++hi) {
		float ry = body_y + static_cast<float>(hi) * ROW_HEIGHT;
		if (ry + ROW_HEIGHT > oy + h) break;
		if (ry + ROW_HEIGHT < body_y) continue;

		auto& h_entry = st.handles[static_cast<size_t>(hi)];
		bool sel = (g_ui.list_selected == hi);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(hi, 0, ImGui::GetIO().DeltaTime, a);
		ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, hi, row_a, 1.f, ar, ag, ab});

		char hbuf[12];
		snprintf(hbuf, sizeof(hbuf), "0x%X", static_cast<unsigned>(h_entry.handle));
		dl->AddText(ImVec2(ox + 6.f, ry + 1.f), text_col, hbuf);
		{
			ImU32 type_col = dim_col;
			if (h_entry.type_name == "File") type_col = IM_COL32(100, 200, 255, static_cast<int>(220*a));
			else if (h_entry.type_name == "Thread") type_col = IM_COL32(255, 200, 100, static_cast<int>(220*a));
			else if (h_entry.type_name == "Mutant") type_col = IM_COL32(200, 130, 240, static_cast<int>(220*a));
			else if (h_entry.type_name == "Section") type_col = IM_COL32(240, 100, 130, static_cast<int>(220*a));
			else if (h_entry.type_name == "Key") type_col = IM_COL32(130, 220, 160, static_cast<int>(220*a));
			else if (h_entry.type_name == "Event" || h_entry.type_name == "Semaphore")
				type_col = IM_COL32(220, 210, 80, static_cast<int>(220*a));
			ImVec2 tts = ImGui::CalcTextSize(h_entry.type_name.c_str());
			float pw = tts.x + 10.f;
			float ph = tts.y + 2.f;
			float py = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 78.f, py), ImVec2(ox + 78.f + pw, py + ph),
				IM_COL32((type_col >> IM_COL32_R_SHIFT) & 0xFF, (type_col >> IM_COL32_G_SHIFT) & 0xFF,
				         (type_col >> IM_COL32_B_SHIFT) & 0xFF, static_cast<int>(35*a)), ph * 0.5f);
			dl->AddText(ImVec2(ox + 83.f, ry + 1.f), type_col, h_entry.type_name.c_str());
		}
		dl->AddText(ImVec2(ox + 200.f, ry + 1.f), text_col, h_entry.name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			g_ui.list_selected = hi;
	}

	ImGui::PopClipRect();

	float total_content = static_cast<float>(total) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	if (total_content > visible_h) {
		static bool hdl_scrollbar_dragging = false;
		static float hdl_scrollbar_offset = 0.f;
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, oy + HEADER_H, 8.f, visible_h,
			g_ui.handle_scroll_y, total_content, visible_h, a, hdl_scrollbar_dragging, hdl_scrollbar_offset);
	}

	if (st.handles.empty())
		ui_anim::render_empty_state(dl, ox, oy + HEADER_H, w, h - HEADER_H,
			"No handles found. Attach to a process to enumerate handles.",
			ar, ag, ab, a, static_cast<float>(ImGui::GetTime()));
}


void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b) {
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##debugger_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float dt = ImGui::GetIO().DeltaTime;

	g_ui.content_fade = ui_anim::smooth_lerp(g_ui.content_fade, 1.f, 14.f, dt);
	float a = alpha * std::max(g_ui.content_fade, 0.3f);
	const auto& _t = themes::resolved;
	const auto _ta = [a](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, a);
	};


	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		ui_anim::theme_alpha(_t.bg_base, alpha));

	render_tab_bar(dl, ox, oy, w, alpha, accent_r, accent_g, accent_b);

	float content_y = oy + TAB_HEIGHT;
	float content_h = h - TAB_HEIGHT;

	switch (g_ui.active_tab) {
		case sub_tab_t::cpu:
			render_cpu(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::breakpoints:
			render_breakpoints(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::memory_map:
			render_memmap(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::call_stack:
			render_callstack(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::threads:
			render_threads(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::watches:
			render_watches(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::handles:
			render_handles(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::trace_log:
			render_trace(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::strings:
			render_strings(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::bookmarks:
			render_bookmarks(dl, ox, content_y, w, content_h, a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::modules:
			module_view::render(ox, content_y, w, content_h,
				a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::patches: {
			float cy = content_y;
			ImU32 dim2 = _ta(_t.text_secondary);
			ImU32 addr2 = IM_COL32(130, 170, 255, static_cast<int>(220*a));
			ImU32 text2 = _ta(_t.text_primary);

			{
				ui_anim::table_col_t cols[] = {{"#", 22.f}, {"Address", 150.f}, {"Original", 140.f}, {"Patched", 140.f}, {"Description", 140.f}, {"Active", 70.f}};
				ui_anim::render_table_header(dl, ox, cy, w, HEADER_H, cols, 6, accent_r, accent_g, accent_b, a);
			}

			std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
			auto& patches = code_patcher::g_state.patches;
			float ry = cy + HEADER_H;

			if (patches.empty()) {
				ui_anim::render_empty_state(dl, ox, cy + HEADER_H, w, content_h - HEADER_H,
					"No patches applied. Use the patcher to modify code.",
					accent_r, accent_g, accent_b, a, static_cast<float>(ImGui::GetTime()));
			}

			for (int i = 0; i < static_cast<int>(patches.size()); ++i) {
				if (ry + ROW_HEIGHT > content_y + content_h) break;
				auto& p = patches[static_cast<size_t>(i)];
				bool sel = (g_ui.list_selected == i);
				bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + ROW_HEIGHT), false);
				float row_a = ui_anim::render_row_entrance(i, 0, ImGui::GetIO().DeltaTime, a);
				ui_anim::render_table_row(dl, ox, ry, w, ROW_HEIGHT, {sel, hov, i, row_a, 1.f, accent_r, accent_g, accent_b});

				char ibuf[8]; snprintf(ibuf, sizeof(ibuf), "%d", i);
				char abuf[20]; snprintf(abuf, sizeof(abuf), "%016" PRIX64, p.address);
				dl->AddText(ImVec2(ox + 6.f, ry + 2.f), dim2, ibuf);
				dl->AddText(ImVec2(ox + 30.f, ry + 2.f), addr2, abuf);

				std::string orig_hex = code_patcher::format_bytes(p.original_bytes);
				std::string patch_hex = code_patcher::format_bytes(p.patched_bytes);

				dl->AddText(ImVec2(ox + 180.f, ry + 2.f), text2, orig_hex.c_str());
				dl->AddText(ImVec2(ox + 320.f, ry + 2.f), text2, patch_hex.c_str());
				dl->AddText(ImVec2(ox + 460.f, ry + 2.f), text2, p.description.c_str());

				const char* st_label = p.active ? "ON" : "OFF";
				ImU32 sc = p.active
					? IM_COL32(100, 220, 120, static_cast<int>(200*a))
					: IM_COL32(180, 100, 100, static_cast<int>(200*a));
				ui_anim::render_badge(dl, st_label, ox + w - 70.f, ry + 2.f, sc,
					_ta(_t.bg_base));

				if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					g_ui.list_selected = i;

				ry += ROW_HEIGHT;
			}
			break;
		}
		case sub_tab_t::seh_chain:
			seh_view::render(ox, content_y, w, content_h,
				a, accent_r, accent_g, accent_b);
			break;
		case sub_tab_t::cfg:
			cfg_view::render(ox, content_y, w, content_h,
				a, accent_r, accent_g, accent_b);
			break;
		default:
			break;
	}

	ImGui::EndChild();
}

}
