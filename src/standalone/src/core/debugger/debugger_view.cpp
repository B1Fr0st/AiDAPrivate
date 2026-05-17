#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "debugger_view.hpp"
#include "debugger_engine.hpp"
#include "spawn_target_dialog.hpp"
#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../anti-tamper/webhook.hpp"
#include "ui_anim.hpp"
#include "memory_map_view.hpp"
#include "thread_view.hpp"
#include "module_view.hpp"
#include "seh_view.hpp"
#include "cfg_view.hpp"
#include "code_patcher.hpp"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "empty_state.hpp"
#include "no_target_overlay.hpp"
#include "responsive.hpp"
#include "skeleton.hpp"
#include "fonts.hpp"
#include "hex_view.hpp"
#include "work_queue.hpp"
#include "toast_notification.hpp"
#include "../session/analysis_session.hpp"
#include "../helpers/win32_dialog.hpp"
#include <fstream>

#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>

extern DisasmState g_disasm;

namespace debugger_view {

static constexpr float TAB_HEIGHT      = 32.f;
static constexpr float ROW_HEIGHT      = 26.f;
static constexpr float HEADER_H        = 28.f;
static constexpr float TOOLBAR_H       = 36.f;
static constexpr float TOOLBAR_BTN_W   = 38.f;
static constexpr float TOOLBAR_BTN_GAP = 4.f;
static constexpr int   TOOLBAR_BTN_COUNT = 8;

namespace {

struct toolbar_btn_t {
	const char* tooltip;
	int icon_id;
	bool enabled;
	bool primary;
};

inline ImU32 with_a(ImU32 c, float a) {
	return aida::ui::with_alpha(c, a);
}

inline void draw_icon(ImDrawList* dl, ImVec2 c, float r, int icon_id, ImU32 col, float thickness) {
	switch (icon_id) {
		case 0: {
			ImVec2 p0 = ImVec2(c.x - r * 0.55f, c.y - r * 0.7f);
			ImVec2 p1 = ImVec2(c.x - r * 0.55f, c.y + r * 0.7f);
			ImVec2 p2 = ImVec2(c.x + r * 0.75f, c.y);
			dl->AddTriangleFilled(p0, p1, p2, col);
			break;
		}
		case 1: {
			float bw = r * 0.32f;
			float bh = r * 0.85f;
			float gap = r * 0.20f;
			dl->AddRectFilled(ImVec2(c.x - bw - gap * 0.5f, c.y - bh),
			                  ImVec2(c.x - gap * 0.5f, c.y + bh), col, 1.5f);
			dl->AddRectFilled(ImVec2(c.x + gap * 0.5f, c.y - bh),
			                  ImVec2(c.x + gap * 0.5f + bw, c.y + bh), col, 1.5f);
			break;
		}
		case 2: {
			ImVec2 a = ImVec2(c.x - r * 0.85f, c.y - r * 0.55f);
			ImVec2 b = ImVec2(c.x + r * 0.30f, c.y - r * 0.55f);
			dl->AddLine(a, b, col, thickness);
			dl->PathLineTo(ImVec2(b.x - r * 0.30f, b.y - r * 0.30f));
			dl->PathLineTo(b);
			dl->PathLineTo(ImVec2(b.x - r * 0.30f, b.y + r * 0.30f));
			dl->PathStroke(col, 0, thickness);
			float cx = c.x + r * 0.55f;
			float cy = c.y + r * 0.30f;
			dl->AddCircleFilled(ImVec2(cx, cy), r * 0.34f, col, 16);
			dl->AddCircleFilled(ImVec2(cx, cy), r * 0.18f,
			                     IM_COL32(0, 0, 0, 200), 16);
			break;
		}
		case 3: {
			float ax0 = c.x - r * 0.85f;
			float ax1 = c.x + r * 0.30f;
			float ay1 = c.y - r * 0.55f;
			dl->AddLine(ImVec2(ax0, ay1), ImVec2(ax1, ay1), col, thickness);
			dl->PathLineTo(ImVec2(ax1 - r * 0.30f, ay1 - r * 0.30f));
			dl->PathLineTo(ImVec2(ax1, ay1));
			dl->PathLineTo(ImVec2(ax1 - r * 0.30f, ay1 + r * 0.30f));
			dl->PathStroke(col, 0, thickness);
			ImVec2 t0 = ImVec2(c.x + r * 0.40f, c.y + r * 0.10f);
			ImVec2 t1 = ImVec2(c.x + r * 0.40f, c.y + r * 0.85f);
			ImVec2 t2 = ImVec2(c.x - r * 0.20f, c.y + r * 0.475f);
			dl->AddTriangleFilled(t0, t1, t2, col);
			break;
		}
		case 4: {
			ImVec2 t0 = ImVec2(c.x - r * 0.55f, c.y + r * 0.30f);
			ImVec2 t1 = ImVec2(c.x + r * 0.55f, c.y + r * 0.30f);
			ImVec2 t2 = ImVec2(c.x, c.y - r * 0.40f);
			dl->AddTriangleFilled(t0, t1, t2, col);
			dl->AddRectFilled(ImVec2(c.x - r * 0.20f, c.y + r * 0.30f),
			                  ImVec2(c.x + r * 0.20f, c.y + r * 0.85f), col, 1.f);
			break;
		}
		case 5: {
			float s = r * 0.65f;
			dl->AddRectFilled(ImVec2(c.x - s, c.y - s),
			                  ImVec2(c.x + s, c.y + s), col, 2.f);
			break;
		}
		case 6: {
			float rad = r * 0.65f;
			float t = aida::ui::clock::seconds() * 1.4f;
			dl->PathArcTo(c, rad, 0.6f + t, 5.5f + t, 24);
			dl->PathStroke(col, 0, thickness);
			float ax = c.x + cosf(5.5f + t) * rad;
			float ay = c.y + sinf(5.5f + t) * rad;
			dl->AddTriangleFilled(
				ImVec2(ax - r * 0.20f, ay),
				ImVec2(ax + r * 0.10f, ay - r * 0.18f),
				ImVec2(ax + r * 0.10f, ay + r * 0.18f), col);
			break;
		}
		case 7: {
			float rad = r * 0.65f;
			dl->PathArcTo(c, rad, 0.5f, 5.4f, 26);
			dl->PathStroke(col, 0, thickness);
			float ax = c.x + cosf(0.5f) * rad;
			float ay = c.y + sinf(0.5f) * rad;
			dl->AddTriangleFilled(
				ImVec2(ax - r * 0.16f, ay - r * 0.20f),
				ImVec2(ax + r * 0.18f, ay),
				ImVec2(ax - r * 0.16f, ay + r * 0.20f), col);
			break;
		}
		case 8: {
			ImVec2 ll = ImVec2(c.x - r * 0.55f, c.y - r * 0.55f);
			ImVec2 lr = ImVec2(c.x + r * 0.55f, c.y + r * 0.55f);
			ImVec2 rl = ImVec2(c.x + r * 0.55f, c.y - r * 0.55f);
			ImVec2 rr = ImVec2(c.x - r * 0.55f, c.y + r * 0.55f);
			dl->AddLine(ll, lr, col, thickness);
			dl->AddLine(rl, rr, col, thickness);
			break;
		}
		default: break;
	}
}

inline ImU32 handle_type_color(const std::string& type, const aida::ui::theme_t& t) {
	if (type == "File")    return t.info;
	if (type == "Thread")  return t.warning;
	if (type == "Mutant")  return t.accent_u32;
	if (type == "Section") return t.error;
	if (type == "Key")     return t.success;
	if (type == "Event" || type == "Semaphore") return t.warning;
	return t.text_secondary;
}

inline void draw_glass_card(ImDrawList* dl, ImVec2 a, ImVec2 b, float radius,
                            float alpha, bool subtle_shadow = true) {
	const auto& t = aida::ui::resolved();
	if (subtle_shadow) {
		for (int i = 0; i < 4; ++i) {
			float s = static_cast<float>(i + 1) * 1.4f;
			float fa = 0.18f * alpha * (1.f - static_cast<float>(i) / 4.f);
			dl->AddRectFilled(
				ImVec2(a.x - s, a.y - s + 2.f),
				ImVec2(b.x + s, b.y + s + 2.f),
				IM_COL32(0, 0, 0, static_cast<int>(fa * 60.f)),
				radius + s);
		}
	}
	dl->AddRectFilled(a, b, with_a(t.panel_bg, alpha), radius);
	dl->AddRectFilled(a, b, with_a(t.glass_tint, alpha * 0.55f), radius);
	dl->AddRect(a, b, with_a(t.border_subtle, alpha), radius, 0, 1.f);
}

inline void draw_panel_header(ImDrawList* dl, float x, float y, float w,
                              const char* label, float alpha) {
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
	                  with_a(t.panel_header, alpha));
	dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
		with_a(t.accent_grad_top, alpha * 0.18f),
		with_a(t.accent_grad_top, alpha * 0.05f),
		with_a(t.accent_grad_bot, alpha * 0.05f),
		with_a(t.accent_grad_bot, alpha * 0.18f));
	dl->AddLine(ImVec2(x, y + HEADER_H - 0.5f),
	            ImVec2(x + w, y + HEADER_H - 0.5f),
	            with_a(t.border_subtle, alpha));
	ImFont* font = aida::ui::fonts::caption();
	if (!font) font = ImGui::GetFont();
	dl->AddText(font, font->FontSize, ImVec2(x + 10.f, y + (HEADER_H - font->FontSize) * 0.5f),
	            with_a(t.text_secondary, alpha), label);
}

inline void draw_table_header(ImDrawList* dl, float x, float y, float w,
                              const ui_anim::table_col_t* cols, int n,
                              float alpha) {
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
	                  with_a(t.panel_header, alpha));
	dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + w, y + HEADER_H),
		with_a(t.accent_grad_top, alpha * 0.10f),
		with_a(t.accent_grad_top, alpha * 0.04f),
		with_a(t.accent_grad_bot, alpha * 0.04f),
		with_a(t.accent_grad_bot, alpha * 0.10f));
	dl->AddLine(ImVec2(x, y + HEADER_H - 0.5f),
	            ImVec2(x + w, y + HEADER_H - 0.5f),
	            with_a(t.border_subtle, alpha));
	ImFont* font = aida::ui::fonts::caption();
	if (!font) font = ImGui::GetFont();
	float cx = x + 10.f;
	for (int i = 0; i < n; ++i) {
		ImVec2 sz = font->CalcTextSizeA(font->FontSize, FLT_MAX, 0.f, cols[i].label);
		dl->AddText(font, font->FontSize,
			ImVec2(cx, y + (HEADER_H - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), cols[i].label);
		cx += cols[i].width;
		if (i < n - 1)
			dl->AddLine(ImVec2(cx - 4.f, y + 6.f),
			            ImVec2(cx - 4.f, y + HEADER_H - 6.f),
			            with_a(t.border_subtle, alpha * 0.6f));
	}
}

inline bool draw_row_bg(ImDrawList* dl, float x, float y, float w, float h,
                        bool selected, bool hovered, int idx,
                        float entrance, float alpha) {
	const auto& t = aida::ui::resolved();
	float ra = alpha * entrance;
	if (ra < 0.01f) return hovered;
	if (selected) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.selection, ra), 4.f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h),
		                  with_a(t.accent_u32, ra * 0.95f));
		for (int g = 0; g < 3; ++g) {
			float gw = 6.f + static_cast<float>(g) * 4.f;
			float ga = (0.10f - static_cast<float>(g) * 0.030f) * ra;
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + gw, y + h),
			                  with_a(t.accent_glow, ga * 6.f));
		}
	} else if (hovered) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.hover_wash, ra), 4.f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 2.f, y + h),
		                  with_a(t.accent_dim, ra));
	} else if (idx & 1) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		                  with_a(t.hover_wash, ra * 0.25f));
	}
	return hovered;
}

inline void draw_run_toolbar(ImDrawList* dl, float ox, float oy, float w,
                             float alpha) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;

	debugger_engine::dbg_status_t status = debugger_engine::g_state.status.load();
	bool running = (status == debugger_engine::dbg_status_t::running);
	bool paused  = (status == debugger_engine::dbg_status_t::paused
	             || status == debugger_engine::dbg_status_t::stepping);
	bool idle    = (status == debugger_engine::dbg_status_t::idle
	             || status == debugger_engine::dbg_status_t::terminated);
	bool attached = driver_bridge::attached_pid() != 0;

	const char* run_tooltip = attached
		? "Run / Continue (F5)"
		: "Launch target binary... (F5)";

	toolbar_btn_t btns[TOOLBAR_BTN_COUNT] = {
		{ run_tooltip,              0, (attached && (idle || paused)) || !attached, true  },
		{ "Pause (F6)",             1, attached && running,         false },
		{ "Step Over (F10)",        2, attached && paused,          false },
		{ "Step Into (F11)",        3, attached && paused,          false },
		{ "Step Out (Shift+F11)",   4, attached && paused,          false },
		{ "Stop / Terminate (Shift+F5)", 5, attached,               false },
		{ "Restart (Ctrl+Shift+F5)", 6, attached,                   false },
		{ "Detach (Ctrl+F2)",       7, attached,                    false },
	};

	float total_w = static_cast<float>(TOOLBAR_BTN_COUNT) * TOOLBAR_BTN_W
	              + static_cast<float>(TOOLBAR_BTN_COUNT - 1) * TOOLBAR_BTN_GAP
	              + 16.f;
	float pad_y = (TOOLBAR_H - 28.f) * 0.5f;
	float bx = ox + 12.f;
	float by = oy + pad_y;

	ImVec2 a = ImVec2(bx - 6.f, by - 4.f);
	ImVec2 b = ImVec2(bx + total_w - 8.f, by + 28.f + 4.f);
	draw_glass_card(dl, a, b, 10.f, alpha);

	ImFont* font = aida::ui::fonts::body();
	if (!font) font = ImGui::GetFont();

	float dt = aida::ui::clock::dt();
	float pulse = running ? aida::ui::clock::pulse(1.5f, 0.f, 1.f) : 0.f;

	for (int i = 0; i < TOOLBAR_BTN_COUNT; ++i) {
		const auto& btn = btns[i];
		float btn_x = bx + static_cast<float>(i) * (TOOLBAR_BTN_W + TOOLBAR_BTN_GAP);
		float btn_y = by;
		ImVec2 ba(btn_x, btn_y);
		ImVec2 bb(btn_x + TOOLBAR_BTN_W, btn_y + 28.f);

		ImGui::SetCursorScreenPos(ba);
		ImGui::PushID(i);
		ImGui::InvisibleButton("##tbn", ImVec2(TOOLBAR_BTN_W, 28.f));
		bool hovered = ImGui::IsItemHovered() && btn.enabled;
		bool clicked = ImGui::IsItemClicked() && btn.enabled;
		bool held    = ImGui::IsItemActive()  && btn.enabled;
		ImGui::PopID();

		float h_v = ui.toolbar.hover[i].tick(hovered, dt, aida::motion::spring::balanced);
		float p_v = ui.toolbar.press[i].tick(held, dt);

		float scale = 1.f - (1.f - 0.95f) * p_v;
		float lift  = h_v * 1.0f - p_v * 1.2f;
		float bw_h = TOOLBAR_BTN_W * 0.5f;
		float bh_h = 14.f;
		ImVec2 ca(btn_x + bw_h - bw_h * scale, btn_y + bh_h - bh_h * scale - lift);
		ImVec2 cb(btn_x + bw_h + bw_h * scale, btn_y + bh_h + bh_h * scale - lift);

		float btn_alpha = btn.enabled ? alpha : alpha * 0.42f;

		ImU32 border;
		ImU32 icon_col;
		if (btn.primary) {
			float pulse_mod = running ? (pulse * 0.4f) : 0.f;
			ImU32 grad_t = aida::ui::mix(t.accent_grad_top, t.accent_hover, h_v * 0.5f + pulse_mod);
			ImU32 grad_b = aida::ui::mix(t.accent_grad_bot, t.accent_u32,   h_v * 0.5f + pulse_mod);
			dl->AddRectFilledMultiColor(ca, cb,
				with_a(grad_t, btn_alpha),
				with_a(grad_t, btn_alpha),
				with_a(grad_b, btn_alpha),
				with_a(grad_b, btn_alpha));
			border = with_a(t.accent_hover, btn_alpha);
			icon_col = with_a(IM_COL32(255, 255, 255, 245), btn_alpha);
			if (running) {
				float pa = pulse * 0.55f * btn_alpha;
				for (int g = 0; g < 4; ++g) {
					float spread = 1.5f + static_cast<float>(g) * 1.4f;
					dl->AddRect(ImVec2(ca.x - spread, ca.y - spread),
					            ImVec2(cb.x + spread, cb.y + spread),
					            with_a(t.accent_glow, pa * (1.f - static_cast<float>(g) / 4.f)),
					            8.f + spread, 0, 1.f);
				}
			}
		} else {
			ImU32 fill = aida::ui::mix(t.panel_header, t.accent_dim, h_v * 0.45f);
			border = aida::ui::mix(t.border_subtle, t.accent_dim, h_v * 0.65f);
			icon_col = aida::ui::mix(t.text_secondary, t.text_primary, h_v);
			dl->AddRectFilled(ca, cb, with_a(fill, btn_alpha), 8.f);
		}

		dl->AddRect(ca, cb, with_a(border, btn_alpha * (0.6f + h_v * 0.4f)),
		            8.f, 0, 1.f);

		ImVec2 ic = ImVec2((ca.x + cb.x) * 0.5f, (ca.y + cb.y) * 0.5f);
		float ir = 9.f * scale;
		float thickness = 1.6f;
		draw_icon(dl, ic, ir, btn.icon_id, icon_col, thickness);

		if (hovered) {
			char tip[96];
			std::snprintf(tip, sizeof(tip), "%s", btn.tooltip);
			ImGui::SetTooltip("%s", tip);
		}

		if (clicked) {
			uint32_t cur_pid = driver_bridge::attached_pid();
			switch (i) {
				case 0: {
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_run_clicked attached_pid=%u status=%d",
						static_cast<unsigned>(cur_pid),
						static_cast<int>(status));
					if (cur_pid != 0) {
						bool ok = debugger_engine::run_target();
						diag::log_tagged_fmt("debugger",
							"toolbar_run_target ok=%d err='%s'",
							ok ? 1 : 0,
							debugger_engine::last_error().c_str());
						if (!ok) {
							toast_notification::push("Run failed: " +
								debugger_engine::last_error(),
								toast_notification::toast_type_t::error);
						}
					} else {
						if (!spawn_target_dialog::is_open()) {
							spawn_target_dialog::request_open();
							diag::log_tagged_fmt("debugger",
								"toolbar_run_open_spawn_dialog");
						}
					}
					break;
				}
				case 1: {
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_pause_clicked attached_pid=%u",
						static_cast<unsigned>(cur_pid));
					bool ok = debugger_engine::pause_target();
					diag::log_tagged_fmt("debugger",
						"toolbar_pause_target ok=%d err='%s'",
						ok ? 1 : 0,
						debugger_engine::last_error().c_str());
					if (!ok) {
						toast_notification::push("Pause failed: " +
							debugger_engine::last_error(),
							toast_notification::toast_type_t::error);
					}
					break;
				}
				case 2: {
					uint64_t pre_rip = debugger_engine::cached_registers().rip;
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_step_over_clicked attached_pid=%u rip=0x%llx",
						static_cast<unsigned>(cur_pid),
						static_cast<unsigned long long>(pre_rip));
					bool ok = debugger_engine::step_over();
					uint64_t post_rip = debugger_engine::cached_registers().rip;
					diag::log_tagged_fmt("debugger",
						"toolbar_step_over_done ok=%d pre_rip=0x%llx post_rip=0x%llx err='%s'",
						ok ? 1 : 0,
						static_cast<unsigned long long>(pre_rip),
						static_cast<unsigned long long>(post_rip),
						debugger_engine::last_error().c_str());
					if (!ok) {
						toast_notification::push("Step over failed: " +
							debugger_engine::last_error(),
							toast_notification::toast_type_t::error);
					}
					break;
				}
				case 3: {
					uint64_t pre_rip = debugger_engine::cached_registers().rip;
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_step_into_clicked attached_pid=%u rip=0x%llx",
						static_cast<unsigned>(cur_pid),
						static_cast<unsigned long long>(pre_rip));
					bool ok = debugger_engine::step_into();
					uint64_t post_rip = debugger_engine::cached_registers().rip;
					diag::log_tagged_fmt("debugger",
						"toolbar_step_into_done ok=%d pre_rip=0x%llx post_rip=0x%llx err='%s'",
						ok ? 1 : 0,
						static_cast<unsigned long long>(pre_rip),
						static_cast<unsigned long long>(post_rip),
						debugger_engine::last_error().c_str());
					if (!ok) {
						toast_notification::push("Step into failed: " +
							debugger_engine::last_error(),
							toast_notification::toast_type_t::error);
					}
					break;
				}
				case 4: {
					uint64_t pre_rsp = debugger_engine::cached_registers().rsp;
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_step_out_clicked attached_pid=%u rsp=0x%llx",
						static_cast<unsigned>(cur_pid),
						static_cast<unsigned long long>(pre_rsp));
					bool ok = debugger_engine::step_out();
					diag::log_tagged_fmt("debugger",
						"toolbar_step_out_done ok=%d err='%s'",
						ok ? 1 : 0,
						debugger_engine::last_error().c_str());
					if (!ok) {
						toast_notification::push("Step out failed: " +
							debugger_engine::last_error(),
							toast_notification::toast_type_t::error);
					}
					break;
				}
				case 5: {
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_stop_clicked attached_pid=%u",
						static_cast<unsigned>(cur_pid));
					if (cur_pid != 0) {
						HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, cur_pid);
						bool terminated = false;
						if (p != nullptr) {
							terminated = TerminateProcess(p, 0xDEADu) != FALSE;
							CloseHandle(p);
						}
						diag::log_tagged_critical_fmt("debugger",
							"toolbar_stop_terminate pid=%u open_ok=%d term_ok=%d gle=%lu",
							static_cast<unsigned>(cur_pid),
							p != nullptr ? 1 : 0,
							terminated ? 1 : 0,
							static_cast<unsigned long>(GetLastError()));
						driver_bridge::detach();
						debugger_engine::g_state.status.store(
							debugger_engine::dbg_status_t::terminated);
						toast_notification::push(
							terminated ? "Target terminated."
							           : "Detached (terminate failed).",
							terminated ? toast_notification::toast_type_t::info
							           : toast_notification::toast_type_t::warning);
					}
					break;
				}
				case 6: {
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_restart_clicked attached_pid=%u",
						static_cast<unsigned>(cur_pid));
					if (cur_pid != 0) {
						HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, cur_pid);
						if (p != nullptr) {
							TerminateProcess(p, 0xDEADu);
							CloseHandle(p);
						}
						driver_bridge::detach();
						debugger_engine::g_state.status.store(
							debugger_engine::dbg_status_t::terminated);
						diag::log_tagged_fmt("debugger",
							"toolbar_restart_detached pid=%u",
							static_cast<unsigned>(cur_pid));
					}
					if (!spawn_target_dialog::is_open()) {
						spawn_target_dialog::request_open();
						diag::log_tagged_fmt("debugger",
							"toolbar_restart_reopen_spawn_dialog");
					}
					break;
				}
				case 7: {
					diag::log_tagged_critical_fmt("debugger",
						"toolbar_detach_clicked attached_pid=%u",
						static_cast<unsigned>(cur_pid));
					if (cur_pid != 0) {
						driver_bridge::detach();
						debugger_engine::g_state.status.store(
							debugger_engine::dbg_status_t::idle);
						diag::log_tagged_critical_fmt("debugger",
							"toolbar_detach_done pid=%u",
							static_cast<unsigned>(cur_pid));
						toast_notification::push("Detached from target.",
							toast_notification::toast_type_t::info);
					}
					break;
				}
			}
		}
	}

	{
		const char* status_label = "IDLE";
		aida::ui::pill_kind_t kind = aida::ui::pill_kind_t::neutral;
		if (running) {
			status_label = "RUNNING";
			kind = aida::ui::pill_kind_t::success;
		} else if (paused) {
			status_label = "PAUSED";
			kind = aida::ui::pill_kind_t::warning;
		} else if (status == debugger_engine::dbg_status_t::terminated) {
			status_label = "STOPPED";
			kind = aida::ui::pill_kind_t::error;
		}
		ImFont* sf = aida::ui::fonts::caption();
		if (!sf) sf = ImGui::GetFont();
		ImVec2 sl_sz = sf->CalcTextSizeA(sf->FontSize, FLT_MAX, 0.f, status_label);
		float sx = bx + total_w + 6.f;
		float sy = by + (28.f - 16.f) * 0.5f;
		ImU32 col;
		switch (kind) {
			case aida::ui::pill_kind_t::success: col = t.success; break;
			case aida::ui::pill_kind_t::warning: col = t.warning; break;
			case aida::ui::pill_kind_t::error:   col = t.error;   break;
			default:                             col = t.text_secondary; break;
		}
		dl->AddRectFilled(ImVec2(sx, sy), ImVec2(sx + sl_sz.x + 22.f, sy + 16.f),
		                  with_a(col, alpha * 0.18f), 8.f);
		dl->AddRect(ImVec2(sx, sy), ImVec2(sx + sl_sz.x + 22.f, sy + 16.f),
		            with_a(col, alpha * 0.55f), 8.f, 0, 1.f);
		float dpulse = aida::ui::clock::pulse(1.6f, 0.55f, 1.f);
		dl->AddCircleFilled(ImVec2(sx + 8.f, sy + 8.f), 3.f,
		                    with_a(col, alpha * dpulse), 14);
		dl->AddText(sf, sf->FontSize, ImVec2(sx + 14.f, sy + (16.f - sf->FontSize) * 0.5f),
		            with_a(col, alpha), status_label);
	}
}

inline bool jump_to_disasm(uint64_t addr) {
	if (addr == 0) return false;
	globals::ui::active_center_view = center_view_t::disassembly;
	disasm_view::goto_address(addr, g_disasm);
	return true;
}

inline bool jump_to_hex(uint64_t addr, size_t bytes) {
	if (addr == 0) return false;
	hex_view::read_from_process(addr, bytes);
	globals::ui::active_center_view = center_view_t::hex_view;
	return true;
}

inline void copy_to_clipboard(const char* s) {
	if (!s || !*s) return;
	ImGui::SetClipboardText(s);
}

inline void copy_addr_to_clipboard(uint64_t addr) {
	char buf[20];
	std::snprintf(buf, sizeof(buf), "0x%016" PRIX64, addr);
	copy_to_clipboard(buf);
}

inline uint64_t parse_hex_address(const char* s) {
	if (!s || !*s) return 0;
	while (*s == ' ' || *s == '\t') ++s;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
	uint64_t v = 0;
	for (; *s; ++s) {
		char c = *s;
		uint8_t d;
		if (c >= '0' && c <= '9') d = static_cast<uint8_t>(c - '0');
		else if (c >= 'a' && c <= 'f') d = static_cast<uint8_t>(10 + (c - 'a'));
		else if (c >= 'A' && c <= 'F') d = static_cast<uint8_t>(10 + (c - 'A'));
		else break;
		v = (v << 4) | d;
	}
	return v;
}

inline uint64_t resolve_register_token(const std::string& tok,
                                       const debugger_engine::register_set_t& r) {
	std::string n;
	n.reserve(tok.size());
	for (char c : tok) n.push_back(static_cast<char>(::toupper(static_cast<unsigned char>(c))));
	if (n == "RAX") return r.rax; if (n == "RBX") return r.rbx;
	if (n == "RCX") return r.rcx; if (n == "RDX") return r.rdx;
	if (n == "RSI") return r.rsi; if (n == "RDI") return r.rdi;
	if (n == "RBP") return r.rbp; if (n == "RSP") return r.rsp;
	if (n == "R8")  return r.r8;  if (n == "R9")  return r.r9;
	if (n == "R10") return r.r10; if (n == "R11") return r.r11;
	if (n == "R12") return r.r12; if (n == "R13") return r.r13;
	if (n == "R14") return r.r14; if (n == "R15") return r.r15;
	if (n == "RIP") return r.rip; if (n == "RFLAGS") return r.rflags;
	if (n == "CS")  return r.cs;  if (n == "SS")  return r.ss;
	if (n == "DS")  return r.ds;  if (n == "ES")  return r.es;
	if (n == "FS")  return r.fs;  if (n == "GS")  return r.gs;
	return 0;
}

inline uint64_t evaluate_watch_expression(const std::string& expr,
                                          const debugger_engine::register_set_t& r,
                                          bool& deref_out, bool& valid_out) {
	deref_out = false;
	valid_out = false;
	std::string s = expr;
	while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
	while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
	if (s.empty()) return 0;
	bool deref = false;
	if (s.front() == '[' && s.back() == ']') {
		deref = true;
		s = s.substr(1, s.size() - 2);
		while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
		while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
	}
	uint64_t total = 0;
	bool subtract = false;
	bool any_token = false;
	std::string cur;
	auto consume = [&]() {
		while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
		while (!cur.empty() && (cur.back()  == ' ' || cur.back()  == '\t')) cur.pop_back();
		if (cur.empty()) return;
		uint64_t v = 0;
		bool numeric = (cur[0] == '0' && (cur.size() > 1 && (cur[1] == 'x' || cur[1] == 'X')));
		if (!numeric) {
			bool all_hex_digits = true;
			for (char c : cur) {
				if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
					all_hex_digits = false; break;
				}
			}
			if (all_hex_digits && cur.size() >= 4) numeric = true;
		}
		if (numeric) v = parse_hex_address(cur.c_str());
		else v = resolve_register_token(cur, r);
		if (subtract) total -= v;
		else          total += v;
		any_token = true;
		cur.clear();
	};
	for (size_t i = 0; i < s.size(); ++i) {
		char c = s[i];
		if (c == '+') { consume(); subtract = false; continue; }
		if (c == '-') { consume(); subtract = true;  continue; }
		cur.push_back(c);
	}
	consume();
	if (!any_token) return 0;
	deref_out = deref;
	valid_out = true;
	return total;
}

inline std::string format_value_hex(uint64_t v) {
	char buf[20];
	std::snprintf(buf, sizeof(buf), "0x%016" PRIX64, v);
	return buf;
}

}

static void render_tab_bar(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();

	struct visible_tab_entry_t { const char* name; const char* short_name; sub_tab_t tab; };
	static const visible_tab_entry_t visible_tabs[] = {
		{ "CPU",         "CPU", sub_tab_t::cpu },
		{ "Breakpoints", "BP",  sub_tab_t::breakpoints },
		{ "Call Stack",  "CS",  sub_tab_t::call_stack },
		{ "Threads",     "Thr", sub_tab_t::threads },
		{ "Watches",     "Wch", sub_tab_t::watches },
		{ "Handles",     "Hnd", sub_tab_t::handles },
		{ "Trace",       "Trc", sub_tab_t::trace_log },
		{ "Strings",     "Str", sub_tab_t::strings },
		{ "Bookmarks",   "Bm",  sub_tab_t::bookmarks },
		{ "Modules",     "Mod", sub_tab_t::modules },
		{ "Patches",     "Pat", sub_tab_t::patches },
		{ "SEH",         "SEH", sub_tab_t::seh_chain }
	};
	static const int visible_tab_count = static_cast<int>(sizeof(visible_tabs) / sizeof(visible_tabs[0]));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT),
	                  with_a(t.panel_bg, a));
	dl->AddLine(ImVec2(ox, oy + TAB_HEIGHT - 1.f),
	            ImVec2(ox + w, oy + TAB_HEIGHT - 1.f),
	            with_a(t.border_subtle, a * 0.7f));
	{
		static bool s_dbg_strip_logged = false;
		if (!s_dbg_strip_logged) {
			s_dbg_strip_logged = true;
			anti_tamper::webhook::write_log("dbg_strip", "[dbg_strip] applied solid_line");
		}
	}

	if (ui.active_tab == sub_tab_t::memory_map || ui.active_tab == sub_tab_t::cfg) {
		ui.active_tab = sub_tab_t::cpu;
	}

	int count = visible_tab_count;
	float tab_widths[16];
	float tab_positions[16];
	float total_tabs_w_full = 6.f;
	float total_tabs_w_short = 6.f;
	ImFont* tf = aida::ui::fonts::body_em();
	if (!tf) tf = ImGui::GetFont();
	for (int i = 0; i < count; ++i) {
		ImVec2 sz_full = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, visible_tabs[i].name);
		ImVec2 sz_short = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, visible_tabs[i].short_name);
		total_tabs_w_full += (sz_full.x + 22.f) + 2.f;
		total_tabs_w_short += (sz_short.x + 18.f) + 2.f;
	}
	total_tabs_w_full += 6.f;
	total_tabs_w_short += 6.f;

	const float reserved_check = 36.f;
	bool use_short_labels = (w - reserved_check) < total_tabs_w_full && (w - reserved_check) >= total_tabs_w_short;

	static bool s_logged_short = false;
	if (use_short_labels && !s_logged_short) {
		s_logged_short = true;
		::diag::log_tagged_fmt("responsive",
			"debugger_view tabs short_labels w=%.0f full_need=%.0f short_need=%.0f",
			w, total_tabs_w_full, total_tabs_w_short);
	} else if (!use_short_labels && s_logged_short) {
		s_logged_short = false;
	}

	float total_tabs_w = 6.f;
	for (int i = 0; i < count; ++i) {
		const char* lbl = use_short_labels ? visible_tabs[i].short_name : visible_tabs[i].name;
		ImVec2 sz = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, lbl);
		tab_widths[i] = sz.x + (use_short_labels ? 18.f : 22.f);
		tab_positions[i] = total_tabs_w;
		total_tabs_w += tab_widths[i] + 2.f;
	}
	total_tabs_w += 6.f;

	float reserved = 36.f;
	float visible_w = w - reserved;
	bool tabs_overflow = total_tabs_w > visible_w;

	if (tabs_overflow) {
		bool bar_hov = ImGui::IsMouseHoveringRect(ImVec2(ox, oy),
			ImVec2(ox + visible_w, oy + TAB_HEIGHT), false);
		if (bar_hov) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f)
				ui.tab_target_scroll_x -= wheel * 60.f;
		}

		float max_scroll = std::max(0.f, total_tabs_w - visible_w);
		ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
		ui.tab_scroll_x = ui_anim::smooth_lerp(ui.tab_scroll_x, ui.tab_target_scroll_x, 16.f, dt);
		if (std::abs(ui.tab_target_scroll_x - ui.tab_scroll_x) < 0.3f)
			ui.tab_scroll_x = ui.tab_target_scroll_x;

		int active_vis = 0;
		for (int vi = 0; vi < count; ++vi) {
			if (visible_tabs[vi].tab == ui.active_tab) { active_vis = vi; break; }
		}
		if (ui.tab_last_ensured != active_vis) {
			float active_left = tab_positions[active_vis] - ui.tab_scroll_x + ox;
			float active_right = active_left + tab_widths[active_vis];
			if (active_left < ox + 10.f)
				ui.tab_target_scroll_x = tab_positions[active_vis] - 10.f;
			else if (active_right > ox + visible_w - 10.f)
				ui.tab_target_scroll_x = tab_positions[active_vis] + tab_widths[active_vis] - visible_w + 10.f;
			ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
			ui.tab_last_ensured = active_vis;
		}
	} else {
		ui.tab_scroll_x = 0.f;
		ui.tab_target_scroll_x = 0.f;
		ui.tab_last_ensured = -1;
	}

	ImGui::PushClipRect(ImVec2(ox, oy), ImVec2(ox + visible_w, oy + TAB_HEIGHT), true);

	int active_idx = 0;
	for (int vi = 0; vi < count; ++vi) {
		if (visible_tabs[vi].tab == ui.active_tab) { active_idx = vi; break; }
	}
	float target_ul_x = ox + tab_positions[active_idx] - ui.tab_scroll_x + 6.f;
	float target_ul_w = tab_widths[active_idx] - 12.f;

	if (ui.underline_w < 0.01f) {
		ui.underline_x = target_ul_x;
		ui.underline_w = target_ul_w;
	}
	ui.underline_x = ui_anim::spring_interp(ui.underline_x, target_ul_x, ui.underline_vel, 280.f, 22.f, dt);
	ui.underline_w = ui_anim::smooth_lerp(ui.underline_w, target_ul_w, 16.f, dt);

	for (int i = 0; i < count; ++i) {
		auto tab = visible_tabs[i].tab;
		const char* tab_name_str = use_short_labels ? visible_tabs[i].short_name : visible_tabs[i].name;
		const char* tab_full_name = visible_tabs[i].name;
		bool active = (ui.active_tab == tab);
		float tx = ox + tab_positions[i] - ui.tab_scroll_x;
		float tw = tab_widths[i];
		float ty = oy + 2.f;
		float th = TAB_HEIGHT - 4.f;

		if (tx + tw < ox || tx > ox + visible_w) continue;

		bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx, ty), ImVec2(tx + tw, ty + th), false);

		int anim_slot = static_cast<int>(tab);
		float& tab_a = ui.tab_anim[anim_slot];
		float tab_target = active ? 1.f : (hov ? 0.55f : 0.f);
		tab_a = ui_anim::smooth_lerp(tab_a, tab_target, 14.f, dt);

		if (tab_a > 0.01f) {
			float ra = tab_a * a;
			ImU32 wash = aida::ui::mix(t.hover_wash, t.accent_glow, tab_a * 0.6f);
			dl->AddRectFilled(ImVec2(tx + 3.f, ty + 1.f),
			                  ImVec2(tx + tw - 3.f, ty + th - 1.f),
			                  with_a(wash, ra), 6.f);
		}

		ImVec2 ts = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, tab_name_str);
		ImU32 col = active
			? with_a(t.accent_hover, a)
			: aida::ui::mix(t.text_secondary, t.text_primary, hov ? 0.6f : 0.f);
		col = with_a(col, a);

		dl->AddText(tf, tf->FontSize,
			ImVec2(tx + (tw - ts.x) * 0.5f, ty + (th - ts.y) * 0.5f),
			col, tab_name_str);

		if (use_short_labels && hov) {
			const auto& thz = aida::ui::resolved();
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
			ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(thz.bg_overlay));
			if (ImGui::BeginTooltip()) {
				ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(thz.text_primary));
				ImGui::TextUnformatted(tab_full_name);
				ImGui::PopStyleColor();
				ImGui::EndTooltip();
			}
			ImGui::PopStyleColor();
			ImGui::PopStyleVar();
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (ui.active_tab != tab) {
				int prev_i = static_cast<int>(ui.active_tab);
				int next_i = static_cast<int>(tab);
				ui.tab_animator.direction = (next_i > prev_i) ? 1.f : -1.f;
				ui.tab_animator.slide.start(aida::motion::dur::md,
					aida::motion::ease::out_cubic);
				ui.prev_tab = ui.active_tab;
				ui.content_fade = 0.f;
			}
			ui.active_tab = tab;
		}
	}

	ui_anim::render_tab_underline_glow(dl, ui.underline_x, ui.underline_w,
		oy + TAB_HEIGHT - 3.f, a);

	ImGui::PopClipRect();

	if (tabs_overflow) {
		float max_scroll = total_tabs_w - visible_w;
		if (ui.tab_scroll_x > 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + static_cast<float>(f), oy),
					ImVec2(ox + static_cast<float>(f) + 1.f, oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
			}
			float ccx_l = ox + 10.f;
			float ccy_l = oy + TAB_HEIGHT * 0.5f;
			ImU32 chev_l = with_a(t.accent_u32, a * 0.95f);
			dl->AddTriangleFilled(ImVec2(ccx_l + 4.f, ccy_l - 6.f), ImVec2(ccx_l + 4.f, ccy_l + 6.f),
				ImVec2(ccx_l - 4.f, ccy_l), chev_l);
			if (ImGui::IsMouseHoveringRect(ImVec2(ccx_l - 10.f, oy), ImVec2(ccx_l + 12.f, oy + TAB_HEIGHT)) &&
				ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ui.tab_target_scroll_x -= 120.f;
				if (ui.tab_target_scroll_x < 0.f) ui.tab_target_scroll_x = 0.f;
			}
		}
		if (ui.tab_scroll_x < max_scroll - 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + visible_w - static_cast<float>(f) - 1.f, oy),
					ImVec2(ox + visible_w - static_cast<float>(f), oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
			}
			float ccx = ox + visible_w - 10.f;
			float ccy = oy + TAB_HEIGHT * 0.5f;
			ImU32 chev = with_a(t.accent_u32, a * 0.95f);
			dl->AddTriangleFilled(ImVec2(ccx - 4.f, ccy - 6.f), ImVec2(ccx - 4.f, ccy + 6.f),
				ImVec2(ccx + 4.f, ccy), chev);
			float pulse = 0.5f + 0.5f * std::sin(static_cast<float>(ImGui::GetTime()) * 3.f);
			dl->AddCircle(ImVec2(ccx, ccy), 11.f,
				with_a(t.accent_u32, a * 0.35f * pulse), 16, 1.2f);
			if (ImGui::IsMouseHoveringRect(ImVec2(ccx - 12.f, oy), ImVec2(ccx + 10.f, oy + TAB_HEIGHT)) &&
				ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				ui.tab_target_scroll_x += 120.f;
				if (ui.tab_target_scroll_x > max_scroll) ui.tab_target_scroll_x = max_scroll;
			}
		}
	}

	for (int si = 0; si < 3; ++si) {
		float sa = (1.f - static_cast<float>(si) / 3.f) * 0.30f * a;
		dl->AddRectFilled(
			ImVec2(ox, oy + TAB_HEIGHT + static_cast<float>(si)),
			ImVec2(ox + w, oy + TAB_HEIGHT + static_cast<float>(si) + 1.f),
			IM_COL32(0, 0, 0, static_cast<int>(sa * 255.f)));
	}

	{
		static bool s_stealth_pill_removed_logged = false;
		if (!s_stealth_pill_removed_logged) {
			s_stealth_pill_removed_logged = true;
			anti_tamper::webhook::write_log("stealth_remove", "[stealth_remove] pill_removed=1");
		}
	}
}


namespace cpu_view_detail {

struct reg_row_t {
	const char* name;
	uint64_t    value;
	uint8_t     group;
	bool        editable;
};

inline ImU32 mnemonic_color(const AsmInstr& ins, const aida::ui::theme_t& t) {
	if (ins.is_call)   return t.syn_function;
	if (ins.is_branch) return t.warning;
	if (ins.is_ret)    return t.error;
	if (ins.is_priv)   return t.accent_u32;
	if (ins.is_nop)    return t.text_dim;
	return t.syn_keyword;
}

inline std::string lowercase_reg_name(const char* name) {
	std::string out;
	for (const char* p = name; *p; ++p)
		out.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(*p))));
	return out;
}

inline void open_edit_modal(int row_idx, uint64_t value) {
	auto& ui = g_ui;
	ui.cpu_edit_reg_idx = row_idx;
	std::snprintf(ui.cpu_edit_value_buf, sizeof(ui.cpu_edit_value_buf),
		"%016" PRIX64, value);
	ui.cpu_edit_popup_open = true;
}

inline bool is_likely_pointer(uint64_t v) {
	return v >= 0x00010000ULL && v < 0x00007FFFFFFFFFFFULL;
}

inline ImU32 register_value_color(uint64_t v, bool is_segment, bool is_debug,
                                  const aida::ui::theme_t& t) {
	if (v == 0)             return t.text_dim;
	if (is_debug)           return t.warning;
	if (is_segment)         return t.info;
	if (is_likely_pointer(v)) return t.text_address;
	return t.syn_number;
}

}

static void draw_cpu_reg_row(ImDrawList* dl, float x, float y, float w, float row_h,
                             int row_idx, const cpu_view_detail::reg_row_t& r,
                             float flash, bool selected, bool hovered, float alpha) {
	const auto& t = aida::ui::resolved();
	draw_row_bg(dl, x, y, w, row_h, selected, hovered, row_idx, 1.f, alpha);

	if (flash > 0.001f) {
		ImU32 flash_col = with_a(t.warning, alpha * flash * 0.55f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + row_h), flash_col, 4.f);
		ImU32 stripe = with_a(t.warning, alpha * flash * 0.85f);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + row_h), stripe);
	}

	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImU32 name_col;
	switch (r.group) {
		case 1:  name_col = t.info;        break;
		case 2:  name_col = t.warning;     break;
		default: name_col = t.text_primary; break;
	}
	dl->AddText(body_font, body_font->FontSize,
		ImVec2(x + 10.f, y + (row_h - body_font->FontSize) * 0.5f),
		with_a(name_col, alpha), r.name);

	char vbuf[20];
	if (r.group == 1)
		std::snprintf(vbuf, sizeof(vbuf), "%04X", static_cast<unsigned>(r.value & 0xFFFFu));
	else
		std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, r.value);

	ImU32 vcol = cpu_view_detail::register_value_color(r.value,
		r.group == 1, r.group == 2, t);
	dl->AddText(code_font, code_font->FontSize,
		ImVec2(x + 64.f, y + (row_h - code_font->FontSize) * 0.5f),
		with_a(vcol, alpha), vbuf);
}

static void render_cpu_disasm_slice(ImDrawList* dl, float x, float y, float w, float h,
                                    uint64_t rip, float alpha) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	draw_glass_card(dl, ImVec2(x, y), ImVec2(x + w, y + h), 10.f, alpha);
	draw_panel_header(dl, x, y, w, "LIVE DISASM @ RIP", alpha);

	if (rip == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const char* msg = "RIP is zero (target not paused at a valid instruction).";
		ImVec2 sz = fnt->CalcTextSizeA(fnt->FontSize, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	debugger_engine::request_disasm_refresh(rip, 220);
	uint64_t base = 0;
	auto buf = debugger_engine::cached_disasm_window(base);
	if (buf.empty() || base == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const char* msg = "Fetching instruction stream...";
		ImVec2 sz = fnt->CalcTextSizeA(fnt->FontSize, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	float content_y = y + HEADER_H + 2.f;
	float content_h = h - HEADER_H - 4.f;
	if (content_h < 24.f) return;

	int max_rows = 256;
	struct decoded_row_t {
		uint64_t addr;
		int      len;
		AsmInstr ins;
	};
	std::vector<decoded_row_t> rows;
	rows.reserve(64);

	size_t offset = 0;
	if (rip > base && rip < base + buf.size()) {
		offset = static_cast<size_t>(rip - base);
		if (offset > 0x40) offset = static_cast<size_t>(rip - base) - 0x40;
		else offset = 0;
	}
	uint64_t cursor_va = base + offset;
	size_t cursor = offset;
	while (cursor < buf.size() && static_cast<int>(rows.size()) < max_rows) {
		int remaining = static_cast<int>(buf.size() - cursor);
		if (remaining <= 0) break;
		AsmInstr ins = zydis_decode_one(buf.data() + cursor, remaining, cursor_va);
		decoded_row_t row;
		row.addr = cursor_va;
		row.len = ins.len > 0 ? ins.len : 1;
		row.ins = ins;
		rows.push_back(row);
		cursor += static_cast<size_t>(row.len);
		cursor_va += static_cast<uint64_t>(row.len);
	}

	int rip_idx = -1;
	for (size_t i = 0; i < rows.size(); ++i) {
		if (rows[i].addr == rip) { rip_idx = static_cast<int>(i); break; }
	}

	float row_h = 20.f;
	float child_w = w - 4.f;

	ImGui::SetCursorScreenPos(ImVec2(x + 2.f, content_y));
	ImGui::PushID("##cpu_disasm_slice");
	ImGui::BeginChild("##cpu_disasm_child", ImVec2(child_w, content_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	if (rip_idx >= 0 && ui.cpu_disasm_anchor_rip != rip) {
		float target = static_cast<float>(rip_idx) * row_h - content_h * 0.35f;
		if (target < 0.f) target = 0.f;
		ImGui::SetScrollY(target);
		ui.cpu_disasm_anchor_rip = rip;
	}

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(static_cast<int>(rows.size()), row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			const auto& dr = rows[static_cast<size_t>(i)];
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();

			ImGui::SetCursorScreenPos(ImVec2(x + 4.f, ry));
			ImGui::PushID(i + 0xD0000);
			ImGui::InvisibleButton("##cpu_disasm_row", ImVec2(child_w - 8.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			bool is_rip = (dr.addr == rip);
			bool is_sel = (ui.cpu_disasm_selected == i);

			if (is_rip) {
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + child_w - 2.f, ry + row_h),
					with_a(t.accent_glow, alpha * 0.30f), 3.f);
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + 4.f, ry + row_h),
					with_a(t.accent_u32, alpha));
				float pulse = aida::ui::clock::pulse(2.4f, 0.55f, 1.f);
				dl->AddTriangleFilled(
					ImVec2(x + 8.f, ry + row_h * 0.5f - 4.f),
					ImVec2(x + 8.f, ry + row_h * 0.5f + 4.f),
					ImVec2(x + 14.f, ry + row_h * 0.5f),
					with_a(t.accent_u32, alpha * pulse));
			} else if (is_sel) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, true, false, i, 1.f, alpha);
			} else if (hov) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, false, true, i, 1.f, alpha);
			}

			char addr_buf[20];
			std::snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64, dr.addr);
			dl->AddText(code_font, code_font->FontSize,
				ImVec2(x + 18.f, ry + (row_h - code_font->FontSize) * 0.5f),
				with_a(is_rip ? t.accent_hover : t.text_address, alpha), addr_buf);

			char bytes_buf[40] = {};
			int blen = dr.ins.len > 8 ? 8 : dr.ins.len;
			char* bp = bytes_buf;
			for (int b = 0; b < blen; ++b) {
				bp += std::snprintf(bp, sizeof(bytes_buf) - (bp - bytes_buf),
					"%02X ", dr.ins.raw[b]);
			}
			if (dr.ins.len > 8) {
				std::snprintf(bp, sizeof(bytes_buf) - (bp - bytes_buf), "+");
			}
			dl->AddText(code_font, code_font->FontSize,
				ImVec2(x + 160.f, ry + (row_h - code_font->FontSize) * 0.5f),
				with_a(t.text_dim, alpha * 0.85f), bytes_buf);

			ImU32 mc = cpu_view_detail::mnemonic_color(dr.ins, t);
			dl->AddText(code_font, code_font->FontSize,
				ImVec2(x + 300.f, ry + (row_h - code_font->FontSize) * 0.5f),
				with_a(mc, alpha), dr.ins.mnem);

			if (dr.ins.ops[0] != 0) {
				dl->AddText(code_font, code_font->FontSize,
					ImVec2(x + 360.f, ry + (row_h - code_font->FontSize) * 0.5f),
					with_a(t.text_primary, alpha), dr.ins.ops);
			}

			if (clicked) ui.cpu_disasm_selected = i;
			if (dclicked && dr.ins.branch_target != 0) {
				diag::log_tagged_fmt("cpu_view",
					"disasm_dclick_follow target=0x%llx",
					static_cast<unsigned long long>(dr.ins.branch_target));
				jump_to_disasm(dr.ins.branch_target);
			}
			if (rclicked) {
				ui.cpu_disasm_context_idx = i;
				ui.cpu_disasm_context_addr = dr.addr;
				ui.cpu_disasm_context_target = dr.ins.branch_target;
				ui.cpu_disasm_context_open = true;
				diag::log_tagged_fmt("cpu_view",
					"disasm_rclick addr=0x%llx target=0x%llx",
					static_cast<unsigned long long>(dr.addr),
					static_cast<unsigned long long>(dr.ins.branch_target));
			}
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();
}

static void render_cpu_stack_view(ImDrawList* dl, float x, float y, float w, float h,
                                  uint64_t rsp, float alpha) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	draw_glass_card(dl, ImVec2(x, y), ImVec2(x + w, y + h), 10.f, alpha);
	draw_panel_header(dl, x, y, w, "STACK @ RSP", alpha);

	if (rsp == 0) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const char* msg = "RSP is zero (target not paused).";
		ImVec2 sz = fnt->CalcTextSizeA(fnt->FontSize, FLT_MAX, 0.f, msg);
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			with_a(t.text_dim, alpha), msg);
		return;
	}

	constexpr size_t kStackBytes = 0x100;
	debugger_engine::request_stack_refresh(rsp, kStackBytes, 220);
	uint64_t base = 0;
	auto buf = debugger_engine::cached_stack_bytes(base);

	float content_y = y + HEADER_H + 2.f;
	float content_h = h - HEADER_H - 4.f;
	if (content_h < 24.f) return;

	float row_h = 20.f;
	float child_w = w - 4.f;

	ImGui::SetCursorScreenPos(ImVec2(x + 2.f, content_y));
	ImGui::PushID("##cpu_stack");
	ImGui::BeginChild("##cpu_stack_child", ImVec2(child_w, content_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	if (buf.empty() || base != rsp) {
		ImFont* fnt = aida::ui::fonts::caption();
		if (!fnt) fnt = ImGui::GetFont();
		const char* msg = "Reading stack frame...";
		ImVec2 sz = fnt->CalcTextSizeA(fnt->FontSize, FLT_MAX, 0.f, msg);
		ImVec2 cp = ImGui::GetCursorScreenPos();
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(cp.x + (child_w - sz.x) * 0.5f, cp.y + 16.f),
			with_a(t.text_dim, alpha), msg);
		ImGui::EndChild();
		ImGui::PopID();
		return;
	}

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	size_t qword_count = buf.size() / 8;
	if (qword_count == 0) qword_count = 1;

	ImGuiListClipper clipper;
	clipper.Begin(static_cast<int>(qword_count), row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			uint64_t qaddr = rsp + static_cast<uint64_t>(i) * 8ULL;
			uint64_t qval = 0;
			size_t qoff = static_cast<size_t>(i) * 8u;
			if (qoff + 8 <= buf.size())
				std::memcpy(&qval, buf.data() + qoff, sizeof(uint64_t));

			ImGui::SetCursorScreenPos(ImVec2(x + 4.f, ry));
			ImGui::PushID(i + 0xC0000);
			ImGui::InvisibleButton("##cpu_stack_row", ImVec2(child_w - 8.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			bool is_top = (i == 0);
			bool is_sel = (ui.cpu_stack_selected == i);
			if (is_top) {
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + 4.f, ry + row_h),
					with_a(t.accent_u32, alpha));
				dl->AddRectFilled(ImVec2(x + 2.f, ry), ImVec2(x + child_w - 2.f, ry + row_h),
					with_a(t.accent_glow, alpha * 0.18f), 3.f);
			}
			if (is_sel && !is_top) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, true, false, i, 1.f, alpha);
			} else if (hov && !is_top) {
				draw_row_bg(dl, x + 2.f, ry, child_w - 4.f, row_h, false, true, i, 1.f, alpha);
			}

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, qaddr);
			dl->AddText(code_font, code_font->FontSize,
				ImVec2(x + 8.f, ry + (row_h - code_font->FontSize) * 0.5f),
				with_a(is_top ? t.accent_hover : t.text_address, alpha), abuf);

			char vbuf[20];
			std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, qval);
			ImU32 vcol = cpu_view_detail::is_likely_pointer(qval) ? t.syn_function
				: (qval == 0 ? t.text_dim : t.syn_number);
			dl->AddText(code_font, code_font->FontSize,
				ImVec2(x + 180.f, ry + (row_h - code_font->FontSize) * 0.5f),
				with_a(vcol, alpha), vbuf);

			if (cpu_view_detail::is_likely_pointer(qval)) {
				ImFont* sf = aida::ui::fonts::caption();
				if (!sf) sf = ImGui::GetFont();
				const char* hint = "ptr";
				dl->AddText(sf, sf->FontSize,
					ImVec2(x + 350.f, ry + (row_h - sf->FontSize) * 0.5f),
					with_a(t.text_dim, alpha * 0.85f), hint);
			}

			if (clicked) ui.cpu_stack_selected = i;
			if (dclicked && cpu_view_detail::is_likely_pointer(qval)) {
				diag::log_tagged_fmt("cpu_view",
					"stack_dclick_follow qaddr=0x%llx qval=0x%llx",
					static_cast<unsigned long long>(qaddr),
					static_cast<unsigned long long>(qval));
				jump_to_hex(qval, 256);
			}
			if (rclicked) {
				ui.cpu_stack_context_idx = i;
				ui.cpu_stack_context_open = true;
				diag::log_tagged_fmt("cpu_view",
					"stack_rclick qaddr=0x%llx qval=0x%llx",
					static_cast<unsigned long long>(qaddr),
					static_cast<unsigned long long>(qval));
			}
		}
	}
	clipper.End();

	if (std::abs(ImGui::GetScrollY() - ui.cpu_stack_scroll_y) > 0.5f) {
		ui.cpu_stack_scroll_y = ImGui::GetScrollY();
		diag::log_tagged_fmt("cpu_view",
			"stack_scroll y=%.1f",
			static_cast<double>(ui.cpu_stack_scroll_y));
	}

	ImGui::EndChild();
	ImGui::PopID();
}

static void render_cpu(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] cpu enter ok=1");
			diag::log_tagged_critical_fmt("cpu_view",
				"cpu_pane_enter w=%.0f h=%.0f", static_cast<double>(w),
				static_cast<double>(h));
		}
	}

	uint32_t attached_pid = driver_bridge::attached_pid();
	if (attached_pid == 0) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to inspect CPU registers and flags.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	debugger_engine::request_refresh(120);
	auto regs = debugger_engine::cached_registers();

	cpu_view_detail::reg_row_t rows[] = {
		{"RAX", regs.rax, 0, true},
		{"RBX", regs.rbx, 0, true},
		{"RCX", regs.rcx, 0, true},
		{"RDX", regs.rdx, 0, true},
		{"RSI", regs.rsi, 0, true},
		{"RDI", regs.rdi, 0, true},
		{"RBP", regs.rbp, 0, true},
		{"RSP", regs.rsp, 0, true},
		{"R8",  regs.r8,  0, true},
		{"R9",  regs.r9,  0, true},
		{"R10", regs.r10, 0, true},
		{"R11", regs.r11, 0, true},
		{"R12", regs.r12, 0, true},
		{"R13", regs.r13, 0, true},
		{"R14", regs.r14, 0, true},
		{"R15", regs.r15, 0, true},
		{"RIP", regs.rip, 0, true},
		{"RFLAGS", regs.rflags, 0, true},
		{"CS", regs.cs, 1, false},
		{"SS", regs.ss, 1, false},
		{"DS", regs.ds, 1, false},
		{"ES", regs.es, 1, false},
		{"FS", regs.fs, 1, false},
		{"GS", regs.gs, 1, false},
		{"DR0", regs.dr0, 2, true},
		{"DR1", regs.dr1, 2, true},
		{"DR2", regs.dr2, 2, true},
		{"DR3", regs.dr3, 2, true},
		{"DR6", regs.dr6, 2, true},
		{"DR7", regs.dr7, 2, true},
	};
	int rows_n = static_cast<int>(sizeof(rows) / sizeof(rows[0]));

	if (!ui.cpu_prev_reg_initialized) {
		for (int i = 0; i < rows_n && i < 32; ++i)
			ui.cpu_prev_reg_values[i] = rows[i].value;
		ui.cpu_prev_reg_initialized = true;
		diag::log_tagged_fmt("cpu_view",
			"prev_reg_initialized rows=%d", rows_n);
	} else {
		for (int i = 0; i < rows_n && i < 32; ++i) {
			if (ui.cpu_prev_reg_values[i] != rows[i].value) {
				ui.cpu_reg_flash[i] = 1.f;
				ui.cpu_prev_reg_values[i] = rows[i].value;
				diag::log_tagged_fmt("cpu_view",
					"reg_change name=%s new=0x%llx",
					rows[i].name,
					static_cast<unsigned long long>(rows[i].value));
			}
			ui.cpu_reg_flash[i] *= std::exp(-3.0f * dt);
			if (ui.cpu_reg_flash[i] < 0.005f) ui.cpu_reg_flash[i] = 0.f;
		}
	}

	float pad = 10.f;
	const float kMinPanelW = 720.f;
	if (w < kMinPanelW) {
		static bool s_logged_cpu_narrow = false;
		if (!s_logged_cpu_narrow) {
			s_logged_cpu_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"debugger_view cpu_pane too_narrow w=%.0f min=%.0f overlay_shown=1",
				w, kMinPanelW);
		}
		float msg_y = oy + h * 0.5f - 24.f;
		float msg_w = std::min(w - 24.f, 520.f);
		float msg_x = ox + (w - msg_w) * 0.5f;
		ui_anim::render_inline_callout(dl, msg_x, msg_y, msg_w, 48.f,
			"Widen the debugger pane to view CPU registers, disassembly, and stack side-by-side.",
			ui_anim::callout_kind_t::info, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	float left_w = std::max(360.f, w * 0.40f);
	float right_w = w - left_w - pad * 3.f;
	if (right_w < 360.f) {
		right_w = std::max(360.f, w - left_w - pad * 2.f);
		if (right_w < 280.f) right_w = std::max(280.f, w - 200.f - pad * 2.f);
	}

	float left_x = ox + pad;
	float right_x = left_x + left_w + pad;
	float top_y = oy + 4.f;
	float bot_y = oy + h - 4.f;
	float total_h = bot_y - top_y;
	float reg_h = total_h * 0.62f;
	float flags_h = total_h - reg_h - pad;
	float disasm_h = total_h * 0.55f;
	float stack_h = total_h - disasm_h - pad;

	float reg_y0 = top_y;
	float reg_y1 = reg_y0 + reg_h;
	float flags_y0 = reg_y1 + pad;
	float flags_y1 = flags_y0 + flags_h;

	float disasm_y0 = top_y;
	float disasm_y1 = disasm_y0 + disasm_h;
	float stack_y0 = disasm_y1 + pad;
	float stack_y1 = stack_y0 + stack_h;

	draw_glass_card(dl, ImVec2(left_x, reg_y0),
		ImVec2(left_x + left_w, reg_y1), 10.f, a);
	{
		char hdr_buf[64];
		std::snprintf(hdr_buf, sizeof(hdr_buf), "REGISTERS  PID %u  TID %u",
			static_cast<unsigned>(attached_pid),
			static_cast<unsigned>(debugger_engine::g_state.active_tid));
		draw_panel_header(dl, left_x, reg_y0, left_w, hdr_buf, a);
	}

	float list_y = reg_y0 + HEADER_H + 2.f;
	float list_h = reg_y1 - 4.f - list_y;
	if (list_h < 80.f) list_h = 80.f;

	ImGui::SetCursorScreenPos(ImVec2(left_x + 2.f, list_y));
	ImGui::PushID("##cpu_reg_list");
	ImGui::BeginChild("##cpu_reg_list_child", ImVec2(left_w - 4.f, list_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	float row_h = 22.f;
	ImGuiListClipper clipper;
	clipper.Begin(rows_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = list_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			const auto& r = rows[static_cast<size_t>(i)];

			ImGui::SetCursorScreenPos(ImVec2(left_x + 4.f, ry));
			ImGui::PushID(i + 0xF0000);
			ImGui::InvisibleButton("##cpu_row", ImVec2(left_w - 8.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			bool rclicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
			ImGui::PopID();

			bool sel = (ui.cpu_panel.selected == i);
			float flash = (i < 32) ? ui.cpu_reg_flash[i] : 0.f;
			draw_cpu_reg_row(dl, left_x + 2.f, ry, left_w - 4.f, row_h,
				i, r, flash, sel, hov, a);

			if (clicked) {
				ui.cpu_panel.selected = i;
				diag::log_tagged_fmt("cpu_view",
					"reg_click name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (dclicked && r.editable) {
				cpu_view_detail::open_edit_modal(i, r.value);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_dclick_edit name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (rclicked && r.editable) {
				ui.cpu_context_reg_idx = i;
				ui.cpu_context_open = true;
				diag::log_tagged_fmt("cpu_view",
					"reg_rclick name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
		}
	}
	clipper.End();

	ui.cpu_reg_scroll_y = ImGui::GetScrollY();

	ImGui::EndChild();
	ImGui::PopID();

	draw_glass_card(dl, ImVec2(left_x, flags_y0),
		ImVec2(left_x + left_w, flags_y1), 10.f, a);
	draw_panel_header(dl, left_x, flags_y0, left_w, "RFLAGS", a);

	struct flag_def_t {
		const char* short_name;
		const char* full_name;
		uint64_t    mask;
	};
	flag_def_t flag_defs[] = {
		{"CF", "Carry",      0x00000001ULL},
		{"PF", "Parity",     0x00000004ULL},
		{"AF", "Aux Carry",  0x00000010ULL},
		{"ZF", "Zero",       0x00000040ULL},
		{"SF", "Sign",       0x00000080ULL},
		{"OF", "Overflow",   0x00000800ULL},
		{"TF", "Trap",       0x00000100ULL},
		{"IF", "Interrupt",  0x00000200ULL},
		{"DF", "Direction",  0x00000400ULL},
		{"NT", "Nested",     0x00004000ULL},
		{"RF", "Resume",     0x00010000ULL},
		{"AC", "AlignCheck", 0x00040000ULL},
	};
	int flag_n = static_cast<int>(sizeof(flag_defs) / sizeof(flag_defs[0]));

	float fcols = 2.f;
	float frows = static_cast<float>((flag_n + 1) / 2);
	float fpad_inner = 8.f;
	float favail_w = left_w - fpad_inner * (fcols + 1.f);
	float fchip_w = favail_w / fcols;
	float favail_h = flags_y1 - (flags_y0 + HEADER_H + 6.f) - fpad_inner;
	float fchip_h = (favail_h - fpad_inner * (frows - 1.f)) / frows;
	if (fchip_h < 22.f) fchip_h = 22.f;
	if (fchip_h > 36.f) fchip_h = 36.f;

	for (int i = 0; i < flag_n; ++i) {
		int col = i % 2;
		int row = i / 2;
		bool set_bit = (regs.rflags & flag_defs[i].mask) != 0;
		float bx = left_x + fpad_inner + static_cast<float>(col) * (fchip_w + fpad_inner);
		float by = flags_y0 + HEADER_H + 6.f
		         + static_cast<float>(row) * (fchip_h + fpad_inner);

		ImGui::SetCursorScreenPos(ImVec2(bx, by));
		ImGui::PushID(i + 0xF1000);
		ImGui::InvisibleButton("##cpu_flag", ImVec2(fchip_w, fchip_h));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		ImGui::PopID();

		ImU32 bg_col = set_bit ? aida::ui::mix(t.panel_header, t.success, 0.35f)
		                       : t.panel_header;
		if (hov) bg_col = aida::ui::mix(bg_col, t.hover_wash, 0.55f);
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + fchip_w, by + fchip_h),
			with_a(bg_col, a), 6.f);
		ImU32 border = set_bit ? aida::ui::mix(t.success, t.accent_u32, 0.25f)
		                       : t.border_subtle;
		dl->AddRect(ImVec2(bx, by), ImVec2(bx + fchip_w, by + fchip_h),
			with_a(border, a * (set_bit ? 0.95f : 0.65f)), 6.f, 0, 1.f);

		ImU32 led = set_bit ? t.success : t.text_dim;
		dl->AddCircleFilled(ImVec2(bx + 14.f, by + fchip_h * 0.5f), 5.f,
			with_a(led, a * 0.30f), 16);
		dl->AddCircleFilled(ImVec2(bx + 14.f, by + fchip_h * 0.5f), 3.f,
			with_a(led, a * (set_bit ? 1.f : 0.55f)), 16);

		ImFont* fnt = aida::ui::fonts::body_em();
		if (!fnt) fnt = ImGui::GetFont();
		dl->AddText(fnt, fnt->FontSize,
			ImVec2(bx + 28.f, by + (fchip_h - fnt->FontSize) * 0.5f),
			with_a(set_bit ? t.text_primary : t.text_secondary, a),
			flag_defs[i].short_name);

		ImFont* sf = aida::ui::fonts::caption();
		if (!sf) sf = ImGui::GetFont();
		float full_x = bx + 60.f;
		dl->AddText(sf, sf->FontSize,
			ImVec2(full_x, by + (fchip_h - sf->FontSize) * 0.5f),
			with_a(t.text_dim, a * 0.95f), flag_defs[i].full_name);

		ImFont* cf = aida::ui::fonts::code();
		if (!cf) cf = ImGui::GetFont();
		const char* bit_str = set_bit ? "1" : "0";
		ImVec2 bs = cf->CalcTextSizeA(cf->FontSize, FLT_MAX, 0.f, bit_str);
		dl->AddText(cf, cf->FontSize,
			ImVec2(bx + fchip_w - bs.x - 10.f, by + (fchip_h - bs.y) * 0.5f),
			with_a(set_bit ? t.success : t.text_dim, a), bit_str);

		if (clicked) {
			uint64_t new_rflags = regs.rflags ^ flag_defs[i].mask;
			bool ok = debugger_engine::set_register("rflags", new_rflags);
			diag::log_tagged_critical_fmt("cpu_view",
				"flag_toggle name=%s mask=0x%llx new_rflags=0x%llx ok=%d",
				flag_defs[i].short_name,
				static_cast<unsigned long long>(flag_defs[i].mask),
				static_cast<unsigned long long>(new_rflags),
				ok ? 1 : 0);
			anti_tamper::webhook::write_log("dbg_audit", ok
				? "[dbg_audit] cpu flag_toggle ok=1"
				: "[dbg_audit] cpu flag_toggle fail reason=set_register_failed");
			if (!ok) {
				toast_notification::push("Failed to toggle flag: " +
					debugger_engine::last_error(),
					toast_notification::toast_type_t::error);
			} else {
				debugger_engine::invalidate_cache();
			}
		}
	}

	render_cpu_disasm_slice(dl, right_x, disasm_y0, right_w, disasm_h, regs.rip, a);
	render_cpu_stack_view(dl, right_x, stack_y0, right_w, stack_h, regs.rsp, a);

	if (ui.cpu_context_open) {
		ImGui::OpenPopup("##cpu_reg_context");
		ui.cpu_context_open = false;
		diag::log_tagged_fmt("cpu_view", "reg_context_open");
	}
	if (ImGui::BeginPopup("##cpu_reg_context")) {
		if (ui.cpu_context_reg_idx >= 0 && ui.cpu_context_reg_idx < rows_n) {
			const auto& r = rows[static_cast<size_t>(ui.cpu_context_reg_idx)];
			ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.f),
				"%s = 0x%016llX", r.name,
				static_cast<unsigned long long>(r.value));
			ImGui::Separator();
			if (ImGui::MenuItem("Edit value...")) {
				cpu_view_detail::open_edit_modal(ui.cpu_context_reg_idx, r.value);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_context_edit name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (ImGui::MenuItem("Copy hex (0x...)")) {
				copy_addr_to_clipboard(r.value);
				diag::log_tagged_fmt("cpu_view",
					"reg_context_copy_hex name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (ImGui::MenuItem("Copy decimal")) {
				char dbuf[32];
				std::snprintf(dbuf, sizeof(dbuf), "%llu",
					static_cast<unsigned long long>(r.value));
				copy_to_clipboard(dbuf);
				diag::log_tagged_fmt("cpu_view",
					"reg_context_copy_dec name=%s value=%llu",
					r.name, static_cast<unsigned long long>(r.value));
			}
			ImGui::Separator();
			if (ImGui::MenuItem("Follow in disasm", nullptr, false, r.value != 0)) {
				jump_to_disasm(r.value);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_context_follow_disasm name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			if (ImGui::MenuItem("Follow in hex dump", nullptr, false, r.value != 0)) {
				jump_to_hex(r.value, 256);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_context_follow_hex name=%s value=0x%llx",
					r.name, static_cast<unsigned long long>(r.value));
			}
			ImGui::Separator();
			if (ImGui::MenuItem("Set to zero")) {
				std::string lname = cpu_view_detail::lowercase_reg_name(r.name);
				bool ok = debugger_engine::set_register(lname, 0);
				diag::log_tagged_critical_fmt("cpu_view",
					"reg_context_zero name=%s ok=%d", r.name, ok ? 1 : 0);
				if (ok) {
					debugger_engine::invalidate_cache();
					toast_notification::push("Register cleared.",
						toast_notification::toast_type_t::info);
				} else {
					toast_notification::push("Set zero failed: " +
						debugger_engine::last_error(),
						toast_notification::toast_type_t::error);
				}
			}
		}
		ImGui::EndPopup();
	}

	if (ui.cpu_stack_context_open) {
		ImGui::OpenPopup("##cpu_stack_context");
		ui.cpu_stack_context_open = false;
		diag::log_tagged_fmt("cpu_view", "stack_context_open");
	}
	if (ImGui::BeginPopup("##cpu_stack_context")) {
		int idx = ui.cpu_stack_context_idx;
		uint64_t qaddr = regs.rsp + static_cast<uint64_t>(idx) * 8ULL;
		uint64_t qval = 0;
		uint64_t scache_base = 0;
		auto sb = debugger_engine::cached_stack_bytes(scache_base);
		size_t qoff = static_cast<size_t>(idx) * 8u;
		if (scache_base == regs.rsp && qoff + 8 <= sb.size())
			std::memcpy(&qval, sb.data() + qoff, sizeof(uint64_t));
		ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.f),
			"[rsp+%02X] @ 0x%016llX = 0x%016llX",
			static_cast<unsigned>(idx) * 8u,
			static_cast<unsigned long long>(qaddr),
			static_cast<unsigned long long>(qval));
		ImGui::Separator();
		if (ImGui::MenuItem("Copy slot address")) {
			copy_addr_to_clipboard(qaddr);
			diag::log_tagged_fmt("cpu_view", "stack_context_copy_addr addr=0x%llx",
				static_cast<unsigned long long>(qaddr));
		}
		if (ImGui::MenuItem("Copy qword value")) {
			copy_addr_to_clipboard(qval);
			diag::log_tagged_fmt("cpu_view", "stack_context_copy_val val=0x%llx",
				static_cast<unsigned long long>(qval));
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Follow value in disasm",
			nullptr, false, cpu_view_detail::is_likely_pointer(qval))) {
			jump_to_disasm(qval);
			diag::log_tagged_critical_fmt("cpu_view",
				"stack_context_follow_disasm val=0x%llx",
				static_cast<unsigned long long>(qval));
		}
		if (ImGui::MenuItem("Follow value in hex dump",
			nullptr, false, cpu_view_detail::is_likely_pointer(qval))) {
			jump_to_hex(qval, 256);
			diag::log_tagged_critical_fmt("cpu_view",
				"stack_context_follow_hex val=0x%llx",
				static_cast<unsigned long long>(qval));
		}
		ImGui::EndPopup();
	}

	if (ui.cpu_disasm_context_open) {
		ImGui::OpenPopup("##cpu_disasm_context");
		ui.cpu_disasm_context_open = false;
		diag::log_tagged_fmt("cpu_view", "disasm_context_open");
	}
	if (ImGui::BeginPopup("##cpu_disasm_context")) {
		ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.f),
			"Instruction @ 0x%016llX",
			static_cast<unsigned long long>(ui.cpu_disasm_context_addr));
		ImGui::Separator();
		if (ImGui::MenuItem("Copy address")) {
			copy_addr_to_clipboard(ui.cpu_disasm_context_addr);
			diag::log_tagged_fmt("cpu_view",
				"disasm_context_copy_addr addr=0x%llx",
				static_cast<unsigned long long>(ui.cpu_disasm_context_addr));
		}
		if (ImGui::MenuItem("Open in disassembly view")) {
			jump_to_disasm(ui.cpu_disasm_context_addr);
			diag::log_tagged_critical_fmt("cpu_view",
				"disasm_context_open_in_disasm addr=0x%llx",
				static_cast<unsigned long long>(ui.cpu_disasm_context_addr));
		}
		if (ImGui::MenuItem("Follow branch target",
			nullptr, false, ui.cpu_disasm_context_target != 0)) {
			jump_to_disasm(ui.cpu_disasm_context_target);
			diag::log_tagged_critical_fmt("cpu_view",
				"disasm_context_follow_target target=0x%llx",
				static_cast<unsigned long long>(ui.cpu_disasm_context_target));
		}
		ImGui::Separator();
		if (ImGui::MenuItem("Set RIP to here")) {
			bool ok = debugger_engine::set_register("rip",
				ui.cpu_disasm_context_addr);
			diag::log_tagged_critical_fmt("cpu_view",
				"disasm_context_set_rip addr=0x%llx ok=%d",
				static_cast<unsigned long long>(ui.cpu_disasm_context_addr),
				ok ? 1 : 0);
			if (ok) {
				debugger_engine::invalidate_cache();
				toast_notification::push("RIP updated.",
					toast_notification::toast_type_t::info);
			} else {
				toast_notification::push("Set RIP failed: " +
					debugger_engine::last_error(),
					toast_notification::toast_type_t::error);
			}
		}
		ImGui::EndPopup();
	}

	if (ui.cpu_edit_popup_open) {
		ImGui::OpenPopup("Edit Register##cpu");
		ui.cpu_edit_popup_open = false;
		diag::log_tagged_fmt("cpu_view", "edit_modal_open idx=%d",
			ui.cpu_edit_reg_idx);
	}
	if (ImGui::BeginPopupModal("Edit Register##cpu", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize)) {
		if (ui.cpu_edit_reg_idx >= 0 && ui.cpu_edit_reg_idx < rows_n) {
			const auto& er = rows[static_cast<size_t>(ui.cpu_edit_reg_idx)];
			ImGui::Text("Register: %s", er.name);
			ImGui::Text("Current:  0x%016llX",
				static_cast<unsigned long long>(er.value));
			ImGui::Separator();
			ImGui::SetNextItemWidth(220.f);
			ImGui::InputText("##cpu_edit_val", ui.cpu_edit_value_buf,
				sizeof(ui.cpu_edit_value_buf),
				ImGuiInputTextFlags_CharsHexadecimal |
				ImGuiInputTextFlags_AutoSelectAll);
			ImGui::Separator();
			if (ImGui::Button("Apply", ImVec2(110.f, 0.f))) {
				uint64_t new_val = parse_hex_address(ui.cpu_edit_value_buf);
				std::string lname = cpu_view_detail::lowercase_reg_name(er.name);
				bool ok = debugger_engine::set_register(lname, new_val);
				diag::log_tagged_critical_fmt("cpu_view",
					"edit_modal_apply name=%s new=0x%llx ok=%d err='%s'",
					lname.c_str(),
					static_cast<unsigned long long>(new_val),
					ok ? 1 : 0,
					debugger_engine::last_error().c_str());
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] cpu reg_edit ok=1"
					: "[dbg_audit] cpu reg_edit fail reason=set_register_failed");
				if (!ok) {
					toast_notification::push("Edit register failed: " +
						debugger_engine::last_error(),
						toast_notification::toast_type_t::error);
				} else {
					debugger_engine::invalidate_cache();
					toast_notification::push("Register updated.",
						toast_notification::toast_type_t::info);
				}
				ui.cpu_edit_reg_idx = -1;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(110.f, 0.f))) {
				diag::log_tagged_fmt("cpu_view", "edit_modal_cancel");
				ui.cpu_edit_reg_idx = -1;
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}
}


static void render_cfg_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& ui = g_ui;
	(void)dl;
	(void)w;
	(void)a;

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] cfg enter ok=1");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_w = 140.f;
	float btn_gap = 6.f;

	uint64_t rip = debugger_engine::cached_registers().rip;
	bool can_build = rip != 0;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##cfg_overlay");
	bool build_clicked = aida::ui::button(
		can_build ? "Build CFG at RIP" : "Build CFG (no RIP)",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		!can_build);
	if (build_clicked && can_build) {
		cfg_view::build_cfg(rip);
		ui.cfg_last_built_addr = rip;
		diag::log_tagged_critical_fmt("cfg",
			"cfg_build_from_debugger rip=0x%llx",
			static_cast<unsigned long long>(rip));
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] cfg build_at_rip ok=1");
	}
	ImGui::SameLine(0.f, btn_gap);
	bool open_full = aida::ui::button("Open in Graph View",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(btn_w + 20.f, btn_h),
		!can_build && ui.cfg_last_built_addr == 0);
	if (open_full) {
		uint64_t target_addr = can_build ? rip : ui.cfg_last_built_addr;
		if (target_addr != 0) {
			globals::ui::active_center_view = center_view_t::graph_view;
			cfg_view::build_cfg(target_addr);
			ui.cfg_last_built_addr = target_addr;
			diag::log_tagged_critical_fmt("cfg",
				"cfg_open_graph_view target=0x%llx",
				static_cast<unsigned long long>(target_addr));
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] cfg open_full ok=1");
		} else {
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] cfg open_full fail reason=no_address");
		}
	}
	ImGui::PopID();
}

static void render_modules_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] modules enter ok=1");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_w = 120.f;
	float btn_gap = 6.f;

	bool can_act = driver_bridge::attached_pid() != 0;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##modules_overlay");
	bool dump_clicked = aida::ui::button("Dump Selected",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		!can_act);
	if (dump_clicked) {
		uint64_t base = 0;
		uint64_t size = 0;
		std::string name;
		{
			std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
			int sel = module_view::g_ui.selected_module;
			if (sel >= 0 && sel < static_cast<int>(module_view::g_ui.modules.size())) {
				base = module_view::g_ui.modules[sel].base;
				size = static_cast<uint64_t>(module_view::g_ui.modules[sel].size);
				name = module_view::g_ui.modules[sel].name;
			}
		}
		if (base == 0 || size == 0) {
			toast_notification::push("Select a module first.",
				toast_notification::toast_type_t::warning);
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] modules dump fail reason=no_selection");
		} else {
			const uint64_t cap = 256ULL * 1024ULL * 1024ULL;
			if (size > cap) {
				toast_notification::push("Module exceeds 256 MiB dump cap.",
					toast_notification::toast_type_t::warning);
				anti_tamper::webhook::write_log("dbg_audit",
					"[dbg_audit] modules dump fail reason=cap_exceeded");
			} else {
				char default_name[160] = {};
				std::snprintf(default_name, sizeof(default_name),
					"%s_%016llX.bin",
					name.empty() ? "module" : name.c_str(),
					static_cast<unsigned long long>(base));
				char path_buf[MAX_PATH] = {};
				std::strncpy(path_buf, default_name, sizeof(path_buf) - 1);
				static const char k_module_filter[] =
					"Binary (*.bin)\0*.bin\0DLL (*.dll)\0*.dll\0EXE (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
				if (win32_dialog::show_save_file_dialog(g_hwnd,
						"Dump Module",
						k_module_filter,
						"bin",
						path_buf, sizeof(path_buf),
						"debugger_view::modules_dump")) {
					uint64_t base_copy = base;
					uint64_t size_copy = size;
					std::string path_copy = path_buf;
					std::string name_copy = name;
					work_queue::post([base_copy, size_copy, path_copy, name_copy]() {
						std::vector<uint8_t> buf;
						bool read_ok = driver_bridge::read_memory(base_copy,
							static_cast<size_t>(size_copy), buf);
						bool write_ok = false;
						if (read_ok && !buf.empty()) {
							std::ofstream ofs(path_copy,
								std::ios::binary | std::ios::trunc);
							if (ofs.is_open()) {
								ofs.write(reinterpret_cast<const char*>(buf.data()),
									static_cast<std::streamsize>(buf.size()));
								ofs.close();
								write_ok = true;
							}
						}
						diag::log_tagged_critical_fmt("modules",
							"modules_dump name='%s' base=0x%llx size=%llu read=%d write=%d path='%s'",
							name_copy.c_str(),
							static_cast<unsigned long long>(base_copy),
							static_cast<unsigned long long>(size_copy),
							read_ok ? 1 : 0,
							write_ok ? 1 : 0,
							path_copy.c_str());
						anti_tamper::webhook::write_log("dbg_audit", write_ok
							? "[dbg_audit] modules dump ok=1"
							: "[dbg_audit] modules dump fail reason=read_or_write_failed");
						if (write_ok) {
							char msg[MAX_PATH + 96];
							std::snprintf(msg, sizeof(msg),
								"Dumped %llu bytes from %s to %s",
								static_cast<unsigned long long>(buf.size()),
								name_copy.c_str(), path_copy.c_str());
							toast_notification::push(msg,
								toast_notification::toast_type_t::info);
						} else {
							toast_notification::push("Module dump failed.",
								toast_notification::toast_type_t::error);
						}
					});
				}
			}
		}
	}
	ImGui::SameLine(0.f, btn_gap);

	bool inject_clicked = aida::ui::button("Inject DLL...",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		true);
	if (inject_clicked) {
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] BROKEN feature=modules_inject_dll reason=driver_bridge_has_no_LoadLibrary_helper");
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip(
			"Inject DLL is not wired: driver_bridge does not expose a remote LoadLibrary helper. "
			"Use the manual mapper from the disassembly toolbar instead.");
	ImGui::SameLine(0.f, btn_gap);

	bool unload_clicked = aida::ui::button("Unload Module",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(btn_w, btn_h),
		true);
	if (unload_clicked) {
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] BROKEN feature=modules_unload reason=driver_bridge_has_no_FreeLibrary_helper");
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip(
			"Unload Module is not wired: driver_bridge does not expose a remote FreeLibrary helper. "
			"Detach and use Process Hacker to unload.");
	ImGui::PopID();

	float cb_y = oy + overlay_h + 2.f;
	float cb_h = 20.f;
	float cb_w = w - 24.f;
	ui_anim::render_inline_callout(dl, ox + 12.f, cb_y, cb_w, cb_h,
		"Inject DLL and Unload Module are unavailable in this build (driver helpers missing). Dump uses kernel read_memory.",
		ui_anim::callout_kind_t::info,
		t.accent.x, t.accent.y, t.accent.z, a);
}

static void render_seh_overlay(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] seh enter ok=1");
		}
	}

	float overlay_h = 36.f;
	float pad = 8.f;
	float btn_h = 22.f;
	float btn_w = 200.f;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + (overlay_h - btn_h) * 0.5f));
	ImGui::PushID("##seh_overlay");
	bool break_clicked = aida::ui::button(
		ui.seh_break_request_active
			? "Break on Next Exception (armed)"
			: "Break on Next Exception",
		ui.seh_break_request_active
			? aida::ui::button_kind_t::destructive
			: aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(btn_w + 40.f, btn_h),
		true);
	if (break_clicked) {
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] BROKEN feature=seh_break_on_exception reason=driver_bridge_has_no_debug_event_subscription");
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip(
			"Break on Exception requires a debug-event subscription that this build's driver_bridge does not expose. "
			"Use a HW BP on the SEH handler address instead.");
	ImGui::PopID();

	float cb_y = oy + overlay_h + 2.f;
	float cb_h = 20.f;
	float cb_w = w - 24.f;
	ui_anim::render_inline_callout(dl, ox + 12.f, cb_y, cb_w, cb_h,
		"Break-on-next-exception is unavailable (no debug-event channel). Use HW exec breakpoint on the handler address instead.",
		ui_anim::callout_kind_t::warn,
		t.accent.x, t.accent.y, t.accent.z, a);
}


static void render_breakpoint_actions(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	(void)dl; (void)t;

	float bar_h = 40.f;
	float pad = 8.f;
	float input_w = w * 0.42f;
	float btn_gap = 6.f;

	ImGui::SetCursorScreenPos(ImVec2(ox + pad, oy + 2.f));
	ImGui::PushID("##bp_actions");

	ImGui::SetNextItemWidth(input_w);
	aida::ui::input_text("##bp_addr", ui.add_bp_addr_buf, sizeof(ui.add_bp_addr_buf),
		"0x... breakpoint address",
		false, ImVec2(input_w, bar_h - 8.f));

	ImGui::SameLine(0.f, btn_gap);

	bool add_clicked = aida::ui::button("Add SW BP", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (add_clicked) {
		uint64_t addr = parse_hex_address(ui.add_bp_addr_buf);
		diag::log_tagged_critical_fmt("bp",
			"bp_add_sw_request raw='%s' parsed_addr=0x%llx",
			ui.add_bp_addr_buf,
			static_cast<unsigned long long>(addr));
		if (addr != 0) {
			int idx = debugger_engine::add_breakpoint(addr,
				debugger_engine::bp_type_t::software, "", "", 1);
			diag::log_tagged_critical_fmt("bp",
				"bp_add_sw addr=0x%llx idx=%d err='%s'",
				static_cast<unsigned long long>(addr),
				idx,
				debugger_engine::last_error().c_str());
			if (idx < 0) {
				toast_notification::push("Add SW BP failed: " +
					debugger_engine::last_error(),
					toast_notification::toast_type_t::error);
			} else {
				ui.add_bp_addr_buf[0] = '\0';
			}
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	ImGui::SameLine(0.f, btn_gap);

	bool add_hw_clicked = aida::ui::button("Add HW Exec",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (add_hw_clicked) {
		uint64_t addr = parse_hex_address(ui.add_bp_addr_buf);
		diag::log_tagged_critical_fmt("bp",
			"bp_add_hw_request raw='%s' parsed_addr=0x%llx",
			ui.add_bp_addr_buf,
			static_cast<unsigned long long>(addr));
		if (addr != 0) {
			int idx = debugger_engine::add_breakpoint(addr,
				debugger_engine::bp_type_t::hardware_execute, "", "", 1);
			diag::log_tagged_critical_fmt("bp",
				"bp_add_hw_exec addr=0x%llx idx=%d err='%s'",
				static_cast<unsigned long long>(addr),
				idx,
				debugger_engine::last_error().c_str());
			if (idx < 0) {
				toast_notification::push("Add HW BP failed: " +
					debugger_engine::last_error(),
					toast_notification::toast_type_t::error);
			} else {
				ui.add_bp_addr_buf[0] = '\0';
			}
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	ImGui::SameLine(0.f, btn_gap);

	bool clear_clicked = aida::ui::button("Clear All",
		aida::ui::button_kind_t::destructive,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (clear_clicked) {
		size_t before_n = debugger_engine::snapshot_breakpoints().size();
		debugger_engine::clear_all_breakpoints();
		diag::log_tagged_critical_fmt("bp",
			"bp_clear_all removed=%zu", before_n);
		toast_notification::push("Cleared all breakpoints.",
			toast_notification::toast_type_t::info);
	}

	ImGui::PopID();
}

static void render_breakpoints(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] breakpoints enter ok=1");
		}
	}

	float bar_h = 40.f;
	render_breakpoint_actions(dl, ox, oy, w, a);

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"State", 70.f}, {"Address", 170.f},
			{"Type", 110.f}, {"Hits", 70.f}, {"Name", 180.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 7, a);
	}

	std::vector<debugger_engine::breakpoint_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.bp_mutex);
		snapshot = st.breakpoints;
	}
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##bp_list");
	ImGui::BeginChild("##bp_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			ImGui::SetCursorScreenPos(ImVec2(ox, content_y + static_cast<float>(i) * ROW_HEIGHT
				- ImGui::GetScrollY()));
			ImVec2 row_min = ImGui::GetCursorScreenPos();
			ImGui::PushID(i);
			ImGui::InvisibleButton("##br", ImVec2(w - 18.f - 220.f, ROW_HEIGHT));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();

			float ry = row_min.y;
			auto& bp = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.bp_panel.selected == i);

			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char ibuf[8];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_dim, a), ibuf);

			bool enabled = (bp.state == debugger_engine::bp_state_t::enabled);
			ImU32 dot_col = enabled ? t.success : t.error;
			float dot_pulse = enabled ? aida::ui::clock::pulse(1.4f, 0.55f, 1.f) : 0.55f;
			dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 5.f,
			                    with_a(dot_col, a * 0.20f), 16);
			dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 3.f,
			                    with_a(dot_col, a * dot_pulse), 16);

			const char* state_str = enabled ? "ON" : "OFF";
			ImU32 pcol = enabled ? t.info : t.text_secondary;
			ImVec2 sts = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, state_str);
			float pw = sts.x + 14.f;
			float ph = 16.f;
			float pyy = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 50.f, pyy),
			                  ImVec2(ox + 50.f + pw, pyy + ph),
			                  with_a(pcol, a * 0.25f), ph * 0.5f);
			dl->AddRect(ImVec2(ox + 50.f, pyy),
			            ImVec2(ox + 50.f + pw, pyy + ph),
			            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
			dl->AddText(body_font, body_font->FontSize,
				ImVec2(ox + 57.f, pyy + (ph - 11.f) * 0.5f),
				with_a(pcol, a), state_str);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, bp.address);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 130.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);

			static const char* type_names[] = {"SW", "HW_EXEC", "HW_WRITE", "HW_READ", "MEM"};
			int ti = static_cast<int>(bp.type);
			if (ti < 0 || ti >= 5) ti = 0;
			ImU32 type_col = t.accent_u32;
			switch (ti) {
				case 0: type_col = t.text_secondary; break;
				case 1: type_col = t.accent_u32;     break;
				case 2: type_col = t.warning;        break;
				case 3: type_col = t.info;           break;
				case 4: type_col = t.success;        break;
			}
			const char* lbl = type_names[ti];
			ImVec2 tssz = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, lbl);
			float bw = tssz.x + 12.f;
			float bh = 16.f;
			float bx = ox + 300.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * 0.85f), 4.f);
			dl->AddText(body_font, body_font->FontSize,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				with_a(IM_COL32(255, 255, 255, 245), a), lbl);

			char hits_buf[16];
			std::snprintf(hits_buf, sizeof(hits_buf), "%d", bp.hit_count);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 420.f, ry + 5.f),
			            with_a(t.text_secondary, a), hits_buf);

			if (!bp.name.empty())
				dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 490.f, ry + 5.f),
				            with_a(t.text_primary, a), bp.name.c_str());

			float bp_act_btn_h = 18.f;
			float bp_act_btn_y = ry + (ROW_HEIGHT - bp_act_btn_h) * 0.5f;
			float bp_act_btn_w = 56.f;
			float bp_act_btn_gap = 4.f;
			float bp_act_x = ox + w - 218.f;

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x, bp_act_btn_y));
			ImGui::PushID(i + 0xC0000);
			bool bp_goto_clicked = aida::ui::button("Jump",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h));
			ImGui::PopID();
			if (bp_goto_clicked) {
				bool ok = jump_to_disasm(bp.address);
				diag::log_tagged_fmt("bp",
					"bp_jump idx=%d addr=0x%llx ok=%d",
					i,
					static_cast<unsigned long long>(bp.address),
					ok ? 1 : 0);
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] bp jump ok=1"
					: "[dbg_audit] bp jump fail reason=zero_addr");
			}

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x + (bp_act_btn_w + bp_act_btn_gap),
				bp_act_btn_y));
			ImGui::PushID(i + 0xC1000);
			bool bp_edit_clicked = aida::ui::button("Edit",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h));
			ImGui::PopID();
			if (bp_edit_clicked) {
				ui.bp_edit_idx = i;
				std::snprintf(ui.bp_edit_condition_buf,
					sizeof(ui.bp_edit_condition_buf), "%s", bp.condition.c_str());
				std::snprintf(ui.bp_edit_log_buf, sizeof(ui.bp_edit_log_buf),
					"%s", bp.log_text.c_str());
				ui.bp_edit_auto_continue = bp.auto_continue;
				ui.bp_edit_popup_open = true;
				anti_tamper::webhook::write_log("dbg_audit",
					"[dbg_audit] bp edit_open ok=1");
			}

			ImGui::SetCursorScreenPos(ImVec2(bp_act_x + (bp_act_btn_w + bp_act_btn_gap) * 2.f,
				bp_act_btn_y));
			ImGui::PushID(i + 0xC2000);
			bool bp_del_clicked = aida::ui::button("Del",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(bp_act_btn_w, bp_act_btn_h));
			ImGui::PopID();
			if (bp_del_clicked) {
				uint64_t addr_log = bp.address;
				bool ok = debugger_engine::remove_breakpoint(i);
				diag::log_tagged_critical_fmt("bp",
					"bp_remove_row idx=%d addr=0x%llx ok=%d err='%s'",
					i,
					static_cast<unsigned long long>(addr_log),
					ok ? 1 : 0,
					debugger_engine::last_error().c_str());
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] bp delete ok=1"
					: "[dbg_audit] bp delete fail reason=remove_failed");
				if (!ok) {
					toast_notification::push("Delete failed: " +
						debugger_engine::last_error(),
						toast_notification::toast_type_t::error);
				} else if (ui.bp_panel.selected == i) {
					ui.bp_panel.selected = -1;
				}
			}

			if (clicked) ui.bp_panel.selected = i;
			if (dclicked) {
				diag::log_tagged_fmt("bp",
					"bp_toggle idx=%d addr=0x%llx",
					i,
					static_cast<unsigned long long>(bp.address));
				bool ok = debugger_engine::toggle_breakpoint(i);
				diag::log_tagged_fmt("bp",
					"bp_toggle_done idx=%d ok=%d err='%s'",
					i,
					ok ? 1 : 0,
					debugger_engine::last_error().c_str());
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] bp toggle ok=1"
					: "[dbg_audit] bp toggle fail reason=toggle_failed");
			}
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(bp.address);
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Right))
				jump_to_disasm(bp.address);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::shield;
		es.title = "No breakpoints set";
		es.body  = "Type an address above and click Add to set a software breakpoint.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.bp_edit_popup_open) {
		ImGui::OpenPopup("Edit Breakpoint##bp");
		ui.bp_edit_popup_open = false;
	}
	if (ImGui::BeginPopupModal("Edit Breakpoint##bp", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize)) {
		if (ui.bp_edit_idx >= 0 &&
			ui.bp_edit_idx < static_cast<int>(snapshot.size())) {
			auto& bp_edit = snapshot[static_cast<size_t>(ui.bp_edit_idx)];
			ImGui::Text("Address: 0x%016llX",
				static_cast<unsigned long long>(bp_edit.address));
			ImGui::Text("Type:    %s",
				bp_edit.type == debugger_engine::bp_type_t::software ? "Software"
				: bp_edit.type == debugger_engine::bp_type_t::hardware_execute ? "HW Exec"
				: bp_edit.type == debugger_engine::bp_type_t::hardware_write   ? "HW Write"
				: bp_edit.type == debugger_engine::bp_type_t::hardware_read    ? "HW Read"
				: "Memory");
			ImGui::Separator();
			ImGui::Text("Condition (evaluated when hit, 0 = skip):");
			ImGui::SetNextItemWidth(360.f);
			ImGui::InputText("##bp_cond_edit", ui.bp_edit_condition_buf,
				sizeof(ui.bp_edit_condition_buf));
			ImGui::Text("Log message (use {RAX}, {[RSP+8]} placeholders):");
			ImGui::SetNextItemWidth(360.f);
			ImGui::InputText("##bp_log_edit", ui.bp_edit_log_buf,
				sizeof(ui.bp_edit_log_buf));
			ImGui::Checkbox("Auto-continue after log", &ui.bp_edit_auto_continue);
			ImGui::Separator();
			if (ImGui::Button("Apply", ImVec2(110.f, 0.f))) {
				bool ok_cond = debugger_engine::set_breakpoint_condition(
					ui.bp_edit_idx, ui.bp_edit_condition_buf);
				bool ok_log = debugger_engine::set_breakpoint_log(
					ui.bp_edit_idx, ui.bp_edit_log_buf, ui.bp_edit_auto_continue);
				diag::log_tagged_critical_fmt("bp",
					"bp_edit_apply idx=%d cond_ok=%d log_ok=%d cond='%s' log='%s' auto=%d",
					ui.bp_edit_idx,
					ok_cond ? 1 : 0,
					ok_log ? 1 : 0,
					ui.bp_edit_condition_buf,
					ui.bp_edit_log_buf,
					ui.bp_edit_auto_continue ? 1 : 0);
				anti_tamper::webhook::write_log("dbg_audit", (ok_cond && ok_log)
					? "[dbg_audit] bp edit_apply ok=1"
					: "[dbg_audit] bp edit_apply fail reason=engine_rejected");
				if (!ok_cond || !ok_log) {
					toast_notification::push(
						"Edit failed: " + debugger_engine::last_error(),
						toast_notification::toast_type_t::error);
				} else {
					toast_notification::push("Breakpoint updated.",
						toast_notification::toast_type_t::info);
				}
				ui.bp_edit_idx = -1;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel", ImVec2(110.f, 0.f))) {
				ui.bp_edit_idx = -1;
				ImGui::CloseCurrentPopup();
			}
		} else {
			ImGui::Text("Selection no longer valid.");
			if (ImGui::Button("Close", ImVec2(110.f, 0.f))) {
				ui.bp_edit_idx = -1;
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}
}


static void render_memmap(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	(void)dl;
	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] memmap enter ok=1");
		}
	}
	memory_map_view::render(ox, oy, w, h, a,
		aida::ui::resolved().accent.x,
		aida::ui::resolved().accent.y,
		aida::ui::resolved().accent.z);
}


static void render_callstack(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] callstack enter ok=1");
		}
	}

	if (driver_bridge::attached_pid() == 0) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process and pause it to capture a call stack.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	{
		static std::atomic<uint64_t> s_last_refresh_ms{0};
		static std::atomic<bool> s_in_flight{false};
		uint64_t now_ms = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
		uint64_t last = s_last_refresh_ms.load(std::memory_order_acquire);
		bool busy = s_in_flight.load(std::memory_order_acquire);
		if (!busy && now_ms - last > 500) {
			bool expected = false;
			if (s_in_flight.compare_exchange_strong(expected, true)) {
				work_queue::post([now_ms]() {
					debugger_engine::get_call_stack();
					s_last_refresh_ms.store(now_ms, std::memory_order_release);
					s_in_flight.store(false, std::memory_order_release);
				});
			}
		}
	}

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + HEADER_H),
	                  with_a(t.panel_header, a));
	ImFont* cap_font = aida::ui::fonts::caption();
	if (!cap_font) cap_font = ImGui::GetFont();
	dl->AddText(cap_font, cap_font->FontSize, ImVec2(ox + 12.f, oy + (HEADER_H - cap_font->FontSize) * 0.5f),
	            with_a(t.text_dim, a), "CALL STACK");
	const char* hint = "double-click to jump, right-click to copy address";
	ImVec2 hs = cap_font->CalcTextSizeA(cap_font->FontSize, FLT_MAX, 0.f, hint);
	dl->AddText(cap_font, cap_font->FontSize,
		ImVec2(ox + w - hs.x - 12.f, oy + (HEADER_H - cap_font->FontSize) * 0.5f),
		with_a(t.text_dim, a * 0.8f), hint);
	dl->AddLine(ImVec2(ox, oy + HEADER_H - 0.5f),
	            ImVec2(ox + w, oy + HEADER_H - 0.5f),
	            with_a(t.border_subtle, a));

	std::vector<debugger_engine::stack_frame_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.stack_mutex);
		snapshot = st.call_stack;
	}

	float card_pad = 10.f;
	float card_h = 56.f;
	float gap = 6.f;
	float row_h = card_h + gap;
	float content_y = oy + HEADER_H + card_pad;
	float visible_h = h - HEADER_H - card_pad * 2.f;
	int total_n = static_cast<int>(snapshot.size());

	std::map<std::string, int> recurse_count;
	for (const auto& f : snapshot)
		++recurse_count[f.module_name + "!" + f.function_name];

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##cs_list");
	ImGui::BeginChild("##cs_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* dim_font = aida::ui::fonts::caption();
	if (!dim_font) dim_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			auto& f = snapshot[static_cast<size_t>(i)];
			float cy = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();

			float card_x = ox + 12.f;
			float card_w = w - 36.f;

			ImGui::SetCursorScreenPos(ImVec2(card_x, cy));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##cs_card", ImVec2(card_w, card_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();

			bool sel = (ui.callstack_panel.selected == i);
			ImVec2 ca(card_x, cy);
			ImVec2 cb(card_x + card_w, cy + card_h);

			float lift = hov ? 2.f : 0.f;
			ca.y -= lift; cb.y -= lift;

			if (hov) {
				for (int g = 0; g < 4; ++g) {
					float spread = static_cast<float>(g + 1) * 1.5f;
					dl->AddRectFilled(
						ImVec2(ca.x - spread, ca.y - spread + 3.f),
						ImVec2(cb.x + spread, cb.y + spread + 3.f),
						IM_COL32(0, 0, 0, static_cast<int>(15 * a * (1.f - static_cast<float>(g) / 4.f))),
						8.f + spread);
				}
			}

			ImU32 fill = aida::ui::mix(t.panel_bg, t.accent_glow, hov ? 0.20f : 0.f);
			dl->AddRectFilled(ca, cb, with_a(fill, a * 0.95f), 8.f);
			dl->AddRectFilled(ca, cb, with_a(t.glass_tint, a * 0.55f), 8.f);
			ImU32 border = sel ? t.accent_u32 : t.border_subtle;
			dl->AddRect(ca, cb, with_a(border, a * (sel ? 0.95f : 0.7f)), 8.f, 0,
				sel ? 1.5f : 1.f);

			if (sel) {
				dl->AddRectFilled(ImVec2(ca.x, ca.y), ImVec2(ca.x + 3.f, cb.y),
				                  with_a(t.accent_u32, a), 1.f);
			}

			char idx_buf[12];
			std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i);
			dl->AddText(dim_font, dim_font->FontSize, ImVec2(ca.x + 12.f, ca.y + 8.f),
			            with_a(t.text_dim, a), idx_buf);

			std::string mod_label = f.module_name.empty() ? std::string("<unknown>") : f.module_name;
			dl->AddText(body_font, body_font->FontSize, ImVec2(ca.x + 44.f, ca.y + 6.f),
			            with_a(t.text_primary, a), mod_label.c_str());

			std::string func = f.function_name.empty() ? std::string("?") : f.function_name;
			char fn_buf[256];
			std::snprintf(fn_buf, sizeof(fn_buf), "%s + 0x%" PRIX64,
				func.c_str(), f.module_offset);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ca.x + 44.f, ca.y + 24.f),
			            with_a(t.syn_function, a), fn_buf);

			char abuf[24];
			std::snprintf(abuf, sizeof(abuf), "0x%016" PRIX64, f.address);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ca.x + 44.f, ca.y + 40.f),
			            with_a(t.text_address, a), abuf);

			std::string key = f.module_name + "!" + f.function_name;
			int rec = recurse_count[key];
			if (rec > 1) {
				char rec_buf[24];
				std::snprintf(rec_buf, sizeof(rec_buf), "x%d recursive", rec);
				ImVec2 rs = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, rec_buf);
				float rx = cb.x - rs.x - 22.f;
				float ry2 = ca.y + 6.f;
				dl->AddRectFilled(ImVec2(rx - 6.f, ry2 - 1.f),
				                  ImVec2(rx + rs.x + 6.f, ry2 + 14.f),
				                  with_a(t.warning, a * 0.18f), 4.f);
				dl->AddText(body_font, body_font->FontSize, ImVec2(rx, ry2),
				            with_a(t.warning, a), rec_buf);
			}

			if (clicked) ui.callstack_panel.selected = i;
			if (dclicked) jump_to_disasm(f.address);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(f.address);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::layers;
		es.title = "No call stack";
		es.body  = "Pause the target to capture the call stack.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_threads(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] threads enter ok=1");
		}
	}

	if (driver_bridge::attached_pid() == 0) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + h * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to enumerate, suspend, resume, or terminate its threads.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	{
		ui_anim::table_col_t cols[] = {
			{"TID", 90.f}, {"Priority", 80.f}, {"State", 110.f},
			{"RIP", 200.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 5, a);
	}

	debugger_engine::request_thread_refresh(250);
	auto threads = debugger_engine::cached_thread_list();
	int total_n = static_cast<int>(threads.size());
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##th_list");
	ImGui::BeginChild("##th_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	float row_h = ROW_HEIGHT + 4.f;

	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int ti = clipper.DisplayStart; ti < clipper.DisplayEnd; ++ti) {
			float ry = content_y + static_cast<float>(ti) * row_h - ImGui::GetScrollY();

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(ti);
			ImGui::InvisibleButton("##th_row", ImVec2(w - 18.f - 280.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();

			auto& th = threads[static_cast<size_t>(ti)];
			bool sel = (ui.threads_panel.selected == ti);

			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, ti, 1.f, a);

			if (ti < 256 && th.state != ui.prev_thread_state[ti]) {
				ui.thread_state_flash[ti] = 1.f;
				ui.prev_thread_state[ti] = th.state;
			}
			if (ti < 256)
				ui_anim::decay_flash(ui.thread_state_flash[ti], 1.5f, dt);

			char tbuf[12];
			std::snprintf(tbuf, sizeof(tbuf), "%u", th.tid);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 8.f, ry + 7.f),
			            with_a(t.text_address, a), tbuf);

			char prbuf[12];
			std::snprintf(prbuf, sizeof(prbuf), "%d", th.priority);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 100.f, ry + 7.f),
			            with_a(t.text_secondary, a), prbuf);

			const char* state_str;
			ImU32 pcol = t.text_secondary;
			switch (th.state) {
				case 0: state_str = "INITIALIZED"; pcol = t.info;    break;
				case 1: state_str = "READY";       pcol = t.info;    break;
				case 2: state_str = "RUNNING";     pcol = t.success; break;
				case 3: state_str = "STANDBY";     pcol = t.info;    break;
				case 4: state_str = "TERMINATED";  pcol = t.error;   break;
				case 5: state_str = "WAITING";     pcol = t.warning; break;
				case 6: state_str = "TRANSITION";  pcol = t.warning; break;
				default: state_str = "UNKNOWN";    pcol = t.text_secondary; break;
			}
			ImVec2 ss = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, state_str);
			float pw = ss.x + 22.f;
			float ph = 16.f;
			float pyy = ry + (row_h - ph) * 0.5f;
			float px = ox + 180.f;
			dl->AddRectFilled(ImVec2(px, pyy), ImVec2(px + pw, pyy + ph),
			                  with_a(pcol, a * 0.22f), ph * 0.5f);
			dl->AddRect(ImVec2(px, pyy), ImVec2(px + pw, pyy + ph),
			            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
			float dot_pulse = (ti < 256) ? (0.5f + ui.thread_state_flash[ti] * 0.5f) : 0.55f;
			dot_pulse += aida::ui::clock::pulse(1.6f, 0.f, 0.4f);
			if (dot_pulse > 1.f) dot_pulse = 1.f;
			dl->AddCircleFilled(ImVec2(px + 9.f, pyy + ph * 0.5f), 3.f,
			                    with_a(pcol, a * dot_pulse), 14);
			dl->AddText(body_font, body_font->FontSize,
				ImVec2(px + 16.f, pyy + (ph - 11.f) * 0.5f),
				with_a(pcol, a), state_str);

			if (th.rip != 0) {
				char rbuf[20];
				std::snprintf(rbuf, sizeof(rbuf), "0x%016" PRIX64, th.rip);
				dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 300.f, ry + 7.f),
				            with_a(t.text_address, a * 0.85f), rbuf);
			}

			float actions_x = ox + 500.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			float btn_g = 4.f;

			float thread_btn_w = 48.f;
			ImGui::SetCursorScreenPos(ImVec2(actions_x, btn_y));
			ImGui::PushID(ti + 0x20000);
			bool susp = aida::ui::button("Susp", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h));
			ImGui::PopID();
			if (susp) {
				uint32_t prev = 0;
				bool ok = driver_bridge::suspend_thread(th.tid, &prev);
				diag::log_tagged_fmt("debugger",
					"thread_suspend tid=%u ok=%d prev_count=%u",
					static_cast<unsigned>(th.tid),
					ok ? 1 : 0,
					static_cast<unsigned>(prev));
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] threads suspend ok=1"
					: "[dbg_audit] threads suspend fail reason=driver_suspend_failed");
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + thread_btn_w + btn_g, btn_y));
			ImGui::PushID(ti + 0x30000);
			bool res = aida::ui::button("Res",
				aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h));
			ImGui::PopID();
			if (res) {
				uint32_t prev = 0;
				bool ok = driver_bridge::resume_thread(th.tid, &prev);
				diag::log_tagged_fmt("debugger",
					"thread_resume tid=%u ok=%d prev_count=%u",
					static_cast<unsigned>(th.tid),
					ok ? 1 : 0,
					static_cast<unsigned>(prev));
				anti_tamper::webhook::write_log("dbg_audit", ok
					? "[dbg_audit] threads resume ok=1"
					: "[dbg_audit] threads resume fail reason=driver_resume_failed");
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + (thread_btn_w + btn_g) * 2.f, btn_y));
			ImGui::PushID(ti + 0x31000);
			bool switch_clicked = aida::ui::button("Switch",
				aida::ui::button_kind_t::primary,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w + 12.f, btn_h));
			ImGui::PopID();
			if (switch_clicked) {
				debugger_engine::g_state.active_tid = th.tid;
				debugger_engine::invalidate_cache();
				diag::log_tagged_critical_fmt("debugger",
					"thread_switch_context tid=%u", static_cast<unsigned>(th.tid));
				anti_tamper::webhook::write_log("dbg_audit",
					"[dbg_audit] threads switch ok=1");
				toast_notification::push("Active thread context switched.",
					toast_notification::toast_type_t::info);
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + (thread_btn_w + btn_g) * 3.f + 8.f, btn_y));
			ImGui::PushID(ti + 0x32000);
			bool kill_clicked = aida::ui::button("Kill",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(thread_btn_w, btn_h));
			ImGui::PopID();
			if (kill_clicked) {
				ui.thread_kill_idx = ti;
				ui.thread_kill_tid = th.tid;
				ui.thread_kill_popup_open = true;
				anti_tamper::webhook::write_log("dbg_audit",
					"[dbg_audit] threads kill_request ok=1");
			}

			if (clicked) ui.threads_panel.selected = ti;
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right) && th.rip != 0)
				copy_addr_to_clipboard(th.rip);
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && th.rip != 0)
				jump_to_disasm(th.rip);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (threads.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::cpu;
		es.title = "No threads enumerated";
		es.body  = "Attach to a process to inspect its threads.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.thread_kill_popup_open) {
		ImGui::OpenPopup("Terminate Thread##th");
		ui.thread_kill_popup_open = false;
	}
	if (ImGui::BeginPopupModal("Terminate Thread##th", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::TextWrapped(
			"Terminate thread %u with exit code 0xDEAD?\nThis cannot be undone and may destabilise the target.",
			static_cast<unsigned>(ui.thread_kill_tid));
		ImGui::Separator();
		if (ImGui::Button("Terminate", ImVec2(130.f, 0.f))) {
			uint32_t target_tid = ui.thread_kill_tid;
			HANDLE th_handle = OpenThread(THREAD_TERMINATE, FALSE, target_tid);
			bool ok = false;
			DWORD gle = 0;
			if (th_handle != nullptr) {
				ok = TerminateThread(th_handle, 0xDEADu) != FALSE;
				if (!ok) gle = GetLastError();
				CloseHandle(th_handle);
			} else {
				gle = GetLastError();
			}
			diag::log_tagged_critical_fmt("debugger",
				"thread_kill tid=%u open_ok=%d term_ok=%d gle=%lu",
				static_cast<unsigned>(target_tid),
				th_handle != nullptr ? 1 : 0,
				ok ? 1 : 0,
				static_cast<unsigned long>(gle));
			anti_tamper::webhook::write_log("dbg_audit", ok
				? "[dbg_audit] threads kill ok=1"
				: "[dbg_audit] threads kill fail reason=open_or_terminate_failed");
			if (ok) {
				toast_notification::push("Thread terminated.",
					toast_notification::toast_type_t::info);
			} else {
				toast_notification::push("Terminate thread failed.",
					toast_notification::toast_type_t::error);
			}
			ui.thread_kill_idx = -1;
			ui.thread_kill_tid = 0;
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Cancel", ImVec2(130.f, 0.f))) {
			ui.thread_kill_idx = -1;
			ui.thread_kill_tid = 0;
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}


static void render_watches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] watches enter ok=1");
		}
	}

	if (driver_bridge::attached_pid() == 0) {
		float bar_h_local = 40.f;
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + bar_h_local + (h - bar_h_local) * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to evaluate register/memory watch expressions live.",
			ui_anim::callout_kind_t::info, t.accent.x, t.accent.y, t.accent.z, a);
	}

	float bar_h = 40.f;
	float input_w = w * 0.55f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##w_actions");
	aida::ui::input_text("##w_expr", ui.add_watch_buf, sizeof(ui.add_watch_buf),
		"watch: RAX, [RBX+0x10], or 0x...",
		false, ImVec2(input_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	bool add_clicked = aida::ui::button("Add Watch", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (add_clicked && ui.add_watch_buf[0]) {
		int idx = debugger_engine::add_watch(ui.add_watch_buf);
		diag::log_tagged_critical_fmt("watches",
			"watch_add expr='%s' idx=%d",
			ui.add_watch_buf, idx);
		ui.add_watch_buf[0] = '\0';
	}
	ImGui::SameLine(0.f, btn_gap);
	bool refresh_clicked = aida::ui::button("Refresh", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (refresh_clicked) {
		diag::log_tagged_fmt("watches", "watch_refresh_all_request");
		debugger_engine::refresh_watches();
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Expression", 220.f}, {"Resolved Address", 180.f},
			{"Value", 220.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 4, a);
	}

	std::vector<debugger_engine::watch_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.watch_mutex);
		snapshot = st.watches;
	}
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	auto regs = debugger_engine::cached_registers();

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##w_list");
	ImGui::BeginChild("##w_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	float row_h = ROW_HEIGHT + 4.f;
	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			auto& w_entry = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.watch_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##w_row", ImVec2(w - 18.f - 90.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();

			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, i, 1.f, a);

			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 10.f, ry + 7.f),
			            with_a(t.text_primary, a), w_entry.expression.c_str());

			bool deref = false;
			bool ok = false;
			uint64_t resolved = evaluate_watch_expression(w_entry.expression, regs, deref, ok);
			char addr_buf[32];
			if (ok) {
				std::snprintf(addr_buf, sizeof(addr_buf), "%s0x%016" PRIX64,
					deref ? "[*] " : "", resolved);
			} else {
				std::snprintf(addr_buf, sizeof(addr_buf), "?");
			}
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 230.f, ry + 7.f),
			            with_a(t.text_address, a), addr_buf);

			ImU32 vcol = w_entry.valid ? t.success : t.error;
			const char* value_text = w_entry.valid
				? w_entry.value.c_str()
				: (w_entry.error.empty() ? "<error>" : w_entry.error.c_str());
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 410.f, ry + 7.f),
			            with_a(vcol, a), value_text);

			float btn_x = ox + w - 84.f;
			float btn_w = 64.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
			ImGui::PushID(i + 0x40000);
			bool rm = aida::ui::button("Remove", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(btn_w, btn_h));
			ImGui::PopID();
			if (rm) {
				diag::log_tagged_fmt("watches",
					"watch_remove idx=%d expr='%s'",
					i, w_entry.expression.c_str());
				debugger_engine::remove_watch(i);
			}

			if (clicked) ui.watch_panel.selected = i;
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ok && resolved != 0)
				jump_to_hex(resolved, 256);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right) && ok)
				copy_addr_to_clipboard(resolved);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No watches added";
		es.body  = "Add expressions like RAX, [RSP+8], or absolute addresses to monitor.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_trace(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] trace enter ok=1");
		}
	}

	float bar_h = 40.f;
	float input_w = w * 0.40f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##tr_actions");
	aida::ui::input_text("##tr_filter", ui.trace_filter_buf, sizeof(ui.trace_filter_buf),
		"filter trace by mnemonic or hex address",
		false, ImVec2(input_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	bool tracing = st.tracing.load();
	bool trace_can_start = driver_bridge::attached_pid() != 0;
	bool start_clicked = aida::ui::button(tracing ? "Stop Trace" : "Start Trace",
		tracing ? aida::ui::button_kind_t::destructive : aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		!tracing && !trace_can_start);
	if (start_clicked) {
		if (tracing) {
			diag::log_tagged_critical_fmt("trace",
				"trace_stop_request prev_count=%zu",
				st.trace_log.size());
			debugger_engine::stop_trace();
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] trace stop ok=1");
		} else {
			diag::log_tagged_critical_fmt("trace",
				"trace_start_request max_depth=%d",
				st.trace_max_depth);
			bool ok = debugger_engine::start_trace();
			anti_tamper::webhook::write_log("dbg_audit", ok
				? "[dbg_audit] trace start ok=1"
				: "[dbg_audit] trace start fail reason=engine_rejected");
		}
	}
	ImGui::SameLine(0.f, btn_gap);
	bool clear_clicked = aida::ui::button("Clear",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (clear_clicked) {
		size_t before = 0;
		{
			std::lock_guard<std::mutex> lk(st.trace_mutex);
			before = st.trace_log.size();
			st.trace_log.clear();
		}
		diag::log_tagged_fmt("trace",
			"trace_clear removed=%zu", before);
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] trace clear ok=1");
	}
	ImGui::SameLine(0.f, btn_gap);
	bool export_clicked = aida::ui::button("Export",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (export_clicked) {
		std::vector<debugger_engine::trace_record_t> trace_copy;
		{
			std::lock_guard<std::mutex> lk(st.trace_mutex);
			trace_copy = st.trace_log;
		}
		if (trace_copy.empty()) {
			toast_notification::push("Trace is empty.",
				toast_notification::toast_type_t::warning);
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] trace export fail reason=empty");
		} else {
			char path_buf[MAX_PATH] = "trace.csv";
			static const char k_trace_filter[] =
				"CSV (*.csv)\0*.csv\0Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
			if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Export Trace",
					k_trace_filter,
					"csv",
					path_buf, sizeof(path_buf),
					"debugger_view::trace_export")) {
				std::ofstream ofs(path_buf, std::ios::trunc);
				if (ofs.is_open()) {
					ofs << "index,address,rip,rax,rcx,rdx,rsp,disasm\n";
					for (const auto& tr : trace_copy) {
						char line[512];
						std::snprintf(line, sizeof(line),
							"%d,0x%016llX,0x%016llX,0x%016llX,0x%016llX,0x%016llX,0x%016llX,",
							tr.index,
							static_cast<unsigned long long>(tr.address),
							static_cast<unsigned long long>(tr.regs.rip),
							static_cast<unsigned long long>(tr.regs.rax),
							static_cast<unsigned long long>(tr.regs.rcx),
							static_cast<unsigned long long>(tr.regs.rdx),
							static_cast<unsigned long long>(tr.regs.rsp));
						ofs << line;
						for (char c : tr.disasm_text) {
							if (c == ',' || c == '"' || c == '\n' || c == '\r') ofs.put(' ');
							else ofs.put(c);
						}
						ofs.put('\n');
					}
					ofs.close();
					diag::log_tagged_critical_fmt("trace",
						"trace_export count=%zu path='%s'",
						trace_copy.size(), path_buf);
					anti_tamper::webhook::write_log("dbg_audit",
						"[dbg_audit] trace export ok=1");
					char msg[MAX_PATH + 64];
					std::snprintf(msg, sizeof(msg),
						"Exported %zu trace records to %s",
						trace_copy.size(), path_buf);
					toast_notification::push(msg,
						toast_notification::toast_type_t::info);
				} else {
					anti_tamper::webhook::write_log("dbg_audit",
						"[dbg_audit] trace export fail reason=open_failed");
					toast_notification::push("Failed to open trace file for writing.",
						toast_notification::toast_type_t::error);
				}
			}
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {{"#", 60.f}, {"Address", 170.f}, {"Instruction", 360.f}};
		draw_table_header(dl, ox, table_y, w, cols, 3, a);
	}

	if (tracing) ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 1.f, 6.f, dt);
	else         ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 0.f, 4.f, dt);

	{
		const char* status = tracing ? "REC" : "STOPPED";
		ImU32 pcol = tracing ? t.error : t.text_secondary;
		ImFont* sf = aida::ui::fonts::body_em();
		if (!sf) sf = ImGui::GetFont();
		ImVec2 sts = sf->CalcTextSizeA(sf->FontSize, FLT_MAX, 0.f, status);
		float pw = sts.x + 32.f;
		float ph = 18.f;
		float px = ox + w - pw - 10.f;
		float py = table_y + (HEADER_H - ph) * 0.5f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(pcol, a * 0.22f), ph * 0.5f);
		dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);
		float pulse = aida::ui::clock::pulse(1.4f, 0.40f, 1.f);
		float dot_a = tracing ? pulse : 0.55f;
		float ring_progress = tracing ? aida::ui::clock::saw(2.0f) : 0.f;
		ImVec2 dc(px + 10.f, py + ph * 0.5f);
		dl->AddCircle(dc, 6.f, with_a(pcol, a * 0.30f), 18, 1.f);
		if (ring_progress > 0.001f) {
			float ang0 = -1.5707963f;
			float ang1 = ang0 + ring_progress * 6.2831853f;
			dl->PathArcTo(dc, 6.f, ang0, ang1, 24);
			dl->PathStroke(with_a(pcol, a), 0, 1.5f);
		}
		dl->AddCircleFilled(dc, 3.5f, with_a(pcol, a * dot_a), 16);
		dl->AddText(sf, sf->FontSize,
			ImVec2(px + 22.f, py + (ph - 11.f) * 0.5f),
			with_a(pcol, a), status);
	}

	std::vector<debugger_engine::trace_record_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.trace_mutex);
		snapshot.reserve(st.trace_log.size());
		std::string filter = ui.trace_filter_buf;
		std::string filt_l;
		for (char c : filter) filt_l.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
		for (auto& tr : st.trace_log) {
			if (filt_l.empty()) {
				snapshot.push_back(tr);
				continue;
			}
			std::string text_l;
			for (char c : tr.disasm_text) text_l.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
			char addr_buf[20];
			std::snprintf(addr_buf, sizeof(addr_buf), "%" PRIx64, tr.address);
			if (text_l.find(filt_l) != std::string::npos ||
				std::strstr(addr_buf, filt_l.c_str()) != nullptr) {
				snapshot.push_back(tr);
			}
		}
	}

	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##tr_list");
	ImGui::BeginChild("##tr_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ImGui::GetScrollY();
			auto& tr = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.trace_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##tr_row", ImVec2(w - 18.f, ROW_HEIGHT));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char ibuf[12];
			std::snprintf(ibuf, sizeof(ibuf), "%d", tr.index);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_dim, a), ibuf);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, tr.address);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 70.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 240.f, ry + 5.f),
			            with_a(t.text_primary, a), tr.disasm_text.c_str());

			if (clicked) ui.trace_panel.selected = i;
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				jump_to_disasm(tr.address);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(tr.address);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty() && !tracing) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::flow;
		es.title = "Trace not recording";
		es.body  = "Click Start Trace to capture executed instructions.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_strings(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] strings enter ok=1");
		}
	}

	bool scanning = st.strings_scanning.load(std::memory_order_acquire);
	bool cancel_pending = st.strings_cancel.load(std::memory_order_acquire);

	float bar_h = 40.f;
	float input_w = w * 0.45f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##s_actions");
	aida::ui::input_text("##s_filter", ui.string_filter, sizeof(ui.string_filter),
		"filter strings by substring",
		false, ImVec2(input_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	const char* btn_label = scanning
		? (cancel_pending ? "Cancelling..." : "Cancel Scan")
		: "Scan Strings";
	aida::ui::button_kind_t btn_kind = scanning
		? aida::ui::button_kind_t::destructive
		: aida::ui::button_kind_t::primary;
	bool scan_clicked = aida::ui::button(btn_label,
		btn_kind,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		cancel_pending, nullptr, scanning && !cancel_pending);
	if (scan_clicked) {
		if (scanning) {
			diag::log_tagged_critical_fmt("strings",
				"strings_cancel_request pages_so_far=%llu found_so_far=%llu",
				static_cast<unsigned long long>(st.strings_pages_scanned.load()),
				static_cast<unsigned long long>(st.strings_found_so_far.load()));
			debugger_engine::request_strings_cancel();
		} else {
			size_t min_len = static_cast<size_t>(std::max(2, ui.string_min_len));
			diag::log_tagged_critical_fmt("strings",
				"strings_scan_request min_length=%zu attached_pid=%u",
				min_len,
				static_cast<unsigned>(driver_bridge::attached_pid()));
			debugger_engine::find_strings_async(min_len);
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Address", 170.f}, {"String", 480.f}, {"Module", 140.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 3, a);
	}

	std::vector<debugger_engine::string_ref_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.strings_mutex);
		std::string filt;
		for (char c : std::string(ui.string_filter))
			filt.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
		snapshot.reserve(st.strings.size());
		for (auto& sr : st.strings) {
			if (filt.empty()) { snapshot.push_back(sr); continue; }
			std::string v_l;
			for (char c : sr.value) v_l.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
			if (v_l.find(filt) != std::string::npos)
				snapshot.push_back(sr);
		}
	}

	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##s_list");
	ImGui::BeginChild("##s_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ImGui::GetScrollY();
			auto& sr = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.strings_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##s_row", ImVec2(w - 18.f, ROW_HEIGHT));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char abuf[20];
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, sr.address);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);

			std::string display = sr.value;
			if (display.size() > 96) display = display.substr(0, 96) + "...";
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 180.f, ry + 5.f),
			            with_a(t.syn_string, a), display.c_str());

			if (!sr.module_name.empty())
				dl->AddText(body_font, body_font->FontSize, ImVec2(ox + w - 150.f, ry + 5.f),
				            with_a(t.text_dim, a), sr.module_name.c_str());

			if (clicked) ui.strings_panel.selected = i;
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				jump_to_hex(sr.address, 256);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(sr.address);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (scanning) {
		static float s_strings_spin_t = 0.f;
		s_strings_spin_t += ImGui::GetIO().DeltaTime * 5.f;
		float region_cx = ox + w * 0.5f;
		float region_cy = content_y + visible_h * 0.5f;
		ImU32 spin_col = with_a(t.accent_u32, a);
		ui_anim::render_spinner(dl, region_cx, region_cy - 18.f, 12.f, 2.5f,
			spin_col, s_strings_spin_t);

		uint64_t pages = st.strings_pages_scanned.load(std::memory_order_acquire);
		uint64_t found_count = st.strings_found_so_far.load(std::memory_order_acquire);
		char hdr_buf[96];
		std::snprintf(hdr_buf, sizeof(hdr_buf), "Scanning strings...");
		char prog_buf[160];
		std::snprintf(prog_buf, sizeof(prog_buf),
			"Scanning %llu pages... %llu strings found so far",
			static_cast<unsigned long long>(pages),
			static_cast<unsigned long long>(found_count));
		ImFont* body_font = aida::ui::fonts::body();
		if (!body_font) body_font = ImGui::GetFont();
		ImVec2 hdr_sz = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, hdr_buf);
		ImVec2 prog_sz = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, prog_buf);
		dl->AddText(body_font, body_font->FontSize,
			ImVec2(region_cx - hdr_sz.x * 0.5f, region_cy + 6.f),
			with_a(t.text_primary, a), hdr_buf);
		dl->AddText(body_font, body_font->FontSize,
			ImVec2(region_cx - prog_sz.x * 0.5f, region_cy + 6.f + hdr_sz.y + 4.f),
			with_a(t.text_dim, a), prog_buf);
	} else if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::search;
		es.title = "No strings indexed";
		es.body  = "Click Scan Strings to enumerate the target's printable strings.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_bookmarks(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] bookmarks enter ok=1");
		}
	}

	float bar_h = 40.f;
	float addr_w = w * 0.22f;
	float lbl_w  = w * 0.32f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##bm_actions");
	aida::ui::input_text("##bm_addr", ui.add_bookmark_buf, sizeof(ui.add_bookmark_buf),
		"0x... address",
		false, ImVec2(addr_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	aida::ui::input_text("##bm_label", ui.add_bookmark_label_buf,
		sizeof(ui.add_bookmark_label_buf),
		"label (optional)",
		false, ImVec2(lbl_w, bar_h - 8.f));
	ImGui::SameLine(0.f, btn_gap);
	bool add_clicked = aida::ui::button("Add Bookmark",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (add_clicked) {
		uint64_t addr = parse_hex_address(ui.add_bookmark_buf);
		diag::log_tagged_critical_fmt("bookmarks",
			"bookmark_add_request raw='%s' parsed_addr=0x%llx label='%s'",
			ui.add_bookmark_buf,
			static_cast<unsigned long long>(addr),
			ui.add_bookmark_label_buf);
		if (addr != 0) {
			debugger_engine::toggle_bookmark(addr);
			if (ui.add_bookmark_label_buf[0])
				debugger_engine::set_label(addr, ui.add_bookmark_label_buf);
			ui.add_bookmark_buf[0] = '\0';
			ui.add_bookmark_label_buf[0] = '\0';
		} else {
			toast_notification::push(
				"Enter a hexadecimal address (e.g. 0x140001234).",
				toast_notification::toast_type_t::warning);
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {{"#", 36.f}, {"Address", 200.f},
			{"Label", 280.f}, {"Actions", 0.f}};
		draw_table_header(dl, ox, table_y, w, cols, 4, a);
	}

	std::vector<uint64_t> snapshot;
	std::map<uint64_t, std::string> labels_snapshot;
	{
		std::lock_guard<std::mutex> lk(st.anno_mutex);
		snapshot = st.bookmarks;
		for (auto& kv : st.labels)
			labels_snapshot[kv.first] = kv.second.text;
	}
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##bm_list");
	ImGui::BeginChild("##bm_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	float row_h = ROW_HEIGHT + 4.f;
	ImGuiListClipper clipper;
	clipper.Begin(total_n, row_h);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * row_h - ImGui::GetScrollY();
			uint64_t addr = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.bookmark_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##bm_row", ImVec2(w - 18.f - 84.f, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			bool dclicked = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && hov;
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, row_h, sel, hov, i, 1.f, a);

			char ibuf[8], abuf[20];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 8.f, ry + 7.f),
			            with_a(t.text_dim, a), ibuf);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 46.f, ry + 7.f),
			            with_a(t.text_address, a), abuf);

			auto it = labels_snapshot.find(addr);
			if (it != labels_snapshot.end())
				dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 246.f, ry + 7.f),
				            with_a(t.text_primary, a), it->second.c_str());

			float btn_x = ox + w - 84.f;
			float btn_w = 64.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
			ImGui::PushID(i + 0x50000);
			bool rm = aida::ui::button("Remove", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(btn_w, btn_h));
			ImGui::PopID();
			if (rm) {
				diag::log_tagged_fmt("bookmarks",
					"bookmark_remove addr=0x%llx",
					static_cast<unsigned long long>(addr));
				debugger_engine::toggle_bookmark(addr);
			}

			if (clicked) ui.bookmark_panel.selected = i;
			if (dclicked) jump_to_disasm(addr);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(addr);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No bookmarks";
		es.body  = "Add a bookmark by entering an address above.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_handles(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] handles enter ok=1");
		}
	}

	float bar_h = 40.f;
	bool attached_handles = driver_bridge::attached_pid() != 0;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##h_actions");
	bool refresh_clicked = aida::ui::button("Enumerate Handles",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f),
		!attached_handles);
	if (refresh_clicked) {
		diag::log_tagged_critical_fmt("handles",
			"handles_enumerate_request attached_pid=%u",
			static_cast<unsigned>(driver_bridge::attached_pid()));
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] handles enumerate ok=1");
		work_queue::post([]() {
			debugger_engine::enumerate_handles();
			size_t n = 0;
			{
				std::lock_guard<std::mutex> lk(
					debugger_engine::g_state.handle_mutex);
				n = debugger_engine::g_state.handles.size();
			}
			diag::log_tagged_fmt("handles",
				"handles_enumerate_done count=%zu", n);
		});
	}
	ImGui::PopID();

	if (!attached_handles) {
		float cw = std::min(w - 40.f, 620.f);
		if (cw < 220.f) cw = std::max(220.f, w - 20.f);
		float cx = ox + (w - cw) * 0.5f;
		float cy = oy + bar_h + (h - bar_h) * 0.5f - 26.f;
		ui_anim::render_inline_callout(dl, cx, cy, cw, 52.f,
			"Attach to a process to enumerate or close its kernel handles.",
			ui_anim::callout_kind_t::warn, t.accent.x, t.accent.y, t.accent.z, a);
		return;
	}

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Handle", 110.f}, {"Type", 160.f}, {"Access", 110.f}, {"Name", 250.f}, {"Actions", 0.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 5, a);
	}

	std::vector<debugger_engine::handle_info_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(st.handle_mutex);
		snapshot = st.handles;
	}
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##h_list");
	ImGui::BeginChild("##h_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int hi = clipper.DisplayStart; hi < clipper.DisplayEnd; ++hi) {
			float ry = content_y + static_cast<float>(hi) * ROW_HEIGHT - ImGui::GetScrollY();
			auto& he = snapshot[static_cast<size_t>(hi)];
			bool sel = (ui.handle_panel.selected == hi);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(hi);
			ImGui::InvisibleButton("##h_row", ImVec2(w - 18.f - 90.f, ROW_HEIGHT));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, hi, 1.f, a);

			char hbuf[12];
			std::snprintf(hbuf, sizeof(hbuf), "0x%X", static_cast<unsigned>(he.handle));
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_primary, a), hbuf);

			ImU32 type_col = handle_type_color(he.type_name, t);
			ImVec2 ts = body_font->CalcTextSizeA(body_font->FontSize, FLT_MAX, 0.f, he.type_name.c_str());
			float bw = ts.x + 12.f;
			float bh = 16.f;
			float bx = ox + 120.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * 0.85f), 4.f);
			dl->AddText(body_font, body_font->FontSize,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				with_a(IM_COL32(255, 255, 255, 245), a),
				he.type_name.c_str());

			char acc_buf[16];
			std::snprintf(acc_buf, sizeof(acc_buf), "0x%08X", he.access);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 280.f, ry + 5.f),
			            with_a(t.text_secondary, a), acc_buf);

			float name_clip_w = w - 484.f;
			if (name_clip_w < 80.f) name_clip_w = 80.f;
			dl->PushClipRect(ImVec2(ox + 390.f, ry),
				ImVec2(ox + 390.f + name_clip_w, ry + ROW_HEIGHT), true);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 390.f, ry + 5.f),
			            with_a(t.text_primary, a), he.name.c_str());
			dl->PopClipRect();

			float hbtn_h = 18.f;
			float hbtn_y = ry + (ROW_HEIGHT - hbtn_h) * 0.5f;
			float hbtn_x = ox + w - 78.f;
			ImGui::SetCursorScreenPos(ImVec2(hbtn_x, hbtn_y));
			ImGui::PushID(hi + 0xC3000);
			bool close_clicked = aida::ui::button("Close",
				aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(60.f, hbtn_h));
			ImGui::PopID();
			if (close_clicked) {
				ui.handle_close_idx = hi;
				ui.handle_close_value = he.handle;
				ui.handle_close_type = he.type_name;
				ui.handle_close_name = he.name;
				ui.handle_close_popup_open = true;
				anti_tamper::webhook::write_log("dbg_audit",
					"[dbg_audit] handles close_request ok=1");
			}

			if (clicked) ui.handle_panel.selected = hi;
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_to_clipboard(he.name.c_str());
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::key;
		es.title = "No handles enumerated";
		es.body  = "Click Enumerate Handles to capture the target's handle table.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}

	if (ui.handle_close_popup_open) {
		ImGui::OpenPopup("Close Handle##hd");
		ui.handle_close_popup_open = false;
	}
	if (ImGui::BeginPopupModal("Close Handle##hd", nullptr,
		ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::TextWrapped(
			"Close handle 0x%X (%s) in target process?\nName: %s\n\nThis duplicates the handle into the host with DUPLICATE_CLOSE_SOURCE, releasing it inside the target. The target may crash if it relies on this handle.",
			static_cast<unsigned>(ui.handle_close_value),
			ui.handle_close_type.c_str(),
			ui.handle_close_name.empty() ? "(unnamed)" : ui.handle_close_name.c_str());
		ImGui::Separator();
		if (ImGui::Button("Close Handle", ImVec2(140.f, 0.f))) {
			uint64_t value = ui.handle_close_value;
			uint32_t target_pid = driver_bridge::attached_pid();
			HANDLE target_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, target_pid);
			bool ok = false;
			DWORD gle = 0;
			if (target_proc != nullptr) {
				HANDLE dup = nullptr;
				BOOL dup_ok = DuplicateHandle(target_proc,
					reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value)),
					GetCurrentProcess(), &dup, 0, FALSE,
					DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
				if (dup_ok) {
					if (dup != nullptr) CloseHandle(dup);
					ok = true;
				} else {
					gle = GetLastError();
				}
				CloseHandle(target_proc);
			} else {
				gle = GetLastError();
			}
			diag::log_tagged_critical_fmt("handles",
				"handles_close pid=%u handle=0x%llx ok=%d gle=%lu",
				static_cast<unsigned>(target_pid),
				static_cast<unsigned long long>(value),
				ok ? 1 : 0,
				static_cast<unsigned long>(gle));
			anti_tamper::webhook::write_log("dbg_audit", ok
				? "[dbg_audit] handles close ok=1"
				: "[dbg_audit] handles close fail reason=duplicate_close_failed");
			if (ok) {
				toast_notification::push("Handle closed in target.",
					toast_notification::toast_type_t::info);
				work_queue::post([]() { debugger_engine::enumerate_handles(); });
			} else {
				toast_notification::push("Close handle failed.",
					toast_notification::toast_type_t::error);
			}
			ui.handle_close_idx = -1;
			ui.handle_close_value = 0;
			ui.handle_close_type.clear();
			ui.handle_close_name.clear();
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Cancel", ImVec2(140.f, 0.f))) {
			ui.handle_close_idx = -1;
			ui.handle_close_value = 0;
			ui.handle_close_type.clear();
			ui.handle_close_name.clear();
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}


static void render_patches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	(void)t;

	{
		static bool s_logged_once = false;
		if (!s_logged_once) {
			s_logged_once = true;
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] patches enter ok=1");
		}
	}

	float bar_h = 40.f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##patches_actions");

	bool apply_sel_clicked = aida::ui::button("Apply Selected",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (apply_sel_clicked && ui.patches_panel.selected >= 0) {
		int sel = ui.patches_panel.selected;
		bool ok = code_patcher::apply_patch(sel);
		diag::log_tagged_critical_fmt("patches",
			"patches_apply_selected idx=%d ok=%d", sel, ok ? 1 : 0);
		anti_tamper::webhook::write_log("dbg_audit", ok
			? "[dbg_audit] patches apply ok=1"
			: "[dbg_audit] patches apply fail reason=apply_failed");
		if (!ok) {
			toast_notification::push("Apply patch failed.",
				toast_notification::toast_type_t::error);
		} else {
			toast_notification::push("Patch applied.",
				toast_notification::toast_type_t::info);
		}
	}
	ImGui::SameLine(0.f, btn_gap);

	bool revert_all_clicked = aida::ui::button("Revert All",
		aida::ui::button_kind_t::destructive,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (revert_all_clicked) {
		size_t before = 0;
		std::vector<code_patcher::patch_entry_t> sn;
		{
			std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
			before = code_patcher::g_state.patches.size();
			sn = code_patcher::g_state.patches;
		}
		size_t reverted = 0;
		for (int i = static_cast<int>(sn.size()) - 1; i >= 0; --i) {
			if (sn[static_cast<size_t>(i)].active) {
				if (code_patcher::toggle_patch(i)) reverted++;
			}
		}
		diag::log_tagged_critical_fmt("patches",
			"patches_revert_all total=%zu reverted=%zu",
			before, reverted);
		anti_tamper::webhook::write_log("dbg_audit",
			"[dbg_audit] patches revert_all ok=1");
		toast_notification::push("Reverted active patches.",
			toast_notification::toast_type_t::info);
	}
	ImGui::SameLine(0.f, btn_gap);

	bool remove_sel_clicked = aida::ui::button("Remove Selected",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (remove_sel_clicked && ui.patches_panel.selected >= 0) {
		int sel = ui.patches_panel.selected;
		uint64_t addr_log = 0;
		{
			std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
			if (sel < static_cast<int>(code_patcher::g_state.patches.size()))
				addr_log = code_patcher::g_state.patches[static_cast<size_t>(sel)].address;
		}
		bool ok = code_patcher::remove_patch(sel);
		diag::log_tagged_critical_fmt("patches",
			"patches_remove_selected idx=%d addr=0x%llx ok=%d",
			sel,
			static_cast<unsigned long long>(addr_log),
			ok ? 1 : 0);
		anti_tamper::webhook::write_log("dbg_audit", ok
			? "[dbg_audit] patches remove ok=1"
			: "[dbg_audit] patches remove fail reason=remove_failed");
		ui.patches_panel.selected = -1;
	}
	ImGui::SameLine(0.f, btn_gap);

	bool save_set_clicked = aida::ui::button("Save Patchset",
		aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (save_set_clicked) {
		std::vector<code_patcher::patch_entry_t> sn;
		{
			std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
			sn = code_patcher::g_state.patches;
		}
		if (sn.empty()) {
			toast_notification::push("No patches to save.",
				toast_notification::toast_type_t::warning);
			anti_tamper::webhook::write_log("dbg_audit",
				"[dbg_audit] patches save fail reason=empty");
		} else {
			char path_buf[MAX_PATH] = "patches.json";
			static const char k_patchset_filter[] =
				"JSON (*.json)\0*.json\0Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0";
			if (win32_dialog::show_save_file_dialog(g_hwnd,
					"Save Patchset",
					k_patchset_filter,
					"json",
					path_buf, sizeof(path_buf),
					"debugger_view::patches_save")) {
				std::ofstream ofs(path_buf, std::ios::trunc);
				if (ofs.is_open()) {
					ofs << "{\n  \"patches\": [\n";
					for (size_t i = 0; i < sn.size(); ++i) {
						const auto& p = sn[i];
						char line[256];
						std::snprintf(line, sizeof(line),
							"    {\n      \"index\": %zu,\n"
							"      \"address\": \"0x%016llX\",\n"
							"      \"timestamp\": %lld,\n"
							"      \"active\": %s,\n"
							"      \"description\": \"",
							i,
							static_cast<unsigned long long>(p.address),
							static_cast<long long>(p.timestamp),
							p.active ? "true" : "false");
						ofs << line;
						for (char c : p.description) {
							if (c == '"' || c == '\\') ofs.put('\\');
							if (c == '\n' || c == '\r') ofs.put(' ');
							else ofs.put(c);
						}
						ofs << "\",\n      \"original\": \""
							<< code_patcher::format_bytes(p.original_bytes)
							<< "\",\n      \"patched\": \""
							<< code_patcher::format_bytes(p.patched_bytes)
							<< "\"\n    }";
						if (i + 1 < sn.size()) ofs << ",";
						ofs << "\n";
					}
					ofs << "  ]\n}\n";
					ofs.close();
					diag::log_tagged_critical_fmt("patches",
						"patches_save_set count=%zu path='%s'",
						sn.size(), path_buf);
					anti_tamper::webhook::write_log("dbg_audit",
						"[dbg_audit] patches save ok=1");
					char msg[MAX_PATH + 64];
					std::snprintf(msg, sizeof(msg),
						"Saved %zu patches to %s",
						sn.size(), path_buf);
					toast_notification::push(msg,
						toast_notification::toast_type_t::info);
				} else {
					anti_tamper::webhook::write_log("dbg_audit",
						"[dbg_audit] patches save fail reason=open_failed");
					toast_notification::push("Failed to open patchset file.",
						toast_notification::toast_type_t::error);
				}
			}
		}
	}
	ImGui::PopID();

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"Address", 170.f}, {"Original", 200.f},
			{"Patched", 200.f}, {"Description", 220.f}, {"Active", 70.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 6, a);
	}

	std::vector<code_patcher::patch_entry_t> snapshot;
	{
		std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
		snapshot = code_patcher::g_state.patches;
	}
	int total_n = static_cast<int>(snapshot.size());
	float content_y = table_y + HEADER_H;
	float visible_h = h - bar_h - HEADER_H;

	ImGui::SetCursorScreenPos(ImVec2(ox, content_y));
	ImGui::PushID("##p_list");
	ImGui::BeginChild("##p_list_child", ImVec2(w, visible_h), false,
		ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_AlwaysVerticalScrollbar);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	ImGuiListClipper clipper;
	clipper.Begin(total_n, ROW_HEIGHT);
	while (clipper.Step()) {
		for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
			float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ImGui::GetScrollY();
			auto& p = snapshot[static_cast<size_t>(i)];
			bool sel = (ui.patches_panel.selected == i);

			ImGui::SetCursorScreenPos(ImVec2(ox, ry));
			ImGui::PushID(i);
			ImGui::InvisibleButton("##p_row", ImVec2(w - 80.f, ROW_HEIGHT));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
			ImGui::PopID();
			draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, 1.f, a);

			char ibuf[8], abuf[20];
			std::snprintf(ibuf, sizeof(ibuf), "%d", i);
			std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, p.address);
			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 8.f, ry + 5.f),
			            with_a(t.text_dim, a), ibuf);
			dl->AddText(code_font, code_font->FontSize, ImVec2(ox + 36.f, ry + 5.f),
			            with_a(t.text_address, a), abuf);

			std::string oh = code_patcher::format_bytes(p.original_bytes);
			std::string ph = code_patcher::format_bytes(p.patched_bytes);
			if (oh.size() > 22) oh = oh.substr(0, 22) + "...";
			if (ph.size() > 22) ph = ph.substr(0, 22) + "...";

			ImVec2 osz = code_font->CalcTextSizeA(code_font->FontSize, FLT_MAX, 0.f, oh.c_str());
			float bx = ox + 200.f;
			float by = ry + 3.f;
			dl->AddRectFilled(ImVec2(bx - 4.f, by),
			                  ImVec2(bx + osz.x + 8.f, by + 16.f),
			                  with_a(t.text_dim, a * 0.18f), 4.f);
			dl->AddText(code_font, code_font->FontSize, ImVec2(bx, ry + 5.f),
			            with_a(t.text_secondary, a), oh.c_str());

			ImVec2 psz = code_font->CalcTextSizeA(code_font->FontSize, FLT_MAX, 0.f, ph.c_str());
			float bx2 = ox + 400.f;
			ImU32 pc = p.active ? t.success : t.warning;
			dl->AddRectFilled(ImVec2(bx2 - 4.f, by),
			                  ImVec2(bx2 + psz.x + 8.f, by + 16.f),
			                  with_a(pc, a * 0.20f), 4.f);
			dl->AddText(code_font, code_font->FontSize, ImVec2(bx2, ry + 5.f),
			            with_a(pc, a), ph.c_str());

			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 600.f, ry + 5.f),
			            with_a(t.text_primary, a), p.description.c_str());

			bool active_state = p.active;
			float track_w = 28.f;
			float track_h = 14.f;
			float tx = ox + w - track_w - 16.f;
			float ty = ry + (ROW_HEIGHT - track_h) * 0.5f;
			ImGui::SetCursorScreenPos(ImVec2(tx, ty));
			ImGui::PushID(i + 0x70000);
			ImGui::InvisibleButton("##patch_tog", ImVec2(track_w, track_h));
			bool tog_clicked = ImGui::IsItemClicked();
			ImGui::PopID();
			ImU32 track_col = aida::ui::mix(t.panel_header, t.accent_u32, active_state ? 1.f : 0.f);
			dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + track_w, ty + track_h),
			                  with_a(track_col, a), track_h * 0.5f);
			float knob_r = (track_h - 4.f) * 0.5f;
			float knob_x = tx + 2.f + knob_r + (track_w - 4.f - knob_r * 2.f) * (active_state ? 1.f : 0.f);
			float knob_y = (ty + ty + track_h) * 0.5f;
			dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
			                    with_a(IM_COL32(255, 255, 255, 240), a), 16);
			if (tog_clicked) {
				diag::log_tagged_critical_fmt("patches",
					"patch_toggle idx=%d addr=0x%llx new_active=%d desc='%s'",
					i,
					static_cast<unsigned long long>(p.address),
					active_state ? 0 : 1,
					p.description.c_str());
				code_patcher::toggle_patch(i);
			}

			if (clicked) ui.patches_panel.selected = i;
			if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				jump_to_disasm(p.address);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				copy_addr_to_clipboard(p.address);
		}
	}
	clipper.End();

	ImGui::EndChild();
	ImGui::PopID();

	if (snapshot.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::flask;
		es.title = "No patches applied";
		es.body  = "Use the patcher to modify the target's code.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b) {
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##debugger_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	if (!analysis_session::has_active_target()) {
		ImVec2 wp_e = ImGui::GetWindowPos();
		aida::ui::no_target_overlay::render(wp_e, ImVec2(width, height),
			"No target attached",
			"The debugger needs a target. Launch a binary with full isolation, attach to a running process, or open a static file to inspect imports, exports and sections.",
			alpha, aida::ui::empty_state::glyph_t::shield);
		ImGui::EndChild();
		return;
	}

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float dt = aida::ui::clock::dt();

	auto& ui = g_ui;
	ui.content_fade = ui_anim::smooth_lerp(ui.content_fade, 1.f, 14.f, dt);
	ui.tab_animator.slide.tick(dt);

	{
		ImGuiIO& io = ImGui::GetIO();
		bool no_text_focus = !io.WantTextInput;
		bool ctrl = io.KeyCtrl;
		bool shift = io.KeyShift;
		uint32_t cur_pid = driver_bridge::attached_pid();
		debugger_engine::dbg_status_t cur_status = debugger_engine::g_state.status.load();
		bool running_now = (cur_status == debugger_engine::dbg_status_t::running);
		bool paused_now  = (cur_status == debugger_engine::dbg_status_t::paused
		                 || cur_status == debugger_engine::dbg_status_t::stepping);

		if (no_text_focus && !ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_f5 attached_pid=%u status=%d",
				static_cast<unsigned>(cur_pid),
				static_cast<int>(cur_status));
			if (cur_pid != 0) {
				bool ok = debugger_engine::run_target();
				diag::log_tagged_fmt("debugger",
					"hotkey_f5_run_target ok=%d err='%s'",
					ok ? 1 : 0,
					debugger_engine::last_error().c_str());
			} else if (!spawn_target_dialog::is_open()) {
				spawn_target_dialog::request_open();
			}
		}

		if (no_text_focus && shift && !ctrl &&
		    ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_shift_f5_stop attached_pid=%u",
				static_cast<unsigned>(cur_pid));
			if (cur_pid != 0) {
				HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, cur_pid);
				bool term = false;
				if (p != nullptr) {
					term = TerminateProcess(p, 0xDEADu) != FALSE;
					CloseHandle(p);
				}
				driver_bridge::detach();
				debugger_engine::g_state.status.store(
					debugger_engine::dbg_status_t::terminated);
				diag::log_tagged_fmt("debugger",
					"hotkey_shift_f5_done term_ok=%d",
					term ? 1 : 0);
			}
		}

		if (no_text_focus && ctrl && shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_ctrl_shift_f5_restart attached_pid=%u",
				static_cast<unsigned>(cur_pid));
			if (cur_pid != 0) {
				HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, cur_pid);
				if (p != nullptr) {
					TerminateProcess(p, 0xDEADu);
					CloseHandle(p);
				}
				driver_bridge::detach();
			}
			if (!spawn_target_dialog::is_open())
				spawn_target_dialog::request_open();
		}

		if (no_text_focus && !ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F6, false) && running_now) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_f6_pause attached_pid=%u",
				static_cast<unsigned>(cur_pid));
			bool ok = debugger_engine::pause_target();
			diag::log_tagged_fmt("debugger",
				"hotkey_f6_pause_done ok=%d err='%s'",
				ok ? 1 : 0,
				debugger_engine::last_error().c_str());
		}

		if (no_text_focus && !ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F10, false) && paused_now) {
			uint64_t pre_rip = debugger_engine::cached_registers().rip;
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_f10_step_over rip=0x%llx",
				static_cast<unsigned long long>(pre_rip));
			bool ok = debugger_engine::step_over();
			diag::log_tagged_fmt("debugger",
				"hotkey_f10_step_over_done ok=%d err='%s'",
				ok ? 1 : 0,
				debugger_engine::last_error().c_str());
		}

		if (no_text_focus && !ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F11, false) && paused_now) {
			uint64_t pre_rip = debugger_engine::cached_registers().rip;
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_f11_step_into rip=0x%llx",
				static_cast<unsigned long long>(pre_rip));
			bool ok = debugger_engine::step_into();
			diag::log_tagged_fmt("debugger",
				"hotkey_f11_step_into_done ok=%d err='%s'",
				ok ? 1 : 0,
				debugger_engine::last_error().c_str());
		}

		if (no_text_focus && shift && !ctrl &&
		    ImGui::IsKeyPressed(ImGuiKey_F11, false) && paused_now) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_shift_f11_step_out attached_pid=%u",
				static_cast<unsigned>(cur_pid));
			bool ok = debugger_engine::step_out();
			diag::log_tagged_fmt("debugger",
				"hotkey_shift_f11_step_out_done ok=%d err='%s'",
				ok ? 1 : 0,
				debugger_engine::last_error().c_str());
		}

		if (no_text_focus && ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F2, false) && cur_pid != 0) {
			diag::log_tagged_critical_fmt("debugger",
				"hotkey_ctrl_f2_detach attached_pid=%u",
				static_cast<unsigned>(cur_pid));
			driver_bridge::detach();
			debugger_engine::g_state.status.store(
				debugger_engine::dbg_status_t::idle);
		}

		if (no_text_focus && !ctrl && !shift &&
		    ImGui::IsKeyPressed(ImGuiKey_F9, false)) {
			uint64_t rip = debugger_engine::cached_registers().rip;
			if (rip != 0 && cur_pid != 0) {
				diag::log_tagged_critical_fmt("debugger",
					"hotkey_f9_bp_toggle rip=0x%llx",
					static_cast<unsigned long long>(rip));
				auto snap = debugger_engine::snapshot_breakpoints();
				int existing = -1;
				for (size_t bi = 0; bi < snap.size(); ++bi) {
					if (snap[bi].address == rip &&
					    snap[bi].type == debugger_engine::bp_type_t::software &&
					    !snap[bi].is_internal) {
						existing = static_cast<int>(bi);
						break;
					}
				}
				if (existing >= 0) {
					bool rm = debugger_engine::remove_breakpoint(existing);
					diag::log_tagged_fmt("bp",
						"hotkey_f9_remove idx=%d ok=%d err='%s'",
						existing,
						rm ? 1 : 0,
						debugger_engine::last_error().c_str());
				} else {
					int idx = debugger_engine::add_breakpoint(rip,
						debugger_engine::bp_type_t::software, "", "", 1);
					diag::log_tagged_fmt("bp",
						"hotkey_f9_add rip=0x%llx idx=%d err='%s'",
						static_cast<unsigned long long>(rip),
						idx,
						debugger_engine::last_error().c_str());
				}
			}
		}
	}

	float a = alpha * std::max(ui.content_fade, 0.3f);
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
	                  with_a(t.bg_base, alpha));

	render_tab_bar(dl, ox, oy, w, alpha);

	float content_y = oy + TAB_HEIGHT;
	float content_h = h - TAB_HEIGHT;

	float toolbar_y = content_y + 6.f;
	bool tab_uses_toolbar =
		ui.active_tab != sub_tab_t::memory_map &&
		ui.active_tab != sub_tab_t::modules &&
		ui.active_tab != sub_tab_t::seh_chain &&
		ui.active_tab != sub_tab_t::cfg;
	float panel_offset = 0.f;
	if (tab_uses_toolbar) {
		draw_run_toolbar(dl, ox, toolbar_y, w, alpha);
		panel_offset = TOOLBAR_H + 8.f;
	}

	float panel_y = content_y + panel_offset;
	float panel_h = content_h - panel_offset;

	float slide_t = ui.tab_animator.slide.eased();
	float slide_offset = (1.f - slide_t) * ui.tab_animator.direction * 28.f;
	if (slide_t >= 0.999f) slide_offset = 0.f;

	ImGui::PushClipRect(ImVec2(ox, panel_y), ImVec2(ox + w, panel_y + panel_h), true);
	float panel_x = ox + slide_offset;
	float panel_w = w;
	float content_alpha = a * (slide_t < 0.999f ? (0.4f + slide_t * 0.6f) : 1.f);

	switch (ui.active_tab) {
		case sub_tab_t::cpu:
			render_cpu(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::breakpoints:
			render_breakpoints(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::memory_map:
			render_memmap(dl, panel_x, content_y, panel_w, content_h, content_alpha);
			break;
		case sub_tab_t::call_stack:
			render_callstack(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::threads:
			render_threads(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::watches:
			render_watches(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::handles:
			render_handles(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::trace_log:
			render_trace(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::strings:
			render_strings(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::bookmarks:
			render_bookmarks(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::modules: {
			float mod_overlay_h = 60.f;
			render_modules_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			module_view::render(panel_x, content_y + mod_overlay_h,
				panel_w, content_h - mod_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		case sub_tab_t::patches:
			render_patches(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::seh_chain: {
			float seh_overlay_h = 60.f;
			render_seh_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			seh_view::render(panel_x, content_y + seh_overlay_h,
				panel_w, content_h - seh_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		case sub_tab_t::cfg: {
			float cfg_overlay_h = 40.f;
			render_cfg_overlay(dl, panel_x, content_y + 4.f, panel_w, content_alpha);
			cfg_view::render(panel_x, content_y + cfg_overlay_h,
				panel_w, content_h - cfg_overlay_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		}
		default:
			break;
	}
	ImGui::PopClipRect();

	ImGui::EndChild();

	spawn_target_dialog::render();
	spawn_target_dialog::result_t spawn_result;
	if (spawn_target_dialog::consume_result(spawn_result) && spawn_result.accepted) {
		run_target::launch_options_t opts = spawn_result.launch_options;
		opts.exe_path    = std::move(spawn_result.exe_path);
		opts.args        = std::move(spawn_result.args);
		opts.working_dir = std::move(spawn_result.working_dir);
		work_queue::post([opts]() {
			uint32_t new_pid = 0;
			run_target::launch_result_t lr{};
			bool ok = debugger_engine::spawn_and_attach_target(opts, &new_pid, &lr);
			std::wstring sandbox_dir_snapshot = lr.sandbox_dir;
			bool sandbox_registered = lr.sandbox_pid_registered;
			bool net_logger_registered = lr.net_logger_registered;
			bool integrity_lowered = lr.integrity_lowered;
			if (lr.thread_handle != 0) {
				CloseHandle(reinterpret_cast<HANDLE>(lr.thread_handle));
				lr.thread_handle = 0;
			}
			if (!sandbox_dir_snapshot.empty()) {
				spawn_target_dialog::detail::last_sandbox_dir() = sandbox_dir_snapshot;
			}
			if (!ok) {
				const std::string& err = debugger_engine::last_error();
				std::string msg = "Launch failed: ";
				msg += err.empty() ? "(no detail)" : err;
				toast_notification::push(msg,
					toast_notification::toast_type_t::error);
			} else if (opts.isolation == run_target::isolation_t::windows_sandbox) {
				toast_notification::push(
					"Launched Windows Sandbox session.",
					toast_notification::toast_type_t::success);
			} else if (opts.malware_safe_mode
			           || opts.isolation == run_target::isolation_t::malware_safe_desktop) {
				char ok_msg[256];
				std::snprintf(ok_msg, sizeof(ok_msg),
					"Launched PID %u in malware-safe mode (kernel_guard=%d, net_log=%d, il_lowered=%d)",
					static_cast<unsigned>(new_pid),
					sandbox_registered ? 1 : 0,
					net_logger_registered ? 1 : 0,
					integrity_lowered ? 1 : 0);
				toast_notification::push(ok_msg,
					toast_notification::toast_type_t::success);
			} else {
				char ok_msg[160];
				std::snprintf(ok_msg, sizeof(ok_msg),
					"Launched PID %u (%s isolation)",
					static_cast<unsigned>(new_pid),
					opts.isolation == run_target::isolation_t::appcontainer
						? "AppContainer" : "jobbed");
				toast_notification::push(ok_msg,
					toast_notification::toast_type_t::success);
			}
		});
	}
}

}
