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
#include "stealth_engine.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
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
#include "skeleton.hpp"
#include "fonts.hpp"
#include "hex_view.hpp"
#include "work_queue.hpp"
#include "toast_notification.hpp"
#include "../session/analysis_session.hpp"

#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
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

	static const char* tab_names[] = {
		"Breakpoints", "Memory Map", "Call Stack", "Threads",
		"Watches", "Handles", "Trace", "Strings", "Bookmarks",
		"Modules", "Patches", "SEH", "CFG"
	};

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + TAB_HEIGHT),
	                  with_a(t.bg_base, a));
	ui_anim::render_gradient_header(dl, ox, oy, w, TAB_HEIGHT,
		t.accent.x, t.accent.y, t.accent.z, a * 0.5f);

	int count = static_cast<int>(sub_tab_t::COUNT);
	float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
	float tab_positions[static_cast<int>(sub_tab_t::COUNT)];
	float total_tabs_w = 6.f;
	ImFont* tf = aida::ui::fonts::body_em();
	if (!tf) tf = ImGui::GetFont();
	for (int i = 0; i < count; ++i) {
		ImVec2 sz = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, tab_names[i]);
		tab_widths[i] = sz.x + 22.f;
		tab_positions[i] = total_tabs_w;
		total_tabs_w += tab_widths[i] + 2.f;
	}
	total_tabs_w += 6.f;

	float reserved = 240.f;
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

		int active_i = static_cast<int>(ui.active_tab);
		if (ui.tab_last_ensured != active_i) {
			float active_left = tab_positions[active_i] - ui.tab_scroll_x + ox;
			float active_right = active_left + tab_widths[active_i];
			if (active_left < ox + 10.f)
				ui.tab_target_scroll_x = tab_positions[active_i] - 10.f;
			else if (active_right > ox + visible_w - 10.f)
				ui.tab_target_scroll_x = tab_positions[active_i] + tab_widths[active_i] - visible_w + 10.f;
			ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
			ui.tab_last_ensured = active_i;
		}
	} else {
		ui.tab_scroll_x = 0.f;
		ui.tab_target_scroll_x = 0.f;
		ui.tab_last_ensured = -1;
	}

	ImGui::PushClipRect(ImVec2(ox, oy), ImVec2(ox + visible_w, oy + TAB_HEIGHT), true);

	int active_idx = static_cast<int>(ui.active_tab);
	float target_ul_x = ox + tab_positions[active_idx] - ui.tab_scroll_x + 6.f;
	float target_ul_w = tab_widths[active_idx] - 12.f;

	if (ui.underline_w < 0.01f) {
		ui.underline_x = target_ul_x;
		ui.underline_w = target_ul_w;
	}
	ui.underline_x = ui_anim::spring_interp(ui.underline_x, target_ul_x, ui.underline_vel, 280.f, 22.f, dt);
	ui.underline_w = ui_anim::smooth_lerp(ui.underline_w, target_ul_w, 16.f, dt);

	for (int i = 0; i < count; ++i) {
		auto tab = static_cast<sub_tab_t>(i);
		bool active = (ui.active_tab == tab);
		float tx = ox + tab_positions[i] - ui.tab_scroll_x;
		float tw = tab_widths[i];
		float ty = oy + 2.f;
		float th = TAB_HEIGHT - 4.f;

		if (tx + tw < ox || tx > ox + visible_w) continue;

		bool hov = ImGui::IsMouseHoveringRect(ImVec2(tx, ty), ImVec2(tx + tw, ty + th), false);

		float& tab_a = ui.tab_anim[i];
		float tab_target = active ? 1.f : (hov ? 0.55f : 0.f);
		tab_a = ui_anim::smooth_lerp(tab_a, tab_target, 14.f, dt);

		if (tab_a > 0.01f) {
			float ra = tab_a * a;
			ImU32 wash = aida::ui::mix(t.hover_wash, t.accent_glow, tab_a * 0.6f);
			dl->AddRectFilled(ImVec2(tx + 3.f, ty + 1.f),
			                  ImVec2(tx + tw - 3.f, ty + th - 1.f),
			                  with_a(wash, ra), 6.f);
		}

		ImVec2 ts = tf->CalcTextSizeA(tf->FontSize, FLT_MAX, 0.f, tab_names[i]);
		ImU32 col = active
			? with_a(t.accent_hover, a)
			: aida::ui::mix(t.text_secondary, t.text_primary, hov ? 0.6f : 0.f);
		col = with_a(col, a);

		dl->AddText(tf, tf->FontSize,
			ImVec2(tx + (tw - ts.x) * 0.5f, ty + (th - ts.y) * 0.5f),
			col, tab_names[i]);

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
		if (ui.tab_scroll_x > 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + static_cast<float>(f), oy),
					ImVec2(ox + static_cast<float>(f) + 1.f, oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
			}
		}
		float max_scroll = total_tabs_w - visible_w;
		if (ui.tab_scroll_x < max_scroll - 1.f) {
			for (int f = 0; f < 24; ++f) {
				float fa = (1.f - static_cast<float>(f) / 24.f) * 0.95f * a;
				dl->AddRectFilled(
					ImVec2(ox + visible_w - static_cast<float>(f) - 1.f, oy),
					ImVec2(ox + visible_w - static_cast<float>(f), oy + TAB_HEIGHT),
					with_a(t.bg_base, fa));
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
		bool stealth_active = stealth_engine::is_active();
		const char* stealth_label = stealth_active ? "Stealth ON" : "Stealth OFF";
		aida::ui::pill_kind_t kind = stealth_active
			? aida::ui::pill_kind_t::success
			: aida::ui::pill_kind_t::neutral;

		ImFont* sf = aida::ui::fonts::caption();
		if (!sf) sf = ImGui::GetFont();
		ImVec2 sz = sf->CalcTextSizeA(sf->FontSize, FLT_MAX, 0.f, stealth_label);
		float pad_x = 10.f;
		float pill_w = sz.x + pad_x * 2.f + 14.f;
		float pill_h = 18.f;
		float px = ox + w - pill_w - 8.f;
		float py = oy + (TAB_HEIGHT - pill_h) * 0.5f;

		ImGui::SetCursorScreenPos(ImVec2(px, py));
		ImGui::PushID("##stealth_pill");
		ImGui::InvisibleButton("##sp", ImVec2(pill_w, pill_h));
		bool stealth_hov = ImGui::IsItemHovered();
		bool stealth_click = ImGui::IsItemClicked();
		ImGui::PopID();

		ImU32 col;
		switch (kind) {
			case aida::ui::pill_kind_t::success: col = t.success; break;
			default:                             col = t.text_secondary; break;
		}
		float fa = stealth_hov ? 0.32f : 0.22f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pill_w, py + pill_h),
		                  with_a(col, a * fa), pill_h * 0.5f);
		dl->AddRect(ImVec2(px, py), ImVec2(px + pill_w, py + pill_h),
		            with_a(col, a * 0.55f), pill_h * 0.5f, 0, 1.f);
		float pulse = aida::ui::clock::pulse(1.4f, 0.55f, 1.f);
		dl->AddCircleFilled(ImVec2(px + pad_x, py + pill_h * 0.5f), 3.5f,
		                    with_a(col, a * (stealth_active ? pulse : 0.6f)), 14);
		dl->AddText(sf, sf->FontSize,
			ImVec2(px + pad_x + 8.f, py + (pill_h - 11.f) * 0.5f),
			with_a(col, a), stealth_label);

		if (stealth_click) {
			if (stealth_active) {
				stealth_engine::disable_stealth();
			} else {
				uint32_t pid = driver_bridge::attached_pid();
				if (pid != 0)
					stealth_engine::enable_stealth(pid);
			}
		}
	}
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

	float bar_h = 40.f;
	render_breakpoint_actions(dl, ox, oy, w, a);

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"State", 70.f}, {"Address", 170.f},
			{"Type", 110.f}, {"Hits", 70.f}, {"Name", 240.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 6, a);
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
			ImGui::InvisibleButton("##br", ImVec2(w - 18.f, ROW_HEIGHT));
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
}


static void render_memmap(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	(void)dl;
	memory_map_view::render(ox, oy, w, h, a,
		aida::ui::resolved().accent.x,
		aida::ui::resolved().accent.y,
		aida::ui::resolved().accent.z);
}


static void render_callstack(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

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
			ImGui::InvisibleButton("##th_row", ImVec2(w - 18.f - 180.f, row_h));
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
			float btn_w = 56.f;
			float btn_h = 22.f;
			float btn_y = ry + (row_h - btn_h) * 0.5f;
			float btn_g = 4.f;

			ImGui::SetCursorScreenPos(ImVec2(actions_x, btn_y));
			ImGui::PushID(ti + 0x20000);
			bool susp = aida::ui::button("Susp", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(btn_w, btn_h));
			ImGui::PopID();
			if (susp) {
				uint32_t prev = 0;
				bool ok = driver_bridge::suspend_thread(th.tid, &prev);
				diag::log_tagged_fmt("debugger",
					"thread_suspend tid=%u ok=%d prev_count=%u",
					static_cast<unsigned>(th.tid),
					ok ? 1 : 0,
					static_cast<unsigned>(prev));
			}

			ImGui::SetCursorScreenPos(ImVec2(actions_x + btn_w + btn_g, btn_y));
			ImGui::PushID(ti + 0x30000);
			bool res = aida::ui::button("Resume", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(btn_w + 6.f, btn_h));
			ImGui::PopID();
			if (res) {
				uint32_t prev = 0;
				bool ok = driver_bridge::resume_thread(th.tid, &prev);
				diag::log_tagged_fmt("debugger",
					"thread_resume tid=%u ok=%d prev_count=%u",
					static_cast<unsigned>(th.tid),
					ok ? 1 : 0,
					static_cast<unsigned>(prev));
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
}


static void render_watches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

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
	bool start_clicked = aida::ui::button(tracing ? "Stop Trace" : "Start Trace",
		tracing ? aida::ui::button_kind_t::destructive : aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (start_clicked) {
		if (tracing) {
			diag::log_tagged_critical_fmt("trace",
				"trace_stop_request prev_count=%zu",
				st.trace_log.size());
			debugger_engine::stop_trace();
		} else {
			diag::log_tagged_critical_fmt("trace",
				"trace_start_request max_depth=%d",
				st.trace_max_depth);
			debugger_engine::start_trace();
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

	float bar_h = 40.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##h_actions");
	bool refresh_clicked = aida::ui::button("Enumerate Handles",
		aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(0.f, bar_h - 8.f));
	if (refresh_clicked) {
		diag::log_tagged_critical_fmt("handles",
			"handles_enumerate_request attached_pid=%u",
			static_cast<unsigned>(driver_bridge::attached_pid()));
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

	float table_y = oy + bar_h;
	{
		ui_anim::table_col_t cols[] = {
			{"Handle", 110.f}, {"Type", 160.f}, {"Access", 110.f}, {"Name", 320.f}
		};
		draw_table_header(dl, ox, table_y, w, cols, 4, a);
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
			ImGui::InvisibleButton("##h_row", ImVec2(w - 18.f, ROW_HEIGHT));
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

			dl->AddText(body_font, body_font->FontSize, ImVec2(ox + 390.f, ry + 5.f),
			            with_a(t.text_primary, a), he.name.c_str());

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
}


static void render_patches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	(void)t;

	float bar_h = 40.f;
	float btn_gap = 6.f;
	ImGui::SetCursorScreenPos(ImVec2(ox + 8.f, oy + 2.f));
	ImGui::PushID("##patches_actions");

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
		ui.patches_panel.selected = -1;
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
		case sub_tab_t::modules:
			module_view::render(panel_x, content_y, panel_w, content_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		case sub_tab_t::patches:
			render_patches(dl, panel_x, panel_y, panel_w, panel_h, content_alpha);
			break;
		case sub_tab_t::seh_chain:
			seh_view::render(panel_x, content_y, panel_w, content_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
		case sub_tab_t::cfg:
			cfg_view::render(panel_x, content_y, panel_w, content_h,
				content_alpha, t.accent.x, t.accent.y, t.accent.z);
			break;
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
			bool ok = debugger_engine::spawn_and_attach_target(opts, &new_pid, nullptr);
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
