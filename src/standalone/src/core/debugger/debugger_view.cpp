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
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "empty_state.hpp"
#include "skeleton.hpp"
#include "fonts.hpp"

#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>
#include <cmath>

namespace debugger_view {

static constexpr float TAB_HEIGHT      = 32.f;
static constexpr float ROW_HEIGHT      = 22.f;
static constexpr float HEADER_H        = 24.f;
static constexpr float TOOLBAR_H       = 36.f;
static constexpr float TOOLBAR_BTN_W   = 38.f;
static constexpr float TOOLBAR_BTN_GAP = 4.f;

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

inline bool handle_list_scroll(float* scroll_y, float* target, float content_h,
                               float visible_h, float row_h, float ox, float oy,
                               float ow, float dt) {
	if (content_h <= visible_h) {
		*target = 0.f;
		*scroll_y = 0.f;
		return false;
	}
	if (ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + ow, oy + visible_h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			*target -= wheel * row_h * 3.f;
	}
	float max_sc = content_h - visible_h;
	if (max_sc < 0.f) max_sc = 0.f;
	if (*target < 0.f) *target = 0.f;
	if (*target > max_sc) *target = max_sc;
	*scroll_y = ui_anim::smooth_lerp(*scroll_y, *target, 16.f, dt);
	return true;
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
	dl->AddText(font, 11.f, ImVec2(x + 10.f, y + (HEADER_H - 11.f) * 0.5f),
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
		ImVec2 sz = font->CalcTextSizeA(11.f, FLT_MAX, 0.f, cols[i].label);
		dl->AddText(font, 11.f,
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

	toolbar_btn_t btns[6] = {
		{ "Run / Continue (F5)",    0, attached && (idle || paused), true  },
		{ "Pause (F6)",             1, attached && running,         false },
		{ "Step Over (F10)",        2, attached && paused,          false },
		{ "Step Into (F11)",        3, attached && paused,          false },
		{ "Step Out (Shift+F11)",   4, attached && paused,          false },
		{ "Stop (Shift+F5)",        5, attached && (running || paused), false },
	};

	float total_w = static_cast<float>(6) * TOOLBAR_BTN_W
	              + static_cast<float>(5) * TOOLBAR_BTN_GAP
	              + 16.f;
	float pad_y = (TOOLBAR_H - 28.f) * 0.5f;
	float bx = ox + w - total_w - 8.f;
	float by = oy + pad_y;

	ImVec2 a = ImVec2(bx - 6.f, by - 4.f);
	ImVec2 b = ImVec2(ox + w - 8.f, by + 28.f + 4.f);
	draw_glass_card(dl, a, b, 10.f, alpha);

	ImFont* font = aida::ui::fonts::body();
	if (!font) font = ImGui::GetFont();

	float dt = aida::ui::clock::dt();
	float pulse = running ? aida::ui::clock::pulse(1.5f, 0.f, 1.f) : 0.f;

	for (int i = 0; i < 6; ++i) {
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
			switch (i) {
				case 0: debugger_engine::run_target();    break;
				case 1: debugger_engine::pause_target();  break;
				case 2: debugger_engine::step_over();     break;
				case 3: debugger_engine::step_into();     break;
				case 4: debugger_engine::step_out();      break;
				case 5: debugger_engine::pause_target();  break;
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
		ImVec2 sl_sz = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, status_label);
		float sx = bx - sl_sz.x - 26.f;
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
		dl->AddText(sf, 11.f, ImVec2(sx + 14.f, sy + (16.f - 11.f) * 0.5f),
		            with_a(col, alpha), status_label);
	}
}

}

static void render_tab_bar(ImDrawList* dl, float ox, float oy, float w, float a) {
	const auto& t = aida::ui::resolved();
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();

	static const char* tab_names[] = {
		"CPU", "Breakpoints", "Memory Map", "Call Stack", "Threads",
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
		ImVec2 sz = tf->CalcTextSizeA(13.f, FLT_MAX, 0.f, tab_names[i]);
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
		float active_left = tab_positions[active_i] - ui.tab_scroll_x + ox;
		float active_right = active_left + tab_widths[active_i];
		if (active_left < ox + 10.f)
			ui.tab_target_scroll_x = tab_positions[active_i] - 10.f;
		else if (active_right > ox + visible_w - 10.f)
			ui.tab_target_scroll_x = tab_positions[active_i] + tab_widths[active_i] - visible_w + 10.f;
		ui.tab_target_scroll_x = std::clamp(ui.tab_target_scroll_x, 0.f, max_scroll);
	} else {
		ui.tab_scroll_x = 0.f;
		ui.tab_target_scroll_x = 0.f;
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

		ImVec2 ts = tf->CalcTextSizeA(13.f, FLT_MAX, 0.f, tab_names[i]);
		ImU32 col = active
			? with_a(t.accent_hover, a)
			: aida::ui::mix(t.text_secondary, t.text_primary, hov ? 0.6f : 0.f);
		col = with_a(col, a);

		dl->AddText(tf, 13.f,
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

	if (ui.underline_w > 0.5f) {
		float ul_y = oy + TAB_HEIGHT - 3.f;
		for (int g = 0; g < 3; ++g) {
			float spread = 2.f + static_cast<float>(g) * 2.f;
			float ga = (0.20f - static_cast<float>(g) * 0.06f) * a;
			dl->AddRectFilled(
				ImVec2(ui.underline_x - spread, ul_y - spread),
				ImVec2(ui.underline_x + ui.underline_w + spread, ul_y + 2.f + spread),
				with_a(t.accent_glow, ga * 4.f),
				3.f + static_cast<float>(g));
		}
		dl->AddRectFilledMultiColor(
			ImVec2(ui.underline_x, ul_y),
			ImVec2(ui.underline_x + ui.underline_w, ul_y + 2.5f),
			with_a(t.accent_grad_top, a),
			with_a(t.accent_grad_bot, a),
			with_a(t.accent_grad_bot, a),
			with_a(t.accent_grad_top, a));
	}

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
		ImVec2 sz = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, stealth_label);
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
		dl->AddText(sf, 11.f,
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


static void render_cpu(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	float dt = aida::ui::clock::dt();
	const auto& t = aida::ui::resolved();

	ui.panel_sep_phase += dt * 1.8f;
	if (ui.panel_sep_phase > 6.283185f) ui.panel_sep_phase -= 6.283185f;

	float left_w = w * 0.65f;
	float right_w = w - left_w;
	float top_h = h * 0.55f;
	float bot_h = h - top_h;

	auto draw_separator_v = [&](float sx, float sy, float sh) {
		float pulse = (sinf(ui.panel_sep_phase) * 0.5f + 0.5f) * 0.4f + 0.4f;
		ImU32 c = with_a(t.accent_dim, a * pulse * 0.6f);
		dl->AddLine(ImVec2(sx, sy), ImVec2(sx, sy + sh), c, 1.f);
	};
	auto draw_separator_h = [&](float sx, float sy, float sw) {
		float pulse = (sinf(ui.panel_sep_phase) * 0.5f + 0.5f) * 0.4f + 0.4f;
		ImU32 c = with_a(t.accent_dim, a * pulse * 0.6f);
		dl->AddLine(ImVec2(sx, sy), ImVec2(sx + sw, sy), c, 1.f);
	};

	debugger_engine::request_refresh(100);
	{
		float px = ox, py = oy, pw = left_w - 1.f, ph = top_h - 1.f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(t.bg_base, a));
		draw_panel_header(dl, px, py, pw, "DISASSEMBLY", a);

		auto regs = debugger_engine::cached_registers();
		uint64_t rip = regs.rip;

		if (rip != ui.prev_rip && rip != 0) {
			ui.rip_flash = 1.f;
			ui.prev_rip = rip;
		}
		ui_anim::decay_flash(ui.rip_flash, 3.f, dt);

		if (rip != 0) {
			debugger_engine::request_disasm_refresh(rip, 100);
			uint64_t base = 0;
			std::vector<uint8_t> code = debugger_engine::cached_disasm_window(base);
			if (!code.empty()) {
				std::vector<AsmInstr> insns;
				const uint8_t* data = code.data();
				int sz = static_cast<int>(code.size());
				int off = 0;
				while (off < sz && insns.size() < 128) {
					int remaining = sz - off;
					int avail = (remaining < 15) ? remaining : 15;
					insns.push_back(zydis_decode_one(data + off, avail, base + static_cast<uint64_t>(off)));
					off += insns.back().len;
				}

				float dy = py + HEADER_H;
				ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

				ImFont* code_font = aida::ui::fonts::code();
				if (!code_font) code_font = ImGui::GetFont();

				for (size_t i = 0; i < insns.size(); ++i) {
					float ry = dy + static_cast<float>(i) * ROW_HEIGHT;
					if (ry + ROW_HEIGHT < dy || ry > py + ph) continue;

					bool is_rip = (insns[i].addr == rip);
					bool sel = (ui.disasm_selected == static_cast<int>(i));

					if (is_rip) {
						float rip_a = 0.10f + ui.rip_flash * 0.12f;
						dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT),
						                  with_a(t.accent_glow, a * rip_a * 4.f));
						dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + 3.f, ry + ROW_HEIGHT),
						                  with_a(t.accent_u32, a * 0.95f));
						dl->AddTriangleFilled(
							ImVec2(px + 6.f, ry + 5.f),
							ImVec2(px + 6.f, ry + ROW_HEIGHT - 5.f),
							ImVec2(px + 13.f, ry + ROW_HEIGHT * 0.5f),
							with_a(t.accent_grad_top, a));

						if (ui.rip_flash > 0.01f) {
							for (int fg = 0; fg < 2; ++fg) {
								float fga = ui.rip_flash * (0.18f - static_cast<float>(fg) * 0.07f) * a;
								dl->AddRect(ImVec2(px - static_cast<float>(fg + 1),
								                    ry - static_cast<float>(fg + 1)),
								            ImVec2(px + pw + static_cast<float>(fg + 1),
								                    ry + ROW_HEIGHT + static_cast<float>(fg + 1)),
								            with_a(t.accent_glow, fga * 4.f),
								            2.f, 0, 1.f);
							}
						}
					} else {
						draw_row_bg(dl, px, ry, pw, ROW_HEIGHT, sel, false,
							static_cast<int>(i), 1.f, a);
					}

					char abuf[20];
					std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, insns[i].addr);
					dl->AddText(code_font, 12.f, ImVec2(px + 18.f, ry + 4.f),
					            with_a(t.text_address, a), abuf);

					char textbuf[164];
					if (insns[i].ops[0])
						std::snprintf(textbuf, sizeof(textbuf), "%s %s",
							insns[i].mnem, insns[i].ops);
					else
						std::snprintf(textbuf, sizeof(textbuf), "%s", insns[i].mnem);
					ImU32 mcol = insns[i].is_call ? t.error
						: (insns[i].is_branch ? t.warning : t.syn_keyword);
					dl->AddText(code_font, 12.f, ImVec2(px + 162.f, ry + 4.f),
					            with_a(mcol, a), textbuf);

					auto comment = debugger_engine::get_comment(insns[i].addr);
					if (!comment.empty()) {
						ImVec2 cs = code_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, comment.c_str());
						float cx = px + pw - cs.x - 10.f;
						dl->AddText(code_font, 11.f, ImVec2(cx, ry + 4.f),
						            with_a(t.syn_comment, a), comment.c_str());
					}

					bool hov = ImGui::IsMouseHoveringRect(ImVec2(px, ry),
						ImVec2(px + pw, ry + ROW_HEIGHT), false);
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
						arrow_col = with_a(t.error, a);
					else if (std::strcmp(insns[bi].mnem, "jmp") == 0)
						arrow_col = with_a(t.accent_u32, a);
					else
						arrow_col = with_a(t.success, a);

					ui_anim::render_branch_arrow(dl, px + 1.f, from_y, to_y, 13.f, arrow_col, 1.f);
				}

				ImGui::PopClipRect();
			}
		} else {
			aida::ui::empty_state::config_t es;
			es.glyph = aida::ui::empty_state::glyph_t::cpu;
			es.title = "No process attached";
			es.body  = "Attach to a process to view live disassembly.";
			aida::ui::empty_state::render(ImVec2(px, py + HEADER_H),
				ImVec2(pw, ph - HEADER_H), es);
		}
	}

	draw_separator_v(ox + left_w - 0.5f, oy, top_h);

	{
		float px = ox + left_w, py = oy, pw = right_w, ph = top_h - 1.f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(t.bg_base, a));
		draw_panel_header(dl, px, py, pw, "REGISTERS", a);

		auto regs = debugger_engine::cached_registers();
		struct reg_info { const char* name; uint64_t val; int idx; };
		reg_info regs_list[] = {
			{"RAX", regs.rax, 0}, {"RBX", regs.rbx, 1}, {"RCX", regs.rcx, 2}, {"RDX", regs.rdx, 3},
			{"RSI", regs.rsi, 4}, {"RDI", regs.rdi, 5}, {"RBP", regs.rbp, 6}, {"RSP", regs.rsp, 7},
			{"R8",  regs.r8,  8}, {"R9",  regs.r9,  9}, {"R10", regs.r10, 10}, {"R11", regs.r11, 11},
			{"R12", regs.r12, 12}, {"R13", regs.r13, 13}, {"R14", regs.r14, 14}, {"R15", regs.r15, 15},
			{"RIP", regs.rip, 16}, {"RFLAGS", regs.rflags, 17},
		};

		for (const auto& ri : regs_list) {
			auto& cell = ui.reg_cells[ri.idx];
			if (ri.val != ui.prev_regs[ri.idx]) {
				ui.reg_flash[ri.idx] = 1.f;
				ui.prev_regs[ri.idx] = ri.val;
				cell.target_value = ri.val;
				cell.change_anim = 1.f;
				cell.edge_intensity = 1.f;
			}
			ui_anim::decay_flash(ui.reg_flash[ri.idx], 2.f, dt);
			cell.change_anim = ui_anim::smooth_lerp(cell.change_anim, 0.f, 4.2f, dt);
			cell.edge_intensity = ui_anim::smooth_lerp(cell.edge_intensity, 0.f, 2.4f, dt);

			float roll_t = 1.f - cell.change_anim;
			float ease = aida::motion::ease::out_cubic(roll_t);
			if (ease >= 0.999f) cell.shown_value = cell.target_value;
		}

		float grid_x = px + 8.f;
		float grid_y = py + HEADER_H + 6.f;
		float gw = pw - 16.f;
		int cols = 2;
		float gap = 6.f;
		float cell_w = (gw - static_cast<float>(cols - 1) * gap) / static_cast<float>(cols);
		float cell_h = 36.f;

		ImFont* lbl_font = aida::ui::fonts::caption();
		if (!lbl_font) lbl_font = ImGui::GetFont();
		ImFont* val_font = aida::ui::fonts::code_em();
		if (!val_font) val_font = ImGui::GetFont();

		ImGui::PushClipRect(ImVec2(px, py + HEADER_H), ImVec2(px + pw, py + ph), true);

		for (int i = 0; i < 18; ++i) {
			const auto& ri = regs_list[i];
			int rr = i / cols;
			int cc = i % cols;
			float cx = grid_x + static_cast<float>(cc) * (cell_w + gap);
			float cy = grid_y + static_cast<float>(rr) * (cell_h + 4.f);
			if (cy + cell_h > py + ph) break;

			ImVec2 ca(cx, cy);
			ImVec2 cb(cx + cell_w, cy + cell_h);

			bool hov = ImGui::IsMouseHoveringRect(ca, cb, false);

			dl->AddRectFilled(ca, cb, with_a(t.panel_bg, a * 0.85f), 6.f);
			if (hov) {
				dl->AddRectFilled(ca, cb, with_a(t.hover_wash, a), 6.f);
			}
			dl->AddRect(ca, cb, with_a(t.border_subtle, a), 6.f, 0, 1.f);

			float edge = ui.reg_cells[ri.idx].edge_intensity;
			if (edge > 0.001f) {
				dl->AddRectFilled(ImVec2(ca.x, ca.y),
				                  ImVec2(ca.x + 2.f, cb.y),
				                  with_a(t.accent_u32, a * edge), 1.f);
				for (int g = 0; g < 3; ++g) {
					float spread = static_cast<float>(g + 1) * 1.5f;
					dl->AddRect(ImVec2(ca.x - spread, ca.y - spread),
					            ImVec2(cb.x + spread, cb.y + spread),
					            with_a(t.accent_glow,
						a * edge * (0.32f - static_cast<float>(g) * 0.10f) * 4.f),
					            6.f + spread, 0, 1.f);
				}
			}

			dl->AddText(lbl_font, 11.f, ImVec2(ca.x + 8.f, ca.y + 4.f),
			            with_a(t.text_dim, a), ri.name);

			char vbuf[20];
			std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, ri.val);
			float roll_anim = ui.reg_cells[ri.idx].change_anim;
			float vy = ca.y + 17.f - roll_anim * 6.f;
			float val_alpha = a * (1.f - roll_anim * 0.3f);

			ImU32 vcol = (edge > 0.01f)
				? aida::ui::mix(t.accent_grad_top, t.text_primary, 1.f - edge)
				: t.syn_register;

			dl->AddText(val_font, 13.f, ImVec2(ca.x + 8.f, vy),
			            with_a(vcol, val_alpha), vbuf);

			if (roll_anim > 0.01f) {
				char prev_buf[20];
				std::snprintf(prev_buf, sizeof(prev_buf), "%016" PRIX64,
					ui.reg_cells[ri.idx].shown_value);
				float py2 = ca.y + 17.f + (1.f - roll_anim) * 6.f;
				dl->AddText(val_font, 13.f, ImVec2(ca.x + 8.f, py2),
				            with_a(t.text_dim, a * roll_anim * 0.5f), prev_buf);
			}
		}

		ImGui::PopClipRect();
	}

	draw_separator_h(ox, oy + top_h - 0.5f, left_w);

	{
		float px = ox, py = oy + top_h, pw = left_w - 1.f, ph = bot_h;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(t.bg_base, a));
		draw_panel_header(dl, px, py, pw, "MEMORY DUMP", a);

		uint64_t dump_addr = ui.dump_address;
		if (dump_addr == 0) {
			auto regs = debugger_engine::cached_registers();
			dump_addr = regs.rsp;
		}

		if (dump_addr != 0) {
			int rows = static_cast<int>((ph - HEADER_H - ROW_HEIGHT) / ROW_HEIGHT);
			size_t bytes_per_row = 16;
			size_t total_bytes = static_cast<size_t>(rows) * bytes_per_row;

			debugger_engine::request_dump_refresh(dump_addr, total_bytes, 100);
			uint64_t cached_addr = 0;
			size_t   cached_size = 0;
			std::vector<uint8_t> buf = debugger_engine::cached_dump_bytes(cached_addr, cached_size);
			if (cached_addr != dump_addr || cached_size != total_bytes)
				buf.clear();

			static std::vector<uint8_t> prev_dump;
			static std::vector<float> dump_byte_flash;
			static std::vector<float> dump_row_flash;
			static uint64_t prev_dump_addr = 0;

			float ddt = aida::ui::clock::dt();
			if (prev_dump_addr != dump_addr || prev_dump.size() != buf.size()) {
				prev_dump = buf;
				prev_dump_addr = dump_addr;
				dump_byte_flash.assign(buf.size(), 0.f);
				dump_row_flash.assign(static_cast<size_t>(rows), 0.f);
			} else {
				for (size_t di = 0; di < buf.size() && di < prev_dump.size(); ++di) {
					if (buf[di] != prev_dump[di]) {
						dump_byte_flash[di] = 1.f;
						size_t row_idx = di / bytes_per_row;
						if (row_idx < dump_row_flash.size())
							dump_row_flash[row_idx] = 1.f;
						prev_dump[di] = buf[di];
					}
					ui_anim::decay_flash(dump_byte_flash[di], 1.5f, ddt);
				}
				for (auto& f : dump_row_flash)
					ui_anim::decay_flash(f, 0.5f, ddt);
			}

			float dy = py + HEADER_H;
			ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();

			{
				float hhx = px + 150.f;
				for (size_t c = 0; c < bytes_per_row; ++c) {
					char hc[4];
					std::snprintf(hc, sizeof(hc), "%X", static_cast<int>(c));
					dl->AddText(code_font, 11.f, ImVec2(hhx + 4.f, dy + 5.f),
					            with_a(t.text_dim, a), hc);
					hhx += 22.f;
					if (c == 7) hhx += 6.f;
				}
				dy += ROW_HEIGHT;
			}

			for (int r = 0; r < rows
			              && r * static_cast<int>(bytes_per_row) < static_cast<int>(buf.size()); ++r) {
				float ry = dy + static_cast<float>(r) * ROW_HEIGHT;

				float row_heat = (r < static_cast<int>(dump_row_flash.size()))
					? dump_row_flash[r] : 0.f;
				if (row_heat > 0.01f) {
					dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT),
					                  with_a(t.accent_glow, a * row_heat * 0.18f * 4.f));
				}

				char abuf[20];
				std::snprintf(abuf, sizeof(abuf), "%016" PRIX64,
					dump_addr + static_cast<uint64_t>(r) * bytes_per_row);
				dl->AddText(code_font, 12.f, ImVec2(px + 6.f, ry + 4.f),
				            with_a(t.text_address, a), abuf);

				float hx = px + 150.f;
				size_t off = static_cast<size_t>(r) * bytes_per_row;
				for (size_t b = 0; b < bytes_per_row && off + b < buf.size(); ++b) {
					size_t byte_idx = off + b;
					float bf = (byte_idx < dump_byte_flash.size()) ? dump_byte_flash[byte_idx] : 0.f;
					if (bf > 0.01f) {
						ImU32 flash_col = aida::ui::mix(t.warning, t.accent_u32, bf * 0.5f);
						dl->AddRectFilled(
							ImVec2(hx - 1.f, ry + 1.f),
							ImVec2(hx + 17.f, ry + ROW_HEIGHT - 1.f),
							with_a(flash_col, a * bf * 0.55f), 3.f);
					}
					char hbuf[4];
					std::snprintf(hbuf, sizeof(hbuf), "%02X", buf[off + b]);
					ImU32 byte_col = (bf > 0.01f)
						? aida::ui::mix(t.text_primary, t.accent_grad_top, bf)
						: t.text_primary;
					dl->AddText(code_font, 12.f, ImVec2(hx, ry + 4.f),
					            with_a(byte_col, a), hbuf);
					hx += 22.f;
					if (b == 7) hx += 6.f;
				}

				float ax = hx + 10.f;
				for (size_t b = 0; b < bytes_per_row && off + b < buf.size(); ++b) {
					char ch = (buf[off + b] >= 0x20 && buf[off + b] <= 0x7e)
						? static_cast<char>(buf[off + b]) : '.';
					char cbuf[2] = {ch, 0};
					dl->AddText(code_font, 12.f, ImVec2(ax, ry + 4.f),
					            with_a(t.text_secondary, a), cbuf);
					ax += 8.f;
				}
			}

			ImGui::PopClipRect();
		}
	}

	draw_separator_h(ox + left_w, oy + top_h - 0.5f, right_w);
	draw_separator_v(ox + left_w - 0.5f, oy + top_h, bot_h);

	{
		float px = ox + left_w, py = oy + top_h, pw = right_w, ph = bot_h;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(t.bg_base, a));
		draw_panel_header(dl, px, py, pw, "STACK", a);

		auto regs = debugger_engine::cached_registers();
		uint64_t rsp = regs.rsp;
		if (rsp != 0) {
			int rows = static_cast<int>((ph - HEADER_H) / ROW_HEIGHT);
			size_t total = static_cast<size_t>(rows) * 8;
			debugger_engine::request_stack_refresh(rsp, total, 100);
			uint64_t cached_rsp = 0;
			std::vector<uint8_t> buf = debugger_engine::cached_stack_bytes(cached_rsp);
			if (cached_rsp != rsp) buf.clear();

			float dy = py + HEADER_H;
			ImGui::PushClipRect(ImVec2(px, dy), ImVec2(px + pw, py + ph), true);

			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();

			for (int r = 0; r < rows && static_cast<size_t>(r) * 8 + 8 <= buf.size(); ++r) {
				float ry = dy + static_cast<float>(r) * ROW_HEIGHT;
				uint64_t addr = rsp + static_cast<uint64_t>(r) * 8;
				uint64_t val;
				std::memcpy(&val, buf.data() + static_cast<size_t>(r) * 8, 8);
				char abuf[20], vbuf[20];
				std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
				std::snprintf(vbuf, sizeof(vbuf), "%016" PRIX64, val);

				bool is_rsp = (r == 0);
				if (is_rsp) {
					dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + pw, ry + ROW_HEIGHT),
					                  with_a(t.accent_glow, a * 0.32f));
					dl->AddRectFilled(ImVec2(px, ry), ImVec2(px + 3.f, ry + ROW_HEIGHT),
					                  with_a(t.accent_u32, a));
				}

				dl->AddText(code_font, 12.f, ImVec2(px + 8.f, ry + 4.f),
				            with_a(t.text_address, a), abuf);
				dl->AddText(code_font, 12.f, ImVec2(px + 154.f, ry + 4.f),
				            with_a(t.text_primary, a), vbuf);
			}
			ImGui::PopClipRect();
		}
	}
}


static void render_breakpoints(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"State", 70.f}, {"Address", 170.f},
			{"Type", 110.f}, {"Name", 240.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 5, a);
	}

	std::lock_guard<std::mutex> lk(st.bp_mutex);
	float total = static_cast<float>(st.breakpoints.size()) * ROW_HEIGHT;
	float visible_h = h - HEADER_H;
	float content_y = oy + HEADER_H;

	handle_list_scroll(&ui.bp_panel.scroll_y, &ui.bp_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int i = 0; i < static_cast<int>(st.breakpoints.size()); ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.bp_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;
		auto& bp = st.breakpoints[static_cast<size_t>(i)];
		bool sel = (ui.bp_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		char ibuf[8];
		std::snprintf(ibuf, sizeof(ibuf), "%d", i);
		dl->AddText(body_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_dim, a * row_a), ibuf);

		bool enabled = (bp.state == debugger_engine::bp_state_t::enabled);
		ImU32 dot_col = enabled ? t.success : t.error;
		float dot_pulse = enabled ? aida::ui::clock::pulse(1.4f, 0.55f, 1.f) : 0.55f;
		dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 5.f,
		                    with_a(dot_col, a * row_a * 0.20f), 16);
		dl->AddCircleFilled(ImVec2(ox + 40.f, ry + ROW_HEIGHT * 0.5f), 3.f,
		                    with_a(dot_col, a * row_a * dot_pulse), 16);

		{
			const char* state_str = enabled ? "ON" : "OFF";
			ImU32 pcol = enabled ? t.info : t.text_secondary;
			ImVec2 sts = body_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, state_str);
			float pw = sts.x + 14.f;
			float ph = 16.f;
			float py = ry + (ROW_HEIGHT - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(ox + 50.f, py),
			                  ImVec2(ox + 50.f + pw, py + ph),
			                  with_a(pcol, a * row_a * 0.25f), ph * 0.5f);
			dl->AddRect(ImVec2(ox + 50.f, py),
			            ImVec2(ox + 50.f + pw, py + ph),
			            with_a(pcol, a * row_a * 0.55f), ph * 0.5f, 0, 1.f);
			dl->AddText(body_font, 11.f,
				ImVec2(ox + 57.f, py + (ph - 11.f) * 0.5f),
				with_a(pcol, a * row_a), state_str);
		}

		char abuf[20];
		std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, bp.address);
		dl->AddText(code_font, 12.f, ImVec2(ox + 100.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), abuf);

		static const char* type_names[] = {"SW", "HW_EXEC", "HW_WRITE", "HW_READ", "MEM"};
		static const aida::ui::pill_kind_t type_kinds[] = {
			aida::ui::pill_kind_t::neutral,
			aida::ui::pill_kind_t::accent,
			aida::ui::pill_kind_t::warning,
			aida::ui::pill_kind_t::info,
			aida::ui::pill_kind_t::success
		};
		int ti = static_cast<int>(bp.type);
		if (ti < 0) ti = 0;
		if (ti >= 5) ti = 0;
		ImU32 type_col;
		switch (type_kinds[ti]) {
			case aida::ui::pill_kind_t::accent:  type_col = t.accent_u32; break;
			case aida::ui::pill_kind_t::warning: type_col = t.warning;    break;
			case aida::ui::pill_kind_t::info:    type_col = t.info;       break;
			case aida::ui::pill_kind_t::success: type_col = t.success;    break;
			default:                             type_col = t.text_secondary; break;
		}
		{
			const char* lbl = type_names[ti];
			ImVec2 ts = body_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, lbl);
			float bw = ts.x + 12.f;
			float bh = 16.f;
			float bx = ox + 270.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * row_a * 0.85f), 4.f);
			ImU32 tx_col = with_a(IM_COL32(255, 255, 255, 245), a * row_a);
			dl->AddText(body_font, 11.f,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				tx_col, lbl);
		}

		if (!bp.name.empty())
			dl->AddText(body_font, 12.f, ImVec2(ox + 390.f, ry + 5.f),
			            with_a(t.text_primary, a * row_a), bp.name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.bp_panel.selected = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
			debugger_engine::toggle_breakpoint(i);
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.bp_panel.scroll_y, total, visible_h, a,
			ui.bp_panel.scrollbar_dragging, ui.bp_panel.scrollbar_drag_offset);
	}

	if (st.breakpoints.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::shield;
		es.title = "No breakpoints set";
		es.body  = "Double-click in the disassembly view to set a breakpoint.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_memmap(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	memory_map_view::render(ox, oy, w, h, a,
		aida::ui::resolved().accent.x,
		aida::ui::resolved().accent.y,
		aida::ui::resolved().accent.z);
}


static void render_callstack(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + HEADER_H),
	                  with_a(t.panel_header, a));
	ImFont* cap_font = aida::ui::fonts::caption();
	if (!cap_font) cap_font = ImGui::GetFont();
	dl->AddText(cap_font, 11.f, ImVec2(ox + 12.f, oy + (HEADER_H - 11.f) * 0.5f),
	            with_a(t.text_dim, a), "CALL STACK");
	dl->AddLine(ImVec2(ox, oy + HEADER_H - 0.5f),
	            ImVec2(ox + w, oy + HEADER_H - 0.5f),
	            with_a(t.border_subtle, a));

	std::lock_guard<std::mutex> lk(st.stack_mutex);

	float card_pad = 10.f;
	float card_h = 56.f;
	float gap = 6.f;
	float content_y = oy + HEADER_H + card_pad;
	float content_total = static_cast<float>(st.call_stack.size()) * (card_h + gap);
	float visible_h = h - HEADER_H - card_pad * 2.f;

	handle_list_scroll(&ui.callstack_panel.scroll_y, &ui.callstack_panel.target_scroll_y,
		content_total, visible_h, card_h + gap, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body_em();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	ImFont* dim_font = aida::ui::fonts::caption();
	if (!dim_font) dim_font = ImGui::GetFont();

	std::map<std::string, int> recurse_count;
	for (const auto& f : st.call_stack)
		++recurse_count[f.module_name + "!" + f.function_name];

	for (int i = 0; i < static_cast<int>(st.call_stack.size()); ++i) {
		auto& f = st.call_stack[static_cast<size_t>(i)];
		float cy = content_y + static_cast<float>(i) * (card_h + gap) - ui.callstack_panel.scroll_y;
		if (cy + card_h < content_y) continue;
		if (cy > content_y + visible_h) break;

		bool sel = (ui.callstack_panel.selected == i);
		float card_x = ox + 12.f;
		float card_w = w - 24.f;
		ImVec2 ca(card_x, cy);
		ImVec2 cb(card_x + card_w, cy + card_h);

		bool hov = ImGui::IsMouseHoveringRect(ca, cb, false);
		float row_a = ui_anim::render_row_entrance(i,
			aida::ui::clock::seconds(), 0.014f, 0.32f);
		float lift = hov ? 2.f : 0.f;
		ca.y -= lift; cb.y -= lift;

		if (hov) {
			for (int g = 0; g < 4; ++g) {
				float spread = static_cast<float>(g + 1) * 1.5f;
				dl->AddRectFilled(
					ImVec2(ca.x - spread, ca.y - spread + 3.f),
					ImVec2(cb.x + spread, cb.y + spread + 3.f),
					IM_COL32(0, 0, 0, static_cast<int>(15 * a * row_a * (1.f - static_cast<float>(g) / 4.f))),
					8.f + spread);
			}
		}

		ImU32 fill = aida::ui::mix(t.panel_bg, t.accent_glow, hov ? 0.20f : 0.f);
		dl->AddRectFilled(ca, cb, with_a(fill, a * row_a * 0.95f), 8.f);
		dl->AddRectFilled(ca, cb, with_a(t.glass_tint, a * row_a * 0.55f), 8.f);
		ImU32 border = sel ? t.accent_u32 : t.border_subtle;
		dl->AddRect(ca, cb, with_a(border, a * row_a * (sel ? 0.95f : 0.7f)), 8.f, 0,
			sel ? 1.5f : 1.f);

		if (sel) {
			dl->AddRectFilled(ImVec2(ca.x, ca.y), ImVec2(ca.x + 3.f, cb.y),
			                  with_a(t.accent_u32, a * row_a), 1.f);
		}

		char idx_buf[12];
		std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i);
		dl->AddText(dim_font, 11.f, ImVec2(ca.x + 12.f, ca.y + 8.f),
		            with_a(t.text_dim, a * row_a), idx_buf);

		std::string mod_label = f.module_name.empty() ? std::string("<unknown>") : f.module_name;
		dl->AddText(body_font, 13.f, ImVec2(ca.x + 44.f, ca.y + 6.f),
		            with_a(t.text_primary, a * row_a), mod_label.c_str());

		std::string func = f.function_name.empty() ? std::string("?") : f.function_name;
		char fn_buf[256];
		std::snprintf(fn_buf, sizeof(fn_buf), "%s + 0x%" PRIX64,
			func.c_str(), f.module_offset);
		dl->AddText(code_font, 12.f, ImVec2(ca.x + 44.f, ca.y + 24.f),
		            with_a(t.syn_function, a * row_a), fn_buf);

		char abuf[24];
		std::snprintf(abuf, sizeof(abuf), "0x%016" PRIX64, f.address);
		dl->AddText(code_font, 11.f, ImVec2(ca.x + 44.f, ca.y + 40.f),
		            with_a(t.text_address, a * row_a), abuf);

		std::string key = f.module_name + "!" + f.function_name;
		int rec = recurse_count[key];
		if (rec > 1) {
			char rec_buf[24];
			std::snprintf(rec_buf, sizeof(rec_buf), "x%d recursive", rec);
			ImVec2 rs = body_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, rec_buf);
			float rx = cb.x - rs.x - 22.f;
			float ry2 = ca.y + 6.f;
			dl->AddRectFilled(ImVec2(rx - 6.f, ry2 - 1.f),
			                  ImVec2(rx + rs.x + 6.f, ry2 + 14.f),
			                  with_a(t.warning, a * row_a * 0.18f), 4.f);
			dl->AddText(body_font, 11.f, ImVec2(rx, ry2),
			            with_a(t.warning, a * row_a), rec_buf);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.callstack_panel.selected = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(f.address, g_disasm);
		}
	}

	ImGui::PopClipRect();

	if (content_total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.callstack_panel.scroll_y, content_total, visible_h, a,
			ui.callstack_panel.scrollbar_dragging,
			ui.callstack_panel.scrollbar_drag_offset);
	}

	if (st.call_stack.empty()) {
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
			{"TID", 80.f}, {"Owner PID", 110.f}, {"Priority", 100.f},
			{"State", 110.f}, {"RIP", 200.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 5, a);
	}

	debugger_engine::request_thread_refresh(250);
	auto threads = debugger_engine::cached_thread_list();
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(threads.size()) * ROW_HEIGHT;

	handle_list_scroll(&ui.threads_panel.scroll_y, &ui.threads_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int ti = 0; ti < static_cast<int>(threads.size()); ++ti) {
		float ry = content_y + static_cast<float>(ti) * ROW_HEIGHT - ui.threads_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;

		auto& th = threads[static_cast<size_t>(ti)];
		bool sel = (ui.threads_panel.selected == ti);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(ti,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, ti, row_a, a);

		if (ti < 256 && th.state != ui.prev_thread_state[ti]) {
			ui.thread_state_flash[ti] = 1.f;
			ui.prev_thread_state[ti] = th.state;
		}
		if (ti < 256)
			ui_anim::decay_flash(ui.thread_state_flash[ti], 1.5f, dt);

		char tbuf[12];
		std::snprintf(tbuf, sizeof(tbuf), "%u", th.tid);
		dl->AddText(code_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), tbuf);

		char pbuf[12];
		std::snprintf(pbuf, sizeof(pbuf), "%u", th.owner_pid);
		dl->AddText(body_font, 12.f, ImVec2(ox + 90.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), pbuf);

		char prbuf[12];
		std::snprintf(prbuf, sizeof(prbuf), "%d", th.priority);
		dl->AddText(body_font, 12.f, ImVec2(ox + 200.f, ry + 5.f),
		            with_a(t.text_secondary, a * row_a), prbuf);

		const char* state_str;
		aida::ui::pill_kind_t kind;
		switch (th.state) {
			case 0: state_str = "INITIALIZED"; kind = aida::ui::pill_kind_t::info; break;
			case 1: state_str = "READY";       kind = aida::ui::pill_kind_t::info; break;
			case 2: state_str = "RUNNING";     kind = aida::ui::pill_kind_t::success; break;
			case 3: state_str = "STANDBY";     kind = aida::ui::pill_kind_t::info; break;
			case 4: state_str = "TERMINATED";  kind = aida::ui::pill_kind_t::error; break;
			case 5: state_str = "WAITING";     kind = aida::ui::pill_kind_t::warning; break;
			case 6: state_str = "TRANSITION";  kind = aida::ui::pill_kind_t::warning; break;
			default: state_str = "UNKNOWN";    kind = aida::ui::pill_kind_t::neutral; break;
		}
		ImU32 pcol;
		switch (kind) {
			case aida::ui::pill_kind_t::success: pcol = t.success; break;
			case aida::ui::pill_kind_t::warning: pcol = t.warning; break;
			case aida::ui::pill_kind_t::error:   pcol = t.error;   break;
			case aida::ui::pill_kind_t::info:    pcol = t.info;    break;
			default:                             pcol = t.text_secondary; break;
		}
		ImVec2 ss = body_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, state_str);
		float pw = ss.x + 22.f;
		float ph = 16.f;
		float py = ry + (ROW_HEIGHT - ph) * 0.5f;
		float px = ox + 290.f;
		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(pcol, a * row_a * 0.22f), ph * 0.5f);
		dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		            with_a(pcol, a * row_a * 0.55f), ph * 0.5f, 0, 1.f);
		float dot_pulse = (ti < 256) ? (0.5f + ui.thread_state_flash[ti] * 0.5f) : 0.55f;
		dot_pulse += aida::ui::clock::pulse(1.6f, 0.f, 0.4f);
		if (dot_pulse > 1.f) dot_pulse = 1.f;
		dl->AddCircleFilled(ImVec2(px + 9.f, py + ph * 0.5f), 3.f,
		                    with_a(pcol, a * row_a * dot_pulse), 14);
		dl->AddText(body_font, 11.f,
			ImVec2(px + 16.f, py + (ph - 11.f) * 0.5f),
			with_a(pcol, a * row_a), state_str);

		if (th.rip != 0) {
			char rbuf[20];
			std::snprintf(rbuf, sizeof(rbuf), "0x%016" PRIX64, th.rip);
			dl->AddText(code_font, 12.f, ImVec2(ox + 410.f, ry + 5.f),
			            with_a(t.text_address, a * row_a * 0.85f), rbuf);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.threads_panel.selected = ti;
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.threads_panel.scroll_y, total, visible_h, a,
			ui.threads_panel.scrollbar_dragging, ui.threads_panel.scrollbar_drag_offset);
	}

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
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {{"Expression", 220.f}, {"Type", 120.f}, {"Value", 280.f}};
		draw_table_header(dl, ox, oy, w, cols, 3, a);
	}

	std::lock_guard<std::mutex> lk(st.watch_mutex);
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(st.watches.size()) * ROW_HEIGHT;

	handle_list_scroll(&ui.watch_panel.scroll_y, &ui.watch_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int i = 0; i < static_cast<int>(st.watches.size()); ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.watch_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;
		auto& w_entry = st.watches[static_cast<size_t>(i)];
		bool sel = (ui.watch_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		dl->AddText(body_font, 12.f, ImVec2(ox + 10.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), w_entry.expression.c_str());
		dl->AddText(body_font, 12.f, ImVec2(ox + 230.f, ry + 5.f),
		            with_a(t.syn_type, a * row_a), w_entry.type.c_str());
		ImU32 vcol = w_entry.valid ? t.success : t.error;
		dl->AddText(code_font, 12.f, ImVec2(ox + 350.f, ry + 5.f),
		            with_a(vcol, a * row_a), w_entry.value.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.watch_panel.selected = i;
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.watch_panel.scroll_y, total, visible_h, a,
			ui.watch_panel.scrollbar_dragging, ui.watch_panel.scrollbar_drag_offset);
	}

	if (st.watches.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No watches added";
		es.body  = "Add expressions to monitor while the target is paused.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_trace(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {{"#", 60.f}, {"Address", 170.f}, {"Instruction", 360.f}};
		draw_table_header(dl, ox, oy, w, cols, 3, a);
	}

	bool tracing = st.tracing.load();
	if (tracing) ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 1.f, 6.f, dt);
	else         ui.record_pulse = ui_anim::smooth_lerp(ui.record_pulse, 0.f, 4.f, dt);

	{
		const char* status = tracing ? "REC" : "STOPPED";
		aida::ui::pill_kind_t kind = tracing
			? aida::ui::pill_kind_t::error
			: aida::ui::pill_kind_t::neutral;
		ImU32 pcol;
		switch (kind) {
			case aida::ui::pill_kind_t::error: pcol = t.error; break;
			default:                           pcol = t.text_secondary; break;
		}
		ImFont* sf = aida::ui::fonts::body_em();
		if (!sf) sf = ImGui::GetFont();
		ImVec2 sts = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, status);
		float pw = sts.x + 32.f;
		float ph = 18.f;
		float px = ox + w - pw - 10.f;
		float py = oy + (HEADER_H - ph) * 0.5f;

		dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		                  with_a(pcol, a * 0.22f), ph * 0.5f);
		dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		            with_a(pcol, a * 0.55f), ph * 0.5f, 0, 1.f);

		float pulse = aida::ui::clock::pulse(1.4f, 0.40f, 1.f);
		float dot_a = tracing ? pulse : 0.55f;
		float ring_progress = tracing
			? aida::ui::clock::saw(2.0f)
			: 0.f;
		ImVec2 dc(px + 10.f, py + ph * 0.5f);
		dl->AddCircle(dc, 6.f, with_a(pcol, a * 0.30f), 18, 1.f);
		if (ring_progress > 0.001f) {
			float ang0 = -1.5707963f;
			float ang1 = ang0 + ring_progress * 6.2831853f;
			dl->PathArcTo(dc, 6.f, ang0, ang1, 24);
			dl->PathStroke(with_a(pcol, a), 0, 1.5f);
		}
		dl->AddCircleFilled(dc, 3.5f, with_a(pcol, a * dot_a), 16);
		dl->AddText(sf, 11.f,
			ImVec2(px + 22.f, py + (ph - 11.f) * 0.5f),
			with_a(pcol, a), status);
	}

	std::lock_guard<std::mutex> lk(st.trace_mutex);
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(st.trace_log.size()) * ROW_HEIGHT;

	handle_list_scroll(&ui.trace_panel.scroll_y, &ui.trace_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	int total_n = static_cast<int>(st.trace_log.size());
	int first = static_cast<int>(ui.trace_panel.scroll_y / ROW_HEIGHT);
	if (first < 0) first = 0;
	int last = std::min(total_n, first + static_cast<int>(visible_h / ROW_HEIGHT) + 2);

	for (int i = first; i < last; ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.trace_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;

		auto& tr = st.trace_log[static_cast<size_t>(i)];
		bool sel = (ui.trace_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i - first,
			aida::ui::clock::seconds(), 0.010f, 0.28f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		char ibuf[12];
		std::snprintf(ibuf, sizeof(ibuf), "%d", tr.index);
		dl->AddText(body_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_dim, a * row_a), ibuf);

		char abuf[20];
		std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, tr.address);
		dl->AddText(code_font, 12.f, ImVec2(ox + 70.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), abuf);
		dl->AddText(code_font, 12.f, ImVec2(ox + 240.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), tr.disasm_text.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.trace_panel.selected = i;
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.trace_panel.scroll_y, total, visible_h, a,
			ui.trace_panel.scrollbar_dragging, ui.trace_panel.scrollbar_drag_offset);
	}

	if (st.trace_log.empty() && !tracing) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::flow;
		es.title = "Trace not recording";
		es.body  = "Start a trace to capture executed instructions.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_strings(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {
			{"Address", 170.f}, {"String", 480.f}, {"Module", 140.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 3, a);
	}

	std::lock_guard<std::mutex> lk(st.strings_mutex);
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(st.strings.size()) * ROW_HEIGHT;

	handle_list_scroll(&ui.strings_panel.scroll_y, &ui.strings_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	int total_n = static_cast<int>(st.strings.size());
	int first = static_cast<int>(ui.strings_panel.scroll_y / ROW_HEIGHT);
	if (first < 0) first = 0;
	int last = std::min(total_n, first + static_cast<int>(visible_h / ROW_HEIGHT) + 2);

	for (int i = first; i < last; ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.strings_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;

		auto& sr = st.strings[static_cast<size_t>(i)];
		bool sel = (ui.strings_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i - first,
			aida::ui::clock::seconds(), 0.010f, 0.28f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		char abuf[20];
		std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, sr.address);
		dl->AddText(code_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), abuf);

		std::string display = sr.value;
		if (display.size() > 96) display = display.substr(0, 96) + "...";
		dl->AddText(code_font, 12.f, ImVec2(ox + 180.f, ry + 5.f),
		            with_a(t.syn_string, a * row_a), display.c_str());

		if (!sr.module_name.empty())
			dl->AddText(body_font, 11.f, ImVec2(ox + w - 150.f, ry + 5.f),
			            with_a(t.text_dim, a * row_a), sr.module_name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.strings_panel.selected = i;
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.strings_panel.scroll_y, total, visible_h, a,
			ui.strings_panel.scrollbar_dragging, ui.strings_panel.scrollbar_drag_offset);
	}

	if (st.strings.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::search;
		es.title = "No strings indexed";
		es.body  = "Run the string scanner to enumerate the target's strings.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_bookmarks(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {{"#", 26.f}, {"Address", 170.f}, {"Label", 320.f}};
		draw_table_header(dl, ox, oy, w, cols, 3, a);
	}

	std::lock_guard<std::mutex> lk(st.anno_mutex);
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(st.bookmarks.size()) * ROW_HEIGHT;

	handle_list_scroll(&ui.bookmark_panel.scroll_y, &ui.bookmark_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int i = 0; i < static_cast<int>(st.bookmarks.size()); ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.bookmark_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;
		uint64_t addr = st.bookmarks[static_cast<size_t>(i)];
		bool sel = (ui.bookmark_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		char ibuf[8], abuf[20];
		std::snprintf(ibuf, sizeof(ibuf), "%d", i);
		std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, addr);
		dl->AddText(body_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_dim, a * row_a), ibuf);
		dl->AddText(code_font, 12.f, ImVec2(ox + 36.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), abuf);

		auto it = st.labels.find(addr);
		if (it != st.labels.end())
			dl->AddText(body_font, 12.f, ImVec2(ox + 200.f, ry + 5.f),
			            with_a(t.text_primary, a * row_a), it->second.text.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.bookmark_panel.selected = i;
		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(addr, g_disasm);
		}
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.bookmark_panel.scroll_y, total, visible_h, a,
			ui.bookmark_panel.scrollbar_dragging, ui.bookmark_panel.scrollbar_drag_offset);
	}

	if (st.bookmarks.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::dots;
		es.title = "No bookmarks";
		es.body  = "Add bookmarks from the disassembly view.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_handles(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& st = debugger_engine::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {
			{"Handle", 110.f}, {"Type", 160.f}, {"Name", 320.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 3, a);
	}

	std::lock_guard<std::mutex> lk(st.handle_mutex);
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	int total_n = static_cast<int>(st.handles.size());
	float total = static_cast<float>(total_n) * ROW_HEIGHT;

	handle_list_scroll(&ui.handle_panel.scroll_y, &ui.handle_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int hi = 0; hi < total_n; ++hi) {
		float ry = content_y + static_cast<float>(hi) * ROW_HEIGHT - ui.handle_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;

		auto& he = st.handles[static_cast<size_t>(hi)];
		bool sel = (ui.handle_panel.selected == hi);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(hi,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, hi, row_a, a);

		char hbuf[12];
		std::snprintf(hbuf, sizeof(hbuf), "0x%X", static_cast<unsigned>(he.handle));
		dl->AddText(code_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), hbuf);

		ImU32 type_col = handle_type_color(he.type_name, t);
		{
			ImVec2 ts = body_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, he.type_name.c_str());
			float bw = ts.x + 12.f;
			float bh = 16.f;
			float bx = ox + 120.f;
			float by = ry + (ROW_HEIGHT - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  with_a(type_col, a * row_a * 0.85f), 4.f);
			dl->AddText(body_font, 11.f,
				ImVec2(bx + 6.f, by + (bh - 11.f) * 0.5f),
				with_a(IM_COL32(255, 255, 255, 245), a * row_a),
				he.type_name.c_str());
		}

		dl->AddText(body_font, 12.f, ImVec2(ox + 290.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), he.name.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.handle_panel.selected = hi;
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.handle_panel.scroll_y, total, visible_h, a,
			ui.handle_panel.scrollbar_dragging, ui.handle_panel.scrollbar_drag_offset);
	}

	if (st.handles.empty()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::key;
		es.title = "No handles enumerated";
		es.body  = "Attach to a process to enumerate its handles.";
		aida::ui::empty_state::render(ImVec2(ox, content_y), ImVec2(w, visible_h), es);
	}
}


static void render_patches(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();
	float dt = aida::ui::clock::dt();

	{
		ui_anim::table_col_t cols[] = {
			{"#", 26.f}, {"Address", 170.f}, {"Original", 200.f},
			{"Patched", 200.f}, {"Description", 220.f}, {"Active", 70.f}
		};
		draw_table_header(dl, ox, oy, w, cols, 6, a);
	}

	std::lock_guard<std::mutex> plk(code_patcher::g_state.mtx);
	auto& patches = code_patcher::g_state.patches;
	int total_n = static_cast<int>(patches.size());
	float content_y = oy + HEADER_H;
	float visible_h = h - HEADER_H;
	float total = static_cast<float>(total_n) * ROW_HEIGHT;

	handle_list_scroll(&ui.patches_panel.scroll_y, &ui.patches_panel.target_scroll_y,
		total, visible_h, ROW_HEIGHT, ox, content_y, w, dt);

	ImGui::PushClipRect(ImVec2(ox, content_y), ImVec2(ox + w, content_y + visible_h), true);

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	for (int i = 0; i < total_n; ++i) {
		float ry = content_y + static_cast<float>(i) * ROW_HEIGHT - ui.patches_panel.scroll_y;
		if (ry + ROW_HEIGHT < content_y) continue;
		if (ry > content_y + visible_h) break;

		auto& p = patches[static_cast<size_t>(i)];
		bool sel = (ui.patches_panel.selected == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry),
			ImVec2(ox + w, ry + ROW_HEIGHT), false);
		float row_a = ui_anim::render_row_entrance(i,
			aida::ui::clock::seconds(), 0.012f, 0.30f);
		draw_row_bg(dl, ox, ry, w, ROW_HEIGHT, sel, hov, i, row_a, a);

		char ibuf[8], abuf[20];
		std::snprintf(ibuf, sizeof(ibuf), "%d", i);
		std::snprintf(abuf, sizeof(abuf), "%016" PRIX64, p.address);
		dl->AddText(body_font, 12.f, ImVec2(ox + 8.f, ry + 5.f),
		            with_a(t.text_dim, a * row_a), ibuf);
		dl->AddText(code_font, 12.f, ImVec2(ox + 36.f, ry + 5.f),
		            with_a(t.text_address, a * row_a), abuf);

		std::string oh = code_patcher::format_bytes(p.original_bytes);
		std::string ph = code_patcher::format_bytes(p.patched_bytes);
		if (oh.size() > 22) oh = oh.substr(0, 22) + "...";
		if (ph.size() > 22) ph = ph.substr(0, 22) + "...";

		{
			ImVec2 sz = code_font->CalcTextSizeA(12.f, FLT_MAX, 0.f, oh.c_str());
			float bx = ox + 200.f;
			float by = ry + 3.f;
			dl->AddRectFilled(ImVec2(bx - 4.f, by),
			                  ImVec2(bx + sz.x + 8.f, by + 16.f),
			                  with_a(t.text_dim, a * row_a * 0.18f), 4.f);
			dl->AddText(code_font, 12.f, ImVec2(bx, ry + 5.f),
			            with_a(t.text_secondary, a * row_a), oh.c_str());
		}
		{
			ImVec2 sz = code_font->CalcTextSizeA(12.f, FLT_MAX, 0.f, ph.c_str());
			float bx = ox + 400.f;
			float by = ry + 3.f;
			ImU32 pc = p.active ? t.success : t.warning;
			dl->AddRectFilled(ImVec2(bx - 4.f, by),
			                  ImVec2(bx + sz.x + 8.f, by + 16.f),
			                  with_a(pc, a * row_a * 0.20f), 4.f);
			dl->AddText(code_font, 12.f, ImVec2(bx, ry + 5.f),
			            with_a(pc, a * row_a), ph.c_str());
		}

		dl->AddText(body_font, 12.f, ImVec2(ox + 600.f, ry + 5.f),
		            with_a(t.text_primary, a * row_a), p.description.c_str());

		bool active_state = p.active;
		float track_w = 28.f;
		float track_h = 14.f;
		float tx = ox + w - track_w - 16.f;
		float ty = ry + (ROW_HEIGHT - track_h) * 0.5f;
		ImGui::SetCursorScreenPos(ImVec2(tx, ty));
		ImGui::PushID(i + 0x70000);
		ImGui::InvisibleButton("##patch_tog", ImVec2(track_w, track_h));
		bool clicked = ImGui::IsItemClicked();
		ImGui::PopID();
		ImU32 track_col = aida::ui::mix(t.panel_header, t.accent_u32, active_state ? 1.f : 0.f);
		dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + track_w, ty + track_h),
		                  with_a(track_col, a * row_a), track_h * 0.5f);
		float knob_r = (track_h - 4.f) * 0.5f;
		float knob_x = tx + 2.f + knob_r + (track_w - 4.f - knob_r * 2.f) * (active_state ? 1.f : 0.f);
		float knob_y = (ty + ty + track_h) * 0.5f;
		dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
		                    with_a(IM_COL32(255, 255, 255, 240), a * row_a), 16);
		if (clicked) {
			code_patcher::toggle_patch(i);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			ui.patches_panel.selected = i;
		}
	}

	ImGui::PopClipRect();

	if (total > visible_h) {
		ui_anim::render_custom_scrollbar(dl, ox + w - 8.f, content_y, 8.f, visible_h,
			ui.patches_panel.scroll_y, total, visible_h, a,
			ui.patches_panel.scrollbar_dragging, ui.patches_panel.scrollbar_drag_offset);
	}

	if (patches.empty()) {
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
}

}
