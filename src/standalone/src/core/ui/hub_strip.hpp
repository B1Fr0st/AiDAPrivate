#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "theme.hpp"
#include "motion.hpp"
#include "transition.hpp"
#include "clock.hpp"
#include "blur_layer.hpp"
#include "fonts.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace aida::ui::hub_strip {

	struct tab_t {
		const char* label = nullptr;
		const char* hint = nullptr;
	};

	struct state_t {
		int   active = 0;
		int   prev = 0;
		int   render_active = 0;
		bool  swap_pending = false;
		float swap_progress = 1.f;
		float direction_sign = 1.f;
		float scroll_x = 0.f;
		float target_scroll_x = 0.f;
		float underline_x = 0.f;
		float underline_w = 0.f;
		float underline_vel = 0.f;
		float halo_phase = 0.f;
		float hover_v[32] = {};
	};

	inline float ease_out_cubic(float t) {
		if (t < 0.f) t = 0.f;
		if (t > 1.f) t = 1.f;
		float u = 1.f - t;
		return 1.f - u * u * u;
	}

	inline void notify_select(state_t& st, int new_idx) {
		if (new_idx == st.active) return;
		st.prev = st.active;
		st.direction_sign = (new_idx > st.active) ? 1.f : -1.f;
		st.active = new_idx;
		st.swap_pending = true;
		st.swap_progress = 0.f;
	}

	inline bool tick_swap(state_t& st, float dt) {
		if (!st.swap_pending) {
			st.render_active = st.active;
			return false;
		}
		float speed = 1.f / aida::motion::dur::md;
		st.swap_progress += dt * speed;
		if (st.swap_progress >= 1.f) {
			st.swap_progress = 1.f;
			st.swap_pending = false;
			st.render_active = st.active;
		}
		return true;
	}

	inline void render_strip(ImDrawList* dl, ImVec2 origin, float pos_x, float pos_y,
	                          float width, const tab_t* tabs, int count,
	                          state_t& st, float alpha)
	{
		if (count <= 0 || count > 32) return;
		const auto& t = aida::ui::resolved();
		float dt = aida::ui::clock::dt();
		st.halo_phase += dt;

		const float tab_h = 30.f;
		const float pad_x = 16.f;
		const float gap = 4.f;
		const float pill_h = tab_h - 8.f;

		float clip_x0 = origin.x + pos_x;
		float clip_y0 = origin.y + pos_y;
		float clip_x1 = clip_x0 + width;
		float clip_y1 = clip_y0 + tab_h;

		ImU32 bar_top = aida::ui::with_alpha(t.panel_header, alpha * 0.55f);
		ImU32 bar_bot = aida::ui::with_alpha(t.panel_bg, alpha * 0.55f);
		dl->AddRectFilledMultiColor(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1),
			bar_top, bar_top, bar_bot, bar_bot);

		ImU32 bottom_line = aida::ui::with_alpha(t.border_subtle, alpha * 0.7f);
		dl->AddLine(ImVec2(clip_x0, clip_y1 - 1.f), ImVec2(clip_x1, clip_y1 - 1.f), bottom_line);

		ImFont* font = aida::ui::fonts::body_em();
		if (!font) font = ImGui::GetFont();
		const float font_size = 13.f;

		float widths[32] = {};
		float offsets[32] = {};
		float total = 0.f;
		for (int i = 0; i < count; ++i) {
			float tw = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, tabs[i].label).x;
			widths[i] = tw + pad_x * 2.f;
			offsets[i] = total;
			total += widths[i] + gap;
		}

		if (ImGui::IsMouseHoveringRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), false)) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) st.target_scroll_x -= wheel * 60.f;
		}
		float max_scroll = std::max(0.f, total - width);
		if (st.target_scroll_x < 0.f) st.target_scroll_x = 0.f;
		if (st.target_scroll_x > max_scroll) st.target_scroll_x = max_scroll;
		st.scroll_x = aida::motion::smooth_lerp(st.scroll_x, st.target_scroll_x, 14.f, dt);

		int active_idx = st.active;
		if (active_idx < 0 || active_idx >= count) active_idx = 0;

		float active_left = offsets[active_idx] - st.scroll_x;
		float active_right = active_left + widths[active_idx];
		if (active_left < 0.f) {
			st.target_scroll_x = offsets[active_idx];
		} else if (active_right > width) {
			st.target_scroll_x = offsets[active_idx] + widths[active_idx] - width;
		}

		float target_ux = clip_x0 + offsets[active_idx] - st.scroll_x + 4.f;
		float target_uw = widths[active_idx] - 8.f;
		if (st.underline_w < 0.5f) {
			st.underline_x = target_ux;
			st.underline_w = target_uw;
		}
		st.underline_x = aida::motion::spring_step(st.underline_x, target_ux,
			st.underline_vel, aida::motion::spring::balanced, dt);
		st.underline_w = aida::motion::smooth_lerp(st.underline_w, target_uw, 16.f, dt);

		float halo_phase = st.halo_phase * 0.45f;
		float halo_offset = sinf(halo_phase) * 6.f;
		ImU32 halo_col = aida::ui::with_alpha(t.accent_glow, alpha * 0.42f);
		dl->AddRectFilled(ImVec2(st.underline_x - 18.f + halo_offset, clip_y0 + 4.f),
			ImVec2(st.underline_x + st.underline_w + 18.f + halo_offset, clip_y1 - 4.f),
			halo_col, pill_h * 0.5f + 6.f);

		dl->PushClipRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), true);

		for (int i = 0; i < count; ++i) {
			float bx0 = clip_x0 + offsets[i] - st.scroll_x;
			float bx1 = bx0 + widths[i];
			float by0 = clip_y0 + 4.f;
			float by1 = clip_y1 - 4.f;

			ImVec2 mp = ImGui::GetMousePos();
			bool hovered = (mp.x >= bx0 && mp.x < bx1 && mp.y >= by0 && mp.y < by1);
			bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);

			float target_h = hovered ? 1.f : 0.f;
			st.hover_v[i] = aida::motion::smooth_lerp(st.hover_v[i], target_h, 14.f, dt);

			bool is_active = (i == active_idx);

			if (is_active) {
				ImU32 pill_top = aida::ui::with_alpha(t.accent_grad_top, alpha * 0.95f);
				ImU32 pill_bot = aida::ui::with_alpha(t.accent_grad_bot, alpha * 0.95f);
				ImU32 pill_flat = aida::ui::mix(pill_top, pill_bot, 0.5f);
				dl->AddRectFilled(ImVec2(bx0 + 4.f, by0), ImVec2(bx1 - 4.f, by1),
					pill_flat, pill_h * 0.5f);
				ImU32 ring = aida::ui::with_alpha(t.accent_hover, alpha * 0.35f);
				dl->AddRect(ImVec2(bx0 + 4.f, by0), ImVec2(bx1 - 4.f, by1),
					ring, pill_h * 0.5f, 0, 1.f);
			} else if (st.hover_v[i] > 0.01f) {
				ImU32 hov_fill = aida::ui::with_alpha(t.hover_wash, alpha * st.hover_v[i]);
				dl->AddRectFilled(ImVec2(bx0 + 4.f, by0), ImVec2(bx1 - 4.f, by1),
					hov_fill, pill_h * 0.5f);
			}

			ImU32 text_col;
			if (is_active) {
				text_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), alpha);
			} else {
				ImU32 base_text = t.text_secondary;
				ImU32 hov_text = t.text_primary;
				text_col = aida::ui::mix(base_text, hov_text, st.hover_v[i]);
				text_col = aida::ui::with_alpha(text_col, alpha);
			}

			float tw = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, tabs[i].label).x;
			float tx = bx0 + (widths[i] - tw) * 0.5f;
			float ty = by0 + ((by1 - by0) - font_size) * 0.5f;
			dl->AddText(font, font_size, ImVec2(tx, ty), text_col, tabs[i].label);

			if (clicked) {
				notify_select(st, i);
			}
		}

		dl->PopClipRect();

		if (st.scroll_x > 1.f) {
			ImU32 fade_col = aida::ui::with_alpha(t.bg_base, alpha * 0.95f);
			ImU32 fade_zero = aida::ui::with_alpha(t.bg_base, 0.f);
			dl->AddRectFilledMultiColor(ImVec2(clip_x0, clip_y0), ImVec2(clip_x0 + 32.f, clip_y1),
				fade_col, fade_zero, fade_zero, fade_col);
		}
		if (st.scroll_x < max_scroll - 1.f) {
			ImU32 fade_col = aida::ui::with_alpha(t.bg_base, alpha * 0.95f);
			ImU32 fade_zero = aida::ui::with_alpha(t.bg_base, 0.f);
			dl->AddRectFilledMultiColor(ImVec2(clip_x1 - 32.f, clip_y0), ImVec2(clip_x1, clip_y1),
				fade_zero, fade_col, fade_col, fade_zero);
		}
	}

	template<typename FA, typename FB>
	inline void render_swap_content(state_t& st, float content_w, FA&& draw_prev, FB&& draw_active) {
		if (!st.swap_pending) {
			draw_active();
			return;
		}
		float p = ease_out_cubic(st.swap_progress);
		float slide_dist = content_w * 0.06f;
		float prev_x = -slide_dist * st.direction_sign * p;
		float new_x  = slide_dist * st.direction_sign * (1.f - p);
		float prev_alpha = (1.f - p);
		float new_alpha = p;

		ImVec2 cp = ImGui::GetCursorPos();

		if (prev_alpha > 0.005f) {
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * prev_alpha);
			ImGui::SetCursorPos(ImVec2(cp.x + prev_x, cp.y));
			draw_prev();
			ImGui::PopStyleVar();
			ImGui::SetCursorPos(cp);
		}
		if (new_alpha > 0.005f) {
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * new_alpha);
			ImGui::SetCursorPos(ImVec2(cp.x + new_x, cp.y));
			draw_active();
			ImGui::PopStyleVar();
		} else {
			ImGui::SetCursorPos(cp);
		}
	}

}
