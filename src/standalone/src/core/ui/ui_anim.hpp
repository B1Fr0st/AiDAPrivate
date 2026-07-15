#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include "imgui/imgui.h"
#include "theme.hpp"
#include "fonts.hpp"

namespace ui_anim {

inline ImU32 theme_alpha(ImU32 c, float alpha) {
	return (c & 0x00FFFFFF) | (static_cast<ImU32>(((c >> 24) & 0xFF) * alpha) << 24);
}

inline ImU32 lighten(ImU32 c, int d) {
	int r = static_cast<int>((c >> IM_COL32_R_SHIFT) & 0xFF) + d;
	int g = static_cast<int>((c >> IM_COL32_G_SHIFT) & 0xFF) + d;
	int b = static_cast<int>((c >> IM_COL32_B_SHIFT) & 0xFF) + d;
	return IM_COL32(r > 255 ? 255 : r, g > 255 ? 255 : g, b > 255 ? 255 : b,
	                (c >> IM_COL32_A_SHIFT) & 0xFF);
}

inline ImU32 darken(ImU32 c, int d) {
	int r = static_cast<int>((c >> IM_COL32_R_SHIFT) & 0xFF) - d;
	int g = static_cast<int>((c >> IM_COL32_G_SHIFT) & 0xFF) - d;
	int b = static_cast<int>((c >> IM_COL32_B_SHIFT) & 0xFF) - d;
	return IM_COL32(r < 0 ? 0 : r, g < 0 ? 0 : g, b < 0 ? 0 : b,
	                (c >> IM_COL32_A_SHIFT) & 0xFF);
}

inline float smooth_lerp(float current, float target, float speed, float dt)
{
	float t = std::min(speed * dt, 1.f);
	return current + (target - current) * t;
}

inline void smooth_scroll(float& scroll_y, float& target_scroll_y, float speed, float dt)
{
	scroll_y += (target_scroll_y - scroll_y) * std::min(speed * dt, 1.f);
	if (std::abs(target_scroll_y - scroll_y) < 0.5f)
		scroll_y = target_scroll_y;
}

inline float pulse_alpha(float time, float frequency, float min_alpha, float max_alpha)
{
	float t = (std::sin(time * frequency * 6.2831853f) + 1.f) * 0.5f;
	return min_alpha + (max_alpha - min_alpha) * t;
}

inline float slide_in(float current, float target, float speed, float dt)
{
	return smooth_lerp(current, target, speed, dt);
}

inline float spring_interp(float current, float target, float& velocity, float stiffness, float damping, float dt)
{
	float force = (target - current) * stiffness;
	velocity += (force - velocity * damping) * dt;
	return current + velocity * dt;
}

inline ImU32 color_lerp(ImU32 col_a, ImU32 col_b, float t)
{
	t = std::clamp(t, 0.f, 1.f);
	int ra = (col_a >> IM_COL32_R_SHIFT) & 0xFF;
	int ga = (col_a >> IM_COL32_G_SHIFT) & 0xFF;
	int ba = (col_a >> IM_COL32_B_SHIFT) & 0xFF;
	int aa = (col_a >> IM_COL32_A_SHIFT) & 0xFF;
	int rb = (col_b >> IM_COL32_R_SHIFT) & 0xFF;
	int gb = (col_b >> IM_COL32_G_SHIFT) & 0xFF;
	int bb = (col_b >> IM_COL32_B_SHIFT) & 0xFF;
	int ab = (col_b >> IM_COL32_A_SHIFT) & 0xFF;
	int r = ra + static_cast<int>(static_cast<float>(rb - ra) * t);
	int g = ga + static_cast<int>(static_cast<float>(gb - ga) * t);
	int b = ba + static_cast<int>(static_cast<float>(bb - ba) * t);
	int a = aa + static_cast<int>(static_cast<float>(ab - aa) * t);
	return IM_COL32(r, g, b, a);
}

inline void handle_scroll_input(float& target_scroll_y, float min_val, float max_val, float row_height, int rows_per_notch = 3)
{
	float wheel = ImGui::GetIO().MouseWheel;
	if (wheel != 0.f) {
		target_scroll_y -= wheel * row_height * static_cast<float>(rows_per_notch);
		if (target_scroll_y < min_val) target_scroll_y = min_val;
		if (target_scroll_y > max_val) target_scroll_y = max_val;
	}
}

inline void clamp_scroll(float& target_scroll_y, float min_val, float max_val)
{
	if (target_scroll_y < min_val) target_scroll_y = min_val;
	if (target_scroll_y > max_val) target_scroll_y = max_val;
}

inline void render_custom_scrollbar(ImDrawList* dl, float ox, float oy, float bar_w, float bar_h,
									float scroll_y, float content_h, float visible_h,
									float alpha, bool& dragging, float& drag_offset)
{
	if (content_h <= visible_h) return;

	float ratio = visible_h / content_h;
	float thumb_h = std::max(bar_h * ratio, 20.f);
	float track_range = bar_h - thumb_h;
	float scroll_ratio = scroll_y / (content_h - visible_h);
	float thumb_y = oy + track_range * scroll_ratio;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + bar_w, oy + bar_h),
					  theme_alpha(aida::ui::resolved().bg_base, 0.24f * alpha), 2.f);

	ImVec2 thumb_min(ox, thumb_y);
	ImVec2 thumb_max(ox + bar_w, thumb_y + thumb_h);
	bool hovered = ImGui::IsMouseHoveringRect(thumb_min, thumb_max, false);

	ImU32 thumb_col = theme_alpha(aida::ui::resolved().accent_dim, (dragging ? 1.f : hovered ? 0.78f : 0.5f) * alpha);
	dl->AddRectFilled(thumb_min, thumb_max, thumb_col, 2.f);

	if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
		dragging = true;
		drag_offset = ImGui::GetMousePos().y - thumb_y;
	}
	if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
		dragging = false;
	}
	if (dragging) {
		float new_thumb_y = ImGui::GetMousePos().y - drag_offset;
		float new_ratio = (new_thumb_y - oy) / track_range;
		new_ratio = std::clamp(new_ratio, 0.f, 1.f);
		scroll_y = new_ratio * (content_h - visible_h);
	}
}

inline void render_tab_underline(ImDrawList* dl, float x, float y, float w, float& anim,
								 bool active, float dt, float ar, float ag, float ab, float alpha)
{
	float target = active ? 1.f : 0.f;
	anim = smooth_lerp(anim, target, 12.f, dt);
	if (anim > 0.01f) {
		dl->AddRectFilled(
			ImVec2(x, y),
			ImVec2(x + w, y + 2.f),
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(220.f * anim * alpha)),
			1.f);
	}
}

inline void render_spinner(ImDrawList* dl, float cx, float cy, float radius, float thickness,
						   ImU32 color, float time)
{
	const float arc_start = time * 5.f;
	const float arc_len = 1.8f;
	const int segments = 24;
	const float segment_count = static_cast<float>(segments);
	for (int i = 0; i < segments; ++i) {
		float t0 = arc_start + (static_cast<float>(i) / segment_count) * arc_len;
		float t1 = arc_start + (static_cast<float>(i + 1) / segment_count) * arc_len;
		float a0 = static_cast<float>(i) / segment_count;
		ImU32 seg_col = (color & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(((color >> 24) & 0xFF) * a0)) << 24);
		dl->AddLine(
			ImVec2(cx + std::cos(t0) * radius, cy + std::sin(t0) * radius),
			ImVec2(cx + std::cos(t1) * radius, cy + std::sin(t1) * radius),
			seg_col, thickness);
	}
}

inline void render_badge(ImDrawList* dl, const char* text, float x, float y,
						 ImU32 bg_color, ImU32 text_color)
{
	ImVec2 sz = ImGui::CalcTextSize(text);
	float pad = 4.f;
	float w = sz.x + pad * 2.f;
	float h = sz.y + 2.f;
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), bg_color, h * 0.5f);
	dl->AddText(ImVec2(x + pad, y + 1.f), text_color, text);
}

inline void render_progress_ring(ImDrawList* dl, float cx, float cy, float radius, float thickness,
								 float progress, ImU32 bg_color, ImU32 fg_color)
{
	const int segments = 48;
	const float segment_count = static_cast<float>(segments);
	const float start_angle = -1.5707963f;

	for (int i = 0; i < segments; ++i) {
		float t0 = start_angle + (static_cast<float>(i) / segment_count) * 6.2831853f;
		float t1 = start_angle + (static_cast<float>(i + 1) / segment_count) * 6.2831853f;
		dl->AddLine(
			ImVec2(cx + std::cos(t0) * radius, cy + std::sin(t0) * radius),
			ImVec2(cx + std::cos(t1) * radius, cy + std::sin(t1) * radius),
			bg_color, thickness);
	}

	int fill_segs = static_cast<int>(progress * segment_count);
	for (int i = 0; i < fill_segs; ++i) {
		float t0 = start_angle + (static_cast<float>(i) / segment_count) * 6.2831853f;
		float t1 = start_angle + (static_cast<float>(i + 1) / segment_count) * 6.2831853f;
		dl->AddLine(
			ImVec2(cx + std::cos(t0) * radius, cy + std::sin(t0) * radius),
			ImVec2(cx + std::cos(t1) * radius, cy + std::sin(t1) * radius),
			fg_color, thickness);
	}
}

inline bool row_hover_select(ImDrawList* dl, float x, float y, float w, float h,
							 int row_idx, int& selected, float alpha,
							 float ar, float ag, float ab)
{
	ImVec2 rmin(x, y);
	ImVec2 rmax(x + w, y + h);
	bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax, false);
	bool clicked = false;

	if (row_idx == selected) {
		dl->AddRectFilled(rmin, rmax,
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(30 * alpha)));
	} else if (hovered) {
		dl->AddRectFilled(rmin, rmax, theme_alpha(aida::ui::resolved().hover_wash, 0.45f * alpha));
	}

	if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
		selected = row_idx;
		clicked = true;
	}
	return clicked;
}

inline bool row_double_click(int row_idx, int& selected)
{
	if (row_idx == selected && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
		return true;
	return false;
}

inline float ease_out_cubic(float t)
{
	t = std::clamp(t, 0.f, 1.f);
	float f = t - 1.f;
	return f * f * f + 1.f;
}

inline float ease_in_out_quad(float t)
{
	t = std::clamp(t, 0.f, 1.f);
	return t < 0.5f ? 2.f * t * t : -1.f + (4.f - 2.f * t) * t;
}

inline float ease_out_elastic(float t)
{
	t = std::clamp(t, 0.f, 1.f);
	if (t <= 0.f || t >= 1.f) return t;
	float p = 0.3f;
	return std::pow(2.f, -10.f * t) * std::sin((t - p / 4.f) * 6.2831853f / p) + 1.f;
}

inline float decay_flash(float& flash, float rate, float dt)
{
	if (flash > 0.f) {
		flash -= rate * dt;
		if (flash < 0.f) flash = 0.f;
	}
	return flash;
}

inline ImU32 accent_col(float ar, float ag, float ab, float alpha)
{
	return IM_COL32(
		static_cast<int>(ar * 255.f),
		static_cast<int>(ag * 255.f),
		static_cast<int>(ab * 255.f),
		static_cast<int>(alpha * 255.f));
}

inline ImU32 accent_col_u8(float ar, float ag, float ab, int alpha)
{
	return IM_COL32(
		static_cast<int>(ar * 255.f),
		static_cast<int>(ag * 255.f),
		static_cast<int>(ab * 255.f),
		alpha);
}

inline void render_gradient_header(ImDrawList* dl, float x, float y, float w, float h,
								   float ar, float ag, float ab, float alpha)
{
	ImU32 left = IM_COL32(
		static_cast<int>(ar * 255.f),
		static_cast<int>(ag * 255.f),
		static_cast<int>(ab * 255.f),
		static_cast<int>(50.f * alpha));
	ImU32 right = IM_COL32(
		static_cast<int>(ar * 255.f),
		static_cast<int>(ag * 255.f),
		static_cast<int>(ab * 255.f),
		0);
	dl->AddRectFilledMultiColor(
		ImVec2(x, y), ImVec2(x + w, y + h),
		left, right, right, left);
}

inline void render_tab_underline_glow(ImDrawList* dl, float underline_x, float underline_w,
									   float baseline_y, float alpha)
{
	if (underline_w <= 0.5f) return;
	const auto& t = aida::ui::resolved();
	for (int g = 0; g < 3; ++g) {
		float spread = 2.f + static_cast<float>(g) * 2.f;
		float ga = (0.20f - static_cast<float>(g) * 0.06f) * alpha;
		dl->AddRectFilled(
			ImVec2(underline_x - spread, baseline_y - spread),
			ImVec2(underline_x + underline_w + spread, baseline_y + 2.f + spread),
			aida::ui::with_alpha(t.accent_glow, ga * 4.f),
			3.f + static_cast<float>(g));
	}
	dl->AddRectFilledMultiColor(
		ImVec2(underline_x, baseline_y),
		ImVec2(underline_x + underline_w, baseline_y + 2.5f),
		aida::ui::with_alpha(t.accent_grad_top, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha),
		aida::ui::with_alpha(t.accent_grad_top, alpha));
}

inline void render_tab_underline_glow_vertical(ImDrawList* dl, float baseline_x, float underline_y,
												float underline_h, float alpha)
{
	if (underline_h <= 0.5f) return;
	const auto& t = aida::ui::resolved();
	for (int g = 0; g < 3; ++g) {
		float spread = 2.f + static_cast<float>(g) * 2.f;
		float ga = (0.20f - static_cast<float>(g) * 0.06f) * alpha;
		dl->AddRectFilled(
			ImVec2(baseline_x - spread, underline_y - spread),
			ImVec2(baseline_x + 2.f + spread, underline_y + underline_h + spread),
			aida::ui::with_alpha(t.accent_glow, ga * 4.f),
			3.f + static_cast<float>(g));
	}
	dl->AddRectFilledMultiColor(
		ImVec2(baseline_x, underline_y),
		ImVec2(baseline_x + 2.5f, underline_y + underline_h),
		aida::ui::with_alpha(t.accent_grad_top, alpha),
		aida::ui::with_alpha(t.accent_grad_top, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha),
		aida::ui::with_alpha(t.accent_grad_bot, alpha));
}

inline void render_status_dot(ImDrawList* dl, float cx, float cy, float radius,
							  ImU32 color, float time, bool pulsing)
{
	float r = radius;
	if (pulsing) {
		float p = (std::sin(time * 4.f) + 1.f) * 0.5f;
		r += p * 1.5f;
		ImU32 glow_col = (color & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(40 + p * 40)) << 24);
		dl->AddCircleFilled(ImVec2(cx, cy), r + 3.f, glow_col, 16);
	}
	dl->AddCircleFilled(ImVec2(cx, cy), r, color, 16);
}

inline ImU32 http_method_color(const char* method, float alpha)
{
	if (!method || !method[0]) return theme_alpha(aida::ui::resolved().text_secondary, alpha);
	char c0 = method[0];
	char c1 = method[1] ? method[1] : 0;
	if (c0 == 'G') return theme_alpha(aida::ui::resolved().success, alpha);
	if (c0 == 'P' && c1 == 'O') return theme_alpha(aida::ui::resolved().info, alpha);
	if (c0 == 'P' && c1 == 'U') return theme_alpha(aida::ui::resolved().warning, alpha);
	if (c0 == 'P' && c1 == 'A') return theme_alpha(aida::ui::resolved().syn_keyword, alpha);
	if (c0 == 'D') return theme_alpha(aida::ui::resolved().error, alpha);
	if (c0 == 'H') return theme_alpha(aida::ui::resolved().text_secondary, alpha);
	if (c0 == 'O') return theme_alpha(aida::ui::resolved().info, alpha);
	return theme_alpha(aida::ui::resolved().text_secondary, alpha);
}

inline ImU32 value_change_color(int64_t curr, int64_t prev, float alpha)
{
	if (curr > prev) return theme_alpha(aida::ui::resolved().success, alpha);
	if (curr < prev) return theme_alpha(aida::ui::resolved().error, alpha);
	return theme_alpha(aida::ui::resolved().text_secondary, alpha);
}

inline ImU32 byte_heat_color(uint8_t val, float alpha)
{
	float t = static_cast<float>(val) / 255.f;
	int r = static_cast<int>(30.f + 225.f * t);
	int g = static_cast<int>(80.f + 100.f * (1.f - std::abs(t - 0.5f) * 2.f));
	int b = static_cast<int>(200.f - 170.f * t);
	return IM_COL32(r, g, b, static_cast<int>(alpha * 255));
}

inline void render_sparkline(ImDrawList* dl, float x, float y, float w, float h,
							 const float* values, int count, ImU32 line_color, ImU32 fill_color)
{
	if (!values || count < 2) return;
	float max_val = 0.001f;
	for (int i = 0; i < count; ++i)
		if (values[i] > max_val) max_val = values[i];

	float step = w / static_cast<float>(count - 1);
	for (int i = 0; i < count - 1; ++i) {
		float x0 = x + step * static_cast<float>(i);
		float x1 = x + step * static_cast<float>(i + 1);
		float y0 = y + h - (values[i] / max_val) * h;
		float y1 = y + h - (values[i + 1] / max_val) * h;

		ImVec2 quad[4] = {
			ImVec2(x0, y0), ImVec2(x1, y1),
			ImVec2(x1, y + h), ImVec2(x0, y + h)
		};
		dl->AddConvexPolyFilled(quad, 4, fill_color);
		dl->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), line_color, 1.5f);
	}
}

inline void render_branch_arrow(ImDrawList* dl, float gutter_x, float from_y, float to_y,
								float gutter_w, ImU32 color, float thickness = 1.f)
{
	float indent = gutter_w * 0.6f;
	float cx = gutter_x + indent;
	float arrow_size = 3.f;

	dl->AddLine(ImVec2(gutter_x + 2.f, from_y), ImVec2(cx, from_y), color, thickness);
	dl->AddLine(ImVec2(cx, from_y), ImVec2(cx, to_y), color, thickness);
	dl->AddLine(ImVec2(cx, to_y), ImVec2(gutter_x + 2.f, to_y), color, thickness);

	dl->AddTriangleFilled(
		ImVec2(gutter_x + 2.f, to_y - arrow_size),
		ImVec2(gutter_x + 2.f, to_y + arrow_size),
		ImVec2(gutter_x - 1.f, to_y),
		color);
}

inline void render_row_slide_in(ImDrawList* dl, float x, float y, float w, float h,
								float& anim, float dt, ImU32 bg_col)
{
	if (anim < 1.f) {
		anim += dt * 12.f;
		if (anim > 1.f) anim = 1.f;
	}
	float t = ease_out_cubic(anim);
	float offset = (1.f - t) * 40.f;
	float a_mult = t;
	ImU32 c = (bg_col & 0x00FFFFFF) | (static_cast<ImU32>(static_cast<int>(((bg_col >> 24) & 0xFF) * a_mult)) << 24);
	dl->AddRectFilled(ImVec2(x - offset, y), ImVec2(x + w - offset, y + h), c);
}

struct animated_counter_t {
	double displayed = 0.0;
	double target = 0.0;

	void set_target(double val) { target = val; }

	void tick(float dt) {
		double diff = target - displayed;
		if (std::abs(diff) < 0.5) {
			displayed = target;
			return;
		}
		displayed += diff * std::min(static_cast<double>(8.0 * dt), 1.0);
	}

	int as_int() const { return static_cast<int>(displayed + 0.5); }
};

struct smooth_value_t {
	float current = 0.f;
	float target = 0.f;
	float velocity = 0.f;

	void set(float val) { target = val; }

	void tick(float dt, float stiffness = 200.f, float damping = 20.f) {
		float force = (target - current) * stiffness;
		velocity += (force - velocity * damping) * dt;
		current += velocity * dt;
		if (std::abs(target - current) < 0.01f && std::abs(velocity) < 0.1f) {
			current = target;
			velocity = 0.f;
		}
	}
};

inline void render_toolbar(ImDrawList* dl, float x, float y, float w, float h,
						   float ar, float ag, float ab, float alpha)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.9f * alpha));
	render_gradient_header(dl, x, y, w, h, ar, ag, ab, alpha * 0.4f);
	dl->AddLine(ImVec2(x, y + h - 1.f), ImVec2(x + w, y + h - 1.f),
		theme_alpha(aida::ui::resolved().border_strong, 0.47f * alpha));
	dl->AddRectFilledMultiColor(
		ImVec2(x, y + h), ImVec2(x + w, y + h + 3.f),
		IM_COL32(0, 0, 0, static_cast<int>(25 * alpha)),
		IM_COL32(0, 0, 0, static_cast<int>(25 * alpha)),
		IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
}

inline void render_section_header(ImDrawList* dl, float x, float y, float w, float h,
								  const char* title, float ar, float ag, float ab, float alpha,
								  int badge_count = -1)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.86f * alpha));
	render_gradient_header(dl, x, y, w, h, ar, ag, ab, alpha * 0.3f);

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(180 * alpha)));

	ImVec2 tsz = ImGui::CalcTextSize(title);
	dl->AddText(ImVec2(x + 12.f, y + (h - tsz.y) * 0.5f),
		IM_COL32(static_cast<int>(ar * 200 + 55), static_cast<int>(ag * 200 + 55),
				 static_cast<int>(ab * 200 + 55), static_cast<int>(alpha * 240)),
		title);

	if (badge_count >= 0) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%d", badge_count);
		float bx = x + 14.f + tsz.x + 8.f;
		render_badge(dl, buf, bx, y + (h - ImGui::CalcTextSize(buf).y - 2.f) * 0.5f,
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(alpha * 160)),
			IM_COL32(255, 255, 255, static_cast<int>(alpha * 220)));
	}

	dl->AddLine(ImVec2(x, y + h - 1.f), ImVec2(x + w, y + h - 1.f),
		theme_alpha(aida::ui::resolved().border_strong, 0.39f * alpha));
}

inline void render_empty_state(ImDrawList* dl, float x, float y, float w, float h,
							   const char* message, float ar, float ag, float ab, float alpha,
							   float time)
{
	float pulse = (std::sin(time * 2.f) + 1.f) * 0.5f;
	float text_a = 0.35f + pulse * 0.25f;

	ImVec2 msz = ImGui::CalcTextSize(message);
	float text_x = x + (w - msz.x) * 0.5f;
	float text_y = y + (h - msz.y) * 0.5f + 12.f;

	ImU32 dot_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							  static_cast<int>(ab * 255), static_cast<int>(alpha * (30 + pulse * 35)));
	float dot_r = 18.f + pulse * 4.f;
	float dcx = x + w * 0.5f;
	float dcy = text_y - 28.f;
	dl->AddCircleFilled(ImVec2(dcx, dcy), dot_r, dot_col, 32);
	dl->AddCircle(ImVec2(dcx, dcy), dot_r + 4.f,
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(alpha * pulse * 20)), 32, 1.5f);

	ImU32 line_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							   static_cast<int>(ab * 255), static_cast<int>(alpha * (20 + pulse * 15)));
	dl->AddLine(ImVec2(dcx - 7.f, dcy - 7.f), ImVec2(dcx + 7.f, dcy + 7.f), line_col, 2.f);
	dl->AddLine(ImVec2(dcx - 7.f, dcy + 7.f), ImVec2(dcx + 7.f, dcy - 7.f), line_col, 2.f);

	dl->AddText(ImVec2(text_x, text_y),
		theme_alpha(aida::ui::resolved().text_secondary, text_a * alpha), message);
}

inline void render_stat_card(ImDrawList* dl, float x, float y, float w, float h,
							 const char* label, const char* value,
							 float ar, float ag, float ab, float alpha,
							 ImU32 value_col = 0)
{
	ImVec2 lsz = ImGui::CalcTextSize(label);
	ImVec2 vsz = ImGui::CalcTextSize(value);

	const float pad_top = 6.f;
	const float gap = 4.f;
	const float pad_bot = 8.f;
	float needed_h = pad_top + lsz.y + gap + vsz.y + pad_bot;
	float eff_h = h > needed_h ? h : needed_h;

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + eff_h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.78f * alpha), 6.f);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + eff_h),
		theme_alpha(aida::ui::resolved().border_strong, 0.39f * alpha), 6.f);

	ImU32 top_line = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							   static_cast<int>(ab * 255), static_cast<int>(alpha * 120));
	dl->AddLine(ImVec2(x + 4.f, y), ImVec2(x + w - 4.f, y), top_line, 2.f);

	float label_y = y + pad_top;
	dl->AddText(ImVec2(x + (w - lsz.x) * 0.5f, label_y),
		theme_alpha(aida::ui::resolved().text_dim, alpha), label);

	if (value_col == 0)
		value_col = theme_alpha(aida::ui::resolved().text_primary, alpha);
	else
		value_col = theme_alpha(value_col, alpha);

	float value_y = label_y + lsz.y + gap;
	float value_bottom = y + eff_h - pad_bot - vsz.y;
	if (value_bottom > value_y) value_y = value_bottom;
	dl->AddText(ImVec2(x + (w - vsz.x) * 0.5f, value_y), value_col, value);
}

inline float render_row_entrance(int row_index, float anim_time, float stagger_delay = 0.015f,
								 float duration = 0.3f)
{
	float row_start = static_cast<float>(row_index) * stagger_delay;
	float elapsed = anim_time - row_start;
	if (elapsed < 0.f) return 0.f;
	if (elapsed >= duration) return 1.f;
	return ease_out_cubic(elapsed / duration);
}

inline void render_separator(ImDrawList* dl, float x, float y, float w,
							 float ar, float ag, float ab, float alpha)
{
	ImU32 left = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						   static_cast<int>(ab * 255), static_cast<int>(60 * alpha));
	ImU32 right = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							static_cast<int>(ab * 255), 0);
	dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + w, y + 1.f), left, right, right, left);
}

inline void render_progress_bar_animated(ImDrawList* dl, float x, float y, float w, float h,
										 float progress, float ar, float ag, float ab, float alpha,
										 float time)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().bg_base, 0.78f * alpha), h * 0.5f);

	float fill_w = w * std::clamp(progress, 0.f, 1.f);
	if (fill_w > 1.f) {
		float fr_l = ar * 255.f;
		float fg_l = ag * 255.f;
		float fb_l = ab * 255.f;
		float fr_r = ar * 200.f + 55.f;
		float fg_r = ag * 200.f + 55.f;
		float fb_r = ab * 200.f + 55.f;
		float t_mix = 0.45f;
		ImU32 fill_mix = IM_COL32(
			static_cast<int>(fr_l + (fr_r - fr_l) * t_mix),
			static_cast<int>(fg_l + (fg_r - fg_l) * t_mix),
			static_cast<int>(fb_l + (fb_r - fb_l) * t_mix),
			static_cast<int>(220.f * alpha));
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + fill_w, y + h), fill_mix, h * 0.5f);

		float shimmer = (std::fmod(time * 0.8f, 1.f));
		float shimmer_x = x + shimmer * fill_w;
		float shimmer_w = fill_w * 0.25f;
		if (shimmer_x + shimmer_w <= x + fill_w) {
			ImU32 shimmer_col = IM_COL32(255, 255, 255, static_cast<int>(25 * alpha));
			dl->AddRectFilledMultiColor(
				ImVec2(shimmer_x, y), ImVec2(shimmer_x + shimmer_w, y + h),
				IM_COL32(255, 255, 255, 0), shimmer_col, shimmer_col, IM_COL32(255, 255, 255, 0));
		}

		ImU32 glow = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							   static_cast<int>(ab * 255), static_cast<int>(30 * alpha));
		dl->AddRectFilled(ImVec2(x, y - 2.f), ImVec2(x + fill_w, y), glow, 1.f);
		dl->AddRectFilled(ImVec2(x, y + h), ImVec2(x + fill_w, y + h + 2.f), glow, 1.f);
	}

	char pct[8];
	std::snprintf(pct, sizeof(pct), "%d%%", static_cast<int>(progress * 100.f));
	ImVec2 psz = ImGui::CalcTextSize(pct);
	if (psz.x + 4.f < w)
		dl->AddText(ImVec2(x + (w - psz.x) * 0.5f, y + (h - psz.y) * 0.5f),
			theme_alpha(aida::ui::resolved().text_primary, alpha), pct);
}

inline void render_glow_rect(ImDrawList* dl, float x, float y, float w, float h,
							 float ar, float ag, float ab, float alpha, float intensity = 1.f)
{
	for (int i = 3; i >= 0; --i) {
		float expand = static_cast<float>(i) * 3.f;
		float ga = (0.06f - static_cast<float>(i) * 0.012f) * alpha * intensity;
		dl->AddRectFilled(
			ImVec2(x - expand, y - expand), ImVec2(x + w + expand, y + h + expand),
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(ga * 255)), 4.f + expand);
	}
}

inline bool render_pill_button(ImDrawList* dl, const char* label, float x, float y,
							   float ar, float ag, float ab, float alpha,
							   float& hover_anim, float dt)
{
	ImVec2 tsz = ImGui::CalcTextSize(label);
	float pad = 10.f;
	float w = tsz.x + pad * 2.f;
	float h = tsz.y + 8.f;
	float rounding = h * 0.5f;

	ImVec2 rmin(x, y);
	ImVec2 rmax(x + w, y + h);
	bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax, false);
	bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);

	float hover_target = hovered ? 1.f : 0.f;
	hover_anim = smooth_lerp(hover_anim, hover_target, 12.f, dt);

	float bg_a = 0.5f + hover_anim * 0.3f;
	dl->AddRectFilled(rmin, rmax,
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(bg_a * alpha * 255)), rounding);

	if (hover_anim > 0.01f) {
		dl->AddRect(rmin, rmax,
			IM_COL32(static_cast<int>(ar * 200 + 55), static_cast<int>(ag * 200 + 55),
					 static_cast<int>(ab * 200 + 55), static_cast<int>(hover_anim * alpha * 100)),
			rounding, 0, 1.f);
	}

	dl->AddText(ImVec2(x + pad, y + 4.f),
		theme_alpha(aida::ui::resolved().text_primary, alpha * (0.78f + hover_anim * 0.22f)), label);

	return clicked;
}

inline void render_toggle_switch(ImDrawList* dl, float x, float y, bool active, float& anim,
								 float ar, float ag, float ab, float alpha, float dt)
{
	float sw_w = 28.f;
	float sw_h = 14.f;
	float rounding = sw_h * 0.5f;

	float target = active ? 1.f : 0.f;
	anim = smooth_lerp(anim, target, 12.f, dt);

	ImU32 bg_off = theme_alpha(aida::ui::resolved().panel_header, 0.78f * alpha);
	ImU32 bg_on = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						    static_cast<int>(ab * 255), static_cast<int>(200 * alpha));
	ImU32 bg = color_lerp(bg_off, bg_on, anim);

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + sw_w, y + sw_h), bg, rounding);

	float knob_r = sw_h * 0.4f;
	float knob_x = x + rounding + anim * (sw_w - sw_h);
	float knob_y = y + sw_h * 0.5f;
	dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
		IM_COL32(255, 255, 255, static_cast<int>(alpha * 240)), 16);
}

inline void render_hub_tab_bar(ImDrawList* dl, ImVec2 origin, float x, float y, float w,
							   const char* const* names, int count, int& active_idx,
							   float& scroll_x, float& target_scroll_x,
							   float& underline_x, float& underline_w, float& underline_vel,
							   float& content_fade, int& prev_idx,
							   float ar, float ag, float ab, float alpha, float dt)
{
	float tab_h = 28.f;
	render_gradient_header(dl, origin.x + x, origin.y + y, w, tab_h, ar, ag, ab, alpha);

	if (count <= 0) return;
	constexpr int max_tabs = 32;
	int clamped_count = count < max_tabs ? count : max_tabs;
	if (active_idx < 0) active_idx = 0;
	if (active_idx >= clamped_count) active_idx = clamped_count - 1;

	float total_w = 0.f;
	float tab_widths[max_tabs] = {};
	float tab_offsets[max_tabs] = {};
	for (int i = 0; i < clamped_count; i++) {
		tab_widths[i] = ImGui::CalcTextSize(names[i]).x + 20.f;
		tab_offsets[i] = total_w;
		total_w += tab_widths[i] + 2.f;
	}

	float clip_x0 = origin.x + x;
	float clip_x1 = origin.x + x + w;
	float clip_y0 = origin.y + y;
	float clip_y1 = origin.y + y + tab_h;

	if (ImGui::IsMouseHoveringRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			target_scroll_x -= wheel * 60.f;
	}

	float max_scroll = std::max(0.f, total_w - w);
	target_scroll_x = std::clamp(target_scroll_x, 0.f, max_scroll);
	scroll_x = smooth_lerp(scroll_x, target_scroll_x, 14.f, dt);

	float active_left = tab_offsets[active_idx] - scroll_x;
	float active_right = active_left + tab_widths[active_idx];
	if (active_left < 0.f)
		target_scroll_x = tab_offsets[active_idx];
	else if (active_right > w)
		target_scroll_x = tab_offsets[active_idx] + tab_widths[active_idx] - w;

	float target_ux = clip_x0 + tab_offsets[active_idx] - scroll_x + 4.f;
	float target_uw = tab_widths[active_idx] - 8.f;
	if (underline_w < 0.1f) {
		underline_x = target_ux;
		underline_w = target_uw;
	}
	underline_x = spring_interp(underline_x, target_ux, underline_vel, 280.f, 22.f, dt);
	underline_w = smooth_lerp(underline_w, target_uw, 16.f, dt);

	ImGui::PushClipRect(ImVec2(clip_x0, clip_y0), ImVec2(clip_x1, clip_y1), true);

	for (int i = 0; i < clamped_count; i++) {
		float bx0 = clip_x0 + tab_offsets[i] - scroll_x;
		float bx1 = bx0 + tab_widths[i];
		float by0 = clip_y0;
		float by1 = clip_y0 + tab_h;
		bool is_active = (i == active_idx);

		ImVec2 mouse = ImGui::GetMousePos();
		bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);
		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (active_idx != i) {
				prev_idx = active_idx;
				content_fade = 0.f;
			}
			active_idx = i;
		}

		float bg_alpha_val = is_active ? 0.15f : (hovered ? 0.08f : 0.f);
		if (bg_alpha_val > 0.01f)
			dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
				IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
						 static_cast<int>(ab * 255), static_cast<int>(bg_alpha_val * alpha * 255)),
				4.f);

		ImVec2 ts = ImGui::CalcTextSize(names[i]);
		float text_alpha = is_active ? 0.95f : (hovered ? 0.7f : 0.5f);
		dl->AddText(ImVec2(bx0 + (tab_widths[i] - ts.x) * 0.5f, by0 + (tab_h - ts.y) * 0.5f),
			theme_alpha(aida::ui::resolved().text_primary, text_alpha * alpha),
			names[i]);
	}

	float ux = underline_x;
	float uw = underline_w;
	float uy = clip_y1 - 2.f;
	ImU32 ul_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							 static_cast<int>(ab * 255), static_cast<int>(alpha * 255));
	dl->AddRectFilled(ImVec2(ux, uy), ImVec2(ux + uw, uy + 2.f), ul_col, 1.f);
	dl->AddRectFilled(ImVec2(ux - 3.f, uy - 1.f), ImVec2(ux + uw + 3.f, uy + 3.f),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(alpha * 40)), 2.f);
	dl->AddRectFilled(ImVec2(ux - 6.f, uy - 2.f), ImVec2(ux + uw + 6.f, uy + 5.f),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(alpha * 15)), 3.f);

	ImGui::PopClipRect();

	if (scroll_x > 1.f) {
		dl->AddRectFilledMultiColor(
			ImVec2(clip_x0, clip_y0), ImVec2(clip_x0 + 30.f, clip_y1),
			theme_alpha(aida::ui::resolved().bg_base, 0.94f * alpha),
			theme_alpha(aida::ui::resolved().bg_base, 0.f),
			theme_alpha(aida::ui::resolved().bg_base, 0.f),
			theme_alpha(aida::ui::resolved().bg_base, 0.94f * alpha));
	}
	if (scroll_x < max_scroll - 1.f) {
		dl->AddRectFilledMultiColor(
			ImVec2(clip_x1 - 30.f, clip_y0), ImVec2(clip_x1, clip_y1),
			theme_alpha(aida::ui::resolved().bg_base, 0.f),
			theme_alpha(aida::ui::resolved().bg_base, 0.94f * alpha),
			theme_alpha(aida::ui::resolved().bg_base, 0.94f * alpha),
			theme_alpha(aida::ui::resolved().bg_base, 0.f));
	}

	dl->AddLine(ImVec2(origin.x + x, origin.y + y + tab_h),
		ImVec2(origin.x + x + w, origin.y + y + tab_h),
		theme_alpha(aida::ui::resolved().border_strong, 0.3f * alpha));
	dl->AddRectFilledMultiColor(
		ImVec2(origin.x + x, origin.y + y + tab_h + 1.f),
		ImVec2(origin.x + x + w, origin.y + y + tab_h + 4.f),
		IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
		IM_COL32(0, 0, 0, static_cast<int>(30.f * alpha)),
		IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
}

inline float ease_out_back(float t)
{
	t = std::clamp(t, 0.f, 1.f);
	const float c1 = 1.70158f;
	const float c3 = c1 + 1.f;
	float f = t - 1.f;
	return 1.f + c3 * f * f * f + c1 * f * f;
}

inline float ease_out_quint(float t)
{
	t = std::clamp(t, 0.f, 1.f);
	float f = t - 1.f;
	return 1.f + f * f * f * f * f;
}

struct table_col_t {
	const char* label;
	float       width;
};

inline void render_table_header(ImDrawList* dl, float x, float y, float w, float row_h,
								const table_col_t* cols, int col_count,
								float ar, float ag, float ab, float alpha)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + row_h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.9f * alpha));
	render_gradient_header(dl, x, y, w, row_h, ar, ag, ab, alpha * 0.25f);
	dl->AddLine(ImVec2(x, y + row_h - 1.f), ImVec2(x + w, y + row_h - 1.f),
		theme_alpha(aida::ui::resolved().border_strong, 0.47f * alpha));

	ImU32 hdr_col = IM_COL32(static_cast<int>(ar * 180 + 60), static_cast<int>(ag * 180 + 60),
							  static_cast<int>(ab * 180 + 60), static_cast<int>(220 * alpha));
	float cx = x + 8.f;
	for (int i = 0; i < col_count; ++i) {
		dl->AddText(ImVec2(cx, y + (row_h - ImGui::CalcTextSize(cols[i].label).y) * 0.5f),
			hdr_col, cols[i].label);
		cx += cols[i].width;
		if (i < col_count - 1)
			dl->AddLine(ImVec2(cx - 4.f, y + 4.f), ImVec2(cx - 4.f, y + row_h - 4.f),
				theme_alpha(aida::ui::resolved().border_subtle, 0.6f * alpha));
	}
}

struct table_row_style_t {
	bool  selected;
	bool  hovered;
	int   index;
	float alpha;
	float entrance;
	float ar, ag, ab;
};

inline void render_table_row(ImDrawList* dl, float x, float y, float w, float h,
							 const table_row_style_t& s)
{
	float ra = s.alpha * s.entrance;
	if (ra < 0.01f) return;

	if (s.selected) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
			IM_COL32(static_cast<int>(s.ar * 180), static_cast<int>(s.ag * 180),
					 static_cast<int>(s.ab * 180), static_cast<int>(28 * ra)));
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h),
			IM_COL32(static_cast<int>(s.ar * 255), static_cast<int>(s.ag * 255),
					 static_cast<int>(s.ab * 255), static_cast<int>(200 * ra)));
	} else if (s.hovered) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
			IM_COL32(255, 255, 255, static_cast<int>(10 * ra)));
	} else if (s.index & 1) {
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
			IM_COL32(255, 255, 255, static_cast<int>(3 * ra)));
	}
}

inline void render_panel_card(ImDrawList* dl, float x, float y, float w, float h,
							  float ar, float ag, float ab, float alpha,
							  float rounding = 6.f, bool header_stripe = true)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.82f * alpha), rounding);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().border_strong, 0.31f * alpha), rounding);
	if (header_stripe) {
		dl->AddLine(ImVec2(x + rounding, y), ImVec2(x + w - rounding, y),
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(100 * alpha)), 2.f);
	}
	dl->AddRectFilledMultiColor(
		ImVec2(x, y + h), ImVec2(x + w, y + h + 3.f),
		IM_COL32(0, 0, 0, static_cast<int>(18 * alpha)),
		IM_COL32(0, 0, 0, static_cast<int>(18 * alpha)),
		IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
}

inline void render_separator_animated(ImDrawList* dl, float x, float y, float w,
									  float ar, float ag, float ab, float alpha, float time,
									  bool vertical = false)
{
	float pulse = (std::sin(time * 1.5f) + 1.f) * 0.5f;
	float base_a = 0.25f + pulse * 0.15f;
	ImU32 center_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
								 static_cast<int>(ab * 255), static_cast<int>(base_a * alpha * 255));
	ImU32 edge_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
							   static_cast<int>(ab * 255), 0);
	if (vertical) {
		float half = w * 0.5f;
		dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + 1.f, y + half),
			edge_col, edge_col, center_col, center_col);
		dl->AddRectFilledMultiColor(ImVec2(x, y + half), ImVec2(x + 1.f, y + w),
			center_col, center_col, edge_col, edge_col);
	} else {
		float half = w * 0.5f;
		dl->AddRectFilledMultiColor(ImVec2(x, y), ImVec2(x + half, y + 1.f),
			edge_col, center_col, center_col, edge_col);
		dl->AddRectFilledMultiColor(ImVec2(x + half, y), ImVec2(x + w, y + 1.f),
			center_col, edge_col, edge_col, center_col);
	}
}

inline void render_popup_frame(ImDrawList* dl, float cx, float cy, float w, float h,
							   float fade, float ar, float ag, float ab, float alpha,
							   float vp_x, float vp_y, float vp_w, float vp_h)
{
	float fa = alpha * fade;
	dl->AddRectFilled(ImVec2(vp_x, vp_y), ImVec2(vp_x + vp_w, vp_y + vp_h),
		IM_COL32(0, 0, 0, static_cast<int>(130 * fa)));

	float t = ease_out_back(std::clamp(fade * 1.2f, 0.f, 1.f));
	float scale = 0.92f + 0.08f * t;
	float pw = w * scale;
	float ph = h * scale;
	float px = cx - pw * 0.5f;
	float py = cy - ph * 0.5f + (1.f - t) * 12.f;

	for (int g = 3; g >= 1; --g) {
		float expand = static_cast<float>(g) * 3.f;
		int ga = static_cast<int>(12 * fa / static_cast<float>(g));
		dl->AddRect(ImVec2(px - expand, py - expand),
			ImVec2(px + pw + expand, py + ph + expand),
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), ga), 10.f + expand, 0, 1.f);
	}

	dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		theme_alpha(aida::ui::resolved().bg_elevated, 0.97f * fa), 8.f);
	dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(70 * fa)), 8.f, 0, 1.5f);
}

inline void render_popup_header(ImDrawList* dl, float px, float py, float pw, float h,
								const char* title, float ar, float ag, float ab, float fa)
{
	dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + h),
		theme_alpha(aida::ui::resolved().panel_header, 0.86f * fa), 8.f, ImDrawFlags_RoundCornersTop);
	render_gradient_header(dl, px, py, pw, h, ar, ag, ab, fa * 0.35f);
	dl->AddLine(ImVec2(px, py + h), ImVec2(px + pw, py + h),
		IM_COL32(static_cast<int>(ar * 100), static_cast<int>(ag * 100),
				 static_cast<int>(ab * 100), static_cast<int>(120 * fa)));
	ImU32 title_col = IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
								static_cast<int>(ab * 255), static_cast<int>(255 * fa));
	dl->AddText(ImVec2(px + 14.f, py + (h - ImGui::CalcTextSize(title).y) * 0.5f), title_col, title);
}

inline bool render_popup_close_button(ImDrawList* dl, float px, float py, float pw, float header_h,
									  float fa, float& hover_anim, float dt)
{
	float btn_sz = 20.f;
	float bx = px + pw - btn_sz - 8.f;
	float by = py + (header_h - btn_sz) * 0.5f;
	ImVec2 rmin(bx, by);
	ImVec2 rmax(bx + btn_sz, by + btn_sz);
	bool hov = ImGui::IsMouseHoveringRect(rmin, rmax, false);
	bool clicked = hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);

	hover_anim = smooth_lerp(hover_anim, hov ? 1.f : 0.f, 14.f, dt);

	if (hover_anim > 0.01f)
		dl->AddRectFilled(rmin, rmax,
			theme_alpha(aida::ui::resolved().error, hover_anim * 0.31f * fa), 4.f);

	float cx = bx + btn_sz * 0.5f;
	float cy = by + btn_sz * 0.5f;
	float s = 5.f;
	ImU32 xc = theme_alpha(aida::ui::resolved().text_secondary, (0.55f + hover_anim * 0.45f) * fa);
	dl->AddLine(ImVec2(cx - s, cy - s), ImVec2(cx + s, cy + s), xc, 1.5f);
	dl->AddLine(ImVec2(cx + s, cy - s), ImVec2(cx - s, cy + s), xc, 1.5f);

	return clicked;
}

inline void render_donut_chart(ImDrawList* dl, float cx, float cy, float radius, float thickness,
							   const float* fractions, const ImU32* colors, int segment_count,
							   float alpha, const char* center_label = nullptr)
{
	const int arc_segments = 64;
	const float start_angle = -1.5707963f;
	float angle = start_angle;

	for (int s = 0; s < segment_count; ++s) {
		float sweep = fractions[s] * 6.2831853f;
		int segs_for_this = std::max(2, static_cast<int>(static_cast<float>(arc_segments) * fractions[s]));
		float segment_divisor = static_cast<float>(segs_for_this);
		ImU32 col = theme_alpha(colors[s], alpha);

		for (int i = 0; i < segs_for_this; ++i) {
			float t0 = angle + (static_cast<float>(i) / segment_divisor) * sweep;
			float t1 = angle + (static_cast<float>(i + 1) / segment_divisor) * sweep;
			ImVec2 outer0(cx + std::cos(t0) * radius, cy + std::sin(t0) * radius);
			ImVec2 outer1(cx + std::cos(t1) * radius, cy + std::sin(t1) * radius);
			ImVec2 inner0(cx + std::cos(t0) * (radius - thickness), cy + std::sin(t0) * (radius - thickness));
			ImVec2 inner1(cx + std::cos(t1) * (radius - thickness), cy + std::sin(t1) * (radius - thickness));
			dl->AddQuadFilled(outer0, outer1, inner1, inner0, col);
		}
		angle += sweep;
	}

	if (center_label) {
		ImVec2 tsz = ImGui::CalcTextSize(center_label);
		dl->AddText(ImVec2(cx - tsz.x * 0.5f, cy - tsz.y * 0.5f),
			theme_alpha(aida::ui::resolved().text_secondary, alpha), center_label);
	}
}

inline void render_status_pill(ImDrawList* dl, float x, float y,
							   const char* text, ImU32 color, float alpha,
							   float time = 0.f, bool pulsing = false)
{
	ImVec2 tsz = ImGui::CalcTextSize(text);
	float pad_x = 8.f;
	float pad_y = 2.f;
	float w = tsz.x + pad_x * 2.f + (pulsing ? 12.f : 0.f);
	float h = tsz.y + pad_y * 2.f;
	float rounding = h * 0.5f;

	int cr = (color >> IM_COL32_R_SHIFT) & 0xFF;
	int cg = (color >> IM_COL32_G_SHIFT) & 0xFF;
	int cb = (color >> IM_COL32_B_SHIFT) & 0xFF;

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		IM_COL32(cr, cg, cb, static_cast<int>(30 * alpha)), rounding);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
		IM_COL32(cr, cg, cb, static_cast<int>(80 * alpha)), rounding, 0, 1.f);

	float text_x = x + pad_x;
	if (pulsing) {
		float pulse = (std::sin(time * 4.f) + 1.f) * 0.5f;
		float dot_cx = x + 10.f;
		float dot_cy = y + h * 0.5f;
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 3.f + pulse * 1.f,
			IM_COL32(cr, cg, cb, static_cast<int>((150 + pulse * 105) * alpha)), 12);
		text_x += 12.f;
	}

	dl->AddText(ImVec2(text_x, y + pad_y),
		IM_COL32(cr, cg, cb, static_cast<int>(220 * alpha)), text);
}

inline bool render_toolbar_button(ImDrawList* dl, const char* label, float x, float y,
								  float ar, float ag, float ab, float alpha,
								  float& hover_anim, float dt,
								  bool active = false, bool disabled = false)
{
	ImVec2 tsz = ImGui::CalcTextSize(label);
	float pad = 8.f;
	float w = tsz.x + pad * 2.f;
	float h = 22.f;

	ImVec2 rmin(x, y);
	ImVec2 rmax(x + w, y + h);
	bool hovered = !disabled && ImGui::IsMouseHoveringRect(rmin, rmax, false);
	bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);

	float target = active ? 1.f : (hovered ? 0.7f : 0.f);
	hover_anim = smooth_lerp(hover_anim, target, 14.f, dt);

	float bg_a = hover_anim * 0.35f;
	if (bg_a > 0.01f)
		dl->AddRectFilled(rmin, rmax,
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(bg_a * alpha * 255)), 6.f);

	if (active)
		dl->AddRectFilled(ImVec2(x, y + h - 2.f), ImVec2(x + w, y + h),
			IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					 static_cast<int>(ab * 255), static_cast<int>(180 * alpha)), 1.f);

	float text_a = disabled ? 0.3f : (0.55f + hover_anim * 0.45f);
	dl->AddText(ImVec2(x + pad, y + (h - tsz.y) * 0.5f),
		IM_COL32(255, 255, 255, static_cast<int>(text_a * alpha * 255)), label);

	return clicked && !disabled;
}

inline float toolbar_button_width(const char* label)
{
	return ImGui::CalcTextSize(label).x + 16.f;
}

inline void render_collapsible_header(ImDrawList* dl, float x, float y, float w, float h,
									  const char* title, bool expanded, float& arrow_anim,
									  float ar, float ag, float ab, float alpha, float dt)
{
	arrow_anim = smooth_lerp(arrow_anim, expanded ? 1.f : 0.f, 12.f, dt);

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_header, 0.86f * alpha));
	render_gradient_header(dl, x, y, w, h, ar, ag, ab, alpha * 0.2f);
	dl->AddLine(ImVec2(x, y + h - 1.f), ImVec2(x + w, y + h - 1.f),
		theme_alpha(aida::ui::resolved().border_strong, 0.31f * alpha));

	float arrow_cx = x + 14.f;
	float arrow_cy = y + h * 0.5f;
	float angle = arrow_anim * 1.5707963f;
	float sz = 4.f;

	float ca = std::cos(angle);
	float sa = std::sin(angle);

	ImVec2 p0(arrow_cx + (-sz) * ca - (-sz) * sa, arrow_cy + (-sz) * sa + (-sz) * ca);
	ImVec2 p1(arrow_cx + (sz) * ca - (0.f) * sa, arrow_cy + (sz) * sa + (0.f) * ca);
	ImVec2 p2(arrow_cx + (-sz) * ca - (sz) * sa, arrow_cy + (-sz) * sa + (sz) * ca);

	ImU32 arrow_col = IM_COL32(static_cast<int>(ar * 200 + 55), static_cast<int>(ag * 200 + 55),
								static_cast<int>(ab * 200 + 55), static_cast<int>(180 * alpha));
	dl->AddTriangleFilled(p0, p1, p2, arrow_col);

	dl->AddText(ImVec2(x + 28.f, y + (h - ImGui::CalcTextSize(title).y) * 0.5f),
		theme_alpha(aida::ui::resolved().text_primary, alpha), title);
}

inline void render_color_legend(ImDrawList* dl, float x, float y,
								const char* const* labels, const ImU32* colors, int count, float alpha)
{
	float cx = x;
	float dot_r = 4.f;
	float spacing = 6.f;
	float item_gap = 16.f;

	for (int i = 0; i < count; ++i) {
		dl->AddCircleFilled(ImVec2(cx + dot_r, y + dot_r + 1.f), dot_r,
			theme_alpha(colors[i], alpha), 12);
		cx += dot_r * 2.f + spacing;
		ImVec2 tsz = ImGui::CalcTextSize(labels[i]);
		dl->AddText(ImVec2(cx, y),
			theme_alpha(aida::ui::resolved().text_secondary, alpha), labels[i]);
		cx += tsz.x + item_gap;
	}
}

inline void render_confidence_bar(ImDrawList* dl, float x, float y, float w, float h,
								  float confidence, float alpha)
{
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().bg_base, 0.7f * alpha), h * 0.5f);

	float fill = w * std::clamp(confidence, 0.f, 1.f);
	if (fill > 1.f) {
		ImU32 col;
		if (confidence > 0.75f)
			col = theme_alpha(aida::ui::resolved().success, alpha);
		else if (confidence > 0.5f)
			col = theme_alpha(aida::ui::resolved().warning, alpha);
		else
			col = theme_alpha(aida::ui::resolved().error, alpha);
		dl->AddRectFilled(ImVec2(x, y), ImVec2(x + fill, y + h), col, h * 0.5f);
	}
}

inline void render_mini_sparkline(ImDrawList* dl, float x, float y, float w, float h,
								  const float* vals, int count, ImU32 color, float alpha)
{
	if (!vals || count < 2) return;
	float mx = 0.001f;
	for (int i = 0; i < count; ++i)
		if (vals[i] > mx) mx = vals[i];

	float step = w / static_cast<float>(count - 1);
	ImU32 lc = theme_alpha(color, alpha);
	ImU32 fc = theme_alpha(color, alpha * 0.15f);

	for (int i = 0; i < count - 1; ++i) {
		float x0 = x + step * static_cast<float>(i);
		float x1 = x + step * static_cast<float>(i + 1);
		float y0 = y + h - (vals[i] / mx) * h;
		float y1 = y + h - (vals[i + 1] / mx) * h;
		dl->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), lc, 1.f);
		ImVec2 quad[4] = { ImVec2(x0, y0), ImVec2(x1, y1), ImVec2(x1, y + h), ImVec2(x0, y + h) };
		dl->AddConvexPolyFilled(quad, 4, fc);
	}
}

inline void render_severity_badge(ImDrawList* dl, float x, float y, int severity, float alpha)
{
	const char* labels[] = { "LOW", "MED", "HIGH", "CRIT" };
	ImU32 colors[] = {
		theme_alpha(aida::ui::resolved().success, alpha),
		theme_alpha(aida::ui::resolved().warning, alpha),
		theme_alpha(aida::ui::resolved().warning, 0.78f * alpha),
		theme_alpha(aida::ui::resolved().error, alpha)
	};
	ImU32 bg_colors[] = {
		theme_alpha(aida::ui::resolved().success, 0.12f * alpha),
		theme_alpha(aida::ui::resolved().warning, 0.12f * alpha),
		theme_alpha(aida::ui::resolved().warning, 0.12f * alpha),
		theme_alpha(aida::ui::resolved().error, 0.12f * alpha)
	};
	int idx = std::clamp(severity, 0, 3);
	render_badge(dl, labels[idx], x, y, bg_colors[idx], colors[idx]);
}

inline void render_protection_badge(ImDrawList* dl, float x, float y, uint32_t protect, float alpha)
{
	bool exec = (protect & 0xF0) != 0;
	bool write = (protect == 0x04 || protect == 0x08 || protect == 0x40 || protect == 0x80);
	bool read = (protect != 0);

	float cx = x;
	if (read) {
		render_badge(dl, "R", cx, y,
			theme_alpha(aida::ui::resolved().info, 0.12f * alpha),
			theme_alpha(aida::ui::resolved().info, alpha));
		cx += ImGui::CalcTextSize("R").x + 14.f;
	}
	if (write) {
		render_badge(dl, "W", cx, y,
			theme_alpha(aida::ui::resolved().success, 0.12f * alpha),
			theme_alpha(aida::ui::resolved().success, alpha));
		cx += ImGui::CalcTextSize("W").x + 14.f;
	}
	if (exec) {
		render_badge(dl, "X", cx, y,
			theme_alpha(aida::ui::resolved().error, 0.12f * alpha),
			theme_alpha(aida::ui::resolved().error, alpha));
	}
}

inline void render_formatted_size(ImDrawList* dl, float x, float y, uint64_t bytes,
								  float alpha)
{
	char buf[32];
	if (bytes >= 1024ULL * 1024ULL * 1024ULL)
		std::snprintf(buf, sizeof(buf), "%.1f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
	else if (bytes >= 1024ULL * 1024ULL)
		std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
	else if (bytes >= 1024ULL)
		std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
	else
		std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));

	dl->AddText(ImVec2(x, y),
		theme_alpha(aida::ui::resolved().text_secondary, alpha), buf);
}

inline void render_hex_address(ImDrawList* dl, float x, float y, uint64_t addr, float alpha,
							   ImU32 color = 0)
{
	char buf[20];
	std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(addr));
	if (color == 0)
		color = theme_alpha(aida::ui::resolved().text_address, alpha);
	else
		color = theme_alpha(color, alpha);
	dl->AddText(ImVec2(x, y), color, buf);
}

inline void render_context_menu_bg(ImDrawList* dl, float x, float y, float w, float h,
								   float fade, float alpha)
{
	float fa = alpha * fade;
	float t = ease_out_back(std::clamp(fade * 1.3f, 0.f, 1.f));
	float scale = 0.95f + 0.05f * t;
	float pw = w * scale;
	float ph = h * scale;
	float px = x + (w - pw) * 0.5f;
	float py = y + (h - ph) * 0.5f;

	dl->AddRectFilled(ImVec2(px - 2.f, py + 2.f), ImVec2(px + pw + 2.f, py + ph + 4.f),
		IM_COL32(0, 0, 0, static_cast<int>(60 * fa)), 8.f);
	dl->AddRectFilled(ImVec2(px, py), ImVec2(px + pw, py + ph),
		theme_alpha(aida::ui::resolved().bg_overlay, 0.96f * fa), 6.f);
	dl->AddRect(ImVec2(px, py), ImVec2(px + pw, py + ph),
		theme_alpha(aida::ui::resolved().border_strong, 0.39f * fa), 6.f, 0, 1.f);
}

enum class callout_kind_t { info, warn, success, error };

inline void render_inline_callout(ImDrawList* dl, float x, float y, float w, float h,
								  const char* text, callout_kind_t kind,
								  float ar, float ag, float ab, float alpha)
{
	ImU32 accent_col;
	ImU32 fill_col;
	const char* glyph = "";
	switch (kind) {
	case callout_kind_t::info:
		accent_col = theme_alpha(aida::ui::resolved().info, 0.9f * alpha);
		fill_col   = theme_alpha(aida::ui::resolved().info, 0.086f * alpha);
		glyph = "i";
		break;
	case callout_kind_t::warn:
		accent_col = theme_alpha(aida::ui::resolved().warning, 0.9f * alpha);
		fill_col   = theme_alpha(aida::ui::resolved().warning, 0.086f * alpha);
		glyph = "!";
		break;
	case callout_kind_t::success:
		accent_col = theme_alpha(aida::ui::resolved().success, 0.9f * alpha);
		fill_col   = theme_alpha(aida::ui::resolved().success, 0.086f * alpha);
		glyph = "+";
		break;
	case callout_kind_t::error:
		accent_col = theme_alpha(aida::ui::resolved().error, 0.9f * alpha);
		fill_col   = theme_alpha(aida::ui::resolved().error, 0.086f * alpha);
		glyph = "x";
		break;
	default:
		accent_col = theme_alpha(aida::ui::resolved().text_secondary, alpha);
		fill_col   = theme_alpha(aida::ui::resolved().text_secondary, 0.08f * alpha);
		glyph = "?";
		break;
	}

	float text_w = 0.f;
	if (text) {
		ImVec2 ts_pre = ImGui::CalcTextSize(text);
		text_w = ts_pre.x;
	}
	const float min_w = 34.f + text_w + 14.f;
	if (w < min_w) w = min_w;

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), fill_col, 5.f);

	ImU32 accent_tint_mix = IM_COL32(
		static_cast<int>(ar * 255), static_cast<int>(ag * 255), static_cast<int>(ab * 255),
		static_cast<int>(6 * alpha));
	dl->AddRectFilled(
		ImVec2(x + 3.f, y), ImVec2(x + w, y + h),
		accent_tint_mix, 5.f, ImDrawFlags_RoundCornersRight);

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h), accent_col);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(accent_col, 0.5f), 5.f, 0, 1.f);

	float glyph_cx = x + 18.f;
	float glyph_cy = y + h * 0.5f;
	dl->AddCircleFilled(ImVec2(glyph_cx, glyph_cy), 8.f,
		theme_alpha(accent_col, 0.6f), 16);
	ImVec2 gs = ImGui::CalcTextSize(glyph);
	dl->AddText(ImVec2(glyph_cx - gs.x * 0.5f, glyph_cy - gs.y * 0.5f),
		theme_alpha(aida::ui::resolved().bg_base, 0.94f * alpha), glyph);

	if (text) {
		ImVec2 ts = ImGui::CalcTextSize(text);
		dl->AddText(ImVec2(x + 34.f, y + (h - ts.y) * 0.5f),
			theme_alpha(aida::ui::resolved().text_primary, 0.9f * alpha), text);
	}
}

inline float render_kbd_chip(ImDrawList* dl, float x, float y, const char* label, float alpha)
{
	if (!label) return 0.f;
	ImVec2 ts = ImGui::CalcTextSize(label);
	float pad_x = 6.f;
	float w = ts.x + pad_x * 2.f;
	float h = ts.y + 4.f;
	float rounding = 3.f;

	dl->AddRectFilled(ImVec2(x, y + 1.f), ImVec2(x + w, y + h + 1.f),
		IM_COL32(0, 0, 0, static_cast<int>(55 * alpha)), rounding);
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_header, 0.9f * alpha), rounding);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().border_strong, 0.7f * alpha), rounding, 0, 1.f);
	dl->AddLine(ImVec2(x + rounding, y + 1.f), ImVec2(x + w - rounding, y + 1.f),
		IM_COL32(255, 255, 255, static_cast<int>(28 * alpha)), 1.f);

	dl->AddText(ImVec2(x + pad_x, y + 2.f),
		theme_alpha(aida::ui::resolved().text_primary, 0.9f * alpha), label);

	return w;
}

inline bool render_filter_input_chip(const char* id, char* buf, size_t bufsz,
									 const char* placeholder, float width,
									 float ar, float ag, float ab, float alpha)
{
	ImU32 frame_bg = theme_alpha(aida::ui::resolved().panel_header, 0.86f * alpha);
	ImU32 frame_hov = IM_COL32(
		static_cast<int>(ar * 70 + 30), static_cast<int>(ag * 70 + 30),
		static_cast<int>(ab * 70 + 30), static_cast<int>(230 * alpha));
	ImU32 frame_active = IM_COL32(
		static_cast<int>(ar * 120 + 25), static_cast<int>(ag * 120 + 25),
		static_cast<int>(ab * 120 + 25), static_cast<int>(240 * alpha));
	ImU32 text_col = theme_alpha(aida::ui::resolved().text_primary, 0.94f * alpha);
	ImU32 hint_col = theme_alpha(aida::ui::resolved().text_dim, alpha);
	ImU32 border_col = theme_alpha(aida::ui::resolved().border_strong, 0.59f * alpha);

	ImGui::PushStyleColor(ImGuiCol_FrameBg, frame_bg);
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, frame_hov);
	ImGui::PushStyleColor(ImGuiCol_FrameBgActive, frame_active);
	ImGui::PushStyleColor(ImGuiCol_Text, text_col);
	ImGui::PushStyleColor(ImGuiCol_TextDisabled, hint_col);
	ImGui::PushStyleColor(ImGuiCol_Border, border_col);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));

	ImGui::PushItemWidth(width);
	bool changed = ImGui::InputTextWithHint(id, placeholder, buf, bufsz);
	ImGui::PopItemWidth();

	ImGui::PopStyleVar(3);
	ImGui::PopStyleColor(6);

	return changed;
}

struct stat_strip_item_t {
	const char*  label;
	const char*  value;
	const char*  delta;
	int          delta_sign;
	const float* sparkline;
	int          sparkline_count;
	ImU32        value_color;
};

inline void render_stat_strip(ImDrawList* dl, float x, float y, float w, float h,
							  const stat_strip_item_t* items, int count,
							  float ar, float ag, float ab, float alpha)
{
	if (!items || count <= 0 || w <= 0.f || h <= 0.f) return;

	const float pad_outer = 6.f;
	const float gap = 8.f;
	float avail = w - pad_outer * 2.f - gap * static_cast<float>(count - 1);
	if (avail < static_cast<float>(count)) return;
	float item_w = avail / static_cast<float>(count);

	const float line_h = ImGui::CalcTextSize("Ag").y;
	const float strip_pad_top = 6.f;
	const float strip_gap = 4.f;
	const float strip_pad_bot = 8.f;
	float needed_h = strip_pad_top + line_h + strip_gap + line_h + strip_pad_bot;
	float eff_h = h > needed_h ? h : needed_h;

	float cx = x + pad_outer;
	for (int i = 0; i < count; ++i) {
		float ix = cx;
		float iy = y;
		const auto& it = items[i];

		dl->AddRectFilled(ImVec2(ix, iy), ImVec2(ix + item_w, iy + eff_h),
			theme_alpha(aida::ui::resolved().panel_bg, 0.78f * alpha), 6.f);
		dl->AddRect(ImVec2(ix, iy), ImVec2(ix + item_w, iy + eff_h),
			theme_alpha(aida::ui::resolved().border_strong, 0.35f * alpha), 6.f, 0, 1.f);

		ImU32 accent_top = IM_COL32(
			static_cast<int>(ar * 255), static_cast<int>(ag * 255),
			static_cast<int>(ab * 255), static_cast<int>(110 * alpha));
		dl->AddRectFilled(ImVec2(ix + 6.f, iy), ImVec2(ix + item_w - 6.f, iy + 2.f),
			accent_top, 1.f);

		if (it.label) {
			dl->AddText(ImVec2(ix + 10.f, iy + strip_pad_top),
				theme_alpha(aida::ui::resolved().text_dim, alpha), it.label);
		}

		float value_baseline_y = iy + eff_h - strip_pad_bot;
		if (it.value) {
			ImU32 vc = it.value_color ? theme_alpha(it.value_color, alpha)
									  : theme_alpha(aida::ui::resolved().text_primary, alpha);
			ImVec2 vs = ImGui::CalcTextSize(it.value);
			float vy = value_baseline_y - vs.y;
			dl->AddText(ImVec2(ix + 10.f, vy), vc, it.value);

			if (it.delta) {
				ImU32 dc;
				if (it.delta_sign > 0)
					dc = theme_alpha(aida::ui::resolved().success, alpha);
				else if (it.delta_sign < 0)
					dc = theme_alpha(aida::ui::resolved().error, alpha);
				else
					dc = theme_alpha(aida::ui::resolved().text_secondary, alpha);
				dl->AddText(ImVec2(ix + 10.f + vs.x + 8.f, vy + 1.f), dc, it.delta);
			}
		}

		if (it.sparkline && it.sparkline_count > 1) {
			float sw = item_w * 0.38f;
			float sh = h - 14.f;
			if (sw > 16.f && sh > 6.f) {
				float sx = ix + item_w - sw - 8.f;
				float sy = iy + 6.f;
				ImU32 sc = IM_COL32(
					static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					static_cast<int>(ab * 255), static_cast<int>(230 * alpha));
				render_mini_sparkline(dl, sx, sy, sw, sh,
					it.sparkline, it.sparkline_count, sc, alpha);
			}
		}

		cx += item_w + gap;
	}
}

inline void render_graph_node_card(ImDrawList* dl, float x, float y, float w, float h,
								   const char* header_text, bool is_entry, bool is_selected,
								   float ar, float ag, float ab, float alpha, float time,
								   float font_scale = 1.f)
{
	if (font_scale < 0.30f) font_scale = 0.30f;
	if (font_scale > 3.00f) font_scale = 3.00f;

	ImFont* hdr_font = aida::ui::fonts::body_em();
	if (!hdr_font) hdr_font = ImGui::GetFont();
	float hdr_base = aida::ui::fonts::size_or(hdr_font, 13.f);

	const float rounding = 7.f * font_scale;
	const float header_h = (hdr_base + 8.f) * font_scale;

	dl->AddRectFilled(ImVec2(x + 3.f, y + 4.f), ImVec2(x + w + 3.f, y + h + 4.f),
		IM_COL32(0, 0, 0, static_cast<int>(70 * alpha)), rounding);

	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
		theme_alpha(aida::ui::resolved().panel_bg, 0.94f * alpha), rounding);

	ImU32 hdr_left;
	ImU32 hdr_right;
	if (is_entry) {
		hdr_left  = IM_COL32(
			static_cast<int>(ar * 200 + 20), static_cast<int>(ag * 200 + 20),
			static_cast<int>(ab * 200 + 20), static_cast<int>(225 * alpha));
		hdr_right = IM_COL32(
			static_cast<int>(ar * 140), static_cast<int>(ag * 140),
			static_cast<int>(ab * 140), static_cast<int>(200 * alpha));
	} else {
		hdr_left  = theme_alpha(aida::ui::resolved().panel_header, 0.94f * alpha);
		hdr_right = theme_alpha(aida::ui::resolved().bg_overlay, 0.88f * alpha);
	}
	int hdr_lr = (hdr_left >> IM_COL32_R_SHIFT) & 0xFF;
	int hdr_lg = (hdr_left >> IM_COL32_G_SHIFT) & 0xFF;
	int hdr_lb = (hdr_left >> IM_COL32_B_SHIFT) & 0xFF;
	int hdr_la = (hdr_left >> IM_COL32_A_SHIFT) & 0xFF;
	int hdr_rr = (hdr_right >> IM_COL32_R_SHIFT) & 0xFF;
	int hdr_rg = (hdr_right >> IM_COL32_G_SHIFT) & 0xFF;
	int hdr_rb = (hdr_right >> IM_COL32_B_SHIFT) & 0xFF;
	int hdr_ra = (hdr_right >> IM_COL32_A_SHIFT) & 0xFF;
	float hdr_t = 0.45f;
	ImU32 hdr_mix = IM_COL32(
		static_cast<int>(static_cast<float>(hdr_lr) + static_cast<float>(hdr_rr - hdr_lr) * hdr_t),
		static_cast<int>(static_cast<float>(hdr_lg) + static_cast<float>(hdr_rg - hdr_lg) * hdr_t),
		static_cast<int>(static_cast<float>(hdr_lb) + static_cast<float>(hdr_rb - hdr_lb) * hdr_t),
		static_cast<int>(static_cast<float>(hdr_la) + static_cast<float>(hdr_ra - hdr_la) * hdr_t));
	dl->AddRectFilled(
		ImVec2(x + 1.f, y + 1.f), ImVec2(x + w - 1.f, y + header_h),
		hdr_mix, rounding, ImDrawFlags_RoundCornersTop);

	dl->AddLine(ImVec2(x + 4.f, y + header_h), ImVec2(x + w - 4.f, y + header_h),
		IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
				 static_cast<int>(ab * 255), static_cast<int>(130 * alpha)), 1.f * font_scale);

	if (header_text) {
		float scaled_font_size = hdr_base * font_scale;
		ImVec2 ts = hdr_font->CalcTextSizeA(scaled_font_size, FLT_MAX, 0.f, header_text);
		ImU32 title_col = is_entry
			? theme_alpha(aida::ui::resolved().bg_base, 0.96f * alpha)
			: IM_COL32(
				static_cast<int>(ar * 200 + 55), static_cast<int>(ag * 200 + 55),
				static_cast<int>(ab * 200 + 55), static_cast<int>(alpha * 240));
		dl->AddText(hdr_font, scaled_font_size,
			ImVec2(x + 10.f * font_scale, y + (header_h - ts.y) * 0.5f),
			title_col, header_text);
	}

	if (is_selected) {
		float pulse = (std::sin(time * 3.5f) + 1.f) * 0.5f;
		ImU32 ring_core = IM_COL32(
			static_cast<int>(ar * 255), static_cast<int>(ag * 255),
			static_cast<int>(ab * 255), static_cast<int>((180 + pulse * 55) * alpha));
		ImU32 ring_halo = IM_COL32(
			static_cast<int>(ar * 255), static_cast<int>(ag * 255),
			static_cast<int>(ab * 255), static_cast<int>(60 * alpha * (0.4f + pulse * 0.6f)));
		dl->AddRect(ImVec2(x - 2.f, y - 2.f), ImVec2(x + w + 2.f, y + h + 2.f),
			ring_halo, rounding + 2.f, 0, 2.f * font_scale);
		dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h), ring_core, rounding, 0, 1.8f * font_scale);
	} else {
		dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
			theme_alpha(aida::ui::resolved().border_strong, 0.63f * alpha), rounding, 0, 1.f * font_scale);
	}
}

}
