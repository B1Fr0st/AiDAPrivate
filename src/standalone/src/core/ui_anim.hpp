#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include "imgui/imgui.h"

namespace ui_anim {

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
	int r = ra + static_cast<int>((rb - ra) * t);
	int g = ga + static_cast<int>((gb - ga) * t);
	int b = ba + static_cast<int>((bb - ba) * t);
	int a = aa + static_cast<int>((ab - aa) * t);
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
					  IM_COL32(20, 22, 28, static_cast<int>(60 * alpha)), 2.f);

	ImVec2 thumb_min(ox, thumb_y);
	ImVec2 thumb_max(ox + bar_w, thumb_y + thumb_h);
	bool hovered = ImGui::IsMouseHoveringRect(thumb_min, thumb_max, false);

	ImU32 thumb_col = IM_COL32(80, 85, 100, static_cast<int>((dragging ? 180 : hovered ? 140 : 90) * alpha));
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
	for (int i = 0; i < segments; ++i) {
		float t0 = arc_start + (static_cast<float>(i) / segments) * arc_len;
		float t1 = arc_start + (static_cast<float>(i + 1) / segments) * arc_len;
		float a0 = static_cast<float>(i) / segments;
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
	const float start_angle = -1.5707963f;

	for (int i = 0; i < segments; ++i) {
		float t0 = start_angle + (static_cast<float>(i) / segments) * 6.2831853f;
		float t1 = start_angle + (static_cast<float>(i + 1) / segments) * 6.2831853f;
		dl->AddLine(
			ImVec2(cx + std::cos(t0) * radius, cy + std::sin(t0) * radius),
			ImVec2(cx + std::cos(t1) * radius, cy + std::sin(t1) * radius),
			bg_color, thickness);
	}

	int fill_segs = static_cast<int>(progress * segments);
	for (int i = 0; i < fill_segs; ++i) {
		float t0 = start_angle + (static_cast<float>(i) / segments) * 6.2831853f;
		float t1 = start_angle + (static_cast<float>(i + 1) / segments) * 6.2831853f;
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
		dl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, static_cast<int>(8 * alpha)));
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
	if (!method || !method[0]) return IM_COL32(180, 180, 180, static_cast<int>(alpha * 255));
	char c0 = method[0];
	char c1 = method[1] ? method[1] : 0;
	if (c0 == 'G') return IM_COL32(80, 200, 120, static_cast<int>(alpha * 255));
	if (c0 == 'P' && c1 == 'O') return IM_COL32(100, 150, 255, static_cast<int>(alpha * 255));
	if (c0 == 'P' && c1 == 'U') return IM_COL32(240, 170, 60, static_cast<int>(alpha * 255));
	if (c0 == 'P' && c1 == 'A') return IM_COL32(180, 120, 255, static_cast<int>(alpha * 255));
	if (c0 == 'D') return IM_COL32(230, 70, 70, static_cast<int>(alpha * 255));
	if (c0 == 'H') return IM_COL32(200, 200, 200, static_cast<int>(alpha * 255));
	if (c0 == 'O') return IM_COL32(170, 200, 230, static_cast<int>(alpha * 255));
	return IM_COL32(180, 180, 180, static_cast<int>(alpha * 255));
}

inline ImU32 value_change_color(int64_t curr, int64_t prev, float alpha)
{
	if (curr > prev) return IM_COL32(80, 220, 100, static_cast<int>(alpha * 255));
	if (curr < prev) return IM_COL32(230, 80, 80, static_cast<int>(alpha * 255));
	return IM_COL32(200, 200, 200, static_cast<int>(alpha * 255));
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

}
