#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include <cmath>

namespace aida::ui::brand {

	inline void render_logomark(ImDrawList* dl, ImVec2 center, float size,
	                              float reveal = 1.f, float pulse = 0.f, float alpha = 1.f) {
		const auto& t = aida::ui::resolved();

		float r = size * 0.5f;
		float reveal_clamped = reveal;
		if (reveal_clamped < 0.f) reveal_clamped = 0.f;
		if (reveal_clamped > 1.f) reveal_clamped = 1.f;

		float halo_r = r * (1.4f + pulse * 0.15f);
		ImU32 halo = aida::ui::with_alpha(t.accent_glow, alpha * (0.45f + pulse * 0.35f) * reveal_clamped);
		for (int i = 0; i < 5; ++i) {
			float rr = halo_r + (float)i * size * 0.08f;
			float ha = (1.f - (float)i / 5.f) * 0.25f;
			dl->AddCircleFilled(center, rr, aida::ui::with_alpha(halo, ha), 32);
		}

		ImU32 stroke_col_top = aida::ui::with_alpha(t.accent_grad_top, alpha * reveal_clamped);
		ImU32 stroke_col_bot = aida::ui::with_alpha(t.accent_grad_bot, alpha * reveal_clamped);

		float th = size * 0.10f;

		ImVec2 left_top    = ImVec2(center.x - r * 0.55f, center.y + r * 0.65f);
		ImVec2 left_apex   = ImVec2(center.x - r * 0.05f, center.y - r * 0.65f);
		ImVec2 right_apex  = ImVec2(center.x + r * 0.05f, center.y - r * 0.65f);
		ImVec2 right_bot   = ImVec2(center.x + r * 0.55f, center.y + r * 0.65f);
		ImVec2 cross_left  = ImVec2(center.x - r * 0.30f, center.y + r * 0.05f);
		ImVec2 cross_right = ImVec2(center.x + r * 0.30f, center.y + r * 0.05f);

		auto draw_segment = [&](ImVec2 a, ImVec2 b, float t0, float t1) {
			if (reveal_clamped <= t0) return;
			float local = (reveal_clamped - t0) / (t1 - t0);
			if (local > 1.f) local = 1.f;
			if (local <= 0.f) return;
			float eased = aida::motion::ease::out_cubic(local);
			ImVec2 p1 = a;
			ImVec2 p2 = ImVec2(a.x + (b.x - a.x) * eased, a.y + (b.y - a.y) * eased);
			dl->AddLine(p1, p2, stroke_col_top, th);
		};

		draw_segment(left_top, left_apex,    0.00f, 0.45f);
		draw_segment(left_apex, right_apex,  0.30f, 0.50f);
		draw_segment(right_apex, right_bot,  0.40f, 0.85f);
		draw_segment(cross_left, cross_right,0.65f, 0.95f);

		(void)stroke_col_bot;
	}

	inline float wordmark_total_width(ImFont* font, float scale) {
		const char* letters = "AiDA";
		float font_size = 32.f * scale;
		float tracking = 4.f * scale;
		float total = 0.f;
		for (int i = 0; i < 4; ++i) {
			char buf[2] = { letters[i], 0 };
			total += font->CalcTextSizeA(font_size, FLT_MAX, 0.f, buf).x;
			if (i < 3) total += tracking;
		}
		return total;
	}

	inline void render_wordmark(ImDrawList* dl, ImVec2 origin, float scale,
	                              ImFont* font, float reveal = 1.f, float alpha = 1.f) {
		const auto& t = aida::ui::resolved();
		const char* letters = "AiDA";
		float font_size = 32.f * scale;
		float tracking = 4.f * scale;
		ImU32 col_base = aida::ui::with_alpha(t.text_primary, alpha);
		float x = origin.x;
		for (int i = 0; i < 4; ++i) {
			float t0 = (float)i * 0.12f;
			float t1 = t0 + 0.35f;
			float local = (reveal - t0) / (t1 - t0);
			if (local < 0.f) local = 0.f;
			if (local > 1.f) local = 1.f;
			float eased = aida::motion::ease::out_quint(local);
			float la = eased;
			ImU32 c = aida::ui::with_alpha(col_base, la * alpha);
			char buf[2] = { letters[i], 0 };
			float glyph_w = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, buf).x;
			float yoff = (1.f - eased) * 8.f * scale;
			dl->AddText(font, font_size, ImVec2(x, origin.y + yoff), c, buf);
			x += glyph_w;
			if (i < 3) x += tracking;
		}
	}

	inline void render_orbit_ring(ImDrawList* dl, ImVec2 center, float radius,
	                                int segments, float speed, ImU32 col, float alpha = 1.f) {
		float t = aida::ui::clock::seconds() * speed;
		for (int i = 0; i < segments; ++i) {
			float ang = t + ((float)i / (float)segments) * 6.2831853f;
			float dot_a = (sinf(ang * 1.3f + t * 0.5f) * 0.5f + 0.5f) * 0.85f + 0.15f;
			ImVec2 p = ImVec2(center.x + cosf(ang) * radius, center.y + sinf(ang) * radius);
			dl->AddCircleFilled(p, 2.5f, aida::ui::with_alpha(col, alpha * dot_a), 12);
		}
	}

	inline void render_sparkle_burst(ImDrawList* dl, ImVec2 center,
	                                   float t01, float max_radius,
	                                   ImU32 col, int count = 8) {
		if (t01 <= 0.f) return;
		float r = max_radius * aida::motion::ease::out_quint(t01);
		float fade = 1.f - t01;
		for (int i = 0; i < count; ++i) {
			float ang = ((float)i / (float)count) * 6.2831853f;
			ImVec2 p = ImVec2(center.x + cosf(ang) * r, center.y + sinf(ang) * r);
			dl->AddCircleFilled(p, 2.f * fade, aida::ui::with_alpha(col, fade), 8);
		}
	}

	inline void render_constellation(ImDrawList* dl, ImVec2 center, float radius,
	                                   int dot_count, float t_seconds, ImU32 col,
	                                   const float* per_dot_brightness = nullptr) {
		for (int i = 0; i < dot_count; ++i) {
			float ang = ((float)i / (float)dot_count) * 6.2831853f + t_seconds * 0.45f;
			ImVec2 p = ImVec2(center.x + cosf(ang) * radius, center.y + sinf(ang) * radius);
			float wave = (sinf(t_seconds * 1.5f + (float)i * 0.7f) * 0.5f + 0.5f);
			float br = 0.3f + wave * 0.5f;
			if (per_dot_brightness) br = per_dot_brightness[i];
			float halo_a = br * 0.5f;
			dl->AddCircleFilled(p, 4.f, aida::ui::with_alpha(col, halo_a * 0.4f), 12);
			dl->AddCircleFilled(p, 2.f, aida::ui::with_alpha(col, halo_a), 12);
		}
	}

	inline void render_check_drawn(ImDrawList* dl, ImVec2 center, float size,
	                                 float t01, ImU32 col, float thickness = 2.5f) {
		if (t01 <= 0.f) return;
		float p = aida::motion::ease::out_quint(t01);
		ImVec2 a = ImVec2(center.x - size * 0.45f, center.y);
		ImVec2 b = ImVec2(center.x - size * 0.10f, center.y + size * 0.30f);
		ImVec2 c = ImVec2(center.x + size * 0.50f, center.y - size * 0.35f);
		float pa = p < 0.5f ? p * 2.f : 1.f;
		float pb = p < 0.5f ? 0.f : (p - 0.5f) * 2.f;
		ImVec2 ab = ImVec2(a.x + (b.x - a.x) * pa, a.y + (b.y - a.y) * pa);
		dl->AddLine(a, ab, col, thickness);
		if (pb > 0.f) {
			ImVec2 bc = ImVec2(b.x + (c.x - b.x) * pb, b.y + (c.y - b.y) * pb);
			dl->AddLine(b, bc, col, thickness);
		}
	}

	inline void render_lock_icon(ImDrawList* dl, ImVec2 center, float size,
	                               ImU32 stroke, ImU32 accent_fill, float alpha = 1.f) {
		float body_w = size * 0.78f;
		float body_h = size * 0.62f;
		float shackle_r = size * 0.30f;
		float shackle_thickness = size * 0.12f;
		float total_h = body_h + shackle_r + shackle_thickness * 0.5f;
		float top_y = center.y - total_h * 0.5f;
		float arc_y = top_y + shackle_r + shackle_thickness * 0.5f;
		float body_top_y = arc_y;
		float body_bot_y = body_top_y + body_h;
		float radius = size * 0.13f;
		ImVec2 body_a = ImVec2(center.x - body_w * 0.5f, body_top_y);
		ImVec2 body_b = ImVec2(center.x + body_w * 0.5f, body_bot_y);
		dl->AddRectFilled(body_a, body_b, aida::ui::with_alpha(accent_fill, alpha * 0.20f), radius);
		dl->AddRect(body_a, body_b, aida::ui::with_alpha(stroke, alpha), radius, 0, size * 0.06f);

		ImVec2 arc_c = ImVec2(center.x, arc_y);
		dl->PathArcTo(arc_c, shackle_r, IM_PI, 2.f * IM_PI, 36);
		dl->PathStroke(aida::ui::with_alpha(stroke, alpha), 0, shackle_thickness * 0.65f);

		float kh_w = size * 0.10f;
		float kh_r = size * 0.045f;
		float kh_y = body_top_y + body_h * 0.40f;
		ImVec2 kh_c = ImVec2(center.x, kh_y);
		dl->AddCircleFilled(kh_c, kh_r, aida::ui::with_alpha(stroke, alpha), 16);
		ImVec2 kh_a = ImVec2(center.x - kh_w * 0.18f, kh_y);
		ImVec2 kh_b = ImVec2(center.x + kh_w * 0.18f, kh_y + size * 0.16f);
		dl->AddRectFilled(kh_a, kh_b, aida::ui::with_alpha(stroke, alpha), size * 0.018f);
	}

	inline ImU32 hash_color(const char* seed, float lightness_target = 0.55f) {
		uint32_t h = 2166136261u;
		while (*seed) { h ^= (uint8_t)*seed++; h *= 16777619u; }
		float hue = (float)(h % 360u) / 360.f;
		float s = 0.55f;
		float l = lightness_target;

		float c = (1.f - fabsf(2.f * l - 1.f)) * s;
		float hp = hue * 6.f;
		float x = c * (1.f - fabsf(fmodf(hp, 2.f) - 1.f));
		float r = 0, g = 0, b = 0;
		if      (hp < 1) { r = c; g = x; b = 0; }
		else if (hp < 2) { r = x; g = c; b = 0; }
		else if (hp < 3) { r = 0; g = c; b = x; }
		else if (hp < 4) { r = 0; g = x; b = c; }
		else if (hp < 5) { r = x; g = 0; b = c; }
		else             { r = c; g = 0; b = x; }
		float m = l - c * 0.5f;
		int ri = (int)((r + m) * 255.f);
		int gi = (int)((g + m) * 255.f);
		int bi = (int)((b + m) * 255.f);
		if (ri < 0) ri = 0; if (ri > 255) ri = 255;
		if (gi < 0) gi = 0; if (gi > 255) gi = 255;
		if (bi < 0) bi = 0; if (bi > 255) bi = 255;
		return IM_COL32(ri, gi, bi, 255);
	}

}
