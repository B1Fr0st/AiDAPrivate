#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "theme.hpp"
#include "clock.hpp"
#include "motion.hpp"
#include <cmath>

namespace aida {
namespace auth_view {
namespace brand_glyph {

	enum class kind_t : int {
		anthropic = 0,
		openai,
		github,
		generic
	};

	inline void render_anthropic(ImDrawList* dl, ImVec2 center, float size,
								  ImU32 stroke_top, ImU32 stroke_bot, float alpha)
	{
		float r = size * 0.5f;
		float thickness = size * 0.13f;
		ImU32 col_top = aida::ui::with_alpha(stroke_top, alpha);
		ImU32 col_bot = aida::ui::with_alpha(stroke_bot, alpha);

		ImVec2 left_base   = ImVec2(center.x - r * 0.78f, center.y + r * 0.74f);
		ImVec2 left_apex   = ImVec2(center.x - r * 0.06f, center.y - r * 0.74f);
		ImVec2 right_base  = ImVec2(center.x + r * 0.78f, center.y + r * 0.74f);
		ImVec2 right_apex  = ImVec2(center.x + r * 0.06f, center.y - r * 0.74f);

		ImVec2 left_mid  = ImVec2(center.x - r * 0.30f, center.y + r * 0.16f);
		ImVec2 right_mid = ImVec2(center.x + r * 0.30f, center.y + r * 0.16f);

		dl->AddLine(left_base,  left_apex,  col_top, thickness);
		dl->AddLine(right_base, right_apex, col_bot, thickness);
		dl->AddLine(left_mid,   right_mid,  aida::ui::mix(col_top, col_bot, 0.5f), thickness * 0.78f);

		float dot_r = thickness * 0.55f;
		dl->AddCircleFilled(left_base,  dot_r, col_top, 12);
		dl->AddCircleFilled(left_apex,  dot_r, col_top, 12);
		dl->AddCircleFilled(right_base, dot_r, col_bot, 12);
		dl->AddCircleFilled(right_apex, dot_r, col_bot, 12);
	}

	inline void render_openai(ImDrawList* dl, ImVec2 center, float size,
							   ImU32 stroke_top, ImU32 stroke_bot, float alpha,
							   float spin_seconds)
	{
		float r = size * 0.46f;
		float thickness = size * 0.10f;
		float petal_w = r * 1.10f;
		float petal_h = r * 0.36f;

		float angles[3] = { 0.f, 2.094395f, 4.188790f };
		ImU32 cols[3] = {
			aida::ui::with_alpha(stroke_top, alpha),
			aida::ui::with_alpha(aida::ui::mix(stroke_top, stroke_bot, 0.5f), alpha),
			aida::ui::with_alpha(stroke_bot, alpha)
		};

		float spin = spin_seconds * 0.45f;

		for (int i = 0; i < 3; ++i) {
			float ang = angles[i] + spin;
			float ca = cosf(ang);
			float sa = sinf(ang);

			constexpr int seg = 28;
			ImVec2 path[seg + 1];
			for (int j = 0; j <= seg; ++j) {
				float t = ((float)j / (float)seg) * 6.2831853f;
				float lx = cosf(t) * petal_w;
				float ly = sinf(t) * petal_h;
				ImVec2 p = ImVec2(
					center.x + lx * ca - ly * sa,
					center.y + lx * sa + ly * ca);
				path[j] = p;
			}
			for (int j = 0; j < seg; ++j) {
				dl->AddLine(path[j], path[j + 1], cols[i], thickness);
			}
		}

		dl->AddCircleFilled(center, thickness * 0.85f,
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 220), alpha), 18);
	}

	inline void render_github(ImDrawList* dl, ImVec2 center, float size,
							   ImU32 fill_top, ImU32 fill_bot, ImU32 stroke, float alpha)
	{
		float r = size * 0.50f;
		ImU32 a_top = aida::ui::with_alpha(fill_top, alpha);
		ImU32 a_bot = aida::ui::with_alpha(fill_bot, alpha);
		ImU32 a_str = aida::ui::with_alpha(stroke, alpha);

		ImVec2 a = ImVec2(center.x - r * 0.95f, center.y - r * 0.85f);
		ImVec2 b = ImVec2(center.x + r * 0.95f, center.y + r * 0.85f);

		{
			ImU32 gh_flat = aida::ui::mix(a_top, a_bot, 0.5f);
			dl->AddRectFilled(a, b, gh_flat, r * 0.32f);
		}
		dl->AddRect(a, b, a_str, r * 0.32f, 0, 1.f);

		float prompt_thickness = size * 0.10f;
		float chev_x = center.x - r * 0.40f;
		float chev_y = center.y;
		float chev_h = r * 0.42f;

		ImVec2 c0 = ImVec2(chev_x - r * 0.12f, chev_y - chev_h * 0.5f);
		ImVec2 c1 = ImVec2(chev_x + r * 0.10f, chev_y);
		ImVec2 c2 = ImVec2(chev_x - r * 0.12f, chev_y + chev_h * 0.5f);

		ImU32 ch_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 245), alpha);
		dl->AddLine(c0, c1, ch_col, prompt_thickness);
		dl->AddLine(c1, c2, ch_col, prompt_thickness);

		float bar_x0 = center.x + r * 0.06f;
		float bar_x1 = center.x + r * 0.46f;
		float bar_y  = center.y + r * 0.28f;
		dl->AddLine(ImVec2(bar_x0, bar_y), ImVec2(bar_x1, bar_y), ch_col, prompt_thickness);
	}

	inline void render(ImDrawList* dl, kind_t k, ImVec2 center, float radius,
					   ImU32 grad_top, ImU32 grad_bot, ImU32 ring_col, float alpha = 1.f)
	{
		const auto& th = aida::ui::resolved();

		ImU32 ring_a  = aida::ui::with_alpha(ring_col, alpha * 0.85f);
		ImU32 inner_a = aida::ui::with_alpha(grad_top, alpha * 0.18f);
		ImU32 inner_b = aida::ui::with_alpha(grad_bot, alpha * 0.10f);

		const int segs = 32;
		for (int i = 0; i < segs; ++i) {
			float a0 = ((float)i / segs) * 6.2831853f - 1.5707963f;
			float a1 = ((float)(i + 1) / segs) * 6.2831853f - 1.5707963f;
			float fy = (sinf(a0) + 1.f) * 0.5f;
			ImU32 col = aida::ui::mix(inner_a, inner_b, fy);
			ImVec2 p0 = ImVec2(center.x + cosf(a0) * radius, center.y + sinf(a0) * radius);
			ImVec2 p1 = ImVec2(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius);
			dl->AddTriangleFilled(center, p0, p1, col);
		}

		dl->AddCircle(center, radius, ring_a, 32, 1.4f);

		float inner_size = radius * 1.25f;
		switch (k) {
			case kind_t::anthropic:
				render_anthropic(dl, center, inner_size, grad_top, grad_bot, alpha);
				break;
			case kind_t::openai:
				render_openai(dl, center, inner_size, grad_top, grad_bot, alpha,
					aida::ui::clock::seconds());
				break;
			case kind_t::github:
				render_github(dl, center, inner_size,
					grad_top, grad_bot, th.text_primary, alpha);
				break;
			case kind_t::generic:
			default: {
				ImU32 dot_col = aida::ui::with_alpha(grad_top, alpha);
				dl->AddCircleFilled(center, radius * 0.30f, dot_col, 16);
				break;
			}
		}
	}

}
}
}
