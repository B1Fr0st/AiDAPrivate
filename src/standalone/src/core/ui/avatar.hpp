#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "brand.hpp"
#include <cstring>
#include <cstdio>
#include <string_view>

namespace aida::ui::avatar {

	enum class kind_t {
		gradient,
		initial,
		brand_glyph
	};

	inline char first_glyph(std::string_view seed) {
		for (char c : seed) {
			if ((c >= 'A' && c <= 'Z')) return c;
			if ((c >= 'a' && c <= 'z')) return (char)(c - 'a' + 'A');
			if ((c >= '0' && c <= '9')) return c;
		}
		return seed.empty() ? '?' : seed.front();
	}

	inline void render(ImDrawList* dl, ImVec2 center, float radius,
	                    std::string_view seed, kind_t kind = kind_t::gradient,
	                    bool ring = true, float alpha = 1.f, ImFont* font = nullptr) {
		const auto& t = aida::ui::resolved();
		ImU32 base = aida::ui::brand::hash_color(std::string(seed).c_str(), t.is_dark ? 0.55f : 0.50f);

		if (kind == kind_t::gradient) {
			ImU32 top = aida::ui::lighten(base, 30);
			ImU32 bot = aida::ui::darken(base, 20);
			int segs = 32;
			for (int i = 0; i < segs; ++i) {
				float a0 = ((float)i / segs) * 6.2831853f - 1.5707963f;
				float a1 = ((float)(i + 1) / segs) * 6.2831853f - 1.5707963f;
				float fy = (sinf(a0) + 1.f) * 0.5f;
				ImU32 col = aida::ui::mix(top, bot, fy);
				ImVec2 p0 = ImVec2(center.x + cosf(a0) * radius, center.y + sinf(a0) * radius);
				ImVec2 p1 = ImVec2(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius);
				dl->AddTriangleFilled(center, p0, p1, aida::ui::with_alpha(col, alpha));
			}
		} else {
			dl->AddCircleFilled(center, radius, aida::ui::with_alpha(base, alpha), 32);
		}

		if (ring) {
			ImU32 ring_col = aida::ui::with_alpha(t.is_dark ? IM_COL32(255, 255, 255, 60) : IM_COL32(0, 0, 0, 50), alpha);
			dl->AddCircle(center, radius - 0.5f, ring_col, 32, 1.f);
		}

		if (kind != kind_t::brand_glyph) {
			char glyph[2] = { first_glyph(seed), 0 };
			ImFont* f = font ? font : ImGui::GetFont();
			float fs = radius * 1.05f;
			ImU32 text_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 240), alpha);

			float r_lin = (float)((base >> IM_COL32_R_SHIFT) & 0xFF) / 255.f;
			float g_lin = (float)((base >> IM_COL32_G_SHIFT) & 0xFF) / 255.f;
			float b_lin = (float)((base >> IM_COL32_B_SHIFT) & 0xFF) / 255.f;
			float lum = 0.299f * r_lin + 0.587f * g_lin + 0.114f * b_lin;
			if (lum > 0.65f) text_col = aida::ui::with_alpha(IM_COL32(20, 20, 30, 240), alpha);

			ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, glyph);
			dl->AddText(f, fs, ImVec2(center.x - sz.x * 0.5f, center.y - sz.y * 0.5f),
			            text_col, glyph);
		}
	}

}
