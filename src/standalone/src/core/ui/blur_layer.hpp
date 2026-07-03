#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include <atomic>

namespace aida::ui::blur {

	struct layer_request_t {
		ImVec2 pos;
		ImVec2 size;
		float  radius   = 8.f;
		float  strength = 0.6f;
		float  alpha    = 1.f;
		ImU32  tint     = 0;
		bool   accent_glow = false;
	};

	namespace detail {
		inline std::atomic<bool> s_blur_supported{ false };
	}

	inline void mark_supported(bool s) { detail::s_blur_supported.store(s, std::memory_order_release); }
	inline bool supported() { return detail::s_blur_supported.load(std::memory_order_acquire); }

	inline void schedule(const layer_request_t& r) {
		(void)r;
	}

	inline void schedule_simple(ImVec2 pos, ImVec2 size, float radius = 8.f,
	                             float strength = 0.6f, float alpha = 1.f) {
		layer_request_t r;
		r.pos = pos;
		r.size = size;
		r.radius = radius;
		r.strength = strength;
		r.alpha = alpha;
		schedule(r);
	}

	inline void render_glass_fill(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                               float radius, float alpha = 1.f) {
		const auto& t = aida::ui::resolved();
		ImU32 fill = aida::ui::with_alpha(t.panel_bg, alpha);
		ImU32 tint = aida::ui::with_alpha(t.glass_tint, alpha * 0.5f);
		dl->AddRectFilled(a, b, fill, radius);
		dl->AddRectFilled(a, b, tint, radius);
	}

	inline void render_glass_border(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                                 float radius, float alpha = 1.f, float thickness = 1.f) {
		const auto& t = aida::ui::resolved();
		ImU32 b1 = aida::ui::with_alpha(t.border_subtle, alpha);
		dl->AddRect(a, b, b1, radius, 0, thickness);
	}

	inline void render_inner_glow(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                               float radius, ImU32 col, int passes = 4) {
		for (int i = 0; i < passes; ++i) {
			float off = (float)(i + 1);
			float fade = 1.f - (float)i / (float)passes;
			ImU32 c = aida::ui::with_alpha(col, fade * 0.18f);
			dl->AddRect(ImVec2(a.x + off, a.y + off), ImVec2(b.x - off, b.y - off),
			            c, radius - off * 0.5f, 0, 1.f);
		}
	}

	inline void render_drop_shadow(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                                float radius, int passes = 4,
	                                float strength = 0.35f, ImVec2 offset = ImVec2(0.f, 4.f)) {
		const auto& t = aida::ui::resolved();
		ImU32 shadow_base = t.is_dark ? aida::ui::darken(t.bg_base, 18) : aida::ui::darken(t.text_dim, 18);
		float scheme_alpha = t.is_dark ? 0.46f : 0.32f;
		for (int i = 0; i < passes; ++i) {
			float spread = (float)(i + 1) * 1.6f;
			float fa = strength * (1.f - (float)i / (float)passes);
			ImU32 sh = aida::ui::with_alpha(shadow_base, fa * scheme_alpha);
			dl->AddRectFilled(
				ImVec2(a.x - spread + offset.x, a.y - spread + offset.y),
				ImVec2(b.x + spread + offset.x, b.y + spread + offset.y),
				sh, radius + spread);
		}
	}

}
