#pragma once

#include "../../helpers/blur.h"
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
		inline constexpr int k_max_blur_draws_per_frame = 3;
		inline std::atomic<bool> s_blur_supported{ false };
		inline std::atomic<int> s_frame_index{ -1 };
		inline std::atomic<int> s_frame_draws{ 0 };
		inline std::atomic<unsigned long long> s_dropped_draws{ 0 };
	}

	inline void mark_supported(bool s) { detail::s_blur_supported.store(s, std::memory_order_release); }
	inline bool supported() { return detail::s_blur_supported.load(std::memory_order_acquire); }

	inline void schedule(const layer_request_t& r) {
		if (!supported() || !ImGui::GetCurrentContext() || r.alpha <= 0.f || r.size.x <= 1.f || r.size.y <= 1.f)
			return;
		int frame = ImGui::GetFrameCount();
		int observed = detail::s_frame_index.load(std::memory_order_acquire);
		if (observed != frame && detail::s_frame_index.compare_exchange_strong(observed, frame, std::memory_order_acq_rel))
			detail::s_frame_draws.store(0, std::memory_order_release);
		const int max_draws = Blur::InteractionPressureActive() ? 1 : detail::k_max_blur_draws_per_frame;
		int draw_index = detail::s_frame_draws.fetch_add(1, std::memory_order_acq_rel);
		if (draw_index >= max_draws) {
			detail::s_dropped_draws.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		ImDrawList* dl = ImGui::GetWindowDrawList();
		if (!dl)
			return;
		ImVec2 a = r.pos;
		ImVec2 b(r.pos.x + r.size.x, r.pos.y + r.size.y);
		Blur::Draw(dl, a, b);
		float alpha = r.alpha < 0.f ? 0.f : (r.alpha > 1.f ? 1.f : r.alpha);
		float strength = r.strength < 0.f ? 0.f : (r.strength > 1.f ? 1.f : r.strength);
		if (r.tint != 0)
			dl->AddRectFilled(a, b, aida::ui::with_alpha(r.tint, alpha * strength * 0.38f), r.radius);
		if (r.accent_glow) {
			const auto& t = aida::ui::resolved();
			dl->AddRect(a, b, aida::ui::with_alpha(t.accent, alpha * 0.28f), r.radius, 0, 1.15f);
		}
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
