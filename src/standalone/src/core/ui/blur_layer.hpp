#pragma once

#include "imgui/imgui.h"

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

	inline void mark_supported(bool) {}
	inline bool supported() { return false; }

	inline void schedule(const layer_request_t&) {}

	inline void render_glass_fill(ImDrawList*, ImVec2, ImVec2, float, float = 1.f) {}

	inline void render_glass_border(ImDrawList*, ImVec2, ImVec2, float, float = 1.f, float = 1.f) {}

	inline void render_inner_glow(ImDrawList*, ImVec2, ImVec2, float, ImU32, int = 4) {}

	inline void render_drop_shadow(ImDrawList*, ImVec2, ImVec2, float, int = 4,
	                              float = 0.35f, ImVec2 = ImVec2(0.f, 4.f)) {}

}
