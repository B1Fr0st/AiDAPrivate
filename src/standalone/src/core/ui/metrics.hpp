#pragma once

#include "imgui/imgui.h"

namespace aida::ui::metrics {

	inline constexpr float grid = 4.f;

	namespace radius {
		inline constexpr float xs = 4.f;
		inline constexpr float sm = 6.f;
		inline constexpr float md = 8.f;
		inline constexpr float lg = 12.f;
		inline constexpr float modal = 14.f;
	}

	namespace spacing {
		inline constexpr float xs = 4.f;
		inline constexpr float sm = 6.f;
		inline constexpr float md = 8.f;
		inline constexpr float lg = 12.f;
		inline constexpr float xl = 16.f;
	}

	namespace control {
		inline constexpr float height_sm = 30.f;
		inline constexpr float height_md = 36.f;
		inline constexpr float height_lg = 44.f;
		inline constexpr float icon_button = 28.f;
		inline constexpr float icon_glyph = 14.f;
		inline constexpr float toolbar_h = 30.f;
		inline constexpr float input_h = 34.f;
	}

	namespace panel {
		inline constexpr float padding = 12.f;
		inline constexpr float padding_compact = 8.f;
		inline constexpr float header_h = 32.f;
		inline constexpr float overlay_margin = 32.f;
	}

	namespace tab {
		inline constexpr float inner_h = 30.f;
		inline constexpr float primary_h = 32.f;
		inline constexpr float document_h = 26.f;
	}

	namespace row {
		inline constexpr float compact = 22.f;
		inline constexpr float standard = 24.f;
		inline constexpr float inspector = 28.f;
	}

	inline ImVec2 pad_sm() { return ImVec2(spacing::lg, spacing::sm); }
	inline ImVec2 pad_md() { return ImVec2(spacing::xl, spacing::md + 2.f); }
	inline ImVec2 pad_lg() { return ImVec2(22.f, spacing::lg + 2.f); }

}
