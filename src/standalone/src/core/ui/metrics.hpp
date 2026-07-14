#pragma once

#include "imgui/imgui.h"

namespace aida::ui::metrics {

	inline constexpr float grid = 4.f;

	namespace radius {
		inline constexpr float xs = 3.f;
		inline constexpr float sm = 4.f;
		inline constexpr float md = 6.f;
		inline constexpr float lg = 8.f;
		inline constexpr float modal = 10.f;
		inline constexpr float pill = 999.f;
	}

	namespace spacing {
		inline constexpr float xxs = 2.f;
		inline constexpr float xs = grid;
		inline constexpr float sm = grid * 2.f;
		inline constexpr float md = grid * 3.f;
		inline constexpr float lg = grid * 4.f;
		inline constexpr float xl = grid * 5.f;
		inline constexpr float xxl = grid * 6.f;
		inline constexpr float section = grid * 8.f;
	}

	namespace control {
		inline constexpr float height_sm = 28.f;
		inline constexpr float height_md = 32.f;
		inline constexpr float height_lg = 40.f;
		inline constexpr float icon_button = 28.f;
		inline constexpr float icon_glyph = 14.f;
		inline constexpr float toolbar_h = 36.f;
		inline constexpr float input_h = 32.f;
		inline constexpr float search_h = 32.f;
		inline constexpr float checkbox = 16.f;
		inline constexpr float focus_ring = 2.f;
	}

	namespace panel {
		inline constexpr float padding = 12.f;
		inline constexpr float padding_compact = 8.f;
		inline constexpr float header_h = 40.f;
		inline constexpr float view_header_h = 56.f;
		inline constexpr float overlay_margin = 32.f;
		inline constexpr float border = 1.f;
	}

	namespace tab {
		inline constexpr float inner_h = 28.f;
		inline constexpr float primary_h = 32.f;
		inline constexpr float document_h = 28.f;
		inline constexpr float underline = 2.f;
		inline constexpr float padding_x = 12.f;
	}

	namespace row {
		inline constexpr float compact = 24.f;
		inline constexpr float standard = 28.f;
		inline constexpr float inspector = 32.f;
		inline constexpr float property_label_w = 132.f;
	}

	namespace table {
		inline constexpr float header_h = 30.f;
		inline constexpr float row_h = 28.f;
		inline constexpr float compact_row_h = 24.f;
		inline constexpr float cell_pad_x = 8.f;
		inline constexpr float cell_pad_y = 4.f;
	}

	namespace toolbar {
		inline constexpr float height = 36.f;
		inline constexpr float group_gap = 8.f;
		inline constexpr float separator_h = 20.f;
		inline constexpr float padding_x = 8.f;
		inline constexpr float padding_y = 4.f;
	}

	namespace status_bar {
		inline constexpr float height = 24.f;
		inline constexpr float padding_x = 8.f;
		inline constexpr float item_gap = 8.f;
		inline constexpr float dot = 5.f;
	}

	namespace splitter {
		inline constexpr float thickness = 5.f;
		inline constexpr float visible = 1.f;
		inline constexpr float hit_padding = 2.f;
	}

	namespace typography {
		inline constexpr float caption_scale = 0.86f;
		inline constexpr float body_scale = 0.94f;
		inline constexpr float title_scale = 1.12f;
		inline constexpr float view_title_scale = 1.20f;
		inline constexpr float code_line_height = 1.45f;
	}

	namespace motion {
		inline constexpr float instant = 0.08f;
		inline constexpr float fast = 0.14f;
		inline constexpr float standard = 0.20f;
		inline constexpr float emphasized = 0.28f;
		inline constexpr float theme = 0.24f;
	}

	inline ImVec2 pad_sm() { return ImVec2(spacing::md, spacing::xs); }
	inline ImVec2 pad_md() { return ImVec2(spacing::lg, spacing::sm); }
	inline ImVec2 pad_lg() { return ImVec2(spacing::xl, spacing::md); }

}
