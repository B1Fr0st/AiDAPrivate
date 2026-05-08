#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "motion.hpp"

namespace aida::ui::skeleton {

	inline void render_block(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                          float radius = 6.f, float speed = 1.5f) {
		const auto& tk = aida::ui::resolved();
		float t = aida::ui::clock::seconds() * speed;
		float phase = fmodf(t, 1.f);

		ImU32 base_col   = aida::ui::with_alpha(tk.panel_header, 0.85f);
		ImU32 sweep_col  = aida::ui::with_alpha(tk.accent_glow, 0.55f);
		dl->AddRectFilled(a, b, base_col, radius);

		float w = b.x - a.x;
		float sweep_x = a.x - w * 0.4f + (w * 1.4f) * phase;
		float sweep_w = w * 0.35f;

		dl->PushClipRect(a, b, true);
		dl->AddRectFilledMultiColor(
			ImVec2(sweep_x, a.y),
			ImVec2(sweep_x + sweep_w * 0.5f, b.y),
			IM_COL32(0,0,0,0), sweep_col, sweep_col, IM_COL32(0,0,0,0));
		dl->AddRectFilledMultiColor(
			ImVec2(sweep_x + sweep_w * 0.5f, a.y),
			ImVec2(sweep_x + sweep_w, b.y),
			sweep_col, IM_COL32(0,0,0,0), IM_COL32(0,0,0,0), sweep_col);
		dl->PopClipRect();
	}

	inline void render_text_line(ImDrawList* dl, ImVec2 origin, float width,
	                                float height = 12.f, float speed = 1.5f) {
		render_block(dl, origin, ImVec2(origin.x + width, origin.y + height),
		              height * 0.5f, speed);
	}

	inline void render_paragraph(ImDrawList* dl, ImVec2 origin, float max_width,
	                                int line_count = 4, float line_height = 14.f,
	                                float gap = 8.f, float speed = 1.5f) {
		float widths[8] = { 1.0f, 0.92f, 0.86f, 0.97f, 0.78f, 0.92f, 0.71f, 0.85f };
		for (int i = 0; i < line_count; ++i) {
			float w = max_width * widths[i % 8];
			float y = origin.y + (line_height + gap) * (float)i;
			render_text_line(dl, ImVec2(origin.x, y), w, line_height, speed);
		}
	}

	inline void render_avatar(ImDrawList* dl, ImVec2 center, float radius,
	                            float speed = 1.5f) {
		const auto& tk = aida::ui::resolved();
		float t = aida::ui::clock::seconds() * speed;
		float pulse = (sinf(t) * 0.5f + 0.5f) * 0.4f + 0.6f;
		dl->AddCircleFilled(center, radius,
		                    aida::ui::with_alpha(tk.panel_header, pulse), 24);
	}

	inline void render_card(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                          float radius = 10.f, float speed = 1.5f) {
		render_block(dl, a, b, radius, speed);

		float pad = 14.f;
		float left = a.x + pad;
		float top  = a.y + pad;
		float aw   = b.x - a.x - pad * 2.f;

		dl->PushClipRect(ImVec2(a.x + 1.f, a.y + 1.f), ImVec2(b.x - 1.f, b.y - 1.f), true);

		render_avatar(dl, ImVec2(left + 14.f, top + 14.f), 14.f, speed);
		render_text_line(dl, ImVec2(left + 36.f, top + 6.f),  aw * 0.55f, 11.f, speed);
		render_text_line(dl, ImVec2(left + 36.f, top + 20.f), aw * 0.30f, 9.f,  speed);
		render_text_line(dl, ImVec2(left,        top + 50.f), aw * 0.95f, 10.f, speed);
		render_text_line(dl, ImVec2(left,        top + 66.f), aw * 0.78f, 10.f, speed);
		render_text_line(dl, ImVec2(left,        top + 82.f), aw * 0.65f, 10.f, speed);

		dl->PopClipRect();
	}

	inline void render_table_rows(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                                int cols = 4, int rows = 8,
	                                float row_h = 22.f, float speed = 1.5f) {
		float w = b.x - a.x;
		float col_w = w / (float)cols;
		for (int r = 0; r < rows; ++r) {
			float y = a.y + (float)r * (row_h + 4.f);
			if (y + row_h > b.y) break;
			for (int ci = 0; ci < cols; ++ci) {
				float cx = a.x + col_w * (float)ci + 8.f;
				float cw = col_w * (0.6f + 0.3f * (float)((r * 3 + ci * 7) % 5) / 4.f) - 16.f;
				if (cw < 12.f) cw = 12.f;
				render_text_line(dl, ImVec2(cx, y + 6.f), cw, 10.f, speed);
			}
		}
	}

}
