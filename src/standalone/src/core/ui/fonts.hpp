#pragma once

#include "imgui/imgui.h"

extern ImFont* g_font_ui_400;
extern ImFont* g_font_ui_500;
extern ImFont* g_font_ui_600;
extern ImFont* g_font_ui_700;
extern ImFont* g_font_ui_400_lg;
extern ImFont* g_font_ui_500_sm;
extern ImFont* g_font_ui_700_xl;
extern ImFont* g_font_code_400;
extern ImFont* g_font_code_600;
extern ImFont* g_font_code_400_lg;

namespace aida::ui::fonts {
	struct font_policy_t {
		float scale = 1.f;
		float body_px = 16.5f;
		float large_px = 18.5f;
		float caption_px = 13.5f;
		float display_px = 28.f;
		float code_px = 14.5f;
		float code_large_px = 21.f;
		bool enable_lcd = false;
	};

	inline float scale_for_dpi(float dpi_scale) {
		if (!(dpi_scale > 0.f)) return 1.f;
		if (dpi_scale < 0.85f) return 0.85f;
		if (dpi_scale > 2.50f) return 2.50f;
		return dpi_scale;
	}

	inline float px(float value, float scale) {
		float scaled = value * scale_for_dpi(scale);
		if (scaled >= 1.f)
			return static_cast<float>(static_cast<int>(scaled + 0.5f));
		return scaled;
	}

	inline font_policy_t policy_for_dpi(float dpi_scale) {
		font_policy_t p;
		p.scale = scale_for_dpi(dpi_scale);
		p.body_px = px(16.5f, p.scale);
		p.large_px = px(18.5f, p.scale);
		p.caption_px = px(13.5f, p.scale);
		p.display_px = px(28.f, p.scale);
		p.code_px = px(14.5f, p.scale);
		p.code_large_px = px(21.f, p.scale);
		p.enable_lcd = p.scale >= 1.50f;
		return p;
	}

	inline float size_or(ImFont* font, float fallback_px) {
		return font && font->FontSize > 0.f ? font->FontSize : fallback_px;
	}

	inline ImFont* body()         { return g_font_ui_400; }
	inline ImFont* body_em()      { return g_font_ui_500; }
	inline ImFont* body_strong()  { return g_font_ui_600; }
	inline ImFont* h1()           { return g_font_ui_700; }
	inline ImFont* h2()           { return g_font_ui_600; }
	inline ImFont* lg()           { return g_font_ui_400_lg; }
	inline ImFont* caption()      { return g_font_ui_500_sm; }
	inline ImFont* display()      { return g_font_ui_700_xl; }
	inline ImFont* code()         { return g_font_code_400; }
	inline ImFont* code_em()      { return g_font_code_600; }
	inline ImFont* code_large()   { return g_font_code_400_lg ? g_font_code_400_lg : g_font_code_400; }
}
