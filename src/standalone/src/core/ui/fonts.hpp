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

namespace aida::ui::fonts {
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
}
