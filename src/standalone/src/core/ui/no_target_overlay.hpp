#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "fonts.hpp"
#include "empty_state.hpp"

#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/globals.h"
#include "../debugger/spawn_target_dialog.hpp"

#include <string>

extern HWND g_hwnd;

namespace analysis_session {
bool open_session(const std::string& path);
}

namespace aida::ui::no_target_overlay {

	inline bool render_button(ImDrawList* dl, ImVec2 a, ImVec2 b,
		const char* id, const char* label, ImU32 base_col, ImU32 hover_col, ImU32 text_col, float alpha)
	{
		ImGui::SetCursorScreenPos(a);
		ImGui::InvisibleButton(id, ImVec2(b.x - a.x, b.y - a.y));
		bool hov = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		ImU32 fill = aida::ui::with_alpha(hov ? hover_col : base_col, (hov ? 0.95f : 0.80f) * alpha);
		dl->AddRectFilled(a, b, fill, 8.f);
		dl->AddRect(a, b, aida::ui::with_alpha(text_col, alpha * 0.30f), 8.f, 0, 1.f);
		ImVec2 ts = ImGui::CalcTextSize(label);
		dl->AddText(ImVec2(a.x + (b.x - a.x - ts.x) * 0.5f, a.y + (b.y - a.y - ts.y) * 0.5f),
			aida::ui::with_alpha(text_col, alpha), label);
		return clicked;
	}

	inline void render(ImVec2 region_pos, ImVec2 region_size,
		const char* title_text, const char* subtitle_text, float alpha,
		aida::ui::empty_state::glyph_t glyph = aida::ui::empty_state::glyph_t::binary_file)
	{
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();

		dl->AddRectFilled(region_pos,
			ImVec2(region_pos.x + region_size.x, region_pos.y + region_size.y),
			aida::ui::with_alpha(t.bg_base, alpha * 0.95f));

		float card_w = 480.f;
		if (card_w > region_size.x - 32.f) card_w = region_size.x - 32.f;
		float card_h = 320.f;
		if (card_h > region_size.y - 32.f) card_h = region_size.y - 32.f;
		float cx = region_pos.x + (region_size.x - card_w) * 0.5f;
		float cy = region_pos.y + (region_size.y - card_h) * 0.5f;
		ImVec2 ca(cx, cy);
		ImVec2 cb(cx + card_w, cy + card_h);

		dl->AddRectFilled(ca, cb, aida::ui::with_alpha(t.panel_bg, alpha * 0.92f), 12.f);
		dl->AddRect(ca, cb, aida::ui::with_alpha(t.border_subtle, alpha * 0.85f), 12.f, 0, 1.2f);

		float gx = ca.x + card_w * 0.5f;
		float gy = ca.y + 60.f;
		aida::ui::empty_state::render_glyph(glyph, dl, ImVec2(gx, gy), 52.f,
			t.accent_dim, alpha);

		ImFont* title_font = aida::ui::fonts::body_strong();
		ImFont* body_font  = ImGui::GetFont();
		if (!title_font) title_font = body_font;
		float ui_size = ImGui::GetFontSize();
		float title_size = ui_size * 1.34f;
		float body_size  = ui_size * 0.92f;

		ImVec2 title_sz = title_font->CalcTextSizeA(title_size, FLT_MAX, 0.f, title_text);
		dl->AddText(title_font, title_size,
			ImVec2(ca.x + (card_w - title_sz.x) * 0.5f, ca.y + 108.f),
			aida::ui::with_alpha(t.text_primary, alpha), title_text);

		if (subtitle_text && *subtitle_text) {
			ImVec2 sub_sz = body_font->CalcTextSizeA(body_size, FLT_MAX, card_w - 48.f, subtitle_text);
			dl->AddText(body_font, body_size,
				ImVec2(ca.x + (card_w - sub_sz.x) * 0.5f, ca.y + 140.f),
				aida::ui::with_alpha(t.text_secondary, alpha), subtitle_text,
				nullptr, card_w - 48.f);
		}

		float btn_w = 140.f;
		float btn_h = 36.f;
		float btn_gap = 12.f;
		float total_btn_w = btn_w * 3.f + btn_gap * 2.f;
		float btn_y = cb.y - btn_h - 24.f;
		float btn_x = ca.x + (card_w - total_btn_w) * 0.5f;

		ImFont* hint_font = aida::ui::fonts::body();
		if (!hint_font) hint_font = body_font;
		const char* tip = "Tip: drag any .exe/.dll/.sys into this window, then ask the AI Assistant on the right.";
		ImVec2 tip_sz = hint_font->CalcTextSizeA(ui_size * 0.78f, FLT_MAX, 0.f, tip);
		dl->AddText(hint_font, ui_size * 0.78f,
			ImVec2(ca.x + (card_w - tip_sz.x) * 0.5f, cb.y - btn_h - 56.f),
			aida::ui::with_alpha(t.text_dim, alpha * 0.95f), tip);

		ImVec2 a1(btn_x, btn_y);
		ImVec2 b1(btn_x + btn_w, btn_y + btn_h);
		bool clicked_open = render_button(dl, a1, b1, "##nt_open", "Open File...",
			t.accent_dim, t.accent_u32, t.text_primary, alpha);

		ImVec2 a2(btn_x + btn_w + btn_gap, btn_y);
		ImVec2 b2(a2.x + btn_w, a2.y + btn_h);
		bool clicked_attach = render_button(dl, a2, b2, "##nt_attach", "Attach to Process...",
			t.panel_header, t.accent_dim, t.text_primary, alpha);

		ImVec2 a3(btn_x + (btn_w + btn_gap) * 2.f, btn_y);
		ImVec2 b3(a3.x + btn_w, a3.y + btn_h);
		bool clicked_run = render_button(dl, a3, b3, "##nt_run", "Run Binary...",
			t.panel_header, t.accent_dim, t.text_primary, alpha);

		if (clicked_open) {
			std::string fpath = disasm::open_file_dialog(g_hwnd);
			if (!fpath.empty()) {
				analysis_session::open_session(fpath);
			}
		}
		if (clicked_attach) {
			globals::ui::process_attach_open = true;
		}
		if (clicked_run) {
			spawn_target_dialog::request_open();
		}
	}

}
