#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "motion.hpp"
#include "fonts.hpp"
#include <vector>
#include <string>

namespace aida::ui::empty_state {

	enum class glyph_t {
		dots,
		binary_file,
		memory,
		network,
		shield,
		key,
		search,
		flask,
		layers,
		cpu,
		bug,
		flow,
		message,
		spark
	};

	struct kbd_hint_t {
		std::string label;
	};

	struct config_t {
		glyph_t     glyph = glyph_t::dots;
		std::string title;
		std::string body;
		std::vector<kbd_hint_t> hints;
		float       max_width = 360.f;
	};

	inline void render_glyph_dots(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha = 1.f) {
		float r_outer = size * 0.42f;
		dl->AddCircle(center, r_outer, aida::ui::with_alpha(col, alpha * 0.55f), 32, 1.4f);
		for (int i = 0; i < 3; ++i) {
			ImVec2 p = ImVec2(center.x + (float)(i - 1) * (size * 0.18f), center.y);
			dl->AddCircleFilled(p, size * 0.07f, aida::ui::with_alpha(col, alpha * 0.85f), 16);
		}
	}

	inline void render_glyph_binary_file(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.7f;
		float h = size * 0.85f;
		ImVec2 a = ImVec2(center.x - w * 0.5f, center.y - h * 0.5f);
		ImVec2 b = ImVec2(center.x + w * 0.5f, center.y + h * 0.5f);
		float fold = w * 0.30f;
		dl->AddRectFilled(a, ImVec2(b.x - fold, b.y), aida::ui::with_alpha(col, alpha * 0.18f), 6.f);
		dl->AddRectFilled(ImVec2(b.x - fold, a.y), b, aida::ui::with_alpha(col, alpha * 0.12f), 6.f);
		dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * 0.7f), 6.f, 0, 1.5f);

		float t = aida::ui::clock::seconds();
		for (int i = 0; i < 4; ++i) {
			float y = a.y + h * 0.30f + (float)i * h * 0.13f;
			float pulse = sinf(t * 1.4f + (float)i * 0.7f) * 0.5f + 0.5f;
			float lw = w * (0.45f + pulse * 0.35f);
			dl->AddLine(ImVec2(a.x + 6.f, y), ImVec2(a.x + 6.f + lw, y),
			            aida::ui::with_alpha(col, alpha * (0.4f + pulse * 0.4f)), 1.f);
		}
	}

	inline void render_glyph_memory(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.85f;
		float h = size * 0.55f;
		ImVec2 a = ImVec2(center.x - w * 0.5f, center.y - h * 0.5f);
		ImVec2 b = ImVec2(center.x + w * 0.5f, center.y + h * 0.5f);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(col, alpha * 0.15f), size * 0.06f);
		dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * 0.7f), size * 0.06f, 0, 1.5f);
		int slots = 4;
		float t = aida::ui::clock::seconds();
		for (int i = 0; i < slots; ++i) {
			float x0 = a.x + 6.f + (float)i * (w - 12.f) / (float)slots;
			float pulse = sinf(t * 2.2f + (float)i * 0.85f) * 0.5f + 0.5f;
			ImU32 c = aida::ui::with_alpha(col, alpha * (0.25f + pulse * 0.55f));
			dl->AddRectFilled(ImVec2(x0, a.y + 4.f), ImVec2(x0 + (w - 12.f)/(float)slots - 4.f, b.y - 4.f),
			                  c, size * 0.04f);
		}
		for (int leg = 0; leg < 6; ++leg) {
			float x = a.x + 6.f + (float)leg * (w - 12.f) / 5.f;
			dl->AddLine(ImVec2(x, b.y), ImVec2(x, b.y + 5.f), aida::ui::with_alpha(col, alpha * 0.45f), 1.f);
		}
	}

	inline void render_glyph_network(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float r = size * 0.45f;
		dl->AddCircle(center, r, aida::ui::with_alpha(col, alpha * 0.6f), 32, 1.5f);
		dl->AddCircle(center, r * 0.65f, aida::ui::with_alpha(col, alpha * 0.45f), 28, 1.f);
		float t = aida::ui::clock::seconds();
		for (int i = 0; i < 6; ++i) {
			float ang = t * 0.6f + (float)i * 1.0471975f;
			ImVec2 p = ImVec2(center.x + cosf(ang) * r, center.y + sinf(ang) * r);
			float a = (sinf(t * 1.5f + (float)i) * 0.5f + 0.5f) * 0.7f + 0.3f;
			dl->AddCircleFilled(p, 3.5f, aida::ui::with_alpha(col, alpha * a), 12);
		}
		dl->AddCircleFilled(center, 3.f, aida::ui::with_alpha(col, alpha), 12);
	}

	inline void render_glyph_shield(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.6f;
		float h = size * 0.78f;
		float t = aida::ui::clock::seconds();
		float breath = sinf(t * 1.1f) * 0.5f + 0.5f;
		float a_mod = 0.55f + breath * 0.35f;
		ImVec2 top = ImVec2(center.x, center.y - h * 0.5f);
		ImVec2 lt  = ImVec2(center.x - w * 0.5f, center.y - h * 0.3f);
		ImVec2 lb  = ImVec2(center.x - w * 0.35f, center.y + h * 0.3f);
		ImVec2 b   = ImVec2(center.x, center.y + h * 0.5f);
		ImVec2 rb  = ImVec2(center.x + w * 0.35f, center.y + h * 0.3f);
		ImVec2 rt  = ImVec2(center.x + w * 0.5f, center.y - h * 0.3f);
		dl->PathLineTo(top); dl->PathLineTo(rt); dl->PathLineTo(rb); dl->PathLineTo(b);
		dl->PathLineTo(lb); dl->PathLineTo(lt); dl->PathLineTo(top);
		dl->PathFillConvex(aida::ui::with_alpha(col, alpha * a_mod * 0.18f));
		dl->PathLineTo(top); dl->PathLineTo(rt); dl->PathLineTo(rb); dl->PathLineTo(b);
		dl->PathLineTo(lb); dl->PathLineTo(lt);
		dl->PathStroke(aida::ui::with_alpha(col, alpha * a_mod), ImDrawFlags_Closed, 1.5f);
	}

	inline void render_glyph_message(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.78f;
		float h = size * 0.58f;
		ImVec2 a = ImVec2(center.x - w * 0.5f, center.y - h * 0.5f);
		ImVec2 b = ImVec2(center.x + w * 0.5f, center.y + h * 0.5f);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(col, alpha * 0.18f), size * 0.10f);
		dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * 0.7f), size * 0.10f, 0, 1.5f);
		ImVec2 tip0 = ImVec2(center.x - w * 0.18f, b.y);
		ImVec2 tip1 = ImVec2(center.x - w * 0.04f, b.y + size * 0.14f);
		ImVec2 tip2 = ImVec2(center.x + w * 0.06f, b.y);
		dl->AddTriangleFilled(tip0, tip1, tip2, aida::ui::with_alpha(col, alpha * 0.18f));
		dl->AddLine(tip0, tip1, aida::ui::with_alpha(col, alpha * 0.7f), 1.5f);
		dl->AddLine(tip1, tip2, aida::ui::with_alpha(col, alpha * 0.7f), 1.5f);
		for (int i = 0; i < 3; ++i) {
			float y = a.y + h * (0.30f + (float)i * 0.18f);
			float lw = w * (0.55f - (float)i * 0.12f);
			dl->AddLine(ImVec2(a.x + size * 0.10f, y), ImVec2(a.x + size * 0.10f + lw, y),
				aida::ui::with_alpha(col, alpha * 0.55f), 1.f);
		}
	}

	inline void render_glyph_search(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float r = size * 0.30f;
		ImVec2 c = ImVec2(center.x - size * 0.05f, center.y - size * 0.05f);
		dl->AddCircle(c, r, aida::ui::with_alpha(col, alpha * 0.7f), 32, 1.8f);
		float lx0 = c.x + r * 0.7071f;
		float ly0 = c.y + r * 0.7071f;
		float lx1 = c.x + r * 1.55f;
		float ly1 = c.y + r * 1.55f;
		dl->AddLine(ImVec2(lx0, ly0), ImVec2(lx1, ly1),
			aida::ui::with_alpha(col, alpha * 0.85f), 2.2f);
	}

	inline void render_glyph_key(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float r = size * 0.18f;
		ImVec2 hc = ImVec2(center.x - size * 0.20f, center.y);
		dl->AddCircle(hc, r, aida::ui::with_alpha(col, alpha * 0.8f), 24, 1.6f);
		dl->AddCircleFilled(hc, r * 0.35f, aida::ui::with_alpha(col, alpha * 0.6f), 16);
		float sx0 = hc.x + r;
		float sx1 = center.x + size * 0.40f;
		dl->AddLine(ImVec2(sx0, center.y), ImVec2(sx1, center.y),
			aida::ui::with_alpha(col, alpha * 0.8f), 1.8f);
		dl->AddLine(ImVec2(sx1 - size * 0.06f, center.y),
			ImVec2(sx1 - size * 0.06f, center.y + size * 0.10f),
			aida::ui::with_alpha(col, alpha * 0.8f), 1.8f);
		dl->AddLine(ImVec2(sx1, center.y), ImVec2(sx1, center.y + size * 0.14f),
			aida::ui::with_alpha(col, alpha * 0.8f), 1.8f);
	}

	inline void render_glyph_layers(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.7f;
		float h = size * 0.18f;
		for (int i = 0; i < 3; ++i) {
			float y = center.y - size * 0.2f + (float)i * size * 0.18f;
			ImVec2 a = ImVec2(center.x - w * 0.5f, y);
			ImVec2 b = ImVec2(center.x + w * 0.5f, y + h);
			float la = 0.55f + (float)i * 0.15f;
			dl->AddRectFilled(a, b, aida::ui::with_alpha(col, alpha * la * 0.3f), 4.f);
			dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * la), 4.f, 0, 1.2f);
		}
	}

	inline void render_glyph_cpu(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float w = size * 0.55f;
		ImVec2 a = ImVec2(center.x - w * 0.5f, center.y - w * 0.5f);
		ImVec2 b = ImVec2(center.x + w * 0.5f, center.y + w * 0.5f);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(col, alpha * 0.18f), 4.f);
		dl->AddRect(a, b, aida::ui::with_alpha(col, alpha * 0.75f), 4.f, 0, 1.4f);
		float ic = size * 0.22f;
		dl->AddRect(ImVec2(center.x - ic * 0.5f, center.y - ic * 0.5f),
			ImVec2(center.x + ic * 0.5f, center.y + ic * 0.5f),
			aida::ui::with_alpha(col, alpha * 0.6f), 2.f, 0, 1.2f);
		for (int side = 0; side < 4; ++side) {
			for (int p = 0; p < 3; ++p) {
				float t01 = 0.30f + (float)p * 0.20f;
				ImVec2 p0, p1;
				if (side == 0) { p0 = ImVec2(a.x + w * t01, a.y); p1 = ImVec2(a.x + w * t01, a.y - size * 0.07f); }
				else if (side == 1) { p0 = ImVec2(a.x + w * t01, b.y); p1 = ImVec2(a.x + w * t01, b.y + size * 0.07f); }
				else if (side == 2) { p0 = ImVec2(a.x, a.y + w * t01); p1 = ImVec2(a.x - size * 0.07f, a.y + w * t01); }
				else { p0 = ImVec2(b.x, a.y + w * t01); p1 = ImVec2(b.x + size * 0.07f, a.y + w * t01); }
				dl->AddLine(p0, p1, aida::ui::with_alpha(col, alpha * 0.65f), 1.2f);
			}
		}
	}

	inline void render_glyph(glyph_t g, ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		switch (g) {
			case glyph_t::dots:        render_glyph_dots(dl, center, size, col, alpha); break;
			case glyph_t::binary_file: render_glyph_binary_file(dl, center, size, col, alpha); break;
			case glyph_t::memory:      render_glyph_memory(dl, center, size, col, alpha); break;
			case glyph_t::network:     render_glyph_network(dl, center, size, col, alpha); break;
			case glyph_t::shield:      render_glyph_shield(dl, center, size, col, alpha); break;
			case glyph_t::message:     render_glyph_message(dl, center, size, col, alpha); break;
			case glyph_t::search:      render_glyph_search(dl, center, size, col, alpha); break;
			case glyph_t::key:         render_glyph_key(dl, center, size, col, alpha); break;
			case glyph_t::layers:      render_glyph_layers(dl, center, size, col, alpha); break;
			case glyph_t::cpu:         render_glyph_cpu(dl, center, size, col, alpha); break;
			default:                   render_glyph_message(dl, center, size, col, alpha); break;
		}
	}

	inline void render(ImVec2 region_pos, ImVec2 region_size, const config_t& cfg) {
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 center = ImVec2(region_pos.x + region_size.x * 0.5f,
		                        region_pos.y + region_size.y * 0.5f);
		float glyph_size = 56.f;

		render_glyph(cfg.glyph, dl, ImVec2(center.x, center.y - 60.f), glyph_size, t.accent_dim, 1.f);

		ImFont* body_font = ImGui::GetFont();
		ImFont* title_font = aida::ui::fonts::body_strong();
		if (!title_font) title_font = body_font;
		float ui_size    = ImGui::GetFontSize();
		float title_size = ui_size * 1.30f;
		float body_size  = ui_size * 0.92f;
		float hint_size  = ui_size * 0.78f;

		if (!cfg.title.empty()) {
			ImVec2 sz = title_font->CalcTextSizeA(title_size, FLT_MAX, 0.f, cfg.title.c_str());
			dl->AddText(title_font, title_size,
			            ImVec2(center.x - sz.x * 0.5f, center.y - 14.f),
			            t.text_primary, cfg.title.c_str());
		}
		if (!cfg.body.empty()) {
			float wrap = cfg.max_width;
			ImVec2 sz = body_font->CalcTextSizeA(body_size, FLT_MAX, wrap, cfg.body.c_str());
			ImVec2 origin = ImVec2(center.x - sz.x * 0.5f, center.y + 16.f);
			dl->AddText(body_font, body_size, origin, t.text_secondary, cfg.body.c_str(),
			            nullptr, wrap);
		}
		ImFont* font = body_font;

		if (!cfg.hints.empty()) {
			float pad_x = 8.f, pad_y = 4.f;
			float gap = 6.f;
			float kbd_h = hint_size + pad_y * 2.f + 4.f;
			float total_w = 0.f;
			for (const auto& h : cfg.hints) {
				ImVec2 sz = font->CalcTextSizeA(hint_size, FLT_MAX, 0.f, h.label.c_str());
				total_w += sz.x + pad_x * 2.f + gap;
			}
			total_w -= gap;
			float x = center.x - total_w * 0.5f;
			float y = region_pos.y + region_size.y - kbd_h - 38.f;
			for (const auto& h : cfg.hints) {
				ImVec2 sz = font->CalcTextSizeA(hint_size, FLT_MAX, 0.f, h.label.c_str());
				ImVec2 a = ImVec2(x, y);
				ImVec2 b = ImVec2(x + sz.x + pad_x * 2.f, y + kbd_h);
				dl->AddRectFilled(a, b, t.panel_header, 6.f);
				dl->AddRect(a, b, t.border_subtle, 6.f, 0, 1.f);
				dl->AddText(font, hint_size, ImVec2(a.x + pad_x, a.y + pad_y - 1.f),
				            t.text_secondary, h.label.c_str());
				x += sz.x + pad_x * 2.f + gap;
			}
		}
	}

}
