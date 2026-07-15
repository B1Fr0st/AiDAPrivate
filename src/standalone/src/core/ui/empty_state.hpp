#pragma once

#include "imgui/imgui.h"
#include "theme.hpp"
#include "clock.hpp"
#include "motion.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "responsive.hpp"
#include "components.hpp"
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

	struct action_t {
		std::string id;
		std::string label;
		aida::ui::components::button_kind_t kind = aida::ui::components::button_kind_t::secondary;
		bool disabled = false;
		std::string tooltip;
	};

	struct render_result_t {
		int action_index = -1;
		std::string action_id;
		bool activated() const { return action_index >= 0; }
	};

	struct config_t {
		glyph_t     glyph = glyph_t::dots;
		std::string title;
		std::string body;
		std::string footer;
		std::vector<kbd_hint_t> hints;
		std::vector<action_t> actions;
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

	inline void render_glyph_flask(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float neck_w = size * 0.20f;
		float neck_h = size * 0.30f;
		float body_w = size * 0.58f;
		float body_h = size * 0.46f;
		ImVec2 n0(center.x - neck_w * 0.5f, center.y - size * 0.42f);
		ImVec2 n1(center.x + neck_w * 0.5f, center.y - size * 0.10f);
		ImVec2 bl(center.x - body_w * 0.5f, center.y + body_h * 0.38f);
		ImVec2 br(center.x + body_w * 0.5f, center.y + body_h * 0.38f);
		ImVec2 sl(center.x - body_w * 0.22f, center.y - body_h * 0.08f);
		ImVec2 sr(center.x + body_w * 0.22f, center.y - body_h * 0.08f);
		dl->AddLine(ImVec2(n0.x, n0.y), ImVec2(n0.x, n0.y + neck_h), aida::ui::with_alpha(col, alpha * 0.75f), 1.5f);
		dl->AddLine(ImVec2(n1.x, n0.y), ImVec2(n1.x, n1.y), aida::ui::with_alpha(col, alpha * 0.75f), 1.5f);
		dl->AddLine(ImVec2(n0.x - size * 0.07f, n0.y), ImVec2(n1.x + size * 0.07f, n0.y), aida::ui::with_alpha(col, alpha * 0.78f), 1.5f);
		dl->PathLineTo(sl);
		dl->PathLineTo(bl);
		dl->PathLineTo(br);
		dl->PathLineTo(sr);
		dl->PathStroke(aida::ui::with_alpha(col, alpha * 0.82f), ImDrawFlags_Closed, 1.6f);
		float liquid_y = center.y + body_h * 0.12f;
		dl->AddRectFilled(ImVec2(bl.x + size * 0.08f, liquid_y),
			ImVec2(br.x - size * 0.08f, br.y - size * 0.06f),
			aida::ui::with_alpha(col, alpha * 0.18f), size * 0.05f);
		float t = aida::ui::clock::seconds();
		for (int i = 0; i < 3; ++i) {
			float bx = center.x - size * 0.18f + static_cast<float>(i) * size * 0.18f;
			float by = center.y - size * 0.06f + sinf(t * 1.7f + static_cast<float>(i)) * size * 0.025f;
			dl->AddCircleFilled(ImVec2(bx, by), size * 0.035f,
				aida::ui::with_alpha(col, alpha * 0.45f), 12);
		}
	}

	inline void render_glyph_bug(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float body_r = size * 0.22f;
		float head_r = size * 0.13f;
		ImVec2 body(center.x, center.y + size * 0.08f);
		ImVec2 head(center.x, center.y - size * 0.23f);
		dl->AddCircleFilled(body, body_r, aida::ui::with_alpha(col, alpha * 0.18f), 28);
		dl->AddCircle(body, body_r, aida::ui::with_alpha(col, alpha * 0.78f), 28, 1.5f);
		dl->AddCircle(head, head_r, aida::ui::with_alpha(col, alpha * 0.68f), 24, 1.4f);
		dl->AddLine(ImVec2(center.x, body.y - body_r), ImVec2(center.x, body.y + body_r),
			aida::ui::with_alpha(col, alpha * 0.45f), 1.f);
		for (int i = 0; i < 3; ++i) {
			float y = body.y - body_r * 0.55f + static_cast<float>(i) * body_r * 0.55f;
			float span = size * (0.30f + static_cast<float>(i == 1) * 0.05f);
			dl->AddLine(ImVec2(center.x - body_r * 0.76f, y), ImVec2(center.x - span, y + size * 0.06f),
				aida::ui::with_alpha(col, alpha * 0.62f), 1.4f);
			dl->AddLine(ImVec2(center.x + body_r * 0.76f, y), ImVec2(center.x + span, y + size * 0.06f),
				aida::ui::with_alpha(col, alpha * 0.62f), 1.4f);
		}
		dl->AddLine(ImVec2(head.x - head_r * 0.5f, head.y - head_r * 0.75f),
			ImVec2(head.x - size * 0.20f, head.y - size * 0.32f),
			aida::ui::with_alpha(col, alpha * 0.60f), 1.2f);
		dl->AddLine(ImVec2(head.x + head_r * 0.5f, head.y - head_r * 0.75f),
			ImVec2(head.x + size * 0.20f, head.y - size * 0.32f),
			aida::ui::with_alpha(col, alpha * 0.60f), 1.2f);
	}

	inline void render_glyph_flow(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		ImVec2 nodes[4] = {
			ImVec2(center.x - size * 0.28f, center.y - size * 0.22f),
			ImVec2(center.x + size * 0.26f, center.y - size * 0.10f),
			ImVec2(center.x - size * 0.18f, center.y + size * 0.24f),
			ImVec2(center.x + size * 0.30f, center.y + size * 0.30f)
		};
		int edges[4][2] = { {0, 1}, {0, 2}, {1, 3}, {2, 3} };
		float t = aida::ui::clock::seconds();
		for (int i = 0; i < 4; ++i) {
			ImVec2 a = nodes[edges[i][0]];
			ImVec2 b = nodes[edges[i][1]];
			float pulse = sinf(t * 1.5f + static_cast<float>(i) * 0.7f) * 0.5f + 0.5f;
			dl->AddLine(a, b, aida::ui::with_alpha(col, alpha * (0.35f + pulse * 0.35f)), 1.5f);
		}
		for (int i = 0; i < 4; ++i) {
			float r = (i == 0) ? size * 0.085f : size * 0.070f;
			dl->AddCircleFilled(nodes[i], r + 2.f, aida::ui::with_alpha(col, alpha * 0.14f), 18);
			dl->AddCircleFilled(nodes[i], r, aida::ui::with_alpha(col, alpha * 0.72f), 18);
		}
	}

	inline void render_glyph_spark(ImDrawList* dl, ImVec2 center, float size, ImU32 col, float alpha) {
		float t = aida::ui::clock::seconds();
		float pulse = sinf(t * 1.8f) * 0.5f + 0.5f;
		float r1 = size * (0.34f + pulse * 0.025f);
		float r2 = size * 0.12f;
		dl->AddQuadFilled(ImVec2(center.x, center.y - r1),
			ImVec2(center.x + r2, center.y),
			ImVec2(center.x, center.y + r1),
			ImVec2(center.x - r2, center.y),
			aida::ui::with_alpha(col, alpha * 0.18f));
		for (int i = 0; i < 8; ++i) {
			float a = -1.5707963f + static_cast<float>(i) * 0.7853982f;
			float r = (i % 2 == 0) ? r1 : r2;
			dl->PathLineTo(ImVec2(center.x + cosf(a) * r, center.y + sinf(a) * r));
		}
		dl->PathStroke(aida::ui::with_alpha(col, alpha * 0.78f), ImDrawFlags_Closed, 1.5f);
		dl->AddCircleFilled(center, size * 0.045f, aida::ui::with_alpha(col, alpha * 0.90f), 12);
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
			case glyph_t::flask:       render_glyph_flask(dl, center, size, col, alpha); break;
			case glyph_t::layers:      render_glyph_layers(dl, center, size, col, alpha); break;
			case glyph_t::cpu:         render_glyph_cpu(dl, center, size, col, alpha); break;
			case glyph_t::bug:         render_glyph_bug(dl, center, size, col, alpha); break;
			case glyph_t::flow:        render_glyph_flow(dl, center, size, col, alpha); break;
			case glyph_t::spark:       render_glyph_spark(dl, center, size, col, alpha); break;
			default:                   render_glyph_message(dl, center, size, col, alpha); break;
		}
	}

	inline render_result_t render_actions(ImVec2 region_pos, ImVec2 region_size,
		const config_t& cfg, float center_y, float body_bottom_y) {
		render_result_t result;
		if (cfg.actions.empty()) return result;
		ImVec2 saved = ImGui::GetCursorScreenPos();
		ImFont* font = ImGui::GetFont();
		float fs = ImGui::GetFontSize();
		float max_w = (std::min)(cfg.max_width, region_size.x - aida::ui::metrics::panel::padding * 2.f);
		if (max_w < 120.f) max_w = (std::max)(1.f, region_size.x - aida::ui::metrics::panel::padding * 2.f);
		float preferred_w = 132.f;
		float compact_w = 108.f;
		aida::ui::responsive::action_row_fit_t fit = aida::ui::responsive::fit_action_row(
			max_w, static_cast<int>(cfg.actions.size()), preferred_w, compact_w);
		float btn_h = aida::ui::metrics::control::height_md;
		float y = body_bottom_y + aida::ui::metrics::spacing::lg;
		float row_w = fit.stack ? fit.item_width :
			fit.item_width * static_cast<float>(cfg.actions.size()) +
			fit.gap * static_cast<float>(cfg.actions.size() - 1);
		float x = region_pos.x + (region_size.x - row_w) * 0.5f;
		if (fit.stack) {
			x = region_pos.x + (region_size.x - fit.item_width) * 0.5f;
			float total_h = static_cast<float>(cfg.actions.size()) * btn_h +
				static_cast<float>(cfg.actions.size() - 1) * fit.gap;
			float max_bottom = region_pos.y + region_size.y - aida::ui::metrics::panel::padding;
			if (y + total_h > max_bottom) y = (std::max)(center_y + 44.f, max_bottom - total_h);
		}
		for (size_t i = 0; i < cfg.actions.size(); ++i) {
			const auto& action = cfg.actions[i];
			std::string stable_id = action.id.empty()
				? std::string("empty_action_") + std::to_string(i)
				: action.id;
			std::string display = aida::ui::responsive::button_label_for_width(
				action.label.c_str(), action.label.c_str(), font, fs, fit.item_width - 18.f);
			ImGui::SetCursorScreenPos(ImVec2(x, y));
			if (aida::ui::components::button(
				(display + "##" + stable_id).c_str(),
				action.kind,
				aida::ui::components::size_t_::sm,
				ImVec2(fit.item_width, btn_h),
				action.disabled)) {
				result.action_index = static_cast<int>(i);
				result.action_id = stable_id;
			}
			if (!action.tooltip.empty()) aida::ui::components::tooltip_for_last_item(action.tooltip.c_str());
			if (fit.stack) {
				y += btn_h + fit.gap;
			} else {
				x += fit.item_width + fit.gap;
			}
		}
		ImGui::SetCursorScreenPos(saved);
		return result;
	}

	inline render_result_t render(ImVec2 region_pos, ImVec2 region_size, const config_t& cfg, float alpha = 1.f) {
		render_result_t result;
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 center = ImVec2(region_pos.x + region_size.x * 0.5f,
		                        region_pos.y + region_size.y * 0.5f);
		float glyph_size = 56.f;

		render_glyph(cfg.glyph, dl, ImVec2(center.x, center.y - 60.f), glyph_size, t.accent_dim, alpha);

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
			            aida::ui::with_alpha(t.text_primary, alpha), cfg.title.c_str());
		}
		float body_bottom_y = center.y + 16.f;
		if (!cfg.body.empty()) {
			float wrap = cfg.max_width;
			ImVec2 sz = body_font->CalcTextSizeA(body_size, FLT_MAX, wrap, cfg.body.c_str());
			ImVec2 origin = ImVec2(center.x - sz.x * 0.5f, center.y + 16.f);
			dl->AddText(body_font, body_size, origin, aida::ui::with_alpha(t.text_secondary, alpha), cfg.body.c_str(),
			            nullptr, wrap);
			body_bottom_y = origin.y + sz.y;
		}
		if (!cfg.footer.empty()) {
			float wrap = cfg.max_width;
			float footer_size = ui_size * 0.78f;
			ImVec2 sz = body_font->CalcTextSizeA(footer_size, FLT_MAX, wrap, cfg.footer.c_str());
			ImVec2 origin = ImVec2(center.x - sz.x * 0.5f, body_bottom_y + aida::ui::metrics::spacing::md);
			dl->AddText(body_font, footer_size, origin, aida::ui::with_alpha(t.accent_u32, alpha), cfg.footer.c_str(), nullptr, wrap);
			body_bottom_y = origin.y + sz.y;
		}
		ImFont* font = body_font;
		result = render_actions(region_pos, region_size, cfg, center.y, body_bottom_y);

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
				dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_header, alpha), 6.f);
				dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 6.f, 0, 1.f);
				dl->AddText(font, hint_size, ImVec2(a.x + pad_x, a.y + pad_y - 1.f),
				            aida::ui::with_alpha(t.text_secondary, alpha), h.label.c_str());
				x += sz.x + pad_x * 2.f + gap;
			}
		}
		ImGui::Dummy(ImVec2(0.f, 0.f));
		return result;
	}

	inline render_result_t render_panel(ImVec2 region_pos, ImVec2 region_size,
		const config_t& cfg, float alpha = 1.f) {
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 card_size = aida::ui::responsive::clamp_overlay_panel(
			region_size, ImVec2(480.f, cfg.actions.empty() ? 300.f : 330.f), ImVec2(280.f, 220.f));
		ImVec2 card_pos(region_pos.x + (region_size.x - card_size.x) * 0.5f,
			region_pos.y + (region_size.y - card_size.y) * 0.5f);
		ImVec2 card_max(card_pos.x + card_size.x, card_pos.y + card_size.y);
		dl->AddRectFilled(card_pos, card_max,
			aida::ui::with_alpha(t.panel_bg, alpha * 0.92f), aida::ui::metrics::radius::lg);
		dl->AddRect(card_pos, card_max,
			aida::ui::with_alpha(t.border_subtle, alpha * 0.85f),
			aida::ui::metrics::radius::lg, 0, 1.2f);
		config_t local = cfg;
		float inner_pad = aida::ui::metrics::panel::padding * 2.f;
		local.max_width = (std::min)(cfg.max_width, (std::max)(120.f, card_size.x - inner_pad));
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * alpha);
		render_result_t result = render(card_pos, card_size, local, alpha);
		ImGui::PopStyleVar();
		return result;
	}

}
