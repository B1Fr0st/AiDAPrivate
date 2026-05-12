#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "theme.hpp"
#include "motion.hpp"
#include "transition.hpp"
#include "clock.hpp"
#include "blur_layer.hpp"
#include "brand.hpp"
#include "avatar.hpp"
#include <string>
#include <string_view>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unordered_map>

namespace aida::ui::components {

	enum class button_kind_t {
		primary,
		secondary,
		ghost,
		destructive,
		accent_gradient
	};

	enum class size_t_ {
		sm,
		md,
		lg
	};

	struct button_state_t {
		hover_state_t hover;
		press_state_t press;
		flash_t       flash;
	};

	namespace detail {
		inline std::unordered_map<ImGuiID, button_state_t> s_button_states;
		inline std::unordered_map<ImGuiID, hover_state_t>  s_hover_states;
		inline std::unordered_map<ImGuiID, transition_t>   s_transitions;

		inline button_state_t& bstate(ImGuiID id) { return s_button_states[id]; }
		inline hover_state_t&  hstate(ImGuiID id) { return s_hover_states[id]; }
		inline transition_t&   tstate(ImGuiID id) { return s_transitions[id]; }

		inline const char* display_end(const char* label) {
			if (!label) return nullptr;
			for (const char* p = label; *p; ++p) {
				if (p[0] == '#' && p[1] == '#') return p;
			}
			return nullptr;
		}

		inline float calc_display_text_width(ImFont* font, float fs, const char* label) {
			if (!label) return 0.f;
			const char* end = display_end(label);
			return font->CalcTextSizeA(fs, FLT_MAX, 0.f, label, end).x;
		}

		inline void add_display_text(ImDrawList* dl, ImFont* font, float fs,
			ImVec2 pos, ImU32 color, const char* label) {
			if (!label) return;
			const char* end = display_end(label);
			dl->AddText(font, fs, pos, color, label, end);
		}

		inline ImVec2 sz_pad(size_t_ s) {
			switch (s) {
				case size_t_::sm: return ImVec2(12.f, 7.f);
				case size_t_::md: return ImVec2(16.f, 10.f);
				case size_t_::lg: return ImVec2(20.f, 14.f);
			}
			return ImVec2(16.f, 10.f);
		}
		inline float sz_font(size_t_ s) {
			switch (s) {
				case size_t_::sm: return 14.f;
				case size_t_::md: return 15.f;
				case size_t_::lg: return 17.f;
			}
			return 15.f;
		}
		inline float sz_height(size_t_ s) {
			switch (s) {
				case size_t_::sm: return 28.f;
				case size_t_::md: return 34.f;
				case size_t_::lg: return 42.f;
			}
			return 34.f;
		}
	}

	inline bool button(const char* label, button_kind_t kind = button_kind_t::secondary,
	                    size_t_ size = size_t_::md, ImVec2 size_override = ImVec2(0.f, 0.f),
	                    bool disabled = false, const char* leading_icon = nullptr,
	                    bool loading = false) {
		const auto& t = aida::ui::resolved();
		ImVec2 pad = detail::sz_pad(size);
		float fs = detail::sz_font(size);
		float h  = (size_override.y > 0.f) ? size_override.y : detail::sz_height(size);
		ImFont* font = ImGui::GetFont();

		float text_w = detail::calc_display_text_width(font, fs, label);
		float icon_w = leading_icon ? (detail::calc_display_text_width(font, fs, leading_icon) + 6.f) : 0.f;
		float w = (size_override.x > 0.f) ? size_override.x : (text_w + icon_w + pad.x * 2.f + 4.f);

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);

		ImGui::InvisibleButton("##b", ImVec2(w, h));
		bool hovered = ImGui::IsItemHovered() && !disabled && !loading;
		bool held    = ImGui::IsItemActive() && !disabled && !loading;
		bool clicked = ImGui::IsItemDeactivated() && ImGui::IsItemHovered() && !disabled && !loading;
		bool focused = ImGui::IsItemFocused();

		auto& st = detail::bstate(id);
		float hov = st.hover.tick(hovered, aida::ui::clock::dt());
		float prs = st.press.tick(held, aida::ui::clock::dt());
		float flash = st.flash.tick(aida::ui::clock::dt());
		if (clicked) st.flash.trigger();

		float scale = 1.f - (1.f - 0.97f) * prs;
		float lift  = hov * 1.5f - prs * 1.5f;
		ImVec2 ca = ImVec2(a.x + (1.f - scale) * w * 0.5f, a.y + (1.f - scale) * h * 0.5f - lift);
		ImVec2 cb = ImVec2(b.x - (1.f - scale) * w * 0.5f, b.y - (1.f - scale) * h * 0.5f - lift);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		float radius = 8.f;
		float alpha = disabled ? t.disabled_alpha : 1.f;

		ImU32 fill = t.panel_header;
		ImU32 border = t.border_subtle;
		ImU32 text_col = t.text_primary;
		ImU32 hover_top = t.accent_grad_top;
		ImU32 hover_bot = t.accent_grad_bot;

		switch (kind) {
			case button_kind_t::primary:
				fill = aida::ui::mix(t.accent_grad_top, t.accent_grad_bot, 0.5f);
				border = aida::ui::with_alpha(t.accent_hover, 1.f);
				text_col = IM_COL32(255, 255, 255, 245);
				break;
			case button_kind_t::secondary:
				fill = t.panel_header;
				border = t.border_subtle;
				text_col = t.text_primary;
				break;
			case button_kind_t::ghost:
				fill = aida::ui::with_alpha(t.panel_header, 0.f);
				border = aida::ui::with_alpha(t.border_subtle, 0.f);
				text_col = t.text_secondary;
				break;
			case button_kind_t::destructive:
				fill = aida::ui::with_alpha(t.error, 0.18f);
				border = aida::ui::with_alpha(t.error, 0.55f);
				text_col = t.error;
				break;
			case button_kind_t::accent_gradient: {
				ImU32 grad_flat = aida::ui::mix(t.accent_grad_top, t.accent_grad_bot, 0.5f);
				dl->AddRectFilled(ca, cb, aida::ui::with_alpha(grad_flat, alpha), radius);
				break;
			}
		}

		if (kind != button_kind_t::accent_gradient) {
			ImU32 hover_blend_top = aida::ui::mix(fill, hover_top, hov * 0.55f);
			ImU32 hover_blend_bot = aida::ui::mix(fill, hover_bot, hov * 0.55f);
			ImU32 fill_flat = aida::ui::mix(hover_blend_top, hover_blend_bot, 0.5f);
			dl->AddRectFilled(ca, cb, aida::ui::with_alpha(fill_flat, alpha), radius);
		}

		dl->AddRect(ca, cb, aida::ui::with_alpha(border, alpha * (1.f + hov * 0.5f)), radius, 0, 1.f);

		if (flash > 0.f) {
			ImU32 flash_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), flash * 0.20f);
			dl->AddRectFilled(ca, cb, flash_col, radius);
		}

		if (focused && !disabled) {
			ImU32 ring = aida::ui::with_alpha(t.border_focus, 0.85f);
			dl->AddRect(ImVec2(ca.x - 2.f, ca.y - 2.f), ImVec2(cb.x + 2.f, cb.y + 2.f),
			            ring, radius + 2.f, 0, 1.5f);
		}

		float text_x = ca.x + pad.x + icon_w;
		float text_y = ca.y + (h - fs) * 0.5f;

		if (loading) {
			float r = h * 0.18f;
			ImVec2 c = ImVec2(ca.x + w * 0.5f, ca.y + h * 0.5f);
			float t_sec = aida::ui::clock::seconds() * 5.f;
			for (int i = 0; i < 3; ++i) {
				float ang = t_sec + (float)i * 2.094395f;
				float aa = (sinf(ang * 0.8f) * 0.5f + 0.5f) * 0.6f + 0.4f;
				ImVec2 p = ImVec2(c.x + cosf(ang) * r, c.y + sinf(ang) * r);
				dl->AddCircleFilled(p, 2.f, aida::ui::with_alpha(text_col, alpha * aa), 12);
			}
		} else {
			if (leading_icon) {
				detail::add_display_text(dl, font, fs, ImVec2(ca.x + pad.x, text_y),
				            aida::ui::with_alpha(text_col, alpha), leading_icon);
			}
			detail::add_display_text(dl, font, fs, ImVec2(text_x, text_y),
			            aida::ui::with_alpha(text_col, alpha), label);
		}

		ImGui::PopID();
		return clicked;
	}

	inline void pill(const char* label, ImU32 color, size_t_ size = size_t_::sm,
	                  bool leading_dot = true) {
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size);
		float pad_x = size == size_t_::sm ? 10.f : 12.f;
		float h     = size == size_t_::sm ? 22.f : 26.f;

		float text_w = detail::calc_display_text_width(font, fs, label);
		float dot_w = leading_dot ? 10.f : 0.f;
		float w = text_w + dot_w + pad_x * 2.f;

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::Dummy(ImVec2(w, h));

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(color, 0.22f), h * 0.5f);
		dl->AddRect(a, b, aida::ui::with_alpha(color, 0.55f), h * 0.5f, 0, 1.f);

		float cx = a.x + pad_x;
		if (leading_dot) {
			float t = aida::ui::clock::seconds();
			float pulse = (sinf(t * 2.5f) * 0.5f + 0.5f) * 0.4f + 0.6f;
			dl->AddCircleFilled(ImVec2(cx + 3.f, a.y + h * 0.5f), 3.f,
			                     aida::ui::with_alpha(color, pulse), 12);
			cx += 10.f;
		}
		detail::add_display_text(dl, font, fs, ImVec2(cx, a.y + (h - fs) * 0.5f),
		             aida::ui::with_alpha(color, 1.f), label);
	}

	enum class pill_kind_t {
		success,
		warning,
		error,
		info,
		neutral,
		accent
	};

	inline void pill_kind(const char* label, pill_kind_t k, size_t_ size = size_t_::sm,
	                       bool leading_dot = true) {
		const auto& t = aida::ui::resolved();
		ImU32 col;
		switch (k) {
			case pill_kind_t::success: col = t.success; break;
			case pill_kind_t::warning: col = t.warning; break;
			case pill_kind_t::error:   col = t.error;   break;
			case pill_kind_t::info:    col = t.info;    break;
			case pill_kind_t::accent:  col = t.accent_u32; break;
			case pill_kind_t::neutral: col = t.text_secondary; break;
		}
		pill(label, col, size, leading_dot);
	}

	inline void badge(const char* label, ImU32 color, float radius = 4.f) {
		ImFont* font = ImGui::GetFont();
		float fs = 13.f;
		float pad_x = 8.f;
		float h = 20.f;
		float text_w = detail::calc_display_text_width(font, fs, label);
		float w = text_w + pad_x * 2.f;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::Dummy(ImVec2(w, h));
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(color, 0.85f), radius);
		ImU32 text_col = IM_COL32(255, 255, 255, 240);
		float r = (float)((color >> IM_COL32_R_SHIFT) & 0xFF) / 255.f;
		float g = (float)((color >> IM_COL32_G_SHIFT) & 0xFF) / 255.f;
		float bl = (float)((color >> IM_COL32_B_SHIFT) & 0xFF) / 255.f;
		float lum = 0.299f * r + 0.587f * g + 0.114f * bl;
		if (lum > 0.7f) text_col = IM_COL32(20, 20, 30, 240);
		detail::add_display_text(dl, font, fs, ImVec2(a.x + pad_x, a.y + (h - fs) * 0.5f), text_col, label);
	}

	inline bool chip(const char* label, ImU32 color, bool removable = false, bool* removed = nullptr) {
		ImFont* font = ImGui::GetFont();
		float fs = 14.f;
		float pad_x = 10.f;
		float h = 26.f;
		float text_w = detail::calc_display_text_width(font, fs, label);
		float remove_w = removable ? 14.f : 0.f;
		float w = text_w + remove_w + pad_x * 2.f;

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID("##chip");
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::InvisibleButton("##chip_b", ImVec2(w, h));
		bool hovered = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();

		auto& hov = detail::hstate(id);
		float h_v = hov.tick(hovered, aida::ui::clock::dt());

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);
		ImU32 fill = aida::ui::with_alpha(color, 0.22f + 0.10f * h_v);
		ImU32 border = aida::ui::with_alpha(color, 0.45f + 0.20f * h_v);
		dl->AddRectFilled(a, b, fill, h * 0.5f);
		dl->AddRect(a, b, border, h * 0.5f, 0, 1.f);

		detail::add_display_text(dl, font, fs, ImVec2(a.x + pad_x, a.y + (h - fs) * 0.5f),
		             aida::ui::with_alpha(color, 1.f), label);

		bool _removed = false;
		if (removable) {
			float xx = b.x - 8.f;
			float xy = a.y + h * 0.5f;
			float xs = 4.f;
			ImU32 xcol = aida::ui::with_alpha(color, 0.7f + h_v * 0.3f);
			dl->AddLine(ImVec2(xx - xs, xy - xs), ImVec2(xx + xs, xy + xs), xcol, 1.5f);
			dl->AddLine(ImVec2(xx - xs, xy + xs), ImVec2(xx + xs, xy - xs), xcol, 1.5f);

			ImVec2 mp = ImGui::GetMousePos();
			if (clicked && mp.x > b.x - 16.f) _removed = true;
		}
		if (removed) *removed = _removed;
		ImGui::PopID();
		return clicked && !_removed;
	}

	inline bool input_text(const char* label, char* buf, size_t buf_size,
	                        const char* placeholder = nullptr,
	                        bool password = false, ImVec2 size = ImVec2(0.f, 0.f)) {
		const auto& t = aida::ui::resolved();
		float h = size.y > 0.f ? size.y : 36.f;
		float w = size.x > 0.f ? size.x : ImGui::GetContentRegionAvail().x;

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		auto& hov = detail::hstate(id);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(a, b, t.panel_header, 8.f);

		bool active = ImGui::GetActiveID() == ImGui::GetID("##in");
		float focus_v = hov.tick(active, aida::ui::clock::dt(), aida::motion::spring::balanced);
		ImU32 border = aida::ui::mix(t.border_subtle, t.border_focus, focus_v);
		dl->AddRect(a, b, border, 8.f, 0, 1.f + focus_v * 0.8f);

		ImGui::SetCursorScreenPos(ImVec2(a.x + 12.f, a.y + (h - ImGui::GetFontSize()) * 0.5f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));
		ImGui::SetNextItemWidth(w - 24.f);
		ImGuiInputTextFlags flags = password ? ImGuiInputTextFlags_Password : 0;
		bool changed = ImGui::InputText("##in", buf, buf_size, flags);
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(3);

		if (placeholder && (buf[0] == '\0') && !active) {
			float fs = ImGui::GetFontSize();
			dl->PushClipRect(ImVec2(a.x + 12.f, a.y), ImVec2(b.x - 12.f, b.y), true);
			dl->AddText(ImGui::GetFont(), fs, ImVec2(a.x + 12.f, a.y + (h - fs) * 0.5f),
			             t.text_dim, placeholder);
			dl->PopClipRect();
		}

		ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + h + 4.f));
		ImGui::PopID();
		return changed;
	}

	inline void section_header(const char* title, const char* count_label = nullptr,
	                            const char* action_label = nullptr, bool* action_clicked = nullptr) {
		const auto& t = aida::ui::resolved();
		ImFont* font = ImGui::GetFont();
		float fs = 15.f;

		ImVec2 pos = ImGui::GetCursorScreenPos();
		float w = ImGui::GetContentRegionAvail().x;
		float h = 32.f;

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);
		dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_header, 0.55f), 6.f);
		ImU32 line = aida::ui::with_alpha(t.accent_dim, 0.4f);
		dl->AddLine(ImVec2(a.x, b.y - 1.f), ImVec2(b.x, b.y - 1.f), line, 1.f);

		dl->AddText(font, fs, ImVec2(a.x + 12.f, a.y + (h - fs) * 0.5f),
		             t.text_primary, title);

		float content_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, title).x + 12.f;

		if (count_label) {
			char buf[64]; snprintf(buf, sizeof(buf), "  %s", count_label);
			ImVec2 sz = font->CalcTextSizeA(fs, FLT_MAX, 0.f, buf);
			dl->AddText(font, fs, ImVec2(a.x + content_w, a.y + (h - fs) * 0.5f),
			             t.text_dim, buf);
		}

		if (action_label) {
			float aw = font->CalcTextSizeA(fs, FLT_MAX, 0.f, action_label).x;
			ImVec2 ax = ImVec2(b.x - aw - 12.f, a.y + (h - fs) * 0.5f);
			ImVec2 ax_a = ImVec2(ax.x - 6.f, a.y + 4.f);
			ImVec2 ax_b = ImVec2(b.x - 6.f, b.y - 4.f);
			ImGui::SetCursorScreenPos(ax_a);
			ImGui::InvisibleButton("##sh_a", ImVec2(ax_b.x - ax_a.x, ax_b.y - ax_a.y));
			bool clicked = ImGui::IsItemClicked();
			bool hovered = ImGui::IsItemHovered();
			if (hovered) {
				dl->AddRectFilled(ax_a, ax_b, t.hover_wash, 4.f);
			}
			dl->AddText(font, fs, ax, hovered ? t.accent_u32 : t.text_secondary, action_label);
			if (action_clicked) *action_clicked = clicked;
		}

		ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + h + 6.f));
	}

	inline bool toggle_switch(const char* label, bool* state, size_t_ size = size_t_::sm) {
		if (!state) return false;
		const auto& t = aida::ui::resolved();
		float track_w = size == size_t_::sm ? 36.f : 44.f;
		float track_h = size == size_t_::sm ? 20.f : 24.f;
		float fs = size == size_t_::sm ? 14.f : 15.f;
		ImFont* font = ImGui::GetFont();

		const char* disp_end = detail::display_end(label);
		bool has_label = label && (disp_end == nullptr ? *label : (label != disp_end));
		float text_w = has_label
			? font->CalcTextSizeA(fs, FLT_MAX, 0.f, label, disp_end).x
			: 0.f;
		float gap = has_label ? 8.f : 0.f;
		float total_w = track_w + 4.f + gap + text_w;
		float total_h = (track_h + 4.f) > (fs + 4.f) ? (track_h + 4.f) : (fs + 4.f);

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		auto& hov = detail::hstate(id);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::InvisibleButton("##tog", ImVec2(total_w, total_h));
		bool clicked = ImGui::IsItemClicked();
		if (clicked) *state = !*state;

		float current = hov.tick(*state, aida::ui::clock::dt(), aida::motion::spring::snappy);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		float center_y = pos.y + total_h * 0.5f;
		ImVec2 ta = ImVec2(pos.x + 2.f, center_y - track_h * 0.5f);
		ImVec2 tb = ImVec2(ta.x + track_w, ta.y + track_h);

		ImU32 off_col = t.panel_header;
		ImU32 on_col  = t.accent_u32;
		ImU32 track_col = aida::ui::mix(off_col, on_col, current);
		dl->AddRectFilled(ta, tb, track_col, track_h * 0.5f);

		float knob_r = (track_h - 4.f) * 0.5f;
		float knob_x = ta.x + 2.f + knob_r + (track_w - 4.f - knob_r * 2.f) * current;
		float knob_y = (ta.y + tb.y) * 0.5f;
		dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
		                     IM_COL32(255, 255, 255, 240), 16);

		if (has_label) {
			float lx = tb.x + gap;
			float ly = center_y - fs * 0.5f;
			detail::add_display_text(dl, font, fs, ImVec2(lx, ly), t.text_primary, label);
		}

		ImGui::PopID();
		return clicked;
	}

	inline void status_dot(ImVec2 center, float radius, ImU32 col,
	                        bool pulsing = true, float pulse_rate = 1.4f) {
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float t = aida::ui::clock::seconds();
		if (pulsing) {
			float halo_r = radius + 2.f + sinf(t * pulse_rate * 6.2831853f) * 1.f;
			dl->AddCircleFilled(center, halo_r, aida::ui::with_alpha(col, 0.18f), 16);
			dl->AddCircleFilled(center, radius + 1.f, aida::ui::with_alpha(col, 0.55f), 16);
		}
		dl->AddCircleFilled(center, radius, col, 16);
	}

	inline void glass_card_begin(const char* id_str, ImVec2 size, float radius = 12.f,
	                              float blur_strength = 0.6f) {
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + size.x, pos.y + size.y);

		aida::ui::blur::layer_request_t r;
		r.pos = a; r.size = size; r.radius = radius;
		r.strength = blur_strength; r.alpha = 1.f;
		aida::ui::blur::schedule(r);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		aida::ui::blur::render_drop_shadow(dl, a, b, radius, 4, 0.30f, ImVec2(0.f, 4.f));
		aida::ui::blur::render_glass_fill(dl, a, b, radius, 1.f);
		aida::ui::blur::render_glass_border(dl, a, b, radius, 1.f, 1.f);

		ImGui::BeginChild(id_str, size, false,
			ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);
	}

	inline void glass_card_end() { ImGui::EndChild(); }

	inline void render_focus_ring(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                                float radius = 8.f, float alpha = 1.f) {
		const auto& t = aida::ui::resolved();
		dl->AddRect(ImVec2(a.x - 2.f, a.y - 2.f),
		             ImVec2(b.x + 2.f, b.y + 2.f),
		             aida::ui::with_alpha(t.border_focus, alpha), radius + 2.f, 0, 1.5f);
	}

	inline void render_progress_bar(ImVec2 origin, float width, float height,
	                                  float progress, bool indeterminate = false,
	                                  bool shimmer = true) {
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = origin;
		ImVec2 b = ImVec2(origin.x + width, origin.y + height);
		dl->AddRectFilled(a, b, t.panel_header, height * 0.5f);

		if (indeterminate) {
			float t_sec = aida::ui::clock::seconds() * 1.2f;
			float phase = fmodf(t_sec, 1.f);
			float bw = width * 0.30f;
			float bx = a.x + (width + bw) * phase - bw;
			ImVec2 ba = ImVec2(bx, a.y);
			ImVec2 bb = ImVec2(bx + bw, b.y);
			if (ba.x < a.x) ba.x = a.x;
			if (bb.x > b.x) bb.x = b.x;
			dl->PushClipRect(a, b, true);
			dl->AddRectFilledMultiColor(ba, bb,
				aida::ui::with_alpha(t.accent_grad_top, 0.f),
				aida::ui::with_alpha(t.accent_grad_top, 1.f),
				aida::ui::with_alpha(t.accent_grad_bot, 1.f),
				aida::ui::with_alpha(t.accent_grad_bot, 0.f));
			dl->PopClipRect();
		} else {
			if (progress < 0.f) progress = 0.f;
			if (progress > 1.f) progress = 1.f;
			float fw = width * progress;
			ImVec2 fa = a;
			ImVec2 fb = ImVec2(a.x + fw, b.y);
			if (fw > 1.f) {
				dl->AddRectFilledMultiColor(fa, fb,
					t.accent_grad_top, t.accent_grad_top,
					t.accent_grad_bot, t.accent_grad_bot);
				if (shimmer) {
					float t_sec = aida::ui::clock::seconds() * 0.8f;
					float ph = fmodf(t_sec, 1.f);
					float sx = fa.x + fw * ph - fw * 0.15f;
					float sw = fw * 0.30f;
					if (sw > 4.f) {
						dl->PushClipRect(fa, fb, true);
						dl->AddRectFilledMultiColor(
							ImVec2(sx, fa.y), ImVec2(sx + sw * 0.5f, fb.y),
							IM_COL32(255,255,255,0), IM_COL32(255,255,255,40),
							IM_COL32(255,255,255,40), IM_COL32(255,255,255,0));
						dl->AddRectFilledMultiColor(
							ImVec2(sx + sw * 0.5f, fa.y), ImVec2(sx + sw, fb.y),
							IM_COL32(255,255,255,40), IM_COL32(255,255,255,0),
							IM_COL32(255,255,255,0), IM_COL32(255,255,255,40));
						dl->PopClipRect();
					}
				}
			}
		}
	}

	inline void render_progress_ring(ImVec2 center, float radius, float thickness,
	                                   float progress, bool indeterminate = false) {
		const auto& t = aida::ui::resolved();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddCircle(center, radius, aida::ui::with_alpha(t.panel_header, 0.85f), 48, thickness);

		if (indeterminate) {
			float ts = aida::ui::clock::seconds() * 4.f;
			float arc_len = 1.5f;
			for (int i = 0; i < 32; ++i) {
				float a0 = ts + (float)i / 32.f * arc_len;
				float a1 = ts + (float)(i + 1) / 32.f * arc_len;
				float fade = 1.f - (float)i / 32.f;
				dl->PathArcTo(center, radius, a0, a1, 4);
				dl->PathStroke(aida::ui::with_alpha(t.accent_u32, fade), 0, thickness);
			}
		} else {
			if (progress < 0.f) progress = 0.f;
			if (progress > 1.f) progress = 1.f;
			float a0 = -1.5707963f;
			float a1 = a0 + progress * 6.2831853f;
			dl->PathArcTo(center, radius, a0, a1, 48);
			dl->PathStroke(t.accent_u32, 0, thickness);
		}
	}

	inline void tooltip_blur(const char* text, float delay = 0.5f) {
		if (!ImGui::IsItemHovered()) return;
		float hov_time = ImGui::GetCurrentContext()->HoveredIdTimer;
		if (hov_time < delay) return;
		const auto& t = aida::ui::resolved();
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
		ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
		if (ImGui::BeginTooltip()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
			ImGui::TextUnformatted(text);
			ImGui::PopStyleColor();
			ImGui::EndTooltip();
		}
		ImGui::PopStyleColor();
		ImGui::PopStyleVar();
	}

	inline void kbd_chip(const char* label) {
		const auto& t = aida::ui::resolved();
		ImFont* font = ImGui::GetFont();
		float fs = 13.f;
		float pad_x = 8.f;
		float pad_y = 3.f;
		float text_w = detail::calc_display_text_width(font, fs, label);
		float w = text_w + pad_x * 2.f;
		float h = fs + pad_y * 2.f + 2.f;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::Dummy(ImVec2(w, h));
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);
		dl->AddRectFilled(a, b, t.panel_header, 4.f);
		dl->AddRect(a, b, t.border_subtle, 4.f, 0, 1.f);
		detail::add_display_text(dl, font, fs, ImVec2(a.x + pad_x, a.y + pad_y), t.text_secondary, label);
	}

}

namespace aida::ui {
	using components::button;
	using components::pill;
	using components::pill_kind;
	using components::badge;
	using components::chip;
	using components::input_text;
	using components::section_header;
	using components::toggle_switch;
	using components::status_dot;
	using components::glass_card_begin;
	using components::glass_card_end;
	using components::render_focus_ring;
	using components::render_progress_bar;
	using components::render_progress_ring;
	using components::tooltip_blur;
	using components::kbd_chip;
	using components::button_kind_t;
	using components::pill_kind_t;
	using components::size_t_;
}
