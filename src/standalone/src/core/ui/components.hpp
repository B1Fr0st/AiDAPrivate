#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "theme.hpp"
#include "metrics.hpp"
#include "motion.hpp"
#include "transition.hpp"
#include "clock.hpp"
#include "blur_layer.hpp"
#include "brand.hpp"
#include "avatar.hpp"
#include <algorithm>
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

	struct control_frame_t {
		ImGuiID id = 0;
		ImVec2 min = ImVec2(0.f, 0.f);
		ImVec2 max = ImVec2(0.f, 0.f);
		ImVec2 size = ImVec2(0.f, 0.f);
		bool hovered = false;
		bool held = false;
		bool clicked = false;
		bool focused = false;
		float hover = 0.f;
		float press = 0.f;
		float flash = 0.f;
	};

	enum class status_kind_t {
		success,
		warning,
		error,
		info,
		neutral,
		accent
	};

	enum class presentation_kind_t {
		empty,
		loading,
		error
	};

	enum class splitter_axis_t {
		x,
		y
	};

	struct action_chip_result_t {
		bool clicked = false;
		bool removed = false;
	};

	struct view_header_result_t {
		bool primary_clicked = false;
		bool secondary_clicked = false;
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

		inline float ui_fs() {
			float fs = ImGui::GetFontSize();
			return (fs > 1.f) ? fs : 16.f;
		}
		inline ImVec2 sz_pad(size_t_ s) {
			switch (s) {
				case size_t_::sm: return aida::ui::metrics::pad_sm();
				case size_t_::md: return aida::ui::metrics::pad_md();
				case size_t_::lg: return aida::ui::metrics::pad_lg();
			}
			return aida::ui::metrics::pad_md();
		}
		inline float sz_font(size_t_ s) {
			float fs = ui_fs();
			switch (s) {
				case size_t_::sm: return fs * 0.94f;
				case size_t_::md: return fs * 1.02f;
				case size_t_::lg: return fs * 1.16f;
			}
			return fs;
		}
		inline float sz_height(size_t_ s) {
			float fs = ui_fs();
			switch (s) {
				case size_t_::sm: return (std::max)(aida::ui::metrics::control::height_sm, fs + 14.f);
				case size_t_::md: return (std::max)(aida::ui::metrics::control::height_md, fs + 18.f);
				case size_t_::lg: return (std::max)(aida::ui::metrics::control::height_lg, fs + 24.f);
			}
			return (std::max)(aida::ui::metrics::control::height_md, fs + 18.f);
		}
	}

	inline button_state_t& control_state(ImGuiID id) { return detail::bstate(id); }
	inline hover_state_t& hover_state(ImGuiID id) { return detail::hstate(id); }
	inline transition_t& transition_state(ImGuiID id) { return detail::tstate(id); }
	inline ImVec2 control_padding(size_t_ s) { return detail::sz_pad(s); }
	inline float control_font_size(size_t_ s) { return detail::sz_font(s); }
	inline float control_height(size_t_ s) { return detail::sz_height(s); }
	inline float display_text_width(ImFont* font, float fs, const char* label) {
		return detail::calc_display_text_width(font, fs, label);
	}

	inline ImU32 status_color(status_kind_t kind) {
		const auto& t = aida::ui::resolved();
		switch (kind) {
			case status_kind_t::success: return t.success;
			case status_kind_t::warning: return t.warning;
			case status_kind_t::error: return t.error;
			case status_kind_t::info: return t.info;
			case status_kind_t::accent: return t.accent_u32;
			case status_kind_t::neutral: return t.text_secondary;
		}
		return t.text_secondary;
	}

	inline control_frame_t control_frame(const char* id, ImVec2 size,
		bool disabled = false, bool flash_on_click = true) {
		control_frame_t frame;
		if (size.x < 1.f) size.x = 1.f;
		if (size.y < 1.f) size.y = 1.f;
		frame.size = size;
		const char* stable_id = (id && *id) ? id : "control";
		ImGui::PushID(stable_id);
		frame.id = ImGui::GetID("##frame");
		frame.min = ImGui::GetCursorScreenPos();
		frame.max = ImVec2(frame.min.x + size.x, frame.min.y + size.y);
		ImGui::InvisibleButton("##frame_btn", size);
		frame.hovered = ImGui::IsItemHovered() && !disabled;
		frame.held = ImGui::IsItemActive() && !disabled;
		frame.clicked = ImGui::IsItemClicked() && !disabled;
		frame.focused = ImGui::IsItemFocused();
		auto& st = control_state(frame.id);
		frame.hover = st.hover.tick(frame.hovered, aida::ui::clock::dt());
		frame.press = st.press.tick(frame.held, aida::ui::clock::dt());
		frame.flash = st.flash.tick(aida::ui::clock::dt(), 2.5f);
		if (frame.clicked && flash_on_click) st.flash.trigger();
		ImGui::PopID();
		return frame;
	}

	inline void tooltip_for_last_item(const char* text, float delay = 0.35f) {
		if (!text || !*text) return;
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

	namespace detail {
		inline ImU32 control_fill(button_kind_t kind, float hover, bool active, bool disabled) {
			const auto& t = aida::ui::resolved();
			float alpha = (disabled ? t.disabled_alpha : 1.f) * ImGui::GetStyle().Alpha;
			if (active) {
				return aida::ui::with_alpha(aida::ui::mix(t.panel_header, t.accent_dim, 0.55f + hover * 0.25f), alpha);
			}
			switch (kind) {
				case button_kind_t::primary:
				case button_kind_t::accent_gradient:
					return aida::ui::with_alpha(aida::ui::mix(t.accent_dim, t.accent_u32, 0.45f + hover * 0.35f), alpha);
				case button_kind_t::destructive:
					return aida::ui::with_alpha(aida::ui::mix(t.panel_header, t.error, 0.24f + hover * 0.18f), alpha);
				case button_kind_t::ghost:
					return aida::ui::with_alpha(aida::ui::mix(t.panel_header, t.accent_grad_top, hover * 0.28f), alpha * 0.78f);
				case button_kind_t::secondary:
					return aida::ui::with_alpha(aida::ui::mix(t.panel_header, t.accent_grad_top, hover * 0.38f), alpha);
			}
			return aida::ui::with_alpha(t.panel_header, alpha);
		}

		inline ImU32 control_border(button_kind_t kind, float hover, bool active, bool disabled) {
			const auto& t = aida::ui::resolved();
			float alpha = (disabled ? t.disabled_alpha : 1.f) * ImGui::GetStyle().Alpha;
			if (active) return aida::ui::with_alpha(t.accent_u32, alpha * (0.78f + hover * 0.18f));
			switch (kind) {
				case button_kind_t::primary:
				case button_kind_t::accent_gradient:
					return aida::ui::with_alpha(aida::ui::mix(t.accent_dim, t.accent_hover, hover), alpha);
				case button_kind_t::destructive:
					return aida::ui::with_alpha(aida::ui::mix(t.error, t.accent_hover, hover * 0.25f), alpha * 0.80f);
				case button_kind_t::ghost:
					return aida::ui::with_alpha(aida::ui::mix(t.border_subtle, t.accent_hover, hover), alpha * 0.85f);
				case button_kind_t::secondary:
					return aida::ui::with_alpha(aida::ui::mix(t.border_subtle, t.accent_hover, hover), alpha);
			}
			return aida::ui::with_alpha(t.border_subtle, alpha);
		}

		inline ImU32 control_text(button_kind_t kind, float hover, bool active, bool disabled) {
			const auto& t = aida::ui::resolved();
			float alpha = (disabled ? t.disabled_alpha : 1.f) * ImGui::GetStyle().Alpha;
			if (kind == button_kind_t::destructive) {
				return aida::ui::with_alpha(aida::ui::mix(t.error, t.text_primary, hover * 0.25f), alpha);
			}
			return aida::ui::with_alpha(aida::ui::mix(active ? t.accent_u32 : t.text_secondary, t.text_primary, hover), alpha);
		}

		inline void draw_control_shell(const control_frame_t& frame, button_kind_t kind,
			bool active, bool disabled, float radius) {
			ImDrawList* dl = ImGui::GetWindowDrawList();
			float scale = 1.f - (1.f - 0.98f) * frame.press;
			float w = frame.max.x - frame.min.x;
			float h = frame.max.y - frame.min.y;
			ImVec2 a = ImVec2(frame.min.x + (1.f - scale) * w * 0.5f,
				frame.min.y + (1.f - scale) * h * 0.5f);
			ImVec2 b = ImVec2(frame.max.x - (1.f - scale) * w * 0.5f,
				frame.max.y - (1.f - scale) * h * 0.5f);
			dl->AddRectFilled(a, b, control_fill(kind, frame.hover, active, disabled), radius);
			dl->AddRect(a, b, control_border(kind, frame.hover, active, disabled), radius, 0, active ? 1.4f : 1.f);
			if (frame.flash > 0.001f) {
				dl->AddRectFilled(a, b,
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), frame.flash * 0.18f),
					radius);
			}
			if (frame.focused && !disabled) {
				const auto& t = aida::ui::resolved();
				dl->AddRect(ImVec2(a.x - 2.f, a.y - 2.f),
					ImVec2(b.x + 2.f, b.y + 2.f),
					aida::ui::with_alpha(t.border_focus, 0.82f), radius + 2.f, 0, 1.5f);
			}
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

		const bool activated = ImGui::InvisibleButton("##b", ImVec2(w, h));
		bool hovered = ImGui::IsItemHovered() && !disabled && !loading;
		bool held    = ImGui::IsItemActive() && !disabled && !loading;
		bool clicked = activated && !disabled && !loading;
		bool focused = ImGui::IsItemFocused();

		auto& st = detail::bstate(id);
		float hov = st.hover.tick(hovered, aida::ui::clock::dt());
		float prs = st.press.tick(held, aida::ui::clock::dt());
		float flash = st.flash.tick(aida::ui::clock::dt());
		if (clicked) st.flash.trigger();

		float scale = 1.f - (1.f - 0.985f) * prs;
		float lift  = hov * 0.5f - prs * 0.5f;
		ImVec2 ca = ImVec2(a.x + (1.f - scale) * w * 0.5f, a.y + (1.f - scale) * h * 0.5f - lift);
		ImVec2 cb = ImVec2(b.x - (1.f - scale) * w * 0.5f, b.y - (1.f - scale) * h * 0.5f - lift);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		float radius = aida::ui::metrics::radius::md;
		float alpha = (disabled ? t.disabled_alpha : 1.f) * ImGui::GetStyle().Alpha;

		ImU32 fill = t.panel_header;
		ImU32 border = t.border_subtle;
		ImU32 text_col = t.text_primary;
		ImU32 hover_top = t.accent_grad_top;
		ImU32 hover_bot = t.accent_grad_bot;

		bool primary_or_accent = (kind == button_kind_t::primary ||
		                          kind == button_kind_t::accent_gradient);

		switch (kind) {
			case button_kind_t::primary:
			case button_kind_t::accent_gradient: {
				radius = aida::ui::metrics::radius::sm;
				ImU32 idle_top = aida::ui::with_alpha(t.accent_dim, 0.55f);
				ImU32 idle_bot = aida::ui::with_alpha(t.accent_dim, 0.30f);
				ImU32 hov_top  = aida::ui::with_alpha(t.accent_grad_top, 0.95f);
				ImU32 hov_bot  = aida::ui::with_alpha(t.accent_grad_bot, 0.95f);
				ImU32 cur_top  = aida::ui::mix(idle_top, hov_top, hov);
				ImU32 cur_bot  = aida::ui::mix(idle_bot, hov_bot, hov);
				ImU32 flat     = aida::ui::mix(cur_top, cur_bot, 0.5f);
				dl->AddRectFilled(ca, cb, aida::ui::with_alpha(flat, alpha), radius);
				ImU32 b_idle = aida::ui::with_alpha(t.accent_dim, 0.75f);
				ImU32 b_hov  = aida::ui::with_alpha(t.accent_hover, 0.92f);
				border = aida::ui::mix(b_idle, b_hov, hov);
				ImU32 tc_idle = aida::ui::with_alpha(t.text_primary, 0.92f);
				ImU32 tc_hov  = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.96f);
				text_col = aida::ui::mix(tc_idle, tc_hov, hov);
				break;
			}
			case button_kind_t::secondary:
				fill = aida::ui::lighten(t.panel_header, t.is_dark ? 5 : -4);
				border = t.border_strong;
				text_col = t.text_primary;
				break;
			case button_kind_t::ghost:
				fill = t.bg_elevated;
				border = t.border_subtle;
				text_col = t.text_primary;
				break;
			case button_kind_t::destructive:
				fill = aida::ui::with_alpha(t.error, 0.20f);
				border = aida::ui::with_alpha(t.error, 0.70f);
				text_col = t.error;
				break;
		}

		if (!primary_or_accent) {
			ImU32 hover_blend_top = aida::ui::mix(fill, hover_top, hov * 0.22f);
			ImU32 hover_blend_bot = aida::ui::mix(fill, hover_bot, hov * 0.22f);
			ImU32 fill_flat = aida::ui::mix(hover_blend_top, hover_blend_bot, 0.5f);
			dl->AddRectFilled(ca, cb, aida::ui::with_alpha(fill_flat, alpha), radius);
			ImU32 top_hi = aida::ui::with_alpha(IM_COL32(255, 255, 255, t.is_dark ? 26 : 60),
			                                    alpha * (0.7f + hov * 0.3f));
			dl->AddLine(ImVec2(ca.x + radius * 0.5f, ca.y + 1.f),
			            ImVec2(cb.x - radius * 0.5f, ca.y + 1.f), top_hi, 1.f);
		}

		float border_thickness = primary_or_accent ? 1.0f : 1.25f;
		dl->AddRect(ca, cb, aida::ui::with_alpha(border, alpha * (primary_or_accent ? 1.f : (1.f + hov * 0.45f))), radius, 0, border_thickness);

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

	inline bool icon_button(const char* id, const char* glyph,
		float size_px = aida::ui::metrics::control::icon_button,
		button_kind_t kind = button_kind_t::ghost,
		bool disabled = false, const char* tooltip = nullptr) {
		const char* text = glyph ? glyph : "";
		float side = size_px > 0.f ? size_px : aida::ui::metrics::control::icon_button;
		control_frame_t frame = control_frame(id, ImVec2(side, side), disabled);
		detail::draw_control_shell(frame, kind, false, disabled, aida::ui::metrics::radius::sm);
		ImFont* font = ImGui::GetFont();
		float fs = (std::min)(aida::ui::metrics::control::icon_glyph, side - 8.f);
		if (fs < 8.f) fs = 8.f;
		ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, text);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddText(font, fs,
			ImVec2(frame.min.x + (side - ts.x) * 0.5f, frame.min.y + (side - fs) * 0.5f),
			detail::control_text(kind, frame.hover, false, disabled), text);
		tooltip_for_last_item(tooltip);
		return frame.clicked;
	}

	inline bool toolbar_button(const char* id, const char* label_or_icon,
		bool active = false, bool disabled = false, const char* tooltip = nullptr,
		float width = 0.f) {
		const char* text = label_or_icon ? label_or_icon : "";
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::sm);
		float h = (std::max)(aida::ui::metrics::control::toolbar_h, fs + 12.f);
		float text_w = detail::calc_display_text_width(font, fs, text);
		float w = width > 0.f ? width : (std::max)(aida::ui::metrics::control::icon_button, text_w + 18.f);
		control_frame_t frame = control_frame(id, ImVec2(w, h), disabled);
		button_kind_t kind = active ? button_kind_t::secondary : button_kind_t::ghost;
		detail::draw_control_shell(frame, kind, active, disabled, aida::ui::metrics::radius::sm);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImU32 col = detail::control_text(kind, frame.hover, active, disabled);
		ImVec2 text_pos = ImVec2(frame.min.x + (w - text_w) * 0.5f, frame.min.y + (h - fs) * 0.5f);
		dl->PushClipRect(ImVec2(frame.min.x + 4.f, frame.min.y), ImVec2(frame.max.x - 4.f, frame.max.y), true);
		detail::add_display_text(dl, font, fs, text_pos, col, text);
		dl->PopClipRect();
		tooltip_for_last_item(tooltip);
		return frame.clicked;
	}

	inline bool copy_button(const char* id, flash_t* copied_flash_state = nullptr,
		const char* tooltip = "Copy", bool disabled = false) {
		const char* glyph = "\xEE\xA4\xAC";
		float side = aida::ui::metrics::control::icon_button;
		control_frame_t frame = control_frame(id, ImVec2(side, side), disabled, copied_flash_state == nullptr);
		if (frame.clicked && copied_flash_state) copied_flash_state->trigger();
		float copied_v = copied_flash_state ? copied_flash_state->tick(aida::ui::clock::dt(), 2.5f) : frame.flash;
		if (frame.clicked && copied_flash_state) copied_v = 1.f;
		detail::draw_control_shell(frame, button_kind_t::ghost, false, disabled, aida::ui::metrics::radius::sm);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImFont* font = ImGui::GetFont();
		float fs = aida::ui::metrics::control::icon_glyph;
		ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, glyph);
		ImU32 col = detail::control_text(button_kind_t::ghost, frame.hover, false, disabled);
		dl->AddText(font, fs,
			ImVec2(frame.min.x + (side - ts.x) * 0.5f, frame.min.y + (side - fs) * 0.5f),
			col, glyph);
		if (copied_v > 0.001f) {
			const auto& t = aida::ui::resolved();
			aida::ui::brand::render_check_drawn(dl,
				ImVec2(frame.min.x + side * 0.5f, frame.min.y + side * 0.5f),
				10.f, 1.f - copied_v,
				aida::ui::with_alpha(t.success, disabled ? t.disabled_alpha : 1.f), 1.8f);
		}
		tooltip_for_last_item(tooltip);
		return frame.clicked;
	}

	inline action_chip_result_t action_chip(const char* id, const char* label,
		button_kind_t kind = button_kind_t::secondary, bool selected = false,
		bool removable = false, bool disabled = false, const char* tooltip = nullptr) {
		action_chip_result_t result;
		const char* text = label ? label : "";
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::sm);
		float pad_x = 10.f;
		float remove_w = removable ? 16.f : 0.f;
		float text_w = detail::calc_display_text_width(font, fs, text);
		float h = (std::max)(26.f, fs + 11.f);
		float w = text_w + remove_w + pad_x * 2.f;
		control_frame_t frame = control_frame(id, ImVec2(w, h), disabled);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		float radius = h * 0.5f;
		detail::draw_control_shell(frame, kind, selected, disabled, radius);
		ImU32 col = detail::control_text(kind, frame.hover, selected, disabled);
		detail::add_display_text(dl, font, fs,
			ImVec2(frame.min.x + pad_x, frame.min.y + (h - fs) * 0.5f), col, text);
		if (removable) {
			float xx = frame.max.x - 9.f;
			float xy = frame.min.y + h * 0.5f;
			float xs = 4.f;
			dl->AddLine(ImVec2(xx - xs, xy - xs), ImVec2(xx + xs, xy + xs), col, 1.5f);
			dl->AddLine(ImVec2(xx - xs, xy + xs), ImVec2(xx + xs, xy - xs), col, 1.5f);
			ImVec2 mp = ImGui::GetMousePos();
			result.removed = frame.clicked && mp.x >= frame.max.x - 20.f && !disabled;
		}
		result.clicked = frame.clicked && !result.removed;
		tooltip_for_last_item(tooltip);
		return result;
	}

	inline void pill(const char* label, ImU32 color, size_t_ size = size_t_::sm,
	                  bool leading_dot = true) {
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size);
		float pad_x = size == size_t_::sm ? 11.f : 13.f;
		float h     = size == size_t_::sm ? (std::max)(24.f, fs + 9.f)
		                                  : (std::max)(28.f, fs + 12.f);

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

	inline void status_badge(const char* label, status_kind_t kind,
		bool compact = true, bool leading_dot = true) {
		pill(label, status_color(kind), compact ? size_t_::sm : size_t_::md, leading_dot);
	}

	inline void badge(const char* label, ImU32 color, float radius = aida::ui::metrics::radius::xs) {
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::sm) * 0.86f;
		float pad_x = 8.f;
		float h = (std::max)(20.f, fs + 8.f);
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
		float fs = detail::sz_font(size_t_::sm);
		float pad_x = 10.f;
		float h = (std::max)(26.f, fs + 11.f);
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
		float h = size.y > 0.f ? size.y : aida::ui::metrics::control::input_h;
		float w = size.x > 0.f ? size.x : ImGui::GetContentRegionAvail().x;

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		auto& hov = detail::hstate(id);
		auto& act = detail::hstate(id ^ 0x9E3779B9u);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(a, b, t.bg_elevated, aida::ui::metrics::radius::sm);

		bool active = ImGui::GetActiveID() == ImGui::GetID("##in");
		bool hovered = !active && ImGui::IsMouseHoveringRect(a, b, false);
		float hover_v = hov.tick(hovered, aida::ui::clock::dt(), aida::motion::spring::balanced);
		float active_v = act.tick(active, aida::ui::clock::dt(), aida::motion::spring::balanced);
		float focus_v = active_v > hover_v * 0.55f ? active_v : hover_v * 0.55f;
		ImU32 border = aida::ui::mix(t.border_subtle, t.border_focus, focus_v);
		dl->AddRect(a, b, border, aida::ui::metrics::radius::sm, 0, 1.f + active_v * 0.8f);

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

		ImGui::SetCursorScreenPos(pos);
		ImGui::Dummy(ImVec2(w, h));
		ImGui::PopID();
		return changed;
	}

	inline bool input_int(const char* label, int* value, ImVec2 size = ImVec2(0.f, 0.f)) {
		if (!value) return false;
		const auto& t = aida::ui::resolved();
		float h = size.y > 0.f ? size.y : aida::ui::metrics::control::input_h;
		float w = size.x > 0.f ? size.x : ImGui::GetContentRegionAvail().x;

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		auto& hov = detail::hstate(id);
		auto& act = detail::hstate(id ^ 0x9E3779B9u);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 a = pos;
		ImVec2 b = ImVec2(pos.x + w, pos.y + h);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(a, b, t.bg_elevated, aida::ui::metrics::radius::sm);

		bool active = ImGui::GetActiveID() == ImGui::GetID("##ii");
		bool hovered = !active && ImGui::IsMouseHoveringRect(a, b, false);
		float hover_v = hov.tick(hovered, aida::ui::clock::dt(), aida::motion::spring::balanced);
		float active_v = act.tick(active, aida::ui::clock::dt(), aida::motion::spring::balanced);
		float focus_v = active_v > hover_v * 0.55f ? active_v : hover_v * 0.55f;
		ImU32 border = aida::ui::mix(t.border_subtle, t.border_focus, focus_v);
		dl->AddRect(a, b, border, aida::ui::metrics::radius::sm, 0, 1.f + active_v * 0.8f);

		ImGui::SetCursorScreenPos(ImVec2(a.x + 12.f, a.y + (h - ImGui::GetFontSize()) * 0.5f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0,0,0,0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0,0,0,0));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));
		ImGui::SetNextItemWidth(w - 24.f);
		bool changed = ImGui::InputInt("##ii", value, 0, 0);
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(3);

		ImGui::SetCursorScreenPos(pos);
		ImGui::Dummy(ImVec2(w, h));
		ImGui::PopID();
		return changed;
	}

	inline void section_header(const char* title, const char* count_label = nullptr,
	                            const char* action_label = nullptr, bool* action_clicked = nullptr) {
		const auto& t = aida::ui::resolved();
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::md);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		float w = ImGui::GetContentRegionAvail().x;
		float h = (std::max)(32.f, fs + 14.f);

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
		ImGui::Dummy(ImVec2(0.f, 0.f));
	}

	inline bool toggle_switch(const char* label, bool* state, size_t_ size = size_t_::sm) {
		if (!state) return false;
		const auto& t = aida::ui::resolved();
		float track_w = size == size_t_::sm ? 38.f : 46.f;
		float track_h = size == size_t_::sm ? 21.f : 25.f;
		float fs = detail::sz_font(size);
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
		tooltip_for_last_item(text, delay);
	}

	inline void kbd_chip(const char* label) {
		const auto& t = aida::ui::resolved();
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::sm) * 0.9f;
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

	inline bool radio_button(const char* label, int* v, int btn_v) {
		if (!v) return false;
		const auto& t = aida::ui::resolved();
		ImFont* font = ImGui::GetFont();
		float fs = detail::sz_font(size_t_::sm);
		float ring_r = fs * 0.52f;
		float diam = ring_r * 2.f;
		float gap = 7.f;

		const char* disp_end = detail::display_end(label);
		bool has_label = label && (disp_end == nullptr ? (*label != '\0') : (label != disp_end));
		float text_w = has_label
			? font->CalcTextSizeA(fs, FLT_MAX, 0.f, label, disp_end).x
			: 0.f;
		float total_w = diam + (has_label ? gap + text_w : 0.f);
		float total_h = ((diam > fs) ? diam : fs) + 4.f;

		ImGui::PushID(label);
		ImGuiID id = ImGui::GetID(label);
		auto& hov = detail::hstate(id);

		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::InvisibleButton("##radio", ImVec2(total_w, total_h));
		bool hovered = ImGui::IsItemHovered();
		bool clicked = ImGui::IsItemClicked();
		bool selected = (*v == btn_v);
		if (clicked) *v = btn_v;

		float hv = hov.tick(hovered, aida::ui::clock::dt(), aida::motion::spring::balanced);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		float cx = pos.x + ring_r;
		float cy = pos.y + total_h * 0.5f;

		ImU32 base_fill = t.is_dark
			? aida::ui::lighten(t.panel_header, 16)
			: aida::ui::darken(t.bg_elevated, 8);
		dl->AddCircleFilled(ImVec2(cx, cy), ring_r, base_fill, 28);

		ImU32 ring_lit = aida::ui::mix(t.border_strong, t.accent_u32, 0.55f + 0.45f * hv);
		ImU32 ring_col = selected ? t.accent_u32 : aida::ui::mix(t.border_strong, ring_lit, hv);
		dl->AddCircle(ImVec2(cx, cy), ring_r, ring_col, 28, selected ? 2.0f : 1.6f);

		if (hv > 0.01f && !selected) {
			dl->AddCircle(ImVec2(cx, cy), ring_r + 1.6f,
			              aida::ui::with_alpha(t.accent_glow, hv), 28, 1.f);
		}

		if (selected) {
			dl->AddCircleFilled(ImVec2(cx, cy), ring_r * 0.5f, t.accent_u32, 24);
		} else if (hv > 0.01f) {
			dl->AddCircleFilled(ImVec2(cx, cy), ring_r * 0.42f,
			                    aida::ui::with_alpha(t.accent_dim, hv * 0.55f), 24);
		}

		if (has_label) {
			ImU32 tc = selected
				? t.text_primary
				: aida::ui::mix(t.text_secondary, t.text_primary, hv);
			detail::add_display_text(dl, font, fs,
				ImVec2(pos.x + diam + gap, cy - fs * 0.5f), tc, label);
		}

		ImGui::PopID();
		return clicked;
	}

	inline ImU32 status_soft_color(status_kind_t kind) {
		const auto& t = aida::ui::resolved();
		switch (kind) {
			case status_kind_t::success: return t.success_soft;
			case status_kind_t::warning: return t.warning_soft;
			case status_kind_t::error: return t.error_soft;
			case status_kind_t::info: return t.info_soft;
			case status_kind_t::accent: return aida::ui::with_alpha(t.accent_u32, 0.24f);
			case status_kind_t::neutral: return aida::ui::with_alpha(t.text_secondary, 0.12f);
		}
		return aida::ui::with_alpha(t.text_secondary, 0.12f);
	}

	inline view_header_result_t view_header(const char* title, const char* subtitle = nullptr,
		const char* primary_action = nullptr, const char* secondary_action = nullptr,
		status_kind_t status = status_kind_t::neutral) {
		view_header_result_t result;
		const auto& t = aida::ui::resolved();
		const char* safe_title = title ? title : "";
		ImFont* font = ImGui::GetFont();
		float title_fs = detail::ui_fs() * aida::ui::metrics::typography::view_title_scale;
		float body_fs = detail::ui_fs() * aida::ui::metrics::typography::caption_scale;
		float h = subtitle && *subtitle ? aida::ui::metrics::panel::view_header_h : aida::ui::metrics::panel::header_h;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		float w = (std::max)(1.f, ImGui::GetContentRegionAvail().x);
		ImVec2 end = ImVec2(pos.x + w, pos.y + h);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(pos, end, t.bg_elevated, aida::ui::metrics::radius::md);
		dl->AddRect(pos, end, t.border_subtle, aida::ui::metrics::radius::md, 0, aida::ui::metrics::panel::border);
		ImU32 marker = status == status_kind_t::neutral ? t.accent_u32 : status_color(status);
		dl->AddRectFilled(ImVec2(pos.x, pos.y + 8.f), ImVec2(pos.x + 3.f, end.y - 8.f), marker, 1.5f);
		float text_x = pos.x + aida::ui::metrics::spacing::lg;
		float title_y = subtitle && *subtitle ? pos.y + 10.f : pos.y + (h - title_fs) * 0.5f;
		dl->AddText(font, title_fs, ImVec2(text_x, title_y), t.text_primary, safe_title);
		if (subtitle && *subtitle) {
			dl->AddText(font, body_fs, ImVec2(text_x, pos.y + 33.f), t.text_secondary, subtitle);
		}

		float primary_w = primary_action && *primary_action
			? detail::calc_display_text_width(font, detail::sz_font(size_t_::sm), primary_action) + 28.f : 0.f;
		float secondary_w = secondary_action && *secondary_action
			? detail::calc_display_text_width(font, detail::sz_font(size_t_::sm), secondary_action) + 28.f : 0.f;
		float action_h = aida::ui::metrics::control::height_sm;
		float action_y = pos.y + (h - action_h) * 0.5f;
		float action_x = end.x - aida::ui::metrics::spacing::md - primary_w - secondary_w;
		if (primary_w > 0.f && secondary_w > 0.f) action_x -= aida::ui::metrics::spacing::sm;
		ImGui::PushID(safe_title);
		if (secondary_w > 0.f) {
			ImGui::SetCursorScreenPos(ImVec2(action_x, action_y));
			result.secondary_clicked = button(secondary_action, button_kind_t::ghost, size_t_::sm,
				ImVec2(secondary_w, action_h));
			action_x += secondary_w + aida::ui::metrics::spacing::sm;
		}
		if (primary_w > 0.f) {
			ImGui::SetCursorScreenPos(ImVec2(action_x, action_y));
			result.primary_clicked = button(primary_action, button_kind_t::primary, size_t_::sm,
				ImVec2(primary_w, action_h));
		}
		ImGui::PopID();
		ImGui::SetCursorScreenPos(ImVec2(pos.x, end.y + aida::ui::metrics::spacing::sm));
		ImGui::Dummy(ImVec2(0.f, 0.f));
		return result;
	}

	inline bool begin_toolbar(const char* id, float height = aida::ui::metrics::toolbar::height) {
		const auto& t = aida::ui::resolved();
		float h = height > 0.f ? height : aida::ui::metrics::toolbar::height;
		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertU32ToFloat4(t.bg_elevated));
		ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(t.border_subtle));
		ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, aida::ui::metrics::radius::sm);
		ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, aida::ui::metrics::panel::border);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
			ImVec2(aida::ui::metrics::toolbar::padding_x, aida::ui::metrics::toolbar::padding_y));
		return ImGui::BeginChild(id && *id ? id : "##toolbar", ImVec2(0.f, h), true,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	}

	inline void end_toolbar() {
		ImGui::EndChild();
		ImGui::PopStyleVar(3);
		ImGui::PopStyleColor(2);
	}

	inline bool begin_toolbar_surface(const char* id,
		float height = aida::ui::metrics::toolbar::height) {
		return begin_toolbar(id, height);
	}

	inline void end_toolbar_surface() {
		end_toolbar();
	}

	inline void begin_toolbar_group(const char* id) {
		ImGui::PushID(id && *id ? id : "toolbar_group");
		ImGui::BeginGroup();
	}

	inline void end_toolbar_group(bool trailing_separator = true) {
		ImGui::EndGroup();
		ImGui::PopID();
		if (!trailing_separator) return;
		ImGui::SameLine(0.f, aida::ui::metrics::toolbar::group_gap);
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::Dummy(ImVec2(1.f, aida::ui::metrics::toolbar::separator_h));
		ImGui::GetWindowDrawList()->AddLine(pos,
			ImVec2(pos.x, pos.y + aida::ui::metrics::toolbar::separator_h),
			aida::ui::resolved().border_subtle, 1.f);
		ImGui::SameLine(0.f, aida::ui::metrics::toolbar::group_gap);
	}

	inline bool search_field(const char* id, char* buffer, size_t buffer_size,
		const char* hint = "Search", float width = 0.f, bool* cleared = nullptr,
		bool* focused = nullptr) {
		if (!buffer || buffer_size == 0) return false;
		const auto& t = aida::ui::resolved();
		float w = width > 0.f ? width : ImGui::GetContentRegionAvail().x;
		if (w < 72.f) w = 72.f;
		float h = aida::ui::metrics::control::search_h;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 end = ImVec2(pos.x + w, pos.y + h);
		bool has_value = buffer[0] != '\0';
		float icon_area = 30.f;
		float clear_area = has_value ? 28.f : 8.f;
		ImGui::PushID(id && *id ? id : "search");
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(t.bg_elevated));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImGui::ColorConvertU32ToFloat4(t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImGui::ColorConvertU32ToFloat4(t.panel_header));
		ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(t.border_subtle));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(icon_area, (h - ImGui::GetFontSize()) * 0.5f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, aida::ui::metrics::radius::sm);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::SetNextItemWidth(w);
		bool changed = ImGui::InputTextWithHint("##input", hint ? hint : "", buffer, buffer_size);
		bool active = ImGui::IsItemActive();
		if (focused) *focused = active;
		ImGui::PopStyleVar(3);
		ImGui::PopStyleColor(4);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImU32 icon_col = active ? t.accent_u32 : t.text_dim;
		ImVec2 center = ImVec2(pos.x + 13.f, pos.y + h * 0.5f - 1.f);
		dl->AddCircle(center, 4.5f, icon_col, 16, 1.4f);
		dl->AddLine(ImVec2(center.x + 3.2f, center.y + 3.2f),
			ImVec2(center.x + 7.f, center.y + 7.f), icon_col, 1.4f);
		bool did_clear = false;
		if (has_value) {
			ImGui::SetCursorScreenPos(ImVec2(end.x - clear_area, pos.y + 2.f));
			ImGui::InvisibleButton("##clear", ImVec2(clear_area - 2.f, h - 4.f));
			bool hovered = ImGui::IsItemHovered();
			ImU32 clear_col = hovered ? t.text_primary : t.text_dim;
			float cx = end.x - 14.f;
			float cy = pos.y + h * 0.5f;
			dl->AddLine(ImVec2(cx - 3.f, cy - 3.f), ImVec2(cx + 3.f, cy + 3.f), clear_col, 1.4f);
			dl->AddLine(ImVec2(cx - 3.f, cy + 3.f), ImVec2(cx + 3.f, cy - 3.f), clear_col, 1.4f);
			if (ImGui::IsItemClicked()) {
				buffer[0] = '\0';
				changed = true;
				did_clear = true;
			}
		}
		if (cleared) *cleared = did_clear;
		ImGui::SetCursorScreenPos(ImVec2(pos.x, end.y));
		ImGui::Dummy(ImVec2(0.f, 0.f));
		ImGui::PopID();
		return changed;
	}

	inline bool inline_notice(const char* id, const char* title, const char* message,
		status_kind_t kind = status_kind_t::info, const char* action_label = nullptr) {
		const auto& t = aida::ui::resolved();
		const char* safe_title = title ? title : "";
		const char* safe_message = message ? message : "";
		ImFont* font = ImGui::GetFont();
		float title_fs = detail::sz_font(size_t_::sm);
		float message_fs = detail::ui_fs() * aida::ui::metrics::typography::caption_scale;
		float w = (std::max)(1.f, ImGui::GetContentRegionAvail().x);
		float h = *safe_message ? 52.f : 40.f;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 end = ImVec2(pos.x + w, pos.y + h);
		ImU32 color = status_color(kind);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(pos, end, status_soft_color(kind), aida::ui::metrics::radius::sm);
		dl->AddRect(pos, end, aida::ui::with_alpha(color, 0.56f), aida::ui::metrics::radius::sm, 0, 1.f);
		dl->AddRectFilled(pos, ImVec2(pos.x + 3.f, end.y), color, aida::ui::metrics::radius::sm);
		dl->AddCircleFilled(ImVec2(pos.x + 16.f, pos.y + (*safe_message ? 18.f : h * 0.5f)), 3.f, color, 12);
		float text_x = pos.x + 28.f;
		dl->AddText(font, title_fs, ImVec2(text_x, pos.y + (*safe_message ? 9.f : (h - title_fs) * 0.5f)),
			t.text_primary, safe_title);
		if (*safe_message) {
			dl->AddText(font, message_fs, ImVec2(text_x, pos.y + 29.f), t.text_secondary, safe_message);
		}
		bool clicked = false;
		if (action_label && *action_label) {
			float action_w = detail::calc_display_text_width(font, detail::sz_font(size_t_::sm), action_label) + 24.f;
			ImGui::PushID(id && *id ? id : safe_title);
			ImGui::SetCursorScreenPos(ImVec2(end.x - action_w - 8.f, pos.y + (h - 28.f) * 0.5f));
			clicked = button(action_label, button_kind_t::ghost, size_t_::sm, ImVec2(action_w, 28.f));
			ImGui::PopID();
		}
		ImGui::SetCursorScreenPos(ImVec2(pos.x, end.y + aida::ui::metrics::spacing::sm));
		ImGui::Dummy(ImVec2(0.f, 0.f));
		return clicked;
	}

	inline bool property_row(const char* id, const char* label, const char* value,
		bool selectable = false, bool selected = false, status_kind_t value_kind = status_kind_t::neutral) {
		const auto& t = aida::ui::resolved();
		const char* safe_label = label ? label : "";
		const char* safe_value = value ? value : "";
		float w = (std::max)(1.f, ImGui::GetContentRegionAvail().x);
		float h = aida::ui::metrics::row::inspector;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::PushID(id && *id ? id : safe_label);
		ImGui::InvisibleButton("##property", ImVec2(w, h));
		bool hovered = ImGui::IsItemHovered();
		bool clicked = selectable && ImGui::IsItemClicked();
		ImGui::PopID();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 end = ImVec2(pos.x + w, pos.y + h);
		if (selected) dl->AddRectFilled(pos, end, t.selection, aida::ui::metrics::radius::xs);
		else if (hovered) dl->AddRectFilled(pos, end, t.hover_wash, aida::ui::metrics::radius::xs);
		dl->AddLine(ImVec2(pos.x, end.y), end, t.border_subtle, 1.f);
		float fs = detail::ui_fs() * aida::ui::metrics::typography::body_scale;
		float y = pos.y + (h - fs) * 0.5f;
		dl->AddText(ImGui::GetFont(), fs, ImVec2(pos.x + 8.f, y), t.text_secondary, safe_label);
		ImU32 value_color = value_kind == status_kind_t::neutral ? t.text_primary : status_color(value_kind);
		dl->PushClipRect(ImVec2(pos.x + aida::ui::metrics::row::property_label_w, pos.y), end, true);
		dl->AddText(ImGui::GetFont(), fs,
			ImVec2(pos.x + aida::ui::metrics::row::property_label_w, y), value_color, safe_value);
		dl->PopClipRect();
		return clicked;
	}

	inline bool splitter(const char* id, splitter_axis_t axis, float* primary_size,
		float min_size, float max_size, float length = 0.f,
		float thickness = aida::ui::metrics::splitter::thickness) {
		if (!primary_size || max_size < min_size) return false;
		const auto& t = aida::ui::resolved();
		ImVec2 avail = ImGui::GetContentRegionAvail();
		float extent = length > 0.f ? length : (axis == splitter_axis_t::x ? avail.y : avail.x);
		if (extent < 1.f) extent = 1.f;
		float hit = (std::max)(thickness, aida::ui::metrics::splitter::visible);
		ImVec2 size = axis == splitter_axis_t::x ? ImVec2(hit, extent) : ImVec2(extent, hit);
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::PushID(id && *id ? id : "splitter");
		ImGui::InvisibleButton("##splitter", size);
		bool hovered = ImGui::IsItemHovered();
		bool active = ImGui::IsItemActive();
		bool changed = false;
		if (active) {
			float delta = axis == splitter_axis_t::x ? ImGui::GetIO().MouseDelta.x : ImGui::GetIO().MouseDelta.y;
			float next = *primary_size + delta;
			if (next < min_size) next = min_size;
			if (next > max_size) next = max_size;
			changed = next != *primary_size;
			*primary_size = next;
		}
		if (hovered || active) {
			ImGui::SetMouseCursor(axis == splitter_axis_t::x ? ImGuiMouseCursor_ResizeEW : ImGuiMouseCursor_ResizeNS);
		}
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImU32 color = active ? t.accent_u32 : (hovered ? t.accent_dim : t.border_subtle);
		if (axis == splitter_axis_t::x) {
			float x = pos.x + hit * 0.5f;
			dl->AddLine(ImVec2(x, pos.y), ImVec2(x, pos.y + extent), color,
				hovered || active ? 2.f : aida::ui::metrics::splitter::visible);
		} else {
			float y = pos.y + hit * 0.5f;
			dl->AddLine(ImVec2(pos.x, y), ImVec2(pos.x + extent, y), color,
				hovered || active ? 2.f : aida::ui::metrics::splitter::visible);
		}
		ImGui::PopID();
		return changed;
	}

	inline bool begin_status_bar(const char* id, float height = aida::ui::metrics::status_bar::height) {
		const auto& t = aida::ui::resolved();
		float h = height > 0.f ? height : aida::ui::metrics::status_bar::height;
		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::ColorConvertU32ToFloat4(t.title_bar));
		ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(t.border_subtle));
		ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.f);
		ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
			ImVec2(aida::ui::metrics::status_bar::padding_x, 2.f));
		return ImGui::BeginChild(id && *id ? id : "##status_bar", ImVec2(0.f, h), true,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	}

	inline void end_status_bar() {
		ImGui::EndChild();
		ImGui::PopStyleVar(3);
		ImGui::PopStyleColor(2);
	}

	inline bool status_item(const char* id, const char* label, const char* value = nullptr,
		status_kind_t kind = status_kind_t::neutral, bool interactive = false,
		bool trailing_separator = true) {
		const auto& t = aida::ui::resolved();
		const char* safe_label = label ? label : "";
		const char* safe_value = value ? value : "";
		ImFont* font = ImGui::GetFont();
		float fs = detail::ui_fs() * aida::ui::metrics::typography::caption_scale;
		float label_w = font->CalcTextSizeA(fs, FLT_MAX, 0.f, safe_label).x;
		float value_w = *safe_value ? font->CalcTextSizeA(fs, FLT_MAX, 0.f, safe_value).x + 5.f : 0.f;
		float dot_w = kind == status_kind_t::neutral ? 0.f : 10.f;
		float w = label_w + value_w + dot_w + 10.f;
		float h = (std::max)(20.f, fs + 4.f);
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImGui::PushID(id && *id ? id : safe_label);
		ImGui::InvisibleButton("##status_item", ImVec2(w, h));
		bool hovered = ImGui::IsItemHovered();
		bool clicked = interactive && ImGui::IsItemClicked();
		ImGui::PopID();
		ImDrawList* dl = ImGui::GetWindowDrawList();
		if (interactive && hovered) {
			dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), t.hover_wash, aida::ui::metrics::radius::xs);
		}
		float x = pos.x + 5.f;
		if (dot_w > 0.f) {
			dl->AddCircleFilled(ImVec2(x + 3.f, pos.y + h * 0.5f), 2.5f, status_color(kind), 12);
			x += dot_w;
		}
		float y = pos.y + (h - fs) * 0.5f;
		dl->AddText(font, fs, ImVec2(x, y), t.text_secondary, safe_label);
		x += label_w;
		if (*safe_value) dl->AddText(font, fs, ImVec2(x + 5.f, y), t.text_primary, safe_value);
		if (trailing_separator) {
			ImGui::SameLine(0.f, aida::ui::metrics::status_bar::item_gap);
			ImVec2 sep = ImGui::GetCursorScreenPos();
			ImGui::Dummy(ImVec2(1.f, 14.f));
			dl->AddLine(sep, ImVec2(sep.x, sep.y + 14.f), t.border_subtle, 1.f);
			ImGui::SameLine(0.f, aida::ui::metrics::status_bar::item_gap);
		}
		return clicked;
	}

	inline bool presentation(const char* id, presentation_kind_t kind, const char* title,
		const char* message = nullptr, const char* action_label = nullptr,
		ImVec2 size = ImVec2(0.f, 0.f)) {
		const auto& t = aida::ui::resolved();
		const char* safe_title = title ? title : "";
		const char* safe_message = message ? message : "";
		float w = size.x > 0.f ? size.x : ImGui::GetContentRegionAvail().x;
		float h = size.y > 0.f ? size.y : 152.f;
		if (w < 1.f) w = 1.f;
		float min_h = action_label && *action_label ? 132.f : (*safe_message ? 112.f : 96.f);
		if (h < min_h) h = min_h;
		ImVec2 pos = ImGui::GetCursorScreenPos();
		ImVec2 end = ImVec2(pos.x + w, pos.y + h);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		dl->AddRectFilled(pos, end, t.bg_elevated, aida::ui::metrics::radius::md);
		dl->AddRect(pos, end, t.border_subtle, aida::ui::metrics::radius::md, 0, 1.f);
		float center_x = pos.x + w * 0.5f;
		float icon_y = pos.y + 30.f;
		if (kind == presentation_kind_t::loading) {
			render_progress_ring(ImVec2(center_x, icon_y), 9.f, 2.f, 0.f, true);
		} else {
			ImU32 color = kind == presentation_kind_t::error ? t.error : t.text_dim;
			dl->AddCircle(ImVec2(center_x, icon_y), 10.f, aida::ui::with_alpha(color, 0.72f), 24, 1.5f);
			if (kind == presentation_kind_t::error) {
				dl->AddLine(ImVec2(center_x, icon_y - 4.f), ImVec2(center_x, icon_y + 2.f), color, 1.7f);
				dl->AddCircleFilled(ImVec2(center_x, icon_y + 5.f), 1.f, color, 8);
			} else {
				dl->AddLine(ImVec2(center_x - 4.f, icon_y), ImVec2(center_x + 4.f, icon_y), color, 1.5f);
			}
		}
		ImFont* font = ImGui::GetFont();
		float title_fs = detail::ui_fs() * aida::ui::metrics::typography::title_scale;
		float body_fs = detail::ui_fs() * aida::ui::metrics::typography::caption_scale;
		float title_w = font->CalcTextSizeA(title_fs, FLT_MAX, 0.f, safe_title).x;
		dl->AddText(font, title_fs, ImVec2(center_x - title_w * 0.5f, pos.y + 50.f), t.text_primary, safe_title);
		if (*safe_message) {
			float message_w = font->CalcTextSizeA(body_fs, FLT_MAX, 0.f, safe_message).x;
			float max_message_w = w - 24.f;
			float message_x = message_w < max_message_w ? center_x - message_w * 0.5f : pos.x + 12.f;
			dl->PushClipRect(ImVec2(pos.x + 12.f, pos.y), ImVec2(end.x - 12.f, end.y), true);
			dl->AddText(font, body_fs, ImVec2(message_x, pos.y + 75.f), t.text_secondary, safe_message);
			dl->PopClipRect();
		}
		bool clicked = false;
		if (action_label && *action_label && kind != presentation_kind_t::loading) {
			float action_w = detail::calc_display_text_width(font, detail::sz_font(size_t_::sm), action_label) + 28.f;
			ImGui::PushID(id && *id ? id : safe_title);
			ImGui::SetCursorScreenPos(ImVec2(center_x - action_w * 0.5f, end.y - 40.f));
			clicked = button(action_label,
				kind == presentation_kind_t::error ? button_kind_t::secondary : button_kind_t::primary,
				size_t_::sm, ImVec2(action_w, 28.f));
			ImGui::PopID();
		}
		ImGui::SetCursorScreenPos(ImVec2(pos.x, end.y + aida::ui::metrics::spacing::sm));
		ImGui::Dummy(ImVec2(0.f, 0.f));
		return clicked;
	}

	inline bool compact_empty_state(const char* id, const char* title, const char* message = nullptr,
		const char* action_label = nullptr, ImVec2 size = ImVec2(0.f, 0.f)) {
		return presentation(id, presentation_kind_t::empty, title, message, action_label, size);
	}

	inline void loading_state(const char* id, const char* title, const char* message = nullptr,
		ImVec2 size = ImVec2(0.f, 0.f)) {
		presentation(id, presentation_kind_t::loading, title, message, nullptr, size);
	}

	inline bool error_state(const char* id, const char* title, const char* message = nullptr,
		const char* retry_label = nullptr, ImVec2 size = ImVec2(0.f, 0.f)) {
		return presentation(id, presentation_kind_t::error, title, message, retry_label, size);
	}

}

namespace aida::ui {
	using components::button;
	using components::icon_button;
	using components::toolbar_button;
	using components::copy_button;
	using components::action_chip;
	using components::pill;
	using components::pill_kind;
	using components::status_badge;
	using components::badge;
	using components::chip;
	using components::input_text;
	using components::input_int;
	using components::section_header;
	using components::toggle_switch;
	using components::radio_button;
	using components::status_dot;
	using components::glass_card_begin;
	using components::glass_card_end;
	using components::render_focus_ring;
	using components::render_progress_bar;
	using components::render_progress_ring;
	using components::tooltip_blur;
	using components::tooltip_for_last_item;
	using components::kbd_chip;
	using components::control_state;
	using components::hover_state;
	using components::transition_state;
	using components::control_frame;
	using components::control_padding;
	using components::control_font_size;
	using components::control_height;
	using components::display_text_width;
	using components::status_color;
	using components::status_soft_color;
	using components::view_header;
	using components::begin_toolbar;
	using components::end_toolbar;
	using components::begin_toolbar_surface;
	using components::end_toolbar_surface;
	using components::begin_toolbar_group;
	using components::end_toolbar_group;
	using components::search_field;
	using components::inline_notice;
	using components::property_row;
	using components::splitter;
	using components::begin_status_bar;
	using components::end_status_bar;
	using components::status_item;
	using components::presentation;
	using components::compact_empty_state;
	using components::loading_state;
	using components::error_state;
	using components::button_kind_t;
	using components::pill_kind_t;
	using components::status_kind_t;
	using components::presentation_kind_t;
	using components::splitter_axis_t;
	using components::size_t_;
	using components::control_frame_t;
	using components::action_chip_result_t;
	using components::view_header_result_t;
}
