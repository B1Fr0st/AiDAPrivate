#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "metrics.hpp"
#include <cstdint>
#include <string>
#include <atomic>

namespace aida::ui {

	struct theme_t {
		std::string name = "Default Dark";
		bool        is_dark = true;

		ImU32 bg_base;
		ImU32 bg_elevated;
		ImU32 bg_overlay;
		ImU32 panel_bg;
		ImU32 panel_header;
		ImU32 glass_tint;
		ImU32 title_bar;

		ImU32 border_subtle;
		ImU32 border_strong;
		ImU32 border_focus;

		ImU32 text_primary;
		ImU32 text_secondary;
		ImU32 text_dim;
		ImU32 text_address;
		ImU32 text_lineno;

		ImU32 hover_wash;
		ImU32 selection;
		ImU32 selection_strong;
		float disabled_alpha;

		ImVec4 accent;
		ImU32  accent_u32;
		ImU32  accent_hover;
		ImU32  accent_dim;
		ImU32  accent_glow;
		ImU32  accent_grad_top;
		ImU32  accent_grad_bot;

		ImU32 success;
		ImU32 success_soft;
		ImU32 warning;
		ImU32 warning_soft;
		ImU32 error;
		ImU32 error_soft;
		ImU32 info;
		ImU32 info_soft;
		ImU32 live;
		ImU32 stale;
		ImU32 breakpoint;
		ImU32 changed;
		ImU32 disabled;

		ImU32 syn_keyword;
		ImU32 syn_type;
		ImU32 syn_string;
		ImU32 syn_number;
		ImU32 syn_comment;
		ImU32 syn_function;
		ImU32 syn_identifier;
		ImU32 syn_register;
		ImU32 syn_address;
		ImU32 syn_preprocessor;
		ImU32 syn_operator;
	};

	inline float ui_scale_for_dpi(float dpi_scale) {
		if (!(dpi_scale > 0.f)) return 1.f;
		if (dpi_scale < 0.85f) return 0.85f;
		if (dpi_scale > 2.50f) return 2.50f;
		return dpi_scale;
	}

	inline float scale_px(float value, float dpi_scale) {
		float scaled = value * ui_scale_for_dpi(dpi_scale);
		if (scaled >= 1.f)
			return static_cast<float>(static_cast<int>(scaled + 0.5f));
		return scaled;
	}

	struct shell_metrics_t {
		float scale = 1.f;
		float pad = 8.f;
		float gap = 4.f;
		float title_h = 40.f;
		float menu_h = 32.f;
		float splitter_w = 5.f;
		float corner_radius = 6.f;
		float panel_radius = 6.f;
		float control_radius = 4.f;
		float title_logo = 22.f;
		float title_control = 28.f;
		float title_font = 16.f;
		float caption_font = 13.5f;
		float menu_font = 17.f;
		float menu_pad_x = 12.f;
		float menu_item_pad_x = 12.f;
		float activity_bar_w = 52.f;
		float activity_icon = 32.f;
		float activity_footer_h = 48.f;
		float bottom_tab_h = 28.f;
		float bottom_action_h = 28.f;
		float min_panel_w = 96.f;
	};

	inline shell_metrics_t shell_metrics(float dpi_scale) {
		const float s = ui_scale_for_dpi(dpi_scale);
		shell_metrics_t m;
		m.scale = s;
		m.pad = scale_px(8.f, s);
		m.gap = scale_px(4.f, s);
		m.title_h = scale_px(40.f, s);
		m.menu_h = scale_px(32.f, s);
		m.splitter_w = scale_px(5.f, s);
		m.corner_radius = scale_px(6.f, s);
		m.panel_radius = scale_px(6.f, s);
		m.control_radius = scale_px(4.f, s);
		m.title_logo = scale_px(22.f, s);
		m.title_control = scale_px(28.f, s);
		m.title_font = scale_px(16.f, s);
		m.caption_font = scale_px(13.5f, s);
		m.menu_font = scale_px(17.f, s);
		m.menu_pad_x = scale_px(12.f, s);
		m.menu_item_pad_x = scale_px(12.f, s);
		m.activity_bar_w = scale_px(52.f, s);
		m.activity_icon = scale_px(32.f, s);
		m.activity_footer_h = scale_px(48.f, s);
		m.bottom_tab_h = scale_px(28.f, s);
		m.bottom_action_h = scale_px(28.f, s);
		m.min_panel_w = scale_px(96.f, s);
		return m;
	}

	namespace detail {

		inline ImU32 u32_from_v4(const ImVec4& v) {
			return IM_COL32((int)(v.x * 255.f + 0.5f), (int)(v.y * 255.f + 0.5f),
			                 (int)(v.z * 255.f + 0.5f), (int)(v.w * 255.f + 0.5f));
		}

		inline theme_t make_default() {
			theme_t t;
			t.name = "Default Dark";
			t.is_dark = true;

			ImGuiStyle tmp;
			tmp = ImGuiStyle();
			ImGui::StyleColorsDark(&tmp);
			const ImVec4* c = tmp.Colors;

			t.bg_base       = u32_from_v4(c[ImGuiCol_WindowBg]);
			t.bg_elevated   = u32_from_v4(c[ImGuiCol_ChildBg]);
			t.bg_overlay    = u32_from_v4(c[ImGuiCol_PopupBg]);
			t.panel_bg      = u32_from_v4(c[ImGuiCol_ChildBg]);
			t.panel_header  = u32_from_v4(c[ImGuiCol_MenuBarBg]);
			t.glass_tint    = u32_from_v4(c[ImGuiCol_WindowBg]);
			t.title_bar     = u32_from_v4(c[ImGuiCol_TitleBg]);

			t.border_subtle = u32_from_v4(c[ImGuiCol_Border]);
			t.border_strong = u32_from_v4(c[ImGuiCol_Separator]);
			t.border_focus  = u32_from_v4(c[ImGuiCol_NavHighlight]);

			t.text_primary   = u32_from_v4(c[ImGuiCol_Text]);
			t.text_secondary = u32_from_v4(c[ImGuiCol_TextDisabled]);
			t.text_dim       = u32_from_v4(c[ImGuiCol_TextDisabled]);
			t.text_address   = u32_from_v4(c[ImGuiCol_Text]);
			t.text_lineno    = u32_from_v4(c[ImGuiCol_TextDisabled]);

			t.hover_wash       = u32_from_v4(c[ImGuiCol_HeaderHovered]);
			t.selection        = u32_from_v4(c[ImGuiCol_Header]);
			t.selection_strong = u32_from_v4(c[ImGuiCol_HeaderActive]);
			t.disabled_alpha   = 0.46f;

			t.accent          = c[ImGuiCol_CheckMark];
			t.accent_u32      = u32_from_v4(c[ImGuiCol_CheckMark]);
			t.accent_hover    = u32_from_v4(c[ImGuiCol_CheckMark]);
			t.accent_dim      = u32_from_v4(c[ImGuiCol_CheckMark]);
			t.accent_glow     = u32_from_v4(c[ImGuiCol_DragDropTarget]);
			t.accent_grad_top = u32_from_v4(c[ImGuiCol_CheckMark]);
			t.accent_grad_bot = u32_from_v4(c[ImGuiCol_CheckMark]);

			t.success      = IM_COL32(91, 194, 139, 255);
			t.success_soft = IM_COL32(40, 92, 68, 150);
			t.warning      = IM_COL32(222, 177, 91, 255);
			t.warning_soft = IM_COL32(104, 76, 31, 150);
			t.error        = IM_COL32(235, 103, 116, 255);
			t.error_soft   = IM_COL32(105, 42, 51, 150);
			t.info         = IM_COL32(94, 158, 235, 255);
			t.info_soft    = IM_COL32(41, 73, 111, 150);
			t.live         = t.success;
			t.stale        = t.warning;
			t.breakpoint   = t.error;
			t.changed      = t.info;
			t.disabled     = IM_COL32(107, 122, 139, 255);

			t.syn_keyword      = IM_COL32(198, 151, 255, 255);
			t.syn_type         = IM_COL32(103, 205, 214, 255);
			t.syn_string       = IM_COL32(157, 208, 137, 255);
			t.syn_number       = IM_COL32(224, 164, 106, 255);
			t.syn_comment      = IM_COL32(107, 122, 139, 255);
			t.syn_function     = IM_COL32(111, 174, 255, 255);
			t.syn_identifier   = IM_COL32(216, 222, 232, 255);
			t.syn_register     = IM_COL32(240, 137, 154, 255);
			t.syn_address      = IM_COL32(103, 166, 245, 255);
			t.syn_preprocessor = IM_COL32(193, 145, 246, 255);
			t.syn_operator     = IM_COL32(168, 181, 199, 255);
			return t;
		}

		inline theme_t make_aida_dark() { return make_default(); }

		inline theme_t  s_resolved = make_default();
		inline std::atomic<uint32_t> s_theme_generation{ 1 };
		inline float s_style_dpi_scale = 1.f;
		inline std::atomic<bool> s_comfortable_density{ false };
		inline std::atomic<bool> s_reduced_motion{ false };

		inline ImU32 lerp_u32(ImU32 a, ImU32 b, float t) {
			float ar = (float)((a >> IM_COL32_R_SHIFT) & 0xFF);
			float ag = (float)((a >> IM_COL32_G_SHIFT) & 0xFF);
			float ab = (float)((a >> IM_COL32_B_SHIFT) & 0xFF);
			float aa = (float)((a >> IM_COL32_A_SHIFT) & 0xFF);
			float br = (float)((b >> IM_COL32_R_SHIFT) & 0xFF);
			float bg = (float)((b >> IM_COL32_G_SHIFT) & 0xFF);
			float bb = (float)((b >> IM_COL32_B_SHIFT) & 0xFF);
			float ba = (float)((b >> IM_COL32_A_SHIFT) & 0xFF);
			int rr = (int)(ar + (br - ar) * t + 0.5f);
			int rg = (int)(ag + (bg - ag) * t + 0.5f);
			int rb = (int)(ab + (bb - ab) * t + 0.5f);
			int ra = (int)(aa + (ba - aa) * t + 0.5f);
			if (rr < 0) rr = 0; if (rr > 255) rr = 255;
			if (rg < 0) rg = 0; if (rg > 255) rg = 255;
			if (rb < 0) rb = 0; if (rb > 255) rb = 255;
			if (ra < 0) ra = 0; if (ra > 255) ra = 255;
			return IM_COL32(rr, rg, rb, ra);
		}

	}

	inline const theme_t& resolved() { return detail::s_resolved; }

	inline void set_dpi_scale(float dpi_scale) {
		detail::s_style_dpi_scale = ui_scale_for_dpi(dpi_scale);
	}

	inline float dpi_scale() {
		return detail::s_style_dpi_scale;
	}

	inline void set_design_preferences(bool comfortable_density, bool reduced_motion) {
		detail::s_comfortable_density.store(comfortable_density, std::memory_order_release);
		detail::s_reduced_motion.store(reduced_motion, std::memory_order_release);
	}

	inline bool reduced_motion_enabled() {
		return detail::s_reduced_motion.load(std::memory_order_acquire);
	}

	inline uint32_t theme_generation() {
		return detail::s_theme_generation.load(std::memory_order_acquire);
	}

	inline void apply_imgui_style(const theme_t& t) {
		ImGuiStyle& s = ImGui::GetStyle();
		s = ImGuiStyle();
		const float ds = detail::s_style_dpi_scale *
			(detail::s_comfortable_density.load(std::memory_order_acquire) ? 1.15f : 1.f);

		s.WindowPadding     = ImVec2(scale_px(12.f, ds), scale_px(12.f, ds));
		s.FramePadding      = ImVec2(scale_px(8.f, ds), scale_px(4.f, ds));
		s.CellPadding       = ImVec2(scale_px(8.f, ds), scale_px(4.f, ds));
		s.ItemSpacing       = ImVec2(scale_px(8.f, ds), scale_px(8.f, ds));
		s.ItemInnerSpacing  = ImVec2(scale_px(8.f, ds), scale_px(4.f, ds));
		s.IndentSpacing     = scale_px(16.f, ds);
		s.ScrollbarSize     = scale_px(8.f, ds);
		s.GrabMinSize       = scale_px(12.f, ds);
		s.WindowRounding    = scale_px(6.f, ds);
		s.ChildRounding     = scale_px(6.f, ds);
		s.FrameRounding     = scale_px(4.f, ds);
		s.PopupRounding     = scale_px(6.f, ds);
		s.ScrollbarRounding = scale_px(4.f, ds);
		s.GrabRounding      = scale_px(4.f, ds);
		s.TabRounding       = scale_px(4.f, ds);
		s.WindowBorderSize  = 0.f;
		s.ChildBorderSize   = 0.f;
		s.PopupBorderSize   = 1.f;
		s.FrameBorderSize   = 1.f;
		s.TabBorderSize     = 0.f;
		s.WindowMenuButtonPosition = ImGuiDir_None;

		ImGui::StyleColorsDark();

		const ImVec4* sc = s.Colors;
		theme_t& r = detail::s_resolved;
		r.bg_base       = detail::u32_from_v4(sc[ImGuiCol_WindowBg]);
		r.bg_elevated   = detail::u32_from_v4(sc[ImGuiCol_ChildBg]);
		r.bg_overlay    = detail::u32_from_v4(sc[ImGuiCol_PopupBg]);
		r.panel_bg      = detail::u32_from_v4(sc[ImGuiCol_ChildBg]);
		r.panel_header  = detail::u32_from_v4(sc[ImGuiCol_MenuBarBg]);
		r.glass_tint    = detail::u32_from_v4(sc[ImGuiCol_WindowBg]);
		r.title_bar     = detail::u32_from_v4(sc[ImGuiCol_TitleBg]);
		r.border_subtle = detail::u32_from_v4(sc[ImGuiCol_Border]);
		r.border_strong = detail::u32_from_v4(sc[ImGuiCol_Separator]);
		r.border_focus  = detail::u32_from_v4(sc[ImGuiCol_NavHighlight]);
		r.text_primary   = detail::u32_from_v4(sc[ImGuiCol_Text]);
		r.text_secondary = detail::u32_from_v4(sc[ImGuiCol_TextDisabled]);
		r.text_dim       = detail::u32_from_v4(sc[ImGuiCol_TextDisabled]);
		r.text_address   = detail::u32_from_v4(sc[ImGuiCol_Text]);
		r.text_lineno    = detail::u32_from_v4(sc[ImGuiCol_TextDisabled]);
		r.hover_wash       = detail::u32_from_v4(sc[ImGuiCol_HeaderHovered]);
		r.selection        = detail::u32_from_v4(sc[ImGuiCol_Header]);
		r.selection_strong = detail::u32_from_v4(sc[ImGuiCol_HeaderActive]);
		r.accent          = sc[ImGuiCol_CheckMark];
		r.accent_u32      = detail::u32_from_v4(sc[ImGuiCol_CheckMark]);
		r.accent_hover    = detail::u32_from_v4(sc[ImGuiCol_CheckMark]);
		r.accent_dim      = detail::u32_from_v4(sc[ImGuiCol_CheckMark]);
		r.accent_glow     = detail::u32_from_v4(sc[ImGuiCol_DragDropTarget]);
		r.accent_grad_top = detail::u32_from_v4(sc[ImGuiCol_CheckMark]);
		r.accent_grad_bot = detail::u32_from_v4(sc[ImGuiCol_CheckMark]);
	}

	inline void apply(const theme_t& t) {
		apply_immediate(t);
	}

	inline void apply_immediate(const theme_t& t) {
		detail::s_resolved = t;
		apply_imgui_style(t);
		detail::s_theme_generation.fetch_add(1u, std::memory_order_release);
	}

	inline void tick_theme_animation(float) {}

	inline void use_default() { apply_immediate(detail::make_default()); }

	inline theme_t make_theme_for_index(int) {
		return detail::make_default();
	}

	inline void apply_for_index(int, bool) {
		apply_immediate(detail::make_default());
	}

	inline bool is_dark() { return true; }

	inline ImU32 with_alpha(ImU32 c, float a) {
		float aa = (float)((c >> IM_COL32_A_SHIFT) & 0xFF) * a;
		if (aa < 0.f) aa = 0.f;
		if (aa > 255.f) aa = 255.f;
		ImU32 mask = (0xFFu << IM_COL32_A_SHIFT);
		return (c & ~mask) | (((ImU32)aa) << IM_COL32_A_SHIFT);
	}

	inline ImU32 with_alpha(const ImVec4& c, float a) {
		return with_alpha(ImGui::ColorConvertFloat4ToU32(c), a);
	}

	inline ImU32 lighten(ImU32 c, int amount) {
		int r = (int)((c >> IM_COL32_R_SHIFT) & 0xFF) + amount;
		int g = (int)((c >> IM_COL32_G_SHIFT) & 0xFF) + amount;
		int b = (int)((c >> IM_COL32_B_SHIFT) & 0xFF) + amount;
		int a = (int)((c >> IM_COL32_A_SHIFT) & 0xFF);
		if (r > 255) r = 255; if (r < 0) r = 0;
		if (g > 255) g = 255; if (g < 0) g = 0;
		if (b > 255) b = 255; if (b < 0) b = 0;
		return IM_COL32(r, g, b, a);
	}

	inline ImU32 darken(ImU32 c, int amount) { return lighten(c, -amount); }

	inline ImU32 mix(ImU32 a, ImU32 b, float t) { return detail::lerp_u32(a, b, t); }

}
