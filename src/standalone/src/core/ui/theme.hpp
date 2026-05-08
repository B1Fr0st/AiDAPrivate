#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include <cstdint>
#include <string>
#include <atomic>

namespace aida::ui {

	struct theme_t {
		std::string name = "Midnight";
		bool        is_dark = true;

		ImU32 bg_base;
		ImU32 bg_elevated;
		ImU32 bg_overlay;
		ImU32 panel_bg;
		ImU32 panel_header;
		ImU32 glass_tint;
		ImU32 title_bar;
		uint32_t acrylic_color;

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

	namespace detail {

		inline ImU32 from_rgba(int r, int g, int b, int a) { return IM_COL32(r, g, b, a); }

		inline theme_t make_midnight_dark() {
			theme_t t;
			t.name = "Midnight";
			t.is_dark = true;

			t.bg_base       = IM_COL32(10, 10, 20, 255);
			t.bg_elevated   = IM_COL32(18, 18, 30, 255);
			t.bg_overlay    = IM_COL32(26, 26, 40, 255);
			t.panel_bg      = IM_COL32(22, 22, 32, 210);
			t.panel_header  = IM_COL32(34, 34, 48, 230);
			t.glass_tint    = IM_COL32(20, 18, 40, 60);
			t.title_bar     = IM_COL32(16, 16, 24, 230);
			t.acrylic_color = (uint32_t)((5) | (12 << 8) | (65 << 16) | (0x70 << 24));

			t.border_subtle = IM_COL32(255, 255, 255, 12);
			t.border_strong = IM_COL32(255, 255, 255, 32);
			t.border_focus  = IM_COL32(134, 136, 254, 200);

			t.text_primary   = IM_COL32(230, 228, 255, 240);
			t.text_secondary = IM_COL32(170, 168, 194, 200);
			t.text_dim       = IM_COL32(118, 115, 157, 180);
			t.text_address   = IM_COL32(91, 123, 201, 220);
			t.text_lineno    = IM_COL32(84, 87, 124, 160);

			t.hover_wash       = IM_COL32(255, 255, 255, 18);
			t.selection        = IM_COL32(134, 136, 254, 70);
			t.selection_strong = IM_COL32(134, 136, 254, 130);
			t.disabled_alpha   = 0.42f;

			t.accent          = ImVec4(134.f/255.f, 136.f/255.f, 254.f/255.f, 1.f);
			t.accent_u32      = IM_COL32(134, 136, 254, 255);
			t.accent_hover    = IM_COL32(157, 158, 255, 255);
			t.accent_dim      = IM_COL32(134, 136, 254, 130);
			t.accent_glow     = IM_COL32(134, 136, 254, 50);
			t.accent_grad_top = IM_COL32(152, 147, 255, 255);
			t.accent_grad_bot = IM_COL32(115, 120, 228, 255);

			t.success      = IM_COL32(91, 209, 139, 255);
			t.success_soft = IM_COL32(91, 209, 139, 30);
			t.warning      = IM_COL32(242, 194, 92, 255);
			t.warning_soft = IM_COL32(242, 194, 92, 30);
			t.error        = IM_COL32(255, 107, 122, 255);
			t.error_soft   = IM_COL32(255, 107, 122, 30);
			t.info         = IM_COL32(91, 172, 224, 255);
			t.info_soft    = IM_COL32(91, 172, 224, 30);

			t.syn_keyword      = IM_COL32(197, 134, 224, 255);
			t.syn_type         = IM_COL32(98, 200, 214, 255);
			t.syn_string       = IM_COL32(156, 208, 141, 255);
			t.syn_number       = IM_COL32(224, 168, 124, 255);
			t.syn_comment      = IM_COL32(102, 107, 130, 255);
			t.syn_function     = IM_COL32(107, 186, 239, 255);
			t.syn_identifier   = IM_COL32(209, 210, 220, 255);
			t.syn_register     = IM_COL32(232, 156, 156, 255);
			t.syn_address      = IM_COL32(91, 123, 201, 255);
			t.syn_preprocessor = IM_COL32(197, 134, 224, 255);
			t.syn_operator     = IM_COL32(171, 178, 191, 255);
			return t;
		}

		inline theme_t make_midnight_light() {
			theme_t t;
			t.name = "Midnight Light";
			t.is_dark = false;

			t.bg_base       = IM_COL32(250, 250, 252, 255);
			t.bg_elevated   = IM_COL32(255, 255, 255, 255);
			t.bg_overlay    = IM_COL32(244, 244, 248, 255);
			t.panel_bg      = IM_COL32(255, 255, 255, 230);
			t.panel_header  = IM_COL32(244, 244, 250, 230);
			t.glass_tint    = IM_COL32(245, 247, 250, 60);
			t.title_bar     = IM_COL32(252, 252, 255, 230);
			t.acrylic_color = (uint32_t)((232) | (236 << 8) | (244 << 16) | (0xA0 << 24));

			t.border_subtle = IM_COL32(0, 0, 0, 18);
			t.border_strong = IM_COL32(0, 0, 0, 40);
			t.border_focus  = IM_COL32(80, 82, 224, 200);

			t.text_primary   = IM_COL32(12, 12, 24, 250);
			t.text_secondary = IM_COL32(72, 72, 92, 220);
			t.text_dim       = IM_COL32(138, 137, 160, 200);
			t.text_address   = IM_COL32(61, 93, 165, 230);
			t.text_lineno    = IM_COL32(147, 149, 176, 220);

			t.hover_wash       = IM_COL32(0, 0, 0, 14);
			t.selection        = IM_COL32(80, 82, 224, 50);
			t.selection_strong = IM_COL32(80, 82, 224, 100);
			t.disabled_alpha   = 0.42f;

			t.accent          = ImVec4(80.f/255.f, 82.f/255.f, 224.f/255.f, 1.f);
			t.accent_u32      = IM_COL32(80, 82, 224, 255);
			t.accent_hover    = IM_COL32(96, 98, 240, 255);
			t.accent_dim      = IM_COL32(80, 82, 224, 130);
			t.accent_glow     = IM_COL32(80, 82, 224, 50);
			t.accent_grad_top = IM_COL32(96, 99, 238, 255);
			t.accent_grad_bot = IM_COL32(64, 74, 200, 255);

			t.success      = IM_COL32(31, 155, 90, 255);
			t.success_soft = IM_COL32(31, 155, 90, 22);
			t.warning      = IM_COL32(167, 123, 11, 255);
			t.warning_soft = IM_COL32(167, 123, 11, 22);
			t.error        = IM_COL32(216, 50, 75, 255);
			t.error_soft   = IM_COL32(216, 50, 75, 22);
			t.info         = IM_COL32(42, 111, 176, 255);
			t.info_soft    = IM_COL32(42, 111, 176, 22);

			t.syn_keyword      = IM_COL32(153, 48, 176, 255);
			t.syn_type         = IM_COL32(15, 134, 150, 255);
			t.syn_string       = IM_COL32(63, 123, 48, 255);
			t.syn_number       = IM_COL32(166, 107, 44, 255);
			t.syn_comment      = IM_COL32(136, 139, 159, 255);
			t.syn_function     = IM_COL32(31, 111, 176, 255);
			t.syn_identifier   = IM_COL32(27, 27, 38, 255);
			t.syn_register     = IM_COL32(178, 58, 58, 255);
			t.syn_address      = IM_COL32(61, 93, 165, 255);
			t.syn_preprocessor = IM_COL32(153, 48, 176, 255);
			t.syn_operator     = IM_COL32(70, 75, 95, 255);
			return t;
		}

		inline theme_t  s_resolved = make_midnight_dark();
		inline theme_t  s_target   = make_midnight_dark();
		inline theme_t  s_source   = make_midnight_dark();
		inline transition_t s_swap_anim;

		inline std::atomic<bool> s_dark_pref_dark{ true };
		inline std::atomic<bool> s_user_override { false };
		inline std::atomic<bool> s_swap_pending  { false };

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

		inline void interpolate(theme_t& dst, const theme_t& a, const theme_t& b, float t) {
			dst.name = b.name;
			dst.is_dark = b.is_dark;
			dst.bg_base       = lerp_u32(a.bg_base, b.bg_base, t);
			dst.bg_elevated   = lerp_u32(a.bg_elevated, b.bg_elevated, t);
			dst.bg_overlay    = lerp_u32(a.bg_overlay, b.bg_overlay, t);
			dst.panel_bg      = lerp_u32(a.panel_bg, b.panel_bg, t);
			dst.panel_header  = lerp_u32(a.panel_header, b.panel_header, t);
			dst.glass_tint    = lerp_u32(a.glass_tint, b.glass_tint, t);
			dst.title_bar     = lerp_u32(a.title_bar, b.title_bar, t);
			dst.acrylic_color = b.acrylic_color;
			dst.border_subtle = lerp_u32(a.border_subtle, b.border_subtle, t);
			dst.border_strong = lerp_u32(a.border_strong, b.border_strong, t);
			dst.border_focus  = lerp_u32(a.border_focus, b.border_focus, t);
			dst.text_primary   = lerp_u32(a.text_primary, b.text_primary, t);
			dst.text_secondary = lerp_u32(a.text_secondary, b.text_secondary, t);
			dst.text_dim       = lerp_u32(a.text_dim, b.text_dim, t);
			dst.text_address   = lerp_u32(a.text_address, b.text_address, t);
			dst.text_lineno    = lerp_u32(a.text_lineno, b.text_lineno, t);
			dst.hover_wash       = lerp_u32(a.hover_wash, b.hover_wash, t);
			dst.selection        = lerp_u32(a.selection, b.selection, t);
			dst.selection_strong = lerp_u32(a.selection_strong, b.selection_strong, t);
			dst.disabled_alpha   = a.disabled_alpha + (b.disabled_alpha - a.disabled_alpha) * t;
			dst.accent.x = a.accent.x + (b.accent.x - a.accent.x) * t;
			dst.accent.y = a.accent.y + (b.accent.y - a.accent.y) * t;
			dst.accent.z = a.accent.z + (b.accent.z - a.accent.z) * t;
			dst.accent.w = a.accent.w + (b.accent.w - a.accent.w) * t;
			dst.accent_u32      = lerp_u32(a.accent_u32, b.accent_u32, t);
			dst.accent_hover    = lerp_u32(a.accent_hover, b.accent_hover, t);
			dst.accent_dim      = lerp_u32(a.accent_dim, b.accent_dim, t);
			dst.accent_glow     = lerp_u32(a.accent_glow, b.accent_glow, t);
			dst.accent_grad_top = lerp_u32(a.accent_grad_top, b.accent_grad_top, t);
			dst.accent_grad_bot = lerp_u32(a.accent_grad_bot, b.accent_grad_bot, t);
			dst.success      = lerp_u32(a.success, b.success, t);
			dst.success_soft = lerp_u32(a.success_soft, b.success_soft, t);
			dst.warning      = lerp_u32(a.warning, b.warning, t);
			dst.warning_soft = lerp_u32(a.warning_soft, b.warning_soft, t);
			dst.error        = lerp_u32(a.error, b.error, t);
			dst.error_soft   = lerp_u32(a.error_soft, b.error_soft, t);
			dst.info         = lerp_u32(a.info, b.info, t);
			dst.info_soft    = lerp_u32(a.info_soft, b.info_soft, t);
			dst.syn_keyword      = lerp_u32(a.syn_keyword, b.syn_keyword, t);
			dst.syn_type         = lerp_u32(a.syn_type, b.syn_type, t);
			dst.syn_string       = lerp_u32(a.syn_string, b.syn_string, t);
			dst.syn_number       = lerp_u32(a.syn_number, b.syn_number, t);
			dst.syn_comment      = lerp_u32(a.syn_comment, b.syn_comment, t);
			dst.syn_function     = lerp_u32(a.syn_function, b.syn_function, t);
			dst.syn_identifier   = lerp_u32(a.syn_identifier, b.syn_identifier, t);
			dst.syn_register     = lerp_u32(a.syn_register, b.syn_register, t);
			dst.syn_address      = lerp_u32(a.syn_address, b.syn_address, t);
			dst.syn_preprocessor = lerp_u32(a.syn_preprocessor, b.syn_preprocessor, t);
			dst.syn_operator     = lerp_u32(a.syn_operator, b.syn_operator, t);
		}
	}

	inline const theme_t& resolved() { return detail::s_resolved; }

	inline void apply_imgui_style(const theme_t& t) {
		ImGuiStyle& s = ImGui::GetStyle();

		s.WindowPadding     = ImVec2(16.f, 12.f);
		s.FramePadding      = ImVec2(10.f, 6.f);
		s.CellPadding       = ImVec2(8.f, 4.f);
		s.ItemSpacing       = ImVec2(8.f, 6.f);
		s.ItemInnerSpacing  = ImVec2(6.f, 4.f);
		s.IndentSpacing     = 20.f;
		s.ScrollbarSize     = 10.f;
		s.GrabMinSize       = 12.f;
		s.WindowRounding    = 12.f;
		s.ChildRounding     = 10.f;
		s.FrameRounding     = 8.f;
		s.PopupRounding     = 14.f;
		s.ScrollbarRounding = 10.f;
		s.GrabRounding      = 6.f;
		s.TabRounding       = 8.f;
		s.WindowBorderSize  = 0.f;
		s.ChildBorderSize   = 0.f;
		s.PopupBorderSize   = 0.f;
		s.FrameBorderSize   = 0.f;
		s.TabBorderSize     = 0.f;
		s.WindowMenuButtonPosition = ImGuiDir_None;

		auto to_v4 = [](ImU32 c) {
			float r = (float)((c >> IM_COL32_R_SHIFT) & 0xFF) / 255.f;
			float g = (float)((c >> IM_COL32_G_SHIFT) & 0xFF) / 255.f;
			float b = (float)((c >> IM_COL32_B_SHIFT) & 0xFF) / 255.f;
			float a = (float)((c >> IM_COL32_A_SHIFT) & 0xFF) / 255.f;
			return ImVec4(r, g, b, a);
		};

		ImVec4* c = s.Colors;
		c[ImGuiCol_Text]                 = to_v4(t.text_primary);
		c[ImGuiCol_TextDisabled]         = to_v4(t.text_dim);
		c[ImGuiCol_WindowBg]             = to_v4(t.bg_base);
		c[ImGuiCol_ChildBg]              = ImVec4(0,0,0,0);
		c[ImGuiCol_PopupBg]              = to_v4(t.bg_overlay);
		c[ImGuiCol_Border]               = to_v4(t.border_subtle);
		c[ImGuiCol_BorderShadow]         = ImVec4(0,0,0,0);
		c[ImGuiCol_FrameBg]              = to_v4(t.panel_header);
		c[ImGuiCol_FrameBgHovered]       = to_v4(t.hover_wash);
		c[ImGuiCol_FrameBgActive]        = to_v4(t.selection);
		c[ImGuiCol_TitleBg]              = to_v4(t.title_bar);
		c[ImGuiCol_TitleBgActive]        = to_v4(t.title_bar);
		c[ImGuiCol_TitleBgCollapsed]     = to_v4(t.title_bar);
		c[ImGuiCol_MenuBarBg]            = to_v4(t.panel_header);
		c[ImGuiCol_ScrollbarBg]          = ImVec4(0,0,0,0);
		c[ImGuiCol_ScrollbarGrab]        = to_v4(t.accent_dim);
		c[ImGuiCol_ScrollbarGrabHovered] = to_v4(t.accent_hover);
		c[ImGuiCol_ScrollbarGrabActive]  = t.accent;
		c[ImGuiCol_CheckMark]            = t.accent;
		c[ImGuiCol_SliderGrab]           = t.accent;
		c[ImGuiCol_SliderGrabActive]     = to_v4(t.accent_hover);
		c[ImGuiCol_Button]               = to_v4(t.panel_header);
		c[ImGuiCol_ButtonHovered]        = to_v4(t.hover_wash);
		c[ImGuiCol_ButtonActive]         = to_v4(t.accent_dim);
		c[ImGuiCol_Header]               = to_v4(t.selection);
		c[ImGuiCol_HeaderHovered]        = to_v4(t.hover_wash);
		c[ImGuiCol_HeaderActive]         = to_v4(t.selection_strong);
		c[ImGuiCol_Separator]            = to_v4(t.border_subtle);
		c[ImGuiCol_SeparatorHovered]     = to_v4(t.accent_dim);
		c[ImGuiCol_SeparatorActive]      = t.accent;
		c[ImGuiCol_ResizeGrip]           = to_v4(t.accent_dim);
		c[ImGuiCol_ResizeGripHovered]    = to_v4(t.accent_hover);
		c[ImGuiCol_ResizeGripActive]     = t.accent;
		c[ImGuiCol_Tab]                  = to_v4(t.panel_header);
		c[ImGuiCol_TabHovered]           = to_v4(t.hover_wash);
		c[ImGuiCol_TabActive]            = to_v4(t.accent_dim);
		c[ImGuiCol_TabUnfocused]         = to_v4(t.title_bar);
		c[ImGuiCol_TabUnfocusedActive]   = to_v4(t.panel_header);
		c[ImGuiCol_DockingPreview]       = to_v4(t.accent_glow);
		c[ImGuiCol_DockingEmptyBg]       = to_v4(t.bg_base);
		c[ImGuiCol_PlotLines]            = t.accent;
		c[ImGuiCol_PlotLinesHovered]     = to_v4(t.accent_hover);
		c[ImGuiCol_PlotHistogram]        = t.accent;
		c[ImGuiCol_PlotHistogramHovered] = to_v4(t.accent_hover);
		c[ImGuiCol_TableHeaderBg]        = to_v4(t.panel_header);
		c[ImGuiCol_TableBorderStrong]    = to_v4(t.border_strong);
		c[ImGuiCol_TableBorderLight]     = to_v4(t.border_subtle);
		c[ImGuiCol_TableRowBg]           = ImVec4(0,0,0,0);
		c[ImGuiCol_TableRowBgAlt]        = to_v4(IM_COL32(255, 255, 255, 6));
		c[ImGuiCol_TextSelectedBg]       = to_v4(t.selection_strong);
		c[ImGuiCol_DragDropTarget]       = to_v4(t.accent_glow);
		c[ImGuiCol_NavHighlight]         = to_v4(t.border_focus);
		c[ImGuiCol_NavWindowingHighlight]= ImVec4(1, 1, 1, 0.7f);
		c[ImGuiCol_NavWindowingDimBg]    = ImVec4(0, 0, 0, 0.55f);
		c[ImGuiCol_ModalWindowDimBg]     = ImVec4(0, 0, 0, 0.55f);
	}

	inline void apply(const theme_t& t) {
		detail::s_target = t;
		detail::s_source = detail::s_resolved;
		detail::s_swap_anim.start(0.240f, aida::motion::ease::in_out_cubic);
		detail::s_swap_pending = true;
	}

	inline void apply_immediate(const theme_t& t) {
		detail::s_target = t;
		detail::s_source = t;
		detail::s_resolved = t;
		detail::s_swap_anim.reset();
		detail::s_swap_pending = false;
		apply_imgui_style(t);
	}

	inline void tick_theme_animation(float dt) {
		if (detail::s_swap_pending.load(std::memory_order_acquire)) {
			detail::s_swap_anim.tick(dt);
			float p = detail::s_swap_anim.eased();
			detail::interpolate(detail::s_resolved, detail::s_source, detail::s_target, p);
			apply_imgui_style(detail::s_resolved);
			if (detail::s_swap_anim.is_finished()) {
				detail::s_resolved = detail::s_target;
				detail::s_swap_pending = false;
				apply_imgui_style(detail::s_resolved);
			}
		}
	}

	inline void use_dark()  { apply(detail::make_midnight_dark()); }
	inline void use_light() { apply(detail::make_midnight_light()); }

	inline bool is_dark() { return detail::s_resolved.is_dark; }
	inline void set_user_override(bool override_active) {
		detail::s_user_override.store(override_active, std::memory_order_release);
	}
	inline bool user_override_active() {
		return detail::s_user_override.load(std::memory_order_acquire);
	}

	inline ImU32 with_alpha(ImU32 c, float a) {
		float aa = (float)((c >> IM_COL32_A_SHIFT) & 0xFF) * a;
		if (aa < 0.f) aa = 0.f;
		if (aa > 255.f) aa = 255.f;
		ImU32 mask = (0xFFu << IM_COL32_A_SHIFT);
		return (c & ~mask) | (((ImU32)aa) << IM_COL32_A_SHIFT);
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
