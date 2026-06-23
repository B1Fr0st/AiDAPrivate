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
		std::string name = "AiDA Dark";
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
		float pad = 6.f;
		float gap = 4.f;
		float title_h = 38.f;
		float menu_h = 34.f;
		float splitter_w = 5.f;
		float corner_radius = 8.f;
		float panel_radius = 6.f;
		float control_radius = 6.f;
		float title_logo = 22.f;
		float title_control = 28.f;
		float title_font = 16.f;
		float caption_font = 13.5f;
		float menu_font = 17.f;
		float menu_pad_x = 12.f;
		float menu_item_pad_x = 12.f;
		float activity_bar_w = 56.f;
		float activity_icon = 36.f;
		float activity_footer_h = 52.f;
		float bottom_tab_h = 30.f;
		float bottom_action_h = 26.f;
		float min_panel_w = 96.f;
	};

	inline shell_metrics_t shell_metrics(float dpi_scale) {
		const float s = ui_scale_for_dpi(dpi_scale);
		shell_metrics_t m;
		m.scale = s;
		m.pad = scale_px(6.f, s);
		m.gap = scale_px(4.f, s);
		m.title_h = scale_px(38.f, s);
		m.menu_h = scale_px(34.f, s);
		m.splitter_w = scale_px(5.f, s);
		m.corner_radius = scale_px(8.f, s);
		m.panel_radius = scale_px(6.f, s);
		m.control_radius = scale_px(6.f, s);
		m.title_logo = scale_px(22.f, s);
		m.title_control = scale_px(28.f, s);
		m.title_font = scale_px(16.f, s);
		m.caption_font = scale_px(13.5f, s);
		m.menu_font = scale_px(17.f, s);
		m.menu_pad_x = scale_px(12.f, s);
		m.menu_item_pad_x = scale_px(12.f, s);
		m.activity_bar_w = scale_px(56.f, s);
		m.activity_icon = scale_px(36.f, s);
		m.activity_footer_h = scale_px(52.f, s);
		m.bottom_tab_h = scale_px(30.f, s);
		m.bottom_action_h = scale_px(26.f, s);
		m.min_panel_w = scale_px(96.f, s);
		return m;
	}

	namespace detail {

		inline ImU32 from_rgba(int r, int g, int b, int a) { return IM_COL32(r, g, b, a); }

		inline theme_t make_aida_dark() {
			theme_t t;
			t.name = "AiDA Dark";
			t.is_dark = true;

			t.bg_base       = IM_COL32(10, 14, 26, 255);
			t.bg_elevated   = IM_COL32(16, 22, 40, 255);
			t.bg_overlay    = IM_COL32(24, 32, 56, 255);
			t.panel_bg      = IM_COL32(15, 21, 38, 214);
			t.panel_header  = IM_COL32(26, 35, 60, 232);
			t.glass_tint    = IM_COL32(22, 40, 86, 64);
			t.title_bar     = IM_COL32(12, 17, 31, 232);
			t.acrylic_color = (uint32_t)((10) | (17 << 8) | (44 << 16) | (0x7A << 24));

			t.border_subtle = IM_COL32(138, 170, 255, 16);
			t.border_strong = IM_COL32(138, 170, 255, 40);
			t.border_focus  = IM_COL32(56, 134, 240, 205);

			t.text_primary   = IM_COL32(226, 234, 250, 242);
			t.text_secondary = IM_COL32(158, 174, 206, 206);
			t.text_dim       = IM_COL32(108, 124, 160, 182);
			t.text_address   = IM_COL32(99, 158, 236, 224);
			t.text_lineno    = IM_COL32(72, 88, 126, 165);

			t.hover_wash       = IM_COL32(120, 166, 255, 20);
			t.selection        = IM_COL32(56, 134, 240, 74);
			t.selection_strong = IM_COL32(56, 134, 240, 134);
			t.disabled_alpha   = 0.42f;

			t.accent          = ImVec4(56.f/255.f, 134.f/255.f, 240.f/255.f, 1.f);
			t.accent_u32      = IM_COL32(56, 134, 240, 255);
			t.accent_hover    = IM_COL32(95, 165, 255, 255);
			t.accent_dim      = IM_COL32(56, 134, 240, 130);
			t.accent_glow     = IM_COL32(56, 134, 240, 54);
			t.accent_grad_top = IM_COL32(92, 168, 255, 255);
			t.accent_grad_bot = IM_COL32(36, 98, 214, 255);

			t.success      = IM_COL32(74, 206, 156, 255);
			t.success_soft = IM_COL32(74, 206, 156, 30);
			t.warning      = IM_COL32(238, 190, 96, 255);
			t.warning_soft = IM_COL32(238, 190, 96, 30);
			t.error        = IM_COL32(255, 104, 122, 255);
			t.error_soft   = IM_COL32(255, 104, 122, 30);
			t.info         = IM_COL32(74, 152, 236, 255);
			t.info_soft    = IM_COL32(74, 152, 236, 30);

			t.syn_keyword      = IM_COL32(167, 150, 238, 255);
			t.syn_type         = IM_COL32(102, 198, 220, 255);
			t.syn_string       = IM_COL32(150, 206, 156, 255);
			t.syn_number       = IM_COL32(226, 174, 132, 255);
			t.syn_comment      = IM_COL32(98, 110, 142, 255);
			t.syn_function     = IM_COL32(96, 168, 252, 255);
			t.syn_identifier   = IM_COL32(206, 214, 230, 255);
			t.syn_register     = IM_COL32(230, 150, 158, 255);
			t.syn_address      = IM_COL32(99, 158, 236, 255);
			t.syn_preprocessor = IM_COL32(167, 150, 238, 255);
			t.syn_operator     = IM_COL32(150, 166, 196, 255);
			return t;
		}

		inline theme_t make_aida_light() {
			theme_t t;
			t.name = "AiDA Light";
			t.is_dark = false;

			t.bg_base       = IM_COL32(244, 246, 251, 255);
			t.bg_elevated   = IM_COL32(251, 252, 255, 255);
			t.bg_overlay    = IM_COL32(232, 238, 248, 255);
			t.panel_bg      = IM_COL32(251, 252, 255, 232);
			t.panel_header  = IM_COL32(231, 237, 248, 234);
			t.glass_tint    = IM_COL32(226, 235, 250, 64);
			t.title_bar     = IM_COL32(231, 237, 248, 232);
			t.acrylic_color = (uint32_t)((240) | (244 << 8) | (251 << 16) | (0xA8 << 24));

			t.border_subtle = IM_COL32(86, 112, 162, 60);
			t.border_strong = IM_COL32(86, 112, 162, 132);
			t.border_focus  = IM_COL32(42, 104, 216, 210);

			t.text_primary   = IM_COL32(22, 28, 44, 252);
			t.text_secondary = IM_COL32(78, 92, 122, 232);
			t.text_dim       = IM_COL32(140, 152, 178, 220);
			t.text_address   = IM_COL32(40, 100, 208, 230);
			t.text_lineno    = IM_COL32(150, 162, 188, 220);

			t.hover_wash       = IM_COL32(42, 104, 216, 20);
			t.selection        = IM_COL32(42, 104, 216, 46);
			t.selection_strong = IM_COL32(42, 104, 216, 104);
			t.disabled_alpha   = 0.45f;

			t.accent          = ImVec4(42.f/255.f, 104.f/255.f, 216.f/255.f, 1.f);
			t.accent_u32      = IM_COL32(42, 104, 216, 255);
			t.accent_hover    = IM_COL32(58, 124, 236, 255);
			t.accent_dim      = IM_COL32(42, 104, 216, 130);
			t.accent_glow     = IM_COL32(42, 104, 216, 46);
			t.accent_grad_top = IM_COL32(58, 124, 236, 255);
			t.accent_grad_bot = IM_COL32(28, 78, 178, 255);

			t.success      = IM_COL32(26, 131, 90, 255);
			t.success_soft = IM_COL32(26, 131, 90, 26);
			t.warning      = IM_COL32(168, 110, 18, 255);
			t.warning_soft = IM_COL32(168, 110, 18, 26);
			t.error        = IM_COL32(196, 50, 62, 255);
			t.error_soft   = IM_COL32(196, 50, 62, 26);
			t.info         = IM_COL32(42, 104, 216, 255);
			t.info_soft    = IM_COL32(42, 104, 216, 26);

			t.syn_keyword      = IM_COL32(124, 58, 178, 255);
			t.syn_type         = IM_COL32(20, 122, 138, 255);
			t.syn_string       = IM_COL32(38, 122, 40, 255);
			t.syn_number       = IM_COL32(170, 96, 36, 255);
			t.syn_comment      = IM_COL32(132, 142, 162, 255);
			t.syn_function     = IM_COL32(36, 96, 200, 255);
			t.syn_identifier   = IM_COL32(28, 34, 50, 255);
			t.syn_register     = IM_COL32(178, 58, 70, 255);
			t.syn_address      = IM_COL32(36, 96, 200, 255);
			t.syn_preprocessor = IM_COL32(124, 58, 178, 255);
			t.syn_operator     = IM_COL32(86, 100, 126, 255);
			return t;
		}

		inline theme_t make_claude_dark() {
			theme_t t;
			t.name = "Claude Dark";
			t.is_dark = true;

			t.bg_base       = IM_COL32(0x26, 0x26, 0x24, 255);
			t.bg_elevated   = IM_COL32(0x2E, 0x2E, 0x2C, 255);
			t.bg_overlay    = IM_COL32(0x36, 0x36, 0x33, 255);
			t.panel_bg      = IM_COL32(0x26, 0x26, 0x24, 232);
			t.panel_header  = IM_COL32(0x1E, 0x1E, 0x1C, 234);
			t.glass_tint    = IM_COL32(0x32, 0x2A, 0x24, 60);
			t.title_bar     = IM_COL32(0x1A, 0x1A, 0x18, 234);
			t.acrylic_color = (uint32_t)((0x1A) | (0x1A << 8) | (0x18 << 16) | (0x84 << 24));

			t.border_subtle = IM_COL32(0xE8, 0xE4, 0xDC, 16);
			t.border_strong = IM_COL32(0xE8, 0xE4, 0xDC, 40);
			t.border_focus  = IM_COL32(0xF4, 0x84, 0x5F, 210);

			t.text_primary   = IM_COL32(0xE8, 0xE4, 0xDC, 244);
			t.text_secondary = IM_COL32(0xB8, 0xB1, 0xA4, 220);
			t.text_dim       = IM_COL32(0x88, 0x88, 0x88, 200);
			t.text_address   = IM_COL32(0xF4, 0x84, 0x5F, 220);
			t.text_lineno    = IM_COL32(0x6F, 0x6F, 0x6A, 200);

			t.hover_wash       = IM_COL32(0xF4, 0x84, 0x5F, 22);
			t.selection        = IM_COL32(0xF4, 0x84, 0x5F, 64);
			t.selection_strong = IM_COL32(0xF4, 0x84, 0x5F, 124);
			t.disabled_alpha   = 0.42f;

			t.accent          = ImVec4(0xF4/255.f, 0x84/255.f, 0x5F/255.f, 1.f);
			t.accent_u32      = IM_COL32(0xF4, 0x84, 0x5F, 255);
			t.accent_hover    = IM_COL32(0xF7, 0x9C, 0x7C, 255);
			t.accent_dim      = IM_COL32(0xF4, 0x84, 0x5F, 130);
			t.accent_glow     = IM_COL32(0xF4, 0x84, 0x5F, 52);
			t.accent_grad_top = IM_COL32(0xF7, 0x9C, 0x7C, 255);
			t.accent_grad_bot = IM_COL32(0xE0, 0x70, 0x4A, 255);

			t.success      = IM_COL32(0x7E, 0xC6, 0x99, 255);
			t.success_soft = IM_COL32(0x7E, 0xC6, 0x99, 30);
			t.warning      = IM_COL32(0xE8, 0xC4, 0x7C, 255);
			t.warning_soft = IM_COL32(0xE8, 0xC4, 0x7C, 30);
			t.error        = IM_COL32(0xE8, 0x6F, 0x6C, 255);
			t.error_soft   = IM_COL32(0xE8, 0x6F, 0x6C, 30);
			t.info         = IM_COL32(0x1F, 0x6F, 0xE4, 255);
			t.info_soft    = IM_COL32(0x1F, 0x6F, 0xE4, 30);

			t.syn_keyword      = IM_COL32(0xD7, 0x3A, 0x83, 255);
			t.syn_type         = IM_COL32(0xE8, 0xC4, 0x7C, 255);
			t.syn_string       = IM_COL32(0x7E, 0xC6, 0x99, 255);
			t.syn_number       = IM_COL32(0x7C, 0xE8, 0xD4, 255);
			t.syn_comment      = IM_COL32(0x88, 0x88, 0x88, 255);
			t.syn_function     = IM_COL32(0x1F, 0x6F, 0xE4, 255);
			t.syn_identifier   = IM_COL32(0xE8, 0xE4, 0xDC, 255);
			t.syn_register     = IM_COL32(0xF4, 0x84, 0x5F, 255);
			t.syn_address      = IM_COL32(0xF4, 0x84, 0x5F, 255);
			t.syn_preprocessor = IM_COL32(0xD7, 0x3A, 0x83, 255);
			t.syn_operator     = IM_COL32(0xB8, 0xB1, 0xA4, 255);
			return t;
		}

		inline theme_t make_claude_light() {
			theme_t t;
			t.name = "Claude Light";
			t.is_dark = false;

			t.bg_base       = IM_COL32(0xF4, 0xF3, 0xEE, 255);
			t.bg_elevated   = IM_COL32(0xFA, 0xF9, 0xF5, 255);
			t.bg_overlay    = IM_COL32(0xE9, 0xEC, 0xEC, 255);
			t.panel_bg      = IM_COL32(0xFA, 0xF9, 0xF5, 232);
			t.panel_header  = IM_COL32(0xE9, 0xEC, 0xEC, 234);
			t.glass_tint    = IM_COL32(0xF4, 0xF3, 0xEE, 60);
			t.title_bar     = IM_COL32(0xE9, 0xEC, 0xEC, 232);
			t.acrylic_color = (uint32_t)((0xEE) | (0xF3 << 8) | (0xF4 << 16) | (0xA8 << 24));

			t.border_subtle = IM_COL32(0xB1, 0xAD, 0xA1, 70);
			t.border_strong = IM_COL32(0xB1, 0xAD, 0xA1, 140);
			t.border_focus  = IM_COL32(0xC1, 0x5F, 0x3C, 210);

			t.text_primary   = IM_COL32(0x1F, 0x1E, 0x1D, 252);
			t.text_secondary = IM_COL32(0x6F, 0x6F, 0x78, 232);
			t.text_dim       = IM_COL32(0xB1, 0xAD, 0xA1, 220);
			t.text_address   = IM_COL32(0xC1, 0x5F, 0x3C, 230);
			t.text_lineno    = IM_COL32(0xA0, 0x9A, 0x90, 220);

			t.hover_wash       = IM_COL32(0xC1, 0x5F, 0x3C, 20);
			t.selection        = IM_COL32(0xC1, 0x5F, 0x3C, 48);
			t.selection_strong = IM_COL32(0xC1, 0x5F, 0x3C, 110);
			t.disabled_alpha   = 0.45f;

			t.accent          = ImVec4(0xC1/255.f, 0x5F/255.f, 0x3C/255.f, 1.f);
			t.accent_u32      = IM_COL32(0xC1, 0x5F, 0x3C, 255);
			t.accent_hover    = IM_COL32(0xD0, 0x72, 0x52, 255);
			t.accent_dim      = IM_COL32(0xC1, 0x5F, 0x3C, 130);
			t.accent_glow     = IM_COL32(0xC1, 0x5F, 0x3C, 48);
			t.accent_grad_top = IM_COL32(0xD0, 0x72, 0x52, 255);
			t.accent_grad_bot = IM_COL32(0xB0, 0x50, 0x30, 255);

			t.success      = IM_COL32(0x26, 0x83, 0x1A, 255);
			t.success_soft = IM_COL32(0x26, 0x83, 0x1A, 26);
			t.warning      = IM_COL32(0xA5, 0x6F, 0x10, 255);
			t.warning_soft = IM_COL32(0xA5, 0x6F, 0x10, 26);
			t.error        = IM_COL32(0xC0, 0x39, 0x2A, 255);
			t.error_soft   = IM_COL32(0xC0, 0x39, 0x2A, 26);
			t.info         = IM_COL32(0x1C, 0x6B, 0xBB, 255);
			t.info_soft    = IM_COL32(0x1C, 0x6B, 0xBB, 26);

			t.syn_keyword      = IM_COL32(0xD7, 0x3A, 0x83, 255);
			t.syn_type         = IM_COL32(0x8A, 0x46, 0xCE, 255);
			t.syn_string       = IM_COL32(0x26, 0x83, 0x1A, 255);
			t.syn_number       = IM_COL32(0x2D, 0x8F, 0x8F, 255);
			t.syn_comment      = IM_COL32(0x88, 0x88, 0x88, 255);
			t.syn_function     = IM_COL32(0x1C, 0x6B, 0xBB, 255);
			t.syn_identifier   = IM_COL32(0x1F, 0x1E, 0x1D, 255);
			t.syn_register     = IM_COL32(0xC1, 0x5F, 0x3C, 255);
			t.syn_address      = IM_COL32(0xC1, 0x5F, 0x3C, 255);
			t.syn_preprocessor = IM_COL32(0xD7, 0x3A, 0x83, 255);
			t.syn_operator     = IM_COL32(0x6F, 0x6F, 0x78, 255);
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

		inline theme_t  s_resolved = make_aida_dark();
		inline theme_t  s_target   = make_aida_dark();
		inline theme_t  s_source   = make_aida_dark();
		inline transition_t s_swap_anim;

		inline std::atomic<bool> s_dark_pref_dark{ true };
		inline std::atomic<bool> s_user_override { false };
		inline std::atomic<bool> s_swap_pending  { false };
		inline std::atomic<uint32_t> s_theme_generation{ 1 };
		inline float s_style_dpi_scale = 1.f;

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

	inline void set_dpi_scale(float dpi_scale) {
		detail::s_style_dpi_scale = ui_scale_for_dpi(dpi_scale);
	}

	inline float dpi_scale() {
		return detail::s_style_dpi_scale;
	}

	inline uint32_t theme_generation() {
		return detail::s_theme_generation.load(std::memory_order_acquire);
	}

	inline void apply_imgui_style(const theme_t& t) {
		ImGuiStyle& s = ImGui::GetStyle();
		s = ImGuiStyle();
		const float ds = detail::s_style_dpi_scale;

		s.WindowPadding     = ImVec2(scale_px(12.f, ds), scale_px(10.f, ds));
		s.FramePadding      = ImVec2(scale_px(9.f, ds), scale_px(5.f, ds));
		s.CellPadding       = ImVec2(scale_px(8.f, ds), scale_px(4.f, ds));
		s.ItemSpacing       = ImVec2(scale_px(8.f, ds), scale_px(6.f, ds));
		s.ItemInnerSpacing  = ImVec2(scale_px(6.f, ds), scale_px(4.f, ds));
		s.IndentSpacing     = scale_px(18.f, ds);
		s.ScrollbarSize     = scale_px(10.f, ds);
		s.GrabMinSize       = scale_px(12.f, ds);
		s.WindowRounding    = scale_px(8.f, ds);
		s.ChildRounding     = scale_px(6.f, ds);
		s.FrameRounding     = scale_px(6.f, ds);
		s.PopupRounding     = scale_px(8.f, ds);
		s.ScrollbarRounding = scale_px(8.f, ds);
		s.GrabRounding      = scale_px(5.f, ds);
		s.TabRounding       = scale_px(6.f, ds);
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
		c[ImGuiCol_NavWindowingDimBg]    = ImVec4(0, 0, 0, 0.0f);
		c[ImGuiCol_ModalWindowDimBg]     = ImVec4(0, 0, 0, 0.0f);
	}

	inline void apply(const theme_t& t) {
		detail::s_target = t;
		detail::s_source = detail::s_resolved;
		detail::s_swap_anim.start(0.240f, aida::motion::ease::in_out_cubic);
		detail::s_swap_pending = true;
		detail::s_theme_generation.fetch_add(1u, std::memory_order_release);
	}

	inline void apply_immediate(const theme_t& t) {
		detail::s_target = t;
		detail::s_source = t;
		detail::s_resolved = t;
		detail::s_swap_anim.reset();
		detail::s_swap_pending = false;
		apply_imgui_style(t);
		detail::s_theme_generation.fetch_add(1u, std::memory_order_release);
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

	inline void use_dark()  { apply(detail::make_aida_dark()); }
	inline void use_light() { apply(detail::make_aida_light()); }

	inline theme_t make_theme_for_index(int idx) {
		switch (idx) {
			case 0:  return detail::make_aida_dark();
			case 1:  return detail::make_aida_light();
			case 2:  return detail::make_claude_dark();
			case 3:  return detail::make_claude_light();
			default: return detail::make_aida_dark();
		}
	}

	inline void apply_for_index(int idx, bool animated = true) {
		theme_t t = make_theme_for_index(idx);
		if (animated) apply(t);
		else apply_immediate(t);
	}

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
