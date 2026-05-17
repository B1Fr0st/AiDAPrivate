#pragma once

#include <algorithm>
#include <cstring>
#include <string>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "theme.hpp"

namespace aida::ui::responsive {

	struct sidebar_metrics_t {
		float width = 0.f;
		bool  icon_only = false;
		bool  hidden = false;
	};

	struct sidebar_policy_t {
		float full_width = 220.f;
		float icon_only_width = 64.f;
		float icon_only_threshold = 160.f;
		float hide_threshold = 40.f;
		float content_min_w = 240.f;
	};

	struct panel_clamp_t {
		float min_total_w = 0.f;
		float min_total_h = 0.f;
	};

	inline float compute_total_min_width(const sidebar_policy_t& pol) {
		return pol.icon_only_width + pol.content_min_w;
	}

	inline sidebar_metrics_t resolve_sidebar(float panel_w, const sidebar_policy_t& pol) {
		sidebar_metrics_t out;
		if (panel_w <= pol.hide_threshold) {
			out.hidden = true;
			out.icon_only = true;
			out.width = 0.f;
			return out;
		}
		float min_total = pol.icon_only_width + 80.f;
		if (panel_w < min_total) {
			out.hidden = true;
			out.icon_only = true;
			out.width = 0.f;
			return out;
		}
		float reserved_for_content = pol.content_min_w;
		float remaining = panel_w - reserved_for_content;
		if (remaining < pol.icon_only_width) {
			out.icon_only = true;
			out.width = pol.icon_only_width;
			return out;
		}
		if (remaining < pol.icon_only_threshold) {
			out.icon_only = true;
			out.width = pol.icon_only_width;
			return out;
		}
		out.width = std::min(pol.full_width, remaining);
		if (out.width < pol.icon_only_width) out.width = pol.icon_only_width;
		out.icon_only = (out.width < pol.icon_only_threshold);
		return out;
	}

	inline float truncated_text_width(ImFont* font, float fs, const char* text) {
		if (!font || !text || !*text) return 0.f;
		return font->CalcTextSizeA(fs, FLT_MAX, 0.f, text).x;
	}

	inline std::string truncate_to_width(const std::string& s, ImFont* font, float font_size, float max_w) {
		if (s.empty() || max_w <= 0.f || !font) return std::string();
		ImVec2 full = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, s.c_str());
		if (full.x <= max_w) return s;
		const char* ell = "...";
		ImVec2 ell_sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ell);
		float budget = max_w - ell_sz.x;
		if (budget <= 0.f) {
			if (max_w < ell_sz.x) {
				const char* dot = ".";
				ImVec2 dot_sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, dot);
				if (max_w < dot_sz.x) return std::string();
				return std::string(dot);
			}
			return std::string(ell);
		}
		size_t lo = 0;
		size_t hi = s.size();
		while (lo < hi) {
			size_t mid = (lo + hi + 1) / 2;
			ImVec2 sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, s.c_str(), s.c_str() + mid);
			if (sz.x <= budget) lo = mid;
			else hi = mid - 1;
		}
		std::string out;
		out.reserve(lo + 3);
		out.append(s, 0, lo);
		out.append(ell);
		return out;
	}

	inline bool fits_width(ImFont* font, float fs, const char* text, float max_w) {
		if (!font || !text || !*text) return true;
		return font->CalcTextSizeA(fs, FLT_MAX, 0.f, text).x <= max_w;
	}

	inline void clamp_window_min_size(const panel_clamp_t& c) {
		float w = c.min_total_w > 0.f ? c.min_total_w : 1.f;
		float h = c.min_total_h > 0.f ? c.min_total_h : 1.f;
		ImGui::SetNextWindowSizeConstraints(ImVec2(w, h), ImVec2(FLT_MAX, FLT_MAX));
	}

	inline void draw_clamp_overlay(ImVec2 pos, ImVec2 size, const char* msg) {
		if (size.x <= 0.f || size.y <= 0.f) return;
		ImDrawList* dl = ImGui::GetWindowDrawList();
		const auto& th = aida::ui::resolved();
		dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y),
			aida::ui::with_alpha(th.bg_overlay, 0.85f));
		if (!msg) msg = "Panel too narrow";
		ImFont* font = ImGui::GetFont();
		float fs = ImGui::GetFontSize();
		float tw = font->CalcTextSizeA(fs, FLT_MAX, 0.f, msg).x;
		ImVec2 tp(pos.x + (size.x - tw) * 0.5f, pos.y + (size.y - fs) * 0.5f);
		dl->AddText(font, fs, tp, th.text_primary, msg);
	}

	inline bool tab_strip_icon_only(float available_w, int tab_count_v,
		float full_tab_w, float icon_only_tab_w) {
		if (tab_count_v <= 0) return false;
		float need_full = static_cast<float>(tab_count_v) * full_tab_w;
		if (available_w >= need_full) return false;
		float need_icon = static_cast<float>(tab_count_v) * icon_only_tab_w;
		(void)need_icon;
		return true;
	}

}
