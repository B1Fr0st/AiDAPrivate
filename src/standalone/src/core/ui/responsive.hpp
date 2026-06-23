#pragma once

#include <algorithm>
#include <cstring>
#include <string>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "metrics.hpp"
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

	struct action_row_fit_t {
		bool stack = false;
		bool compact = false;
		float gap = aida::ui::metrics::spacing::lg;
		float item_width = 0.f;
	};

	struct tab_label_fit_t {
		bool icon_only = false;
		bool compact = false;
		float tab_width = 0.f;
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

	inline ImVec2 measure_text(ImFont* font, float fs, const char* text,
		const char* text_end = nullptr, float wrap_width = FLT_MAX) {
		if (!font || !text || !*text) return ImVec2(0.f, 0.f);
		return font->CalcTextSizeA(fs, FLT_MAX, wrap_width, text, text_end);
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

	inline std::string ellipsize_end(const std::string& s, ImFont* font, float font_size, float max_w) {
		return truncate_to_width(s, font, font_size, max_w);
	}

	inline std::string ellipsize_middle(const std::string& s, ImFont* font, float font_size, float max_w) {
		if (s.empty() || max_w <= 0.f || !font) return std::string();
		ImVec2 full = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, s.c_str());
		if (full.x <= max_w) return s;
		const char* ell = "...";
		ImVec2 ell_sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, ell);
		if (max_w <= ell_sz.x) return truncate_to_width(s, font, font_size, max_w);
		size_t lo = 0;
		size_t hi = s.size();
		while (lo < hi) {
			size_t keep = (lo + hi + 1) / 2;
			size_t head = (keep + 1) / 2;
			size_t tail = keep / 2;
			if (head + tail > s.size()) {
				hi = keep - 1;
				continue;
			}
			std::string candidate;
			candidate.reserve(head + 3 + tail);
			candidate.append(s, 0, head);
			candidate.append(ell);
			if (tail > 0) candidate.append(s, s.size() - tail, tail);
			ImVec2 sz = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, candidate.c_str());
			if (sz.x <= max_w) lo = keep;
			else hi = keep - 1;
		}
		size_t head = (lo + 1) / 2;
		size_t tail = lo / 2;
		std::string out;
		out.reserve(head + 3 + tail);
		out.append(s, 0, head);
		out.append(ell);
		if (tail > 0) out.append(s, s.size() - tail, tail);
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

	inline ImVec2 clamp_overlay_panel(ImVec2 region_size, ImVec2 desired,
		ImVec2 minimum = ImVec2(280.f, 220.f),
		float margin = aida::ui::metrics::panel::overlay_margin) {
		float max_w = (std::max)(minimum.x, region_size.x - margin);
		float max_h = (std::max)(minimum.y, region_size.y - margin);
		float w = (std::min)(desired.x, max_w);
		float h = (std::min)(desired.y, max_h);
		if (w < minimum.x) w = (std::min)(minimum.x, region_size.x);
		if (h < minimum.y) h = (std::min)(minimum.y, region_size.y);
		return ImVec2((std::max)(1.f, w), (std::max)(1.f, h));
	}

	inline action_row_fit_t fit_action_row(float available_w, int action_count,
		float preferred_item_w, float compact_item_w,
		float preferred_gap = aida::ui::metrics::spacing::lg,
		float compact_gap = aida::ui::metrics::spacing::sm) {
		action_row_fit_t fit;
		if (action_count <= 0 || available_w <= 0.f) {
			fit.stack = true;
			fit.compact = true;
			fit.gap = compact_gap;
			fit.item_width = (std::max)(1.f, available_w);
			return fit;
		}
		float count = static_cast<float>(action_count);
		float preferred_total = preferred_item_w * count + preferred_gap * (count - 1.f);
		if (preferred_total <= available_w) {
			fit.item_width = preferred_item_w;
			fit.gap = preferred_gap;
			return fit;
		}
		float compact_total = compact_item_w * count + compact_gap * (count - 1.f);
		if (compact_total <= available_w) {
			fit.compact = true;
			fit.item_width = compact_item_w;
			fit.gap = compact_gap;
			return fit;
		}
		fit.stack = true;
		fit.compact = true;
		fit.gap = compact_gap;
		fit.item_width = (std::max)(compact_item_w, available_w);
		return fit;
	}

	inline tab_label_fit_t fit_tab_labels(float available_w, int tab_count_v,
		float full_tab_w, float compact_tab_w, float icon_only_tab_w) {
		tab_label_fit_t fit;
		if (tab_count_v <= 0) return fit;
		float count = static_cast<float>(tab_count_v);
		float need_full = count * full_tab_w;
		if (available_w >= need_full) {
			fit.tab_width = full_tab_w;
			return fit;
		}
		float need_compact = count * compact_tab_w;
		if (available_w >= need_compact) {
			fit.compact = true;
			fit.tab_width = compact_tab_w;
			return fit;
		}
		fit.compact = true;
		fit.icon_only = true;
		fit.tab_width = icon_only_tab_w;
		return fit;
	}

	inline std::string button_label_for_width(const char* full_label, const char* compact_label,
		ImFont* font, float font_size, float max_w) {
		if (!full_label) full_label = "";
		if (!compact_label) compact_label = full_label;
		if (fits_width(font, font_size, full_label, max_w)) return std::string(full_label);
		if (fits_width(font, font_size, compact_label, max_w)) return std::string(compact_label);
		return ellipsize_end(std::string(full_label), font, font_size, max_w);
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
