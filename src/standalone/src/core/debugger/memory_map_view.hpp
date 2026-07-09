#pragma once

#include <Windows.h>
#include <commdlg.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cmath>

#include "imgui/imgui.h"
#include "standalone_driver.hpp"
#include "debugger_engine.hpp"
#include "../infra/executor.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "empty_state.hpp"
#include "fonts.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../anti-tamper/webhook.hpp"

extern DisasmState g_disasm;

namespace memory_map_view {

struct stat_counter_t {
	float displayed = 0.f;
	float velocity  = 0.f;
	float target    = 0.f;
};

struct hero_segment_t {
	uint64_t base = 0;
	uint64_t size = 0;
	uint32_t protect = 0;
	uint32_t state = 0;
	uint32_t type = 0;
	int      region_index = -1;
	float    start_x = 0.f;
	float    width   = 0.f;
};

struct ui_state_t {
	int                                        selected = -1;
	float                                      scroll_y = 0.f;
	float                                      target_scroll_y = 0.f;
	char                                       filter_buf[64] = {};
	float                                      last_refresh = 0.f;
	float                                      refresh_interval = 2.f;
	std::vector<debugger_engine::memory_region_t> regions;
	std::mutex                                 regions_mutex;
	std::atomic<bool>                          refreshing{false};
	bool                                       scrollbar_dragging = false;
	float                                      scrollbar_drag_offset = 0.f;
	uint64_t                                   context_addr = 0;
	bool                                       show_context = false;
	bool                                       change_protect_open = false;
	uint64_t                                   change_protect_addr = 0;
	uint64_t                                   change_protect_size = 0;
	int                                        change_protect_choice = 0;
	uint32_t                                   change_protect_old = 0;
	stat_counter_t                             stat_regions;
	stat_counter_t                             stat_committed;
	stat_counter_t                             stat_rwx;
	stat_counter_t                             stat_attached;
	int                                        hovered_segment = -1;
	int                                        selected_segment = -1;
	float                                      hero_scroll_target = 0.f;
	bool                                       request_pending_scroll = false;
	int                                        pending_scroll_index = -1;
};

inline ui_state_t g_ui;

inline void refresh()
{
	if (!driver_bridge::is_loaded() || driver_bridge::attached_pid() == 0) {
		diag::log_tagged_fmt("memmap",
			"memmap_refresh_skipped driver_loaded=%d attached_pid=%u",
			driver_bridge::is_loaded() ? 1 : 0,
			static_cast<unsigned>(driver_bridge::attached_pid()));
		return;
	}

	bool expected = false;
	if (!g_ui.refreshing.compare_exchange_strong(expected, true)) {
		diag::log_tagged_fmt("memmap",
			"memmap_refresh_already_in_flight");
		return;
	}

	diag::log_tagged_fmt("memmap",
		"memmap_refresh_request attached_pid=%u",
		static_cast<unsigned>(driver_bridge::attached_pid()));
	aida::infra::executor::submission_t sub;
	sub.owner_subsystem = "debugger";
	sub.label = "debugger.memory_map_refresh";
	sub.thread_class = "debugger_refresh";
	sub.domain = aida::infra::executor::domain_t::feature_worker;
	sub.priority = 3;
	sub.target_pid = driver_bridge::attached_pid();
	sub.body = []() {
		auto map = debugger_engine::get_memory_map();
		size_t n = map.size();
		{
			std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
			g_ui.regions = std::move(map);
		}
		diag::log_tagged_fmt("memmap",
			"memmap_refresh_done regions=%zu", n);
		g_ui.refreshing.store(false);
	};
	if (!aida::infra::executor::submit(std::move(sub)).submitted) {
		diag::log_tagged("memmap", "memmap_refresh_post_failed");
		g_ui.refreshing.store(false);
	}
}

namespace detail {

inline std::string format_size(uint64_t bytes)
{
	char buf[32];
	if (bytes >= 1073741824ULL)
		std::snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / 1073741824.0);
	else if (bytes >= 1048576)
		std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / 1048576.0);
	else if (bytes >= 1024)
		std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
	else
		std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
	return buf;
}

inline std::string format_state(uint32_t state)
{
	if (state == 0x1000) return "COMMIT";
	if (state == 0x2000) return "RESERVE";
	if (state == 0x10000) return "FREE";
	char buf[16];
	std::snprintf(buf, sizeof(buf), "0x%X", state);
	return buf;
}

inline std::string format_type(uint32_t type)
{
	if (type == 0x1000000) return "IMAGE";
	if (type == 0x20000) return "PRIVATE";
	if (type == 0x40000) return "MAPPED";
	if (type == 0) return "";
	char buf[16];
	std::snprintf(buf, sizeof(buf), "0x%X", type);
	return buf;
}

inline ImU32 protect_token(uint32_t protect, const aida::ui::theme_t& t)
{
	bool exec  = (protect & 0xF0) != 0;
	bool write = (protect == 0x04) || (protect == 0x08)
	          || (protect == 0x40) || (protect == 0x80);
	if (exec)  return t.error;
	if (write) return t.warning;
	return t.success;
}

inline ImU32 segment_color(uint32_t protect, uint32_t state, const aida::ui::theme_t& t,
                           float alpha)
{
	bool exec  = (protect & 0xF0) != 0;
	bool write = (protect & 0x04) || (protect & 0x08)
	          || (protect & 0x40) || (protect & 0x80);
	bool read  = (protect & 0x02) || (protect & 0x20)
	          || (protect & 0x04) || (protect & 0x40);
	float r_w = exec ? 1.0f : 0.f;
	float g_w = (write && !exec) ? 1.0f : (write ? 0.55f : 0.f);
	float b_w = (read && !exec && !write) ? 1.0f : (read ? 0.45f : 0.f);
	float sum = r_w + g_w + b_w;
	if (sum < 0.0001f) {
		r_w = 0.6f; g_w = 0.6f; b_w = 0.6f;
	} else {
		r_w /= sum; g_w /= sum; b_w /= sum;
	}
	float er = static_cast<float>((t.error >> IM_COL32_R_SHIFT) & 0xFF);
	float eg = static_cast<float>((t.error >> IM_COL32_G_SHIFT) & 0xFF);
	float eb = static_cast<float>((t.error >> IM_COL32_B_SHIFT) & 0xFF);
	float wr = static_cast<float>((t.warning >> IM_COL32_R_SHIFT) & 0xFF);
	float wg = static_cast<float>((t.warning >> IM_COL32_G_SHIFT) & 0xFF);
	float wb = static_cast<float>((t.warning >> IM_COL32_B_SHIFT) & 0xFF);
	float ir = static_cast<float>((t.info >> IM_COL32_R_SHIFT) & 0xFF);
	float ig = static_cast<float>((t.info >> IM_COL32_G_SHIFT) & 0xFF);
	float ib = static_cast<float>((t.info >> IM_COL32_B_SHIFT) & 0xFF);
	int rr = static_cast<int>(er * r_w + wr * g_w + ir * b_w);
	int gg = static_cast<int>(eg * r_w + wg * g_w + ig * b_w);
	int bb = static_cast<int>(eb * r_w + wb * g_w + ib * b_w);
	if (rr > 255) rr = 255; if (rr < 0) rr = 0;
	if (gg > 255) gg = 255; if (gg < 0) gg = 0;
	if (bb > 255) bb = 255; if (bb < 0) bb = 0;
	float state_alpha = 1.0f;
	if (state == 0x2000) state_alpha = 0.55f;
	else if (state == 0x10000) state_alpha = 0.18f;
	int ai = static_cast<int>(255.f * alpha * state_alpha);
	if (ai < 0) ai = 0; if (ai > 255) ai = 255;
	return IM_COL32(rr, gg, bb, ai);
}

inline ImU32 state_color(uint32_t state, const aida::ui::theme_t& t)
{
	if (state == 0x1000)  return t.text_primary;
	if (state == 0x2000)  return t.text_secondary;
	return t.text_dim;
}

inline ImU32 type_color(uint32_t type, const aida::ui::theme_t& t)
{
	if (type == 0x1000000) return t.info;
	if (type == 0x40000)   return t.success;
	return t.text_secondary;
}

inline bool match_filter(const debugger_engine::memory_region_t& r, const char* filter)
{
	if (filter[0] == 0) return true;
	std::string lower_filter;
	for (const char* p = filter; *p; ++p)
		lower_filter.push_back(static_cast<char>((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p));
	std::string lower_mod;
	for (auto& c : r.module_name)
		lower_mod.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	std::string lower_info;
	for (auto& c : r.info)
		lower_info.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c + 32) : c));
	if (lower_mod.find(lower_filter) != std::string::npos) return true;
	if (lower_info.find(lower_filter) != std::string::npos) return true;
	return false;
}

inline void tween_counter(stat_counter_t& c, float target, float dt)
{
	c.target = target;
	c.displayed = aida::motion::critically_damped_step(c.displayed, c.target,
		c.velocity, 0.20f, dt);
}

inline void format_counter(char* buf, size_t bufsz, float value, bool is_size, bool is_pid)
{
	if (is_pid) {
		int v = static_cast<int>(value + 0.5f);
		if (v <= 0) std::snprintf(buf, bufsz, "—");
		else        std::snprintf(buf, bufsz, "%d", v);
		return;
	}
	if (!is_size) {
		std::snprintf(buf, bufsz, "%d", static_cast<int>(value + 0.5f));
		return;
	}
	if (value >= 1073741824.f)
		std::snprintf(buf, bufsz, "%.2f GB", value / 1073741824.f);
	else if (value >= 1048576.f)
		std::snprintf(buf, bufsz, "%.1f MB", value / 1048576.f);
	else if (value >= 1024.f)
		std::snprintf(buf, bufsz, "%.1f KB", value / 1024.f);
	else
		std::snprintf(buf, bufsz, "%d B", static_cast<int>(value + 0.5f));
}

}

inline bool find_region_by_base(uint64_t base, debugger_engine::memory_region_t& out)
{
	std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
	for (const auto& r : g_ui.regions) {
		if (r.base == base) {
			out = r;
			return true;
		}
	}
	return false;
}

inline void render_hero_map(ImDrawList* dl, float x, float y, float w, float h,
                             float alpha,
                             const std::vector<debugger_engine::memory_region_t>& regions,
                             const std::vector<int>& filtered_indices)
{
	const auto& t = aida::ui::resolved();

	ImVec2 a(x, y);
	ImVec2 b(x + w, y + h);
	for (int i = 0; i < 4; ++i) {
		float s = static_cast<float>(i + 1) * 1.6f;
		float fa = 0.18f * alpha * (1.f - static_cast<float>(i) / 4.f);
		dl->AddRectFilled(
			ImVec2(a.x - s, a.y - s + 3.f),
			ImVec2(b.x + s, b.y + s + 3.f),
			IM_COL32(0, 0, 0, static_cast<int>(fa * 60.f)),
			10.f + s);
	}
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.panel_bg, alpha), 10.f);
	dl->AddRectFilled(a, b, aida::ui::with_alpha(t.glass_tint, alpha * 0.65f), 10.f);
	dl->AddRect(a, b, aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);

	uint64_t total = 0;
	for (int idx : filtered_indices) {
		if (idx < 0 || idx >= static_cast<int>(regions.size())) continue;
		total += regions[idx].size;
	}
	if (total == 0) {
		ImFont* f = aida::ui::fonts::body();
		if (!f) f = ImGui::GetFont();
		const char* msg = "No regions to map. Refresh while attached.";
		const float fs_empty_msg = aida::ui::components::detail::ui_fs() * 1.00f;
		ImVec2 sz = f->CalcTextSizeA(fs_empty_msg, FLT_MAX, 0.f, msg);
		dl->AddText(f, fs_empty_msg,
			ImVec2(x + (w - sz.x) * 0.5f, y + (h - sz.y) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha), msg);
		return;
	}

	float pad = 12.f;
	float strip_x0 = x + pad;
	float strip_x1 = x + w - pad;
	float strip_y0 = y + pad;
	float strip_y1 = y + h - 32.f;
	float strip_w = strip_x1 - strip_x0;

	dl->AddRectFilled(ImVec2(strip_x0, strip_y0),
	                  ImVec2(strip_x1, strip_y1),
	                  aida::ui::with_alpha(t.panel_header, alpha * 0.6f), 6.f);
	dl->AddRect(ImVec2(strip_x0, strip_y0),
	            ImVec2(strip_x1, strip_y1),
	            aida::ui::with_alpha(t.border_subtle, alpha), 6.f, 0, 1.f);

	std::vector<hero_segment_t> segs;
	segs.reserve(filtered_indices.size());
	double cumulative = 0.0;
	for (int idx : filtered_indices) {
		if (idx < 0 || idx >= static_cast<int>(regions.size())) continue;
		const auto& r = regions[idx];
		double frac = static_cast<double>(r.size) / static_cast<double>(total);
		hero_segment_t s;
		s.base = r.base;
		s.size = r.size;
		s.protect = r.protect;
		s.state = r.state;
		s.type = r.type;
		s.region_index = idx;
		s.start_x = strip_x0 + static_cast<float>(cumulative) * strip_w;
		s.width = static_cast<float>(frac) * strip_w;
		segs.push_back(s);
		cumulative += frac;
	}

	int hover_idx = -1;
	ImVec2 mp = ImGui::GetMousePos();
	bool inside = ImGui::IsMouseHoveringRect(ImVec2(strip_x0, strip_y0),
	                                         ImVec2(strip_x1, strip_y1), false);

	dl->PushClipRect(ImVec2(strip_x0, strip_y0), ImVec2(strip_x1, strip_y1), true);

	for (size_t i = 0; i < segs.size(); ++i) {
		auto& s = segs[i];
		ImU32 col = detail::segment_color(s.protect, s.state, t, alpha);
		float seg_w = s.width < 1.f ? 1.f : s.width;
		dl->AddRectFilled(ImVec2(s.start_x, strip_y0 + 1.f),
		                  ImVec2(s.start_x + seg_w, strip_y1 - 1.f),
		                  col);
		if (inside && mp.x >= s.start_x && mp.x <= s.start_x + s.width)
			hover_idx = static_cast<int>(i);
	}

	for (size_t i = 0; i < segs.size(); ++i) {
		auto& s = segs[i];
		float opacity = (s.width >= 4.f) ? 0.4f : 0.f;
		if (opacity > 0.f && i + 1 < segs.size())
			dl->AddLine(ImVec2(s.start_x + s.width, strip_y0 + 1.f),
			            ImVec2(s.start_x + s.width, strip_y1 - 1.f),
			            aida::ui::with_alpha(t.bg_base, alpha * opacity), 1.f);
	}

	if (hover_idx >= 0) {
		auto& s = segs[static_cast<size_t>(hover_idx)];
		float seg_w = s.width < 1.f ? 1.f : s.width;
		dl->AddRectFilled(ImVec2(s.start_x, strip_y0 + 1.f),
		                  ImVec2(s.start_x + seg_w, strip_y1 - 1.f),
		                  aida::ui::with_alpha(IM_COL32(255, 255, 255, 30), alpha));
		dl->AddRect(ImVec2(s.start_x, strip_y0),
		            ImVec2(s.start_x + seg_w, strip_y1),
		            aida::ui::with_alpha(t.accent_hover, alpha), 0.f, 0, 1.5f);
	}

	if (g_ui.selected_segment >= 0
	 && g_ui.selected_segment < static_cast<int>(segs.size())) {
		auto& s = segs[static_cast<size_t>(g_ui.selected_segment)];
		float seg_w = s.width < 1.f ? 1.f : s.width;
		for (int g = 0; g < 4; ++g) {
			float spread = static_cast<float>(g + 1) * 1.5f;
			float ga = (0.30f - static_cast<float>(g) * 0.07f) * alpha;
			dl->AddRect(ImVec2(s.start_x - spread, strip_y0 - spread),
			            ImVec2(s.start_x + seg_w + spread, strip_y1 + spread),
			            aida::ui::with_alpha(t.accent_glow, ga * 4.f),
			            2.f + spread, 0, 1.f);
		}
		dl->AddRect(ImVec2(s.start_x, strip_y0),
		            ImVec2(s.start_x + seg_w, strip_y1),
		            aida::ui::with_alpha(t.accent_u32, alpha), 0.f, 0, 2.f);
	}

	dl->PopClipRect();

	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();
	int ticks = 6;
	uint64_t low_va = segs.empty() ? 0 : segs.front().base;
	uint64_t high_va = segs.empty() ? 0
		: segs.back().base + segs.back().size;
	for (int ti = 0; ti < ticks; ++ti) {
		float frac = static_cast<float>(ti) / static_cast<float>(ticks - 1);
		float tx = strip_x0 + frac * strip_w;
		dl->AddLine(ImVec2(tx, strip_y1 + 4.f), ImVec2(tx, strip_y1 + 8.f),
		            aida::ui::with_alpha(t.text_dim, alpha), 1.f);
		uint64_t va = low_va + static_cast<uint64_t>(static_cast<double>(high_va - low_va) * frac);
		char buf[20];
		std::snprintf(buf, sizeof(buf), "%012" PRIX64, va);
		const float fs_tick = aida::ui::components::detail::ui_fs() * 0.85f;
		ImVec2 sz = code_font->CalcTextSizeA(fs_tick, FLT_MAX, 0.f, buf);
		float tlx = tx - sz.x * 0.5f;
		if (tlx < strip_x0) tlx = strip_x0;
		if (tlx + sz.x > strip_x1) tlx = strip_x1 - sz.x;
		dl->AddText(code_font, fs_tick, ImVec2(tlx, strip_y1 + 12.f),
		            aida::ui::with_alpha(t.text_dim, alpha), buf);
	}

	if (inside && hover_idx >= 0) {
		auto& s = segs[static_cast<size_t>(hover_idx)];
		const auto& r = regions[static_cast<size_t>(s.region_index)];
		std::string ps = debugger_engine::format_protect(r.protect);
		std::string ts = detail::format_state(r.state);
		std::string tps = detail::format_type(r.type);
		std::string sz = detail::format_size(r.size);
		char tip[512];
		if (!r.module_name.empty()) {
			std::snprintf(tip, sizeof(tip),
				"%s\n0x%016" PRIX64 " - 0x%016" PRIX64
				"\n%s | %s | %s\n%s",
				r.module_name.c_str(), r.base, r.base + r.size,
				ps.c_str(), ts.c_str(), tps.c_str(), sz.c_str());
		} else {
			std::snprintf(tip, sizeof(tip),
				"0x%016" PRIX64 " - 0x%016" PRIX64
				"\n%s | %s | %s\n%s",
				r.base, r.base + r.size,
				ps.c_str(), ts.c_str(), tps.c_str(), sz.c_str());
		}
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 8.f));
		ImGui::PushStyleColor(ImGuiCol_PopupBg,
			ImGui::ColorConvertU32ToFloat4(t.bg_overlay));
		ImGui::SetTooltip("%s", tip);
		ImGui::PopStyleColor();
		ImGui::PopStyleVar();

		if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_ui.selected_segment = hover_idx;
			g_ui.selected = s.region_index;
			g_ui.request_pending_scroll = true;
			g_ui.pending_scroll_index = s.region_index;
		}
	}

	g_ui.hovered_segment = hover_idx;
}

inline void render_stat_pod(ImDrawList* dl, float x, float y, float w, float h,
                             const char* label, const char* value,
                             ImU32 accent_col, float alpha)
{
	const auto& t = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
	                  aida::ui::with_alpha(t.panel_bg, alpha * 0.85f), 8.f);
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h),
	                  aida::ui::with_alpha(t.glass_tint, alpha * 0.55f), 8.f);
	dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
	            aida::ui::with_alpha(t.border_subtle, alpha), 8.f, 0, 1.f);
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + 3.f, y + h),
	                  aida::ui::with_alpha(accent_col, alpha * 0.85f), 1.f);

	ImFont* lab_font = aida::ui::fonts::caption();
	if (!lab_font) lab_font = ImGui::GetFont();
	ImFont* val_font = aida::ui::fonts::body_em();
	if (!val_font) val_font = ImGui::GetFont();

	const float fs_pod_base = aida::ui::components::detail::ui_fs();
	dl->AddText(lab_font, fs_pod_base * 0.88f, ImVec2(x + 12.f, y + 6.f),
	            aida::ui::with_alpha(t.text_dim, alpha), label);
	dl->AddText(val_font, fs_pod_base * 1.18f, ImVec2(x + 12.f, y + 28.f),
	            aida::ui::with_alpha(t.text_primary, alpha), value);
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float ar, float ag, float ab)
{
	{
		static bool s_mem_map_logged = false;
		if (!s_mem_map_logged) {
			s_mem_map_logged = true;
			anti_tamper::webhook::write_log("mem_map", "[mem_map] scaled");
		}
	}
	(void)ar; (void)ag; (void)ab;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	float dt = aida::ui::clock::dt();
	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height),
	                  aida::ui::with_alpha(t.bg_base, alpha));

	float toolbar_h = 48.f;
	float hero_h    = 240.f;
	float strip_h   = 70.f;
	float col_header_h = 30.f;

	float toolbar_y = pos_y + 8.f;
	float hero_y    = toolbar_y + toolbar_h + 8.f;
	float strip_y   = hero_y + hero_h + 10.f;
	float table_y   = strip_y + strip_h + 6.f;

	{
		float tbx = pos_x + 12.f;
		ImFont* h2 = aida::ui::fonts::h2();
		if (!h2) h2 = ImGui::GetFont();
		const float fs_mm_base   = aida::ui::components::detail::ui_fs();
		const float fs_mm_title  = fs_mm_base * 1.30f;
		const float fs_mm_sub    = fs_mm_base * 0.92f;
		dl->AddText(h2, fs_mm_title, ImVec2(tbx, toolbar_y + (toolbar_h - fs_mm_title) * 0.5f),
		            aida::ui::with_alpha(t.text_primary, alpha), "Memory Map");

		ImFont* cf = aida::ui::fonts::caption();
		if (!cf) cf = ImGui::GetFont();
		uint32_t pid = driver_bridge::attached_pid();
		char sub[64];
		if (pid)
			std::snprintf(sub, sizeof(sub), "Process %u", pid);
		else
			std::snprintf(sub, sizeof(sub), "Not attached");
		ImVec2 hs = h2->CalcTextSizeA(fs_mm_title, FLT_MAX, 0.f, "Memory Map");
		dl->AddText(cf, fs_mm_sub,
			ImVec2(tbx + hs.x + 12.f, toolbar_y + (toolbar_h - fs_mm_sub) * 0.5f + 2.f),
			aida::ui::with_alpha(t.text_dim, alpha), sub);

		float btn_w = 120.f;
		float min_filter_w = 100.f;
		float reserved_left = (hs.x + 12.f) + 200.f;
		float available_right = width - reserved_left - 24.f;
		bool collapse_refresh = (available_right < (btn_w + min_filter_w + 12.f));
		float effective_btn_w = collapse_refresh ? 64.f : btn_w;
		float fw = std::max(min_filter_w,
			std::min(260.f, available_right - effective_btn_w - 12.f));
		if (fw < min_filter_w) fw = min_filter_w;

		ImGui::SetCursorScreenPos(ImVec2(pos_x + width - effective_btn_w - 12.f, toolbar_y + 4.f));
		bool refreshing = g_ui.refreshing.load();
		const char* refresh_label = collapse_refresh ? "Refr" : "Refresh";
		bool clicked = aida::ui::components::button(
			refresh_label,
			aida::ui::components::button_kind_t::secondary,
			aida::ui::components::size_t_::sm,
			ImVec2(effective_btn_w, 28.f),
			false, nullptr, refreshing);
		if (collapse_refresh && ImGui::IsItemHovered()) {
			aida::ui::components::tooltip_blur("Refresh", 0.35f);
		}
		if (clicked && !refreshing)
			refresh();

		float fx = pos_x + width - effective_btn_w - fw - 24.f;
		ImGui::SetCursorScreenPos(ImVec2(fx, toolbar_y + 6.f));
		aida::ui::components::input_text("##memmap_filter", g_ui.filter_buf,
			sizeof(g_ui.filter_buf), "Filter modules or info...",
			false, ImVec2(fw, 28.f));

		static bool s_mm_logged_collapse = false;
		if (collapse_refresh && !s_mm_logged_collapse) {
			s_mm_logged_collapse = true;
			::diag::log_tagged_fmt("responsive",
				"memory_map_view toolbar collapsed avail=%.0f width=%.0f",
				available_right, width);
		} else if (!collapse_refresh && s_mm_logged_collapse) {
			s_mm_logged_collapse = false;
		}
	}

	std::vector<debugger_engine::memory_region_t> snapshot;
	{
		std::lock_guard<std::mutex> lk(g_ui.regions_mutex);
		snapshot = g_ui.regions;
	}

	std::vector<int> filtered_indices;
	filtered_indices.reserve(snapshot.size());
	for (size_t i = 0; i < snapshot.size(); ++i) {
		if (detail::match_filter(snapshot[i], g_ui.filter_buf))
			filtered_indices.push_back(static_cast<int>(i));
	}

	render_hero_map(dl, pos_x + 12.f, hero_y, width - 24.f, hero_h,
		alpha, snapshot, filtered_indices);

	{
		size_t n_regions = snapshot.size();
		uint64_t total_size = 0;
		int rwx_count = 0;
		for (auto& r : snapshot) {
			if (r.state == 0x1000)
				total_size += r.size;
			bool exec = (r.protect & 0xF0) != 0;
			bool write = (r.protect == 0x04) || (r.protect == 0x08)
			          || (r.protect == 0x40) || (r.protect == 0x80);
			if (exec && write) rwx_count++;
		}
		uint32_t pid = driver_bridge::attached_pid();

		detail::tween_counter(g_ui.stat_regions,    static_cast<float>(n_regions), dt);
		detail::tween_counter(g_ui.stat_committed,  static_cast<float>(total_size), dt);
		detail::tween_counter(g_ui.stat_rwx,        static_cast<float>(rwx_count), dt);
		detail::tween_counter(g_ui.stat_attached,   static_cast<float>(pid), dt);

		float pod_w = (width - 24.f - 6.f * 3.f) / 4.f;
		float px = pos_x + 12.f;

		char buf[32];
		detail::format_counter(buf, sizeof(buf), g_ui.stat_regions.displayed, false, false);
		render_stat_pod(dl, px, strip_y, pod_w, strip_h, "REGIONS", buf,
			t.accent_u32, alpha);
		px += pod_w + 6.f;

		detail::format_counter(buf, sizeof(buf), g_ui.stat_committed.displayed, true, false);
		render_stat_pod(dl, px, strip_y, pod_w, strip_h, "COMMITTED", buf,
			t.info, alpha);
		px += pod_w + 6.f;

		detail::format_counter(buf, sizeof(buf), g_ui.stat_rwx.displayed, false, false);
		render_stat_pod(dl, px, strip_y, pod_w, strip_h, "RWX",
			buf, rwx_count > 0 ? t.error : t.success, alpha);
		px += pod_w + 6.f;

		detail::format_counter(buf, sizeof(buf), g_ui.stat_attached.displayed, false, true);
		std::string val = buf;
		if (pid != 0) {
			char pidbuf[24];
			std::snprintf(pidbuf, sizeof(pidbuf), "PID %s", buf);
			val = pidbuf;
		}
		render_stat_pod(dl, px, strip_y, pod_w, strip_h, "ATTACHED", val.c_str(),
			pid != 0 ? t.success : t.text_dim, alpha);
	}

	{
		ImFont* cf = aida::ui::fonts::caption();
		if (!cf) cf = ImGui::GetFont();
		dl->AddRectFilled(ImVec2(pos_x, table_y),
		                  ImVec2(pos_x + width, table_y + col_header_h),
		                  aida::ui::with_alpha(t.panel_header, alpha));
		dl->AddRectFilledMultiColor(ImVec2(pos_x, table_y),
			ImVec2(pos_x + width, table_y + col_header_h),
			aida::ui::with_alpha(t.accent_grad_top, alpha * 0.10f),
			aida::ui::with_alpha(t.accent_grad_top, alpha * 0.04f),
			aida::ui::with_alpha(t.accent_grad_bot, alpha * 0.04f),
			aida::ui::with_alpha(t.accent_grad_bot, alpha * 0.10f));
		dl->AddLine(ImVec2(pos_x, table_y + col_header_h - 0.5f),
		            ImVec2(pos_x + width, table_y + col_header_h - 0.5f),
		            aida::ui::with_alpha(t.border_subtle, alpha));

		const char* labels[] = { "ADDRESS", "SIZE", "PROTECT", "STATE", "TYPE", "MODULE", "INFO" };
		float fracs[] = { 0.18f, 0.10f, 0.15f, 0.11f, 0.10f, 0.16f, 0.20f };
		const float fs_col_label = aida::ui::components::detail::ui_fs() * 0.88f;
		float lx = pos_x + 12.f;
		for (int i = 0; i < 7; ++i) {
			dl->AddText(cf, fs_col_label,
				ImVec2(lx, table_y + (col_header_h - fs_col_label) * 0.5f),
				aida::ui::with_alpha(t.text_dim, alpha), labels[i]);
			lx += width * fracs[i];
		}
	}

	float row_h = 28.f;
	float list_y = table_y + col_header_h;
	float list_h = pos_y + height - list_y;
	if (list_h <= 0.f) return;

	float content_h = static_cast<float>(filtered_indices.size()) * row_h;
	float max_scroll = content_h - list_h;
	if (max_scroll < 0.f) max_scroll = 0.f;

	if (g_ui.request_pending_scroll && g_ui.pending_scroll_index >= 0) {
		int target_pos = -1;
		for (size_t i = 0; i < filtered_indices.size(); ++i) {
			if (filtered_indices[i] == g_ui.pending_scroll_index) {
				target_pos = static_cast<int>(i);
				break;
			}
		}
		if (target_pos >= 0) {
			float target_scroll = static_cast<float>(target_pos) * row_h - list_h * 0.5f;
			if (target_scroll < 0.f) target_scroll = 0.f;
			if (target_scroll > max_scroll) target_scroll = max_scroll;
			g_ui.target_scroll_y = target_scroll;
		}
		g_ui.request_pending_scroll = false;
		g_ui.pending_scroll_index = -1;
	}

	if (ImGui::IsMouseHoveringRect(ImVec2(pos_x, list_y),
	                               ImVec2(pos_x + width, list_y + list_h), false))
		ui_anim::handle_scroll_input(g_ui.target_scroll_y, 0.f, max_scroll, row_h);
	ui_anim::clamp_scroll(g_ui.target_scroll_y, 0.f, max_scroll);
	ui_anim::smooth_scroll(g_ui.scroll_y, g_ui.target_scroll_y, 16.f, dt);

	dl->PushClipRect(ImVec2(pos_x, list_y), ImVec2(pos_x + width, list_y + list_h), true);

	if (filtered_indices.empty() && !g_ui.refreshing.load()) {
		aida::ui::empty_state::config_t es;
		es.glyph = aida::ui::empty_state::glyph_t::memory;
		es.title = "No memory regions";
		es.body  = (driver_bridge::attached_pid() == 0)
			? std::string("Attach to a process to enumerate its memory map.")
			: std::string("Click Refresh to reload the memory map.");
		aida::ui::empty_state::render(ImVec2(pos_x, list_y), ImVec2(width, list_h), es);
		dl->PopClipRect();
		return;
	}

	ImFont* body_font = aida::ui::fonts::body();
	if (!body_font) body_font = ImGui::GetFont();
	ImFont* code_font = aida::ui::fonts::code();
	if (!code_font) code_font = ImGui::GetFont();

	int first_visible = static_cast<int>(g_ui.scroll_y / row_h);
	if (first_visible < 0) first_visible = 0;
	int visible_count = static_cast<int>(list_h / row_h) + 2;

	float fracs[] = { 0.18f, 0.10f, 0.15f, 0.11f, 0.10f, 0.16f, 0.20f };
	float col_x[7];
	{
		float lx = pos_x + 12.f;
		for (int i = 0; i < 7; ++i) { col_x[i] = lx; lx += width * fracs[i]; }
	}

	for (int vi = 0; vi < visible_count; ++vi) {
		int row_pos = first_visible + vi;
		if (row_pos < 0 || row_pos >= static_cast<int>(filtered_indices.size())) continue;

		int idx = filtered_indices[static_cast<size_t>(row_pos)];
		auto& r = snapshot[static_cast<size_t>(idx)];
		float ry = list_y + static_cast<float>(row_pos) * row_h - g_ui.scroll_y;
		if (ry + row_h < list_y || ry > list_y + list_h) continue;

		bool sel = (g_ui.selected == idx);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(pos_x, ry),
			ImVec2(pos_x + width, ry + row_h), false);
		float row_a = ui_anim::render_row_entrance(vi,
			aida::ui::clock::seconds(), 0.012f, 0.30f);

		if (sel) {
			dl->AddRectFilled(ImVec2(pos_x, ry),
			                  ImVec2(pos_x + width, ry + row_h),
			                  aida::ui::with_alpha(t.selection, alpha * row_a), 0.f);
			dl->AddRectFilled(ImVec2(pos_x, ry),
			                  ImVec2(pos_x + 3.f, ry + row_h),
			                  aida::ui::with_alpha(t.accent_u32, alpha * row_a));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(pos_x, ry),
			                  ImVec2(pos_x + width, ry + row_h),
			                  aida::ui::with_alpha(t.hover_wash, alpha * row_a));
		} else if (row_pos & 1) {
			dl->AddRectFilled(ImVec2(pos_x, ry),
			                  ImVec2(pos_x + width, ry + row_h),
			                  aida::ui::with_alpha(t.hover_wash, alpha * row_a * 0.25f));
		}

		const float fs_mm_row    = aida::ui::components::detail::ui_fs() * 0.92f;
		const float fs_mm_chip   = aida::ui::components::detail::ui_fs() * 0.85f;
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%016" PRIX64, r.base);
		dl->AddText(code_font, fs_mm_row, ImVec2(col_x[0], ry + 6.f),
		            aida::ui::with_alpha(t.text_address, alpha * row_a), buf);

		std::string sz_str = detail::format_size(r.size);
		dl->AddText(body_font, fs_mm_row, ImVec2(col_x[1], ry + 6.f),
		            aida::ui::with_alpha(t.text_secondary, alpha * row_a), sz_str.c_str());

		std::string prot_str = debugger_engine::format_protect(r.protect);
		ImU32 prot_col = detail::protect_token(r.protect, t);
		{
			ImVec2 ps = body_font->CalcTextSizeA(fs_mm_chip, FLT_MAX, 0.f, prot_str.c_str());
			float bw = ps.x + 14.f;
			float bh = 20.f;
			float bx = col_x[2];
			float by = ry + (row_h - bh) * 0.5f;
			dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			                  aida::ui::with_alpha(prot_col, alpha * row_a * 0.22f),
			                  bh * 0.5f);
			dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
			            aida::ui::with_alpha(prot_col, alpha * row_a * 0.55f),
			            bh * 0.5f, 0, 1.f);
			dl->AddText(body_font, fs_mm_chip,
				ImVec2(bx + 7.f, by + (bh - fs_mm_chip) * 0.5f),
				aida::ui::with_alpha(prot_col, alpha * row_a), prot_str.c_str());
		}

		std::string state_str = detail::format_state(r.state);
		ImU32 state_col = detail::state_color(r.state, t);
		dl->AddText(body_font, fs_mm_row, ImVec2(col_x[3], ry + 6.f),
		            aida::ui::with_alpha(state_col, alpha * row_a), state_str.c_str());

		std::string type_str = detail::format_type(r.type);
		ImU32 type_col = detail::type_color(r.type, t);
		dl->AddText(body_font, fs_mm_row, ImVec2(col_x[4], ry + 6.f),
		            aida::ui::with_alpha(type_col, alpha * row_a), type_str.c_str());

		dl->AddText(body_font, fs_mm_row, ImVec2(col_x[5], ry + 6.f),
		            aida::ui::with_alpha(t.text_secondary, alpha * row_a),
		            r.module_name.c_str());
		dl->AddText(body_font, fs_mm_row, ImVec2(col_x[6], ry + 6.f),
		            aida::ui::with_alpha(t.text_dim, alpha * row_a), r.info.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			g_ui.selected = idx;
			g_ui.selected_segment = -1;
		}

		if (g_ui.selected == idx && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			g_ui.context_addr = r.base;
			g_ui.show_context = true;
			ImGui::OpenPopup("##memmap_ctx");
		}
	}

	dl->PopClipRect();

	if (content_h > list_h) {
		ui_anim::render_custom_scrollbar(dl, pos_x + width - 10.f, list_y, 8.f, list_h,
			g_ui.scroll_y, content_h, list_h, alpha,
			g_ui.scrollbar_dragging, g_ui.scrollbar_drag_offset);
	}

	bool open_change_protect_popup = false;

	if (ImGui::BeginPopup("##memmap_ctx")) {
		if (ImGui::MenuItem("Go to Hex View")) {
			debugger_engine::memory_region_t r{};
			if (find_region_by_base(g_ui.context_addr, r)) {
				const size_t cap = static_cast<size_t>(1024ULL * 1024ULL);
				size_t req = static_cast<size_t>(std::min<uint64_t>(r.size, static_cast<uint64_t>(cap)));
				diag::log_tagged_fmt("memmap",
					"memmap_go_hex base=0x%llx size=%zu",
					static_cast<unsigned long long>(r.base), req);
				if (req == 0) {
					toast_notification::push("Region has zero size.", toast_notification::toast_type_t::error);
				}
				else if (hex_view::read_from_process(r.base, req)) {
					globals::ui::active_center_view = center_view_t::hex_view;
				}
				else {
					toast_notification::push("Failed to read region for hex view.", toast_notification::toast_type_t::error);
				}
			}
			else {
				toast_notification::push("Region no longer present.", toast_notification::toast_type_t::error);
			}
			g_ui.show_context = false;
		}
		if (ImGui::MenuItem("Go to Disassembly")) {
			debugger_engine::memory_region_t r{};
			if (find_region_by_base(g_ui.context_addr, r)) {
				diag::log_tagged_fmt("memmap",
					"memmap_go_disasm base=0x%llx",
					static_cast<unsigned long long>(r.base));
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(r.base, g_disasm);
			}
			else {
				toast_notification::push("Region no longer present.", toast_notification::toast_type_t::error);
			}
			g_ui.show_context = false;
		}
		if (ImGui::MenuItem("Change Protection")) {
			debugger_engine::memory_region_t r{};
			if (find_region_by_base(g_ui.context_addr, r)) {
				g_ui.change_protect_addr = r.base;
				g_ui.change_protect_size = r.size;
				g_ui.change_protect_choice = 0;
				g_ui.change_protect_old = r.protect;
				g_ui.change_protect_open = true;
				open_change_protect_popup = true;
			}
			else {
				toast_notification::push("Region no longer present.", toast_notification::toast_type_t::error);
			}
			g_ui.show_context = false;
		}
		if (ImGui::MenuItem("Dump Region")) {
			debugger_engine::memory_region_t r{};
			if (find_region_by_base(g_ui.context_addr, r)) {
				const uint64_t max_dump = 256ULL * 1024ULL * 1024ULL;
				if (r.size == 0) {
					toast_notification::push("Region has zero size.", toast_notification::toast_type_t::error);
				}
				else if (r.size > max_dump) {
					toast_notification::push("Region exceeds 256 MiB dump cap.", toast_notification::toast_type_t::warning);
				}
				else {
					char default_name[64] = {};
					std::snprintf(default_name, sizeof(default_name), "dump_%016llX_%llu.bin",
						static_cast<unsigned long long>(r.base),
						static_cast<unsigned long long>(r.size));

					char path_buf[MAX_PATH] = {};
					std::strncpy(path_buf, default_name, sizeof(path_buf) - 1);

					static const char k_mem_dump_filter[] =
						"Binary (*.bin)\0*.bin\0"
						"All files (*.*)\0*.*\0\0";
					if (win32_dialog::show_save_file_dialog(g_hwnd,
							"Dump Region",
							k_mem_dump_filter,
							"bin",
							path_buf, sizeof(path_buf),
							"memory_map_view::dump_region")) {
						diag::log_tagged_critical_fmt("memmap",
							"memmap_dump_request base=0x%llx size=%llu path='%s'",
							static_cast<unsigned long long>(r.base),
							static_cast<unsigned long long>(r.size),
							path_buf);
						std::vector<uint8_t> buf;
						size_t req = static_cast<size_t>(r.size);
						if (driver_bridge::read_memory(r.base, req, buf) && !buf.empty()) {
							std::ofstream ofs(path_buf, std::ios::binary | std::ios::trunc);
							if (ofs.is_open()) {
								ofs.write(reinterpret_cast<const char*>(buf.data()),
									static_cast<std::streamsize>(buf.size()));
								ofs.close();
								diag::log_tagged_critical_fmt("memmap",
									"memmap_dump_done bytes=%zu path='%s'",
									buf.size(), path_buf);
								char msg[MAX_PATH + 64];
								std::snprintf(msg, sizeof(msg), "Dumped %llu bytes to %s",
									static_cast<unsigned long long>(buf.size()), path_buf);
								toast_notification::push(msg, toast_notification::toast_type_t::info);
							}
							else {
								diag::log_tagged_fmt("memmap",
									"memmap_dump_FAILED_open path='%s'", path_buf);
								toast_notification::push("Failed to open dump file for writing.", toast_notification::toast_type_t::error);
							}
						}
						else {
							diag::log_tagged_fmt("memmap",
								"memmap_dump_FAILED_read base=0x%llx",
								static_cast<unsigned long long>(r.base));
							toast_notification::push("Failed to read region memory.", toast_notification::toast_type_t::error);
						}
					}
				}
			}
			else {
				toast_notification::push("Region no longer present.", toast_notification::toast_type_t::error);
			}
			g_ui.show_context = false;
		}
		ImGui::EndPopup();
	}

	if (open_change_protect_popup)
		ImGui::OpenPopup("Change Protection");

	if (ImGui::BeginPopupModal("Change Protection", &g_ui.change_protect_open, ImGuiWindowFlags_AlwaysAutoResize)) {
		ImGui::Text("Address: %016llX", static_cast<unsigned long long>(g_ui.change_protect_addr));
		ImGui::Text("Size:    %llu bytes", static_cast<unsigned long long>(g_ui.change_protect_size));
		ImGui::Text("Current: 0x%X", g_ui.change_protect_old);
		ImGui::Separator();

		const char* labels[] = {
			"PAGE_NOACCESS (0x01)",
			"PAGE_READONLY (0x02)",
			"PAGE_READWRITE (0x04)",
			"PAGE_WRITECOPY (0x08)",
			"PAGE_EXECUTE (0x10)",
			"PAGE_EXECUTE_READ (0x20)",
			"PAGE_EXECUTE_READWRITE (0x40)",
			"PAGE_EXECUTE_WRITECOPY (0x80)"
		};
		const uint32_t values[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
		const int value_count = static_cast<int>(sizeof(values) / sizeof(values[0]));

		if (g_ui.change_protect_choice < 0) g_ui.change_protect_choice = 0;
		if (g_ui.change_protect_choice >= value_count) g_ui.change_protect_choice = value_count - 1;

		ImGui::Combo("##new_protect", &g_ui.change_protect_choice, labels, value_count);

		ImGui::Separator();
		if (ImGui::Button("Apply", ImVec2(100.f, 0.f))) {
			uint32_t new_protect = values[g_ui.change_protect_choice];
			uint32_t old_protect = 0;
			diag::log_tagged_critical_fmt("memmap",
				"memmap_protect_request addr=0x%llx size=%llu new=0x%X",
				static_cast<unsigned long long>(g_ui.change_protect_addr),
				static_cast<unsigned long long>(g_ui.change_protect_size),
				static_cast<unsigned>(new_protect));
			bool ok = driver_bridge::protect_memory(g_ui.change_protect_addr, g_ui.change_protect_size, new_protect, &old_protect);
			diag::log_tagged_critical_fmt("memmap",
				"memmap_protect_done addr=0x%llx ok=%d old=0x%X new=0x%X",
				static_cast<unsigned long long>(g_ui.change_protect_addr),
				ok ? 1 : 0,
				static_cast<unsigned>(old_protect),
				static_cast<unsigned>(new_protect));
			if (ok) {
				char msg[96];
				std::snprintf(msg, sizeof(msg), "Protection changed 0x%X -> 0x%X", old_protect, new_protect);
				toast_notification::push(msg, toast_notification::toast_type_t::info);
				refresh();
			}
			else {
				toast_notification::push("Failed to change protection.", toast_notification::toast_type_t::error);
			}
			g_ui.change_protect_open = false;
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Cancel", ImVec2(100.f, 0.f))) {
			g_ui.change_protect_open = false;
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}

}
