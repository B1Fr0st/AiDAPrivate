#pragma once

#include "code_patcher.hpp"
#include "standalone_driver.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida::code_patcher::view {

	struct row_anim_t {
		aida::ui::flash_t apply_flash;
		aida::ui::flash_t revert_flash;
	};

	struct create_modal_t {
		bool   open = false;
		float  appear = 0.f;
		float  appear_vel = 0.f;
		char   addr_buf[32] = {};
		char   bytes_buf[256] = {};
		char   desc_buf[160] = {};
	};

	struct view_state_t {
		float scroll_y = 0.f;
		float target_scroll_y = 0.f;
		bool  scrollbar_dragging = false;
		float scrollbar_drag_offset = 0.f;
		int   selected_index = -1;
		float anim_time = 0.f;
		std::unordered_map<int, row_anim_t> row_anims;
		create_modal_t modal;
		std::vector<::code_patcher::code_cave_t> caves;
		bool  caves_loaded = false;
		char  cave_module_buf[64] = {};
		char  cave_min_size[16] = "32";
		bool  show_caves = false;
	};

	inline view_state_t& state() {
		static view_state_t s;
		return s;
	}

	inline std::string format_bytes_short(const std::vector<uint8_t>& bytes, size_t max_n = 16) {
		std::string out;
		size_t n = bytes.size();
		size_t shown = n < max_n ? n : max_n;
		for (size_t i = 0; i < shown; ++i) {
			if (i > 0) out += ' ';
			char hex[4];
			std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
			out += hex;
		}
		if (n > max_n) out += " ...";
		return out;
	}

	inline std::string format_timestamp(int64_t unix_seconds) {
		if (unix_seconds <= 0) return "-";
		int64_t now = ::code_patcher::current_timestamp();
		int64_t diff = now - unix_seconds;
		char buf[48];
		if (diff < 60) std::snprintf(buf, sizeof(buf), "%llds ago", static_cast<long long>(diff));
		else if (diff < 3600) std::snprintf(buf, sizeof(buf), "%lldm ago", static_cast<long long>(diff / 60));
		else if (diff < 86400) std::snprintf(buf, sizeof(buf), "%lldh ago", static_cast<long long>(diff / 3600));
		else std::snprintf(buf, sizeof(buf), "%lldd ago", static_cast<long long>(diff / 86400));
		return buf;
	}

	inline void render_diff_panel(ImDrawList* dl, ImVec2 a, ImVec2 b,
	                              const ::code_patcher::patch_entry_t& patch,
	                              float alpha)
	{
		const auto& th = aida::ui::resolved();
		aida::ui::blur::render_glass_fill(dl, a, b, 10.f, alpha);
		aida::ui::blur::render_glass_border(dl, a, b, 10.f, alpha, 1.f);

		ImFont* head = aida::ui::fonts::body_em();
		if (!head) head = ImGui::GetFont();
		dl->AddText(head, 13.f, ImVec2(a.x + 12.f, a.y + 8.f),
			aida::ui::with_alpha(th.text_primary, alpha), "Patch Diff");

		char addr[32];
		std::snprintf(addr, sizeof(addr), "0x%llX",
			static_cast<unsigned long long>(patch.address));
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		dl->AddText(code_font, 13.f, ImVec2(a.x + 100.f, a.y + 10.f),
			aida::ui::with_alpha(th.text_address, alpha), addr);

		float ax = a.x + 12.f;
		float top = a.y + 32.f;
		float w = b.x - a.x - 24.f;
		float row_y = top;

		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ax, row_y),
			aida::ui::with_alpha(th.text_dim, alpha), "Original");
		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ax + w * 0.5f, row_y),
			aida::ui::with_alpha(th.text_dim, alpha), "Patched");
		row_y += 14.f;

		ImVec2 a_l = ImVec2(ax, row_y);
		ImVec2 a_r = ImVec2(ax + w * 0.5f - 6.f, row_y + 36.f);
		ImVec2 b_l = ImVec2(ax + w * 0.5f + 2.f, row_y);
		ImVec2 b_r = ImVec2(ax + w, row_y + 36.f);

		dl->AddRectFilled(a_l, a_r, aida::ui::with_alpha(th.error_soft, alpha), 6.f);
		dl->AddRectFilled(b_l, b_r, aida::ui::with_alpha(th.success_soft, alpha), 6.f);
		dl->AddRect(a_l, a_r, aida::ui::with_alpha(th.error, alpha * 0.55f), 6.f, 0, 1.f);
		dl->AddRect(b_l, b_r, aida::ui::with_alpha(th.success, alpha * 0.55f), 6.f, 0, 1.f);

		std::string orig_str = format_bytes_short(patch.original_bytes, 16);
		std::string patched_str = format_bytes_short(patch.patched_bytes, 16);
		dl->AddText(code_font, 13.f, ImVec2(a_l.x + 8.f, a_l.y + 12.f),
			aida::ui::with_alpha(th.error, alpha), orig_str.c_str());
		dl->AddText(code_font, 13.f, ImVec2(b_l.x + 8.f, b_l.y + 12.f),
			aida::ui::with_alpha(th.success, alpha), patched_str.c_str());

		row_y += 42.f;
		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ax, row_y),
			aida::ui::with_alpha(th.text_dim, alpha), "Description");
		row_y += 14.f;
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			12.f, ImVec2(ax, row_y),
			aida::ui::with_alpha(th.text_primary, alpha),
			patch.description.empty() ? "(no description)" : patch.description.c_str());
		row_y += 22.f;

		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ax, row_y),
			aida::ui::with_alpha(th.text_dim, alpha),
			patch.active ? "Status: APPLIED" : "Status: not applied");
	}

	inline void render_modal(view_state_t& st, ImDrawList* dl, ImVec2 wp,
	                          float win_w, float win_h, float alpha, float dt)
	{
		auto& m = st.modal;
		float target = m.open ? 1.f : 0.f;
		m.appear = aida::motion::spring_step(m.appear, target, m.appear_vel,
			aida::motion::spring::balanced, dt);
		if (m.appear < 0.001f && !m.open) return;

		const auto& th = aida::ui::resolved();
		dl->AddRectFilled(wp, ImVec2(wp.x + win_w, wp.y + win_h),
			IM_COL32(0, 0, 0, static_cast<int>(120 * m.appear)));

		float card_w = 480.f;
		float card_h = 280.f;
		float scale = 0.92f + 0.08f * m.appear;
		ImVec2 ca = ImVec2(wp.x + (win_w - card_w * scale) * 0.5f,
		                    wp.y + (win_h - card_h * scale) * 0.5f);
		ImVec2 cb = ImVec2(ca.x + card_w * scale, ca.y + card_h * scale);

		aida::ui::blur::render_drop_shadow(dl, ca, cb, 14.f, 6, 0.45f, ImVec2(0.f, 8.f));
		aida::ui::blur::render_glass_fill(dl, ca, cb, 14.f, alpha * m.appear);
		aida::ui::blur::render_glass_border(dl, ca, cb, 14.f, alpha * m.appear, 1.f);

		float ix = ca.x + 18.f;
		float iy = ca.y + 16.f;
		ImFont* head = aida::ui::fonts::h2();
		if (!head) head = ImGui::GetFont();
		dl->AddText(head, 16.f, ImVec2(ix, iy),
			aida::ui::with_alpha(th.text_primary, alpha * m.appear),
			"Create Patch");
		iy += 28.f;

		float field_w = card_w * scale - 36.f;

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha * m.appear)));
		ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.border_subtle, alpha * m.appear)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha * m.appear)));

		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ix, iy),
			aida::ui::with_alpha(th.text_dim, alpha * m.appear), "Address (hex)");
		iy += 14.f;
		ImGui::SetCursorScreenPos(ImVec2(ix, iy));
		ImGui::PushItemWidth(field_w);
		ImGui::InputTextWithHint("##cp_modal_addr", "0x...", m.addr_buf, sizeof(m.addr_buf));
		ImGui::PopItemWidth();
		iy += 28.f;

		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ix, iy),
			aida::ui::with_alpha(th.text_dim, alpha * m.appear), "Bytes (hex, space-separated)");
		iy += 14.f;
		ImGui::SetCursorScreenPos(ImVec2(ix, iy));
		ImGui::PushItemWidth(field_w);
		ImGui::InputTextWithHint("##cp_modal_bytes", "90 90 90 ...",
			m.bytes_buf, sizeof(m.bytes_buf));
		ImGui::PopItemWidth();
		iy += 28.f;

		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			10.f, ImVec2(ix, iy),
			aida::ui::with_alpha(th.text_dim, alpha * m.appear), "Description");
		iy += 14.f;
		ImGui::SetCursorScreenPos(ImVec2(ix, iy));
		ImGui::PushItemWidth(field_w);
		ImGui::InputTextWithHint("##cp_modal_desc", "Describe what this patches",
			m.desc_buf, sizeof(m.desc_buf));
		ImGui::PopItemWidth();
		iy += 28.f;

		ImGui::PopStyleColor(3);
		ImGui::PopStyleVar(2);

		float btn_y = cb.y - 44.f;
		ImGui::SetCursorScreenPos(ImVec2(cb.x - 240.f, btn_y));
		if (aida::ui::button("Save", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(72.f, 32.f))) {
			uint64_t addr = std::strtoull(m.addr_buf, nullptr, 16);
			auto bytes = ::code_patcher::parse_bytes(m.bytes_buf);
			if (addr != 0 && !bytes.empty()) {
				::code_patcher::create_patch(addr, bytes, m.desc_buf);
				m.open = false;
				m.addr_buf[0] = 0;
				m.bytes_buf[0] = 0;
				m.desc_buf[0] = 0;
			}
		}
		ImGui::SetCursorScreenPos(ImVec2(cb.x - 158.f, btn_y));
		if (aida::ui::button("Save & Apply", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::md, ImVec2(126.f, 32.f))) {
			uint64_t addr = std::strtoull(m.addr_buf, nullptr, 16);
			auto bytes = ::code_patcher::parse_bytes(m.bytes_buf);
			if (addr != 0 && !bytes.empty()) {
				int idx = ::code_patcher::create_patch(addr, bytes, m.desc_buf);
				if (idx >= 0) ::code_patcher::apply_patch(idx);
				m.open = false;
				m.addr_buf[0] = 0;
				m.bytes_buf[0] = 0;
				m.desc_buf[0] = 0;
			}
		}
		ImGui::SetCursorScreenPos(ImVec2(ca.x + 18.f, btn_y));
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(96.f, 32.f))) {
			m.open = false;
		}
	}

	inline void render(float panel_w, float panel_h) {
		view_state_t& st = state();
		ImGui::BeginChild("##code_patcher_view", ImVec2(panel_w, panel_h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		float ox = wp.x;
		float oy = wp.y;

		const auto& th = aida::ui::resolved();
		const float dt = aida::ui::clock::dt();
		const float alpha = ImGui::GetStyle().Alpha;
		st.anim_time += dt;

		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + panel_w, oy + panel_h),
			aida::ui::with_alpha(th.bg_base, alpha));

		const float toolbar_h = 56.f;
		ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
		ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
		dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + panel_w, oy + toolbar_h),
			bar_top, bar_top, bar_bot, bar_bot);
		dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + panel_w, oy + toolbar_h - 1.f),
			aida::ui::with_alpha(th.border_subtle, alpha));

		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		dl->AddText(head, 15.f, ImVec2(ox + 14.f, oy + 8.f),
			aida::ui::with_alpha(th.text_primary, alpha), "Code Patcher");

		size_t total = ::code_patcher::count();
		size_t active = ::code_patcher::active_count();
		char meta[64];
		std::snprintf(meta, sizeof(meta), "%zu patches   %zu applied", total, active);
		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			11.f, ImVec2(ox + 14.f, oy + 28.f),
			aida::ui::with_alpha(th.text_dim, alpha), meta);

		float btn_x = ox + panel_w - 14.f;
		float btn_y = oy + 14.f;

		ImGui::SetCursorScreenPos(ImVec2(btn_x - 110.f, btn_y));
		if (aida::ui::button("Find Caves", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(106.f, 28.f))) {
			st.show_caves = !st.show_caves;
			if (st.show_caves) {
				st.caves.clear();
				st.caves_loaded = false;
			}
		}
		ImGui::SetCursorScreenPos(ImVec2(btn_x - 110.f - 110.f, btn_y));
		if (aida::ui::button("Toggle", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(106.f, 28.f))) {
			if (st.selected_index >= 0)
				::code_patcher::toggle_patch(st.selected_index);
		}
		ImGui::SetCursorScreenPos(ImVec2(btn_x - 110.f - 110.f - 110.f, btn_y));
		if (aida::ui::button("Revert", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm, ImVec2(106.f, 28.f))) {
			if (st.selected_index >= 0)
				::code_patcher::revert_patch(st.selected_index);
		}
		ImGui::SetCursorScreenPos(ImVec2(btn_x - 110.f - 110.f - 110.f - 110.f, btn_y));
		if (aida::ui::button("Apply", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(106.f, 28.f))) {
			if (st.selected_index >= 0) {
				if (::code_patcher::apply_patch(st.selected_index)) {
					st.row_anims[st.selected_index].apply_flash.trigger();
				}
			}
		}
		ImGui::SetCursorScreenPos(ImVec2(btn_x - 110.f - 110.f - 110.f - 110.f - 110.f, btn_y));
		if (aida::ui::button("Add Patch", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(106.f, 28.f))) {
			st.modal.open = true;
		}

		const float pad = 14.f;
		float content_y = oy + toolbar_h + 8.f;
		float content_h = panel_h - toolbar_h - 16.f;

		float right_w = (st.show_caves || st.selected_index >= 0)
			? std::max(280.f, panel_w * 0.32f) : 0.f;
		float table_w = panel_w - right_w - 16.f;
		if (right_w > 0.f) table_w -= 8.f;
		float table_x = ox + pad;

		std::vector<::code_patcher::patch_entry_t> patches;
		{
			std::lock_guard<std::mutex> lk(::code_patcher::g_state.mtx);
			patches = ::code_patcher::g_state.patches;
		}

		if (patches.empty()) {
			ImVec2 e_pos = ImVec2(ox + pad, content_y);
			ImVec2 e_sz  = ImVec2(table_w, content_h);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No patches yet";
			cfg.body = "Click Add Patch to create your first byte patch, or Find Caves to discover empty space for hooks.";
			cfg.max_width = 360.f;
			aida::ui::empty_state::render(e_pos, e_sz, cfg);
		} else {
			const float row_h = 32.f;
			const float col_addr_w = 130.f;
			const float col_size_w = 60.f;
			const float col_active_w = 56.f;
			const float col_time_w = 90.f;
			const float col_actions_w = 84.f;
			const float col_desc_w = table_w - col_addr_w - col_size_w - col_active_w
			                        - col_time_w - col_actions_w - 16.f;

			ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
			dl->AddRectFilled(ImVec2(table_x, content_y), ImVec2(table_x + table_w, content_y + 24.f),
				hdr_bg, 6.f);
			dl->AddLine(ImVec2(table_x, content_y + 23.f), ImVec2(table_x + table_w, content_y + 23.f),
				aida::ui::with_alpha(th.border_subtle, alpha));

			ImFont* head_em = aida::ui::fonts::body_em();
			if (!head_em) head_em = ImGui::GetFont();
			ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
			float hxx = table_x + 8.f;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Address");
			hxx += col_addr_w;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Size");
			hxx += col_size_w;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Description");
			hxx += col_desc_w;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Active");
			hxx += col_active_w;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Created");
			hxx += col_time_w;
			dl->AddText(head_em, 13.f, ImVec2(hxx, content_y + 7.f), hc, "Actions");

			float table_top = content_y + 24.f;
			float table_h = content_h - 24.f;
			float total_h = static_cast<float>(patches.size()) * row_h;

			float wheel = 0.f;
			if (ImGui::IsMouseHoveringRect(ImVec2(table_x, table_top),
				ImVec2(table_x + table_w, table_top + table_h))) {
				wheel = ImGui::GetIO().MouseWheel;
			}
			if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
			if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
			float ms = std::max(0.f, total_h - table_h);
			if (st.target_scroll_y > ms) st.target_scroll_y = ms;
			st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

			ImGui::PushClipRect(ImVec2(table_x, table_top),
				ImVec2(table_x + table_w, table_top + table_h), true);

			int first_vis = static_cast<int>(st.scroll_y / row_h);
			int last_vis = first_vis + static_cast<int>(table_h / row_h) + 2;
			if (first_vis < 0) first_vis = 0;
			if (last_vis > static_cast<int>(patches.size()))
				last_vis = static_cast<int>(patches.size());

			for (int i = first_vis; i < last_vis; ++i) {
				float ry = table_top + static_cast<float>(i) * row_h - st.scroll_y;
				if (ry + row_h < table_top || ry > table_top + table_h) continue;

				const auto& p = patches[static_cast<size_t>(i)];
				auto& ra = st.row_anims[i];

				ImVec2 rmin(table_x, ry);
				ImVec2 rmax(table_x + table_w, ry + row_h);

				bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
				bool selected = (st.selected_index == i);

				float entrance_delay = std::min(static_cast<float>(i - first_vis) * 0.012f, 0.240f);
				float entrance_t = (st.anim_time - entrance_delay) / 0.32f;
				if (entrance_t < 0.f) entrance_t = 0.f;
				if (entrance_t > 1.f) entrance_t = 1.f;
				float entrance = aida::motion::ease::out_cubic(entrance_t);

				ImU32 row_fill;
				if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
				else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
				else row_fill = (i & 1)
					? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f * entrance)
					: 0u;
				if ((row_fill & 0xFF000000) != 0) {
					dl->AddRectFilled(rmin, rmax, row_fill, 5.f);
				}
				if (selected) {
					dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
						aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
				}

				float apply_v = ra.apply_flash.tick(dt, 2.0f);
				if (apply_v > 0.001f) {
					dl->AddRectFilled(rmin, rmax,
						aida::ui::with_alpha(th.success_soft, alpha * apply_v * 1.5f), 5.f);
				}
				float revert_v = ra.revert_flash.tick(dt, 2.0f);
				if (revert_v > 0.001f) {
					dl->AddRectFilled(rmin, rmax,
						aida::ui::with_alpha(th.error_soft, alpha * revert_v * 1.5f), 5.f);
				}

				if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					st.selected_index = i;
				}

				ImFont* code_font = aida::ui::fonts::code();
				if (!code_font) code_font = ImGui::GetFont();

				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(p.address));
				dl->AddText(code_font, 13.f, ImVec2(rmin.x + 12.f, ry + 9.f),
					aida::ui::with_alpha(th.text_address, alpha * entrance), addr_buf);

				float rx2 = rmin.x + col_addr_w + 8.f;
				char size_buf[16];
				std::snprintf(size_buf, sizeof(size_buf), "%zu B", p.patched_bytes.size());
				dl->AddText(code_font, 13.f, ImVec2(rx2, ry + 9.f),
					aida::ui::with_alpha(th.text_secondary, alpha * entrance), size_buf);

				rx2 += col_size_w;
				std::string desc = p.description.empty() ? "(no description)" : p.description;
				if (desc.size() > 50) desc = desc.substr(0, 48) + "..";
				dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
					12.f, ImVec2(rx2, ry + 9.f),
					aida::ui::with_alpha(p.description.empty()
						? th.text_dim : th.text_primary, alpha * entrance),
					desc.c_str());

				rx2 += col_desc_w;
				bool active_now = p.active;
				ImGui::SetCursorScreenPos(ImVec2(rx2, ry + 6.f));
				ImGui::PushID(i);
				if (aida::ui::toggle_switch("##cp_active", &active_now, aida::ui::size_t_::sm)) {
					if (active_now) {
						if (::code_patcher::apply_patch(i)) ra.apply_flash.trigger();
					} else {
						if (::code_patcher::revert_patch(i)) ra.revert_flash.trigger();
					}
				}
				ImGui::PopID();

				rx2 += col_active_w;
				std::string ts = format_timestamp(p.timestamp);
				dl->AddText(code_font, 13.f, ImVec2(rx2, ry + 9.f),
					aida::ui::with_alpha(th.text_dim, alpha * entrance), ts.c_str());

				rx2 += col_time_w;
				ImGui::SetCursorScreenPos(ImVec2(rx2, ry + 4.f));
				ImGui::PushID(i + 0x10000);
				if (aida::ui::button("Del", aida::ui::button_kind_t::destructive,
					aida::ui::size_t_::sm, ImVec2(60.f, 28.f))) {
					::code_patcher::remove_patch(i);
					if (st.selected_index == i) st.selected_index = -1;
				}
				ImGui::PopID();
			}

			ImGui::PopClipRect();

			if (total_h > table_h && table_h > 0.f) {
				float bar_x = table_x + table_w - 8.f;
				float bar_y = table_top;
				float ratio = table_h / total_h;
				float thumb_h = std::max(table_h * ratio, 24.f);
				float track = table_h - thumb_h;
				float scroll_ratio = (total_h - table_h > 0.f)
					? st.scroll_y / (total_h - table_h) : 0.f;
				float thumb_y = bar_y + track * scroll_ratio;
				dl->AddRectFilled(ImVec2(bar_x, bar_y),
					ImVec2(bar_x + 6.f, bar_y + table_h),
					aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
				dl->AddRectFilled(ImVec2(bar_x, thumb_y),
					ImVec2(bar_x + 6.f, thumb_y + thumb_h),
					aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
			}
		}

		if (right_w > 0.f) {
			float rx_panel = ox + pad + table_w + 8.f;
			ImVec2 r_a = ImVec2(rx_panel, content_y);
			ImVec2 r_b = ImVec2(rx_panel + right_w, content_y + content_h);

			if (st.show_caves) {
				aida::ui::blur::render_glass_fill(dl, r_a, r_b, 10.f, alpha);
				aida::ui::blur::render_glass_border(dl, r_a, r_b, 10.f, alpha, 1.f);

				ImFont* head_l = aida::ui::fonts::body_em();
				if (!head_l) head_l = ImGui::GetFont();
				dl->AddText(head_l, 13.f, ImVec2(r_a.x + 12.f, r_a.y + 8.f),
					aida::ui::with_alpha(th.text_primary, alpha), "Code Caves");

				float cy = r_a.y + 30.f;
				ImGui::SetCursorScreenPos(ImVec2(r_a.x + 12.f, cy));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
					aida::ui::with_alpha(th.panel_header, alpha)));
				ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
					aida::ui::with_alpha(th.text_primary, alpha)));
				ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
				ImGui::PushItemWidth(right_w * 0.55f);
				ImGui::InputTextWithHint("##cv_mod", "module name", st.cave_module_buf, sizeof(st.cave_module_buf));
				ImGui::PopItemWidth();
				ImGui::SameLine();
				ImGui::PushItemWidth(60.f);
				ImGui::InputTextWithHint("##cv_min", "min", st.cave_min_size, sizeof(st.cave_min_size));
				ImGui::PopItemWidth();
				ImGui::PopStyleVar();
				ImGui::PopStyleColor(2);

				cy += 30.f;
				ImGui::SetCursorScreenPos(ImVec2(r_a.x + 12.f, cy));
				if (aida::ui::button("Scan", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
					st.caves.clear();
					st.caves_loaded = false;
					auto mods = driver_bridge::enumerate_modules();
					for (const auto& m : mods) {
						if (st.cave_module_buf[0] == 0 ||
							m.name.find(st.cave_module_buf) != std::string::npos) {
							size_t min_sz = static_cast<size_t>(std::strtoul(st.cave_min_size, nullptr, 0));
							if (min_sz < 1) min_sz = 32;
							auto cs = ::code_patcher::find_code_caves(m.base, m.size, min_sz);
							st.caves.insert(st.caves.end(), cs.begin(), cs.end());
						}
					}
					st.caves_loaded = true;
				}

				cy += 30.f;
				float list_top = cy;
				float list_h = (r_b.y - cy) - 10.f;
				ImFont* code_font = aida::ui::fonts::code();
				if (!code_font) code_font = ImGui::GetFont();

				if (st.caves.empty() && st.caves_loaded) {
					dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
						12.f, ImVec2(r_a.x + 12.f, cy + 6.f),
						aida::ui::with_alpha(th.text_dim, alpha),
						"No caves found in selected module(s).");
				}

				ImGui::SetCursorScreenPos(ImVec2(r_a.x + 8.f, cy));
				ImGui::BeginChild("##cp_caves_list", ImVec2(right_w - 16.f, list_h), false,
					ImGuiWindowFlags_NoBackground);
				for (size_t ci = 0; ci < st.caves.size(); ++ci) {
					const auto& cv = st.caves[ci];
					ImVec2 cp = ImGui::GetCursorScreenPos();
					float lw = right_w - 24.f;
					float lh = 28.f;
					bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + lw, cp.y + lh), true);
					if (hov) {
						dl->AddRectFilled(cp, ImVec2(cp.x + lw, cp.y + lh),
							aida::ui::with_alpha(th.hover_wash, alpha), 5.f);
					}
					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(cv.address));
					dl->AddText(code_font, 13.f, ImVec2(cp.x + 8.f, cp.y + 4.f),
						aida::ui::with_alpha(th.text_address, alpha), addr_buf);
					char sz_buf[24];
					std::snprintf(sz_buf, sizeof(sz_buf), "%llu B",
						static_cast<unsigned long long>(cv.size));
					dl->AddText(code_font, 13.f, ImVec2(cp.x + 8.f, cp.y + 18.f),
						aida::ui::with_alpha(th.text_dim, alpha), sz_buf);
					if (!cv.module_name.empty()) {
						dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
							10.f, ImVec2(cp.x + 130.f, cp.y + 4.f),
							aida::ui::with_alpha(th.text_secondary, alpha),
							cv.module_name.c_str());
					}

					ImGui::SetCursorScreenPos(ImVec2(cp.x + lw - 80.f, cp.y + 4.f));
					ImGui::PushID(static_cast<int>(0x20000 | ci));
					if (aida::ui::button("Use", aida::ui::button_kind_t::ghost,
						aida::ui::size_t_::sm, ImVec2(76.f, 28.f))) {
						std::snprintf(st.modal.addr_buf, sizeof(st.modal.addr_buf),
							"0x%llX", static_cast<unsigned long long>(cv.address));
						st.modal.bytes_buf[0] = 0;
						st.modal.desc_buf[0] = 0;
						st.modal.open = true;
					}
					ImGui::PopID();

					ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + lh + 2.f));
				}
				ImGui::EndChild();
			} else if (st.selected_index >= 0 &&
				st.selected_index < static_cast<int>(patches.size())) {
				render_diff_panel(dl, r_a, r_b,
					patches[static_cast<size_t>(st.selected_index)], alpha);
			}
		}

		render_modal(st, dl, wp, panel_w, panel_h, alpha, dt);

		ImGui::EndChild();
	}

}
