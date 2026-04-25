#pragma once

#include "imgui/imgui.h"

#include "../helpers/globals.h"
#include "binary_map.hpp"
#include "disasm_view.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <vector>

extern DisasmState g_disasm;

namespace aida {
namespace binary_map_view {

	struct view_state_t
	{
		std::mutex                              mutex;
		binary_map::map_t                       map;
		binary_map::map_options_t               opts;
		std::string                             rendered_text;
		std::set<std::string>                   collapsed_groups;
		std::set<std::string>                   expanded_imports;
		char                                    filter_buf[160] = {};
		std::string                             filter_lower;
		std::string                             last_error;
		std::atomic<bool>                       has_map{false};
		std::atomic<bool>                       refreshing{false};
		std::atomic<bool>                       refresh_requested{false};
		std::atomic<uint64_t>                   selected_va{0};
		std::atomic<int>                        ctx_target{-1};
		uint64_t                                ctx_va = 0;
		float                                   left_split = 0.5f;
		float                                   list_scroll_y = 0.f;
		float                                   list_target_scroll_y = 0.f;
		float                                   row_anim_time = 0.f;
		bool                                    initialized = false;
		bool                                    auto_refreshed_once = false;
		aida::events::subscription_handle_t     subscription;
	};

	inline view_state_t& state()
	{
		static view_state_t s;
		return s;
	}

	namespace detail {

		inline std::string to_lower_copy(const std::string& s)
		{
			std::string out;
			out.resize(s.size());
			for (size_t i = 0; i < s.size(); ++i) {
				const unsigned char c = static_cast<unsigned char>(s[i]);
				out[i] = static_cast<char>(std::tolower(c));
			}
			return out;
		}

		inline bool filter_matches(const std::string& filter_lower, const std::string& text)
		{
			if (filter_lower.empty()) return true;
			std::string lower = to_lower_copy(text);
			return lower.find(filter_lower) != std::string::npos;
		}

		inline std::string format_size_human(uint64_t bytes)
		{
			char buf[48];
			if (bytes >= (1ull << 30)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 30);
				std::snprintf(buf, sizeof(buf), "%.2f GiB", v);
			} else if (bytes >= (1ull << 20)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 20);
				std::snprintf(buf, sizeof(buf), "%.2f MiB", v);
			} else if (bytes >= (1ull << 10)) {
				const double v = static_cast<double>(bytes) / static_cast<double>(1ull << 10);
				std::snprintf(buf, sizeof(buf), "%.2f KiB", v);
			} else {
				std::snprintf(buf, sizeof(buf), "%llu B",
					static_cast<unsigned long long>(bytes));
			}
			return std::string(buf);
		}

		inline std::string format_va(uint64_t va)
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "0x%llX",
				static_cast<unsigned long long>(va));
			return std::string(buf);
		}

		inline std::string section_perm_string(const binary_map::map_section_t& s)
		{
			std::string out;
			out += s.readable ? 'R' : '-';
			out += s.writable ? 'W' : '-';
			out += s.executable ? 'X' : '-';
			return out;
		}

		inline std::string format_function_summary(const binary_map::map_function_t& f)
		{
			std::string callees;
			for (size_t i = 0; i < f.top_callees.size() && i < 5; ++i) {
				if (i > 0) callees += ", ";
				callees += f.top_callees[i];
			}
			if (callees.empty()) callees = "(none)";

			char buf[512];
			std::snprintf(buf, sizeof(buf),
				"%s @ 0x%llX (xrefs=%d, callees: %s)",
				f.name.c_str(),
				static_cast<unsigned long long>(f.va),
				f.xref_count,
				callees.c_str());
			return std::string(buf);
		}

		inline void rebuild_text_locked(view_state_t& s)
		{
			s.rendered_text = binary_map::render_text(s.map, s.opts);
		}

		inline void inject_to_chat(const std::string& text)
		{
			if (text.empty()) return;

			const size_t cap = sizeof(g_chat_buf) - 1u;
			const size_t cur = std::strlen(g_chat_buf);

			if (cur + text.size() < cap) {
				if (cur > 0) {
					if (cur + 2u < cap) {
						g_chat_buf[cur] = '\n';
						g_chat_buf[cur + 1u] = '\n';
						g_chat_buf[cur + 2u] = '\0';
					}
				}
				const size_t now = std::strlen(g_chat_buf);
				const size_t room = cap - now;
				const size_t copy = (text.size() < room) ? text.size() : room;
				std::memcpy(g_chat_buf + now, text.data(), copy);
				g_chat_buf[now + copy] = '\0';
				toast_notification::push("Binary map appended to chat input",
					toast_notification::toast_type_t::info, 3.0f);
			} else {
				ImGui::SetClipboardText(text.c_str());
				toast_notification::push(
					"Binary map exceeds chat buffer; copied to clipboard instead",
					toast_notification::toast_type_t::warning, 4.0f);
			}
		}

		inline void perform_refresh(view_state_t& s)
		{
			if (s.refreshing.exchange(true)) return;

			binary_map::clear_cache();

			binary_map::map_t fresh;
			binary_map::map_options_t opts_copy;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				opts_copy = s.opts;
			}

			const bool ok = binary_map::generate(opts_copy, fresh);

			std::lock_guard<std::mutex> g(s.mutex);
			if (ok) {
				s.map = std::move(fresh);
				s.has_map.store(true);
				s.last_error.clear();
				rebuild_text_locked(s);
			} else {
				s.last_error = binary_map::last_error();
			}
			s.refreshing.store(false);
		}

		inline void ensure_subscription(view_state_t& s)
		{
			if (s.subscription.valid()) return;
			s.subscription = aida::events::subscribe(
				aida::events::event_binary_loaded,
				[](const aida::events::binary_loaded_t&)
				{
					state().refresh_requested.store(true);
				});
		}

		inline ImU32 chip_color(float alpha, int kind)
		{
			switch (kind) {
			case 0:  return IM_COL32(70, 110, 170, static_cast<int>(220 * alpha));
			case 1:  return IM_COL32(140, 90, 160, static_cast<int>(220 * alpha));
			case 2:  return IM_COL32(80, 130, 90, static_cast<int>(220 * alpha));
			default: return IM_COL32(80, 80, 100, static_cast<int>(220 * alpha));
			}
		}

		inline void draw_chip(ImDrawList* dl, float x, float y, const char* label,
			ImU32 fill, ImU32 text_col)
		{
			ImVec2 ts = ImGui::CalcTextSize(label);
			const float pad = 5.f;
			const float w = ts.x + pad * 2.f;
			const float h = ts.y + 2.f;
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), fill, h * 0.5f);
			dl->AddText(ImVec2(x + pad, y + 1.f), text_col, label);
		}

		inline float draw_chip_advance(ImDrawList* dl, float x, float y, const char* label,
			ImU32 fill, ImU32 text_col)
		{
			ImVec2 ts = ImGui::CalcTextSize(label);
			const float pad = 5.f;
			const float w = ts.x + pad * 2.f;
			const float h = ts.y + 2.f;
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), fill, h * 0.5f);
			dl->AddText(ImVec2(x + pad, y + 1.f), text_col, label);
			return w;
		}

		inline void jump_to_address(uint64_t va)
		{
			if (va == 0) return;
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(va, g_disasm);
		}

		inline std::string make_function_chat_payload(const binary_map::map_function_t& f)
		{
			std::string out = "Binary map function summary:\n";
			out += format_function_summary(f);
			if (!f.section_name.empty()) {
				out += "\nSection: ";
				out += f.section_name;
			}
			if (f.pinned) out += "\n(pinned)";
			out += "\n";
			return out;
		}

		inline std::string make_global_chat_payload(const binary_map::map_global_t& g)
		{
			char buf[256];
			std::snprintf(buf, sizeof(buf),
				"Binary map global: %s @ 0x%llX (xrefs=%d, %s%s)\n",
				g.name.c_str(),
				static_cast<unsigned long long>(g.va),
				g.xref_count,
				g.writable ? "rw" : "ro",
				g.section_name.empty() ? "" : (std::string(", ") + g.section_name).c_str());
			return std::string(buf);
		}

		inline bool group_is_collapsed(view_state_t& s, const std::string& key)
		{
			return s.collapsed_groups.count(key) != 0;
		}

		inline void toggle_group(view_state_t& s, const std::string& key)
		{
			auto it = s.collapsed_groups.find(key);
			if (it == s.collapsed_groups.end())
				s.collapsed_groups.insert(key);
			else
				s.collapsed_groups.erase(it);
		}

	}

	inline void initialize()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.initialized) return;
		s.opts.max_functions = 50;
		s.opts.max_globals = 30;
		s.opts.max_callees_per_function = 5;
		s.opts.max_chars = 8192;
		s.opts.include_imports = true;
		s.opts.include_exports = true;
		detail::ensure_subscription(s);
		s.initialized = true;
	}

	inline void shutdown()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		if (s.subscription.valid()) {
			aida::events::unsubscribe(s.subscription);
			s.subscription = aida::events::subscription_handle_t{};
		}
		s.collapsed_groups.clear();
		s.expanded_imports.clear();
		s.rendered_text.clear();
		s.map = binary_map::map_t{};
		s.has_map.store(false);
		s.initialized = false;
	}

	inline const std::string& last_error()
	{
		view_state_t& s = state();
		std::lock_guard<std::mutex> g(s.mutex);
		return s.last_error;
	}

	inline void refresh()
	{
		state().refresh_requested.store(true);
	}

	inline void render(int x, int y, float w, float h,
		float anim, float anim_x, float anim_y, float anim_z)
	{
		view_state_t& s = state();
		if (!s.initialized) initialize();

		if (s.refresh_requested.exchange(false)) {
			detail::perform_refresh(s);
		}

		const float a = anim;
		const float ax = anim_x;
		const float ay = anim_y;
		const float az = anim_z;

		const auto& th = themes::resolved;
		const auto ta = [a](ImU32 c) -> ImU32 { return ui_anim::theme_alpha(c, a); };

		ImU32 bg          = ta(th.bg_base);
		ImU32 panel_hdr   = ta(th.panel_header);
		ImU32 text_main   = ta(th.text_primary);
		ImU32 text_dim    = ta(th.text_dim);
		ImU32 text_sec    = ta(th.text_secondary);
		ImU32 sep_col     = ta(ui_anim::lighten(th.panel_bg, 14));
		ImU32 row_hover   = ta(ui_anim::lighten(th.panel_header, 14));
		ImU32 accent_full = IM_COL32(
			static_cast<int>(ax * 255), static_cast<int>(ay * 255),
			static_cast<int>(az * 255), static_cast<int>(230 * a));

		ImGui::BeginChild("##binary_map_view", ImVec2(w, h), false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		const float ox = wp.x;
		const float oy = wp.y;

		dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h), bg);

		const float toolbar_h = 64.f;
		ui_anim::render_toolbar(dl, ox, oy, w, toolbar_h, ax, ay, az, a);
		dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + w, oy + toolbar_h), sep_col);

		int total_funcs = 0;
		int total_globs = 0;
		int total_imports = 0;
		int total_exports = 0;
		std::string module_name;
		std::string module_format;
		uint64_t image_base = 0;
		uint64_t image_size = 0;

		{
			std::lock_guard<std::mutex> g(s.mutex);
			total_funcs   = static_cast<int>(s.map.functions.size());
			total_globs   = static_cast<int>(s.map.globals.size());
			total_imports = static_cast<int>(s.map.imports.size());
			total_exports = static_cast<int>(s.map.exports.size());
			module_name   = s.map.module_name;
			module_format = s.map.format;
			image_base    = s.map.image_base;
			image_size    = s.map.image_size;
		}

		char val_funcs[24];   std::snprintf(val_funcs,   sizeof(val_funcs),   "%d", total_funcs);
		char val_globs[24];   std::snprintf(val_globs,   sizeof(val_globs),   "%d", total_globs);
		char val_imports[24]; std::snprintf(val_imports, sizeof(val_imports), "%d", total_imports);
		char val_exports[24]; std::snprintf(val_exports, sizeof(val_exports), "%d", total_exports);

		ui_anim::stat_strip_item_t strip_items[4] = {
			{ "Functions", val_funcs,   nullptr, 0, nullptr, 0, 0 },
			{ "Globals",   val_globs,   nullptr, 0, nullptr, 0, 0 },
			{ "Imports",   val_imports, nullptr, 0, nullptr, 0, 0 },
			{ "Exports",   val_exports, nullptr, 0, nullptr, 0, 0 },
		};

		const float strip_w = std::max(360.f, w * 0.46f);
		const float strip_x = ox + 8.f;
		const float strip_y = oy + 6.f;
		const float strip_h = 40.f;
		ui_anim::render_stat_strip(dl, strip_x, strip_y, strip_w, strip_h,
			strip_items, 4, ax, ay, az, a);

		const float btn_y = oy + 8.f;
		const float btn_h = 24.f;
		float btn_x = strip_x + strip_w + 12.f;

		ImGui::PushStyleColor(ImGuiCol_Button,        ta(th.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ta(ui_anim::lighten(th.panel_header, 18)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ta(ui_anim::lighten(th.panel_header, 28)));
		ImGui::PushStyleColor(ImGuiCol_Text,          text_main);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));

		ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
		const bool refreshing = s.refreshing.load();
		if (refreshing) ImGui::BeginDisabled();
		if (ImGui::Button("Refresh##bm_refresh", ImVec2(0.f, btn_h))) {
			s.refresh_requested.store(true);
		}
		if (refreshing) ImGui::EndDisabled();
		btn_x += ImGui::GetItemRectSize().x + 6.f;

		ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
		if (ImGui::Button("Copy entire map##bm_copy", ImVec2(0.f, btn_h))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			detail::inject_to_chat(payload);
		}
		btn_x += ImGui::GetItemRectSize().x + 6.f;

		ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
		if (ImGui::Button("Copy clipboard##bm_clip", ImVec2(0.f, btn_h))) {
			std::string payload;
			{
				std::lock_guard<std::mutex> g(s.mutex);
				if (s.rendered_text.empty()) detail::rebuild_text_locked(s);
				payload = s.rendered_text;
			}
			ImGui::SetClipboardText(payload.c_str());
			toast_notification::push("Binary map copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}

		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(4);

		const float filter_y = oy + 36.f;
		ImGui::SetCursorScreenPos(ImVec2(ox + 10.f, filter_y));
		const float filter_w = std::max(260.f, w * 0.32f);
		ui_anim::render_filter_input_chip("##bm_filter", s.filter_buf, sizeof(s.filter_buf),
			"Filter functions, globals, imports, exports...",
			filter_w, ax, ay, az, a);
		s.filter_lower = detail::to_lower_copy(std::string(s.filter_buf));

		{
			std::string mod_summary;
			if (!module_name.empty()) {
				char tmp[256];
				std::snprintf(tmp, sizeof(tmp), "%s  %s  base=0x%llX  size=%s",
					module_name.c_str(),
					module_format.empty() ? "" : module_format.c_str(),
					static_cast<unsigned long long>(image_base),
					detail::format_size_human(image_size).c_str());
				mod_summary = tmp;
			} else {
				mod_summary = refreshing ? "Building binary map..." : "(no binary loaded)";
			}
			ImVec2 mts = ImGui::CalcTextSize(mod_summary.c_str());
			dl->AddText(ImVec2(ox + w - mts.x - 12.f, filter_y + 8.f),
				text_dim, mod_summary.c_str());
		}

		const float content_y = oy + toolbar_h + 1.f;
		const float content_h = h - toolbar_h - 1.f;

		float left_w = std::max(220.f, w * s.left_split);
		if (left_w > w - 220.f) left_w = w - 220.f;
		const float right_w = w - left_w - 1.f;

		const float split_x = ox + left_w;
		dl->AddLine(ImVec2(split_x, content_y), ImVec2(split_x, content_y + content_h), sep_col);
		{
			ImGui::SetCursorScreenPos(ImVec2(split_x - 3.f, content_y));
			ImGui::InvisibleButton("##bm_splitter", ImVec2(6.f, content_h));
			if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
				const float dx = ImGui::GetIO().MouseDelta.x;
				const float new_left = left_w + dx;
				if (new_left >= 200.f && new_left <= w - 220.f) {
					s.left_split = new_left / std::max(1.f, w);
				}
			}
			if (ImGui::IsItemHovered()) {
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
			}
		}

		ui_anim::render_panel_card(dl, ox + 4.f, content_y + 4.f,
			left_w - 8.f, content_h - 8.f, ax, ay, az, a, 6.f, false);

		ImGui::SetCursorPos(ImVec2(static_cast<float>(x) + 8.f,
			static_cast<float>(y) + toolbar_h + 6.f));
		ImGui::BeginChild("##bm_left_list", ImVec2(left_w - 16.f, content_h - 12.f),
			false, ImGuiWindowFlags_HorizontalScrollbar);

		s.row_anim_time += ImGui::GetIO().DeltaTime;
		const float row_anim = s.row_anim_time;

		std::lock_guard<std::mutex> g(s.mutex);

		const std::string filter_lower = s.filter_lower;
		bool refresh_after_pin = false;

		auto draw_section_header = [&](const char* title, int count_value, const std::string& key) -> bool {
			char hbuf[160];
			std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)", title, count_value);
			const bool collapsed = detail::group_is_collapsed(s, key);
			ImVec2 cp = ImGui::GetCursorScreenPos();
			float row_w = left_w - 16.f;
			float row_h = 22.f;
			bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
			ImU32 fill = hov ? row_hover : panel_hdr;
			dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 4.f);
			dl->AddText(ImVec2(cp.x + 22.f, cp.y + 3.f), text_main, hbuf);
			const char* arrow = collapsed ? "+" : "-";
			dl->AddText(ImVec2(cp.x + 8.f, cp.y + 3.f), accent_full, arrow);
			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				detail::toggle_group(s, key);
			}
			ImGui::Dummy(ImVec2(row_w, row_h + 2.f));
			return !collapsed;
		};

		if (draw_section_header("Sections", static_cast<int>(s.map.sections.size()), "sections")) {
			int idx = 0;
			for (const auto& sec : s.map.sections) {
				if (!detail::filter_matches(filter_lower, sec.name)) continue;
				char line[256];
				std::snprintf(line, sizeof(line), "  %-10s 0x%llX  %s  [%s]",
					sec.name.c_str(),
					static_cast<unsigned long long>(sec.va),
					detail::format_size_human(sec.size).c_str(),
					detail::section_perm_string(sec).c_str());
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = left_w - 20.f;
				float row_h = 20.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				float entrance = ui_anim::render_row_entrance(idx++, row_anim, 0.012f);
				ui_anim::table_row_style_t rs{};
				rs.selected = false;
				rs.hovered = hov;
				rs.index = idx;
				rs.alpha = a;
				rs.entrance = entrance;
				rs.ar = ax; rs.ag = ay; rs.ab = az;
				ui_anim::render_table_row(dl, cp.x, cp.y, row_w, row_h, rs);
				dl->AddText(ImVec2(cp.x + 4.f, cp.y + 2.f), text_main, line);
				ImGui::Dummy(ImVec2(row_w, row_h));
			}
		}

		if (draw_section_header("Functions", static_cast<int>(s.map.functions.size()), "functions")) {
			int idx = 0;
			const uint64_t selected_va = s.selected_va.load();
			for (auto& fn : s.map.functions) {
				if (!detail::filter_matches(filter_lower, fn.name)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = left_w - 20.f;
				float row_h = 26.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				bool sel = (selected_va == fn.va) && (fn.va != 0);

				float entrance = ui_anim::render_row_entrance(idx, row_anim, 0.012f);
				ui_anim::table_row_style_t rs{};
				rs.selected = sel;
				rs.hovered = hov;
				rs.index = idx;
				rs.alpha = a;
				rs.entrance = entrance;
				rs.ar = ax; rs.ag = ay; rs.ab = az;
				ui_anim::render_table_row(dl, cp.x, cp.y, row_w, row_h, rs);

				const char* star = fn.pinned ? "*" : "+";
				ImU32 star_col = fn.pinned ? accent_full : text_dim;
				dl->AddText(ImVec2(cp.x + 6.f, cp.y + 3.f), star_col, star);

				ImGui::SetCursorScreenPos(ImVec2(cp.x + 4.f, cp.y + 2.f));
				ImGui::PushID(static_cast<int>(idx));
				if (ImGui::InvisibleButton("##bm_pin_btn", ImVec2(18.f, row_h - 4.f))) {
					if (fn.pinned) binary_map::unpin_function(fn.va);
					else           binary_map::pin_function(fn.va);
					refresh_after_pin = true;
				}
				ImGui::PopID();

				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(fn.va));
				dl->AddText(ImVec2(cp.x + 26.f, cp.y + 2.f), accent_full, addr_buf);

				dl->AddText(ImVec2(cp.x + 26.f + 100.f, cp.y + 2.f),
					text_main, fn.name.c_str());

				char chip_xref[24];
				std::snprintf(chip_xref, sizeof(chip_xref), "x:%d", fn.xref_count);
				char chip_call[24];
				std::snprintf(chip_call, sizeof(chip_call), "c:%d", fn.callee_count);

				float chip_y = cp.y + row_h - ImGui::GetTextLineHeight() - 3.f;
				float chip_x = cp.x + 26.f + 100.f;
				chip_x += detail::draw_chip_advance(dl, chip_x, chip_y, chip_xref,
					detail::chip_color(a, 0), text_main) + 4.f;
				chip_x += detail::draw_chip_advance(dl, chip_x, chip_y, chip_call,
					detail::chip_color(a, 1), text_main) + 4.f;

				for (size_t k = 0; k < fn.top_callees.size() && k < 3; ++k) {
					const std::string& nm = fn.top_callees[k];
					const float w_left = (cp.x + row_w) - chip_x - 6.f;
					if (w_left <= 30.f) break;
					std::string trimmed = nm;
					if (trimmed.size() > 18) trimmed = trimmed.substr(0, 17) + ".";
					chip_x += detail::draw_chip_advance(dl, chip_x, chip_y, trimmed.c_str(),
						detail::chip_color(a, 2), text_main) + 4.f;
				}

				ImGui::SetCursorScreenPos(ImVec2(cp.x + 26.f, cp.y));
				ImGui::PushID(static_cast<int>(0x40000000 | idx));
				ImGui::InvisibleButton("##bm_fn_row", ImVec2(row_w - 26.f, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					s.selected_va.store(fn.va);
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					s.ctx_target.store(idx);
					s.ctx_va = fn.va;
					ImGui::OpenPopup("##bm_fn_ctx");
				}
				if (ImGui::BeginPopup("##bm_fn_ctx")) {
					if (ImGui::MenuItem("Copy summary to chat")) {
						std::string payload = detail::make_function_chat_payload(fn);
						detail::inject_to_chat(payload);
					}
					if (ImGui::MenuItem(fn.pinned ? "Unpin" : "Pin")) {
						if (fn.pinned) binary_map::unpin_function(fn.va);
						else           binary_map::pin_function(fn.va);
						refresh_after_pin = true;
					}
					if (ImGui::MenuItem("Jump to address")) {
						const uint64_t va = fn.va;
						ImGui::CloseCurrentPopup();
						detail::jump_to_address(va);
					}
					ImGui::EndPopup();
				}
				ImGui::PopID();

				ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + row_h));
				++idx;
			}
		}

		if (draw_section_header("Globals", static_cast<int>(s.map.globals.size()), "globals")) {
			int idx = 0;
			for (const auto& gl : s.map.globals) {
				if (!detail::filter_matches(filter_lower, gl.name)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = left_w - 20.f;
				float row_h = 22.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				float entrance = ui_anim::render_row_entrance(idx, row_anim, 0.012f);
				ui_anim::table_row_style_t rs{};
				rs.selected = false;
				rs.hovered = hov;
				rs.index = idx;
				rs.alpha = a;
				rs.entrance = entrance;
				rs.ar = ax; rs.ag = ay; rs.ab = az;
				ui_anim::render_table_row(dl, cp.x, cp.y, row_w, row_h, rs);

				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
					static_cast<unsigned long long>(gl.va));
				dl->AddText(ImVec2(cp.x + 6.f, cp.y + 2.f), accent_full, addr_buf);
				dl->AddText(ImVec2(cp.x + 110.f, cp.y + 2.f), text_main, gl.name.c_str());

				char chip_buf[24];
				std::snprintf(chip_buf, sizeof(chip_buf), "x:%d", gl.xref_count);
				detail::draw_chip(dl, cp.x + row_w - 56.f, cp.y + 4.f, chip_buf,
					detail::chip_color(a, 0), text_main);

				const char* perm = gl.writable ? "rw" : "ro";
				dl->AddText(ImVec2(cp.x + row_w - 22.f, cp.y + 2.f), text_dim, perm);

				ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y));
				ImGui::PushID(static_cast<int>(0x50000000 | idx));
				ImGui::InvisibleButton("##bm_gl_row", ImVec2(row_w, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
					ImGui::OpenPopup("##bm_gl_ctx");
				}
				if (ImGui::BeginPopup("##bm_gl_ctx")) {
					if (ImGui::MenuItem("Copy summary to chat")) {
						std::string payload = detail::make_global_chat_payload(gl);
						detail::inject_to_chat(payload);
					}
					if (ImGui::MenuItem("Jump to address")) {
						const uint64_t va = gl.va;
						ImGui::CloseCurrentPopup();
						detail::jump_to_address(va);
					}
					ImGui::EndPopup();
				}
				ImGui::PopID();
				ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + row_h));
				++idx;
			}
		}

		if (draw_section_header("Imports", total_imports, "imports")) {
			int imp_idx = 0;
			for (const auto& imp : s.map.imports) {
				const auto colon = imp.find(':');
				const std::string dll = (colon == std::string::npos) ? imp : imp.substr(0, colon);
				std::string func_list;
				if (colon != std::string::npos && colon + 1 < imp.size()) {
					size_t start = colon + 1;
					while (start < imp.size() && imp[start] == ' ') ++start;
					func_list = imp.substr(start);
				}

				std::vector<std::string> funcs;
				{
					size_t pos = 0;
					while (pos < func_list.size()) {
						size_t next = func_list.find(',', pos);
						if (next == std::string::npos) next = func_list.size();
						std::string token = func_list.substr(pos, next - pos);
						while (!token.empty() && token.front() == ' ') token.erase(token.begin());
						while (!token.empty() && token.back() == ' ') token.pop_back();
						if (!token.empty()) funcs.push_back(std::move(token));
						pos = next + 1u;
					}
				}

				bool any_match = detail::filter_matches(filter_lower, dll);
				if (!any_match) {
					for (const auto& fn : funcs) {
						if (detail::filter_matches(filter_lower, fn)) {
							any_match = true;
							break;
						}
					}
				}
				if (!any_match) continue;

				const std::string key = std::string("imports::") + dll;
				bool collapsed = detail::group_is_collapsed(s, key);

				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = left_w - 20.f;
				float row_h = 20.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				ImU32 fill = hov ? row_hover : ta(ui_anim::lighten(th.panel_bg, 14));
				dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), fill, 3.f);
				const char* arrow = collapsed ? "+" : "-";
				dl->AddText(ImVec2(cp.x + 12.f, cp.y + 2.f), accent_full, arrow);
				char hbuf[200];
				std::snprintf(hbuf, sizeof(hbuf), "%s  (%d)",
					dll.c_str(), static_cast<int>(funcs.size()));
				dl->AddText(ImVec2(cp.x + 28.f, cp.y + 2.f), text_main, hbuf);

				ImGui::SetCursorScreenPos(cp);
				ImGui::PushID(static_cast<int>(0x60000000 | imp_idx));
				ImGui::InvisibleButton("##bm_imp_hdr", ImVec2(row_w, row_h));
				if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
					detail::toggle_group(s, key);
				}
				ImGui::PopID();

				if (!collapsed) {
					for (const auto& fn : funcs) {
						if (!detail::filter_matches(filter_lower, fn) &&
							!detail::filter_matches(filter_lower, dll)) continue;
						ImVec2 ip = ImGui::GetCursorScreenPos();
						dl->AddText(ImVec2(ip.x + 32.f, ip.y + 2.f), text_sec, fn.c_str());
						ImGui::Dummy(ImVec2(row_w, row_h - 2.f));
					}
				}
				++imp_idx;
			}
		}

		if (draw_section_header("Exports", total_exports, "exports")) {
			int idx = 0;
			for (const auto& ex : s.map.exports) {
				if (!detail::filter_matches(filter_lower, ex)) continue;
				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = left_w - 20.f;
				float row_h = 18.f;
				bool hov = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h), true);
				ui_anim::table_row_style_t rs{};
				rs.selected = false;
				rs.hovered = hov;
				rs.index = idx;
				rs.alpha = a;
				rs.entrance = ui_anim::render_row_entrance(idx, row_anim, 0.012f);
				rs.ar = ax; rs.ag = ay; rs.ab = az;
				ui_anim::render_table_row(dl, cp.x, cp.y, row_w, row_h, rs);
				dl->AddText(ImVec2(cp.x + 12.f, cp.y + 1.f), text_main, ex.c_str());
				ImGui::Dummy(ImVec2(row_w, row_h));
				++idx;
			}
		}

		if (s.map.functions.empty() && !refreshing) {
			ImVec2 cp = ImGui::GetCursorScreenPos();
			ui_anim::render_empty_state(dl, cp.x, cp.y,
				left_w - 24.f, std::max(120.f, content_h * 0.5f),
				s.last_error.empty()
					? "Load a binary and press Refresh to build the map."
					: s.last_error.c_str(),
				ax, ay, az, a, static_cast<float>(ImGui::GetTime()));
		}

		ImGui::EndChild();

		const float right_x = ox + left_w + 1.f;
		ui_anim::render_panel_card(dl, right_x + 4.f, content_y + 4.f,
			right_w - 8.f, content_h - 8.f, ax, ay, az, a, 6.f, false);

		dl->AddText(ImVec2(right_x + 12.f, content_y + 8.f), text_sec, "LLM Preview");

		const float preview_btn_w = 100.f;
		ImGui::SetCursorScreenPos(ImVec2(right_x + right_w - preview_btn_w - 12.f,
			content_y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_Button,        ta(th.panel_header));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ta(ui_anim::lighten(th.panel_header, 18)));
		ImGui::PushStyleColor(ImGuiCol_Text,          text_main);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 3.f));
		if (ImGui::Button("Copy##bm_preview_copy", ImVec2(preview_btn_w, 0.f))) {
			ImGui::SetClipboardText(s.rendered_text.c_str());
			toast_notification::push("Preview copied to clipboard",
				toast_notification::toast_type_t::info, 3.0f);
		}
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);

		ImGui::SetCursorScreenPos(ImVec2(right_x + 8.f, content_y + 32.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ta(ui_anim::lighten(th.panel_bg, 4)));
		ImGui::PushStyleColor(ImGuiCol_Border,  sep_col);
		ImGui::PushStyleColor(ImGuiCol_Text,    text_main);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

		ImFont* mono = g_code_font ? g_code_font : ImGui::GetFont();
		ImGui::PushFont(mono);

		const float preview_w = right_w - 16.f;
		const float preview_h = content_h - 44.f;
		std::string preview_data = s.rendered_text;
		if (preview_data.empty()) {
			preview_data = refreshing ? "Building binary map..." : "(map empty)";
		}
		std::vector<char> ro_buf(preview_data.size() + 1u);
		std::memcpy(ro_buf.data(), preview_data.data(), preview_data.size());
		ro_buf[preview_data.size()] = '\0';
		ImGui::InputTextMultiline("##bm_preview", ro_buf.data(), ro_buf.size(),
			ImVec2(preview_w, preview_h),
			ImGuiInputTextFlags_ReadOnly);

		ImGui::PopFont();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);

		ImGui::EndChild();

		if (refresh_after_pin) {
			s.refresh_requested.store(true);
		}

		if (!s.auto_refreshed_once && !refreshing) {
			s.auto_refreshed_once = true;
			s.refresh_requested.store(true);
		}
	}

}
}
