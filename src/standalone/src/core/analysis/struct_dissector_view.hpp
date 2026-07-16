#pragma once

#include "struct_dissector.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#endif
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/responsive.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/ui_anim.hpp"
#include "ui/toast_notification.hpp"
#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#include "imgui/imgui.h"
#include "../helpers/globals.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#include "../anti-tamper/webhook.hpp"
#endif

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace struct_dissector_view {

struct field_anim_t {
	aida::ui::flash_t change_flash;
	aida::ui::flash_t write_success;
	std::vector<uint8_t> last_bytes;
	bool                  has_last = false;
	aida::ui::transition_t expand;
	bool                  expanded = false;
};

enum class edit_target_t : int {
	none = 0,
	field_name,
	field_size,
	field_comment,
	struct_name,
};

struct ui_state_t {
	int   active_tab = 0;
	int   selected_field = -1;
	std::vector<bool> field_expand;
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	float list_scroll_y = 0.f;
	float list_target_scroll_y = 0.f;
	char  name_buf[128] = {};
	char  field_name_buf[128] = {};
	char  offset_buf[32] = {};
	char  size_buf[32] = {};
	char  edit_value_buf[256] = {};
	char  addr_buf[20] = {};
	char  rename_buf[128] = {};
	char  list_filter[96] = {};
	int   editing_field = -1;
	int   add_type = 0;
	int   selected_struct = -1;
	bool  sb_dragging = false;
	float sb_drag_offset = 0.f;
	bool  list_sb_dragging = false;
	float list_sb_drag_offset = 0.f;
	float row_anim_time = 0.f;
	std::unordered_map<int, field_anim_t> field_anims;
	float edit_ring_phase = 0.f;
	bool  addr_buf_seeded = false;
	edit_target_t edit_target = edit_target_t::none;
	int   edit_target_field = -1;
	bool  table_focused = false;
	uint64_t context_refresh_seq = 0;
	uint64_t context_base_address = 0;
	uint32_t context_target_pid = 0;
	uint32_t edit_target_pid = 0;
	uint64_t edit_base_address = 0;
	int pending_remove_field = -1;
};

inline ui_state_t g_ui;

inline void publish_field_selection(const std::string& structure_name,
	const struct_dissector::field_def_t& field) {
	auto context = disasm_view::capture_selected_workspace();
	if (!context.workspace)
		return;
	aida::workbench::selection_context_t selection;
	selection.kind = aida::workbench::selection_kind_t::entity;
	selection.entity_key = "structure.dissector." + structure_name + ".field." +
		std::to_string(field.offset);
	aida::workbench::document_local_cursor_t cursor;
	cursor.has_position = true;
	cursor.position = field.offset;
	aida::workbench::workbench_shell_workspace_context_t workbench;
	static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
		.publish_selection(context.workspace, selection, cursor,
			aida::workbench::navigation_origin_t::inspector, workbench));
}

inline ImU32 type_color_token(struct_dissector::field_type_t tp, float alpha) {
	const auto& th = aida::ui::resolved();
	ImU32 base;
	switch (tp) {
		case struct_dissector::field_type_t::pointer:        base = th.syn_function; break;
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string:   base = th.syn_string;   break;
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64:        base = th.syn_number;   break;
		case struct_dissector::field_type_t::padding:        base = th.text_dim;     break;
		case struct_dissector::field_type_t::nested_struct:  base = th.syn_keyword;  break;
		case struct_dissector::field_type_t::byte_array:     base = th.warning;      break;
		case struct_dissector::field_type_t::int8:
		case struct_dissector::field_type_t::int16:
		case struct_dissector::field_type_t::int32:
		case struct_dissector::field_type_t::int64:
		case struct_dissector::field_type_t::uint8:
		case struct_dissector::field_type_t::uint16:
		case struct_dissector::field_type_t::uint32:
		case struct_dissector::field_type_t::uint64:         base = th.syn_number;   break;
		default:                                             base = th.text_primary; break;
	}
	return aida::ui::with_alpha(base, alpha);
}

inline void render_type_glyph(ImDrawList* dl, ImVec2 center,
                              struct_dissector::field_type_t tp, ImU32 color)
{
	switch (tp) {
		case struct_dissector::field_type_t::pointer: {
			dl->AddCircle(center, 5.f, color, 12, 1.2f);
			ImVec2 tip = ImVec2(center.x + 7.f, center.y);
			dl->AddLine(center, tip, color, 1.2f);
			dl->AddTriangleFilled(
				ImVec2(tip.x - 3.f, center.y - 3.f),
				ImVec2(tip.x + 1.f, center.y),
				ImVec2(tip.x - 3.f, center.y + 3.f), color);
			break;
		}
		case struct_dissector::field_type_t::ascii_string:
		case struct_dissector::field_type_t::utf16_string: {
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 1.f),
				ImVec2(center.x + 5.f, center.y + 1.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y + 3.f),
				ImVec2(center.x + 3.f, center.y + 5.f), color, 1.f);
			dl->AddRectFilled(ImVec2(center.x - 5.f, center.y - 5.f),
				ImVec2(center.x + 4.f, center.y - 3.f), color, 1.f);
			break;
		}
		case struct_dissector::field_type_t::float32:
		case struct_dissector::field_type_t::float64: {
			dl->AddText(ImGui::GetFont(), aida::ui::components::detail::ui_fs() * 0.85f,
				ImVec2(center.x - 5.f, center.y - 7.f), color, "f");
			break;
		}
		case struct_dissector::field_type_t::nested_struct: {
			ImVec2 a = ImVec2(center.x - 5.f, center.y - 5.f);
			ImVec2 b = ImVec2(center.x + 5.f, center.y + 5.f);
			dl->AddRect(a, b, color, 1.5f, 0, 1.f);
			dl->AddLine(ImVec2(a.x + 2.f, center.y), ImVec2(b.x - 2.f, center.y), color, 1.f);
			break;
		}
		default: {
			dl->AddCircleFilled(center, 2.f, color, 12);
			break;
		}
	}
}

inline field_anim_t& fanim(int idx) { return g_ui.field_anims[idx]; }

inline void render(float pos_x, float pos_y, float width, float height,
				   float alpha, float accent_r, float accent_g, float accent_b) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	struct_dissector::ensure_preview_fixture();
	if (struct_dissector::g_state.cached_values.empty())
		struct_dissector::refresh_values();
#else
	{
		static bool s_types_font_logged_dissector = false;
		if (!s_types_font_logged_dissector) {
			s_types_font_logged_dissector = true;
			anti_tamper::webhook::write_log("types_font", "[types_font] scaled struct_dissector_view");
		}
	}
#endif

	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowPos().x + pos_x,
	                                 ImGui::GetWindowPos().y + pos_y));

	ImGui::BeginChild("##struct_dissector_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto& ui = g_ui;
	auto& st = struct_dissector::g_state;
	const float dt = aida::ui::clock::dt();
	const float line_h = 36.f;
	const float top_bar_h = 52.f;

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wpos = ImGui::GetWindowPos();
	float ox = wpos.x;
	float oy = wpos.y;

	ui.row_anim_time += dt;
	ui.edit_ring_phase += dt;

	const auto& th = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + top_bar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + top_bar_h - 1.f), ImVec2(ox + width, oy + top_bar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float bx = ox + 12.f;
	float by = oy + 12.f;

	const float fs_diss_base = aida::ui::components::detail::ui_fs();
	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		fs_diss_base * 1.05f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_secondary, alpha), "Base");
	bx += 48.f;

	if (!ui.addr_buf_seeded) {
		uint64_t seed = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			seed = st.base_address;
		}
		if (seed != 0) {
			std::snprintf(ui.addr_buf, sizeof(ui.addr_buf), "%llX",
				static_cast<unsigned long long>(seed));
		}
		ui.addr_buf_seeded = true;
	}

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushItemWidth(170.f);
	if (ImGui::InputText("##sd_addr", ui.addr_buf, sizeof(ui.addr_buf),
						 ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			uint64_t prev = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				prev = st.base_address;
				st.base_address = addr;
			}
			diag::log_tagged_fmt("dissector",
				"base_address_changed prev=0x%llX new=0x%llX",
				static_cast<unsigned long long>(prev),
				static_cast<unsigned long long>(addr));
		} else {
			diag::log_tagged_fmt("dissector",
				"base_address_parse_failed input='%s'", ui.addr_buf);
		}
	}
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);
	bx += 180.f + 6.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Go", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(48.f, 28.f))) {
		uint64_t addr = 0;
		if (std::sscanf(ui.addr_buf, "%llx", reinterpret_cast<unsigned long long*>(&addr)) == 1) {
			uint64_t prev = 0;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				prev = st.base_address;
				st.base_address = addr;
			}
			diag::log_tagged_fmt("dissector",
				"base_address_go prev=0x%llX new=0x%llX",
				static_cast<unsigned long long>(prev),
				static_cast<unsigned long long>(addr));
			struct_dissector::refresh_values();
		} else {
			diag::log_tagged_fmt("dissector",
				"base_address_go_failed input='%s'", ui.addr_buf);
		}
	}
	bx += 56.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Refresh", aida::ui::button_kind_t::primary,
		aida::ui::size_t_::sm, ImVec2(96.f, 28.f))) {
		diag::log_tagged_fmt("dissector", "refresh_clicked manual=1");
		struct_dissector::refresh_values();
	}
	bx += 102.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	{
		bool auto_now = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto_now = st.auto_refresh;
		}
		if (aida::ui::toggle_switch("##sd_auto", &auto_now, aida::ui::size_t_::sm)) {
			std::lock_guard<std::mutex> lk(st.mtx);
			st.auto_refresh = auto_now;
		}
	}
	bx += 38.f;
	dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
		fs_diss_base * 0.92f, ImVec2(bx, by + 4.f),
		aida::ui::with_alpha(th.text_dim, alpha), "Auto");
	bx += 42.f + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(bx, by));
	if (aida::ui::button("Export C", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
		int aidx = -1;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			aidx = st.active_struct;
		}
		if (aidx >= 0) {
			std::string c_src = struct_dissector::export_to_c(aidx);
			if (!c_src.empty()) {
				ImGui::SetClipboardText(c_src.c_str());
				diag::log_tagged_fmt("dissector",
					"export_to_c_clipboard idx=%d bytes=%zu",
					aidx, c_src.size());
			}
		} else {
			diag::log_tagged_fmt("dissector",
				"export_to_c_clicked_no_active");
		}
	}

	{
		bool auto_now_snap = false;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			auto_now_snap = st.auto_refresh;
			if (auto_now_snap) {
				st.refresh_timer += dt;
				if (st.refresh_timer >= st.refresh_interval) {
					st.refresh_timer = 0.f;
					auto_now_snap = true;
				} else {
					auto_now_snap = false;
				}
			}
		}
		if (auto_now_snap) {
			struct_dissector::refresh_values();
		}
	}

	float body_y = oy + top_bar_h + 4.f;
	float body_h = height - top_bar_h - 4.f;

	bool driver_loaded = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	driver_loaded = driver_bridge::is_loaded();
#endif
	if (!driver_loaded) {
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static bool s_no_driver_logged_diss = false;
		if (!s_no_driver_logged_diss) {
			s_no_driver_logged_diss = true;
			anti_tamper::webhook::write_log("types_audit",
				"[types_audit] dissector_view_no_driver reason='driver_not_loaded'");
		}
#endif
		float callout_h = 36.f;
		ui_anim::render_inline_callout(dl, ox + 8.f, body_y + 4.f, width - 16.f, callout_h,
			"Dissector live values need an attached process. Attach via the debugger to enable Read/Write.",
			ui_anim::callout_kind_t::warn,
			accent_r, accent_g, accent_b, alpha);
		body_y += callout_h + 8.f;
		body_h -= callout_h + 8.f;
	}

	const float kMinDissPanelW = 460.f;
	if (width < kMinDissPanelW) {
		static bool s_logged_diss_narrow = false;
		if (!s_logged_diss_narrow) {
			s_logged_diss_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"struct_dissector_view clamp_overlay width=%.0f min=%.0f",
				width, kMinDissPanelW);
		}
		ImVec2 wp = ImGui::GetWindowPos();
		aida::ui::responsive::draw_clamp_overlay(
			ImVec2(wp.x + pos_x, wp.y + body_y),
			ImVec2(width, body_h),
			"Widen the panel to view the struct dissector");
		return;
	}

	float left_w = std::floor(width * 0.28f);
	if (left_w < 200.f) left_w = 200.f;
	float right_min_w = 240.f;
	if (width - left_w - 1.f < right_min_w) {
		left_w = std::max(160.f, width - right_min_w - 1.f);
	}
	float right_w = width - left_w - 1.f;

	dl->AddLine(ImVec2(ox + left_w, body_y), ImVec2(ox + left_w, body_y + body_h),
		aida::ui::with_alpha(th.border_subtle, alpha));

	{
		float lx = ox;
		float ly = body_y;
		float lw = left_w;
		float lh = body_h;

		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			fs_diss_base * 0.95f, ImVec2(lx + 10.f, ly + 8.f),
			aida::ui::with_alpha(th.text_secondary, alpha), "Structures");

		float filter_y = ly + 30.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, filter_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw - 16.f);
		ImGui::InputTextWithHint("##sd_list_filter", "filter structures",
			ui.list_filter, sizeof(ui.list_filter));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		float list_y = filter_y + 32.f;
		float list_h = lh - (list_y - ly) - (line_h * 2.f + 16.f);

		ui.list_scroll_y = aida::motion::smooth_lerp(ui.list_scroll_y,
			ui.list_target_scroll_y, 18.f, dt);

		bool list_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h));
		if (list_hovered) {
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.list_target_scroll_y -= wheel * line_h * 3.f;
		}

		std::vector<std::pair<std::string, uint32_t>> entries;
		std::vector<int> entry_index;
		int active_struct_idx = -1;
		std::string filter_lc;
		filter_lc.reserve(64);
		for (std::size_t i = 0; i < sizeof(ui.list_filter) && ui.list_filter[i] != '\0'; ++i) {
			char c = ui.list_filter[i];
			if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
			filter_lc.push_back(c);
		}
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			active_struct_idx = st.active_struct;
			entries.reserve(st.structs.size());
			entry_index.reserve(st.structs.size());
			for (std::size_t i = 0; i < st.structs.size(); ++i) {
				auto& sd = st.structs[i];
				if (!filter_lc.empty()) {
					std::string name_lc;
					name_lc.reserve(sd.name.size());
					for (char c : sd.name) {
						if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
						name_lc.push_back(c);
					}
					if (name_lc.find(filter_lc) == std::string::npos) continue;
				}
				if (!struct_dissector::index_fits_int(i)) break;
				entries.emplace_back(sd.name, sd.total_size);
				entry_index.push_back(static_cast<int>(i));
			}
		}
		const std::size_t struct_count = entries.size();

		float content_h = static_cast<float>(struct_count) * line_h;
		if (ui.list_target_scroll_y < 0.f) ui.list_target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - list_h);
		if (ui.list_target_scroll_y > ms) ui.list_target_scroll_y = ms;

		ImGui::PushClipRect(ImVec2(lx, list_y), ImVec2(lx + lw, list_y + list_h), true);
		if (struct_count == 0) {
			ImFont* hint_font = aida::ui::fonts::body_em();
			if (!hint_font) hint_font = ImGui::GetFont();
			const char* msg = filter_lc.empty() ? "No structs yet" : "No matches";
			const float fs_hint = fs_diss_base * 1.00f;
			ImVec2 sz = hint_font->CalcTextSizeA(fs_hint, FLT_MAX, 0.f, msg);
			dl->AddText(hint_font, fs_hint,
				ImVec2(lx + (lw - sz.x) * 0.5f, list_y + list_h * 0.5f - sz.y * 0.5f),
				aida::ui::with_alpha(th.text_dim, alpha), msg);
		}
		for (std::size_t i = 0; i < struct_count; ++i) {
			int sd_idx = entry_index[i];
			float ry = list_y + static_cast<float>(i) * line_h - ui.list_scroll_y;
			if (ry + line_h < list_y || ry > list_y + list_h) continue;

			ImVec2 a = ImVec2(lx + 4.f, ry);
			ImVec2 b = ImVec2(lx + lw - 4.f, ry + line_h);
			bool hov = ImGui::IsMouseHoveringRect(a, b, true);
			bool sel = (active_struct_idx == sd_idx);

			ImU32 fill = sel
				? aida::ui::with_alpha(th.selection, alpha)
				: (hov ? aida::ui::with_alpha(th.hover_wash, alpha * 0.6f) : 0u);
			if ((fill & 0xFF000000) != 0) {
				dl->AddRectFilled(a, b, fill, 6.f);
			}
			if (sel) {
				dl->AddRectFilled(ImVec2(a.x, a.y),
					ImVec2(a.x + 3.f, b.y), aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
			}

			if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
				std::string sel_name;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					st.active_struct = sd_idx;
					if (struct_dissector::valid_index(sd_idx, st.structs.size())) {
						sel_name = st.structs[static_cast<std::size_t>(sd_idx)].name;
					}
					ui.selected_field = -1;
					ui.editing_field = -1;
					ui.edit_target = edit_target_t::none;
				}
				diag::log_tagged_fmt("dissector",
					"struct_selected idx=%d name='%s'",
					sd_idx, sel_name.c_str());
			}

			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				fs_diss_base * 1.05f, ImVec2(a.x + 10.f, ry + 5.f),
				aida::ui::with_alpha(th.text_primary, alpha),
				entries[i].first.c_str());
			char sz_buf[32];
			std::snprintf(sz_buf, sizeof(sz_buf), "(%u)", entries[i].second);
			ImFont* code_font = aida::ui::fonts::code();
			if (!code_font) code_font = ImGui::GetFont();
			const float fs_diss_count = fs_diss_base * 0.92f;
			ImVec2 sz = code_font->CalcTextSizeA(fs_diss_count, FLT_MAX, 0.f, sz_buf);
			dl->AddText(code_font, fs_diss_count, ImVec2(b.x - sz.x - 8.f, ry + 6.f),
				aida::ui::with_alpha(th.text_dim, alpha), sz_buf);
		}
		ImGui::PopClipRect();

		float ren_y = ly + lh - line_h * 2.f - 8.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, ren_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw - 16.f - 64.f - 4.f);
		ImGui::InputTextWithHint("##sd_rename", "rename selected",
			ui.rename_buf, sizeof(ui.rename_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();
		ImGui::SameLine();
		if (aida::ui::button("Rename", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(64.f, 28.f))) {
			int target_idx = -1;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				target_idx = st.active_struct;
			}
			if (target_idx >= 0 && ui.rename_buf[0] != '\0') {
				if (struct_dissector::rename_struct(target_idx, ui.rename_buf)) {
					ui.rename_buf[0] = '\0';
				}
			} else {
				diag::log_tagged_fmt("dissector",
					"rename_struct_skipped reason='%s'",
					target_idx < 0 ? "no_active" : "empty_name");
			}
		}

		float btn_y = ly + lh - line_h + 2.f;
		ImGui::SetCursorScreenPos(ImVec2(lx + 8.f, btn_y));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushItemWidth(lw * 0.5f);
		ImGui::InputTextWithHint("##sd_newname", "name", ui.name_buf, sizeof(ui.name_buf));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		ImGui::SameLine();
		if (aida::ui::button("+", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			if (ui.name_buf[0] != '\0') {
				int new_idx = struct_dissector::create_struct(ui.name_buf);
				if (new_idx >= 0) {
					std::lock_guard<std::mutex> lk(st.mtx);
					st.active_struct = new_idx;
					ui.selected_field = -1;
					ui.editing_field = -1;
				}
				ui.name_buf[0] = '\0';
			} else {
				diag::log_tagged_fmt("dissector",
					"create_struct_skipped reason='empty_name'");
			}
		}
		ImGui::SameLine();
		if (aida::ui::button("-", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(28.f, 28.f))) {
			std::string deleted_name;
			int removed_idx = -1;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(st.active_struct, st.structs.size())) {
					removed_idx = st.active_struct;
					const auto struct_index = static_cast<std::size_t>(st.active_struct);
					deleted_name = st.structs[struct_index].name;
					st.structs.erase(st.structs.begin() + static_cast<std::ptrdiff_t>(struct_index));
					if (!struct_dissector::valid_index(st.active_struct, st.structs.size())) {
						const std::size_t next_index = st.structs.empty() ? 0U : st.structs.size() - 1U;
						st.active_struct = !st.structs.empty() && struct_dissector::index_fits_int(next_index)
							? static_cast<int>(next_index)
							: -1;
					}
					ui.selected_field = -1;
					ui.editing_field = -1;
					ui.edit_target = edit_target_t::none;
					st.cached_values.clear();
				}
			}
			if (removed_idx >= 0) {
				diag::log_tagged_fmt("dissector",
					"delete_struct idx=%d name='%s'", removed_idx, deleted_name.c_str());
			} else {
				diag::log_tagged_fmt("dissector",
					"delete_struct_skipped reason='no_active'");
			}
		}
	}

	{
		float rx = ox + left_w + 1.f;
		float ry_start = body_y;
		float rw = right_w;
		float rh = body_h;

		int active_idx = -1;
		std::size_t field_count = 0;
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			active_idx = st.active_struct;
			if (struct_dissector::valid_index(active_idx, st.structs.size()))
				field_count = st.structs[static_cast<std::size_t>(active_idx)].fields.size();
		}

		if (active_idx < 0) {
			ImVec2 sz = ImVec2(rw, rh);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::memory;
			cfg.title = "No struct selected";
			cfg.body = "Create or select a struct from the list to begin dissecting memory.";
			cfg.max_width = 320.f;
			aida::ui::empty_state::render(ImVec2(rx, ry_start), sz, cfg);
			ImGui::EndChild();
			return;
		}

		const float col_offset_w = 92.f;
		const float col_glyph_w  = 28.f;
		const float col_name_w   = 260.f;
		const float col_type_w   = 144.f;
		const float col_value_w  = std::max(200.f, rw - col_offset_w - col_glyph_w
		                          - col_name_w - col_type_w - 180.f - 12.f);
		const float col_desc_w   = 180.f;

		float hdr_y = ry_start;
		ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
		dl->AddRectFilled(ImVec2(rx, hdr_y), ImVec2(rx + rw, hdr_y + line_h), hdr_bg, 6.f);
		dl->AddLine(ImVec2(rx, hdr_y + line_h - 1.f), ImVec2(rx + rw, hdr_y + line_h - 1.f),
			aida::ui::with_alpha(th.border_subtle, alpha));

		ImFont* head_em = aida::ui::fonts::body_em();
		if (!head_em) head_em = ImGui::GetFont();
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		const float fs_dh = fs_diss_base * 0.95f;
		float hx = rx + 8.f;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Offset");
		hx += col_offset_w + col_glyph_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Name");
		hx += col_name_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Value");
		hx += col_value_w;
		dl->AddText(head_em, fs_dh, ImVec2(hx, hdr_y + 9.f), hc, "Description");

		float table_y = ry_start + line_h;
		float table_h = rh - line_h - line_h - 8.f;

		ui.scroll_y = aida::motion::smooth_lerp(ui.scroll_y, ui.target_scroll_y, 18.f, dt);

		bool table_hovered = ImGui::IsMouseHoveringRect(
			ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h));
		if (table_hovered) {
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
				ImGui::IsMouseClicked(ImGuiMouseButton_Right))
				ui.table_focused = true;
			float wheel = ImGui::GetIO().MouseWheel;
			if (wheel != 0.f) ui.target_scroll_y -= wheel * line_h * 3.f;
		}

		float content_h = static_cast<float>(field_count) * line_h;
		if (ui.target_scroll_y < 0.f) ui.target_scroll_y = 0.f;
		float ms = std::max(0.f, content_h - table_h);
		if (ui.target_scroll_y > ms) ui.target_scroll_y = ms;

		struct deferred_edit_t {
			edit_target_t target = edit_target_t::none;
			int field_idx = -1;
			std::string seed_text;
		} pending_edit;
		bool ctx_open_request = false;
		int  ctx_open_field = -1;

		ImGui::PushClipRect(ImVec2(rx, table_y), ImVec2(rx + rw, table_y + table_h), true);
		{
			std::lock_guard<std::mutex> lk(st.mtx);
			if (struct_dissector::valid_index(active_idx, st.structs.size())) {
				const auto& sd = st.structs[static_cast<std::size_t>(active_idx)];
				const std::size_t first_visible = static_cast<std::size_t>((std::max)(0,
					static_cast<int>(ui.scroll_y / line_h)));
				const std::size_t visible_capacity = static_cast<std::size_t>((std::max)(1,
					static_cast<int>(table_h / line_h) + 2));
				const std::size_t last_visible = (std::min)(sd.fields.size(),
					first_visible + visible_capacity);
				for (std::size_t field_index = first_visible; field_index < last_visible; ++field_index) {
					if (!struct_dissector::index_fits_int(field_index)) break;
					const int fi = static_cast<int>(field_index);
					float row_y = table_y + static_cast<float>(field_index) * line_h - ui.scroll_y;
					if (row_y + line_h < table_y || row_y > table_y + table_h) continue;

					float entrance_delay = std::min(static_cast<float>(fi) * 0.008f, 0.240f);
					float entrance_t = (ui.row_anim_time - entrance_delay) / 0.32f;
					if (entrance_t < 0.f) entrance_t = 0.f;
					if (entrance_t > 1.f) entrance_t = 1.f;
					float entrance = aida::motion::ease::out_cubic(entrance_t);
					if (entrance < 0.01f) continue;

					bool row_sel = (ui.selected_field == fi);
					bool row_hov = ImGui::IsMouseHoveringRect(
						ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h), false);

					ImU32 row_fill;
					if (row_sel) row_fill = aida::ui::with_alpha(th.selection, alpha);
					else if (row_hov) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
					else row_fill = ((field_index & 1U) != 0U)
						? aida::ui::with_alpha(th.panel_bg, alpha * 0.55f * entrance)
						: 0u;
					if ((row_fill & 0xFF000000) != 0) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							row_fill, 4.f);
					}
					if (row_sel) {
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + 3.f, row_y + line_h),
							aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
					}

					auto& fa = fanim(fi);
					float change_v = fa.change_flash.tick(dt, 1.7f);
					if (change_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.error, alpha * change_v * 0.4f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}
					float write_v = fa.write_success.tick(dt, 2.0f);
					if (write_v > 0.001f) {
						ImU32 pulse = aida::ui::with_alpha(th.success_soft, alpha * write_v * 1.5f);
						dl->AddRectFilled(ImVec2(rx, row_y), ImVec2(rx + rw, row_y + line_h),
							pulse, 4.f);
					}

					const auto& f = sd.fields[field_index];
					if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						ui.selected_field = fi;
						publish_field_selection(sd.name, f);
					}
					if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
						ui.selected_field = fi;
						ctx_open_request = true;
						ctx_open_field = fi;
						publish_field_selection(sd.name, f);
					}
					float fx = rx + 8.f;
					ImFont* code_font = aida::ui::fonts::code();
					if (!code_font) code_font = ImGui::GetFont();

					const float fs_drow_meta = fs_diss_base * 0.95f;
					const float fs_drow_body = fs_diss_base * 1.00f;
					char off_str[16];
					std::snprintf(off_str, sizeof(off_str), "+0x%03X", f.offset);
					dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
						aida::ui::with_alpha(th.text_address, alpha * entrance), off_str);
					fx += col_offset_w;

					ImU32 type_c = type_color_token(f.type, alpha * entrance);
					render_type_glyph(dl, ImVec2(fx + col_glyph_w * 0.5f, row_y + line_h * 0.5f),
						f.type, type_c);
					fx += col_glyph_w;

					float name_x = fx;
					dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
						fs_drow_body, ImVec2(fx, row_y + 9.f),
						aida::ui::with_alpha(th.text_primary, alpha * entrance), f.name.c_str());
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= name_x && mp.x <= name_x + col_name_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							pending_edit.target = edit_target_t::field_name;
							pending_edit.field_idx = fi;
							pending_edit.seed_text = f.name;
						}
					}
					fx += col_name_w;

					float type_x = fx;
					dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
						type_c, struct_dissector::field_type_name(f.type));
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= type_x && mp.x <= type_x + col_type_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							ctx_open_request = true;
							ctx_open_field = fi;
						}
					}
					fx += col_type_w;

					if (field_index < st.cached_values.size()) {
						const auto& cv = st.cached_values[field_index];
						bool changed_now = cv.changed && fa.has_last && fa.last_bytes != cv.raw_bytes;
						if (changed_now) fa.change_flash.trigger();
						fa.last_bytes = cv.raw_bytes;
						fa.has_last = true;

						ImU32 val_col = aida::ui::with_alpha(th.text_primary, alpha * entrance);
						dl->AddText(code_font, fs_drow_meta, ImVec2(fx, row_y + 9.f),
							val_col, cv.display_text.c_str());

						if (ui.editing_field == fi) {
							float ring_pulse = sinf(ui.edit_ring_phase * 6.f) * 0.5f + 0.5f;
							ImU32 ring = aida::ui::with_alpha(th.accent_hover,
								alpha * (0.45f + ring_pulse * 0.45f));
							dl->AddRect(ImVec2(fx - 2.f, row_y + 1.f),
								ImVec2(fx + col_value_w - 4.f, row_y + line_h - 1.f),
								ring, 5.f, 0, 1.5f);

							ImGui::SetCursorScreenPos(ImVec2(fx, row_y + 1.f));
							ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.panel_header, alpha)));
							ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
								aida::ui::with_alpha(th.text_primary, alpha)));
							ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
							ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, 2.f));
							ImGui::PushItemWidth(col_value_w - 8.f);
							bool committed = ImGui::InputText("##sd_edit_val", ui.edit_value_buf,
								sizeof(ui.edit_value_buf),
								ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
							ImGui::PopItemWidth();
							ImGui::PopStyleVar(2);
							ImGui::PopStyleColor(2);
							if (committed) {
								bool wrote_ok = false;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
								wrote_ok = struct_dissector::write_preview_value(fi, ui.edit_value_buf);
#else
								uint64_t write_addr = ui.edit_base_address + f.offset;
								memory_scanner::value_type_t scanner_type = memory_scanner::value_type_t::int32_val;
								bool hex_input = false;
								switch (f.type) {
								case struct_dissector::field_type_t::int8:
								case struct_dissector::field_type_t::uint8:
									scanner_type = memory_scanner::value_type_t::byte_val; break;
								case struct_dissector::field_type_t::int16:
								case struct_dissector::field_type_t::uint16:
									scanner_type = memory_scanner::value_type_t::int16_val; break;
								case struct_dissector::field_type_t::int32:
								case struct_dissector::field_type_t::uint32:
									scanner_type = memory_scanner::value_type_t::int32_val; break;
								case struct_dissector::field_type_t::int64:
								case struct_dissector::field_type_t::uint64:
								case struct_dissector::field_type_t::pointer:
									scanner_type = memory_scanner::value_type_t::int64_val;
									hex_input = (f.type == struct_dissector::field_type_t::pointer);
									break;
								case struct_dissector::field_type_t::float32:
									scanner_type = memory_scanner::value_type_t::float_val; break;
								case struct_dissector::field_type_t::float64:
									scanner_type = memory_scanner::value_type_t::double_val; break;
								case struct_dissector::field_type_t::ascii_string:
									scanner_type = memory_scanner::value_type_t::string_ascii; break;
								case struct_dissector::field_type_t::utf16_string:
									scanner_type = memory_scanner::value_type_t::string_utf16; break;
								default:
									scanner_type = memory_scanner::value_type_t::byte_array;
									hex_input = true;
									break;
								}
								auto bytes = memory_scanner::parse_value(ui.edit_value_buf,
									scanner_type, hex_input);
								const bool target_current = driver_bridge::is_loaded() &&
									driver_bridge::attached_pid() != 0 &&
									driver_bridge::attached_pid() == ui.edit_target_pid &&
									st.base_address == ui.edit_base_address;
								if (target_current && !bytes.empty()) {
									const bool submitted = driver_bridge::write_memory(write_addr, bytes);
									std::vector<uint8_t> observed;
									wrote_ok = submitted &&
										driver_bridge::read_memory(write_addr, bytes.size(), observed) &&
										observed == bytes;
								}
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
								diag::log_tagged_fmt("dissector",
									"write_field addr=0x%llX type=%s input='%s' bytes=%zu verified=%d",
									static_cast<unsigned long long>(write_addr),
									struct_dissector::field_type_name(f.type),
									ui.edit_value_buf,
									bytes.size(),
									wrote_ok ? 1 : 0);
#endif
								if (wrote_ok) {
									fa.write_success.trigger();
									toast_notification::push("Field value written and verified.",
										toast_notification::toast_type_t::success, 2.f);
								} else {
									toast_notification::push("Field write was rejected, stale, or failed readback verification.",
										toast_notification::toast_type_t::error, 5.f);
								}
								ui.editing_field = -1;
							}
							if (!ImGui::IsItemActive() && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
								ui.editing_field = -1;
						}

						if (ui.selected_field == fi && ui.editing_field != fi &&
							ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
							ImVec2 mp = ImGui::GetMousePos();
							if (mp.x >= fx && mp.x <= fx + col_value_w &&
								mp.y >= row_y && mp.y <= row_y + line_h) {
								ui.editing_field = fi;
								ui.edit_base_address = st.base_address;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
								ui.edit_target_pid = 4242;
#else
								ui.edit_target_pid = driver_bridge::attached_pid();
#endif
								std::strncpy(ui.edit_value_buf, cv.display_text.c_str(),
											 sizeof(ui.edit_value_buf) - 1);
								ui.edit_value_buf[sizeof(ui.edit_value_buf) - 1] = '\0';
							}
						}
					}
					fx += col_value_w;

					float desc_x = fx;
					if (!f.description.empty()) {
						dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
							fs_drow_meta, ImVec2(fx, row_y + 9.f),
							aida::ui::with_alpha(th.text_dim, alpha * entrance),
							f.description.c_str());
					} else {
						dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
							fs_drow_meta, ImVec2(fx, row_y + 9.f),
							aida::ui::with_alpha(th.text_dim, alpha * entrance * 0.55f),
							"(comment)");
					}
					if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						ImVec2 mp = ImGui::GetMousePos();
						if (mp.x >= desc_x && mp.x <= desc_x + col_desc_w &&
							mp.y >= row_y && mp.y <= row_y + line_h) {
							pending_edit.target = edit_target_t::field_comment;
							pending_edit.field_idx = fi;
							pending_edit.seed_text = f.description;
						}
					}
				}
			}
		}
		ImGui::PopClipRect();

		if (!ctx_open_request && ui.table_focused && ui.selected_field >= 0 &&
			(ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
				(ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)))) {
			ctx_open_request = true;
			ctx_open_field = ui.selected_field;
		}

		if (pending_edit.target != edit_target_t::none && pending_edit.field_idx >= 0) {
			ui.edit_target = pending_edit.target;
			ui.edit_target_field = pending_edit.field_idx;
			std::strncpy(ui.rename_buf, pending_edit.seed_text.c_str(),
				sizeof(ui.rename_buf) - 1);
			ui.rename_buf[sizeof(ui.rename_buf) - 1] = '\0';
			ImGui::OpenPopup("##sd_inline_edit");
			diag::log_tagged_fmt("dissector",
				"inline_edit_open kind=%d field_idx=%d",
				static_cast<int>(pending_edit.target), pending_edit.field_idx);
		}
		if (ctx_open_request && ctx_open_field >= 0) {
			ui.edit_target_field = ctx_open_field;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(active_idx, st.structs.size())) {
					const auto& selected = st.structs[static_cast<std::size_t>(active_idx)];
					if (struct_dissector::valid_index(ctx_open_field, selected.fields.size()))
						publish_field_selection(selected.name,
							selected.fields[static_cast<std::size_t>(ctx_open_field)]);
				}
			}
			ui.context_refresh_seq = st.last_completed_seq.load(std::memory_order_acquire);
			ui.context_base_address = st.base_address;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			ui.context_target_pid = 4242;
#else
			ui.context_target_pid = driver_bridge::attached_pid();
#endif
			ImGui::OpenPopup("##sd_field_ctx");
			diag::log_tagged_fmt("dissector",
				"field_ctx_open field_idx=%d", ctx_open_field);
		}

		if (ImGui::BeginPopup("##sd_inline_edit")) {
			const char* hint = "rename";
			const char* commit = "Rename";
			switch (ui.edit_target) {
			case edit_target_t::field_name:    hint = "field name";    commit = "Rename";     break;
			case edit_target_t::field_size:    hint = "new size";      commit = "Set Size";   break;
			case edit_target_t::field_comment: hint = "comment";       commit = "Set Comment";break;
			case edit_target_t::struct_name:   hint = "struct name";   commit = "Rename";     break;
			default: break;
			}
			ImGui::TextDisabled("%s", hint);
			ImGui::PushItemWidth(280.f);
			bool accept = ImGui::InputText("##sd_inline_buf", ui.rename_buf,
				sizeof(ui.rename_buf), ImGuiInputTextFlags_EnterReturnsTrue);
			ImGui::PopItemWidth();
			ImGui::SameLine();
			if (ImGui::Button(commit) || accept) {
				int tgt_field = ui.edit_target_field;
				switch (ui.edit_target) {
				case edit_target_t::field_name:
					if (tgt_field >= 0 && ui.rename_buf[0] != '\0')
						struct_dissector::rename_field(active_idx, tgt_field, ui.rename_buf);
					break;
				case edit_target_t::field_size: {
					uint32_t nsz = 0;
					if (std::sscanf(ui.rename_buf, "%u", &nsz) == 1 && nsz > 0)
						struct_dissector::set_field_size(active_idx, tgt_field, nsz);
					else
						diag::log_tagged_fmt("dissector",
							"set_field_size_input_invalid input='%s'", ui.rename_buf);
					break;
				}
				case edit_target_t::field_comment:
					if (tgt_field >= 0)
						struct_dissector::set_field_comment(active_idx, tgt_field, ui.rename_buf);
					break;
				case edit_target_t::struct_name:
					if (active_idx >= 0 && ui.rename_buf[0] != '\0')
						struct_dissector::rename_struct(active_idx, ui.rename_buf);
					break;
				default: break;
				}
				ui.edit_target = edit_target_t::none;
				ui.edit_target_field = -1;
				ui.rename_buf[0] = '\0';
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel")) {
				ui.edit_target = edit_target_t::none;
				ui.edit_target_field = -1;
				ui.rename_buf[0] = '\0';
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		} else if (ui.edit_target != edit_target_t::none) {
			ui.edit_target = edit_target_t::none;
		}

		bool open_remove_confirmation = false;
		if (ImGui::BeginPopup("##sd_field_ctx")) {
			int tgt_field = ui.edit_target_field;
			struct_dissector::field_def_t field_snapshot;
			struct_dissector::live_value_t value_snapshot;
			bool valid_field = false;
			{
				std::lock_guard<std::mutex> lk(st.mtx);
				if (struct_dissector::valid_index(active_idx, st.structs.size())) {
					const auto& fields = st.structs[static_cast<std::size_t>(active_idx)].fields;
					if (struct_dissector::valid_index(tgt_field, fields.size())) {
						field_snapshot = fields[static_cast<std::size_t>(tgt_field)];
						if (static_cast<std::size_t>(tgt_field) < st.cached_values.size())
							value_snapshot = st.cached_values[static_cast<std::size_t>(tgt_field)];
						valid_field = true;
					}
				}
			}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const bool live_current = valid_field;
#else
			const bool live_current = valid_field && driver_bridge::is_loaded() &&
				driver_bridge::attached_pid() != 0 &&
				driver_bridge::attached_pid() == ui.context_target_pid &&
				st.base_address == ui.context_base_address &&
				st.last_completed_seq.load(std::memory_order_acquire) == ui.context_refresh_seq;
#endif
			auto unavailable = [](const char* label, const char* reason) {
				ImGui::MenuItem(label, nullptr, false, false);
				if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
					ImGui::SetTooltip("%s", reason);
			};
			ImGui::TextDisabled("%s  |  +0x%X  |  %s",
				live_current ? "Live process" : "Structure definition",
				field_snapshot.offset,
				valid_field ? struct_dissector::field_type_name(field_snapshot.type) : "stale field");
			if (!valid_field)
				ImGui::TextDisabled("The structure changed; select the field again.");
			ImGui::Separator();
			if (ImGui::MenuItem("Copy field name", "Ctrl+C", false, valid_field))
				ImGui::SetClipboardText(field_snapshot.name.c_str());
			if (ImGui::MenuItem("Copy offset", nullptr, false, valid_field)) {
				char text[24]{};
				std::snprintf(text, sizeof(text), "0x%X", field_snapshot.offset);
				ImGui::SetClipboardText(text);
			}
			if (ImGui::MenuItem("Copy absolute address", nullptr, false,
					valid_field && ui.context_base_address != 0)) {
				char text[32]{};
				std::snprintf(text, sizeof(text), "0x%016llX",
					static_cast<unsigned long long>(ui.context_base_address + field_snapshot.offset));
				ImGui::SetClipboardText(text);
			}
			if (ImGui::MenuItem("Copy current value", nullptr, false,
					live_current && !value_snapshot.display_text.empty()))
				ImGui::SetClipboardText(value_snapshot.display_text.c_str());
			ImGui::Separator();
			if (ImGui::MenuItem("Edit live value...", nullptr, false,
					live_current && !value_snapshot.raw_bytes.empty())) {
				ui.editing_field = tgt_field;
				ui.edit_target_pid = ui.context_target_pid;
				ui.edit_base_address = ui.context_base_address;
				std::strncpy(ui.edit_value_buf, value_snapshot.display_text.c_str(),
					sizeof(ui.edit_value_buf) - 1);
				ui.edit_value_buf[sizeof(ui.edit_value_buf) - 1] = '\0';
			}
			if (!live_current)
				unavailable("Refresh live value", "Attach the original target and reselect the field before reading live memory.");
			ImGui::Separator();
			if (ImGui::MenuItem("Rename field...")) {
				std::string seed;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					if (struct_dissector::valid_index(active_idx, st.structs.size())) {
						const auto& fields = st.structs[static_cast<std::size_t>(active_idx)].fields;
						if (struct_dissector::valid_index(tgt_field, fields.size()))
							seed = fields[static_cast<std::size_t>(tgt_field)].name;
					}
				}
				ui.edit_target = edit_target_t::field_name;
				std::strncpy(ui.rename_buf, seed.c_str(), sizeof(ui.rename_buf) - 1);
				ui.rename_buf[sizeof(ui.rename_buf) - 1] = '\0';
				ImGui::CloseCurrentPopup();
				ImGui::OpenPopup("##sd_inline_edit");
			}
			if (ImGui::MenuItem("Set size...")) {
				ui.edit_target = edit_target_t::field_size;
				ui.rename_buf[0] = '\0';
				ImGui::CloseCurrentPopup();
				ImGui::OpenPopup("##sd_inline_edit");
			}
			if (ImGui::MenuItem("Set comment...")) {
				std::string seed;
				{
					std::lock_guard<std::mutex> lk(st.mtx);
					if (struct_dissector::valid_index(active_idx, st.structs.size())) {
						const auto& fields = st.structs[static_cast<std::size_t>(active_idx)].fields;
						if (struct_dissector::valid_index(tgt_field, fields.size()))
							seed = fields[static_cast<std::size_t>(tgt_field)].description;
					}
				}
				ui.edit_target = edit_target_t::field_comment;
				std::strncpy(ui.rename_buf, seed.c_str(), sizeof(ui.rename_buf) - 1);
				ui.rename_buf[sizeof(ui.rename_buf) - 1] = '\0';
				ImGui::CloseCurrentPopup();
				ImGui::OpenPopup("##sd_inline_edit");
			}
			ImGui::Separator();
			static const char* k_type_names[] = {
				"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
				"Int64", "UInt64", "Float", "Double", "Pointer",
				"ASCII String", "UTF-16 String", "Byte Array", "Padding", "Struct"
			};
			if (ImGui::BeginMenu("Change type")) {
				const auto type_count = static_cast<std::size_t>(struct_dissector::field_type_t::COUNT);
				for (std::size_t type_index = 0; type_index < type_count; ++type_index) {
					if (ImGui::MenuItem(k_type_names[type_index])) {
						struct_dissector::retype_field(active_idx, tgt_field,
							static_cast<struct_dissector::field_type_t>(type_index));
					}
				}
				ImGui::EndMenu();
			}
			unavailable("Set array count...", "The current structure backend does not expose array-count mutation.");
			unavailable("Choose nested structure...", "Nested-structure linkage is not implemented by the current backend.");
			unavailable("Configure bitfield...", "The current field model has no bitfield layout representation.");
			unavailable("Set alignment...", "Alignment and packing are not represented by the current structure backend.");
			ImGui::Separator();
			if (ImGui::MenuItem("Remove field...", nullptr, false, valid_field)) {
				ui.pending_remove_field = tgt_field;
				open_remove_confirmation = true;
			}
			ImGui::EndPopup();
		}
		if (open_remove_confirmation)
			ImGui::OpenPopup("##sd_confirm_remove_field");

		if (ImGui::BeginPopupModal("##sd_confirm_remove_field", nullptr,
			ImGuiWindowFlags_AlwaysAutoResize)) {
			ImGui::TextUnformatted("Remove this field from the structure definition?");
			ImGui::TextDisabled("This backend has no field-removal undo journal.");
			if (ImGui::Button("Cancel", ImVec2(110.f, 0.f))) {
				ui.pending_remove_field = -1;
				ImGui::CloseCurrentPopup();
			}
			ImGui::SameLine();
			if (ImGui::Button("Remove", ImVec2(110.f, 0.f))) {
				const int target = ui.pending_remove_field;
				if (target >= 0 && struct_dissector::remove_field(active_idx, target)) {
					if (ui.selected_field == target) ui.selected_field = -1;
					if (ui.editing_field == target) ui.editing_field = -1;
				}
				ui.pending_remove_field = -1;
				ImGui::CloseCurrentPopup();
			}
			ImGui::EndPopup();
		}

		if (content_h > table_h && table_h > 0.f) {
			float bar_x = rx + rw - 10.f;
			float bar_y = table_y;
			float bar_h = table_h;
			float ratio = table_h / content_h;
			float thumb_h = std::max(bar_h * ratio, 24.f);
			float track = bar_h - thumb_h;
			float scroll_ratio = (content_h - table_h > 0.f) ? ui.scroll_y / (content_h - table_h) : 0.f;
			float thumb_y = bar_y + track * scroll_ratio;
			dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 5.f, bar_y + bar_h),
				aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 2.f);
			dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 5.f, thumb_y + thumb_h),
				aida::ui::with_alpha(th.accent_dim, alpha), 2.f);
		}

		float add_y = ry_start + rh - line_h - 6.f;
		ImGui::SetCursorScreenPos(ImVec2(rx + 8.f, add_y + 2.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.panel_header, alpha)));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));

		ImGui::PushItemWidth(170.f);
		ImGui::InputTextWithHint("##sd_fn", "field name", ui.field_name_buf, sizeof(ui.field_name_buf));
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		ImGui::PushItemWidth(80.f);
		ImGui::InputTextWithHint("##sd_fo", "+0x?", ui.offset_buf, sizeof(ui.offset_buf),
						 ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		static const char* type_names[] = {
			"Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32",
			"Int64", "UInt64", "Float", "Double", "Pointer",
			"ASCII", "UTF-16", "Bytes", "Padding", "Struct"
		};
		ImGui::PushItemWidth(110.f);
		ImGui::Combo("##sd_ft", &ui.add_type, type_names,
					 static_cast<int>(struct_dissector::field_type_t::COUNT));
		ImGui::PopItemWidth();
		ImGui::SameLine(0.f, 6.f);

		ImGui::PopStyleColor(2);
		ImGui::PopStyleVar();

		if (aida::ui::button("Add", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(72.f, 28.f))) {
			if (ui.field_name_buf[0] != '\0') {
				struct_dissector::field_def_t fd;
				fd.name = ui.field_name_buf;
				fd.type = static_cast<struct_dissector::field_type_t>(ui.add_type);
				uint32_t off = 0;
				std::sscanf(ui.offset_buf, "%x", &off);
				fd.offset = off;
				std::size_t ts = struct_dissector::field_type_size(fd.type);
				fd.size = static_cast<uint32_t>(ts > 0 ? ts : 1);
				struct_dissector::add_field(active_idx, fd);
				ui.field_name_buf[0] = '\0';
				ui.offset_buf[0] = '\0';
			} else {
				diag::log_tagged_fmt("dissector",
					"add_field_skipped reason='empty_name'");
			}
		}
		ImGui::SameLine(0.f, 6.f);
		if (aida::ui::button("Del", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(64.f, 28.f))) {
			if (ui.selected_field >= 0) {
				struct_dissector::remove_field(active_idx, ui.selected_field);
				ui.selected_field = -1;
				ui.editing_field = -1;
			} else {
				diag::log_tagged_fmt("dissector",
					"remove_field_skipped reason='no_selection'");
			}
		}
	}

	ImGui::EndChild();
}

}
