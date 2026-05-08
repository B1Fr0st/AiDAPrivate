#include "struct_recon_view.hpp"
#include "struct_recon_engine.hpp"
#include "struct_monitor.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/blur_layer.hpp"
#include "ui/empty_state.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>

namespace struct_recon_view {

struct field_anim_t {
	float heat_v = 0.f;
	aida::ui::flash_t change_flash;
	aida::ui::flash_t write_success;
	aida::ui::transition_t expand_anim;
	bool  expanded = false;
	uint64_t last_value = 0;
	bool  has_last = false;
};

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_field = -1;
	int   editing_field = -1;
	char  edit_value_buf[128] = {};
	float row_anim_time = 0.f;
	std::unordered_map<int, field_anim_t> field_anims;
	aida::ui::transition_t vtable_expand;
	bool  vtable_expanded = true;
};

static local_state_t s_state;

static ImU32 type_color_token(struct_recon::field_type_t tp, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImU32 base;
	switch (tp) {
		case struct_recon::field_type_t::int8:
		case struct_recon::field_type_t::int16:
		case struct_recon::field_type_t::int32:
		case struct_recon::field_type_t::int64:
		case struct_recon::field_type_t::uint8:
		case struct_recon::field_type_t::uint16:
		case struct_recon::field_type_t::uint32:
		case struct_recon::field_type_t::uint64:        base = th.syn_number; break;
		case struct_recon::field_type_t::float32:
		case struct_recon::field_type_t::float64:       base = th.syn_number; break;
		case struct_recon::field_type_t::pointer:       base = th.syn_function; break;
		case struct_recon::field_type_t::vtable_ptr:    base = th.error;       break;
		case struct_recon::field_type_t::c_string:
		case struct_recon::field_type_t::wide_string:
		case struct_recon::field_type_t::utf8_string:
		case struct_recon::field_type_t::utf16_string:  base = th.syn_string;  break;
		case struct_recon::field_type_t::padding:       base = th.text_dim;    break;
		case struct_recon::field_type_t::nested_struct: base = th.syn_keyword; break;
		case struct_recon::field_type_t::vec2:
		case struct_recon::field_type_t::vec3:
		case struct_recon::field_type_t::vec4:
		case struct_recon::field_type_t::mat4x4:        base = th.warning;     break;
		case struct_recon::field_type_t::color_rgba:    base = th.accent_grad_top; break;
		case struct_recon::field_type_t::bitfield:      base = th.syn_keyword; break;
		case struct_recon::field_type_t::bool8:         base = th.syn_keyword; break;
		default:                                        base = th.text_secondary; break;
	}
	return aida::ui::with_alpha(base, alpha);
}

static void render_type_glyph(ImDrawList* dl, ImVec2 center, struct_recon::field_type_t tp,
                              ImU32 color, float size = 10.f)
{
	switch (tp) {
		case struct_recon::field_type_t::pointer:
		case struct_recon::field_type_t::vtable_ptr: {
			dl->AddCircle(center, size * 0.5f, color, 12, 1.2f);
			ImVec2 tip = ImVec2(center.x + size * 0.7f, center.y);
			dl->AddLine(center, tip, color, 1.2f);
			dl->AddTriangleFilled(
				ImVec2(tip.x - 3.f, center.y - 3.f),
				ImVec2(tip.x + 1.f, center.y),
				ImVec2(tip.x - 3.f, center.y + 3.f), color);
			break;
		}
		case struct_recon::field_type_t::c_string:
		case struct_recon::field_type_t::wide_string:
		case struct_recon::field_type_t::utf8_string:
		case struct_recon::field_type_t::utf16_string: {
			ImVec2 a = ImVec2(center.x - size * 0.5f, center.y - 1.f);
			ImVec2 b = ImVec2(center.x + size * 0.5f, center.y + 1.f);
			dl->AddRectFilled(a, b, color, 1.f);
			dl->AddRectFilled(ImVec2(a.x, a.y + 4.f), ImVec2(b.x - 2.f, b.y + 4.f), color, 1.f);
			dl->AddRectFilled(ImVec2(a.x, a.y + 8.f), ImVec2(b.x + 2.f, b.y + 8.f), color, 1.f);
			break;
		}
		case struct_recon::field_type_t::float32:
		case struct_recon::field_type_t::float64: {
			dl->AddText(ImGui::GetFont(), 10.f,
				ImVec2(center.x - 4.f, center.y - 5.f), color, "f");
			break;
		}
		case struct_recon::field_type_t::nested_struct: {
			ImVec2 a = ImVec2(center.x - size * 0.5f, center.y - size * 0.5f);
			ImVec2 b = ImVec2(center.x + size * 0.5f, center.y + size * 0.5f);
			dl->AddRect(a, b, color, 1.5f, 0, 1.f);
			dl->AddLine(ImVec2(a.x + 2.f, center.y), ImVec2(b.x - 2.f, center.y), color, 1.f);
			break;
		}
		default: {
			dl->AddCircleFilled(center, size * 0.25f, color, 12);
			break;
		}
	}
}

static field_anim_t& fanim(int idx) { return s_state.field_anims[idx]; }

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y;
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##struct_recon_view", ImVec2(width, height), false,
	    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& sr = struct_recon::g_state;
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
	st.row_anim_time += dt;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	const float toolbar_h = 56.f;

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + width, oy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float cx = ox + 12.f;
	float cy = oy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));

	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##sr_addr", "Base address (hex)", sr.address_input, sizeof(sr.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(140.f);
	ImGui::InputTextWithHint("##sr_name", "Struct name", sr.name_input, sizeof(sr.name_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(70.f);
	ImGui::InputTextWithHint("##sr_size", "Size", sr.size_input, sizeof(sr.size_input));
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	bool monitoring = sr.monitoring.load();

	if (!monitoring) {
		if (aida::ui::button("Snapshot", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(86.f, 22.f))) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) struct_recon::reconstruct_from_snapshot(addr, sz, sr.name_input);
		}
		ImGui::SameLine();
		if (aida::ui::button("HW Monitor", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(98.f, 22.f))) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) struct_recon::monitor_with_hwbp(addr, sz, sr.name_input);
		}
		ImGui::SameLine();
		bool live_active = struct_monitor::g_state.active.load();
		if (!live_active) {
			if (aida::ui::button("Live Monitor", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(108.f, 22.f))) {
				uint64_t addr = 0;
				int sz = 256;
				if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
				if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
				if (sz <= 0) sz = 256;
				if (sz > 4096) sz = 4096;
				if (addr != 0) struct_monitor::start(addr, sz, sr.name_input);
			}
		} else {
			if (aida::ui::button("Stop Live", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(94.f, 22.f))) {
				struct_monitor::stop();
			}
			ImGui::SameLine();
			uint64_t cps = struct_monitor::g_state.captures_per_second.load();
			uint64_t total = struct_monitor::g_state.total_captures.load();
			char live_buf[64];
			std::snprintf(live_buf, sizeof(live_buf), "%llu cap/s   %llu total",
				static_cast<unsigned long long>(cps),
				static_cast<unsigned long long>(total));
			ImGui::SameLine();
			ImVec2 cp = ImGui::GetCursorScreenPos();
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				12.f, ImVec2(cp.x, cp.y + 4.f),
				aida::ui::with_alpha(th.success, alpha), live_buf);
		}
	} else {
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(80.f, 22.f))) {
			struct_recon::cancel();
		}
		ImGui::SameLine();
		float prog = sr.progress.load();
		ImVec2 cp = ImGui::GetCursorScreenPos();
		aida::ui::components::render_progress_bar(ImVec2(cp.x, cp.y + 6.f),
			120.f, 10.f, prog, false, true);
		ImGui::Dummy(ImVec2(124.f, 22.f));
	}

	ImGui::SameLine();
	if (aida::ui::button("Export C++", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(94.f, 22.f))) {
		std::lock_guard<std::mutex> lk(sr.mutex);
		std::string cpp = struct_recon::export_as_cpp(sr.current);
		ImGui::SetClipboardText(cpp.c_str());
	}
	ImGui::SameLine();
	{
		bool ai_naming = sr.ai_naming.load();
		bool clicked = aida::ui::button(ai_naming ? "Naming" : "AI Name",
			aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm,
			ImVec2(82.f, 22.f), ai_naming, nullptr, ai_naming);
		if (clicked && !ai_naming) struct_recon::ai_name_fields();
	}
	ImGui::SameLine();
	if (aida::ui::button("Save", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(64.f, 22.f))) {
		struct_recon::save_struct_to_disk(sr.current);
	}
	ImGui::SameLine();
	if (aida::ui::button("Load All", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(82.f, 22.f))) {
		struct_recon::load_structs_from_disk();
	}
	ImGui::SameLine();
	if (aida::ui::button("Refresh", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(76.f, 22.f))) {
		struct_recon::refresh_value_history();
	}

	cy = oy + toolbar_h + 8.f;

	struct_recon::reconstructed_struct_t current_copy;
	{
		std::lock_guard<std::mutex> lk(sr.mutex);
		current_copy = sr.current;
	}

	if (current_copy.fields.empty() && !monitoring) {
		ImVec2 sz = ImVec2(width, oy + height - cy - 8.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		cfg.title = "No struct reconstructed";
		cfg.body  = "Enter a base address and click Snapshot to reconstruct struct layout.";
		cfg.max_width = 380.f;
		aida::ui::empty_state::render(ImVec2(ox, cy), sz, cfg);
		ImGui::EndChild();
		return;
	}

	{
		char info_buf[160];
		std::snprintf(info_buf, sizeof(info_buf), "%s   0x%llX   %d bytes   %zu fields",
			current_copy.name.c_str(),
			static_cast<unsigned long long>(current_copy.base_address),
			current_copy.total_size,
			current_copy.fields.size());
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		dl->AddText(code_font, 12.f, ImVec2(cx, cy),
			aida::ui::with_alpha(th.accent_u32, alpha), info_buf);
		cy += 22.f;
	}

	bool show_right_panel = width > 640.f;
	float main_w = show_right_panel ? width * 0.62f : width - 24.f;
	float right_x = ox + main_w + 12.f;
	float right_w = width - main_w - 24.f;

	const float row_h = 26.f;
	const float table_top = cy;
	const float table_h = oy + height - cy - 8.f;
	float content_h = static_cast<float>(current_copy.fields.size()) * row_h;
	float visible_h = table_h;

	const float col_offset_w = main_w * 0.10f;
	const float col_glyph_w  = 24.f;
	const float col_type_w   = main_w * 0.13f;
	const float col_name_w   = main_w * 0.22f;
	const float col_size_w   = main_w * 0.07f;
	const float col_conf_w   = main_w * 0.08f;
	const float col_heat_w   = main_w * 0.10f;
	const float col_comment_w= main_w - col_offset_w - col_glyph_w - col_type_w
	                          - col_name_w - col_size_w - col_conf_w - col_heat_w - 8.f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + main_w, cy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(ox, cy + row_h - 1.f), ImVec2(ox + main_w, cy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	{
		float hx = cx;
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Offset");
		hx += col_offset_w + col_glyph_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Name");
		hx += col_name_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Size");
		hx += col_size_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Conf");
		hx += col_conf_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Heat");
		hx += col_heat_w;
		dl->AddText(head_em, 11.f, ImVec2(hx, cy + 7.f), hc, "Comment");
	}
	cy += row_h + 2.f;
	visible_h -= row_h + 2.f;

	float wheel = 0.f;
	if (ImGui::IsMouseHoveringRect(ImVec2(ox, cy), ImVec2(ox + main_w, oy + height))) {
		wheel = ImGui::GetIO().MouseWheel;
	}
	if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
	if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
	float max_scroll = std::max(0.f, content_h - visible_h);
	if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + main_w, oy + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(current_copy.fields.size()))
		last_vis = static_cast<int>(current_copy.fields.size());

	const float per_item_delay = 0.008f;
	const float total_stagger_cap = 0.240f;
	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + height) continue;

		auto& field = current_copy.fields[static_cast<size_t>(i)];
		auto& fa = fanim(i);

		float entrance_delay = std::min(static_cast<float>(i) * per_item_delay, total_stagger_cap);
		float entrance_t = (st.row_anim_time - entrance_delay) / 0.32f;
		if (entrance_t < 0.f) entrance_t = 0.f;
		if (entrance_t > 1.f) entrance_t = 1.f;
		float entrance = aida::motion::ease::out_cubic(entrance_t);

		ImVec2 rmin(ox, ry);
		ImVec2 rmax(ox + main_w, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_field == i);

		ImU32 row_fill;
		if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
		else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
		else row_fill = (i & 1)
			? aida::ui::with_alpha(th.panel_bg, alpha * 0.55f * entrance)
			: aida::ui::with_alpha(IM_COL32(0,0,0,0), alpha);

		dl->AddRectFilled(rmin, rmax, row_fill, 4.f);
		if (selected) {
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		}

		float change_v = fa.change_flash.tick(dt, 1.7f);
		if (change_v > 0.001f) {
			ImU32 pulse = aida::ui::with_alpha(th.error, alpha * change_v * 0.45f);
			dl->AddRectFilled(rmin, rmax, pulse, 4.f);
		}
		float write_v = fa.write_success.tick(dt, 2.0f);
		if (write_v > 0.001f) {
			ImU32 pulse = aida::ui::with_alpha(th.success_soft, alpha * write_v * 1.4f);
			dl->AddRectFilled(rmin, rmax, pulse, 4.f);
		}

		uint64_t cur_val = 0;
		if (!field.value_history.values.empty() && field.value_history.count > 0) {
			int last_idx = (field.value_history.write_idx - 1 + struct_recon::value_history_t::MAX_ENTRIES)
				% struct_recon::value_history_t::MAX_ENTRIES;
			cur_val = field.value_history.values[static_cast<size_t>(last_idx)];
		}
		if (fa.has_last && fa.last_value != cur_val) {
			fa.change_flash.trigger();
		}
		fa.last_value = cur_val;
		fa.has_last = true;

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_field = i;
		}

		float rx = cx;
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		char buf[160];
		std::snprintf(buf, sizeof(buf), "0x%04llX",
			static_cast<unsigned long long>(field.offset));
		dl->AddText(code_font, 11.f, ImVec2(rx + 6.f, ry + 7.f),
			aida::ui::with_alpha(th.text_address, alpha * entrance), buf);
		rx += col_offset_w;

		ImU32 type_col = type_color_token(field.type, alpha * entrance);
		render_type_glyph(dl, ImVec2(rx + col_glyph_w * 0.5f, ry + row_h * 0.5f),
			field.type, type_col, 12.f);
		rx += col_glyph_w;

		if (field.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "%s[%d]",
				struct_recon::field_type_name(field.type), field.array_count);
		} else {
			std::snprintf(buf, sizeof(buf), "%s", struct_recon::field_type_name(field.type));
		}
		dl->AddText(code_font, 11.f, ImVec2(rx + 4.f, ry + 7.f), type_col, buf);
		rx += col_type_w;

		ImU32 name_col = aida::ui::with_alpha(th.text_primary, alpha * entrance);
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			12.f, ImVec2(rx + 4.f, ry + 7.f), name_col, field.name.c_str());
		rx += col_name_w;

		std::snprintf(buf, sizeof(buf), "%d", field.size);
		dl->AddText(code_font, 11.f, ImVec2(rx + 4.f, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), buf);
		rx += col_size_w;

		{
			const char* conf_str = "-";
			ImU32 conf_col = aida::ui::with_alpha(th.text_dim, alpha * entrance);
			if (field.type_confidence >= 75.f) {
				conf_str = "Strong"; conf_col = aida::ui::with_alpha(th.success, alpha * entrance);
			} else if (field.type_confidence >= 50.f) {
				conf_str = "Med"; conf_col = aida::ui::with_alpha(th.warning, alpha * entrance);
			} else if (field.type_confidence >= 25.f) {
				conf_str = "Weak"; conf_col = aida::ui::with_alpha(th.error, alpha * entrance);
			}
			dl->AddText(code_font, 11.f, ImVec2(rx + 4.f, ry + 7.f), conf_col, conf_str);
		}
		rx += col_conf_w;

		{
			int heat = field.value_history.heat_level();
			float target = static_cast<float>(heat) / 10.f;
			fa.heat_v = aida::motion::smooth_lerp(fa.heat_v, target, 8.f, dt);
			float visible_v = fa.heat_v;
			float bar_w = (col_heat_w - 12.f) * visible_v;
			ImU32 heat_col;
			if (heat <= 3)      heat_col = aida::ui::with_alpha(th.success, alpha * 0.85f);
			else if (heat <= 6) heat_col = aida::ui::with_alpha(th.warning, alpha * 0.85f);
			else                heat_col = aida::ui::with_alpha(th.error,   alpha * 0.85f);
			float bar_y = ry + (row_h - 6.f) * 0.5f;
			dl->AddRectFilled(ImVec2(rx + 6.f, bar_y),
				ImVec2(rx + 6.f + col_heat_w - 12.f, bar_y + 6.f),
				aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 2.f);
			if (bar_w > 0.5f) {
				dl->AddRectFilled(ImVec2(rx + 6.f, bar_y),
					ImVec2(rx + 6.f + bar_w, bar_y + 6.f),
					heat_col, 2.f);
			}
		}
		rx += col_heat_w;

		if (!field.comment.empty()) {
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				11.f, ImVec2(rx + 4.f, ry + 7.f),
				aida::ui::with_alpha(th.text_dim, alpha * entrance),
				field.comment.c_str());
		} else if (!field.accesses.empty()) {
			std::snprintf(buf, sizeof(buf), "%zu accesses", field.accesses.size());
			dl->AddText(code_font, 11.f, ImVec2(rx + 4.f, ry + 7.f),
				aida::ui::with_alpha(th.text_dim, alpha * entrance), buf);
		}
	}

	ImGui::PopClipRect();

	if (content_h > visible_h && visible_h > 0.f) {
		float bar_x = ox + main_w - 12.f;
		float bar_y = table_top + row_h + 2.f;
		float bar_h = visible_h;
		float ratio = visible_h / content_h;
		float thumb_h = std::max(bar_h * ratio, 24.f);
		float track = bar_h - thumb_h;
		float scroll_ratio = (content_h - visible_h > 0.f) ? st.scroll_y / (content_h - visible_h) : 0.f;
		float thumb_y = bar_y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 6.f, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 6.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
	}

	if (show_right_panel && st.selected_field >= 0 &&
		st.selected_field < static_cast<int>(current_copy.fields.size())) {

		auto& sel = current_copy.fields[static_cast<size_t>(st.selected_field)];

		float rp_w = (ox + width - 8.f) - (right_x - 4.f);
		float rp_h = oy + height - table_top - 8.f;
		ImVec2 r_a = ImVec2(right_x - 4.f, table_top);
		ImVec2 r_b = ImVec2(r_a.x + rp_w, r_a.y + rp_h);

		aida::ui::blur::layer_request_t req;
		req.pos = r_a; req.size = ImVec2(rp_w, rp_h);
		req.radius = 10.f; req.alpha = alpha; req.strength = 0.5f;
		aida::ui::blur::schedule(req);
		aida::ui::blur::render_glass_fill(dl, r_a, r_b, 10.f, alpha);
		aida::ui::blur::render_glass_border(dl, r_a, r_b, 10.f, alpha, 1.f);

		float ry = r_a.y + 12.f;
		float rxx = r_a.x + 12.f;

		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		dl->AddText(head, 13.f, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_primary, alpha), "Field Details");
		ry += 24.f;

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		char buf[160];
		std::snprintf(buf, sizeof(buf), "Offset   0x%04llX",
			static_cast<unsigned long long>(sel.offset));
		dl->AddText(code_font, 11.f, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_secondary, alpha), buf);
		ry += 16.f;

		std::snprintf(buf, sizeof(buf), "Size     %d bytes", sel.size);
		dl->AddText(code_font, 11.f, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_secondary, alpha), buf);
		ry += 16.f;

		ImU32 type_c = type_color_token(sel.type, alpha);
		render_type_glyph(dl, ImVec2(rxx + 6.f, ry + 7.f), sel.type, type_c, 12.f);
		std::snprintf(buf, sizeof(buf), "Type     %s",
			struct_recon::field_type_name(sel.type));
		dl->AddText(code_font, 11.f, ImVec2(rxx + 18.f, ry), type_c, buf);
		ry += 18.f;

		if (sel.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "Array    [%d]", sel.array_count);
			dl->AddText(code_font, 11.f, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.accent_u32, alpha), buf);
			ry += 16.f;
		}

		{
			const char* conf_name = "Unknown";
			aida::ui::pill_kind_t pk = aida::ui::pill_kind_t::neutral;
			if (sel.type_confidence >= 75.f) { conf_name = "Strong"; pk = aida::ui::pill_kind_t::success; }
			else if (sel.type_confidence >= 50.f) { conf_name = "Moderate"; pk = aida::ui::pill_kind_t::warning; }
			else if (sel.type_confidence >= 25.f) { conf_name = "Weak"; pk = aida::ui::pill_kind_t::error; }
			ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
			aida::ui::pill_kind(conf_name, pk, aida::ui::size_t_::sm, true);
			ry += 24.f;
		}

		{
			int heat = sel.value_history.heat_level();
			std::snprintf(buf, sizeof(buf), "Heat     %d/10  (%d unique)",
				heat, static_cast<int>(sel.value_history.unique_count()));
			dl->AddText(code_font, 11.f, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.text_secondary, alpha), buf);
			ry += 18.f;
		}

		ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
		dl->AddText(code_font, 11.f, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_dim, alpha), "Name");
		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			12.f, ImVec2(rxx + 60.f, ry),
			aida::ui::with_alpha(th.text_primary, alpha), sel.name.c_str());
		ry += 22.f;

		if (sel.type == struct_recon::field_type_t::vtable_ptr && !sel.vtable_entries.empty()) {
			float arrow_x = rxx;
			ImU32 arr_col = aida::ui::with_alpha(th.accent_u32, alpha);
			ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
			ImGui::InvisibleButton("##sr_vtable_hdr", ImVec2(rp_w - 24.f, 22.f));
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
				st.vtable_expanded = !st.vtable_expanded;
				if (st.vtable_expanded) st.vtable_expand.start(0.18f);
				else                    st.vtable_expand.start_reverse(0.18f);
			}
			st.vtable_expand.tick(dt);
			if (st.vtable_expanded && st.vtable_expand.at_origin()) {
				st.vtable_expand.start(0.18f);
			}
			float arrow_p = st.vtable_expanded ? 1.f : 0.f;
			float arrow_off = st.vtable_expand.eased();
			float ax = arrow_x + 2.f;
			float ay = ry + 11.f;
			ImVec2 a1, a2, a3;
			if (arrow_off > 0.5f) {
				a1 = ImVec2(ax - 1.f, ay - 3.f);
				a2 = ImVec2(ax + 7.f, ay - 3.f);
				a3 = ImVec2(ax + 3.f, ay + 4.f);
			} else {
				a1 = ImVec2(ax, ay - 4.f);
				a2 = ImVec2(ax + 6.f, ay);
				a3 = ImVec2(ax, ay + 4.f);
			}
			(void)arrow_p;
			dl->AddTriangleFilled(a1, a2, a3, arr_col);
			dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
				12.f, ImVec2(rxx + 16.f, ry + 5.f),
				aida::ui::with_alpha(th.error, alpha), "VTable Entries");
			char vbuf[24];
			std::snprintf(vbuf, sizeof(vbuf), "(%zu)", sel.vtable_entries.size());
			dl->AddText(code_font, 11.f,
				ImVec2(rxx + 130.f, ry + 6.f),
				aida::ui::with_alpha(th.text_dim, alpha), vbuf);
			ry += 24.f;

			float content_alpha = alpha * arrow_off;
			if (content_alpha > 0.01f) {
				for (size_t vi = 0; vi < sel.vtable_entries.size() && vi < 32; ++vi) {
					auto& ve = sel.vtable_entries[vi];
					bool has_symbol = ve.name.find('!') != std::string::npos ||
									   ve.name.find('+') != std::string::npos;
					ImU32 name_col = has_symbol
						? aida::ui::with_alpha(th.accent_u32, content_alpha)
						: aida::ui::with_alpha(th.text_dim, content_alpha);

					char idx_buf[16];
					std::snprintf(idx_buf, sizeof(idx_buf), "[%2d]", ve.index);
					dl->AddText(code_font, 11.f, ImVec2(rxx + 8.f, ry),
						aida::ui::with_alpha(th.text_dim, content_alpha), idx_buf);

					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(ve.func_addr));
					dl->AddText(code_font, 11.f, ImVec2(rxx + 44.f, ry),
						aida::ui::with_alpha(th.text_address, content_alpha), addr_buf);

					float name_x = rxx + 174.f;
					if (name_x + 10.f < r_b.x - 12.f) {
						dl->AddText(code_font, 11.f, ImVec2(name_x, ry), name_col, ve.name.c_str());
					}
					ry += 16.f * arrow_off;
					if (ry > r_b.y - 60.f) break;
				}
			}
			ry += 6.f;
		}

		if (!sel.accesses.empty() && ry < r_b.y - 60.f) {
			dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
				12.f, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.accent_u32, alpha), "Access Log");
			ry += 18.f;
			for (size_t ai = 0; ai < sel.accesses.size() && ai < 20; ++ai) {
				if (ry > r_b.y - 16.f) break;
				auto& acc = sel.accesses[static_cast<size_t>(ai)];
				char buf2[160];
				std::snprintf(buf2, sizeof(buf2), "%s 0x%llX  +0x%llX  %dB  x%d",
					acc.is_write ? "W" : "R",
					static_cast<unsigned long long>(acc.instruction_addr),
					static_cast<unsigned long long>(acc.access_offset),
					acc.access_size, acc.hit_count);
				dl->AddText(code_font, 11.f, ImVec2(rxx + 4.f, ry),
					aida::ui::with_alpha(th.text_dim, alpha), buf2);
				ry += 15.f;
			}
		}
	}

	ImGui::EndChild();
}

}
