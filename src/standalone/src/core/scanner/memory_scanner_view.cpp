#include "memory_scanner_view.hpp"
#include "memory_scanner.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "ui_anim.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <unordered_set>

namespace memory_scanner_view {

static void render_toolbar(ImDrawList* dl, float ox, float oy, float w, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	const float h = 52.f;
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.panel_header, a));
	dl->AddLine(ImVec2(ox, oy + h),
		ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float pad = 14.f;
	float cy = oy + (h - 36.f) * 0.5f;
	float cx = ox + pad;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(96.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_bg, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##vtype", memory_scanner::value_type_name(sc.config.value_type))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::value_type_t::COUNT); ++i) {
			auto vt = static_cast<memory_scanner::value_type_t>(i);
			bool sel = (sc.config.value_type == vt);
			if (ImGui::Selectable(memory_scanner::value_type_name(vt), sel))
				sc.config.value_type = vt;
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cx += 104.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 4.f));
	ImGui::PushItemWidth(186.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_bg, a));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_strong, a));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 5.f));
	if (ImGui::BeginCombo("##smode", memory_scanner::scan_mode_name(sc.config.scan_mode))) {
		for (int i = 0; i < static_cast<int>(memory_scanner::scan_mode_t::COUNT); ++i) {
			auto sm = static_cast<memory_scanner::scan_mode_t>(i);
			bool sel = (sc.config.scan_mode == sm);
			if (ImGui::Selectable(memory_scanner::scan_mode_name(sm), sel))
				sc.config.scan_mode = sm;
		}
		ImGui::EndCombo();
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(4);
	ImGui::PopItemWidth();
	cx += 196.f;

	bool needs_value = (sc.config.scan_mode != memory_scanner::scan_mode_t::changed &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::unchanged &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::increased &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::decreased &&
						sc.config.scan_mode != memory_scanner::scan_mode_t::unknown_initial);

	float input_h = 32.f;
	float input_y = oy + (h - input_h) * 0.5f;
	if (needs_value) {
		float input_w = 180.f;
		ImVec2 ia(cx, input_y);
		ImVec2 ib(cx + input_w, input_y + input_h);
		dl->AddRectFilled(ia, ib, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia, ib, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, aida::ui::with_alpha(t.accent_dim, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 7.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::InputTextWithHint("##val", "value", ui.value_buf, sizeof(ui.value_buf));
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);
		ImGui::PopItemWidth();
		cx += input_w + 10.f;
	}

	if (sc.config.scan_mode == memory_scanner::scan_mode_t::value_between) {
		ImFont* body_fn = aida::ui::fonts::body();
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(cx, oy + (h - body_fn->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), "to");
		cx += 28.f;
		float input2_w = 140.f;
		ImVec2 ia2(cx, input_y);
		ImVec2 ib2(cx + input2_w, input_y + input_h);
		dl->AddRectFilled(ia2, ib2, aida::ui::with_alpha(t.bg_elevated, a), 8.f);
		dl->AddRect(ia2, ib2, aida::ui::with_alpha(t.border_focus, a * 0.55f), 8.f, 0, 1.5f);
		ImGui::SetCursorScreenPos(ImVec2(cx + 4.f, input_y + 2.f));
		ImGui::PushItemWidth(input2_w - 8.f);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, a));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 7.f));
		ImGui::InputTextWithHint("##val2", "max", ui.value_buf2, sizeof(ui.value_buf2));
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
		ImGui::PopItemWidth();
		cx += input2_w + 10.f;
	}

	{
		ImFont* hex_fn = aida::ui::fonts::body();
		float lbl_w = ImGui::CalcTextSize("HEX").x;
		float pill_w = lbl_w + 40.f;
		float pill_h = input_h;
		float py = input_y;
		ImGui::SetCursorScreenPos(ImVec2(cx, py));
		ImGui::PushID("hex_toggle");
		ImGui::InvisibleButton("##hex_b", ImVec2(pill_w, pill_h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		if (clk) sc.config.hex_input = !sc.config.hex_input;
		bool on = sc.config.hex_input;
		ImU32 track = on ? aida::ui::with_alpha(t.accent_dim, a * 0.92f)
		                  : aida::ui::with_alpha(t.panel_header, a);
		ImU32 border = on ? aida::ui::with_alpha(t.accent_u32, a * 0.95f)
		                   : aida::ui::with_alpha(t.border_strong, a);
		if (hov) border = aida::ui::with_alpha(t.accent_hover, a);
		ImVec2 pa(cx, py);
		ImVec2 pb(cx + pill_w, py + pill_h);
		dl->AddRectFilled(pa, pb, track, pill_h * 0.5f);
		dl->AddRect(pa, pb, border, pill_h * 0.5f, 0, 1.5f);
		float knob_r = (pill_h - 8.f) * 0.5f;
		float knob_x = on ? (cx + pill_w - knob_r - 6.f) : (cx + knob_r + 6.f);
		float knob_y = py + pill_h * 0.5f;
		dl->AddCircleFilled(ImVec2(knob_x, knob_y), knob_r,
			on ? aida::ui::with_alpha(t.accent_u32, a)
			   : aida::ui::with_alpha(t.text_dim, a * 0.85f), 24);
		ImU32 lbl_col = on ? aida::ui::with_alpha(t.text_primary, a)
		                   : aida::ui::with_alpha(t.text_secondary, a);
		float lbl_x = on ? (cx + 12.f) : (cx + pill_w - lbl_w - 14.f);
		dl->AddText(hex_fn, hex_fn->FontSize,
			ImVec2(lbl_x, py + (pill_h - hex_fn->FontSize) * 0.5f),
			lbl_col, "HEX");
		ImGui::PopID();
		cx += pill_w + 12.f;
	}

	bool scanning = sc.scanning.load();
	bool attached = driver_bridge::is_loaded() && driver_bridge::attached_pid() != 0;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (scanning) {
		if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f))) {
			diag::log_tagged("mem_scanner", "view stop_button clicked");
			sc.scanning.store(false);
		}
	} else if (!sc.has_initial_scan) {
		if (aida::ui::button("First Scan", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !attached)) {
			diag::log_tagged_fmt("mem_scanner", "view first_scan_button value='%s' value2='%s'",
				ui.value_buf, ui.value_buf2);
			sc.config.value_text = ui.value_buf;
			sc.config.value_text2 = ui.value_buf2;
			memory_scanner::first_scan(sc.config);
		}
	} else {
		if (aida::ui::button("Next Scan", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), false)) {
			diag::log_tagged_fmt("mem_scanner", "view next_scan_button mode=%s value='%s'",
				memory_scanner::scan_mode_name(sc.config.scan_mode), ui.value_buf);
			memory_scanner::next_scan(sc.config.scan_mode, std::string(ui.value_buf), std::string(ui.value_buf2));
		}
	}
	cx += 110.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Undo", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(0.f, 0.f), !(sc.has_initial_scan && !scanning))) {
		diag::log_tagged("mem_scanner", "view undo_button");
		memory_scanner::undo_scan();
	}
	cx += 78.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	if (aida::ui::button("Reset", aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::md, ImVec2(0.f, 0.f), scanning)) {
		diag::log_tagged("mem_scanner", "view reset_button");
		memory_scanner::reset_scan();
	}
	cx += 80.f;

	if (scanning) {
		float prog = sc.scan_progress.load();
		float ring_r = 12.f;
		float ring_cx = cx + ring_r + 4.f;
		float ring_cy = oy + h * 0.5f;
		aida::ui::render_progress_ring(ImVec2(ring_cx, ring_cy), ring_r, 2.5f, prog, false);

		char pct_buf[8];
		snprintf(pct_buf, sizeof(pct_buf), "%d%%", static_cast<int>(prog * 100.f));
		ImVec2 pct_sz = ImGui::CalcTextSize(pct_buf);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(ring_cx - pct_sz.x * 0.5f, ring_cy - pct_sz.y * 0.5f),
			aida::ui::with_alpha(t.text_primary, a), pct_buf);
		cx += ring_r * 2.f + 14.f;
	}

	{
		char count_buf[64];
		snprintf(count_buf, sizeof(count_buf), "%zu found", sc.total_found);
		ImVec2 cts = ImGui::CalcTextSize(count_buf);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(ox + w - pad - cts.x, oy + (h - cts.y) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a), count_buf);
	}
}

static void render_results(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	float row_h = 32.f;
	float hdr_h = 36.f;

	ImU32 hdr_bg = aida::ui::with_alpha(t.panel_header, a * 0.85f);
	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + hdr_h), hdr_bg);
	dl->AddLine(ImVec2(ox, oy + hdr_h), ImVec2(ox + w, oy + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	float col_addr_w = 150.f;
	float col_val_w = 130.f;
	float col_prev_w = 130.f;
	float col_mod_w = w - col_addr_w - col_val_w - col_prev_w - 24.f;
	if (col_mod_w < 80.f) col_mod_w = 80.f;

	const char* col_names[4] = { "Address", "Value", "Previous", "Module" };
	float col_widths[4] = { col_addr_w, col_val_w, col_prev_w, col_mod_w };
	float hx = ox + 12.f;
	for (int c = 0; c < 4; ++c) {
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(hx, oy + (hdr_h - aida::ui::fonts::body()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	{
		char count_buf[32];
		snprintf(count_buf, sizeof(count_buf), "%zu found", sc.total_found);
		ImVec2 cs = ImGui::CalcTextSize(count_buf);
		float pad_x = 10.f;
		float pill_w = cs.x + pad_x * 2.f;
		float pill_h = 24.f;
		float bx = ox + w - 16.f - pill_w;
		float by = oy + (hdr_h - pill_h) * 0.5f;
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + pill_w, by + pill_h),
			aida::ui::with_alpha(t.accent_dim, a * 0.4f), pill_h * 0.5f);
		dl->AddRect(ImVec2(bx, by), ImVec2(bx + pill_w, by + pill_h),
			aida::ui::with_alpha(t.accent_u32, a * 0.6f), pill_h * 0.5f, 0, 1.f);
		ImFont* body_fn = aida::ui::fonts::body();
		dl->AddText(body_fn, body_fn->FontSize,
			ImVec2(bx + pad_x, by + (pill_h - body_fn->FontSize) * 0.5f),
			aida::ui::with_alpha(t.accent_u32, a), count_buf);
	}

	float body_y = oy + hdr_h;
	float body_h = h - hdr_h;
	int visible_rows = static_cast<int>(body_h / row_h);
	if (visible_rows < 1) visible_rows = 1;

	std::lock_guard<std::mutex> lk(sc.results_mutex);
	int total = static_cast<int>(sc.results.size());

	if (static_cast<int>(ui.row_flash.size()) < total) {
		ui.row_flash.resize(static_cast<size_t>(total), 0.f);
	}

	{
		std::unordered_set<uint64_t> current;
		current.reserve(static_cast<size_t>(total));
		for (auto& r : sc.results) current.insert(r.address);

		bool changed = (current.size() != ui.prev_result_addresses.size());
		if (!changed) {
			for (auto a_addr : current) {
				if (ui.prev_result_addresses.find(a_addr) == ui.prev_result_addresses.end()) {
					changed = true; break;
				}
			}
		}
		if (changed) {
			for (int i = 0; i < total; ++i) {
				if (ui.prev_result_addresses.find(sc.results[static_cast<size_t>(i)].address) ==
					ui.prev_result_addresses.end()) {
					if (i < static_cast<int>(ui.row_flash.size())) ui.row_flash[static_cast<size_t>(i)] = 1.f;
				}
			}
			ui.prev_result_addresses = std::move(current);
		}
	}

	for (auto& f : ui.row_flash) {
		if (f > 0.f) {
			f -= aida::ui::clock::dt() * 1.66f;
			if (f < 0.f) f = 0.f;
		}
	}

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) {
			ui.result_target_scroll_y -= wheel * row_h * 3.f;
			if (wheel > 0.f) ui.user_scrolled_up = true;
		}
	}
	float max_scroll = std::max(0.f, static_cast<float>(total) * row_h - body_h);
	ui.result_target_scroll_y = std::clamp(ui.result_target_scroll_y, 0.f, max_scroll);
	float dt = aida::ui::clock::dt();
	ui_anim::smooth_scroll(ui.result_scroll_y, ui.result_target_scroll_y, 20.f, dt);

	if (ui.result_target_scroll_y >= max_scroll - 1.f) ui.user_scrolled_up = false;

	int first_row = static_cast<int>(ui.result_scroll_y / row_h);
	int last_row = std::min(total, first_row + visible_rows + 2);

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	static float result_row_anim_time = 0.f;
	result_row_anim_time += dt;

	for (int i = first_row; i < last_row; ++i) {
		float ry = body_y + static_cast<float>(i) * row_h - ui.result_scroll_y;
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		float row_entrance = ui_anim::render_row_entrance(i - first_row, result_row_anim_time, 0.012f);
		bool sel = (ui.selected_result == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h), false);

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.selection, a * row_entrance));
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, a * row_entrance));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, a * row_entrance));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, 0.22f * a * row_entrance));
		}

		float flash = (i < static_cast<int>(ui.row_flash.size())) ? ui.row_flash[static_cast<size_t>(i)] : 0.f;
		if (flash > 0.f) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.accent_glow, a * flash * 0.85f));
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, a * flash));
		}

		auto& r = sc.results[static_cast<size_t>(i)];

		char addr_buf[20];
		snprintf(addr_buf, sizeof(addr_buf), "%016" PRIX64, r.address);

		float rx = ox + 12.f;
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_address, a * row_entrance), addr_buf);
		rx += col_addr_w;

		std::string cur_str = memory_scanner::format_value(r.current_value, sc.config.value_type);
		ImU32 cur_color = aida::ui::with_alpha(t.success, a * row_entrance);
		if (!r.previous_value.empty() && !r.current_value.empty()) {
			int64_t cv = 0, pv = 0;
			std::memcpy(&cv, r.current_value.data(),
				std::min(r.current_value.size(), sizeof(int64_t)));
			std::memcpy(&pv, r.previous_value.data(),
				std::min(r.previous_value.size(), sizeof(int64_t)));
			if (cv > pv) cur_color = aida::ui::with_alpha(t.success, a * row_entrance);
			else if (cv < pv) cur_color = aida::ui::with_alpha(t.error, a * row_entrance);
			else cur_color = aida::ui::with_alpha(t.text_primary, a * row_entrance);
		}
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f), cur_color, cur_str.c_str());
		rx += col_val_w;

		if (!r.previous_value.empty()) {
			std::string prev_str = memory_scanner::format_value(r.previous_value, sc.config.value_type);
			dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
				ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f),
				aida::ui::with_alpha(t.text_dim, a * row_entrance), prev_str.c_str());
		}
		rx += col_prev_w;

		if (!r.module_name.empty()) {
			char mod_buf[128];
			snprintf(mod_buf, sizeof(mod_buf), "%s+0x%" PRIX64, r.module_name.c_str(), r.module_offset);
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(rx, ry + (row_h - aida::ui::fonts::body()->FontSize) * 0.5f),
				aida::ui::with_alpha(t.text_secondary, a * row_entrance), mod_buf);
		}

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.selected_result = i;

		if (hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			diag::log_tagged_fmt("mem_scanner", "view double_click_add_address row=%d addr=0x%016llX",
				i, static_cast<unsigned long long>(r.address));
			memory_scanner::add_address(r.address, "", sc.config.value_type);
		}
	}

	ImGui::PopClipRect();

	if (total > visible_rows) {
		float sb_w = 6.f;
		float sb_x = ox + w - sb_w - 4.f;
		float content_total = static_cast<float>(total) * row_h;
		ui_anim::render_custom_scrollbar(dl, sb_x, body_y, sb_w, body_h,
			ui.result_scroll_y, content_total, body_h,
			a, ui.result_sb_dragging, ui.result_sb_drag_offset);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		cfg.title = sc.has_initial_scan ? "No matches" : "Nothing scanned yet";
		cfg.body = sc.has_initial_scan
			? "Refine your filter or undo to widen the search."
			: "Pick a value type and a comparison, then start a scan.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	} else if (sc.scanning.load() && total < 6) {
		float sk_y = body_y + static_cast<float>(total) * row_h + 6.f;
		for (int s = 0; s < 4; ++s) {
			if (sk_y + 16.f > body_y + body_h) break;
			aida::ui::skeleton::render_block(dl,
				ImVec2(ox + 12.f, sk_y),
				ImVec2(ox + w - 24.f, sk_y + 14.f), 6.f, 1.4f);
			sk_y += 22.f;
		}
	}

	float pill_target = (ui.user_scrolled_up && total > visible_rows) ? 1.f : 0.f;
	ui.autoscroll_pill_alpha = aida::motion::smooth_lerp(ui.autoscroll_pill_alpha, pill_target, 12.f, dt);
	if (ui.autoscroll_pill_alpha > 0.02f) {
		float pa = ui.autoscroll_pill_alpha;
		const char* lbl = "Jump to bottom";
		ImVec2 pts = ImGui::CalcTextSize(lbl);
		float pad_x = 12.f;
		float pw = pts.x + pad_x * 2.f + 14.f;
		float ph = 26.f;
		float px = ox + w * 0.5f - pw * 0.5f;
		float py = oy + h - ph - 14.f;
		ImVec2 pa_min(px, py - (1.f - pa) * 6.f);
		ImVec2 pa_max(px + pw, py + ph - (1.f - pa) * 6.f);

		dl->AddRectFilled(pa_min, pa_max,
			aida::ui::with_alpha(t.bg_overlay, a * pa * 0.95f), ph * 0.5f);
		dl->AddRect(pa_min, pa_max,
			aida::ui::with_alpha(t.accent_u32, a * pa), ph * 0.5f, 0, 1.f);

		float dot_cx = pa_min.x + pad_x;
		float dot_cy = (pa_min.y + pa_max.y) * 0.5f;
		dl->AddTriangleFilled(
			ImVec2(dot_cx - 5.f, dot_cy - 3.f),
			ImVec2(dot_cx + 5.f, dot_cy - 3.f),
			ImVec2(dot_cx, dot_cy + 4.f),
			aida::ui::with_alpha(t.accent_u32, a * pa));
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(dot_cx + 10.f, pa_min.y + (ph - aida::ui::fonts::body()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a * pa), lbl);

		ImGui::SetCursorScreenPos(pa_min);
		ImGui::PushID("##scroll_jump");
		ImGui::InvisibleButton("##sj_b", ImVec2(pw, ph));
		if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
			ui.result_target_scroll_y = max_scroll;
			ui.user_scrolled_up = false;
		}
		ImGui::PopID();
	}
}

static void render_address_list(ImDrawList* dl, float ox, float oy, float w, float h, float a) {
	auto& sc = memory_scanner::g_state;
	auto& ui = g_ui;
	const auto& t = aida::ui::resolved();

	float row_h = 30.f;
	float hdr_h = 32.f;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + hdr_h),
		aida::ui::with_alpha(t.panel_header, a * 0.85f));
	dl->AddLine(ImVec2(ox, oy + hdr_h), ImVec2(ox + w, oy + hdr_h),
		aida::ui::with_alpha(t.border_subtle, a), 1.f);

	dl->AddText(aida::ui::fonts::body_em(), 13.f,
		ImVec2(ox + 12.f, oy + (hdr_h - 13.f) * 0.5f),
		aida::ui::with_alpha(t.text_primary, a), "Address List");

	{
		ImGui::SetCursorScreenPos(ImVec2(ox + w - 90.f, oy + (hdr_h - 18.f) * 0.5f));
		ImGui::PushID("##auto_tog");
		bool prev = ui.auto_refresh;
		aida::ui::toggle_switch("##atog", &ui.auto_refresh, aida::ui::size_t_::sm);
		(void)prev;
		ImGui::PopID();
		const char* lbl = ui.auto_refresh ? "Auto" : "Manual";
		ImU32 lbl_col = ui.auto_refresh ? aida::ui::with_alpha(t.accent_u32, a)
		                                 : aida::ui::with_alpha(t.text_dim, a);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(ox + w - 50.f, oy + (hdr_h - aida::ui::fonts::body()->FontSize) * 0.5f), lbl_col, lbl);
	}

	float col_freeze_w = 56.f;
	float col_desc_w = 160.f;
	float col_addr_w = 150.f;
	float col_type_w = 90.f;
	float col_val_w = w - col_freeze_w - col_desc_w - col_addr_w - col_type_w - 28.f;
	if (col_val_w < 60.f) col_val_w = 60.f;

	const char* col_names[5] = { "Freeze", "Description", "Address", "Type", "Value" };
	float col_widths[5] = { col_freeze_w, col_desc_w, col_addr_w, col_type_w, col_val_w };

	float tbl_hdr_h = 22.f;
	dl->AddRectFilled(ImVec2(ox, oy + hdr_h), ImVec2(ox + w, oy + hdr_h + tbl_hdr_h),
		aida::ui::with_alpha(t.bg_overlay, a * 0.4f));

	float hx = ox + 12.f;
	for (int c = 0; c < 5; ++c) {
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(hx, oy + hdr_h + (tbl_hdr_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, a), col_names[c]);
		hx += col_widths[c];
	}

	float body_y = oy + hdr_h + tbl_hdr_h;
	float body_h = h - hdr_h - tbl_hdr_h;
	int visible_rows = static_cast<int>(body_h / row_h);
	if (visible_rows < 1) visible_rows = 1;

	int freeze_toggle_idx = -1;
	bool freeze_toggle_val = false;
	int delete_idx = -1;

	std::unique_lock<std::mutex> lk(sc.address_mutex);
	int total = static_cast<int>(sc.address_list.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), false)) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f)
			ui.address_target_scroll_y -= wheel * row_h * 3.f;
	}
	float max_scroll = std::max(0.f, static_cast<float>(total) * row_h - body_h);
	ui.address_target_scroll_y = std::clamp(ui.address_target_scroll_y, 0.f, max_scroll);
	float dt = aida::ui::clock::dt();
	ui_anim::smooth_scroll(ui.address_scroll_y, ui.address_target_scroll_y, 20.f, dt);

	int first_row = static_cast<int>(ui.address_scroll_y / row_h);
	int last_row = std::min(total, first_row + visible_rows + 2);

	ImGui::PushClipRect(ImVec2(ox, body_y), ImVec2(ox + w, body_y + body_h), true);

	for (int i = first_row; i < last_row; ++i) {
		float ry = body_y + static_cast<float>(i) * row_h - ui.address_scroll_y;
		if (ry + row_h < body_y || ry > body_y + body_h) continue;

		bool sel = (ui.selected_address == i);
		bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h), false);

		if (sel) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.selection, a));
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + 3.f, ry + row_h),
				aida::ui::with_alpha(t.accent_u32, a));
		} else if (hov) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, a));
		} else if (i & 1) {
			dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + w, ry + row_h),
				aida::ui::with_alpha(t.hover_wash, 0.22f * a));
		}

		auto& e = sc.address_list[static_cast<size_t>(i)];
		float rx = ox + 12.f;

		{
			ImGui::PushID(i * 7 + 1);
			ImGui::SetCursorScreenPos(ImVec2(rx, ry + (row_h - 18.f) * 0.5f));
			bool fr = e.frozen;
			aida::ui::toggle_switch("##fz", &fr, aida::ui::size_t_::sm);
			if (fr != e.frozen) {
				e.frozen = fr;
				if (fr && !e.last_value.empty())
					e.freeze_value = e.last_value;
				freeze_toggle_idx = i;
				freeze_toggle_val = fr;
			}
			if (e.frozen) {
				float dot_cx = rx + 36.f;
				float dot_cy = ry + row_h * 0.5f;
				aida::ui::status_dot(ImVec2(dot_cx, dot_cy), 3.f,
					aida::ui::with_alpha(t.info, a), true, 1.4f);
			}
			ImGui::PopID();
		}
		rx += col_freeze_w;

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_primary, a),
			e.description.empty() ? "<no description>" : e.description.c_str());
		rx += col_desc_w;

		char abuf[20];
		snprintf(abuf, sizeof(abuf), "%016" PRIX64, e.address);
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_address, a), abuf);
		rx += col_addr_w;

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::body()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, a),
			memory_scanner::value_type_name(e.value_type));
		rx += col_type_w;

		std::string val_str = memory_scanner::format_value(e.last_value, e.value_type);
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(rx, ry + (row_h - aida::ui::fonts::code()->FontSize) * 0.5f),
			aida::ui::with_alpha(t.success, a), val_str.c_str());

		if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
			ui.selected_address = i;

		if (sel && ImGui::IsKeyPressed(ImGuiKey_Delete, false)) {
			delete_idx = i;
			ui.selected_address = -1;
			break;
		}
	}

	ImGui::PopClipRect();

	if (total > visible_rows) {
		float sb_w = 6.f;
		float sb_x = ox + w - sb_w - 4.f;
		float content_total = static_cast<float>(total) * row_h;
		ui_anim::render_custom_scrollbar(dl, sb_x, body_y, sb_w, body_h,
			ui.address_scroll_y, content_total, body_h,
			a, ui.address_sb_dragging, ui.address_sb_drag_offset);
	}

	if (total == 0) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Watchlist is empty";
		cfg.body = "Double-click a result above to start tracking and freezing values.";
		aida::ui::empty_state::render(ImVec2(ox, body_y), ImVec2(w, body_h), cfg);
	}

	lk.unlock();

	if (freeze_toggle_idx >= 0)
		memory_scanner::freeze_address(static_cast<size_t>(freeze_toggle_idx), freeze_toggle_val);
	if (delete_idx >= 0)
		memory_scanner::remove_address(static_cast<size_t>(delete_idx));
}

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float, float, float) {
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##scanner_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = width;
	float h = height;
	float a = alpha;

	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, a));

	auto& ui = g_ui;
	if (ui.auto_refresh) {
		ui.refresh_timer += aida::ui::clock::dt();
		if (ui.refresh_timer >= ui.refresh_interval) {
			ui.refresh_timer = 0.f;
			memory_scanner::refresh_address_list();
		}
	}

	float toolbar_h = 52.f;
	float remaining = h - toolbar_h;
	float results_h = remaining * 0.6f;
	float address_h = remaining - results_h;

	render_toolbar(dl, ox, oy, w, a);

	float results_y = oy + toolbar_h;
	render_results(dl, ox, results_y, w, results_h, a);

	float split_y = results_y + results_h;
	float pulse = aida::ui::clock::pulse(0.4f, 0.3f, 0.6f);
	dl->AddLine(ImVec2(ox + 12.f, split_y), ImVec2(ox + w - 12.f, split_y),
		aida::ui::with_alpha(t.accent_dim, a * pulse), 1.f);

	render_address_list(dl, ox, split_y + 1.f, w, address_h - 1.f, a);

	ImGui::EndChild();
}

}
