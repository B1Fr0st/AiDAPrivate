#pragma once

#include "decrypt_oracle.hpp"
#include "disasm_view.hpp"
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
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

extern DisasmState g_disasm;

namespace decrypt_oracle_view {

struct row_anim_t {
	float entrance_delay = 0.f;
	aida::ui::transition_t conf_anim;
	float spawned_at = 0.f;
};

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected_row = -1;
	int   sort_column = -1;
	bool  sort_ascending = true;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	float anim_time = 0.f;
	char  filter_buf[64] = {};
	int   prev_result_count = 0;
	std::unordered_map<uint64_t, row_anim_t> row_anims;
};

static local_state_t s_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y;
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##decrypt_oracle_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& oracle = decrypt_oracle::g_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float cx = wp.x;
	float cy = wp.y;

	st.anim_time += aida::ui::clock::dt();
	float dt = aida::ui::clock::dt();

	const auto& th = aida::ui::resolved();
	dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + width, cy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	const float toolbar_h = 64.f;
	const float strip_h = 72.f;
	const float pad = 12.f;

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(cx, cy), ImVec2(cx + width, cy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(cx, cy + toolbar_h - 1.f), ImVec2(cx + width, cy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float tx = cx + pad;
	float ty = cy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(tx, ty));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 6.f));
	ImGui::PushItemWidth(190.f);
	ImGui::InputTextWithHint("##do_addr", "Encrypted region (hex)",
		oracle.address_input, sizeof(oracle.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine(0.f, 10.f);
	ImGui::PushItemWidth(90.f);
	ImGui::InputTextWithHint("##do_size", "Size", oracle.size_input, sizeof(oracle.size_input));
	ImGui::PopItemWidth();
	ImGui::PopStyleVar(3);
	ImGui::PopStyleColor(3);

	ImGui::SameLine(0.f, 14.f);
	bool scanning = oracle.scanning.load();
	if (!scanning) {
		if (aida::ui::button("Scan & Decrypt", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(132.f, 32.f))) {
			uint64_t addr = 0;
			uint64_t sz = 4096;
			if (oracle.address_input[0]) addr = std::strtoull(oracle.address_input, nullptr, 16);
			if (oracle.size_input[0]) sz = std::strtoull(oracle.size_input, nullptr, 0);
			if (addr != 0) decrypt_oracle::scan_and_decrypt(addr, sz);
		}
	} else {
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(90.f, 32.f))) {
			oracle.cancel.store(true);
		}
	}

	ty += 32.f;

	if (scanning) {
		float prog = oracle.progress.load();
		int done = oracle.processed_xrefs.load();
		int total = oracle.total_xrefs.load();

		float bar_x = cx + pad;
		float bar_w = width - pad * 2.f;
		float bar_h = 6.f;
		float bar_y = ty + 4.f;

		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 3.f);
		{
			ImU32 prog_flat = aida::ui::mix(
				aida::ui::with_alpha(th.accent_grad_top, alpha),
				aida::ui::with_alpha(th.accent_grad_bot, alpha), 0.5f);
			dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w * prog, bar_y + bar_h),
				prog_flat, 3.f);
		}

		char prog_text[64];
		std::snprintf(prog_text, sizeof(prog_text), "%d / %d xrefs   %.0f%%",
			done, total, prog * 100.f);
		ImVec2 pts = ImGui::CalcTextSize(prog_text);
		dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
			11.f, ImVec2(bar_x + bar_w * 0.5f - pts.x * 0.5f, bar_y + bar_h + 2.f),
			aida::ui::with_alpha(th.text_dim, alpha), prog_text);
	} else {
		std::string status;
		{
			std::lock_guard<std::mutex> lk(oracle.mutex);
			status = oracle.status_text;
		}
		if (!status.empty()) {
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				11.f, ImVec2(cx + pad, ty + 2.f),
				aida::ui::with_alpha(th.text_dim, alpha), status.c_str());
		}
	}

	float strip_y = cy + toolbar_h + 4.f;
	{
		std::vector<decrypt_oracle::decrypted_string_t> ss_copy;
		{
			std::lock_guard<std::mutex> lk(oracle.mutex);
			ss_copy = oracle.results;
		}
		int found = static_cast<int>(ss_copy.size());
		double avg_conf = 0.0;
		int strong = 0;
		int total_len = 0;
		for (auto& r : ss_copy) {
			avg_conf += r.confidence;
			if (r.confidence >= 0.9f) strong++;
			total_len += r.length;
		}
		if (found > 0) avg_conf /= static_cast<double>(found);

		ImVec2 sa = ImVec2(cx + 8.f, strip_y);
		ImVec2 sb = ImVec2(cx + width - 8.f, strip_y + strip_h - 8.f);
		aida::ui::blur::render_glass_fill(dl, sa, sb, 8.f, alpha);
		aida::ui::blur::render_glass_border(dl, sa, sb, 8.f, alpha, 1.f);

		auto draw_stat = [&](float x_pos, const char* label, const char* value, ImU32 col) {
			ImFont* num = aida::ui::fonts::body_strong();
			if (!num) num = ImGui::GetFont();
			dl->AddText(num, 22.f, ImVec2(x_pos, sa.y + 10.f), col, value);
			ImFont* lblf = aida::ui::fonts::body();
			if (!lblf) lblf = ImGui::GetFont();
			dl->AddText(lblf, 13.f, ImVec2(x_pos, sa.y + 40.f),
				aida::ui::with_alpha(th.text_dim, alpha), label);
		};

		float cell_w = (width - 32.f) / 4.f;
		float sx = sa.x + 16.f;

		char fb[16], ab[16], sb_buf[16], lb[24];
		std::snprintf(fb, sizeof(fb), "%d", found);
		std::snprintf(ab, sizeof(ab), "%.0f%%", avg_conf * 100.0);
		std::snprintf(sb_buf, sizeof(sb_buf), "%d", strong);
		std::snprintf(lb, sizeof(lb), "%d B", total_len);

		ImU32 conf_col = aida::ui::with_alpha(th.text_primary, alpha);
		if (avg_conf > 0.75) conf_col = aida::ui::with_alpha(th.success, alpha);
		else if (avg_conf > 0.5) conf_col = aida::ui::with_alpha(th.warning, alpha);
		else if (found > 0) conf_col = aida::ui::with_alpha(th.error, alpha);

		draw_stat(sx, "Found", fb, aida::ui::with_alpha(th.text_primary, alpha));
		sx += cell_w;
		draw_stat(sx, "Avg Conf", ab, conf_col);
		sx += cell_w;
		draw_stat(sx, "High Conf", sb_buf, aida::ui::with_alpha(th.success, alpha));
		sx += cell_w;
		draw_stat(sx, "Total Len", lb, aida::ui::with_alpha(th.text_primary, alpha));
	}

	float table_top = cy + toolbar_h + strip_h + 8.f;
	float table_h = height - toolbar_h - strip_h - 12.f;

	const float col_func_w = 140.f;
	const float col_offset_w = 110.f;
	const float col_conf_w = 96.f;
	const float col_len_w = 60.f;
	const float col_string_w = width - col_func_w - col_offset_w - col_conf_w - col_len_w - pad * 2.f;

	float hx = cx + pad;
	float hy = table_top;
	const float row_h = 28.f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(hx, hy), ImVec2(cx + width - pad, hy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(hx, hy + row_h - 1.f), ImVec2(cx + width - pad, hy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
	float hxx = hx + 6.f;
	dl->AddText(head_em, 13.f, ImVec2(hxx, hy + 7.f), hc, "Source Func");
	hxx += col_func_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, hy + 7.f), hc, "Enc Offset");
	hxx += col_offset_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, hy + 7.f), hc, "Decrypted String");
	hxx += col_string_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, hy + 7.f), hc, "Conf");
	hxx += col_conf_w;
	dl->AddText(head_em, 13.f, ImVec2(hxx, hy + 7.f), hc, "Len");
	float conf_x = hx + col_func_w + col_offset_w + col_string_w;
	hy += row_h;

	std::vector<decrypt_oracle::decrypted_string_t> results_copy;
	{
		std::lock_guard<std::mutex> lk(oracle.mutex);
		results_copy = oracle.results;
	}

	if (static_cast<int>(results_copy.size()) > st.prev_result_count) {
		for (int i = st.prev_result_count; i < static_cast<int>(results_copy.size()); ++i) {
			uint64_t key = results_copy[static_cast<size_t>(i)].xref_addr;
			auto& ra = st.row_anims[key];
			ra.spawned_at = st.anim_time;
			ra.conf_anim.start(aida::motion::dur::lg, aida::motion::ease::out_cubic);
		}
	}
	st.prev_result_count = static_cast<int>(results_copy.size());

	int visible_rows = static_cast<int>((table_h - row_h) / row_h);
	int total_rows = static_cast<int>(results_copy.size());

	if (ImGui::IsMouseHoveringRect(ImVec2(cx, table_top), ImVec2(cx + width, cy + height))) {
		float wheel = ImGui::GetIO().MouseWheel;
		if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
	}
	float max_scroll = std::max(0.f, static_cast<float>(total_rows) * row_h - (table_h - row_h));
	if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
	if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

	ImGui::PushClipRect(ImVec2(hx, hy), ImVec2(cx + width - pad, cy + height - 8.f), true);

	int start_row = static_cast<int>(st.scroll_y / row_h);
	if (start_row < 0) start_row = 0;

	for (int i = start_row; i < total_rows && i < start_row + visible_rows + 2; ++i) {
		float ry = hy + static_cast<float>(i - start_row) * row_h;
		if (ry > cy + height) break;

		auto& r = results_copy[static_cast<size_t>(i)];
		auto& ra = st.row_anims[r.xref_addr];
		ra.conf_anim.tick(dt);

		float age = st.anim_time - ra.spawned_at;
		float entrance_t = age / 0.32f;
		if (entrance_t < 0.f) entrance_t = 0.f;
		if (entrance_t > 1.f) entrance_t = 1.f;
		float entrance = aida::motion::ease::out_cubic(entrance_t);

		ImVec2 rmin(hx, ry);
		ImVec2 rmax(cx + width - pad, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_row == i);

		ImU32 row_fill;
		if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
		else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
		else row_fill = (i & 1) ? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f * entrance) : 0u;
		if ((row_fill & 0xFF000000) != 0) {
			dl->AddRectFilled(rmin, rmax, row_fill, 4.f);
		}
		if (selected) {
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		}

		float sweep_age = age;
		if (sweep_age >= 0.f && sweep_age < 0.6f) {
			float sweep_p = sweep_age / 0.6f;
			float sweep_w = (rmax.x - rmin.x) * 0.30f;
			float sx = rmin.x - sweep_w + (rmax.x - rmin.x + sweep_w) * sweep_p;
			ImU32 sweep_a = aida::ui::with_alpha(th.success, 0.f);
			ImU32 sweep_b = aida::ui::with_alpha(th.success, alpha * (1.f - sweep_p) * 0.6f);
			dl->PushClipRect(rmin, rmax, true);
			dl->AddRectFilledMultiColor(
				ImVec2(sx, rmin.y), ImVec2(sx + sweep_w * 0.5f, rmax.y),
				sweep_a, sweep_b, sweep_b, sweep_a);
			dl->AddRectFilledMultiColor(
				ImVec2(sx + sweep_w * 0.5f, rmin.y), ImVec2(sx + sweep_w, rmax.y),
				sweep_b, sweep_a, sweep_a, sweep_b);
			dl->PopClipRect();
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_row = i;
		}
		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(r.source_function, g_disasm);
		}

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		char func_buf[24];
		std::snprintf(func_buf, sizeof(func_buf), "0x%llX",
			static_cast<unsigned long long>(r.source_function));
		dl->AddText(code_font, 13.f, ImVec2(hx + 6.f, ry + 7.f),
			aida::ui::with_alpha(th.text_primary, alpha * entrance), func_buf);

		char off_buf[24];
		std::snprintf(off_buf, sizeof(off_buf), "0x%llX",
			static_cast<unsigned long long>(r.encrypted_offset));
		dl->AddText(code_font, 13.f, ImVec2(hx + col_func_w + 4.f, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), off_buf);

		float str_max_w = col_string_w - 8.f;
		std::string display_str = r.decrypted;
		if (display_str.size() > 80) display_str = display_str.substr(0, 77) + "...";
		dl->AddText(code_font, 13.f,
			ImVec2(hx + col_func_w + col_offset_w + 4.f, ry + 7.f),
			aida::ui::with_alpha(th.success, alpha * entrance),
			display_str.c_str(), display_str.c_str() + display_str.size(),
			str_max_w);

		float conf_progress = ra.conf_anim.eased();
		if (ra.conf_anim.is_finished() && ra.conf_anim.at_target()) conf_progress = 1.f;
		float visible_conf = r.confidence * conf_progress;
		float bar_w = col_conf_w - 12.f;
		float bar_h = 7.f;
		float bar_x = conf_x + 4.f;
		float bar_y = ry + (row_h - bar_h) * 0.5f;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 2.f);
		ImU32 fill_top, fill_bot;
		if (r.confidence > 0.75f) {
			fill_top = th.success; fill_bot = aida::ui::darken(th.success, 30);
		} else if (r.confidence > 0.5f) {
			fill_top = th.warning; fill_bot = aida::ui::darken(th.warning, 30);
		} else {
			fill_top = th.error; fill_bot = aida::ui::darken(th.error, 30);
		}
		{
			ImU32 conf_flat = aida::ui::mix(
				aida::ui::with_alpha(fill_top, alpha * entrance),
				aida::ui::with_alpha(fill_bot, alpha * entrance),
				0.5f);
			dl->AddRectFilled(ImVec2(bar_x, bar_y),
				ImVec2(bar_x + bar_w * visible_conf, bar_y + bar_h),
				conf_flat, 2.f);
		}
		char conf_buf[16];
		std::snprintf(conf_buf, sizeof(conf_buf), "%.0f%%", r.confidence * 100.f);
		ImVec2 confts = ImGui::CalcTextSize(conf_buf);
		dl->AddText(code_font, 12.f, ImVec2(bar_x + bar_w - confts.x, ry + 5.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), conf_buf);

		char len_buf[16];
		std::snprintf(len_buf, sizeof(len_buf), "%d", r.length);
		dl->AddText(code_font, 13.f, ImVec2(conf_x + col_conf_w + 4.f, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), len_buf);
	}

	ImGui::PopClipRect();

	if (total_rows == 0) {
		if (scanning) {
			float cw = std::min(width - 40.f, 600.f);
			float ccx = cx + (width - cw) * 0.5f;
			float ccy = table_top + 12.f;
			for (int i = 0; i < 6; ++i) {
				float ry = ccy + static_cast<float>(i) * 28.f;
				aida::ui::skeleton::render_block(dl,
					ImVec2(ccx, ry),
					ImVec2(ccx + cw, ry + 22.f),
					6.f, 1.4f);
			}
		} else {
			ImVec2 e_pos = ImVec2(cx, table_top);
			ImVec2 e_sz = ImVec2(width, table_h);
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::key;
			cfg.title = "No decrypted strings";
			cfg.body  = "Enter an encrypted region address and click Scan & Decrypt to recover strings.";
			cfg.max_width = 360.f;
			aida::ui::empty_state::render(e_pos, e_sz, cfg);
		}
	}

	if (total_rows * row_h > table_h - row_h && table_h - row_h > 0.f) {
		float bar_x = cx + width - 10.f;
		float bar_y = table_top + row_h;
		float bar_h = table_h - row_h;
		float content_h = static_cast<float>(total_rows) * row_h;
		float ratio = bar_h / content_h;
		float thumb_h = std::max(bar_h * ratio, 24.f);
		float track = bar_h - thumb_h;
		float scroll_ratio = (content_h - bar_h > 0.f) ? st.scroll_y / (content_h - bar_h) : 0.f;
		float thumb_y = bar_y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 6.f, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 6.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
	}

	ImGui::EndChild();
}

}
