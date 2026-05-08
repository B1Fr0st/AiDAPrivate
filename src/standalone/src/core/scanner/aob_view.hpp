#pragma once

#include <cstdio>
#include <string>

#include "imgui.h"
#include "aob_generator.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"

namespace aob_view {

enum class format_tab_t : int {
	standard = 0,
	ida_style,
	code_pattern,
	x64dbg,
	COUNT
};

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_saved = -1;
	format_tab_t active_format = format_tab_t::standard;
};

inline state_t g_state;

namespace detail {

inline aida::ui::components::pill_kind_t grade_pill_kind(float qs) {
	if (qs >= 0.85f) return aida::ui::components::pill_kind_t::success;
	if (qs >= 0.7f)  return aida::ui::components::pill_kind_t::info;
	if (qs >= 0.5f)  return aida::ui::components::pill_kind_t::warning;
	return aida::ui::components::pill_kind_t::error;
}

inline ImU32 grade_color(float qs) {
	const auto& t = aida::ui::resolved();
	if (qs >= 0.85f) return t.success;
	if (qs >= 0.7f)  return t.info;
	if (qs >= 0.5f)  return t.warning;
	return t.error;
}

inline std::string format_for_tab(const aob_generator::signature_t& sig, format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return aob_generator::format_signature(sig);
	case format_tab_t::ida_style:    return aob_generator::format_ida_signature(sig);
	case format_tab_t::code_pattern: return aob_generator::format_code_signature(sig);
	case format_tab_t::x64dbg:       return aob_generator::format_x64dbg_signature(sig);
	default: return aob_generator::format_signature(sig);
	}
}

inline const char* tab_name(format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return "Standard";
	case format_tab_t::ida_style:    return "IDA";
	case format_tab_t::code_pattern: return "Code";
	case format_tab_t::x64dbg:       return "x64dbg";
	default: return "Standard";
	}
}

inline void render_format_segmented(float x, float y, float& width_used, format_tab_t& active) {
	const auto& t = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float pad_x = 4.f;
	float h = 26.f;
	float total_w = pad_x * 2.f;
	float seg_w[(int)format_tab_t::COUNT];
	for (int i = 0; i < (int)format_tab_t::COUNT; ++i) {
		const char* nm = tab_name((format_tab_t)i);
		ImVec2 sz = ImGui::CalcTextSize(nm);
		seg_w[i] = sz.x + 18.f;
		total_w += seg_w[i];
	}
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.panel_header, 1.f), h * 0.5f);
	dl->AddRect(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.border_subtle, 1.f), h * 0.5f, 0, 1.f);

	float cx = x + pad_x;
	for (int i = 0; i < (int)format_tab_t::COUNT; ++i) {
		ImGui::PushID(i);
		ImGui::SetCursorScreenPos(ImVec2(cx, y));
		ImGui::InvisibleButton("##seg", ImVec2(seg_w[i], h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		bool act = (active == (format_tab_t)i);
		if (clk) active = (format_tab_t)i;

		if (act) {
			ImVec2 a(cx + 2.f, y + 2.f);
			ImVec2 b(cx + seg_w[i] - 2.f, y + h - 2.f);
			dl->AddRectFilledMultiColor(a, b,
				t.accent_grad_top, t.accent_grad_top,
				t.accent_grad_bot, t.accent_grad_bot);
		} else if (hov) {
			dl->AddRectFilled(ImVec2(cx + 2.f, y + 2.f),
				ImVec2(cx + seg_w[i] - 2.f, y + h - 2.f),
				aida::ui::with_alpha(t.hover_wash, 1.f), (h - 4.f) * 0.5f);
		}

		const char* nm = tab_name((format_tab_t)i);
		ImVec2 ts = ImGui::CalcTextSize(nm);
		ImU32 tc = act ? IM_COL32(255, 255, 255, 240) : t.text_secondary;
		dl->AddText(ImVec2(cx + (seg_w[i] - ts.x) * 0.5f, y + (h - ts.y) * 0.5f), tc, nm);

		cx += seg_w[i];
		ImGui::PopID();
	}
	width_used = total_w;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float)
{
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##aob_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	auto* dl = ImGui::GetWindowDrawList();
	auto& st = g_state;
	auto& gen = aob_generator::g_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = ImGui::GetWindowSize().x;
	float h = ImGui::GetWindowSize().y;

	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, alpha));

	float left_w = w * 0.55f;
	float right_w = w - left_w - 8.f;

	float cx = ox + 16.f;
	float cy = oy + 12.f;

	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(cx, cy),
		aida::ui::with_alpha(t.text_primary, alpha),
		"AOB Signature Generator");
	cy += 22.f;

	{
		float input_h = 32.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		aida::ui::input_text("##aob_addr", gen.address_input, sizeof(gen.address_input),
			"Address (hex)", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 178.f, cy));
		aida::ui::input_text("##aob_name", gen.name_input, sizeof(gen.name_input),
			"Signature name", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 356.f, cy + 2.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushItemWidth(80.f);
		ImGui::InputInt("##aob_count", &gen.instruction_count, 1, 4);
		if (gen.instruction_count < 1) gen.instruction_count = 1;
		if (gen.instruction_count > 128) gen.instruction_count = 128;
		ImGui::PopItemWidth();
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
	}
	cy += 38.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool aw = gen.auto_wildcard;
		aida::ui::toggle_switch("##aw", &aw, aida::ui::size_t_::sm);
		gen.auto_wildcard = aw;
		dl->AddText(aida::ui::fonts::caption(), 12.f,
			ImVec2(cx + 40.f, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Auto-wildcard");

		ImGui::SetCursorScreenPos(ImVec2(cx + 160.f, cy));
		bool vu = gen.validate_uniqueness;
		aida::ui::toggle_switch("##vu", &vu, aida::ui::size_t_::sm);
		gen.validate_uniqueness = vu;
		dl->AddText(aida::ui::fonts::caption(), 12.f,
			ImVec2(cx + 200.f, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Validate uniqueness");
	}
	cy += 30.f;

	{
		bool generating = gen.generating.load();
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Generate", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), generating, nullptr, generating)) {
			uint64_t addr = 0;
			if (gen.address_input[0]) {
				addr = std::strtoull(gen.address_input, nullptr, 16);
			}
			if (addr != 0) {
				aob_generator::generate_from_address(addr, gen.instruction_count, gen.auto_wildcard);
			}
		}

		ImGui::SetCursorScreenPos(ImVec2(cx + 100.f, cy));
		if (aida::ui::button("Save", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			aob_generator::save_current();
		}

		ImGui::SetCursorScreenPos(ImVec2(cx + 174.f, cy));
		if (aida::ui::button("Optimize", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			std::lock_guard<std::mutex> lk(gen.mutex);
			aob_generator::optimize_signature(gen.current);
		}

		bool batch_running = gen.batch_generating.load();
		if (batch_running) {
			char batch_buf[32];
			std::snprintf(batch_buf, sizeof(batch_buf), "Batch %d/%d",
			              gen.batch_done.load(), gen.batch_total.load());
			ImGui::SetCursorScreenPos(ImVec2(cx + 268.f, cy));
			aida::ui::pill_kind(batch_buf, aida::ui::components::pill_kind_t::accent,
				aida::ui::size_t_::sm, true);
		}
	}
	cy += 40.f;

	aob_generator::signature_t current_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		current_copy = gen.current;
	}

	if (!current_copy.bytes.empty()) {
		float card_x = cx - 4.f;
		float card_w = ox + left_w - card_x - 12.f;
		float card_h = 36.f;
		dl->AddRectFilled(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 10.f);
		dl->AddRect(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);

		char info_buf[160];
		std::snprintf(info_buf, sizeof(info_buf), "0x%llX  |  %s  |  %zu bytes  |  %.0f%%",
		              static_cast<unsigned long long>(current_copy.address),
		              current_copy.module_name.empty() ? "<unknown>" : current_copy.module_name.c_str(),
		              current_copy.bytes.size(),
		              current_copy.quality_score * 100.f);
		dl->AddText(aida::ui::fonts::caption(), 12.f,
			ImVec2(card_x + 12.f, cy + (card_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, alpha), info_buf);

		{
			const char* grade_str = aob_generator::score_grade(current_copy.quality_score);
			ImU32 gc = detail::grade_color(current_copy.quality_score);
			const char* lbl = "Grade";
			ImVec2 ts_lbl = ImGui::CalcTextSize(lbl);
			float ph = 22.f;
			float pw = ts_lbl.x + 36.f;
			float gx = card_x + card_w - pw - 12.f;
			float gy = cy + (card_h - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.18f), ph * 0.5f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.55f), ph * 0.5f, 0, 1.f);
			float dot_cx = gx + 12.f;
			float dot_cy = gy + ph * 0.5f;
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 8.f,
				aida::ui::with_alpha(gc, 0.85f), 18);
			ImVec2 g_ts = ImGui::CalcTextSize(grade_str);
			dl->AddText(aida::ui::fonts::body_em(), 11.f,
				ImVec2(dot_cx - g_ts.x * 0.5f, dot_cy - 6.f),
				IM_COL32(255, 255, 255, 245), grade_str);
			dl->AddText(aida::ui::fonts::caption(), 11.f,
				ImVec2(dot_cx + 12.f, gy + (ph - 11.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), lbl);
		}
		cy += card_h + 10.f;

		float byte_x = cx;
		float byte_y = cy;
		const float byte_w = 24.f;
		const float byte_h = 18.f;
		const float max_x = ox + left_w - 20.f;

		ImU32 wild_col = aida::ui::with_alpha(t.error, alpha);
		ImU32 fixed_col = aida::ui::with_alpha(t.info, alpha);

		for (size_t i = 0; i < current_copy.bytes.size(); ++i) {
			if (byte_x + byte_w > max_x) {
				byte_x = cx;
				byte_y += byte_h + 2.f;
			}
			char hex[4];
			if (current_copy.bytes[i].wildcard) {
				hex[0] = '?'; hex[1] = '?'; hex[2] = 0;
				dl->AddText(aida::ui::fonts::code(), 12.f,
					ImVec2(byte_x, byte_y), wild_col, hex);
			} else {
				std::snprintf(hex, sizeof(hex), "%02X", current_copy.bytes[i].value);
				dl->AddText(aida::ui::fonts::code(), 12.f,
					ImVec2(byte_x, byte_y), fixed_col, hex);
			}
			byte_x += byte_w;
		}
		cy = byte_y + byte_h + 14.f;

		float seg_w_used = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		detail::render_format_segmented(cx, cy, seg_w_used, st.active_format);
		cy += 32.f;

		std::string fmt = detail::format_for_tab(current_copy, st.active_format);
		float code_h = 30.f;
		dl->AddRectFilled(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 8.f);
		dl->AddRect(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 8.f, 0, 1.f);
		ImGui::PushClipRect(ImVec2(cx, cy), ImVec2(ox + left_w - 16.f, cy + code_h), true);
		dl->AddText(aida::ui::fonts::code(), 12.f,
			ImVec2(cx + 4.f, cy + (code_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha), fmt.c_str());
		ImGui::PopClipRect();
		cy += code_h + 10.f;

		{
			ImGui::SetCursorScreenPos(ImVec2(cx, cy));
			char copy_lbl[24];
			std::snprintf(copy_lbl, sizeof(copy_lbl), "Copy %s", detail::tab_name(st.active_format));
			if (aida::ui::button(copy_lbl, aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				ImGui::SetClipboardText(fmt.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(cx + 110.f, cy));
			if (aida::ui::button("Copy YARA", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string yara = aob_generator::format_yara_rule(current_copy);
				ImGui::SetClipboardText(yara.c_str());
			}
		}
		cy += 30.f;

		{
			float bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export JSON", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.json";
					free(appdata);
					aob_generator::export_signatures_json(path);
				}
			}
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export YARA", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.yar";
					free(appdata);
					aob_generator::export_signatures_yara(path);
				}
			}
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export Header", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\signatures.hpp";
					free(appdata);
					aob_generator::export_signatures_header(path);
				}
			}
			cy += 30.f;

			bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Compare", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::lock_guard<std::mutex> lk(gen.mutex);
				auto results = aob_generator::compare_signatures_against_process(gen.saved_signatures);
				for (size_t ri = 0; ri < results.size() && ri < gen.saved_signatures.size(); ++ri) {
					gen.saved_signatures[ri].unique = results[ri].still_found;
					gen.saved_signatures[ri].uniqueness_count = results[ri].match_count;
					gen.saved_signatures[ri].quality_score = aob_generator::compute_quality_score(gen.saved_signatures[ri]);
				}
			}
			bx += 90.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Save Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				aob_generator::save_signatures_to_disk();
			}
			bx += 96.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Load Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				aob_generator::load_signatures_from_disk();
			}
		}
	} else {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
		cfg.title = "No signature yet";
		cfg.body = "Enter an address and click Generate to extract an AOB pattern.";
		aida::ui::empty_state::render(ImVec2(ox, cy), ImVec2(left_w, 220.f), cfg);
	}

	float rx = ox + left_w + 6.f;
	float ry = oy + 12.f;
	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(rx, ry),
		aida::ui::with_alpha(t.text_primary, alpha),
		"Saved Signatures");
	ry += 22.f;

	std::vector<aob_generator::signature_t> saved_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		saved_copy = gen.saved_signatures;
	}

	float saved_h = oy + h - ry - 12.f;
	float row_h = 28.f;
	float content_h = static_cast<float>(saved_copy.size()) * row_h;

	float dt = aida::ui::clock::dt();
	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - saved_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, dt);

	ImGui::PushClipRect(ImVec2(rx, ry), ImVec2(rx + right_w, oy + h - 8.f), true);

	static float saved_anim_time = 0.f;
	saved_anim_time += dt;

	for (size_t i = 0; i < saved_copy.size(); ++i) {
		float row_y = ry + static_cast<float>(i) * row_h - st.scroll_y;
		if (row_y + row_h < ry || row_y > oy + h) continue;

		ImVec2 rmin(rx, row_y);
		ImVec2 rmax(rx + right_w, row_y + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_saved == static_cast<int>(i));
		float entrance = ui_anim::render_row_entrance(static_cast<int>(i), saved_anim_time, 0.012f);

		if (selected) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.selection, alpha * entrance), 6.f);
			dl->AddRectFilled(rmin, ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(t.accent_u32, alpha * entrance));
		} else if (hovered) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.hover_wash, alpha * entrance), 6.f);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_saved = (selected ? -1 : static_cast<int>(i));
		}

		auto& sig = saved_copy[i];
		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(sig.address));

		{
			float gx = rx + 8.f;
			float gy = row_y + (row_h - 20.f) * 0.5f;
			ImU32 gc = detail::grade_color(sig.quality_score);
			const char* g_str = aob_generator::score_grade(sig.quality_score);
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.22f), 5.f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.55f), 5.f, 0, 1.f);
			ImVec2 g_ts = ImGui::CalcTextSize(g_str);
			dl->AddText(aida::ui::fonts::body_em(), 12.f,
				ImVec2(gx + (22.f - g_ts.x) * 0.5f, gy + (20.f - 12.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), g_str);
		}

		dl->AddText(aida::ui::fonts::body(), 12.f,
			ImVec2(rx + 38.f, row_y + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha * entrance), sig.name.c_str());

		float mid_x = rx + right_w * 0.42f;
		dl->AddText(aida::ui::fonts::code(), 11.f,
			ImVec2(mid_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, alpha * entrance), addr_buf);

		float end_x = rx + right_w * 0.65f;
		char sz_buf[16];
		std::snprintf(sz_buf, sizeof(sz_buf), "%zu B", sig.bytes.size());
		dl->AddText(aida::ui::fonts::caption(), 11.f,
			ImVec2(end_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha * entrance), sz_buf);

		if (sig.uniqueness_count > 0) {
			float u_x = rx + right_w - 76.f;
			ImGui::SetCursorScreenPos(ImVec2(u_x, row_y + (row_h - 18.f) * 0.5f));
			ImGui::PushID(static_cast<int>(i) + 4096);
			aida::ui::pill_kind(sig.unique ? "unique" : "non-unique",
				sig.unique ? aida::ui::components::pill_kind_t::success
				           : aida::ui::components::pill_kind_t::warning,
				aida::ui::size_t_::sm, true);
			ImGui::PopID();
		}
	}

	ImGui::PopClipRect();

	if (saved_copy.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Nothing saved yet";
		cfg.body = "Generated signatures appear here once you click Save.";
		aida::ui::empty_state::render(ImVec2(rx, ry), ImVec2(right_w, saved_h), cfg);
	}

	if (content_h > saved_h) {
		ui_anim::render_custom_scrollbar(dl, rx + right_w - 12.f, ry, 8.f, saved_h,
		                                  st.scroll_y, content_h, saved_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	ImGui::EndChild();
}

}
