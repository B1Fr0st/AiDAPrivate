#pragma once

#include <cstdio>
#include <string>

#include "imgui.h"
#include "aob_generator.hpp"
#include "ui_anim.hpp"

namespace aob_view {

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_saved = -1;
};

inline state_t g_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = g_state;
	auto& gen = aob_generator::g_state;

	const ImU32 bg          = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col    = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col     = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent      = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                    static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 fixed_col   = IM_COL32(86, 182, 194, static_cast<int>(alpha * 255));
	const ImU32 wild_col    = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 panel_bg    = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 header_bg   = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 row_even    = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd     = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover   = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 unique_col  = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 notuniq_col = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height), bg);

	float left_w = width * 0.55f;
	float right_w = width - left_w - 4.f;

	float cx = pos_x + 12.f;
	float cy = pos_y + 8.f;

	dl->AddRectFilled(ImVec2(pos_x, cy - 4.f), ImVec2(pos_x + left_w, cy + 32.f), header_bg);
	dl->AddText(ImVec2(cx, cy + 2.f), accent, "AOB Signature Generator");
	cy += 38.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));

	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##aob_addr", "Address (hex)", gen.address_input, sizeof(gen.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##aob_name", "Signature name", gen.name_input, sizeof(gen.name_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(80.f);
	ImGui::InputInt("##aob_count", &gen.instruction_count, 1, 4);
	if (gen.instruction_count < 1) gen.instruction_count = 1;
	if (gen.instruction_count > 128) gen.instruction_count = 128;
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(2);

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
	ImGui::Checkbox("Auto-wildcard", &gen.auto_wildcard);
	ImGui::SameLine();
	ImGui::Checkbox("Validate uniqueness", &gen.validate_uniqueness);
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

	bool generating = gen.generating.load();
	if (!generating) {
		if (ImGui::SmallButton("Generate")) {
			uint64_t addr = 0;
			if (gen.address_input[0]) {
				addr = std::strtoull(gen.address_input, nullptr, 16);
			}
			if (addr != 0) {
				aob_generator::generate_from_address(addr, gen.instruction_count, gen.auto_wildcard);
			}
		}
	} else {
		ImGui::SmallButton("Generating...");
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("Save")) {
		aob_generator::save_current();
	}

	bool batch_running = gen.batch_generating.load();
	if (batch_running) {
		ImGui::SameLine();
		char batch_buf[32];
		std::snprintf(batch_buf, sizeof(batch_buf), "Batch %d/%d",
		              gen.batch_done.load(), gen.batch_total.load());
		ImGui::SmallButton(batch_buf);
	}

	ImGui::PopStyleColor(4);

	cy += 28.f;

	aob_generator::signature_t current_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		current_copy = gen.current;
	}

	if (!current_copy.bytes.empty()) {
		dl->AddRectFilled(ImVec2(cx - 4.f, cy), ImVec2(pos_x + left_w - 8.f, cy + 24.f), panel_bg);

		char info_buf[128];
		std::snprintf(info_buf, sizeof(info_buf), "0x%llX  |  %s  |  %zu bytes  |  Score: %.0f%% (%s)",
		              static_cast<unsigned long long>(current_copy.address),
		              current_copy.module_name.empty() ? "<unknown>" : current_copy.module_name.c_str(),
		              current_copy.bytes.size(),
		              current_copy.quality_score * 100.f,
		              aob_generator::score_grade(current_copy.quality_score));
		dl->AddText(ImVec2(cx, cy + 4.f), dim_col, info_buf);

		{
			float score_x = pos_x + left_w - 60.f;
			ImU32 grade_col = dim_col;
			float qs = current_copy.quality_score;
			if (qs >= 0.85f) grade_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
			else if (qs >= 0.7f) grade_col = IM_COL32(97, 175, 239, static_cast<int>(alpha * 255));
			else if (qs >= 0.5f) grade_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
			else grade_col = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
			dl->AddRectFilled(ImVec2(score_x, cy + 2.f), ImVec2(score_x + 40.f, cy + 20.f), grade_col, 3.f);
			const char* grade_str = aob_generator::score_grade(current_copy.quality_score);
			ImVec2 gsz = ImGui::CalcTextSize(grade_str);
			dl->AddText(ImVec2(score_x + 20.f - gsz.x * 0.5f, cy + 3.f),
			            IM_COL32(30, 30, 30, static_cast<int>(alpha * 255)), grade_str);
		}
		cy += 30.f;

		float byte_x = cx;
		float byte_y = cy;
		const float byte_w = 22.f;
		const float byte_h = 18.f;
		const float max_x = pos_x + left_w - 20.f;

		for (size_t i = 0; i < current_copy.bytes.size(); ++i) {
			if (byte_x + byte_w > max_x) {
				byte_x = cx;
				byte_y += byte_h + 2.f;
			}

			char hex[4];
			if (current_copy.bytes[i].wildcard) {
				hex[0] = '?'; hex[1] = '?'; hex[2] = 0;
				dl->AddText(ImVec2(byte_x, byte_y), wild_col, hex);
			} else {
				std::snprintf(hex, sizeof(hex), "%02X", current_copy.bytes[i].value);
				dl->AddText(ImVec2(byte_x, byte_y), fixed_col, hex);
			}

			byte_x += byte_w;
		}

		cy = byte_y + byte_h + 12.f;

		dl->AddText(ImVec2(cx, cy), dim_col, "Standard:");
		cy += 16.f;
		std::string standard_fmt = aob_generator::format_signature(current_copy);
		dl->AddText(ImVec2(cx, cy), text_col, standard_fmt.c_str(), standard_fmt.c_str() + std::min(standard_fmt.size(), static_cast<size_t>(200)));
		cy += 16.f;

		dl->AddText(ImVec2(cx, cy), dim_col, "IDA Style:");
		cy += 16.f;
		std::string ida_fmt = aob_generator::format_ida_signature(current_copy);
		dl->AddText(ImVec2(cx, cy), text_col, ida_fmt.c_str(), ida_fmt.c_str() + std::min(ida_fmt.size(), static_cast<size_t>(200)));
		cy += 16.f;

		dl->AddText(ImVec2(cx, cy), dim_col, "Code Pattern:");
		cy += 16.f;
		std::string code_fmt = aob_generator::format_code_signature(current_copy);
		dl->AddText(ImVec2(cx, cy), text_col, code_fmt.c_str(), code_fmt.c_str() + std::min(code_fmt.size(), static_cast<size_t>(200)));
		cy += 16.f;

		dl->AddText(ImVec2(cx, cy), dim_col, "x64dbg:");
		cy += 16.f;
		std::string x64dbg_fmt = aob_generator::format_x64dbg_signature(current_copy);
		dl->AddText(ImVec2(cx, cy), text_col, x64dbg_fmt.c_str(), x64dbg_fmt.c_str() + std::min(x64dbg_fmt.size(), static_cast<size_t>(200)));
		cy += 20.f;

		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.2f, 0.2f, alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.3f, 0.3f, alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.35f, 0.35f, 0.35f, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.9f, alpha));

		if (ImGui::SmallButton("Copy Standard")) {
			ImGui::SetClipboardText(standard_fmt.c_str());
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Copy IDA")) {
			ImGui::SetClipboardText(ida_fmt.c_str());
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Copy Code")) {
			ImGui::SetClipboardText(code_fmt.c_str());
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Copy YARA")) {
			std::string yara = aob_generator::format_yara_rule(current_copy);
			ImGui::SetClipboardText(yara.c_str());
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Copy x64dbg")) {
			ImGui::SetClipboardText(x64dbg_fmt.c_str());
		}

		cy += 22.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));

		if (ImGui::SmallButton("Optimize")) {
			std::lock_guard<std::mutex> lk(gen.mutex);
			aob_generator::optimize_signature(gen.current);
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Export JSON")) {
			char* appdata = nullptr;
			size_t elen = 0;
			_dupenv_s(&appdata, &elen, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.json";
				free(appdata);
				aob_generator::export_signatures_json(path);
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Export YARA")) {
			char* appdata = nullptr;
			size_t elen = 0;
			_dupenv_s(&appdata, &elen, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.yar";
				free(appdata);
				aob_generator::export_signatures_yara(path);
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Export Header")) {
			char* appdata = nullptr;
			size_t elen = 0;
			_dupenv_s(&appdata, &elen, "APPDATA");
			if (appdata) {
				std::string path = std::string(appdata) + "\\AiDA\\Standalone\\signatures.hpp";
				free(appdata);
				aob_generator::export_signatures_header(path);
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Compare")) {
			std::lock_guard<std::mutex> lk(gen.mutex);
			auto results = aob_generator::compare_signatures_against_process(gen.saved_signatures);
			for (size_t ri = 0; ri < results.size() && ri < gen.saved_signatures.size(); ++ri) {
				gen.saved_signatures[ri].unique = results[ri].still_found;
				gen.saved_signatures[ri].uniqueness_count = results[ri].match_count;
				gen.saved_signatures[ri].quality_score = aob_generator::compute_quality_score(gen.saved_signatures[ri]);
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Save Disk")) {
			aob_generator::save_signatures_to_disk();
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Load Disk")) {
			aob_generator::load_signatures_from_disk();
		}

		ImGui::PopStyleColor(4);
	} else {
		dl->AddText(ImVec2(cx, cy + 40.f), dim_col, "Enter an address and click Generate to create an AOB signature.");
		dl->AddText(ImVec2(cx, cy + 58.f), dim_col, "Auto-wildcard masks RIP-relative offsets and large immediates.");
	}

	float rx = pos_x + left_w + 4.f;
	float ry = pos_y + 8.f;
	dl->AddRectFilled(ImVec2(rx, ry - 4.f), ImVec2(rx + right_w, ry + 32.f), header_bg);
	dl->AddText(ImVec2(rx + 8.f, ry + 2.f), accent, "Saved Signatures");
	ry += 38.f;

	std::vector<aob_generator::signature_t> saved_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		saved_copy = gen.saved_signatures;
	}

	float saved_h = pos_y + height - ry - 8.f;
	float row_h = 22.f;
	float content_h = static_cast<float>(saved_copy.size()) * row_h;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - saved_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(rx, ry), ImVec2(rx + right_w, pos_y + height - 8.f), true);

	for (size_t i = 0; i < saved_copy.size(); ++i) {
		float row_y = ry + static_cast<float>(i) * row_h - st.scroll_y;
		if (row_y + row_h < ry || row_y > pos_y + height) continue;

		ImVec2 rmin(rx, row_y);
		ImVec2 rmax(rx + right_w, row_y + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_saved == static_cast<int>(i));
		dl->AddRectFilled(rmin, rmax, hovered ? row_hover : (selected ? header_bg : (i % 2 == 0 ? row_even : row_odd)));

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_saved = (selected ? -1 : static_cast<int>(i));
		}

		auto& sig = saved_copy[i];
		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(sig.address));

		{
			ImU32 g_bg = IM_COL32(80, 80, 80, static_cast<int>(alpha * 180));
			ImU32 g_fg = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
			float qs = sig.quality_score;
			if (qs >= 0.85f) g_bg = IM_COL32(152, 195, 121, static_cast<int>(alpha * 200));
			else if (qs >= 0.7f) g_bg = IM_COL32(97, 175, 239, static_cast<int>(alpha * 200));
			else if (qs >= 0.5f) g_bg = IM_COL32(229, 192, 123, static_cast<int>(alpha * 200));
			else if (qs > 0.f) g_bg = IM_COL32(224, 108, 117, static_cast<int>(alpha * 200));
			const char* g_str = aob_generator::score_grade(qs);
			dl->AddRectFilled(ImVec2(rx + 4.f, row_y + 3.f), ImVec2(rx + 22.f, row_y + row_h - 3.f), g_bg, 2.f);
			ImVec2 g_tsz = ImGui::CalcTextSize(g_str);
			dl->AddText(ImVec2(rx + 13.f - g_tsz.x * 0.5f, row_y + 3.f), g_fg, g_str);
		}

		dl->AddText(ImVec2(rx + 28.f, row_y + 3.f), text_col, sig.name.c_str());

		float mid_x = rx + right_w * 0.4f;
		dl->AddText(ImVec2(mid_x, row_y + 3.f), dim_col, addr_buf);

		float end_x = rx + right_w * 0.65f;
		char sz_buf[16];
		std::snprintf(sz_buf, sizeof(sz_buf), "%zu bytes", sig.bytes.size());
		dl->AddText(ImVec2(end_x, row_y + 3.f), dim_col, sz_buf);

		if (sig.uniqueness_count > 0) {
			float u_x = rx + right_w - 55.f;
			dl->AddText(ImVec2(u_x, row_y + 3.f), sig.unique ? unique_col : notuniq_col,
			            sig.unique ? "Unique" : "Non-unique");
		}
	}

	ImGui::PopClipRect();

	if (content_h > saved_h) {
		ui_anim::render_custom_scrollbar(dl, rx + right_w - 12.f, ry, 10.f, saved_h,
		                                  st.scroll_y, content_h, saved_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}
}

}
