#pragma once

#include <algorithm>
#include <cstdio>
#include <string>

#include "imgui.h"
#include "crypto_scanner.hpp"
#include "disasm_view.hpp"
#include "ui_anim.hpp"

extern DisasmState g_disasm;

namespace crypto_scanner_view {

struct state_t {
	float  scroll_y = 0.f;
	float  target_scroll_y = 0.f;
	bool   scrollbar_dragging = false;
	float  scrollbar_drag_offset = 0.f;
	int    category_filter = -1;
	char   search_filter[128] = {};
	int    sort_column = -1;
	bool   sort_ascending = true;
	int    ctx_hit_idx = -1;
};

inline state_t g_state;

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = g_state;
	auto& cs = crypto_scanner::g_state;
	const ImU32 bg        = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col  = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col   = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent    = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 row_even  = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd   = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 header_bg = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 bar_bg    = IM_COL32(50, 50, 50, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height), bg);

	float cx = pos_x + 12.f;
	float cy = pos_y + 8.f;
	const float toolbar_h = 36.f;

	dl->AddRectFilled(ImVec2(pos_x, cy - 4.f), ImVec2(pos_x + width, cy + toolbar_h), header_bg);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 2.f));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

	bool scanning = cs.scanning.load();

	if (!scanning) {
		if (ImGui::SmallButton("Scan Process")) {
			crypto_scanner::scan_process();
		}
	} else {
		if (ImGui::SmallButton("Cancel")) {
			crypto_scanner::cancel();
		}
	}

	ImGui::SameLine();
	if (!scanning) {
		if (ImGui::SmallButton("Scan File")) {
			if (g_disasm.file.loaded) {
				crypto_scanner::scan_file(g_disasm.file);
			}
		}
	}

	ImGui::SameLine();
	if (!scanning && !cs.scanning.load()) {
		if (ImGui::SmallButton("Entropy")) {
			crypto_scanner::scan_entropy();
		}
	}

	ImGui::SameLine();
	{
		bool analyzing = cs.analyzing.load();
		if (analyzing) {
			ImGui::BeginDisabled();
			ImGui::SmallButton("Analyzing...");
			ImGui::EndDisabled();
		} else {
			if (ImGui::SmallButton("AI Analyze")) {
				crypto_scanner::ai_analyze_results();
			}
		}
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("JSON")) {
		char* appdata = nullptr;
		size_t len = 0;
		_dupenv_s(&appdata, &len, "APPDATA");
		if (appdata) {
			std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export.json";
			free(appdata);
			crypto_scanner::export_results_json(path);
		}
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("CSV")) {
		char* appdata = nullptr;
		size_t len = 0;
		_dupenv_s(&appdata, &len, "APPDATA");
		if (appdata) {
			std::string path = std::string(appdata) + "\\AiDA\\Standalone\\crypto_export.csv";
			free(appdata);
			crypto_scanner::export_results_csv(path);
		}
	}

	ImGui::SameLine();

	ImGui::PopStyleColor(4);

	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
	ImGui::PushItemWidth(180.f);
	ImGui::InputTextWithHint("##crypto_filter", "Filter...", st.search_filter, sizeof(st.search_filter));
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(2);

	ImGui::SameLine();

	const char* cats[] = {"All", "Symmetric", "Hash", "Stream Cipher", "Block Cipher", "Checksum", "Encoding", "Asymmetric"};
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
	ImGui::PushItemWidth(120.f);
	int combo_sel = st.category_filter + 1;
	if (ImGui::Combo("##cat_combo", &combo_sel, cats, 8)) {
		st.category_filter = combo_sel - 1;
	}
	ImGui::PopItemWidth();
	ImGui::PopStyleColor(2);

	if (scanning) {
		ImGui::SameLine();
		float prog = cs.progress.load();
		ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(accent_r, accent_g, accent_b, alpha));
		ImGui::PushItemWidth(120.f);
		char prog_buf[32];
		std::snprintf(prog_buf, sizeof(prog_buf), "%.1f%%", prog * 100.f);
		ImGui::ProgressBar(prog, ImVec2(120, 0), prog_buf);
		ImGui::PopItemWidth();
		ImGui::PopStyleColor();
	}

	cy += toolbar_h + 8.f;

	std::vector<crypto_scanner::crypto_hit_t> filtered;
	{
		std::lock_guard<std::mutex> lk(cs.mutex);
		for (auto& hit : cs.results) {
			if (st.category_filter >= 0 && static_cast<int>(hit.category) != st.category_filter)
				continue;
			if (st.search_filter[0]) {
				std::string lower_name = hit.signature_name;
				std::string lower_algo = hit.algorithm;
				std::string lower_mod = hit.module_name;
				std::string lower_filter = st.search_filter;
				for (auto& c : lower_name) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_algo) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_mod) c = static_cast<char>(std::tolower(c));
				for (auto& c : lower_filter) c = static_cast<char>(std::tolower(c));
				if (lower_name.find(lower_filter) == std::string::npos &&
				    lower_algo.find(lower_filter) == std::string::npos &&
				    lower_mod.find(lower_filter) == std::string::npos)
					continue;
			}
			filtered.push_back(hit);
		}
	}

	if (st.sort_column >= 0) {
		std::sort(filtered.begin(), filtered.end(),
			[&](const crypto_scanner::crypto_hit_t& a, const crypto_scanner::crypto_hit_t& b) {
				int cmp = 0;
				switch (st.sort_column) {
				case 0: cmp = a.algorithm.compare(b.algorithm); break;
				case 1: cmp = a.signature_name.compare(b.signature_name); break;
				case 2: cmp = (a.address < b.address) ? -1 : (a.address > b.address ? 1 : 0); break;
				case 3: cmp = a.module_name.compare(b.module_name); break;
				default: break;
				}
				return st.sort_ascending ? (cmp < 0) : (cmp > 0);
			});
	}

	const float row_h = 22.f;
	const float table_top = cy;
	const float table_h = pos_y + height - cy - 8.f;
	const float col_widths[6] = {width * 0.12f, width * 0.18f, width * 0.16f, width * 0.22f, width * 0.14f, width * 0.16f};
	const char* col_names[6] = {"Algorithm", "Signature", "Address", "Module + Offset", "Category", "Refs"};

	float hx = cx;
	for (int c = 0; c < 6; ++c) {
		dl->AddRectFilled(ImVec2(hx, cy), ImVec2(hx + col_widths[c], cy + row_h), header_bg);
		ImGui::SetCursorScreenPos(ImVec2(hx + 6.f, cy + 3.f));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.9f, alpha));
		if (ImGui::SmallButton(col_names[c])) {
			if (st.sort_column == c) st.sort_ascending = !st.sort_ascending;
			else { st.sort_column = c; st.sort_ascending = true; }
		}
		ImGui::PopStyleColor();
		hx += col_widths[c];
	}
	cy += row_h + 1.f;

	float content_h = static_cast<float>(filtered.size()) * row_h;
	float visible_h = table_h - row_h - 1.f;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - visible_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(pos_x, cy), ImVec2(pos_x + width - 14.f, pos_y + height - 8.f), true);

	int first_visible = static_cast<int>(st.scroll_y / row_h);
	int last_visible = first_visible + static_cast<int>(visible_h / row_h) + 2;
	if (first_visible < 0) first_visible = 0;
	if (last_visible > static_cast<int>(filtered.size())) last_visible = static_cast<int>(filtered.size());

	char addr_buf[32];
	char offset_buf[64];

	for (int i = first_visible; i < last_visible; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > pos_y + height) continue;

		auto& hit = filtered[static_cast<size_t>(i)];
		ImVec2 row_min(pos_x, ry);
		ImVec2 row_max(pos_x + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(row_min, row_max);
		dl->AddRectFilled(row_min, row_max, hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd));

		if (hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
			globals::ui::active_center_view = center_view_t::disassembly;
			disasm_view::goto_address(hit.address, g_disasm);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			st.ctx_hit_idx = i;
			ImGui::OpenPopup("##crypto_ctx");
		}

		float rx = cx;
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), accent, hit.algorithm.c_str());
		rx += col_widths[0];

		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), text_col, hit.signature_name.c_str());
		rx += col_widths[1];

		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(hit.address));
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), text_col, addr_buf);
		rx += col_widths[2];

		std::snprintf(offset_buf, sizeof(offset_buf), "%s+0x%llX",
		              hit.module_name.c_str(), static_cast<unsigned long long>(hit.module_offset));
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, offset_buf);
		rx += col_widths[3];

		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, crypto_scanner::category_name(hit.category));

		rx += col_widths[4];
		if (!hit.referencing_functions.empty()) {
			char ref_buf[32];
			std::snprintf(ref_buf, sizeof(ref_buf), "%zu refs", hit.referencing_functions.size());
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), accent, ref_buf);
		}
	}

	ImGui::PopClipRect();

	if (ImGui::BeginPopup("##crypto_ctx")) {
		if (st.ctx_hit_idx >= 0 && st.ctx_hit_idx < static_cast<int>(filtered.size())) {
			auto& ctx_hit = filtered[static_cast<size_t>(st.ctx_hit_idx)];

			if (ImGui::MenuItem("Go to Disassembly")) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(ctx_hit.address, g_disasm);
			}

			if (!ctx_hit.referencing_functions.empty()) {
				if (ImGui::BeginMenu("Show References")) {
					for (auto ref_addr : ctx_hit.referencing_functions) {
						char ref_label[64];
						std::snprintf(ref_label, sizeof(ref_label), "0x%llX", static_cast<unsigned long long>(ref_addr));
						auto lbl = crypto_scanner::get_function_label(ref_addr);
						std::string menu_text = ref_label;
						if (!lbl.empty()) menu_text += " (" + lbl + ")";
						if (ImGui::MenuItem(menu_text.c_str())) {
							globals::ui::active_center_view = center_view_t::disassembly;
							disasm_view::goto_address(ref_addr, g_disasm);
						}
					}
					ImGui::EndMenu();
				}
			}

			if (ImGui::MenuItem("Copy Address")) {
				char addr_copy[32];
				std::snprintf(addr_copy, sizeof(addr_copy), "0x%llX", static_cast<unsigned long long>(ctx_hit.address));
				ImGui::SetClipboardText(addr_copy);
			}

			if (!ctx_hit.ai_analysis.empty()) {
				if (ImGui::BeginMenu("AI Analysis")) {
					ImGui::PushTextWrapPos(400.f);
					ImGui::TextUnformatted(ctx_hit.ai_analysis.c_str());
					ImGui::PopTextWrapPos();
					ImGui::EndMenu();
				}
			}
		}
		ImGui::EndPopup();
	}

	{
		char count_buf[128];
		std::lock_guard<std::mutex> lk(cs.mutex);
		size_t entropy_count = cs.entropy_map.size();
		if (entropy_count > 0) {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results  |  %zu entropy regions", filtered.size(), entropy_count);
		} else {
			std::snprintf(count_buf, sizeof(count_buf), "%zu results", filtered.size());
		}
		dl->AddText(ImVec2(pos_x + width - 200.f, pos_y + height - 20.f), dim_col, count_buf);
	}

	if (content_h > visible_h) {
		ui_anim::render_custom_scrollbar(dl, pos_x + width - 12.f, table_top + row_h + 1.f,
		                                  10.f, visible_h, st.scroll_y, content_h, visible_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}
}

}
