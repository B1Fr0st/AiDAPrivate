#include "struct_recon_view.hpp"
#include "struct_recon_engine.hpp"
#include "struct_monitor.hpp"
#include "ui_anim.hpp"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>

namespace struct_recon_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_field = -1;
	bool  show_vtable = true;
	bool  show_access_log = false;
};

static local_state_t s_state;

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& sr = struct_recon::g_state;

	const ImU32 bg        = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col  = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col   = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent    = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 panel_bg  = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_even  = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd   = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 sel_col   = IM_COL32(60, 60, 80, static_cast<int>(alpha * 255));
	const ImU32 vtable_col= IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height), bg);

	float cx = pos_x + 12.f;
	float cy = pos_y + 8.f;
	const float toolbar_h = 64.f;

	dl->AddRectFilled(ImVec2(pos_x, cy - 4.f), ImVec2(pos_x + width, cy + toolbar_h), header_bg);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));

	ImGui::PushItemWidth(150.f);
	ImGui::InputTextWithHint("##sr_addr", "Base Address (hex)", sr.address_input, sizeof(sr.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(120.f);
	ImGui::InputTextWithHint("##sr_name", "Struct name", sr.name_input, sizeof(sr.name_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(60.f);
	ImGui::InputTextWithHint("##sr_size", "Size", sr.size_input, sizeof(sr.size_input));
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(2);

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

	bool monitoring = sr.monitoring.load();

	if (!monitoring) {
		if (ImGui::SmallButton("Snapshot")) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) {
				struct_recon::reconstruct_from_snapshot(addr, sz, sr.name_input);
			}
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Monitor (HWBP)")) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) {
				struct_recon::monitor_with_hwbp(addr, sz, sr.name_input);
			}
		}
		ImGui::SameLine();
		{
			bool live_active = struct_monitor::g_state.active.load();
			if (!live_active) {
				if (ImGui::SmallButton("Live Monitor")) {
					uint64_t addr = 0;
					int sz = 256;
					if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
					if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
					if (sz <= 0) sz = 256;
					if (sz > 4096) sz = 4096;
					if (addr != 0) {
						struct_monitor::start(addr, sz, sr.name_input);
					}
				}
			} else {
				if (ImGui::SmallButton("Stop Live")) {
					struct_monitor::stop();
				}
				ImGui::SameLine();
				uint64_t cps = struct_monitor::g_state.captures_per_second.load();
				uint64_t total = struct_monitor::g_state.total_captures.load();
				char live_buf[64];
				std::snprintf(live_buf, sizeof(live_buf), "%llu cap/s  %llu total",
				              static_cast<unsigned long long>(cps),
				              static_cast<unsigned long long>(total));
				ImGui::TextColored(ImVec4(accent_r, accent_g, accent_b, alpha), "%s", live_buf);
			}
		}
	} else {
		if (ImGui::SmallButton("Cancel")) {
			struct_recon::cancel();
		}
		ImGui::SameLine();
		float prog = sr.progress.load();
		char prog_buf[32];
		std::snprintf(prog_buf, sizeof(prog_buf), "%.0f%%", prog * 100.f);
		ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(accent_r, accent_g, accent_b, alpha));
		ImGui::ProgressBar(prog, ImVec2(100, 0), prog_buf);
		ImGui::PopStyleColor();
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("Export C++")) {
		std::lock_guard<std::mutex> lk(sr.mutex);
		std::string cpp = struct_recon::export_as_cpp(sr.current);
		ImGui::SetClipboardText(cpp.c_str());
	}

	ImGui::SameLine();
	{
		bool ai_naming = sr.ai_naming.load();
		if (ai_naming) {
			ImGui::BeginDisabled();
			ImGui::SmallButton("Naming...");
			ImGui::EndDisabled();
		} else {
			if (ImGui::SmallButton("AI Name")) {
				struct_recon::ai_name_fields();
			}
		}
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("Save")) {
		struct_recon::save_struct_to_disk(sr.current);
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("Load All")) {
		struct_recon::load_structs_from_disk();
	}

	ImGui::SameLine();
	if (ImGui::SmallButton("Refresh")) {
		struct_recon::refresh_value_history(sr.current);
	}

	ImGui::PopStyleColor(4);

	cy += toolbar_h - 24.f;

	struct_recon::reconstructed_struct_t current_copy;
	{
		std::lock_guard<std::mutex> lk(sr.mutex);
		current_copy = sr.current;
	}

	if (current_copy.fields.empty() && !monitoring) {
		dl->AddText(ImVec2(cx, cy + 40.f), dim_col, "Enter a base address and click Snapshot to reconstruct a struct.");
		dl->AddText(ImVec2(cx, cy + 58.f), dim_col, "Monitor (HWBP) mode uses hardware breakpoints for live analysis.");
		return;
	}

	{
		char info_buf[128];
		std::snprintf(info_buf, sizeof(info_buf), "%s  |  0x%llX  |  0x%X bytes  |  %zu fields",
		              current_copy.name.c_str(),
		              static_cast<unsigned long long>(current_copy.base_address),
		              current_copy.total_size,
		              current_copy.fields.size());
		dl->AddText(ImVec2(cx, cy), accent, info_buf);
		cy += 20.f;
	}

	bool show_right_panel = width > 600.f;
	float main_w = show_right_panel ? width * 0.65f : width - 24.f;
	float right_x = pos_x + main_w + 12.f;
	float right_w = width - main_w - 24.f;

	const float row_h = 22.f;
	const float table_top = cy;
	const float table_h = pos_y + height - cy - 8.f;
	float content_h = static_cast<float>(current_copy.fields.size()) * row_h;
	float visible_h = table_h;

	const char* col_names[] = {"Offset", "Type", "Name", "Size", "Conf", "Heat", "Comment"};
	const float col_pcts[] = {0.10f, 0.12f, 0.18f, 0.07f, 0.07f, 0.06f, 0.40f};

	float hx = cx;
	for (int c = 0; c < 7; ++c) {
		float cw = main_w * col_pcts[c];
		dl->AddRectFilled(ImVec2(hx, cy), ImVec2(hx + cw, cy + row_h), header_bg);
		dl->AddText(ImVec2(hx + 6.f, cy + 3.f), text_col, col_names[c]);
		hx += cw;
	}
	cy += row_h + 1.f;
	visible_h -= row_h + 1.f;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - visible_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(pos_x, cy), ImVec2(pos_x + main_w, pos_y + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(current_copy.fields.size())) last_vis = static_cast<int>(current_copy.fields.size());

	char buf[128];

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > pos_y + height) continue;

		auto& field = current_copy.fields[static_cast<size_t>(i)];

		ImVec2 rmin(pos_x, ry);
		ImVec2 rmax(pos_x + main_w, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = st.selected_field == i;
		ImU32 row_col = selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd));
		dl->AddRectFilled(rmin, rmax, row_col);

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_field = i;
		}

		float rx = cx;
		float cw;

		cw = main_w * col_pcts[0];
		std::snprintf(buf, sizeof(buf), "0x%04llX", static_cast<unsigned long long>(field.offset));
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, buf);
		rx += cw;

		cw = main_w * col_pcts[1];
		ImU32 type_col = struct_recon::field_type_color(field.type, alpha);
		if (field.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "%s[%d]", struct_recon::field_type_name(field.type), field.array_count);
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), type_col, buf);
		} else {
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), type_col, struct_recon::field_type_name(field.type));
		}
		rx += cw;

		cw = main_w * col_pcts[2];
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), text_col, field.name.c_str());
		rx += cw;

		cw = main_w * col_pcts[3];
		std::snprintf(buf, sizeof(buf), "%d", field.size);
		dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, buf);
		rx += cw;

		cw = main_w * col_pcts[4];
		{
			const char* conf_str = "?";
			ImU32 conf_col = dim_col;
			switch (field.type_confidence) {
			case struct_recon::confidence_t::strong:
				conf_str = "Strong";
				conf_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
				break;
			case struct_recon::confidence_t::moderate:
				conf_str = "Med";
				conf_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
				break;
			case struct_recon::confidence_t::weak:
				conf_str = "Weak";
				conf_col = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
				break;
			default:
				conf_str = "-";
				break;
			}
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), conf_col, conf_str);
		}
		rx += cw;

		cw = main_w * col_pcts[5];
		{
			int heat = field.value_history.heat_level();
			if (heat > 0) {
				float bar_w = (cw - 12.f) * (static_cast<float>(heat) / 10.f);
				ImU32 heat_col;
				if (heat <= 3) heat_col = IM_COL32(60, 140, 60, static_cast<int>(alpha * 180));
				else if (heat <= 6) heat_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 180));
				else heat_col = IM_COL32(224, 108, 117, static_cast<int>(alpha * 180));
				dl->AddRectFilled(ImVec2(rx + 6.f, ry + 5.f), ImVec2(rx + 6.f + bar_w, ry + row_h - 5.f), heat_col, 2.f);
			}
		}
		rx += cw;

		cw = main_w * col_pcts[6];
		if (!field.comment.empty()) {
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, field.comment.c_str());
		} else if (!field.accesses.empty()) {
			std::snprintf(buf, sizeof(buf), "%zu accesses", field.accesses.size());
			dl->AddText(ImVec2(rx + 6.f, ry + 3.f), dim_col, buf);
		}
	}

	ImGui::PopClipRect();

	if (content_h > visible_h) {
		ui_anim::render_custom_scrollbar(dl, pos_x + main_w - 12.f, table_top + row_h + 1.f,
		                                  10.f, visible_h, st.scroll_y, content_h, visible_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (show_right_panel && st.selected_field >= 0 &&
	    st.selected_field < static_cast<int>(current_copy.fields.size())) {

		auto& sel = current_copy.fields[static_cast<size_t>(st.selected_field)];

		float ry = table_top;
		dl->AddRectFilled(ImVec2(right_x - 4.f, ry), ImVec2(pos_x + width - 8.f, ry + row_h), header_bg);
		dl->AddText(ImVec2(right_x, ry + 3.f), accent, "Field Details");
		ry += row_h + 4.f;

		std::snprintf(buf, sizeof(buf), "Offset: 0x%04llX", static_cast<unsigned long long>(sel.offset));
		dl->AddText(ImVec2(right_x, ry), text_col, buf);
		ry += 16.f;

		std::snprintf(buf, sizeof(buf), "Size: %d bytes", sel.size);
		dl->AddText(ImVec2(right_x, ry), text_col, buf);
		ry += 16.f;

		std::snprintf(buf, sizeof(buf), "Type: %s", struct_recon::field_type_name(sel.type));
		ImU32 type_c = struct_recon::field_type_color(sel.type, alpha);
		dl->AddText(ImVec2(right_x, ry), type_c, buf);
		ry += 16.f;

		if (sel.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "Array: [%d]", sel.array_count);
			dl->AddText(ImVec2(right_x, ry), accent, buf);
			ry += 16.f;
		}

		{
			const char* conf_name = "Unknown";
			switch (sel.type_confidence) {
			case struct_recon::confidence_t::strong:   conf_name = "Strong"; break;
			case struct_recon::confidence_t::moderate:  conf_name = "Moderate"; break;
			case struct_recon::confidence_t::weak:      conf_name = "Weak"; break;
			default: break;
			}
			std::snprintf(buf, sizeof(buf), "Confidence: %s", conf_name);
			dl->AddText(ImVec2(right_x, ry), text_col, buf);
			ry += 16.f;
		}

		{
			int heat = sel.value_history.heat_level();
			std::snprintf(buf, sizeof(buf), "Heat: %d/10 (%d unique vals)", heat, static_cast<int>(sel.value_history.unique_count()));
			dl->AddText(ImVec2(right_x, ry), text_col, buf);
			ry += 16.f;
		}

		dl->AddText(ImVec2(right_x, ry), text_col,
		            (std::string("Name: ") + sel.name).c_str());
		ry += 20.f;

		if (sel.type == struct_recon::field_type_t::vtable_ptr && !sel.vtable_entries.empty()) {
			dl->AddText(ImVec2(right_x, ry), vtable_col, "VTable Entries:");
			ry += 18.f;

			for (size_t vi = 0; vi < sel.vtable_entries.size() && vi < 32; ++vi) {
				auto& ve = sel.vtable_entries[vi];

				bool has_symbol = ve.name.find('!') != std::string::npos ||
				                  ve.name.find('+') != std::string::npos;
				ImU32 name_col = has_symbol ? accent : dim_col;

				char idx_buf[16];
				std::snprintf(idx_buf, sizeof(idx_buf), "[%2d]", ve.index);
				dl->AddText(ImVec2(right_x + 4.f, ry), dim_col, idx_buf);

				char addr_buf[24];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
				              static_cast<unsigned long long>(ve.func_addr));
				dl->AddText(ImVec2(right_x + 40.f, ry), dim_col, addr_buf);

				float name_x = right_x + 170.f;
				if (name_x + 10.f < pos_x + width - 12.f) {
					dl->AddText(ImVec2(name_x, ry), name_col, ve.name.c_str());
				}

				ry += 15.f;
			}
		}

		if (!sel.accesses.empty()) {
			ry += 4.f;
			dl->AddText(ImVec2(right_x, ry), accent, "Access Log:");
			ry += 18.f;

			for (size_t ai = 0; ai < sel.accesses.size() && ai < 20; ++ai) {
				auto& acc = sel.accesses[ai];
				std::snprintf(buf, sizeof(buf), "%s 0x%llX  +0x%llX  %dB  x%d",
				              acc.is_write ? "W" : "R",
				              static_cast<unsigned long long>(acc.instruction_addr),
				              static_cast<unsigned long long>(acc.access_offset),
				              acc.access_size, acc.hit_count);
				dl->AddText(ImVec2(right_x + 4.f, ry), dim_col, buf);
				ry += 15.f;
			}
		}
	}
}

}
