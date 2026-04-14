#include "struct_recon_view.hpp"
#include "struct_recon_engine.hpp"
#include "struct_monitor.hpp"
#include "ui_anim.hpp"
#include "imgui.h"
#include "../helpers/globals.h"

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
	ImGui::BeginChild("##struct_recon_view", ImVec2(width, height), false,
	    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& sr = struct_recon::g_state;
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 bg        = _ta(_t.bg_base);
	const ImU32 text_col  = _ta(_t.text_primary);
	const ImU32 dim_col   = _ta(_t.text_dim);
	const ImU32 accent    = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                  static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg = _ta(_t.panel_header);
	const ImU32 panel_bg  = _ta(_t.panel_bg);
	const ImU32 row_even  = _ta(_t.panel_bg);
	const ImU32 row_odd   = _ta(ui_anim::lighten(_t.panel_bg, 8));
	const ImU32 row_hover = _ta(ui_anim::lighten(_t.panel_header, 14));
	const ImU32 sel_col   = _ta(ui_anim::lighten(_t.panel_header, 10));
	const ImU32 vtable_col= IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height), bg);

	float cx = ox + 12.f;
	float cy = oy + 8.f;
	const float toolbar_h = 64.f;

	ui_anim::render_toolbar(dl, ox, cy - 4.f, width, toolbar_h + 4.f, alpha, accent_r, accent_g, accent_b);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(35, 37, 48, static_cast<int>(200 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 65, 80, static_cast<int>(120 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(210, 210, 220, static_cast<int>(220 * alpha)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

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

	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140), static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(200 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180), static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(220 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100), static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(240 * alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, static_cast<int>(255 * alpha)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);

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
		struct_recon::refresh_value_history();
	}

	ImGui::PopStyleVar();
	ImGui::PopStyleColor(4);

	cy += toolbar_h - 24.f;

	struct_recon::reconstructed_struct_t current_copy;
	{
		std::lock_guard<std::mutex> lk(sr.mutex);
		current_copy = sr.current;
	}

	if (current_copy.fields.empty() && !monitoring) {
		ui_anim::render_empty_state(dl, ox, cy, width, oy + height - cy - 8.f,
			"Enter a base address and click Snapshot to reconstruct",
			accent_r, accent_g, accent_b, alpha,
			static_cast<float>(ImGui::GetTime()));
		ImGui::EndChild();
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
	float right_x = ox + main_w + 12.f;
	float right_w = width - main_w - 24.f;

	const float row_h = 22.f;
	const float table_top = cy;
	const float table_h = oy + height - cy - 8.f;
	float content_h = static_cast<float>(current_copy.fields.size()) * row_h;
	float visible_h = table_h;

	const char* col_names[] = {"Offset", "Type", "Name", "Size", "Conf", "Heat", "Comment"};
	const float col_pcts[] = {0.10f, 0.12f, 0.18f, 0.07f, 0.07f, 0.06f, 0.40f};

	ui_anim::table_col_t struct_cols[] = {
		{"Offset", main_w * 0.10f}, {"Type", main_w * 0.12f}, {"Name", main_w * 0.18f},
		{"Size", main_w * 0.07f}, {"Conf", main_w * 0.07f}, {"Heat", main_w * 0.06f},
		{"Comment", main_w * 0.40f}
	};
	ui_anim::render_table_header(dl, cx, cy, main_w, row_h, struct_cols, 7, accent_r, accent_g, accent_b, alpha);
	cy += row_h + 1.f;
	visible_h -= row_h + 1.f;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - visible_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + main_w, oy + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(current_copy.fields.size())) last_vis = static_cast<int>(current_copy.fields.size());

	char buf[128];

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + height) continue;

		auto& field = current_copy.fields[static_cast<size_t>(i)];

		ImVec2 rmin(ox, ry);
		ImVec2 rmax(ox + main_w, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = st.selected_field == i;
		ui_anim::render_table_row(dl, ox, ry, main_w, row_h,
			{selected, hovered, i, alpha, 1.f, accent_r, accent_g, accent_b});

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
			const char* conf_str = "-";
			ImU32 conf_col = dim_col;
			if (field.type_confidence >= 75.f) {
				conf_str = "Strong";
				conf_col = IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
			} else if (field.type_confidence >= 50.f) {
				conf_str = "Med";
				conf_col = IM_COL32(229, 192, 123, static_cast<int>(alpha * 255));
			} else if (field.type_confidence >= 25.f) {
				conf_str = "Weak";
				conf_col = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
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
		ui_anim::render_custom_scrollbar(dl, ox + main_w - 12.f, table_top + row_h + 1.f,
		                                  10.f, visible_h, st.scroll_y, content_h, visible_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (show_right_panel && st.selected_field >= 0 &&
	    st.selected_field < static_cast<int>(current_copy.fields.size())) {

		auto& sel = current_copy.fields[static_cast<size_t>(st.selected_field)];

		float ry = table_top;
		float rp_w = (ox + width - 8.f) - (right_x - 4.f);
		ui_anim::render_panel_card(dl, right_x - 4.f, ry, rp_w, row_h,
			accent_r, accent_g, accent_b, alpha, 4.f, true);
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
			if (sel.type_confidence >= 75.f) conf_name = "Strong";
			else if (sel.type_confidence >= 50.f) conf_name = "Moderate";
			else if (sel.type_confidence >= 25.f) conf_name = "Weak";
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
				if (name_x + 10.f < ox + width - 12.f) {
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
	ImGui::EndChild();
}

}
