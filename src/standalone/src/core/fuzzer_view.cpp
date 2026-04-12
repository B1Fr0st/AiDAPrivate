#include "fuzzer_view.hpp"
#include "fuzzer_engine.hpp"
#include "ui_anim.hpp"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>

namespace fuzzer_view {

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_crash = -1;
	bool  show_corpus = false;
};

static local_state_t s_state;

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& fz = fuzzer_engine::g_state;

	const ImU32 bg          = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
	const ImU32 text_col    = IM_COL32(212, 212, 212, static_cast<int>(alpha * 255));
	const ImU32 dim_col     = IM_COL32(140, 140, 140, static_cast<int>(alpha * 255));
	const ImU32 accent      = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                    static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg   = IM_COL32(45, 45, 45, static_cast<int>(alpha * 255));
	const ImU32 stat_bg     = IM_COL32(38, 38, 38, static_cast<int>(alpha * 255));
	const ImU32 crash_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 coverage_col= IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 row_even    = IM_COL32(35, 35, 35, static_cast<int>(alpha * 255));
	const ImU32 row_odd     = IM_COL32(40, 40, 40, static_cast<int>(alpha * 255));
	const ImU32 row_hover   = IM_COL32(55, 55, 55, static_cast<int>(alpha * 255));
	const ImU32 sel_col     = IM_COL32(60, 60, 80, static_cast<int>(alpha * 255));
	const ImU32 graph_bg    = IM_COL32(25, 25, 25, static_cast<int>(alpha * 255));
	const ImU32 graph_line  = IM_COL32(static_cast<int>(accent_r * 200), static_cast<int>(accent_g * 200),
	                                    static_cast<int>(accent_b * 200), static_cast<int>(alpha * 200));

	dl->AddRectFilled(ImVec2(pos_x, pos_y), ImVec2(pos_x + width, pos_y + height), bg);

	float cx = pos_x + 12.f;
	float cy = pos_y + 8.f;
	const float toolbar_h = 72.f;

	dl->AddRectFilled(ImVec2(pos_x, cy - 4.f), ImVec2(pos_x + width, cy + toolbar_h), header_bg);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));

	ImGui::PushItemWidth(140.f);
	ImGui::InputTextWithHint("##fz_addr", "Target Address", fz.addr_input, sizeof(fz.addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(140.f);
	ImGui::InputTextWithHint("##fz_end", "End Address", fz.end_addr_input, sizeof(fz.end_addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(140.f);
	ImGui::InputTextWithHint("##fz_input", "Input Address", fz.input_addr, sizeof(fz.input_addr));
	ImGui::PopItemWidth();

	cy += 26.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushItemWidth(60.f);
	ImGui::InputTextWithHint("##fz_isz", "InpSz", fz.input_size_str, sizeof(fz.input_size_str));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(80.f);
	ImGui::InputTextWithHint("##fz_iter", "MaxIter", fz.max_iter_str, sizeof(fz.max_iter_str));
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(2);

	ImGui::SameLine();

	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
	const char* strat_names[] = {"Bit Flip", "Byte Flip", "Arith", "Interesting", "Havoc", "Splice"};
	for (int i = 0; i < static_cast<int>(fuzzer_engine::mutation_strategy_t::COUNT); ++i) {
		if (i > 0) ImGui::SameLine();
		ImGui::Checkbox(strat_names[i], &fz.config.strategies[i]);
	}
	ImGui::PopStyleColor();

	cy += 26.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

	bool running = fz.running.load();

	if (!running) {
		if (ImGui::SmallButton("Start Fuzzing")) {
			auto& cfg = fz.config;
			if (fz.addr_input[0]) cfg.target_address = std::strtoull(fz.addr_input, nullptr, 16);
			if (fz.end_addr_input[0]) cfg.end_address = std::strtoull(fz.end_addr_input, nullptr, 16);
			if (fz.input_addr[0]) cfg.input_address = std::strtoull(fz.input_addr, nullptr, 16);
			if (fz.input_size_str[0]) cfg.input_size = static_cast<int>(std::strtol(fz.input_size_str, nullptr, 0));
			if (fz.max_iter_str[0]) cfg.max_iterations = static_cast<uint32_t>(std::strtoul(fz.max_iter_str, nullptr, 0));
			if (cfg.input_size <= 0) cfg.input_size = 256;
			if (cfg.max_iterations == 0) cfg.max_iterations = 10000;
			if (cfg.target_address != 0) {
				fuzzer_engine::start_fuzzing();
			}
		}
	} else {
		if (ImGui::SmallButton("Stop")) {
			fuzzer_engine::stop_fuzzing();
		}
	}

	ImGui::PopStyleColor(4);

	cy += toolbar_h - 40.f;

	fuzzer_engine::fuzz_stats_t stats_copy;
	std::vector<fuzzer_engine::crash_info_t> crashes_copy;
	std::vector<uint64_t> rate_history;
	{
		std::lock_guard<std::mutex> lk(fz.mutex);
		stats_copy = fz.stats;
		crashes_copy = fz.unique_crashes;
		rate_history = fz.stats.exec_rate_history;
	}

	float stat_panel_h = 100.f;
	dl->AddRectFilled(ImVec2(pos_x + 4.f, cy), ImVec2(pos_x + width - 4.f, cy + stat_panel_h), stat_bg);

	struct stat_box_t { const char* label; std::string value; ImU32 color; };
	char buf[64];

	std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats_copy.total_executions));
	stat_box_t boxes[8];
	boxes[0] = {"Executions", buf, text_col};
	std::snprintf(buf, sizeof(buf), "%llu/s", static_cast<unsigned long long>(stats_copy.executions_per_second));
	boxes[1] = {"Speed", buf, accent};
	std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats_copy.total_crashes));
	boxes[2] = {"Crashes", buf, crash_col};
	std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats_copy.total_unique_crashes));
	boxes[3] = {"Unique", buf, crash_col};
	std::snprintf(buf, sizeof(buf), "%u", stats_copy.edge_coverage);
	boxes[4] = {"Edges", buf, coverage_col};
	std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(stats_copy.new_coverage_finds));
	boxes[5] = {"New Cov", buf, coverage_col};
	std::snprintf(buf, sizeof(buf), "%u", stats_copy.corpus_size);
	boxes[6] = {"Corpus", buf, text_col};
	std::snprintf(buf, sizeof(buf), "%.1fs", stats_copy.elapsed_seconds);
	boxes[7] = {"Elapsed", buf, dim_col};

	float box_w = (width - 32.f) / 8.f;
	for (int i = 0; i < 8; ++i) {
		float bx = pos_x + 12.f + static_cast<float>(i) * box_w;
		float by = cy + 8.f;
		dl->AddText(ImVec2(bx, by), dim_col, boxes[i].label);
		dl->AddText(ImVec2(bx, by + 18.f), boxes[i].color, boxes[i].value.c_str());
	}

	float graph_y = cy + 50.f;
	float graph_h = stat_panel_h - 58.f;
	float graph_w = width - 32.f;
	float gx = pos_x + 12.f;

	dl->AddRectFilled(ImVec2(gx, graph_y), ImVec2(gx + graph_w, graph_y + graph_h), graph_bg);

	if (rate_history.size() >= 2) {
		uint64_t max_rate = *std::max_element(rate_history.begin(), rate_history.end());
		if (max_rate == 0) max_rate = 1;

		float step = graph_w / static_cast<float>(rate_history.size() - 1);
		for (size_t i = 1; i < rate_history.size(); ++i) {
			float x1 = gx + static_cast<float>(i - 1) * step;
			float y1 = graph_y + graph_h - (static_cast<float>(rate_history[i - 1]) / static_cast<float>(max_rate)) * graph_h;
			float x2 = gx + static_cast<float>(i) * step;
			float y2 = graph_y + graph_h - (static_cast<float>(rate_history[i]) / static_cast<float>(max_rate)) * graph_h;
			dl->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), graph_line, 1.5f);
		}
	}

	cy += stat_panel_h + 8.f;

	dl->AddRectFilled(ImVec2(pos_x + 4.f, cy), ImVec2(pos_x + width - 4.f, cy + 22.f), header_bg);
	std::snprintf(buf, sizeof(buf), "Unique Crashes (%zu)", crashes_copy.size());
	dl->AddText(ImVec2(cx, cy + 3.f), accent, buf);
	cy += 24.f;

	float crash_table_h = pos_y + height - cy - 8.f;
	float row_h = 22.f;
	float content_h = static_cast<float>(crashes_copy.size()) * row_h;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - crash_table_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(pos_x, cy), ImVec2(pos_x + width - 14.f, pos_y + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(crash_table_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(crashes_copy.size())) last_vis = static_cast<int>(crashes_copy.size());

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > pos_y + height) continue;

		auto& crash = crashes_copy[static_cast<size_t>(i)];

		ImVec2 rmin(pos_x + 4.f, ry);
		ImVec2 rmax(pos_x + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = st.selected_crash == i;
		dl->AddRectFilled(rmin, rmax, selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd)));

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_crash = i;
		}

		float rx = cx;

		char idx_buf[8];
		std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i + 1);
		dl->AddText(ImVec2(rx, ry + 3.f), dim_col, idx_buf);
		rx += 40.f;

		dl->AddText(ImVec2(rx, ry + 3.f), crash_col, fuzzer_engine::crash_type_name(crash.type));
		rx += width * 0.18f;

		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(crash.instruction_address));
		dl->AddText(ImVec2(rx, ry + 3.f), text_col, addr_buf);
		rx += width * 0.16f;

		dl->AddText(ImVec2(rx, ry + 3.f), dim_col,
		            crash.description.c_str(),
		            crash.description.c_str() + std::min(crash.description.size(), static_cast<size_t>(60)));
	}

	ImGui::PopClipRect();

	if (content_h > crash_table_h) {
		ui_anim::render_custom_scrollbar(dl, pos_x + width - 12.f, cy, 10.f, crash_table_h,
		                                  st.scroll_y, content_h, crash_table_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (!fz.active && !running) {
		float center_y = pos_y + height * 0.5f;
		dl->AddText(ImVec2(cx, center_y), dim_col, "Configure target function address and input buffer, then click Start Fuzzing.");
		dl->AddText(ImVec2(cx, center_y + 18.f), dim_col, "The fuzzer uses Unicorn emulation snapshots for crash-safe iteration.");
	}
}

}
