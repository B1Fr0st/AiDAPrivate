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
	ImGui::BeginChild("##fuzzer_view", ImVec2(width, height), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
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

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height), bg);

	float cx = ox + 12.f;
	float cy = oy + 8.f;
	const float toolbar_h = 72.f;

	dl->AddRectFilled(ImVec2(ox, cy - 4.f), ImVec2(ox + width, cy + toolbar_h), header_bg);

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

	ImGui::SameLine();
	if (ImGui::SmallButton("Export")) {
		fuzzer_engine::export_crashes();
	}
	ImGui::SameLine();
	if (ImGui::SmallButton("Import")) {
		fuzzer_engine::import_crashes();
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
	dl->AddRectFilled(ImVec2(ox + 4.f, cy), ImVec2(ox + width - 4.f, cy + stat_panel_h), stat_bg);

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
		float bx = ox + 12.f + static_cast<float>(i) * box_w;
		float by = cy + 8.f;
		dl->AddText(ImVec2(bx, by), dim_col, boxes[i].label);
		dl->AddText(ImVec2(bx, by + 18.f), boxes[i].color, boxes[i].value.c_str());
	}

	float graph_y = cy + 50.f;
	float graph_h = stat_panel_h - 58.f;
	float graph_w = width - 32.f;
	float gx = ox + 12.f;

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

	dl->AddRectFilled(ImVec2(ox + 4.f, cy), ImVec2(ox + width - 4.f, cy + 22.f), header_bg);
	std::snprintf(buf, sizeof(buf), "Unique Crashes (%zu)", crashes_copy.size());
	dl->AddText(ImVec2(cx, cy + 3.f), accent, buf);
	cy += 24.f;

	const float detail_panel_h = (st.selected_crash >= 0 && st.selected_crash < static_cast<int>(crashes_copy.size())) ? 240.f : 0.f;
	float crash_table_h = oy + height - cy - 8.f - detail_panel_h;
	float row_h = 22.f;
	float content_h = static_cast<float>(crashes_copy.size()) * row_h;

	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - crash_table_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, ImGui::GetIO().DeltaTime);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + width - 14.f, oy + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(crash_table_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(crashes_copy.size())) last_vis = static_cast<int>(crashes_copy.size());

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + height) continue;

		auto& crash = crashes_copy[static_cast<size_t>(i)];

		ImVec2 rmin(ox + 4.f, ry);
		ImVec2 rmax(ox + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = st.selected_crash == i;
		dl->AddRectFilled(rmin, rmax, selected ? sel_col : (hovered ? row_hover : (i % 2 == 0 ? row_even : row_odd)));

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_crash = selected ? -1 : i;
		}

		float rx = cx;

		char idx_buf[8];
		std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i + 1);
		dl->AddText(ImVec2(rx, ry + 3.f), dim_col, idx_buf);
		rx += 40.f;

		{
			ImU32 score_bg = IM_COL32(80, 80, 80, static_cast<int>(alpha * 200));
			ImU32 score_fg = text_col;
			switch (crash.score) {
			case fuzzer_engine::exploit_score_t::critical:
				score_bg = IM_COL32(180, 40, 40, static_cast<int>(alpha * 220));
				score_fg = IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
				break;
			case fuzzer_engine::exploit_score_t::high:
				score_bg = IM_COL32(200, 120, 40, static_cast<int>(alpha * 220));
				score_fg = IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
				break;
			case fuzzer_engine::exploit_score_t::medium:
				score_bg = IM_COL32(180, 180, 50, static_cast<int>(alpha * 200));
				score_fg = IM_COL32(30, 30, 30, static_cast<int>(alpha * 255));
				break;
			case fuzzer_engine::exploit_score_t::low:
				score_bg = IM_COL32(60, 140, 60, static_cast<int>(alpha * 200));
				score_fg = IM_COL32(255, 255, 255, static_cast<int>(alpha * 255));
				break;
			default: break;
			}
			const char* score_str = fuzzer_engine::exploit_score_name(crash.score);
			ImVec2 tsz = ImGui::CalcTextSize(score_str);
			float badge_w = tsz.x + 8.f;
			dl->AddRectFilled(ImVec2(rx, ry + 2.f), ImVec2(rx + badge_w, ry + row_h - 2.f), score_bg, 3.f);
			dl->AddText(ImVec2(rx + 4.f, ry + 3.f), score_fg, score_str);
			rx += badge_w + 6.f;
		}

		dl->AddText(ImVec2(rx, ry + 3.f), crash_col, fuzzer_engine::crash_type_name(crash.type));
		rx += width * 0.14f;

		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(crash.instruction_address));
		dl->AddText(ImVec2(rx, ry + 3.f), text_col, addr_buf);
		rx += width * 0.14f;

		if (!crash.crashing_instruction.empty()) {
			dl->AddText(ImVec2(rx, ry + 3.f), dim_col,
			            crash.crashing_instruction.c_str(),
			            crash.crashing_instruction.c_str() + std::min(crash.crashing_instruction.size(), static_cast<size_t>(30)));
			rx += width * 0.18f;
		} else {
			rx += width * 0.18f;
		}

		dl->AddText(ImVec2(rx, ry + 3.f), dim_col,
		            crash.description.c_str(),
		            crash.description.c_str() + std::min(crash.description.size(), static_cast<size_t>(40)));
	}

	ImGui::PopClipRect();

	if (content_h > crash_table_h) {
		ui_anim::render_custom_scrollbar(dl, ox + width - 12.f, cy, 10.f, crash_table_h,
		                                  st.scroll_y, content_h, crash_table_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (detail_panel_h > 0.f && st.selected_crash >= 0 && st.selected_crash < static_cast<int>(crashes_copy.size())) {
		auto& sel = crashes_copy[static_cast<size_t>(st.selected_crash)];
		float dy = cy + crash_table_h + 4.f;
		float dw = width - 8.f;

		dl->AddRectFilled(ImVec2(ox + 4.f, dy), ImVec2(ox + 4.f + dw, dy + detail_panel_h - 4.f), stat_bg);
		dl->AddRect(ImVec2(ox + 4.f, dy), ImVec2(ox + 4.f + dw, dy + detail_panel_h - 4.f),
		            IM_COL32(60, 60, 60, static_cast<int>(alpha * 200)));

		float dx = ox + 16.f;
		float dcy = dy + 6.f;

		char detail_buf[128];
		std::snprintf(detail_buf, sizeof(detail_buf), "Crash #%d — %s [%s]",
		              st.selected_crash + 1,
		              fuzzer_engine::crash_type_name(sel.type),
		              fuzzer_engine::exploit_score_name(sel.score));
		dl->AddText(ImVec2(dx, dcy), accent, detail_buf);
		dcy += 18.f;

		if (!sel.crashing_instruction.empty()) {
			std::snprintf(detail_buf, sizeof(detail_buf), "Instruction: %s", sel.crashing_instruction.c_str());
			dl->AddText(ImVec2(dx, dcy), text_col, detail_buf);
			dcy += 16.f;
		}

		std::snprintf(detail_buf, sizeof(detail_buf), "Fault: 0x%llX  RIP: 0x%llX",
		              static_cast<unsigned long long>(sel.fault_address),
		              static_cast<unsigned long long>(sel.rip));
		dl->AddText(ImVec2(dx, dcy), text_col, detail_buf);
		dcy += 16.f;

		float col1 = dx;
		float col2 = dx + dw * 0.25f;
		float col3 = dx + dw * 0.5f;
		float col4 = dx + dw * 0.75f;

		auto draw_reg = [&](float rx, float ry, const char* name, uint64_t val) {
			std::snprintf(detail_buf, sizeof(detail_buf), "%-4s 0x%016llX", name, static_cast<unsigned long long>(val));
			dl->AddText(ImVec2(rx, ry), dim_col, detail_buf);
		};

		draw_reg(col1, dcy, "RAX", sel.rax);
		draw_reg(col2, dcy, "RBX", sel.rbx);
		draw_reg(col3, dcy, "RCX", sel.rcx);
		draw_reg(col4, dcy, "RDX", sel.rdx);
		dcy += 14.f;

		draw_reg(col1, dcy, "RSP", sel.rsp);
		draw_reg(col2, dcy, "RBP", sel.rbp);
		draw_reg(col3, dcy, "RSI", sel.rsi);
		draw_reg(col4, dcy, "RDI", sel.rdi);
		dcy += 14.f;

		draw_reg(col1, dcy, "R8", sel.r8);
		draw_reg(col2, dcy, "R9", sel.r9);
		draw_reg(col3, dcy, "R10", sel.r10);
		draw_reg(col4, dcy, "R11", sel.r11);
		dcy += 14.f;

		draw_reg(col1, dcy, "R12", sel.r12);
		draw_reg(col2, dcy, "R13", sel.r13);
		draw_reg(col3, dcy, "R14", sel.r14);
		draw_reg(col4, dcy, "R15", sel.r15);
		dcy += 18.f;

		const char* mut_strat = "unknown";
		switch (sel.mutation.strategy) {
		case fuzzer_engine::mutation_strategy_t::bit_flip: mut_strat = "bit_flip"; break;
		case fuzzer_engine::mutation_strategy_t::byte_flip: mut_strat = "byte_flip"; break;
		case fuzzer_engine::mutation_strategy_t::arithmetic: mut_strat = "arithmetic"; break;
		case fuzzer_engine::mutation_strategy_t::interesting_values: mut_strat = "interesting"; break;
		case fuzzer_engine::mutation_strategy_t::havoc: mut_strat = "havoc"; break;
		case fuzzer_engine::mutation_strategy_t::splice: mut_strat = "splice"; break;
		default: break;
		}
		std::snprintf(detail_buf, sizeof(detail_buf), "Mutation: %s  offset=%zu  size=%zu",
		              mut_strat, sel.mutation.offset, sel.mutation.size);
		dl->AddText(ImVec2(dx, dcy), dim_col, detail_buf);
		dcy += 16.f;

		if (!sel.input.empty()) {
			std::string hex_str = "Input: ";
			size_t show_n = std::min(sel.input.size(), static_cast<size_t>(32));
			for (size_t bi = 0; bi < show_n; ++bi) {
				char hb[4];
				std::snprintf(hb, sizeof(hb), "%02X ", sel.input[bi]);
				hex_str += hb;
			}
			if (sel.input.size() > 32) hex_str += "...";
			dl->AddText(ImVec2(dx, dcy), dim_col, hex_str.c_str());
			dcy += 16.f;
		}

		if (sel.is_minimized) {
			std::string min_str = "Minimized: ";
			size_t show_n = std::min(sel.minimized_input.size(), static_cast<size_t>(32));
			for (size_t bi = 0; bi < show_n; ++bi) {
				char hb[4];
				std::snprintf(hb, sizeof(hb), "%02X ", sel.minimized_input[bi]);
				min_str += hb;
			}
			if (sel.minimized_input.size() > 32) min_str += "...";
			std::snprintf(detail_buf, sizeof(detail_buf), "%s (%zu bytes)", min_str.c_str(), sel.minimized_input.size());
			dl->AddText(ImVec2(dx, dcy), IM_COL32(152, 195, 121, static_cast<int>(alpha * 255)), detail_buf);
			dcy += 16.f;
		}

		dcy += 4.f;
		ImGui::SetCursorScreenPos(ImVec2(dx, dcy));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.2f, 0.3f, alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.3f, 0.4f, alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.35f, 0.35f, 0.45f, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.9f, alpha));

		bool analyzing = fz.analyzing_crash.load();
		bool minimizing = fz.minimizing.load();

		if (analyzing) {
			ImGui::BeginDisabled();
			ImGui::SmallButton("Analyzing...");
			ImGui::EndDisabled();
		} else {
			if (ImGui::SmallButton("AI Analyze")) {
				fuzzer_engine::ai_analyze_crash(st.selected_crash);
			}
		}
		ImGui::SameLine();
		if (minimizing) {
			ImGui::BeginDisabled();
			ImGui::SmallButton("Minimizing...");
			ImGui::EndDisabled();
		} else {
			if (ImGui::SmallButton("Minimize")) {
				fuzzer_engine::minimize_crash(st.selected_crash);
			}
		}

		ImGui::PopStyleColor(4);
		dcy += 26.f;

		if (!sel.ai_analysis.empty()) {
			dl->AddText(ImVec2(dx, dcy), accent, "AI Analysis:");
			dcy += 16.f;
			float wrap_w = dw - 24.f;
			ImVec2 tsz = ImGui::CalcTextSize(sel.ai_analysis.c_str(), nullptr, false, wrap_w);
			dl->AddText(nullptr, 0.f, ImVec2(dx, dcy),
			            IM_COL32(180, 180, 195, static_cast<int>(alpha * 220)),
			            sel.ai_analysis.c_str(),
			            sel.ai_analysis.c_str() + sel.ai_analysis.size(),
			            wrap_w);
		}
	}

	if (!fz.active && !running) {
		float center_y = oy + height * 0.5f;
		dl->AddText(ImVec2(cx, center_y), dim_col, "Configure target function address and input buffer, then click Start Fuzzing.");
		dl->AddText(ImVec2(cx, center_y + 18.f), dim_col, "The fuzzer uses Unicorn emulation snapshots for crash-safe iteration.");
	}
	ImGui::EndChild();
}

}
