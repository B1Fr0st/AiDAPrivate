#include "fuzzer_view.hpp"
#include "fuzzer_engine.hpp"
#include "ui_anim.hpp"
#include "imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
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
	float anim_time = 0.f;
	float detail_slide = 0.f;
	float running_pulse = 0.f;
	float graph_hover_x = -1.f;
	float stat_counters[8] = {};
	float stat_targets[8] = {};
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

	const auto& _t = themes::resolved;
	const auto _ta = [alpha](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, alpha);
	};
	const ImU32 bg          = _ta(_t.bg_base);
	const ImU32 text_col    = _ta(_t.text_primary);
	const ImU32 dim_col     = _ta(_t.text_dim);
	const ImU32 accent      = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
	                                    static_cast<int>(accent_b * 255), static_cast<int>(alpha * 255));
	const ImU32 header_bg   = _ta(_t.panel_header);
	const ImU32 stat_bg     = _ta(ui_anim::lighten(_t.panel_bg, 6));
	const ImU32 crash_col   = IM_COL32(224, 108, 117, static_cast<int>(alpha * 255));
	const ImU32 coverage_col= IM_COL32(152, 195, 121, static_cast<int>(alpha * 255));
	const ImU32 row_even    = _ta(_t.panel_bg);
	const ImU32 row_odd     = _ta(ui_anim::lighten(_t.panel_bg, 8));
	const ImU32 row_hover   = _ta(ui_anim::lighten(_t.panel_header, 14));
	const ImU32 sel_col     = _ta(ui_anim::lighten(_t.panel_header, 10));
	const ImU32 graph_bg    = _ta(_t.bg_base);
	const ImU32 graph_line  = IM_COL32(static_cast<int>(accent_r * 200), static_cast<int>(accent_g * 200),
	                                    static_cast<int>(accent_b * 200), static_cast<int>(alpha * 200));

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height), bg);

	float cx = ox + 12.f;
	float cy = oy + 8.f;
	const float toolbar_h = 72.f;

	ui_anim::render_toolbar(dl, ox, cy - 4.f, width, toolbar_h + 4.f, accent_r, accent_g, accent_b, alpha);

	ImGui::SetCursorScreenPos(ImVec2(cx, cy + 2.f));
	ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(35, 37, 48, static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(212, 212, 212, static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(60, 65, 80, static_cast<int>(alpha * 150)));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);

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

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);

	ImGui::SameLine();

	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(212, 212, 212, static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_CheckMark, accent);
	const char* strat_names[] = {"Bit Flip", "Byte Flip", "Arith", "Interesting", "Havoc", "Splice"};
	for (int i = 0; i < static_cast<int>(fuzzer_engine::mutation_strategy_t::COUNT); ++i) {
		if (i > 0) ImGui::SameLine();
		ImGui::Checkbox(strat_names[i], &fz.config.strategies[i]);
	}
	ImGui::PopStyleColor(2);

	cy += 26.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140),
		static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180),
		static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 240)));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100),
		static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, static_cast<int>(alpha * 255)));

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
	ImGui::PopStyleVar();

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

	float dt = ImGui::GetIO().DeltaTime;
	st.anim_time += dt;

	if (running) {
		st.running_pulse += dt * 3.f;
		if (st.running_pulse > 6.2831853f) st.running_pulse -= 6.2831853f;
	}

	float stat_panel_h = 160.f;
	ui_anim::render_panel_card(dl, ox + 4.f, cy, width - 8.f, stat_panel_h,
		accent_r, accent_g, accent_b, alpha, 6.f, true);

	if (running) {
		float pulse_a = (std::sin(st.running_pulse) + 1.f) * 0.5f;
		ImU32 pulse_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
			static_cast<int>(accent_b * 255), static_cast<int>(pulse_a * 25 * alpha));
		dl->AddRectFilled(ImVec2(ox + 4.f, cy), ImVec2(ox + width - 4.f, cy + stat_panel_h), pulse_col, 6.f);
		float dot_cx = ox + width - 20.f;
		float dot_cy = cy + 10.f;
		float dot_r = 4.f + pulse_a * 1.5f;
		ImU32 glow = IM_COL32(80, 220, 100, static_cast<int>(pulse_a * 40 * alpha));
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r + 4.f, glow, 16);
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r, IM_COL32(80, 220, 100, static_cast<int>(alpha * 240)), 16);
		ui_anim::render_status_pill(dl, ox + width - 120.f, cy + 6.f,
			"Running", IM_COL32(80, 220, 100, 220), alpha, st.anim_time, true);
	} else {
		ui_anim::render_status_pill(dl, ox + width - 124.f, cy + 6.f,
			"Idle", IM_COL32(120, 130, 150, 180), alpha, st.anim_time, false);
	}

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

	float box_w = (width - 32.f - 16.f) / 4.f;
	for (int i = 0; i < 8; ++i) {
		int col_idx = i % 4;
		int row_idx = i / 4;
		float bx = ox + 8.f + static_cast<float>(col_idx) * (box_w + 4.f);
		float by = cy + 4.f + static_cast<float>(row_idx) * 42.f;
		ui_anim::render_stat_card(dl, bx, by, box_w, 38.f,
			boxes[i].label, boxes[i].value.c_str(),
			accent_r, accent_g, accent_b, alpha, boxes[i].color);
	}

	float graph_y = cy + 90.f;
	float graph_h = stat_panel_h - 96.f;
	float graph_w = width - 32.f;
	float gx = ox + 12.f;

	dl->AddRectFilled(ImVec2(gx, graph_y), ImVec2(gx + graph_w, graph_y + graph_h),
		IM_COL32(16, 18, 24, static_cast<int>(alpha * 200)), 4.f);
	dl->AddRect(ImVec2(gx, graph_y), ImVec2(gx + graph_w, graph_y + graph_h),
		IM_COL32(40, 44, 58, static_cast<int>(alpha * 80)), 4.f);

	for (int gi = 1; gi < 4; ++gi) {
		float gy = graph_y + graph_h * static_cast<float>(gi) / 4.f;
		dl->AddLine(ImVec2(gx, gy), ImVec2(gx + graph_w, gy),
			IM_COL32(40, 44, 58, static_cast<int>(alpha * 60)));
	}

	dl->AddText(ImVec2(gx + 4.f, graph_y + 2.f),
		IM_COL32(100, 105, 120, static_cast<int>(alpha * 180)), "exec/s");

	if (rate_history.size() >= 2) {
		uint64_t max_rate = *std::max_element(rate_history.begin(), rate_history.end());
		if (max_rate == 0) max_rate = 1;

		float step = graph_w / static_cast<float>(rate_history.size() - 1);

		for (size_t i = 1; i < rate_history.size(); ++i) {
			float x1 = gx + static_cast<float>(i - 1) * step;
			float y1 = graph_y + graph_h - (static_cast<float>(rate_history[i - 1]) / static_cast<float>(max_rate)) * (graph_h - 14.f);
			float x2 = gx + static_cast<float>(i) * step;
			float y2 = graph_y + graph_h - (static_cast<float>(rate_history[i]) / static_cast<float>(max_rate)) * (graph_h - 14.f);

			ImVec2 quad[4] = {
				ImVec2(x1, y1), ImVec2(x2, y2),
				ImVec2(x2, graph_y + graph_h), ImVec2(x1, graph_y + graph_h)
			};
			ImU32 fill_top = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), static_cast<int>(alpha * 40));
			ImU32 fill_bot = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
				static_cast<int>(accent_b * 255), 0);
			dl->AddRectFilledMultiColor(ImVec2(x1, std::min(y1, y2)), ImVec2(x2, graph_y + graph_h),
				fill_top, fill_top, fill_bot, fill_bot);

			dl->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), graph_line, 2.f);
		}

		ImVec2 mouse = ImGui::GetMousePos();
		if (mouse.x >= gx && mouse.x <= gx + graph_w && mouse.y >= graph_y && mouse.y <= graph_y + graph_h) {
			float rel = (mouse.x - gx) / graph_w;
			size_t idx = static_cast<size_t>(rel * static_cast<float>(rate_history.size() - 1));
			if (idx < rate_history.size()) {
				float hx = gx + static_cast<float>(idx) * step;
				float hy = graph_y + graph_h - (static_cast<float>(rate_history[idx]) / static_cast<float>(max_rate)) * (graph_h - 14.f);
				dl->AddLine(ImVec2(hx, graph_y), ImVec2(hx, graph_y + graph_h),
					IM_COL32(255, 255, 255, static_cast<int>(alpha * 30)));
				dl->AddCircleFilled(ImVec2(hx, hy), 4.f, accent, 12);
				dl->AddCircle(ImVec2(hx, hy), 6.f, IM_COL32(255, 255, 255, static_cast<int>(alpha * 80)), 12, 1.f);
				char tip[32];
				std::snprintf(tip, sizeof(tip), "%llu/s", static_cast<unsigned long long>(rate_history[idx]));
				ImVec2 tsz = ImGui::CalcTextSize(tip);
				float tx = hx - tsz.x * 0.5f;
				if (tx < gx) tx = gx;
				if (tx + tsz.x > gx + graph_w) tx = gx + graph_w - tsz.x;
				dl->AddRectFilled(ImVec2(tx - 4.f, hy - tsz.y - 6.f), ImVec2(tx + tsz.x + 4.f, hy - 2.f),
					IM_COL32(10, 12, 18, static_cast<int>(alpha * 230)), 4.f);
				dl->AddText(ImVec2(tx, hy - tsz.y - 4.f), text_col, tip);
			}
		}
	}

	cy += stat_panel_h + 8.f;

	ui_anim::render_section_header(dl, ox + 4.f, cy, width - 8.f, 20.f, "Unique Crashes",
		accent_r, accent_g, accent_b, alpha);
	cy += 22.f;

	ui_anim::table_col_t crash_cols[] = {
		{ "#", 36.f },
		{ "Score", 70.f },
		{ "Type", width * 0.14f },
		{ "Address", width * 0.14f },
		{ "Instruction", width * 0.18f },
		{ "Description", width - 36.f - 70.f - width * 0.14f - width * 0.14f - width * 0.18f - 30.f }
	};
	ui_anim::render_table_header(dl, ox + 4.f, cy, width - 18.f, 22.f,
		crash_cols, 6, accent_r, accent_g, accent_b, alpha);
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

		float row_alpha = ui_anim::render_row_entrance(i - first_vis, st.anim_time > 1.f ? 1.f : st.anim_time);
		ui_anim::table_row_style_t row_style{};
		row_style.selected = selected;
		row_style.hovered = hovered;
		row_style.index = i;
		row_style.alpha = alpha;
		row_style.entrance = row_alpha;
		row_style.ar = accent_r;
		row_style.ag = accent_g;
		row_style.ab = accent_b;
		ui_anim::render_table_row(dl, rmin.x, rmin.y, rmax.x - rmin.x, row_h, row_style);

		if (selected) {
			ui_anim::render_glow_rect(dl, rmin.x, rmin.y, rmax.x - rmin.x, row_h, accent_r, accent_g, accent_b, alpha * 0.15f);
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y), accent, 1.5f);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (selected) {
				st.selected_crash = -1;
			} else {
				st.selected_crash = i;
				st.detail_slide = 0.f;
			}
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
		st.detail_slide += (1.f - st.detail_slide) * std::min(10.f * dt, 1.f);
		auto& sel = crashes_copy[static_cast<size_t>(st.selected_crash)];
		float dy = cy + crash_table_h + 4.f;
		float dw = width - 8.f;
		float slide_offset = (1.f - ui_anim::ease_out_cubic(st.detail_slide)) * 20.f;
		float detail_alpha = alpha * st.detail_slide;

		dl->AddRectFilled(ImVec2(ox + 4.f, dy + slide_offset), ImVec2(ox + 4.f + dw, dy + detail_panel_h - 4.f + slide_offset),
			IM_COL32(22, 24, 33, static_cast<int>(detail_alpha * 240)), 6.f);
		dl->AddRect(ImVec2(ox + 4.f, dy + slide_offset), ImVec2(ox + 4.f + dw, dy + detail_panel_h - 4.f + slide_offset),
			IM_COL32(50, 55, 70, static_cast<int>(detail_alpha * 80)), 6.f);

		ui_anim::render_gradient_header(dl, ox + 4.f, dy + slide_offset, dw, 24.f, accent_r, accent_g, accent_b, detail_alpha * 0.5f);

		float dx = ox + 16.f;
		float dcy = dy + 6.f + slide_offset;

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
		ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(static_cast<int>(accent_r * 140), static_cast<int>(accent_g * 140), static_cast<int>(accent_b * 140), static_cast<int>(alpha * 200)));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(static_cast<int>(accent_r * 180), static_cast<int>(accent_g * 180), static_cast<int>(accent_b * 180), static_cast<int>(alpha * 220)));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(static_cast<int>(accent_r * 100), static_cast<int>(accent_g * 100), static_cast<int>(accent_b * 100), static_cast<int>(alpha * 255)));
		ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, static_cast<int>(alpha * 255)));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);

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
		ImGui::PopStyleVar();
		dcy += 26.f;

		if (!sel.ai_analysis.empty()) {
			ui_anim::render_section_header(dl, dx - 4.f, dcy, dw - 8.f, 18.f, "AI Analysis", accent_r, accent_g, accent_b, alpha);
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
		ui_anim::render_empty_state(dl, ox, oy + height * 0.35f, width, height * 0.3f,
			"Configure target and click Start Fuzzing",
			accent_r, accent_g, accent_b, alpha, st.anim_time);
	}
	ImGui::EndChild();
}

}
