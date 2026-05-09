#include "fuzzer_view.hpp"
#include "fuzzer_engine.hpp"
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/empty_state.hpp"
#include "ui/blur_layer.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "imgui.h"
#include "../helpers/globals.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

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
	float detail_vel = 0.f;
	float running_pulse = 0.f;
	float graph_hover_x = -1.f;
	float stat_counter[8] = {};
	float stat_target[8] = {};
	float stat_velocity[8] = {};
	uint64_t last_unique_crashes = 0;
	aida::ui::flash_t new_crash_flash;
	int   new_crash_index = -1;
	float strategy_efficacy[6] = {};
	float strategy_efficacy_target[6] = {};
	int   strategy_count_total[6] = {};
	int   strategy_count_unique[6] = {};
};

static local_state_t s_state;

static const char* g_strategy_names[] = {
	"BitFlip", "ByteFlip", "Arith", "Interest", "Havoc", "Splice"
};

static int crashes_strategy_index(fuzzer_engine::mutation_strategy_t s) {
	switch (s) {
		case fuzzer_engine::mutation_strategy_t::bit_flip:           return 0;
		case fuzzer_engine::mutation_strategy_t::byte_flip:          return 1;
		case fuzzer_engine::mutation_strategy_t::arithmetic:         return 2;
		case fuzzer_engine::mutation_strategy_t::interesting_values: return 3;
		case fuzzer_engine::mutation_strategy_t::havoc:              return 4;
		case fuzzer_engine::mutation_strategy_t::splice:             return 5;
		default: return -1;
	}
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)pos_x; (void)pos_y;
	(void)accent_r; (void)accent_g; (void)accent_b;

	ImGui::BeginChild("##fuzzer_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	auto& fz = fuzzer_engine::g_state;

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();
	st.anim_time += dt;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	float cx = ox + 12.f;
	float cy = oy + 8.f;
	const float toolbar_h = 84.f;

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + width, oy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));

	ImGui::PushItemWidth(150.f);
	ImGui::InputTextWithHint("##fz_addr", "Target address", fz.addr_input, sizeof(fz.addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(150.f);
	ImGui::InputTextWithHint("##fz_end", "End address", fz.end_addr_input, sizeof(fz.end_addr_input));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(150.f);
	ImGui::InputTextWithHint("##fz_input", "Input address", fz.input_addr, sizeof(fz.input_addr));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(70.f);
	ImGui::InputTextWithHint("##fz_isz", "size", fz.input_size_str, sizeof(fz.input_size_str));
	ImGui::PopItemWidth();
	ImGui::SameLine();
	ImGui::PushItemWidth(90.f);
	ImGui::InputTextWithHint("##fz_iter", "max iter", fz.max_iter_str, sizeof(fz.max_iter_str));
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	const char* strat_names_full[] = {
		"Bit", "Byte", "Arith", "Interesting", "Havoc", "Splice"
	};
	for (int i = 0; i < static_cast<int>(fuzzer_engine::mutation_strategy_t::COUNT); ++i) {
		if (i > 0) ImGui::SameLine();
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.text_primary, alpha)));
		ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertU32ToFloat4(
			aida::ui::with_alpha(th.accent_u32, alpha)));
		ImGui::Checkbox(strat_names_full[i], &fz.config.strategies[i]);
		ImGui::PopStyleColor(2);
	}

	cy += 28.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	bool running = fz.running.load();
	if (!running) {
		if (aida::ui::button("Start Fuzzing", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(112.f, 28.f))) {
			auto& cfg = fz.config;
			if (fz.addr_input[0]) cfg.target_address = std::strtoull(fz.addr_input, nullptr, 16);
			if (fz.end_addr_input[0]) cfg.end_address = std::strtoull(fz.end_addr_input, nullptr, 16);
			if (fz.input_addr[0]) cfg.input_address = std::strtoull(fz.input_addr, nullptr, 16);
			if (fz.input_size_str[0]) cfg.input_size = static_cast<int>(std::strtol(fz.input_size_str, nullptr, 0));
			if (fz.max_iter_str[0]) cfg.max_iterations = static_cast<uint32_t>(std::strtoul(fz.max_iter_str, nullptr, 0));
			if (cfg.input_size <= 0) cfg.input_size = 256;
			if (cfg.max_iterations == 0) cfg.max_iterations = 10000;
			if (cfg.target_address != 0) fuzzer_engine::start_fuzzing();
		}
	} else {
		if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
			fuzzer_engine::stop_fuzzing();
		}
	}
	ImGui::SameLine();
	if (aida::ui::button("Export", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(78.f, 28.f))) {
		fuzzer_engine::export_crashes();
	}
	ImGui::SameLine();
	if (aida::ui::button("Import", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(78.f, 28.f))) {
		fuzzer_engine::import_crashes();
	}

	cy = oy + toolbar_h + 8.f;

	fuzzer_engine::fuzz_stats_t stats_copy;
	std::vector<fuzzer_engine::crash_info_t> crashes_copy;
	std::vector<uint64_t> rate_history;
	{
		std::lock_guard<std::mutex> lk(fz.mutex);
		stats_copy = fz.stats;
		crashes_copy = fz.unique_crashes;
		rate_history = fz.stats.exec_rate_history;
	}

	uint64_t cur_unique = stats_copy.total_unique_crashes;
	if (cur_unique > st.last_unique_crashes) {
		st.new_crash_flash.trigger();
		st.new_crash_index = static_cast<int>(crashes_copy.size()) - 1;
	}
	st.last_unique_crashes = cur_unique;

	if (running) {
		st.running_pulse += dt * 3.f;
		if (st.running_pulse > 6.2831853f) st.running_pulse -= 6.2831853f;
	}

	float stat_panel_h = 254.f;
	ImVec2 sp_a = ImVec2(ox + 8.f, cy);
	ImVec2 sp_b = ImVec2(ox + width - 8.f, cy + stat_panel_h);
	aida::ui::blur::render_glass_fill(dl, sp_a, sp_b, 10.f, alpha);
	aida::ui::blur::render_glass_border(dl, sp_a, sp_b, 10.f, alpha, 1.f);

	if (running) {
		float pulse_a = (sinf(st.running_pulse) + 1.f) * 0.5f;
		float pulse_b = (sinf(st.running_pulse * 0.7f + 1.2f) + 1.f) * 0.5f;
		ImU32 pulse_col = aida::ui::with_alpha(th.accent_glow, alpha * (0.18f + pulse_a * 0.18f));
		dl->AddRectFilled(sp_a, sp_b, pulse_col, 10.f);
		ImU32 border_pulse = aida::ui::with_alpha(th.success, alpha * (0.30f + pulse_b * 0.30f));
		dl->AddRect(sp_a, sp_b, border_pulse, 10.f, 0, 1.5f);

		float dot_cx = sp_b.x - 16.f;
		float dot_cy = sp_a.y + 14.f;
		float dot_r = 4.f + pulse_a * 2.f;
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r + 8.f,
			aida::ui::with_alpha(th.success, alpha * pulse_a * 0.3f), 16);
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r + 4.f,
			aida::ui::with_alpha(th.success, alpha * pulse_a * 0.55f), 16);
		dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), dot_r,
			aida::ui::with_alpha(th.success, alpha), 16);

		ImFont* cap_f = aida::ui::fonts::caption();
		if (!cap_f) cap_f = ImGui::GetFont();
		ImVec2 lbl_ts = cap_f->CalcTextSizeA(10.f, FLT_MAX, 0.f, "STATUS");
		dl->AddText(cap_f, 12.f,
			ImVec2(sp_b.x - 124.f - lbl_ts.x - 6.f, sp_a.y + 8.f),
			aida::ui::with_alpha(th.text_dim, alpha), "STATUS");
		ImGui::SetCursorScreenPos(ImVec2(sp_b.x - 124.f, sp_a.y + 6.f));
		aida::ui::pill_kind("Running", aida::ui::pill_kind_t::success,
			aida::ui::size_t_::sm, true);
	} else {
		ImFont* cap_f = aida::ui::fonts::caption();
		if (!cap_f) cap_f = ImGui::GetFont();
		ImVec2 lbl_ts = cap_f->CalcTextSizeA(10.f, FLT_MAX, 0.f, "STATUS");
		dl->AddText(cap_f, 12.f,
			ImVec2(sp_b.x - 100.f - lbl_ts.x - 6.f, sp_a.y + 8.f),
			aida::ui::with_alpha(th.text_dim, alpha), "STATUS");
		ImGui::SetCursorScreenPos(ImVec2(sp_b.x - 100.f, sp_a.y + 6.f));
		aida::ui::pill_kind("Idle", aida::ui::pill_kind_t::neutral,
			aida::ui::size_t_::sm, false);
	}

	st.stat_target[0] = static_cast<float>(stats_copy.total_executions);
	st.stat_target[1] = static_cast<float>(stats_copy.executions_per_second);
	st.stat_target[2] = static_cast<float>(stats_copy.total_crashes);
	st.stat_target[3] = static_cast<float>(stats_copy.total_unique_crashes);
	st.stat_target[4] = static_cast<float>(stats_copy.edge_coverage);
	st.stat_target[5] = static_cast<float>(stats_copy.new_coverage_finds);
	st.stat_target[6] = static_cast<float>(stats_copy.corpus_size);
	st.stat_target[7] = static_cast<float>(stats_copy.elapsed_seconds);
	for (int i = 0; i < 8; ++i) {
		st.stat_counter[i] = aida::motion::critically_damped_step(
			st.stat_counter[i], st.stat_target[i], st.stat_velocity[i], 0.18f, dt);
	}

	struct stat_box_t { const char* label; std::string value; ImU32 color; };
	char buf[64];
	stat_box_t boxes[8];

	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[0]));
	boxes[0] = {"Executions", buf, aida::ui::with_alpha(th.text_primary, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu/s",
		static_cast<unsigned long long>(st.stat_counter[1]));
	boxes[1] = {"Speed", buf, aida::ui::with_alpha(th.accent_u32, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[2]));
	boxes[2] = {"Crashes", buf, aida::ui::with_alpha(th.error, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[3]));
	boxes[3] = {"Unique", buf, aida::ui::with_alpha(th.error, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[4]));
	boxes[4] = {"Edges", buf, aida::ui::with_alpha(th.success, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[5]));
	boxes[5] = {"New Cov", buf, aida::ui::with_alpha(th.success, alpha)};
	std::snprintf(buf, sizeof(buf), "%llu",
		static_cast<unsigned long long>(st.stat_counter[6]));
	boxes[6] = {"Corpus", buf, aida::ui::with_alpha(th.text_primary, alpha)};
	std::snprintf(buf, sizeof(buf), "%.1fs", st.stat_counter[7]);
	boxes[7] = {"Elapsed", buf, aida::ui::with_alpha(th.text_dim, alpha)};

	ImFont* num_font = aida::ui::fonts::display();
	if (!num_font) num_font = aida::ui::fonts::body_strong();
	if (!num_font) num_font = ImGui::GetFont();
	ImFont* lbl_font = aida::ui::fonts::caption();
	if (!lbl_font) lbl_font = ImGui::GetFont();

	float box_pad = 8.f;
	float box_w = (width - 16.f - box_pad * 3.f) / 4.f;
	float box_h = 56.f;
	for (int i = 0; i < 8; ++i) {
		int col_idx = i % 4;
		int row_idx = i / 4;
		float bx = sp_a.x + 8.f + static_cast<float>(col_idx) * (box_w + box_pad);
		float by = sp_a.y + 8.f + static_cast<float>(row_idx) * (box_h + 6.f);
		ImVec2 ba = ImVec2(bx, by);
		ImVec2 bb = ImVec2(bx + box_w, by + box_h);
		dl->AddRectFilled(ba, bb, aida::ui::with_alpha(th.panel_header, alpha * 0.55f), 6.f);
		dl->AddRect(ba, bb, aida::ui::with_alpha(th.border_subtle, alpha), 6.f, 0, 1.f);
		dl->AddText(lbl_font, 12.f, ImVec2(bx + 10.f, by + 8.f),
			aida::ui::with_alpha(th.text_dim, alpha), boxes[i].label);
		dl->AddText(num_font, 22.f, ImVec2(bx + 10.f, by + 22.f), boxes[i].color, boxes[i].value.c_str());
	}

	float graph_y = sp_a.y + 8.f + 2.f * (box_h + 6.f);
	float graph_h = sp_b.y - graph_y - 12.f;
	float graph_w = width - 32.f;
	float gx = sp_a.x + 8.f;

	dl->AddRectFilled(ImVec2(gx, graph_y), ImVec2(gx + graph_w, graph_y + graph_h),
		aida::ui::with_alpha(th.bg_base, alpha * 0.6f), 6.f);
	dl->AddRect(ImVec2(gx, graph_y), ImVec2(gx + graph_w, graph_y + graph_h),
		aida::ui::with_alpha(th.border_subtle, alpha), 6.f, 0, 1.f);

	for (int gi = 1; gi < 4; ++gi) {
		float gy = graph_y + graph_h * static_cast<float>(gi) / 4.f;
		dl->AddLine(ImVec2(gx, gy), ImVec2(gx + graph_w, gy),
			aida::ui::with_alpha(th.border_subtle, alpha * 0.6f));
	}

	dl->AddText(lbl_font, 12.f, ImVec2(gx + 6.f, graph_y + 4.f),
		aida::ui::with_alpha(th.text_dim, alpha), "exec/s");

	if (rate_history.size() >= 2) {
		uint64_t max_rate = *std::max_element(rate_history.begin(), rate_history.end());
		if (max_rate == 0) max_rate = 1;
		float step = graph_w / static_cast<float>(rate_history.size() - 1);

		ImU32 line_col = aida::ui::with_alpha(th.accent_u32, alpha * 0.85f);
		for (size_t i = 1; i < rate_history.size(); ++i) {
			float x1 = gx + static_cast<float>(i - 1) * step;
			float y1 = graph_y + graph_h - (static_cast<float>(rate_history[i - 1]) / static_cast<float>(max_rate)) * (graph_h - 14.f);
			float x2 = gx + static_cast<float>(i) * step;
			float y2 = graph_y + graph_h - (static_cast<float>(rate_history[i]) / static_cast<float>(max_rate)) * (graph_h - 14.f);

			ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, alpha * 0.30f);
			ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, 0);
			dl->AddRectFilledMultiColor(ImVec2(x1, std::min(y1, y2)),
				ImVec2(x2, graph_y + graph_h),
				fill_top, fill_top, fill_bot, fill_bot);

			dl->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), line_col, 2.f);
		}

		if (running) {
			float scan_phase = aida::ui::clock::saw(2.0f);
			float scan_x = gx + graph_w * scan_phase;
			ImU32 scan_a = aida::ui::with_alpha(th.accent_hover, 0.f);
			ImU32 scan_b = aida::ui::with_alpha(th.accent_hover, alpha * 0.65f);
			dl->AddRectFilledMultiColor(ImVec2(scan_x - 50.f, graph_y),
				ImVec2(scan_x, graph_y + graph_h),
				scan_a, scan_b, scan_b, scan_a);
			dl->AddLine(ImVec2(scan_x, graph_y), ImVec2(scan_x, graph_y + graph_h),
				aida::ui::with_alpha(th.accent_hover, alpha * 0.95f), 1.5f);
		}

		ImVec2 mouse = ImGui::GetMousePos();
		if (mouse.x >= gx && mouse.x <= gx + graph_w &&
			mouse.y >= graph_y && mouse.y <= graph_y + graph_h) {
			float rel = (mouse.x - gx) / graph_w;
			size_t idx = static_cast<size_t>(rel * static_cast<float>(rate_history.size() - 1));
			if (idx < rate_history.size()) {
				float hx = gx + static_cast<float>(idx) * step;
				float hy = graph_y + graph_h - (static_cast<float>(rate_history[idx]) / static_cast<float>(max_rate)) * (graph_h - 14.f);
				dl->AddLine(ImVec2(hx, graph_y), ImVec2(hx, graph_y + graph_h),
					aida::ui::with_alpha(th.text_dim, alpha * 0.5f));
				dl->AddCircleFilled(ImVec2(hx, hy), 4.f,
					aida::ui::with_alpha(th.accent_u32, alpha), 12);
				dl->AddCircle(ImVec2(hx, hy), 6.f,
					aida::ui::with_alpha(th.text_primary, alpha * 0.45f), 12, 1.f);
				char tip[32];
				std::snprintf(tip, sizeof(tip), "%llu/s",
					static_cast<unsigned long long>(rate_history[idx]));
				ImVec2 tsz = ImGui::CalcTextSize(tip);
				float tx = hx - tsz.x * 0.5f;
				if (tx < gx) tx = gx;
				if (tx + tsz.x > gx + graph_w) tx = gx + graph_w - tsz.x;
				dl->AddRectFilled(ImVec2(tx - 6.f, hy - tsz.y - 8.f),
					ImVec2(tx + tsz.x + 6.f, hy - 2.f),
					aida::ui::with_alpha(th.bg_overlay, alpha), 4.f);
				dl->AddText(ImGui::GetFont(), 13.f, ImVec2(tx, hy - tsz.y - 6.f),
					aida::ui::with_alpha(th.text_primary, alpha), tip);
			}
		}
	}

	cy += stat_panel_h + 10.f;

	for (int i = 0; i < 6; ++i) {
		st.strategy_count_total[i] = 0;
		st.strategy_count_unique[i] = 0;
	}
	for (const auto& c : crashes_copy) {
		int s_idx = crashes_strategy_index(c.mutation.strategy);
		if (s_idx >= 0 && s_idx < 6) {
			st.strategy_count_unique[s_idx]++;
		}
	}
	int max_s = 1;
	for (int i = 0; i < 6; ++i) {
		if (st.strategy_count_unique[i] > max_s) max_s = st.strategy_count_unique[i];
	}
	for (int i = 0; i < 6; ++i) {
		st.strategy_efficacy_target[i] = static_cast<float>(st.strategy_count_unique[i]) / static_cast<float>(max_s);
		st.strategy_efficacy[i] = aida::motion::smooth_lerp(st.strategy_efficacy[i],
			st.strategy_efficacy_target[i], 6.f, dt);
	}

	float strat_panel_h = 78.f;
	ImVec2 sp2_a = ImVec2(ox + 8.f, cy);
	ImVec2 sp2_b = ImVec2(ox + width * 0.55f - 4.f, cy + strat_panel_h);
	aida::ui::blur::render_glass_fill(dl, sp2_a, sp2_b, 10.f, alpha);
	aida::ui::blur::render_glass_border(dl, sp2_a, sp2_b, 10.f, alpha, 1.f);
	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		12.f, ImVec2(sp2_a.x + 12.f, sp2_a.y + 6.f),
		aida::ui::with_alpha(th.text_secondary, alpha), "Mutation Strategy Efficacy");

	float bar_left = sp2_a.x + 12.f;
	float bar_right = sp2_b.x - 12.f;
	float bar_total_w = bar_right - bar_left;
	float bar_w = bar_total_w / 6.f - 6.f;
	for (int i = 0; i < 6; ++i) {
		float bx = bar_left + static_cast<float>(i) * (bar_w + 6.f);
		float by = sp2_a.y + 24.f;
		float bh = strat_panel_h - 36.f;
		ImU32 col = (i % 2 == 0) ? th.accent_grad_top : th.accent_grad_bot;
		float fill_h = bh * st.strategy_efficacy[i];
		dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bar_w, by + bh),
			aida::ui::with_alpha(th.panel_header, alpha * 0.5f), 4.f);
		dl->AddRectFilled(ImVec2(bx, by + bh - fill_h), ImVec2(bx + bar_w, by + bh),
			aida::ui::with_alpha(col, alpha * 0.85f), 4.f);
		ImFont* lbl = aida::ui::fonts::caption();
		if (!lbl) lbl = ImGui::GetFont();
		ImVec2 sz = lbl->CalcTextSizeA(10.f, FLT_MAX, 0.f, g_strategy_names[i]);
		dl->AddText(lbl, 12.f, ImVec2(bx + (bar_w - sz.x) * 0.5f, by + bh + 2.f),
			aida::ui::with_alpha(th.text_dim, alpha), g_strategy_names[i]);
		char nv[8];
		std::snprintf(nv, sizeof(nv), "%d", st.strategy_count_unique[i]);
		ImVec2 vsz = lbl->CalcTextSizeA(10.f, FLT_MAX, 0.f, nv);
		dl->AddText(lbl, 12.f,
			ImVec2(bx + (bar_w - vsz.x) * 0.5f, by + bh - fill_h - 12.f),
			aida::ui::with_alpha(th.text_primary, alpha), nv);
	}

	ImVec2 sp3_a = ImVec2(ox + width * 0.55f + 4.f, cy);
	ImVec2 sp3_b = ImVec2(ox + width - 8.f, cy + strat_panel_h);
	aida::ui::blur::render_glass_fill(dl, sp3_a, sp3_b, 10.f, alpha);
	aida::ui::blur::render_glass_border(dl, sp3_a, sp3_b, 10.f, alpha, 1.f);
	dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
		12.f, ImVec2(sp3_a.x + 12.f, sp3_a.y + 6.f),
		aida::ui::with_alpha(th.text_secondary, alpha), "Coverage Map");

	const int hm_cols = 16;
	const int hm_rows = 4;
	float cov_left = sp3_a.x + 12.f;
	float cov_top  = sp3_a.y + 24.f;
	float cov_w = sp3_b.x - sp3_a.x - 24.f;
	float cell_w = cov_w / static_cast<float>(hm_cols);
	float cell_h = (strat_panel_h - 36.f) / static_cast<float>(hm_rows);
	uint32_t edges = stats_copy.edge_coverage;
	uint32_t total_cells = static_cast<uint32_t>(hm_cols * hm_rows);
	for (int r = 0; r < hm_rows; ++r) {
		for (int c = 0; c < hm_cols; ++c) {
			int idx = r * hm_cols + c;
			float frac = (static_cast<float>(idx) / static_cast<float>(total_cells));
			float fill = 0.f;
			if (edges > 0) {
				float thresh = frac * static_cast<float>(edges) / 64.f;
				fill = std::min(1.f, thresh);
			}
			ImU32 c_low = aida::ui::with_alpha(th.panel_header, alpha * 0.6f);
			ImU32 c_high = aida::ui::with_alpha(th.success, alpha * 0.85f);
			ImU32 cell_col = aida::ui::mix(c_low, c_high, fill);
			float pad = 1.5f;
			dl->AddRectFilled(
				ImVec2(cov_left + c * cell_w + pad, cov_top + r * cell_h + pad),
				ImVec2(cov_left + (c + 1) * cell_w - pad, cov_top + (r + 1) * cell_h - pad),
				cell_col, 2.f);
		}
	}
	char edge_buf[32];
	std::snprintf(edge_buf, sizeof(edge_buf), "%u edges", edges);
	dl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
		10.f, ImVec2(sp3_b.x - 90.f, sp3_a.y + 6.f),
		aida::ui::with_alpha(th.text_dim, alpha), edge_buf);

	cy += strat_panel_h + 10.f;

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	dl->AddText(head_em, 13.f, ImVec2(ox + 12.f, cy),
		aida::ui::with_alpha(th.text_primary, alpha), "Unique Crashes");
	cy += 22.f;

	const float row_h = 28.f;
	const float pad = 12.f;
	const float col_idx_w = 36.f;
	const float col_score_w = 78.f;
	const float col_type_w = width * 0.14f;
	const float col_addr_w = width * 0.14f;
	const float col_inst_w = width * 0.18f;
	const float col_desc_w = width - col_idx_w - col_score_w - col_type_w - col_addr_w - col_inst_w - pad * 2.f - 14.f;

	{
		ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
		dl->AddRectFilled(ImVec2(ox + 8.f, cy), ImVec2(ox + width - 8.f, cy + row_h), hdr_bg, 6.f);
		dl->AddLine(ImVec2(ox + 8.f, cy + row_h - 1.f), ImVec2(ox + width - 8.f, cy + row_h - 1.f),
			aida::ui::with_alpha(th.border_subtle, alpha));
		float hx = ox + 16.f;
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "#");
		hx += col_idx_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "Score");
		hx += col_score_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "Address");
		hx += col_addr_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "Instruction");
		hx += col_inst_w;
		dl->AddText(head_em, 13.f, ImVec2(hx, cy + 7.f), hc, "Description");
	}
	cy += row_h + 2.f;

	const float detail_target = (st.selected_crash >= 0 && st.selected_crash < static_cast<int>(crashes_copy.size())) ? 1.f : 0.f;
	st.detail_slide = aida::motion::spring_step(st.detail_slide, detail_target,
		st.detail_vel, aida::motion::spring::balanced, dt);

	float detail_panel_max = std::clamp(height * 0.30f, 160.f, 280.f);
	float detail_panel_h = detail_panel_max * st.detail_slide;
	float crash_table_h = oy + height - cy - 8.f - detail_panel_h;
	float content_h = static_cast<float>(crashes_copy.size()) * row_h;

	float wheel = 0.f;
	if (ImGui::IsMouseHoveringRect(ImVec2(ox, cy), ImVec2(ox + width, cy + crash_table_h))) {
		wheel = ImGui::GetIO().MouseWheel;
	}
	if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
	if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
	float ms = std::max(0.f, content_h - crash_table_h);
	if (st.target_scroll_y > ms) st.target_scroll_y = ms;
	st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + width - 14.f, oy + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(crash_table_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(crashes_copy.size()))
		last_vis = static_cast<int>(crashes_copy.size());

	float new_flash_v = st.new_crash_flash.tick(dt, 1.4f);

	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + height) continue;

		auto& crash = crashes_copy[static_cast<size_t>(i)];

		ImVec2 rmin(ox + 8.f, ry);
		ImVec2 rmax(ox + width - 14.f, ry + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_crash == i);

		float entrance_delay = std::min(static_cast<float>(i - first_vis) * 0.012f, 0.240f);
		float entrance_t = (st.anim_time - entrance_delay) / 0.32f;
		if (entrance_t < 0.f) entrance_t = 0.f;
		if (entrance_t > 1.f) entrance_t = 1.f;
		float entrance = aida::motion::ease::out_cubic(entrance_t);

		ImU32 row_fill;
		if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
		else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
		else row_fill = (i & 1)
			? aida::ui::with_alpha(th.panel_bg, alpha * 0.45f * entrance)
			: 0u;
		if ((row_fill & 0xFF000000) != 0) {
			dl->AddRectFilled(rmin, rmax, row_fill, 4.f);
		}

		bool is_new_flash = (i == st.new_crash_index) && new_flash_v > 0.001f;
		if (is_new_flash) {
			ImU32 flash_col = aida::ui::with_alpha(th.error, alpha * new_flash_v * 0.55f);
			dl->AddRectFilled(rmin, rmax, flash_col, 4.f);
			ImU32 sweep = aida::ui::with_alpha(th.error, alpha * new_flash_v);
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y), sweep, 1.5f);
		}

		if (selected) {
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_crash = selected ? -1 : i;
		}

		float rx = ox + 16.f;
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		char idx_buf[8];
		std::snprintf(idx_buf, sizeof(idx_buf), "#%d", i + 1);
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), idx_buf);
		rx += col_idx_w;

		{
			aida::ui::pill_kind_t pk;
			switch (crash.score) {
				case fuzzer_engine::exploit_score_t::critical: pk = aida::ui::pill_kind_t::error;   break;
				case fuzzer_engine::exploit_score_t::high:     pk = aida::ui::pill_kind_t::warning; break;
				case fuzzer_engine::exploit_score_t::medium:   pk = aida::ui::pill_kind_t::warning; break;
				case fuzzer_engine::exploit_score_t::low:      pk = aida::ui::pill_kind_t::success; break;
				default:                                       pk = aida::ui::pill_kind_t::neutral; break;
			}
			ImGui::SetCursorScreenPos(ImVec2(rx, ry + 2.f));
			aida::ui::pill_kind(fuzzer_engine::exploit_score_name(crash.score), pk,
				aida::ui::size_t_::sm, false);
		}
		rx += col_score_w;

		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.error, alpha * entrance),
			fuzzer_engine::crash_type_name(crash.type));
		rx += col_type_w;

		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
			static_cast<unsigned long long>(crash.instruction_address));
		dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
			aida::ui::with_alpha(th.text_address, alpha * entrance), addr_buf);
		rx += col_addr_w;

		if (!crash.crashing_instruction.empty()) {
			std::string trim = crash.crashing_instruction;
			if (trim.size() > 30) trim = trim.substr(0, 28) + "..";
			dl->AddText(code_font, 13.f, ImVec2(rx, ry + 7.f),
				aida::ui::with_alpha(th.text_dim, alpha * entrance), trim.c_str());
		}
		rx += col_inst_w;

		std::string desc = crash.description;
		if (desc.size() > 40) desc = desc.substr(0, 38) + "..";
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			11.f, ImVec2(rx, ry + 6.f),
			aida::ui::with_alpha(th.text_secondary, alpha * entrance),
			desc.c_str());

		(void)col_desc_w;
	}

	ImGui::PopClipRect();

	if (content_h > crash_table_h && crash_table_h > 0.f) {
		float bar_x = ox + width - 12.f;
		float bar_y = cy;
		float bar_h = crash_table_h;
		float ratio = crash_table_h / content_h;
		float thumb_h = std::max(bar_h * ratio, 24.f);
		float track = bar_h - thumb_h;
		float scroll_ratio = (content_h - crash_table_h > 0.f)
			? st.scroll_y / (content_h - crash_table_h) : 0.f;
		float thumb_y = bar_y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 6.f, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 6.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
	}

	if (detail_panel_h > 8.f && st.selected_crash >= 0 &&
		st.selected_crash < static_cast<int>(crashes_copy.size())) {
		auto& sel = crashes_copy[static_cast<size_t>(st.selected_crash)];
		float dy = cy + crash_table_h + 4.f;
		float dw = width - 16.f;
		float detail_alpha = alpha * st.detail_slide;

		ImVec2 da = ImVec2(ox + 8.f, dy);
		ImVec2 db = ImVec2(da.x + dw, dy + detail_panel_h - 4.f);
		aida::ui::blur::render_glass_fill(dl, da, db, 10.f, detail_alpha);
		aida::ui::blur::render_glass_border(dl, da, db, 10.f, detail_alpha, 1.f);

		float dx_inner = da.x + 14.f;
		float dy_inner = da.y + 8.f;

		char detail_buf[160];
		std::snprintf(detail_buf, sizeof(detail_buf), "Crash #%d   %s   [%s]",
			st.selected_crash + 1,
			fuzzer_engine::crash_type_name(sel.type),
			fuzzer_engine::exploit_score_name(sel.score));
		dl->AddText(head_em, 13.f, ImVec2(dx_inner, dy_inner),
			aida::ui::with_alpha(th.accent_u32, detail_alpha), detail_buf);
		dy_inner += 22.f;

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		if (!sel.crashing_instruction.empty()) {
			std::snprintf(detail_buf, sizeof(detail_buf), "Instruction   %s",
				sel.crashing_instruction.c_str());
			dl->AddText(code_font, 13.f, ImVec2(dx_inner, dy_inner),
				aida::ui::with_alpha(th.text_primary, detail_alpha), detail_buf);
			dy_inner += 16.f;
		}

		std::snprintf(detail_buf, sizeof(detail_buf), "Fault 0x%llX   RIP 0x%llX",
			static_cast<unsigned long long>(sel.fault_address),
			static_cast<unsigned long long>(sel.rip));
		dl->AddText(code_font, 13.f, ImVec2(dx_inner, dy_inner),
			aida::ui::with_alpha(th.text_secondary, detail_alpha), detail_buf);
		dy_inner += 18.f;

		float col1 = dx_inner;
		float col2 = dx_inner + dw * 0.25f;
		float col3 = dx_inner + dw * 0.5f;
		float col4 = dx_inner + dw * 0.75f;

		auto draw_reg = [&](float rx, float ry, const char* name, uint64_t val) {
			std::snprintf(detail_buf, sizeof(detail_buf), "%-4s 0x%016llX",
				name, static_cast<unsigned long long>(val));
			dl->AddText(code_font, 13.f, ImVec2(rx, ry),
				aida::ui::with_alpha(th.text_dim, detail_alpha), detail_buf);
		};
		draw_reg(col1, dy_inner, "RAX", sel.rax);
		draw_reg(col2, dy_inner, "RBX", sel.rbx);
		draw_reg(col3, dy_inner, "RCX", sel.rcx);
		draw_reg(col4, dy_inner, "RDX", sel.rdx);
		dy_inner += 14.f;
		draw_reg(col1, dy_inner, "RSP", sel.rsp);
		draw_reg(col2, dy_inner, "RBP", sel.rbp);
		draw_reg(col3, dy_inner, "RSI", sel.rsi);
		draw_reg(col4, dy_inner, "RDI", sel.rdi);
		dy_inner += 14.f;
		draw_reg(col1, dy_inner, "R8",  sel.r8);
		draw_reg(col2, dy_inner, "R9",  sel.r9);
		draw_reg(col3, dy_inner, "R10", sel.r10);
		draw_reg(col4, dy_inner, "R11", sel.r11);
		dy_inner += 14.f;
		draw_reg(col1, dy_inner, "R12", sel.r12);
		draw_reg(col2, dy_inner, "R13", sel.r13);
		draw_reg(col3, dy_inner, "R14", sel.r14);
		draw_reg(col4, dy_inner, "R15", sel.r15);
		dy_inner += 18.f;

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
		std::snprintf(detail_buf, sizeof(detail_buf), "Mutation %s   offset=%zu   size=%zu",
			mut_strat, sel.mutation.offset, sel.mutation.size);
		dl->AddText(code_font, 13.f, ImVec2(dx_inner, dy_inner),
			aida::ui::with_alpha(th.text_dim, detail_alpha), detail_buf);
		dy_inner += 16.f;

		if (!sel.input.empty() && dy_inner < db.y - 60.f) {
			std::string hex_str = "Input ";
			size_t show_n = std::min(sel.input.size(), static_cast<size_t>(32));
			for (size_t bi = 0; bi < show_n; ++bi) {
				char hb[4];
				std::snprintf(hb, sizeof(hb), "%02X ", sel.input[bi]);
				hex_str += hb;
			}
			if (sel.input.size() > 32) hex_str += "...";
			dl->AddText(code_font, 13.f, ImVec2(dx_inner, dy_inner),
				aida::ui::with_alpha(th.text_dim, detail_alpha), hex_str.c_str());
			dy_inner += 16.f;
		}

		if (sel.is_minimized && dy_inner < db.y - 60.f) {
			std::string min_str = "Minimized ";
			size_t show_n = std::min(sel.minimized_input.size(), static_cast<size_t>(32));
			for (size_t bi = 0; bi < show_n; ++bi) {
				char hb[4];
				std::snprintf(hb, sizeof(hb), "%02X ", sel.minimized_input[bi]);
				min_str += hb;
			}
			if (sel.minimized_input.size() > 32) min_str += "...";
			std::snprintf(detail_buf, sizeof(detail_buf), "%s (%zu bytes)",
				min_str.c_str(), sel.minimized_input.size());
			dl->AddText(code_font, 13.f, ImVec2(dx_inner, dy_inner),
				aida::ui::with_alpha(th.success, detail_alpha), detail_buf);
			dy_inner += 16.f;
		}

		dy_inner += 4.f;
		ImGui::SetCursorScreenPos(ImVec2(dx_inner, dy_inner));
		bool analyzing = fz.analyzing_crash.load();
		bool minimizing = fz.minimizing.load();

		if (aida::ui::button(analyzing ? "Analyzing" : "AI Analyze",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm,
			ImVec2(112.f, 28.f),
			analyzing, nullptr, analyzing)) {
			if (!analyzing) fuzzer_engine::ai_analyze_crash(st.selected_crash);
		}
		ImGui::SameLine();
		if (aida::ui::button(minimizing ? "Minimizing" : "Minimize",
			aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm,
			ImVec2(102.f, 28.f),
			minimizing, nullptr, minimizing)) {
			if (!minimizing) fuzzer_engine::minimize_crash(st.selected_crash);
		}
		dy_inner += 28.f;

		if (!sel.ai_analysis.empty() && dy_inner < db.y - 8.f) {
			dl->AddText(head_em, 14.f, ImVec2(dx_inner, dy_inner),
				aida::ui::with_alpha(th.accent_u32, detail_alpha), "AI Analysis");
			dy_inner += 16.f;
			float wrap_w = dw - 24.f;
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				11.f, ImVec2(dx_inner, dy_inner),
				aida::ui::with_alpha(th.text_secondary, detail_alpha),
				sel.ai_analysis.c_str(),
				sel.ai_analysis.c_str() + sel.ai_analysis.size(),
				wrap_w);
		}
	}

	if (!fz.active && !running && crashes_copy.empty()) {
		float body_top = cy + 6.f;
		float body_bot = oy + height - 8.f - detail_panel_h;
		float body_height = std::max(80.f, body_bot - body_top);
		ImVec2 e_pos = ImVec2(ox, body_top);
		ImVec2 e_sz = ImVec2(width, body_height);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::flask;
		cfg.title = "Configure target and start fuzzing";
		cfg.body  = "Enter a target address and input region above, then press Start Fuzzing.";
		cfg.max_width = 380.f;
		aida::ui::empty_state::render(e_pos, e_sz, cfg);
	}

	ImGui::EndChild();
}

}
