#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "source_reconstructor.hpp"
#include "ui_anim.hpp"
#include "theme.hpp"

namespace source_reconstruct_view {

struct state_t {
	bool   open = false;
	float  fade = 0.f;
	float  scale_anim = 0.f;
	float  anim_time = 0.f;
	char   output_dir[512] = {};
	char   module_filter[128] = {};
	bool   started = false;
	float  progress_display = 0.f;
	float  shimmer_phase = 0.f;
	int    total_display = 0;
	int    done_display = 0;
	float  stage_dot_pulse[8] = {};
	float  pipeline_line_anim = 0.f;
};

inline state_t g_state;

inline bool is_open() { return g_state.open || g_state.fade > 0.01f; }

inline void open() {
	g_state.open = true;
	g_state.started = false;
	g_state.progress_display = 0.f;
	g_state.pipeline_line_anim = 0.f;
	for (int i = 0; i < 8; ++i) g_state.stage_dot_pulse[i] = 0.f;
}

inline void close() {
	g_state.open = false;
}

inline void render(float alpha, float ar, float ag, float ab) {
	auto& st = g_state;
	float dt = ImGui::GetIO().DeltaTime;
	st.anim_time += dt;

	float fade_target = st.open ? 1.f : 0.f;
	st.fade = ui_anim::smooth_lerp(st.fade, fade_target, 10.f, dt);
	if (st.fade < 0.005f) return;

	float scale_target = st.open ? 1.f : 0.85f;
	st.scale_anim = ui_anim::smooth_lerp(st.scale_anim, scale_target, 12.f, dt);

	float fa = alpha * st.fade;
	ImDrawList* dl = ImGui::GetForegroundDrawList();
	ImVec2 vp = ImGui::GetMainViewport()->Size;

	const auto& _t = themes::resolved;
	const auto _ta = [fa](ImU32 c) -> ImU32 {
		return ui_anim::theme_alpha(c, fa);
	};

	dl->AddRectFilled(ImVec2(0, 0), vp,
		IM_COL32(0, 0, 0, static_cast<int>(120 * fa)));

	const float dialog_w = 680.f;
	const float dialog_h = 360.f;
	float cx = vp.x * 0.5f;
	float cy = vp.y * 0.5f;

	float sw = dialog_w * st.scale_anim;
	float sh = dialog_h * st.scale_anim;
	float dx = cx - sw * 0.5f;
	float dy = cy - sh * 0.5f;

	ImVec2 dmin(dx, dy);
	ImVec2 dmax(dx + sw, dy + sh);

	ImU32 bg = _ta(_t.bg_base);
	ImU32 border = _ta(ui_anim::lighten(_t.panel_bg, 12));
	ImU32 accent = IM_COL32(
		static_cast<int>(ar * 255), static_cast<int>(ag * 255),
		static_cast<int>(ab * 255), static_cast<int>(220 * fa));
	ImU32 accent_dim = IM_COL32(
		static_cast<int>(ar * 255), static_cast<int>(ag * 255),
		static_cast<int>(ab * 255), static_cast<int>(60 * fa));
	ImU32 accent_glow = IM_COL32(
		static_cast<int>(ar * 255), static_cast<int>(ag * 255),
		static_cast<int>(ab * 255), static_cast<int>(30 * fa));
	ImU32 text_primary = _ta(_t.text_primary);
	ImU32 text_secondary = _ta(_t.text_secondary);
	ImU32 text_dim = _ta(_t.text_dim);

	dl->AddRectFilled(dmin, dmax, bg, 12.f);
	dl->AddRect(dmin, dmax, border, 12.f, 0, 1.f);

	dl->AddRectFilledMultiColor(
		ImVec2(dx, dy), ImVec2(dx + sw, dy + 3.f),
		accent, accent_dim, accent_dim, accent);

	const float pad = 20.f;
	float cur_y = dy + 12.f;

	{
		const char* title = "Reconstruct Source";
		ImVec2 tsz = ImGui::CalcTextSize(title);
		dl->AddText(ImVec2(dx + pad, cur_y), text_primary, title);

		float close_x = dx + sw - pad - 16.f;
		ImVec2 cmin(close_x, cur_y);
		ImVec2 cmax(close_x + 16.f, cur_y + 16.f);
		bool close_hov = ImGui::IsMouseHoveringRect(cmin, cmax);
		ImU32 close_col = close_hov ? aida::ui::with_alpha(aida::ui::resolved().error, 0.86f * fa)
		                            : _ta(_t.text_secondary);
		dl->AddLine(ImVec2(close_x + 2, cur_y + 2), ImVec2(close_x + 14, cur_y + 14), close_col, 2.f);
		dl->AddLine(ImVec2(close_x + 14, cur_y + 2), ImVec2(close_x + 2, cur_y + 14), close_col, 2.f);

		if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (source_reconstructor::is_running())
				source_reconstructor::cancel();
			st.open = false;
		}

		cur_y += tsz.y + 12.f;
	}

	{
		dl->AddText(ImVec2(dx + pad, cur_y), text_secondary, "Output Directory");
		cur_y += 18.f;

		float input_w = sw - pad * 2.f;
		float input_h = 28.f;
		ImVec2 imin(dx + pad, cur_y);
		ImVec2 imax(dx + pad + input_w, cur_y + input_h);

		dl->AddRectFilled(imin, imax, _ta(_t.bg_base), 4.f);
		dl->AddRect(imin, imax, _ta(ui_anim::lighten(_t.panel_bg, 12)), 4.f, 0, 1.f);

		ImGui::SetCursorScreenPos(ImVec2(imin.x + 6.f, imin.y + 4.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
		ImGui::PushItemWidth(input_w - 16.f);

		if (!st.started)
			ImGui::InputText("##recon_outdir", st.output_dir, sizeof(st.output_dir), ImGuiInputTextFlags_None);
		else {
			ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
			ImGui::InputText("##recon_outdir", st.output_dir, sizeof(st.output_dir), ImGuiInputTextFlags_ReadOnly);
			ImGui::PopStyleColor();
		}

		ImGui::PopItemWidth();
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);

		cur_y += input_h + 8.f;
	}

	auto recon_stage = source_reconstructor::get_stage();
	int total_fn = source_reconstructor::get_total_functions();
	int done_fn = source_reconstructor::get_decompiled_count();

	if (st.started && total_fn > 0) {
		char info[256];
		snprintf(info, sizeof(info), "%d functions | x64", total_fn);
		dl->AddText(ImVec2(dx + pad, cur_y), text_dim, info);
		cur_y += 18.f;
	} else {
		cur_y += 18.f;
	}

	{
		const char* stage_labels[] = { "Collect", "Decompile", "Cluster", "Headers", "Modules", "Metadata" };
		const source_reconstructor::stage_t stage_values[] = {
			source_reconstructor::stage_t::collect,
			source_reconstructor::stage_t::decompile,
			source_reconstructor::stage_t::cluster,
			source_reconstructor::stage_t::headers,
			source_reconstructor::stage_t::modules,
			source_reconstructor::stage_t::metadata
		};
		const int num_stages = 6;

		float pipeline_w = sw - pad * 2.f;
		float pipeline_x = dx + pad;
		float pipeline_y = cur_y + 10.f;
		float dot_spacing = pipeline_w / static_cast<float>(num_stages - 1);
		float dot_radius = 6.f;

		int active_stage_idx = -1;
		for (int i = 0; i < num_stages; ++i) {
			if (recon_stage == stage_values[i]) active_stage_idx = i;
		}
		bool is_done = (recon_stage == source_reconstructor::stage_t::done);
		bool is_failed = (recon_stage == source_reconstructor::stage_t::failed);

		float line_target = 0.f;
		if (active_stage_idx >= 0)
			line_target = static_cast<float>(active_stage_idx) / static_cast<float>(num_stages - 1);
		if (is_done) line_target = 1.f;
		st.pipeline_line_anim = ui_anim::smooth_lerp(st.pipeline_line_anim, line_target, 6.f, dt);

		dl->AddLine(
			ImVec2(pipeline_x, pipeline_y),
			ImVec2(pipeline_x + pipeline_w, pipeline_y),
			_ta(_t.panel_header), 2.f);

		if (st.started) {
			float fill_w = pipeline_w * st.pipeline_line_anim;
			if (fill_w > 1.f) {
				dl->AddLine(
					ImVec2(pipeline_x, pipeline_y),
					ImVec2(pipeline_x + fill_w, pipeline_y),
					accent, 2.f);
				dl->AddLine(
					ImVec2(pipeline_x, pipeline_y),
					ImVec2(pipeline_x + fill_w, pipeline_y),
					accent_glow, 4.f);
			}
		}

		for (int i = 0; i < num_stages; ++i) {
			float dot_x = pipeline_x + dot_spacing * i;
			float dot_y = pipeline_y;

			bool completed = false;
			bool active = false;
			if (is_done) {
				completed = true;
			} else if (active_stage_idx >= 0) {
				if (i < active_stage_idx) completed = true;
				else if (i == active_stage_idx) active = true;
			}

			float pulse_target = active ? 1.f : 0.f;
			st.stage_dot_pulse[i] = ui_anim::smooth_lerp(st.stage_dot_pulse[i], pulse_target, 8.f, dt);

			if (active) {
				float glow_r = dot_radius + 4.f + std::sin(st.anim_time * 3.f) * 2.f;
				dl->AddCircleFilled(ImVec2(dot_x, dot_y), glow_r,
					IM_COL32(static_cast<int>(ar * 255), static_cast<int>(ag * 255),
					         static_cast<int>(ab * 255), static_cast<int>(40 * fa)), 20);
			}

			const auto& th_tok = aida::ui::resolved();
			ImU32 dot_col;
			if (completed)
				dot_col = aida::ui::with_alpha(th_tok.success, 0.86f * fa);
			else if (active)
				dot_col = accent;
			else
				dot_col = _ta(_t.panel_header);

			dl->AddCircleFilled(ImVec2(dot_x, dot_y), dot_radius, dot_col, 20);

			if (completed) {
				ImU32 ck = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.86f * fa);
				dl->AddLine(ImVec2(dot_x - 3, dot_y), ImVec2(dot_x - 1, dot_y + 3), ck, 1.5f);
				dl->AddLine(ImVec2(dot_x - 1, dot_y + 3), ImVec2(dot_x + 4, dot_y - 2), ck, 1.5f);
			}

			ImVec2 lsz = ImGui::CalcTextSize(stage_labels[i]);
			float lx = dot_x - lsz.x * 0.5f;
			float ly = dot_y + dot_radius + 6.f;

			ImU32 label_col = active ? text_primary :
			                  completed ? aida::ui::with_alpha(th_tok.success, 0.78f * fa) : text_dim;
			dl->AddText(ImVec2(lx, ly), label_col, stage_labels[i]);
		}

		cur_y = pipeline_y + dot_radius + 30.f;
	}

	{
		float bar_x = dx + pad;
		float bar_y = cur_y;
		float bar_w = sw - pad * 2.f;
		float bar_h = 18.f;

		float real_progress = source_reconstructor::get_progress();
		st.progress_display = ui_anim::smooth_lerp(st.progress_display, real_progress, 8.f, dt);
		st.shimmer_phase += dt * 1.5f;
		if (st.shimmer_phase > 1.f) st.shimmer_phase -= 1.f;

		dl->AddRectFilled(
			ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w, bar_y + bar_h),
			_ta(_t.bg_base), bar_h * 0.5f);

		float fill_w = bar_w * st.progress_display;
		if (fill_w > 2.f) {
			const auto& th_bar = aida::ui::resolved();
			ImU32 bar_top = aida::ui::with_alpha(th_bar.accent_grad_top, 0.92f * fa);
			ImU32 bar_bot = aida::ui::with_alpha(th_bar.accent_grad_bot, 0.92f * fa);
			ImU32 bar_flat = aida::ui::mix(bar_top, bar_bot, 0.5f);

			dl->AddRectFilled(
				ImVec2(bar_x, bar_y), ImVec2(bar_x + fill_w, bar_y + bar_h),
				bar_flat, bar_h * 0.5f);

			float shimmer_x = bar_x + fill_w * st.shimmer_phase;
			float shimmer_w = fill_w * 0.15f;
			if (shimmer_w > 8.f && source_reconstructor::is_running()) {
				ImU32 sh_off = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.f);
				ImU32 sh_on  = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.20f * fa);
				dl->AddRectFilledMultiColor(
					ImVec2(shimmer_x - shimmer_w * 0.5f, bar_y),
					ImVec2(shimmer_x + shimmer_w * 0.5f, bar_y + bar_h),
					sh_off, sh_on, sh_on, sh_off);
			}
		}

		char pct_str[32];
		snprintf(pct_str, sizeof(pct_str), "%d%%", static_cast<int>(st.progress_display * 100.f));
		ImVec2 pct_sz = ImGui::CalcTextSize(pct_str);
		dl->AddText(ImVec2(bar_x + bar_w * 0.5f - pct_sz.x * 0.5f, bar_y + 1.f),
			aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.78f * fa), pct_str);

		cur_y += bar_h + 10.f;
	}

	if (st.started) {
		int total = source_reconstructor::get_total_functions();
		int done = source_reconstructor::get_decompiled_count();
		float progress = source_reconstructor::get_progress();

		st.total_display = total;
		st.done_display = done;

		size_t est_bytes = static_cast<size_t>(done) * 4000;

		char counter[256];
		if (est_bytes >= 1024 * 1024) {
			snprintf(counter, sizeof(counter), "%d / %d (%d MB)",
				done, total, static_cast<int>(est_bytes / (1024 * 1024)));
		} else if (est_bytes >= 1024) {
			snprintf(counter, sizeof(counter), "%d / %d (%d KB)",
				done, total, static_cast<int>(est_bytes / 1024));
		} else {
			snprintf(counter, sizeof(counter), "%d / %d", done, total);
		}

		dl->AddText(ImVec2(dx + pad, cur_y), text_secondary, counter);

		char right_counter[64];
		snprintf(right_counter, sizeof(right_counter), "%d / %d", done, total);
		ImVec2 rc_sz = ImGui::CalcTextSize(right_counter);
		dl->AddText(ImVec2(dx + sw - pad - rc_sz.x, cur_y), text_dim, right_counter);

		cur_y += 22.f;

		std::string status = source_reconstructor::get_status();
		if (!status.empty()) {
			if (status.size() > 80) status = status.substr(0, 80) + "...";
			dl->AddText(ImVec2(dx + pad, cur_y), text_dim, status.c_str());
			cur_y += 18.f;
		}
	}

	{
		float btn_area_y = dy + sh - 50.f;

		if (!st.started) {
			bool has_output = (st.output_dir[0] != '\0');

			float btn_w = 120.f;
			float btn_h = 32.f;
			float btn_x = dx + sw * 0.5f - btn_w * 0.5f;
			float btn_y = btn_area_y;

			ImVec2 bmin(btn_x, btn_y);
			ImVec2 bmax(btn_x + btn_w, btn_y + btn_h);
			bool bhov = has_output && ImGui::IsMouseHoveringRect(bmin, bmax);

			const auto& th_btn_start = aida::ui::resolved();
			ImU32 btn_bg;
			if (!has_output)
				btn_bg = _ta(_t.panel_header);
			else if (bhov)
				btn_bg = aida::ui::with_alpha(th_btn_start.accent_hover, 0.86f * fa);
			else
				btn_bg = aida::ui::with_alpha(th_btn_start.accent_u32, 0.78f * fa);

			dl->AddRectFilled(bmin, bmax, btn_bg, 8.f);
			if (has_output) {
				dl->AddRectFilledMultiColor(bmin,
					ImVec2(bmax.x, bmin.y + 2.f),
					aida::ui::with_alpha(th_btn_start.accent_grad_top, fa),
					aida::ui::with_alpha(th_btn_start.accent_grad_top, fa),
					aida::ui::with_alpha(th_btn_start.accent_grad_bot, fa),
					aida::ui::with_alpha(th_btn_start.accent_grad_bot, fa));
			}

			const char* start_lbl = "Start";
			ImVec2 slsz = ImGui::CalcTextSize(start_lbl);
			ImU32 start_text_col = has_output ? aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.94f * fa)
			                                  : _ta(_t.text_dim);
			dl->AddText(ImVec2(btn_x + btn_w * 0.5f - slsz.x * 0.5f,
			                    btn_y + btn_h * 0.5f - slsz.y * 0.5f), start_text_col, start_lbl);

			if (bhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !source_reconstructor::is_running()) {
				auto mods = driver_bridge::enumerate_modules();
				if (!mods.empty()) {
					source_reconstructor::reconstruction_config_t config;
					config.output_dir = st.output_dir;
					config.module_base = mods[0].base;
					config.module_size = mods[0].size;
					config.module_name = mods[0].name;
					config.use_ai_refinement = false;
					source_reconstructor::reconstruct(config);
					st.started = true;
				}
			}
		} else {
			bool running = source_reconstructor::is_running();

			if (running) {
				float btn_w = 100.f;
				float btn_h = 30.f;
				float btn_x = dx + pad;
				float btn_y = btn_area_y;

				ImVec2 bmin(btn_x, btn_y);
				ImVec2 bmax(btn_x + btn_w, btn_y + btn_h);
				bool bhov = ImGui::IsMouseHoveringRect(bmin, bmax);

				const auto& th_btn = aida::ui::resolved();
				ImU32 cancel_bg = bhov ? aida::ui::with_alpha(th_btn.error, 0.78f * fa)
				                       : aida::ui::with_alpha(th_btn.error, 0.50f * fa);
				dl->AddRectFilled(bmin, bmax, cancel_bg, 8.f);
				dl->AddRect(bmin, bmax, aida::ui::with_alpha(th_btn.error, 0.85f * fa), 8.f, 0, 1.f);

				const char* cancel_lbl = "Cancel";
				ImVec2 clsz = ImGui::CalcTextSize(cancel_lbl);
				dl->AddText(ImVec2(btn_x + btn_w * 0.5f - clsz.x * 0.5f,
				                    btn_y + btn_h * 0.5f - clsz.y * 0.5f),
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.86f * fa), cancel_lbl);

				if (bhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					source_reconstructor::cancel();
			} else {
				auto& last = source_reconstructor::get_last_result();
				const char* done_lbl = last.success ? "Complete!" : "Failed";
				const auto& th_done = aida::ui::resolved();
				ImU32 done_col = last.success ? aida::ui::with_alpha(th_done.success, 0.86f * fa)
				                              : aida::ui::with_alpha(th_done.error,   0.86f * fa);
				dl->AddText(ImVec2(dx + pad, btn_area_y + 6.f), done_col, done_lbl);

				if (last.success) {
					char summary[128];
					snprintf(summary, sizeof(summary), "%d functions, %d modules, %d files",
						last.decompiled_functions, last.modules_created,
						static_cast<int>(last.files_created.size()));
					dl->AddText(ImVec2(dx + pad + ImGui::CalcTextSize(done_lbl).x + 12.f,
					                    btn_area_y + 6.f), text_secondary, summary);
				}

				float close_btn_w = 80.f;
				float close_btn_h = 30.f;
				float close_btn_x = dx + sw - pad - close_btn_w;
				float close_btn_y = btn_area_y;
				ImVec2 cbmin(close_btn_x, close_btn_y);
				ImVec2 cbmax(close_btn_x + close_btn_w, close_btn_y + close_btn_h);
				bool cbhov = ImGui::IsMouseHoveringRect(cbmin, cbmax);

				dl->AddRectFilled(cbmin, cbmax,
					cbhov ? _ta(ui_anim::lighten(_t.panel_header, 14)) : _ta(_t.panel_header), 6.f);
				const char* close_lbl = "Close";
				ImVec2 clsz2 = ImGui::CalcTextSize(close_lbl);
				dl->AddText(ImVec2(close_btn_x + close_btn_w * 0.5f - clsz2.x * 0.5f,
				                    close_btn_y + close_btn_h * 0.5f - clsz2.y * 0.5f),
					text_primary, close_lbl);

				if (cbhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
					st.open = false;
			}
		}
	}

	if (st.open) {
		bool esc = ImGui::IsKeyPressed(ImGuiKey_Escape);
		if (esc) {
			if (source_reconstructor::is_running())
				source_reconstructor::cancel();
			st.open = false;
		}
	}
}

}
