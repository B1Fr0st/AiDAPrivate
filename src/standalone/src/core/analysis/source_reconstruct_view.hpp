#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "imgui/imgui.h"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../helpers/win32_dialog.hpp"
#include "source_reconstructor.hpp"
#include "ui_anim.hpp"
#include "theme.hpp"
#include "../disasm/disasm_view.hpp"

namespace source_reconstruct_view {

struct view_state_t {
	bool   open = false;
	bool   prev_open = false;
	float  fade = 0.f;
	float  scale_anim = 0.f;
	float  anim_time = 0.f;
	char   output_dir[512] = {};
	bool   started = false;
	float  progress_display = 0.f;
	float  shimmer_phase = 0.f;
	int    total_display = 0;
	int    done_display = 0;
	float  stage_dot_pulse[8] = {};
	float  pipeline_line_anim = 0.f;
	source_reconstructor::workspace_reconstruction_state_t recon_state;
};

namespace {

inline std::mutex& view_registry_mutex() {
	static std::mutex value;
	return value;
}

inline std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<view_state_t>, aida::analysis::binary_id_hash_t>&
view_registry() {
	static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<view_state_t>, aida::analysis::binary_id_hash_t> value;
	return value;
}

inline std::shared_ptr<view_state_t> view_for(const disasm_view::workspace_context_t& context) {
	if (!context.workspace)
		return {};
	const auto id = context.workspace->identity().binary_id();
	std::lock_guard<std::mutex> lock(view_registry_mutex());
	auto& registry = view_registry();
	for (auto it = registry.begin(); it != registry.end();) {
		if (it->second && !it->second->open &&
		    !source_reconstructor::is_running_workspace(it->second->recon_state) &&
		    it->second->fade < 0.01f)
			it = registry.erase(it);
		else
			++it;
	}
	auto found = registry.find(id);
	if (found != registry.end())
		return found->second;
	auto created = std::make_shared<view_state_t>();
	registry[id] = created;
	return created;
}

inline std::shared_ptr<view_state_t> view_for_selected() {
	return view_for(disasm_view::capture_selected_workspace());
}

}

inline bool is_open() {
	auto st = view_for_selected();
	if (!st) return false;
	return st->open || st->fade > 0.01f;
}

inline void apply_default_output_dir(view_state_t& st) {
	if (st.output_dir[0] != '\0') return;
	char home[MAX_PATH] = {};
	DWORD got = GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH);
	if (got == 0 || got >= MAX_PATH) {
		const char* fallback = std::getenv("USERPROFILE");
		if (fallback && *fallback) {
			std::strncpy(home, fallback, MAX_PATH - 1);
		}
	}
	if (home[0] == '\0') {
		std::strncpy(st.output_dir, "C:\\AiDA_Reconstruction", sizeof(st.output_dir) - 1);
		return;
	}
	std::snprintf(st.output_dir, sizeof(st.output_dir),
		"%s\\Documents\\AiDA_Reconstruction", home);
}

inline void open(const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	st->open = true;
	st->started = false;
	st->progress_display = 0.f;
	st->pipeline_line_anim = 0.f;
	for (int i = 0; i < 8; ++i) st->stage_dot_pulse[i] = 0.f;
	apply_default_output_dir(*st);
}

inline void close(const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	if (source_reconstructor::is_running_workspace(st->recon_state))
		source_reconstructor::cancel_workspace(st->recon_state);
	st->open = false;
}

inline bool pick_output_directory(HWND owner, char* buf, size_t buf_size) {
	if (!buf || buf_size < 4) return false;
	std::string picked;
	if (!win32_dialog::show_open_folder_dialog(owner,
			L"Select Output Directory",
			picked,
			"source_reconstruct_view::pick_output_directory")) {
		return false;
	}
	if (picked.empty() || picked.size() + 1 > buf_size) return false;
	std::memcpy(buf, picked.data(), picked.size());
	buf[picked.size()] = '\0';
	return true;
}

inline void render_impl(float alpha, float ar, float ag, float ab,
                        view_state_t& st,
                        const disasm_view::workspace_context_t& context) {
	float dt = ImGui::GetIO().DeltaTime;
	st.anim_time += dt;

	bool opening_transition = (st.open && !st.prev_open);
	st.prev_open = st.open;
	if (opening_transition) apply_default_output_dir(st);

	float fade_target = st.open ? 1.f : 0.f;
	st.fade = ui_anim::smooth_lerp(st.fade, fade_target, 10.f, dt);
	if (st.fade < 0.005f) return;

	float scale_target = st.open ? 1.f : 0.85f;
	st.scale_anim = ui_anim::smooth_lerp(st.scale_anim, scale_target, 12.f, dt);

	float fa = alpha * st.fade;
	ImVec2 vp = ImGui::GetMainViewport()->Size;

	ImGui::SetNextWindowPos(ImVec2(0.f, 0.f));
	ImGui::SetNextWindowSize(vp);
	ImGui::SetNextWindowBgAlpha(0.0f);
	if (opening_transition) ImGui::SetNextWindowFocus();
	ImGuiWindowFlags modal_flags =
		ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoScrollbar |
		ImGuiWindowFlags_NoScrollWithMouse |
		ImGuiWindowFlags_NoBackground |
		ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_NoDocking;
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
	bool window_open = ImGui::Begin("##source_reconstruct_modal", nullptr, modal_flags);
	ImGui::PopStyleVar(2);
	if (!window_open) {
		ImGui::End();
		return;
	}

	ImDrawList* dl = ImGui::GetWindowDrawList();

	const auto& _t = themes::resolved;
	const auto& _ut = aida::ui::resolved();
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

	const float pad = 22.f;
	float cur_y = dy + 16.f;

	{
		const float icon_sz = 22.f;
		float icon_x = dx + pad;
		float icon_y = cur_y + 1.f;
		ImU32 ic_top = aida::ui::with_alpha(_ut.accent_grad_top, fa);
		ImU32 ic_bot = aida::ui::with_alpha(_ut.accent_grad_bot, fa);
		ImU32 ic_flat = aida::ui::mix(ic_top, ic_bot, 0.5f);
		dl->AddRectFilled(ImVec2(icon_x, icon_y),
			ImVec2(icon_x + icon_sz, icon_y + icon_sz), ic_flat, 6.f);
		dl->AddRect(ImVec2(icon_x, icon_y),
			ImVec2(icon_x + icon_sz, icon_y + icon_sz),
			aida::ui::with_alpha(_ut.accent_hover, fa * 0.85f), 6.f, 0, 1.2f);
		ImU32 glyph_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), fa);
		float gy0 = icon_y + 6.f;
		float gx0 = icon_x + 6.f;
		float gw = icon_sz - 12.f;
		dl->AddLine(ImVec2(gx0, gy0), ImVec2(gx0 + gw, gy0), glyph_col, 1.5f);
		dl->AddLine(ImVec2(gx0, gy0 + 4.f), ImVec2(gx0 + gw - 2.f, gy0 + 4.f), glyph_col, 1.5f);
		dl->AddLine(ImVec2(gx0, gy0 + 8.f), ImVec2(gx0 + gw - 4.f, gy0 + 8.f), glyph_col, 1.5f);

		ImFont* title_font = aida::ui::fonts::body_strong();
		if (!title_font) title_font = ImGui::GetFont();
		const char* title = "Reconstruct Source";
		ImVec2 tsz = title_font->CalcTextSizeA(title_font->FontSize, FLT_MAX, 0.f, title);
		dl->AddText(title_font, title_font->FontSize,
			ImVec2(icon_x + icon_sz + 10.f, icon_y + (icon_sz - tsz.y) * 0.5f),
			text_primary, title);

		float close_x = dx + sw - pad - 18.f;
		float close_y = icon_y + (icon_sz - 16.f) * 0.5f;
		ImVec2 cmin(close_x, close_y);
		ImVec2 cmax(close_x + 16.f, close_y + 16.f);
		bool close_hov = ImGui::IsMouseHoveringRect(cmin, cmax);
		ImU32 close_col = close_hov ? aida::ui::with_alpha(aida::ui::resolved().error, 0.86f * fa)
		                            : _ta(_t.text_secondary);
		dl->AddLine(ImVec2(close_x + 2, close_y + 2), ImVec2(close_x + 14, close_y + 14), close_col, 2.f);
		dl->AddLine(ImVec2(close_x + 14, close_y + 2), ImVec2(close_x + 2, close_y + 14), close_col, 2.f);

		if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			if (source_reconstructor::is_running_workspace(st.recon_state))
				source_reconstructor::cancel_workspace(st.recon_state);
			st.open = false;
		}

		cur_y = icon_y + icon_sz + 18.f;
	}

	{
		ImFont* lbl_font = aida::ui::fonts::body_em();
		if (!lbl_font) lbl_font = ImGui::GetFont();
		dl->AddText(lbl_font, lbl_font->FontSize,
			ImVec2(dx + pad, cur_y), text_secondary, "Output Directory");
		cur_y += lbl_font->FontSize + 10.f;

		float browse_w = 92.f;
		float gap = 8.f;
		float input_h = 34.f;
		float input_w = sw - pad * 2.f - browse_w - gap;
		ImVec2 imin(dx + pad, cur_y);
		ImVec2 imax(dx + pad + input_w, cur_y + input_h);

		dl->AddRectFilled(imin, imax, _ta(_ut.bg_elevated), 8.f);
		dl->AddRect(imin, imax, _ta(ui_anim::lighten(_t.panel_bg, 14)), 8.f, 0, 1.2f);

		ImGui::SetCursorScreenPos(ImVec2(imin.x + 4.f, imin.y + 2.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_primary));
		ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, aida::ui::with_alpha(_ut.accent_dim, fa));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushItemWidth(input_w - 8.f);

		if (!st.started) {
			ImGui::InputTextWithHint("##recon_outdir", "C:\\path\\to\\output", st.output_dir,
				sizeof(st.output_dir), ImGuiInputTextFlags_None);
		} else {
			ImGui::PushStyleColor(ImGuiCol_Text, _ta(_t.text_secondary));
			ImGui::InputText("##recon_outdir", st.output_dir, sizeof(st.output_dir),
				ImGuiInputTextFlags_ReadOnly);
			ImGui::PopStyleColor();
		}

		ImGui::PopItemWidth();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);

		float browse_x = imax.x + gap;
		ImVec2 bmin(browse_x, cur_y);
		ImVec2 bmax(browse_x + browse_w, cur_y + input_h);
		bool br_hov = !st.started && ImGui::IsMouseHoveringRect(bmin, bmax);
		ImU32 br_top = br_hov ? aida::ui::with_alpha(_ut.accent_grad_top, fa * 0.95f)
		                       : aida::ui::with_alpha(_ut.accent_dim, fa * 0.55f);
		ImU32 br_bot = br_hov ? aida::ui::with_alpha(_ut.accent_grad_bot, fa * 0.95f)
		                       : aida::ui::with_alpha(_ut.accent_dim, fa * 0.30f);
		ImU32 br_flat = aida::ui::mix(br_top, br_bot, 0.5f);
		dl->AddRectFilled(bmin, bmax, br_flat, 8.f);
		dl->AddRect(bmin, bmax,
			br_hov ? aida::ui::with_alpha(_ut.accent_hover, fa * 0.92f)
			       : aida::ui::with_alpha(_ut.accent_dim, fa * 0.75f),
			8.f, 0, 1.0f);
		ImFont* br_font = aida::ui::fonts::body_em();
		if (!br_font) br_font = ImGui::GetFont();
		const char* br_lbl = "Browse...";
		ImVec2 bsz = br_font->CalcTextSizeA(br_font->FontSize, FLT_MAX, 0.f, br_lbl);
		dl->AddText(br_font, br_font->FontSize,
			ImVec2(browse_x + (browse_w - bsz.x) * 0.5f,
			       cur_y + (input_h - bsz.y) * 0.5f),
			br_hov ? aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), fa)
			       : aida::ui::with_alpha(_t.text_primary, fa * 0.92f),
			br_lbl);
		if (br_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			pick_output_directory(::g_hwnd, st.output_dir, sizeof(st.output_dir));
		}

		cur_y += input_h + 10.f;
	}

	auto recon_stage = static_cast<source_reconstructor::stage_t>(
		st.recon_state.stage.load(std::memory_order_relaxed));
	int total_fn = source_reconstructor::get_total_functions_workspace(st.recon_state);

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

		float real_progress = source_reconstructor::get_progress_workspace(st.recon_state);
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
			if (shimmer_w > 8.f && source_reconstructor::is_running_workspace(st.recon_state)) {
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
		int total = source_reconstructor::get_total_functions_workspace(st.recon_state);
		int done = source_reconstructor::get_decompiled_count_workspace(st.recon_state);

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

		std::string status = source_reconstructor::get_status_workspace(st.recon_state);
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
			bool has_workspace = context.workspace && !context.workspace->closed();

			float btn_w = 140.f;
			float btn_h = 36.f;
			float btn_x = dx + sw * 0.5f - btn_w * 0.5f;
			float btn_y = btn_area_y;

			ImVec2 bmin(btn_x, btn_y);
			ImVec2 bmax(btn_x + btn_w, btn_y + btn_h);
			bool bhov = has_output && has_workspace && ImGui::IsMouseHoveringRect(bmin, bmax);

			float button_alpha = (has_output && has_workspace) ? fa : (fa * _ut.disabled_alpha);
			float bhov_f = bhov ? 1.f : 0.f;
			ImU32 idle_top = aida::ui::with_alpha(_ut.accent_dim, 0.55f);
			ImU32 idle_bot = aida::ui::with_alpha(_ut.accent_dim, 0.30f);
			ImU32 hov_top  = aida::ui::with_alpha(_ut.accent_grad_top, 0.95f);
			ImU32 hov_bot  = aida::ui::with_alpha(_ut.accent_grad_bot, 0.95f);
			ImU32 cur_top  = aida::ui::mix(idle_top, hov_top, bhov_f);
			ImU32 cur_bot  = aida::ui::mix(idle_bot, hov_bot, bhov_f);
			ImU32 btn_flat = aida::ui::mix(cur_top, cur_bot, 0.5f);
			dl->AddRectFilled(bmin, bmax, aida::ui::with_alpha(btn_flat, button_alpha), 6.f);
			ImU32 br_idle = aida::ui::with_alpha(_ut.accent_dim, 0.75f);
			ImU32 br_hov  = aida::ui::with_alpha(_ut.accent_hover, 0.92f);
			ImU32 btn_border = aida::ui::mix(br_idle, br_hov, bhov_f);
			dl->AddRect(bmin, bmax, aida::ui::with_alpha(btn_border, button_alpha), 6.f, 0, 1.0f);

			const char* start_lbl = "Start";
			ImFont* st_font = aida::ui::fonts::body_em();
			if (!st_font) st_font = ImGui::GetFont();
			ImVec2 slsz = st_font->CalcTextSizeA(st_font->FontSize, FLT_MAX, 0.f, start_lbl);
			ImU32 tc_idle = aida::ui::with_alpha(_t.text_primary, 0.92f);
			ImU32 tc_hov  = aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), 0.96f);
			ImU32 start_text_col = aida::ui::with_alpha(aida::ui::mix(tc_idle, tc_hov, bhov_f), button_alpha);
			dl->AddText(st_font, st_font->FontSize,
				ImVec2(btn_x + (btn_w - slsz.x) * 0.5f,
				       btn_y + (btn_h - slsz.y) * 0.5f),
				start_text_col, start_lbl);

			if (bhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
			    !source_reconstructor::is_running_workspace(st.recon_state) && has_workspace) {
				source_reconstructor::workspace_reconstruction_config_t config;
				config.workspace = context.workspace;
				config.output_dir = st.output_dir;
				config.project_name = "reconstructed";
				config.include_imports = true;
				config.include_exports = true;
				config.generate_cmake = true;
				config.max_functions = 0;
				source_reconstructor::reconstruct_workspace(config, st.recon_state);
				st.started = true;
			}
		} else {
			bool running = source_reconstructor::is_running_workspace(st.recon_state);

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
					source_reconstructor::cancel_workspace(st.recon_state);
			} else {
				const auto& last = source_reconstructor::get_last_result_workspace(st.recon_state);
				const char* done_lbl = last.success
					? "Complete!"
					: last.decompiled_functions > 0 ? "Incomplete" : "Failed";
				const auto& th_done = aida::ui::resolved();
				ImU32 done_col = last.success ? aida::ui::with_alpha(th_done.success, 0.86f * fa)
				                              : aida::ui::with_alpha(th_done.error,   0.86f * fa);
				dl->AddText(ImVec2(dx + pad, btn_area_y + 6.f), done_col, done_lbl);

				char summary[160];
				snprintf(summary, sizeof(summary), "%d / %d functions, %d diagnostics, %d files",
					last.decompiled_functions, last.total_functions,
					static_cast<int>(last.diagnostics.size()),
					static_cast<int>(last.files_created.size()));
				const float summary_x = dx + pad + ImGui::CalcTextSize(done_lbl).x + 12.f;
				const float summary_right = dx + sw - pad - 92.f;
				if (summary_right > summary_x) {
					dl->PushClipRect(ImVec2(summary_x, btn_area_y),
						ImVec2(summary_right, btn_area_y + 30.f), true);
					dl->AddText(ImVec2(summary_x, btn_area_y + 6.f), text_secondary, summary);
					dl->PopClipRect();
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
			if (source_reconstructor::is_running_workspace(st.recon_state))
				source_reconstructor::cancel_workspace(st.recon_state);
			st.open = false;
		}

		bool inside_dialog = (ImGui::GetMousePos().x >= dmin.x &&
		                      ImGui::GetMousePos().x <= dmax.x &&
		                      ImGui::GetMousePos().y >= dmin.y &&
		                      ImGui::GetMousePos().y <= dmax.y);
		if (!inside_dialog && !source_reconstructor::is_running_workspace(st.recon_state) &&
		    ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !ImGui::IsAnyItemActive()) {
			st.open = false;
		}
	}

	ImGui::End();
}

inline void render(float alpha, float ar, float ag, float ab,
                   const disasm_view::workspace_context_t& context) {
	auto st = view_for(context);
	if (!st) return;
	render_impl(alpha, ar, ag, ab, *st, context);
}

inline void render(float alpha, float ar, float ag, float ab) {
	auto st = view_for_selected();
	if (!st) return;
	render_impl(alpha, ar, ag, ab, *st, disasm_view::capture_selected_workspace());
}

}
