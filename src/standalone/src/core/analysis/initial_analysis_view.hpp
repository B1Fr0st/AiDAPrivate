#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "initial_analysis.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/fonts.hpp"
#include "../ui/clock.hpp"
#include "../ui/blur_layer.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/win32_dialog.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <string>

extern HWND g_hwnd;

namespace initial_analysis_view {

namespace detail {

inline float& modal_anim()       { static float v = 0.f; return v; }
inline bool&  modal_closing()    { static bool v = false; return v; }
inline int&   modal_open_frame() { static int v = -1; return v; }
inline float& overlay_anim()     { static float v = 0.f; return v; }
inline bool&  pending_close()    { static bool v = false; return v; }

inline bool& load_types_local() { static bool v = true; return v; }
inline bool& load_names_local() { static bool v = true; return v; }

inline void sync_local_options()
{
	load_types_local() = initial_analysis::g_state.opt_load_types.load(std::memory_order_acquire);
	load_names_local() = initial_analysis::g_state.opt_load_names.load(std::memory_order_acquire);
}

inline ImU32 step_color(const initial_analysis::step_t& s)
{
	const auto& t = aida::ui::resolved();
	if (s.skipped.load(std::memory_order_acquire)) return t.text_dim;
	if (s.done.load(std::memory_order_acquire))    return t.success;
	if (s.running.load(std::memory_order_acquire)) return t.accent_u32;
	return t.text_dim;
}

inline const char* step_glyph(const initial_analysis::step_t& s)
{
	if (s.skipped.load(std::memory_order_acquire)) return "-";
	if (s.done.load(std::memory_order_acquire))    return "v";
	if (s.running.load(std::memory_order_acquire)) return ">";
	return "o";
}

}

inline void render_modal()
{
	auto& st = initial_analysis::g_state;
	bool wants_prompt = st.needs_pdb_prompt.load(std::memory_order_acquire);

	float& anim     = detail::modal_anim();
	bool&  closing  = detail::modal_closing();
	int&   open_fr  = detail::modal_open_frame();
	bool&  pending  = detail::pending_close();

	float dt = ImGui::GetIO().DeltaTime;
	float target = (wants_prompt && !closing) ? 1.f : 0.f;
	anim += (target - anim) * (std::min)(dt * 14.f, 1.f);
	if (std::fabs(anim - target) < 0.003f) anim = target;

	if (pending && anim < 0.01f) {
		pending = false;
		closing = false;
		open_fr = -1;
		anim = 0.f;
		return;
	}

	if (!wants_prompt && anim < 0.005f) {
		if (open_fr >= 0) open_fr = -1;
		return;
	}

	if (open_fr < 0) {
		open_fr = ImGui::GetFrameCount();
		detail::sync_local_options();
	}

	ImVec2 vp = ImGui::GetIO().DisplaySize;
	ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), vp,
		IM_COL32(0, 0, 0, static_cast<int>(150.f * anim)));

	float pw = 620.f, ph = 500.f;
	float scale = 0.96f + 0.04f * anim;
	float sw = pw * scale, sh = ph * scale;
	float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

	if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !closing && wants_prompt) {
		initial_analysis::decline_pdb_prompt();
		closing = true;
		pending = true;
	}

	ImGui::SetNextWindowPos(ImVec2(px, py));
	ImGui::SetNextWindowSize(ImVec2(sw, sh));
	ImGui::SetNextWindowFocus();
	const auto& th = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th.bg_elevated, anim * 0.97f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th.border_strong, anim));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 16));

	ImGui::Begin("Debug information available##ia_pdb_dlg", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);

	{
		ImGui::PushFont(aida::ui::fonts::h2());
		ImVec4 acc = th.accent;
		ImGui::TextColored(acc, "Debug information available");
		ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 4.f));
		ImGui::PushFont(aida::ui::fonts::body());

		initial_analysis::pdb_hint_t hint;
		{
			std::lock_guard<std::mutex> lk(st.pdb_hint_mtx);
			hint = st.pdb_hint;
		}

		ImGui::TextWrapped("The input file was linked with debug information stored here: %s",
			hint.pdb_name.c_str());
		ImGui::Dummy(ImVec2(0.f, 6.f));
		ImGui::TextWrapped("Do you want to look for this file at the specified path and the Microsoft Symbol Server?");
		ImGui::Dummy(ImVec2(0.f, 8.f));

		ImGui::PushStyleColor(ImGuiCol_Text, th.text_dim);
		ImGui::PushFont(aida::ui::fonts::caption());
		ImGui::TextWrapped("GUID: %s   Age: %u", hint.pdb_guid.c_str(),
			static_cast<unsigned>(hint.pdb_age));
		ImGui::PushFont(aida::ui::fonts::code());
		ImGui::TextWrapped("%s", hint.symbol_url.c_str());
		ImGui::PopFont();
		ImGui::PopFont();
		ImGui::PopStyleColor();

		ImGui::PopFont();
	}

	float btn_h = 38.f;
	float btn_w = 156.f;
	float btn_spacing = 14.f;
	float total_w = btn_w * 2.f + btn_spacing;
	float bx = (sw - total_w) * 0.5f;
	float by_btn = sh - btn_h - 24.f;
	float toggle_row_h = 60.f;
	float toggle_block_top = by_btn - toggle_row_h - 20.f;

	{
		ImGui::SetCursorPos(ImVec2(20.f, toggle_block_top));
		ImGui::PushFont(aida::ui::fonts::body());
		bool lt = detail::load_types_local();
		bool ln = detail::load_names_local();
		if (aida::ui::toggle_switch("Load Types", &lt, aida::ui::size_t_::md))
			detail::load_types_local() = lt;
		ImGui::Dummy(ImVec2(0.f, 12.f));
		if (aida::ui::toggle_switch("Load Names", &ln, aida::ui::size_t_::md))
			detail::load_names_local() = ln;
		ImGui::PopFont();
	}

	{
		ImGui::SetCursorPos(ImVec2(bx, by_btn));
		bool yes_clicked = aida::ui::button("Yes, download",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::md, ImVec2(btn_w, btn_h));
		ImGui::SetCursorPos(ImVec2(bx + btn_w + btn_spacing, by_btn));
		bool no_clicked = aida::ui::button("No, skip",
			aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(btn_w, btn_h));

		if (yes_clicked && !closing) {
			initial_analysis::accept_pdb_prompt(detail::load_types_local(),
				detail::load_names_local());
			closing = true;
			pending = true;
		}
		if (no_clicked && !closing) {
			initial_analysis::decline_pdb_prompt();
			closing = true;
			pending = true;
		}
	}

	ImGui::End();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
}

inline void render_overlay()
{
	auto& st = initial_analysis::g_state;
	bool running = st.running.load(std::memory_order_acquire);
	bool finished = st.finished.load(std::memory_order_acquire);
	bool dismissed = st.overlay_dismissed.load(std::memory_order_acquire);
	bool any_logs_yet = false;
	{
		std::lock_guard<std::mutex> lk(st.log_mtx);
		any_logs_yet = !st.log_lines.empty();
	}

	bool wants_visible = (running || (finished && !dismissed)) && any_logs_yet;

	ImVec2 vp_for_hit = ImGui::GetIO().DisplaySize;
	float w_for_hit = 420.f;
	float h_for_hit = 240.f;
	float margin_for_hit = 24.f;
	float ov_x_for_hit = vp_for_hit.x - w_for_hit - margin_for_hit;
	float ov_y_for_hit = vp_for_hit.y - h_for_hit - margin_for_hit - 28.f;
	if (ov_y_for_hit < 80.f) ov_y_for_hit = 80.f;
	ImVec2 mp_for_hit = ImGui::GetMousePos();
	bool hovered_overlay = (mp_for_hit.x >= ov_x_for_hit && mp_for_hit.x <= ov_x_for_hit + w_for_hit &&
	                       mp_for_hit.y >= ov_y_for_hit && mp_for_hit.y <= ov_y_for_hit + h_for_hit);

	if (finished && !dismissed) {
		uint64_t fin_ns = st.finish_time_ns.load(std::memory_order_acquire);
		if (fin_ns != 0 && !hovered_overlay) {
			uint64_t now = initial_analysis::detail::now_ns();
			if (now - fin_ns > 5ull * 1000000000ull) {
				wants_visible = false;
				st.overlay_dismissed.store(true, std::memory_order_release);
			}
		} else if (fin_ns != 0 && hovered_overlay) {
			st.finish_time_ns.store(initial_analysis::detail::now_ns(), std::memory_order_release);
		}
	}

	float& anim = detail::overlay_anim();
	float dt = ImGui::GetIO().DeltaTime;
	float target = wants_visible ? 1.f : 0.f;
	anim += (target - anim) * (std::min)(dt * 8.f, 1.f);
	if (std::fabs(anim - target) < 0.003f) anim = target;
	st.overlay_visibility.store(anim, std::memory_order_release);

	if (anim < 0.005f) return;

	const auto& th = aida::ui::resolved();

	ImVec2 vp = ImGui::GetIO().DisplaySize;
	float w = 420.f;
	float h = 240.f;
	float margin = 24.f;
	float x = vp.x - w - margin;
	float y = vp.y - h - margin - 28.f;
	if (y < 80.f) y = 80.f;

	float slide = (1.f - anim) * 24.f;
	x += slide;

	ImVec2 a(x, y);
	ImVec2 b(x + w, y + h);

	ImDrawList* fg = ImGui::GetForegroundDrawList();

	ImU32 shadow_col = aida::ui::with_alpha(IM_COL32(0, 0, 0, 220), anim * 0.55f);
	for (int i = 0; i < 4; ++i) {
		float k = static_cast<float>(i + 1);
		fg->AddRectFilled(ImVec2(a.x - k, a.y - k + 3.f), ImVec2(b.x + k, b.y + k + 3.f),
			aida::ui::with_alpha(shadow_col, 0.16f / k), 14.f + k);
	}

	fg->AddRectFilled(a, b, aida::ui::with_alpha(th.bg_elevated, anim * 0.96f), 12.f);
	fg->AddRect(a, b, aida::ui::with_alpha(th.border_strong, anim), 12.f, 0, 1.2f);

	float pad = 14.f;
	float header_h = 30.f;

	bool ov_running = st.running.load(std::memory_order_acquire);
	bool ov_finished = st.finished.load(std::memory_order_acquire);

	ImFont* hf = aida::ui::fonts::body_strong();
	float hfs = hf ? 14.f : 14.f;
	const char* title = "Initial autoanalysis";
	fg->AddText(hf, hfs, ImVec2(a.x + pad, a.y + pad - 2.f),
		aida::ui::with_alpha(th.text_primary, anim), title);

	const char* status_text = ov_finished ? "complete"
	                         : (ov_running ? "in progress" : "idle");
	ImU32 status_col = ov_finished ? th.success : (ov_running ? th.accent_u32 : th.text_dim);
	ImFont* cf = aida::ui::fonts::caption();
	float cfs = cf ? 12.f : 12.f;
	float sw = cf ? cf->CalcTextSizeA(cfs, FLT_MAX, 0.f, status_text).x : 50.f;

	float status_right_x = b.x - pad;
	bool show_rerun_btn = ov_finished && initial_analysis::can_run_for_disk_load();
	if (show_rerun_btn) {
		const char* rerun_lbl = "Re-run";
		float rerun_text_w = cf ? cf->CalcTextSizeA(cfs, FLT_MAX, 0.f, rerun_lbl).x : 44.f;
		float rerun_btn_w = rerun_text_w + 14.f;
		float rerun_btn_h = 18.f;
		float rerun_btn_x = b.x - pad - rerun_btn_w;
		float rerun_btn_y = a.y + pad - 3.f;
		ImVec2 rmin(rerun_btn_x, rerun_btn_y);
		ImVec2 rmax(rerun_btn_x + rerun_btn_w, rerun_btn_y + rerun_btn_h);
		bool rhov = (mp_for_hit.x >= rmin.x && mp_for_hit.x <= rmax.x &&
		             mp_for_hit.y >= rmin.y && mp_for_hit.y <= rmax.y);
		ImU32 rbg = rhov
			? aida::ui::with_alpha(th.accent_grad_top, anim * 0.92f)
			: aida::ui::with_alpha(th.panel_header, anim * 0.85f);
		ImU32 rbr = rhov
			? aida::ui::with_alpha(th.accent_hover, anim)
			: aida::ui::with_alpha(th.border_subtle, anim);
		fg->AddRectFilled(rmin, rmax, rbg, 5.f);
		fg->AddRect(rmin, rmax, rbr, 5.f, 0, 1.f);
		ImU32 rtxt = rhov
			? aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), anim)
			: aida::ui::with_alpha(th.text_primary, anim);
		fg->AddText(cf, cfs,
			ImVec2(rmin.x + (rerun_btn_w - rerun_text_w) * 0.5f,
			       rmin.y + (rerun_btn_h - cfs) * 0.5f + 1.f),
			rtxt, rerun_lbl);
		if (rhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			anti_tamper::webhook::write_log("analysis_audit",
				"[analysis_audit] initial_analysis rerun_clicked");
			diag::log_tagged("initial_analysis", "[analysis_audit] view_rerun_request");
			initial_analysis::run_initial_analysis_for_loaded_file();
		}
		status_right_x = rmin.x - 8.f;

		bool deep_done = function_index::deep_static_analysis_requested();
		const char* deep_lbl = deep_done ? "Deep [running]" : "Deep";
		float deep_text_w = cf ? cf->CalcTextSizeA(cfs, FLT_MAX, 0.f, deep_lbl).x : 36.f;
		float deep_btn_w = deep_text_w + 14.f;
		float deep_btn_h = 18.f;
		float deep_btn_x = rerun_btn_x - 8.f - deep_btn_w;
		float deep_btn_y = a.y + pad - 3.f;
		ImVec2 dmin(deep_btn_x, deep_btn_y);
		ImVec2 dmax(deep_btn_x + deep_btn_w, deep_btn_y + deep_btn_h);
		bool dhov = (mp_for_hit.x >= dmin.x && mp_for_hit.x <= dmax.x &&
		             mp_for_hit.y >= dmin.y && mp_for_hit.y <= dmax.y);
		ImU32 dbg = deep_done
			? aida::ui::with_alpha(th.success, anim * 0.55f)
			: (dhov
				? aida::ui::with_alpha(th.accent_grad_top, anim * 0.85f)
				: aida::ui::with_alpha(th.panel_header, anim * 0.85f));
		ImU32 dbr = dhov
			? aida::ui::with_alpha(th.accent_hover, anim)
			: aida::ui::with_alpha(th.border_subtle, anim);
		fg->AddRectFilled(dmin, dmax, dbg, 5.f);
		fg->AddRect(dmin, dmax, dbr, 5.f, 0, 1.f);
		ImU32 dtxt = dhov
			? aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), anim)
			: aida::ui::with_alpha(th.text_primary, anim);
		fg->AddText(cf, cfs,
			ImVec2(dmin.x + (deep_btn_w - deep_text_w) * 0.5f,
			       dmin.y + (deep_btn_h - cfs) * 0.5f + 1.f),
			dtxt, deep_lbl);
		if (dhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !deep_done) {
			anti_tamper::webhook::write_log("analysis_audit",
				"[analysis_audit] deep_static_analysis_clicked");
			diag::log_tagged("initial_analysis", "[analysis_audit] deep_static_analysis_request");
			function_index::request_deep_static_analysis();
			xref_index::request_deep_static_xref();
		}
		status_right_x = dmin.x - 8.f;
	}

	fg->AddText(cf, cfs, ImVec2(status_right_x - sw, a.y + pad),
		aida::ui::with_alpha(status_col, anim), status_text);

	std::string fn;
	{
		std::lock_guard<std::mutex> lk(st.path_mtx);
		fn = st.target_filename;
	}
	if (!fn.empty()) {
		ImFont* sf = aida::ui::fonts::caption();
		float sfs = 11.f;
		fg->AddText(sf, sfs, ImVec2(a.x + pad, a.y + pad + 18.f),
			aida::ui::with_alpha(th.text_dim, anim), fn.c_str());
	}

	float bar_y = a.y + header_h + 12.f;
	float bar_w = w - pad * 2.f;
	float bar_h = 4.f;

	float prog = st.overall_progress.load(std::memory_order_acquire);
	fg->AddRectFilled(ImVec2(a.x + pad, bar_y), ImVec2(a.x + pad + bar_w, bar_y + bar_h),
		aida::ui::with_alpha(th.panel_header, anim), bar_h * 0.5f);
	if (prog > 0.f) {
		float fw = bar_w * prog;
		fg->AddRectFilledMultiColor(ImVec2(a.x + pad, bar_y),
			ImVec2(a.x + pad + fw, bar_y + bar_h),
			aida::ui::with_alpha(th.accent_grad_top, anim),
			aida::ui::with_alpha(th.accent_grad_top, anim),
			aida::ui::with_alpha(th.accent_grad_bot, anim),
			aida::ui::with_alpha(th.accent_grad_bot, anim));
	}

	int active = st.active_step_index.load(std::memory_order_acquire);
	std::string active_label;
	if (active >= 0 && active < static_cast<int>(st.steps.size())) {
		active_label = st.steps[active]->label;
	} else if (st.finished.load(std::memory_order_acquire)) {
		active_label = "The initial autoanalysis has been finished.";
	}
	if (!active_label.empty()) {
		ImFont* lf = aida::ui::fonts::body();
		float lfs = 12.5f;
		fg->AddText(lf, lfs,
			ImVec2(a.x + pad, bar_y + bar_h + 8.f),
			aida::ui::with_alpha(th.text_secondary, anim), active_label.c_str());
	}

	float log_y = bar_y + bar_h + 32.f;
	float log_h = b.y - log_y - pad;
	if (log_h < 40.f) log_h = 40.f;

	fg->AddRectFilled(ImVec2(a.x + pad, log_y),
		ImVec2(b.x - pad, log_y + log_h),
		aida::ui::with_alpha(th.bg_base, anim * 0.85f), 6.f);
	fg->AddRect(ImVec2(a.x + pad, log_y),
		ImVec2(b.x - pad, log_y + log_h),
		aida::ui::with_alpha(th.border_subtle, anim), 6.f);

	ImFont* lf = aida::ui::fonts::code();
	float lfs = 11.f;
	float line_h = lfs + 3.f;
	int max_lines = static_cast<int>(log_h / line_h) - 1;
	if (max_lines < 1) max_lines = 1;

	std::vector<std::string> tail;
	{
		std::lock_guard<std::mutex> lk(st.log_mtx);
		int total = static_cast<int>(st.log_lines.size());
		int from = (total > max_lines) ? (total - max_lines) : 0;
		tail.reserve(static_cast<size_t>(total - from));
		for (int i = from; i < total; ++i)
			tail.push_back(st.log_lines[static_cast<size_t>(i)]);
	}

	float ty = log_y + 4.f;
	float tx = a.x + pad + 6.f;
	float tw = w - pad * 2.f - 12.f;
	fg->PushClipRect(ImVec2(a.x + pad, log_y),
		ImVec2(b.x - pad, log_y + log_h), true);
	for (const auto& line : tail) {
		std::string display = line;
		if (lf) {
			while (lf->CalcTextSizeA(lfs, FLT_MAX, 0.f, display.c_str()).x > tw &&
				display.size() > 4)
			{
				display.pop_back();
			}
		}
		fg->AddText(lf, lfs, ImVec2(tx, ty),
			aida::ui::with_alpha(th.text_secondary, anim * 0.95f),
			display.c_str());
		ty += line_h;
		if (ty > log_y + log_h - 3.f) break;
	}
	fg->PopClipRect();
}

namespace detail {

inline float& local_pdb_anim()      { static float v = 0.f; return v; }
inline bool&  local_pdb_closing()   { static bool v = false; return v; }
inline int&   local_pdb_open_frame(){ static int v = -1; return v; }
inline bool&  local_pdb_pending()   { static bool v = false; return v; }
inline std::string& local_pdb_typed_path()
{
	static std::string s;
	return s;
}
inline std::array<char, 1024>& local_pdb_typed_buf()
{
	static std::array<char, 1024> buf{};
	return buf;
}

inline std::string browse_for_pdb_dialog(HWND owner, const std::string& initial_name)
{
	char file_buf[1024] = {};
	if (!initial_name.empty()) {
		std::strncpy(file_buf, initial_name.c_str(),
			sizeof(file_buf) - 1);
	}

	static const char k_initial_pdb_filter[] =
		"PDB files (*.pdb)\0*.pdb\0"
		"All files (*.*)\0*.*\0\0";
	if (!win32_dialog::show_open_file_dialog(owner,
			"Select PDB file",
			k_initial_pdb_filter,
			file_buf, sizeof(file_buf),
			"initial_analysis_view::browse_for_pdb")) {
		return std::string();
	}
	return std::string(file_buf);
}

}

inline void render_local_pdb_modal()
{
	auto& st = initial_analysis::g_state;
	bool wants_prompt = st.needs_local_pdb_prompt.load(std::memory_order_acquire);

	float& anim    = detail::local_pdb_anim();
	bool&  closing = detail::local_pdb_closing();
	int&   open_fr = detail::local_pdb_open_frame();
	bool&  pending = detail::local_pdb_pending();

	float dt = ImGui::GetIO().DeltaTime;
	float target = (wants_prompt && !closing) ? 1.f : 0.f;
	anim += (target - anim) * (std::min)(dt * 14.f, 1.f);
	if (std::fabs(anim - target) < 0.003f) anim = target;

	if (pending && anim < 0.01f) {
		pending = false;
		closing = false;
		open_fr = -1;
		anim = 0.f;
		return;
	}

	if (!wants_prompt && anim < 0.005f) {
		if (open_fr >= 0) open_fr = -1;
		return;
	}

	if (open_fr < 0) {
		open_fr = ImGui::GetFrameCount();
		{
			std::lock_guard<std::mutex> lk(st.local_pdb_mtx);
			std::string seed = st.local_pdb_module_name;
			auto dot = seed.rfind('.');
			if (dot != std::string::npos) seed = seed.substr(0, dot);
			if (!seed.empty()) seed += ".pdb";
			detail::local_pdb_typed_path() = seed;
			std::strncpy(detail::local_pdb_typed_buf().data(), seed.c_str(),
				detail::local_pdb_typed_buf().size() - 1);
		}
	}

	ImVec2 vp = ImGui::GetIO().DisplaySize;
	ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), vp,
		IM_COL32(0, 0, 0, static_cast<int>(160.f * anim)));

	float pw = 680.f, ph = 360.f;
	float scale = 0.96f + 0.04f * anim;
	float sw = pw * scale, sh = ph * scale;
	float px = (vp.x - sw) * 0.5f, py = (vp.y - sh) * 0.5f;

	if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && !closing && wants_prompt) {
		initial_analysis::decline_local_pdb_prompt();
		closing = true;
		pending = true;
	}

	ImGui::SetNextWindowPos(ImVec2(px, py));
	ImGui::SetNextWindowSize(ImVec2(sw, sh));
	ImGui::SetNextWindowFocus();
	const auto& th = aida::ui::resolved();
	ImGui::PushStyleColor(ImGuiCol_WindowBg, aida::ui::with_alpha(th.bg_elevated, anim * 0.97f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(th.border_strong, anim));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22, 18));

	ImGui::Begin("Local PDB needed##ia_local_pdb_dlg", nullptr,
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);

	std::string reason;
	std::string module_name;
	{
		std::lock_guard<std::mutex> lk(st.local_pdb_mtx);
		reason = st.local_pdb_reason;
		module_name = st.local_pdb_module_name;
	}

	{
		ImGui::PushFont(aida::ui::fonts::h2());
		ImVec4 acc = th.accent;
		ImGui::TextColored(acc, "Local PDB file");
		ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 4.f));
		ImGui::PushFont(aida::ui::fonts::body());
		ImGui::TextWrapped("%s", reason.c_str());
		if (!module_name.empty()) {
			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::PushStyleColor(ImGuiCol_Text, th.text_dim);
			ImGui::PushFont(aida::ui::fonts::caption());
			ImGui::TextWrapped("Module: %s", module_name.c_str());
			ImGui::PopFont();
			ImGui::PopStyleColor();
		}
		ImGui::PopFont();
	}

	ImGui::Dummy(ImVec2(0.f, 12.f));

	{
		ImGui::PushFont(aida::ui::fonts::body());
		ImGui::PushStyleColor(ImGuiCol_Text, th.text_secondary);
		ImGui::TextUnformatted("Type the absolute path to the PDB, or click Browse...");
		ImGui::PopStyleColor();
		ImGui::PopFont();

		ImGui::Dummy(ImVec2(0.f, 6.f));
		auto& buf = detail::local_pdb_typed_buf();
		ImGui::PushItemWidth(sw - 44.f - 110.f - 12.f);
		ImGui::PushFont(aida::ui::fonts::code());
		if (ImGui::InputText("##ia_local_pdb_path", buf.data(),
			static_cast<int>(buf.size()),
			ImGuiInputTextFlags_AutoSelectAll))
		{
			detail::local_pdb_typed_path() = buf.data();
		}
		ImGui::PopFont();
		ImGui::PopItemWidth();
		ImGui::SameLine();
		if (aida::ui::button("Browse...",
			aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(108.f, 28.f)))
		{
			std::string seed = module_name;
			auto dot = seed.rfind('.');
			if (dot != std::string::npos) seed = seed.substr(0, dot);
			if (!seed.empty()) seed += ".pdb";
			std::string picked = detail::browse_for_pdb_dialog(g_hwnd, seed);
			if (!picked.empty()) {
				detail::local_pdb_typed_path() = picked;
				std::strncpy(buf.data(), picked.c_str(), buf.size() - 1);
				buf[buf.size() - 1] = '\0';
			}
		}
	}

	float btn_h = 38.f;
	float btn_w = 156.f;
	float btn_spacing = 14.f;
	float total_w = btn_w * 2.f + btn_spacing;
	float bx = (sw - total_w) * 0.5f;
	float by_btn = sh - btn_h - 24.f;

	{
		ImGui::SetCursorPos(ImVec2(bx, by_btn));
		bool load_clicked = aida::ui::button("Load this PDB",
			aida::ui::button_kind_t::primary,
			aida::ui::size_t_::md, ImVec2(btn_w, btn_h));
		ImGui::SetCursorPos(ImVec2(bx + btn_w + btn_spacing, by_btn));
		bool skip_clicked = aida::ui::button("No, skip",
			aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::md, ImVec2(btn_w, btn_h));

		if (load_clicked && !closing) {
			std::string picked = detail::local_pdb_typed_path();
			while (!picked.empty() && (picked.front() == ' ' || picked.front() == '\t'))
				picked.erase(picked.begin());
			while (!picked.empty() && (picked.back() == ' ' || picked.back() == '\t' ||
			                            picked.back() == '\r' || picked.back() == '\n'))
				picked.pop_back();

			bool path_ok = !picked.empty() && std::filesystem::exists(picked) &&
				std::filesystem::is_regular_file(picked);
			if (path_ok) {
				initial_analysis::accept_local_pdb_prompt(picked);
				closing = true;
				pending = true;
			} else {
				std::string seed = module_name;
				auto dot = seed.rfind('.');
				if (dot != std::string::npos) seed = seed.substr(0, dot);
				if (!seed.empty()) seed += ".pdb";
				std::string browsed = detail::browse_for_pdb_dialog(g_hwnd, seed);
				if (!browsed.empty()) {
					initial_analysis::accept_local_pdb_prompt(browsed);
					closing = true;
					pending = true;
				}
			}
		}
		if (skip_clicked && !closing) {
			initial_analysis::decline_local_pdb_prompt();
			closing = true;
			pending = true;
		}
	}

	ImGui::End();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
}

inline void render_frame()
{
	render_overlay();
	render_modal();
	render_local_pdb_modal();
}

}
