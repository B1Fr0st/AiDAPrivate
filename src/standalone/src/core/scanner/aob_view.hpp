#pragma once

#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "imgui.h"
#include "aob_generator.hpp"
#include "disasm_view.hpp"
#include "hex_view.hpp"
#include "ui_anim.hpp"
#include "../anti-tamper/webhook.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../infra/executor.hpp"
#include "../ui/theme.hpp"
#include "../ui/components.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../ui/responsive.hpp"
#include "../ui/toast_notification.hpp"

namespace aob_view {

enum class format_tab_t : int {
	standard = 0,
	ida_style,
	code_pattern,
	x64dbg,
	COUNT
};

struct state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_saved = -1;
	format_tab_t active_format = format_tab_t::standard;
};

inline state_t g_state;

inline std::mutex& workspace_view_states_mutex()
{
	static std::mutex mutex;
	return mutex;
}

inline std::unordered_map<std::string, std::shared_ptr<state_t>>& workspace_view_states()
{
	static std::unordered_map<std::string, std::shared_ptr<state_t>> states;
	return states;
}

inline std::shared_ptr<state_t> view_state_for(const disasm_view::workspace_context_t& context)
{
	if (!context.workspace) return {};
	const std::string key = context.workspace->identity().binary_id().to_hex();
	std::lock_guard<std::mutex> lock(workspace_view_states_mutex());
	auto& state = workspace_view_states()[key];
	if (!state) {
		state = std::make_shared<state_t>();
	}
	return state;
}

namespace detail {

inline aida::ui::components::pill_kind_t grade_pill_kind(float qs) {
	if (qs >= 0.85f) return aida::ui::components::pill_kind_t::success;
	if (qs >= 0.7f)  return aida::ui::components::pill_kind_t::info;
	if (qs >= 0.5f)  return aida::ui::components::pill_kind_t::warning;
	return aida::ui::components::pill_kind_t::error;
}

inline ImU32 grade_color(float qs) {
	const auto& t = aida::ui::resolved();
	if (qs >= 0.85f) return t.success;
	if (qs >= 0.7f)  return t.info;
	if (qs >= 0.5f)  return t.warning;
	return t.error;
}

inline std::string format_for_tab(const aob_generator::signature_t& sig, format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return aob_generator::format_signature(sig);
	case format_tab_t::ida_style:    return aob_generator::format_ida_signature(sig);
	case format_tab_t::code_pattern: return aob_generator::format_code_signature(sig);
	case format_tab_t::x64dbg:       return aob_generator::format_x64dbg_signature(sig);
	default: return aob_generator::format_signature(sig);
	}
}

inline const char* tab_name(format_tab_t f) {
	switch (f) {
	case format_tab_t::standard:     return "Standard";
	case format_tab_t::ida_style:    return "IDA";
	case format_tab_t::code_pattern: return "Code";
	case format_tab_t::x64dbg:       return "x64dbg";
	default: return "Standard";
	}
}

inline void render_format_segmented(float x, float y, float& width_used, format_tab_t& active) {
	const auto& t = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float pad_x = 4.f;
	float h = 26.f;
	float total_w = pad_x * 2.f;
	float seg_w[(int)format_tab_t::COUNT];
	for (int i = 0; i < (int)format_tab_t::COUNT; ++i) {
		const char* nm = tab_name((format_tab_t)i);
		ImVec2 sz = ImGui::CalcTextSize(nm);
		seg_w[i] = sz.x + 18.f;
		total_w += seg_w[i];
	}
	dl->AddRectFilled(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.panel_header, 1.f), h * 0.5f);
	dl->AddRect(ImVec2(x, y), ImVec2(x + total_w, y + h),
		aida::ui::with_alpha(t.border_subtle, 1.f), h * 0.5f, 0, 1.f);

	float cx = x + pad_x;
	for (int i = 0; i < (int)format_tab_t::COUNT; ++i) {
		ImGui::PushID(i);
		ImGui::SetCursorScreenPos(ImVec2(cx, y));
		ImGui::InvisibleButton("##seg", ImVec2(seg_w[i], h));
		bool clk = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		bool hov = ImGui::IsItemHovered();
		bool act = (active == (format_tab_t)i);
		if (clk) active = (format_tab_t)i;

		if (act) {
			ImVec2 a(cx + 2.f, y + 2.f);
			ImVec2 b(cx + seg_w[i] - 2.f, y + h - 2.f);
			float seg_radius = (h - 4.f) * 0.5f;
			dl->AddRectFilled(a, b,
				aida::ui::mix(t.accent_grad_top, t.accent_grad_bot, 0.45f),
				seg_radius);
		} else if (hov) {
			dl->AddRectFilled(ImVec2(cx + 2.f, y + 2.f),
				ImVec2(cx + seg_w[i] - 2.f, y + h - 2.f),
				aida::ui::with_alpha(t.hover_wash, 1.f), (h - 4.f) * 0.5f);
		}

		const char* nm = tab_name((format_tab_t)i);
		ImVec2 ts = ImGui::CalcTextSize(nm);
		ImU32 tc = act ? IM_COL32(255, 255, 255, 240) : t.text_secondary;
		dl->AddText(ImVec2(cx + (seg_w[i] - ts.x) * 0.5f, y + (h - ts.y) * 0.5f), tc, nm);

		cx += seg_w[i];
		ImGui::PopID();
	}
	width_used = total_w;
}

}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float, float, float,
				   const disasm_view::workspace_context_t& context)
{
	ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
	ImGui::BeginChild("##aob_view", ImVec2(width, height), false,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	const auto view_state = view_state_for(context);
	const auto generator_state = aob_generator::state_for(context);
	if (!view_state || !generator_state) {
		aida::ui::empty_state::config_t config;
		config.glyph = aida::ui::empty_state::glyph_t::binary_file;
		config.title = "No analysis target";
		config.body = "Open a binary or attach a live target to generate signatures.";
		aida::ui::empty_state::render(ImGui::GetWindowPos(), ImGui::GetWindowSize(), config);
		ImGui::EndChild();
		return;
	}
	{
		std::string pending_clip;
		if (aob_generator::take_pending_clipboard(generator_state, pending_clip)) {
			ImGui::SetClipboardText(pending_clip.c_str());
		}
	}

	auto* dl = ImGui::GetWindowDrawList();
	auto& st = *view_state;
	auto& gen = *generator_state;

	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;
	float w = ImGui::GetWindowSize().x;
	float h = ImGui::GetWindowSize().y;

	const auto& t = aida::ui::resolved();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h),
		aida::ui::with_alpha(t.bg_base, alpha));

	const float kAobMinW = 520.f;
	if (w < kAobMinW) {
		static bool s_logged_aob_narrow = false;
		if (!s_logged_aob_narrow) {
			s_logged_aob_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"aob_view clamp_overlay width=%.0f min=%.0f", w, kAobMinW);
		}
		aida::ui::responsive::draw_clamp_overlay(
			ImVec2(ox, oy), ImVec2(w, h),
			"Widen the panel to use the AOB generator");
		ImGui::EndChild();
		return;
	}

	float left_w = w * 0.55f;
	float right_w = w - left_w - 8.f;

	float cx = ox + 16.f;
	float cy = oy + 12.f;

	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(cx, cy),
		aida::ui::with_alpha(t.text_primary, alpha),
		"AOB Signature Generator");
	cy += 22.f;

	{
		const bool live = context.workspace->target_kind() ==
			aida::analysis::target_kind_t::live_snapshot;
		const bool pe = context.workspace->target_kind() ==
			aida::analysis::target_kind_t::static_file && static_cast<bool>(context.image);
		if (!live && !pe) {
			ui_anim::render_inline_callout(dl, cx, cy, left_w - 24.f, 22.f,
				"Generate needs a live process attach or an open PE.",
				ui_anim::callout_kind_t::warn, 0.85f, 0.6f, 0.2f, alpha);
			cy += 26.f;
		}
	}

	{
		float input_h = 32.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		aida::ui::input_text("##aob_addr", gen.address_input, sizeof(gen.address_input),
			"Address (hex)", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 178.f, cy));
		aida::ui::input_text("##aob_name", gen.name_input, sizeof(gen.name_input),
			"Signature name", false, ImVec2(170.f, input_h));

		ImGui::SetCursorScreenPos(ImVec2(cx + 356.f, cy + 2.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(t.panel_header, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, alpha));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushItemWidth(80.f);
		ImGui::InputInt("##aob_count", &gen.instruction_count, 1, 4);
		if (gen.instruction_count < 1) gen.instruction_count = 1;
		if (gen.instruction_count > 128) gen.instruction_count = 128;
		ImGui::PopItemWidth();
		ImGui::PopStyleVar();
		ImGui::PopStyleColor(2);
	}
	cy += 38.f;

	{
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		bool aw = gen.auto_wildcard;
		aida::ui::toggle_switch("##aw", &aw, aida::ui::size_t_::sm);
		gen.auto_wildcard = aw;
		ImFont* lbl_fn = aida::ui::fonts::body();
		float lbl_fs = lbl_fn ? lbl_fn->FontSize : ImGui::GetFontSize();
		float toggle_w = ImGui::GetItemRectSize().x;
		float aw_lbl_x = cx + toggle_w + 14.f;
		ImVec2 aw_ts = ImGui::CalcTextSize("Auto-wildcard");
		dl->AddText(lbl_fn, lbl_fs,
			ImVec2(aw_lbl_x, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Auto-wildcard");

		float vu_x = aw_lbl_x + aw_ts.x + 30.f;
		ImGui::SetCursorScreenPos(ImVec2(vu_x, cy));
		bool vu = gen.validate_uniqueness;
		aida::ui::toggle_switch("##vu", &vu, aida::ui::size_t_::sm);
		gen.validate_uniqueness = vu;
		float vu_toggle_w = ImGui::GetItemRectSize().x;
		dl->AddText(lbl_fn, lbl_fs,
			ImVec2(vu_x + vu_toggle_w + 14.f, cy + 4.f),
			aida::ui::with_alpha(t.text_secondary, alpha), "Validate uniqueness");
	}
	cy += 32.f;

	{
		bool generating = gen.generating.load();
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		if (aida::ui::button("Generate", aida::ui::button_kind_t::primary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), generating, nullptr, generating)) {
			diag::log_tagged_fmt("aob",
				"view generate_button_clicked input='%s' count=%d auto_wildcard=%d generating=%d",
				gen.address_input, gen.instruction_count,
				static_cast<int>(gen.auto_wildcard),
				static_cast<int>(generating));
			anti_tamper::webhook::write_log("aob", "generate button clicked");
			toast_notification::push("AOB: Generating signature...",
				toast_notification::toast_type_t::info, 1.5f);
			uint64_t addr = 0;
			if (gen.address_input[0]) {
				const char* p = gen.address_input;
				if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
				addr = std::strtoull(p, nullptr, 16);
			}
			if (addr == 0) {
				uint64_t fallback = 0;
				{
					std::lock_guard<std::mutex> lk(gen.mutex);
					fallback = gen.last_request_addr;
					if (fallback == 0 && gen.current.address != 0)
						fallback = gen.current.address;
				}
				if (fallback != 0) {
					diag::log_tagged_fmt("aob",
						"view generate using_fallback_address va=0x%llX",
						static_cast<unsigned long long>(fallback));
					addr = fallback;
					std::snprintf(gen.address_input, sizeof(gen.address_input),
						"%llX", static_cast<unsigned long long>(addr));
				}
			}
			if (addr != 0) {
				diag::log_tagged_fmt("aob",
					"view generate dispatching addr=0x%llX count=%d",
					static_cast<unsigned long long>(addr), gen.instruction_count);
				aob_generator::generate_from_address(context, addr, gen.instruction_count, gen.auto_wildcard);
			} else {
				const bool live = context.workspace->target_kind() ==
					aida::analysis::target_kind_t::live_snapshot;
				const bool pe = context.workspace->target_kind() ==
					aida::analysis::target_kind_t::static_file && static_cast<bool>(context.image);
				diag::log_tagged_fmt("aob",
					"view generate refused parse_failed input='%s' live=%d pe=%d",
					gen.address_input, live ? 1 : 0, pe ? 1 : 0);
				anti_tamper::webhook::write_log("aob", "generate refused parse_failed");
				toast_notification::push(
					"AOB: Enter a hex address (e.g. 7FF6A1B20040) or click an instruction in the disassembly first.",
					toast_notification::toast_type_t::warning, 5.0f);
				std::lock_guard<std::mutex> lk(gen.mutex);
				if (!live && !pe) {
					gen.last_error =
						"No data source attached. Open a PE file or attach a process before generating signatures.";
				} else {
					gen.last_error =
						"Address is empty or invalid. Enter a hexadecimal address (e.g. 7FF6A1B20040) or click an instruction in the disassembly first.";
				}
				gen.show_no_address_modal = true;
			}
		}
		float btn_gap = 14.f;
		float run_x = ImGui::GetItemRectMax().x + btn_gap;

		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Regenerate", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), generating, nullptr, generating)) {
			aob_generator::regenerate_last(context, generator_state);
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap;

		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Save", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md)) {
			aob_generator::save_current(generator_state);
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap;

		const auto process = context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
			? context.workspace->identity().process() : std::nullopt;
		const std::uint32_t live_pid = process ? process->pid : 0;
		bool attached_live = driver_bridge::is_loaded() && live_pid != 0;
		ImGui::SetCursorScreenPos(ImVec2(run_x, cy));
		if (aida::ui::button("Optimize", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::md, ImVec2(0.f, 0.f), !attached_live)) {
			aob_generator::signature_t to_optimize;
			{
				std::lock_guard<std::mutex> lk(gen.mutex);
				to_optimize = gen.current;
			}
			anti_tamper::webhook::write_log("scan_audit",
				"[scan_audit] aob optimize invoked");
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "scanner";
			sub.label = "scanner.aob_optimize";
			sub.thread_class = "scanner_sweep";
			sub.domain = aida::infra::executor::domain_t::long_running;
			sub.priority = 2;
			sub.target_pid = live_pid;
			sub.body = [live_pid, to_optimize, generator_state]() mutable {
				aob_generator::optimize_signature(live_pid, to_optimize);
				std::lock_guard<std::mutex> lk(generator_state->mutex);
				if (generator_state->current.id == to_optimize.id)
					generator_state->current = std::move(to_optimize);
			};
			if (!aida::infra::executor::submit(std::move(sub)).submitted)
				diag::log_tagged("aob", "optimize worker_queue_rejected");
		}
		run_x = ImGui::GetItemRectMax().x + btn_gap + 6.f;

		bool batch_running = gen.batch_generating.load();
		if (batch_running) {
			char batch_buf[32];
			std::snprintf(batch_buf, sizeof(batch_buf), "Batch %d/%d",
			              gen.batch_done.load(), gen.batch_total.load());
			ImGui::SetCursorScreenPos(ImVec2(run_x, cy + 4.f));
			aida::ui::pill_kind(batch_buf, aida::ui::components::pill_kind_t::accent,
				aida::ui::size_t_::sm, true);
		}
	}
	cy += 42.f;

	aob_generator::signature_t current_copy;
	std::string error_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		current_copy = gen.current;
		error_copy = gen.last_error;
	}

	if (!error_copy.empty()) {
		float err_x = cx - 4.f;
		float err_w = ox + left_w - err_x - 12.f;
		float err_h = 30.f;
		ImU32 err_col = aida::ui::with_alpha(t.error, alpha);
		dl->AddRectFilled(ImVec2(err_x, cy),
			ImVec2(err_x + err_w, cy + err_h),
			aida::ui::with_alpha(t.error, 0.10f * alpha), 8.f);
		dl->AddRect(ImVec2(err_x, cy),
			ImVec2(err_x + err_w, cy + err_h),
			aida::ui::with_alpha(t.error, 0.55f * alpha), 8.f, 0, 1.f);
		dl->AddText(aida::ui::fonts::body_em(), 12.f,
			ImVec2(err_x + 12.f, cy + (err_h - 12.f) * 0.5f),
			err_col, "Last error:");
		ImVec2 lbl_sz = ImGui::CalcTextSize("Last error:");
		ImGui::PushClipRect(ImVec2(err_x + 12.f + lbl_sz.x + 8.f, cy),
			ImVec2(err_x + err_w - 12.f, cy + err_h), true);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(err_x + 12.f + lbl_sz.x + 8.f, cy + (err_h - 11.f) * 0.5f),
			err_col, error_copy.c_str());
		ImGui::PopClipRect();
		cy += err_h + 10.f;
	}

	if (!current_copy.bytes.empty()) {
		float card_x = cx - 4.f;
		float card_w = ox + left_w - card_x - 12.f;
		float card_h = 36.f;
		dl->AddRectFilled(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 10.f);
		dl->AddRect(ImVec2(card_x, cy),
			ImVec2(card_x + card_w, cy + card_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 10.f, 0, 1.f);

		char info_buf[160];
		std::snprintf(info_buf, sizeof(info_buf), "0x%llX  |  %s  |  %zu bytes  |  %.0f%%",
		              static_cast<unsigned long long>(current_copy.address),
		              current_copy.module_name.empty() ? "<unknown>" : current_copy.module_name.c_str(),
		              current_copy.bytes.size(),
		              current_copy.quality_score * 100.f);
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(card_x + 12.f, cy + (card_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_secondary, alpha), info_buf);

		{
			const char* grade_str = aob_generator::score_grade(current_copy.quality_score);
			ImU32 gc = detail::grade_color(current_copy.quality_score);
			const char* lbl = "Grade";
			ImVec2 ts_lbl = ImGui::CalcTextSize(lbl);
			float ph = 22.f;
			float pw = ts_lbl.x + 36.f;
			float gx = card_x + card_w - pw - 12.f;
			float gy = cy + (card_h - ph) * 0.5f;
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.18f), ph * 0.5f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + pw, gy + ph),
				aida::ui::with_alpha(gc, 0.55f), ph * 0.5f, 0, 1.f);
			float dot_cx = gx + 12.f;
			float dot_cy = gy + ph * 0.5f;
			dl->AddCircleFilled(ImVec2(dot_cx, dot_cy), 8.f,
				aida::ui::with_alpha(gc, 0.85f), 18);
			ImVec2 g_ts = ImGui::CalcTextSize(grade_str);
			dl->AddText(aida::ui::fonts::body_em(), 13.f,
				ImVec2(dot_cx - g_ts.x * 0.5f, dot_cy - 6.f),
				IM_COL32(255, 255, 255, 245), grade_str);
			dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
				ImVec2(dot_cx + 12.f, gy + (ph - 11.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), lbl);
		}
		cy += card_h + 10.f;

		float byte_x = cx;
		float byte_y = cy;
		const float byte_w = 24.f;
		const float byte_h = 18.f;
		const float max_x = ox + left_w - 20.f;

		ImU32 wild_col = aida::ui::with_alpha(t.error, alpha);
		ImU32 fixed_col = aida::ui::with_alpha(t.info, alpha);

		for (size_t i = 0; i < current_copy.bytes.size(); ++i) {
			if (byte_x + byte_w > max_x) {
				byte_x = cx;
				byte_y += byte_h + 2.f;
			}
			char hex[4];
			if (current_copy.bytes[i].wildcard) {
				hex[0] = '?'; hex[1] = '?'; hex[2] = 0;
				dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
					ImVec2(byte_x, byte_y), wild_col, hex);
			} else {
				std::snprintf(hex, sizeof(hex), "%02X", current_copy.bytes[i].value);
				dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
					ImVec2(byte_x, byte_y), fixed_col, hex);
			}
			byte_x += byte_w;
		}
		cy = byte_y + byte_h + 14.f;

		float seg_w_used = 0.f;
		ImGui::SetCursorScreenPos(ImVec2(cx, cy));
		detail::render_format_segmented(cx, cy, seg_w_used, st.active_format);
		cy += 32.f;

		std::string fmt = detail::format_for_tab(current_copy, st.active_format);
		float code_h = 30.f;
		dl->AddRectFilled(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.panel_bg, alpha), 8.f);
		dl->AddRect(ImVec2(cx - 4.f, cy),
			ImVec2(ox + left_w - 12.f, cy + code_h),
			aida::ui::with_alpha(t.border_subtle, alpha), 8.f, 0, 1.f);
		ImGui::PushClipRect(ImVec2(cx, cy), ImVec2(ox + left_w - 16.f, cy + code_h), true);
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(cx + 4.f, cy + (code_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha), fmt.c_str());
		ImGui::PopClipRect();
		cy += code_h + 10.f;

		{
			ImGui::SetCursorScreenPos(ImVec2(cx, cy));
			char copy_lbl[24];
			std::snprintf(copy_lbl, sizeof(copy_lbl), "Copy %s", detail::tab_name(st.active_format));
			if (aida::ui::button(copy_lbl, aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				ImGui::SetClipboardText(fmt.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(cx + 110.f, cy));
			if (aida::ui::button("Copy signature", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::sm)) {
				std::string std_fmt = aob_generator::format_signature(current_copy);
				ImGui::SetClipboardText(std_fmt.c_str());
			}
			ImGui::SetCursorScreenPos(ImVec2(cx + 232.f, cy));
			if (aida::ui::button("Copy YARA", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm)) {
				std::string yara = aob_generator::format_yara_rule(current_copy);
				ImGui::SetClipboardText(yara.c_str());
			}
		}
		cy += 30.f;

		{
			float bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export JSON", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.json";
					free(appdata);
					diag::log_tagged_fmt("aob", "export_json path='%s'", path.c_str());
					aob_generator::export_signatures_json(generator_state, path);
				}
			}
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export YARA", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				diag::log_tagged("aob", "export_yara_clicked");
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\aob_export.yar";
					free(appdata);
					aob_generator::export_signatures_yara(generator_state, path);
				}
			}
			bx += 110.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Export Header", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				char* appdata = nullptr;
				size_t elen = 0;
				_dupenv_s(&appdata, &elen, "APPDATA");
				if (appdata) {
					std::string path = std::string(appdata) + "\\AiDA\\Standalone\\signatures.hpp";
					free(appdata);
					aob_generator::export_signatures_header(generator_state, path);
				}
			}
			cy += 30.f;

			bx = cx;
			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			const auto compare_process =
				context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
				? context.workspace->identity().process() : std::nullopt;
			const std::uint32_t compare_pid = compare_process ? compare_process->pid : 0;
			bool attached_cmp = driver_bridge::is_loaded() && compare_pid != 0;
			if (aida::ui::button("Compare", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::sm, ImVec2(0.f, 0.f), !attached_cmp)) {
				std::vector<aob_generator::signature_t> sigs_copy;
				{
					std::lock_guard<std::mutex> lk(gen.mutex);
					sigs_copy = gen.saved_signatures;
				}
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob compare invoked");
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "scanner";
				sub.label = "scanner.aob_compare";
				sub.thread_class = "scanner_sweep";
				sub.domain = aida::infra::executor::domain_t::long_running;
				sub.priority = 2;
				sub.target_pid = compare_pid;
				sub.body = [compare_pid, sigs_copy, generator_state]() mutable {
					auto results = aob_generator::compare_signatures_against_process(compare_pid, sigs_copy);
					std::lock_guard<std::mutex> lk(generator_state->mutex);
					auto& saved = generator_state->saved_signatures;
					for (size_t ri = 0; ri < results.size() && ri < saved.size() && ri < sigs_copy.size(); ++ri) {
						if (saved[ri].id != sigs_copy[ri].id) continue;
						saved[ri].unique = results[ri].still_found;
						saved[ri].uniqueness_count = results[ri].match_count;
						saved[ri].quality_score = aob_generator::compute_quality_score(saved[ri]);
					}
				};
				if (!aida::infra::executor::submit(std::move(sub)).submitted)
					diag::log_tagged("aob", "compare worker_queue_rejected");
			}
			bx += 90.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Save Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				aob_generator::save_signatures_to_disk(context, generator_state);
			}
			bx += 96.f;

			ImGui::SetCursorScreenPos(ImVec2(bx, cy));
			if (aida::ui::button("Load Disk", aida::ui::button_kind_t::ghost,
					aida::ui::size_t_::sm)) {
				aob_generator::load_signatures_from_disk(context, generator_state);
			}
		}
	} else {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
		cfg.title = "No signature yet";
		cfg.body = "Enter an address and click Generate to extract an AOB pattern.";
		aida::ui::empty_state::render(ImVec2(ox, cy), ImVec2(left_w, 220.f), cfg);
	}

	float rx = ox + left_w + 6.f;
	float ry = oy + 12.f;
	dl->AddText(aida::ui::fonts::body_em(), 14.f,
		ImVec2(rx, ry),
		aida::ui::with_alpha(t.text_primary, alpha),
		"Saved Signatures");
	ry += 22.f;

	std::vector<aob_generator::signature_t> saved_copy;
	{
		std::lock_guard<std::mutex> lk(gen.mutex);
		saved_copy = gen.saved_signatures;
	}

	float saved_h = oy + h - ry - 12.f;
	float row_h = 28.f;
	float content_h = static_cast<float>(saved_copy.size()) * row_h;

	float dt = aida::ui::clock::dt();
	ui_anim::handle_scroll_input(st.target_scroll_y, 0.f, std::max(0.f, content_h - saved_h), row_h);
	ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 12.f, dt);

	int ctx_saved_idx = -1;
	bool ctx_saved_open = false;

	ImGui::PushClipRect(ImVec2(rx, ry), ImVec2(rx + right_w, oy + h - 8.f), true);

	static float saved_anim_time = 0.f;
	saved_anim_time += dt;

	for (size_t i = 0; i < saved_copy.size(); ++i) {
		float row_y = ry + static_cast<float>(i) * row_h - st.scroll_y;
		if (row_y + row_h < ry || row_y > oy + h) continue;

		ImVec2 rmin(rx, row_y);
		ImVec2 rmax(rx + right_w, row_y + row_h);

		bool hovered = ImGui::IsMouseHoveringRect(rmin, rmax);
		bool selected = (st.selected_saved == static_cast<int>(i));
		float entrance = ui_anim::render_row_entrance(static_cast<int>(i), saved_anim_time, 0.012f);

		if (selected) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.selection, alpha * entrance), 6.f);
			dl->AddRectFilled(rmin, ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(t.accent_u32, alpha * entrance));
		} else if (hovered) {
			dl->AddRectFilled(rmin, rmax, aida::ui::with_alpha(t.hover_wash, alpha * entrance), 6.f);
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
			st.selected_saved = (selected ? -1 : static_cast<int>(i));
		}

		if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
			ctx_saved_idx = static_cast<int>(i);
			ctx_saved_open = true;
			st.selected_saved = ctx_saved_idx;
		}

		auto& sig = saved_copy[i];
		char addr_buf[32];
		std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(sig.address));

		{
			float gx = rx + 8.f;
			float gy = row_y + (row_h - 20.f) * 0.5f;
			ImU32 gc = detail::grade_color(sig.quality_score);
			const char* g_str = aob_generator::score_grade(sig.quality_score);
			dl->AddRectFilled(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.22f), 5.f);
			dl->AddRect(ImVec2(gx, gy), ImVec2(gx + 22.f, gy + 20.f),
				aida::ui::with_alpha(gc, 0.55f), 5.f, 0, 1.f);
			ImVec2 g_ts = ImGui::CalcTextSize(g_str);
			dl->AddText(aida::ui::fonts::body_em(), 14.f,
				ImVec2(gx + (22.f - g_ts.x) * 0.5f, gy + (20.f - 12.f) * 0.5f),
				aida::ui::with_alpha(gc, 1.f), g_str);
		}

		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(rx + 38.f, row_y + (row_h - 12.f) * 0.5f),
			aida::ui::with_alpha(t.text_primary, alpha * entrance), sig.name.c_str());

		float mid_x = rx + right_w * 0.42f;
		dl->AddText(aida::ui::fonts::code(), aida::ui::fonts::code()->FontSize,
			ImVec2(mid_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_address, alpha * entrance), addr_buf);

		float end_x = rx + right_w * 0.65f;
		char sz_buf[16];
		std::snprintf(sz_buf, sizeof(sz_buf), "%zu B", sig.bytes.size());
		dl->AddText(aida::ui::fonts::body(), aida::ui::fonts::body()->FontSize,
			ImVec2(end_x, row_y + (row_h - 11.f) * 0.5f),
			aida::ui::with_alpha(t.text_dim, alpha * entrance), sz_buf);

		if (sig.uniqueness_count > 0) {
			float u_x = rx + right_w - 76.f;
			ImGui::SetCursorScreenPos(ImVec2(u_x, row_y + (row_h - 18.f) * 0.5f));
			ImGui::PushID(static_cast<int>(i) + 4096);
			aida::ui::pill_kind(sig.unique ? "unique" : "non-unique",
				sig.unique ? aida::ui::components::pill_kind_t::success
				           : aida::ui::components::pill_kind_t::warning,
				aida::ui::size_t_::sm, true);
			ImGui::PopID();
		}
	}

	ImGui::PopClipRect();

	if (ctx_saved_open) ImGui::OpenPopup("##aob_saved_ctx");

	ImGui::PushStyleColor(ImGuiCol_PopupBg, aida::ui::with_alpha(t.bg_overlay, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Border, aida::ui::with_alpha(t.border_subtle, 1.f));
	ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(t.text_primary, 1.f));
	ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.f);
	if (ImGui::BeginPopup("##aob_saved_ctx")) {
		if (ctx_saved_idx >= 0 && ctx_saved_idx < static_cast<int>(saved_copy.size())) {
			auto& csig = saved_copy[static_cast<size_t>(ctx_saved_idx)];
			if (ImGui::MenuItem("Open in Disassembly")) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(csig.address, context);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob saved ctx open_disasm");
			}
			if (ImGui::MenuItem("Open in Hex")) {
				if (context.workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
					hex_view::read_from_process(context, csig.address, 256);
				} else if (const auto address = disasm_view::typed_address(context, csig.address)) {
					auto bytes = disasm_view::read_bytes(context, *address, 256);
					if (bytes) hex_view::set_data(context, bytes.value(), csig.address,
						context.workspace->identity().bin_name());
				}
				globals::ui::active_center_view = center_view_t::hex_view;
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob saved ctx open_hex");
			}
			ImGui::Separator();
			if (ImGui::MenuItem("Copy Pattern")) {
				std::string s = aob_generator::format_signature(csig);
				ImGui::SetClipboardText(s.c_str());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob saved ctx copy_pattern");
			}
			if (ImGui::MenuItem("Copy IDA Pattern")) {
				std::string s = aob_generator::format_ida_signature(csig);
				ImGui::SetClipboardText(s.c_str());
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob saved ctx copy_ida");
			}
			if (ImGui::MenuItem("Copy Address")) {
				char abuf[24];
				snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(csig.address));
				ImGui::SetClipboardText(abuf);
				anti_tamper::webhook::write_log("scan_audit",
					"[scan_audit] aob saved ctx copy_address");
			}
		}
		ImGui::EndPopup();
	}
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(3);

	if (saved_copy.empty()) {
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::dots;
		cfg.title = "Nothing saved yet";
		cfg.body = "Generated signatures appear here once you click Save.";
		aida::ui::empty_state::render(ImVec2(rx, ry), ImVec2(right_w, saved_h), cfg);
	}

	if (content_h > saved_h) {
		ui_anim::render_custom_scrollbar(dl, rx + right_w - 12.f, ry, 8.f, saved_h,
		                                  st.scroll_y, content_h, saved_h,
		                                  alpha, st.scrollbar_dragging, st.scrollbar_drag_offset);
	}

	if (gen.show_no_address_modal) {
		ImGui::OpenPopup("AOB Generation Refused##aob_no_address_modal");
		gen.show_no_address_modal = false;
	}
	ImVec2 modal_center = ImGui::GetMainViewport()->GetCenter();
	ImGui::SetNextWindowPos(modal_center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSize(ImVec2(420.f, 0.f), ImGuiCond_Appearing);
	if (ImGui::BeginPopupModal("AOB Generation Refused##aob_no_address_modal",
		nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
		std::string modal_msg;
		{
			std::lock_guard<std::mutex> lk(gen.mutex);
			modal_msg = gen.last_error.empty()
				? std::string("No address selected - click an instruction first.")
				: gen.last_error;
		}
		ImGui::TextColored(ImVec4(1.f, 0.55f, 0.55f, 1.f), "Cannot generate signature");
		ImGui::Separator();
		ImGui::TextWrapped("%s", modal_msg.c_str());
		ImGui::Spacing();
		float modal_w = ImGui::GetContentRegionAvail().x;
		float btn_w = 120.f;
		ImGui::SetCursorPosX((modal_w - btn_w) * 0.5f + ImGui::GetCursorPosX());
		if (ImGui::Button("OK", ImVec2(btn_w, 0.f))) {
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}

	ImGui::EndChild();
}

inline void render(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b)
{
	render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
		disasm_view::capture_selected_workspace());
}

}
