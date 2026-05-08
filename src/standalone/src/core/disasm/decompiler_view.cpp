#include "decompiler_view.hpp"
#include "decompiler_engine.hpp"
#include "syntax_highlight.hpp"
#include "ui_anim.hpp"
#include "disasm_view.hpp"
#include "../helpers/globals.h"
#include "../ui/theme.hpp"
#include "../ui/motion.hpp"
#include "../ui/clock.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/fonts.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

extern DisasmState g_disasm;

namespace decompiler_view {

namespace {

struct line_info_t {
	std::string text;
	int         number = 0;
};

char batch_input[2048] = {};
bool show_batch_panel = false;

std::vector<line_info_t> split_lines(const std::string& text)
{
	std::vector<line_info_t> result;
	size_t start = 0;
	int num = 1;
	while (start <= text.size()) {
		size_t end = text.find('\n', start);
		if (end == std::string::npos) end = text.size();
		line_info_t li;
		li.text = text.substr(start, end - start);
		li.number = num++;
		result.push_back(std::move(li));
		start = end + 1;
		if (end == text.size()) break;
	}
	return result;
}

ImU32 token_color(syntax::token_type t, float alpha)
{
	const auto& tk = aida::ui::resolved();
	switch (t) {
	case syntax::token_type::keyword:       return aida::ui::with_alpha(tk.syn_keyword, alpha);
	case syntax::token_type::type_name:     return aida::ui::with_alpha(tk.syn_type, alpha);
	case syntax::token_type::string_lit:    return aida::ui::with_alpha(tk.syn_string, alpha);
	case syntax::token_type::number:        return aida::ui::with_alpha(tk.syn_number, alpha);
	case syntax::token_type::comment_line:  return aida::ui::with_alpha(tk.syn_comment, alpha);
	case syntax::token_type::comment_block: return aida::ui::with_alpha(tk.syn_comment, alpha);
	case syntax::token_type::preprocessor:  return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case syntax::token_type::operator_sym:  return aida::ui::with_alpha(tk.syn_operator, alpha);
	case syntax::token_type::function_call: return aida::ui::with_alpha(tk.syn_function, alpha);
	case syntax::token_type::boolean_lit:   return aida::ui::with_alpha(tk.syn_number, alpha);
	case syntax::token_type::punctuation:   return aida::ui::with_alpha(tk.syn_operator, alpha * 0.85f);
	case syntax::token_type::register_name: return aida::ui::with_alpha(tk.syn_register, alpha);
	case syntax::token_type::decorator:     return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	case syntax::token_type::directive:     return aida::ui::with_alpha(tk.syn_preprocessor, alpha);
	default:                                return aida::ui::with_alpha(tk.syn_identifier, alpha);
	}
}

void copy_to_clipboard(const std::string& text)
{
#ifdef _WIN32
	if (OpenClipboard(nullptr)) {
		EmptyClipboard();
		HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
		if (hg) {
			memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
			GlobalUnlock(hg);
			SetClipboardData(CF_TEXT, hg);
		}
		CloseClipboard();
	}
#endif
}

bool scrollbar_dragging = false;
float scrollbar_drag_offset = 0.f;
size_t s_last_cache_size = 0;
aida::ui::flash_t s_cache_flash;
size_t s_last_pseudocode_len = 0;
float s_pseudocode_reveal = 1.f;
std::unordered_map<int, float> s_callee_hover;
std::unordered_map<int, float> s_history_hover;

bool s_section_func_open = true;
bool s_section_callees_open = true;
bool s_section_history_open = true;
float s_section_func_anim = 1.f;
float s_section_callees_anim = 1.f;
float s_section_history_anim = 1.f;

bool render_section_header(const char* label, bool* open, ImVec2 origin, float width, float arrow_anim)
{
	const auto& tk = aida::ui::resolved();
	ImDrawList* dl = ImGui::GetWindowDrawList();
	float h = 24.f;
	ImVec2 a = origin;
	ImVec2 b(origin.x + width, origin.y + h);

	ImGui::SetCursorScreenPos(a);
	ImGui::PushID(label);
	ImGui::InvisibleButton("##sec_h", ImVec2(width, h));
	bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
	bool hovered = ImGui::IsItemHovered();

	if (clicked && open) *open = !*open;

	if (hovered) {
		dl->AddRectFilled(a, b, aida::ui::with_alpha(tk.hover_wash, 1.f), 6.f);
	}

	float arrow_y = a.y + h * 0.5f;
	float arrow_x = a.x + 8.f;
	float ang = arrow_anim * 1.5707963f;
	float c = cosf(ang);
	float si = sinf(ang);
	ImVec2 p0(4.f, -3.f);
	ImVec2 p1(4.f, 3.f);
	ImVec2 p2(-2.f, 0.f);
	auto rot = [&](ImVec2 p) -> ImVec2 {
		return ImVec2(arrow_x + (p.x * c - p.y * si),
		              arrow_y + (p.x * si + p.y * c));
	};
	ImU32 arrow_col = hovered
		? aida::ui::with_alpha(tk.accent_u32, 1.f)
		: aida::ui::with_alpha(tk.text_secondary, 1.f);
	dl->AddTriangleFilled(rot(p0), rot(p1), rot(p2), arrow_col);

	dl->AddText(ImVec2(a.x + 24.f, a.y + (h - 13.f) * 0.5f),
	            aida::ui::with_alpha(tk.text_primary, 1.f), label);

	ImGui::PopID();
	ImGui::SetCursorScreenPos(ImVec2(a.x, a.y + h));
	return open && *open;
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	(void)accent_r; (void)accent_g; (void)accent_b;
	auto& st = decompiler_engine::g_state;
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();
	float ox = origin.x + pos_x;
	float oy = origin.y + pos_y;

	const auto& tk = aida::ui::resolved();
	const auto _ta = [alpha](ImU32 c) -> ImU32 { return aida::ui::with_alpha(c, alpha); };

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
	                  _ta(tk.bg_base));

	float toolbar_h = 40.f;
	float gutter_w = 48.f;
	float right_panel_w = 240.f;
	float line_h = 18.f;

	bool has_right_panel = (width > 640.f);
	float code_w = has_right_panel ? (width - right_panel_w) : width;
	float dt = aida::ui::clock::dt();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
	                  _ta(tk.panel_header));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + width, oy + toolbar_h),
	            aida::ui::with_alpha(tk.border_subtle, alpha));

	{
		std::lock_guard<std::mutex> lk(st.mutex);
		char title[256];
		if (st.current.function_addr) {
			snprintf(title, sizeof(title), "%s",
			         st.current.function_name.empty()
			             ? "Decompiler"
			             : st.current.function_name.c_str());
		} else {
			snprintf(title, sizeof(title), "Decompiler");
		}
		ImFont* th_font = aida::ui::fonts::body_em();
		dl->AddText(th_font, 14.f, ImVec2(ox + 14.f, oy + (toolbar_h - 14.f) * 0.5f),
		            aida::ui::with_alpha(tk.text_primary, alpha), title);

		float title_offset = ImGui::CalcTextSize(title).x + 14.f;

		if (st.current.function_addr) {
			char addr_buf[32];
			snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
			         static_cast<unsigned long long>(st.current.function_addr));
			dl->AddText(ImVec2(ox + 14.f + title_offset, oy + (toolbar_h - 12.f) * 0.5f + 1.f),
			            aida::ui::with_alpha(tk.text_address, alpha), addr_buf);
			title_offset += ImGui::CalcTextSize(addr_buf).x + 14.f;
		}

		aida::ui::components::pill_kind_t mode_kind = aida::ui::components::pill_kind_t::neutral;
		const char* mode_label = nullptr;
		switch (st.active_mode) {
		case decompiler_engine::decompile_mode_t::ai:
			mode_label = "AI";
			mode_kind = aida::ui::components::pill_kind_t::info;
			break;
		case decompiler_engine::decompile_mode_t::native_ghidra:
			mode_label = "Ghidra";
			mode_kind = aida::ui::components::pill_kind_t::success;
			break;
		case decompiler_engine::decompile_mode_t::hybrid:
			mode_label = "Hybrid";
			mode_kind = aida::ui::components::pill_kind_t::warning;
			break;
		}
		if (mode_label && st.current.function_addr) {
			ImGui::SetCursorScreenPos(ImVec2(ox + 14.f + title_offset, oy + (toolbar_h - 22.f) * 0.5f));
			aida::ui::components::pill_kind(mode_label, mode_kind,
			                                 aida::ui::components::size_t_::sm, false);
		}
	}

	{
		size_t cs = decompiler_engine::cache_size();
		if (cs != s_last_cache_size && cs > s_last_cache_size) s_cache_flash.trigger();
		s_last_cache_size = cs;
		s_cache_flash.tick(dt);
	}

	float btn_w_default = 78.f;
	(void)btn_w_default;
	float btn_pad = 6.f;
	float btn_h = 26.f;
	float btn_y = oy + (toolbar_h - btn_h) * 0.5f;
	float btn_x_right = ox + code_w - 10.f;

	auto place_button_right = [&](float w) -> ImVec2 {
		btn_x_right -= w + btn_pad;
		ImGui::SetCursorScreenPos(ImVec2(btn_x_right, btn_y));
		return ImVec2(btn_x_right, btn_y);
	};

	{
		float w = 60.f;
		place_button_right(w);
		if (aida::ui::components::button("Copy",
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			std::lock_guard<std::mutex> lk(st.mutex);
			std::string text = st.current.complete ? st.current.pseudocode : st.streaming_text;
			if (!text.empty()) copy_to_clipboard(text);
		}
	}

	if (st.decompiling.load()) {
		float w = 70.f;
		place_button_right(w);
		if (aida::ui::components::button("Cancel",
		    aida::ui::components::button_kind_t::destructive,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			decompiler_engine::cancel_decompile();
		}
	}

#ifdef __NT__
	{
		uint64_t deobf_addr = 0;
		if (!st.decompiling.load() && !st.emulating.load()) {
			std::lock_guard<std::mutex> lk(st.mutex);
			if (st.current.function_addr != 0)
				deobf_addr = st.current.function_addr;
		}
		if (deobf_addr != 0) {
			float w = 96.f;
			place_button_right(w);
			if (aida::ui::components::button("Deobfuscate",
			    aida::ui::components::button_kind_t::ghost,
			    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
				decompiler_engine::decompile_with_deobfuscation(deobf_addr, g_sa_settings);
			}
		}
	}
#endif

	if (st.history_pos > 0) {
		float w = 70.f;
		place_button_right(w);
		if (aida::ui::components::button("< Back",
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			decompiler_engine::navigate_back();
		}
	}

	if (st.history_pos + 1 < static_cast<int>(st.history.size())) {
		float w = 70.f;
		place_button_right(w);
		if (aida::ui::components::button("Fwd >",
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			decompiler_engine::navigate_forward();
		}
	}

	{
		size_t cs = decompiler_engine::cache_size();
		if (cs > 0) {
			char cache_lbl[32];
			snprintf(cache_lbl, sizeof(cache_lbl), "Cache %zu", cs);
			float w = 80.f;
			ImVec2 bp = place_button_right(w);
			float scale = 1.f + s_cache_flash.v * 0.12f;
			float bx_off = (w * (scale - 1.f)) * 0.5f;
			float by_off = (btn_h * (scale - 1.f)) * 0.5f;
			ImGui::SetCursorScreenPos(ImVec2(bp.x - bx_off, bp.y - by_off));
			if (aida::ui::components::button(cache_lbl,
			    aida::ui::components::button_kind_t::secondary,
			    aida::ui::components::size_t_::sm,
			    ImVec2(w * scale, btn_h * scale))) {
				decompiler_engine::clear_cache();
			}
		}
	}

	if (st.batch_running.load()) {
		char batch_lbl[48];
		snprintf(batch_lbl, sizeof(batch_lbl), "Batch %d/%d",
		         st.batch_done.load(), st.batch_total.load());
		float w = 110.f;
		place_button_right(w);
		aida::ui::components::button(batch_lbl,
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h),
		    true, nullptr, true);
	}

	{
		uint64_t sync_addr = 0;
		{
			std::lock_guard<std::mutex> lk(st.mutex);
			sync_addr = st.current.function_addr;
		}
		if (sync_addr != 0) {
			float w = 70.f;
			place_button_right(w);
			if (aida::ui::components::button("Disasm",
			    aida::ui::components::button_kind_t::ghost,
			    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(sync_addr, g_disasm);
			}
		}
	}

	if (!st.batch_running.load() && !st.decompiling.load()) {
		float w = 60.f;
		place_button_right(w);
		if (aida::ui::components::button("Batch",
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			show_batch_panel = !show_batch_panel;
		}
	}

	{
		float w = 64.f;
		place_button_right(w);
		if (aida::ui::components::button("Save$",
		    aida::ui::components::button_kind_t::ghost,
		    aida::ui::components::size_t_::sm, ImVec2(w, btn_h))) {
			decompiler_engine::detail::save_all_cache_to_disk();
		}
	}

	float code_top = oy + toolbar_h + 1.f;
	float code_h = height - toolbar_h - 1.f;

	if (show_batch_panel && !st.batch_running.load() && !st.decompiling.load()) {
		float batch_panel_h = 132.f;
		dl->AddRectFilled(ImVec2(ox, code_top), ImVec2(ox + code_w, code_top + batch_panel_h),
		                  _ta(tk.panel_header));
		dl->AddLine(ImVec2(ox, code_top + batch_panel_h),
		            ImVec2(ox + code_w, code_top + batch_panel_h),
		            aida::ui::with_alpha(tk.border_subtle, alpha));

		dl->AddText(aida::ui::fonts::body_em(), 13.f,
		            ImVec2(ox + 14.f, code_top + 8.f),
		            aida::ui::with_alpha(tk.text_primary, alpha),
		            "Batch Decompile");
		dl->AddText(aida::ui::fonts::caption(), 11.f,
		            ImVec2(ox + 14.f, code_top + 26.f),
		            aida::ui::with_alpha(tk.text_secondary, alpha),
		            "One hex address per line");

		ImGui::SetCursorScreenPos(ImVec2(ox + 14.f, code_top + 46.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(tk.panel_bg));
		ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(tk.border_subtle));
		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(tk.text_primary));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
		ImGui::PushItemWidth(code_w - 120.f);
		ImGui::InputTextMultiline("##batch_addrs", batch_input, sizeof(batch_input),
		                          ImVec2(code_w - 120.f, batch_panel_h - 56.f));
		ImGui::PopItemWidth();
		ImGui::PopStyleVar(2);
		ImGui::PopStyleColor(3);

		ImGui::SetCursorScreenPos(ImVec2(ox + code_w - 96.f, code_top + 46.f));
		if (aida::ui::components::button("Run",
		    aida::ui::components::button_kind_t::primary,
		    aida::ui::components::size_t_::md, ImVec2(80.f, 32.f))) {
			std::vector<uint64_t> addrs;
			std::string text = batch_input;
			size_t pos = 0;
			while (pos < text.size()) {
				size_t nl = text.find('\n', pos);
				if (nl == std::string::npos) nl = text.size();
				std::string line = text.substr(pos, nl - pos);
				pos = nl + 1;
				while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
				if (line.empty()) continue;
				uint64_t addr = std::strtoull(line.c_str(), nullptr, 16);
				if (addr != 0) addrs.push_back(addr);
			}
			if (!addrs.empty()) {
				decompiler_engine::batch_decompile(addrs);
				show_batch_panel = false;
			}
		}

		code_top += batch_panel_h;
		code_h -= batch_panel_h;
	}
	dl->PushClipRect(ImVec2(ox, code_top), ImVec2(ox + code_w, code_top + code_h), true);

	if ((st.decompiling.load() || st.emulating.load()) && !st.current.complete) {
		std::lock_guard<std::mutex> lk(st.mutex);
		std::string display_text = st.streaming_text;

		if (display_text.empty()) {
			float panel_w = std::min(440.f, code_w * 0.65f);
			float panel_h = 200.f;
			float px = ox + (code_w - panel_w) * 0.5f;
			float py = code_top + (code_h - panel_h) * 0.5f;
			ImVec2 a(px, py);
			ImVec2 b(px + panel_w, py + panel_h);
			aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 4, 0.30f * alpha);
			aida::ui::blur::render_glass_fill(dl, a, b, 12.f, alpha);
			aida::ui::blur::render_glass_border(dl, a, b, 12.f, alpha);

			if (st.emulating.load()) {
				float emu_prog = st.emulation_progress.load();
				char prog_msg[128];
				snprintf(prog_msg, sizeof(prog_msg), "Emulating (%.0f%%)", emu_prog * 100.f);
				dl->AddText(aida::ui::fonts::body_em(), 14.f,
				            ImVec2(px + 22.f, py + 22.f),
				            _ta(tk.text_primary), prog_msg);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 56.f),
				                                      panel_w - 44.f, 12.f);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 78.f),
				                                      (panel_w - 44.f) * 0.78f, 12.f);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 100.f),
				                                      (panel_w - 44.f) * 0.62f, 12.f);
				aida::ui::components::render_progress_bar(ImVec2(px + 22.f, py + panel_h - 26.f),
				                                          panel_w - 44.f, 4.f, emu_prog, false, true);
			} else {
				dl->AddText(aida::ui::fonts::body_em(), 14.f,
				            ImVec2(px + 22.f, py + 22.f),
				            _ta(tk.text_primary), "Decompiling...");
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 56.f),
				                                      panel_w - 44.f, 12.f);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 78.f),
				                                      (panel_w - 44.f) * 0.78f, 12.f);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 100.f),
				                                      (panel_w - 44.f) * 0.62f, 12.f);
				aida::ui::skeleton::render_text_line(dl, ImVec2(px + 22.f, py + 122.f),
				                                      (panel_w - 44.f) * 0.85f, 12.f);
				aida::ui::components::render_progress_bar(ImVec2(px + 22.f, py + panel_h - 26.f),
				                                          panel_w - 44.f, 4.f, 0.f, true, true);
			}
		} else {
			if (display_text.size() != s_last_pseudocode_len) {
				s_last_pseudocode_len = display_text.size();
				s_pseudocode_reveal = 0.f;
			}
			s_pseudocode_reveal += dt * 6.f;
			if (s_pseudocode_reveal > 1.f) s_pseudocode_reveal = 1.f;

			auto lines = split_lines(display_text);
			static auto cpp_lang = syntax::lang_cpp();
			std::vector<syntax::token_t> tokens;

			dl->AddRectFilled(ImVec2(ox, code_top), ImVec2(ox + gutter_w, code_top + code_h),
			                  _ta(tk.bg_base));

			int reveal_until = static_cast<int>((float)lines.size() * s_pseudocode_reveal + 0.5f);

			for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
				float ly = code_top + static_cast<float>(i) * line_h;
				if (ly + line_h < code_top || ly > code_top + code_h) continue;

				if (i >= reveal_until) {
					aida::ui::skeleton::render_text_line(dl,
					    ImVec2(ox + gutter_w + 8.f, ly + 2.f),
					    code_w - gutter_w - 24.f, 12.f, 1.5f);
					continue;
				}

				char num[16];
				snprintf(num, sizeof(num), "%d", lines[i].number);
				ImVec2 ns = ImGui::CalcTextSize(num);
				dl->AddText(ImVec2(ox + gutter_w - ns.x - 8.f, ly + 1.f),
				            _ta(tk.text_lineno), num);

				syntax::tokenize(lines[i].text, cpp_lang, tokens);
				float tx = ox + gutter_w + 8.f;
				for (auto& tok : tokens) {
					std::string_view sv(lines[i].text.data() + tok.start, tok.length);
					ImU32 col = token_color(tok.type, alpha);
					dl->AddText(ImVec2(tx, ly + 1.f), col, sv.data(), sv.data() + sv.size());
					tx += ImGui::CalcTextSize(sv.data(), sv.data() + sv.size()).x;
				}
			}

			float blink = aida::ui::clock::pulse(2.0f, 0.3f, 1.f);
			int last_line = reveal_until - 1;
			if (last_line < 0) last_line = static_cast<int>(lines.size()) - 1;
			if (last_line >= 0) {
				float cy2 = code_top + static_cast<float>(last_line) * line_h;
				float cursor_x = ox + gutter_w + 8.f;
				if (last_line < static_cast<int>(lines.size()) && !lines[last_line].text.empty())
					cursor_x += ImGui::CalcTextSize(lines[last_line].text.c_str()).x;
				dl->AddRectFilled(ImVec2(cursor_x, cy2 + 1.f), ImVec2(cursor_x + 2.f, cy2 + line_h - 2.f),
				                  aida::ui::with_alpha(tk.accent_u32, blink * alpha));
			}
		}
	} else {
		std::lock_guard<std::mutex> lk(st.mutex);
		s_last_pseudocode_len = 0;
		s_pseudocode_reveal = 1.f;

		if (st.current.is_error) {
			float panel_w = std::min(420.f, code_w * 0.6f);
			float panel_h = 100.f;
			float px = ox + (code_w - panel_w) * 0.5f;
			float py = code_top + (code_h - panel_h) * 0.5f;
			ImVec2 a(px, py);
			ImVec2 b(px + panel_w, py + panel_h);
			aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 4, 0.30f * alpha);
			aida::ui::blur::render_glass_fill(dl, a, b, 12.f, alpha);
			aida::ui::blur::render_glass_border(dl, a, b, 12.f, alpha);
			dl->AddText(aida::ui::fonts::body_em(), 14.f,
			            ImVec2(px + 18.f, py + 16.f),
			            aida::ui::with_alpha(tk.error, alpha), "Decompilation failed");
			dl->AddText(aida::ui::fonts::caption(), 12.f,
			            ImVec2(px + 18.f, py + 38.f),
			            _ta(tk.text_secondary), st.current.error_text.c_str(),
			            nullptr, panel_w - 36.f);
		} else if (st.current.pseudocode.empty()) {
			aida::ui::empty_state::config_t cfg;
			cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
			cfg.title = "No decompilation yet";
			cfg.body  = "Right-click a function in disassembly and choose Decompile, or press F5.";
			cfg.hints = { { "F5" }, { "Right-click" } };
			aida::ui::empty_state::render(ImVec2(ox, code_top), ImVec2(code_w, code_h), cfg);
		} else {
			s_last_pseudocode_len = st.current.pseudocode.size();
			s_pseudocode_reveal = 1.f;

			auto lines = split_lines(st.current.pseudocode);
			static auto cpp_lang = syntax::lang_cpp();
			std::vector<syntax::token_t> tokens;

			float content_h = static_cast<float>(lines.size()) * line_h;
			float visible_h = code_h;

			bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, code_top),
			                                       ImVec2(ox + code_w, code_top + code_h), false);
			if (hov) {
				ui_anim::handle_scroll_input(st.target_scroll_y, 0.f,
				                              (std::max)(0.f, content_h - visible_h), line_h);
			}
			ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 15.f,
			                        ImGui::GetIO().DeltaTime);

			int first_vis = static_cast<int>(st.scroll_y / line_h);
			if (first_vis < 0) first_vis = 0;
			int vis_count = static_cast<int>(visible_h / line_h) + 2;

			dl->AddRectFilled(ImVec2(ox, code_top), ImVec2(ox + gutter_w, code_top + code_h),
			                  _ta(tk.bg_base));

			for (int i = first_vis; i < (std::min)(first_vis + vis_count, static_cast<int>(lines.size())); ++i) {
				float ly = code_top + static_cast<float>(i) * line_h - st.scroll_y;

				char num[16];
				snprintf(num, sizeof(num), "%d", lines[i].number);
				ImVec2 ns = ImGui::CalcTextSize(num);
				dl->AddText(ImVec2(ox + gutter_w - ns.x - 8.f, ly + 1.f),
				            _ta(tk.text_lineno), num);

				syntax::tokenize(lines[i].text, cpp_lang, tokens);
				float tx = ox + gutter_w + 8.f;
				for (auto& tok : tokens) {
					std::string_view sv(lines[i].text.data() + tok.start, tok.length);
					ImU32 col = token_color(tok.type, alpha);
					dl->AddText(ImVec2(tx, ly + 1.f), col, sv.data(), sv.data() + sv.size());
					tx += ImGui::CalcTextSize(sv.data(), sv.data() + sv.size()).x;
				}
			}

			if (content_h > visible_h) {
				float sb_x = ox + code_w - 10.f;
				ui_anim::render_custom_scrollbar(dl, sb_x, code_top, 8.f, code_h,
				                                  st.scroll_y, content_h, visible_h,
				                                  alpha, scrollbar_dragging, scrollbar_drag_offset);
				if (scrollbar_dragging) {
					if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
						scrollbar_dragging = false;
					else {
						float track = code_h - (std::max)(code_h * visible_h / content_h, 20.f);
						float mouse_y = ImGui::GetMousePos().y - code_top - scrollbar_drag_offset;
						float ratio = mouse_y / track;
						if (ratio < 0.f) ratio = 0.f;
						if (ratio > 1.f) ratio = 1.f;
						st.target_scroll_y = ratio * (content_h - visible_h);
						st.scroll_y = st.target_scroll_y;
					}
				}
			}
		}
	}

	dl->PopClipRect();

	if (has_right_panel) {
		float rp_x = ox + code_w;
		float rp_y = code_top;
		float rp_h = code_h;

		dl->AddLine(ImVec2(rp_x, rp_y), ImVec2(rp_x, rp_y + rp_h),
		            aida::ui::with_alpha(tk.border_subtle, alpha));
		dl->AddRectFilled(ImVec2(rp_x, rp_y), ImVec2(rp_x + right_panel_w, rp_y + rp_h),
		                  _ta(tk.panel_bg));

		static float s_func_vel = 0.f;
		static float s_callees_vel = 0.f;
		static float s_history_vel = 0.f;
		s_section_func_anim    = aida::motion::spring_step(s_section_func_anim,
		                                                    s_section_func_open ? 1.f : 0.f,
		                                                    s_func_vel, aida::motion::spring::snappy, dt);
		s_section_callees_anim = aida::motion::spring_step(s_section_callees_anim,
		                                                    s_section_callees_open ? 1.f : 0.f,
		                                                    s_callees_vel, aida::motion::spring::snappy, dt);
		s_section_history_anim = aida::motion::spring_step(s_section_history_anim,
		                                                    s_section_history_open ? 1.f : 0.f,
		                                                    s_history_vel, aida::motion::spring::snappy, dt);

		float py = rp_y + 6.f;

		std::lock_guard<std::mutex> lk(st.mutex);

		ImGui::PushClipRect(ImVec2(rp_x, rp_y), ImVec2(rp_x + right_panel_w, rp_y + rp_h), true);

		render_section_header("Function Info", &s_section_func_open,
		                       ImVec2(rp_x + 6.f, py), right_panel_w - 12.f,
		                       s_section_func_anim);
		py += 24.f;
		float func_target_h = 0.f;
		if (st.current.function_addr) func_target_h += 18.f;
		if (!st.current.function_name.empty()) func_target_h += 18.f;
		if (!st.current.parameters.empty()) {
			float wrap = right_panel_w - 28.f;
			ImVec2 ps = ImGui::CalcTextSize(st.current.parameters.c_str(), nullptr, false, wrap);
			func_target_h += 18.f + ps.y + 6.f;
		}
		float func_block_h = func_target_h * s_section_func_anim;

		if (func_block_h > 1.f) {
			ImGui::PushClipRect(ImVec2(rp_x + 6.f, py),
			                    ImVec2(rp_x + right_panel_w - 6.f, py + func_block_h), true);
			float ipy = py;
			if (st.current.function_addr) {
				char addr[24];
				snprintf(addr, sizeof(addr), "0x%llX",
				         static_cast<unsigned long long>(st.current.function_addr));
				dl->AddText(ImVec2(rp_x + 14.f, ipy),
				            _ta(tk.text_dim), "Address");
				dl->AddText(ImVec2(rp_x + 80.f, ipy),
				            _ta(tk.text_address), addr);
				ipy += 18.f;
			}
			if (!st.current.function_name.empty()) {
				dl->AddText(ImVec2(rp_x + 14.f, ipy),
				            _ta(tk.text_dim), "Name");
				dl->AddText(ImVec2(rp_x + 80.f, ipy),
				            _ta(tk.text_secondary),
				            st.current.function_name.c_str());
				ipy += 18.f;
			}
			if (!st.current.parameters.empty()) {
				dl->AddText(ImVec2(rp_x + 14.f, ipy),
				            _ta(tk.text_dim), "Params");
				ipy += 18.f;
				float wrap = right_panel_w - 28.f;
				ImVec2 ps = ImGui::CalcTextSize(st.current.parameters.c_str(), nullptr, false, wrap);
				dl->AddText(nullptr, 0.f, ImVec2(rp_x + 18.f, ipy),
				            aida::ui::with_alpha(tk.syn_type, alpha),
				            st.current.parameters.c_str(),
				            st.current.parameters.c_str() + st.current.parameters.size(),
				            wrap);
				ipy += ps.y + 6.f;
			}
			ImGui::PopClipRect();
		}
		py += func_block_h;
		if (py + 6.f < rp_y + rp_h)
			dl->AddLine(ImVec2(rp_x + 6.f, py + 4.f),
			            ImVec2(rp_x + right_panel_w - 6.f, py + 4.f),
			            aida::ui::with_alpha(tk.border_subtle, alpha));
		py += 8.f;

		if (!st.current.callees.empty()) {
			render_section_header("Callees", &s_section_callees_open,
			                       ImVec2(rp_x + 6.f, py), right_panel_w - 12.f,
			                       s_section_callees_anim);
			py += 24.f;
			float callees_target_h = static_cast<float>(st.current.callees.size()) * 18.f;
			if (callees_target_h > rp_y + rp_h - py - 6.f)
				callees_target_h = rp_y + rp_h - py - 6.f;
			float callees_h = callees_target_h * s_section_callees_anim;

			if (callees_h > 1.f) {
				ImGui::PushClipRect(ImVec2(rp_x + 6.f, py),
				                    ImVec2(rp_x + right_panel_w - 6.f, py + callees_h), true);
				float ipy = py;
				int idx = 0;
				for (auto& callee : st.current.callees) {
					if (ipy + 14.f > rp_y + rp_h - 4.f) break;

					ImVec2 cp0(rp_x + 14.f, ipy);
					ImVec2 cts = ImGui::CalcTextSize(callee.c_str());
					ImVec2 cp1(cp0.x + cts.x + 8.f, ipy + 16.f);
					bool callee_hov = ImGui::IsMouseHoveringRect(cp0, cp1, false);

					float& ch = s_callee_hover[idx];
					ch = aida::motion::smooth_lerp(ch, callee_hov ? 1.f : 0.f, 14.f, dt);

					ImU32 callee_col = aida::ui::mix(
						aida::ui::with_alpha(tk.syn_function, alpha),
						aida::ui::with_alpha(tk.accent_u32, alpha),
						ch);
					dl->AddText(ImVec2(rp_x + 18.f, ipy), callee_col, callee.c_str());

					if (ch > 0.001f) {
						dl->AddLine(ImVec2(rp_x + 18.f, ipy + cts.y),
						            ImVec2(rp_x + 18.f + cts.x * ch, ipy + cts.y),
						            callee_col);
					}

					if (callee_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
						uint64_t target_addr = 0;
						if (callee.size() > 4 && callee.substr(0, 4) == "sub_") {
							if (sscanf_s(callee.c_str() + 4, "%llx", &target_addr) == 1 && target_addr != 0) {
								decompiler_engine::decompile_function(target_addr, g_sa_settings);
							}
						}
					}

					ipy += 18.f;
					++idx;
				}
				ImGui::PopClipRect();
			}
			py += callees_h;
			if (py + 6.f < rp_y + rp_h)
				dl->AddLine(ImVec2(rp_x + 6.f, py + 4.f),
				            ImVec2(rp_x + right_panel_w - 6.f, py + 4.f),
				            aida::ui::with_alpha(tk.border_subtle, alpha));
			py += 8.f;
		}

		if (!st.history.empty() && py + 24.f < rp_y + rp_h) {
			render_section_header("History", &s_section_history_open,
			                       ImVec2(rp_x + 6.f, py), right_panel_w - 12.f,
			                       s_section_history_anim);
			py += 24.f;
			float history_target_h = static_cast<float>(st.history.size()) * 18.f;
			if (history_target_h > rp_y + rp_h - py - 6.f)
				history_target_h = rp_y + rp_h - py - 6.f;
			float history_h = history_target_h * s_section_history_anim;

			if (history_h > 1.f) {
				ImGui::PushClipRect(ImVec2(rp_x + 6.f, py),
				                    ImVec2(rp_x + right_panel_w - 6.f, py + history_h), true);
				float ipy = py;
				for (int hi = static_cast<int>(st.history.size()) - 1; hi >= 0; --hi) {
					if (ipy + 14.f > rp_y + rp_h - 4.f) break;
					auto& he = st.history[hi];

					ImVec2 hp0(rp_x + 14.f, ipy);
					ImVec2 hts = ImGui::CalcTextSize(he.name.c_str());
					ImVec2 hp1(hp0.x + hts.x + 8.f, ipy + 16.f);
					bool hist_hov = ImGui::IsMouseHoveringRect(hp0, hp1, false);

					float& hh = s_history_hover[hi];
					hh = aida::motion::smooth_lerp(hh, hist_hov ? 1.f : 0.f, 14.f, dt);

					ImU32 hc;
					if (hi == st.history_pos)
						hc = aida::ui::with_alpha(tk.accent_u32, alpha);
					else
						hc = aida::ui::mix(_ta(tk.text_secondary), _ta(tk.text_primary), hh);
					dl->AddText(ImVec2(rp_x + 18.f, ipy), hc, he.name.c_str());

					if (hist_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && hi != st.history_pos) {
						st.history_pos = hi;
						decompiler_engine::decompile_function(he.addr, g_sa_settings);
					}

					ipy += 18.f;
				}
				ImGui::PopClipRect();
			}
			py += history_h;
		}

		ImGui::PopClipRect();
	}
}

}
