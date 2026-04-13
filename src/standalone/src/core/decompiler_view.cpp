#include "decompiler_view.hpp"
#include "decompiler_engine.hpp"
#include "syntax_highlight.hpp"
#include "ui_anim.hpp"
#include "disasm_view.hpp"
#include "../helpers/globals.h"

#include "imgui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>
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

ImU32 token_color(syntax::token_type t, float alpha, float ar, float ag, float ab)
{
	int a = static_cast<int>(220 * alpha);
	switch (t) {
	case syntax::token_type::keyword:       return IM_COL32(198, 120, 221, a);
	case syntax::token_type::type_name:     return IM_COL32(86, 182, 194, a);
	case syntax::token_type::string_lit:    return IM_COL32(152, 195, 121, a);
	case syntax::token_type::number:        return IM_COL32(209, 154, 102, a);
	case syntax::token_type::comment_line:  return IM_COL32(92, 99, 112, a);
	case syntax::token_type::comment_block: return IM_COL32(92, 99, 112, a);
	case syntax::token_type::preprocessor:  return IM_COL32(224, 108, 117, a);
	case syntax::token_type::operator_sym:  return IM_COL32(171, 178, 191, a);
	case syntax::token_type::function_call: return IM_COL32(97, 175, 239, a);
	case syntax::token_type::boolean_lit:   return IM_COL32(209, 154, 102, a);
	case syntax::token_type::punctuation:   return IM_COL32(171, 178, 191, a);
	default:                                return IM_COL32(171, 178, 191, a);
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

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
	auto& st = decompiler_engine::g_state;
	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetWindowPos();
	float ox = origin.x + pos_x;
	float oy = origin.y + pos_y;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
	                  IM_COL32(18, 18, 24, static_cast<int>(240 * alpha)));

	int ar_i = static_cast<int>(accent_r * 255);
	int ag_i = static_cast<int>(accent_g * 255);
	int ab_i = static_cast<int>(accent_b * 255);
	ImU32 accent_col = IM_COL32(ar_i, ag_i, ab_i, static_cast<int>(220 * alpha));

	float toolbar_h = 32.f;
	float gutter_w = 48.f;
	float right_panel_w = 220.f;
	float line_h = 18.f;

	bool has_right_panel = (width > 600.f);
	float code_w = has_right_panel ? (width - right_panel_w) : width;

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
	                  IM_COL32(25, 25, 35, static_cast<int>(230 * alpha)));
	dl->AddLine(ImVec2(ox, oy + toolbar_h), ImVec2(ox + width, oy + toolbar_h),
	            IM_COL32(50, 50, 65, static_cast<int>(180 * alpha)));

	{
		std::lock_guard<std::mutex> lk(st.mutex);
		char title[256];
		if (st.current.function_addr) {
			snprintf(title, sizeof(title), "Decompiler - %s (0x%llX)",
			         st.current.function_name.c_str(),
			         static_cast<unsigned long long>(st.current.function_addr));
		} else {
			snprintf(title, sizeof(title), "Decompiler");
		}
		dl->AddText(ImVec2(ox + 10.f, oy + (toolbar_h - 14.f) * 0.5f), accent_col, title);

		const char* mode_label = nullptr;
		ImU32 mode_color = 0;
		switch (st.active_mode) {
		case decompiler_engine::decompile_mode_t::ai:
			mode_label = "AI";
			mode_color = IM_COL32(100, 180, 255, 220);
			break;
		case decompiler_engine::decompile_mode_t::native_ghidra:
			mode_label = "Ghidra";
			mode_color = IM_COL32(100, 220, 120, 220);
			break;
		case decompiler_engine::decompile_mode_t::hybrid:
			mode_label = "Hybrid";
			mode_color = IM_COL32(220, 180, 80, 220);
			break;
		}
		if (mode_label && st.current.function_addr) {
			ImVec2 title_size = ImGui::CalcTextSize(title);
			float badge_x = ox + 10.f + title_size.x + 10.f;
			float badge_y = oy + (toolbar_h - 16.f) * 0.5f;
			ImVec2 label_size = ImGui::CalcTextSize(mode_label);
			float badge_w = label_size.x + 10.f;
			float badge_h = 16.f;
			dl->AddRectFilled(ImVec2(badge_x, badge_y),
			                  ImVec2(badge_x + badge_w, badge_y + badge_h),
			                  mode_color, 3.f);
			dl->AddText(ImVec2(badge_x + 5.f, badge_y + 1.f),
			            IM_COL32(0, 0, 0, 240), mode_label);
		}
	}

	float btn_x = ox + code_w - 10.f;
	float btn_w = 55.f;
	float btn_h = 22.f;
	float btn_y = oy + (toolbar_h - btn_h) * 0.5f;

	auto toolbar_button = [&](const char* label, float& bx) -> bool {
		ImVec2 ts = ImGui::CalcTextSize(label);
		float w = ts.x + 16.f;
		bx -= w + 4.f;
		ImVec2 p0(bx, btn_y);
		ImVec2 p1(bx + w, btn_y + btn_h);
		bool hov = ImGui::IsMouseHoveringRect(p0, p1, false);
		dl->AddRectFilled(p0, p1,
		    hov ? IM_COL32(70, 70, 90, static_cast<int>(180 * alpha))
		        : IM_COL32(40, 40, 55, static_cast<int>(160 * alpha)), 4.f);
		dl->AddText(ImVec2(bx + 8.f, btn_y + (btn_h - ts.y) * 0.5f),
		            IM_COL32(200, 200, 210, static_cast<int>(220 * alpha)), label);
		return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
	};

	if (toolbar_button("Copy", btn_x)) {
		std::lock_guard<std::mutex> lk(st.mutex);
		std::string text = st.current.complete ? st.current.pseudocode : st.streaming_text;
		if (!text.empty()) copy_to_clipboard(text);
	}

	if (st.decompiling.load()) {
		if (toolbar_button("Cancel", btn_x)) {
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
			if (toolbar_button("Deobfuscate", btn_x)) {
				decompiler_engine::decompile_with_deobfuscation(deobf_addr, g_sa_settings);
			}
		}
	}
#endif

	if (st.history_pos > 0) {
		if (toolbar_button("< Back", btn_x)) {
			decompiler_engine::navigate_back();
		}
	}

	if (st.history_pos + 1 < static_cast<int>(st.history.size())) {
		if (toolbar_button("Fwd >", btn_x)) {
			decompiler_engine::navigate_forward();
		}
	}

	{
		size_t cs = decompiler_engine::cache_size();
		if (cs > 0) {
			char cache_lbl[32];
			snprintf(cache_lbl, sizeof(cache_lbl), "Cache: %zu", cs);
			if (toolbar_button(cache_lbl, btn_x)) {
				decompiler_engine::clear_cache();
			}
		}
	}

	if (st.batch_running.load()) {
		char batch_lbl[48];
		snprintf(batch_lbl, sizeof(batch_lbl), "Batch %d/%d",
		         st.batch_done.load(), st.batch_total.load());
		toolbar_button(batch_lbl, btn_x);
	}

	{
		uint64_t sync_addr = 0;
		{
			std::lock_guard<std::mutex> lk(st.mutex);
			sync_addr = st.current.function_addr;
		}
		if (sync_addr != 0) {
			if (toolbar_button("Disasm", btn_x)) {
				globals::ui::active_center_view = center_view_t::disassembly;
				disasm_view::goto_address(sync_addr, g_disasm);
			}
		}
	}

	if (!st.batch_running.load() && !st.decompiling.load()) {
		if (toolbar_button("Batch", btn_x)) {
			show_batch_panel = !show_batch_panel;
		}
	}

	if (toolbar_button("Save$", btn_x)) {
		decompiler_engine::detail::save_all_cache_to_disk();
	}

	float code_top = oy + toolbar_h + 1.f;
	float code_h = height - toolbar_h - 1.f;

	if (show_batch_panel && !st.batch_running.load() && !st.decompiling.load()) {
		float batch_panel_h = 120.f;
		dl->AddRectFilled(ImVec2(ox, code_top), ImVec2(ox + code_w, code_top + batch_panel_h),
		                  IM_COL32(25, 25, 35, static_cast<int>(230 * alpha)));
		dl->AddLine(ImVec2(ox, code_top + batch_panel_h),
		            ImVec2(ox + code_w, code_top + batch_panel_h),
		            IM_COL32(50, 50, 65, static_cast<int>(180 * alpha)));

		ImGui::SetCursorScreenPos(ImVec2(ox + 10.f, code_top + 4.f));
		dl->AddText(ImVec2(ox + 10.f, code_top + 4.f), accent_col, "Batch Decompile — one hex address per line");

		ImGui::SetCursorScreenPos(ImVec2(ox + 10.f, code_top + 22.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.14f, alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.83f, 0.83f, 0.83f, alpha));
		ImGui::PushItemWidth(code_w - 100.f);
		ImGui::InputTextMultiline("##batch_addrs", batch_input, sizeof(batch_input),
		                          ImVec2(code_w - 100.f, batch_panel_h - 30.f));
		ImGui::PopItemWidth();
		ImGui::PopStyleColor(2);

		ImGui::SetCursorScreenPos(ImVec2(ox + code_w - 80.f, code_top + 22.f));
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_r, accent_g, accent_b, 0.7f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_r, accent_g, accent_b, 0.9f * alpha));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(accent_r, accent_g, accent_b, 1.0f * alpha));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, alpha));

		if (ImGui::Button("Run##batch", ImVec2(70.f, 30.f))) {
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
				uint64_t a = std::strtoull(line.c_str(), nullptr, 16);
				if (a != 0) addrs.push_back(a);
			}
			if (!addrs.empty()) {
				decompiler_engine::batch_decompile(addrs);
				show_batch_panel = false;
			}
		}

		ImGui::PopStyleColor(4);

		code_top += batch_panel_h;
		code_h -= batch_panel_h;
	}
	dl->PushClipRect(ImVec2(ox, code_top), ImVec2(ox + code_w, code_top + code_h), true);

	if ((st.decompiling.load() || st.emulating.load()) && !st.current.complete) {
		std::lock_guard<std::mutex> lk(st.mutex);
		std::string display_text = st.streaming_text;

		if (display_text.empty()) {
			float cx = ox + code_w * 0.5f;
			float cy = code_top + code_h * 0.5f;
			float t = static_cast<float>(ImGui::GetTime());
			int dot_count = static_cast<int>(t * 2.f) % 4;
			std::string dots(dot_count, '.');

			if (st.emulating.load()) {
				float emu_prog = st.emulation_progress.load();
				char prog_msg[128];
				snprintf(prog_msg, sizeof(prog_msg), "Emulating (%.0f%%)%s", emu_prog * 100.f, dots.c_str());
				std::string msg = prog_msg;
				ImVec2 ts = ImGui::CalcTextSize(msg.c_str());
				dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f - 10.f),
				            IM_COL32(140, 140, 160, static_cast<int>(200 * alpha)),
				            msg.c_str());

				float bar_w = 200.f;
				float bar_h = 4.f;
				float bar_x = cx - bar_w * 0.5f;
				float bar_y = cy + 10.f;
				dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + bar_w, bar_y + bar_h),
				                  IM_COL32(50, 50, 65, static_cast<int>(150 * alpha)), 2.f);
				dl->AddRectFilled(ImVec2(bar_x, bar_y),
				                  ImVec2(bar_x + bar_w * emu_prog, bar_y + bar_h),
				                  accent_col, 2.f);
			} else {
				std::string msg = "Decompiling" + dots;
				ImVec2 ts = ImGui::CalcTextSize(msg.c_str());
				dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f),
				            IM_COL32(140, 140, 160, static_cast<int>(200 * alpha)),
				            msg.c_str());
			}
		} else {
			auto lines = split_lines(display_text);
			static auto cpp_lang = syntax::lang_cpp();
			std::vector<syntax::token_t> tokens;

			dl->AddRectFilled(ImVec2(ox, code_top), ImVec2(ox + gutter_w, code_top + code_h),
			                  IM_COL32(22, 22, 30, static_cast<int>(220 * alpha)));

			for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
				float ly = code_top + static_cast<float>(i) * line_h;
				if (ly + line_h < code_top || ly > code_top + code_h) continue;

				char num[16];
				snprintf(num, sizeof(num), "%d", lines[i].number);
				ImVec2 ns = ImGui::CalcTextSize(num);
				dl->AddText(ImVec2(ox + gutter_w - ns.x - 8.f, ly + 1.f),
				            IM_COL32(80, 80, 100, static_cast<int>(150 * alpha)), num);

				syntax::tokenize(lines[i].text, cpp_lang, tokens);
				float tx = ox + gutter_w + 8.f;
				for (auto& tok : tokens) {
					std::string_view sv(lines[i].text.data() + tok.start, tok.length);
					ImU32 col = token_color(tok.type, alpha, accent_r, accent_g, accent_b);
					dl->AddText(ImVec2(tx, ly + 1.f), col, sv.data(), sv.data() + sv.size());
					tx += ImGui::CalcTextSize(sv.data(), sv.data() + sv.size()).x;
				}
			}

			float blink = ui_anim::pulse_alpha(static_cast<float>(ImGui::GetTime()), 1.5f, 0.3f, 1.f);
			int last_line = static_cast<int>(lines.size()) - 1;
			if (last_line >= 0) {
				float cy2 = code_top + static_cast<float>(last_line) * line_h;
				float cursor_x = ox + gutter_w + 8.f;
				if (!lines[last_line].text.empty())
					cursor_x += ImGui::CalcTextSize(lines[last_line].text.c_str()).x;
				dl->AddRectFilled(ImVec2(cursor_x, cy2 + 1.f), ImVec2(cursor_x + 2.f, cy2 + line_h - 2.f),
				                  IM_COL32(ar_i, ag_i, ab_i, static_cast<int>(200 * blink * alpha)));
			}
		}
	} else {
		std::lock_guard<std::mutex> lk(st.mutex);

		if (st.current.is_error) {
			float cx = ox + code_w * 0.5f;
			float cy = code_top + code_h * 0.5f;
			ImVec2 ts = ImGui::CalcTextSize(st.current.error_text.c_str());
			dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f),
			            IM_COL32(220, 80, 80, static_cast<int>(220 * alpha)),
			            st.current.error_text.c_str());
		} else if (st.current.pseudocode.empty()) {
			const char* hint = "Right-click a function in Disassembly or CFG and select 'Decompile Function'";
			ImVec2 ts = ImGui::CalcTextSize(hint);
			float cx = ox + code_w * 0.5f;
			float cy = code_top + code_h * 0.5f;
			dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f),
			            IM_COL32(100, 100, 120, static_cast<int>(150 * alpha)), hint);
		} else {
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
			                  IM_COL32(22, 22, 30, static_cast<int>(220 * alpha)));

			for (int i = first_vis; i < (std::min)(first_vis + vis_count, static_cast<int>(lines.size())); ++i) {
				float ly = code_top + static_cast<float>(i) * line_h - st.scroll_y;

				char num[16];
				snprintf(num, sizeof(num), "%d", lines[i].number);
				ImVec2 ns = ImGui::CalcTextSize(num);
				dl->AddText(ImVec2(ox + gutter_w - ns.x - 8.f, ly + 1.f),
				            IM_COL32(80, 80, 100, static_cast<int>(150 * alpha)), num);

				syntax::tokenize(lines[i].text, cpp_lang, tokens);
				float tx = ox + gutter_w + 8.f;
				for (auto& tok : tokens) {
					std::string_view sv(lines[i].text.data() + tok.start, tok.length);
					ImU32 col = token_color(tok.type, alpha, accent_r, accent_g, accent_b);
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
		            IM_COL32(50, 50, 65, static_cast<int>(180 * alpha)));
		dl->AddRectFilled(ImVec2(rp_x, rp_y), ImVec2(rp_x + right_panel_w, rp_y + rp_h),
		                  IM_COL32(22, 22, 30, static_cast<int>(220 * alpha)));

		float py = rp_y + 8.f;

		dl->AddText(ImVec2(rp_x + 10.f, py), accent_col, "Function Info");
		py += 20.f;
		dl->AddLine(ImVec2(rp_x + 6.f, py), ImVec2(rp_x + right_panel_w - 6.f, py),
		            IM_COL32(50, 50, 65, static_cast<int>(120 * alpha)));
		py += 8.f;

		std::lock_guard<std::mutex> lk(st.mutex);

		if (st.current.function_addr) {
			char addr[24];
			snprintf(addr, sizeof(addr), "0x%llX",
			         static_cast<unsigned long long>(st.current.function_addr));
			dl->AddText(ImVec2(rp_x + 10.f, py),
			            IM_COL32(120, 120, 140, static_cast<int>(180 * alpha)), "Address:");
			dl->AddText(ImVec2(rp_x + 70.f, py),
			            IM_COL32(180, 180, 195, static_cast<int>(200 * alpha)), addr);
			py += 16.f;
		}

		if (!st.current.function_name.empty()) {
			dl->AddText(ImVec2(rp_x + 10.f, py),
			            IM_COL32(120, 120, 140, static_cast<int>(180 * alpha)), "Name:");
			dl->AddText(ImVec2(rp_x + 70.f, py),
			            IM_COL32(180, 180, 195, static_cast<int>(200 * alpha)),
			            st.current.function_name.c_str());
			py += 16.f;
		}

		if (!st.current.parameters.empty()) {
			dl->AddText(ImVec2(rp_x + 10.f, py),
			            IM_COL32(120, 120, 140, static_cast<int>(180 * alpha)), "Params:");
			py += 16.f;

			float wrap = right_panel_w - 20.f;
			ImVec2 ps = ImGui::CalcTextSize(st.current.parameters.c_str(), nullptr, false, wrap);
			dl->AddText(nullptr, 0.f, ImVec2(rp_x + 14.f, py), 
			            IM_COL32(86, 182, 194, static_cast<int>(200 * alpha)),
			            st.current.parameters.c_str(),
			            st.current.parameters.c_str() + st.current.parameters.size(),
			            wrap);
			py += ps.y + 8.f;
		}

		if (!st.current.callees.empty()) {
			py += 8.f;
			dl->AddText(ImVec2(rp_x + 10.f, py), accent_col, "Callees");
			py += 20.f;
			dl->AddLine(ImVec2(rp_x + 6.f, py), ImVec2(rp_x + right_panel_w - 6.f, py),
			            IM_COL32(50, 50, 65, static_cast<int>(120 * alpha)));
			py += 6.f;

			for (auto& callee : st.current.callees) {
				if (py + 14.f > rp_y + rp_h - 4.f) break;

				ImVec2 cp0(rp_x + 10.f, py);
				ImVec2 cts = ImGui::CalcTextSize(callee.c_str());
				ImVec2 cp1(cp0.x + cts.x + 8.f, py + 16.f);
				bool callee_hov = ImGui::IsMouseHoveringRect(cp0, cp1, false);

				ImU32 callee_col = callee_hov
					? accent_col
					: IM_COL32(97, 175, 239, static_cast<int>(200 * alpha));
				dl->AddText(ImVec2(rp_x + 14.f, py), callee_col, callee.c_str());

				if (callee_hov) {
					dl->AddLine(ImVec2(rp_x + 14.f, py + cts.y),
					            ImVec2(rp_x + 14.f + cts.x, py + cts.y),
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

				py += 16.f;
			}
		}

		if (!st.history.empty()) {
			py += 12.f;
			if (py + 20.f < rp_y + rp_h) {
				dl->AddText(ImVec2(rp_x + 10.f, py), accent_col, "History");
				py += 20.f;
				dl->AddLine(ImVec2(rp_x + 6.f, py), ImVec2(rp_x + right_panel_w - 6.f, py),
				            IM_COL32(50, 50, 65, static_cast<int>(120 * alpha)));
				py += 6.f;

				for (int hi = static_cast<int>(st.history.size()) - 1; hi >= 0; --hi) {
					if (py + 14.f > rp_y + rp_h - 4.f) break;
					auto& he = st.history[hi];

					ImVec2 hp0(rp_x + 10.f, py);
					ImVec2 hts = ImGui::CalcTextSize(he.name.c_str());
					ImVec2 hp1(hp0.x + hts.x + 8.f, py + 16.f);
					bool hist_hov = ImGui::IsMouseHoveringRect(hp0, hp1, false);

					ImU32 hc = (hi == st.history_pos)
						? accent_col
						: hist_hov
							? IM_COL32(200, 200, 210, static_cast<int>(220 * alpha))
							: IM_COL32(150, 150, 165, static_cast<int>(180 * alpha));
					dl->AddText(ImVec2(rp_x + 14.f, py), hc, he.name.c_str());

					if (hist_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && hi != st.history_pos) {
						st.history_pos = hi;
						decompiler_engine::decompile_function(he.addr, g_sa_settings);
					}

					py += 16.f;
				}
			}
		}
	}
}

}
