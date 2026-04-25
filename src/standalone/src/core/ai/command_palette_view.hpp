#pragma once

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "imgui/imgui.h"

#include "command_registry.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"

#include "../helpers/globals.h"


namespace aida {
namespace command_palette {


	namespace detail {

		inline int&  selected_index()        { static int v = 0; return v; }
		inline int&  preview_index()         { static int v = -1; return v; }
		inline bool& was_open_last_frame()   { static bool v = false; return v; }
		inline std::string& last_query()     { static std::string s; return s; }
		inline std::string& chat_inject()    { static std::string s; return s; }


		inline ImU32 source_color(commands::command_source_t src, float alpha)
		{
			int r = 100, g = 160, b = 230;
			switch (src) {
			case commands::command_source_t::builtin:
				r = 100; g = 160; b = 230;
				break;
			case commands::command_source_t::mcp:
				r = 180; g = 130; b = 230;
				break;
			case commands::command_source_t::skill:
				r = 120; g = 200; b = 130;
				break;
			case commands::command_source_t::agent:
				r = 230; g = 160; b = 80;
				break;
			}
			return IM_COL32(r, g, b, static_cast<int>(255.f * alpha));
		}


		inline const char* source_label(commands::command_source_t src)
		{
			switch (src) {
			case commands::command_source_t::builtin: return "builtin";
			case commands::command_source_t::mcp:     return "mcp";
			case commands::command_source_t::skill:   return "skill";
			case commands::command_source_t::agent:   return "agent";
			}
			return "?";
		}


		inline std::string truncate_for_display(const std::string& s, size_t max_len)
		{
			if (s.size() <= max_len) return s;
			std::string out = s.substr(0, max_len);
			out += "...";
			return out;
		}


		inline std::string excerpt_template(const std::string& tmpl, size_t max_len)
		{
			std::string compact;
			compact.reserve(tmpl.size());
			bool last_space = false;
			for (char c : tmpl) {
				char ch = c;
				if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
				if (ch == ' ') {
					if (last_space) continue;
					last_space = true;
				} else {
					last_space = false;
				}
				compact.push_back(ch);
			}
			return truncate_for_display(compact, max_len);
		}


		inline void draw_source_pill(ImDrawList* dl, float x, float y,
		                              commands::command_source_t src, float alpha)
		{
			const char* label = source_label(src);
			ImVec2 ts = ImGui::CalcTextSize(label);
			float pad_x = 6.f;
			float pad_y = 2.f;
			float w = ts.x + pad_x * 2.f;
			float h = ts.y + pad_y * 2.f;
			ImU32 col_fg = source_color(src, alpha);
			ImU32 col_bg = source_color(src, alpha * 0.15f);
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), col_bg, 4.f);
			dl->AddRect(ImVec2(x, y), ImVec2(x + w, y + h),
				ui_anim::theme_alpha(col_fg, 0.55f), 4.f, 0, 1.f);
			dl->AddText(ImVec2(x + pad_x, y + pad_y), col_fg, label);
		}


		inline float source_pill_width(commands::command_source_t src)
		{
			ImVec2 ts = ImGui::CalcTextSize(source_label(src));
			return ts.x + 12.f;
		}


		inline void inject_into_chat(const std::string& text)
		{
			std::strncpy(g_chat_buf, text.c_str(), sizeof(g_chat_buf) - 1);
			g_chat_buf[sizeof(g_chat_buf) - 1] = '\0';

			ChatMessage um;
			um.text = text;
			um.is_user = true;
			um.has_thinking = false;
			um.streaming = false;
			g_chat_messages.push_back(um);
			g_chat_scroll_to_bottom = true;
			g_chat_buf[0] = '\0';
		}


		inline void close_palette()
		{
			globals::ui::command_palette_open = false;
			globals::ui::command_palette_buf[0] = '\0';
			selected_index() = 0;
			preview_index() = -1;
			last_query().clear();
		}


		inline void execute_selection(const commands::command_t& cmd)
		{
			std::vector<std::string> args;
			std::string out;
			const bool ok = commands::execute(cmd.name, args, out);
			if (!ok) {
				toast_notification::push(
					std::string("/") + cmd.name + ": " + commands::last_error(),
					toast_notification::toast_type_t::error);
				close_palette();
				return;
			}

			const bool is_programmatic =
				(cmd.source == commands::command_source_t::builtin && cmd.template_text.empty()) ||
				(cmd.source == commands::command_source_t::agent);

			if (is_programmatic) {
				if (!out.empty())
					toast_notification::push(out, toast_notification::toast_type_t::info, 6.0f);
			} else {
				if (!out.empty()) inject_into_chat(out);
			}

			close_palette();
		}

	}


	inline void initialize()
	{
		(void)commands::initialize();
	}


	inline void shutdown()
	{
		detail::close_palette();
	}


	inline void render()
	{
		using namespace detail;

		const bool open_now = globals::ui::command_palette_open;
		if (!open_now) {
			if (was_open_last_frame()) {
				close_palette();
			}
			was_open_last_frame() = false;
			return;
		}

		if (!was_open_last_frame()) {
			selected_index() = 0;
			preview_index() = -1;
			last_query().clear();
		}
		was_open_last_frame() = true;

		const std::string current_query(globals::ui::command_palette_buf);
		if (current_query != last_query()) {
			selected_index() = 0;
			preview_index() = -1;
			last_query() = current_query;
		}

		std::vector<commands::command_t> hits = commands::fuzzy_search(current_query, 50);
		const int hit_count = static_cast<int>(hits.size());
		if (selected_index() >= hit_count) selected_index() = std::max(0, hit_count - 1);
		if (selected_index() < 0) selected_index() = 0;

		ImGuiIO& io = ImGui::GetIO();
		ImVec2 vp = io.DisplaySize;
		ImDrawList* fdl = ImGui::GetForegroundDrawList();
		fdl->AddRectFilled(ImVec2(0, 0), vp, IM_COL32(0, 0, 0, 140));

		const float palette_w = 600.f;
		const float palette_h = 500.f;
		const float palette_x = (vp.x - palette_w) * 0.5f;
		const float palette_y = (vp.y - palette_h) * 0.5f;

		ImGui::SetNextWindowPos(ImVec2(palette_x, palette_y));
		ImGui::SetNextWindowSize(ImVec2(palette_w, palette_h));

		ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(28, 30, 38, 248));
		ImGui::PushStyleColor(ImGuiCol_Border,   IM_COL32(80, 82, 110, 220));
		ImGui::PushStyleColor(ImGuiCol_FrameBg,  IM_COL32(40, 42, 56, 255));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  10.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(12, 12));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,   6.f);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.f);

		const ImGuiWindowFlags flags =
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

		bool window_visible = ImGui::Begin("##aida_command_palette", nullptr, flags);
		if (window_visible) {
			ImGui::PushItemWidth(-1);
			if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();

			const bool enter_pressed = ImGui::InputTextWithHint(
				"##palette_input",
				"Type a command (e.g. /init, /review, /compact)...",
				globals::ui::command_palette_buf,
				sizeof(globals::ui::command_palette_buf),
				ImGuiInputTextFlags_EnterReturnsTrue);
			ImGui::PopItemWidth();

			ImGui::Separator();

			if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
				close_palette();
				ImGui::End();
				ImGui::PopStyleVar(4);
				ImGui::PopStyleColor(3);
				return;
			}

			if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
				if (hit_count > 0)
					selected_index() = (selected_index() + 1) % hit_count;
				preview_index() = -1;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
				if (hit_count > 0)
					selected_index() = (selected_index() - 1 + hit_count) % hit_count;
				preview_index() = -1;
			}
			if (ImGui::IsKeyPressed(ImGuiKey_Tab, false) && hit_count > 0) {
				if (preview_index() == selected_index())
					preview_index() = -1;
				else
					preview_index() = selected_index();
			}

			if (enter_pressed && hit_count > 0) {
				execute_selection(hits[selected_index()]);
				ImGui::End();
				ImGui::PopStyleVar(4);
				ImGui::PopStyleColor(3);
				return;
			}

			const float row_h    = 28.f;
			const float list_h   = palette_h - 90.f;
			const float preview_h = (preview_index() >= 0 && preview_index() < hit_count) ? 100.f : 0.f;

			ImGui::BeginChild("##palette_list", ImVec2(-1, list_h - preview_h), false,
				ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_AlwaysVerticalScrollbar);

			for (int i = 0; i < hit_count; ++i) {
				const commands::command_t& c = hits[i];
				const bool is_selected = (i == selected_index());

				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				ImDrawList* dl = ImGui::GetWindowDrawList();

				ImU32 row_bg = is_selected
					? IM_COL32(58, 64, 86, 220)
					: IM_COL32(0, 0, 0, 0);
				if (row_bg != 0)
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), row_bg, 5.f);

				ImVec2 mouse_pos = io.MousePos;
				const bool hovering =
					mouse_pos.x >= cp.x && mouse_pos.x <= cp.x + row_w &&
					mouse_pos.y >= cp.y && mouse_pos.y <= cp.y + row_h;
				if (hovering && !is_selected)
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h),
						IM_COL32(60, 64, 84, 110), 5.f);
				if (hovering) {
					selected_index() = i;
					if (ImGui::IsMouseClicked(0)) {
						execute_selection(c);
						ImGui::EndChild();
						ImGui::End();
						ImGui::PopStyleVar(4);
						ImGui::PopStyleColor(3);
						return;
					}
				}

				const float pill_w  = source_pill_width(c.source);
				const float name_x  = cp.x + 10.f;
				const float pill_x  = name_x;
				const float pill_y  = cp.y + (row_h - 18.f) * 0.5f;
				draw_source_pill(dl, pill_x, pill_y, c.source, 1.f);

				const float name_xpos = pill_x + pill_w + 8.f;
				const ImU32 name_col = is_selected
					? IM_COL32(255, 255, 255, 255)
					: IM_COL32(220, 222, 235, 240);
				const std::string display_name = std::string("/") + c.name;
				dl->AddText(ImVec2(name_xpos, cp.y + 6.f), name_col, display_name.c_str());

				ImVec2 name_ts = ImGui::CalcTextSize(display_name.c_str());

				const float desc_xpos = name_xpos + name_ts.x + 14.f;
				const float right_reserved = 84.f;
				const float desc_max_w = (cp.x + row_w - right_reserved) - desc_xpos;
				if (!c.description.empty() && desc_max_w > 40.f) {
					ImFont* font = ImGui::GetFont();
					ImVec2 dts = font->CalcTextSizeA(font->FontSize, FLT_MAX, FLT_MAX,
						c.description.c_str());
					std::string desc = c.description;
					if (dts.x > desc_max_w) {
						const size_t approx = static_cast<size_t>(desc_max_w / (dts.x / desc.size() + 0.0001f));
						if (approx + 3 < desc.size())
							desc = desc.substr(0, approx) + "...";
					}
					dl->AddText(ImVec2(desc_xpos, cp.y + 7.f),
						IM_COL32(150, 155, 175, 220), desc.c_str());
				}

				if (is_selected) {
					const char* hint = "Enter run  Tab preview";
					ImVec2 hts = ImGui::CalcTextSize(hint);
					dl->AddText(ImVec2(cp.x + row_w - hts.x - 10.f, cp.y + 7.f),
						IM_COL32(160, 165, 195, 220), hint);
				}

				ImGui::SetCursorScreenPos(ImVec2(cp.x, cp.y + row_h));
			}

			if (hit_count == 0) {
				ImGui::Dummy(ImVec2(0, 16.f));
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(160, 165, 185, 220));
				ImGui::TextWrapped("No matches. Try shorter input or check skills/MCP servers.");
				ImGui::PopStyleColor();
			}

			if (selected_index() >= 0 && selected_index() < hit_count) {
				const float target_y = selected_index() * row_h;
				const float scroll_y = ImGui::GetScrollY();
				if (target_y < scroll_y) ImGui::SetScrollY(target_y);
				const float visible_h = ImGui::GetWindowHeight();
				if (target_y + row_h > scroll_y + visible_h)
					ImGui::SetScrollY(target_y + row_h - visible_h);
			}

			ImGui::EndChild();

			if (preview_index() >= 0 && preview_index() < hit_count) {
				const commands::command_t& c = hits[preview_index()];
				ImGui::Spacing();
				ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(34, 36, 48, 220));
				ImGui::BeginChild("##palette_preview", ImVec2(-1, preview_h - 10.f), true,
					ImGuiWindowFlags_NoScrollbar);
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(210, 215, 230, 240));
				if (!c.placeholder_hints.empty()) {
					std::string hints_str = "args: ";
					for (size_t i = 0; i < c.placeholder_hints.size(); ++i) {
						if (i > 0) hints_str += ", ";
						hints_str += c.placeholder_hints[i];
					}
					ImGui::TextWrapped("%s", hints_str.c_str());
				}
				const std::string excerpt = c.template_text.empty()
					? std::string("(programmatic command - no template)")
					: excerpt_template(c.template_text, 360);
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(170, 175, 195, 230));
				ImGui::TextWrapped("%s", excerpt.c_str());
				ImGui::PopStyleColor();
				if (!c.source_path.empty()) {
					ImGui::Spacing();
					ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(130, 135, 160, 200));
					ImGui::TextWrapped("source: %s", c.source_path.c_str());
					ImGui::PopStyleColor();
				}
				ImGui::PopStyleColor();
				ImGui::EndChild();
				ImGui::PopStyleColor();
			}

			const ImVec2 footer_pos(palette_x + 12.f, palette_y + palette_h - 24.f);
			char count_buf[64];
			std::snprintf(count_buf, sizeof(count_buf), "%d match%s",
				hit_count, hit_count == 1 ? "" : "es");
			fdl->AddText(footer_pos, IM_COL32(150, 155, 180, 210), count_buf);

			const char* footer_hint = "Up/Down navigate  -  Tab preview  -  Enter run  -  Esc close";
			ImVec2 fhs = ImGui::CalcTextSize(footer_hint);
			fdl->AddText(ImVec2(palette_x + palette_w - fhs.x - 12.f,
				palette_y + palette_h - 24.f),
				IM_COL32(150, 155, 180, 210), footer_hint);
		}
		ImGui::End();
		ImGui::PopStyleVar(4);
		ImGui::PopStyleColor(3);

		if (ImGui::IsMouseClicked(0)) {
			ImVec2 mp = io.MousePos;
			const bool inside =
				mp.x >= palette_x && mp.x <= palette_x + palette_w &&
				mp.y >= palette_y && mp.y <= palette_y + palette_h;
			if (!inside)
				close_palette();
		}
	}


}
}
