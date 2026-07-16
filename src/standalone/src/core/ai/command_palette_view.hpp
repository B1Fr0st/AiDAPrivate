#pragma once

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include "command_registry.hpp"
#include "avatar.hpp"
#include "blur_layer.hpp"
#include "clock.hpp"
#include "components.hpp"
#include "fonts.hpp"
#include "motion.hpp"
#include "theme.hpp"
#include "transition.hpp"
#include "toast_notification.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../../preview/studio_semantics.hpp"

#include "../helpers/globals.h"


namespace aida {
namespace command_palette {


	namespace detail {

			enum class category_t : int {
			commands  = 0,
			ide_actions = 1,
			files     = 2,
			agents    = 3,
			skills    = 4,
			mcp       = 5,
			ai_actions= 6,
			count     = 7,
		};

		struct preview_state_t {
			std::string         key;
			ui::transition_t    reveal;
		};

		inline int&  selected_index()        { static int v = 0; return v; }
		inline bool& preview_visible()       { static bool v = true; return v; }
		inline bool& was_open_last_frame()   { static bool v = false; return v; }
		inline std::string& last_query()     { static std::string s; return s; }
		inline std::string& last_result_key(){ static std::string s; return s; }

		inline ui::transition_t& open_anim()        { static ui::transition_t t; return t; }
		inline ui::transition_t& close_anim()       { static ui::transition_t t; return t; }
		inline ui::transition_t& filter_xfade()     { static ui::transition_t t; return t; }
		inline ui::transition_t& preview_anim()     { static ui::transition_t t; return t; }
		inline std::vector<ui::transition_t>& row_anims() {
			static std::vector<ui::transition_t> v; return v;
		}

		inline bool& is_closing()            { static bool v = false; return v; }

		inline preview_state_t& preview_state(){ static preview_state_t s; return s; }

		inline category_t classify(const commands::command_t& c)
		{
			if (!c.application_action_id.empty()) return category_t::ide_actions;
			switch (c.source) {
			case commands::command_source_t::agent:   return category_t::agents;
			case commands::command_source_t::skill:   return category_t::skills;
			case commands::command_source_t::mcp:     return category_t::mcp;
			case commands::command_source_t::builtin:
			default:
				if (!c.template_text.empty()) return category_t::ai_actions;
				return category_t::commands;
			}
		}


		inline const char* category_label(category_t cat)
		{
			switch (cat) {
			case category_t::commands:   return "COMMANDS";
			case category_t::ide_actions:return "IDE ACTIONS";
			case category_t::files:      return "FILES";
			case category_t::agents:     return "AGENTS";
			case category_t::skills:     return "SKILLS";
			case category_t::mcp:        return "MCP";
			case category_t::ai_actions: return "AI ACTIONS";
			default:                     return "";
			}
		}


		inline ImU32 source_color(const ui::theme_t& t, commands::command_source_t src)
		{
			switch (src) {
			case commands::command_source_t::builtin: return t.accent_u32;
			case commands::command_source_t::mcp:     return t.info;
			case commands::command_source_t::skill:   return t.success;
			case commands::command_source_t::agent:   return t.warning;
			}
			return t.text_secondary;
		}


		inline std::string preview_key_for(const commands::command_t& c)
		{
			std::string k;
			k.reserve(c.name.size() + c.source_path.size() + 8);
			k.push_back(static_cast<char>('0' + static_cast<int>(c.source)));
			k.push_back('|');
			k += c.name;
			k.push_back('|');
			k += c.source_path;
			return k;
		}


		inline std::string compute_results_key(const std::vector<commands::command_t>& v)
		{
			std::string k;
			k.reserve(v.size() * 16);
			for (const auto& c : v) {
				k.push_back(static_cast<char>('0' + static_cast<int>(c.source)));
				k.push_back(':');
				k += c.name;
				k.push_back(';');
			}
			return k;
		}


		inline void draw_source_icon(ImDrawList* dl, ImVec2 center, float size,
		                              const commands::command_t& cmd, ImU32 col, float alpha)
		{
			const ImU32 c = ui::with_alpha(col, alpha);
			const float r = size * 0.5f;
			const float th = std::max(1.2f, size * 0.10f);

			switch (cmd.source) {
			case commands::command_source_t::builtin: {
				const float arm = r * 0.95f;
				const float arm_thin = r * 0.40f;
				ImVec2 p_top   (center.x,         center.y - arm);
				ImVec2 p_bot   (center.x,         center.y + arm);
				ImVec2 p_left  (center.x - arm,   center.y);
				ImVec2 p_right (center.x + arm,   center.y);
				ImVec2 p_tl    (center.x - arm_thin * 0.55f, center.y - arm_thin * 0.55f);
				ImVec2 p_tr    (center.x + arm_thin * 0.55f, center.y - arm_thin * 0.55f);
				ImVec2 p_bl    (center.x - arm_thin * 0.55f, center.y + arm_thin * 0.55f);
				ImVec2 p_br    (center.x + arm_thin * 0.55f, center.y + arm_thin * 0.55f);
				dl->AddQuadFilled(p_top, p_tr, p_right, p_br, c);
				dl->AddQuadFilled(p_right, p_br, p_bot, p_bl, c);
				dl->AddQuadFilled(p_bot, p_bl, p_left, p_tl, c);
				dl->AddQuadFilled(p_left, p_tl, p_top, p_tr, c);
				dl->AddCircleFilled(center, arm_thin * 0.30f,
					ui::with_alpha(IM_COL32(255, 255, 255, 200), alpha), 12);
				break;
			}
			case commands::command_source_t::mcp: {
				const float node_r = r * 0.30f;
				ImVec2 a(center.x - r * 0.65f, center.y + r * 0.30f);
				ImVec2 b(center.x + r * 0.65f, center.y + r * 0.30f);
				ImVec2 top(center.x,           center.y - r * 0.55f);
				dl->AddLine(a,   top, c, th);
				dl->AddLine(top, b,   c, th);
				dl->AddLine(a,   b,   ui::with_alpha(col, alpha * 0.55f), th * 0.85f);
				dl->AddCircleFilled(a,   node_r, c, 14);
				dl->AddCircleFilled(b,   node_r, c, 14);
				dl->AddCircleFilled(top, node_r, c, 14);
				break;
			}
			case commands::command_source_t::skill: {
				ImVec2 p0(center.x + r * 0.10f,  center.y - r * 0.95f);
				ImVec2 p1(center.x - r * 0.45f,  center.y + r * 0.05f);
				ImVec2 p2(center.x + r * 0.05f,  center.y + r * 0.05f);
				ImVec2 p3(center.x - r * 0.10f,  center.y + r * 0.95f);
				ImVec2 p4(center.x + r * 0.55f,  center.y - r * 0.10f);
				ImVec2 p5(center.x + r * 0.05f,  center.y - r * 0.10f);
				dl->AddQuadFilled(p0, p4, p5, p1, c);
				dl->AddQuadFilled(p2, p5, p4, p3, c);
				break;
			}
			case commands::command_source_t::agent: {
				ui::avatar::render(dl, center, r, cmd.name,
					ui::avatar::kind_t::gradient, true, alpha,
					ui::fonts::caption());
				break;
			}
			}
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


		inline void begin_close()
		{
			if (is_closing()) return;
			is_closing() = true;
			close_anim().start(0.160f, motion::ease::in_out_cubic);
		}


		inline void hard_reset_state()
		{
			globals::ui::command_palette_open = false;
			globals::ui::command_palette_buf[0] = '\0';
			selected_index() = 0;
			last_query().clear();
			last_result_key().clear();
			is_closing() = false;
			open_anim().reset();
			close_anim().reset();
			filter_xfade().reset();
			preview_anim().reset();
			row_anims().clear();
			preview_state().key.clear();
		}


		inline void execute_selection(const commands::command_t& cmd)
		{
			if (!cmd.enabled) {
				toast_notification::push(
					cmd.disabled_reason.empty() ? "This action is unavailable" : cmd.disabled_reason,
					toast_notification::toast_type_t::warning, 6.0f);
				return;
			}
			if (!cmd.application_action_id.empty()) {
				const auto result = ui::application_ui::execute_action(
					cmd.application_action_id.c_str(), ui::action_invocation_source_t::command_palette);
				if (!result.executed()) {
					toast_notification::push(
						result.message.empty() ? "The action could not be completed" : result.message,
						toast_notification::toast_type_t::error, 6.0f);
					return;
				}
				begin_close();
				return;
			}
			std::vector<std::string> args;
			std::string out;
			const bool ok = commands::execute(cmd.name, args, out);
			if (!ok) {
				toast_notification::push(
					std::string("/") + cmd.name + ": " + commands::last_error(),
					toast_notification::toast_type_t::error);
				begin_close();
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

			begin_close();
		}


		inline void render_card_chrome(ImDrawList* dl, ImVec2 a, ImVec2 b,
		                                float radius, float open_t, float close_t)
		{
			const auto& th = ui::resolved();

			const int   shadow_passes = std::max(1, static_cast<int>(floorf(open_t * 4.5f)) - static_cast<int>(floorf(close_t * 4.0f)));
			const float shadow_strength = 0.40f * open_t * (1.f - close_t);
			ui::blur::render_drop_shadow(dl, a, b, radius, shadow_passes, shadow_strength,
				ImVec2(0.f, 6.f + 2.f * (1.f - open_t)));

			ImU32 fill = ui::with_alpha(th.bg_overlay, 0.92f);
			ImU32 tint = ui::with_alpha(th.glass_tint, 0.65f);
			dl->AddRectFilled(a, b, fill, radius);
			dl->AddRectFilled(a, b, tint, radius);

			ImU32 grad_top = ui::with_alpha(th.accent_grad_top, 0.10f);
			ImU32 grad_bot = ui::with_alpha(th.accent_grad_bot, 0.04f);
			ImU32 grad_flat = ui::mix(grad_top, grad_bot, 0.5f);
			dl->AddRectFilled(a, b, grad_flat, radius);

			ui::blur::render_glass_border(dl, a, b, radius, 1.f, 1.f);

			ImU32 inner = ui::with_alpha(th.accent_glow, 0.55f);
			ui::blur::render_inner_glow(dl, a, b, radius, inner, 3);
		}


		inline void draw_search_chip(ImDrawList* dl, ImVec2 center, float size, ImU32 col)
		{
			float r = size * 0.36f;
			float th = std::max(1.4f, size * 0.10f);
			dl->AddCircle(center, r, col, 24, th);
			float ang = 0.78539816f;
			ImVec2 p0(center.x + cosf(ang) * r,        center.y + sinf(ang) * r);
			ImVec2 p1(center.x + cosf(ang) * size * 0.60f,
			          center.y + sinf(ang) * size * 0.60f);
			dl->AddLine(p0, p1, col, th);
		}


		inline float row_eased_progress(int idx)
		{
			auto& v = row_anims();
			if (idx < 0) return 1.f;
			const std::size_t row_index = static_cast<std::size_t>(idx);
			if (row_index >= v.size()) return 1.f;
			return v[row_index].eased();
		}


		inline void ensure_row_anims(std::size_t count)
		{
			auto& v = row_anims();
			if (v.size() == count) return;
			v.resize(count);
			for (std::size_t i = 0; i < count; ++i) {
				const float delay = static_cast<float>(std::min<std::size_t>(8, i)) * 0.012f;
				v[i].reset();
				v[i].start(0.260f, motion::ease::out_quint, delay);
			}
		}


		inline void retrigger_row_anims(std::size_t count)
		{
			auto& v = row_anims();
			v.assign(count, ui::transition_t{});
			for (std::size_t i = 0; i < count; ++i) {
				const float delay = static_cast<float>(std::min<std::size_t>(8, i)) * 0.012f;
				v[i].start(0.260f, motion::ease::out_quint, delay);
			}
		}


		inline void render_row(ImDrawList* dl, ImVec2 ra, ImVec2 rb,
		                        const commands::command_t& c, bool is_selected,
		                        bool hovered, float entrance_t, float close_alpha,
		                        bool show_kbd_chips)
		{
			const auto& t = ui::resolved();

			const float lift_y = (1.f - entrance_t) * 6.f;
			ImVec2 a(ra.x, ra.y + lift_y);
			ImVec2 b(rb.x, rb.y + lift_y);

			const float inner_pad = 12.f;
			const float row_radius = 10.f;

			const float alpha = entrance_t * close_alpha;

			if (is_selected) {
				ImU32 grad_top = ui::with_alpha(t.accent_grad_top, 0.18f * alpha);
				ImU32 grad_bot = ui::with_alpha(t.accent_grad_bot, 0.10f * alpha);
				ImU32 grad_flat = ui::mix(grad_top, grad_bot, 0.5f);
				dl->AddRectFilled(a, b, grad_flat, row_radius);
				ImU32 wash = ui::with_alpha(t.hover_wash, 0.85f * alpha);
				dl->AddRectFilled(a, b, wash, row_radius);
			} else if (hovered) {
				ImU32 wash = ui::with_alpha(t.hover_wash, 0.95f * alpha);
				dl->AddRectFilled(a, b, wash, row_radius);
				ImU32 tint = ui::with_alpha(t.glass_tint, 0.45f * alpha);
				dl->AddRectFilled(a, b, tint, row_radius);
			}

			if (is_selected) {
				ImU32 border_top = ui::with_alpha(t.accent_grad_top, 0.95f * alpha);
				ImU32 border_bot = ui::with_alpha(t.accent_grad_bot, 0.85f * alpha);
				dl->AddRect(a, b, border_top, row_radius, 0, 1.5f);
				dl->AddRect(ImVec2(a.x + 0.5f, a.y + 0.5f), ImVec2(b.x - 0.5f, b.y - 0.5f),
					border_bot, row_radius, 0, 0.6f);
				ui::blur::render_inner_glow(dl, a, b, row_radius,
					ui::with_alpha(t.accent_glow, alpha), 3);
			}

			const float icon_size = 22.f;
			ImVec2 icon_center(a.x + inner_pad + icon_size * 0.5f, (a.y + b.y) * 0.5f);
			ImU32 icon_col = source_color(t, c.source);
			draw_source_icon(dl, icon_center, icon_size, c, icon_col, alpha);

			ImFont* name_font = ui::fonts::body_em();
			ImFont* desc_font = ui::fonts::body();
			const float name_fs = 14.f;
			const float desc_fs = 13.f;

			const float text_x = a.x + inner_pad + icon_size + 12.f;

			ImU32 name_col = ui::with_alpha(
				!c.enabled ? t.text_dim : is_selected ? t.text_primary : ui::mix(t.text_primary, t.text_secondary, 0.25f),
				alpha);
			ImU32 desc_col = ui::with_alpha(t.text_secondary, alpha * 0.85f);

			const std::string display_name = c.display_name.empty()
				? std::string("/") + c.name : c.display_name;
			ImVec2 name_sz = name_font->CalcTextSizeA(name_fs, FLT_MAX, 0.f, display_name.c_str());
			dl->AddText(name_font, name_fs,
				ImVec2(text_x, (a.y + b.y) * 0.5f - name_fs * 0.5f),
				name_col, display_name.c_str());

			float right_reserve = 0.f;
			if (is_selected && show_kbd_chips) right_reserve = c.shortcut.empty() ? 150.f : 230.f;

			if (!c.description.empty()) {
				const float desc_x = text_x + name_sz.x + 14.f;
				const float max_desc_w = (b.x - inner_pad - right_reserve) - desc_x;
				if (max_desc_w > 60.f) {
					std::string desc = c.description;
					ImVec2 dts = desc_font->CalcTextSizeA(desc_fs, FLT_MAX, 0.f, desc.c_str());
					if (dts.x > max_desc_w) {
						const std::size_t approx = static_cast<std::size_t>(max_desc_w / (dts.x / static_cast<float>(desc.size()) + 0.0001f));
						if (approx + 3 < desc.size()) desc = desc.substr(0, approx) + "...";
					}
					dl->AddText(desc_font, desc_fs,
						ImVec2(desc_x, (a.y + b.y) * 0.5f - desc_fs * 0.5f),
						desc_col, desc.c_str());
				}
			}

			if (is_selected && show_kbd_chips) {
				ImFont* sf = ui::fonts::caption();
				const float kfs = 13.f;
				const struct { const char* lbl; const char* key; } chips[] = {
					{ "run",     "Enter" },
					{ "preview", "Tab" },
				};
				float right_x = b.x - inner_pad;
				for (const auto& chip : chips) {
					ImVec2 lts = sf->CalcTextSizeA(kfs, FLT_MAX, 0.f, chip.lbl);
					ImVec2 kts = sf->CalcTextSizeA(kfs, FLT_MAX, 0.f, chip.key);
					float kw = kts.x + 10.f;
					float total = kw + 4.f + lts.x;
					float chip_y = (a.y + b.y) * 0.5f - 8.f;
					ImVec2 ka(right_x - lts.x - 4.f - kw, chip_y);
					ImVec2 kb(ka.x + kw, chip_y + 16.f);
					dl->AddRectFilled(ka, kb,
						ui::with_alpha(t.panel_header, 0.95f * alpha), 4.f);
					dl->AddRect(ka, kb,
						ui::with_alpha(t.border_subtle, 0.95f * alpha), 4.f, 0, 1.f);
					dl->AddText(sf, kfs, ImVec2(ka.x + 5.f, ka.y + (16.f - kfs) * 0.5f),
						ui::with_alpha(t.text_secondary, alpha), chip.key);
					dl->AddText(sf, kfs, ImVec2(kb.x + 4.f, ka.y + (16.f - kfs) * 0.5f),
						ui::with_alpha(t.text_dim, alpha), chip.lbl);
					right_x -= total + 8.f;
				}
				if (!c.shortcut.empty()) {
					ImVec2 kts = sf->CalcTextSizeA(kfs, FLT_MAX, 0.f, c.shortcut.c_str());
					float kw = kts.x + 10.f;
					ImVec2 ka(right_x - kw, (a.y + b.y) * 0.5f - 8.f);
					ImVec2 kb(ka.x + kw, ka.y + 16.f);
					dl->AddRectFilled(ka, kb, ui::with_alpha(t.panel_header, 0.95f * alpha), 4.f);
					dl->AddRect(ka, kb, ui::with_alpha(t.border_subtle, 0.95f * alpha), 4.f, 0, 1.f);
					dl->AddText(sf, kfs, ImVec2(ka.x + 5.f, ka.y + (16.f - kfs) * 0.5f),
						ui::with_alpha(t.text_secondary, alpha), c.shortcut.c_str());
				}
			}
		}


		inline void render_category_header(ImDrawList* dl, ImVec2 a, ImVec2 b,
		                                    const char* label, float close_alpha)
		{
			const auto& t = ui::resolved();
			ImFont* font = ui::fonts::caption();
			const float fs = 13.f;
			ImU32 line_col = ui::with_alpha(t.border_subtle, 0.85f * close_alpha);
			float text_y = (a.y + b.y) * 0.5f - fs * 0.5f;
			dl->AddText(font, fs, ImVec2(a.x + 4.f, text_y),
				ui::with_alpha(t.text_dim, close_alpha), label);
			ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
			float line_x = a.x + 4.f + ts.x + 10.f;
			dl->AddLine(ImVec2(line_x, (a.y + b.y) * 0.5f),
			             ImVec2(b.x - 4.f, (a.y + b.y) * 0.5f),
			             line_col, 1.f);
		}


		inline void render_text_lines_mono(ImDrawList* dl, ImVec2 origin, float max_w,
		                                     const std::string& text, ImU32 col,
		                                     int max_lines, float line_h)
		{
			ImFont* mono = ui::fonts::code();
			const float fs = 13.f;
			float y = origin.y;
			std::size_t i = 0;
			int line = 0;
			while (i < text.size() && line < max_lines) {
				std::size_t end = text.find('\n', i);
				if (end == std::string::npos) end = text.size();
				std::string ln = text.substr(i, end - i);
				if (!ln.empty() && ln.back() == '\r') ln.pop_back();
				ImVec2 tsz = mono->CalcTextSizeA(fs, FLT_MAX, 0.f, ln.c_str());
				if (tsz.x > max_w) {
					std::size_t approx = static_cast<std::size_t>(max_w / (tsz.x / static_cast<float>(ln.size()) + 0.0001f));
					if (approx + 3 < ln.size()) ln = ln.substr(0, approx) + "...";
				}
				dl->AddText(mono, fs, ImVec2(origin.x, y), col, ln.c_str());
				y += line_h;
				++line;
				i = end + 1;
			}
		}


		inline void render_template_preview(ImDrawList* dl, ImVec2 a, ImVec2 b,
		                                      const commands::command_t& c, float alpha)
		{
			const auto& t = ui::resolved();
			ImFont* mono = ui::fonts::code();
			const float fs = 13.f;
			const float line_h = 16.f;
			const float pad = 14.f;

			float y = a.y + pad;

			ImFont* hf = ui::fonts::caption();
			const char* heading = c.application_action_id.empty() ? "TEMPLATE" : "APPLICATION ACTION";
			dl->AddText(hf, 13.f, ImVec2(a.x + pad, y),
				ui::with_alpha(t.text_dim, alpha), heading);
			y += 18.f;

			std::string body;
			if (!c.application_action_id.empty()) {
				body = c.display_name;
				if (!c.category.empty())
					body += "\nCategory: " + c.category;
				if (!c.shortcut.empty())
					body += "\nShortcut: " + c.shortcut;
				if (c.enabled) {
					body += "\nAvailable now";
				} else {
					body += "\nUnavailable: ";
					body += c.disabled_reason.empty() ? "No capability provider" : c.disabled_reason;
				}
			} else {
				body = c.template_text.empty() ? std::string("(programmatic command)") : c.template_text;
			}

			float max_w = b.x - a.x - pad * 2.f;
			ImU32 base = ui::with_alpha(t.text_secondary, alpha);
			ImU32 ph_col = ui::with_alpha(t.accent_u32, alpha);

			std::size_t i = 0;
			int line = 0;
			const int max_lines = 18;
			while (i < body.size() && line < max_lines && y + line_h < b.y - pad - 60.f) {
				std::size_t end = body.find('\n', i);
				if (end == std::string::npos) end = body.size();
				std::string ln = body.substr(i, end - i);
				if (!ln.empty() && ln.back() == '\r') ln.pop_back();

				ImVec2 tsz = mono->CalcTextSizeA(fs, FLT_MAX, 0.f, ln.c_str());
				if (tsz.x > max_w) {
					std::size_t approx = static_cast<std::size_t>(max_w / (tsz.x / static_cast<float>(ln.size()) + 0.0001f));
					if (approx + 3 < ln.size()) ln = ln.substr(0, approx) + "...";
				}

				float x = a.x + pad;
				std::size_t k = 0;
				while (k < ln.size()) {
					if (ln[k] == '$' && k + 1 < ln.size() && ln[k + 1] == '{') {
						std::size_t close = ln.find('}', k + 2);
						if (close == std::string::npos) close = ln.size();
						std::string token = ln.substr(k, close - k + 1);
						dl->AddText(mono, fs, ImVec2(x, y), ph_col, token.c_str());
						x += mono->CalcTextSizeA(fs, FLT_MAX, 0.f, token.c_str()).x;
						k = close + 1;
					} else {
						std::size_t next = ln.find('$', k);
						if (next == std::string::npos) next = ln.size();
						std::string seg = ln.substr(k, next - k);
						dl->AddText(mono, fs, ImVec2(x, y), base, seg.c_str());
						x += mono->CalcTextSizeA(fs, FLT_MAX, 0.f, seg.c_str()).x;
						k = next;
					}
				}

				y += line_h;
				++line;
				i = end + 1;
			}

			if (!c.placeholder_hints.empty()) {
				y += 8.f;
				dl->AddText(hf, 13.f, ImVec2(a.x + pad, y),
					ui::with_alpha(t.text_dim, alpha), "ARGUMENTS");
				y += 18.f;
				std::string args;
				for (std::size_t j = 0; j < c.placeholder_hints.size(); ++j) {
					if (j > 0) args += ", ";
					args += c.placeholder_hints[j];
				}
				dl->AddText(ui::fonts::body(), 13.f, ImVec2(a.x + pad, y),
					ui::with_alpha(t.text_secondary, alpha), args.c_str());
			}
		}


		inline void render_agent_preview(ImDrawList* dl, ImVec2 a, ImVec2,
		                                   const commands::command_t& c, float alpha)
		{
			const auto& t = ui::resolved();
			const float pad = 14.f;
			ImVec2 av_center(a.x + pad + 18.f, a.y + pad + 18.f);
			ui::avatar::render(dl, av_center, 18.f, c.name,
				ui::avatar::kind_t::gradient, true, alpha, ui::fonts::body_em());

			ImFont* hf = ui::fonts::body_em();
			dl->AddText(hf, 16.f, ImVec2(av_center.x + 28.f, a.y + pad + 4.f),
				ui::with_alpha(t.text_primary, alpha), c.name.c_str());

			ImFont* sub = ui::fonts::caption();
			dl->AddText(sub, 13.f, ImVec2(av_center.x + 28.f, a.y + pad + 22.f),
				ui::with_alpha(t.text_dim, alpha), "AGENT");

			float y = a.y + pad + 50.f;
			dl->AddText(sub, 13.f, ImVec2(a.x + pad, y),
				ui::with_alpha(t.text_dim, alpha), "DESCRIPTION");
			y += 18.f;
			std::string desc = c.description.empty() ? std::string("(no description)") : c.description;
			dl->AddText(ui::fonts::body(), 13.f, ImVec2(a.x + pad, y),
				ui::with_alpha(t.text_secondary, alpha), desc.c_str());
		}


		inline void render_skill_preview(ImDrawList* dl, ImVec2 a, ImVec2 b,
		                                   const commands::command_t& c, float alpha)
		{
			const auto& t = ui::resolved();
			const float pad = 14.f;
			float y = a.y + pad;

			ImFont* hf = ui::fonts::caption();
			dl->AddText(hf, 13.f, ImVec2(a.x + pad, y),
				ui::with_alpha(t.text_dim, alpha), "SKILL");
			y += 18.f;

			dl->AddText(ui::fonts::body_em(), 16.f, ImVec2(a.x + pad, y),
				ui::with_alpha(t.text_primary, alpha), c.name.c_str());
			y += 26.f;

			if (!c.description.empty()) {
				dl->AddText(ui::fonts::body(), 13.f, ImVec2(a.x + pad, y),
					ui::with_alpha(t.text_secondary, alpha), c.description.c_str());
				y += 22.f;
			}

			if (!c.template_text.empty()) {
				y += 6.f;
				dl->AddText(hf, 13.f, ImVec2(a.x + pad, y),
					ui::with_alpha(t.text_dim, alpha), "TEMPLATE");
				y += 18.f;
				render_text_lines_mono(dl, ImVec2(a.x + pad, y),
					b.x - a.x - pad * 2.f,
					c.template_text,
					ui::with_alpha(t.text_secondary, alpha),
					14, 16.f);
			}
		}


		inline void render_preview_panel(ImDrawList* dl, ImVec2 a, ImVec2 b,
		                                   const commands::command_t* sel,
		                                   float alpha)
		{
			const auto& t = ui::resolved();
			const float radius = 10.f;
			ImU32 fill = ui::with_alpha(t.bg_elevated, 0.65f * alpha);
			ImU32 border = ui::with_alpha(t.border_subtle, 0.95f * alpha);
			dl->AddRectFilled(a, b, fill, radius);
			dl->AddRect(a, b, border, radius, 0, 1.f);

			if (!sel) {
				ImFont* font = ui::fonts::body();
				const char* hint = "Select an item to preview";
				ImVec2 ts = font->CalcTextSizeA(13.f, FLT_MAX, 0.f, hint);
				dl->AddText(font, 13.f,
					ImVec2((a.x + b.x) * 0.5f - ts.x * 0.5f,
					       (a.y + b.y) * 0.5f - ts.y * 0.5f),
					ui::with_alpha(t.text_dim, alpha), hint);
				return;
			}

			switch (sel->source) {
			case commands::command_source_t::agent:
				render_agent_preview(dl, a, b, *sel, alpha);
				break;
			case commands::command_source_t::skill:
				render_skill_preview(dl, a, b, *sel, alpha);
				break;
			default:
				render_template_preview(dl, a, b, *sel, alpha);
				break;
			}

			if (!sel->source_path.empty()) {
				ImFont* sm_font = ui::fonts::caption();
				const float fs = 12.f;
				std::string sp = sel->source_path;
				if (sp.size() > 80) sp = std::string("...") + sp.substr(sp.size() - 77);
				ImVec2 ts = sm_font->CalcTextSizeA(fs, FLT_MAX, 0.f, sp.c_str());
				dl->AddText(sm_font, fs,
					ImVec2(b.x - 12.f - ts.x, b.y - 12.f - fs),
					ui::with_alpha(t.text_dim, alpha * 0.85f), sp.c_str());
			}
		}

	}


	inline void initialize()
	{
		(void)commands::initialize();
	}


	inline void shutdown()
	{
		detail::hard_reset_state();
	}


	inline void render()
	{
		using namespace detail;
		const auto& th = ui::resolved();

		const bool open_now = globals::ui::command_palette_open;

		const float dt = ui::clock::dt();

		if (!open_now && !is_closing() && !was_open_last_frame()) {
			return;
		}

		const bool just_opened = open_now && !was_open_last_frame();
		if (just_opened) {
			selected_index() = 0;
			last_query().clear();
			last_result_key().clear();
			is_closing() = false;
			open_anim().reset();
			open_anim().start(0.220f, motion::ease::out_back);
			close_anim().reset();
			filter_xfade().reset();
			preview_anim().reset();
			preview_anim().start(0.220f, motion::ease::out_cubic);
			row_anims().clear();
		}

		open_anim().tick(dt);
		close_anim().tick(dt);
		filter_xfade().tick(dt);
		preview_anim().tick(dt);

		if (is_closing() && close_anim().is_finished()) {
			hard_reset_state();
			was_open_last_frame() = false;
			return;
		}

		if (!open_now && !is_closing()) {
			hard_reset_state();
			was_open_last_frame() = false;
			return;
		}

		was_open_last_frame() = true;

		const std::string current_query(globals::ui::command_palette_buf);
		const bool query_changed = (current_query != last_query());

		std::vector<commands::command_t> hits = commands::fuzzy_search(current_query, 256);

		std::sort(hits.begin(), hits.end(), [](const commands::command_t& a, const commands::command_t& b) {
			category_t ca = classify(a);
			category_t cb = classify(b);
			if (ca != cb) return static_cast<int>(ca) < static_cast<int>(cb);
			return a.name < b.name;
		});

		const int hit_count = static_cast<int>(hits.size());
		if (selected_index() >= hit_count) selected_index() = std::max(0, hit_count - 1);
		if (selected_index() < 0) selected_index() = 0;

		std::string new_results_key = compute_results_key(hits);
		if (query_changed) {
			last_query() = current_query;
			selected_index() = 0;
		}

		if (new_results_key != last_result_key()) {
			retrigger_row_anims(hits.size());
			filter_xfade().reset();
			filter_xfade().start(0.140f, motion::ease::out_cubic);
			last_result_key() = new_results_key;
		} else {
			ensure_row_anims(hits.size());
		}

		const float open_t = open_anim().eased();
		const float close_t = is_closing() ? close_anim().eased() : 0.f;
		const float close_alpha = 1.f - close_t;

		ImGuiIO& io = ImGui::GetIO();
		ImVec2 vp = io.DisplaySize;
		ImDrawList* fdl = ImGui::GetForegroundDrawList();

		const float palette_w = 720.f;
		const float palette_h = 540.f;

		const float overshoot_extra = 0.40f * std::max(0.f, open_t - 1.f);
		const float scale_open  = 0.95f + 0.05f * std::min(1.f, open_t) + overshoot_extra;
		const float scale_close = is_closing() ? (1.f - 0.03f * close_t) : 1.f;
		float scale = scale_open;
		if (is_closing()) scale = scale_close;
		if (scale < 0.5f) scale = 0.5f;

		const float y_offset = (1.f - open_t) * -12.f;

		const float draw_w = palette_w * scale;
		const float draw_h = palette_h * scale;
		const float palette_x = (vp.x - draw_w) * 0.5f;
		const float palette_y = (vp.y - draw_h) * 0.5f + y_offset;

		const ImVec2 card_a(palette_x, palette_y);
		const ImVec2 card_b(palette_x + draw_w, palette_y + draw_h);
		const float card_radius = 16.f;

		render_card_chrome(fdl, card_a, card_b, card_radius, open_t, close_t);

		ImGui::SetNextWindowPos(card_a);
		ImGui::SetNextWindowSize(ImVec2(draw_w, draw_h));

		ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Border,   ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_ChildBg,  ImVec4(0, 0, 0, 0));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  card_radius);
		ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding,   card_radius);
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(0.f, 0.f));
		ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha,           ImGui::GetStyle().Alpha * close_alpha);

		ImGuiWindowFlags flags =
			ImGuiWindowFlags_NoTitleBar   | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove       | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoScrollbar  | ImGuiWindowFlags_NoScrollWithMouse |
			ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoFocusOnAppearing;
#ifdef IMGUI_HAS_DOCK
		flags |= ImGuiWindowFlags_NoDocking;
#endif

		const bool window_visible = ImGui::Begin("##aida_command_palette", nullptr, flags);
		if (!window_visible) {
			ImGui::End();
			ImGui::PopStyleVar(5);
			ImGui::PopStyleColor(3);
			return;
		}

		const float input_h = 60.f;
		const float footer_h = 38.f;
		const float side_pad = 18.f;

		const bool wide_enough_for_preview = draw_w >= 600.f;
		const bool show_preview = preview_visible() && hit_count > 0 && wide_enough_for_preview;

		const float list_w = show_preview ? (draw_w - side_pad * 3.f) * 0.58f : (draw_w - side_pad * 2.f);
		const float preview_w = show_preview ? (draw_w - side_pad * 3.f) - list_w : 0.f;
		(void)preview_w;

		ImVec2 input_a(card_a.x + side_pad, card_a.y + side_pad);
		ImVec2 input_b(card_b.x - side_pad, input_a.y + input_h);
		{
			ImU32 fill = ui::with_alpha(th.bg_elevated, 0.85f * close_alpha);
			fdl->AddRectFilled(input_a, input_b, fill, 12.f);

			ImU32 border = ui::with_alpha(th.border_focus,
				(0.55f + 0.45f * ui::clock::pulse(1.5f, 0.f, 1.f)) * close_alpha * open_t);
			fdl->AddRect(input_a, input_b, border, 12.f, 0, 1.4f);

			ImU32 wash = ui::with_alpha(th.glass_tint, 0.35f * close_alpha);
			fdl->AddRectFilled(input_a, input_b, wash, 12.f);
		}

		const float chip_size = 22.f;
		ImVec2 chip_center(input_a.x + 18.f + chip_size * 0.5f,
		                   (input_a.y + input_b.y) * 0.5f);
		draw_search_chip(fdl, chip_center, chip_size,
			ui::with_alpha(th.text_secondary, 0.92f * close_alpha));

		const float input_text_left = input_a.x + 18.f + chip_size + 14.f;
		const float input_text_right = input_b.x - 18.f;
		const float input_text_w = input_text_right - input_text_left;

		ImGui::PushFont(ui::fonts::lg());
		const float font_h = ImGui::GetFontSize();
		ImVec2 input_cursor(input_text_left, (input_a.y + input_b.y) * 0.5f - font_h * 0.5f);
		ImGui::SetCursorScreenPos(input_cursor);
		ImGui::PushItemWidth(input_text_w);

		ImGui::PushStyleColor(ImGuiCol_FrameBg,        ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive,  ImVec4(0, 0, 0, 0));
		ImGui::PushStyleColor(ImGuiCol_Text,           ImGui::ColorConvertU32ToFloat4(
			ui::with_alpha(th.text_primary, close_alpha)));
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));

		if (just_opened) ImGui::SetKeyboardFocusHere(0);

		const bool enter_pressed = ImGui::InputTextWithHint(
			"##palette_input",
			"Search commands, files, agents, or AI actions...",
			globals::ui::command_palette_buf,
			sizeof(globals::ui::command_palette_buf),
			ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			"aida.palette.search", "command-palette-input");
#endif

		if (globals::ui::command_palette_buf[0] == '\0') {
			ImFont* placeholder_font = ui::fonts::lg();
			float pfs = ui::fonts::size_or(placeholder_font, ImGui::GetFontSize());
			fdl->AddText(placeholder_font, pfs,
				ImVec2(input_text_left, (input_a.y + input_b.y) * 0.5f - pfs * 0.5f),
				ui::with_alpha(th.text_dim, close_alpha),
				"Search commands, files, agents, or AI actions...");
		}

		ImGui::PopStyleVar();
		ImGui::PopStyleColor(4);
		ImGui::PopItemWidth();
		ImGui::PopFont();

		const bool block_input = is_closing();

		if (!block_input && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
			begin_close();
		}
		if (!block_input && ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
			if (hit_count > 0)
				selected_index() = (selected_index() + 1) % hit_count;
		}
		if (!block_input && ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
			if (hit_count > 0)
				selected_index() = (selected_index() - 1 + hit_count) % hit_count;
		}
		if (!block_input && ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
			preview_visible() = !preview_visible();
			if (preview_visible()) {
				preview_anim().reset();
				preview_anim().start(0.220f, motion::ease::out_cubic);
			} else {
				preview_anim().reset();
			}
		}

		if (enter_pressed && hit_count > 0 && !block_input) {
			execute_selection(hits[static_cast<std::size_t>(selected_index())]);
		}

		const float list_top = input_b.y + 14.f;
		const float list_bottom = card_b.y - footer_h - 14.f;
		const float list_height = list_bottom - list_top;

		ImVec2 list_a(card_a.x + side_pad, list_top);
		ImVec2 list_b(list_a.x + list_w, list_bottom);

		ImVec2 preview_a(list_b.x + side_pad, list_top);
		ImVec2 preview_b(card_b.x - side_pad, list_bottom);

		const float row_h = 40.f;
		const float row_gap = 4.f;

		std::vector<bool> show_header_for(hits.size(), false);
		bool any_two_categories = false;
		category_t prev_cat = category_t::count;
		for (std::size_t i = 0; i < hits.size(); ++i) {
			category_t cat = classify(hits[i]);
			if (cat != prev_cat) {
				show_header_for[i] = true;
				if (prev_cat != category_t::count) any_two_categories = true;
				prev_cat = cat;
			}
		}
		const bool show_headers = any_two_categories;

		const ImVec2 list_clip_a = list_a;
		const ImVec2 list_clip_b = list_b;
		fdl->PushClipRect(list_clip_a, list_clip_b, true);

		ImGui::SetCursorScreenPos(list_a);
		ImGui::BeginChild("##palette_list_region", ImVec2(list_w, list_height), false,
			ImGuiWindowFlags_NoBackground);

		ImDrawList* wdl = ImGui::GetWindowDrawList();

		float y_cursor = 0.f;
		const float xfade_t = filter_xfade().eased();
		const float xfade_dx = (1.f - xfade_t) * 24.f;
		const float new_alpha = xfade_t;

		ImVec2 win_pos = ImGui::GetCursorScreenPos();
		ImVec2 win_avail = ImGui::GetContentRegionAvail();

		for (std::size_t idx = 0; idx < hits.size(); ++idx) {
			const int row_index = static_cast<int>(idx);
			const commands::command_t& c = hits[idx];
			const bool show_header = show_headers && show_header_for[idx];

			if (show_header) {
				ImVec2 ha(win_pos.x, win_pos.y + y_cursor);
				ImVec2 hb(win_pos.x + win_avail.x, ha.y + 22.f);
				render_category_header(wdl, ha, hb, category_label(classify(c)), close_alpha);
				y_cursor += 26.f;
			}

			ImVec2 ra(win_pos.x + xfade_dx, win_pos.y + y_cursor);
			ImVec2 rb(ra.x + win_avail.x - xfade_dx, ra.y + row_h);

			ImGui::SetCursorScreenPos(ImVec2(win_pos.x, win_pos.y + y_cursor));
			ImGui::PushID(row_index);
			ImGui::InvisibleButton("##row", ImVec2(win_avail.x, row_h));
			const bool hovered = ImGui::IsItemHovered();
			const bool clicked = ImGui::IsItemClicked();
			#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			if (!c.application_action_id.empty()) {
				const std::string semantic_id = aida::preview::semantics::stable_id(
					"aida.palette.action", c.application_action_id);
				aida::preview::semantics::register_last_item(
					semantic_id, "command-palette-action");
			}
			#endif
			ImGui::PopID();

			if (hovered) selected_index() = row_index;

			float entrance_t = row_eased_progress(row_index);
			float row_close_alpha = new_alpha * close_alpha;

			ImGui::PushClipRect(ra, rb, true);
			render_row(wdl, ra, rb, c, row_index == selected_index(), hovered,
				entrance_t, row_close_alpha, true);
			ImGui::PopClipRect();

			if (clicked && !block_input) {
				execute_selection(c);
				ImGui::EndChild();
				fdl->PopClipRect();
				ImGui::End();
				ImGui::PopStyleVar(5);
				ImGui::PopStyleColor(3);
				return;
			}

			y_cursor += row_h + row_gap;
		}

		ImGui::Dummy(ImVec2(0.f, y_cursor));

		if (selected_index() >= 0 && selected_index() < hit_count) {
			float target_y = 0.f;
			category_t prev = category_t::count;
			for (int i = 0; i <= selected_index(); ++i) {
				category_t cat = classify(hits[static_cast<std::size_t>(i)]);
				if (show_headers && cat != prev) {
					if (i != 0) target_y += 26.f;
					else target_y += 0.f;
					prev = cat;
				}
				if (i < selected_index()) target_y += row_h + row_gap;
			}
			const float scroll_y = ImGui::GetScrollY();
			if (target_y < scroll_y) ImGui::SetScrollY(target_y);
			const float visible = ImGui::GetWindowHeight();
			if (target_y + row_h > scroll_y + visible)
				ImGui::SetScrollY(target_y + row_h - visible);
		}

		if (hit_count == 0) {
			ImFont* font = ui::fonts::body();
			const char* msg = "No matches. Try shorter input or check skills, agents, and MCP servers.";
			ImVec2 tsz = font->CalcTextSizeA(13.f, FLT_MAX, list_w - 40.f, msg);
			ImVec2 origin(list_a.x + (list_w - tsz.x) * 0.5f,
			              list_a.y + (list_height - tsz.y) * 0.5f);
			fdl->AddText(font, 13.f, origin,
				ui::with_alpha(th.text_dim, close_alpha), msg);
		}

		ImGui::EndChild();

		fdl->PopClipRect();

		if (show_preview) {
			float p_alpha = preview_anim().eased() * close_alpha;
			const commands::command_t* sel =
				(selected_index() >= 0 && selected_index() < hit_count)
				? &hits[static_cast<std::size_t>(selected_index())] : nullptr;

			std::string key = sel ? preview_key_for(*sel) : std::string();
			if (key != preview_state().key) {
				preview_state().key = key;
				preview_state().reveal.reset();
				preview_state().reveal.start(0.180f, motion::ease::out_cubic);
			}
			preview_state().reveal.tick(dt);
			float reveal_t = preview_state().reveal.eased();
			float xoff = (1.f - reveal_t) * 6.f;
			ImVec2 pa(preview_a.x + xoff, preview_a.y);
			ImVec2 pb(preview_b.x + xoff, preview_b.y);
			float combined_alpha = p_alpha * (0.4f + 0.6f * reveal_t);
			fdl->PushClipRect(preview_a, preview_b, true);
			render_preview_panel(fdl, pa, pb, sel, combined_alpha);
			fdl->PopClipRect();
		}

		{
			ImVec2 fa(card_a.x + side_pad, card_b.y - footer_h);
			ImVec2 fb(card_b.x - side_pad, card_b.y - 12.f);

			ImU32 sep = ui::with_alpha(th.border_subtle, 0.95f * close_alpha);
			fdl->AddLine(ImVec2(card_a.x + side_pad, fa.y - 2.f),
			              ImVec2(card_b.x - side_pad, fa.y - 2.f), sep, 1.f);

			char count_buf[64];
			std::snprintf(count_buf, sizeof(count_buf), "%d match%s",
				hit_count, hit_count == 1 ? "" : "es");
			ImFont* font = ui::fonts::caption();
			const float fs = 13.f;
			fdl->AddText(font, fs,
				ImVec2(fa.x, fa.y + (footer_h - fs) * 0.5f),
				ui::with_alpha(th.text_dim, close_alpha), count_buf);

			float right_x = fb.x;
			struct kbd_pair_t { const char* key; const char* lbl; };
			const kbd_pair_t pairs[] = {
				{ "Esc",   "close"    },
				{ "Enter", "run"      },
				{ "Tab",   "preview"  },
				{ "Up/Down", "navigate" },
			};
			ImFont* sf = ui::fonts::caption();
			float spacing = 14.f;
			for (const auto& p : pairs) {
				ImVec2 lts = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, p.lbl);
				ImVec2 kts = sf->CalcTextSizeA(11.f, FLT_MAX, 0.f, p.key);
				float kw = kts.x + 12.f;
				float total = lts.x + 6.f + kw;
				right_x -= total;
				ImVec2 kbox_a(right_x, fa.y + (footer_h - 18.f) * 0.5f);
				ImVec2 kbox_b(kbox_a.x + kw, kbox_a.y + 18.f);
				fdl->AddRectFilled(kbox_a, kbox_b,
					ui::with_alpha(th.panel_header, 0.95f * close_alpha), 4.f);
				fdl->AddRect(kbox_a, kbox_b,
					ui::with_alpha(th.border_subtle, 0.95f * close_alpha), 4.f, 0, 1.f);
				fdl->AddText(sf, 13.f,
					ImVec2(kbox_a.x + 6.f, kbox_a.y + (18.f - 11.f) * 0.5f),
					ui::with_alpha(th.text_secondary, close_alpha), p.key);
				fdl->AddText(sf, 13.f,
					ImVec2(kbox_b.x + 6.f, kbox_a.y + (18.f - 11.f) * 0.5f),
					ui::with_alpha(th.text_dim, close_alpha), p.lbl);
				right_x -= spacing;
			}
		}

		ImGui::End();
		ImGui::PopStyleVar(5);
		ImGui::PopStyleColor(3);

		if (!block_input && ImGui::IsMouseClicked(0)) {
			ImVec2 mp = io.MousePos;
			const bool inside =
				mp.x >= card_a.x && mp.x <= card_b.x &&
				mp.y >= card_a.y && mp.y <= card_b.y;
			if (!inside) begin_close();
		}
	}


}
}
