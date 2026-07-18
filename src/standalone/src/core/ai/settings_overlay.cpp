#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#include "settings_overlay.hpp"
#include "../ui/application_view_registry.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"

#include "auth_view.hpp"
#include "agent_manager_view.hpp"
#include "skill_manager_view.hpp"
#include "../ui/application_view_registry.hpp"

#include "mcp_client.hpp"
#include "mcp_marketplace.hpp"
#include "standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "toast_notification.hpp"

#include "mcp_marketplace_view.hpp"
#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/design_system.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/responsive.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../helpers/diag_log.hpp"
#endif


extern settings_sa_t g_sa_settings;
mcp_client::manager_t& get_mcp_client_manager();


namespace aida {
namespace settings_overlay {


	namespace detail {

		struct overlay_state_t
		{
			std::mutex mtx;
			std::atomic<int> active_tab{ tab_accounts };
			std::atomic<int> previous_tab{ tab_accounts };
			std::atomic<bool> initialized{ false };
			float tab_anim = 0.f;
			float tab_underline_x = 0.f;
			float tab_underline_y = 0.f;
			float tab_underline_h = 0.f;
			float tab_underline_target_y = 0.f;
			float tab_underline_target_h = 0.f;
			float tab_underline_vel_y = 0.f;
			float tab_underline_vel_h = 0.f;
			float tab_row_screen_y[tab_count] = {};
			bool  tab_rows_captured = false;
			float tab_crossfade_progress = 1.f;
			int tab_crossfade_from = tab_accounts;
			aida::ui::flash_t header_flash;

			char  filter_buf[128] = {};
			char  mcp_search_buf[128] = {};

			bool editor_loaded = false;
			int  ed_tab_size = 4;
			float ed_font_size = 14.0f;

			std::unordered_map<std::string, aida::ui::hover_state_t> mcp_row_anims;
			float anim_input_count = 0.f;
			float anim_input_velocity = 0.f;
			float anim_cost_count = 0.f;

			std::mutex pending_focus_mtx;
			std::string pending_provider_focus;
			std::mutex mcp_oauth_mtx;
			std::unordered_map<std::string, std::uint64_t> mcp_oauth_generations;
			std::uint64_t mcp_oauth_generation = 0;
		};


		inline overlay_state_t& state()
		{
			static overlay_state_t s;
			return s;
		}


		inline std::uint64_t begin_mcp_oauth_generation(const std::string& server_name)
		{
			auto& s = state();
			std::lock_guard<std::mutex> lock(s.mcp_oauth_mtx);
			if (s.mcp_oauth_generation == (std::numeric_limits<std::uint64_t>::max)())
				return 0;
			const std::uint64_t generation = ++s.mcp_oauth_generation;
			s.mcp_oauth_generations[server_name] = generation;
			return generation;
		}


		inline bool complete_mcp_oauth_generation(const std::string& server_name,
			std::uint64_t generation)
		{
			auto& s = state();
			std::lock_guard<std::mutex> lock(s.mcp_oauth_mtx);
			const auto it = s.mcp_oauth_generations.find(server_name);
			if (it == s.mcp_oauth_generations.end() || it->second != generation)
				return false;
			s.mcp_oauth_generations.erase(it);
			return true;
		}


		inline void cancel_mcp_oauth_generation(const std::string& server_name)
		{
			auto& s = state();
			std::lock_guard<std::mutex> lock(s.mcp_oauth_mtx);
			s.mcp_oauth_generations.erase(server_name);
		}


		inline void load_editor_locked(overlay_state_t& s)
		{
			if (s.editor_loaded) return;
			s.editor_loaded = true;
			s.ed_tab_size        = g_sa_settings.editor_tab_size;
			s.ed_font_size       = g_sa_settings.editor_font_size;
		}


		inline void persist_editor_locked(overlay_state_t& s)
		{
			editor_config::tab_size                = (std::max)(s.ed_tab_size, 1);
			editor_config::font_size               = s.ed_font_size;
			editor_config::show_line_numbers       = true;
			editor_config::word_wrap               = true;
			editor_config::minimap                 = true;
			editor_config::bracket_match           = true;
			editor_config::highlight_current_line  = true;
			editor_config::auto_complete           = true;

			g_sa_settings.editor_tab_size          = (std::max)(s.ed_tab_size, 1);
			g_sa_settings.editor_font_size         = s.ed_font_size;
			g_sa_settings.editor_line_numbers      = true;
			g_sa_settings.editor_word_wrap         = true;
			g_sa_settings.editor_minimap           = true;
			g_sa_settings.editor_bracket_match     = true;
			g_sa_settings.editor_highlight_line    = true;
			g_sa_settings.editor_auto_complete     = true;
			g_sa_settings.ghost_text_enabled       = true;
			g_sa_settings.auto_save_enabled        = true;
			static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
		}


		inline aida::ui::pill_kind_t oauth_pill_kind(mcp_client::oauth_status_t st)
		{
			switch (st) {
			case mcp_client::oauth_status_t::authenticated:           return aida::ui::pill_kind_t::success;
			case mcp_client::oauth_status_t::not_required:            return aida::ui::pill_kind_t::neutral;
			case mcp_client::oauth_status_t::needs_auth:              return aida::ui::pill_kind_t::warning;
			case mcp_client::oauth_status_t::needs_client_registration: return aida::ui::pill_kind_t::error;
			case mcp_client::oauth_status_t::authenticating:          return aida::ui::pill_kind_t::info;
			case mcp_client::oauth_status_t::failed:                  return aida::ui::pill_kind_t::error;
			}
			return aida::ui::pill_kind_t::neutral;
		}


		inline const char* oauth_pill_label(mcp_client::oauth_status_t st)
		{
			switch (st) {
			case mcp_client::oauth_status_t::authenticated:           return "connected";
			case mcp_client::oauth_status_t::not_required:            return "no auth";
			case mcp_client::oauth_status_t::needs_auth:              return "sign in";
			case mcp_client::oauth_status_t::needs_client_registration: return "configure";
			case mcp_client::oauth_status_t::authenticating:          return "auth...";
			case mcp_client::oauth_status_t::failed:                  return "auth failed";
			}
			return "?";
		}

		inline void draw_tab_glyph(ImDrawList* dl, ImVec2 c, float r, int tab_idx, ImU32 col)
		{
			float th_w = r * 0.16f;
			switch (tab_idx) {
			case tab_accounts: {
				dl->AddCircle(ImVec2(c.x - r * 0.22f, c.y - r * 0.18f), r * 0.26f, col, 24, th_w);
				dl->PathArcTo(ImVec2(c.x - r * 0.22f, c.y + r * 0.40f), r * 0.46f, 3.4f, 5.98f, 24);
				dl->PathStroke(col, 0, th_w);
				dl->AddCircle(ImVec2(c.x + r * 0.42f, c.y + r * 0.10f), r * 0.20f, col, 20, th_w);
				dl->AddLine(ImVec2(c.x + r * 0.42f, c.y + r * 0.30f),
					ImVec2(c.x + r * 0.42f, c.y + r * 0.55f), col, th_w);
				break;
			}
			case tab_agents: {
				dl->AddCircle(c, r * 0.50f, col, 24, th_w);
				dl->AddCircleFilled(ImVec2(c.x - r * 0.18f, c.y - r * 0.10f), th_w * 0.8f, col, 12);
				dl->AddCircleFilled(ImVec2(c.x + r * 0.18f, c.y - r * 0.10f), th_w * 0.8f, col, 12);
				dl->PathArcTo(c, r * 0.20f, 0.f, 3.14159f, 16);
				dl->PathStroke(col, 0, th_w);
				break;
			}
			case tab_skills: {
				ImVec2 p0(c.x - r * 0.55f, c.y + r * 0.50f);
				ImVec2 p1(c.x, c.y - r * 0.55f);
				ImVec2 p2(c.x + r * 0.55f, c.y + r * 0.50f);
				dl->AddLine(p0, p1, col, th_w);
				dl->AddLine(p1, p2, col, th_w);
				dl->AddLine(ImVec2(c.x - r * 0.32f, c.y + r * 0.10f),
					ImVec2(c.x + r * 0.32f, c.y + r * 0.10f), col, th_w);
				break;
			}
			case tab_mcp_servers: {
				dl->AddRect(ImVec2(c.x - r * 0.55f, c.y - r * 0.50f),
					ImVec2(c.x + r * 0.55f, c.y - r * 0.10f), col, 3.f, 0, th_w);
				dl->AddRect(ImVec2(c.x - r * 0.55f, c.y + r * 0.10f),
					ImVec2(c.x + r * 0.55f, c.y + r * 0.50f), col, 3.f, 0, th_w);
				dl->AddCircleFilled(ImVec2(c.x - r * 0.30f, c.y - r * 0.30f), th_w * 0.7f, col, 12);
				dl->AddCircleFilled(ImVec2(c.x - r * 0.30f, c.y + r * 0.30f), th_w * 0.7f, col, 12);
				break;
			}
			case tab_editor_theme: {
				dl->AddLine(ImVec2(c.x - r * 0.55f, c.y - r * 0.40f),
					ImVec2(c.x + r * 0.55f, c.y - r * 0.40f), col, th_w);
				dl->AddLine(ImVec2(c.x - r * 0.55f, c.y), ImVec2(c.x + r * 0.20f, c.y), col, th_w);
				dl->AddLine(ImVec2(c.x - r * 0.55f, c.y + r * 0.40f),
					ImVec2(c.x + r * 0.40f, c.y + r * 0.40f), col, th_w);
				break;
			}
			default: break;
			}
		}

		inline void render_tab_label(int idx, const char* label, float side_w, float row_h,
			ImU32 active_text, ImU32 dim_text, float dt, bool icon_only)
		{
			auto& s = state();
			const auto& th = aida::ui::resolved();
			const int active = s.active_tab.load();
			const bool is_active = (active == idx);

			ImVec2 row_pos = ImGui::GetCursorScreenPos();
			if (idx >= 0 && idx < tab_count) {
				s.tab_row_screen_y[static_cast<std::size_t>(idx)] = row_pos.y;
				if (idx == tab_count - 1) {
					s.tab_rows_captured = true;
				}
			}

			ImGui::PushID(idx);
			ImGui::SetCursorScreenPos(row_pos);
			ImGui::InvisibleButton("##tab_btn", ImVec2(side_w, row_h));
			bool hov = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			if (icon_only && hov && label && *label) {
				aida::ui::components::tooltip_blur(label, 0.35f);
			}
			ImGui::PopID();

			ImDrawList* dl = ImGui::GetWindowDrawList();
			float inset = icon_only ? 4.f : 6.f;
			ImVec2 a(row_pos.x + inset, row_pos.y);
			ImVec2 b(row_pos.x + side_w - inset, row_pos.y + row_h - 4.f);

			ImU32 bg = aida::ui::with_alpha(th.panel_header, 0.f);
			if (is_active) {
				bg = aida::ui::with_alpha(th.selection, 0.85f);
			} else if (hov) {
				bg = th.hover_wash;
			}
			if (((bg >> IM_COL32_A_SHIFT) & 0xFF) > 0) {
				dl->AddRectFilled(a, b, bg, 8.f);
			}

			const float base_fs = aida::ui::components::detail::ui_fs();
			float glyph_r = base_fs * 0.72f;
			float gx;
			float gy = (a.y + b.y) * 0.5f;
			if (icon_only) {
				gx = (a.x + b.x) * 0.5f;
			} else {
				gx = a.x + 14.f + glyph_r;
			}
			ImU32 ic = is_active ? active_text : dim_text;
			draw_tab_glyph(dl, ImVec2(gx, gy), glyph_r, idx, ic);

			if (!icon_only) {
				ImFont* font = is_active ? aida::ui::fonts::body_strong() : aida::ui::fonts::body();
				float fs = base_fs * 0.95f;
				float label_x = gx + glyph_r + 10.f;
				float label_max_w = (b.x - 8.f) - label_x;
				ImVec2 sz = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
				if (label_max_w > 0.f && sz.x > label_max_w) {
					std::string truncated = aida::ui::responsive::truncate_to_width(
						std::string(label), font, fs, label_max_w);
					sz = font->CalcTextSizeA(fs, FLT_MAX, 0.f, truncated.c_str());
					dl->AddText(font, fs,
						ImVec2(label_x, a.y + (row_h - 4.f - sz.y) * 0.5f),
						is_active ? active_text : dim_text, truncated.c_str());
					if (hov && label && *label) {
						ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
						ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(th.bg_overlay));
						if (ImGui::BeginTooltip()) {
							ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
							ImGui::TextUnformatted(label);
							ImGui::PopStyleColor();
							ImGui::EndTooltip();
						}
						ImGui::PopStyleColor();
						ImGui::PopStyleVar();
					}
				} else {
					dl->AddText(font, fs,
						ImVec2(label_x, a.y + (row_h - 4.f - sz.y) * 0.5f),
						is_active ? active_text : dim_text, label);
				}
			}

			if (clicked) {
				int prev = s.active_tab.exchange(idx);
				if (prev != idx) {
					s.previous_tab.store(prev);
					s.tab_crossfade_progress = 0.f;
					s.tab_crossfade_from = prev;
				}
			}

			(void)dt;
		}

		inline void render_sidebar_underline(float side_w, float content_y,
			float row_h, float dt)
		{
			auto& s = state();
			ImDrawList* dl = ImGui::GetWindowDrawList();

			ImVec2 wp = ImGui::GetWindowPos();
			float row_visible_h = row_h - 4.f;
			float indicator_h = row_visible_h * 0.6f;
			const int active_idx = s.active_tab.load();
			float row_top;
			if (s.tab_rows_captured && active_idx >= 0 && active_idx < tab_count) {
				row_top = s.tab_row_screen_y[static_cast<std::size_t>(active_idx)];
			} else {
				const ImGuiStyle& style = ImGui::GetStyle();
				const float row_stride = row_h + style.ItemSpacing.y + 2.f + style.ItemSpacing.y;
				row_top = wp.y + 8.f + style.ItemSpacing.y + static_cast<float>(active_idx) * row_stride;
			}
			float target_y = row_top + (row_visible_h - indicator_h) * 0.5f;
			float target_h = indicator_h;
			(void)content_y;

			s.tab_underline_target_y = target_y;
			s.tab_underline_target_h = target_h;

			if (s.tab_underline_h <= 0.001f) {
				s.tab_underline_y = target_y;
				s.tab_underline_h = target_h;
			} else {
				s.tab_underline_y = aida::motion::spring_step(s.tab_underline_y,
					s.tab_underline_target_y, s.tab_underline_vel_y,
					aida::motion::spring::balanced, dt);
				s.tab_underline_h = aida::motion::spring_step(s.tab_underline_h,
					s.tab_underline_target_h, s.tab_underline_vel_h,
					aida::motion::spring::balanced, dt);
			}

			float bx = wp.x + 2.f;
			ui_anim::render_tab_underline_glow_vertical(dl, bx, s.tab_underline_y,
				s.tab_underline_h, 1.f);
			(void)side_w;
		}

		inline void render_compact_tab_row(float row_w, float row_h, float dt)
		{
			auto& s = state();
			const auto& th = aida::ui::resolved();
			static const char* tab_labels[tab_count] = {
				"Accounts",
				"Agents",
				"Skills",
				"MCP Servers",
				"Editor"
			};
			const float gap = 4.f;
			const float btn_w = (std::max)(32.f, (row_w - gap * (tab_count - 1)) / static_cast<float>(tab_count));
			const float base_fs = aida::ui::components::detail::ui_fs();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 p = ImGui::GetCursorScreenPos();
			const int active = s.active_tab.load();
			for (int i = 0; i < tab_count; ++i) {
				const std::size_t tab_idx = static_cast<std::size_t>(i);
				ImGui::PushID(1000 + i);
				ImGui::SetCursorScreenPos(ImVec2(p.x + (btn_w + gap) * static_cast<float>(i), p.y));
				ImGui::InvisibleButton("##compact_settings_tab", ImVec2(btn_w, row_h));
				const bool hov = ImGui::IsItemHovered();
				if (hov)
					aida::ui::components::tooltip_blur(tab_labels[tab_idx], 0.35f);
				if (ImGui::IsItemClicked()) {
					int prev = s.active_tab.exchange(i);
					if (prev != i) {
						s.previous_tab.store(prev);
						s.tab_crossfade_progress = 0.f;
						s.tab_crossfade_from = prev;
					}
				}
				ImGui::PopID();
				ImVec2 a(p.x + (btn_w + gap) * static_cast<float>(i), p.y);
				ImVec2 b(a.x + btn_w, a.y + row_h - 4.f);
				ImU32 bg = (active == i)
					? aida::ui::with_alpha(th.selection, 0.88f)
					: (hov ? th.hover_wash : aida::ui::with_alpha(th.panel_header, 0.55f));
				dl->AddRectFilled(a, b, bg, 7.f);
				dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, active == i ? 0.9f : 0.45f), 7.f);
				draw_tab_glyph(dl, ImVec2((a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f),
					base_fs * 0.70f, i, active == i ? th.text_primary : th.text_secondary);
			}
			ImGui::SetCursorScreenPos(ImVec2(p.x, p.y + row_h));
			(void)dt;
		}


		inline void render_tab_accounts(float content_w, float content_h)
		{
			aida::auth_view::render(content_w, content_h);
		}


		inline void render_tab_agents(float content_w, float content_h)
		{
			const auto& th = aida::ui::resolved();
			ImGui::Dummy(ImVec2(0.f, (std::max)(20.f, content_h * 0.18f)));
			ImGui::SetCursorPosX((std::max)(0.f, (content_w - 360.f) * 0.5f));
			ImGui::BeginGroup();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary), "Agents are an independent IDE view");
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary),
				"Dock, float, close, and reopen the Agents view without duplicating its renderer in Settings.");
			if (aida::ui::button("Open Agents", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::md, ImVec2(140.f, 36.f)))
				(void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("view.ai.agents"));
			ImGui::EndGroup();
		}


		inline void render_tab_skills(float content_w, float content_h)
		{
			const auto& th = aida::ui::resolved();
			ImGui::Dummy(ImVec2(0.f, (std::max)(20.f, content_h * 0.18f)));
			ImGui::SetCursorPosX((std::max)(0.f, (content_w - 360.f) * 0.5f));
			ImGui::BeginGroup();
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary), "Skills are an independent IDE view");
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary),
				"Manage installed and remote skills in one dockable owner with no duplicate Settings renderer.");
			if (aida::ui::button("Open Skills", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::md, ImVec2(140.f, 36.f)))
				(void)aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("view.ai.skills"));
			ImGui::EndGroup();
		}


		inline std::string trim_copy(const std::string& v)
		{
			size_t first = 0;
			while (first < v.size() && std::isspace(static_cast<unsigned char>(v[first]))) ++first;
			size_t last = v.size();
			while (last > first && std::isspace(static_cast<unsigned char>(v[last - 1]))) --last;
			return v.substr(first, last - first);
		}


		inline bool parse_mcp_args(const std::string& text, std::vector<std::string>& out,
			std::string& error)
		{
			out.clear();
			error.clear();
			std::string cur;
			bool in_quote = false;
			char quote_char = 0;
			bool escaped = false;
			for (char c : text) {
				if (escaped) {
					cur.push_back(c);
					escaped = false;
					continue;
				}
				if (in_quote) {
					if (c == '\\') {
						escaped = true;
					} else if (c == quote_char) {
						in_quote = false;
						quote_char = 0;
					} else {
						cur.push_back(c);
					}
					continue;
				}
				if (c == '"' || c == '\'') {
					in_quote = true;
					quote_char = c;
					continue;
				}
				if (std::isspace(static_cast<unsigned char>(c))) {
					if (!cur.empty()) {
						out.push_back(cur);
						cur.clear();
					}
					continue;
				}
				cur.push_back(c);
			}
			if (escaped)
				cur.push_back('\\');
			if (in_quote) {
				error = "Unclosed quote in args";
				return false;
			}
			if (!cur.empty())
				out.push_back(cur);
			return true;
		}


		inline std::string quote_argv_preview(const std::string& arg)
		{
			if (arg.empty())
				return "\"\"";
			bool quote = false;
			for (char c : arg) {
				if (std::isspace(static_cast<unsigned char>(c)) || c == '"' || c == '\'') {
					quote = true;
					break;
				}
			}
			if (!quote)
				return arg;
			std::string out = "\"";
			for (char c : arg) {
				if (c == '"')
					out += "\\\"";
				else
					out.push_back(c);
			}
			out.push_back('"');
			return out;
		}


		inline std::string make_argv_preview(const std::string& command,
			const std::vector<std::string>& args)
		{
			std::string out = quote_argv_preview(command);
			for (const auto& arg : args) {
				out.push_back(' ');
				out += quote_argv_preview(arg);
			}
			return out;
		}


		inline bool build_mcp_client_config(const mcp_client_server_t& srv,
			mcp_client::server_config_t& cfg,
			std::string& error)
		{
			error.clear();
			cfg = {};
			cfg.name = trim_copy(srv.name);
			cfg.url = trim_copy(srv.url);
			cfg.api_key = srv.api_key;
			cfg.enabled = srv.enabled;
			cfg.auto_connect = srv.enabled && srv.auto_connect;
			if (cfg.name.empty()) {
				error = "Server name is required";
				return false;
			}
			if (srv.transport == "stdio") {
				cfg.transport = mcp_client::transport_type_t::stdio;
				cfg.command = trim_copy(srv.command);
				if (cfg.command.empty()) {
					error = "Stdio command is required for " + cfg.name;
					return false;
				}
				if (!parse_mcp_args(srv.args, cfg.args, error)) {
					error = cfg.name + ": " + error;
					return false;
				}
			} else {
				cfg.transport = mcp_client::transport_type_t::http_sse;
				if (cfg.url.empty()) {
					error = "URL is required for " + cfg.name;
					return false;
				}
			}
			return true;
		}


		inline mcp_client::connection_state_t status_for_server(
			const std::vector<mcp_client::manager_t::server_status_t>& statuses,
			const std::string& name)
		{
			for (const auto& st : statuses)
				if (st.name == name)
					return st.state;
			return mcp_client::connection_state_t::disconnected;
		}


		inline const char* connection_label(mcp_client::connection_state_t st)
		{
			switch (st) {
			case mcp_client::connection_state_t::connected: return "Connected";
			case mcp_client::connection_state_t::connecting: return "Connecting";
			case mcp_client::connection_state_t::reconnecting: return "Reconnecting";
			case mcp_client::connection_state_t::error: return "Error";
			default: return "Disconnected";
			}
		}


		inline aida::ui::pill_kind_t connection_pill_kind(mcp_client::connection_state_t st)
		{
			switch (st) {
			case mcp_client::connection_state_t::connected: return aida::ui::pill_kind_t::success;
			case mcp_client::connection_state_t::connecting:
			case mcp_client::connection_state_t::reconnecting: return aida::ui::pill_kind_t::warning;
			case mcp_client::connection_state_t::error: return aida::ui::pill_kind_t::error;
			default: return aida::ui::pill_kind_t::neutral;
			}
		}


		inline void render_marketplace_server_review(
			mcp_client::manager_t& mgr,
			const std::vector<mcp_client::manager_t::server_status_t>& statuses)
		{
			const auto& th = aida::ui::resolved();
			auto installed = ::mcp_marketplace::get_installed();
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary),
				"Marketplace Installed");
			ImGui::TextWrapped("%s",
				"Installed marketplace servers stay disabled until explicitly enabled here. Connecting starts local third-party MCP code and exposes any tools it registers.");
			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (installed.empty()) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
					"No marketplace servers installed.");
				return;
			}

			for (auto srv : installed) {
				ImGui::PushID(srv.package_name.c_str());
				ImGui::BeginGroup();
				const float group_w = (std::max)(96.f, ImGui::GetContentRegionAvail().x);
				auto calc_label_w = [](const char* label, float pad) {
					return ImGui::CalcTextSize(label ? label : "").x + pad;
				};
				auto place_wrapped = [&](float& used, bool& first, float width) {
					const float gap = 8.f;
					width = (std::min)(width, group_w);
					if (first) {
						first = false;
						used = width;
						return;
					}
					if (used + gap + width <= group_w) {
						ImGui::SameLine(0.f, gap);
						used += gap + width;
					} else {
						used = width;
					}
				};

				ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + group_w);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary),
					"%s", srv.package_name.c_str());
				ImGui::PopTextWrapPos();

				float badge_used = 0.f;
				bool badge_first = true;
				const std::string registry = ::mcp_marketplace::registry_label(srv.registry);
				place_wrapped(badge_used, badge_first, calc_label_w(registry.c_str(), 20.f));
				aida::ui::components::badge(registry.c_str(),
					aida::ui::with_alpha(th.info, 0.9f), 4.f);
				if (!srv.version.empty()) {
					place_wrapped(badge_used, badge_first, calc_label_w(srv.version.c_str(), 20.f));
					aida::ui::components::badge(srv.version.c_str(),
						aida::ui::with_alpha(th.text_secondary, 0.9f), 4.f);
				}
				const char* enabled_label = srv.enabled ? "Enabled" : "Disabled";
				place_wrapped(badge_used, badge_first, calc_label_w(enabled_label, 34.f));
				aida::ui::pill_kind(srv.enabled ? "Enabled" : "Disabled",
					srv.enabled ? aida::ui::pill_kind_t::warning : aida::ui::pill_kind_t::neutral,
					aida::ui::size_t_::sm, false);
				if (srv.auto_connect) {
					place_wrapped(badge_used, badge_first, calc_label_w("Auto-connect", 34.f));
					aida::ui::pill_kind("Auto-connect", aida::ui::pill_kind_t::warning,
						aida::ui::size_t_::sm, false);
				}
				mcp_client::connection_state_t st = status_for_server(statuses, srv.package_name);
				place_wrapped(badge_used, badge_first, calc_label_w(connection_label(st), 34.f));
				aida::ui::pill_kind(connection_label(st), connection_pill_kind(st),
					aida::ui::size_t_::sm, false);

				ImGui::Dummy(ImVec2(0.f, 5.f));
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary),
					"Launch command");
				std::string launch = ::mcp_marketplace::launch_command_preview(srv);
				ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
				const float code_fs = aida::ui::fonts::size_or(code_font, ImGui::GetFontSize());
				const float command_w = (std::max)(72.f, group_w - 16.f);
				ImVec2 command_sz = code_font->CalcTextSizeA(code_fs, FLT_MAX, command_w,
					launch.c_str());
				const float command_h = (std::min)(92.f, (std::max)(38.f, command_sz.y + 16.f));
				ImGui::PushStyleColor(ImGuiCol_ChildBg,
					ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_header, 0.42f)));
				ImGui::BeginChild("##market_launch_cmd", ImVec2(0.f, command_h), true,
					ImGuiWindowFlags_NoSavedSettings);
				ImGui::PushFont(code_font);
				ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
					(std::max)(64.f, ImGui::GetContentRegionAvail().x - 4.f));
				ImGui::TextWrapped("%s", launch.c_str());
				ImGui::PopTextWrapPos();
				ImGui::PopFont();
				ImGui::EndChild();
				ImGui::PopStyleColor();
				ImGui::Dummy(ImVec2(0.f, 5.f));

				const bool connected = st == mcp_client::connection_state_t::connected;
				float action_used = 0.f;
				bool action_first = true;
				auto action_w = [&](float preferred) {
					return (std::min)(preferred, (std::max)(72.f, group_w));
				};
				if (!srv.enabled) {
					const float bw = action_w(84.f);
					place_wrapped(action_used, action_first, bw);
					if (aida::ui::button("Enable",
							aida::ui::button_kind_t::primary,
							aida::ui::size_t_::sm,
							ImVec2(bw, 28.f))) {
						if (::mcp_marketplace::set_server_policy(srv.package_name, true, false))
							toast_notification::push("Marketplace server enabled with auto-connect off.",
								toast_notification::toast_type_t::info);
					}
				} else {
					const float disable_w = action_w(84.f);
					place_wrapped(action_used, action_first, disable_w);
					if (aida::ui::button("Disable",
							aida::ui::button_kind_t::destructive,
							aida::ui::size_t_::sm,
							ImVec2(disable_w, 28.f))) {
						if (::mcp_marketplace::set_server_policy(srv.package_name, false, false))
							toast_notification::push("Marketplace server disabled.",
								toast_notification::toast_type_t::info);
					}
					if (connected) {
						const float bw = action_w(104.f);
						place_wrapped(action_used, action_first, bw);
						if (aida::ui::button("Disconnect",
								aida::ui::button_kind_t::secondary,
								aida::ui::size_t_::sm,
								ImVec2(bw, 28.f))) {
							::mcp_marketplace::deactivate_server(srv.package_name);
						}
					} else {
						const float bw = action_w(92.f);
						place_wrapped(action_used, action_first, bw);
						if (aida::ui::button("Connect",
								aida::ui::button_kind_t::primary,
								aida::ui::size_t_::sm,
								ImVec2(bw, 28.f))) {
							::mcp_marketplace::activate_server(srv);
						}
					}
					const float auto_w = action_w(90.f);
					place_wrapped(action_used, action_first, auto_w);
					if (aida::ui::button(srv.auto_connect ? "Auto off" : "Auto on",
							aida::ui::button_kind_t::secondary,
							aida::ui::size_t_::sm,
							ImVec2(auto_w, 28.f))) {
						if (::mcp_marketplace::set_server_policy(
								srv.package_name, true, !srv.auto_connect)) {
							toast_notification::push(
								srv.auto_connect ? "Marketplace auto-connect disabled."
								                 : "Marketplace auto-connect enabled.",
								toast_notification::toast_type_t::info);
						}
					}
				}
				ImGui::EndGroup();
				ImGui::Dummy(ImVec2(0.f, 8.f));
				ImGui::Separator();
				ImGui::PopID();
			}
			(void)mgr;
		}


		inline void render_tab_mcp_servers(float content_w, float content_h)
		{
			auto& s = state();
			const auto& th = aida::ui::resolved();
			const float dt = aida::ui::clock::dt();
			ImGui::PushID("##mcp_settings_tab");
			ImGui::PushFont(aida::ui::fonts::lg());
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.f, 8.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 7.f));

			const ImVec2 mcp_tab_origin = ImGui::GetCursorScreenPos();

			{
				ImDrawList* hdl = ImGui::GetWindowDrawList();
				ImVec2 hp = ImGui::GetCursorScreenPos();
				hdl->AddText(aida::ui::fonts::h1(), 22.f, ImVec2(hp.x + 12.f, hp.y + 2.f),
					th.text_primary, "External MCP Servers");
				hdl->AddText(aida::ui::fonts::caption(), 13.f, ImVec2(hp.x + 12.f, hp.y + 30.f),
					th.text_dim, content_w < 520.f
						? "Configure servers and marketplace packages."
						: "Configure trusted external servers and review installed marketplace packages.");
				ImGui::Dummy(ImVec2(0.f, 52.f));
			}

			static int s_sel_index = 0;
			static char s_name[160] = {};
			static char s_url[512] = {};
			static char s_key[512] = {};
			static char s_cmd[512] = {};
			static char s_args[512] = {};
			static int  s_transport = 0;
			static bool s_enabled = true;
			static bool s_auto = true;
			static bool s_draft_loaded = false;
			static bool s_dirty = false;
			static std::vector<mcp_client_server_t> s_draft_servers;
			static int s_remove_index = -1;

			auto& mgr = get_mcp_client_manager();
			auto statuses = mgr.get_status();
			auto& servers = s_draft_servers;

			auto refresh_buf = [&]() {
				if (servers.empty()) {
					s_sel_index = -1;
					s_name[0] = s_url[0] = s_key[0] = s_cmd[0] = s_args[0] = '\0';
					s_transport = 0;
					s_enabled = false;
					s_auto = false;
					return;
				}
				if (s_sel_index < 0) s_sel_index = 0;
				if (s_sel_index >= static_cast<int>(servers.size()))
					s_sel_index = static_cast<int>(servers.size()) - 1;
				const auto& srv = servers[static_cast<std::size_t>(s_sel_index)];
				std::snprintf(s_name, sizeof(s_name), "%s", srv.name.c_str());
				std::snprintf(s_url,  sizeof(s_url),  "%s", srv.url.c_str());
				std::snprintf(s_key,  sizeof(s_key),  "%s", srv.api_key.c_str());
				std::snprintf(s_cmd,  sizeof(s_cmd),  "%s", srv.command.c_str());
				std::snprintf(s_args, sizeof(s_args), "%s", srv.args.c_str());
				s_transport = (srv.transport == "stdio") ? 1 : 0;
				s_enabled = srv.enabled;
				s_auto    = srv.enabled && srv.auto_connect;
			};

			auto load_draft = [&]() {
				s_draft_servers = g_sa_settings.mcp_client_servers;
				if (s_draft_servers.empty()) s_sel_index = -1;
				else if (s_sel_index < 0 || s_sel_index >= static_cast<int>(s_draft_servers.size()))
					s_sel_index = 0;
				refresh_buf();
				s_dirty = false;
				s_draft_loaded = true;
			};

			auto commit_buf = [&]() {
				if (s_sel_index < 0 || s_sel_index >= static_cast<int>(servers.size()))
					return;
				auto& srv = servers[static_cast<std::size_t>(s_sel_index)];
				srv.name = s_name;
				srv.url = s_url;
				srv.api_key = s_key;
				srv.command = s_cmd;
				srv.args = s_args;
				srv.transport = (s_transport == 1) ? "stdio" : "http_sse";
				srv.enabled = s_enabled;
				srv.auto_connect = s_enabled && s_auto;
			};

			if (!s_draft_loaded)
				load_draft();

			float avail_w = ImGui::GetContentRegionAvail().x;
			if (avail_w < 320.f) {
				aida::ui::responsive::draw_clamp_overlay(mcp_tab_origin,
					ImVec2(content_w, content_h), "Widen Settings to edit MCP servers");
				ImGui::PopStyleVar(2);
				ImGui::PopFont();
				ImGui::PopID();
				return;
			}
			float left_w = 280.f;
			float min_detail_w = 260.f;
			bool stack_vertical = (avail_w - left_w - 8.f) < min_detail_w;
			float row_h  = 58.f;
			float list_h_horiz = (std::max)(content_h - 170.f, 240.f);
			float list_h = stack_vertical
				? std::clamp(content_h * 0.22f, 150.f, 210.f)
				: list_h_horiz;
			if (stack_vertical) {
				left_w = (std::max)(avail_w - 8.f, 200.f);
			}

			static bool s_mcp_logged_stack = false;
			if (stack_vertical && !s_mcp_logged_stack) {
				s_mcp_logged_stack = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
				::diag::log_tagged_fmt("responsive",
					"settings_overlay mcp panel stacked avail_w=%.0f min_detail_w=%.0f",
					avail_w, min_detail_w);
#endif
			} else if (!stack_vertical && s_mcp_logged_stack) {
				s_mcp_logged_stack = false;
			}

			ImGui::PushStyleColor(ImGuiCol_ChildBg,
				ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_header, 0.22f)));
			ImGui::PushStyleColor(ImGuiCol_Border,
				ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.border_subtle, 0.85f)));
			ImGui::BeginChild("##mcp_list", ImVec2(left_w, list_h), true,
				ImGuiWindowFlags_NoSavedSettings);

			ImDrawList* dl = ImGui::GetWindowDrawList();
			if (servers.empty()) {
				ImVec2 region_pos = ImGui::GetCursorScreenPos();
				ImVec2 region_size(ImGui::GetContentRegionAvail().x,
					(std::max)(80.f, ImGui::GetContentRegionAvail().y));
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::network;
				cfg.title = "No configured servers";
				cfg.body = "Add a server below or install one from the marketplace.";
				cfg.max_width = region_size.x * 0.82f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
			}

			for (int i = 0; i < static_cast<int>(servers.size()); ++i) {
				ImGui::PushID(i);
				const auto& srv = servers[static_cast<std::size_t>(i)];

				mcp_client::oauth_status_t oauth = mcp_client::auth_status(srv.name);
				mcp_client::connection_state_t cstate = mcp_client::connection_state_t::disconnected;
				for (const auto& stt : statuses) {
					if (stt.name == srv.name) { cstate = stt.state; break; }
				}

				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x - 4.f;
				bool selected = (i == s_sel_index);

				ImGui::SetNextItemAllowOverlap();
				ImGui::InvisibleButton("##row_hit", ImVec2(row_w, row_h));
				bool hovered = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked();

				auto& hov_state = s.mcp_row_anims[srv.name];
				float hov_v = hov_state.tick(hovered, dt, aida::motion::spring::playful);
				float lift = hov_v * 1.5f;

				ImVec2 a(cp.x, cp.y - lift);
				ImVec2 b(cp.x + row_w, cp.y + row_h - 4.f - lift);

				ImU32 bg = aida::ui::mix(
					aida::ui::with_alpha(th.panel_header, 0.4f),
					aida::ui::with_alpha(th.hover_wash, 1.f),
					hov_v * 0.7f);
				if (selected) {
					bg = aida::ui::mix(bg,
						aida::ui::with_alpha(th.selection, 0.85f), 0.55f);
				}
				dl->AddRectFilled(a, b, bg, 8.f);
				if (selected) {
					dl->AddRect(a, b, th.accent_u32, 8.f, 0, 1.5f);
				} else {
					dl->AddRect(a, b,
						aida::ui::with_alpha(th.border_subtle, 0.5f + 0.4f * hov_v),
						8.f, 0, 1.f);
				}

				ImU32 dot_col = th.text_dim;
				bool pulsing = false;
				switch (cstate) {
				case mcp_client::connection_state_t::connected:    dot_col = th.success; pulsing = true; break;
				case mcp_client::connection_state_t::connecting:
				case mcp_client::connection_state_t::reconnecting: dot_col = th.warning; pulsing = true; break;
				case mcp_client::connection_state_t::error:        dot_col = th.error;   pulsing = true; break;
				default: break;
				}
				aida::ui::status_dot(ImVec2(a.x + 14.f, (a.y + b.y) * 0.5f),
					4.5f, dot_col, pulsing, 1.4f);

				dl->AddText(aida::ui::fonts::body_strong(),
					aida::ui::components::detail::ui_fs() * 1.05f,
					ImVec2(a.x + 32.f, a.y + 8.f), th.text_primary, srv.name.c_str());

				ImGui::SetCursorScreenPos(ImVec2(a.x + 32.f, a.y + 30.f));
				aida::ui::pill_kind(oauth_pill_label(oauth), oauth_pill_kind(oauth),
					aida::ui::size_t_::md, false);

				if (clicked && i != s_sel_index) {
					if (s_dirty) {
						toast_notification::push("Apply or discard MCP server changes before switching.",
							toast_notification::toast_type_t::warning);
					} else {
						s_sel_index = i;
						refresh_buf();
					}
				}

				if (oauth == mcp_client::oauth_status_t::needs_auth ||
					oauth == mcp_client::oauth_status_t::needs_client_registration ||
					oauth == mcp_client::oauth_status_t::failed ||
					oauth == mcp_client::oauth_status_t::authenticating)
				{
					float btn_x = b.x - 96.f;
					float btn_y = a.y + (row_h - 4.f - 28.f) * 0.5f;
					ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
					const bool authenticating = oauth == mcp_client::oauth_status_t::authenticating;
					if (aida::ui::button(authenticating ? "Cancel" : "Sign in",
							aida::ui::button_kind_t::primary,
							aida::ui::size_t_::md,
							ImVec2(88.f, 28.f))) {
						std::string srv_name = srv.name;
						if (authenticating) {
							cancel_mcp_oauth_generation(srv_name);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
							const bool cancelled = true;
#else
							const bool cancelled = mcp_client::cancel_auth(srv_name);
#endif
							if (cancelled) {
								toast_notification::push(std::string("MCP auth ") + srv_name + ": cancelled",
									toast_notification::toast_type_t::info);
							} else {
								toast_notification::push(std::string("MCP auth ") + srv_name + ": "
									+ mcp_client::last_error(), toast_notification::toast_type_t::error);
							}
						} else {
							const std::uint64_t generation = begin_mcp_oauth_generation(srv_name);
							if (generation == 0) {
								toast_notification::push(std::string("MCP auth ") + srv_name
									+ ": UI authorization generation exhausted; restart is required",
									toast_notification::toast_type_t::error);
							} else {
								const bool accepted = mcp_client::trigger_auth_flow(srv_name,
									[generation](const std::string& nm, mcp_client::oauth_status_t final_status,
										const std::string& err) {
										if (!complete_mcp_oauth_generation(nm, generation))
											return;
										if (!err.empty())
											toast_notification::push(std::string("MCP auth ") + nm + ": " + err,
												toast_notification::toast_type_t::error);
										else if (final_status == mcp_client::oauth_status_t::authenticated)
											toast_notification::push(std::string("MCP auth ") + nm + ": OK",
												toast_notification::toast_type_t::info);
									});
								if (!accepted && complete_mcp_oauth_generation(srv_name, generation)) {
									toast_notification::push(std::string("MCP auth ") + srv_name + ": "
										+ mcp_client::last_error(), toast_notification::toast_type_t::error);
								}
							}
						}
					}
				}

				ImGui::PopID();
				ImGui::Dummy(ImVec2(row_w, 0.f));
			}

			ImGui::Dummy(ImVec2(0.f, 0.f));
			ImGui::EndChild();

			const float footer_avail = ImGui::GetContentRegionAvail().x;
			const float btn_sep = 8.f;
			const bool btn_narrow = footer_avail < 440.f;
			const char* lbl_add    = "+ Add Server";
			const char* lbl_apply  = btn_narrow ? "Apply" : "Apply Changes";
			const char* lbl_discard = btn_narrow ? "Discard" : "Discard Draft";
			const char* lbl_remove = btn_narrow ? "Remove" : "Remove Selected";
			const char* lbl_market = btn_narrow ? "Market..." : "Marketplace...";

			ImFont* mcp_btn_font = ImGui::GetFont();
			const float mcp_btn_fs = aida::ui::components::detail::ui_fs();
			auto mcp_bw = [&](const char* lbl) -> float {
				float tw = mcp_btn_font->CalcTextSizeA(mcp_btn_fs, FLT_MAX, 0.f, lbl).x;
				return tw + 24.f;
			};
			const float w_add    = std::max(mcp_bw(lbl_add), 90.f);
			const float w_apply  = std::max(mcp_bw(lbl_apply), 90.f);
			const float w_discard = std::max(mcp_bw(lbl_discard), 90.f);
			const float w_remove = std::max(mcp_bw(lbl_remove), 90.f);
			const float w_market = std::max(mcp_bw(lbl_market), 90.f);
			const float btn_total_w = w_add + w_apply + w_discard + w_remove + w_market + btn_sep * 4.f;
			const bool btn_wrap = (footer_avail < btn_total_w);

			int btn_rows = 1;
			{
				float cx = 0.f;
				int rows = 1;
				auto adv = [&](float w) {
					if (cx <= 0.f) { cx = w; return; }
					if (btn_wrap && (cx + btn_sep + w) > footer_avail) { cx = w; ++rows; }
					else cx += btn_sep + w;
				};
				adv(w_add); adv(w_apply); adv(w_discard); adv(w_remove); adv(w_market);
				btn_rows = rows;
			}
			const float footer_h = static_cast<float>(btn_rows) * 36.f +
				static_cast<float>(btn_rows - 1) * btn_sep + 12.f + 6.f;

			float detail_h;
			if (stack_vertical) {
				detail_h = (std::max)(content_h - 52.f - list_h - footer_h - 28.f, 240.f);
			} else {
				detail_h = list_h;
				ImGui::SameLine();
			}
			ImGui::BeginChild("##mcp_detail", ImVec2(0.f, detail_h), true,
				ImGuiWindowFlags_NoSavedSettings);

			ImDrawList* ddl = ImGui::GetWindowDrawList();
			ImVec2 dp = ImGui::GetCursorScreenPos();
			ddl->AddText(aida::ui::fonts::body_strong(),
				aida::ui::components::detail::ui_fs() * 1.25f,
				ImVec2(dp.x + 8.f, dp.y + 4.f),
				th.text_primary, "Server Configuration");
			ImGui::Dummy(ImVec2(0.f, 30.f));
			if (s_dirty) {
				aida::ui::pill_kind("Unsaved changes", aida::ui::pill_kind_t::warning,
					aida::ui::size_t_::sm, false);
				if (ImGui::GetContentRegionAvail().x >= 300.f)
					ImGui::SameLine(0.f, 8.f);
				ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + (std::max)(80.f, ImGui::GetContentRegionAvail().x - 8.f));
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
					"Apply reconnects configured MCP clients.");
				ImGui::PopTextWrapPos();
			} else {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
					"Edits are staged until Apply.");
			}
			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size())) {
				bool field_changed = false;
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Name");
				field_changed |= aida::ui::input_text("##mcp_name", s_name, sizeof(s_name),
					"Server name", false, ImVec2(0.f, 36.f));

				ImGui::Dummy(ImVec2(0.f, 4.f));
				const char* transports[] = { "HTTP/SSE", "Stdio" };
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Transport");
				ImGui::SetNextItemWidth(-12.f);
				if (ImGui::Combo("##mcp_transport", &s_transport, transports, 2))
					field_changed = true;

				if (s_transport == 0) {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "URL");
					field_changed |= aida::ui::input_text("##mcp_url", s_url, sizeof(s_url),
						"https://server", false, ImVec2(0.f, 36.f));
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "API Key");
					field_changed |= aida::ui::input_text("##mcp_key", s_key, sizeof(s_key),
						"secret", true, ImVec2(0.f, 36.f));
				} else {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Command");
					field_changed |= aida::ui::input_text("##mcp_cmd", s_cmd, sizeof(s_cmd),
						"node server.js", false, ImVec2(0.f, 36.f));
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Args");
					field_changed |= aida::ui::input_text("##mcp_args", s_args, sizeof(s_args),
						"--port 3001", false, ImVec2(0.f, 36.f));
					std::vector<std::string> parsed_args;
					std::string parse_error;
					const bool args_ok = parse_mcp_args(s_args, parsed_args, parse_error);
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(args_ok ? th.text_secondary : th.error),
						"%s", args_ok ? "Argv preview" : parse_error.c_str());
					if (args_ok) {
						ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - 8.f);
						ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
							"%s", make_argv_preview(s_cmd, parsed_args).c_str());
						ImGui::PopTextWrapPos();
					}
				}

				ImGui::Dummy(ImVec2(0.f, 6.f));
				field_changed |= aida::ui::toggle_switch("Enabled##mcp", &s_enabled, aida::ui::size_t_::md);
				if (ImGui::GetContentRegionAvail().x >= 230.f)
					ImGui::SameLine(140.f);
				field_changed |= aida::ui::toggle_switch("Auto-connect", &s_auto, aida::ui::size_t_::md);
				if (!s_enabled && s_auto) {
					s_auto = false;
					field_changed = true;
				}
				if (field_changed)
					s_dirty = true;

				ImGui::Dummy(ImVec2(0.f, 8.f));
				const bool actions_disabled = s_dirty || !s_enabled;
				const bool stack_conn_actions = ImGui::GetContentRegionAvail().x < 230.f;
				if (aida::ui::button("Reconnect",
						aida::ui::button_kind_t::secondary,
						aida::ui::size_t_::sm,
						ImVec2(98.f, 28.f),
						actions_disabled)) {
					commit_buf();
					mcp_client::server_config_t cfg;
					std::string err;
					if (build_mcp_client_config(servers[static_cast<std::size_t>(s_sel_index)], cfg, err)) {
						mgr.add_server(cfg);
						mgr.disconnect_server(cfg.name);
						mgr.connect_server(cfg.name);
					} else {
						toast_notification::push(err, toast_notification::toast_type_t::error);
					}
				}
				if (!stack_conn_actions)
					ImGui::SameLine(0.f, 8.f);
				if (aida::ui::button("Disconnect",
						aida::ui::button_kind_t::secondary,
						aida::ui::size_t_::sm,
						ImVec2(104.f, 28.f),
						s_dirty)) {
					mgr.disconnect_server(servers[static_cast<std::size_t>(s_sel_index)].name);
				}
			} else {
				ImVec2 region_pos = ImGui::GetCursorScreenPos();
				const float empty_h = (std::min)(180.f,
					(std::max)(120.f, ImGui::GetContentRegionAvail().y * 0.30f));
				ImVec2 region_size(ImGui::GetContentRegionAvail().x, empty_h);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::network;
				cfg.title = "No server selected";
				cfg.body = "Pick a server on the left or add a new one to configure it.";
				cfg.max_width = region_size.x * 0.8f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
				ImGui::SetCursorScreenPos(ImVec2(region_pos.x, region_pos.y + empty_h));
				ImGui::Dummy(ImVec2(0.f, 0.f));
			}

			ImGui::Dummy(ImVec2(0.f, 10.f));
			render_marketplace_server_review(mgr, statuses);

			ImGui::EndChild();
			ImGui::PopStyleColor(2);

			ImGui::Dummy(ImVec2(0.f, 12.f));

			float btn_cursor_x = 0.f;
			auto place_button = [&](float bw) -> bool {
				if (btn_cursor_x <= 0.f) {
					btn_cursor_x = bw;
					return false;
				}
				if (btn_wrap && (btn_cursor_x + btn_sep + bw) > footer_avail) {
					btn_cursor_x = bw;
					return false;
				}
				btn_cursor_x += btn_sep + bw;
				return true;
			};

			if (place_button(w_add)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_add,
					aida::ui::button_kind_t::primary,
					aida::ui::size_t_::md,
					ImVec2(w_add, 36.f))) {
				commit_buf();
				mcp_client_server_t srv;
				std::string base = "New Server";
				std::string candidate = base;
				int suffix = 2;
				bool unique = false;
				while (!unique) {
					unique = true;
					for (const auto& existing : servers) {
						if (existing.name == candidate) {
							unique = false;
							candidate = base + " " + std::to_string(suffix++);
							break;
						}
					}
				}
				srv.name = candidate;
				srv.url = "http://localhost:3001";
				srv.enabled = false;
				srv.auto_connect = false;
				servers.push_back(srv);
				s_sel_index = static_cast<int>(servers.size()) - 1;
				refresh_buf();
				s_dirty = true;
			}
			if (place_button(w_apply)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_apply,
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(w_apply, 36.f),
					!s_dirty)) {
				commit_buf();
				bool ok = true;
				std::string apply_error;
				std::vector<mcp_client::server_config_t> configs;
				configs.reserve(servers.size());
				std::unordered_map<std::string, int> seen_names;
				for (const auto& srv : servers) {
					mcp_client::server_config_t cfg;
					if (!build_mcp_client_config(srv, cfg, apply_error)) {
						ok = false;
						break;
					}
					if (++seen_names[cfg.name] > 1) {
						apply_error = "Duplicate MCP server name: " + cfg.name;
						ok = false;
						break;
					}
					configs.push_back(std::move(cfg));
				}
				if (!ok) {
					toast_notification::push(apply_error, toast_notification::toast_type_t::error);
				} else {
					g_sa_settings.mcp_client_servers = servers;
					mgr.disconnect_all();
					for (const auto& cfg : configs)
						mgr.add_server(cfg);
					mgr.connect_all();
					static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
					s_dirty = false;
					toast_notification::push("MCP server settings applied.",
						toast_notification::toast_type_t::info);
				}
			}
			if (place_button(w_discard)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_discard,
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(w_discard, 36.f),
					!s_dirty)) {
				load_draft();
				toast_notification::push("MCP server draft discarded.",
					toast_notification::toast_type_t::info);
			}
			if (place_button(w_remove)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_remove,
					aida::ui::button_kind_t::destructive,
					aida::ui::size_t_::md,
					ImVec2(w_remove, 36.f)) &&
				s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size()))
			{
				commit_buf();
				s_remove_index = s_sel_index;
				ImGui::OpenPopup("Remove MCP server##mcp_remove_confirm");
			}
			if (place_button(w_market)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_market,
					aida::ui::button_kind_t::accent_gradient,
					aida::ui::size_t_::md,
					ImVec2(w_market, 36.f))) {
				(void)aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("view.ai.mcp_marketplace"));
			}

			if (aida::ui::design::begin_dialog_exact(
					"Remove MCP server##mcp_remove_confirm", ImVec2(480.f, 280.f),
					ImVec2(360.f, 230.f))) {
				std::string remove_name = "selected server";
				const bool remove_current = s_remove_index >= 0 &&
					s_remove_index < static_cast<int>(servers.size());
				if (remove_current)
					remove_name = servers[static_cast<std::size_t>(s_remove_index)].name;
				const float footer_height = aida::ui::design::dialog_footer_reserve_height("Remove");
				aida::ui::design::begin_dialog_body("mcp_remove_confirm_body", footer_height);
				const float modal_wrap_w = (std::min)(420.f, (std::max)(180.f, ImGui::GetContentRegionAvail().x));
				ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + modal_wrap_w);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary),
					"Remove %s?", remove_name.c_str());
				ImGui::TextWrapped("%s",
					"Removal is staged as a draft. Apply Changes will disconnect and remove this server from the MCP client configuration.");
				if (!remove_current)
					ImGui::TextDisabled("The reviewed server no longer exists; cancel and select it again.");
				ImGui::PopTextWrapPos();
				aida::ui::design::end_dialog_body();
				const auto footer = aida::ui::design::dialog_footer(
					"mcp_remove_confirm_footer", "Remove", remove_current, true);
				if (footer.confirmed && remove_current) {
					if (s_remove_index >= 0 && s_remove_index < static_cast<int>(servers.size())) {
						servers.erase(servers.begin() + static_cast<std::ptrdiff_t>(s_remove_index));
						if (servers.empty()) s_sel_index = -1;
						else if (s_remove_index <= s_sel_index && s_sel_index > 0) --s_sel_index;
						refresh_buf();
						s_dirty = true;
					}
					s_remove_index = -1;
					ImGui::CloseCurrentPopup();
				} else if (footer.cancelled) {
					s_remove_index = -1;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			if (footer_avail < 320.f) {
				aida::ui::responsive::draw_clamp_overlay(mcp_tab_origin,
					ImVec2(content_w, content_h), "Settings pane too narrow");
			}

			ImGui::PopStyleVar(2);
			ImGui::PopFont();
			ImGui::PopID();

		}


		inline void render_tab_editor_theme(float content_w, float content_h)
		{
			auto& s = state();
			const auto& th = aida::ui::resolved();
			std::lock_guard<std::mutex> lk(s.mtx);
			load_editor_locked(s);

			ImGui::PushID("##editor_theme_tab");
			ImGui::PushFont(aida::ui::fonts::lg());
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10.f, 10.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 7.f));

			ImGui::BeginChild("##editor_theme_scroll", ImVec2(content_w, content_h), false,
				ImGuiWindowFlags_NoSavedSettings);
			ImDrawList* dl = ImGui::GetWindowDrawList();
			const ImVec2 hp = ImGui::GetCursorScreenPos();
			dl->AddText(aida::ui::fonts::h1(), 22.f, ImVec2(hp.x + 12.f, hp.y + 2.f),
				th.text_primary, "Editor & Appearance");
			dl->AddText(aida::ui::fonts::caption(), 13.f, ImVec2(hp.x + 12.f, hp.y + 30.f),
				th.text_dim, content_w < 520.f
					? "Tune code, disassembly, and workspace appearance."
					: "Tune readability and visual behavior across code and disassembly views.");
			ImGui::Dummy(ImVec2(0.f, 58.f));

			const float pad = 12.f;
			const float gap = 12.f;
			const float avail_w = (std::max)(180.f, content_w - pad * 2.f);
			const bool two_columns = avail_w >= 560.f;
			const float card_w = two_columns ? (avail_w - gap) * 0.5f : avail_w;
			const float field_w = (std::min)(240.f, (std::max)(140.f, card_w - 24.f));
			bool changed = false;

			ImGui::PushStyleColor(ImGuiCol_ChildBg,
				ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.panel_header, 0.22f)));
			ImGui::PushStyleColor(ImGuiCol_Border,
				ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.border_subtle, 0.85f)));
			ImGui::SetCursorPosX(ImGui::GetCursorPosX() + pad);
			ImGui::BeginChild("##editor_code_card", ImVec2(card_w, 184.f), true,
				ImGuiWindowFlags_NoSavedSettings);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary), "Code editor");
			ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + (std::max)(120.f, card_w - 24.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
				"Typography and indentation for source-oriented views.");
			ImGui::PopTextWrapPos();
			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Tab size");
			ImGui::SetNextItemWidth(field_w);
			changed |= ImGui::InputInt("##ed_tab", &s.ed_tab_size, 0, 0);
			s.ed_tab_size = (std::max)(s.ed_tab_size, 1);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Font size");
			ImGui::SetNextItemWidth(field_w);
			changed |= ImGui::SliderFloat("##ed_font", &s.ed_font_size, 9.f, 32.f, "%.0f px");
			ImGui::EndChild();

			if (two_columns)
				ImGui::SameLine(0.f, gap);
			else {
				ImGui::Dummy(ImVec2(0.f, gap));
				ImGui::SetCursorPosX(ImGui::GetCursorPosX() + pad);
			}

			ImGui::BeginChild("##editor_disasm_card", ImVec2(card_w, 184.f), true,
				ImGuiWindowFlags_NoSavedSettings);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary), "Disassembly");
			ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + (std::max)(120.f, card_w - 24.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
				"Control how instruction selection is emphasized while navigating a binary.");
			ImGui::Dummy(ImVec2(0.f, 10.f));
			bool full_line_sel = editor_config::disasm_full_line_select;
			if (ImGui::Checkbox("Highlight the full instruction row##disasm_full_line_sel",
				&full_line_sel)) {
				editor_config::disasm_full_line_select = full_line_sel;
			}
			ImGui::PopTextWrapPos();
			ImGui::EndChild();

			ImGui::Dummy(ImVec2(0.f, gap));
			ImGui::SetCursorPosX(ImGui::GetCursorPosX() + pad);
			const float appearance_card_height = aida::ui::scale_px(
				g_sa_settings.ui_density == 1 ? 312.f : 284.f, aida::ui::dpi_scale());
			ImGui::BeginChild("##editor_theme_card", ImVec2(avail_w, appearance_card_height), true,
				ImGuiWindowFlags_NoSavedSettings);
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_primary), "Appearance");
			ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + (std::max)(120.f, avail_w - 24.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
				"Choose the color system used by the complete AiDA workspace.");
			ImGui::PopTextWrapPos();
			ImGui::Dummy(ImVec2(0.f, 8.f));
			static const char* theme_names[] = { "AiDA Dark", "AiDA Light", "Claude Dark", "Claude Light" };
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Active theme");
			ImGui::SetNextItemWidth((std::min)(280.f, (std::max)(140.f, avail_w - 24.f)));
			int prev_idx = g_sa_settings.active_theme_idx;
			if (ImGui::Combo("##theme_idx", &g_sa_settings.active_theme_idx, theme_names,
				IM_ARRAYSIZE(theme_names))) {
				if (prev_idx != g_sa_settings.active_theme_idx) {
					themes::active = std::clamp(g_sa_settings.active_theme_idx, 0, themes::count - 1);
					themes::changed = true;
					static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
				}
			}
			ImGui::Dummy(ImVec2(0.f, 8.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Interface density");
			static const char* density_names[] = { "Compact", "Comfortable" };
			ImGui::SetNextItemWidth((std::min)(280.f, (std::max)(140.f, avail_w - 24.f)));
			if (ImGui::Combo("##ui_density", &g_sa_settings.ui_density, density_names,
				IM_ARRAYSIZE(density_names))) {
				g_sa_settings.ui_density = g_sa_settings.ui_density == 1 ? 1 : 0;
				aida::ui::design::set_preferences({
					g_sa_settings.ui_density == 1
						? aida::ui::design::density_t::comfortable
						: aida::ui::design::density_t::compact,
					g_sa_settings.ui_reduced_motion
				});
				static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
			}
			if (ImGui::Checkbox("Reduce interface motion##ui_reduced_motion",
				&g_sa_settings.ui_reduced_motion)) {
				aida::ui::design::set_preferences({
					g_sa_settings.ui_density == 1
						? aida::ui::design::density_t::comfortable
						: aida::ui::design::density_t::compact,
					g_sa_settings.ui_reduced_motion
				});
				static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
			}
			aida::ui::design::tooltip_for_last_item(
				"Disable decorative transitions and animated progress where a static equivalent is available",
				nullptr, nullptr);
			if (ImGui::Checkbox("Show frame diagnostics in status bar##ui_diagnostics_mode",
				&g_sa_settings.ui_diagnostics_mode))
				static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
			ImGui::EndChild();
			ImGui::PopStyleColor(2);
			ImGui::EndChild();

			if (changed)
				persist_editor_locked(s);

			ImGui::PopStyleVar(2);
			ImGui::PopFont();
			ImGui::PopID();
		}

	}


	void initialize()
	{
		auto& s = detail::state();
		bool expected = false;
		if (!s.initialized.compare_exchange_strong(expected, true))
			return;
		s.active_tab.store(tab_accounts);
		s.previous_tab.store(tab_accounts);
		s.tab_anim = static_cast<float>(tab_accounts);
		s.tab_crossfade_progress = 1.f;
	}


	void shutdown()
	{
		auto& s = detail::state();
		s.initialized.store(false);
		std::vector<std::string> active_oauth;
		{
			std::lock_guard<std::mutex> lock(s.mcp_oauth_mtx);
			active_oauth.reserve(s.mcp_oauth_generations.size());
			for (const auto& entry : s.mcp_oauth_generations)
				active_oauth.push_back(entry.first);
			s.mcp_oauth_generations.clear();
		}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
		for (const auto& server_name : active_oauth)
			(void)mcp_client::cancel_auth(server_name);
#endif
	}


	void open()
	{
		static_cast<void>(aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("view.settings")));
	}


	void close()
	{
		static_cast<void>(aida::ui::application_views::close(
			aida::ui::stable_view_id_t("view.settings")));
	}


	void toggle()
	{
		if (is_open())
			close();
		else
			open();
	}


	bool is_open()
	{
		return aida::ui::application_views::is_open(
			aida::ui::stable_view_id_t("view.settings"));
	}


	void set_active_tab(tab_index_t tab_index)
	{
		auto& s = detail::state();
		const int idx = static_cast<int>(tab_index);
		if (idx < 0 || idx >= tab_count) return;
		int prev = s.active_tab.exchange(idx);
		if (prev != idx) {
			s.previous_tab.store(prev);
			s.tab_crossfade_progress = 0.f;
			s.tab_crossfade_from = prev;
		}
	}


	tab_index_t active_tab()
	{
		return static_cast<tab_index_t>(detail::state().active_tab.load());
	}


	void open_to_provider(const std::string& provider_id)
	{
		auto& s = detail::state();
		{
			std::lock_guard<std::mutex> lk(s.pending_focus_mtx);
			s.pending_provider_focus = provider_id;
		}
		set_active_tab(tab_accounts);
		open();
	}


	std::string consume_pending_provider_focus()
	{
		auto& s = detail::state();
		std::lock_guard<std::mutex> lk(s.pending_focus_mtx);
		std::string out;
		out.swap(s.pending_provider_focus);
		return out;
	}


	void render_inline(float panel_w, float panel_h)
	{
		auto& s = detail::state();
		const auto& th = aida::ui::resolved();

		const float dt = aida::ui::clock::dt();

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		ImVec2 ws = ImGui::GetWindowSize();

		const float header_h = 38.f;
		ImVec2 hdr_a(wp.x, wp.y);
		ImVec2 hdr_b(wp.x + ws.x, wp.y + header_h);

		aida::ui::blur::layer_request_t br;
		br.pos = hdr_a;
		br.size = ImVec2(ws.x, header_h);
		br.radius = 0.f;
		br.strength = 0.85f;
		br.alpha = 1.f;
		aida::ui::blur::schedule(br);

		dl->AddRectFilled(hdr_a, hdr_b,
			aida::ui::with_alpha(th.title_bar, 0.95f));
		dl->AddLine(ImVec2(hdr_a.x, hdr_b.y), ImVec2(hdr_b.x, hdr_b.y),
			aida::ui::with_alpha(th.border_subtle, 1.f), 1.f);

		ImGui::SetCursorPos(ImVec2(8.f, 6.f));
		if (aida::ui::button("<##settings_back",
				aida::ui::button_kind_t::ghost,
				aida::ui::size_t_::sm,
				ImVec2(28.f, 26.f))) {
			close();
		}
		ImGui::SameLine();
		dl->AddText(aida::ui::fonts::h2(), 16.f,
			ImVec2(wp.x + 44.f, wp.y + 11.f),
			th.text_primary, "Settings");
		const auto persistence = aida::settings_persistence::status();
		const char* persistence_label = persistence.pending ? "Saving settings..." :
			(persistence.failed ? "Settings save failed" :
			(persistence.committed_generation != 0 ? "Settings saved" : ""));
		if (persistence_label[0] != '\0' && ws.x >= 300.f) {
			ImFont* status_font = aida::ui::fonts::caption();
			if (!status_font)
				status_font = ImGui::GetFont();
			const float status_size = aida::ui::fonts::size_or(status_font, 12.f);
			const ImVec2 text_size = status_font->CalcTextSizeA(status_size,
				FLT_MAX, 0.f, persistence_label);
			const ImVec2 text_pos(wp.x + ws.x - text_size.x - 12.f,
				wp.y + (header_h - text_size.y) * 0.5f);
			const ImU32 status_color = persistence.failed ? th.error :
				(persistence.pending ? th.warning : th.success);
			dl->AddText(status_font, status_size, text_pos, status_color,
				persistence_label);
			if (ImGui::IsMouseHoveringRect(text_pos,
					ImVec2(text_pos.x + text_size.x, text_pos.y + text_size.y))) {
				if (persistence.failed && !persistence.error.empty())
					ImGui::SetTooltip("%s", persistence.error.c_str());
				else if (!persistence.stage.empty())
					ImGui::SetTooltip("%s", persistence.stage.c_str());
			}
		}

		aida::ui::responsive::sidebar_policy_t side_pol;
		side_pol.full_width = 184.f;
		side_pol.icon_only_width = 56.f;
		side_pol.icon_only_threshold = 148.f;
		side_pol.hide_threshold = 36.f;
		side_pol.content_min_w = 300.f;
		const float min_panel_w = aida::ui::responsive::compute_total_min_width(side_pol);
		(void)min_panel_w;

		aida::ui::responsive::sidebar_metrics_t side_metrics =
			aida::ui::responsive::resolve_sidebar(panel_w - 8.f, side_pol);
		float side_w = side_metrics.width;
		const bool side_icon_only = side_metrics.icon_only;
		bool side_hidden = side_metrics.hidden;

		if (panel_w < 320.f || panel_h < 220.f) {
			ImVec2 overlay_pos(wp.x, wp.y + header_h);
			aida::ui::responsive::draw_clamp_overlay(overlay_pos,
				ImVec2(ws.x, (std::max)(1.f, ws.y - header_h)), "Widen Settings");
			return;
		}

		static bool s_logged_icon_only = false;
		if (side_icon_only && !s_logged_icon_only) {
			s_logged_icon_only = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			::diag::log_tagged_fmt("responsive",
				"settings_overlay sidebar icon_only_threshold=%.0f panel_w=%.0f",
				side_pol.icon_only_threshold, panel_w);
#endif
		} else if (!side_icon_only && s_logged_icon_only) {
			s_logged_icon_only = false;
		}

		const float content_y = header_h + 4.f;
		const float content_h = panel_h - content_y - 8.f;
		float content_avail_w = panel_w - side_w - (side_hidden ? 0.f : 10.f);
		bool compact_top_tabs = side_hidden;
		if (!side_hidden && content_avail_w < 320.f) {
			side_hidden = true;
			side_w = 0.f;
			content_avail_w = panel_w;
			compact_top_tabs = true;
		}
		if (content_avail_w < 180.f) content_avail_w = 180.f;
		float content_w = content_avail_w;

		if (!side_hidden) {
			ImGui::SetCursorPos(ImVec2(0.f, content_y));
			ImGui::BeginChild("##settings_sidebar", ImVec2(side_w, content_h), false,
				ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar);
			{
				static const char* tab_labels[tab_count] = {
					"Accounts",
					"Agents",
					"Skills",
					"MCP Servers",
					"Editor"
				};
				const float row_h = 44.f;
				ImGui::Dummy(ImVec2(0.f, 8.f));
				for (int i = 0; i < tab_count; ++i) {
					detail::render_tab_label(i, tab_labels[static_cast<std::size_t>(i)], side_w, row_h,
						th.text_primary, th.text_secondary, dt, side_icon_only);
					ImGui::Dummy(ImVec2(0.f, 2.f));
				}
				detail::render_sidebar_underline(side_w, content_y, row_h, dt);
			}
			ImGui::EndChild();
		}

		float content_x = side_hidden ? 0.f : (side_w + 8.f);
		float content_body_y = content_y;
		float content_body_h = content_h;
		if (compact_top_tabs) {
			ImGui::SetCursorPos(ImVec2(6.f, content_y));
			detail::render_compact_tab_row((std::max)(1.f, panel_w - 12.f), 34.f, dt);
			content_body_y += 38.f;
			content_body_h = (std::max)(1.f, content_body_h - 38.f);
			content_x = 0.f;
			content_w = (std::max)(180.f, panel_w);
		}
		ImGui::SetCursorPos(ImVec2(content_x, content_body_y));
		ImGui::BeginChild("##settings_content", ImVec2(content_w, content_body_h), false,
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse);
		{
			s.tab_crossfade_progress = aida::motion::smooth_lerp(
				s.tab_crossfade_progress, 1.f, 18.f, dt);

			const int active = s.active_tab.load();
			ImGui::PushClipRect(ImGui::GetWindowPos(),
				ImVec2(ImGui::GetWindowPos().x + content_w,
					ImGui::GetWindowPos().y + content_body_h),
				true);

			float p = s.tab_crossfade_progress;
			float style_alpha = ImGui::GetStyle().Alpha;

			auto draw_tab = [&](int idx) {
				switch (idx) {
				case tab_accounts:        detail::render_tab_accounts(content_w, content_body_h); break;
				case tab_agents:          detail::render_tab_agents(content_w, content_body_h); break;
				case tab_skills:          detail::render_tab_skills(content_w, content_body_h); break;
				case tab_mcp_servers:     detail::render_tab_mcp_servers(content_w, content_body_h); break;
				case tab_editor_theme:    detail::render_tab_editor_theme(content_w, content_body_h); break;
				default:                  detail::render_tab_accounts(content_w, content_body_h); break;
				}
			};

			float fade = 0.55f + 0.45f * p;
			ImGui::PushStyleVar(ImGuiStyleVar_Alpha, style_alpha * fade);
			draw_tab(active);
			ImGui::PopStyleVar();

			ImGui::PopClipRect();
		}
		ImGui::EndChild();
	}


}
}
