#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "settings_overlay.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"

#include "auth_view.hpp"
#include "agent_manager_view.hpp"
#include "skill_manager_view.hpp"

#include "mcp_client.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"

#include "mcp_marketplace_view.hpp"
#include "../ui/avatar.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/brand.hpp"
#include "../ui/clock.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/fonts.hpp"
#include "../ui/motion.hpp"
#include "../ui/responsive.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/theme.hpp"
#include "../ui/transition.hpp"
#include "../helpers/globals.h"
#include "../helpers/helpers.h"
#include "../helpers/diag_log.hpp"
#include "../runtime/ida_injector.hpp"
#include "work_queue.hpp"


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
		};


		inline overlay_state_t& state()
		{
			static overlay_state_t s;
			return s;
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
			g_sa_settings.save();
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
			case tab_ida_pro: {
				dl->AddRect(ImVec2(c.x - r * 0.50f, c.y - r * 0.50f),
					ImVec2(c.x + r * 0.50f, c.y + r * 0.50f), col, 4.f, 0, th_w);
				ImFont* f = ImGui::GetFont();
				float fs = r * 0.85f;
				ImVec2 sz = f->CalcTextSizeA(fs, FLT_MAX, 0.f, "I");
				dl->AddText(f, fs, ImVec2(c.x - sz.x * 0.5f, c.y - sz.y * 0.5f), col, "I");
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
				s.tab_row_screen_y[idx] = row_pos.y;
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
				row_top = s.tab_row_screen_y[active_idx];
			} else {
				const ImGuiStyle& style = ImGui::GetStyle();
				const float row_stride = row_h + style.ItemSpacing.y + 2.f + style.ItemSpacing.y;
				row_top = wp.y + 8.f + style.ItemSpacing.y + active_idx * row_stride;
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


		inline void render_tab_accounts(float content_w, float content_h)
		{
			aida::auth_view::render(content_w, content_h);
		}


		inline void render_tab_agents(float content_w, float content_h)
		{
			aida::agent_manager::render(content_w, content_h);
		}


		inline void render_tab_skills(float content_w, float content_h)
		{
			aida::skill_manager::render(content_w, content_h);
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
				hdl->AddText(aida::ui::fonts::h1(), 22.f, hp,
					th.text_primary, "External MCP Servers");
				ImGui::Dummy(ImVec2(0.f, 32.f));
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
			static bool s_first_load = true;

			auto& mgr = get_mcp_client_manager();
			auto statuses = mgr.get_status();
			auto& servers = g_sa_settings.mcp_client_servers;

			auto refresh_buf = [&]() {
				if (s_sel_index < 0 || s_sel_index >= static_cast<int>(servers.size())) return;
				const auto& srv = servers[s_sel_index];
				std::snprintf(s_name, sizeof(s_name), "%s", srv.name.c_str());
				std::snprintf(s_url,  sizeof(s_url),  "%s", srv.url.c_str());
				std::snprintf(s_key,  sizeof(s_key),  "%s", srv.api_key.c_str());
				std::snprintf(s_cmd,  sizeof(s_cmd),  "%s", srv.command.c_str());
				std::snprintf(s_args, sizeof(s_args), "%s", srv.args.c_str());
				s_transport = (srv.transport == "stdio") ? 1 : 0;
				s_enabled = srv.enabled;
				s_auto    = srv.auto_connect;
			};

			if (s_first_load) {
				s_first_load = false;
				if (!servers.empty()) refresh_buf();
			}

			float avail_w = ImGui::GetContentRegionAvail().x;
			float left_w = 280.f;
			float min_detail_w = 260.f;
			bool stack_vertical = (avail_w - left_w - 8.f) < min_detail_w;
			float row_h  = 58.f;
			float list_h_horiz = (std::max)(content_h - 130.f, 240.f);
			float list_h = stack_vertical ? (std::max)(content_h * 0.45f, 200.f) : list_h_horiz;
			if (stack_vertical) {
				left_w = (std::max)(avail_w - 8.f, 200.f);
			}

			static bool s_mcp_logged_stack = false;
			if (stack_vertical && !s_mcp_logged_stack) {
				s_mcp_logged_stack = true;
				::diag::log_tagged_fmt("responsive",
					"settings_overlay mcp panel stacked avail_w=%.0f min_detail_w=%.0f",
					avail_w, min_detail_w);
			} else if (!stack_vertical && s_mcp_logged_stack) {
				s_mcp_logged_stack = false;
			}

			ImGui::BeginChild("##mcp_list", ImVec2(left_w, list_h), false,
				ImGuiWindowFlags_NoSavedSettings);

			ImDrawList* dl = ImGui::GetWindowDrawList();

			for (int i = 0; i < static_cast<int>(servers.size()); ++i) {
				ImGui::PushID(i);
				const auto& srv = servers[i];

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

				if (clicked) {
					s_sel_index = i;
					refresh_buf();
				}

				if (oauth == mcp_client::oauth_status_t::needs_auth ||
					oauth == mcp_client::oauth_status_t::needs_client_registration ||
					oauth == mcp_client::oauth_status_t::failed)
				{
					float btn_x = b.x - 96.f;
					float btn_y = a.y + (row_h - 4.f - 28.f) * 0.5f;
					ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
					if (aida::ui::button("Sign in",
							aida::ui::button_kind_t::primary,
							aida::ui::size_t_::md,
							ImVec2(88.f, 28.f))) {
						std::string srv_name = srv.name;
						mcp_client::trigger_auth_flow(srv_name,
							[](const std::string& nm, mcp_client::oauth_status_t final_status,
								const std::string& err) {
								(void)final_status;
								if (!err.empty())
									toast_notification::push(std::string("MCP auth ") + nm + ": " + err,
										toast_notification::toast_type_t::error);
								else
									toast_notification::push(std::string("MCP auth ") + nm + ": OK",
										toast_notification::toast_type_t::info);
							});
					}
				}

				ImGui::PopID();
				ImGui::Dummy(ImVec2(row_w, 0.f));
			}

			ImGui::EndChild();

			const float footer_avail = ImGui::GetContentRegionAvail().x;
			const float btn_sep = 8.f;
			const bool btn_narrow = footer_avail < 440.f;
			const char* lbl_add    = "+ Add Server";
			const char* lbl_apply  = btn_narrow ? "Apply" : "Apply Changes";
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
			const float w_remove = std::max(mcp_bw(lbl_remove), 90.f);
			const float w_market = std::max(mcp_bw(lbl_market), 90.f);
			const float btn_total_w = w_add + w_apply + w_remove + w_market + btn_sep * 3.f;
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
				adv(w_add); adv(w_apply); adv(w_remove); adv(w_market);
				btn_rows = rows;
			}
			const float footer_h = btn_rows * 36.f + (btn_rows - 1) * btn_sep + 12.f + 6.f;

			float detail_h;
			if (stack_vertical) {
				detail_h = (std::max)(content_h * 0.55f - 4.f - footer_h, 200.f);
			} else {
				detail_h = (std::max)(list_h - footer_h, 160.f);
				ImGui::SameLine();
			}
			ImGui::BeginChild("##mcp_detail", ImVec2(0, detail_h), false,
				ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_HorizontalScrollbar);

			ImDrawList* ddl = ImGui::GetWindowDrawList();
			ImVec2 dp = ImGui::GetCursorScreenPos();
			ddl->AddText(aida::ui::fonts::body_strong(),
				aida::ui::components::detail::ui_fs() * 1.25f,
				ImVec2(dp.x + 8.f, dp.y + 4.f),
				th.text_primary, "Server Configuration");
			ImGui::Dummy(ImVec2(0.f, 30.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 4.f));

			if (s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size())) {
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Name");
				aida::ui::input_text("##mcp_name", s_name, sizeof(s_name),
					"Server name", false, ImVec2(0.f, 36.f));

				ImGui::Dummy(ImVec2(0.f, 4.f));
				const char* transports[] = { "HTTP/SSE", "Stdio" };
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Transport");
				ImGui::SetNextItemWidth(-12.f);
				ImGui::Combo("##mcp_transport", &s_transport, transports, 2);

				if (s_transport == 0) {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "URL");
					aida::ui::input_text("##mcp_url", s_url, sizeof(s_url),
						"https://server", false, ImVec2(0.f, 36.f));
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "API Key");
					aida::ui::input_text("##mcp_key", s_key, sizeof(s_key),
						"secret", true, ImVec2(0.f, 36.f));
				} else {
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Command");
					aida::ui::input_text("##mcp_cmd", s_cmd, sizeof(s_cmd),
						"node server.js", false, ImVec2(0.f, 36.f));
					ImGui::Dummy(ImVec2(0.f, 4.f));
					ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Args");
					aida::ui::input_text("##mcp_args", s_args, sizeof(s_args),
						"--port 3001", false, ImVec2(0.f, 36.f));
				}

				ImGui::Dummy(ImVec2(0.f, 6.f));
				aida::ui::toggle_switch("Enabled##mcp", &s_enabled, aida::ui::size_t_::md);
				ImGui::SameLine(140.f);
				aida::ui::toggle_switch("Auto-connect", &s_auto, aida::ui::size_t_::md);

				auto& srv = servers[s_sel_index];
				srv.name = s_name;
				srv.url = s_url;
				srv.api_key = s_key;
				srv.command = s_cmd;
				srv.args = s_args;
				srv.transport = (s_transport == 1) ? "stdio" : "http_sse";
				srv.enabled = s_enabled;
				srv.auto_connect = s_auto;
			} else {
				ImVec2 region_pos = ImGui::GetCursorScreenPos();
				ImVec2 region_size(ImGui::GetContentRegionAvail().x, 200.f);
				aida::ui::empty_state::config_t cfg;
				cfg.glyph = aida::ui::empty_state::glyph_t::network;
				cfg.title = "No server selected";
				cfg.body = "Pick a server on the left or add a new one to configure it.";
				cfg.max_width = region_size.x * 0.8f;
				aida::ui::empty_state::render(region_pos, region_size, cfg);
			}

			ImGui::EndChild();

			ImGui::Dummy(ImVec2(0, 12.f));

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
				mcp_client_server_t srv;
				srv.name = "New Server";
				srv.url = "http://localhost:3001";
				servers.push_back(srv);
				s_sel_index = static_cast<int>(servers.size()) - 1;
				refresh_buf();
				g_sa_settings.save();
			}
			if (place_button(w_apply)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_apply,
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(w_apply, 36.f))) {
				mgr.disconnect_all();
				for (const auto& srv : servers) {
					mcp_client::server_config_t cfg;
					cfg.name = srv.name;
					cfg.url = srv.url;
					cfg.api_key = srv.api_key;
					cfg.enabled = srv.enabled;
					cfg.auto_connect = srv.auto_connect;
					if (srv.transport == "stdio") {
						cfg.transport = mcp_client::transport_type_t::stdio;
						cfg.command = srv.command;
						if (!srv.args.empty()) {
							std::istringstream iss(srv.args);
							std::string a;
							while (iss >> a) cfg.args.push_back(a);
						}
					} else {
						cfg.transport = mcp_client::transport_type_t::http_sse;
					}
					mgr.add_server(cfg);
				}
				mgr.connect_all();
				g_sa_settings.save();
			}
			if (place_button(w_remove)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_remove,
					aida::ui::button_kind_t::destructive,
					aida::ui::size_t_::md,
					ImVec2(w_remove, 36.f)) &&
				s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size()))
			{
				servers.erase(servers.begin() + s_sel_index);
				if (s_sel_index > 0) --s_sel_index;
				refresh_buf();
				g_sa_settings.save();
			}
			if (place_button(w_market)) ImGui::SameLine(0.f, btn_sep);
			if (aida::ui::button(lbl_market,
					aida::ui::button_kind_t::accent_gradient,
					aida::ui::size_t_::md,
					ImVec2(w_market, 36.f))) {
				aida::mcp_marketplace_view::open();
			}

			if (footer_avail < 200.f) {
				aida::ui::responsive::draw_clamp_overlay(mcp_tab_origin,
					ImVec2(content_w, content_h), "Settings pane too narrow");
			}

			ImGui::PopStyleVar(2);
			ImGui::PopFont();
			ImGui::PopID();

			aida::mcp_marketplace_view::render_modal_if_open();
		}


		inline std::mutex& ida_status_mutex()
		{
			static std::mutex m;
			return m;
		}

		inline std::string& ida_status_string()
		{
			static std::string s;
			return s;
		}

		inline std::atomic<bool>& ida_busy_flag()
		{
			static std::atomic<bool> b{false};
			return b;
		}

		inline void set_ida_status(const std::string& s)
		{
			std::lock_guard<std::mutex> lk(ida_status_mutex());
			ida_status_string() = s;
		}

		inline std::string snapshot_ida_status()
		{
			std::lock_guard<std::mutex> lk(ida_status_mutex());
			return ida_status_string();
		}

		inline void render_tab_ida_pro(float content_w, float content_h)
		{
			(void)content_h;
			const auto& th = aida::ui::resolved();
			static char s_path_buf[1024] = {};
			static bool s_path_loaded = false;

			if (!s_path_loaded)
			{
				std::snprintf(s_path_buf, sizeof(s_path_buf), "%s",
					g_sa_settings.ida_pro_path.c_str());
				s_path_loaded = true;
			}

			ImGui::PushID("##ida_pro_tab");
			ImGui::PushFont(aida::ui::fonts::lg());
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10.f, 10.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 7.f));

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 hp = ImGui::GetCursorScreenPos();
			dl->AddText(aida::ui::fonts::h1(), 22.f, hp, th.text_primary,
				"IDA Pro Integration");
			ImGui::Dummy(ImVec2(0.f, 32.f));

			ImGui::TextWrapped("Press Launch to open a fresh IDA instance and manual-map "
				"the AiDA plugin into it. The AiDA plugin DLL is never written to disk.");
			ImGui::Dummy(ImVec2(0.f, 6.f));

			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "IDA executable path");
			float ida_row_avail = ImGui::GetContentRegionAvail().x;
			bool ida_path_wrap_browse = (ida_row_avail < (220.f + 10.f + 126.f));
			float ida_input_w = ida_path_wrap_browse
				? (std::max)(ida_row_avail - 12.f, 120.f)
				: (std::max)(ida_row_avail - 136.f, 200.f);
			if (aida::ui::input_text("##ida_pro_path",
					s_path_buf, sizeof(s_path_buf),
					"C:\\Program Files\\IDA Pro\\ida.exe", false,
					ImVec2(ida_input_w, 36.f)))
			{
				g_sa_settings.ida_pro_path = s_path_buf;
			}
			if (!ida_path_wrap_browse) ImGui::SameLine(0.f, 10.f);
			if (aida::ui::button("Browse...##ida_browse",
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(126.f, 36.f)))
			{
				std::string picked;
				if (ida_injector::prompt_and_persist_ida_path(::g_hwnd, picked))
				{
					std::snprintf(s_path_buf, sizeof(s_path_buf), "%s", picked.c_str());
					set_ida_status("Saved IDA path: " + picked);
				}
			}

			ImGui::Dummy(ImVec2(0.f, 4.f));
			float ida_btn_avail = ImGui::GetContentRegionAvail().x;
			bool ida_btn_wrap = (ida_btn_avail < (112.f + 10.f + 140.f));
			if (aida::ui::button("Save##ida_save",
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(112.f, 32.f)))
			{
				g_sa_settings.ida_pro_path = s_path_buf;
				if (g_sa_settings.save())
					set_ida_status("Saved.");
				else
					set_ida_status("Failed to write settings file.");
			}
			if (!ida_btn_wrap) ImGui::SameLine(0.f, 10.f);
			if (aida::ui::button("Auto-detect##ida_detect",
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(140.f, 32.f)))
			{
				std::string discovered = ida_injector::discover_ida_path();
				if (!discovered.empty())
				{
					std::snprintf(s_path_buf, sizeof(s_path_buf), "%s", discovered.c_str());
					g_sa_settings.ida_pro_path = discovered;
					g_sa_settings.save();
					set_ida_status("Auto-detected: " + discovered);
				}
				else
				{
					set_ida_status("No IDA installation found via registry or Program Files.");
				}
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 6.f));

			bool busy = ida_busy_flag().load(std::memory_order_acquire);
			bool can_launch = !busy && ida_injector::validate_ida_path(g_sa_settings.ida_pro_path);
			if (!can_launch)
				ImGui::BeginDisabled();
			float launch_avail = ImGui::GetContentRegionAvail().x;
			float launch_w = (launch_avail < 280.f) ? (std::max)(launch_avail - 12.f, 160.f) : 280.f;
			const char* launch_label = (launch_w < 220.f) ? "Launch IDA" : "Launch IDA Pro with AiDA";
			if (aida::ui::button(launch_label,
					aida::ui::button_kind_t::accent_gradient,
					aida::ui::size_t_::lg,
					ImVec2(launch_w, 44.f),
					false, nullptr, busy))
			{
				::diag::log_tagged_critical("ida_launch", "click_received");
				ida_busy_flag().store(true, std::memory_order_release);
				std::filesystem::path ida_p(g_sa_settings.ida_pro_path);
				std::string ida_name = ida_p.filename().string();
				if (ida_name.empty()) ida_name = "IDA";
				::diag::log_tagged_fmt("ida_launch", "configured_ida_path=%s", g_sa_settings.ida_pro_path.c_str());
				set_ida_status(std::string("Launching ") + ida_name
					+ " and manual-mapping AiDA...");
				::diag::log_tagged("ida_launch", "posting_to_work_queue");
				work_queue::post([ida_name]{
					::diag::log_tagged_critical_fmt("ida_launch", "lambda_enter tid=%lu", GetCurrentThreadId());
					struct busy_guard_t {
						~busy_guard_t() {
							ida_busy_flag().store(false, std::memory_order_release);
							::diag::log_tagged_critical("ida_launch", "busy_guard_cleared");
						}
					} guard;
					std::string err;
					bool ok = false;
					::diag::log_tagged("ida_launch", "calling_launch_ida_with_aida");
					try {
						ok = ida_injector::launch_ida_with_aida(std::string(), err);
					} catch (const std::exception& ex) {
						ok = false;
						err = std::string("internal exception: ") + ex.what();
					} catch (...) {
						ok = false;
						err = "unknown internal exception";
					}
					::diag::log_tagged_critical_fmt("ida_launch", "launch_ida_with_aida_returned ok=%d err=%s",
						ok ? 1 : 0,
						err.empty() ? "(none)" : err.c_str());
					if (ok)
						set_ida_status("AiDA mapped into " + ida_name + " successfully.");
					else
						set_ida_status(std::string("Launch failed: ") + (err.empty() ? "(no detail)" : err));
				});
				::diag::log_tagged("ida_launch", "post_returned");
			}
			if (!can_launch)
				ImGui::EndDisabled();

			if (busy)
			{
				ImGui::SameLine(0.f, 12.f);
				ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.warning), "Working...");
			}

			std::string status_snap = snapshot_ida_status();
			if (!status_snap.empty())
			{
				ImGui::Dummy(ImVec2(0.f, 6.f));
				ImGui::TextWrapped("%s", status_snap.c_str());
			}

			ImGui::PopStyleVar(2);
			ImGui::PopFont();
			ImGui::PopID();
		}

		inline void render_tab_editor_theme(float content_w, float content_h)
		{
			(void)content_w; (void)content_h;
			auto& s = state();
			const auto& th = aida::ui::resolved();
			std::lock_guard<std::mutex> lk(s.mtx);
			load_editor_locked(s);

			ImGui::PushID("##editor_theme_tab");
			ImGui::PushFont(aida::ui::fonts::lg());
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10.f, 10.f));
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 7.f));

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 hp = ImGui::GetCursorScreenPos();
			dl->AddText(aida::ui::fonts::h1(), 22.f, hp, th.text_primary, "Editor");
			ImGui::Dummy(ImVec2(0.f, 32.f));

			bool changed = false;
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Tab size");
			ImGui::SetNextItemWidth(240.f);
			changed |= ImGui::InputInt("##ed_tab", &s.ed_tab_size, 0, 0);
			s.ed_tab_size = (std::max)(s.ed_tab_size, 1);

			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Font size");
			ImGui::SetNextItemWidth(240.f);
			changed |= ImGui::SliderFloat("##ed_font", &s.ed_font_size, 9.f, 32.f, "%.0f");

			ImGui::Dummy(ImVec2(0.f, 4.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary),
				"Disassembly selection");
			bool full_line_sel = editor_config::disasm_full_line_select;
			if (ImGui::Checkbox("Full-line selection (highlight entire row)##disasm_full_line_sel",
				&full_line_sel))
			{
				editor_config::disasm_full_line_select = full_line_sel;
			}

			ImGui::Dummy(ImVec2(0.f, 6.f));
			ImGui::Separator();
			ImGui::Dummy(ImVec2(0.f, 6.f));

			dl->AddText(aida::ui::fonts::h1(), 22.f, ImGui::GetCursorScreenPos(),
				th.text_primary, "Theme");
			ImGui::Dummy(ImVec2(0.f, 32.f));

			static const char* theme_names[] = { "AiDA Dark", "AiDA Light", "Claude Dark", "Claude Light" };
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_secondary), "Active theme");
			ImGui::SetNextItemWidth(240.f);
			int prev_idx = g_sa_settings.active_theme_idx;
			if (ImGui::Combo("##theme_idx", &g_sa_settings.active_theme_idx, theme_names,
				IM_ARRAYSIZE(theme_names)))
			{
				if (prev_idx != g_sa_settings.active_theme_idx) {
					themes::active = std::clamp(g_sa_settings.active_theme_idx,
						0, themes::count - 1);
					themes::changed = true;
					g_sa_settings.save();
				}
			}

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
	}


	void open()
	{
		g_settings_open = true;
	}


	void close()
	{
		g_settings_open = false;
	}


	void toggle()
	{
		g_settings_open = !g_settings_open;
	}


	bool is_open()
	{
		return g_settings_open;
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
		g_settings_open = true;
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
			g_settings_open = false;
		}
		ImGui::SameLine();
		dl->AddText(aida::ui::fonts::h2(), 16.f,
			ImVec2(wp.x + 44.f, wp.y + 11.f),
			th.text_primary, "Settings");

		aida::ui::responsive::sidebar_policy_t side_pol;
		side_pol.full_width = 190.f;
		side_pol.icon_only_width = 56.f;
		side_pol.icon_only_threshold = 150.f;
		side_pol.hide_threshold = 36.f;
		side_pol.content_min_w = 280.f;
		const float min_panel_w = aida::ui::responsive::compute_total_min_width(side_pol);
		(void)min_panel_w;

		aida::ui::responsive::sidebar_metrics_t side_metrics =
			aida::ui::responsive::resolve_sidebar(panel_w - 8.f, side_pol);
		const float side_w = side_metrics.width;
		const bool side_icon_only = side_metrics.icon_only;
		const bool side_hidden = side_metrics.hidden;

		static bool s_logged_icon_only = false;
		if (side_icon_only && !s_logged_icon_only) {
			s_logged_icon_only = true;
			::diag::log_tagged_fmt("responsive",
				"settings_overlay sidebar icon_only_threshold=%.0f panel_w=%.0f",
				side_pol.icon_only_threshold, panel_w);
		} else if (!side_icon_only && s_logged_icon_only) {
			s_logged_icon_only = false;
		}

		const float content_y = header_h + 4.f;
		const float content_h = panel_h - content_y - 8.f;
		float content_avail_w = panel_w - side_w - (side_hidden ? 0.f : 8.f);
		if (content_avail_w < 80.f) content_avail_w = 80.f;
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
					"Editor",
					"IDA Pro"
				};
				const float row_h = 44.f;
				ImGui::Dummy(ImVec2(0, 8.f));
				for (int i = 0; i < tab_count; ++i) {
					detail::render_tab_label(i, tab_labels[i], side_w, row_h,
						th.text_primary, th.text_secondary, dt, side_icon_only);
					ImGui::Dummy(ImVec2(0, 2.f));
				}
				detail::render_sidebar_underline(side_w, content_y, row_h, dt);
			}
			ImGui::EndChild();
		}

		float content_x = side_hidden ? 0.f : (side_w + 6.f);
		ImGui::SetCursorPos(ImVec2(content_x, content_y));
		ImGui::BeginChild("##settings_content", ImVec2(content_w, content_h), false,
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_HorizontalScrollbar);
		{
			s.tab_crossfade_progress = aida::motion::smooth_lerp(
				s.tab_crossfade_progress, 1.f, 18.f, dt);

			const int active = s.active_tab.load();
			ImGui::PushClipRect(ImGui::GetWindowPos(),
				ImVec2(ImGui::GetWindowPos().x + content_w,
					ImGui::GetWindowPos().y + content_h),
				true);

			float p = s.tab_crossfade_progress;
			float style_alpha = ImGui::GetStyle().Alpha;

			auto draw_tab = [&](int idx) {
				switch (idx) {
				case tab_accounts:        detail::render_tab_accounts(content_w, content_h); break;
				case tab_agents:          detail::render_tab_agents(content_w, content_h); break;
				case tab_skills:          detail::render_tab_skills(content_w, content_h); break;
				case tab_mcp_servers:     detail::render_tab_mcp_servers(content_w, content_h); break;
				case tab_editor_theme:    detail::render_tab_editor_theme(content_w, content_h); break;
				case tab_ida_pro:         detail::render_tab_ida_pro(content_w, content_h); break;
				default:                  detail::render_tab_accounts(content_w, content_h); break;
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
