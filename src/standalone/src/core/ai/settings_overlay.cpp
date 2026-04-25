#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#include "settings_overlay.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "imgui/imgui.h"

#include "auth_view.hpp"
#include "provider_view.hpp"
#include "agent_manager_view.hpp"
#include "skill_manager_view.hpp"

#include "mcp_client.hpp"
#include "compaction.hpp"
#include "session_store.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"

#include "../helpers/globals.h"


extern settings_sa_t g_sa_settings;
mcp_client::manager_t& get_mcp_client_manager();


namespace aida {
namespace settings_overlay {


	namespace detail {

		inline std::filesystem::path aida_json_path()
		{
			wchar_t* appdata = nullptr;
			if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
				auto root = std::filesystem::path(appdata) / L"AiDA";
				CoTaskMemFree(appdata);
				return root / L"aida.json";
			}
			return std::filesystem::current_path() / "aida.json";
		}


		struct overlay_state_t
		{
			std::mutex mtx;
			std::atomic<int> active_tab{ tab_accounts };
			std::atomic<bool> initialized{ false };
			float tab_anim = 0.f;

			char  filter_buf[128] = {};
			char  mcp_search_buf[128] = {};

			bool  compaction_loaded = false;
			float compaction_trigger_ratio = 0.85f;
			int   compaction_preserve_messages = 2;
			int   compaction_preserve_tokens = 8000;
			float compaction_cost_anim = 0.f;
			std::string compaction_session_id;
			double compaction_session_cost = 0.0;
			int64_t compaction_session_input = 0;
			int64_t compaction_session_output = 0;
			int64_t compaction_session_reasoning = 0;
			int64_t compaction_session_cache_read = 0;
			int64_t compaction_session_cache_write = 0;
			double compaction_last_refresh = 0.0;

			bool editor_loaded = false;
			int  ed_tab_size = 4;
			float ed_font_size = 14.0f;
			bool  ed_line_numbers = true;
			bool  ed_word_wrap = false;
			bool  ed_minimap = false;
			bool  ed_bracket_match = true;
			bool  ed_highlight_line = true;
			bool  ed_autocomplete = true;
			bool  ed_ghost_text = false;

			bool  permissions_loaded = false;
			char  perm_allowed_commands[1024] = {};
			char  perm_denied_commands[1024] = {};
		};


		inline overlay_state_t& state()
		{
			static overlay_state_t s;
			return s;
		}


		inline void load_compaction_locked(overlay_state_t& s)
		{
			if (s.compaction_loaded) return;
			s.compaction_loaded = true;

			nlohmann::json root;
			const auto path = aida_json_path();
			std::error_code ec;
			if (std::filesystem::exists(path, ec)) {
				std::ifstream ifs(path, std::ios::binary);
				std::string raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
				try {
					root = nlohmann::json::parse(raw);
					if (!root.is_object()) root = nlohmann::json::object();
				} catch (...) {
					root = nlohmann::json::object();
				}
			}
			if (root.contains("compaction") && root["compaction"].is_object()) {
				const auto& c = root["compaction"];
				if (c.contains("trigger_ratio") && c["trigger_ratio"].is_number())
					s.compaction_trigger_ratio = c["trigger_ratio"].get<float>();
				if (c.contains("preserve_recent_messages") && c["preserve_recent_messages"].is_number_integer())
					s.compaction_preserve_messages = c["preserve_recent_messages"].get<int>();
				if (c.contains("preserve_recent_tokens") && c["preserve_recent_tokens"].is_number_integer())
					s.compaction_preserve_tokens = c["preserve_recent_tokens"].get<int>();
			} else {
				s.compaction_trigger_ratio = static_cast<float>(g_sa_settings.condense_threshold);
			}
		}


		inline void save_compaction_locked(overlay_state_t& s)
		{
			nlohmann::json root;
			const auto path = aida_json_path();
			std::error_code ec;
			std::filesystem::create_directories(path.parent_path(), ec);
			if (std::filesystem::exists(path, ec)) {
				std::ifstream ifs(path, std::ios::binary);
				std::string raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
				try {
					root = nlohmann::json::parse(raw);
					if (!root.is_object()) root = nlohmann::json::object();
				} catch (...) {
					root = nlohmann::json::object();
				}
			}
			nlohmann::json c = nlohmann::json::object();
			c["trigger_ratio"]            = s.compaction_trigger_ratio;
			c["preserve_recent_messages"] = s.compaction_preserve_messages;
			c["preserve_recent_tokens"]   = s.compaction_preserve_tokens;
			root["compaction"] = c;

			std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
			if (ofs) ofs << root.dump(2);

			g_sa_settings.condense_threshold = static_cast<double>(s.compaction_trigger_ratio);
			g_sa_settings.save();
		}


		inline void load_editor_locked(overlay_state_t& s)
		{
			if (s.editor_loaded) return;
			s.editor_loaded = true;
			s.ed_tab_size        = g_sa_settings.editor_tab_size;
			s.ed_font_size       = g_sa_settings.editor_font_size;
			s.ed_line_numbers    = g_sa_settings.editor_line_numbers;
			s.ed_word_wrap       = g_sa_settings.editor_word_wrap;
			s.ed_minimap         = g_sa_settings.editor_minimap;
			s.ed_bracket_match   = g_sa_settings.editor_bracket_match;
			s.ed_highlight_line  = g_sa_settings.editor_highlight_line;
			s.ed_autocomplete    = g_sa_settings.editor_auto_complete;
			s.ed_ghost_text      = g_sa_settings.ghost_text_enabled;
		}


		inline void persist_editor_locked(overlay_state_t& s)
		{
			editor_config::tab_size                = (std::max)(s.ed_tab_size, 1);
			editor_config::font_size               = s.ed_font_size;
			editor_config::show_line_numbers       = s.ed_line_numbers;
			editor_config::word_wrap               = s.ed_word_wrap;
			editor_config::minimap                 = s.ed_minimap;
			editor_config::bracket_match           = s.ed_bracket_match;
			editor_config::highlight_current_line  = s.ed_highlight_line;
			editor_config::auto_complete           = s.ed_autocomplete;

			g_sa_settings.editor_tab_size          = (std::max)(s.ed_tab_size, 1);
			g_sa_settings.editor_font_size         = s.ed_font_size;
			g_sa_settings.editor_line_numbers      = s.ed_line_numbers;
			g_sa_settings.editor_word_wrap         = s.ed_word_wrap;
			g_sa_settings.editor_minimap           = s.ed_minimap;
			g_sa_settings.editor_bracket_match     = s.ed_bracket_match;
			g_sa_settings.editor_highlight_line    = s.ed_highlight_line;
			g_sa_settings.editor_auto_complete     = s.ed_autocomplete;
			g_sa_settings.ghost_text_enabled       = s.ed_ghost_text;
			g_sa_settings.save();
		}


		inline void load_permissions_locked(overlay_state_t& s)
		{
			if (s.permissions_loaded) return;
			s.permissions_loaded = true;
			std::snprintf(s.perm_allowed_commands, sizeof(s.perm_allowed_commands), "%s",
				g_sa_settings.auto_approve_allowed_commands.c_str());
			std::snprintf(s.perm_denied_commands, sizeof(s.perm_denied_commands), "%s",
				g_sa_settings.tool_always_deny.c_str());
		}


		inline void persist_permissions_locked(overlay_state_t& s)
		{
			g_sa_settings.auto_approve_allowed_commands = s.perm_allowed_commands;
			g_sa_settings.tool_always_deny              = s.perm_denied_commands;
			g_sa_settings.save();
		}


		inline ImU32 oauth_pill_bg(mcp_client::oauth_status_t st)
		{
			switch (st) {
			case mcp_client::oauth_status_t::authenticated:           return IM_COL32(40, 110, 60, 220);
			case mcp_client::oauth_status_t::not_required:            return IM_COL32(60, 60, 70, 200);
			case mcp_client::oauth_status_t::needs_auth:              return IM_COL32(170, 110, 30, 220);
			case mcp_client::oauth_status_t::needs_client_registration: return IM_COL32(170, 50, 50, 220);
			case mcp_client::oauth_status_t::authenticating:          return IM_COL32(60, 90, 170, 220);
			case mcp_client::oauth_status_t::failed:                  return IM_COL32(170, 50, 50, 220);
			}
			return IM_COL32(60, 60, 70, 200);
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


		inline void render_oauth_pill(ImDrawList* dl, ImVec2 pos,
			mcp_client::oauth_status_t st, float alpha_mult)
		{
			const char* label = oauth_pill_label(st);
			ImVec2 ts = ImGui::CalcTextSize(label);
			float pad_x = 8.f;
			float pad_y = 3.f;
			float pw = ts.x + pad_x * 2.f;
			float ph = ts.y + pad_y * 2.f;
			ImU32 bg = oauth_pill_bg(st);
			int br = (bg >> 0) & 0xFF;
			int bg_g = (bg >> 8) & 0xFF;
			int bb = (bg >> 16) & 0xFF;
			int ba = static_cast<int>(((bg >> 24) & 0xFF) * alpha_mult);
			ImU32 final_bg = IM_COL32(br, bg_g, bb, ba);
			dl->AddRectFilled(pos, ImVec2(pos.x + pw, pos.y + ph), final_bg, 4.f);
			dl->AddText(ImVec2(pos.x + pad_x, pos.y + pad_y),
				IM_COL32(240, 240, 245, static_cast<int>(255 * alpha_mult)), label);
		}


		inline void render_tab_label(int idx, const char* label, const char* glyph,
			float content_h_unused)
		{
			(void)content_h_unused;
			auto& s = state();
			const int active = s.active_tab.load();
			const bool is_active = (active == idx);

			ImGui::PushID(idx);
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 8.f));

			ImVec4 bg_col = is_active ? ImVec4(0.18f, 0.18f, 0.24f, 1.f) : ImVec4(0.f, 0.f, 0.f, 0.f);
			ImVec4 fg_col = is_active ? ImVec4(0.95f, 0.95f, 1.f, 1.f) : ImVec4(0.65f, 0.65f, 0.74f, 1.f);
			ImGui::PushStyleColor(ImGuiCol_Button,        bg_col);
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.22f, 0.28f, 1.f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.26f, 0.26f, 0.32f, 1.f));
			ImGui::PushStyleColor(ImGuiCol_Text,          fg_col);

			char btn_label[96];
			std::snprintf(btn_label, sizeof(btn_label), "%s  %s", glyph, label);
			if (ImGui::Button(btn_label, ImVec2(132.f, 32.f)))
				s.active_tab.store(idx);

			ImGui::PopStyleColor(4);
			ImGui::PopStyleVar(2);
			ImGui::PopID();
		}


		inline void render_tab_accounts(float content_w, float content_h)
		{
			aida::auth_view::render(content_w, content_h);
		}


		inline void render_tab_providers(float content_w, float content_h)
		{
			aida::provider_view::render(content_w, content_h);
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
			(void)content_w;
			ImGui::PushID("##mcp_settings_tab");

			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "External MCP Servers");
			ImGui::Separator();

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

			float left_w = 240.f;
			float row_h  = 44.f;
			float list_h = (std::max)(content_h - 70.f, 200.f);

			ImGui::BeginChild("##mcp_list", ImVec2(left_w, list_h), true,
				ImGuiWindowFlags_NoSavedSettings);

			ImDrawList* dl = ImGui::GetWindowDrawList();

			for (int i = 0; i < static_cast<int>(servers.size()); ++i) {
				ImGui::PushID(i);
				const auto& srv = servers[i];

				mcp_client::oauth_status_t oauth = mcp_client::auth_status(srv.name);
				mcp_client::connection_state_t cstate = mcp_client::connection_state_t::disconnected;
				for (const auto& st : statuses) {
					if (st.name == srv.name) { cstate = st.state; break; }
				}

				ImVec2 cp = ImGui::GetCursorScreenPos();
				float row_w = ImGui::GetContentRegionAvail().x;
				bool selected = (i == s_sel_index);
				bool hovered = ImGui::IsMouseHoveringRect(cp, ImVec2(cp.x + row_w, cp.y + row_h));

				ImU32 bg = selected ? IM_COL32(50, 56, 76, 220)
				             : hovered ? IM_COL32(40, 44, 60, 180)
				                       : IM_COL32(0, 0, 0, 0);
				if (bg != 0)
					dl->AddRectFilled(cp, ImVec2(cp.x + row_w, cp.y + row_h), bg, 4.f);

				ImU32 conn_col = IM_COL32(120, 120, 130, 220);
				switch (cstate) {
				case mcp_client::connection_state_t::connected:    conn_col = IM_COL32(80, 200, 110, 240); break;
				case mcp_client::connection_state_t::connecting:
				case mcp_client::connection_state_t::reconnecting: conn_col = IM_COL32(220, 190, 70, 240); break;
				case mcp_client::connection_state_t::error:        conn_col = IM_COL32(220, 90, 90, 240);  break;
				default: break;
				}
				dl->AddCircleFilled(ImVec2(cp.x + 12.f, cp.y + 14.f), 5.f, conn_col);

				dl->AddText(ImVec2(cp.x + 26.f, cp.y + 6.f),
					IM_COL32(225, 226, 240, 255), srv.name.c_str());

				render_oauth_pill(dl, ImVec2(cp.x + 26.f, cp.y + 22.f), oauth, 1.f);

				ImGui::InvisibleButton("##row", ImVec2(row_w, row_h));
				if (ImGui::IsItemClicked()) {
					s_sel_index = i;
					refresh_buf();
				}

				if (oauth == mcp_client::oauth_status_t::needs_auth ||
				    oauth == mcp_client::oauth_status_t::needs_client_registration ||
				    oauth == mcp_client::oauth_status_t::failed)
				{
					float btn_x = cp.x + row_w - 78.f;
					float btn_y = cp.y + 12.f;
					ImGui::SetCursorScreenPos(ImVec2(btn_x, btn_y));
					if (ImGui::SmallButton("Sign in")) {
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
			}

			ImGui::EndChild();

			ImGui::SameLine();
			ImGui::BeginChild("##mcp_detail", ImVec2(0, list_h), true,
				ImGuiWindowFlags_NoSavedSettings);

			if (s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size())) {
				ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Server Configuration");
				ImGui::Separator();

				ImGui::Text("Name");
				ImGui::SetNextItemWidth(-12.f);
				ImGui::InputText("##mcp_name", s_name, sizeof(s_name));

				const char* transports[] = { "HTTP/SSE", "Stdio" };
				ImGui::Text("Transport");
				ImGui::SetNextItemWidth(-12.f);
				ImGui::Combo("##mcp_transport", &s_transport, transports, 2);

				if (s_transport == 0) {
					ImGui::Text("URL");
					ImGui::SetNextItemWidth(-12.f);
					ImGui::InputText("##mcp_url", s_url, sizeof(s_url));
					ImGui::Text("API Key");
					ImGui::SetNextItemWidth(-12.f);
					ImGui::InputText("##mcp_key", s_key, sizeof(s_key), ImGuiInputTextFlags_Password);
				} else {
					ImGui::Text("Command");
					ImGui::SetNextItemWidth(-12.f);
					ImGui::InputText("##mcp_cmd", s_cmd, sizeof(s_cmd));
					ImGui::Text("Args");
					ImGui::SetNextItemWidth(-12.f);
					ImGui::InputText("##mcp_args", s_args, sizeof(s_args));
				}

				ImGui::Checkbox("Enabled##mcp", &s_enabled);
				ImGui::SameLine();
				ImGui::Checkbox("Auto-connect", &s_auto);

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
				ImGui::TextColored(ImVec4(0.65f, 0.65f, 0.74f, 1.f), "No server selected");
			}

			ImGui::EndChild();

			ImGui::Dummy(ImVec2(0, 4));
			if (ImGui::Button("+ Add Server", ImVec2(150.f, 28.f))) {
				mcp_client_server_t srv;
				srv.name = "New Server";
				srv.url = "http://localhost:3001";
				servers.push_back(srv);
				s_sel_index = static_cast<int>(servers.size()) - 1;
				refresh_buf();
				g_sa_settings.save();
			}
			ImGui::SameLine();
			if (ImGui::Button("Apply Connection Changes", ImVec2(220.f, 28.f))) {
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
			ImGui::SameLine();
			if (ImGui::Button("Remove Selected", ImVec2(150.f, 28.f)) &&
			    s_sel_index >= 0 && s_sel_index < static_cast<int>(servers.size()))
			{
				servers.erase(servers.begin() + s_sel_index);
				if (s_sel_index > 0) --s_sel_index;
				refresh_buf();
				g_sa_settings.save();
			}

			ImGui::PopID();
		}


		inline void render_tab_permissions(float content_w, float content_h)
		{
			(void)content_w; (void)content_h;
			auto& s = state();
			std::lock_guard<std::mutex> lk(s.mtx);
			load_permissions_locked(s);

			ImGui::PushID("##permissions_tab");
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Auto-approval Policies");
			ImGui::Separator();

			bool changed = false;
			changed |= ImGui::Checkbox("Auto-approve read-only operations", &g_sa_settings.auto_approve_read);
			changed |= ImGui::Checkbox("Auto-approve write operations",    &g_sa_settings.auto_approve_write);
			changed |= ImGui::Checkbox("Auto-approve command execution",   &g_sa_settings.auto_approve_execute);
			changed |= ImGui::Checkbox("Auto-approve MCP tool calls",      &g_sa_settings.auto_approve_mcp);
			changed |= ImGui::Checkbox("Auto-approve mode/agent switches", &g_sa_settings.auto_approve_mode_switch);
			changed |= ImGui::Checkbox("Auto-approve subtask delegation",  &g_sa_settings.auto_approve_subtask);
			ImGui::Spacing();

			ImGui::Text("Per-task request cap (0 = unlimited)");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::InputInt("##perm_max_req", &g_sa_settings.auto_approve_max_requests, 1, 10);
			ImGui::SameLine();
			ImGui::Text("Per-task cost cap USD (0 = unlimited)");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::InputDouble("##perm_max_cost", &g_sa_settings.auto_approve_max_cost,
				0.5, 5.0, "%.2f");

			ImGui::Spacing();
			ImGui::Text("Allowed shell commands (CSV - prefixes ok)");
			ImGui::SetNextItemWidth(-12.f);
			if (ImGui::InputText("##perm_allow", s.perm_allowed_commands, sizeof(s.perm_allowed_commands)))
				changed = true;

			ImGui::Text("Denied shell commands (CSV)");
			ImGui::SetNextItemWidth(-12.f);
			if (ImGui::InputText("##perm_deny", s.perm_denied_commands, sizeof(s.perm_denied_commands)))
				changed = true;

			if (changed)
				persist_permissions_locked(s);

			ImGui::PopID();
		}


		inline void render_tab_compaction_cost(float content_w, float content_h)
		{
			(void)content_w; (void)content_h;
			auto& s = state();
			std::lock_guard<std::mutex> lk(s.mtx);
			load_compaction_locked(s);

			double now = ImGui::GetTime();
			std::string sid = ::chat_active_session();
			if (!sid.empty() && (now - s.compaction_last_refresh > 1.5 || sid != s.compaction_session_id)) {
				s.compaction_session_id   = sid;
				s.compaction_session_cost = aida::session::session_cost(sid);
				auto t = aida::session::session_tokens(sid);
				s.compaction_session_input       = t.input;
				s.compaction_session_output      = t.output;
				s.compaction_session_reasoning   = t.reasoning;
				s.compaction_session_cache_read  = t.cache_read;
				s.compaction_session_cache_write = t.cache_write;
				s.compaction_last_refresh = now;
			}

			ImGui::PushID("##compact_cost_tab");
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Auto-compaction Threshold");
			ImGui::Separator();

			bool changed = false;
			ImGui::Text("Trigger when used / context >= ratio");
			ImGui::SetNextItemWidth(-12.f);
			changed |= ImGui::SliderFloat("##compact_ratio", &s.compaction_trigger_ratio,
				0.50f, 0.98f, "%.2f");

			ImGui::Text("Preserve recent N messages (always keep)");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::InputInt("##compact_msg", &s.compaction_preserve_messages, 1, 5);
			s.compaction_preserve_messages = (std::max)(0, s.compaction_preserve_messages);

			ImGui::Text("Preserve recent tokens budget");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::InputInt("##compact_tok", &s.compaction_preserve_tokens, 256, 1024);
			s.compaction_preserve_tokens = (std::max)(0, s.compaction_preserve_tokens);

			if (changed)
				save_compaction_locked(s);

			ImGui::Spacing();
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Current Session Cost");
			ImGui::Separator();

			if (sid.empty()) {
				ImGui::TextColored(ImVec4(0.65f, 0.65f, 0.74f, 1.f), "No active session.");
			} else {
				char buf[256];
				std::snprintf(buf, sizeof(buf), "Session: %s", sid.c_str());
				ImGui::TextUnformatted(buf);
				std::snprintf(buf, sizeof(buf), "Total cost: $%.4f", s.compaction_session_cost);
				ImGui::TextUnformatted(buf);
				std::snprintf(buf, sizeof(buf),
					"Tokens - input: %lld   output: %lld   reasoning: %lld",
					static_cast<long long>(s.compaction_session_input),
					static_cast<long long>(s.compaction_session_output),
					static_cast<long long>(s.compaction_session_reasoning));
				ImGui::TextUnformatted(buf);
				std::snprintf(buf, sizeof(buf),
					"Cache - read: %lld   write: %lld",
					static_cast<long long>(s.compaction_session_cache_read),
					static_cast<long long>(s.compaction_session_cache_write));
				ImGui::TextUnformatted(buf);

				ImGui::Spacing();
				if (ImGui::Button("Run /compact now", ImVec2(180.f, 28.f))) {
					aida::compaction::compaction_options_t opts;
					opts.trigger_ratio              = static_cast<double>(s.compaction_trigger_ratio);
					opts.preserve_recent_messages   = s.compaction_preserve_messages;
					opts.preserve_recent_tokens     = s.compaction_preserve_tokens;
					aida::compaction::compaction_result_t res;
					if (!aida::compaction::run(sid, opts, res)) {
						toast_notification::push(std::string("Compaction failed: ") + res.error,
							toast_notification::toast_type_t::error);
					} else {
						char m[160];
						std::snprintf(m, sizeof(m), "Compacted %d msgs, freed %d tokens",
							res.messages_summarized, res.tokens_freed);
						toast_notification::push(m, toast_notification::toast_type_t::info);
					}
				}
			}
			ImGui::PopID();
		}


		inline void render_tab_editor_theme(float content_w, float content_h)
		{
			(void)content_w; (void)content_h;
			auto& s = state();
			std::lock_guard<std::mutex> lk(s.mtx);
			load_editor_locked(s);

			ImGui::PushID("##editor_theme_tab");
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Editor");
			ImGui::Separator();

			bool changed = false;
			ImGui::Text("Tab size");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::InputInt("##ed_tab", &s.ed_tab_size, 1, 2);
			s.ed_tab_size = (std::max)(s.ed_tab_size, 1);

			ImGui::Text("Font size");
			ImGui::SetNextItemWidth(220.f);
			changed |= ImGui::SliderFloat("##ed_font", &s.ed_font_size, 9.f, 32.f, "%.0f");

			changed |= ImGui::Checkbox("Show line numbers",       &s.ed_line_numbers);
			changed |= ImGui::Checkbox("Word wrap",                &s.ed_word_wrap);
			changed |= ImGui::Checkbox("Minimap",                  &s.ed_minimap);
			changed |= ImGui::Checkbox("Bracket match",            &s.ed_bracket_match);
			changed |= ImGui::Checkbox("Highlight current line",   &s.ed_highlight_line);
			changed |= ImGui::Checkbox("Auto-complete",            &s.ed_autocomplete);
			changed |= ImGui::Checkbox("Ghost text",               &s.ed_ghost_text);

			ImGui::Spacing();
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Theme");
			ImGui::Separator();

			static const char* theme_names[] = { "Mio", "Nagi", "Rias", "Kaneki" };
			ImGui::Text("Active theme");
			ImGui::SetNextItemWidth(220.f);
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

			ImGui::Spacing();
			ImGui::TextColored(ImVec4(0.78f, 0.80f, 0.88f, 1.f), "Auto-save");
			ImGui::Separator();

			bool autosave_changed = false;
			autosave_changed |= ImGui::Checkbox("Auto-save edited files", &g_sa_settings.auto_save_enabled);
			ImGui::Text("Auto-save interval (seconds)");
			ImGui::SetNextItemWidth(220.f);
			autosave_changed |= ImGui::InputInt("##autosave_int",
				&g_sa_settings.auto_save_interval_s, 1, 5);
			g_sa_settings.auto_save_interval_s = (std::max)(g_sa_settings.auto_save_interval_s, 5);

			if (changed)
				persist_editor_locked(s);
			if (autosave_changed)
				g_sa_settings.save();

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
		s.tab_anim = static_cast<float>(tab_accounts);
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
		s.active_tab.store(idx);
	}


	tab_index_t active_tab()
	{
		return static_cast<tab_index_t>(detail::state().active_tab.load());
	}


	void render_inline(float panel_w, float panel_h)
	{
		auto& s = detail::state();

		const float dt = ImGui::GetIO().DeltaTime;
		const float target = static_cast<float>(s.active_tab.load());
		s.tab_anim += (target - s.tab_anim) * (std::min)(dt * 14.f, 1.f);

		ImGui::PushStyleColor(ImGuiCol_Text,             ImVec4(0.92f, 0.92f, 0.97f, 1.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBg,          ImVec4(0.10f, 0.10f, 0.14f, 1.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,   ImVec4(0.14f, 0.14f, 0.19f, 1.f));
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive,    ImVec4(0.16f, 0.16f, 0.22f, 1.f));
		ImGui::PushStyleColor(ImGuiCol_Border,           ImVec4(1.f, 1.f, 1.f, 0.05f));
		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,  ImVec2(8.f, 5.f));
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,   ImVec2(6.f, 6.f));

		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 wp = ImGui::GetWindowPos();
		ImVec2 ws = ImGui::GetWindowSize();

		const float header_h = 38.f;
		dl->AddRectFilled(wp, ImVec2(wp.x + ws.x, wp.y + header_h),
			IM_COL32(14, 14, 20, 255));
		dl->AddLine(ImVec2(wp.x, wp.y + header_h), ImVec2(wp.x + ws.x, wp.y + header_h),
			IM_COL32(255, 255, 255, 18));

		ImGui::SetCursorPos(ImVec2(8.f, 7.f));
		ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.f, 0.f, 0.f, 0.f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.f, 1.f, 1.f, 0.08f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(1.f, 1.f, 1.f, 0.14f));
		if (ImGui::Button("<##settings_back", ImVec2(28.f, 24.f)))
			g_settings_open = false;
		ImGui::PopStyleColor(3);
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Back to chat");
		ImGui::SameLine();
		dl->AddText(ImGui::GetCursorScreenPos(),
			IM_COL32(225, 225, 240, 255), "Settings");

		const float side_w = 152.f;
		const float content_y = header_h + 4.f;
		const float content_h = panel_h - content_y - 8.f;
		const float content_w = panel_w - side_w - 8.f;

		ImGui::SetCursorPos(ImVec2(0.f, content_y));
		ImGui::BeginChild("##settings_sidebar", ImVec2(side_w, content_h), false,
			ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar);
		{
			static const char* tab_labels[tab_count] = {
				"Accounts",
				"Providers",
				"Agents",
				"Skills",
				"MCP Servers",
				"Permissions",
				"Compaction",
				"Editor"
			};
			static const char* tab_glyphs[tab_count] = {
				"@", "P", "A", "S", "M", "L", "C", "E"
			};

			ImGui::Dummy(ImVec2(0, 4));
			for (int i = 0; i < tab_count; ++i) {
				ImGui::SetCursorPosX(8.f);
				detail::render_tab_label(i, tab_labels[i], tab_glyphs[i], content_h);
				ImGui::Dummy(ImVec2(0, 2));
			}
		}
		ImGui::EndChild();

		ImGui::SetCursorPos(ImVec2(side_w + 6.f, content_y));
		ImGui::BeginChild("##settings_content", ImVec2(content_w, content_h), false,
			ImGuiWindowFlags_NoSavedSettings);
		{
			const int active = s.active_tab.load();
			ImGui::PushClipRect(ImGui::GetWindowPos(),
				ImVec2(ImGui::GetWindowPos().x + content_w,
					ImGui::GetWindowPos().y + content_h),
				true);
			switch (active) {
			case tab_accounts:        detail::render_tab_accounts(content_w, content_h); break;
			case tab_providers:       detail::render_tab_providers(content_w, content_h); break;
			case tab_agents:          detail::render_tab_agents(content_w, content_h); break;
			case tab_skills:          detail::render_tab_skills(content_w, content_h); break;
			case tab_mcp_servers:     detail::render_tab_mcp_servers(content_w, content_h); break;
			case tab_permissions:     detail::render_tab_permissions(content_w, content_h); break;
			case tab_compaction_cost: detail::render_tab_compaction_cost(content_w, content_h); break;
			case tab_editor_theme:    detail::render_tab_editor_theme(content_w, content_h); break;
			default:                  detail::render_tab_accounts(content_w, content_h); break;
			}
			ImGui::PopClipRect();
		}
		ImGui::EndChild();

		ImGui::PopStyleVar(3);
		ImGui::PopStyleColor(5);
	}


}
}
