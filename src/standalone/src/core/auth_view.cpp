#define NOMINMAX
#include "auth_view.hpp"

#include "auth_store.hpp"
#include "auth_codex.hpp"
#include "auth_copilot.hpp"
#include "auth_claude_code.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../helpers/globals.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>
#include <shellapi.h>

namespace aida {
namespace auth_view {

	namespace {

		enum class row_kind_t : int {
			oauth_claude_code = 0,
			oauth_codex,
			oauth_copilot,
			api_anthropic,
			api_openai,
		};

		struct row_def_t {
			row_kind_t kind;
			const char* display_name;
			const char* subtitle;
			const char* store_key;
			float accent_r;
			float accent_g;
			float accent_b;
			char glyph;
			bool is_oauth;
		};

		static const row_def_t k_rows[] = {
			{ row_kind_t::oauth_claude_code, "Claude Code",     "Anthropic OAuth (PKCE)",          "anthropic",      0.80f, 0.47f, 0.36f, 'C', true  },
			{ row_kind_t::oauth_codex,       "OpenAI Codex",    "ChatGPT OAuth (PKCE)",            "openai",         0.06f, 0.64f, 0.50f, 'O', true  },
			{ row_kind_t::oauth_copilot,     "GitHub Copilot",  "GitHub Device Code",              "github-copilot", 0.05f, 0.05f, 0.09f, 'G', true  },
			{ row_kind_t::api_anthropic,     "Anthropic API",   "Direct API key for api.anthropic.com", "anthropic", 0.80f, 0.47f, 0.36f, 'A', false },
			{ row_kind_t::api_openai,        "OpenAI API",      "Direct API key for api.openai.com",    "openai",    0.06f, 0.64f, 0.50f, 'O', false },
		};

		struct view_state_t {
			std::mutex mtx;

			std::unique_ptr<aida::auth::codex::codex_login_state_t> codex_state;
			std::unique_ptr<aida::auth::copilot::copilot_login_state_t> copilot_state;
			std::unique_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_code_state;

			std::atomic<bool> codex_modal_open{ false };
			std::atomic<bool> copilot_modal_open{ false };
			std::atomic<bool> claude_code_modal_open{ false };

			std::atomic<bool> codex_starting{ false };
			std::atomic<bool> copilot_starting{ false };
			std::atomic<bool> claude_code_starting{ false };

			std::thread codex_start_thread;
			std::thread copilot_start_thread;
			std::thread claude_code_start_thread;

			std::string err;

			aida::events::subscription_handle_t sub_completed;
			aida::events::subscription_handle_t sub_failed;

			std::string last_completed_provider;
			std::string last_completed_email;
			std::atomic<bool> have_completed_event{ false };

			std::string last_failed_provider;
			std::string last_failed_error;
			std::atomic<bool> have_failed_event{ false };

			char api_key_buf[5][1024]{};
			bool api_key_show[5]{};

			char custom_client_id_buf[3][512]{};
			char custom_redirect_uri_buf[3][512]{};
			char custom_scopes_buf[3][512]{};
			bool custom_loaded[3]{};

			float modal_anim = 0.f;
			float spinner_time = 0.f;

			int active_top_tab = 0;
		};

		static view_state_t g_state;

		static int row_index(row_kind_t k)
		{
			return static_cast<int>(k);
		}

		static void set_err_locked(const std::string& msg)
		{
			g_state.err = msg;
		}

		static int64_t now_unix()
		{
			return static_cast<int64_t>(std::time(nullptr));
		}

		static std::string format_relative_time(int64_t expires_unix)
		{
			int64_t now = now_unix();
			int64_t diff = expires_unix - now;
			if (diff <= 0) return "expired";

			if (diff < 60) {
				return "expires in " + std::to_string(diff) + "s";
			}
			if (diff < 3600) {
				return "expires in " + std::to_string(diff / 60) + " min";
			}
			if (diff < 86400) {
				int64_t hours = diff / 3600;
				int64_t mins = (diff % 3600) / 60;
				return "expires in " + std::to_string(hours) + "h " + std::to_string(mins) + "m";
			}
			int64_t days = diff / 86400;
			return "expires in " + std::to_string(days) + " day" + (days == 1 ? "" : "s");
		}

		static std::string mask_key(const std::string& k)
		{
			if (k.size() <= 8) return std::string(k.size(), '*');
			std::string out;
			out.reserve(k.size());
			out.append(k.substr(0, 4));
			out.append(k.size() - 8, '*');
			out.append(k.substr(k.size() - 4));
			return out;
		}

		static void open_url_in_browser(const std::string& url)
		{
			int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
			if (wlen <= 0) return;
			std::wstring wurl(static_cast<size_t>(wlen), L'\0');
			MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wurl[0], wlen);
			if (!wurl.empty() && wurl.back() == L'\0') wurl.pop_back();
			ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
		}

		static void start_codex_login()
		{
			if (g_state.codex_starting.exchange(true)) return;

			std::thread prior;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_start_thread.joinable())
					prior = std::move(g_state.codex_start_thread);
				g_state.codex_state = std::make_unique<aida::auth::codex::codex_login_state_t>();
				g_state.codex_modal_open.store(true);
				g_state.modal_anim = 0.f;
			}
			if (prior.joinable()) prior.join();

			std::thread t([]() {
				aida::auth::codex::codex_login_state_t* sp = nullptr;
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp = g_state.codex_state.get();
				}
				if (sp == nullptr) {
					g_state.codex_starting.store(false);
					return;
				}
				if (!aida::auth::codex::start_login(*sp)) {
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp->error = aida::auth::codex::last_error();
					sp->done.store(true);
					set_err_locked(sp->error);
				}
				g_state.codex_starting.store(false);
			});

			std::lock_guard<std::mutex> lk(g_state.mtx);
			g_state.codex_start_thread = std::move(t);
		}

		static void start_copilot_login()
		{
			if (g_state.copilot_starting.exchange(true)) return;

			std::thread prior;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.copilot_start_thread.joinable())
					prior = std::move(g_state.copilot_start_thread);
				g_state.copilot_state = std::make_unique<aida::auth::copilot::copilot_login_state_t>();
				g_state.copilot_modal_open.store(true);
				g_state.modal_anim = 0.f;
			}
			if (prior.joinable()) prior.join();

			std::thread t([]() {
				aida::auth::copilot::copilot_login_state_t* sp = nullptr;
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp = g_state.copilot_state.get();
				}
				if (sp == nullptr) {
					g_state.copilot_starting.store(false);
					return;
				}
				if (!aida::auth::copilot::start_login(*sp, std::nullopt)) {
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp->error = aida::auth::copilot::last_error();
					sp->done.store(true);
					set_err_locked(sp->error);
				}
				g_state.copilot_starting.store(false);
			});

			std::lock_guard<std::mutex> lk(g_state.mtx);
			g_state.copilot_start_thread = std::move(t);
		}

		static void start_claude_code_login()
		{
			if (g_state.claude_code_starting.exchange(true)) return;

			std::thread prior;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.claude_code_start_thread.joinable())
					prior = std::move(g_state.claude_code_start_thread);
				g_state.claude_code_state = std::make_unique<aida::auth::claude_code::claude_code_login_state_t>();
				g_state.claude_code_modal_open.store(true);
				g_state.modal_anim = 0.f;
			}
			if (prior.joinable()) prior.join();

			std::thread t([]() {
				aida::auth::claude_code::claude_code_login_state_t* sp = nullptr;
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp = g_state.claude_code_state.get();
				}
				if (sp == nullptr) {
					g_state.claude_code_starting.store(false);
					return;
				}
				if (!aida::auth::claude_code::start_login(*sp)) {
					std::lock_guard<std::mutex> lk(g_state.mtx);
					sp->error = aida::auth::claude_code::last_error();
					sp->done.store(true);
					set_err_locked(sp->error);
				}
				g_state.claude_code_starting.store(false);
			});

			std::lock_guard<std::mutex> lk(g_state.mtx);
			g_state.claude_code_start_thread = std::move(t);
		}

		static void close_codex_modal()
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (g_state.codex_state)
				aida::auth::codex::cancel_login(*g_state.codex_state);
			g_state.codex_modal_open.store(false);
		}

		static void close_copilot_modal()
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (g_state.copilot_state)
				aida::auth::copilot::cancel_login(*g_state.copilot_state);
			g_state.copilot_modal_open.store(false);
		}

		static void close_claude_code_modal()
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (g_state.claude_code_state)
				aida::auth::claude_code::cancel_login(*g_state.claude_code_state);
			g_state.claude_code_modal_open.store(false);
		}

		static void poll_active_logins()
		{
			std::unique_lock<std::mutex> lk(g_state.mtx);

			if (g_state.codex_modal_open.load() && g_state.codex_state) {
				auto* sp = g_state.codex_state.get();
				bool finished = sp->done.load();
				if (finished) {
					lk.unlock();
					if (aida::auth::codex::poll_login(*sp)) {
						aida::auth::auth_info_t info;
						aida::auth::store::get("openai", info);
						std::string disp = info.email.empty() ? info.account_id : info.email;
						if (disp.empty()) disp = "OpenAI account";
						toast_notification::push("Signed in: " + disp,
							toast_notification::toast_type_t::info, 5.0f);
						aida::events::publish(aida::events::event_oauth_completed,
							aida::events::oauth_completed_t{ "openai", disp });
					} else {
						std::string err = aida::auth::codex::last_error();
						if (err.empty()) err = sp->error;
						if (err.empty()) err = "OpenAI login failed";
						toast_notification::push("OpenAI login failed: " + err,
							toast_notification::toast_type_t::error, 6.0f);
						aida::events::publish(aida::events::event_oauth_failed,
							aida::events::oauth_failed_t{ "openai", err });
					}
					g_state.codex_modal_open.store(false);
					lk.lock();
				}
			}

			if (g_state.copilot_modal_open.load() && g_state.copilot_state) {
				auto* sp = g_state.copilot_state.get();
				int64_t now = now_unix();
				bool ready_to_poll = sp->next_poll_unix == 0 || now >= sp->next_poll_unix;
				bool finished = sp->done.load();
				bool can_poll = !finished && ready_to_poll && !sp->device_code.empty();
				bool start_failed = finished && sp->device_code.empty();

				if (start_failed) {
					std::string err = sp->error;
					if (err.empty()) err = aida::auth::copilot::last_error();
					if (err.empty()) err = "Copilot login failed";
					lk.unlock();
					toast_notification::push("Copilot login failed: " + err,
						toast_notification::toast_type_t::error, 6.0f);
					aida::events::publish(aida::events::event_oauth_failed,
						aida::events::oauth_failed_t{ "github-copilot", err });
					g_state.copilot_modal_open.store(false);
					lk.lock();
				} else if (can_poll) {
					lk.unlock();
					if (aida::auth::copilot::poll_login(*sp)) {
						aida::auth::auth_info_t info;
						aida::auth::store::get("github-copilot", info);
						std::string disp = info.email.empty() ? info.account_id : info.email;
						if (disp.empty()) disp = "GitHub account";
						toast_notification::push("Signed in: " + disp,
							toast_notification::toast_type_t::info, 5.0f);
						aida::events::publish(aida::events::event_oauth_completed,
							aida::events::oauth_completed_t{ "github-copilot", disp });
						g_state.copilot_modal_open.store(false);
					} else if (sp->done.load()) {
						std::string err = aida::auth::copilot::last_error();
						if (err.empty()) err = sp->error;
						if (err.empty()) err = "Copilot login failed";
						toast_notification::push("Copilot login failed: " + err,
							toast_notification::toast_type_t::error, 6.0f);
						aida::events::publish(aida::events::event_oauth_failed,
							aida::events::oauth_failed_t{ "github-copilot", err });
						g_state.copilot_modal_open.store(false);
					}
					lk.lock();
				}
			}

			if (g_state.claude_code_modal_open.load() && g_state.claude_code_state) {
				auto* sp = g_state.claude_code_state.get();
				bool finished = sp->done.load();
				if (finished) {
					lk.unlock();
					if (aida::auth::claude_code::poll_login(*sp)) {
						aida::auth::auth_info_t info;
						aida::auth::store::get("anthropic", info);
						std::string disp = info.email.empty() ? info.account_id : info.email;
						if (disp.empty()) disp = "Anthropic account";
						toast_notification::push("Signed in: " + disp,
							toast_notification::toast_type_t::info, 5.0f);
						aida::events::publish(aida::events::event_oauth_completed,
							aida::events::oauth_completed_t{ "anthropic", disp });
					} else {
						std::string err = aida::auth::claude_code::last_error();
						if (err.empty()) err = sp->error;
						if (err.empty()) err = "Claude Code login failed";
						toast_notification::push("Claude Code login failed: " + err,
							toast_notification::toast_type_t::error, 6.0f);
						aida::events::publish(aida::events::event_oauth_failed,
							aida::events::oauth_failed_t{ "anthropic", err });
					}
					g_state.claude_code_modal_open.store(false);
					lk.lock();
				}
			}
		}

		static void render_provider_avatar(ImDrawList* dl, float cx, float cy, float radius,
			float r, float g, float b, char glyph)
		{
			ImU32 fill = IM_COL32(
				static_cast<int>(r * 255.f),
				static_cast<int>(g * 255.f),
				static_cast<int>(b * 255.f),
				230);
			ImU32 ring = IM_COL32(
				static_cast<int>(r * 255.f * 0.6f),
				static_cast<int>(g * 255.f * 0.6f),
				static_cast<int>(b * 255.f * 0.6f),
				255);

			dl->AddCircleFilled(ImVec2(cx, cy), radius, fill, 28);
			dl->AddCircle(ImVec2(cx, cy), radius, ring, 28, 1.5f);

			char buf[2] = { glyph, 0 };
			ImVec2 ts = ImGui::CalcTextSize(buf);
			float lum = 0.299f * r + 0.587f * g + 0.114f * b;
			ImU32 text_col = lum < 0.5f
				? IM_COL32(245, 245, 250, 255)
				: IM_COL32(20, 20, 28, 255);
			dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f), text_col, buf);
		}

		static void render_status_pill(ImDrawList* dl, float x, float y,
			const char* text, ImU32 bg, ImU32 fg)
		{
			ImVec2 ts = ImGui::CalcTextSize(text);
			float pad_x = 7.f;
			float pad_y = 2.f;
			float w = ts.x + pad_x * 2.f;
			float h = ts.y + pad_y * 2.f;
			dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + h), bg, h * 0.5f);
			dl->AddText(ImVec2(x + pad_x, y + pad_y), fg, text);
		}

		struct row_status_t {
			std::string pill_text;
			ImU32 pill_bg;
			ImU32 pill_fg;
			std::string detail_text;
			bool logged_in = false;
			bool expired = false;
		};

		static row_status_t compute_status(const row_def_t& def)
		{
			row_status_t s;
			aida::auth::auth_info_t info;
			bool have = aida::auth::store::get(def.store_key, info);

			if (def.is_oauth) {
				if (have && info.kind == aida::auth::auth_kind_t::oauth) {
					int64_t now = now_unix();
					if (info.expires_unix > 0 && info.expires_unix <= now) {
						s.expired = true;
						s.pill_text = "Token expired";
						s.pill_bg = IM_COL32(80, 32, 32, 220);
						s.pill_fg = IM_COL32(245, 180, 180, 255);
						s.detail_text = info.email.empty() ? info.account_id : info.email;
					} else {
						s.logged_in = true;
						s.pill_text = info.expires_unix > 0
							? format_relative_time(info.expires_unix)
							: std::string("Logged in");
						s.pill_bg = IM_COL32(28, 64, 38, 220);
						s.pill_fg = IM_COL32(170, 230, 180, 255);
						s.detail_text = info.email.empty() ? info.account_id : info.email;
						if (s.detail_text.empty()) s.detail_text = "Signed in";
					}
				} else if (have && info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty()) {
					s.pill_text = "API key active";
					s.pill_bg = IM_COL32(40, 50, 70, 220);
					s.pill_fg = IM_COL32(180, 200, 230, 255);
					s.detail_text = "Clear API key to use OAuth";
				} else {
					s.pill_text = "Logged out";
					s.pill_bg = IM_COL32(50, 50, 58, 220);
					s.pill_fg = IM_COL32(180, 180, 195, 255);
					s.detail_text = "Sign in with your account";
				}
			} else {
				if (have && info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty()) {
					s.logged_in = true;
					s.pill_text = "API key set";
					s.pill_bg = IM_COL32(28, 64, 38, 220);
					s.pill_fg = IM_COL32(170, 230, 180, 255);
					s.detail_text = mask_key(info.api_key);
				} else if (have && info.kind == aida::auth::auth_kind_t::oauth) {
					s.pill_text = "OAuth active";
					s.pill_bg = IM_COL32(40, 50, 70, 220);
					s.pill_fg = IM_COL32(180, 200, 230, 255);
					s.detail_text = "Sign out of OAuth to use API key";
				} else {
					s.pill_text = "Not configured";
					s.pill_bg = IM_COL32(50, 50, 58, 220);
					s.pill_fg = IM_COL32(180, 180, 195, 255);
					s.detail_text = "Paste your API key to enable";
				}
			}
			return s;
		}

		static void save_api_key(const row_def_t& def, const std::string& key)
		{
			aida::auth::auth_info_t info;
			aida::auth::store::get(def.store_key, info);
			info.kind = aida::auth::auth_kind_t::api;
			info.api_key = key;
			info.access.clear();
			info.refresh.clear();
			info.expires_unix = 0;
			info.email.clear();
			info.account_id.clear();
			if (!aida::auth::store::set(def.store_key, info)) {
				std::lock_guard<std::mutex> lk(g_state.mtx);
				set_err_locked("auth_view: failed to persist api key: " + aida::auth::store::last_error());
				toast_notification::push("Failed to save API key",
					toast_notification::toast_type_t::error, 5.0f);
				return;
			}
			toast_notification::push(std::string(def.display_name) + " API key saved",
				toast_notification::toast_type_t::info, 4.0f);
		}

		static void clear_credentials(const row_def_t& def, bool only_oauth, bool only_api)
		{
			aida::auth::auth_info_t info;
			if (!aida::auth::store::get(def.store_key, info)) {
				return;
			}
			if (only_oauth && info.kind != aida::auth::auth_kind_t::oauth) return;
			if (only_api && info.kind != aida::auth::auth_kind_t::api) return;

			std::string saved_client = info.custom_client_id;
			std::string saved_redirect = info.custom_redirect_uri;
			std::vector<std::string> saved_scopes = info.custom_scopes;

			info = aida::auth::auth_info_t{};
			info.custom_client_id = std::move(saved_client);
			info.custom_redirect_uri = std::move(saved_redirect);
			info.custom_scopes = std::move(saved_scopes);

			if (!aida::auth::store::set(def.store_key, info)) {
				toast_notification::push("Failed to clear credentials",
					toast_notification::toast_type_t::error, 5.0f);
				return;
			}
			toast_notification::push(std::string(def.display_name) + " signed out",
				toast_notification::toast_type_t::info, 3.5f);
		}

		static bool refresh_token_for(row_kind_t k)
		{
			switch (k) {
			case row_kind_t::oauth_claude_code:
				return aida::auth::claude_code::refresh_token();
			case row_kind_t::oauth_codex:
				return aida::auth::codex::refresh_token();
			case row_kind_t::oauth_copilot:
				return aida::auth::copilot::refresh_token();
			default:
				return false;
			}
		}

		static const char* refresh_last_error_for(row_kind_t k)
		{
			switch (k) {
			case row_kind_t::oauth_claude_code: return aida::auth::claude_code::last_error().c_str();
			case row_kind_t::oauth_codex:       return aida::auth::codex::last_error().c_str();
			case row_kind_t::oauth_copilot:     return aida::auth::copilot::last_error().c_str();
			default: return "";
			}
		}

		static void render_provider_row(const row_def_t& def, float row_w, int idx)
		{
			const float row_h = 64.f;
			ImVec2 origin = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();

			ImU32 row_bg = IM_COL32(255, 255, 255, 6);
			dl->AddRectFilled(origin, ImVec2(origin.x + row_w, origin.y + row_h), row_bg, 6.f);

			float left_pad = 12.f;
			float avatar_radius = 18.f;
			float avatar_cx = origin.x + left_pad + avatar_radius;
			float avatar_cy = origin.y + row_h * 0.5f;

			render_provider_avatar(dl, avatar_cx, avatar_cy, avatar_radius,
				def.accent_r, def.accent_g, def.accent_b, def.glyph);

			float text_x = avatar_cx + avatar_radius + 14.f;
			float text_y = origin.y + 10.f;

			dl->AddText(ImVec2(text_x, text_y),
				IM_COL32(232, 232, 245, 245), def.display_name);

			ImU32 sub_col = IM_COL32(150, 152, 168, 200);
			ImVec2 sub_size = ImGui::CalcTextSize(def.subtitle);
			dl->AddText(ImVec2(text_x, text_y + sub_size.y + 4.f), sub_col, def.subtitle);

			row_status_t status = compute_status(def);
			float pill_y = origin.y + row_h - 22.f;
			render_status_pill(dl, text_x, pill_y, status.pill_text.c_str(),
				status.pill_bg, status.pill_fg);

			if (!status.detail_text.empty()) {
				ImVec2 ps = ImGui::CalcTextSize(status.pill_text.c_str());
				float detail_x = text_x + ps.x + 14.f + 14.f;
				dl->AddText(ImVec2(detail_x, pill_y + 2.f),
					IM_COL32(168, 170, 188, 200), status.detail_text.c_str());
			}

			ImGui::SetCursorScreenPos(ImVec2(origin.x + row_w - 360.f, origin.y + 16.f));
			ImGui::PushID(idx);

			if (def.is_oauth) {
				if (status.logged_in || status.expired) {
					ImGui::PushStyleColor(ImGuiCol_Button,        IM_COL32(54, 60, 80, 200));
					ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(74, 82, 110, 220));
					ImGui::PushStyleColor(ImGuiCol_ButtonActive,  IM_COL32(48, 54, 76, 240));
					if (ImGui::Button("Refresh", ImVec2(86.f, 30.f))) {
						if (refresh_token_for(def.kind)) {
							toast_notification::push(std::string(def.display_name) + " token refreshed",
								toast_notification::toast_type_t::info, 3.5f);
						} else {
							std::string err = refresh_last_error_for(def.kind);
							if (err.empty()) err = "refresh failed";
							toast_notification::push(
								std::string(def.display_name) + " refresh failed: " + err,
								toast_notification::toast_type_t::error, 5.0f);
						}
					}
					ImGui::PopStyleColor(3);

					ImGui::SameLine(0.f, 8.f);

					ImGui::PushStyleColor(ImGuiCol_Button,        IM_COL32(96, 36, 36, 200));
					ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(132, 50, 50, 220));
					ImGui::PushStyleColor(ImGuiCol_ButtonActive,  IM_COL32(86, 32, 32, 240));
					if (ImGui::Button("Sign out", ImVec2(86.f, 30.f))) {
						clear_credentials(def, true, false);
					}
					ImGui::PopStyleColor(3);
				} else {
					float ar = globals::ui::accent.x;
					float ag = globals::ui::accent.y;
					float ab = globals::ui::accent.z;
					ImGui::PushStyleColor(ImGuiCol_Button,
						ImVec4(ar * 0.42f, ag * 0.42f, ab * 0.42f, 0.85f));
					ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
						ImVec4(ar * 0.62f, ag * 0.62f, ab * 0.62f, 0.95f));
					ImGui::PushStyleColor(ImGuiCol_ButtonActive,
						ImVec4(ar * 0.52f, ag * 0.52f, ab * 0.52f, 1.f));
					bool busy = (def.kind == row_kind_t::oauth_claude_code && g_state.claude_code_modal_open.load())
						|| (def.kind == row_kind_t::oauth_codex && g_state.codex_modal_open.load())
						|| (def.kind == row_kind_t::oauth_copilot && g_state.copilot_modal_open.load());
					const char* label = busy ? "Signing in..." : "Sign in";
					if (ImGui::Button(label, ImVec2(178.f, 30.f)) && !busy) {
						if (def.kind == row_kind_t::oauth_claude_code) start_claude_code_login();
						else if (def.kind == row_kind_t::oauth_codex)  start_codex_login();
						else if (def.kind == row_kind_t::oauth_copilot) start_copilot_login();
					}
					ImGui::PopStyleColor(3);
				}
			} else {
				int b_idx = row_index(def.kind);
				if (b_idx < 0 || b_idx >= 5) b_idx = 0;

				ImGui::SetNextItemWidth(220.f);
				ImGuiInputTextFlags flags = ImGuiInputTextFlags_None;
				if (!g_state.api_key_show[b_idx])
					flags |= ImGuiInputTextFlags_Password;

				ImGui::InputTextWithHint("##api_key", "Paste API key",
					g_state.api_key_buf[b_idx],
					sizeof(g_state.api_key_buf[b_idx]), flags);

				ImGui::SameLine(0.f, 6.f);
				ImGui::Checkbox("##show", &g_state.api_key_show[b_idx]);
				if (ImGui::IsItemHovered()) ImGui::SetTooltip("Reveal key");

				ImGui::SameLine(0.f, 8.f);
				if (ImGui::Button("Save", ImVec2(56.f, 30.f))) {
					std::string k = g_state.api_key_buf[b_idx];
					if (!k.empty()) {
						save_api_key(def, k);
						std::memset(g_state.api_key_buf[b_idx], 0,
							sizeof(g_state.api_key_buf[b_idx]));
					}
				}
				if (status.logged_in) {
					ImGui::SameLine(0.f, 6.f);
					ImGui::PushStyleColor(ImGuiCol_Button,        IM_COL32(96, 36, 36, 200));
					ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(132, 50, 50, 220));
					ImGui::PushStyleColor(ImGuiCol_ButtonActive,  IM_COL32(86, 32, 32, 240));
					if (ImGui::Button("Clear", ImVec2(56.f, 30.f))) {
						clear_credentials(def, false, true);
					}
					ImGui::PopStyleColor(3);
				}
			}

			ImGui::PopID();

			float sep_y = origin.y + row_h - 1.f;
			dl->AddLine(ImVec2(origin.x + 8.f, sep_y),
				ImVec2(origin.x + row_w - 8.f, sep_y),
				IM_COL32(255, 255, 255, 14), 1.f);

			ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + row_h + 6.f));
		}

		static void render_providers_tab(float panel_w, float panel_h)
		{
			(void)panel_h;
			float row_w = panel_w - 16.f;
			ImGui::Dummy(ImVec2(0.f, 4.f));
			for (int i = 0; i < static_cast<int>(sizeof(k_rows) / sizeof(k_rows[0])); ++i) {
				render_provider_row(k_rows[i], row_w, i);
			}
		}

		static void load_custom_buf(int b_idx)
		{
			if (b_idx < 0 || b_idx >= 3) return;
			if (g_state.custom_loaded[b_idx]) return;

			const char* keys[3] = { "anthropic", "openai", "github-copilot" };
			aida::auth::auth_info_t info;
			aida::auth::store::get(keys[b_idx], info);

			std::strncpy(g_state.custom_client_id_buf[b_idx],
				info.custom_client_id.c_str(),
				sizeof(g_state.custom_client_id_buf[b_idx]) - 1);
			g_state.custom_client_id_buf[b_idx][sizeof(g_state.custom_client_id_buf[b_idx]) - 1] = '\0';

			std::strncpy(g_state.custom_redirect_uri_buf[b_idx],
				info.custom_redirect_uri.c_str(),
				sizeof(g_state.custom_redirect_uri_buf[b_idx]) - 1);
			g_state.custom_redirect_uri_buf[b_idx][sizeof(g_state.custom_redirect_uri_buf[b_idx]) - 1] = '\0';

			std::string scopes_joined;
			for (size_t i = 0; i < info.custom_scopes.size(); ++i) {
				if (i > 0) scopes_joined += ",";
				scopes_joined += info.custom_scopes[i];
			}
			std::strncpy(g_state.custom_scopes_buf[b_idx],
				scopes_joined.c_str(),
				sizeof(g_state.custom_scopes_buf[b_idx]) - 1);
			g_state.custom_scopes_buf[b_idx][sizeof(g_state.custom_scopes_buf[b_idx]) - 1] = '\0';

			g_state.custom_loaded[b_idx] = true;
		}

		static void save_custom_buf(int b_idx)
		{
			if (b_idx < 0 || b_idx >= 3) return;
			const char* keys[3] = { "anthropic", "openai", "github-copilot" };
			aida::auth::auth_info_t info;
			aida::auth::store::get(keys[b_idx], info);

			info.custom_client_id = g_state.custom_client_id_buf[b_idx];
			info.custom_redirect_uri = g_state.custom_redirect_uri_buf[b_idx];

			info.custom_scopes.clear();
			std::string raw = g_state.custom_scopes_buf[b_idx];
			std::string token;
			for (char c : raw) {
				if (c == ',' || c == ' ' || c == ';') {
					if (!token.empty()) {
						info.custom_scopes.push_back(token);
						token.clear();
					}
				} else {
					token.push_back(c);
				}
			}
			if (!token.empty()) info.custom_scopes.push_back(token);

			if (!aida::auth::store::set(keys[b_idx], info)) {
				toast_notification::push("Failed to save custom OAuth config",
					toast_notification::toast_type_t::error, 5.0f);
				return;
			}
			toast_notification::push("Custom OAuth saved",
				toast_notification::toast_type_t::info, 3.5f);
		}

		static void reset_custom_buf(int b_idx)
		{
			if (b_idx < 0 || b_idx >= 3) return;
			std::memset(g_state.custom_client_id_buf[b_idx], 0,
				sizeof(g_state.custom_client_id_buf[b_idx]));
			std::memset(g_state.custom_redirect_uri_buf[b_idx], 0,
				sizeof(g_state.custom_redirect_uri_buf[b_idx]));
			std::memset(g_state.custom_scopes_buf[b_idx], 0,
				sizeof(g_state.custom_scopes_buf[b_idx]));

			const char* keys[3] = { "anthropic", "openai", "github-copilot" };
			aida::auth::auth_info_t info;
			aida::auth::store::get(keys[b_idx], info);
			info.custom_client_id.clear();
			info.custom_redirect_uri.clear();
			info.custom_scopes.clear();
			aida::auth::store::set(keys[b_idx], info);
			toast_notification::push("Reset to AiDA default OAuth app",
				toast_notification::toast_type_t::info, 3.5f);
		}

		static void render_custom_provider_card(const char* title, int b_idx,
			const char* default_redirect, const char* default_scopes_hint)
		{
			ImGui::PushID(b_idx + 100);

			float ar = globals::ui::accent.x;
			float ag = globals::ui::accent.y;
			float ab = globals::ui::accent.z;

			ImVec2 cur = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			float card_w = ImGui::GetContentRegionAvail().x;
			float card_h = 184.f;
			dl->AddRectFilled(cur, ImVec2(cur.x + card_w, cur.y + card_h),
				IM_COL32(255, 255, 255, 8), 6.f);
			dl->AddRect(cur, ImVec2(cur.x + card_w, cur.y + card_h),
				IM_COL32(static_cast<int>(ar * 60.f),
					static_cast<int>(ag * 60.f),
					static_cast<int>(ab * 60.f), 90), 6.f, 0, 1.f);

			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 10.f));
			ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.96f, 1.f), "%s", title);

			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 36.f));
			ImGui::TextDisabled("client_id");
			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 52.f));
			ImGui::SetNextItemWidth(card_w - 24.f);
			ImGui::InputTextWithHint("##cid", "Custom OAuth client_id",
				g_state.custom_client_id_buf[b_idx],
				sizeof(g_state.custom_client_id_buf[b_idx]));

			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 86.f));
			ImGui::TextDisabled("redirect_uri");
			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 102.f));
			ImGui::SetNextItemWidth((card_w - 24.f) * 0.55f);
			ImGui::InputTextWithHint("##ruri", default_redirect,
				g_state.custom_redirect_uri_buf[b_idx],
				sizeof(g_state.custom_redirect_uri_buf[b_idx]));

			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f + (card_w - 24.f) * 0.55f + 8.f, cur.y + 86.f));
			ImGui::TextDisabled("scopes (comma-separated)");
			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f + (card_w - 24.f) * 0.55f + 8.f, cur.y + 102.f));
			ImGui::SetNextItemWidth((card_w - 24.f) * 0.45f - 8.f);
			ImGui::InputTextWithHint("##scp", default_scopes_hint,
				g_state.custom_scopes_buf[b_idx],
				sizeof(g_state.custom_scopes_buf[b_idx]));

			ImGui::SetCursorScreenPos(ImVec2(cur.x + 12.f, cur.y + 138.f));
			ImGui::PushStyleColor(ImGuiCol_Button,
				ImVec4(ar * 0.42f, ag * 0.42f, ab * 0.42f, 0.85f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
				ImVec4(ar * 0.62f, ag * 0.62f, ab * 0.62f, 0.95f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,
				ImVec4(ar * 0.52f, ag * 0.52f, ab * 0.52f, 1.f));
			if (ImGui::Button("Save", ImVec2(84.f, 30.f))) {
				save_custom_buf(b_idx);
			}
			ImGui::PopStyleColor(3);

			ImGui::SameLine(0.f, 8.f);
			ImGui::PushStyleColor(ImGuiCol_Button,        IM_COL32(54, 60, 80, 200));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(74, 82, 110, 220));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive,  IM_COL32(48, 54, 76, 240));
			if (ImGui::Button("Reset to default", ImVec2(140.f, 30.f))) {
				reset_custom_buf(b_idx);
				g_state.custom_loaded[b_idx] = false;
				load_custom_buf(b_idx);
			}
			ImGui::PopStyleColor(3);

			ImGui::SetCursorScreenPos(ImVec2(cur.x, cur.y + card_h + 10.f));

			ImGui::PopID();
		}

		static void render_custom_oauth_tab(float panel_w, float panel_h)
		{
			(void)panel_h;
			(void)panel_w;

			for (int i = 0; i < 3; ++i) load_custom_buf(i);

			ImGui::Dummy(ImVec2(0.f, 4.f));

			float ar = globals::ui::accent.x;
			float ag = globals::ui::accent.y;
			float ab = globals::ui::accent.z;

			ImVec2 cur = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			float w = ImGui::GetContentRegionAvail().x;
			ui_anim::render_inline_callout(dl,
				cur.x, cur.y, w, 36.f,
				"If you've registered your own AiDA OAuth app, paste your credentials here. Leave blank to use AiDA's default app.",
				ui_anim::callout_kind_t::info, ar, ag, ab, 1.f);
			ImGui::Dummy(ImVec2(0.f, 44.f));

			render_custom_provider_card("Anthropic (Claude Code)", 0,
				"http://127.0.0.1:0/callback", "org:create_api_key,user:profile,user:inference");

			render_custom_provider_card("OpenAI (Codex / ChatGPT)", 1,
				"http://127.0.0.1:1455/auth/callback", "openid,profile,email,offline_access");

			render_custom_provider_card("GitHub Copilot", 2,
				"(device-code flow ignores redirect_uri)", "read:user,read:org");
		}

		static void render_modal_chrome(ImDrawList* fdl, float& anim, float dt,
			float pw, float ph, float& out_px, float& out_py, float& out_alpha)
		{
			anim += dt * 5.f;
			if (anim > 1.f) anim = 1.f;

			ImVec2 display = ImGui::GetIO().DisplaySize;
			fdl->AddRectFilled(ImVec2(0, 0), display,
				IM_COL32(0, 0, 0, static_cast<int>(140 * anim)));

			float scale = 0.92f + 0.08f * anim;
			float sw = pw * scale;
			float sh = ph * scale;
			float px = display.x * 0.5f - sw * 0.5f;
			float py = display.y * 0.5f - sh * 0.5f - 20.f * (1.f - anim);
			float alpha = anim;

			for (int s = 0; s < 4; ++s) {
				float off = 4.f + s * 3.f;
				fdl->AddRectFilled(
					ImVec2(px + off, py + off),
					ImVec2(px + sw + off, py + sh + off),
					IM_COL32(0, 0, 0, static_cast<int>(30 * alpha * (4 - s) / 4.f)), 12.f);
			}

			float ax = globals::ui::accent.x;
			float ay = globals::ui::accent.y;
			float az = globals::ui::accent.z;

			fdl->AddRectFilled(ImVec2(px, py), ImVec2(px + sw, py + sh),
				IM_COL32(28, 28, 38, static_cast<int>(245 * alpha)), 12.f);
			fdl->AddRect(ImVec2(px, py), ImVec2(px + sw, py + sh),
				IM_COL32(80, 80, 120, static_cast<int>(60 * alpha)), 12.f);

			fdl->AddRectFilled(ImVec2(px + 1.f, py + 1.f), ImVec2(px + sw - 1.f, py + 3.f),
				IM_COL32(static_cast<int>(ax * 255), static_cast<int>(ay * 255),
					static_cast<int>(az * 255),
					static_cast<int>(180 * alpha)), 2.f);

			out_px = px;
			out_py = py;
			out_alpha = alpha;
		}

		static bool draw_modal_button(ImDrawList* fdl, float bx, float by, float bw, float bh,
			const char* label, ImU32 bg, ImU32 bg_hov, float alpha)
		{
			ImVec2 mp = ImGui::GetIO().MousePos;
			bool hov = mp.x >= bx && mp.x <= bx + bw && mp.y >= by && mp.y <= by + bh;
			ImU32 fill = hov ? bg_hov : bg;
			fdl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh), fill, 8.f);
			if (hov) {
				fdl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
					IM_COL32(255, 255, 255, static_cast<int>(35 * alpha)), 8.f);
				ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
			}
			ImVec2 ts = ImGui::CalcTextSize(label);
			fdl->AddText(ImVec2(bx + (bw - ts.x) * 0.5f, by + (bh - ts.y) * 0.5f),
				IM_COL32(220, 222, 240, static_cast<int>((hov ? 255 : 210) * alpha)), label);
			return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		}

		static void render_codex_modal(float dt)
		{
			if (!g_state.codex_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 440.f;
			const float ph = 260.f;
			float px = 0.f, py = 0.f, alpha = 0.f;
			render_modal_chrome(fdl, g_state.modal_anim, dt, pw, ph, px, py, alpha);

			std::string title = "Sign in with OpenAI";
			ImVec2 tts = ImGui::CalcTextSize(title.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - tts.x * 0.5f, py + 18.f),
				IM_COL32(228, 228, 244, static_cast<int>(245 * alpha)), title.c_str());

			std::string sub = "Your browser is opening. Complete the login there.";
			ImVec2 sts = ImGui::CalcTextSize(sub.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - sts.x * 0.5f, py + 46.f),
				IM_COL32(168, 170, 188, static_cast<int>(220 * alpha)), sub.c_str());

			float cx = px + pw * 0.5f;
			float cy = py + 110.f;
			ImU32 spin_col = IM_COL32(150, 200, 255, static_cast<int>(230 * alpha));
			g_state.spinner_time += dt;
			ui_anim::render_spinner(fdl, cx, cy, 18.f, 3.f, spin_col, g_state.spinner_time);

			std::string status = "Waiting for browser callback (port 1455)...";
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_state) {
					if (!g_state.codex_state->error.empty())
						status = "Error: " + g_state.codex_state->error;
					else if (g_state.codex_state->done.load())
						status = "Finalizing...";
				}
			}
			ImVec2 ss = ImGui::CalcTextSize(status.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - ss.x * 0.5f, py + 152.f),
				IM_COL32(195, 198, 215, static_cast<int>(225 * alpha)), status.c_str());

			std::string url_open;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_state) url_open = g_state.codex_state->auth_url;
			}

			float bw = 130.f;
			float bh = 32.f;
			float bx_open = px + pw * 0.5f - bw - 6.f;
			float bx_cancel = px + pw * 0.5f + 6.f;
			float by = py + ph - bh - 18.f;

			ImU32 bg_open = IM_COL32(60, 70, 100, static_cast<int>(220 * alpha));
			ImU32 bg_open_hov = IM_COL32(80, 92, 130, static_cast<int>(235 * alpha));
			if (draw_modal_button(fdl, bx_open, by, bw, bh, "Open browser",
					bg_open, bg_open_hov, alpha) && !url_open.empty()) {
				open_url_in_browser(url_open);
			}

			ImU32 bg_cancel = IM_COL32(96, 36, 36, static_cast<int>(220 * alpha));
			ImU32 bg_cancel_hov = IM_COL32(132, 50, 50, static_cast<int>(235 * alpha));
			if (draw_modal_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					bg_cancel, bg_cancel_hov, alpha)) {
				close_codex_modal();
			}
		}

		static void render_claude_code_modal(float dt)
		{
			if (!g_state.claude_code_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 440.f;
			const float ph = 260.f;
			float px = 0.f, py = 0.f, alpha = 0.f;
			render_modal_chrome(fdl, g_state.modal_anim, dt, pw, ph, px, py, alpha);

			std::string title = "Sign in with Claude (Anthropic)";
			ImVec2 tts = ImGui::CalcTextSize(title.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - tts.x * 0.5f, py + 18.f),
				IM_COL32(228, 228, 244, static_cast<int>(245 * alpha)), title.c_str());

			std::string sub = "Your browser is opening. Complete the login there.";
			ImVec2 sts = ImGui::CalcTextSize(sub.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - sts.x * 0.5f, py + 46.f),
				IM_COL32(168, 170, 188, static_cast<int>(220 * alpha)), sub.c_str());

			float cx = px + pw * 0.5f;
			float cy = py + 110.f;
			ImU32 spin_col = IM_COL32(220, 160, 130, static_cast<int>(230 * alpha));
			g_state.spinner_time += dt;
			ui_anim::render_spinner(fdl, cx, cy, 18.f, 3.f, spin_col, g_state.spinner_time);

			std::string status = "Waiting for browser callback...";
			std::string url_open;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.claude_code_state) {
					if (!g_state.claude_code_state->error.empty())
						status = "Error: " + g_state.claude_code_state->error;
					else if (g_state.claude_code_state->done.load())
						status = "Finalizing...";
					url_open = g_state.claude_code_state->auth_url;
				}
			}
			ImVec2 ss = ImGui::CalcTextSize(status.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - ss.x * 0.5f, py + 152.f),
				IM_COL32(195, 198, 215, static_cast<int>(225 * alpha)), status.c_str());

			float bw = 130.f;
			float bh = 32.f;
			float bx_open = px + pw * 0.5f - bw - 6.f;
			float bx_cancel = px + pw * 0.5f + 6.f;
			float by = py + ph - bh - 18.f;

			ImU32 bg_open = IM_COL32(60, 70, 100, static_cast<int>(220 * alpha));
			ImU32 bg_open_hov = IM_COL32(80, 92, 130, static_cast<int>(235 * alpha));
			if (draw_modal_button(fdl, bx_open, by, bw, bh, "Open browser",
					bg_open, bg_open_hov, alpha) && !url_open.empty()) {
				open_url_in_browser(url_open);
			}

			ImU32 bg_cancel = IM_COL32(96, 36, 36, static_cast<int>(220 * alpha));
			ImU32 bg_cancel_hov = IM_COL32(132, 50, 50, static_cast<int>(235 * alpha));
			if (draw_modal_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					bg_cancel, bg_cancel_hov, alpha)) {
				close_claude_code_modal();
			}
		}

		static void render_copilot_modal(float dt)
		{
			if (!g_state.copilot_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 460.f;
			const float ph = 320.f;
			float px = 0.f, py = 0.f, alpha = 0.f;
			render_modal_chrome(fdl, g_state.modal_anim, dt, pw, ph, px, py, alpha);

			std::string title = "Sign in with GitHub Copilot";
			ImVec2 tts = ImGui::CalcTextSize(title.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - tts.x * 0.5f, py + 18.f),
				IM_COL32(228, 228, 244, static_cast<int>(245 * alpha)), title.c_str());

			std::string sub = "Enter the code below at the GitHub verification page.";
			ImVec2 sts = ImGui::CalcTextSize(sub.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - sts.x * 0.5f, py + 46.f),
				IM_COL32(168, 170, 188, static_cast<int>(220 * alpha)), sub.c_str());

			std::string user_code;
			std::string verify_uri;
			std::string status_text = "Initializing device flow...";
			bool have_code = false;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.copilot_state) {
					user_code = g_state.copilot_state->user_code;
					verify_uri = g_state.copilot_state->verification_uri;
					have_code = !user_code.empty();
					if (!g_state.copilot_state->error.empty())
						status_text = "Error: " + g_state.copilot_state->error;
					else if (g_state.copilot_state->done.load())
						status_text = "Authorizing...";
					else if (have_code)
						status_text = "Polling GitHub for completion...";
				}
			}

			if (have_code) {
				ImFont* font = ImGui::GetFont();
				float prev_size = font->FontSize;
				float chip_h = 56.f;
				float chip_pad_x = 22.f;
				float code_size = prev_size * 1.7f;
				ImVec2 code_ts = font->CalcTextSizeA(code_size, FLT_MAX, -1.f, user_code.c_str());
				float chip_w = code_ts.x + chip_pad_x * 2.f;
				float chip_x = px + (pw - chip_w) * 0.5f;
				float chip_y = py + 76.f;

				fdl->AddRectFilled(ImVec2(chip_x, chip_y),
					ImVec2(chip_x + chip_w, chip_y + chip_h),
					IM_COL32(20, 24, 36, static_cast<int>(240 * alpha)), 8.f);
				fdl->AddRect(ImVec2(chip_x, chip_y),
					ImVec2(chip_x + chip_w, chip_y + chip_h),
					IM_COL32(120, 130, 170, static_cast<int>(140 * alpha)), 8.f, 0, 1.f);

				fdl->AddText(font, code_size,
					ImVec2(chip_x + chip_pad_x, chip_y + (chip_h - code_ts.y) * 0.5f),
					IM_COL32(232, 234, 250, static_cast<int>(245 * alpha)),
					user_code.c_str());

				std::string copy_label = "Copy code";
				ImU32 bg_copy = IM_COL32(50, 56, 78, static_cast<int>(220 * alpha));
				ImU32 bg_copy_hov = IM_COL32(70, 80, 110, static_cast<int>(235 * alpha));
				float bw = 110.f;
				float bh = 28.f;
				float bx = px + (pw - bw) * 0.5f;
				float by = chip_y + chip_h + 10.f;
				if (draw_modal_button(fdl, bx, by, bw, bh, copy_label.c_str(),
						bg_copy, bg_copy_hov, alpha)) {
					ImGui::SetClipboardText(user_code.c_str());
					toast_notification::push("Code copied",
						toast_notification::toast_type_t::info, 2.5f);
				}
			}

			ImVec2 ss = ImGui::CalcTextSize(status_text.c_str());
			fdl->AddText(ImVec2(px + pw * 0.5f - ss.x * 0.5f, py + ph - 92.f),
				IM_COL32(195, 198, 215, static_cast<int>(225 * alpha)), status_text.c_str());

			float bw = 150.f;
			float bh = 32.f;
			float bx_open = px + pw * 0.5f - bw - 6.f;
			float bx_cancel = px + pw * 0.5f + 6.f;
			float by = py + ph - bh - 18.f;

			ImU32 bg_open = IM_COL32(60, 70, 100, static_cast<int>(220 * alpha));
			ImU32 bg_open_hov = IM_COL32(80, 92, 130, static_cast<int>(235 * alpha));
			std::string open_label = verify_uri.empty() ? std::string("Open verification") : std::string("Open ") + "github.com";
			if (draw_modal_button(fdl, bx_open, by, bw, bh, open_label.c_str(),
					bg_open, bg_open_hov, alpha) && !verify_uri.empty()) {
				open_url_in_browser(verify_uri);
			}

			ImU32 bg_cancel = IM_COL32(96, 36, 36, static_cast<int>(220 * alpha));
			ImU32 bg_cancel_hov = IM_COL32(132, 50, 50, static_cast<int>(235 * alpha));
			if (draw_modal_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					bg_cancel, bg_cancel_hov, alpha)) {
				close_copilot_modal();
			}
		}

	}

	void initialize()
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);

		if (g_state.sub_completed.valid())
			aida::events::unsubscribe(g_state.sub_completed);
		if (g_state.sub_failed.valid())
			aida::events::unsubscribe(g_state.sub_failed);

		g_state.sub_completed = aida::events::subscribe(
			aida::events::event_oauth_completed,
			std::function<void(const aida::events::oauth_completed_t&)>(
				[](const aida::events::oauth_completed_t& ev) {
					std::lock_guard<std::mutex> lk2(g_state.mtx);
					g_state.last_completed_provider = ev.provider_id;
					g_state.last_completed_email = ev.email;
					g_state.have_completed_event.store(true);
				}));

		g_state.sub_failed = aida::events::subscribe(
			aida::events::event_oauth_failed,
			std::function<void(const aida::events::oauth_failed_t&)>(
				[](const aida::events::oauth_failed_t& ev) {
					std::lock_guard<std::mutex> lk2(g_state.mtx);
					g_state.last_failed_provider = ev.provider_id;
					g_state.last_failed_error = ev.error;
					g_state.have_failed_event.store(true);
					set_err_locked(ev.error);
				}));
	}

	void shutdown()
	{
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			if (g_state.codex_state)
				aida::auth::codex::cancel_login(*g_state.codex_state);
			if (g_state.copilot_state)
				aida::auth::copilot::cancel_login(*g_state.copilot_state);
			if (g_state.claude_code_state)
				aida::auth::claude_code::cancel_login(*g_state.claude_code_state);

			g_state.codex_modal_open.store(false);
			g_state.copilot_modal_open.store(false);
			g_state.claude_code_modal_open.store(false);
		}

		if (g_state.codex_start_thread.joinable())
			g_state.codex_start_thread.join();
		if (g_state.copilot_start_thread.joinable())
			g_state.copilot_start_thread.join();
		if (g_state.claude_code_start_thread.joinable())
			g_state.claude_code_start_thread.join();

		std::lock_guard<std::mutex> lk(g_state.mtx);

		if (g_state.sub_completed.valid()) {
			aida::events::unsubscribe(g_state.sub_completed);
			g_state.sub_completed = aida::events::subscription_handle_t{};
		}
		if (g_state.sub_failed.valid()) {
			aida::events::unsubscribe(g_state.sub_failed);
			g_state.sub_failed = aida::events::subscription_handle_t{};
		}

		g_state.codex_state.reset();
		g_state.copilot_state.reset();
		g_state.claude_code_state.reset();
	}

	bool any_login_in_progress()
	{
		return g_state.codex_modal_open.load()
			|| g_state.copilot_modal_open.load()
			|| g_state.claude_code_modal_open.load();
	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		return g_state.err;
	}

	void render(float panel_w, float panel_h)
	{
		ImGui::PushID("aida_auth_view");

		float content_h = panel_h > 0.f ? panel_h : ImGui::GetContentRegionAvail().y;
		ImGui::BeginChild("##auth_view_root", ImVec2(panel_w, content_h),
			false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));

		if (ImGui::BeginTabBar("##auth_view_tabs", ImGuiTabBarFlags_None)) {
			if (ImGui::BeginTabItem("Providers")) {
				g_state.active_top_tab = 0;
				ImGui::BeginChild("##auth_providers_child",
					ImVec2(0, ImGui::GetContentRegionAvail().y), false);
				render_providers_tab(ImGui::GetContentRegionAvail().x,
					ImGui::GetContentRegionAvail().y);
				ImGui::EndChild();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Custom OAuth")) {
				g_state.active_top_tab = 1;
				ImGui::BeginChild("##auth_custom_child",
					ImVec2(0, ImGui::GetContentRegionAvail().y), false);
				render_custom_oauth_tab(ImGui::GetContentRegionAvail().x,
					ImGui::GetContentRegionAvail().y);
				ImGui::EndChild();
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}

		ImGui::PopStyleVar(2);

		ImGui::EndChild();
		ImGui::PopID();

		float dt = ImGui::GetIO().DeltaTime;
		poll_active_logins();

		render_codex_modal(dt);
		render_claude_code_modal(dt);
		render_copilot_modal(dt);
	}

}
}
