#define NOMINMAX
#include "auth_view.hpp"

#include "auth_store.hpp"
#include "auth_codex.hpp"
#include "auth_copilot.hpp"
#include "auth_claude_code.hpp"
#include "auth_brand_glyphs.hpp"
#include "event_bus.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "brand.hpp"
#include "avatar.hpp"
#include "fonts.hpp"
#include "work_queue.hpp"
#include "../helpers/globals.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
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

		enum class flow_phase_t : int {
			idle = 0,
			browser,
			callback,
			session,
			complete,
			error_state
		};

		struct row_def_t {
			row_kind_t kind;
			const char* display_name;
			const char* subtitle;
			const char* store_key;
			brand_glyph::kind_t glyph_kind;
			ImU32 grad_top;
			ImU32 grad_bot;
			ImU32 ring;
			bool is_oauth;
		};

		static const row_def_t k_rows[] = {
			{ row_kind_t::oauth_claude_code, "Claude Code",     "Anthropic OAuth (PKCE)",
			  "anthropic",      brand_glyph::kind_t::anthropic,
			  IM_COL32(228, 168, 132, 255), IM_COL32(196, 124, 84, 255),
			  IM_COL32(255, 200, 168, 220), true  },
			{ row_kind_t::oauth_codex,       "OpenAI Codex",    "ChatGPT OAuth (PKCE)",
			  "openai",         brand_glyph::kind_t::openai,
			  IM_COL32(106, 220, 178, 255), IM_COL32(40, 168, 138, 255),
			  IM_COL32(160, 240, 210, 220), true  },
			{ row_kind_t::oauth_copilot,     "GitHub Copilot",  "GitHub Device Code",
			  "github-copilot", brand_glyph::kind_t::github,
			  IM_COL32(60, 64, 92, 255),    IM_COL32(28, 32, 52, 255),
			  IM_COL32(150, 158, 198, 220), true  },
			{ row_kind_t::api_anthropic,     "Anthropic API",   "Direct API key for api.anthropic.com",
			  "anthropic",      brand_glyph::kind_t::generic,
			  IM_COL32(228, 168, 132, 255), IM_COL32(196, 124, 84, 255),
			  IM_COL32(255, 200, 168, 220), false },
			{ row_kind_t::api_openai,        "OpenAI API",      "Direct API key for api.openai.com",
			  "openai",         brand_glyph::kind_t::generic,
			  IM_COL32(106, 220, 178, 255), IM_COL32(40, 168, 138, 255),
			  IM_COL32(160, 240, 210, 220), false },
		};

		struct modal_anim_t {
			aida::ui::transition_t enter;
			aida::ui::transition_t exit;
			aida::ui::transition_t shake;
			aida::ui::transition_t success;
			aida::ui::transition_t sparkle;
			bool exiting = false;
			bool success_played = false;

			void reset_for_open()
			{
				exit.reset();
				shake.reset();
				success.reset();
				sparkle.reset();
				exiting = false;
				success_played = false;
				enter.start(aida::motion::dur::lg, aida::motion::ease::out_back);
			}

			void begin_exit()
			{
				if (exiting) return;
				exiting = true;
				exit.start(aida::motion::dur::md, aida::motion::ease::in_out_cubic);
			}

			void begin_shake()
			{
				shake.start(aida::motion::dur::md + 0.060f, aida::motion::ease::out_quad);
			}

			void begin_success()
			{
				if (success_played) return;
				if (exiting) return;
				success_played = true;
				success.start(aida::motion::dur::lg, aida::motion::ease::out_quint);
				sparkle.start(aida::motion::dur::lg, aida::motion::ease::out_quint);
			}
		};

		enum class exchange_result_t : int {
			pending = 0,
			success = 1,
			failure = 2,
		};

		struct view_state_t {
			std::mutex mtx;

			std::shared_ptr<aida::auth::codex::codex_login_state_t> codex_state;
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot_state;
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_code_state;

			std::atomic<bool> codex_modal_open{ false };
			std::atomic<bool> copilot_modal_open{ false };
			std::atomic<bool> claude_code_modal_open{ false };

			std::atomic<bool> codex_starting{ false };
			std::atomic<bool> copilot_starting{ false };
			std::atomic<bool> claude_code_starting{ false };

			std::atomic<bool> codex_exchange_in_flight{ false };
			std::atomic<bool> copilot_poll_in_flight{ false };
			std::atomic<bool> claude_code_exchange_in_flight{ false };

			std::atomic<int> codex_exchange_result{ static_cast<int>(exchange_result_t::pending) };
			std::atomic<int> copilot_poll_result{ static_cast<int>(exchange_result_t::pending) };
			std::atomic<int> claude_code_exchange_result{ static_cast<int>(exchange_result_t::pending) };

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

			char copilot_ghe_buf[256]{};
			std::atomic<bool> copilot_flow_started{ false };

			modal_anim_t codex_anim;
			modal_anim_t copilot_anim;
			modal_anim_t claude_code_anim;

			aida::ui::flash_t copilot_copy_flash;
			std::vector<aida::ui::hover_state_t> row_hover;

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

		static const row_def_t& row_def_for(row_kind_t k)
		{
			int n = static_cast<int>(sizeof(k_rows) / sizeof(k_rows[0]));
			for (int i = 0; i < n; ++i) {
				if (k_rows[i].kind == k) return k_rows[i];
			}
			return k_rows[0];
		}

		static void start_codex_login()
		{
			if (g_state.codex_starting.exchange(true)) return;

			std::thread prior;
			std::shared_ptr<aida::auth::codex::codex_login_state_t> previous;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_start_thread.joinable())
					prior = std::move(g_state.codex_start_thread);
				previous = g_state.codex_state;
				g_state.codex_state = std::make_shared<aida::auth::codex::codex_login_state_t>();
				g_state.codex_modal_open.store(true);
				g_state.codex_anim.reset_for_open();
				g_state.codex_exchange_result.store(static_cast<int>(exchange_result_t::pending));
			}
			if (previous)
				aida::auth::codex::cancel_login(*previous);
			if (prior.joinable()) prior.join();

			std::shared_ptr<aida::auth::codex::codex_login_state_t> codex_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				codex_ref = g_state.codex_state;
			}
			std::thread t([codex_ref]() {
				if (!codex_ref) {
					g_state.codex_starting.store(false);
					return;
				}
				const bool ok = aida::auth::codex::start_login(*codex_ref);
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					if (!ok) {
						codex_ref->error = aida::auth::codex::last_error();
						codex_ref->done.store(true);
						set_err_locked(codex_ref->error);
					}
				}
				g_state.codex_starting.store(false);
			});

			std::lock_guard<std::mutex> lk(g_state.mtx);
			g_state.codex_start_thread = std::move(t);
		}

		static void open_copilot_modal()
		{
			std::thread prior;
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> previous;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.copilot_start_thread.joinable())
					prior = std::move(g_state.copilot_start_thread);
				previous = g_state.copilot_state;
				g_state.copilot_state = std::make_shared<aida::auth::copilot::copilot_login_state_t>();
				g_state.copilot_modal_open.store(true);
				g_state.copilot_anim.reset_for_open();
				g_state.copilot_poll_result.store(static_cast<int>(exchange_result_t::pending));
				g_state.copilot_flow_started.store(false);
				SecureZeroMemory(g_state.copilot_ghe_buf, sizeof(g_state.copilot_ghe_buf));

				aida::auth::auth_info_t prev_info;
				if (aida::auth::store::get("github-copilot", prev_info)
					&& !prev_info.enterprise_url.empty()) {
					const size_t cap = sizeof(g_state.copilot_ghe_buf) - 1;
					const size_t len = prev_info.enterprise_url.size() < cap
						? prev_info.enterprise_url.size() : cap;
					std::memcpy(g_state.copilot_ghe_buf, prev_info.enterprise_url.data(), len);
					g_state.copilot_ghe_buf[len] = '\0';
				}
			}
			if (previous)
				aida::auth::copilot::cancel_login(*previous);
			if (prior.joinable()) prior.join();
		}

		static void start_copilot_flow(std::optional<std::string> enterprise_url)
		{
			if (g_state.copilot_starting.exchange(true)) return;
			g_state.copilot_flow_started.store(true);

			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				copilot_ref = g_state.copilot_state;
			}
			std::thread t([copilot_ref, enterprise_url]() {
				if (!copilot_ref) {
					g_state.copilot_starting.store(false);
					return;
				}
				const bool ok = aida::auth::copilot::start_login(*copilot_ref, enterprise_url);
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					if (!ok) {
						copilot_ref->error = aida::auth::copilot::last_error();
						copilot_ref->done.store(true);
						set_err_locked(copilot_ref->error);
					}
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
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> previous;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.claude_code_start_thread.joinable())
					prior = std::move(g_state.claude_code_start_thread);
				previous = g_state.claude_code_state;
				g_state.claude_code_state = std::make_shared<aida::auth::claude_code::claude_code_login_state_t>();
				g_state.claude_code_modal_open.store(true);
				g_state.claude_code_anim.reset_for_open();
				g_state.claude_code_exchange_result.store(static_cast<int>(exchange_result_t::pending));
			}
			if (previous)
				aida::auth::claude_code::cancel_login(*previous);
			if (prior.joinable()) prior.join();

			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				claude_ref = g_state.claude_code_state;
			}
			std::thread t([claude_ref]() {
				if (!claude_ref) {
					g_state.claude_code_starting.store(false);
					return;
				}
				const bool ok = aida::auth::claude_code::start_login(*claude_ref);
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					if (!ok) {
						claude_ref->error = aida::auth::claude_code::last_error();
						claude_ref->done.store(true);
						set_err_locked(claude_ref->error);
					}
				}
				g_state.claude_code_starting.store(false);
			});

			std::lock_guard<std::mutex> lk(g_state.mtx);
			g_state.claude_code_start_thread = std::move(t);
		}

		static void close_codex_modal_immediate()
		{
			std::shared_ptr<aida::auth::codex::codex_login_state_t> state_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				state_ref = g_state.codex_state;
				g_state.codex_modal_open.store(false);
				if (state_ref)
					state_ref->cancelled.store(true);
			}
			if (state_ref) {
				if (!work_queue::post([state_ref]() {
						aida::auth::codex::cancel_login(*state_ref);
					})) {
					aida::auth::codex::cancel_login(*state_ref);
				}
			}
		}

		static void close_copilot_modal_immediate()
		{
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> state_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				state_ref = g_state.copilot_state;
				g_state.copilot_modal_open.store(false);
				g_state.copilot_flow_started.store(false);
				SecureZeroMemory(g_state.copilot_ghe_buf, sizeof(g_state.copilot_ghe_buf));
				if (state_ref)
					state_ref->cancelled.store(true);
			}
			if (state_ref) {
				if (!work_queue::post([state_ref]() {
						aida::auth::copilot::cancel_login(*state_ref);
					})) {
					aida::auth::copilot::cancel_login(*state_ref);
				}
			}
		}

		static void close_claude_code_modal_immediate()
		{
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> state_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				state_ref = g_state.claude_code_state;
				g_state.claude_code_modal_open.store(false);
				if (state_ref)
					state_ref->cancelled.store(true);
			}
			if (state_ref) {
				if (!work_queue::post([state_ref]() {
						aida::auth::claude_code::cancel_login(*state_ref);
					})) {
					aida::auth::claude_code::cancel_login(*state_ref);
				}
			}
		}

		static void request_close_codex()
		{
			g_state.codex_anim.begin_exit();
		}

		static void request_close_copilot()
		{
			g_state.copilot_anim.begin_exit();
		}

		static void request_close_claude_code()
		{
			g_state.claude_code_anim.begin_exit();
		}

		static void poll_active_logins()
		{
			std::unique_lock<std::mutex> lk(g_state.mtx);

			if (g_state.codex_modal_open.load() && g_state.codex_state) {
				auto sp = g_state.codex_state;
				bool finished = sp->done.load();
				const int prior_result = g_state.codex_exchange_result.load();

				if (finished
					&& !g_state.codex_exchange_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.codex_exchange_in_flight.store(true);
					auto state_ref = sp;
					if (!work_queue::post([state_ref]() {
						if (!state_ref) {
							g_state.codex_exchange_result.store(
								static_cast<int>(exchange_result_t::failure));
							g_state.codex_exchange_in_flight.store(false);
							return;
						}
						bool ok = aida::auth::codex::poll_login(*state_ref);
						{
							std::lock_guard<std::mutex> lk2(g_state.mtx);
							g_state.codex_exchange_result.store(static_cast<int>(
								ok ? exchange_result_t::success : exchange_result_t::failure));
						}
						g_state.codex_exchange_in_flight.store(false);
					})) {
						g_state.codex_exchange_in_flight.store(false);
						g_state.codex_exchange_result.store(
							static_cast<int>(exchange_result_t::failure));
					}
				}

				if (prior_result == static_cast<int>(exchange_result_t::success)) {
					g_state.codex_exchange_result.store(
						static_cast<int>(exchange_result_t::pending));
					lk.unlock();
					aida::auth::auth_info_t info;
					aida::auth::store::get("openai", info);
					std::string disp = info.email.empty() ? info.account_id : info.email;
					if (disp.empty()) disp = "OpenAI account";
					toast_notification::push("Signed in: " + disp,
						toast_notification::toast_type_t::info, 5.0f);
					aida::events::publish(aida::events::event_oauth_completed,
						aida::events::oauth_completed_t{ "openai", disp });
					g_state.codex_anim.begin_success();
					lk.lock();
				} else if (prior_result == static_cast<int>(exchange_result_t::failure)) {
					g_state.codex_exchange_result.store(
						static_cast<int>(exchange_result_t::pending));
					std::string err = aida::auth::codex::last_error();
					if (err.empty() && sp) err = sp->error;
					if (err.empty()) err = "OpenAI login failed";
					lk.unlock();
					toast_notification::push("OpenAI login failed: " + err,
						toast_notification::toast_type_t::error, 6.0f);
					aida::events::publish(aida::events::event_oauth_failed,
						aida::events::oauth_failed_t{ "openai", err });
					g_state.codex_anim.begin_shake();
					lk.lock();
				}
			}

			if (g_state.copilot_modal_open.load() && g_state.copilot_state) {
				auto sp = g_state.copilot_state;
				int64_t now = now_unix();
				bool ready_to_poll = sp->next_poll_unix == 0 || now >= sp->next_poll_unix;
				bool finished = sp->done.load();
				bool can_poll = !finished && ready_to_poll && !sp->device_code.empty();
				bool start_failed = finished && sp->device_code.empty();
				const int prior_result = g_state.copilot_poll_result.load();

				if (start_failed && prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.copilot_poll_result.store(
						static_cast<int>(exchange_result_t::failure));
				} else if (can_poll && !g_state.copilot_poll_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.copilot_poll_in_flight.store(true);
					auto state_ref = sp;
					if (!work_queue::post([state_ref]() {
						if (!state_ref) {
							g_state.copilot_poll_in_flight.store(false);
							return;
						}
						bool ok = aida::auth::copilot::poll_login(*state_ref);
						{
							std::lock_guard<std::mutex> lk2(g_state.mtx);
							if (ok) {
								g_state.copilot_poll_result.store(
									static_cast<int>(exchange_result_t::success));
							} else if (state_ref->done.load()) {
								g_state.copilot_poll_result.store(
									static_cast<int>(exchange_result_t::failure));
							}
						}
						g_state.copilot_poll_in_flight.store(false);
					})) {
						g_state.copilot_poll_in_flight.store(false);
					}
				}

				if (prior_result == static_cast<int>(exchange_result_t::success)) {
					g_state.copilot_poll_result.store(
						static_cast<int>(exchange_result_t::pending));
					lk.unlock();
					aida::auth::auth_info_t info;
					aida::auth::store::get("github-copilot", info);
					std::string disp = info.email.empty() ? info.account_id : info.email;
					if (disp.empty()) disp = "GitHub account";
					toast_notification::push("Signed in: " + disp,
						toast_notification::toast_type_t::info, 5.0f);
					aida::events::publish(aida::events::event_oauth_completed,
						aida::events::oauth_completed_t{ "github-copilot", disp });
					g_state.copilot_anim.begin_success();
					lk.lock();
				} else if (prior_result == static_cast<int>(exchange_result_t::failure)) {
					g_state.copilot_poll_result.store(
						static_cast<int>(exchange_result_t::pending));
					std::string err = aida::auth::copilot::last_error();
					if (err.empty() && sp) err = sp->error;
					if (err.empty()) err = "Copilot login failed";
					lk.unlock();
					toast_notification::push("Copilot login failed: " + err,
						toast_notification::toast_type_t::error, 6.0f);
					aida::events::publish(aida::events::event_oauth_failed,
						aida::events::oauth_failed_t{ "github-copilot", err });
					g_state.copilot_anim.begin_shake();
					lk.lock();
				}
			}

			if (g_state.claude_code_modal_open.load() && g_state.claude_code_state) {
				auto sp = g_state.claude_code_state;
				bool finished = sp->done.load();
				const int prior_result = g_state.claude_code_exchange_result.load();

				if (finished
					&& !g_state.claude_code_exchange_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.claude_code_exchange_in_flight.store(true);
					auto state_ref = sp;
					if (!work_queue::post([state_ref]() {
						if (!state_ref) {
							g_state.claude_code_exchange_result.store(
								static_cast<int>(exchange_result_t::failure));
							g_state.claude_code_exchange_in_flight.store(false);
							return;
						}
						bool ok = aida::auth::claude_code::poll_login(*state_ref);
						{
							std::lock_guard<std::mutex> lk2(g_state.mtx);
							g_state.claude_code_exchange_result.store(static_cast<int>(
								ok ? exchange_result_t::success : exchange_result_t::failure));
						}
						g_state.claude_code_exchange_in_flight.store(false);
					})) {
						g_state.claude_code_exchange_in_flight.store(false);
						g_state.claude_code_exchange_result.store(
							static_cast<int>(exchange_result_t::failure));
					}
				}

				if (prior_result == static_cast<int>(exchange_result_t::success)) {
					g_state.claude_code_exchange_result.store(
						static_cast<int>(exchange_result_t::pending));
					lk.unlock();
					aida::auth::auth_info_t info;
					aida::auth::store::get("anthropic", info);
					std::string disp = info.email.empty() ? info.account_id : info.email;
					if (disp.empty()) disp = "Anthropic account";
					toast_notification::push("Signed in: " + disp,
						toast_notification::toast_type_t::info, 5.0f);
					aida::events::publish(aida::events::event_oauth_completed,
						aida::events::oauth_completed_t{ "anthropic", disp });
					g_state.claude_code_anim.begin_success();
					lk.lock();
				} else if (prior_result == static_cast<int>(exchange_result_t::failure)) {
					g_state.claude_code_exchange_result.store(
						static_cast<int>(exchange_result_t::pending));
					std::string err = aida::auth::claude_code::last_error();
					if (err.empty() && sp) err = sp->error;
					if (err.empty()) err = "Claude Code login failed";
					lk.unlock();
					toast_notification::push("Claude Code login failed: " + err,
						toast_notification::toast_type_t::error, 6.0f);
					aida::events::publish(aida::events::event_oauth_failed,
						aida::events::oauth_failed_t{ "anthropic", err });
					g_state.claude_code_anim.begin_shake();
					lk.lock();
				}
			}
		}

		static void render_provider_avatar(ImDrawList* dl, ImVec2 center, float radius,
										   const row_def_t& def, float alpha)
		{
			if (def.is_oauth) {
				brand_glyph::render(dl, def.glyph_kind, center, radius,
					def.grad_top, def.grad_bot, def.ring, alpha);
			} else {
				aida::ui::avatar::render(dl, center, radius, def.display_name,
					aida::ui::avatar::kind_t::gradient, true, alpha);
			}
		}

		struct row_status_t {
			std::string pill_text;
			aida::ui::pill_kind_t pill_kind = aida::ui::pill_kind_t::neutral;
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
						s.pill_kind = aida::ui::pill_kind_t::error;
						s.detail_text = info.email.empty() ? info.account_id : info.email;
					} else {
						s.logged_in = true;
						s.pill_text = info.expires_unix > 0
							? format_relative_time(info.expires_unix)
							: std::string("Logged in");
						s.pill_kind = aida::ui::pill_kind_t::success;
						s.detail_text = info.email.empty() ? info.account_id : info.email;
						if (s.detail_text.empty()) s.detail_text = "Signed in";
					}
				} else if (have && info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty()) {
					s.pill_text = "API key active";
					s.pill_kind = aida::ui::pill_kind_t::info;
					s.detail_text = "Clear API key to use OAuth";
				} else {
					s.pill_text = "Logged out";
					s.pill_kind = aida::ui::pill_kind_t::neutral;
					s.detail_text = "Sign in with your account";
				}
			} else {
				if (have && info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty()) {
					s.logged_in = true;
					s.pill_text = "API key set";
					s.pill_kind = aida::ui::pill_kind_t::success;
					s.detail_text = mask_key(info.api_key);
				} else if (have && info.kind == aida::auth::auth_kind_t::oauth) {
					s.pill_text = "OAuth active";
					s.pill_kind = aida::ui::pill_kind_t::info;
					s.detail_text = "Sign out of OAuth to use API key";
				} else {
					s.pill_text = "Not configured";
					s.pill_kind = aida::ui::pill_kind_t::neutral;
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

			const bool revoke_needed = info.kind == aida::auth::auth_kind_t::oauth
				&& (!info.access.empty() || !info.refresh.empty());
			const row_kind_t kind_copy = def.kind;
			std::string captured_access = info.access;
			std::string captured_refresh = info.refresh;
			std::string captured_client_id = info.custom_client_id;

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

			if (revoke_needed) {
				work_queue::post([kind_copy,
					access = std::move(captured_access),
					refresh = std::move(captured_refresh),
					client = std::move(captured_client_id)]() {
					switch (kind_copy) {
					case row_kind_t::oauth_claude_code:
						aida::auth::claude_code::revoke_tokens(access, refresh, client);
						break;
					case row_kind_t::oauth_codex:
						aida::auth::codex::revoke_tokens(access, refresh, client);
						break;
					case row_kind_t::oauth_copilot:
						aida::auth::copilot::revoke_tokens(access, refresh, client);
						break;
					default:
						break;
					}
				});
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

		static std::string refresh_last_error_for(row_kind_t k)
		{
			switch (k) {
			case row_kind_t::oauth_claude_code: return aida::auth::claude_code::last_error();
			case row_kind_t::oauth_codex:       return aida::auth::codex::last_error();
			case row_kind_t::oauth_copilot:     return aida::auth::copilot::last_error();
			default: return std::string{};
			}
		}

		static void render_provider_row(const row_def_t& def, float row_w, int idx)
		{
			const auto& th = aida::ui::resolved();

			while ((int)g_state.row_hover.size() <= idx) {
				g_state.row_hover.emplace_back();
			}
			auto& hov_state = g_state.row_hover[idx];

			const float left_pad = 16.f;
			const float avatar_radius = 22.f;
			const float text_offset_x = left_pad + avatar_radius * 2.f + 16.f;
			const float right_pad = 14.f;

			row_status_t status = compute_status(def);

			float ctrl_w_full = 0.f;
			if (def.is_oauth) {
				if (status.logged_in || status.expired) {
					ctrl_w_full = 100.f + 8.f + 92.f;
				} else {
					ctrl_w_full = 188.f;
				}
			} else {
				const float api_input_pref = 188.f;
				const float api_check_w = 24.f;
				const float api_save_w = 64.f;
				const float api_clear_w = status.logged_in ? (6.f + 72.f) : 0.f;
				ctrl_w_full = api_input_pref + 6.f + api_check_w + 8.f + api_save_w + api_clear_w;
			}

			const float ctrl_w_min = def.is_oauth
				? ((status.logged_in || status.expired) ? 200.f : 188.f)
				: 220.f;
			const float text_min_room = 220.f;
			const bool stack_layout = (row_w - text_offset_x - right_pad - 12.f - text_min_room) < ctrl_w_min;

			const float row_h = stack_layout ? 124.f : 72.f;

			ImVec2 origin = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();

			ImGui::PushID(idx);
			ImGui::SetCursorScreenPos(origin);
			ImGui::InvisibleButton("##row_bg", ImVec2(row_w, row_h));
			bool row_hovered = ImGui::IsItemHovered();
			float hov = hov_state.tick(row_hovered, aida::ui::clock::dt(),
				aida::motion::spring::balanced);

			float lift = hov * 2.f;
			ImVec2 a = ImVec2(origin.x, origin.y - lift);
			ImVec2 b = ImVec2(origin.x + row_w, origin.y + row_h - lift);

			if (hov > 0.05f) {
				aida::ui::blur::render_drop_shadow(dl, a, b, 10.f, 4,
					0.18f + 0.20f * hov, ImVec2(0.f, 4.f + 2.f * hov));
			}

			ImU32 row_bg = aida::ui::mix(th.bg_elevated, th.panel_header, 0.45f + 0.30f * hov);
			dl->AddRectFilled(a, b, row_bg, 10.f);

			ImU32 border = aida::ui::mix(th.border_subtle, th.accent_dim, hov * 0.55f);
			dl->AddRect(a, b, border, 10.f, 0, 1.f);

			float avatar_cx = a.x + left_pad + avatar_radius;
			float avatar_cy = stack_layout ? (a.y + 12.f + avatar_radius) : (a.y + row_h * 0.5f);

			render_provider_avatar(dl, ImVec2(avatar_cx, avatar_cy), avatar_radius, def, 1.f);

			float text_x = avatar_cx + avatar_radius + 16.f;
			float text_y = a.y + 12.f;

			ImFont* f_strong = aida::ui::fonts::body_strong();
			ImFont* f_body = aida::ui::fonts::body();
			ImFont* f_caption = aida::ui::fonts::caption();
			float fs_title = 14.f;
			float fs_sub = 14.f;
			float fs_detail = 13.f;

			dl->AddText(f_strong, fs_title, ImVec2(text_x, text_y),
				th.text_primary, def.display_name);

			ImVec2 sub_size = f_body->CalcTextSizeA(fs_sub, FLT_MAX, 0.f, def.subtitle);
			dl->AddText(f_body, fs_sub, ImVec2(text_x, text_y + sub_size.y + 4.f),
				th.text_secondary, def.subtitle);

			float pill_y = stack_layout
				? (a.y + 12.f + avatar_radius * 2.f + 6.f)
				: (a.y + row_h - 26.f);
			ImGui::SetCursorScreenPos(ImVec2(text_x, pill_y));
			aida::ui::pill_kind(status.pill_text.c_str(), status.pill_kind,
				aida::ui::size_t_::sm, true);

			if (!status.detail_text.empty()) {
				float ps = ImGui::GetItemRectSize().x;
				float detail_x = text_x + ps + 12.f;
				dl->AddText(f_caption, fs_detail,
					ImVec2(detail_x, pill_y + 3.f),
					th.text_dim, status.detail_text.c_str());
			}

			float ctrl_x;
			float ctrl_y;
			float ctrl_avail;
			if (stack_layout) {
				ctrl_x = a.x + left_pad;
				ctrl_y = pill_y + 26.f;
				ctrl_avail = row_w - left_pad - right_pad;
			} else {
				ctrl_x = a.x + row_w - ctrl_w_full - right_pad;
				ctrl_y = a.y + (row_h - 32.f) * 0.5f;
				ctrl_avail = ctrl_w_full;
			}

			ImGui::SetCursorScreenPos(ImVec2(ctrl_x, ctrl_y));

			if (def.is_oauth) {
				if (status.logged_in || status.expired) {
					float refresh_w = 100.f;
					float signout_w = 92.f;
					float gap = 8.f;
					if (refresh_w + gap + signout_w > ctrl_avail) {
						float total = ctrl_avail - gap;
						refresh_w = (total > 0.f) ? (total * 0.5f) : 100.f;
						signout_w = (total > 0.f) ? (total * 0.5f) : 92.f;
					}
					ImGui::SetCursorScreenPos(ImVec2(ctrl_x, ctrl_y));
					if (aida::ui::button("Refresh", aida::ui::button_kind_t::secondary,
							aida::ui::size_t_::md, ImVec2(refresh_w, 32.f))) {
						row_kind_t kind_copy = def.kind;
						std::string name_copy = def.display_name;
						work_queue::post([kind_copy, name_copy]() {
							if (refresh_token_for(kind_copy)) {
								toast_notification::push(name_copy + " token refreshed",
									toast_notification::toast_type_t::info, 3.5f);
							} else {
								std::string err = refresh_last_error_for(kind_copy);
								if (err.empty()) err = "refresh failed";
								toast_notification::push(
									name_copy + " refresh failed: " + err,
									toast_notification::toast_type_t::error, 5.0f);
							}
						});
					}

					ImGui::SetCursorScreenPos(ImVec2(ctrl_x + refresh_w + gap, ctrl_y));
					if (aida::ui::button("Sign out", aida::ui::button_kind_t::destructive,
							aida::ui::size_t_::md, ImVec2(signout_w, 32.f))) {
						clear_credentials(def, true, false);
					}
				} else {
					bool busy =
						(def.kind == row_kind_t::oauth_claude_code && g_state.claude_code_modal_open.load())
						|| (def.kind == row_kind_t::oauth_codex && g_state.codex_modal_open.load())
						|| (def.kind == row_kind_t::oauth_copilot && g_state.copilot_modal_open.load());
					const char* label = busy ? "Signing in" : "Sign in";

					float signin_w = (ctrl_avail < 188.f) ? ctrl_avail : 188.f;
					ImGui::SetCursorScreenPos(ImVec2(ctrl_x, ctrl_y));
					if (aida::ui::button(label, aida::ui::button_kind_t::primary,
							aida::ui::size_t_::md, ImVec2(signin_w, 32.f),
							busy, nullptr, busy) && !busy) {
						if (def.kind == row_kind_t::oauth_claude_code) start_claude_code_login();
						else if (def.kind == row_kind_t::oauth_codex)  start_codex_login();
						else if (def.kind == row_kind_t::oauth_copilot) open_copilot_modal();
					}
				}
			} else {
				int b_idx = row_index(def.kind);
				if (b_idx < 0 || b_idx >= 5) b_idx = 0;

				float check_w = 24.f;
				float save_w = 64.f;
				float clear_w = status.logged_in ? 72.f : 0.f;
				float gap_input_check = 6.f;
				float gap_check_save = 8.f;
				float gap_save_clear = status.logged_in ? 6.f : 0.f;
				float reserved = check_w + save_w + clear_w
					+ gap_input_check + gap_check_save + gap_save_clear;
				float input_w = ctrl_avail - reserved;
				if (input_w > 188.f) input_w = 188.f;
				if (input_w < 96.f) input_w = 96.f;

				ImGui::SetCursorScreenPos(ImVec2(ctrl_x, ctrl_y));
				ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th.panel_header));
				ImGui::SetNextItemWidth(input_w);
				ImGuiInputTextFlags flags = ImGuiInputTextFlags_None;
				if (!g_state.api_key_show[b_idx])
					flags |= ImGuiInputTextFlags_Password;
				ImGui::InputTextWithHint("##api_key", "Paste API key",
					g_state.api_key_buf[b_idx],
					sizeof(g_state.api_key_buf[b_idx]), flags);
				ImGui::PopStyleColor();

				ImGui::SameLine(0.f, gap_input_check);
				ImGui::Checkbox("##show", &g_state.api_key_show[b_idx]);
				if (ImGui::IsItemHovered()) ImGui::SetTooltip("Reveal key");

				ImGui::SameLine(0.f, gap_check_save);
				ImVec2 save_pos = ImGui::GetCursorScreenPos();
				ImGui::SetCursorScreenPos(save_pos);
				if (aida::ui::button("Save", aida::ui::button_kind_t::primary,
						aida::ui::size_t_::md, ImVec2(save_w, 32.f))) {
					std::string k = g_state.api_key_buf[b_idx];
					if (!k.empty()) {
						save_api_key(def, k);
						SecureZeroMemory(g_state.api_key_buf[b_idx],
							sizeof(g_state.api_key_buf[b_idx]));
					}
				}
				if (status.logged_in) {
					ImGui::SameLine(0.f, gap_save_clear);
					ImVec2 clr_pos = ImGui::GetCursorScreenPos();
					ImGui::SetCursorScreenPos(clr_pos);
					if (aida::ui::button("Clear", aida::ui::button_kind_t::destructive,
							aida::ui::size_t_::md, ImVec2(clear_w, 32.f))) {
						clear_credentials(def, false, true);
					}
				}
			}

			ImGui::PopID();

			ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + row_h + 8.f));
		}

		static void render_providers_tab(float panel_w, float panel_h)
		{
			(void)panel_h;
			float row_w = panel_w - 16.f;
			ImGui::Dummy(ImVec2(0.f, 8.f));
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
			const char* default_redirect, const char* default_scopes_hint,
			const row_def_t& def_for_glyph)
		{
			ImGui::PushID(b_idx + 100);
			const auto& th = aida::ui::resolved();

			ImVec2 cur = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			float card_w = ImGui::GetContentRegionAvail().x;
			float card_h = 220.f;

			static aida::ui::hover_state_t s_hovers[3];
			ImGui::SetCursorScreenPos(cur);
			ImGui::InvisibleButton("##card_hit", ImVec2(card_w, card_h));
			bool card_hov = ImGui::IsItemHovered();
			float hv = s_hovers[b_idx].tick(card_hov, aida::ui::clock::dt(),
				aida::motion::spring::balanced);

			float lift = hv * 2.f;
			ImVec2 a = ImVec2(cur.x, cur.y - lift);
			ImVec2 b = ImVec2(cur.x + card_w, cur.y + card_h - lift);

			aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 4,
				0.22f + 0.18f * hv, ImVec2(0.f, 4.f + 2.f * hv));
			aida::ui::blur::render_glass_fill(dl, a, b, 12.f, 1.f);
			aida::ui::blur::render_glass_border(dl, a, b, 12.f, 1.f, 1.f);

			ImU32 stripe_top = th.accent_grad_top;
			ImU32 stripe_bot = th.accent_grad_bot;
			dl->AddRectFilledMultiColor(a, ImVec2(b.x, a.y + 3.f),
				stripe_top, stripe_bot, stripe_bot, stripe_top);

			float glyph_x = a.x + 18.f;
			float glyph_y = a.y + 18.f;
			float glyph_r = 18.f;
			brand_glyph::render(dl, def_for_glyph.glyph_kind,
				ImVec2(glyph_x + glyph_r, glyph_y + glyph_r), glyph_r,
				def_for_glyph.grad_top, def_for_glyph.grad_bot, def_for_glyph.ring, 1.f);

			ImFont* f_h2 = aida::ui::fonts::h2();
			ImFont* f_caption = aida::ui::fonts::caption();
			dl->AddText(f_h2, 15.f,
				ImVec2(glyph_x + glyph_r * 2.f + 12.f, glyph_y + 4.f),
				th.text_primary, title);
			dl->AddText(f_caption, 13.f,
				ImVec2(glyph_x + glyph_r * 2.f + 12.f, glyph_y + 22.f),
				th.text_dim, "Custom OAuth client");

			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f, a.y + 64.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim), "client_id");
			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f, a.y + 80.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th.panel_header));
			ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(th.border_subtle));
			ImGui::SetNextItemWidth(card_w - 32.f);
			ImGui::InputTextWithHint("##cid", "Custom OAuth client_id",
				g_state.custom_client_id_buf[b_idx],
				sizeof(g_state.custom_client_id_buf[b_idx]));
			ImGui::PopStyleColor(2);

			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f, a.y + 116.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim), "redirect_uri");
			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f, a.y + 132.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th.panel_header));
			ImGui::SetNextItemWidth((card_w - 32.f) * 0.55f);
			ImGui::InputTextWithHint("##ruri", default_redirect,
				g_state.custom_redirect_uri_buf[b_idx],
				sizeof(g_state.custom_redirect_uri_buf[b_idx]));
			ImGui::PopStyleColor();

			float right_x = a.x + 16.f + (card_w - 32.f) * 0.55f + 10.f;
			ImGui::SetCursorScreenPos(ImVec2(right_x, a.y + 116.f));
			ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(th.text_dim),
				"scopes (comma-separated)");
			ImGui::SetCursorScreenPos(ImVec2(right_x, a.y + 132.f));
			ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(th.panel_header));
			ImGui::SetNextItemWidth((card_w - 32.f) * 0.45f - 10.f);
			ImGui::InputTextWithHint("##scp", default_scopes_hint,
				g_state.custom_scopes_buf[b_idx],
				sizeof(g_state.custom_scopes_buf[b_idx]));
			ImGui::PopStyleColor();

			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f, a.y + 172.f));
			if (aida::ui::button("Save", aida::ui::button_kind_t::primary,
					aida::ui::size_t_::md, ImVec2(96.f, 32.f))) {
				save_custom_buf(b_idx);
			}

			ImGui::SetCursorScreenPos(ImVec2(a.x + 16.f + 96.f + 8.f, a.y + 172.f));
			if (aida::ui::button("Reset to default", aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md, ImVec2(160.f, 32.f))) {
				reset_custom_buf(b_idx);
				g_state.custom_loaded[b_idx] = false;
				load_custom_buf(b_idx);
			}

			ImGui::SetCursorScreenPos(ImVec2(cur.x, cur.y + card_h + 14.f));
			ImGui::PopID();
		}

		static void render_custom_oauth_tab(float panel_w, float panel_h)
		{
			(void)panel_h;
			(void)panel_w;

			for (int i = 0; i < 3; ++i) load_custom_buf(i);

			ImGui::Dummy(ImVec2(0.f, 6.f));

			float ar = globals::ui::accent.x;
			float ag = globals::ui::accent.y;
			float ab = globals::ui::accent.z;

			ImVec2 cur = ImGui::GetCursorScreenPos();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			float w = ImGui::GetContentRegionAvail().x;
			ui_anim::render_inline_callout(dl,
				cur.x, cur.y, w, 40.f,
				"If you've registered your own AiDA OAuth app, paste your credentials here. Leave blank to use AiDA's default app.",
				ui_anim::callout_kind_t::info, ar, ag, ab, 1.f);
			ImGui::Dummy(ImVec2(0.f, 50.f));

			render_custom_provider_card("Anthropic (Claude Code)", 0,
				"http://localhost:0/callback",
				"org:create_api_key,user:profile,user:inference,user:sessions:claude_code,user:mcp_servers,user:file_upload",
				row_def_for(row_kind_t::oauth_claude_code));

			render_custom_provider_card("OpenAI (Codex / ChatGPT)", 1,
				"http://127.0.0.1:1455/auth/callback",
				"openid,profile,email,offline_access",
				row_def_for(row_kind_t::oauth_codex));

			render_custom_provider_card("GitHub Copilot", 2,
				"(device-code flow ignores redirect_uri)",
				"read:user,read:org",
				row_def_for(row_kind_t::oauth_copilot));
		}

		static void render_phase_chips(ImDrawList* fdl, float x, float y, float w,
									   flow_phase_t phase, float alpha,
									   ImU32 accent_top, ImU32 accent_bot, bool is_device_flow)
		{
			const auto& th = aida::ui::resolved();
			const char* labels[3];
			if (is_device_flow) {
				labels[0] = "Device Code";
				labels[1] = "Browser";
				labels[2] = "Session";
			} else {
				labels[0] = "Browser";
				labels[1] = "Callback";
				labels[2] = "Session";
			}

			int active = 0;
			int completed = 0;
			switch (phase) {
				case flow_phase_t::idle:
				case flow_phase_t::browser:    active = 0; completed = 0; break;
				case flow_phase_t::callback:   active = 1; completed = 1; break;
				case flow_phase_t::session:    active = 2; completed = 2; break;
				case flow_phase_t::complete:   active = -1; completed = 3; break;
				case flow_phase_t::error_state:active = -1; completed = 0; break;
			}

			ImFont* f = aida::ui::fonts::caption();
			float fs = 10.5f;

			float chip_h = 26.f;
			float gap = 8.f;
			float chip_w = (w - gap * 2.f) / 3.f;

			float pulse = aida::ui::clock::pulse(0.7f, 0.75f, 1.f);

			for (int i = 0; i < 3; ++i) {
				float cx = x + (chip_w + gap) * (float)i;
				float cy = y;
				ImVec2 ca = ImVec2(cx, cy);
				ImVec2 cb = ImVec2(cx + chip_w, cy + chip_h);

				bool is_active = (i == active);
				bool is_done = (i < completed);

				ImU32 fill = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
				ImU32 border = aida::ui::with_alpha(th.border_subtle, alpha);
				ImU32 text_col = aida::ui::with_alpha(th.text_dim, alpha);

				if (is_done) {
					fill = aida::ui::with_alpha(aida::ui::mix(th.success_soft, th.success, 0.35f), alpha);
					border = aida::ui::with_alpha(th.success, alpha * 0.7f);
					text_col = aida::ui::with_alpha(th.success, alpha);
				} else if (is_active) {
					ImU32 grad_top = aida::ui::with_alpha(accent_top, alpha * pulse);
					ImU32 grad_bot = aida::ui::with_alpha(accent_bot, alpha * pulse);
					ImU32 grad_flat = aida::ui::mix(grad_top, grad_bot, 0.5f);
					fdl->AddRectFilled(ca, cb, grad_flat, chip_h * 0.5f);
					border = aida::ui::with_alpha(th.accent_hover, alpha);
					text_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), alpha);
				}

				if (!is_active || is_done) {
					fdl->AddRectFilled(ca, cb, fill, chip_h * 0.5f);
				}
				fdl->AddRect(ca, cb, border, chip_h * 0.5f, 0, 1.f);

				float dot_r = 4.5f;
				float dot_x = cx + 12.f;
				float dot_y = cy + chip_h * 0.5f;

				if (is_done) {
					aida::ui::brand::render_check_drawn(fdl,
						ImVec2(dot_x, dot_y), 10.f, 1.f,
						aida::ui::with_alpha(th.success, alpha), 2.f);
				} else if (is_active) {
					fdl->AddCircleFilled(ImVec2(dot_x, dot_y), dot_r * pulse,
						aida::ui::with_alpha(IM_COL32(255, 255, 255, 235), alpha), 12);
					fdl->AddCircle(ImVec2(dot_x, dot_y), dot_r + 1.5f,
						aida::ui::with_alpha(IM_COL32(255, 255, 255, 100), alpha * pulse), 12, 1.f);
				} else {
					fdl->AddCircle(ImVec2(dot_x, dot_y), dot_r,
						aida::ui::with_alpha(th.text_dim, alpha * 0.6f), 12, 1.f);
				}

				ImVec2 lts = f->CalcTextSizeA(fs, FLT_MAX, 0.f, labels[i]);
				fdl->AddText(f, fs,
					ImVec2(cx + chip_w - lts.x - 12.f, cy + (chip_h - lts.y) * 0.5f),
					text_col, labels[i]);

				if (i < 2) {
					float lx0 = cx + chip_w;
					float lx1 = cx + chip_w + gap;
					float ly = cy + chip_h * 0.5f;
					ImU32 conn_col = (i < completed)
						? aida::ui::with_alpha(th.success, alpha * 0.7f)
						: aida::ui::with_alpha(th.border_subtle, alpha);
					fdl->AddLine(ImVec2(lx0, ly), ImVec2(lx1, ly), conn_col, 1.5f);
				}
			}
		}

		struct sheet_layout_t {
			float px;
			float py;
			float pw;
			float ph;
			float alpha;
			float scale;
			float shake_offset_x;
		};

		static sheet_layout_t render_modal_chrome(ImDrawList* fdl, modal_anim_t& ma,
			float pw, float ph, ImU32 stripe_top, ImU32 stripe_bot)
		{
			float dt = aida::ui::clock::dt();
			ma.enter.tick(dt);
			ma.exit.tick(dt);
			ma.shake.tick(dt);
			ma.success.tick(dt);
			ma.sparkle.tick(dt);

			const auto& th = aida::ui::resolved();
			ImVec2 display = ImGui::GetIO().DisplaySize;

			float enter_t = ma.enter.eased();
			float exit_t = ma.exit.eased();
			float visible = enter_t * (1.f - exit_t);

			float dim_alpha = visible * 0.45f;
			fdl->AddRectFilled(ImVec2(0, 0), display,
				aida::ui::with_alpha(IM_COL32(8, 8, 16, 255), dim_alpha));

			float scale = 0.92f + 0.08f * enter_t;
			scale *= (1.f - 0.04f * exit_t);

			float right_margin = 36.f;
			float bottom_margin = 36.f;
			float anchor_x = display.x - right_margin;
			float anchor_y = display.y - bottom_margin;

			float sw = pw * scale;
			float sh = ph * scale;
			float px_target = anchor_x - sw;
			float py_target = anchor_y - sh;

			float slide = (1.f - enter_t) * 16.f + exit_t * 16.f;
			float py = py_target + slide;
			float px = px_target;

			float shake_x = 0.f;
			if (ma.shake.active || ma.shake.progress > 0.001f) {
				float st = ma.shake.progress;
				float decay = 1.f - st;
				float osc = sinf(st * 6.2831853f * 3.0f);
				shake_x = osc * 6.f * decay;
			}
			px += shake_x;

			sheet_layout_t out;
			out.px = px;
			out.py = py;
			out.pw = sw;
			out.ph = sh;
			out.alpha = visible;
			out.scale = scale;
			out.shake_offset_x = shake_x;

			ImVec2 a = ImVec2(px, py);
			ImVec2 b = ImVec2(px + sw, py + sh);

			aida::ui::blur::render_drop_shadow(fdl, a, b, 14.f, 4,
				0.30f * visible, ImVec2(0.f, 6.f));

			ImU32 fill = aida::ui::with_alpha(th.bg_elevated, visible);
			fdl->AddRectFilled(a, b, fill, 14.f);

			ImU32 glass = aida::ui::with_alpha(th.glass_tint, visible);
			fdl->AddRectFilled(a, b, glass, 14.f);

			ImU32 border = aida::ui::with_alpha(th.border_strong, visible);
			fdl->AddRect(a, b, border, 14.f, 0, 1.f);

			ImU32 stripe_a = aida::ui::with_alpha(stripe_top, visible);
			ImU32 stripe_b = aida::ui::with_alpha(stripe_bot, visible);
			fdl->AddRectFilledMultiColor(
				ImVec2(a.x + 1.f, a.y + 1.f),
				ImVec2(b.x - 1.f, a.y + 4.f),
				stripe_a, stripe_b, stripe_b, stripe_a);

			return out;
		}

		static bool draw_sheet_button(ImDrawList* fdl, float bx, float by, float bw, float bh,
			const char* label, aida::ui::button_kind_t kind, float alpha,
			bool pulse_gentle = false, bool disabled = false)
		{
			const auto& th = aida::ui::resolved();
			ImVec2 mp = ImGui::GetIO().MousePos;
			bool hov = mp.x >= bx && mp.x <= bx + bw && mp.y >= by && mp.y <= by + bh && !disabled;

			float pulse = pulse_gentle ? aida::ui::clock::pulse(0.42f, 0.97f, 1.02f) : 1.f;
			float scale = (hov ? 1.02f : 1.0f) * pulse;
			float dx = (bw - bw * scale) * 0.5f;
			float dy = (bh - bh * scale) * 0.5f;
			ImVec2 a = ImVec2(bx + dx, by + dy);
			ImVec2 b = ImVec2(bx + bw - dx, by + bh - dy);

			ImU32 fill_top, fill_bot, border, text_col;
			switch (kind) {
				case aida::ui::button_kind_t::primary:
					fill_top = aida::ui::with_alpha(th.accent_grad_top, alpha);
					fill_bot = aida::ui::with_alpha(th.accent_grad_bot, alpha);
					border = aida::ui::with_alpha(th.accent_hover, alpha);
					text_col = aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), alpha);
					break;
				case aida::ui::button_kind_t::destructive:
					fill_top = aida::ui::with_alpha(th.error, alpha * 0.18f);
					fill_bot = aida::ui::with_alpha(th.error, alpha * 0.22f);
					border = aida::ui::with_alpha(th.error, alpha * 0.55f);
					text_col = aida::ui::with_alpha(th.error, alpha);
					break;
				case aida::ui::button_kind_t::secondary:
				default:
					fill_top = aida::ui::with_alpha(th.panel_header, alpha);
					fill_bot = aida::ui::with_alpha(th.panel_header, alpha);
					border = aida::ui::with_alpha(th.border_subtle, alpha * (1.f + (hov ? 0.6f : 0.f)));
					text_col = aida::ui::with_alpha(th.text_primary, alpha);
					break;
			}

			{
				ImU32 fill_flat = aida::ui::mix(fill_top, fill_bot, 0.5f);
				fdl->AddRectFilled(a, b, fill_flat, 8.f);
			}
			fdl->AddRect(a, b, border, 8.f, 0, 1.f);

			if (hov) {
				ImU32 wash = aida::ui::with_alpha(IM_COL32(255, 255, 255, 32), alpha);
				fdl->AddRectFilled(a, b, wash, 8.f);
				ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
			}

			ImFont* f = aida::ui::fonts::body_em();
			float fs = 13.f;
			ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
			fdl->AddText(f, fs,
				ImVec2(a.x + (bw - ts.x) * 0.5f, a.y + (bh - ts.y) * 0.5f),
				text_col, label);

			return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		}

		static void render_modal_header(ImDrawList* fdl, const sheet_layout_t& sl,
			const row_def_t& def, const char* title)
		{
			const auto& th = aida::ui::resolved();
			float alpha = sl.alpha;

			float glyph_r = 16.f;
			float glyph_cx = sl.px + 22.f + glyph_r;
			float glyph_cy = sl.py + 24.f + glyph_r;
			brand_glyph::render(fdl, def.glyph_kind, ImVec2(glyph_cx, glyph_cy), glyph_r,
				def.grad_top, def.grad_bot, def.ring, alpha);

			ImFont* f_h2 = aida::ui::fonts::h2();
			ImFont* f_caption = aida::ui::fonts::caption();
			fdl->AddText(f_h2, 16.f,
				ImVec2(glyph_cx + glyph_r + 14.f, glyph_cy - 13.f),
				aida::ui::with_alpha(th.text_primary, alpha), title);

			fdl->AddText(f_caption, 13.f,
				ImVec2(glyph_cx + glyph_r + 14.f, glyph_cy + 4.f),
				aida::ui::with_alpha(th.text_dim, alpha), def.subtitle);
		}

		static flow_phase_t derive_phase_codex(const aida::auth::codex::codex_login_state_t* sp,
			const modal_anim_t& ma, bool exchange_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			if (sp->done.load() && !exchange_in_progress && !sp->error.empty())
				return flow_phase_t::error_state;
			if (sp->done.load()) return flow_phase_t::session;
			if (!sp->received_code.empty()) return flow_phase_t::callback;
			return flow_phase_t::browser;
		}

		static flow_phase_t derive_phase_claude(const aida::auth::claude_code::claude_code_login_state_t* sp,
			const modal_anim_t& ma, bool exchange_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			if (sp->done.load() && !exchange_in_progress && !sp->error.empty())
				return flow_phase_t::error_state;
			if (sp->done.load()) return flow_phase_t::session;
			if (!sp->received_code.empty()) return flow_phase_t::callback;
			return flow_phase_t::browser;
		}

		static flow_phase_t derive_phase_copilot(const aida::auth::copilot::copilot_login_state_t* sp,
			const modal_anim_t& ma, bool poll_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			if (sp->done.load() && !poll_in_progress && !sp->error.empty())
				return flow_phase_t::error_state;
			if (sp->done.load()) return flow_phase_t::session;
			if (!sp->user_code.empty()) return flow_phase_t::callback;
			return flow_phase_t::browser;
		}

		static void render_modal_footer_overlay(ImDrawList* fdl, const sheet_layout_t& sl,
			modal_anim_t& ma, ImU32 accent_col)
		{
			float alpha = sl.alpha;
			if (ma.success.progress > 0.001f) {
				float t01 = ma.success.eased();
				float cx = sl.px + sl.pw * 0.5f;
				float cy = sl.py + sl.ph * 0.5f;
				aida::ui::brand::render_check_drawn(fdl, ImVec2(cx, cy), 32.f, t01,
					aida::ui::with_alpha(accent_col, alpha), 3.5f);
			}
			if (ma.sparkle.progress > 0.001f) {
				float t01 = ma.sparkle.eased();
				float cx = sl.px + sl.pw * 0.5f;
				float cy = sl.py + sl.ph * 0.5f;
				aida::ui::brand::render_sparkle_burst(fdl, ImVec2(cx, cy),
					t01, 60.f, aida::ui::with_alpha(accent_col, alpha), 10);
			}
		}

		static void tick_modal_post_success(modal_anim_t& ma)
		{
			if (ma.success_played && ma.success.is_finished() && !ma.exiting) {
				ma.begin_exit();
			}
		}

		static bool modal_should_dismiss(const modal_anim_t& ma)
		{
			return ma.exiting && ma.exit.is_finished();
		}

		static void render_codex_modal()
		{
			if (!g_state.codex_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 460.f;
			const float ph = 320.f;

			const row_def_t& def = row_def_for(row_kind_t::oauth_codex);
			sheet_layout_t sl = render_modal_chrome(fdl, g_state.codex_anim, pw, ph,
				def.grad_top, def.grad_bot);

			render_modal_header(fdl, sl, def, "Sign in with OpenAI");

			const auto& th = aida::ui::resolved();
			ImU32 accent_col = aida::ui::mix(def.grad_top, def.grad_bot, 0.5f);

			std::string url_open;
			std::string err_text;
			flow_phase_t phase = flow_phase_t::browser;
			const bool starting_in_progress = g_state.codex_starting.load();
			const bool exchange_in_progress = g_state.codex_exchange_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_state) {
					if (!starting_in_progress)
						url_open = g_state.codex_state->auth_url;
					if (g_state.codex_state->done.load() && !exchange_in_progress)
						err_text = g_state.codex_state->error;
					phase = derive_phase_codex(g_state.codex_state.get(), g_state.codex_anim,
						exchange_in_progress);
				}
			}

			float chip_y = sl.py + 76.f;
			render_phase_chips(fdl, sl.px + 22.f, chip_y, sl.pw - 44.f,
				phase, sl.alpha, def.grad_top, def.grad_bot, false);

			float center_x = sl.px + sl.pw * 0.5f;
			float orbit_y = sl.py + 156.f;

			if (g_state.codex_anim.success_played) {
				aida::ui::brand::render_check_drawn(fdl, ImVec2(center_x, orbit_y), 28.f,
					g_state.codex_anim.success.eased(),
					aida::ui::with_alpha(accent_col, sl.alpha), 3.f);
			} else {
				aida::ui::brand::render_orbit_ring(fdl, ImVec2(center_x, orbit_y), 18.f, 4, 2.5f,
					accent_col, sl.alpha);
				aida::ui::brand::render_orbit_ring(fdl, ImVec2(center_x, orbit_y), 11.f, 3, -1.7f,
					aida::ui::lighten(accent_col, 30), sl.alpha * 0.85f);
			}

			std::string status = "Waiting for browser callback (port 1455)";
			if (!err_text.empty()) status = "Error: " + err_text;
			else if (phase == flow_phase_t::session) status = "Finalizing session";
			else if (phase == flow_phase_t::callback) status = "Received callback, exchanging code";

			ImFont* f_body = aida::ui::fonts::body();
			ImVec2 ss = f_body->CalcTextSizeA(13.f, FLT_MAX, 0.f, status.c_str());
			fdl->AddText(f_body, 13.f,
				ImVec2(sl.px + (sl.pw - ss.x) * 0.5f, sl.py + 198.f),
				aida::ui::with_alpha(th.text_secondary, sl.alpha * 0.95f), status.c_str());

			float bw = (sl.pw - 44.f - 10.f) * 0.5f;
			float bh = 36.f;
			float bx_open = sl.px + 22.f;
			float bx_cancel = bx_open + bw + 10.f;
			float by = sl.py + sl.ph - bh - 18.f;

			if (draw_sheet_button(fdl, bx_open, by, bw, bh, "Open browser",
					aida::ui::button_kind_t::primary, sl.alpha, true) && !url_open.empty()) {
				open_url_in_browser(url_open);
			}

			if (draw_sheet_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					aida::ui::button_kind_t::secondary, sl.alpha)) {
				request_close_codex();
			}

			render_modal_footer_overlay(fdl, sl, g_state.codex_anim, accent_col);
			tick_modal_post_success(g_state.codex_anim);

			if (modal_should_dismiss(g_state.codex_anim)) {
				close_codex_modal_immediate();
			}
		}

		static void render_claude_code_modal()
		{
			if (!g_state.claude_code_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 460.f;
			const float ph = 320.f;

			const row_def_t& def = row_def_for(row_kind_t::oauth_claude_code);
			sheet_layout_t sl = render_modal_chrome(fdl, g_state.claude_code_anim, pw, ph,
				def.grad_top, def.grad_bot);

			render_modal_header(fdl, sl, def, "Sign in with Claude");

			const auto& th = aida::ui::resolved();
			ImU32 accent_col = aida::ui::mix(def.grad_top, def.grad_bot, 0.5f);

			std::string url_open;
			std::string err_text;
			flow_phase_t phase = flow_phase_t::browser;
			const bool starting_in_progress = g_state.claude_code_starting.load();
			const bool exchange_in_progress = g_state.claude_code_exchange_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.claude_code_state) {
					if (!starting_in_progress)
						url_open = g_state.claude_code_state->auth_url;
					if (g_state.claude_code_state->done.load() && !exchange_in_progress)
						err_text = g_state.claude_code_state->error;
					phase = derive_phase_claude(g_state.claude_code_state.get(),
						g_state.claude_code_anim, exchange_in_progress);
				}
			}

			float chip_y = sl.py + 76.f;
			render_phase_chips(fdl, sl.px + 22.f, chip_y, sl.pw - 44.f,
				phase, sl.alpha, def.grad_top, def.grad_bot, false);

			float center_x = sl.px + sl.pw * 0.5f;
			float orbit_y = sl.py + 156.f;

			if (g_state.claude_code_anim.success_played) {
				aida::ui::brand::render_check_drawn(fdl, ImVec2(center_x, orbit_y), 28.f,
					g_state.claude_code_anim.success.eased(),
					aida::ui::with_alpha(accent_col, sl.alpha), 3.f);
			} else {
				aida::ui::brand::render_orbit_ring(fdl, ImVec2(center_x, orbit_y), 18.f, 4, 2.5f,
					accent_col, sl.alpha);
				aida::ui::brand::render_orbit_ring(fdl, ImVec2(center_x, orbit_y), 11.f, 3, -1.7f,
					aida::ui::lighten(accent_col, 30), sl.alpha * 0.85f);
			}

			std::string status = "Waiting for browser callback";
			if (!err_text.empty()) status = "Error: " + err_text;
			else if (phase == flow_phase_t::session) status = "Finalizing session";
			else if (phase == flow_phase_t::callback) status = "Received callback, exchanging code";

			ImFont* f_body = aida::ui::fonts::body();
			ImVec2 ss = f_body->CalcTextSizeA(13.f, FLT_MAX, 0.f, status.c_str());
			fdl->AddText(f_body, 13.f,
				ImVec2(sl.px + (sl.pw - ss.x) * 0.5f, sl.py + 198.f),
				aida::ui::with_alpha(th.text_secondary, sl.alpha * 0.95f), status.c_str());

			float bw = (sl.pw - 44.f - 10.f) * 0.5f;
			float bh = 36.f;
			float bx_open = sl.px + 22.f;
			float bx_cancel = bx_open + bw + 10.f;
			float by = sl.py + sl.ph - bh - 18.f;

			if (draw_sheet_button(fdl, bx_open, by, bw, bh, "Open browser",
					aida::ui::button_kind_t::primary, sl.alpha, true) && !url_open.empty()) {
				open_url_in_browser(url_open);
			}

			if (draw_sheet_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					aida::ui::button_kind_t::secondary, sl.alpha)) {
				request_close_claude_code();
			}

			render_modal_footer_overlay(fdl, sl, g_state.claude_code_anim, accent_col);
			tick_modal_post_success(g_state.claude_code_anim);

			if (modal_should_dismiss(g_state.claude_code_anim)) {
				close_claude_code_modal_immediate();
			}
		}

		static void render_copilot_modal()
		{
			if (!g_state.copilot_modal_open.load()) return;

			ImDrawList* fdl = ImGui::GetForegroundDrawList();
			const float pw = 480.f;
			const float ph = 388.f;

			const row_def_t& def = row_def_for(row_kind_t::oauth_copilot);
			sheet_layout_t sl = render_modal_chrome(fdl, g_state.copilot_anim, pw, ph,
				def.grad_top, def.grad_bot);

			render_modal_header(fdl, sl, def, "Sign in with GitHub Copilot");

			const auto& th = aida::ui::resolved();
			ImU32 accent_col = aida::ui::mix(th.accent_grad_top, th.accent_grad_bot, 0.5f);

			const bool flow_started = g_state.copilot_flow_started.load();

			if (!flow_started) {
				ImFont* f_caption = aida::ui::fonts::caption();
				ImFont* f_body = aida::ui::fonts::body();

				const char* prompt = "Optional: enter your GitHub Enterprise URL, "
					"or leave blank to use github.com.";
				ImVec2 ps = f_body->CalcTextSizeA(13.f, FLT_MAX, sl.pw - 44.f, prompt);
				fdl->AddText(f_body, 13.f,
					ImVec2(sl.px + 22.f, sl.py + 84.f),
					aida::ui::with_alpha(th.text_secondary, sl.alpha * 0.95f),
					prompt, nullptr, sl.pw - 44.f);

				float label_y = sl.py + 84.f + ps.y + 12.f;
				fdl->AddText(f_caption, 12.f,
					ImVec2(sl.px + 22.f, label_y),
					aida::ui::with_alpha(th.text_dim, sl.alpha),
					"GitHub Enterprise URL (optional)");

				float input_x = sl.px + 22.f;
				float input_y = label_y + 16.f;
				float input_w = sl.pw - 44.f;
				float input_h = 36.f;

				ImU32 input_fill = aida::ui::with_alpha(th.bg_elevated, sl.alpha * 0.85f);
				fdl->AddRectFilled(ImVec2(input_x, input_y),
					ImVec2(input_x + input_w, input_y + input_h), input_fill, 8.f);
				ImU32 input_border = aida::ui::with_alpha(th.border_subtle, sl.alpha);
				fdl->AddRect(ImVec2(input_x, input_y),
					ImVec2(input_x + input_w, input_y + input_h), input_border, 8.f, 0, 1.f);

				ImGui::SetNextWindowPos(ImVec2(sl.px, sl.py), ImGuiCond_Always);
				ImGui::SetNextWindowSize(ImVec2(sl.pw, sl.ph), ImGuiCond_Always);
				ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
				ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
				ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
				ImGui::PushStyleVar(ImGuiStyleVar_Alpha, sl.alpha);

				const ImGuiWindowFlags flags =
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
					ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
					ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
					ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoFocusOnAppearing;

				if (ImGui::Begin("##aida_copilot_preflow", nullptr, flags)) {
					float input_text_x = input_x + 10.f;
					float input_text_y = input_y + (input_h - ImGui::GetFontSize()) * 0.5f;
					ImGui::SetCursorScreenPos(ImVec2(input_text_x, input_text_y));
					ImGui::PushItemWidth(input_w - 20.f);

					ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
					ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0, 0, 0, 0));
					ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0, 0, 0, 0));
					ImGui::PushStyleColor(ImGuiCol_Text,
						ImGui::ColorConvertU32ToFloat4(
							aida::ui::with_alpha(th.text_primary, sl.alpha)));
					ImGui::PushStyleColor(ImGuiCol_TextDisabled,
						ImGui::ColorConvertU32ToFloat4(
							aida::ui::with_alpha(th.text_dim, sl.alpha)));
					ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.f, 0.f));

					if (ImGui::IsWindowAppearing())
						ImGui::SetKeyboardFocusHere();

					ImGui::InputTextWithHint("##copilot_ghe_url",
						"https://github.your-company.com",
						g_state.copilot_ghe_buf,
						sizeof(g_state.copilot_ghe_buf));

					ImGui::PopStyleVar();
					ImGui::PopStyleColor(5);
					ImGui::PopItemWidth();
				}
				ImGui::End();

				ImGui::PopStyleVar(3);
				ImGui::PopStyleColor(2);

				float bw = (sl.pw - 44.f - 10.f) * 0.5f;
				float bh = 36.f;
				float bx_start = sl.px + 22.f;
				float bx_cancel = bx_start + bw + 10.f;
				float by = sl.py + sl.ph - bh - 18.f;

				if (draw_sheet_button(fdl, bx_start, by, bw, bh, "Start login",
						aida::ui::button_kind_t::primary, sl.alpha, true)
					&& !g_state.copilot_anim.exiting) {
					std::string trimmed = g_state.copilot_ghe_buf;
					while (!trimmed.empty()
						&& (trimmed.back() == ' ' || trimmed.back() == '\t'
							|| trimmed.back() == '\r' || trimmed.back() == '\n'))
						trimmed.pop_back();
					size_t first_non_ws = 0;
					while (first_non_ws < trimmed.size()
						&& (trimmed[first_non_ws] == ' ' || trimmed[first_non_ws] == '\t'))
						++first_non_ws;
					if (first_non_ws > 0)
						trimmed.erase(0, first_non_ws);
					std::optional<std::string> ghe;
					if (!trimmed.empty())
						ghe = trimmed;
					start_copilot_flow(ghe);
				}

				if (draw_sheet_button(fdl, bx_cancel, by, bw, bh, "Cancel",
						aida::ui::button_kind_t::secondary, sl.alpha)) {
					request_close_copilot();
				}

				render_modal_footer_overlay(fdl, sl, g_state.copilot_anim, accent_col);
				tick_modal_post_success(g_state.copilot_anim);

				if (modal_should_dismiss(g_state.copilot_anim)) {
					close_copilot_modal_immediate();
				}
				return;
			}

			std::string user_code;
			std::string verify_uri;
			std::string err_text;
			flow_phase_t phase = flow_phase_t::browser;
			bool have_code = false;
			const bool starting_in_progress = g_state.copilot_starting.load();
			const bool poll_in_progress = g_state.copilot_poll_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.copilot_state) {
					if (!starting_in_progress) {
						user_code = g_state.copilot_state->user_code;
						verify_uri = g_state.copilot_state->verification_uri;
						have_code = !user_code.empty();
					}
					if (g_state.copilot_state->done.load() && !poll_in_progress)
						err_text = g_state.copilot_state->error;
					phase = derive_phase_copilot(g_state.copilot_state.get(),
						g_state.copilot_anim, poll_in_progress);
				}
			}

			float chip_y = sl.py + 76.f;
			render_phase_chips(fdl, sl.px + 22.f, chip_y, sl.pw - 44.f,
				phase, sl.alpha, th.accent_grad_top, th.accent_grad_bot, true);

			if (have_code) {
				ImFont* fdisp = aida::ui::fonts::display();
				float code_size = 24.f;
				float chip_h = 56.f;
				float chip_pad_x = 24.f;
				ImVec2 code_ts = fdisp->CalcTextSizeA(code_size, FLT_MAX, 0.f, user_code.c_str());
				float chip_w = code_ts.x + chip_pad_x * 2.f + 60.f;
				if (chip_w > sl.pw - 44.f) chip_w = sl.pw - 44.f;
				float chip_x = sl.px + (sl.pw - chip_w) * 0.5f;
				float chip_y_code = sl.py + 124.f;

				ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, sl.alpha);
				ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, sl.alpha);
				ImU32 fill_flat = aida::ui::mix(fill_top, fill_bot, 0.5f);
				fdl->AddRectFilled(
					ImVec2(chip_x, chip_y_code),
					ImVec2(chip_x + chip_w, chip_y_code + chip_h),
					fill_flat, 10.f);
				fdl->AddRect(
					ImVec2(chip_x, chip_y_code),
					ImVec2(chip_x + chip_w, chip_y_code + chip_h),
					aida::ui::with_alpha(th.accent_hover, sl.alpha), 10.f, 0, 1.5f);

				fdl->AddText(fdisp, code_size,
					ImVec2(chip_x + chip_pad_x, chip_y_code + (chip_h - code_ts.y) * 0.5f),
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), sl.alpha),
					user_code.c_str());

				float copy_w = 50.f;
				float copy_h = 32.f;
				float copy_x = chip_x + chip_w - copy_w - 12.f;
				float copy_y = chip_y_code + (chip_h - copy_h) * 0.5f;
				ImVec2 mp = ImGui::GetIO().MousePos;
				bool copy_hov = mp.x >= copy_x && mp.x <= copy_x + copy_w
					&& mp.y >= copy_y && mp.y <= copy_y + copy_h;
				ImU32 copy_bg = aida::ui::with_alpha(IM_COL32(255, 255, 255, copy_hov ? 60 : 30), sl.alpha);
				fdl->AddRectFilled(ImVec2(copy_x, copy_y), ImVec2(copy_x + copy_w, copy_y + copy_h),
					copy_bg, 6.f);
				fdl->AddRect(ImVec2(copy_x, copy_y), ImVec2(copy_x + copy_w, copy_y + copy_h),
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 120), sl.alpha), 6.f, 0, 1.f);
				ImFont* f_em = aida::ui::fonts::body_em();
				ImVec2 cs = f_em->CalcTextSizeA(12.f, FLT_MAX, 0.f, "Copy");
				fdl->AddText(f_em, 14.f,
					ImVec2(copy_x + (copy_w - cs.x) * 0.5f, copy_y + (copy_h - cs.y) * 0.5f),
					aida::ui::with_alpha(IM_COL32(255, 255, 255, 250), sl.alpha), "Copy");

				if (copy_hov) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
				if (copy_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
					ImGui::SetClipboardText(user_code.c_str());
					toast_notification::push("Code copied",
						toast_notification::toast_type_t::info, 2.5f);
					g_state.copilot_copy_flash.trigger();
				}

				float flash_v = g_state.copilot_copy_flash.tick(aida::ui::clock::dt(), 2.0f);
				if (flash_v > 0.f) {
					ImVec2 burst_c = ImVec2(copy_x + copy_w * 0.5f, copy_y + copy_h * 0.5f);
					aida::ui::brand::render_sparkle_burst(fdl, burst_c, 1.f - flash_v, 28.f,
						aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), sl.alpha * flash_v), 8);
				}
			}

			float orbit_y = sl.py + ph - 122.f;
			float center_x = sl.px + sl.pw * 0.5f;

			if (g_state.copilot_anim.success_played) {
				aida::ui::brand::render_check_drawn(fdl, ImVec2(center_x, orbit_y), 24.f,
					g_state.copilot_anim.success.eased(),
					aida::ui::with_alpha(accent_col, sl.alpha), 3.f);
			} else if (have_code) {
				aida::ui::brand::render_orbit_ring(fdl, ImVec2(center_x, orbit_y), 14.f, 4, 2.0f,
					accent_col, sl.alpha * 0.85f);
			}

			std::string status_text = "Initializing device flow";
			if (!err_text.empty()) status_text = "Error: " + err_text;
			else if (phase == flow_phase_t::session) status_text = "Authorizing";
			else if (have_code) status_text = "Polling GitHub for completion";

			ImFont* f_body = aida::ui::fonts::body();
			ImVec2 ss = f_body->CalcTextSizeA(13.f, FLT_MAX, 0.f, status_text.c_str());
			fdl->AddText(f_body, 13.f,
				ImVec2(sl.px + (sl.pw - ss.x) * 0.5f, sl.py + ph - 88.f),
				aida::ui::with_alpha(th.text_secondary, sl.alpha * 0.95f), status_text.c_str());

			float bw = (sl.pw - 44.f - 10.f) * 0.5f;
			float bh = 36.f;
			float bx_open = sl.px + 22.f;
			float bx_cancel = bx_open + bw + 10.f;
			float by = sl.py + sl.ph - bh - 18.f;

			std::string open_label = verify_uri.empty()
				? std::string("Open verification")
				: std::string("Open github.com");

			if (draw_sheet_button(fdl, bx_open, by, bw, bh, open_label.c_str(),
					aida::ui::button_kind_t::primary, sl.alpha, true) && !verify_uri.empty()) {
				open_url_in_browser(verify_uri);
			}

			if (draw_sheet_button(fdl, bx_cancel, by, bw, bh, "Cancel",
					aida::ui::button_kind_t::secondary, sl.alpha)) {
				request_close_copilot();
			}

			render_modal_footer_overlay(fdl, sl, g_state.copilot_anim, accent_col);
			tick_modal_post_success(g_state.copilot_anim);

			if (modal_should_dismiss(g_state.copilot_anim)) {
				close_copilot_modal_immediate();
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
		std::shared_ptr<aida::auth::codex::codex_login_state_t> codex_local;
		std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot_local;
		std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_local;
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			codex_local = g_state.codex_state;
			copilot_local = g_state.copilot_state;
			claude_local = g_state.claude_code_state;

			if (codex_local)
				codex_local->cancelled.store(true);
			if (copilot_local)
				copilot_local->cancelled.store(true);
			if (claude_local)
				claude_local->cancelled.store(true);

			g_state.codex_modal_open.store(false);
			g_state.copilot_modal_open.store(false);
			g_state.claude_code_modal_open.store(false);
			g_state.copilot_flow_started.store(false);
			SecureZeroMemory(g_state.copilot_ghe_buf, sizeof(g_state.copilot_ghe_buf));
		}

		if (g_state.codex_start_thread.joinable())
			g_state.codex_start_thread.join();
		if (g_state.copilot_start_thread.joinable())
			g_state.copilot_start_thread.join();
		if (g_state.claude_code_start_thread.joinable())
			g_state.claude_code_start_thread.join();

		using namespace std::chrono_literals;
		const auto deadline = std::chrono::steady_clock::now() + 35s;
		while ((g_state.codex_exchange_in_flight.load()
				|| g_state.copilot_poll_in_flight.load()
				|| g_state.claude_code_exchange_in_flight.load())
			&& std::chrono::steady_clock::now() < deadline) {
			std::this_thread::sleep_for(20ms);
		}

		if (codex_local)
			aida::auth::codex::cancel_login(*codex_local);
		if (copilot_local)
			aida::auth::copilot::cancel_login(*copilot_local);
		if (claude_local)
			aida::auth::claude_code::cancel_login(*claude_local);

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

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 6.f));

		if (ImGui::BeginTabBar("##auth_view_tabs",
				ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_NoTabListScrollingButtons)) {
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

		poll_active_logins();

		render_codex_modal();
		render_claude_code_modal();
		render_copilot_modal();
	}

}
}
