#define WIN32_LEAN_AND_MEAN
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
#include "responsive.hpp"
#include "blur_layer.hpp"
#include "brand.hpp"
#include "avatar.hpp"
#include "empty_state.hpp"
#include "fonts.hpp"
#include "../infra/executor.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"

#include "provider_catalog.hpp"
#include "provider_transforms.hpp"
#include "standalone_settings.hpp"
#include "settings_overlay.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

#include <nlohmann/json.hpp>

#include "auth_browser_launch.hpp"
#include "auth_http.hpp"

extern settings_sa_t g_sa_settings;

namespace aida {
namespace auth_view {

	namespace {

		enum class flow_phase_t : int {
			idle = 0,
			browser,
			callback,
			session,
			complete,
			error_state
		};

		struct modal_brand_t {
			const char* display_name;
			const char* subtitle;
			brand_glyph::kind_t glyph_kind;
			ImU32 grad_top;
			ImU32 grad_bot;
			ImU32 ring;
		};

		static const modal_brand_t k_brand_claude_code = {
			"Claude Code",     "Anthropic OAuth (PKCE)",
			brand_glyph::kind_t::anthropic,
			IM_COL32(228, 168, 132, 255), IM_COL32(196, 124, 84, 255),
			IM_COL32(255, 200, 168, 220)
		};
		static const modal_brand_t k_brand_codex = {
			"OpenAI Codex",    "ChatGPT OAuth (PKCE)",
			brand_glyph::kind_t::openai,
			IM_COL32(106, 220, 178, 255), IM_COL32(40, 168, 138, 255),
			IM_COL32(160, 240, 210, 220)
		};
		static const modal_brand_t k_brand_copilot = {
			"GitHub Copilot",  "GitHub Device Code",
			brand_glyph::kind_t::github,
			IM_COL32(60, 64, 92, 255),    IM_COL32(28, 32, 52, 255),
			IM_COL32(150, 158, 198, 220)
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

		enum class login_start_result_t : int {
			idle = 0,
			pending,
			succeeded,
			failed,
			cancelled,
			timed_out,
			rejected
		};

		struct login_start_ticket_t {
			std::atomic<bool> worker_started{false};
			std::atomic<bool> cancellation_requested{false};
			std::atomic<bool> terminal_published{false};
			std::uint64_t generation = 0;
			std::uint64_t deadline_ms = 0;
			std::atomic<std::uint64_t> task_id{0};
		};

		struct login_start_control_t {
			std::mutex mutex;
			std::shared_ptr<login_start_ticket_t> current;
			std::atomic<bool> active{false};
			std::atomic<bool> completion_pending{false};
			std::atomic<int> result{static_cast<int>(login_start_result_t::idle)};
			std::atomic<std::uint64_t> deadline_ms{0};
			std::atomic<std::uint64_t> generation{0};
		};

		struct browser_open_control_t {
			std::atomic<bool> in_flight{false};
			std::atomic<bool> completion_pending{false};
			std::atomic<int> result{static_cast<int>(aida::auth::browser_open_result_t::queue_rejected)};
			std::atomic<std::uint64_t> generation{0};
			std::atomic<std::uint64_t> task_id{0};
		};

		struct test_result_t {
			bool        completed = false;
			bool        success = false;
			int         latency_ms = 0;
			int         http_status = 0;
			std::string message;
		};

		struct refresh_state_t {
			std::atomic<bool> in_flight{ false };
			std::atomic<bool> completed{ false };
			std::atomic<bool> success{ false };
			std::string       message;
		};

		struct view_state_t {
			std::mutex mtx;

			std::shared_ptr<aida::auth::codex::codex_login_state_t> codex_state;
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot_state;
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_code_state;

			std::atomic<bool> codex_modal_open{ false };
			std::atomic<bool> copilot_modal_open{ false };
			std::atomic<bool> claude_code_modal_open{ false };

			login_start_control_t codex_start;
			login_start_control_t copilot_start;
			login_start_control_t claude_code_start;

			std::atomic<bool> codex_exchange_in_flight{ false };
			std::atomic<bool> copilot_poll_in_flight{ false };
			std::atomic<bool> claude_code_exchange_in_flight{ false };

			std::atomic<int> codex_exchange_result{ static_cast<int>(exchange_result_t::pending) };
			std::atomic<int> copilot_poll_result{ static_cast<int>(exchange_result_t::pending) };
			std::atomic<int> claude_code_exchange_result{ static_cast<int>(exchange_result_t::pending) };

			std::string err;
			browser_open_control_t browser_open;

			aida::events::subscription_handle_t sub_completed;
			aida::events::subscription_handle_t sub_failed;

			std::string last_completed_provider;
			std::string last_completed_email;
			std::atomic<bool> have_completed_event{ false };

			std::string last_failed_provider;
			std::string last_failed_error;
			std::atomic<bool> have_failed_event{ false };

			char copilot_ghe_buf[256]{};
			std::atomic<bool> copilot_flow_started{ false };

			modal_anim_t codex_anim;
			modal_anim_t copilot_anim;
			modal_anim_t claude_code_anim;

			aida::ui::flash_t copilot_copy_flash;

			std::string selected_provider_id;
			refresh_state_t refresh;
			std::atomic<bool> shutdown_flag{ false };

			std::mutex pending_focus_mtx;
			std::string pending_focus_provider;

			int  chatbox_active_section = 0;
			int  chatbox_provider_dropdown_index = 0;
			char chatbox_key_buf[1024] = {};
			bool chatbox_key_show = false;
			std::map<std::string, test_result_t> validate_results;
			std::map<std::string, std::shared_ptr<std::atomic<bool>>> validate_in_flight;
		};

		static view_state_t g_state;

		static void set_err_locked(const std::string& msg)
		{
			g_state.err = msg;
		}

		static int64_t now_unix()
		{
			return static_cast<int64_t>(std::time(nullptr));
		}

		static std::string canonical_provider_key(const std::string& provider_id)
		{
			std::string out;
			out.reserve(provider_id.size());
			for (unsigned char ch : provider_id) {
				if (ch == '\\') out.push_back('/');
				else out.push_back(static_cast<char>(std::tolower(ch)));
			}
			while (!out.empty() && out.back() == '/')
				out.pop_back();
			return out;
		}

		static bool auth_info_authenticated(const aida::auth::auth_info_t& info, int64_t now)
		{
			if (info.kind == aida::auth::auth_kind_t::none) return false;
			if (info.kind == aida::auth::auth_kind_t::oauth) {
				if (info.expires_unix > 0 && info.expires_unix <= now) return false;
				return !info.access.empty();
			}
			if (info.kind == aida::auth::auth_kind_t::api) return !info.api_key.empty();
			if (info.kind == aida::auth::auth_kind_t::wellknown) return !info.wellknown_token.empty();
			return false;
		}

		static std::shared_ptr<const std::unordered_map<std::string, bool>>& auth_snapshot_ref()
		{
			static std::shared_ptr<const std::unordered_map<std::string, bool>> s;
			return s;
		}

		static std::atomic<bool>& auth_snapshot_refreshing()
		{
			static std::atomic<bool> b{ false };
			return b;
		}

		static std::atomic<int64_t>& auth_snapshot_last_unix()
		{
			static std::atomic<int64_t> v{ 0 };
			return v;
		}

		static void publish_auth_snapshot(const std::vector<std::pair<std::string, aida::auth::auth_info_t>>& entries)
		{
			auto snapshot = std::make_shared<std::unordered_map<std::string, bool>>();
			snapshot->reserve(entries.size() * 2 + 8);
			const int64_t now = now_unix();
			for (const auto& kv : entries) {
				const bool authed = auth_info_authenticated(kv.second, now);
				(*snapshot)[kv.first] = authed;
				(*snapshot)[canonical_provider_key(kv.first)] = authed;
			}
			std::atomic_store_explicit(&auth_snapshot_ref(),
				std::static_pointer_cast<const std::unordered_map<std::string, bool>>(snapshot),
				std::memory_order_release);
			auth_snapshot_last_unix().store(now, std::memory_order_release);
		}

		static void schedule_auth_snapshot_refresh(bool force = false)
		{
			if (g_state.shutdown_flag.load(std::memory_order_acquire)) return;
			const int64_t now = now_unix();
			const int64_t last = auth_snapshot_last_unix().load(std::memory_order_acquire);
			if (!force && last > 0 && now >= last && now - last < 5) return;
			bool expected = false;
			if (!auth_snapshot_refreshing().compare_exchange_strong(expected, true, std::memory_order_acq_rel))
				return;
			const uint64_t start_ms = GetTickCount64();
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "auth_view";
			sub.label = "auth.snapshot_refresh";
			sub.thread_class = "service_task";
			sub.domain = aida::infra::executor::domain_t::security_liveness;
			sub.priority = 1;
			sub.body = [start_ms]() {
					bool success = false;
					size_t provider_count = 0;
					try {
						auto entries = aida::auth::store::all();
						provider_count = entries.size();
						publish_auth_snapshot(entries);
						success = true;
					} catch (...) {
					}
					auth_snapshot_refreshing().store(false, std::memory_order_release);
					const uint64_t elapsed_ms = GetTickCount64() - start_ms;
					if (!success || elapsed_ms >= 250) {
						diag::log_tagged_fmt("auth",
							"auth_snapshot_refresh_done ok=%d providers=%zu elapsed_ms=%llu",
							success ? 1 : 0,
							provider_count,
							static_cast<unsigned long long>(elapsed_ms));
					}
				};
			if (!aida::infra::executor::submit(std::move(sub)).submitted) {
				auth_snapshot_refreshing().store(false, std::memory_order_release);
			}
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

		inline constexpr std::uint64_t kLoginStartDeadlineMs =
			aida::auth::kBrowserExternalOperationDeadlineMs;
		inline constexpr std::uint64_t kLoginCancelDeadlineMs = 35000;

		static const char* login_start_result_name(login_start_result_t result)
		{
			switch (result) {
			case login_start_result_t::idle: return "idle";
			case login_start_result_t::pending: return "pending";
			case login_start_result_t::succeeded: return "succeeded";
			case login_start_result_t::failed: return "failed";
			case login_start_result_t::cancelled: return "cancelled";
			case login_start_result_t::timed_out: return "timed_out";
			case login_start_result_t::rejected: return "rejected";
			default: return "unknown";
			}
		}

		static std::uint64_t bounded_deadline(std::uint64_t budget_ms)
		{
			const std::uint64_t now = aida::infra::executor::now_ms();
			return now > (std::numeric_limits<std::uint64_t>::max)() - budget_ms
				? (std::numeric_limits<std::uint64_t>::max)()
				: now + budget_ms;
		}

		template <typename State>
		static void publish_login_start_failure(
			const std::shared_ptr<State>& state,
			const char* error) noexcept
		{
			if (!state || !error || !*error) return;
			try {
				std::lock_guard<std::mutex> state_lock(state->mutex);
				state->error = error;
			} catch (...) {
			}
			state->done.store(true, std::memory_order_release);
			try {
				std::lock_guard<std::mutex> view_lock(g_state.mtx);
				set_err_locked(error);
			} catch (...) {
			}
		}

		template <typename State, typename StartFn, typename CancelFn, typename ErrorFn>
		static bool submit_login_start_task(
			const char* label,
			const char* provider,
			login_start_control_t& control,
			const std::shared_ptr<State>& state,
			const std::shared_ptr<State>& previous,
			StartFn start_fn,
			CancelFn cancel_fn,
			ErrorFn error_fn)
		{
			std::shared_ptr<login_start_ticket_t> ticket;
			try {
				ticket = std::make_shared<login_start_ticket_t>();
			} catch (...) {
				publish_login_start_failure(state, "Login startup state allocation failed");
				control.result.store(static_cast<int>(login_start_result_t::rejected), std::memory_order_release);
				control.completion_pending.store(true, std::memory_order_release);
				return false;
			}
			{
				std::lock_guard<std::mutex> lock(control.mutex);
				if (control.current || control.active.load(std::memory_order_acquire)) return false;
				ticket->generation = control.generation.fetch_add(1, std::memory_order_acq_rel) + 1;
				control.current = ticket;
				control.active.store(true, std::memory_order_release);
			}

			const std::uint64_t generation = ticket->generation;
			const std::uint64_t deadline = bounded_deadline(kLoginStartDeadlineMs);
			ticket->deadline_ms = deadline;
			control.completion_pending.store(false, std::memory_order_release);
			control.result.store(static_cast<int>(login_start_result_t::pending),
				std::memory_order_release);
			control.deadline_ms.store(deadline, std::memory_order_release);

			auto finish = [state, ticket, &control, provider](
				login_start_result_t result,
				const char* error,
				bool worker_finished) noexcept {
				try {
					bool expected_terminal = false;
					if (ticket->terminal_published.compare_exchange_strong(expected_terminal, true,
						std::memory_order_acq_rel, std::memory_order_acquire)) {
						if (result == login_start_result_t::failed
							|| result == login_start_result_t::timed_out
							|| result == login_start_result_t::rejected) {
							publish_login_start_failure(state, error);
						}
						std::lock_guard<std::mutex> lock(control.mutex);
						if (control.current == ticket) {
							control.result.store(static_cast<int>(result), std::memory_order_release);
							control.deadline_ms.store(0, std::memory_order_release);
							control.completion_pending.store(true, std::memory_order_release);
						}
					}
					if (worker_finished || !ticket->worker_started.load(std::memory_order_acquire)) {
						std::lock_guard<std::mutex> lock(control.mutex);
						if (control.current == ticket) {
							control.current.reset();
							control.active.store(false, std::memory_order_release);
						}
					}
					diag::log_tagged_fmt("auth",
						"AUTH-LOGIN-START-PUBLISH provider=%s generation=%llu result=%s worker_finished=%d error_len=%zu",
						provider, static_cast<unsigned long long>(ticket->generation),
						login_start_result_name(result), worker_finished ? 1 : 0,
						error ? std::strlen(error) : 0);
				} catch (...) {
					if (worker_finished) {
						try {
							std::lock_guard<std::mutex> lock(control.mutex);
							if (control.current == ticket) {
								control.current.reset();
								control.active.store(false, std::memory_order_release);
							}
						} catch (...) {
						}
					}
				}
			};
			std::shared_ptr<CancelFn> cancel_operation;
			try {
				cancel_operation = std::make_shared<CancelFn>(std::move(cancel_fn));
			} catch (...) {
				finish(login_start_result_t::rejected,
					"Login cancellation state allocation failed", false);
				return false;
			}

			aida::infra::executor::submit_result_t submitted;
			try {
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "auth_provider";
			sub.label = label;
			sub.thread_class = "security_liveness";
			sub.domain = aida::infra::executor::domain_t::security_liveness;
			sub.priority = 1;
			sub.deadline_ms = deadline;
			sub.generation = generation;
			sub.ui_access_policy = "none";
			sub.failure_policy = "publish_typed_failure";
			sub.shutdown_policy = "cancel_pending";
			sub.cancel_hook = [state, cancel_operation, ticket, deadline, finish]() mutable noexcept {
				ticket->cancellation_requested.store(true, std::memory_order_release);
				if (state) state->cancelled.store(true, std::memory_order_release);
				if (state && cancel_operation) {
					try {
						const std::function<void()> guarded_cancel = [&]() { (*cancel_operation)(*state); };
						aida::infra::win_thread::run_function_seh_guarded(guarded_cancel);
					} catch (...) {
					}
				}
				const login_start_result_t result = aida::infra::executor::now_ms() >= deadline
					? login_start_result_t::timed_out
					: login_start_result_t::cancelled;
				finish(result,
					result == login_start_result_t::timed_out
						? "Login startup timed out"
						: "Login startup cancelled",
					false);
			};
			sub.body = [state, previous, start_fn = std::move(start_fn),
				cancel_operation, error_fn = std::move(error_fn),
				ticket, finish]() mutable noexcept {
				ticket->worker_started.store(true, std::memory_order_release);
				bool ok = false;
				std::string error;
				const char* fallback_error = nullptr;
				login_start_result_t result = login_start_result_t::failed;
				struct terminal_guard_t {
					decltype(finish)* callback;
					login_start_result_t* result;
					std::string* error;
					const char** fallback_error;
					~terminal_guard_t() noexcept
					{
						(*callback)(*result, *fallback_error ? *fallback_error
							: (error->empty() ? nullptr : error->c_str()), true);
					}
				} terminal{&finish, &result, &error, &fallback_error};
				try {
					const std::function<void()> guarded = [&]() {
						if (previous) (*cancel_operation)(*previous);
						if (!state) {
							error = "Login startup state is unavailable";
							return;
						}
						if (g_state.shutdown_flag.load(std::memory_order_acquire)
							|| ticket->cancellation_requested.load(std::memory_order_acquire)
							|| state->cancelled.load(std::memory_order_acquire)) {
							result = login_start_result_t::cancelled;
							error = "Login startup cancelled";
							return;
						}
						ok = start_fn(*state, ticket->deadline_ms);
						if (ticket->cancellation_requested.load(std::memory_order_acquire)) {
							state->cancelled.store(true, std::memory_order_release);
							(*cancel_operation)(*state);
							result = login_start_result_t::cancelled;
							return;
						}
						if (!ok) error = error_fn();
					};
					const DWORD seh = aida::infra::win_thread::run_function_seh_guarded(guarded);
					if (seh != 0) {
						ok = false;
						char buffer[96];
						std::snprintf(buffer, sizeof(buffer),
							"Login startup raised SEH 0x%08lX",
							static_cast<unsigned long>(seh));
						error = buffer;
						result = login_start_result_t::failed;
					}
				} catch (...) {
					ok = false;
					fallback_error = "Login startup exception";
					result = login_start_result_t::failed;
				}
				if (ticket->cancellation_requested.load(std::memory_order_acquire)
					|| (state && state->cancelled.load(std::memory_order_acquire))) {
					result = login_start_result_t::cancelled;
				} else if (ok) {
					result = login_start_result_t::succeeded;
				}
				if (!ok && state) {
					state->cancelled.store(true, std::memory_order_release);
					try {
						const std::function<void()> guarded_cancel = [&]() { (*cancel_operation)(*state); };
						aida::infra::win_thread::run_function_seh_guarded(guarded_cancel);
					} catch (...) {
					}
				}
				if (!ok && error.empty() && !fallback_error
					&& result != login_start_result_t::cancelled)
					fallback_error = "Login startup failed";
			};

			submitted = aida::infra::executor::submit(std::move(sub));
			} catch (...) {
				finish(login_start_result_t::rejected,
					"Login startup submission exception", false);
				return false;
			}
			if (!submitted.submitted) {
				finish(login_start_result_t::rejected,
					submitted.reject_reason.empty()
						? "Login startup queue rejected"
						: submitted.reject_reason.c_str(),
					false);
				return false;
			}
			ticket->task_id.store(submitted.task_id, std::memory_order_release);
			try {
				diag::log_tagged_fmt("auth",
					"AUTH-LOGIN-START-QUEUED provider=%s generation=%llu task_id=%llu deadline_ms=%llu",
					provider,
					static_cast<unsigned long long>(generation),
					static_cast<unsigned long long>(submitted.task_id),
					static_cast<unsigned long long>(deadline));
			} catch (...) {
			}
			return true;
		}

		template <typename State, typename CancelFn>
		static void submit_provider_cancel(
			const char* label,
			const char* provider,
			const std::shared_ptr<State>& state,
			CancelFn cancel_fn)
		{
			if (!state) return;
			state->cancelled.store(true, std::memory_order_release);
			std::shared_ptr<std::atomic<bool>> terminal;
			try { terminal = std::make_shared<std::atomic<bool>>(false); } catch (...) {}
			auto publish_terminal = [terminal, provider](const char* result) noexcept {
				if (!terminal) return;
				bool expected = false;
				if (!terminal->compare_exchange_strong(expected, true,
					std::memory_order_acq_rel, std::memory_order_acquire)) return;
				try { diag::log_tagged_fmt("auth", "AUTH-LOGIN-CANCEL-TERMINAL provider=%s result=%s",
					provider, result ? result : "unknown"); } catch (...) {}
			};
			auto execute_cancel = [state, cancel_fn, publish_terminal]() mutable noexcept {
				const char* result = "completed";
				struct terminal_guard_t {
					decltype(publish_terminal)* publish;
					const char** result;
					~terminal_guard_t() noexcept { (*publish)(*result); }
				} guard{&publish_terminal, &result};
				try {
					const std::function<void()> guarded = [&]() { cancel_fn(*state); };
					if (aida::infra::win_thread::run_function_seh_guarded(guarded) != 0)
						result = "seh_failure";
				} catch (...) {
					result = "exception";
				}
			};
			if (!terminal) {
				execute_cancel();
				return;
			}
			aida::infra::executor::submit_result_t submitted;
			try {
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "auth_provider";
				sub.label = label;
				sub.thread_class = "security_liveness";
				sub.domain = aida::infra::executor::domain_t::security_liveness;
				sub.priority = 0;
				sub.deadline_ms = bounded_deadline(kLoginCancelDeadlineMs);
				sub.ui_access_policy = "none";
				sub.failure_policy = "publish_typed_failure";
				sub.shutdown_policy = "cancel_pending";
				sub.cancel_hook = execute_cancel;
				sub.body = execute_cancel;
				submitted = aida::infra::executor::submit(std::move(sub));
			} catch (...) {
				execute_cancel();
				return;
			}
			if (!submitted.submitted)
				execute_cancel();
			try {
				diag::log_tagged_fmt("auth",
					"AUTH-LOGIN-CANCEL-QUEUE provider=%s submitted=%d task_id=%llu reason=%s",
					provider,
					submitted.submitted ? 1 : 0,
					static_cast<unsigned long long>(submitted.task_id),
					submitted.reject_reason.empty() ? "none" : submitted.reject_reason.c_str());
			} catch (...) {
			}
		}

		static std::string browser_open_failure_message(aida::auth::browser_open_result_t result)
		{
			switch (result) {
			case aida::auth::browser_open_result_t::queued:
				return {};
			case aida::auth::browser_open_result_t::invalid_url:
				return "The browser URL was rejected";
			case aida::auth::browser_open_result_t::queue_rejected:
				return "The Camoufox request queue is unavailable";
			case aida::auth::browser_open_result_t::cancelled:
				return "The Camoufox request was cancelled";
			case aida::auth::browser_open_result_t::deadline_expired:
				return "The Camoufox request timed out";
			case aida::auth::browser_open_result_t::ensure_ready_failed:
				return "Camoufox could not become ready";
			case aida::auth::browser_open_result_t::navigate_failed:
				return "Camoufox could not open the requested page";
			case aida::auth::browser_open_result_t::exception:
				return "Camoufox failed while opening the requested page";
			case aida::auth::browser_open_result_t::opened:
			default:
				return {};
			}
		}

		static bool open_url_in_browser(const std::string& url)
		{
			if (g_state.shutdown_flag.load(std::memory_order_acquire)) return false;
			bool expected = false;
			if (!g_state.browser_open.in_flight.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel, std::memory_order_acquire)) {
				diag::log_tagged_fmt("auth", "AUTH-BROWSER-UI-QUEUE-REJECT reason=already_in_flight");
				toast_notification::push("A Camoufox request is already in progress",
					toast_notification::toast_type_t::warning, 4.0f);
				return false;
			}
			const std::uint64_t generation =
				g_state.browser_open.generation.fetch_add(1, std::memory_order_acq_rel) + 1;
			g_state.browser_open.completion_pending.store(false, std::memory_order_release);
			g_state.browser_open.result.store(static_cast<int>(aida::auth::browser_open_result_t::queued),
				std::memory_order_release);
			aida::auth::browser_open_submission_t submitted;
			try {
				submitted = aida::auth::submit_open_url_external(url,
					[generation](const aida::auth::browser_open_completion_t& result) noexcept {
						if (g_state.browser_open.generation.load(std::memory_order_acquire)
							!= generation) return;
						g_state.browser_open.result.store(static_cast<int>(result.result),
							std::memory_order_release);
						g_state.browser_open.task_id.store(0, std::memory_order_release);
						g_state.browser_open.in_flight.store(false, std::memory_order_release);
						g_state.browser_open.completion_pending.store(true, std::memory_order_release);
					});
			} catch (...) {
				g_state.browser_open.result.store(static_cast<int>(aida::auth::browser_open_result_t::exception),
					std::memory_order_release);
				g_state.browser_open.task_id.store(0, std::memory_order_release);
				g_state.browser_open.in_flight.store(false, std::memory_order_release);
				g_state.browser_open.completion_pending.store(true, std::memory_order_release);
				return false;
			}
			if (submitted.submitted
				&& g_state.browser_open.generation.load(std::memory_order_acquire) == generation
				&& g_state.browser_open.in_flight.load(std::memory_order_acquire))
				g_state.browser_open.task_id.store(submitted.task_id, std::memory_order_release);
			return submitted.submitted;
		}

		static void poll_browser_open_completion()
		{
			if (!g_state.browser_open.completion_pending.exchange(false,
				std::memory_order_acq_rel)) return;
			const auto result = static_cast<aida::auth::browser_open_result_t>(
				g_state.browser_open.result.load(std::memory_order_acquire));
			if (result == aida::auth::browser_open_result_t::opened) return;
			const std::string message = browser_open_failure_message(result);
			if (!message.empty() && !g_state.shutdown_flag.load(std::memory_order_acquire)) {
				toast_notification::push(message,
					toast_notification::toast_type_t::error, 6.0f);
			}
		}

		template <typename State>
		static void poll_login_start_control(
			const char* provider,
			login_start_control_t& control,
			const std::shared_ptr<State>& state)
		{
			std::shared_ptr<login_start_ticket_t> ticket;
			{
				std::lock_guard<std::mutex> lock(control.mutex);
				ticket = control.current;
			}
			const std::uint64_t deadline = control.deadline_ms.load(std::memory_order_acquire);
			const std::uint64_t now = aida::infra::executor::now_ms();
			if (ticket && control.active.load(std::memory_order_acquire)
				&& deadline != 0 && now >= deadline) {
				int pending = static_cast<int>(login_start_result_t::pending);
				if (control.result.compare_exchange_strong(pending,
					static_cast<int>(login_start_result_t::timed_out),
					std::memory_order_acq_rel, std::memory_order_acquire)) {
					ticket->cancellation_requested.store(true, std::memory_order_release);
					if (state) state->cancelled.store(true, std::memory_order_release);
					publish_login_start_failure(state, "Login startup timed out");
					control.deadline_ms.store(0, std::memory_order_release);
					control.completion_pending.store(true, std::memory_order_release);
					const std::uint64_t task_id = ticket->task_id.load(std::memory_order_acquire);
					if (task_id != 0) {
						try { aida::infra::executor::cancel(task_id); } catch (...) {}
					}
				}
			}
			if (control.completion_pending.exchange(false, std::memory_order_acq_rel)) {
				const auto result = static_cast<login_start_result_t>(
					control.result.load(std::memory_order_acquire));
				diag::log_tagged_fmt("auth",
					"AUTH-LOGIN-START-POLL provider=%s result=%s active=%d worker_started=%d",
					provider,
					login_start_result_name(result),
					control.active.load(std::memory_order_acquire) ? 1 : 0,
					ticket && ticket->worker_started.load(std::memory_order_acquire) ? 1 : 0);
			}
		}

		static void poll_login_startups()
		{
			std::shared_ptr<aida::auth::codex::codex_login_state_t> codex;
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot;
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				codex = g_state.codex_state;
				copilot = g_state.copilot_state;
				claude = g_state.claude_code_state;
			}
			poll_login_start_control("openai", g_state.codex_start, codex);
			poll_login_start_control("github-copilot", g_state.copilot_start, copilot);
			poll_login_start_control("anthropic", g_state.claude_code_start, claude);
		}

		static void request_login_start_cancel(login_start_control_t& control) noexcept
		{
			std::shared_ptr<login_start_ticket_t> ticket;
			try {
				std::lock_guard<std::mutex> lock(control.mutex);
				ticket = control.current;
			} catch (...) {
				return;
			}
			if (!ticket) return;
			ticket->cancellation_requested.store(true, std::memory_order_release);
			const std::uint64_t task_id = ticket->task_id.load(std::memory_order_acquire);
			if (task_id != 0) {
				try { aida::infra::executor::cancel(task_id); } catch (...) {}
			}
		}

		static void start_codex_login()
		{
			if (g_state.codex_start.active.load(std::memory_order_acquire)) {
				toast_notification::push("The previous OpenAI login is still stopping",
					toast_notification::toast_type_t::warning, 4.0f);
				return;
			}
			std::shared_ptr<aida::auth::codex::codex_login_state_t> previous;
			std::shared_ptr<aida::auth::codex::codex_login_state_t> current;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				previous = g_state.codex_state;
				current = std::make_shared<aida::auth::codex::codex_login_state_t>();
				g_state.codex_state = current;
				g_state.codex_modal_open.store(true);
				g_state.codex_anim.reset_for_open();
				g_state.codex_exchange_result.store(static_cast<int>(exchange_result_t::pending));
			}
			submit_login_start_task(
				"auth.codex.start_login", "openai", g_state.codex_start,
				current, previous,
				[](aida::auth::codex::codex_login_state_t& state, std::uint64_t deadline_ms) {
					return aida::auth::codex::start_login(state, deadline_ms);
				},
				[](aida::auth::codex::codex_login_state_t& state) {
					return aida::auth::codex::cancel_login(state);
				},
				[]() { return aida::auth::codex::last_error(); });
		}

		static void open_copilot_modal()
		{
			if (g_state.copilot_start.active.load(std::memory_order_acquire)) {
				toast_notification::push("The previous GitHub login is still stopping",
					toast_notification::toast_type_t::warning, 4.0f);
				return;
			}
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> previous;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
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
			if (previous) {
				submit_provider_cancel("auth.copilot.cancel_previous", "github-copilot",
					previous,
					[](aida::auth::copilot::copilot_login_state_t& state) {
						return aida::auth::copilot::cancel_login(state);
					});
			}
		}

		static void start_copilot_flow(std::optional<std::string> enterprise_url)
		{
			if (g_state.copilot_start.active.load(std::memory_order_acquire)) {
				toast_notification::push("The previous GitHub login is still stopping",
					toast_notification::toast_type_t::warning, 4.0f);
				return;
			}
			g_state.copilot_flow_started.store(true);
			std::shared_ptr<aida::auth::copilot::copilot_login_state_t> current;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				current = g_state.copilot_state;
			}
			submit_login_start_task(
				"auth.copilot.start_login", "github-copilot", g_state.copilot_start,
				current, std::shared_ptr<aida::auth::copilot::copilot_login_state_t>{},
				[enterprise_url](aida::auth::copilot::copilot_login_state_t& state, std::uint64_t deadline_ms) {
					return aida::auth::copilot::start_login(state, enterprise_url, deadline_ms);
				},
				[](aida::auth::copilot::copilot_login_state_t& state) {
					return aida::auth::copilot::cancel_login(state);
				},
				[]() { return aida::auth::copilot::last_error(); });
		}

		static void start_claude_code_login()
		{
			if (g_state.claude_code_start.active.load(std::memory_order_acquire)) {
				toast_notification::push("The previous Claude Code login is still stopping",
					toast_notification::toast_type_t::warning, 4.0f);
				return;
			}
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> previous;
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> current;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				previous = g_state.claude_code_state;
				current = std::make_shared<aida::auth::claude_code::claude_code_login_state_t>();
				g_state.claude_code_state = current;
				g_state.claude_code_modal_open.store(true);
				g_state.claude_code_anim.reset_for_open();
				g_state.claude_code_exchange_result.store(static_cast<int>(exchange_result_t::pending));
			}
			submit_login_start_task(
				"auth.claude_code.start_login", "anthropic", g_state.claude_code_start,
				current, previous,
				[](aida::auth::claude_code::claude_code_login_state_t& state, std::uint64_t deadline_ms) {
					return aida::auth::claude_code::start_login(state, deadline_ms);
				},
				[](aida::auth::claude_code::claude_code_login_state_t& state) {
					return aida::auth::claude_code::cancel_login(state);
				},
				[]() { return aida::auth::claude_code::last_error(); });
		}

		static void close_codex_modal_immediate()
		{
			request_login_start_cancel(g_state.codex_start);
			std::shared_ptr<aida::auth::codex::codex_login_state_t> state_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				state_ref = g_state.codex_state;
				g_state.codex_modal_open.store(false);
				if (state_ref)
					state_ref->cancelled.store(true);
			}
			if (state_ref) {
				submit_provider_cancel("auth.codex.cancel_login", "openai", state_ref,
					[](aida::auth::codex::codex_login_state_t& state) {
						return aida::auth::codex::cancel_login(state);
					});
			}
		}

		static void close_copilot_modal_immediate()
		{
			request_login_start_cancel(g_state.copilot_start);
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
				submit_provider_cancel("auth.copilot.cancel_login", "github-copilot", state_ref,
					[](aida::auth::copilot::copilot_login_state_t& state) {
						return aida::auth::copilot::cancel_login(state);
					});
			}
		}

		static void close_claude_code_modal_immediate()
		{
			request_login_start_cancel(g_state.claude_code_start);
			std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> state_ref;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				state_ref = g_state.claude_code_state;
				g_state.claude_code_modal_open.store(false);
				if (state_ref)
					state_ref->cancelled.store(true);
			}
			if (state_ref) {
				submit_provider_cancel("auth.claude_code.cancel_login", "anthropic", state_ref,
					[](aida::auth::claude_code::claude_code_login_state_t& state) {
						return aida::auth::claude_code::cancel_login(state);
					});
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
				const auto start_result = static_cast<login_start_result_t>(
					g_state.codex_start.result.load(std::memory_order_acquire));
				const bool start_failed = start_result == login_start_result_t::failed
					|| start_result == login_start_result_t::timed_out
					|| start_result == login_start_result_t::rejected;

				if (finished && start_failed
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.codex_exchange_result.store(
						static_cast<int>(exchange_result_t::failure));
				} else if (finished
					&& !g_state.codex_exchange_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.codex_exchange_in_flight.store(true);
					auto state_ref = sp;
					aida::infra::executor::submission_t sub;
					sub.owner_subsystem = "auth_provider";
					sub.label = "auth.codex.poll_login";
					sub.thread_class = "service_task";
					sub.domain = aida::infra::executor::domain_t::security_liveness;
					sub.priority = 1;
					sub.body = [state_ref]() {
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
					};
					if (!aida::infra::executor::submit(std::move(sub)).submitted) {
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
					if (err.empty() && sp) err = aida::auth::codex::snapshot(*sp).error;
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
				const auto copilot_snapshot = aida::auth::copilot::snapshot(*sp);
				bool ready_to_poll = copilot_snapshot.next_poll_unix == 0 || now >= copilot_snapshot.next_poll_unix;
				bool finished = sp->done.load();
				bool can_poll = !finished && ready_to_poll && !copilot_snapshot.device_code.empty();
				bool start_failed = finished && copilot_snapshot.device_code.empty();
				const int prior_result = g_state.copilot_poll_result.load();

				if (start_failed && prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.copilot_poll_result.store(
						static_cast<int>(exchange_result_t::failure));
				} else if (can_poll && !g_state.copilot_poll_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.copilot_poll_in_flight.store(true);
					auto state_ref = sp;
					aida::infra::executor::submission_t sub;
					sub.owner_subsystem = "auth_provider";
					sub.label = "auth.copilot.poll_login";
					sub.thread_class = "service_task";
					sub.domain = aida::infra::executor::domain_t::security_liveness;
					sub.priority = 1;
					sub.body = [state_ref]() {
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
					};
					if (!aida::infra::executor::submit(std::move(sub)).submitted) {
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
					if (err.empty() && sp) err = aida::auth::copilot::snapshot(*sp).error;
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
				const auto start_result = static_cast<login_start_result_t>(
					g_state.claude_code_start.result.load(std::memory_order_acquire));
				const bool start_failed = start_result == login_start_result_t::failed
					|| start_result == login_start_result_t::timed_out
					|| start_result == login_start_result_t::rejected;

				if (finished && start_failed
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.claude_code_exchange_result.store(
						static_cast<int>(exchange_result_t::failure));
				} else if (finished
					&& !g_state.claude_code_exchange_in_flight.load()
					&& prior_result == static_cast<int>(exchange_result_t::pending)) {
					g_state.claude_code_exchange_in_flight.store(true);
					auto state_ref = sp;
					aida::infra::executor::submission_t sub;
					sub.owner_subsystem = "auth_provider";
					sub.label = "auth.claude_code.poll_login";
					sub.thread_class = "service_task";
					sub.domain = aida::infra::executor::domain_t::security_liveness;
					sub.priority = 1;
					sub.body = [state_ref]() {
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
					};
					if (!aida::infra::executor::submit(std::move(sub)).submitted) {
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
					if (err.empty() && sp) err = aida::auth::claude_code::snapshot(*sp).error;
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

		static bool eye_toggle_button(const char* id, bool* shown, ImVec2 size)
		{
			if (!shown) return false;
			const auto& th = aida::ui::resolved();

			ImGui::PushID(id);
			ImGuiID iid = ImGui::GetID("##eye");
			auto& hov = aida::ui::components::detail::hstate(iid);

			ImVec2 pos = ImGui::GetCursorScreenPos();
			ImGui::InvisibleButton("##eye", size);
			bool hovered = ImGui::IsItemHovered();
			bool clicked = ImGui::IsItemClicked();
			if (clicked) *shown = !*shown;
			if (hovered) ImGui::SetTooltip(*shown ? "Hide key" : "Reveal key");

			float hv = hov.tick(hovered, aida::ui::clock::dt(), aida::motion::spring::balanced);

			ImDrawList* dl = ImGui::GetWindowDrawList();
			ImVec2 a = pos;
			ImVec2 b = ImVec2(pos.x + size.x, pos.y + size.y);
			dl->AddRectFilled(a, b, th.panel_header, 6.f);
			ImU32 border = aida::ui::mix(th.border_subtle, th.border_focus, hv);
			dl->AddRect(a, b, border, 6.f, 0, 1.f + hv * 0.6f);

			ImVec2 c = ImVec2((a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f);
			float ew = size.x * 0.34f;
			float eh = size.y * 0.20f;
			ImU32 glyph = *shown
				? th.accent_u32
				: aida::ui::mix(th.text_secondary, th.text_primary, hv);

			float arc_r = (ew * ew + eh * eh) / (2.f * eh);
			float sin_arg = ew / arc_r;
			if (sin_arg > 1.f) sin_arg = 1.f;
			float span = asinf(sin_arg);
			float thick = size.y * 0.055f;
			if (thick < 1.4f) thick = 1.4f;

			ImVec2 top_center = ImVec2(c.x, c.y + (arc_r - eh));
			dl->PathArcTo(top_center, arc_r, -1.5707963f - span, -1.5707963f + span, 20);
			dl->PathStroke(glyph, 0, thick);

			ImVec2 bot_center = ImVec2(c.x, c.y - (arc_r - eh));
			dl->PathArcTo(bot_center, arc_r, 1.5707963f - span, 1.5707963f + span, 20);
			dl->PathStroke(glyph, 0, thick);

			float iris_r = eh * 0.78f;
			if (*shown) {
				dl->AddCircleFilled(c, iris_r, glyph, 16);
			} else {
				dl->AddCircle(c, iris_r, glyph, 16, thick);
			}

			if (!*shown) {
				float sx = ew + 2.f;
				float sy = ew + 2.f;
				dl->AddLine(ImVec2(c.x - sx * 0.7f, c.y - sy * 0.55f),
					ImVec2(c.x + sx * 0.7f, c.y + sy * 0.55f), glyph, thick + 0.4f);
			}

			ImGui::PopID();
			return clicked;
		}


		struct provider_status_t {
			std::string label;
			aida::ui::pill_kind_t kind = aida::ui::pill_kind_t::neutral;
			bool dot_pulse = false;
			bool authenticated = false;
			bool expired = false;
			std::string detail;
		};

		static provider_status_t compute_provider_status(const std::string& provider_id)
		{
			provider_status_t s;
			aida::auth::auth_info_t info;
			const bool present = aida::auth::store::get(provider_id, info);
			if (!present || info.kind == aida::auth::auth_kind_t::none) {
				s.label = "Not connected";
				s.kind = aida::ui::pill_kind_t::neutral;
				return s;
			}
			const int64_t now = now_unix();
			if (info.kind == aida::auth::auth_kind_t::oauth) {
				if (info.expires_unix > 0 && info.expires_unix <= now) {
					s.label = "Token expired";
					s.kind = aida::ui::pill_kind_t::warning;
					s.dot_pulse = true;
					s.expired = true;
					s.detail = info.email.empty() ? info.account_id : info.email;
					return s;
				}
				s.label = info.expires_unix > 0 ? format_relative_time(info.expires_unix) : std::string("OAuth");
				s.kind = aida::ui::pill_kind_t::success;
				s.dot_pulse = true;
				s.authenticated = true;
				s.detail = info.email.empty() ? info.account_id : info.email;
				if (s.detail.empty()) s.detail = "Signed in";
				return s;
			}
			if (info.kind == aida::auth::auth_kind_t::api && !info.api_key.empty()) {
				s.label = "API key set";
				s.kind = aida::ui::pill_kind_t::success;
				s.dot_pulse = false;
				s.authenticated = true;
				s.detail = mask_key(info.api_key);
				return s;
			}
			if (info.kind == aida::auth::auth_kind_t::wellknown) {
				s.label = "Well-known";
				s.kind = aida::ui::pill_kind_t::info;
				s.authenticated = true;
				s.detail = "Configured";
				return s;
			}
			s.label = "Connected";
			s.kind = aida::ui::pill_kind_t::success;
			s.authenticated = true;
			return s;
		}

		static std::string format_cost_pair(double in_per_m, double out_per_m)
		{
			char buf[96];
			if (in_per_m <= 0.0 && out_per_m <= 0.0) {
				std::snprintf(buf, sizeof(buf), "free");
			} else {
				std::snprintf(buf, sizeof(buf), "$%.2f / $%.2f per M", in_per_m, out_per_m);
			}
			return std::string(buf);
		}

		static std::string format_context_pretty(int64_t context)
		{
			if (context <= 0) return std::string("ctx ?");
			char buf[32];
			if (context >= 1000)
				std::snprintf(buf, sizeof(buf), "ctx %lldK", static_cast<long long>(context / 1000));
			else
				std::snprintf(buf, sizeof(buf), "ctx %lld", static_cast<long long>(context));
			return std::string(buf);
		}

		static std::vector<const aida::provider::model_info_t*> sorted_models_for(const std::string& provider_id)
		{
			std::vector<const aida::provider::model_info_t*> out;
			const auto* prov = aida::provider::catalog::get_provider(provider_id);
			if (!prov) return out;
			out.reserve(prov->model_ids.size());
			for (const auto& mid : prov->model_ids) {
				const auto* m = aida::provider::catalog::get_model(provider_id, mid);
				if (m && m->status != aida::provider::model_info_t::status_t::deprecated)
					out.push_back(m);
			}
			std::sort(out.begin(), out.end(),
				[](const aida::provider::model_info_t* a, const aida::provider::model_info_t* b) {
					const double ca = a->cost.input_per_million + a->cost.output_per_million;
					const double cb = b->cost.input_per_million + b->cost.output_per_million;
					if (ca != cb) return ca < cb;
					return a->id < b->id;
				});
			return out;
		}

		static std::string preferred_model_id(const std::string& provider_id)
		{
			auto& prefs = g_sa_settings.preferred_model_per_provider;
			auto it = prefs.find(provider_id);
			if (it != prefs.end() && !it->second.empty()) {
				if (aida::provider::catalog::get_model(provider_id, it->second) != nullptr)
					return it->second;
			}
			const auto* def = aida::provider::catalog::default_model(provider_id);
			if (def) return def->id;
			const auto* p = aida::provider::catalog::get_provider(provider_id);
			if (p && !p->model_ids.empty()) return p->model_ids.front();
			return std::string();
		}

		static void start_refresh_catalog()
		{
			if (g_state.shutdown_flag.load()) return;
			bool expected = false;
			if (!g_state.refresh.in_flight.compare_exchange_strong(expected, true)) return;
			g_state.refresh.completed.store(false);
			g_state.refresh.success.store(false);
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				g_state.refresh.message.clear();
			}
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "auth_provider";
			sub.label = "auth.catalog.refresh";
			sub.thread_class = "service_task";
			sub.domain = aida::infra::executor::domain_t::service;
			sub.priority = 2;
			sub.body = []() {
				if (g_state.shutdown_flag.load()) {
					g_state.refresh.in_flight.store(false);
					g_state.refresh.completed.store(false);
					return;
				}
				const bool ok = aida::provider::catalog::fetch_and_cache(10000);
				if (g_state.shutdown_flag.load()) {
					g_state.refresh.in_flight.store(false);
					g_state.refresh.completed.store(false);
					return;
				}
				{
					std::lock_guard<std::mutex> lk(g_state.mtx);
					g_state.refresh.success.store(ok);
					g_state.refresh.message = ok ? std::string("Catalog updated")
						: aida::provider::catalog::last_error();
				}
				g_state.refresh.completed.store(true);
				g_state.refresh.in_flight.store(false);
			};
			const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
			if (!posted) {
				g_state.refresh.in_flight.store(false);
				g_state.refresh.completed.store(false);
			}
		}



		static void clear_credentials_for(const std::string& provider_id)
		{
			aida::auth::auth_info_t info;
			if (!aida::auth::store::get(provider_id, info)) return;
			const bool revoke_oauth = (info.kind == aida::auth::auth_kind_t::oauth)
				&& (!info.access.empty() || !info.refresh.empty());
			std::string access = info.access;
			std::string refresh = info.refresh;
			info = aida::auth::auth_info_t{};
			if (!aida::auth::store::set(provider_id, info)) {
				toast_notification::push("Failed to sign out",
					toast_notification::toast_type_t::error, 5.0f);
				return;
			}
			schedule_auth_snapshot_refresh(true);
			if (revoke_oauth) {
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "auth_provider";
				sub.label = "auth.credentials.revoke";
				sub.thread_class = "service_task";
				sub.domain = aida::infra::executor::domain_t::security_liveness;
				sub.priority = 1;
				sub.body = [provider_id, access, refresh]() {
					if (provider_id == "anthropic")
						aida::auth::claude_code::revoke_tokens(access, refresh, std::string());
					else if (provider_id == "openai")
						aida::auth::codex::revoke_tokens(access, refresh, std::string());
					else if (provider_id == "github-copilot")
						aida::auth::copilot::revoke_tokens(access, refresh, std::string());
				};
				aida::infra::executor::submit(std::move(sub));
			}
			toast_notification::push(provider_id + " signed out",
				toast_notification::toast_type_t::info, 3.5f);
		}

		struct chatbox_provider_entry_t;
		static const chatbox_provider_entry_t* chatbox_entry_for(const std::string& id);
		static int chatbox_dropdown_index_for(const std::string& provider_id);
		static void chatbox_load_persisted_key(const std::string& provider_id);

		static void apply_pending_focus()
		{
			std::string requested;
			{
				std::lock_guard<std::mutex> lk(g_state.pending_focus_mtx);
				requested.swap(g_state.pending_focus_provider);
			}
			if (requested.empty()) {
				std::string overlay_req = aida::settings_overlay::consume_pending_provider_focus();
				if (overlay_req.empty()) return;
				requested = std::move(overlay_req);
			}
			g_state.selected_provider_id = requested;
			if (chatbox_entry_for(requested) != nullptr) {
				g_state.chatbox_active_section = 0;
				g_state.chatbox_provider_dropdown_index = chatbox_dropdown_index_for(requested);
				chatbox_load_persisted_key(requested);
			} else {
				g_state.chatbox_active_section = 1;
			}
		}

		struct chatbox_provider_entry_t {
			std::string id;
			std::string display_name;
			std::string console_url;
			std::string fallback_base;
			std::string models_path;
			std::string key_header_name;
			std::string key_header_prefix;
			std::string key_query_param;
		};

		static const std::vector<chatbox_provider_entry_t>& chatbox_provider_catalog()
		{
			static const std::vector<chatbox_provider_entry_t> entries = {
				{ "anthropic",  "Anthropic",       "https://console.anthropic.com/settings/keys",
				  "https://api.anthropic.com",          "/v1/models",
				  "x-api-key",        "",            ""    },
				{ "openai",     "OpenAI",          "https://platform.openai.com/api-keys",
				  "https://api.openai.com",             "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "openrouter", "OpenRouter",      "https://openrouter.ai/settings/keys",
				  "https://openrouter.ai/api",          "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "google",     "Google Gemini",   "https://aistudio.google.com/app/apikey",
				  "https://generativelanguage.googleapis.com", "/v1beta/models",
				  "",                 "",            "key" },
				{ "mistral",    "Mistral",         "https://console.mistral.ai/api-keys/",
				  "https://api.mistral.ai",             "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "groq",       "Groq",            "https://console.groq.com/keys",
				  "https://api.groq.com",               "/openai/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "deepseek",   "DeepSeek",        "https://platform.deepseek.com/api_keys",
				  "https://api.deepseek.com",           "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "xai",        "xAI Grok",        "https://console.x.ai/",
				  "https://api.x.ai",                   "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
				{ "cerebras",   "Cerebras",        "https://cloud.cerebras.ai/?tab=api-keys",
				  "https://api.cerebras.ai",            "/v1/models",
				  "Authorization",    "Bearer ",     ""    },
			};
			return entries;
		}

		static int count_models_in_response(const std::string& provider_id, const std::string& body)
		{
			if (body.empty()) return 0;
			try {
				auto json = nlohmann::json::parse(body);
				if (provider_id == "anthropic" && json.is_object() && json.contains("data") && json["data"].is_array())
					return static_cast<int>(json["data"].size());
				if ((provider_id == "openai" || provider_id == "openrouter" || provider_id == "mistral"
					|| provider_id == "groq" || provider_id == "deepseek" || provider_id == "xai"
					|| provider_id == "cerebras")
					&& json.is_object() && json.contains("data") && json["data"].is_array())
					return static_cast<int>(json["data"].size());
				if (provider_id == "google" && json.is_object() && json.contains("models") && json["models"].is_array())
					return static_cast<int>(json["models"].size());
				if (json.is_object() && json.contains("data") && json["data"].is_array())
					return static_cast<int>(json["data"].size());
				if (json.is_array())
					return static_cast<int>(json.size());
			} catch (...) {
			}
			return 0;
		}

		static std::string extract_error_from_body(const std::string& body)
		{
			if (body.empty()) return std::string();
			try {
				auto json = nlohmann::json::parse(body);
				if (json.is_object()) {
					if (json.contains("error")) {
						const auto& e = json["error"];
						if (e.is_string()) return e.get<std::string>();
						if (e.is_object()) {
							if (e.contains("message") && e["message"].is_string())
								return e["message"].get<std::string>();
							if (e.contains("code") && e["code"].is_string())
								return e["code"].get<std::string>();
						}
					}
					if (json.contains("message") && json["message"].is_string())
						return json["message"].get<std::string>();
				}
			} catch (...) {
			}
			std::string snippet = body.substr(0, 200);
			for (char& c : snippet) if (c == '\n' || c == '\r') c = ' ';
			return snippet;
		}

		static const chatbox_provider_entry_t* chatbox_entry_for(const std::string& id)
		{
			const auto& cat = chatbox_provider_catalog();
			for (const auto& e : cat) if (e.id == id) return &e;
			return nullptr;
		}

		static void run_chatbox_validate(const std::string& provider_id, const std::string& key)
		{
			if (g_state.shutdown_flag.load()) return;
			const chatbox_provider_entry_t* entry = chatbox_entry_for(provider_id);
			if (entry == nullptr || key.empty()) return;

			std::shared_ptr<std::atomic<bool>> flag;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				auto it = g_state.validate_in_flight.find(provider_id);
				if (it != g_state.validate_in_flight.end() && it->second && it->second->load()) return;
				flag = std::make_shared<std::atomic<bool>>(true);
				g_state.validate_in_flight[provider_id] = flag;
				test_result_t pending;
				pending.completed = false;
				g_state.validate_results[provider_id] = pending;
			}

			const std::string captured_id = provider_id;
			const std::string captured_key = key;
			chatbox_provider_entry_t entry_copy = *entry;

			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "auth_provider";
			sub.label = "auth.provider_key.validate";
			sub.thread_class = "service_task";
			sub.domain = aida::infra::executor::domain_t::security_liveness;
			sub.priority = 1;
			sub.body = [captured_id, captured_key, entry_copy, flag]() {
				if (g_state.shutdown_flag.load()) {
					std::lock_guard<std::mutex> lk(g_state.mtx);
					if (flag) flag->store(false);
					g_state.validate_in_flight.erase(captured_id);
					return;
				}

				std::string base_url;
				aida::auth::auth_info_t tmp_info;
				tmp_info.api_key = captured_key;
				std::string resolved = aida::provider::transforms::resolve_endpoint(
					captured_id, preferred_model_id(captured_id), tmp_info);
				if (!resolved.empty() && resolved.rfind("http", 0) == 0)
					base_url = resolved;
				if (base_url.empty()) {
					const auto* prov = aida::provider::catalog::get_provider(captured_id);
					if (prov && !prov->base_url.empty()) base_url = prov->base_url;
				}
				if (base_url.empty()) base_url = entry_copy.fallback_base;
				while (!base_url.empty() && base_url.back() == '/') base_url.pop_back();

				std::string url = base_url + entry_copy.models_path;
				if (!entry_copy.key_query_param.empty()) {
					url += (url.find('?') == std::string::npos ? '?' : '&');
					url += entry_copy.key_query_param;
					url += '=';
					url += captured_key;
				}

				aida::auth::http::header_list_t headers;
				headers.emplace_back("User-Agent", "AiDAStandalone/1.0");
				headers.emplace_back("Accept", "application/json");
				if (captured_id == "anthropic")
					headers.emplace_back("anthropic-version", "2023-06-01");
				if (captured_id == "openrouter") {
					headers.emplace_back("HTTP-Referer", "https://aida.dev/");
					headers.emplace_back("X-Title", "AiDA");
				}
				if (!entry_copy.key_header_name.empty()) {
					headers.emplace_back(entry_copy.key_header_name,
						entry_copy.key_header_prefix + captured_key);
				}

				const auto t0 = std::chrono::steady_clock::now();
				aida::auth::http::response_t resp = aida::auth::http::get(url, headers, 14);
				const auto t1 = std::chrono::steady_clock::now();

				test_result_t result;
				result.completed = true;
				result.latency_ms = static_cast<int>(
					std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

				if (g_state.shutdown_flag.load()) {
					std::lock_guard<std::mutex> lk(g_state.mtx);
					if (flag) flag->store(false);
					g_state.validate_in_flight.erase(captured_id);
					g_state.validate_results.erase(captured_id);
					return;
				}

				if (!resp.ok && resp.status == 0) {
					result.success = false;
					result.message = resp.error.empty()
						? std::string("Transport error")
						: resp.error;
				} else {
					result.http_status = resp.status;
					if (resp.status >= 200 && resp.status < 300) {
						int n = count_models_in_response(captured_id, resp.body);
						result.success = true;
						char buf[96];
						if (n > 0) {
							std::snprintf(buf, sizeof(buf), "Connected - %d model%s available",
								n, n == 1 ? "" : "s");
						} else {
							std::snprintf(buf, sizeof(buf), "Connected (HTTP %d)", resp.status);
						}
						result.message = buf;
					} else if (resp.status == 401 || resp.status == 403) {
						result.success = false;
						std::string detail = extract_error_from_body(resp.body);
						char buf[256];
						std::snprintf(buf, sizeof(buf), "HTTP %d - %s", resp.status,
							detail.empty() ? "invalid api key" : detail.c_str());
						result.message = buf;
					} else {
						result.success = false;
						std::string detail = extract_error_from_body(resp.body);
						char buf[320];
						std::snprintf(buf, sizeof(buf), "HTTP %d - %s", resp.status,
							detail.empty() ? "request failed" : detail.c_str());
						result.message = buf;
					}
				}

				if (result.success) {
					aida::auth::auth_info_t info;
					aida::auth::store::get(captured_id, info);
					info.kind = aida::auth::auth_kind_t::api;
					info.api_key = captured_key;
					info.access.clear();
					info.refresh.clear();
					info.expires_unix = 0;
					info.email.clear();
					info.account_id.clear();
					if (!aida::auth::store::set(captured_id, info)) {
						result.success = false;
						result.message = std::string("Connected, but failed to persist key: ")
							+ aida::auth::store::last_error();
					} else {
						schedule_auth_snapshot_refresh(true);
						const std::string mid = preferred_model_id(captured_id);
						if (!mid.empty()) {
							g_sa_settings.set_selection(captured_id, mid);
							auto* prof = g_sa_settings.get_active_profile();
							if (prof != nullptr) {
								prof->model = mid;
								g_sa_settings.sync_legacy_fields_from_active_profile();
							}
							g_sa_settings.save();
							aida::events::model_changed_t evt;
							evt.session_id.clear();
							evt.provider_id = captured_id;
							evt.model_id = mid;
							aida::events::publish(aida::events::event_model_changed, evt);
						}
					}
				}

				std::lock_guard<std::mutex> lk(g_state.mtx);
				g_state.validate_results[captured_id] = result;
				if (flag) flag->store(false);

				if (result.success) {
					toast_notification::push(captured_id + " connected",
						toast_notification::toast_type_t::info, 3.5f);
				}
			};
			const bool posted = aida::infra::executor::submit(std::move(sub)).submitted;

			if (!posted) {
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (flag) flag->store(false);
				g_state.validate_in_flight.erase(provider_id);
				g_state.validate_results.erase(provider_id);
			}
		}

		static int chatbox_dropdown_index_for(const std::string& provider_id)
		{
			const auto& cat = chatbox_provider_catalog();
			for (size_t i = 0; i < cat.size(); ++i)
				if (cat[i].id == provider_id) return static_cast<int>(i);
			return 0;
		}

		static void chatbox_load_persisted_key(const std::string& provider_id)
		{
			aida::auth::auth_info_t info;
			if (aida::auth::store::get(provider_id, info)
				&& info.kind == aida::auth::auth_kind_t::api
				&& !info.api_key.empty()) {
				std::snprintf(g_state.chatbox_key_buf, sizeof(g_state.chatbox_key_buf),
					"%s", info.api_key.c_str());
			} else {
				g_state.chatbox_key_buf[0] = '\0';
			}
			g_state.chatbox_key_show = false;
		}

		struct oauth_entry_t {
			const char* provider_id;
			const char* display_name;
			const char* description;
			brand_glyph::kind_t glyph;
			ImU32 grad_top;
			ImU32 grad_bot;
			ImU32 ring;
		};

		static const std::vector<oauth_entry_t>& oauth_catalog()
		{
			static const std::vector<oauth_entry_t> entries = {
				{ "anthropic",      "Claude Code",     "Anthropic OAuth (PKCE) - claude.com",
				  brand_glyph::kind_t::anthropic,
				  IM_COL32(228, 168, 132, 255), IM_COL32(196, 124, 84, 255), IM_COL32(255, 200, 168, 220) },
				{ "openai",         "OpenAI Codex",    "ChatGPT OAuth (PKCE) - chatgpt.com",
				  brand_glyph::kind_t::openai,
				  IM_COL32(106, 220, 178, 255), IM_COL32(40, 168, 138, 255), IM_COL32(160, 240, 210, 220) },
				{ "github-copilot", "GitHub Copilot",  "GitHub Device Code - github.com/login/device",
				  brand_glyph::kind_t::github,
				  IM_COL32(60, 64, 92, 255),    IM_COL32(28, 32, 52, 255),   IM_COL32(150, 158, 198, 220) },
			};
			return entries;
		}

		static void render_chatbox_api_section(float origin_x, float origin_y, float section_w, float section_h)
		{
			const auto& th = aida::ui::resolved();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			const float pad = 18.f;
			const auto& cat = chatbox_provider_catalog();
			if (cat.empty()) return;

			if (g_state.chatbox_provider_dropdown_index < 0
				|| g_state.chatbox_provider_dropdown_index >= static_cast<int>(cat.size())) {
				g_state.chatbox_provider_dropdown_index = 0;
			}
			static std::string s_last_loaded_for_provider;
			const std::string current_provider_id =
				cat[g_state.chatbox_provider_dropdown_index].id;
			if (s_last_loaded_for_provider != current_provider_id) {
				s_last_loaded_for_provider = current_provider_id;
				chatbox_load_persisted_key(current_provider_id);
			}

			float cy = origin_y + pad;

			dl->AddText(aida::ui::fonts::body_em(),
				aida::ui::components::detail::ui_fs() * 0.95f,
				ImVec2(origin_x + pad, cy),
				th.text_secondary, "Provider");
			cy += 22.f;

			ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
			ImGui::SetNextItemWidth(section_w - pad * 2.f);
			std::vector<const char*> names_storage;
			names_storage.reserve(cat.size());
			for (const auto& e : cat) names_storage.push_back(e.display_name.c_str());
			int prev_dd = g_state.chatbox_provider_dropdown_index;
			if (ImGui::Combo("##chatbox_provider_dd",
					&g_state.chatbox_provider_dropdown_index,
					names_storage.data(),
					static_cast<int>(names_storage.size()))) {
				if (prev_dd != g_state.chatbox_provider_dropdown_index) {
					chatbox_load_persisted_key(
						cat[g_state.chatbox_provider_dropdown_index].id);
					s_last_loaded_for_provider =
						cat[g_state.chatbox_provider_dropdown_index].id;
				}
			}
			cy += 40.f;

			const chatbox_provider_entry_t& selected = cat[g_state.chatbox_provider_dropdown_index];
			const provider_status_t status = compute_provider_status(selected.id);

			ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
			aida::ui::pill_kind(status.label.c_str(), status.kind,
				aida::ui::size_t_::sm, status.dot_pulse);
			if (!status.detail.empty()) {
				ImGui::SameLine(0.f, 10.f);
				ImGui::PushStyleColor(ImGuiCol_Text,
					ImGui::ColorConvertU32ToFloat4(th.text_dim));
				ImGui::TextUnformatted(status.detail.c_str());
				ImGui::PopStyleColor();
			}
			cy += 32.f;

			dl->AddText(aida::ui::fonts::body_em(),
				aida::ui::components::detail::ui_fs() * 0.95f,
				ImVec2(origin_x + pad, cy),
				th.text_secondary, "API key");
			cy += 22.f;

			const float eye_w = 36.f;
			const float input_h = 36.f;
			const float input_w = section_w - pad * 2.f - eye_w - 8.f;
			ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
			ImGui::PushStyleColor(ImGuiCol_FrameBg,
				ImGui::ColorConvertU32ToFloat4(th.panel_header));
			ImGui::SetNextItemWidth(input_w);
			ImGuiInputTextFlags ifl = ImGuiInputTextFlags_None;
			if (!g_state.chatbox_key_show) ifl |= ImGuiInputTextFlags_Password;
			ImGui::InputTextWithHint("##chatbox_api_key", "Paste API key",
				g_state.chatbox_key_buf, sizeof(g_state.chatbox_key_buf), ifl);
			ImGui::PopStyleColor();
			ImGui::SameLine(0.f, 8.f);
			eye_toggle_button("##chatbox_api_key_eye", &g_state.chatbox_key_show,
				ImVec2(eye_w, input_h));
			cy += input_h + 12.f;

			test_result_t cur_res;
			bool have_res = false;
			bool busy = false;
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				auto it = g_state.validate_in_flight.find(selected.id);
				if (it != g_state.validate_in_flight.end() && it->second)
					busy = it->second->load();
				auto rit = g_state.validate_results.find(selected.id);
				if (rit != g_state.validate_results.end()) {
					cur_res = rit->second;
					have_res = cur_res.completed;
				}
			}

			ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
			const char* save_label = busy ? "Verifying..." : "Save & verify";
			if (aida::ui::button(save_label,
					aida::ui::button_kind_t::accent_gradient,
					aida::ui::size_t_::md,
					ImVec2(180.f, 36.f),
					busy, nullptr, busy)) {
				if (!busy) {
					std::string k = g_state.chatbox_key_buf;
					if (k.empty()) {
						toast_notification::push("Enter an API key first",
							toast_notification::toast_type_t::warning, 3.0f);
					} else {
						run_chatbox_validate(selected.id, k);
					}
				}
			}
			ImGui::SameLine(0.f, 10.f);
			if (status.authenticated) {
				if (aida::ui::button("Clear",
						aida::ui::button_kind_t::destructive,
						aida::ui::size_t_::md,
						ImVec2(100.f, 36.f))) {
					clear_credentials_for(selected.id);
					SecureZeroMemory(g_state.chatbox_key_buf, sizeof(g_state.chatbox_key_buf));
					g_state.chatbox_key_show = false;
					std::lock_guard<std::mutex> lk(g_state.mtx);
					g_state.validate_results.erase(selected.id);
				}
				ImGui::SameLine(0.f, 10.f);
			}
			if (!selected.console_url.empty()) {
				if (aida::ui::button("Get key",
						aida::ui::button_kind_t::secondary,
						aida::ui::size_t_::md,
						ImVec2(120.f, 36.f))) {
					open_url_in_browser(selected.console_url);
				}
			}
			cy += 48.f;

			if (busy) {
				ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
				ImGui::PushStyleColor(ImGuiCol_Text,
					ImGui::ColorConvertU32ToFloat4(th.text_secondary));
				ImGui::TextUnformatted("Calling /models endpoint to verify the key...");
				ImGui::PopStyleColor();
				cy += 24.f;
			} else if (have_res) {
				const ImU32 line_col = cur_res.success ? th.success : th.error;
				ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
				ImGui::PushStyleColor(ImGuiCol_Text,
					ImGui::ColorConvertU32ToFloat4(line_col));
				char buf[400];
				if (cur_res.success) {
					std::snprintf(buf, sizeof(buf), "%s  (%dms)",
						cur_res.message.c_str(), cur_res.latency_ms);
				} else {
					std::snprintf(buf, sizeof(buf), "Failed: %s",
						cur_res.message.c_str());
				}
				ImGui::PushTextWrapPos(origin_x + section_w - pad);
				ImGui::TextWrapped("%s", buf);
				ImGui::PopTextWrapPos();
				ImGui::PopStyleColor();
				cy += 56.f;
			}

			if (status.authenticated) {
				ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
				ImGui::PushStyleColor(ImGuiCol_Text,
					ImGui::ColorConvertU32ToFloat4(th.text_secondary));
				ImGui::TextUnformatted("Default model for chat");
				ImGui::PopStyleColor();
				cy += 22.f;

				ImGui::SetCursorScreenPos(ImVec2(origin_x + pad, cy));
				ImGui::SetNextItemWidth(section_w - pad * 2.f);
				const std::string current_mid = preferred_model_id(selected.id);
				const auto* current_m = current_mid.empty()
					? nullptr : aida::provider::catalog::get_model(selected.id, current_mid);
				const std::string preview = current_m ? current_m->name : std::string("(no model)");
				if (ImGui::BeginCombo("##chatbox_default_model", preview.c_str())) {
					const auto models = sorted_models_for(selected.id);
					for (const auto* m : models) {
						const bool is_sel = (current_mid == m->id);
						char label[200];
						std::snprintf(label, sizeof(label), "%s   %s   %s##chatbox_default_model_%s",
							m->name.c_str(),
							format_cost_pair(m->cost.input_per_million, m->cost.output_per_million).c_str(),
							format_context_pretty(m->limit.context).c_str(),
							m->id.c_str());
						ImGui::PushID(m->id.c_str());
						if (ImGui::Selectable(label, is_sel)) {
							g_sa_settings.preferred_model_per_provider[selected.id] = m->id;
							g_sa_settings.set_selection(selected.id, m->id);
							auto* prof = g_sa_settings.get_active_profile();
							if (prof != nullptr) {
								prof->model = m->id;
								g_sa_settings.sync_legacy_fields_from_active_profile();
							}
							g_sa_settings.save();
							aida::events::model_changed_t evt;
							evt.session_id.clear();
							evt.provider_id = selected.id;
							evt.model_id = m->id;
							aida::events::publish(aida::events::event_model_changed, evt);
						}
						if (is_sel) ImGui::SetItemDefaultFocus();
						ImGui::PopID();
					}
					ImGui::EndCombo();
				}
				cy += 44.f;
			}

			(void)section_h;
		}

		static void render_chatbox_oauth_section(float origin_x, float origin_y, float section_w, float section_h)
		{
			const auto& th = aida::ui::resolved();
			ImDrawList* dl = ImGui::GetWindowDrawList();
			const float pad = 18.f;
			const auto& entries = oauth_catalog();

			float cy = origin_y + pad;

			dl->AddText(aida::ui::fonts::body_em(),
				aida::ui::components::detail::ui_fs() * 0.95f,
				ImVec2(origin_x + pad, cy),
				th.text_secondary,
				"Sign in with your browser - PKCE tokens stored in DPAPI-protected auth.json.");
			cy += 28.f;

			const float row_h = 84.f;
			const float row_gap = 12.f;
			const float row_w = section_w - pad * 2.f;

			const float glyph_r = 22.f;
			const float text_x_rel = 18.f + glyph_r * 2.f + 16.f;
			const float name_fs = aida::ui::components::detail::ui_fs() * 1.08f;
			const float desc_fs = aida::ui::components::detail::ui_fs() * 0.88f;
			const float btn_w_full = 156.f;
			const float btn_h = 32.f;
			const float btn_min_gap = 12.f;
			const float right_inset = 14.f;

			const float w_if_inline = row_w - text_x_rel - right_inset - (btn_w_full + btn_min_gap);
			const bool wrap_btn = (w_if_inline < 150.f);
			const float card_text_w = wrap_btn
				? (row_w - text_x_rel - right_inset)
				: w_if_inline;
			const float this_row_h = wrap_btn ? (row_h + btn_h + 14.f) : row_h;

			for (size_t i = 0; i < entries.size(); ++i) {
				const auto& e = entries[i];
				ImVec2 a(origin_x + pad, cy);
				ImVec2 b(a.x + row_w, a.y + this_row_h);

				ImGui::SetCursorScreenPos(a);
				ImGui::BeginGroup();

				dl->AddRectFilled(a, b,
					aida::ui::with_alpha(th.bg_elevated, 0.85f), 12.f);
				dl->AddRect(a, b,
					aida::ui::with_alpha(th.border_subtle, 0.85f), 12.f, 0, 1.f);

				ImVec2 gc(a.x + 18.f + glyph_r, a.y + 14.f + glyph_r);
				brand_glyph::render(dl, e.glyph, gc, glyph_r,
					e.grad_top, e.grad_bot, e.ring, 1.f);

				float text_x = a.x + text_x_rel;
				dl->AddText(aida::ui::fonts::body_strong(),
					name_fs,
					ImVec2(text_x, a.y + 14.f),
					th.text_primary, e.display_name);

				std::string desc_str = aida::ui::responsive::truncate_to_width(
					std::string(e.description), aida::ui::fonts::caption(), desc_fs, card_text_w);
				dl->AddText(aida::ui::fonts::caption(),
					desc_fs,
					ImVec2(text_x, a.y + 38.f),
					th.text_secondary, desc_str.c_str());

				const provider_status_t st = compute_provider_status(e.provider_id);
				ImGui::SetCursorScreenPos(ImVec2(text_x, a.y + 58.f));
				aida::ui::pill_kind(st.label.c_str(), st.kind,
					aida::ui::size_t_::sm, st.dot_pulse);

				const bool authed = st.authenticated && !st.expired;
				bool busy = false;
				if (e.glyph == brand_glyph::kind_t::anthropic)
					busy = g_state.claude_code_modal_open.load()
						|| g_state.claude_code_start.active.load(std::memory_order_acquire);
				else if (e.glyph == brand_glyph::kind_t::openai)
					busy = g_state.codex_modal_open.load()
						|| g_state.codex_start.active.load(std::memory_order_acquire);
				else if (e.glyph == brand_glyph::kind_t::github)
					busy = g_state.copilot_modal_open.load()
						|| g_state.copilot_start.active.load(std::memory_order_acquire);

				float btn_w = btn_w_full;
				ImVec2 btn_pos;
				const char* signin_lbl;
				if (wrap_btn) {
					btn_w = (card_text_w < btn_w_full)
						? std::max(110.f, card_text_w * 0.5f) : btn_w_full;
					btn_pos = ImVec2(text_x, a.y + row_h);
					signin_lbl = busy ? "Signing in..." : "Sign in";
				} else {
					btn_pos = ImVec2(b.x - btn_w - right_inset, a.y + (row_h - btn_h) * 0.5f);
					signin_lbl = busy ? "Signing in..." : "Sign in with browser";
				}
				ImGui::SetCursorScreenPos(btn_pos);
				ImGui::PushID(static_cast<int>(i));
				if (authed) {
					if (aida::ui::button("Sign out",
							aida::ui::button_kind_t::destructive,
							aida::ui::size_t_::md,
							ImVec2(btn_w, btn_h))) {
						clear_credentials_for(e.provider_id);
					}
				} else {
					if (aida::ui::button(signin_lbl,
							aida::ui::button_kind_t::primary,
							aida::ui::size_t_::md,
							ImVec2(btn_w, btn_h), busy, nullptr, busy)
						&& !busy) {
						if (e.glyph == brand_glyph::kind_t::anthropic)
							start_claude_code_login();
						else if (e.glyph == brand_glyph::kind_t::openai)
							start_codex_login();
						else if (e.glyph == brand_glyph::kind_t::github)
							open_copilot_modal();
					}
				}
				ImGui::PopID();

				ImGui::SetCursorScreenPos(ImVec2(a.x, b.y));
				ImGui::Dummy(ImVec2(row_w, 0.f));
				ImGui::EndGroup();

				cy += this_row_h + row_gap;
			}

			float consumed = cy - origin_y;
			ImGui::SetCursorScreenPos(ImVec2(origin_x, origin_y));
			ImGui::Dummy(ImVec2(section_w, consumed));

			(void)section_h;
		}

		static void render_combined_view(float panel_w, float panel_h)
		{
			apply_pending_focus();

			{
				if (g_state.refresh.completed.exchange(false)) {
					if (g_state.refresh.success.load()) {
						toast_notification::push("Provider catalog refreshed",
							toast_notification::toast_type_t::info, 3.0f);
					} else {
						std::string m;
						{
							std::lock_guard<std::mutex> lk(g_state.mtx);
							m = g_state.refresh.message;
						}
						toast_notification::push(std::string("Refresh failed: ") + m,
							toast_notification::toast_type_t::error, 5.0f);
					}
				}
			}

			const auto& th = aida::ui::resolved();
			const float pad = 12.f;

			ImGui::BeginChild("##aida_chatbox_root", ImVec2(panel_w, panel_h), false,
				ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

			const ImVec2 wp = ImGui::GetWindowPos();
			const float root_x = wp.x;
			const float root_y = wp.y;
			const float root_w = panel_w;
			const float root_h = panel_h;

			ImDrawList* hdl = ImGui::GetWindowDrawList();
			hdl->AddText(aida::ui::fonts::h2(), 22.f,
				ImVec2(root_x + pad, root_y + 2.f),
				th.text_primary, "Accounts");

			const float toolbar_h = 40.f;

			if (!g_state.selected_provider_id.empty()) {
				const int idx = chatbox_dropdown_index_for(g_state.selected_provider_id);
				if (idx != g_state.chatbox_provider_dropdown_index) {
					g_state.chatbox_provider_dropdown_index = idx;
					chatbox_load_persisted_key(g_state.selected_provider_id);
				}
				g_state.selected_provider_id.clear();
			}

			const bool refreshing = g_state.refresh.in_flight.load();
			float refresh_w = 220.f;
			const char* refresh_label_full = refreshing ? "Refreshing catalog..." : "Refresh model catalog";
			const char* refresh_label_short = refreshing ? "Refreshing..." : "Refresh";
			const char* refresh_label = refresh_label_full;
			if (root_w < 520.f) {
				refresh_w = 110.f;
				refresh_label = refresh_label_short;
			}
			ImGui::SetCursorScreenPos(ImVec2(root_x + root_w - pad - refresh_w, root_y + 4.f));
			if (aida::ui::button(refresh_label,
					aida::ui::button_kind_t::secondary,
					aida::ui::size_t_::md,
					ImVec2(refresh_w, 30.f),
					false, nullptr, refreshing)) {
				if (!refreshing) start_refresh_catalog();
			}
			if (root_w < 520.f && ImGui::IsItemHovered()) {
				aida::ui::components::tooltip_blur("Refresh model catalog", 0.35f);
			}

			const float tab_y = root_y + toolbar_h;
			const float tab_h = 36.f;
			float tab_w = 200.f;
			float avail_for_tabs = root_w - pad * 2.f - 6.f;
			float two_tabs = 2.f * tab_w + 6.f;
			bool use_short_auth_tabs = (avail_for_tabs < two_tabs);
			if (use_short_auth_tabs) {
				tab_w = std::max(80.f, (avail_for_tabs - 6.f) * 0.5f);
			}
			static bool s_logged_auth_short = false;
			if (use_short_auth_tabs && !s_logged_auth_short) {
				s_logged_auth_short = true;
				::diag::log_tagged_fmt("responsive",
					"auth_view tabs short_labels root_w=%.0f tab_w=%.0f",
					root_w, tab_w);
			} else if (!use_short_auth_tabs && s_logged_auth_short) {
				s_logged_auth_short = false;
			}
			ImGui::SetCursorScreenPos(ImVec2(root_x + pad, tab_y));
			ImGui::PushID("##chatbox_section_tabs");

			const char* tab_labels_full[2] = { "API key (chatbox)", "Browser OAuth" };
			const char* tab_labels_short[2] = { "API key", "OAuth" };
			const char* const* tab_labels = use_short_auth_tabs ? tab_labels_short : tab_labels_full;
			ImDrawList* tdl = ImGui::GetWindowDrawList();
			for (int i = 0; i < 2; ++i) {
				ImVec2 ta(root_x + pad + (tab_w + 6.f) * static_cast<float>(i), tab_y);
				ImVec2 tb(ta.x + tab_w, ta.y + tab_h);
				ImGui::SetCursorScreenPos(ta);
				ImGui::PushID(i);
				ImGui::InvisibleButton("##chatbox_tab", ImVec2(tb.x - ta.x, tb.y - ta.y));
				bool hov = ImGui::IsItemHovered();
				bool clicked = ImGui::IsItemClicked();
				if (use_short_auth_tabs && hov) {
					aida::ui::components::tooltip_blur(tab_labels_full[i], 0.35f);
				}
				ImGui::PopID();

				const bool is_sel = (g_state.chatbox_active_section == i);
				ImU32 bg = is_sel
					? aida::ui::with_alpha(th.selection, 0.85f)
					: (hov ? aida::ui::with_alpha(th.hover_wash, 1.f)
							: aida::ui::with_alpha(th.panel_header, 0.5f));
				tdl->AddRectFilled(ta, tb, bg, 10.f);
				tdl->AddRect(ta, tb,
					is_sel ? th.accent_u32 : aida::ui::with_alpha(th.border_subtle, 0.7f),
					10.f, 0, is_sel ? 1.6f : 1.f);

				ImFont* lf = is_sel ? aida::ui::fonts::body_strong() : aida::ui::fonts::body();
				float lfs = aida::ui::components::detail::ui_fs() * 0.98f;
				ImVec2 lsz = lf->CalcTextSizeA(lfs, FLT_MAX, 0.f, tab_labels[i]);
				tdl->AddText(lf, lfs,
					ImVec2(ta.x + ((tb.x - ta.x) - lsz.x) * 0.5f,
						ta.y + ((tb.y - ta.y) - lsz.y) * 0.5f),
					is_sel ? th.text_primary : th.text_secondary, tab_labels[i]);

				if (clicked) g_state.chatbox_active_section = i;
			}
			ImGui::PopID();

			const float body_y = tab_y + tab_h + 14.f;
			const float body_h = root_h - (body_y - root_y) - pad;
			const float body_max_w = 720.f;
			const float body_w = (std::min)(body_max_w, root_w - pad * 2.f);
			const float body_x = root_x + ((root_w - body_w) * 0.5f);

			ImVec2 ca(body_x, body_y);
			ImVec2 cb(body_x + body_w, body_y + body_h);
			ImDrawList* bdl = ImGui::GetWindowDrawList();
			bdl->AddRectFilled(ca, cb,
				aida::ui::with_alpha(th.bg_elevated, 0.55f), 14.f);
			bdl->AddRect(ca, cb,
				aida::ui::with_alpha(th.border_subtle, 0.85f), 14.f, 0, 1.f);

			ImGui::SetCursorScreenPos(ImVec2(body_x + 1.f, body_y + 1.f));
			ImGui::BeginChild("##chatbox_body", ImVec2(body_w - 2.f, body_h - 2.f), false,
				ImGuiWindowFlags_NoBackground);

			if (g_state.chatbox_active_section == 0) {
				render_chatbox_api_section(body_x, body_y, body_w, body_h);
			} else {
				render_chatbox_oauth_section(body_x, body_y, body_w, body_h);
			}

			ImGui::EndChild();
			ImGui::EndChild();
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
			float fs = aida::ui::components::detail::ui_fs() * 0.82f;

			float chip_h = 28.f;
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

			float dim_alpha = visible * 0.f;
			(void)dim_alpha;

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
			float fs = aida::ui::components::detail::ui_fs() * 0.98f;
			ImVec2 ts = f->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
			fdl->AddText(f, fs,
				ImVec2(a.x + (bw - ts.x) * 0.5f, a.y + (bh - ts.y) * 0.5f),
				text_col, label);

			return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
		}

		static void render_modal_header(ImDrawList* fdl, const sheet_layout_t& sl,
			const modal_brand_t& def, const char* title)
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
			const float base_fs = aida::ui::components::detail::ui_fs();
			fdl->AddText(f_h2, base_fs * 1.18f,
				ImVec2(glyph_cx + glyph_r + 14.f, glyph_cy - base_fs * 0.95f),
				aida::ui::with_alpha(th.text_primary, alpha), title);

			fdl->AddText(f_caption, base_fs * 0.88f,
				ImVec2(glyph_cx + glyph_r + 14.f, glyph_cy + 4.f),
				aida::ui::with_alpha(th.text_secondary, alpha), def.subtitle);
		}

		static flow_phase_t derive_phase_codex(const aida::auth::codex::codex_login_state_t* sp,
			const modal_anim_t& ma, bool exchange_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			const auto value = aida::auth::codex::snapshot(*sp);
			if (value.done && !exchange_in_progress && !value.error.empty())
				return flow_phase_t::error_state;
			if (value.done) return flow_phase_t::session;
			if (!value.received_code.empty()) return flow_phase_t::callback;
			return flow_phase_t::browser;
		}

		static flow_phase_t derive_phase_claude(const aida::auth::claude_code::claude_code_login_state_t* sp,
			const modal_anim_t& ma, bool exchange_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			const auto value = aida::auth::claude_code::snapshot(*sp);
			if (value.done && !exchange_in_progress && !value.error.empty())
				return flow_phase_t::error_state;
			if (value.done) return flow_phase_t::session;
			if (!value.received_code.empty()) return flow_phase_t::callback;
			return flow_phase_t::browser;
		}

		static flow_phase_t derive_phase_copilot(const aida::auth::copilot::copilot_login_state_t* sp,
			const modal_anim_t& ma, bool poll_in_progress)
		{
			if (ma.success_played) return flow_phase_t::complete;
			if (!sp) return flow_phase_t::browser;
			const auto value = aida::auth::copilot::snapshot(*sp);
			if (value.done && !poll_in_progress && !value.error.empty())
				return flow_phase_t::error_state;
			if (value.done) return flow_phase_t::session;
			if (!value.user_code.empty()) return flow_phase_t::callback;
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

			const modal_brand_t& def = k_brand_codex;
			sheet_layout_t sl = render_modal_chrome(fdl, g_state.codex_anim, pw, ph,
				def.grad_top, def.grad_bot);

			render_modal_header(fdl, sl, def, "Sign in with OpenAI");

			const auto& th = aida::ui::resolved();
			ImU32 accent_col = aida::ui::mix(def.grad_top, def.grad_bot, 0.5f);

			std::string url_open;
			std::string err_text;
			flow_phase_t phase = flow_phase_t::browser;
			const bool starting_in_progress = g_state.codex_start.active.load();
			const bool exchange_in_progress = g_state.codex_exchange_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.codex_state) {
					const auto value = aida::auth::codex::snapshot(*g_state.codex_state);
					if (!starting_in_progress)
						url_open = value.auth_url;
					if (value.done && !exchange_in_progress)
						err_text = value.error;
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
			const float status_fs = aida::ui::components::detail::ui_fs() * 0.95f;
			ImVec2 ss = f_body->CalcTextSizeA(status_fs, FLT_MAX, 0.f, status.c_str());
			fdl->AddText(f_body, status_fs,
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

			const modal_brand_t& def = k_brand_claude_code;
			sheet_layout_t sl = render_modal_chrome(fdl, g_state.claude_code_anim, pw, ph,
				def.grad_top, def.grad_bot);

			render_modal_header(fdl, sl, def, "Sign in with Claude");

			const auto& th = aida::ui::resolved();
			ImU32 accent_col = aida::ui::mix(def.grad_top, def.grad_bot, 0.5f);

			std::string url_open;
			std::string err_text;
			flow_phase_t phase = flow_phase_t::browser;
			const bool starting_in_progress = g_state.claude_code_start.active.load();
			const bool exchange_in_progress = g_state.claude_code_exchange_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.claude_code_state) {
					const auto value = aida::auth::claude_code::snapshot(*g_state.claude_code_state);
					if (!starting_in_progress)
						url_open = value.auth_url;
					if (value.done && !exchange_in_progress)
						err_text = value.error;
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
			const float status_fs = aida::ui::components::detail::ui_fs() * 0.95f;
			ImVec2 ss = f_body->CalcTextSizeA(status_fs, FLT_MAX, 0.f, status.c_str());
			fdl->AddText(f_body, status_fs,
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

			const modal_brand_t& def = k_brand_copilot;
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
				const float prompt_fs = aida::ui::components::detail::ui_fs() * 0.95f;
				ImVec2 ps = f_body->CalcTextSizeA(prompt_fs, FLT_MAX, sl.pw - 44.f, prompt);
				fdl->AddText(f_body, prompt_fs,
					ImVec2(sl.px + 22.f, sl.py + 84.f),
					aida::ui::with_alpha(th.text_secondary, sl.alpha * 0.95f),
					prompt, nullptr, sl.pw - 44.f);

				float label_y = sl.py + 84.f + ps.y + 12.f;
				fdl->AddText(f_caption, aida::ui::components::detail::ui_fs() * 0.85f,
					ImVec2(sl.px + 22.f, label_y),
					aida::ui::with_alpha(th.text_secondary, sl.alpha),
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
			const bool starting_in_progress = g_state.copilot_start.active.load();
			const bool poll_in_progress = g_state.copilot_poll_in_flight.load();
			{
				std::lock_guard<std::mutex> lk(g_state.mtx);
				if (g_state.copilot_state) {
					const auto value = aida::auth::copilot::snapshot(*g_state.copilot_state);
					if (!starting_in_progress) {
						user_code = value.user_code;
						verify_uri = value.verification_uri;
						have_code = !user_code.empty();
					}
					if (value.done && !poll_in_progress)
						err_text = value.error;
					phase = derive_phase_copilot(g_state.copilot_state.get(),
						g_state.copilot_anim, poll_in_progress);
				}
			}

			float chip_y = sl.py + 76.f;
			render_phase_chips(fdl, sl.px + 22.f, chip_y, sl.pw - 44.f,
				phase, sl.alpha, th.accent_grad_top, th.accent_grad_bot, true);

			if (have_code) {
				ImFont* fdisp = aida::ui::fonts::display();
				float code_size = aida::ui::components::detail::ui_fs() * 1.5f;
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
				const float copy_fs = aida::ui::components::detail::ui_fs() * 0.95f;
				ImVec2 cs = f_em->CalcTextSizeA(copy_fs, FLT_MAX, 0.f, "Copy");
				fdl->AddText(f_em, copy_fs,
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
			const float status_fs = aida::ui::components::detail::ui_fs() * 0.95f;
			ImVec2 ss = f_body->CalcTextSizeA(status_fs, FLT_MAX, 0.f, status_text.c_str());
			fdl->AddText(f_body, status_fs,
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
		g_state.shutdown_flag.store(false);
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
						{
							std::lock_guard<std::mutex> lk2(g_state.mtx);
							g_state.last_completed_provider = ev.provider_id;
							g_state.last_completed_email = ev.email;
							g_state.have_completed_event.store(true);
						}
						schedule_auth_snapshot_refresh(true);
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
		schedule_auth_snapshot_refresh(true);
	}

	void shutdown()
	{
		g_state.shutdown_flag.store(true);
		request_login_start_cancel(g_state.codex_start);
		request_login_start_cancel(g_state.copilot_start);
		request_login_start_cancel(g_state.claude_code_start);
		std::shared_ptr<aida::auth::codex::codex_login_state_t> codex_local;
		std::shared_ptr<aida::auth::copilot::copilot_login_state_t> copilot_local;
		std::shared_ptr<aida::auth::claude_code::claude_code_login_state_t> claude_local;
		{
			std::lock_guard<std::mutex> lk(g_state.mtx);
			codex_local = g_state.codex_state;
			copilot_local = g_state.copilot_state;
			claude_local = g_state.claude_code_state;
			for (auto& kv : g_state.validate_in_flight) {
				if (kv.second) kv.second->store(false);
			}
			g_state.validate_in_flight.clear();
			g_state.validate_results.clear();

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

		if (codex_local) {
			submit_provider_cancel("auth.codex.shutdown_cancel", "openai", codex_local,
				[](aida::auth::codex::codex_login_state_t& state) {
					return aida::auth::codex::cancel_login(state);
				});
		}
		if (copilot_local) {
			submit_provider_cancel("auth.copilot.shutdown_cancel", "github-copilot", copilot_local,
				[](aida::auth::copilot::copilot_login_state_t& state) {
					return aida::auth::copilot::cancel_login(state);
				});
		}
		if (claude_local) {
			submit_provider_cancel("auth.claude_code.shutdown_cancel", "anthropic", claude_local,
				[](aida::auth::claude_code::claude_code_login_state_t& state) {
					return aida::auth::claude_code::cancel_login(state);
				});
		}
		const std::uint64_t browser_task_id = g_state.browser_open.task_id.exchange(0,
			std::memory_order_acq_rel);
		if (browser_task_id != 0) aida::auth::cancel_open_url_external(browser_task_id);
		g_state.browser_open.generation.fetch_add(1, std::memory_order_acq_rel);
		g_state.browser_open.in_flight.store(false, std::memory_order_release);
		g_state.browser_open.completion_pending.store(false, std::memory_order_release);

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

	void focus_provider(const std::string& provider_id)
	{
		std::lock_guard<std::mutex> lk(g_state.pending_focus_mtx);
		g_state.pending_focus_provider = provider_id;
	}

	bool is_provider_authenticated(const std::string& provider_id)
	{
		if (provider_id.empty()) return false;
		const int64_t last = auth_snapshot_last_unix().load(std::memory_order_acquire);
		if (last == 0 || now_unix() - last >= 5)
			schedule_auth_snapshot_refresh(false);
		auto snapshot = std::atomic_load_explicit(&auth_snapshot_ref(), std::memory_order_acquire);
		if (!snapshot) return false;
		auto it = snapshot->find(canonical_provider_key(provider_id));
		if (it != snapshot->end()) return it->second;
		it = snapshot->find(provider_id);
		if (it != snapshot->end()) return it->second;
		return false;
	}

	void render(float panel_w, float panel_h)
	{
		ImGui::PushID("aida_auth_view");
		poll_login_startups();
		poll_browser_open_completion();

		if (aida::provider::catalog::list_providers().empty()) {
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "auth_provider";
			sub.label = "auth.catalog.load_cached_or_fetch";
			sub.thread_class = "service_task";
			sub.domain = aida::infra::executor::domain_t::service;
			sub.priority = 3;
			sub.body = []() {
				if (g_state.shutdown_flag.load()) return;
				aida::provider::catalog::load_cached_or_fetch(86400);
			};
			aida::infra::executor::submit(std::move(sub));
		}

		float content_h = panel_h > 0.f ? panel_h : ImGui::GetContentRegionAvail().y;
		ImGui::BeginChild("##auth_view_root", ImVec2(panel_w, content_h),
			false,
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

		ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 6.f));

		render_combined_view(ImGui::GetContentRegionAvail().x,
			ImGui::GetContentRegionAvail().y);

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
