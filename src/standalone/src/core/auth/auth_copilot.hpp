#pragma once

#include "auth_http.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace aida {
namespace auth {
namespace copilot {

	constexpr const char* COPILOT_CLIENT_ID = "Iv1.b507a08c87ecfe98";
	constexpr int COPILOT_POLLING_SAFETY_MARGIN_MS = 3000;

	struct copilot_login_state_t {
		mutable std::mutex mutex;
		std::string device_code;
		std::string user_code;
		std::string verification_uri;
		int interval = 5;
		int64_t expires_unix = 0;
		std::optional<std::string> enterprise_url;
		std::atomic<bool> done{ false };
		std::atomic<bool> cancelled{ false };
		std::atomic<std::uint8_t> terminal_phase{ 0 };
		std::string error;
		int64_t last_poll_unix = 0;
		int64_t next_poll_unix = 0;

		copilot_login_state_t() = default;
		copilot_login_state_t(const copilot_login_state_t&) = delete;
		copilot_login_state_t& operator=(const copilot_login_state_t&) = delete;
	};

	struct copilot_login_snapshot_t {
		std::string device_code;
		std::string user_code;
		std::string verification_uri;
		int interval = 5;
		int64_t expires_unix = 0;
		std::optional<std::string> enterprise_url;
		bool done = false;
		bool cancelled = false;
		std::uint8_t terminal_phase = 0;
		std::string error;
		int64_t last_poll_unix = 0;
		int64_t next_poll_unix = 0;
	};

	bool start_login(copilot_login_state_t& state, std::optional<std::string> enterprise_url,
		std::uint64_t absolute_deadline_ms = 0);
	bool poll_login(copilot_login_state_t& state);
	bool request_cancel(copilot_login_state_t& state) noexcept;
	bool cancel_login(copilot_login_state_t& state);
	bool refresh_token(const http::cancel_cb_t& cancelled = {}, int timeout_sec = 30);
	bool revoke_token();
	bool revoke_tokens(const std::string& access_token,
		const std::string& refresh_token_value,
		const std::string& client_id_override);
	copilot_login_snapshot_t snapshot(const copilot_login_state_t& state);
	std::string last_error();

}
}
}
