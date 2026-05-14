#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

namespace aida {
namespace auth {
namespace copilot {

	constexpr const char* COPILOT_CLIENT_ID = "Iv1.b507a08c87ecfe98";
	constexpr int COPILOT_POLLING_SAFETY_MARGIN_MS = 3000;

	struct copilot_login_state_t {
		std::string device_code;
		std::string user_code;
		std::string verification_uri;
		int interval = 5;
		int64_t expires_unix = 0;
		std::optional<std::string> enterprise_url;
		std::atomic<bool> done{ false };
		std::atomic<bool> cancelled{ false };
		std::string error;
		int64_t last_poll_unix = 0;
		int64_t next_poll_unix = 0;

		copilot_login_state_t() = default;
		copilot_login_state_t(const copilot_login_state_t&) = delete;
		copilot_login_state_t& operator=(const copilot_login_state_t&) = delete;
	};

	bool start_login(copilot_login_state_t& state, std::optional<std::string> enterprise_url);
	bool poll_login(copilot_login_state_t& state);
	bool cancel_login(copilot_login_state_t& state);
	bool refresh_token();
	bool revoke_token();
	bool revoke_tokens(const std::string& access_token,
		const std::string& refresh_token_value,
		const std::string& client_id_override);
	const std::string& last_error();

}
}
}
