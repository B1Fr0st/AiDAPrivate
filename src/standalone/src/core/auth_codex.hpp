#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace aida {
namespace auth {
namespace codex {

	constexpr const char* CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
	constexpr const char* CODEX_ISSUER = "https://auth.openai.com";
	constexpr const char* CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses";
	constexpr int CODEX_OAUTH_PORT = 1455;
	constexpr int OAUTH_POLLING_SAFETY_MARGIN_MS = 3000;
	constexpr int OAUTH_TIMEOUT_SECONDS = 300;

	struct codex_login_state_t {
		std::string verifier;
		std::string challenge;
		std::string state;
		std::string auth_url;
		int port = CODEX_OAUTH_PORT;
		std::atomic<bool> done{ false };
		std::atomic<bool> cancelled{ false };
		std::string received_code;
		std::string received_state;
		std::string error;
		void* listener_handle = nullptr;
		int64_t started_unix = 0;

		codex_login_state_t() = default;
		codex_login_state_t(const codex_login_state_t&) = delete;
		codex_login_state_t& operator=(const codex_login_state_t&) = delete;
	};

	bool start_login(codex_login_state_t& state);
	bool poll_login(codex_login_state_t& state);
	bool cancel_login(codex_login_state_t& state);
	bool refresh_token();
	const std::string& last_error();

}
}
}
