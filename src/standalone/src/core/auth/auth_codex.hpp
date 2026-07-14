#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
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

	struct codex_login_state_t : std::enable_shared_from_this<codex_login_state_t> {
		mutable std::mutex mutex;
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
		std::shared_ptr<void> listener_handle;
		int64_t started_unix = 0;

		codex_login_state_t() = default;
		codex_login_state_t(const codex_login_state_t&) = delete;
		codex_login_state_t& operator=(const codex_login_state_t&) = delete;
	};

	struct codex_login_snapshot_t {
		std::string verifier;
		std::string challenge;
		std::string state;
		std::string auth_url;
		int port = CODEX_OAUTH_PORT;
		bool done = false;
		bool cancelled = false;
		std::string received_code;
		std::string received_state;
		std::string error;
		bool listener_active = false;
		int64_t started_unix = 0;
	};

	bool start_login(codex_login_state_t& state, std::uint64_t absolute_deadline_ms = 0);
	bool poll_login(codex_login_state_t& state);
	bool cancel_login(codex_login_state_t& state);
	bool refresh_token();
	bool revoke_token();
	bool revoke_tokens(const std::string& access_token,
		const std::string& refresh_token_value,
		const std::string& client_id_override);
	codex_login_snapshot_t snapshot(const codex_login_state_t& state);
	std::string last_error();

}
}
}
