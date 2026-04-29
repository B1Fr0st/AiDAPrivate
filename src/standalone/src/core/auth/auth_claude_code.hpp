#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace aida {
namespace auth {
namespace claude_code {

	constexpr const char* CLAUDE_CODE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
	constexpr const char* CLAUDE_CODE_BASE_API_URL =
		"https://api.anthropic.com";
	constexpr const char* CLAUDE_CODE_AUTHORIZE_URL =
		"https://claude.com/cai/oauth/authorize";
	constexpr const char* CLAUDE_CODE_TOKEN_URL =
		"https://platform.claude.com/v1/oauth/token";
	constexpr const char* CLAUDE_CODE_PROFILE_PATH =
		"/api/oauth/profile";
	constexpr const char* CLAUDE_CODE_DEFAULT_SCOPES =
		"org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
	constexpr const char* CLAUDE_CODE_REFRESH_SCOPES =
		"user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
	constexpr int OAUTH_TIMEOUT_SECONDS = 300;

	struct claude_code_login_state_t {
		std::string verifier;
		std::string challenge;
		std::string state;
		std::string auth_url;
		int port = 0;
		std::atomic<bool> done{ false };
		std::atomic<bool> cancelled{ false };
		std::string received_code;
		std::string received_state;
		std::string error;
		void* listener_handle = nullptr;
		int64_t started_unix = 0;

		claude_code_login_state_t() = default;
		claude_code_login_state_t(const claude_code_login_state_t&) = delete;
		claude_code_login_state_t& operator=(const claude_code_login_state_t&) = delete;
	};

	bool start_login(claude_code_login_state_t& state);
	bool poll_login(claude_code_login_state_t& state);
	bool cancel_login(claude_code_login_state_t& state);
	bool refresh_token();
	const std::string& last_error();

}
}
}
