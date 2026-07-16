#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_claude_code.hpp"
#include <chrono>
#include <mutex>
#include <string>
#include <utility>

namespace aida {
namespace auth {
namespace claude_code {

namespace {

	std::mutex& preview_error_mutex()
	{
		static std::mutex value;
		return value;
	}

	std::string& preview_error()
	{
		static std::string value;
		return value;
	}

	void set_preview_error(std::string value)
	{
		std::lock_guard<std::mutex> lock(preview_error_mutex());
		preview_error() = std::move(value);
	}

	bool claim_preview_terminal(claude_code_login_state_t& state, std::uint8_t phase) noexcept
	{
		std::uint8_t expected = 0;
		return state.terminal_phase.compare_exchange_strong(expected, phase,
			std::memory_order_acq_rel, std::memory_order_acquire);
	}

}

bool start_login(claude_code_login_state_t& state, std::uint64_t)
{
	state.done.store(false, std::memory_order_release);
	state.terminal_phase.store(0, std::memory_order_release);
	const bool cancelled = state.cancelled.load(std::memory_order_acquire);
	const char* error = cancelled
		? "preview_auth_cancelled" : "preview_auth_unavailable";
	{
		std::lock_guard<std::mutex> lock(state.mutex);
		if (!claim_preview_terminal(state, cancelled ? 3 : 2)) return false;
		state.verifier.clear();
		state.challenge.clear();
		state.state.clear();
		state.auth_url.clear();
		state.port = 0;
		state.received_code.clear();
		state.received_state.clear();
		state.error = error;
		state.listener_handle.reset();
		state.started_unix = 0;
		state.done.store(true, std::memory_order_release);
	}
	set_preview_error(error);
	return false;
}

bool poll_login(claude_code_login_state_t& state)
{
	const bool cancelled = state.cancelled.load(std::memory_order_acquire);
	const char* error = cancelled
		? "preview_auth_cancelled" : "preview_auth_unavailable";
	{
		std::lock_guard<std::mutex> lock(state.mutex);
		if (!claim_preview_terminal(state, cancelled ? 3 : 2)) return false;
		state.listener_handle.reset();
		state.error = error;
		state.done.store(true, std::memory_order_release);
	}
	set_preview_error(error);
	return false;
}

bool request_cancel(claude_code_login_state_t& state) noexcept
{
	std::uint8_t phase = state.terminal_phase.load(std::memory_order_acquire);
	while (phase == 0 || phase == 4 || phase == 5) {
		if (state.terminal_phase.compare_exchange_weak(phase, 3,
			std::memory_order_acq_rel, std::memory_order_acquire)) break;
	}
	if (phase != 0 && phase != 4 && phase != 5) return false;
	state.cancelled.store(true, std::memory_order_release);
	state.done.store(true, std::memory_order_release);
	try {
		std::lock_guard<std::mutex> lock(state.mutex);
		state.listener_handle.reset();
		state.error = "preview_auth_cancelled";
	} catch (...) {
	}
	try { set_preview_error("preview_auth_cancelled"); } catch (...) {}
	return true;
}

bool cancel_login(claude_code_login_state_t& state)
{
	return request_cancel(state);
}

bool refresh_token(const http::cancel_cb_t&, int)
{
	set_preview_error("preview_auth_unavailable");
	return false;
}

bool revoke_tokens(const std::string&,
	const std::string&,
	const std::string&)
{
	set_preview_error("preview_auth_unavailable");
	return false;
}

bool revoke_token()
{
	set_preview_error("preview_auth_unavailable");
	return false;
}

claude_code_login_snapshot_t snapshot(const claude_code_login_state_t& state)
{
	claude_code_login_snapshot_t value;
	std::lock_guard<std::mutex> lock(state.mutex);
	value.verifier = state.verifier;
	value.challenge = state.challenge;
	value.state = state.state;
	value.auth_url = state.auth_url;
	value.port = state.port;
	value.done = state.done.load(std::memory_order_acquire);
	value.cancelled = state.cancelled.load(std::memory_order_acquire);
	value.terminal_phase = state.terminal_phase.load(std::memory_order_acquire);
	value.received_code = state.received_code;
	value.received_state = state.received_state;
	value.error = state.error;
	value.listener_active = static_cast<bool>(state.listener_handle);
	value.started_unix = state.started_unix;
	return value;
}

std::string last_error()
{
	std::lock_guard<std::mutex> lock(preview_error_mutex());
	return preview_error();
}

}
}
}

#else

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "auth_claude_code.hpp"

#include "auth_store.hpp"
#include "anti-tamper/webhook.hpp"
#include "../infra/executor.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include "auth_http.hpp"
#include "auth_browser_launch.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

namespace aida {
namespace auth {
namespace claude_code {

	namespace {

		std::mutex& mtx()
		{
			static std::mutex m;
			return m;
		}

		std::string& last_error_ref()
		{
			static std::string s;
			return s;
		}

		void set_last_error(const std::string& text)
		{
			std::lock_guard<std::mutex> lk(mtx());
			last_error_ref() = text;
			if (!text.empty()) {
				const std::string line = std::string("[aida.auth.claude_code] ") + text;
				anti_tamper::webhook::write_log("auth.claude_code", line.c_str());
			}
		}

		struct listener_t {
			std::mutex mutex;
			std::vector<SOCKET> sockets;
			std::atomic<SOCKET> active_client{ INVALID_SOCKET };
			std::atomic<bool> worker_done{ true };
			std::atomic<bool> worker_started{ false };
			std::atomic<bool> stop{ false };
			std::atomic<bool> cancellation_dispatched{ false };
			std::atomic<std::uint64_t> task_id{ 0 };
		};

		void close_active_client(const std::shared_ptr<listener_t>& ctx, SOCKET client) noexcept
		{
			if (!ctx || client == INVALID_SOCKET) return;
			SOCKET expected = client;
			if (ctx->active_client.compare_exchange_strong(expected, INVALID_SOCKET,
				std::memory_order_acq_rel, std::memory_order_acquire)) closesocket(client);
		}

		void close_listener_sockets(const std::shared_ptr<listener_t>& ctx) noexcept
		{
			if (!ctx) return;
			std::vector<SOCKET> sockets;
			try {
				std::lock_guard<std::mutex> lock(ctx->mutex);
				sockets.swap(ctx->sockets);
			} catch (...) {
				return;
			}
			for (const SOCKET value : sockets)
				if (value != INVALID_SOCKET) closesocket(value);
		}

		void close_listener_resources(const std::shared_ptr<listener_t>& ctx) noexcept
		{
			if (!ctx) return;
			ctx->stop.store(true, std::memory_order_release);
			close_listener_sockets(ctx);
			const SOCKET client = ctx->active_client.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
			if (client != INVALID_SOCKET) closesocket(client);
		}

		void dispatch_listener_cancel(const std::shared_ptr<listener_t>& ctx) noexcept
		{
			if (!ctx) return;
			bool expected = false;
			if (!ctx->cancellation_dispatched.compare_exchange_strong(expected, true,
				std::memory_order_acq_rel, std::memory_order_acquire)) return;
			close_listener_resources(ctx);
			const std::uint64_t task_id = ctx->task_id.load(std::memory_order_acquire);
			if (task_id != 0) {
				try { aida::infra::executor::cancel(task_id); } catch (...) {}
			}
		}

		bool claim_login_publication(claude_code_login_state_t& state,
			std::uint8_t expected_phase, std::uint8_t published_phase) noexcept
		{
			return state.terminal_phase.compare_exchange_strong(expected_phase, published_phase,
				std::memory_order_acq_rel, std::memory_order_acquire);
		}

		bool publish_login_terminal_state(claude_code_login_state_t& state,
			const char* failure, std::uint8_t phase, std::uint8_t expected_phase = 0) noexcept
		{
			bool claimed = false;
			try {
				std::lock_guard<std::mutex> lock(state.mutex);
				claimed = claim_login_publication(state, expected_phase, phase);
				if (!claimed) return false;
				try { state.error = failure ? failure : "login failed"; } catch (...) {}
				state.done.store(true, std::memory_order_release);
			} catch (...) {
				if (claimed) state.done.store(true, std::memory_order_release);
			}
			if (claimed) {
				try { set_last_error(failure ? failure : "login failed"); } catch (...) {}
			}
			return claimed;
		}

		bool publish_login_terminal_failure(claude_code_login_state_t& state,
			const char* failure, std::uint8_t phase = 2) noexcept
		{
			static_cast<void>(publish_login_terminal_state(state, failure, phase));
			return false;
		}

		bool publish_login_callback(claude_code_login_state_t& state,
			const std::string& code, const std::string& callback_state) noexcept
		{
			bool claimed = false;
			try {
				std::lock_guard<std::mutex> lock(state.mutex);
				claimed = claim_login_publication(state, 0, 5);
				if (!claimed) return false;
				state.received_code = code;
				state.received_state = callback_state;
				state.error.clear();
				state.done.store(true, std::memory_order_release);
			} catch (...) {
				if (claimed) {
					try {
						std::lock_guard<std::mutex> lock(state.mutex);
						try { state.error = "callback publication failed"; } catch (...) {}
						state.done.store(true, std::memory_order_release);
						std::uint8_t expected = 5;
						state.terminal_phase.compare_exchange_strong(expected, 2,
							std::memory_order_acq_rel, std::memory_order_acquire);
					} catch (...) {
						state.done.store(true, std::memory_order_release);
						std::uint8_t expected = 5;
						state.terminal_phase.compare_exchange_strong(expected, 2,
							std::memory_order_acq_rel, std::memory_order_acquire);
					}
				}
				try { set_last_error("callback publication failed"); } catch (...) {}
				return false;
			}
			return true;
		}

		bool claim_login_exchange(claude_code_login_state_t& state) noexcept
		{
			try {
				std::lock_guard<std::mutex> lock(state.mutex);
				return claim_login_publication(state, 5, 4);
			} catch (...) {
				return false;
			}
		}

		bool finish_login_exchange(claude_code_login_state_t& state, bool success,
			const char* failure) noexcept
		{
			if (success && state.terminal_phase.load(std::memory_order_acquire) != 1)
				return false;
			try {
				std::lock_guard<std::mutex> lock(state.mutex);
				const std::uint8_t phase = state.terminal_phase.load(std::memory_order_acquire);
				if (success) {
					if (phase != 1) return false;
				} else {
					if (phase != 4) return false;
					std::uint8_t expected = 4;
					if (!state.terminal_phase.compare_exchange_strong(expected, 2,
						std::memory_order_acq_rel, std::memory_order_acquire)) return false;
				}
				try {
					if (success) state.error.clear();
					else state.error = failure && *failure ? failure : "token exchange failed";
				} catch (...) {
				}
				state.done.store(true, std::memory_order_release);
			} catch (...) {
				if (!success) {
					std::uint8_t expected = 4;
					state.terminal_phase.compare_exchange_strong(expected, 2,
						std::memory_order_acq_rel, std::memory_order_acquire);
				}
				state.done.store(true, std::memory_order_release);
				try { set_last_error("token exchange publication failed"); } catch (...) {}
				return false;
			}
			try { set_last_error(success ? std::string{}
				: std::string(failure && *failure ? failure : "token exchange failed")); } catch (...) {}
			return success;
		}

		const char kVerifierCharset[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

		std::string base64url_encode(const unsigned char* data, size_t length)
		{
			static const char kCharset[] =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
			std::string out;
			out.reserve(((length + 2) / 3) * 4);
			size_t i = 0;
			while (i + 3 <= length) {
				const unsigned int v = (static_cast<unsigned int>(data[i]) << 16)
					| (static_cast<unsigned int>(data[i + 1]) << 8)
					| static_cast<unsigned int>(data[i + 2]);
				out.push_back(kCharset[(v >> 18) & 0x3F]);
				out.push_back(kCharset[(v >> 12) & 0x3F]);
				out.push_back(kCharset[(v >> 6) & 0x3F]);
				out.push_back(kCharset[v & 0x3F]);
				i += 3;
			}
			if (i < length) {
				const size_t left = length - i;
				unsigned int v = static_cast<unsigned int>(data[i]) << 16;
				if (left == 2)
					v |= static_cast<unsigned int>(data[i + 1]) << 8;
				out.push_back(kCharset[(v >> 18) & 0x3F]);
				out.push_back(kCharset[(v >> 12) & 0x3F]);
				if (left == 2)
					out.push_back(kCharset[(v >> 6) & 0x3F]);
			}
			std::replace(out.begin(), out.end(), '+', '-');
			std::replace(out.begin(), out.end(), '/', '_');
			return out;
		}

		bool secure_random_bytes(unsigned char* out, size_t length)
		{
			NTSTATUS rc = BCryptGenRandom(nullptr, out, static_cast<ULONG>(length),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			return rc == 0;
		}

		std::string generate_verifier()
		{
			constexpr size_t kLen = 43;
			unsigned char rnd[kLen];
			if (!secure_random_bytes(rnd, kLen))
				return {};
			const size_t charset_len = std::strlen(kVerifierCharset);
			std::string out;
			out.reserve(kLen);
			for (size_t i = 0; i < kLen; ++i)
				out.push_back(kVerifierCharset[rnd[i] % charset_len]);
			return out;
		}

		std::string sha256_base64url(const std::string& input)
		{
			unsigned char digest[32] = {};
			EVP_MD_CTX* ctx = EVP_MD_CTX_new();
			if (!ctx)
				return {};
			std::string out;
			if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1
				&& EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) {
				unsigned int dl = 0;
				if (EVP_DigestFinal_ex(ctx, digest, &dl) == 1)
					out = base64url_encode(digest, dl);
			}
			EVP_MD_CTX_free(ctx);
			return out;
		}

		std::string generate_state_token()
		{
			unsigned char rnd[32] = {};
			if (!secure_random_bytes(rnd, sizeof(rnd)))
				return {};
			return base64url_encode(rnd, sizeof(rnd));
		}

		std::string url_encode(const std::string& s)
		{
			std::string out;
			out.reserve(s.size() * 3);
			for (unsigned char c : s) {
				if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
					|| (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
					out.push_back(static_cast<char>(c));
				} else {
					char buf[4];
					_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
					out.append(buf);
				}
			}
			return out;
		}

		bool ensure_winsock()
		{
			static std::once_flag once;
			static int rc = 0;
			std::call_once(once, []() {
				WSADATA wsa{};
				rc = WSAStartup(MAKEWORD(2, 2), &wsa);
			});
			return rc == 0;
		}

		std::string load_custom_client_id()
		{
			auth_info_t existing;
			if (store::get("anthropic", existing) && !existing.custom_client_id.empty())
				return existing.custom_client_id;
			return CLAUDE_CODE_CLIENT_ID;
		}

		std::string load_redirect_uri(int port)
		{
			auth_info_t existing;
			if (store::get("anthropic", existing) && !existing.custom_redirect_uri.empty())
				return existing.custom_redirect_uri;
			return std::string("http://localhost:") + std::to_string(port) + "/callback";
		}

		std::string load_scopes()
		{
			auth_info_t existing;
			if (store::get("anthropic", existing) && !existing.custom_scopes.empty()) {
				std::string joined;
				for (size_t i = 0; i < existing.custom_scopes.size(); ++i) {
					if (i > 0)
						joined.push_back(' ');
					joined += existing.custom_scopes[i];
				}
				return joined;
			}
			return CLAUDE_CODE_DEFAULT_SCOPES;
		}

		std::string build_authorize_url(const std::string& redirect_uri,
			const std::string& challenge,
			const std::string& state_token,
			const std::string& client_id,
			const std::string& scopes)
		{
			std::string url = std::string(CLAUDE_CODE_AUTHORIZE_URL) + "?";
			url += "code=true";
			url += "&client_id=" + url_encode(client_id);
			url += "&response_type=code";
			url += "&redirect_uri=" + url_encode(redirect_uri);
			url += "&scope=" + url_encode(scopes);
			url += "&code_challenge=" + url_encode(challenge);
			url += "&code_challenge_method=S256";
			url += "&state=" + url_encode(state_token);
			return url;
		}

		int hex_digit(char c)
		{
			if (c >= '0' && c <= '9')
				return c - '0';
			if (c >= 'a' && c <= 'f')
				return 10 + (c - 'a');
			if (c >= 'A' && c <= 'F')
				return 10 + (c - 'A');
			return -1;
		}

		std::vector<std::string> split_scopes(const std::string& scope_string)
		{
			std::vector<std::string> scopes;
			std::string token;
			for (char ch : scope_string) {
				if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v') {
					if (!token.empty()) {
						scopes.push_back(token);
						token.clear();
					}
				} else {
					token.push_back(ch);
				}
			}
			if (!token.empty())
				scopes.push_back(token);
			return scopes;
		}

		std::string join_scopes(const std::vector<std::string>& scopes)
		{
			std::string joined;
			for (size_t i = 0; i < scopes.size(); ++i) {
				if (i > 0)
					joined.push_back(' ');
				joined += scopes[i];
			}
			return joined;
		}

		std::string json_string(const nlohmann::json& object, const char* key)
		{
			if (!object.is_object() || !object.contains(key))
				return {};
			const auto& value = object.at(key);
			if (!value.is_string())
				return {};
			return value.get<std::string>();
		}

		std::string subscription_type_from_profile(const nlohmann::json& profile)
		{
			if (!profile.is_object() || !profile.contains("organization")
				|| !profile["organization"].is_object())
				return {};
			const std::string org_type = json_string(profile["organization"], "organization_type");
			if (org_type == "claude_max")
				return "max";
			if (org_type == "claude_pro")
				return "pro";
			if (org_type == "claude_enterprise")
				return "enterprise";
			if (org_type == "claude_team")
				return "team";
			return {};
		}

		void read_token_account(const nlohmann::json& resp,
			std::string& account_id,
			std::string& email,
			std::string& organization_id)
		{
			if (account_id.empty())
				account_id = resp.value("account_id", std::string{});
			if (email.empty())
				email = resp.value("email", std::string{});
			if (resp.contains("account") && resp["account"].is_object()) {
				const auto& account = resp["account"];
				if (account_id.empty())
					account_id = json_string(account, "uuid");
				if (account_id.empty())
					account_id = json_string(account, "id");
				if (email.empty())
					email = json_string(account, "email_address");
				if (email.empty())
					email = json_string(account, "email");
			}
			if (resp.contains("organization") && resp["organization"].is_object()) {
				const auto& organization = resp["organization"];
				organization_id = json_string(organization, "uuid");
				if (organization_id.empty())
					organization_id = json_string(organization, "id");
			}
		}

		void read_profile_account(const nlohmann::json& profile,
			std::string& account_id,
			std::string& email,
			std::string& organization_id)
		{
			if (!profile.is_object())
				return;
			if (profile.contains("account") && profile["account"].is_object()) {
				const auto& account = profile["account"];
				const std::string profile_account = json_string(account, "uuid");
				const std::string profile_email = json_string(account, "email");
				if (!profile_account.empty())
					account_id = profile_account;
				if (!profile_email.empty())
					email = profile_email;
			}
			if (profile.contains("organization") && profile["organization"].is_object()) {
				const std::string profile_org = json_string(profile["organization"], "uuid");
				if (!profile_org.empty())
					organization_id = profile_org;
			}
		}

		nlohmann::json build_oauth_metadata(const nlohmann::json& resp,
			const nlohmann::json& profile,
			const std::vector<std::string>& scopes,
			const std::string& organization_id)
		{
			nlohmann::json metadata = nlohmann::json::object();
			metadata["scope"] = join_scopes(scopes);
			metadata["scopes"] = scopes;
			metadata["base_api_url"] = CLAUDE_CODE_BASE_API_URL;
			metadata["authorize_url"] = CLAUDE_CODE_AUTHORIZE_URL;
			metadata["token_url"] = CLAUDE_CODE_TOKEN_URL;
			if (!organization_id.empty())
				metadata["organization_uuid"] = organization_id;
			if (resp.contains("account") && resp["account"].is_object())
				metadata["token_account"] = resp["account"];
			if (resp.contains("organization") && resp["organization"].is_object())
				metadata["token_organization"] = resp["organization"];
			if (profile.is_object() && !profile.empty()) {
				metadata["profile"] = profile;
				const std::string subscription = subscription_type_from_profile(profile);
				if (!subscription.empty())
					metadata["subscription_type"] = subscription;
				if (profile.contains("organization") && profile["organization"].is_object()) {
					const auto& organization = profile["organization"];
					const std::string tier = json_string(organization, "rate_limit_tier");
					const std::string billing = json_string(organization, "billing_type");
					const std::string sub_created = json_string(organization, "subscription_created_at");
					if (!tier.empty())
						metadata["rate_limit_tier"] = tier;
					if (!billing.empty())
						metadata["billing_type"] = billing;
					if (!sub_created.empty())
						metadata["subscription_created_at"] = sub_created;
					if (organization.contains("has_extra_usage_enabled")
						&& organization["has_extra_usage_enabled"].is_boolean())
						metadata["has_extra_usage_enabled"] = organization["has_extra_usage_enabled"];
				}
				if (profile.contains("account") && profile["account"].is_object()) {
					const auto& account = profile["account"];
					const std::string display = json_string(account, "display_name");
					const std::string created = json_string(account, "created_at");
					if (!display.empty())
						metadata["display_name"] = display;
					if (!created.empty())
						metadata["account_created_at"] = created;
				}
			}
			return metadata;
		}

		std::string success_html()
		{
			return std::string(
				"<!doctype html><html><head><title>AiDA Login Successful "
				"&mdash; close this tab</title><style>body{font-family:system-ui,"
				"-apple-system,sans-serif;display:flex;justify-content:center;"
				"align-items:center;height:100vh;margin:0;background:#131010;"
				"color:#f1ecec}.container{text-align:center;padding:2rem}h1{color:"
				"#f1ecec;margin-bottom:1rem}p{color:#b7b1b1}</style></head><body>"
				"<div class=\"container\"><h1>Authorization Successful</h1><p>You "
				"can close this window and return to AiDA.</p></div><script>"
				"setTimeout(function(){window.close();},2000);</script></body></html>");
		}

		std::string failure_html(const std::string& reason)
		{
			std::string esc;
			esc.reserve(reason.size() + 16);
			for (char c : reason) {
				switch (c) {
					case '<': esc += "&lt;"; break;
					case '>': esc += "&gt;"; break;
					case '&': esc += "&amp;"; break;
					case '"': esc += "&quot;"; break;
					default: esc.push_back(c); break;
				}
			}
			return std::string(
				"<!doctype html><html><head><title>AiDA Login Failed</title>"
				"<style>body{font-family:system-ui,-apple-system,sans-serif;"
				"display:flex;justify-content:center;align-items:center;height:"
				"100vh;margin:0;background:#131010;color:#f1ecec}.container{"
				"text-align:center;padding:2rem}h1{color:#fc533a;margin-bottom:"
				"1rem}p{color:#b7b1b1}.error{color:#ff917b;font-family:monospace;"
				"margin-top:1rem;padding:1rem;background:#3c140d;border-radius:"
				"0.5rem}</style></head><body><div class=\"container\"><h1>"
				"Authorization Failed</h1><p>An error occurred during "
				"authorization.</p><div class=\"error\">") + esc
				+ "</div></div></body></html>";
		}

		void send_response(SOCKET client, int status, const std::string& body)
		{
			std::string status_text;
				switch (status) {
				case 200: status_text = "OK"; break;
				case 400: status_text = "Bad Request"; break;
				case 405: status_text = "Method Not Allowed"; break;
				case 404: status_text = "Not Found"; break;
				default: status_text = "OK"; break;
			}
			std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + status_text + "\r\n";
			resp += "Content-Type: text/html; charset=utf-8\r\n";
			resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
			resp += "Connection: close\r\n";
			resp += "Server: AiDA/1.0\r\n";
			resp += "\r\n";
			resp += body;
			::send(client, resp.data(), static_cast<int>(resp.size()), 0);
		}

		bool decode_query_component(const std::string& input, std::string& output)
		{
			output.clear();
			output.reserve(input.size());
			for (std::size_t i = 0; i < input.size(); ++i) {
				unsigned char value = static_cast<unsigned char>(input[i]);
				if (value == '+') {
					value = ' ';
				} else if (value == '%') {
					if (i + 2 >= input.size()) return false;
					const int hi = hex_digit(input[i + 1]);
					const int lo = hex_digit(input[i + 2]);
					if (hi < 0 || lo < 0) return false;
					value = static_cast<unsigned char>((hi << 4) | lo);
					i += 2;
				}
				if (value < 0x20 || value >= 0x7F) return false;
				output.push_back(static_cast<char>(value));
			}
			return true;
		}

		struct callback_query_t {
			bool valid = false;
			std::map<std::string, std::string> params;
		};

		callback_query_t parse_query(const std::string& query)
		{
			callback_query_t result;
			if (query.empty()) {
				result.valid = true;
				return result;
			}
			std::size_t pos = 0;
			while (pos < query.size()) {
				if (result.params.size() >= 64) return result;
				std::size_t amp = query.find('&', pos);
				if (amp == std::string::npos) amp = query.size();
				if (amp == pos) return result;
				const std::string pair = query.substr(pos, amp - pos);
				const std::size_t eq = pair.find('=');
				const std::string encoded_key = eq == std::string::npos
					? pair : pair.substr(0, eq);
				const std::string encoded_value = eq == std::string::npos
					? std::string{} : pair.substr(eq + 1);
				std::string key;
				std::string value;
				if (!decode_query_component(encoded_key, key) || key.empty()
					|| !decode_query_component(encoded_value, value)) return result;
				if (!result.params.emplace(std::move(key), std::move(value)).second)
					return result;
				if (amp == query.size()) break;
				pos = amp + 1;
				if (pos == query.size()) return result;
			}
			result.valid = true;
			return result;
		}

		struct callback_request_t {
			int status = 400;
			std::string query;
		};

		callback_request_t parse_callback_request(const std::string& raw)
		{
			callback_request_t result;
			const std::size_t line_end = raw.find("\r\n");
			if (line_end == std::string::npos || line_end > 8192) return result;
			const std::string line = raw.substr(0, line_end);
			const std::size_t first_space = line.find(' ');
			const std::size_t second_space = first_space == std::string::npos
				? std::string::npos : line.find(' ', first_space + 1);
			if (first_space == std::string::npos || second_space == std::string::npos
				|| line.find(' ', second_space + 1) != std::string::npos) return result;
			if (line.substr(0, first_space) != "GET") {
				result.status = 405;
				return result;
			}
			const std::string target = line.substr(first_space + 1,
				second_space - first_space - 1);
			const std::string version = line.substr(second_space + 1);
			if (version != "HTTP/1.1" && version != "HTTP/1.0") return result;
			if (target.empty() || target.front() != '/' || target.find('#') != std::string::npos)
				return result;
			for (const unsigned char value : target) {
				if (value <= 0x20 || value >= 0x7F || value == '\\') return result;
			}
			const std::size_t query = target.find('?');
			const std::string path = query == std::string::npos ? target : target.substr(0, query);
			if (path != "/callback" && path != "/auth/callback") {
				result.status = 404;
				return result;
			}
			result.status = 200;
			if (query != std::string::npos) result.query = target.substr(query + 1);
			return result;
		}

		void listener_thread(claude_code_login_state_t* state, std::shared_ptr<listener_t> ctx)
		{
			while (!ctx->stop.load() && !state->cancelled.load()) {
				std::vector<SOCKET> sockets;
				{
					std::lock_guard<std::mutex> lock(ctx->mutex);
					sockets = ctx->sockets;
				}
				std::vector<WSAPOLLFD> poll_fds;
				poll_fds.reserve(sockets.size());
				for (SOCKET listen_socket : sockets) {
					if (listen_socket == INVALID_SOCKET)
						continue;
					WSAPOLLFD poll_fd{};
					poll_fd.fd = listen_socket;
					poll_fd.events = POLLIN;
					poll_fds.push_back(poll_fd);
				}
				if (poll_fds.empty())
					return;
				int rc = WSAPoll(poll_fds.data(), static_cast<ULONG>(poll_fds.size()), 250);
				if (rc <= 0)
					continue;

				SOCKET ready_socket = INVALID_SOCKET;
				for (const auto& poll_fd : poll_fds) {
					if ((poll_fd.revents & POLLIN) != 0) {
						ready_socket = poll_fd.fd;
						break;
					}
				}
				if (ready_socket == INVALID_SOCKET)
					continue;

				sockaddr_storage cli{};
				int cli_len = sizeof(cli);
				SOCKET client = accept(ready_socket, reinterpret_cast<sockaddr*>(&cli), &cli_len);
				if (client == INVALID_SOCKET)
					continue;
				ctx->active_client.store(client, std::memory_order_release);

				DWORD tv = 5000;
				setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
				setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

				std::string raw;
				raw.reserve(2048);
				char buf[1024];
				for (int i = 0; i < 32; ++i) {
					int n = recv(client, buf, sizeof(buf), 0);
					if (n <= 0)
						break;
					raw.append(buf, n);
					if (raw.find("\r\n\r\n") != std::string::npos)
						break;
					if (raw.size() > 16384)
						break;
				}

				const callback_request_t request = parse_callback_request(raw);
				if (request.status != 200) {
					const char* detail = request.status == 405 ? "method not allowed"
						: request.status == 404 ? "not found" : "malformed request";
					send_response(client, request.status, failure_html(detail));
					close_active_client(ctx, client);
					continue;
				}

				const callback_query_t query = parse_query(request.query);
				if (!query.valid) {
					send_response(client, 400, failure_html("malformed query"));
					close_active_client(ctx, client);
					continue;
				}
				const auto& params = query.params;

				const auto err_it = params.find("error");
				if (err_it != params.end()) {
					std::string detail = err_it->second;
					const auto desc_it = params.find("error_description");
					if (desc_it != params.end() && !desc_it->second.empty())
						detail = detail.empty() ? desc_it->second : detail + ": " + desc_it->second;
					if (detail.empty()) detail = "authorization failed";
					if (!publish_login_terminal_state(*state, detail.c_str(), 2)) {
						send_response(client, 400, failure_html("login no longer active"));
						close_active_client(ctx, client);
						return;
					}
					send_response(client, 200, failure_html(detail));
					close_active_client(ctx, client);
					return;
				}

				const auto code_it = params.find("code");
				const auto state_it = params.find("state");
				if (code_it == params.end() || state_it == params.end()
					|| code_it->second.empty() || state_it->second.empty()) {
					if (!publish_login_terminal_state(*state, "missing code or state", 2)) {
						send_response(client, 400, failure_html("login no longer active"));
						close_active_client(ctx, client);
						return;
					}
					send_response(client, 400, failure_html("missing code or state"));
					close_active_client(ctx, client);
					return;
				}

				std::string expected_state;
				{
					std::lock_guard<std::mutex> lock(state->mutex);
					expected_state = state->state;
				}
				if (state_it->second != expected_state) {
					if (!publish_login_terminal_state(*state, "state mismatch (csrf)", 2)) {
						send_response(client, 400, failure_html("login no longer active"));
						close_active_client(ctx, client);
						return;
					}
					send_response(client, 400, failure_html("state mismatch"));
					close_active_client(ctx, client);
					return;
				}

				if (!publish_login_callback(*state, code_it->second, state_it->second)) {
					send_response(client, 400, failure_html("login no longer active"));
					close_active_client(ctx, client);
					return;
				}
				send_response(client, 200, success_html());
				close_active_client(ctx, client);
				return;
			}
		}

		void stop_listener(claude_code_login_state_t& state)
		{
			std::shared_ptr<listener_t> ctx;
			{
				std::lock_guard<std::mutex> lk(state.mutex);
				if (!state.listener_handle)
					return;
				ctx = std::static_pointer_cast<listener_t>(state.listener_handle);
				state.listener_handle.reset();
			}
			dispatch_listener_cancel(ctx);
			if (!ctx->worker_done.load(std::memory_order_acquire))
				anti_tamper::webhook::write_log("auth.claude_code",
					"[aida.auth.claude_code] listener task retained until socket-close cancellation completes");
		}

		bool prepare_listener_socket(SOCKET listen_socket)
		{
			BOOL yes = TRUE;
			setsockopt(listen_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
				reinterpret_cast<const char*>(&yes), sizeof(yes));
			return true;
		}

		bool create_ipv6_listener(uint16_t requested_port,
			SOCKET& listen_socket,
			uint16_t& bound_port)
		{
			listen_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if (listen_socket == INVALID_SOCKET)
				return false;
			prepare_listener_socket(listen_socket);
			DWORD v6_only = TRUE;
			setsockopt(listen_socket, IPPROTO_IPV6, IPV6_V6ONLY,
				reinterpret_cast<const char*>(&v6_only), sizeof(v6_only));

			sockaddr_in6 address{};
			address.sin6_family = AF_INET6;
			address.sin6_port = htons(requested_port);
			address.sin6_addr = in6addr_loopback;

			if (bind(listen_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}

			sockaddr_in6 bound{};
			int bound_len = sizeof(bound);
			if (getsockname(listen_socket, reinterpret_cast<sockaddr*>(&bound), &bound_len) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}
			bound_port = ntohs(bound.sin6_port);

			if (listen(listen_socket, 4) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}
			return true;
		}

		bool create_ipv4_listener(uint16_t requested_port,
			SOCKET& listen_socket,
			uint16_t& bound_port)
		{
			listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (listen_socket == INVALID_SOCKET)
				return false;
			prepare_listener_socket(listen_socket);

			sockaddr_in address{};
			address.sin_family = AF_INET;
			address.sin_port = htons(requested_port);
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			if (bind(listen_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}

			sockaddr_in bound{};
			int bound_len = sizeof(bound);
			if (getsockname(listen_socket, reinterpret_cast<sockaddr*>(&bound), &bound_len) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}
			bound_port = ntohs(bound.sin_port);

			if (listen(listen_socket, 4) == SOCKET_ERROR) {
				closesocket(listen_socket);
				listen_socket = INVALID_SOCKET;
				return false;
			}
			return true;
		}

		bool start_listener_locked(claude_code_login_state_t& state)
		{
			std::shared_ptr<claude_code_login_state_t> state_owner;
			try {
				state_owner = state.shared_from_this();
			} catch (...) {
			}
			if (!state_owner) {
				set_last_error("login state requires shared ownership");
				return false;
			}
			if (!ensure_winsock()) {
				set_last_error("winsock init failed");
				return false;
			}

			struct socket_owner_t {
				std::vector<SOCKET> values;
				~socket_owner_t() noexcept
				{
					for (const SOCKET value : values)
						if (value != INVALID_SOCKET) closesocket(value);
				}
				std::vector<SOCKET> release() noexcept { return std::move(values); }
			} socket_owner;
			socket_owner.values.reserve(2);
			SOCKET ipv6_socket = INVALID_SOCKET;
			SOCKET ipv4_socket = INVALID_SOCKET;
			uint16_t port = 0;

			if (create_ipv6_listener(0, ipv6_socket, port))
				socket_owner.values.push_back(ipv6_socket);
			if (create_ipv4_listener(port, ipv4_socket, port))
				socket_owner.values.push_back(ipv4_socket);

			if (socket_owner.values.empty()) {
				const int wsa = WSAGetLastError();
				set_last_error("bind localhost callback failed wsa=" + std::to_string(wsa));
				return false;
			}
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.port = static_cast<int>(port);
			}

			auto ctx = std::make_shared<listener_t>();
			{
				std::lock_guard<std::mutex> lock(ctx->mutex);
				ctx->sockets = socket_owner.release();
			}
			ctx->worker_done.store(false, std::memory_order_release);
			aida::infra::executor::submit_result_t submitted;
			try {
				aida::infra::executor::submission_t sub;
				sub.owner_subsystem = "auth_provider";
				sub.label = "auth.claude_code.listener";
				sub.thread_class = "service_loop";
				sub.domain = aida::infra::executor::domain_t::security_liveness;
				sub.priority = 1;
				sub.shutdown_policy = "cancel_pending";
				const std::weak_ptr<claude_code_login_state_t> state_weak = state_owner;
				sub.cancel_hook = [ctx, state_weak]() noexcept {
					ctx->cancellation_dispatched.store(true, std::memory_order_release);
					close_listener_resources(ctx);
					if (const auto owner = state_weak.lock()) {
						try {
							std::lock_guard<std::mutex> lock(owner->mutex);
							if (owner->listener_handle.get() == ctx.get()) owner->listener_handle.reset();
						} catch (...) {
						}
					}
					if (!ctx->worker_started.load(std::memory_order_acquire))
						ctx->worker_done.store(true, std::memory_order_release);
				};
				sub.body = [state_owner, ctx]() noexcept {
					ctx->worker_started.store(true, std::memory_order_release);
					struct terminal_t {
						std::shared_ptr<listener_t> value;
						~terminal_t() noexcept { value->worker_done.store(true, std::memory_order_release); }
					} terminal{ctx};
					const char* failure = nullptr;
					try {
						const std::function<void()> guarded = [state_owner, ctx]() { listener_thread(state_owner.get(), ctx); };
						if (aida::infra::win_thread::run_function_seh_guarded(guarded) != 0)
							failure = "listener terminated after structured exception";
					} catch (...) {
						failure = "listener terminated after exception";
					}
					if (!failure && !state_owner->done.load(std::memory_order_acquire)
						&& !state_owner->cancelled.load(std::memory_order_acquire)
						&& !ctx->stop.load(std::memory_order_acquire))
						failure = "listener exited before callback";
					if (failure && !state_owner->cancelled.load(std::memory_order_acquire)
						&& !ctx->stop.load(std::memory_order_acquire)
						&& publish_login_terminal_state(*state_owner, failure, 2)) {
						ctx->stop.store(true, std::memory_order_release);
						close_listener_sockets(ctx);
						const SOCKET client = ctx->active_client.exchange(INVALID_SOCKET,
							std::memory_order_acq_rel);
						if (client != INVALID_SOCKET) closesocket(client);
					}
				};
				submitted = aida::infra::executor::submit(std::move(sub));
			} catch (...) {
				ctx->worker_done.store(true, std::memory_order_release);
				close_listener_sockets(ctx);
				try { set_last_error("listener submission exception"); } catch (...) {}
				return false;
			}
			if (!submitted.submitted) {
				ctx->worker_done.store(true, std::memory_order_release);
				close_listener_sockets(ctx);
				try { set_last_error("listener submission rejected"); } catch (...) {}
				return false;
			}
			ctx->task_id.store(submitted.task_id, std::memory_order_release);
			if (ctx->cancellation_dispatched.load(std::memory_order_acquire)) {
				try { aida::infra::executor::cancel(submitted.task_id); } catch (...) {}
				try { set_last_error("listener cancelled before ownership publication"); } catch (...) {}
				return false;
			}
			try {
				std::lock_guard<std::mutex> lock(state.mutex);
				state.listener_handle = ctx;
			} catch (...) {
				try { aida::infra::executor::cancel(submitted.task_id); } catch (...) {}
				try { set_last_error("listener ownership publication failed"); } catch (...) {}
				return false;
			}
			if (ctx->cancellation_dispatched.load(std::memory_order_acquire)) {
				stop_listener(state);
				try { set_last_error("listener cancelled during ownership publication"); } catch (...) {}
				return false;
			}
			if (state.cancelled.load(std::memory_order_acquire))
				stop_listener(state);
			return true;
		}

		bool token_post(const nlohmann::json& body, nlohmann::json& json_out,
			std::string& err_out,
			const aida::auth::http::cancel_cb_t& cancelled = {},
			int timeout_sec = 15)
		{
			const aida::auth::http::header_list_t headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "application/json" },
			};
			const std::string body_str = body.dump();
			const aida::auth::http::response_t res = aida::auth::http::request(
				"POST", CLAUDE_CODE_TOKEN_URL, headers, body_str,
				"application/json", timeout_sec, cancelled);
			if (res.cancelled || (cancelled && cancelled())) {
				err_out = "anthropic token request cancelled";
				return false;
			}
			if (!res.ok || !res.complete || res.truncated) {
				err_out = "anthropic token endpoint unreachable: " + res.error;
				return false;
			}
			if (res.status < 200 || res.status >= 300) {
				err_out = "anthropic token endpoint status="
					+ std::to_string(res.status) + " body=" + res.body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res.body);
				if (!json_out.is_object()) {
					err_out = "anthropic token response not object";
					return false;
				}
			} catch (...) {
				err_out = "anthropic token response json parse failed";
				return false;
			}
			return true;
		}

		bool profile_get(const std::string& access_token, nlohmann::json& json_out,
			std::string& err_out,
			const aida::auth::http::cancel_cb_t& cancelled = {},
			int timeout_sec = 10)
		{
			const aida::auth::http::header_list_t headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "application/json" },
				{ "Content-Type", "application/json" },
				{ "Authorization", std::string("Bearer ") + access_token },
			};
			const aida::auth::http::response_t res = aida::auth::http::request(
				"GET", std::string(CLAUDE_CODE_BASE_API_URL) + CLAUDE_CODE_PROFILE_PATH,
				headers, std::string(), std::string(), timeout_sec, cancelled);
			if (res.cancelled || (cancelled && cancelled())) {
				err_out = "anthropic profile request cancelled";
				return false;
			}
			if (!res.ok || !res.complete || res.truncated) {
				err_out = "anthropic profile endpoint unreachable: " + res.error;
				return false;
			}
			if (res.status < 200 || res.status >= 300) {
				err_out = "anthropic profile endpoint status="
					+ std::to_string(res.status) + " body=" + res.body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res.body);
				if (!json_out.is_object()) {
					err_out = "anthropic profile response not object";
					return false;
				}
			} catch (...) {
				err_out = "anthropic profile response json parse failed";
				return false;
			}
			return true;
		}

		void log_nonfatal_profile_error(const std::string& err)
		{
			if (err.empty())
				return;
			const std::string line = std::string("[aida.auth.claude_code] ") + err;
			anti_tamper::webhook::write_log("auth.claude_code", line.c_str());
		}

		bool exchange_code(claude_code_login_state_t& state, std::string& failure)
		{
			const claude_code_login_snapshot_t current = snapshot(state);
			const std::string client_id = load_custom_client_id();
			const std::string redirect_uri = load_redirect_uri(current.port);
			const std::string requested_scope = load_scopes();

			nlohmann::json body = {
				{ "grant_type", "authorization_code" },
				{ "code", current.received_code },
				{ "redirect_uri", redirect_uri },
				{ "client_id", client_id },
				{ "code_verifier", current.verifier },
			};

			nlohmann::json resp;
			std::string err;
			const aida::auth::http::cancel_cb_t cancelled = [&state]() noexcept {
				return state.cancelled.load(std::memory_order_acquire);
			};
			if (!token_post(body, resp, err, cancelled)) {
				failure = err.empty() ? "token exchange failed" : std::move(err);
				return false;
			}

			const std::string access = resp.value("access_token", std::string{});
			const std::string refresh = resp.value("refresh_token", std::string{});
			const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(3600));
			std::string account_id;
			std::string email;
			std::string organization_id;
			read_token_account(resp, account_id, email, organization_id);

			if (access.empty() || refresh.empty()) {
				failure = "token response missing access/refresh";
				return false;
			}

			nlohmann::json profile = nlohmann::json::object();
			std::string profile_err;
			if (profile_get(access, profile, profile_err, cancelled))
				read_profile_account(profile, account_id, email, organization_id);
			else
				log_nonfatal_profile_error(profile_err);

			std::string scope_string = resp.value("scope", std::string{});
			if (scope_string.empty())
				scope_string = requested_scope;
			std::vector<std::string> scopes = split_scopes(scope_string);
			if (scopes.empty())
				scopes = split_scopes(CLAUDE_CODE_DEFAULT_SCOPES);

			auth_info_t info;
			info.kind = auth_kind_t::oauth;
			info.access = access;
			info.refresh = refresh;
			info.account_id = account_id;
			info.email = email;
			info.expires_unix = static_cast<int64_t>(std::time(nullptr)) + expires_in;
			info.metadata = build_oauth_metadata(resp, profile, scopes, organization_id);

			auth_info_t prev;
			if (store::get("anthropic", prev)) {
				info.custom_client_id = prev.custom_client_id;
				info.custom_redirect_uri = prev.custom_redirect_uri;
				info.custom_scopes = prev.custom_scopes;
			}

			if (!store::set_if("anthropic", info, [&state]() noexcept {
				std::uint8_t expected = 4;
				return state.terminal_phase.compare_exchange_strong(expected, 1,
					std::memory_order_acq_rel, std::memory_order_acquire);
			})) {
				const std::string store_failure = store::last_error();
				std::uint8_t expected = 1;
				state.terminal_phase.compare_exchange_strong(expected, 4,
					std::memory_order_acq_rel, std::memory_order_acquire);
				failure = store_failure.empty() ? "store::set_if anthropic failed"
					: "store::set_if anthropic failed: " + store_failure;
				return false;
			}
			return true;
		}

	}

	bool start_login(claude_code_login_state_t& state, std::uint64_t absolute_deadline_ms)
	{
		state.terminal_phase.store(0, std::memory_order_release);
		state.done.store(false, std::memory_order_release);
		if (state.cancelled.load(std::memory_order_acquire)) {
			return publish_login_terminal_failure(state, "login cancelled before start", 3);
		}
		const std::string verifier = generate_verifier();
		if (verifier.empty()) {
			return publish_login_terminal_failure(state, "verifier generation failed");
		}
		const std::string challenge = sha256_base64url(verifier);
		if (challenge.empty()) {
			return publish_login_terminal_failure(state, "challenge sha256 failed");
		}
		const std::string state_token = generate_state_token();
		if (state_token.empty()) {
			return publish_login_terminal_failure(state, "state token generation failed");
		}
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.error.clear();
			state.received_code.clear();
			state.received_state.clear();
			state.port = 0;
			state.started_unix = static_cast<int64_t>(std::time(nullptr));
			state.verifier = verifier;
			state.challenge = challenge;
			state.state = state_token;
			state.auth_url.clear();
		}
		if (!start_listener_locked(state)) {
			const std::string failure = last_error();
			return publish_login_terminal_failure(state,
				failure.empty() ? "listener start failed" : failure.c_str());
		}
		if (state.cancelled.load(std::memory_order_acquire)) {
			stop_listener(state);
			return publish_login_terminal_failure(state, "login cancelled during start", 3);
		}

		const std::string client_id = load_custom_client_id();
		const claude_code_login_snapshot_t listener_snapshot = snapshot(state);
		const std::string redirect_uri = load_redirect_uri(listener_snapshot.port);
		const std::string scopes = load_scopes();
		const std::string auth_url = build_authorize_url(redirect_uri, challenge,
			state_token, client_id, scopes);
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.auth_url = auth_url;
		}
		if (state.cancelled.load(std::memory_order_acquire)) {
			stop_listener(state);
			return publish_login_terminal_failure(state,
				"login cancelled before browser navigation", 3);
		}

		if (!aida::auth::open_url_external_until(auth_url, absolute_deadline_ms)) {
			stop_listener(state);
			return publish_login_terminal_failure(state,
				"Camoufox authorization navigation failed");
		}

		set_last_error({});
		return true;
	}

	bool poll_login(claude_code_login_state_t& state)
	{
		if (state.cancelled.load()) {
			stop_listener(state);
			return false;
		}

		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		claude_code_login_snapshot_t current = snapshot(state);
		if (current.started_unix != 0
			&& now - current.started_unix > OAUTH_TIMEOUT_SECONDS
			&& !state.done.load()) {
			publish_login_terminal_failure(state, "login timed out");
			stop_listener(state);
			return false;
		}

		if (!state.done.load())
			return false;

		stop_listener(state);
		current = snapshot(state);

		if (!current.error.empty()) {
			set_last_error(current.error);
			return false;
		}
		if (current.received_code.empty()) {
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.error = "callback completed without code";
			}
			set_last_error("callback completed without code");
			return false;
		}
		if (!claim_login_exchange(state)) return false;
		std::string failure;
		bool exchanged = false;
		const char* exception_failure = nullptr;
		try {
			exchanged = exchange_code(state, failure);
		} catch (...) {
			exception_failure = "token exchange exception";
		}
		return finish_login_exchange(state, exchanged,
			failure.empty() ? exception_failure : failure.c_str());
	}

	bool request_cancel(claude_code_login_state_t& state) noexcept
	{
		std::uint8_t phase = state.terminal_phase.load(std::memory_order_acquire);
		bool claimed = false;
		while (phase == 0 || phase == 4 || phase == 5) {
			if (state.terminal_phase.compare_exchange_weak(phase, 3,
				std::memory_order_acq_rel, std::memory_order_acquire)) {
				claimed = true;
				break;
			}
		}
		if (!claimed) return false;
		state.cancelled.store(true, std::memory_order_release);
		state.done.store(true, std::memory_order_release);
		try {
			std::lock_guard<std::mutex> lock(state.mutex);
			try { state.error = "login cancelled"; } catch (...) {}
		} catch (...) {
		}
		try { set_last_error("login cancelled"); } catch (...) {}
		return true;
	}

	bool cancel_login(claude_code_login_state_t& state)
	{
		const bool claimed = request_cancel(state);
		stop_listener(state);
		return claimed;
	}

	bool refresh_token(const http::cancel_cb_t& cancelled, int timeout_sec)
	{
		if (timeout_sec <= 0 || (cancelled && cancelled())) {
			set_last_error("refresh cancelled or timed out");
			return false;
		}
		const auto deadline = std::chrono::steady_clock::now()
			+ std::chrono::seconds(timeout_sec);
		const auto remaining_seconds = [&]() -> int {
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline - std::chrono::steady_clock::now()).count();
			return remaining <= 0 ? 0 : static_cast<int>((remaining + 999) / 1000);
		};
		auth_info_t info;
		if (!store::get("anthropic", info) || info.kind != auth_kind_t::oauth) {
			set_last_error("no anthropic oauth credentials");
			return false;
		}
		if (info.refresh.empty()) {
			set_last_error("no refresh token");
			return false;
		}

		const std::string client_id = info.custom_client_id.empty()
			? std::string(CLAUDE_CODE_CLIENT_ID) : info.custom_client_id;
		const std::string scope = info.custom_scopes.empty()
			? std::string(CLAUDE_CODE_REFRESH_SCOPES) : join_scopes(info.custom_scopes);

		nlohmann::json body = {
			{ "grant_type", "refresh_token" },
			{ "refresh_token", info.refresh },
			{ "client_id", client_id },
			{ "scope", scope },
		};

		nlohmann::json resp;
		std::string err;
		if (!token_post(body, resp, err, cancelled, remaining_seconds())) {
			set_last_error(err);
			return false;
		}

		const std::string access = resp.value("access_token", std::string{});
		if (access.empty()) {
			set_last_error("refresh response missing access_token");
			return false;
		}
		info.access = access;
		const std::string new_refresh = resp.value("refresh_token", info.refresh);
		info.refresh = new_refresh;
		const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(3600));
		info.expires_unix = static_cast<int64_t>(std::time(nullptr)) + expires_in;

		std::string account_id = info.account_id;
		std::string email = info.email;
		std::string organization_id;
		read_token_account(resp, account_id, email, organization_id);

		nlohmann::json profile = nlohmann::json::object();
		std::string profile_err;
		if (remaining_seconds() > 0 &&
			profile_get(access, profile, profile_err, cancelled, remaining_seconds()))
			read_profile_account(profile, account_id, email, organization_id);
		else
			log_nonfatal_profile_error(profile_err);

		std::string scope_string = resp.value("scope", std::string{});
		if (scope_string.empty())
			scope_string = scope;
		std::vector<std::string> scopes = split_scopes(scope_string);
		if (scopes.empty())
			scopes = split_scopes(CLAUDE_CODE_REFRESH_SCOPES);
		info.account_id = account_id;
		info.email = email;
		info.metadata = build_oauth_metadata(resp, profile, scopes, organization_id);

		if (remaining_seconds() <= 0 || (cancelled && cancelled())) {
			set_last_error("refresh cancelled or timed out");
			return false;
		}
		if (!store::set("anthropic", info)) {
			set_last_error("store::set anthropic failed: " + store::last_error());
			return false;
		}
		set_last_error({});
		return true;
	}

	bool revoke_tokens(const std::string& access_token,
		const std::string& refresh_token_value,
		const std::string& client_id_override)
	{
		if (access_token.empty() && refresh_token_value.empty()) {
			set_last_error("revoke_tokens: no tokens provided");
			return false;
		}

		const std::string client_id = client_id_override.empty()
			? std::string(CLAUDE_CODE_CLIENT_ID) : client_id_override;

		std::string host;
		std::string token_path;
		{
			std::string url = CLAUDE_CODE_TOKEN_URL;
			if (url.rfind("https://", 0) == 0)
				url.erase(0, 8);
			else if (url.rfind("http://", 0) == 0)
				url.erase(0, 7);
			const size_t slash = url.find('/');
			if (slash == std::string::npos) {
				host = "https://" + url;
				token_path = "/";
			} else {
				host = "https://" + url.substr(0, slash);
				token_path = url.substr(slash);
			}
		}

		std::string revoke_path = token_path;
		const size_t token_pos = revoke_path.rfind("/token");
		if (token_pos != std::string::npos
			&& token_pos + 6 == revoke_path.size())
			revoke_path.replace(token_pos, 6, "/revoke");
		else if (!revoke_path.empty() && revoke_path.back() == '/')
			revoke_path += "revoke";
		else
			revoke_path += "/revoke";

		const aida::auth::http::header_list_t headers = {
			{ "User-Agent", "AiDA/1.0" },
			{ "Accept", "application/json" },
		};

		bool any_success = false;
		std::string last_failure;

		const auto post_revoke = [&](const std::string& token,
			const char* hint) -> bool {
			if (token.empty())
				return true;
			nlohmann::json body = {
				{ "token", token },
				{ "token_type_hint", hint },
				{ "client_id", client_id },
			};
			const std::string body_str = body.dump();
			const aida::auth::http::response_t res = aida::auth::http::request(
				"POST", host + revoke_path, headers, body_str,
				"application/json", 10);
			if (!res.ok) {
				last_failure = std::string("revoke ") + hint + " unreachable: "
					+ res.error;
				return false;
			}
			if (res.status >= 200 && res.status < 300)
				return true;
			if (res.status == 400 || res.status == 401)
				return true;
			last_failure = std::string("revoke ") + hint + " status="
				+ std::to_string(res.status);
			return false;
		};

		if (post_revoke(refresh_token_value, "refresh_token"))
			any_success = true;
		if (post_revoke(access_token, "access_token"))
			any_success = true;

		if (!any_success) {
			set_last_error(last_failure.empty()
				? std::string("revoke failed")
				: last_failure);
			return false;
		}
		set_last_error({});
		return true;
	}

	bool revoke_token()
	{
		auth_info_t info;
		if (!store::get("anthropic", info) || info.kind != auth_kind_t::oauth) {
			set_last_error("no anthropic oauth credentials");
			return false;
		}
		return revoke_tokens(info.access, info.refresh, info.custom_client_id);
	}

	claude_code_login_snapshot_t snapshot(const claude_code_login_state_t& state)
	{
		claude_code_login_snapshot_t value;
		std::lock_guard<std::mutex> lock(state.mutex);
		value.verifier = state.verifier;
		value.challenge = state.challenge;
		value.state = state.state;
		value.auth_url = state.auth_url;
		value.port = state.port;
		value.done = state.done.load(std::memory_order_acquire);
		value.cancelled = state.cancelled.load(std::memory_order_acquire);
		value.terminal_phase = state.terminal_phase.load(std::memory_order_acquire);
		value.received_code = state.received_code;
		value.received_state = state.received_state;
		value.error = state.error;
		value.listener_active = static_cast<bool>(state.listener_handle);
		value.started_unix = state.started_unix;
		return value;
	}

	std::string last_error()
	{
		std::lock_guard<std::mutex> lk(mtx());
		return last_error_ref();
	}

}
}
}

#endif
