#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "auth_copilot.hpp"

#include "auth_store.hpp"
#include "anti-tamper/webhook.hpp"

#include <windows.h>
#include <shellapi.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <mutex>
#include <string>

#pragma comment(lib, "Shell32.lib")

namespace aida {
namespace auth {
namespace copilot {

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
				const std::string line = std::string("[aida.auth.copilot] ") + text;
				anti_tamper::webhook::write_log("auth.copilot", line.c_str());
			}
		}

		std::string normalize_domain(const std::string& url)
		{
			std::string out = url;
			if (out.rfind("https://", 0) == 0)
				out.erase(0, 8);
			else if (out.rfind("http://", 0) == 0)
				out.erase(0, 7);
			while (!out.empty() && out.back() == '/')
				out.pop_back();
			return out;
		}

		std::string device_host(const std::optional<std::string>& enterprise_url)
		{
			if (enterprise_url.has_value() && !enterprise_url->empty())
				return std::string("https://") + normalize_domain(*enterprise_url);
			return "https://github.com";
		}

		std::string load_custom_client_id()
		{
			auth_info_t existing;
			if (store::get("github-copilot", existing) && !existing.custom_client_id.empty())
				return existing.custom_client_id;
			return COPILOT_CLIENT_ID;
		}

		bool open_browser(const std::string& url)
		{
			const int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(),
				static_cast<int>(url.size()), nullptr, 0);
			if (wlen <= 0)
				return false;
			std::wstring wurl(static_cast<size_t>(wlen), L'\0');
			MultiByteToWideChar(CP_UTF8, 0, url.c_str(), static_cast<int>(url.size()),
				wurl.data(), wlen);
			HINSTANCE rc = ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr,
				nullptr, SW_SHOWNORMAL);
			return reinterpret_cast<INT_PTR>(rc) > 32;
		}

		bool github_post(const std::string& host, const std::string& path,
			const std::string& json_body, nlohmann::json& json_out, std::string& err_out)
		{
			httplib::Client cli(host);
			cli.set_connection_timeout(30);
			cli.set_read_timeout(30);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers headers = {
				{ "Accept", "application/json" },
				{ "User-Agent", "GithubCopilot/1.155.0" },
				{ "Editor-Version", "AiDA/1.0" },
				{ "Editor-Plugin-Version", "copilot-aida/1.0.0" },
			};
			auto res = cli.Post(path.c_str(), headers, json_body, "application/json");
			if (!res) {
				err_out = "request to " + host + path + " failed: "
					+ httplib::to_string(res.error());
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				err_out = host + path + " status=" + std::to_string(res->status)
					+ " body=" + res->body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res->body);
				if (!json_out.is_object()) {
					err_out = "non-object response";
					return false;
				}
				return true;
			} catch (...) {
				err_out = "json parse failed: body=" + res->body.substr(0, 256);
				return false;
			}
		}

		bool fetch_internal_token(const std::string& long_lived_token,
			const std::optional<std::string>& enterprise_url,
			std::string& token_out, int64_t& expires_out, std::string& err_out)
		{
			std::string host;
			std::string path;
			if (enterprise_url.has_value() && !enterprise_url->empty()) {
				host = std::string("https://") + normalize_domain(*enterprise_url);
				path = "/api/v3/copilot_internal/v2/token";
			} else {
				host = "https://api.github.com";
				path = "/copilot_internal/v2/token";
			}

			httplib::Client cli(host);
			cli.set_connection_timeout(30);
			cli.set_read_timeout(30);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers headers = {
				{ "Authorization", "Bearer " + long_lived_token },
				{ "Accept", "application/json" },
				{ "User-Agent", "GithubCopilot/1.155.0" },
				{ "Editor-Version", "AiDA/1.0" },
				{ "Editor-Plugin-Version", "copilot-aida/1.0.0" },
			};
			auto res = cli.Get(path.c_str(), headers);
			if (!res) {
				err_out = host + path + " unreachable: "
					+ httplib::to_string(res.error());
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				err_out = host + path + " status="
					+ std::to_string(res->status) + " body=" + res->body.substr(0, 256);
				return false;
			}
			try {
				const auto j = nlohmann::json::parse(res->body);
				if (!j.is_object()) {
					err_out = host + path + " non-object response";
					return false;
				}
				token_out = j.value("token", std::string{});
				expires_out = j.value("expires_at", static_cast<int64_t>(0));
				if (token_out.empty()) {
					err_out = host + path + " missing token field";
					return false;
				}
				return true;
			} catch (...) {
				err_out = host + path + " json parse failed";
				return false;
			}
		}

	}

	bool start_login(copilot_login_state_t& state,
		std::optional<std::string> enterprise_url)
	{
		state.done.store(false);
		state.cancelled.store(false);
		state.error.clear();
		state.device_code.clear();
		state.user_code.clear();
		state.verification_uri.clear();
		state.enterprise_url = enterprise_url;
		state.last_poll_unix = 0;
		state.next_poll_unix = 0;

		const std::string client_id = load_custom_client_id();
		const std::string host = device_host(enterprise_url);

		nlohmann::json req_body = {
			{ "client_id", client_id },
			{ "scope", "read:user" },
		};

		nlohmann::json resp;
		std::string err;
		if (!github_post(host, "/login/device/code", req_body.dump(), resp, err)) {
			set_last_error(err);
			state.error = err;
			return false;
		}

		state.device_code = resp.value("device_code", std::string{});
		state.user_code = resp.value("user_code", std::string{});
		state.verification_uri = resp.value("verification_uri", std::string{});
		state.interval = resp.value("interval", 5);
		const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(900));
		state.expires_unix = static_cast<int64_t>(std::time(nullptr)) + expires_in;

		if (state.device_code.empty() || state.user_code.empty()
			|| state.verification_uri.empty()) {
			set_last_error("device code response incomplete");
			state.error = "device code response incomplete";
			return false;
		}

		state.next_poll_unix = static_cast<int64_t>(std::time(nullptr))
			+ state.interval + (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);

		if (!open_browser(state.verification_uri))
			anti_tamper::webhook::write_log("auth.copilot",
				"[aida.auth.copilot] ShellExecuteW open browser failed; user must open verification_uri manually");

		set_last_error({});
		return true;
	}

	bool poll_login(copilot_login_state_t& state)
	{
		if (state.cancelled.load())
			return false;

		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		if (state.expires_unix > 0 && now > state.expires_unix) {
			state.error = "device code expired";
			set_last_error(state.error);
			return false;
		}
		if (state.next_poll_unix > 0 && now < state.next_poll_unix)
			return false;

		state.last_poll_unix = now;

		const std::string client_id = load_custom_client_id();
		const std::string host = device_host(state.enterprise_url);

		nlohmann::json req_body = {
			{ "client_id", client_id },
			{ "device_code", state.device_code },
			{ "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
		};

		nlohmann::json resp;
		std::string err;
		if (!github_post(host, "/login/oauth/access_token", req_body.dump(), resp, err)) {
			state.next_poll_unix = now + state.interval + (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}

		const std::string access_token = resp.value("access_token", std::string{});
		if (!access_token.empty()) {
			std::string short_token;
			int64_t expires_at = 0;
			std::string fetch_err;
			if (!fetch_internal_token(access_token, state.enterprise_url,
					short_token, expires_at, fetch_err)) {
				set_last_error(fetch_err);
				state.error = fetch_err;
				state.done.store(true);
				return false;
			}

			auth_info_t info;
			info.kind = auth_kind_t::oauth;
			info.refresh = access_token;
			info.access = short_token;
			info.expires_unix = expires_at;
			if (state.enterprise_url.has_value() && !state.enterprise_url->empty())
				info.enterprise_url = normalize_domain(*state.enterprise_url);

			auth_info_t prev;
			if (store::get("github-copilot", prev)) {
				info.custom_client_id = prev.custom_client_id;
				info.custom_redirect_uri = prev.custom_redirect_uri;
				info.custom_scopes = prev.custom_scopes;
			}

			if (!store::set("github-copilot", info)) {
				set_last_error("store::set github-copilot failed: " + store::last_error());
				state.error = "store::set github-copilot failed";
				state.done.store(true);
				return false;
			}
			state.done.store(true);
			set_last_error({});
			return true;
		}

		const std::string err_field = resp.value("error", std::string{});
		if (err_field == "authorization_pending") {
			state.next_poll_unix = now + state.interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}
		if (err_field == "slow_down") {
			int new_interval = state.interval + 5;
			if (resp.contains("interval") && resp["interval"].is_number_integer())
				new_interval = resp["interval"].get<int>();
			state.interval = new_interval;
			state.next_poll_unix = now + new_interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}
		if (err_field == "expired_token" || err_field == "access_denied") {
			state.error = "device flow " + err_field;
			set_last_error(state.error);
			state.done.store(true);
			return false;
		}
		if (!err_field.empty()) {
			state.error = "device flow error: " + err_field;
			set_last_error(state.error);
			state.next_poll_unix = now + state.interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}
		state.next_poll_unix = now + state.interval
			+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
		return false;
	}

	bool cancel_login(copilot_login_state_t& state)
	{
		state.cancelled.store(true);
		state.done.store(true);
		return true;
	}

	bool refresh_token()
	{
		auth_info_t info;
		if (!store::get("github-copilot", info) || info.kind != auth_kind_t::oauth) {
			set_last_error("no github-copilot oauth credentials");
			return false;
		}
		if (info.refresh.empty()) {
			set_last_error("no long-lived github token");
			return false;
		}

		std::optional<std::string> enterprise;
		if (!info.enterprise_url.empty())
			enterprise = info.enterprise_url;

		std::string short_token;
		int64_t expires_at = 0;
		std::string err;
		if (!fetch_internal_token(info.refresh, enterprise, short_token, expires_at, err)) {
			set_last_error(err);
			return false;
		}
		info.access = short_token;
		info.expires_unix = expires_at;
		if (!store::set("github-copilot", info)) {
			set_last_error("store::set github-copilot failed: " + store::last_error());
			return false;
		}
		set_last_error({});
		return true;
	}

	bool revoke_tokens(const std::string& access_token,
		const std::string& refresh_token_value,
		const std::string& client_id_override)
	{
		(void)access_token;
		(void)refresh_token_value;
		(void)client_id_override;
		anti_tamper::webhook::write_log("auth.copilot",
			"[aida.auth.copilot] revoke_tokens: GitHub does not support per-token "
			"revocation without an OAuth app client secret; skipping server-side "
			"revoke and proceeding with local clear");
		set_last_error({});
		return true;
	}

	bool revoke_token()
	{
		auth_info_t info;
		if (!store::get("github-copilot", info) || info.kind != auth_kind_t::oauth) {
			set_last_error("no github-copilot oauth credentials");
			return false;
		}
		return revoke_tokens(info.access, info.refresh, info.custom_client_id);
	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(mtx());
		return last_error_ref();
	}

}
}
}
