#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_copilot.hpp"
#include "auth_store.hpp"
#include "auth_preview_platform.hpp"

#include <ctime>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace aida {
namespace auth {
namespace copilot {

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

}

bool start_login(copilot_login_state_t& state,
	std::optional<std::string> enterprise_url,
	std::uint64_t absolute_deadline_ms)
{
	if (state.cancelled.load(std::memory_order_acquire)) {
		set_preview_error("login cancelled before start");
		return false;
	}
	if (absolute_deadline_ms != 0 && aida::infra::executor::now_ms() >= absolute_deadline_ms) {
		set_preview_error("login startup timed out");
		return false;
	}
	const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
	{
		std::lock_guard<std::mutex> lock(state.mutex);
		state.device_code = "aida-studio-copilot-device";
		state.user_code = "AIDA-RE42";
		state.verification_uri = enterprise_url && !enterprise_url->empty()
			? *enterprise_url + "/login/device"
			: "https://github.com/login/device";
		state.interval = 1;
		state.expires_unix = now + 900;
		state.enterprise_url = std::move(enterprise_url);
		state.error.clear();
		state.last_poll_unix = 0;
		state.next_poll_unix = 0;
	}
	state.done.store(false, std::memory_order_release);
	set_preview_error({});
	return true;
}

bool poll_login(copilot_login_state_t& state)
{
	if (state.cancelled.load(std::memory_order_acquire)) {
		set_preview_error("login cancelled");
		return false;
	}
	const copilot_login_snapshot_t current = snapshot(state);
	if (current.device_code.empty()) {
		set_preview_error("device flow is not initialized");
		state.done.store(true, std::memory_order_release);
		return false;
	}
	auth_info_t info;
	info.kind = auth_kind_t::oauth;
	info.access = "aida-studio-copilot-access";
	info.refresh = "aida-studio-copilot-refresh";
	info.account_id = "studio-github";
	info.email = "reverse.engineer@preview.aida";
	info.expires_unix = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
	info.enterprise_url = current.enterprise_url.value_or(std::string{});
	info.metadata["preview_receipt"] = "oauth:github-copilot:accepted";
	if (!store::set("github-copilot", info)) {
		set_preview_error(store::last_error());
		state.done.store(true, std::memory_order_release);
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(state.mutex);
		state.last_poll_unix = static_cast<std::int64_t>(std::time(nullptr));
		state.next_poll_unix = state.last_poll_unix;
		state.error.clear();
	}
	state.done.store(true, std::memory_order_release);
	set_preview_error({});
	return true;
}

bool cancel_login(copilot_login_state_t& state)
{
	state.cancelled.store(true, std::memory_order_release);
	state.done.store(true, std::memory_order_release);
	return true;
}

bool refresh_token()
{
	auth_info_t info;
	if (!store::get("github-copilot", info) || info.kind != auth_kind_t::oauth) {
		set_preview_error("no github-copilot oauth credentials");
		return false;
	}
	info.access = "aida-studio-copilot-access-refreshed";
	info.expires_unix = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
	info.metadata["preview_receipt"] = "oauth:github-copilot:refreshed";
	const bool result = store::set("github-copilot", info);
	set_preview_error(result ? std::string{} : store::last_error());
	return result;
}

bool revoke_tokens(const std::string& access_token,
	const std::string& refresh_token_value,
	const std::string&)
{
	if (access_token.empty() && refresh_token_value.empty()) {
		set_preview_error("revoke_tokens: no tokens provided");
		return false;
	}
	set_preview_error({});
	return true;
}

bool revoke_token()
{
	auth_info_t info;
	if (!store::get("github-copilot", info) || info.kind != auth_kind_t::oauth) {
		set_preview_error("no github-copilot oauth credentials");
		return false;
	}
	return revoke_tokens(info.access, info.refresh, info.custom_client_id);
}

copilot_login_snapshot_t snapshot(const copilot_login_state_t& state)
{
	copilot_login_snapshot_t value;
	std::lock_guard<std::mutex> lock(state.mutex);
	value.device_code = state.device_code;
	value.user_code = state.user_code;
	value.verification_uri = state.verification_uri;
	value.interval = state.interval;
	value.expires_unix = state.expires_unix;
	value.enterprise_url = state.enterprise_url;
	value.done = state.done.load(std::memory_order_acquire);
	value.cancelled = state.cancelled.load(std::memory_order_acquire);
	value.error = state.error;
	value.last_poll_unix = state.last_poll_unix;
	value.next_poll_unix = state.next_poll_unix;
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
#include "auth_copilot.hpp"

#include "auth_store.hpp"
#include "auth_http.hpp"
#include "auth_browser_launch.hpp"
#include "anti-tamper/webhook.hpp"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <mutex>
#include <string>


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

		bool github_post(const std::string& host, const std::string& path,
			const std::string& json_body, nlohmann::json& json_out, std::string& err_out)
		{
			const aida::auth::http::header_list_t headers = {
				{ "Accept", "application/json" },
				{ "User-Agent", "GithubCopilot/1.155.0" },
				{ "Editor-Version", "AiDA/1.0" },
				{ "Editor-Plugin-Version", "copilot-aida/1.0.0" },
			};
			const aida::auth::http::response_t res = aida::auth::http::request(
				"POST", host + path, headers, json_body, "application/json", 30);
			if (!res.ok) {
				err_out = "request to " + host + path + " failed: " + res.error;
				return false;
			}
			if (res.status < 200 || res.status >= 300) {
				err_out = host + path + " status=" + std::to_string(res.status)
					+ " body=" + res.body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res.body);
				if (!json_out.is_object()) {
					err_out = "non-object response";
					return false;
				}
				return true;
			} catch (...) {
				err_out = "json parse failed: body=" + res.body.substr(0, 256);
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

			const aida::auth::http::header_list_t headers = {
				{ "Authorization", "token " + long_lived_token },
				{ "Accept", "application/json" },
				{ "User-Agent", "GithubCopilot/1.155.0" },
				{ "Editor-Version", "AiDA/1.0" },
				{ "Editor-Plugin-Version", "copilot-aida/1.0.0" },
			};
			const aida::auth::http::response_t res = aida::auth::http::request(
				"GET", host + path, headers, std::string(), std::string(), 30);
			if (!res.ok) {
				err_out = host + path + " unreachable: " + res.error;
				return false;
			}
			if (res.status < 200 || res.status >= 300) {
				err_out = host + path + " status="
					+ std::to_string(res.status) + " body=" + res.body.substr(0, 256);
				return false;
			}
			try {
				const auto j = nlohmann::json::parse(res.body);
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
		std::optional<std::string> enterprise_url,
		std::uint64_t absolute_deadline_ms)
	{
		state.done.store(false);
		if (state.cancelled.load(std::memory_order_acquire)) {
			set_last_error("login cancelled before start");
			return false;
		}
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.error.clear();
			state.device_code.clear();
			state.user_code.clear();
			state.verification_uri.clear();
			state.enterprise_url = enterprise_url;
			state.interval = 5;
			state.expires_unix = 0;
			state.last_poll_unix = 0;
			state.next_poll_unix = 0;
		}

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
			std::lock_guard<std::mutex> lock(state.mutex);
			state.error = err;
			return false;
		}
		if (state.cancelled.load(std::memory_order_acquire)) {
			set_last_error("login cancelled during device authorization");
			return false;
		}

		const std::string device_code = resp.value("device_code", std::string{});
		const std::string user_code = resp.value("user_code", std::string{});
		const std::string verification_uri = resp.value("verification_uri", std::string{});
		const int interval = (std::max)(1, resp.value("interval", 5));
		const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(900));
		const int64_t now = static_cast<int64_t>(std::time(nullptr));

		if (device_code.empty() || user_code.empty() || verification_uri.empty()) {
			set_last_error("device code response incomplete");
			std::lock_guard<std::mutex> lock(state.mutex);
			state.error = "device code response incomplete";
			return false;
		}
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.device_code = device_code;
			state.user_code = user_code;
			state.verification_uri = verification_uri;
			state.interval = interval;
			state.expires_unix = now + expires_in;
			state.next_poll_unix = now + interval + (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
		}
		if (state.cancelled.load(std::memory_order_acquire)) {
			set_last_error("login cancelled before browser navigation");
			return false;
		}

		if (!aida::auth::open_url_external_until(verification_uri, absolute_deadline_ms))
			anti_tamper::webhook::write_log("auth.copilot",
				"[aida.auth.copilot] open browser failed; user must open verification_uri manually");

		set_last_error({});
		return true;
	}

	bool poll_login(copilot_login_state_t& state)
	{
		if (state.cancelled.load())
			return false;

		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		copilot_login_snapshot_t current = snapshot(state);
		if (current.expires_unix > 0 && now > current.expires_unix) {
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.error = "device code expired";
			}
			set_last_error("device code expired");
			return false;
		}
		if (current.next_poll_unix > 0 && now < current.next_poll_unix)
			return false;

		{
			std::lock_guard<std::mutex> lock(state.mutex);
			if (state.cancelled.load(std::memory_order_acquire)) return false;
			state.last_poll_unix = now;
		}

		const std::string client_id = load_custom_client_id();
		const std::string host = device_host(current.enterprise_url);

		nlohmann::json req_body = {
			{ "client_id", client_id },
			{ "device_code", current.device_code },
			{ "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
		};

		nlohmann::json resp;
		std::string err;
		if (!github_post(host, "/login/oauth/access_token", req_body.dump(), resp, err)) {
			std::lock_guard<std::mutex> lock(state.mutex);
			state.next_poll_unix = now + state.interval + (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}

		const std::string access_token = resp.value("access_token", std::string{});
		if (!access_token.empty()) {
			std::string short_token;
			int64_t expires_at = 0;
			std::string fetch_err;
			if (!fetch_internal_token(access_token, current.enterprise_url,
					short_token, expires_at, fetch_err)) {
				set_last_error(fetch_err);
				std::lock_guard<std::mutex> lock(state.mutex);
				state.error = fetch_err;
				state.done.store(true);
				return false;
			}

			auth_info_t info;
			info.kind = auth_kind_t::oauth;
			info.refresh = access_token;
			info.access = short_token;
			info.expires_unix = expires_at;
			if (current.enterprise_url.has_value() && !current.enterprise_url->empty())
				info.enterprise_url = normalize_domain(*current.enterprise_url);

			auth_info_t prev;
			if (store::get("github-copilot", prev)) {
				info.custom_client_id = prev.custom_client_id;
				info.custom_redirect_uri = prev.custom_redirect_uri;
				info.custom_scopes = prev.custom_scopes;
			}

			if (!store::set("github-copilot", info)) {
				set_last_error("store::set github-copilot failed: " + store::last_error());
				std::lock_guard<std::mutex> lock(state.mutex);
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
			std::lock_guard<std::mutex> lock(state.mutex);
			state.next_poll_unix = now + state.interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}
		if (err_field == "slow_down") {
			int new_interval = current.interval + 5;
			if (resp.contains("interval") && resp["interval"].is_number_integer())
				new_interval = resp["interval"].get<int>();
			std::lock_guard<std::mutex> lock(state.mutex);
			state.interval = new_interval;
			state.next_poll_unix = now + new_interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			return false;
		}
		if (err_field == "expired_token" || err_field == "access_denied") {
			const std::string failure = "device flow " + err_field;
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.error = failure;
			}
			set_last_error(failure);
			state.done.store(true);
			return false;
		}
		if (!err_field.empty()) {
			const std::string failure = "device flow error: " + err_field;
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.error = failure;
				state.next_poll_unix = now + state.interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
			}
			set_last_error(failure);
			return false;
		}
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.next_poll_unix = now + state.interval
				+ (COPILOT_POLLING_SAFETY_MARGIN_MS / 1000);
		}
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

	copilot_login_snapshot_t snapshot(const copilot_login_state_t& state)
	{
		copilot_login_snapshot_t value;
		std::lock_guard<std::mutex> lock(state.mutex);
		value.device_code = state.device_code;
		value.user_code = state.user_code;
		value.verification_uri = state.verification_uri;
		value.interval = state.interval;
		value.expires_unix = state.expires_unix;
		value.enterprise_url = state.enterprise_url;
		value.done = state.done.load(std::memory_order_acquire);
		value.cancelled = state.cancelled.load(std::memory_order_acquire);
		value.error = state.error;
		value.last_poll_unix = state.last_poll_unix;
		value.next_poll_unix = state.next_poll_unix;
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
