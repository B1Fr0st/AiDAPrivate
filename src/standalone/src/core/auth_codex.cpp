#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "auth_codex.hpp"

#include "auth_store.hpp"
#include "anti-tamper/webhook.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Crypt32.lib")

namespace aida {
namespace auth {
namespace codex {

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
				const std::string line = std::string("[aida.auth.codex] ") + text;
				anti_tamper::webhook::write_log("auth.codex", line.c_str());
			}
		}

		struct listener_t {
			SOCKET sock = INVALID_SOCKET;
			std::thread worker;
			std::atomic<bool> stop{ false };
		};

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
			if (store::get("openai", existing) && !existing.custom_client_id.empty())
				return existing.custom_client_id;
			return CODEX_CLIENT_ID;
		}

		std::string load_redirect_uri(int port)
		{
			auth_info_t existing;
			if (store::get("openai", existing) && !existing.custom_redirect_uri.empty())
				return existing.custom_redirect_uri;
			return std::string("http://127.0.0.1:") + std::to_string(port) + "/auth/callback";
		}

		std::string build_authorize_url(const std::string& redirect_uri,
			const std::string& challenge,
			const std::string& state_token,
			const std::string& client_id)
		{
			std::string url = std::string(CODEX_ISSUER) + "/oauth/authorize?";
			url += "response_type=code";
			url += "&client_id=" + url_encode(client_id);
			url += "&redirect_uri=" + url_encode(redirect_uri);
			url += "&scope=" + url_encode("openid profile email offline_access");
			url += "&code_challenge=" + url_encode(challenge);
			url += "&code_challenge_method=S256";
			url += "&id_token_add_organizations=true";
			url += "&codex_cli_simplified_flow=true";
			url += "&state=" + url_encode(state_token);
			url += "&originator=aida";
			return url;
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

		std::map<std::string, std::string> parse_query(const std::string& query)
		{
			std::map<std::string, std::string> out;
			size_t pos = 0;
			while (pos < query.size()) {
				size_t amp = query.find('&', pos);
				if (amp == std::string::npos)
					amp = query.size();
				const std::string pair = query.substr(pos, amp - pos);
				const size_t eq = pair.find('=');
				std::string key = (eq == std::string::npos) ? pair : pair.substr(0, eq);
				std::string val = (eq == std::string::npos) ? std::string{} : pair.substr(eq + 1);
				std::string decoded;
				decoded.reserve(val.size());
				for (size_t i = 0; i < val.size(); ++i) {
					if (val[i] == '+') {
						decoded.push_back(' ');
					} else if (val[i] == '%' && i + 2 < val.size()) {
						const std::string hex = val.substr(i + 1, 2);
						decoded.push_back(static_cast<char>(std::stoi(hex, nullptr, 16)));
						i += 2;
					} else {
						decoded.push_back(val[i]);
					}
				}
				out[key] = decoded;
				pos = amp + 1;
			}
			return out;
		}

		void listener_thread(codex_login_state_t* state, std::shared_ptr<listener_t> ctx)
		{
			while (!ctx->stop.load() && !state->cancelled.load()) {
				WSAPOLLFD pfd{};
				pfd.fd = ctx->sock;
				pfd.events = POLLIN;
				int rc = WSAPoll(&pfd, 1, 250);
				if (rc <= 0)
					continue;

				sockaddr_storage cli{};
				int cli_len = sizeof(cli);
				SOCKET client = accept(ctx->sock, reinterpret_cast<sockaddr*>(&cli), &cli_len);
				if (client == INVALID_SOCKET)
					continue;

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

				const size_t first_space = raw.find(' ');
				const size_t second_space = (first_space == std::string::npos)
					? std::string::npos
					: raw.find(' ', first_space + 1);
				if (first_space == std::string::npos || second_space == std::string::npos) {
					send_response(client, 400, failure_html("malformed request"));
					closesocket(client);
					continue;
				}

				const std::string target = raw.substr(first_space + 1, second_space - first_space - 1);

				if (target.rfind("/auth/callback", 0) != 0) {
					send_response(client, 404, failure_html("not found"));
					closesocket(client);
					continue;
				}

				const size_t qpos = target.find('?');
				const std::string query_str = (qpos == std::string::npos)
					? std::string{} : target.substr(qpos + 1);
				const auto params = parse_query(query_str);

				const auto err_it = params.find("error");
				if (err_it != params.end()) {
					std::string detail = err_it->second;
					const auto desc_it = params.find("error_description");
					if (desc_it != params.end())
						detail += ": " + desc_it->second;
					state->error = detail;
					send_response(client, 200, failure_html(detail));
					closesocket(client);
					state->done.store(true);
					return;
				}

				const auto code_it = params.find("code");
				const auto state_it = params.find("state");
				if (code_it == params.end() || state_it == params.end()) {
					state->error = "missing code or state";
					send_response(client, 400, failure_html("missing code or state"));
					closesocket(client);
					state->done.store(true);
					return;
				}

				if (state_it->second != state->state) {
					state->error = "state mismatch (csrf)";
					send_response(client, 400, failure_html("state mismatch"));
					closesocket(client);
					state->done.store(true);
					return;
				}

				state->received_code = code_it->second;
				state->received_state = state_it->second;
				send_response(client, 200, success_html());
				closesocket(client);
				state->done.store(true);
				return;
			}
		}

		void stop_listener(codex_login_state_t& state)
		{
			if (!state.listener_handle)
				return;
			std::unique_ptr<std::shared_ptr<listener_t>> holder(
				static_cast<std::shared_ptr<listener_t>*>(state.listener_handle));
			state.listener_handle = nullptr;
			(*holder)->stop.store(true);
			if ((*holder)->sock != INVALID_SOCKET) {
				closesocket((*holder)->sock);
				(*holder)->sock = INVALID_SOCKET;
			}
			if ((*holder)->worker.joinable())
				(*holder)->worker.join();
		}

		bool start_listener_locked(codex_login_state_t& state)
		{
			if (!ensure_winsock()) {
				set_last_error("winsock init failed");
				return false;
			}

			SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET) {
				set_last_error("socket() failed wsa=" + std::to_string(WSAGetLastError()));
				return false;
			}

			BOOL yes = TRUE;
			setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
				reinterpret_cast<const char*>(&yes), sizeof(yes));

			sockaddr_in addr{};
			addr.sin_family = AF_INET;
			addr.sin_port = htons(static_cast<u_short>(state.port));
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
				const int wsa = WSAGetLastError();
				closesocket(s);
				set_last_error("bind 127.0.0.1:" + std::to_string(state.port)
					+ " failed wsa=" + std::to_string(wsa));
				return false;
			}

			if (listen(s, 4) == SOCKET_ERROR) {
				const int wsa = WSAGetLastError();
				closesocket(s);
				set_last_error("listen failed wsa=" + std::to_string(wsa));
				return false;
			}

			auto ctx = std::make_shared<listener_t>();
			ctx->sock = s;
			auto holder = std::make_unique<std::shared_ptr<listener_t>>(ctx);

			state.listener_handle = holder.release();
			ctx->worker = std::thread(listener_thread, &state, ctx);
			return true;
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

		bool jwt_parse_claims(const std::string& token, nlohmann::json& claims_out)
		{
			const size_t first_dot = token.find('.');
			if (first_dot == std::string::npos)
				return false;
			const size_t second_dot = token.find('.', first_dot + 1);
			if (second_dot == std::string::npos)
				return false;
			std::string payload = token.substr(first_dot + 1, second_dot - first_dot - 1);
			std::replace(payload.begin(), payload.end(), '-', '+');
			std::replace(payload.begin(), payload.end(), '_', '/');
			while (payload.size() % 4 != 0)
				payload.push_back('=');

			DWORD decoded_len = 0;
			if (!CryptStringToBinaryA(payload.c_str(), 0, CRYPT_STRING_BASE64,
					nullptr, &decoded_len, nullptr, nullptr))
				return false;
			std::vector<unsigned char> decoded(decoded_len);
			if (!CryptStringToBinaryA(payload.c_str(), 0, CRYPT_STRING_BASE64,
					decoded.data(), &decoded_len, nullptr, nullptr))
				return false;

			try {
				claims_out = nlohmann::json::parse(
					std::string(reinterpret_cast<char*>(decoded.data()), decoded_len));
				return claims_out.is_object();
			} catch (...) {
				return false;
			}
		}

		std::string extract_account_id(const nlohmann::json& claims)
		{
			if (!claims.is_object())
				return {};
			if (claims.contains("chatgpt_account_id") && claims["chatgpt_account_id"].is_string())
				return claims["chatgpt_account_id"].get<std::string>();
			if (claims.contains("https://api.openai.com/auth")
				&& claims["https://api.openai.com/auth"].is_object()) {
				const auto& nested = claims["https://api.openai.com/auth"];
				if (nested.contains("chatgpt_account_id")
					&& nested["chatgpt_account_id"].is_string())
					return nested["chatgpt_account_id"].get<std::string>();
			}
			if (claims.contains("organizations") && claims["organizations"].is_array()
				&& !claims["organizations"].empty()) {
				const auto& first = claims["organizations"].front();
				if (first.is_object() && first.contains("id") && first["id"].is_string())
					return first["id"].get<std::string>();
			}
			return {};
		}

		std::string extract_email(const nlohmann::json& claims)
		{
			if (!claims.is_object())
				return {};
			if (claims.contains("email") && claims["email"].is_string())
				return claims["email"].get<std::string>();
			return {};
		}

		bool token_post(const std::string& form_body, nlohmann::json& json_out, std::string& err_out)
		{
			httplib::Client cli(CODEX_ISSUER);
			cli.set_connection_timeout(30);
			cli.set_read_timeout(30);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "application/json" },
			};
			auto res = cli.Post("/oauth/token", headers, form_body,
				"application/x-www-form-urlencoded");
			if (!res) {
				err_out = "token endpoint unreachable: "
					+ httplib::to_string(res.error());
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				err_out = "token endpoint status=" + std::to_string(res->status)
					+ " body=" + res->body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res->body);
				if (!json_out.is_object()) {
					err_out = "token response not object";
					return false;
				}
			} catch (...) {
				err_out = "token response json parse failed";
				return false;
			}
			return true;
		}

		bool exchange_code(codex_login_state_t& state)
		{
			const std::string client_id = load_custom_client_id();
			const std::string redirect_uri = load_redirect_uri(state.port);

			std::string body = "grant_type=authorization_code";
			body += "&code=" + url_encode(state.received_code);
			body += "&redirect_uri=" + url_encode(redirect_uri);
			body += "&client_id=" + url_encode(client_id);
			body += "&code_verifier=" + url_encode(state.verifier);

			nlohmann::json resp;
			std::string err;
			if (!token_post(body, resp, err)) {
				set_last_error(err);
				state.error = err;
				return false;
			}

			const std::string access = resp.value("access_token", std::string{});
			const std::string refresh = resp.value("refresh_token", std::string{});
			const std::string id_token = resp.value("id_token", std::string{});
			const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(3600));

			if (access.empty() || refresh.empty()) {
				set_last_error("token response missing access/refresh");
				state.error = "token response missing access/refresh";
				return false;
			}

			std::string account_id;
			std::string email;
			if (!id_token.empty()) {
				nlohmann::json claims;
				if (jwt_parse_claims(id_token, claims)) {
					account_id = extract_account_id(claims);
					email = extract_email(claims);
				}
			}
			if (account_id.empty() && !access.empty()) {
				nlohmann::json claims;
				if (jwt_parse_claims(access, claims))
					account_id = extract_account_id(claims);
			}

			auth_info_t info;
			info.kind = auth_kind_t::oauth;
			info.access = access;
			info.refresh = refresh;
			info.account_id = account_id;
			info.email = email;
			info.expires_unix = static_cast<int64_t>(std::time(nullptr)) + expires_in;

			auth_info_t prev;
			if (store::get("openai", prev)) {
				info.custom_client_id = prev.custom_client_id;
				info.custom_redirect_uri = prev.custom_redirect_uri;
				info.custom_scopes = prev.custom_scopes;
			}

			if (!store::set("openai", info)) {
				set_last_error("store::set openai failed: " + store::last_error());
				state.error = "store::set openai failed";
				return false;
			}
			set_last_error({});
			return true;
		}

	}

	bool start_login(codex_login_state_t& state)
	{
		state.done.store(false);
		state.cancelled.store(false);
		state.error.clear();
		state.received_code.clear();
		state.received_state.clear();
		state.port = CODEX_OAUTH_PORT;
		state.started_unix = static_cast<int64_t>(std::time(nullptr));

		state.verifier = generate_verifier();
		if (state.verifier.empty()) {
			set_last_error("verifier generation failed");
			return false;
		}
		state.challenge = sha256_base64url(state.verifier);
		if (state.challenge.empty()) {
			set_last_error("challenge sha256 failed");
			return false;
		}
		state.state = generate_state_token();
		if (state.state.empty()) {
			set_last_error("state token generation failed");
			return false;
		}

		if (!start_listener_locked(state))
			return false;

		const std::string client_id = load_custom_client_id();
		const std::string redirect_uri = load_redirect_uri(state.port);
		state.auth_url = build_authorize_url(redirect_uri, state.challenge,
			state.state, client_id);

		if (!open_browser(state.auth_url))
			anti_tamper::webhook::write_log("auth.codex",
				"[aida.auth.codex] ShellExecuteW open browser failed; user must open auth_url manually");

		set_last_error({});
		return true;
	}

	bool poll_login(codex_login_state_t& state)
	{
		if (state.cancelled.load()) {
			stop_listener(state);
			return false;
		}

		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		if (state.started_unix != 0
			&& now - state.started_unix > OAUTH_TIMEOUT_SECONDS
			&& !state.done.load()) {
			state.error = "login timed out";
			set_last_error(state.error);
			stop_listener(state);
			return false;
		}

		if (!state.done.load())
			return false;

		stop_listener(state);

		if (!state.error.empty()) {
			set_last_error(state.error);
			return false;
		}
		if (state.received_code.empty()) {
			state.error = "callback completed without code";
			set_last_error(state.error);
			return false;
		}
		return exchange_code(state);
	}

	bool cancel_login(codex_login_state_t& state)
	{
		state.cancelled.store(true);
		stop_listener(state);
		return true;
	}

	bool refresh_token()
	{
		auth_info_t info;
		if (!store::get("openai", info) || info.kind != auth_kind_t::oauth) {
			set_last_error("no openai oauth credentials");
			return false;
		}
		if (info.refresh.empty()) {
			set_last_error("no refresh token");
			return false;
		}

		const std::string client_id = info.custom_client_id.empty()
			? std::string(CODEX_CLIENT_ID) : info.custom_client_id;

		std::string body = "grant_type=refresh_token";
		body += "&refresh_token=" + url_encode(info.refresh);
		body += "&client_id=" + url_encode(client_id);

		nlohmann::json resp;
		std::string err;
		if (!token_post(body, resp, err)) {
			set_last_error(err);
			return false;
		}

		const std::string access = resp.value("access_token", std::string{});
		if (access.empty()) {
			set_last_error("refresh response missing access_token");
			return false;
		}
		const std::string new_refresh = resp.value("refresh_token", info.refresh);
		const int64_t expires_in = resp.value("expires_in", static_cast<int64_t>(3600));
		const std::string id_token = resp.value("id_token", std::string{});

		info.access = access;
		info.refresh = new_refresh;
		info.expires_unix = static_cast<int64_t>(std::time(nullptr)) + expires_in;
		if (!id_token.empty()) {
			nlohmann::json claims;
			if (jwt_parse_claims(id_token, claims)) {
				const std::string acc = extract_account_id(claims);
				const std::string em = extract_email(claims);
				if (!acc.empty())
					info.account_id = acc;
				if (!em.empty())
					info.email = em;
			}
		}

		if (!store::set("openai", info)) {
			set_last_error("store::set openai failed: " + store::last_error());
			return false;
		}
		set_last_error({});
		return true;
	}

	const std::string& last_error()
	{
		std::lock_guard<std::mutex> lk(mtx());
		return last_error_ref();
	}

}
}
}
