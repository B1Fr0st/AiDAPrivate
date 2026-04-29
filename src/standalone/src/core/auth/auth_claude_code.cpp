#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "auth_claude_code.hpp"

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
#include <cctype>
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
			std::vector<SOCKET> sockets;
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
				if (std::isspace(static_cast<unsigned char>(ch))) {
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

		bool is_callback_target(const std::string& target)
		{
			const size_t query_pos = target.find('?');
			const std::string path = query_pos == std::string::npos
				? target : target.substr(0, query_pos);
			return path == "/callback" || path == "/auth/callback";
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
						const int hi = hex_digit(val[i + 1]);
						const int lo = hex_digit(val[i + 2]);
						if (hi >= 0 && lo >= 0) {
							decoded.push_back(static_cast<char>((hi << 4) | lo));
							i += 2;
						} else {
							decoded.push_back(val[i]);
						}
					} else {
						decoded.push_back(val[i]);
					}
				}
				out[key] = decoded;
				pos = amp + 1;
			}
			return out;
		}

		void listener_thread(claude_code_login_state_t* state, std::shared_ptr<listener_t> ctx)
		{
			while (!ctx->stop.load() && !state->cancelled.load()) {
				std::vector<WSAPOLLFD> poll_fds;
				poll_fds.reserve(ctx->sockets.size());
				for (SOCKET listen_socket : ctx->sockets) {
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

				if (!is_callback_target(target)) {
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

		void stop_listener(claude_code_login_state_t& state)
		{
			if (!state.listener_handle)
				return;
			std::unique_ptr<std::shared_ptr<listener_t>> holder(
				static_cast<std::shared_ptr<listener_t>*>(state.listener_handle));
			state.listener_handle = nullptr;
			(*holder)->stop.store(true);
			for (SOCKET& listen_socket : (*holder)->sockets) {
				if (listen_socket != INVALID_SOCKET) {
					closesocket(listen_socket);
					listen_socket = INVALID_SOCKET;
				}
			}
			if ((*holder)->worker.joinable())
				(*holder)->worker.join();
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
			if (!ensure_winsock()) {
				set_last_error("winsock init failed");
				return false;
			}

			std::vector<SOCKET> sockets;
			SOCKET ipv6_socket = INVALID_SOCKET;
			SOCKET ipv4_socket = INVALID_SOCKET;
			uint16_t port = 0;

			if (create_ipv6_listener(0, ipv6_socket, port))
				sockets.push_back(ipv6_socket);
			if (create_ipv4_listener(port, ipv4_socket, port))
				sockets.push_back(ipv4_socket);

			if (sockets.empty()) {
				const int wsa = WSAGetLastError();
				set_last_error("bind localhost callback failed wsa=" + std::to_string(wsa));
				return false;
			}
			state.port = static_cast<int>(port);

			auto ctx = std::make_shared<listener_t>();
			ctx->sockets = std::move(sockets);
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

		void parse_token_url(std::string& host_out, std::string& path_out)
		{
			std::string url = CLAUDE_CODE_TOKEN_URL;
			if (url.rfind("https://", 0) == 0)
				url.erase(0, 8);
			else if (url.rfind("http://", 0) == 0)
				url.erase(0, 7);
			const size_t slash = url.find('/');
			if (slash == std::string::npos) {
				host_out = "https://" + url;
				path_out = "/";
			} else {
				host_out = "https://" + url.substr(0, slash);
				path_out = url.substr(slash);
			}
		}

		bool token_post(const nlohmann::json& body, nlohmann::json& json_out, std::string& err_out)
		{
			std::string host;
			std::string path;
			parse_token_url(host, path);

			httplib::Client cli(host);
			cli.set_connection_timeout(15);
			cli.set_read_timeout(15);
			cli.set_write_timeout(15);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "application/json" },
			};
			const std::string body_str = body.dump();
			auto res = cli.Post(path.c_str(), headers, body_str, "application/json");
			if (!res) {
				err_out = "anthropic token endpoint unreachable: "
					+ httplib::to_string(res.error());
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				err_out = "anthropic token endpoint status="
					+ std::to_string(res->status) + " body=" + res->body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res->body);
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

		bool profile_get(const std::string& access_token, nlohmann::json& json_out, std::string& err_out)
		{
			httplib::Client cli(CLAUDE_CODE_BASE_API_URL);
			cli.set_connection_timeout(10);
			cli.set_read_timeout(10);
			cli.set_write_timeout(10);
			cli.set_follow_location(true);
			cli.enable_server_certificate_verification(true);

			httplib::Headers headers = {
				{ "User-Agent", "AiDA/1.0" },
				{ "Accept", "application/json" },
				{ "Content-Type", "application/json" },
				{ "Authorization", std::string("Bearer ") + access_token },
			};
			auto res = cli.Get(CLAUDE_CODE_PROFILE_PATH, headers);
			if (!res) {
				err_out = "anthropic profile endpoint unreachable: "
					+ httplib::to_string(res.error());
				return false;
			}
			if (res->status < 200 || res->status >= 300) {
				err_out = "anthropic profile endpoint status="
					+ std::to_string(res->status) + " body=" + res->body.substr(0, 256);
				return false;
			}
			try {
				json_out = nlohmann::json::parse(res->body);
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

		bool exchange_code(claude_code_login_state_t& state)
		{
			const std::string client_id = load_custom_client_id();
			const std::string redirect_uri = load_redirect_uri(state.port);
			const std::string requested_scope = load_scopes();

			nlohmann::json body = {
				{ "grant_type", "authorization_code" },
				{ "code", state.received_code },
				{ "redirect_uri", redirect_uri },
				{ "client_id", client_id },
				{ "code_verifier", state.verifier },
			};

			nlohmann::json resp;
			std::string err;
			if (!token_post(body, resp, err)) {
				set_last_error(err);
				state.error = err;
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
				set_last_error("token response missing access/refresh");
				state.error = "token response missing access/refresh";
				return false;
			}

			nlohmann::json profile = nlohmann::json::object();
			std::string profile_err;
			if (profile_get(access, profile, profile_err))
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

			if (!store::set("anthropic", info)) {
				set_last_error("store::set anthropic failed: " + store::last_error());
				state.error = "store::set anthropic failed";
				return false;
			}
			set_last_error({});
			return true;
		}

	}

	bool start_login(claude_code_login_state_t& state)
	{
		state.done.store(false);
		state.cancelled.store(false);
		state.error.clear();
		state.received_code.clear();
		state.received_state.clear();
		state.port = 0;
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
		const std::string scopes = load_scopes();
		state.auth_url = build_authorize_url(redirect_uri, state.challenge,
			state.state, client_id, scopes);

		if (!open_browser(state.auth_url))
			anti_tamper::webhook::write_log("auth.claude_code",
				"[aida.auth.claude_code] ShellExecuteW open browser failed; user must open auth_url manually");

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

	bool cancel_login(claude_code_login_state_t& state)
	{
		state.cancelled.store(true);
		stop_listener(state);
		return true;
	}

	bool refresh_token()
	{
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
		if (!token_post(body, resp, err)) {
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
			if (profile_get(access, profile, profile_err))
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

		if (!store::set("anthropic", info)) {
			set_last_error("store::set anthropic failed: " + store::last_error());
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
