#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "auth_http.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <winhttp.h>
#include <wincrypt.h>

#undef X509_NAME
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Crypt32.lib")

namespace aida {
namespace auth {
namespace http {

	namespace {

		struct parsed_url_t {
			bool https = true;
			std::string host;
			std::string path = "/";
			int port = 443;
		};

		struct resolved_addr_t {
			int family = 0;
			sockaddr_storage sa = {};
			int sa_len = 0;
		};

		struct dns_query_state_t {
			HANDLE event_handle = nullptr;
			DNS_QUERY_RESULT result = {};
			DNS_QUERY_CANCEL cancel = {};
		};

		struct winhttp_handle_t {
			HINTERNET handle = nullptr;
			winhttp_handle_t() = default;
			explicit winhttp_handle_t(HINTERNET h) : handle(h) {}
			~winhttp_handle_t() { if (handle) WinHttpCloseHandle(handle); }
			winhttp_handle_t(const winhttp_handle_t&) = delete;
			winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
			explicit operator bool() const { return handle != nullptr; }
		};

		std::wstring utf8_to_utf16(const std::string& text)
		{
			if (text.empty())
				return std::wstring();
			const int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
				static_cast<int>(text.size()), nullptr, 0);
			if (wlen <= 0)
				return std::wstring();
			std::wstring out(static_cast<size_t>(wlen), L'\0');
			MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
				static_cast<int>(text.size()), &out[0], wlen);
			return out;
		}

		bool parse_url(const std::string& url, parsed_url_t& out)
		{
			std::string work = url;
			if (work.rfind("https://", 0) == 0) {
				out.https = true;
				out.port = 443;
				work.erase(0, 8);
			} else if (work.rfind("http://", 0) == 0) {
				out.https = false;
				out.port = 80;
				work.erase(0, 7);
			} else {
				return false;
			}
			if (work.empty())
				return false;

			const size_t slash = work.find('/');
			if (slash == std::string::npos) {
				out.host = work;
				out.path = "/";
			} else {
				out.host = work.substr(0, slash);
				out.path = work.substr(slash);
			}

			const size_t colon = out.host.find(':');
			if (colon != std::string::npos) {
				out.port = atoi(out.host.c_str() + colon + 1);
				out.host = out.host.substr(0, colon);
			}
			return !out.host.empty() && out.port > 0;
		}

		int ensure_winsock()
		{
			static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
			static int result = WSASYSNOTREADY;
			BOOL pending = FALSE;
			if (InitOnceBeginInitialize(&once, 0, &pending, nullptr) && pending) {
				WSADATA wsa = {};
				result = WSAStartup(MAKEWORD(2, 2), &wsa);
				InitOnceComplete(&once, 0, nullptr);
			}
			return result;
		}

		void append_addrinfoex_results(PADDRINFOEXW info,
			std::vector<resolved_addr_t>& results)
		{
			for (PADDRINFOEXW it = info; it != nullptr; it = it->ai_next) {
				if (it->ai_family != AF_INET && it->ai_family != AF_INET6)
					continue;
				if (!it->ai_addr || it->ai_addrlen == 0)
					continue;
				resolved_addr_t addr;
				addr.family = it->ai_family;
				const size_t copy_len = it->ai_addrlen <= sizeof(addr.sa)
					? it->ai_addrlen : sizeof(addr.sa);
				addr.sa_len = static_cast<int>(copy_len);
				memcpy(&addr.sa, it->ai_addr, copy_len);
				results.push_back(addr);
			}
		}

		void append_dns_records(PDNS_RECORD records, WORD query_type, int port,
			std::vector<resolved_addr_t>& results)
		{
			for (PDNS_RECORD rec = records; rec != nullptr; rec = rec->pNext) {
				if (rec->wType != query_type)
					continue;
				if (query_type == DNS_TYPE_A) {
					resolved_addr_t addr;
					addr.family = AF_INET;
					addr.sa_len = static_cast<int>(sizeof(sockaddr_in));
					sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&addr.sa);
					sin->sin_family = AF_INET;
					sin->sin_port = htons(static_cast<u_short>(port));
					sin->sin_addr.S_un.S_addr = rec->Data.A.IpAddress;
					results.push_back(addr);
				} else if (query_type == DNS_TYPE_AAAA) {
					resolved_addr_t addr;
					addr.family = AF_INET6;
					addr.sa_len = static_cast<int>(sizeof(sockaddr_in6));
					sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(&addr.sa);
					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = htons(static_cast<u_short>(port));
					memcpy(&sin6->sin6_addr, &rec->Data.AAAA.Ip6Address,
						sizeof(sin6->sin6_addr));
					results.push_back(addr);
				}
			}
		}

		void WINAPI dns_query_completion(void* context, PDNS_QUERY_RESULT)
		{
			dns_query_state_t* state = static_cast<dns_query_state_t*>(context);
			if (state && state->event_handle)
				SetEvent(state->event_handle);
		}

		DNS_STATUS query_dns_records_bounded(const std::wstring& host_w, WORD query_type,
			int timeout_ms, PDNS_RECORD* records_out, bool& timed_out)
		{
			timed_out = false;
			*records_out = nullptr;

			std::unique_ptr<dns_query_state_t> state = std::make_unique<dns_query_state_t>();
			state->event_handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			if (!state->event_handle)
				return static_cast<DNS_STATUS>(GetLastError());
			state->result.Version = DNS_QUERY_RESULTS_VERSION1;

			DNS_QUERY_REQUEST request = {};
			request.Version = DNS_QUERY_REQUEST_VERSION1;
			request.QueryName = host_w.c_str();
			request.QueryType = query_type;
			request.QueryOptions = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE
				| DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST;
			request.pQueryContext = state.get();
			request.pQueryCompletionCallback = dns_query_completion;

			DNS_STATUS status = DnsQueryEx(&request, &state->result, &state->cancel);
			if (status == DNS_REQUEST_PENDING) {
				const DWORD wait_ms = static_cast<DWORD>(timeout_ms > 1 ? timeout_ms : 1);
				const DWORD wait_rc = WaitForSingleObject(state->event_handle, wait_ms);
				if (wait_rc == WAIT_TIMEOUT) {
					timed_out = true;
					DnsCancelQuery(&state->cancel);
					const DWORD cancel_wait = WaitForSingleObject(state->event_handle, 1000);
					if (cancel_wait != WAIT_OBJECT_0) {
						static_cast<void>(state.release());
						return ERROR_TIMEOUT;
					}
				} else if (wait_rc != WAIT_OBJECT_0) {
					CloseHandle(state->event_handle);
					return static_cast<DNS_STATUS>(GetLastError());
				}
				status = state->result.QueryStatus;
			} else if (state->result.QueryStatus != 0) {
				status = state->result.QueryStatus;
			}

			if (status == 0 && state->result.pQueryRecords) {
				*records_out = state->result.pQueryRecords;
				state->result.pQueryRecords = nullptr;
			}
			if (state->result.pQueryRecords) {
				DnsRecordListFree(state->result.pQueryRecords, DnsFreeRecordList);
				state->result.pQueryRecords = nullptr;
			}
			CloseHandle(state->event_handle);
			return status;
		}

		std::vector<resolved_addr_t> resolve_host_addrs(const std::string& host,
			int port, int timeout_ms, std::string& diag_out)
		{
			std::vector<resolved_addr_t> results;
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%d", port);
			char gai_buf[160] = {};

			const int total_budget_ms = timeout_ms > 500 ? timeout_ms : 500;
			const auto deadline = std::chrono::steady_clock::now()
				+ std::chrono::milliseconds(total_budget_ms);
			auto remaining_ms = [&]() -> int {
				const auto now = std::chrono::steady_clock::now();
				if (now >= deadline)
					return 0;
				return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
					deadline - now).count());
			};

			const std::wstring host_w = utf8_to_utf16(host);
			const std::wstring port_w = utf8_to_utf16(port_str);

			{
				ADDRINFOEXW hints = {};
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				PADDRINFOEXW gai_res = nullptr;
				const int gai_budget_ms = remaining_ms() > 250 ? remaining_ms() : 250;
				timeval gai_timeout = {};
				gai_timeout.tv_sec = gai_budget_ms / 1000;
				gai_timeout.tv_usec = (gai_budget_ms % 1000) * 1000;
				const int gai_rc = GetAddrInfoExW(host_w.c_str(), port_w.c_str(), NS_DNS,
					nullptr, &hints, &gai_res, &gai_timeout, nullptr, nullptr, nullptr);
				if (gai_rc == 0 && gai_res) {
					append_addrinfoex_results(gai_res, results);
					FreeAddrInfoExW(gai_res);
				} else {
					snprintf(gai_buf, sizeof(gai_buf), "GetAddrInfoExW rc=%d wsa=%lu",
						gai_rc, static_cast<unsigned long>(WSAGetLastError()));
					if (gai_res)
						FreeAddrInfoExW(gai_res);
				}
			}

			if (!results.empty())
				return results;

			char dns_buf[160] = {};
			bool a_timeout = false;
			PDNS_RECORD records_a = nullptr;
			const int budget_a = remaining_ms() / 2;
			const DNS_STATUS status_a = query_dns_records_bounded(host_w, DNS_TYPE_A,
				budget_a > 1 ? budget_a : 1, &records_a, a_timeout);
			if (status_a == 0 && records_a) {
				append_dns_records(records_a, DNS_TYPE_A, port, results);
				DnsRecordListFree(records_a, DnsFreeRecordList);
			}

			bool aaaa_timeout = false;
			PDNS_RECORD records_aaaa = nullptr;
			const int budget_aaaa = remaining_ms();
			const DNS_STATUS status_aaaa = query_dns_records_bounded(host_w, DNS_TYPE_AAAA,
				budget_aaaa > 1 ? budget_aaaa : 1, &records_aaaa, aaaa_timeout);
			if (status_aaaa == 0 && records_aaaa) {
				append_dns_records(records_aaaa, DNS_TYPE_AAAA, port, results);
				DnsRecordListFree(records_aaaa, DnsFreeRecordList);
			}

			if (results.empty()) {
				snprintf(dns_buf, sizeof(dns_buf), "DnsQueryEx A=%lu%s AAAA=%lu%s",
					static_cast<unsigned long>(status_a), a_timeout ? ":timeout" : "",
					static_cast<unsigned long>(status_aaaa), aaaa_timeout ? ":timeout" : "");
				diag_out.clear();
				if (gai_buf[0] != '\0')
					diag_out += gai_buf;
				if (gai_buf[0] != '\0' && dns_buf[0] != '\0')
					diag_out += "; ";
				if (dns_buf[0] != '\0')
					diag_out += dns_buf;
				if (diag_out.empty())
					diag_out = "no addresses returned";
			}
			return results;
		}

		void parse_http_response(const std::string& raw, response_t& out)
		{
			const size_t header_end = raw.find("\r\n\r\n");
			if (header_end == std::string::npos) {
				out.error = "malformed HTTP response (no header terminator)";
				return;
			}
			const size_t line_end = raw.find("\r\n");
			const std::string status_line = raw.substr(0, line_end);
			const size_t sp = status_line.find(' ');
			if (sp != std::string::npos)
				out.status = atoi(status_line.c_str() + sp + 1);
			if (out.status <= 0) {
				out.error = "malformed HTTP status line";
				return;
			}

			const std::string headers_str = raw.substr(0, header_end);
			std::string body_raw = raw.substr(header_end + 4);

			std::string headers_lower = headers_str;
			for (char& c : headers_lower)
				c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

			if (headers_lower.find("transfer-encoding: chunked") != std::string::npos) {
				std::string decoded;
				size_t pos = 0;
				while (pos < body_raw.size()) {
					const size_t crlf = body_raw.find("\r\n", pos);
					if (crlf == std::string::npos)
						break;
					const long chunk_size = strtol(body_raw.c_str() + pos, nullptr, 16);
					if (chunk_size <= 0)
						break;
					pos = crlf + 2;
					if (pos + static_cast<size_t>(chunk_size) > body_raw.size())
						break;
					decoded.append(body_raw, pos, static_cast<size_t>(chunk_size));
					pos += static_cast<size_t>(chunk_size) + 2;
				}
				out.body = std::move(decoded);
			} else {
				out.body = std::move(body_raw);
			}
			out.ok = true;
			out.error.clear();
		}

		void load_windows_root_certs(SSL_CTX* ctx)
		{
			X509_STORE* ossl_store = SSL_CTX_get_cert_store(ctx);
			if (!ossl_store)
				return;
			const wchar_t* store_names[] = { L"ROOT", L"CA" };
			for (const wchar_t* name : store_names) {
				HCERTSTORE win_store = CertOpenSystemStoreW(0, name);
				if (!win_store)
					continue;
				PCCERT_CONTEXT cert = nullptr;
				while ((cert = CertEnumCertificatesInStore(win_store, cert)) != nullptr) {
					const unsigned char* encoded = cert->pbCertEncoded;
					X509* x = d2i_X509(nullptr, &encoded,
						static_cast<long>(cert->cbCertEncoded));
					if (x) {
						X509_STORE_add_cert(ossl_store, x);
						X509_free(x);
					}
				}
				CertCloseStore(win_store, 0);
			}
		}

		response_t winhttp_request(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, int timeout_sec)
		{
			response_t out;

			const std::wstring host_w = utf8_to_utf16(pu.host);
			const std::wstring path_w = utf8_to_utf16(pu.path.empty()
				? std::string("/") : pu.path);
			const std::wstring verb_w = utf8_to_utf16(std::string(verb));

			HINTERNET raw_session = WinHttpOpen(L"AiDA/1.0",
				WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
				WINHTTP_NO_PROXY_BYPASS, 0);
			if (!raw_session)
				raw_session = WinHttpOpen(L"AiDA/1.0",
					WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
					WINHTTP_NO_PROXY_BYPASS, 0);
			winhttp_handle_t session(raw_session);
			if (!session) {
				out.error = "WinHttpOpen failed err=" + std::to_string(GetLastError());
				return out;
			}

			const int ms = (timeout_sec > 0 ? timeout_sec : 30) * 1000;
			WinHttpSetTimeouts(session.handle, ms, ms, ms, ms);

			winhttp_handle_t connection(WinHttpConnect(session.handle, host_w.c_str(),
				static_cast<INTERNET_PORT>(pu.port), 0));
			if (!connection) {
				out.error = "WinHttpConnect failed err=" + std::to_string(GetLastError());
				return out;
			}

			const DWORD req_flags = pu.https ? WINHTTP_FLAG_SECURE : 0u;
			winhttp_handle_t request_handle(WinHttpOpenRequest(connection.handle,
				verb_w.c_str(), path_w.c_str(), nullptr, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags));
			if (!request_handle) {
				out.error = "WinHttpOpenRequest failed err="
					+ std::to_string(GetLastError());
				return out;
			}

			std::wstring all_headers;
			if (!content_type.empty())
				all_headers += L"Content-Type: " + utf8_to_utf16(content_type) + L"\r\n";
			for (const auto& kv : headers)
				all_headers += utf8_to_utf16(kv.first) + L": "
					+ utf8_to_utf16(kv.second) + L"\r\n";

			void* body_ptr = body.empty()
				? nullptr
				: const_cast<void*>(static_cast<const void*>(body.data()));
			const DWORD body_len = static_cast<DWORD>(body.size());
			const DWORD headers_len = all_headers.empty()
				? 0u : static_cast<DWORD>(-1);

			if (!WinHttpSendRequest(request_handle.handle,
					all_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
						: all_headers.c_str(),
					headers_len, body_ptr, body_len, body_len, 0)) {
				out.error = "WinHttpSendRequest failed err="
					+ std::to_string(GetLastError());
				return out;
			}

			if (!WinHttpReceiveResponse(request_handle.handle, nullptr)) {
				out.error = "WinHttpReceiveResponse failed err="
					+ std::to_string(GetLastError());
				return out;
			}

			DWORD status_code = 0;
			DWORD status_size = sizeof(status_code);
			if (!WinHttpQueryHeaders(request_handle.handle,
					WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
					WINHTTP_NO_HEADER_INDEX)) {
				out.error = "WinHttpQueryHeaders failed err="
					+ std::to_string(GetLastError());
				return out;
			}
			out.status = static_cast<int>(status_code);

			bool body_complete = true;
			for (;;) {
				DWORD available = 0;
				if (!WinHttpQueryDataAvailable(request_handle.handle, &available)) {
					body_complete = false;
					out.error = "WinHttpQueryDataAvailable failed err="
						+ std::to_string(GetLastError());
					break;
				}
				if (available == 0)
					break;
				std::string chunk(available, '\0');
				DWORD read = 0;
				if (!WinHttpReadData(request_handle.handle, &chunk[0], available, &read)) {
					body_complete = false;
					out.error = "WinHttpReadData failed err="
						+ std::to_string(GetLastError());
					break;
				}
				if (read == 0)
					break;
				out.body.append(chunk.data(), read);
				if (out.body.size() > 8u * 1024u * 1024u)
					break;
			}

			if (out.status > 0 && body_complete) {
				out.ok = true;
				out.error.clear();
			} else if (out.error.empty()) {
				out.error = "winhttp incomplete response";
			}
			return out;
		}

		response_t raw_socket_request(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, int timeout_sec)
		{
			response_t out;

			const int wsa = ensure_winsock();
			if (wsa != 0) {
				out.error = "WSAStartup failed rc=" + std::to_string(wsa);
				return out;
			}

			const int effective_timeout = timeout_sec > 0 ? timeout_sec : 30;
			const int resolve_budget = (effective_timeout * 1000 / 2) > 2000
				? (effective_timeout * 1000 / 2) : 2000;
			std::string resolve_diag;
			std::vector<resolved_addr_t> candidates =
				resolve_host_addrs(pu.host, pu.port, resolve_budget, resolve_diag);
			if (candidates.empty()) {
				out.error = "DNS resolution failed for " + pu.host
					+ " (" + resolve_diag + ")";
				return out;
			}

			std::stable_sort(candidates.begin(), candidates.end(),
				[](const resolved_addr_t& a, const resolved_addr_t& b) {
					return (a.family == AF_INET) && (b.family != AF_INET);
				});

			const auto deadline = std::chrono::steady_clock::now()
				+ std::chrono::seconds(effective_timeout);
			auto remaining_ms = [&]() -> int {
				const auto now = std::chrono::steady_clock::now();
				if (now >= deadline)
					return 0;
				return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
					deadline - now).count());
			};

			SOCKET sock = INVALID_SOCKET;
			std::string connect_errors;
			for (const resolved_addr_t& addr : candidates) {
				if (remaining_ms() <= 0) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "deadline_before_connect";
					break;
				}
				SOCKET s = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
				if (s == INVALID_SOCKET) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "socket wsa=" + std::to_string(WSAGetLastError());
					continue;
				}
				u_long nonblocking = 1;
				ioctlsocket(s, FIONBIO, &nonblocking);
				const int cr = ::connect(s,
					reinterpret_cast<const sockaddr*>(&addr.sa), addr.sa_len);
				if (cr == 0) {
					sock = s;
					break;
				}
				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "connect wsa="
						+ std::to_string(WSAGetLastError());
					closesocket(s);
					continue;
				}
				WSAPOLLFD pfd = {};
				pfd.fd = s;
				pfd.events = POLLOUT;
				const int pr = WSAPoll(&pfd, 1, remaining_ms());
				if (pr <= 0) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += pr == 0 ? "connect_timeout"
						: ("connect_poll wsa=" + std::to_string(WSAGetLastError()));
					closesocket(s);
					continue;
				}
				int so_error = 0;
				int so_len = static_cast<int>(sizeof(so_error));
				if (getsockopt(s, SOL_SOCKET, SO_ERROR,
						reinterpret_cast<char*>(&so_error), &so_len) != 0
					|| so_error != 0) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "so_error=" + std::to_string(so_error);
					closesocket(s);
					continue;
				}
				sock = s;
				break;
			}
			if (sock == INVALID_SOCKET) {
				out.error = "connect failed for " + pu.host + " ("
					+ (connect_errors.empty() ? std::string("no_candidates")
						: connect_errors) + ")";
				return out;
			}

			SSL_CTX* ctx = nullptr;
			SSL* ssl = nullptr;
			auto cleanup = [&]() {
				if (ssl) {
					SSL_shutdown(ssl);
					SSL_free(ssl);
					ssl = nullptr;
				}
				if (ctx) {
					SSL_CTX_free(ctx);
					ctx = nullptr;
				}
				if (sock != INVALID_SOCKET) {
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			};

			if (pu.https) {
				ctx = SSL_CTX_new(TLS_client_method());
				if (!ctx) {
					out.error = "SSL_CTX_new failed";
					cleanup();
					return out;
				}
				SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
					| SSL_OP_NO_COMPRESSION);
				SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
				load_windows_root_certs(ctx);

				ssl = SSL_new(ctx);
				if (!ssl) {
					out.error = "SSL_new failed";
					cleanup();
					return out;
				}
				SSL_set_fd(ssl, static_cast<int>(sock));
				SSL_set_tlsext_host_name(ssl, pu.host.c_str());
				X509_VERIFY_PARAM* verify_param = SSL_get0_param(ssl);
				if (!verify_param
					|| X509_VERIFY_PARAM_set1_host(verify_param,
						pu.host.c_str(), pu.host.size()) != 1) {
					out.error = "set verify host failed";
					cleanup();
					return out;
				}
				for (;;) {
					const int rc = SSL_connect(ssl);
					if (rc == 1)
						break;
					const int err = SSL_get_error(ssl, rc);
					short events;
					if (err == SSL_ERROR_WANT_READ) {
						events = POLLIN;
					} else if (err == SSL_ERROR_WANT_WRITE) {
						events = POLLOUT;
					} else {
						const long verify_rc = SSL_get_verify_result(ssl);
						out.error = "TLS handshake failed err="
							+ std::to_string(err) + " verify="
							+ std::to_string(verify_rc);
						cleanup();
						return out;
					}
					WSAPOLLFD pfd = {};
					pfd.fd = sock;
					pfd.events = events;
					const int pr = WSAPoll(&pfd, 1, remaining_ms());
					if (pr <= 0) {
						out.error = pr == 0 ? "TLS handshake timeout"
							: "TLS handshake poll error";
						cleanup();
						return out;
					}
				}
				const long verify_rc = SSL_get_verify_result(ssl);
				if (verify_rc != X509_V_OK) {
					out.error = "TLS certificate verification failed rc="
						+ std::to_string(verify_rc);
					cleanup();
					return out;
				}
			}

			std::string req;
			req += verb;
			req += " ";
			req += pu.path.empty() ? std::string("/") : pu.path;
			req += " HTTP/1.1\r\n";
			req += "Host: " + pu.host + "\r\n";
			req += "Connection: close\r\n";
			req += "Accept-Encoding: identity\r\n";
			if (!content_type.empty())
				req += "Content-Type: " + content_type + "\r\n";
			if (!body.empty())
				req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
			for (const auto& kv : headers)
				req += kv.first + ": " + kv.second + "\r\n";
			req += "\r\n";
			req += body;

			auto poll_sock = [&](short events, int wait_ms) -> int {
				WSAPOLLFD pfd = {};
				pfd.fd = sock;
				pfd.events = events;
				return WSAPoll(&pfd, 1, wait_ms > 0 ? wait_ms : 0);
			};

			{
				const char* data = req.data();
				int len = static_cast<int>(req.size());
				bool send_ok = true;
				while (len > 0) {
					int n;
					if (ssl)
						n = SSL_write(ssl, data, len);
					else
						n = ::send(sock, data, len, 0);
					if (n > 0) {
						data += n;
						len -= n;
						continue;
					}
					short events = POLLOUT;
					if (ssl) {
						const int err = SSL_get_error(ssl, n);
						if (err == SSL_ERROR_WANT_READ) {
							events = POLLIN;
						} else if (err == SSL_ERROR_WANT_WRITE) {
							events = POLLOUT;
						} else {
							send_ok = false;
							break;
						}
					} else if (WSAGetLastError() != WSAEWOULDBLOCK) {
						send_ok = false;
						break;
					}
					if (poll_sock(events, remaining_ms()) <= 0) {
						send_ok = false;
						break;
					}
				}
				if (!send_ok) {
					out.error = "send failed to " + pu.host;
					cleanup();
					return out;
				}
			}

			std::string raw;
			raw.reserve(8192);
			char buf[8192];
			for (;;) {
				int n;
				if (ssl)
					n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
				else
					n = ::recv(sock, buf, static_cast<int>(sizeof(buf)), 0);
				if (n > 0) {
					raw.append(buf, static_cast<size_t>(n));
					if (raw.size() > 8u * 1024u * 1024u)
						break;
					continue;
				}
				if (n == 0)
					break;
				short events = POLLIN;
				bool fatal = false;
				if (ssl) {
					const int err = SSL_get_error(ssl, n);
					if (err == SSL_ERROR_ZERO_RETURN)
						break;
					if (err == SSL_ERROR_WANT_READ)
						events = POLLIN;
					else if (err == SSL_ERROR_WANT_WRITE)
						events = POLLOUT;
					else
						fatal = true;
				} else if (WSAGetLastError() != WSAEWOULDBLOCK) {
					fatal = true;
				}
				if (fatal)
					break;
				if (poll_sock(events, remaining_ms()) <= 0)
					break;
			}
			cleanup();

			if (raw.empty()) {
				out.error = "empty response from " + pu.host;
				return out;
			}
			parse_http_response(raw, out);
			return out;
		}

	}

	response_t request(const char* verb, const std::string& url,
		const header_list_t& headers, const std::string& body,
		const std::string& content_type, int timeout_sec)
	{
		response_t out;
		parsed_url_t pu;
		if (!parse_url(url, pu)) {
			out.error = "invalid url: " + url;
			return out;
		}

		response_t via_winhttp = winhttp_request(verb, pu, headers, body,
			content_type, timeout_sec);
		if (via_winhttp.ok)
			return via_winhttp;

		response_t via_socket = raw_socket_request(verb, pu, headers, body,
			content_type, timeout_sec);
		if (via_socket.ok)
			return via_socket;

		out.ok = false;
		out.status = 0;
		out.error = "winhttp: "
			+ (via_winhttp.error.empty() ? std::string("unknown") : via_winhttp.error)
			+ " | socket: "
			+ (via_socket.error.empty() ? std::string("unknown") : via_socket.error);
		return out;
	}

	response_t get(const std::string& url, const header_list_t& headers,
		int timeout_sec)
	{
		return request("GET", url, headers, std::string(), std::string(), timeout_sec);
	}

	response_t post(const std::string& url, const header_list_t& headers,
		const std::string& body, const std::string& content_type, int timeout_sec)
	{
		return request("POST", url, headers, body, content_type, timeout_sec);
	}

}
}
}
