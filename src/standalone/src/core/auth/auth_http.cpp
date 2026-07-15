#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_http.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace aida {
namespace auth {
namespace http {

namespace {

	bool contains_rejected_credential(const header_list_t& headers, const std::string& url)
	{
		std::string combined = url;
		for (const auto& header : headers) {
			combined.push_back(' ');
			combined.append(header.second);
		}
		std::transform(combined.begin(), combined.end(), combined.begin(), [](unsigned char ch) {
			return static_cast<char>(std::tolower(ch));
		});
		return combined.find("invalid") != std::string::npos
			|| combined.find("rejected") != std::string::npos
			|| combined.find("expired") != std::string::npos;
	}

	std::string fixture_body(const std::string& url)
	{
		if (url.find("generativelanguage.googleapis.com") != std::string::npos)
			return R"({"models":[{"name":"gemini-2.5-pro"},{"name":"gemini-2.5-flash"},{"name":"gemini-2.0-flash"}]})";
		return R"({"data":[{"id":"preview-primary"},{"id":"preview-fast"},{"id":"preview-reasoning"}]})";
	}

}

response_t request(const char* verb,
	const std::string& url,
	const header_list_t& headers,
	const std::string&,
	const std::string&,
	int)
{
	response_t result;
	if (verb == nullptr || *verb == '\0' || url.rfind("http", 0) != 0) {
		result.error = "invalid url";
		return result;
	}
	result.ok = true;
	if (contains_rejected_credential(headers, url)) {
		result.status = 401;
		result.body = R"({"error":{"message":"The preview credential was rejected"}})";
		return result;
	}
	result.status = 200;
	result.body = fixture_body(url);
	return result;
}

response_t get(const std::string& url, const header_list_t& headers, int timeout_sec)
{
	return request("GET", url, headers, {}, {}, timeout_sec);
}

response_t post(const std::string& url,
	const header_list_t& headers,
	const std::string& body,
	const std::string& content_type,
	int timeout_sec)
{
	return request("POST", url, headers, body, content_type, timeout_sec);
}

stream_result_t stream(const char* verb,
	const std::string& url,
	const header_list_t& headers,
	const std::string& body,
	const std::string& content_type,
	int timeout_sec,
	const stream_chunk_cb_t& on_chunk)
{
	stream_result_t result;
	const response_t response = request(verb, url, headers, body, content_type, timeout_sec);
	result.status = response.status;
	result.ok = response.ok;
	result.error = response.error;
	if (response.ok && on_chunk && !on_chunk(response.body.data(), response.body.size())) {
		result.ok = false;
		result.cancelled = true;
		result.error = "cancelled";
	}
	return result;
}

void cleanup()
{
}

}
}
}

#else

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "auth_http.hpp"
#include "../../helpers/diag_log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <windns.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iphlpapi.h>

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
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

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

		struct wsa_guard_t {
			WSADATA data{};
			bool ok = false;
			wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
			~wsa_guard_t() { if (ok) WSACleanup(); }
		};

		static wsa_guard_t s_wsa_guard;

		struct pooled_conn_t {
			SOCKET sock = INVALID_SOCKET;
			SSL* ssl = nullptr;
			SSL_CTX* ctx = nullptr;
			int family = 0;
			uint64_t last_used_ms = 0;
			std::string host_key;
		};

		constexpr size_t kPoolMaxEntries = 8;
		constexpr uint64_t kPoolIdleMs = 30000;
		constexpr uint64_t kPoolMaxAgeMs = 240000;

		static std::shared_mutex s_pool_mtx;
		static std::deque<std::unique_ptr<pooled_conn_t>> s_pool;
		static std::atomic<bool> s_pool_enabled{ true };

		static uint64_t now_steady_ms()
		{
			using namespace std::chrono;
			return static_cast<uint64_t>(duration_cast<milliseconds>(
				steady_clock::now().time_since_epoch()).count());
		}

		static std::string make_pool_key(const std::string& host, int port)
		{
			std::string key;
			key.reserve(host.size() + 8);
			key += host;
			key += ':';
			key += std::to_string(port);
			return key;
		}

		static void destroy_pooled_conn(pooled_conn_t* conn)
		{
			if (!conn)
				return;
			if (conn->ssl) {
				SSL_shutdown(conn->ssl);
				SSL_free(conn->ssl);
				conn->ssl = nullptr;
			}
			if (conn->ctx) {
				SSL_CTX_free(conn->ctx);
				conn->ctx = nullptr;
			}
			if (conn->sock != INVALID_SOCKET) {
				::shutdown(conn->sock, SD_BOTH);
				closesocket(conn->sock);
				conn->sock = INVALID_SOCKET;
			}
		}

		static unsigned long count_time_wait_for_pid()
		{
			DWORD pid = GetCurrentProcessId();
			DWORD size = 0;
			DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
				TCP_TABLE_OWNER_PID_ALL, 0);
			if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
				return 0;
			std::unique_ptr<unsigned char[]> buf(new unsigned char[size]);
			rc = GetExtendedTcpTable(buf.get(), &size, FALSE, AF_INET,
				TCP_TABLE_OWNER_PID_ALL, 0);
			if (rc != NO_ERROR)
				return 0;
			const MIB_TCPTABLE_OWNER_PID* tbl =
				reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.get());
			unsigned long count = 0;
			for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
				const MIB_TCPROW_OWNER_PID& row = tbl->table[i];
				if (row.dwOwningPid == pid && row.dwState == MIB_TCP_STATE_TIME_WAIT)
					++count;
			}
			return count;
		}

		static void log_wsaenobufs(const char* where, const std::string& host, int port)
		{
			const unsigned long tw = count_time_wait_for_pid();
			diag::log_tagged_critical_fmt("net",
				"WSAENOBUFS detected -- ephemeral-port pool exhausted; "
				"consider reducing parallelism (where=%s host=%s port=%d "
				"pid_time_wait=%lu)",
				where ? where : "?", host.c_str(), port, tw);
		}

		static bool apply_short_lived_socket_opts(SOCKET s, std::string& last_error)
		{
			BOOL reuse = TRUE;
			if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
					reinterpret_cast<const char*>(&reuse), sizeof(reuse)) != 0) {
				last_error = "SO_REUSEADDR wsa="
					+ std::to_string(WSAGetLastError());
				return false;
			}
			BOOL nodelay = TRUE;
			if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
					reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
				last_error = "TCP_NODELAY wsa="
					+ std::to_string(WSAGetLastError());
				return false;
			}
			LINGER lin;
			lin.l_onoff = 1;
			lin.l_linger = 0;
			if (setsockopt(s, SOL_SOCKET, SO_LINGER,
					reinterpret_cast<const char*>(&lin), sizeof(lin)) != 0) {
				last_error = "SO_LINGER wsa="
					+ std::to_string(WSAGetLastError());
				return false;
			}
			last_error.clear();
			return true;
		}

		static std::unique_ptr<pooled_conn_t> acquire_pooled_conn(
			const std::string& host, int port)
		{
			if (!s_pool_enabled.load(std::memory_order_acquire))
				return nullptr;
			const std::string key = make_pool_key(host, port);
			const uint64_t now_ms = now_steady_ms();
			std::unique_lock<std::shared_mutex> lock(s_pool_mtx);
			for (auto it = s_pool.begin(); it != s_pool.end(); ) {
				pooled_conn_t* p = it->get();
				if (!p || p->sock == INVALID_SOCKET) {
					it = s_pool.erase(it);
					continue;
				}
				if (now_ms - p->last_used_ms > kPoolIdleMs) {
					destroy_pooled_conn(p);
					it = s_pool.erase(it);
					continue;
				}
				if (p->host_key == key) {
					WSAPOLLFD pfd = {};
					pfd.fd = p->sock;
					pfd.events = POLLRDNORM;
					const int probe = WSAPoll(&pfd, 1, 0);
					if (probe > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
						destroy_pooled_conn(p);
						it = s_pool.erase(it);
						continue;
					}
					if (probe > 0 && (pfd.revents & POLLRDNORM)) {
						destroy_pooled_conn(p);
						it = s_pool.erase(it);
						continue;
					}
					std::unique_ptr<pooled_conn_t> taken = std::move(*it);
					s_pool.erase(it);
					return taken;
				}
				++it;
			}
			return nullptr;
		}

		static void release_pooled_conn(std::unique_ptr<pooled_conn_t> conn)
		{
			if (!conn || conn->sock == INVALID_SOCKET) {
				destroy_pooled_conn(conn.get());
				return;
			}
			if (!s_pool_enabled.load(std::memory_order_acquire)) {
				destroy_pooled_conn(conn.get());
				return;
			}
			conn->last_used_ms = now_steady_ms();
			std::unique_lock<std::shared_mutex> lock(s_pool_mtx);
			if (!s_pool_enabled.load(std::memory_order_acquire)) {
				lock.unlock();
				destroy_pooled_conn(conn.get());
				return;
			}
			while (s_pool.size() >= kPoolMaxEntries) {
				if (s_pool.empty())
					break;
				std::unique_ptr<pooled_conn_t> evict = std::move(s_pool.front());
				s_pool.pop_front();
				destroy_pooled_conn(evict.get());
			}
			s_pool.push_back(std::move(conn));
		}

		static void drain_pool_locked()
		{
			while (!s_pool.empty()) {
				std::unique_ptr<pooled_conn_t> c = std::move(s_pool.front());
				s_pool.pop_front();
				destroy_pooled_conn(c.get());
			}
		}

		static void purge_stale_pool_entries()
		{
			const uint64_t now_ms = now_steady_ms();
			std::unique_lock<std::shared_mutex> lock(s_pool_mtx);
			for (auto it = s_pool.begin(); it != s_pool.end(); ) {
				pooled_conn_t* p = it->get();
				if (!p || p->sock == INVALID_SOCKET
					|| now_ms - p->last_used_ms > kPoolMaxAgeMs) {
					destroy_pooled_conn(p);
					it = s_pool.erase(it);
				} else {
					++it;
				}
			}
		}

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

		static int ensure_winsock()
		{
			return s_wsa_guard.ok ? 0 : WSASYSNOTREADY;
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

			const uint64_t req_start_ms = now_steady_ms();
			diag::log_tagged_fmt("net",
				"raw_socket_request begin host=%s port=%d verb=%s timeout_s=%d",
				pu.host.c_str(), pu.port, verb ? verb : "?",
				timeout_sec > 0 ? timeout_sec : 30);

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
			int chosen_family = 0;
			std::string connect_errors;
			bool saw_wsaenobufs = false;
			for (const resolved_addr_t& addr : candidates) {
				if (remaining_ms() <= 0) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "deadline_before_connect";
					break;
				}
				SOCKET s = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
				if (s == INVALID_SOCKET) {
					const int e = WSAGetLastError();
					if (e == WSAENOBUFS) {
						saw_wsaenobufs = true;
						log_wsaenobufs("raw_socket_request:socket",
							pu.host, pu.port);
					}
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "socket wsa=" + std::to_string(e);
					continue;
				}
				diag::log_tagged_fmt("net",
					"raw_socket_request socket created family=%d host=%s port=%d",
					addr.family, pu.host.c_str(), pu.port);
				std::string opt_err;
				if (!apply_short_lived_socket_opts(s, opt_err)) {
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += opt_err;
					closesocket(s);
					continue;
				}
				u_long nonblocking = 1;
				ioctlsocket(s, FIONBIO, &nonblocking);
				const int cr = ::connect(s,
					reinterpret_cast<const sockaddr*>(&addr.sa), addr.sa_len);
				if (cr == 0) {
					sock = s;
					chosen_family = addr.family;
					break;
				}
				const int connect_err = WSAGetLastError();
				if (connect_err != WSAEWOULDBLOCK) {
					if (connect_err == WSAENOBUFS) {
						saw_wsaenobufs = true;
						log_wsaenobufs("raw_socket_request:connect",
							pu.host, pu.port);
					}
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "connect wsa="
						+ std::to_string(connect_err);
					closesocket(s);
					continue;
				}
				WSAPOLLFD pfd = {};
				pfd.fd = s;
				pfd.events = POLLOUT;
				const int pr = WSAPoll(&pfd, 1, remaining_ms());
				if (pr <= 0) {
					const int poll_err = pr == 0 ? 0 : WSAGetLastError();
					if (poll_err == WSAENOBUFS) {
						saw_wsaenobufs = true;
						log_wsaenobufs("raw_socket_request:poll",
							pu.host, pu.port);
					}
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += pr == 0 ? "connect_timeout"
						: ("connect_poll wsa=" + std::to_string(poll_err));
					closesocket(s);
					continue;
				}
				int so_error = 0;
				int so_len = static_cast<int>(sizeof(so_error));
				if (getsockopt(s, SOL_SOCKET, SO_ERROR,
						reinterpret_cast<char*>(&so_error), &so_len) != 0
					|| so_error != 0) {
					if (so_error == WSAENOBUFS) {
						saw_wsaenobufs = true;
						log_wsaenobufs("raw_socket_request:so_error",
							pu.host, pu.port);
					}
					if (!connect_errors.empty())
						connect_errors += "; ";
					connect_errors += "so_error=" + std::to_string(so_error);
					closesocket(s);
					continue;
				}
				sock = s;
				chosen_family = addr.family;
				break;
			}
			if (sock == INVALID_SOCKET) {
				out.error = "connect failed for " + pu.host + " ("
					+ (connect_errors.empty() ? std::string("no_candidates")
						: connect_errors) + ")";
				if (saw_wsaenobufs)
					out.error += " [wsaenobufs]";
				diag::log_tagged_fmt("net",
					"raw_socket_request connect failed host=%s port=%d err=%s "
					"elapsed_ms=%llu",
					pu.host.c_str(), pu.port, out.error.c_str(),
					static_cast<unsigned long long>(now_steady_ms() - req_start_ms));
				return out;
			}
			(void)chosen_family;

			SSL_CTX* ctx = nullptr;
			SSL* ssl = nullptr;
			const char* close_reason = "success";
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
					diag::log_tagged_fmt("net",
						"raw_socket_request close host=%s port=%d reason=%s",
						pu.host.c_str(), pu.port,
						close_reason ? close_reason : "?");
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			};

			if (pu.https) {
				ctx = SSL_CTX_new(TLS_client_method());
				if (!ctx) {
					out.error = "SSL_CTX_new failed";
					close_reason = "ssl_ctx_new_failed";
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
					close_reason = "ssl_new_failed";
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
					close_reason = "set_verify_host_failed";
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
						close_reason = "tls_handshake_failed";
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
						close_reason = pr == 0 ? "tls_handshake_timeout"
							: "tls_handshake_poll_error";
						cleanup();
						return out;
					}
				}
				const long verify_rc = SSL_get_verify_result(ssl);
				if (verify_rc != X509_V_OK) {
					out.error = "TLS certificate verification failed rc="
						+ std::to_string(verify_rc);
					close_reason = "tls_verify_failed";
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

			const size_t total_to_send = req.size();
			size_t total_sent = 0;
			{
				const char* data = req.data();
				int len = static_cast<int>(req.size());
				bool send_ok = true;
				bool send_enobufs = false;
				while (len > 0) {
					int n;
					if (ssl)
						n = SSL_write(ssl, data, len);
					else
						n = ::send(sock, data, len, 0);
					if (n > 0) {
						data += n;
						len -= n;
						total_sent += static_cast<size_t>(n);
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
					} else {
						const int se = WSAGetLastError();
						if (se == WSAENOBUFS) {
							send_enobufs = true;
							log_wsaenobufs("raw_socket_request:send",
								pu.host, pu.port);
						}
						if (se != WSAEWOULDBLOCK) {
							send_ok = false;
							break;
						}
					}
					if (poll_sock(events, remaining_ms()) <= 0) {
						send_ok = false;
						break;
					}
				}
				if (!send_ok) {
					out.error = "send failed to " + pu.host;
					if (send_enobufs)
						out.error += " [wsaenobufs]";
					close_reason = send_enobufs ? "send_wsaenobufs"
						: "send_failed";
					cleanup();
					return out;
				}
			}

			std::string raw;
			raw.reserve(8192);
			char buf[8192];
			size_t total_recv = 0;
			for (;;) {
				int n;
				if (ssl)
					n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
				else
					n = ::recv(sock, buf, static_cast<int>(sizeof(buf)), 0);
				if (n > 0) {
					raw.append(buf, static_cast<size_t>(n));
					total_recv += static_cast<size_t>(n);
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
				} else {
					const int re = WSAGetLastError();
					if (re == WSAENOBUFS) {
						log_wsaenobufs("raw_socket_request:recv",
							pu.host, pu.port);
						fatal = true;
					} else if (re != WSAEWOULDBLOCK) {
						fatal = true;
					}
				}
				if (fatal)
					break;
				if (poll_sock(events, remaining_ms()) <= 0)
					break;
			}
			cleanup();

			const uint64_t req_elapsed_ms = now_steady_ms() - req_start_ms;
			diag::log_tagged_fmt("net",
				"raw_socket_request complete host=%s port=%d sent=%zu/%zu "
				"recv=%zu elapsed_ms=%llu",
				pu.host.c_str(), pu.port, total_sent, total_to_send, total_recv,
				static_cast<unsigned long long>(req_elapsed_ms));

			if (raw.empty()) {
				out.error = "empty response from " + pu.host;
				return out;
			}
			parse_http_response(raw, out);
			return out;
		}

		thread_local int t_stream_pool_attempts = 0;

		stream_result_t raw_socket_stream(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, int timeout_sec,
			const stream_chunk_cb_t& on_chunk)
		{
			stream_result_t out;

			const int wsa = ensure_winsock();
			if (wsa != 0) {
				out.error = "WSAStartup failed rc=" + std::to_string(wsa);
				return out;
			}

			purge_stale_pool_entries();

			const uint64_t req_start_ms = now_steady_ms();
			diag::log_tagged_fmt("net",
				"raw_socket_stream begin host=%s port=%d verb=%s timeout_s=%d",
				pu.host.c_str(), pu.port, verb ? verb : "?",
				timeout_sec > 0 ? timeout_sec : 30);

			const int effective_timeout = timeout_sec > 0 ? timeout_sec : 30;

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
			SSL_CTX* ctx = nullptr;
			SSL* ssl = nullptr;
			int chosen_family = 0;
			bool from_pool = false;
			const bool pool_eligible = pu.https && s_pool_enabled.load(
				std::memory_order_acquire) && t_stream_pool_attempts < 2;

			struct pool_attempt_guard_t {
				int* counter;
				bool acquired;
				pool_attempt_guard_t(int* c) : counter(c), acquired(false) {}
				~pool_attempt_guard_t() { if (acquired && counter) --(*counter); }
			};
			pool_attempt_guard_t attempt_guard(&t_stream_pool_attempts);

			if (pool_eligible) {
				std::unique_ptr<pooled_conn_t> reused =
					acquire_pooled_conn(pu.host, pu.port);
				if (reused) {
					sock = reused->sock;
					ssl = reused->ssl;
					ctx = reused->ctx;
					chosen_family = reused->family;
					reused->sock = INVALID_SOCKET;
					reused->ssl = nullptr;
					reused->ctx = nullptr;
					from_pool = true;
					++t_stream_pool_attempts;
					attempt_guard.acquired = true;
					diag::log_tagged_fmt("net",
						"raw_socket_stream pool hit host=%s port=%d",
						pu.host.c_str(), pu.port);
				}
			}

			std::string connect_errors;
			bool saw_wsaenobufs = false;

			if (!from_pool) {
				const int resolve_budget = (effective_timeout * 1000 / 4) > 2000
					? (effective_timeout * 1000 / 4) : 2000;
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

				for (const resolved_addr_t& addr : candidates) {
					if (remaining_ms() <= 0) {
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += "deadline_before_connect";
						break;
					}
					SOCKET s = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
					if (s == INVALID_SOCKET) {
						const int e = WSAGetLastError();
						if (e == WSAENOBUFS) {
							saw_wsaenobufs = true;
							log_wsaenobufs("raw_socket_stream:socket",
								pu.host, pu.port);
						}
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += "socket wsa=" + std::to_string(e);
						continue;
					}
					diag::log_tagged_fmt("net",
						"raw_socket_stream socket created family=%d host=%s "
						"port=%d", addr.family, pu.host.c_str(), pu.port);
					std::string opt_err;
					if (!apply_short_lived_socket_opts(s, opt_err)) {
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += opt_err;
						closesocket(s);
						continue;
					}
					u_long nonblocking = 1;
					ioctlsocket(s, FIONBIO, &nonblocking);
					const int cr = ::connect(s,
						reinterpret_cast<const sockaddr*>(&addr.sa), addr.sa_len);
					if (cr == 0) {
						sock = s;
						chosen_family = addr.family;
						break;
					}
					const int connect_err = WSAGetLastError();
					if (connect_err != WSAEWOULDBLOCK) {
						if (connect_err == WSAENOBUFS) {
							saw_wsaenobufs = true;
							log_wsaenobufs("raw_socket_stream:connect",
								pu.host, pu.port);
						}
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += "connect wsa="
							+ std::to_string(connect_err);
						closesocket(s);
						continue;
					}
					WSAPOLLFD pfd = {};
					pfd.fd = s;
					pfd.events = POLLOUT;
					const int pr = WSAPoll(&pfd, 1, remaining_ms());
					if (pr <= 0) {
						const int poll_err = pr == 0 ? 0 : WSAGetLastError();
						if (poll_err == WSAENOBUFS) {
							saw_wsaenobufs = true;
							log_wsaenobufs("raw_socket_stream:poll",
								pu.host, pu.port);
						}
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += pr == 0 ? "connect_timeout"
							: ("connect_poll wsa=" + std::to_string(poll_err));
						closesocket(s);
						continue;
					}
					int so_error = 0;
					int so_len = static_cast<int>(sizeof(so_error));
					if (getsockopt(s, SOL_SOCKET, SO_ERROR,
							reinterpret_cast<char*>(&so_error), &so_len) != 0
						|| so_error != 0) {
						if (so_error == WSAENOBUFS) {
							saw_wsaenobufs = true;
							log_wsaenobufs("raw_socket_stream:so_error",
								pu.host, pu.port);
						}
						if (!connect_errors.empty())
							connect_errors += "; ";
						connect_errors += "so_error=" + std::to_string(so_error);
						closesocket(s);
						continue;
					}
					sock = s;
					chosen_family = addr.family;
					break;
				}
				if (sock == INVALID_SOCKET) {
					out.error = "connect failed for " + pu.host + " ("
						+ (connect_errors.empty() ? std::string("no_candidates")
							: connect_errors) + ")";
					if (saw_wsaenobufs)
						out.error += " [wsaenobufs]";
					diag::log_tagged_fmt("net",
						"raw_socket_stream connect failed host=%s port=%d err=%s "
						"elapsed_ms=%llu",
						pu.host.c_str(), pu.port, out.error.c_str(),
						static_cast<unsigned long long>(
							now_steady_ms() - req_start_ms));
					return out;
				}
			}

			const char* close_reason = "success";
			bool reusable = pool_eligible;
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
					diag::log_tagged_fmt("net",
						"raw_socket_stream close host=%s port=%d reason=%s",
						pu.host.c_str(), pu.port,
						close_reason ? close_reason : "?");
					::shutdown(sock, SD_BOTH);
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			};

			if (!from_pool && pu.https) {
				ctx = SSL_CTX_new(TLS_client_method());
				if (!ctx) {
					out.error = "SSL_CTX_new failed";
					close_reason = "ssl_ctx_new_failed";
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
					close_reason = "ssl_new_failed";
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
					close_reason = "set_verify_host_failed";
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
						close_reason = "tls_handshake_failed";
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
						close_reason = pr == 0 ? "tls_handshake_timeout"
							: "tls_handshake_poll_error";
						cleanup();
						return out;
					}
				}
				const long verify_rc = SSL_get_verify_result(ssl);
				if (verify_rc != X509_V_OK) {
					out.error = "TLS certificate verification failed rc="
						+ std::to_string(verify_rc);
					close_reason = "tls_verify_failed";
					cleanup();
					return out;
				}
			}

			const std::string connection_header_value = pool_eligible
				? std::string("keep-alive") : std::string("close");

			std::string req;
			req += verb;
			req += " ";
			req += pu.path.empty() ? std::string("/") : pu.path;
			req += " HTTP/1.1\r\n";
			req += "Host: " + pu.host + "\r\n";
			req += "Connection: " + connection_header_value + "\r\n";
			if (pool_eligible)
				req += "Keep-Alive: timeout=30\r\n";
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

			const size_t total_to_send = req.size();
			size_t total_sent = 0;
			size_t total_recv = 0;
			{
				const char* data = req.data();
				int len = static_cast<int>(req.size());
				bool send_ok = true;
				bool send_enobufs = false;
				while (len > 0) {
					int n;
					if (ssl)
						n = SSL_write(ssl, data, len);
					else
						n = ::send(sock, data, len, 0);
					if (n > 0) {
						data += n;
						len -= n;
						total_sent += static_cast<size_t>(n);
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
					} else {
						const int se = WSAGetLastError();
						if (se == WSAENOBUFS) {
							send_enobufs = true;
							log_wsaenobufs("raw_socket_stream:send",
								pu.host, pu.port);
						}
						if (se != WSAEWOULDBLOCK) {
							send_ok = false;
							break;
						}
					}
					if (poll_sock(events, remaining_ms()) <= 0) {
						send_ok = false;
						break;
					}
				}
				if (!send_ok) {
					if (from_pool) {
						from_pool = false;
						reusable = pool_eligible;
						diag::log_tagged_fmt("net",
							"raw_socket_stream pooled send failed, retrying with "
							"fresh connection host=%s port=%d",
							pu.host.c_str(), pu.port);
						close_reason = "pool_stale_send_failed";
						cleanup();
						return raw_socket_stream(verb, pu, headers, body,
							content_type, timeout_sec, on_chunk);
					}
					out.error = "send failed to " + pu.host;
					if (send_enobufs)
						out.error += " [wsaenobufs]";
					close_reason = send_enobufs ? "send_wsaenobufs"
						: "send_failed";
					cleanup();
					return out;
				}
			}

			std::string header_buf;
			header_buf.reserve(4096);
			std::string body_pending;
			bool headers_done = false;
			bool read_fatal_recv = false;

			auto read_more = [&](std::string& sink) -> int {
				char buf[8192];
				int n;
				if (ssl)
					n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
				else
					n = ::recv(sock, buf, static_cast<int>(sizeof(buf)), 0);
				if (n > 0) {
					sink.append(buf, static_cast<size_t>(n));
					total_recv += static_cast<size_t>(n);
					return n;
				}
				if (n == 0)
					return 0;
				short events = POLLIN;
				bool fatal = false;
				if (ssl) {
					const int err = SSL_get_error(ssl, n);
					if (err == SSL_ERROR_ZERO_RETURN)
						return 0;
					if (err == SSL_ERROR_WANT_READ)
						events = POLLIN;
					else if (err == SSL_ERROR_WANT_WRITE)
						events = POLLOUT;
					else
						fatal = true;
				} else {
					const int re = WSAGetLastError();
					if (re == WSAENOBUFS) {
						log_wsaenobufs("raw_socket_stream:recv",
							pu.host, pu.port);
						fatal = true;
					} else if (re != WSAEWOULDBLOCK) {
						fatal = true;
					}
				}
				if (fatal) {
					read_fatal_recv = true;
					return -1;
				}
				if (poll_sock(events, remaining_ms()) <= 0)
					return -1;
				return -2;
			};

			while (!headers_done) {
				const int n = read_more(header_buf);
				if (n == -1)
					break;
				if (n == 0)
					break;
				if (n == -2)
					continue;
				const size_t pos = header_buf.find("\r\n\r\n");
				if (pos != std::string::npos) {
					body_pending = header_buf.substr(pos + 4);
					header_buf.resize(pos);
					headers_done = true;
					break;
				}
				if (header_buf.size() > 256u * 1024u) {
					out.error = "response headers too large from " + pu.host;
					close_reason = "headers_too_large";
					reusable = false;
					cleanup();
					return out;
				}
			}

			if (!headers_done) {
				if (from_pool && header_buf.empty() && !read_fatal_recv) {
					diag::log_tagged_fmt("net",
						"raw_socket_stream pooled response empty, retrying with "
						"fresh connection host=%s port=%d",
						pu.host.c_str(), pu.port);
					close_reason = "pool_stale_no_response";
					reusable = false;
					cleanup();
					return raw_socket_stream(verb, pu, headers, body,
						content_type, timeout_sec, on_chunk);
				}
				out.error = "incomplete response headers from " + pu.host;
				close_reason = "incomplete_response_headers";
				reusable = false;
				cleanup();
				return out;
			}

			const size_t line_end = header_buf.find("\r\n");
			const std::string status_line = header_buf.substr(0, line_end);
			const size_t sp = status_line.find(' ');
			if (sp != std::string::npos)
				out.status = atoi(status_line.c_str() + sp + 1);
			if (out.status <= 0) {
				out.error = "malformed HTTP status line from " + pu.host;
				close_reason = "malformed_status_line";
				reusable = false;
				cleanup();
				return out;
			}

			std::string headers_lower = header_buf;
			for (char& c : headers_lower)
				c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
			const bool chunked = headers_lower.find("transfer-encoding: chunked")
				!= std::string::npos;
			const bool server_close = headers_lower.find("connection: close")
				!= std::string::npos;
			if (server_close)
				reusable = false;

			int64_t content_length = -1;
			{
				const size_t cl = headers_lower.find("content-length:");
				if (cl != std::string::npos) {
					size_t v = cl + 15;
					while (v < headers_lower.size()
						&& (headers_lower[v] == ' ' || headers_lower[v] == '\t'))
						++v;
					content_length = strtoll(headers_lower.c_str() + v, nullptr, 10);
				}
			}

			if (!chunked && content_length < 0)
				reusable = false;

			auto emit_payload = [&](const char* data, size_t len) -> bool {
				if (len == 0)
					return true;
				if (!on_chunk)
					return true;
				return on_chunk(data, len);
			};

			if (out.status < 200 || out.status >= 300) {
				std::string error_raw = std::move(body_pending);
				while (true) {
					const int n = read_more(error_raw);
					if (n == -1 || n == 0)
						break;
					if (error_raw.size() > 64u * 1024u)
						break;
				}
				std::string error_body = error_raw;
				if (chunked) {
					std::string decoded;
					size_t p = 0;
					while (p < error_raw.size()) {
						const size_t crlf = error_raw.find("\r\n", p);
						if (crlf == std::string::npos)
							break;
						const long chunk_size = strtol(error_raw.c_str() + p,
							nullptr, 16);
						p = crlf + 2;
						if (chunk_size <= 0)
							break;
						if (p + static_cast<size_t>(chunk_size) > error_raw.size())
							break;
						decoded.append(error_raw, p, static_cast<size_t>(chunk_size));
						p += static_cast<size_t>(chunk_size) + 2;
					}
					if (!decoded.empty())
						error_body = std::move(decoded);
				}
				out.ok = false;
				if (out.error.empty()) {
					std::string snippet = error_body.substr(0,
						(std::min)(error_body.size(), static_cast<size_t>(800)));
					out.error = "HTTP " + std::to_string(out.status)
						+ (snippet.empty() ? std::string() : (": " + snippet));
				}
				if (on_chunk)
					on_chunk(error_body.data(), error_body.size());
				close_reason = "http_error";
				reusable = false;
				cleanup();
				return out;
			}

			bool delivery_cancelled = false;
			bool body_complete = false;

			if (chunked) {
				std::string buffer = std::move(body_pending);
				bool stream_done = false;
				while (!stream_done) {
					while (true) {
						const size_t crlf = buffer.find("\r\n");
						if (crlf == std::string::npos) {
							const int n = read_more(buffer);
							if (n == -1) {
								stream_done = true;
								break;
							}
							if (n == 0) {
								stream_done = true;
								break;
							}
							continue;
						}
						const long chunk_size = strtol(buffer.c_str(), nullptr, 16);
						if (chunk_size < 0) {
							stream_done = true;
							break;
						}
						buffer.erase(0, crlf + 2);
						if (chunk_size == 0) {
							stream_done = true;
							body_complete = true;
							break;
						}
						size_t remaining = static_cast<size_t>(chunk_size);
						while (remaining > 0) {
							if (!buffer.empty()) {
								const size_t take = (std::min)(remaining, buffer.size());
								if (!emit_payload(buffer.data(), take)) {
									delivery_cancelled = true;
									stream_done = true;
									break;
								}
								buffer.erase(0, take);
								remaining -= take;
								if (remaining == 0)
									break;
							}
							const int n = read_more(buffer);
							if (n == -1 || n == 0) {
								stream_done = true;
								break;
							}
						}
						if (stream_done)
							break;
						while (buffer.size() < 2) {
							const int n = read_more(buffer);
							if (n == -1 || n == 0) {
								stream_done = true;
								break;
							}
						}
						if (stream_done)
							break;
						if (buffer.size() >= 2 && buffer[0] == '\r' && buffer[1] == '\n')
							buffer.erase(0, 2);
					}
				}
			} else {
				if (!body_pending.empty()) {
					if (!emit_payload(body_pending.data(), body_pending.size()))
						delivery_cancelled = true;
				}
				int64_t delivered = static_cast<int64_t>(body_pending.size());
				body_pending.clear();
				std::string buf;
				while (!delivery_cancelled) {
					if (content_length >= 0 && delivered >= content_length) {
						body_complete = true;
						break;
					}
					buf.clear();
					const int n = read_more(buf);
					if (n == -1 || n == 0) {
						if (content_length < 0 && !delivery_cancelled
							&& !read_fatal_recv)
							body_complete = true;
						break;
					}
					if (n == -2)
						continue;
					if (!emit_payload(buf.data(), buf.size())) {
						delivery_cancelled = true;
						break;
					}
					delivered += static_cast<int64_t>(buf.size());
				}
			}

			out.ok = !delivery_cancelled;
			out.cancelled = delivery_cancelled;
			if (delivery_cancelled && out.error.empty())
				out.error = "stream cancelled by receiver";

			const bool can_pool_back = reusable && out.ok && body_complete
				&& !delivery_cancelled && pool_eligible && sock != INVALID_SOCKET
				&& !read_fatal_recv;

			const uint64_t req_elapsed_ms = now_steady_ms() - req_start_ms;
			diag::log_tagged_fmt("net",
				"raw_socket_stream complete host=%s port=%d sent=%zu/%zu "
				"recv=%zu elapsed_ms=%llu pool_hit=%d pool_back=%d "
				"body_complete=%d cancelled=%d",
				pu.host.c_str(), pu.port, total_sent, total_to_send, total_recv,
				static_cast<unsigned long long>(req_elapsed_ms),
				from_pool ? 1 : 0, can_pool_back ? 1 : 0,
				body_complete ? 1 : 0, delivery_cancelled ? 1 : 0);

			if (can_pool_back) {
				std::unique_ptr<pooled_conn_t> conn = std::make_unique<pooled_conn_t>();
				conn->sock = sock;
				conn->ssl = ssl;
				conn->ctx = ctx;
				conn->family = chosen_family;
				conn->host_key = make_pool_key(pu.host, pu.port);
				conn->last_used_ms = now_steady_ms();
				sock = INVALID_SOCKET;
				ssl = nullptr;
				ctx = nullptr;
				release_pooled_conn(std::move(conn));
				close_reason = "pooled";
			} else {
				close_reason = delivery_cancelled ? "stream_cancelled"
					: (body_complete ? "completed_unpoolable"
						: "incomplete_body");
			}
			cleanup();
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
		const std::string e_winhttp = via_winhttp.error.empty()
			? std::string("unknown") : via_winhttp.error;
		const std::string e_socket = via_socket.error.empty()
			? std::string("unknown") : via_socket.error;
		const bool both_enobufs = e_winhttp.find("wsa=10055") != std::string::npos
			&& e_socket.find("wsa=10055") != std::string::npos;
		const bool either_enobufs = e_winhttp.find("wsaenobufs") != std::string::npos
			|| e_socket.find("wsaenobufs") != std::string::npos
			|| e_winhttp.find("wsa=10055") != std::string::npos
			|| e_socket.find("wsa=10055") != std::string::npos;
		if (both_enobufs || either_enobufs) {
			out.error = "Ephemeral-port pool exhausted (WSAENOBUFS / wsa=10055). "
				"Restart AiDA or wait ~2 minutes for TIME_WAIT to clear.";
			diag::log_tagged_critical_fmt("net",
				"request collapsed to wsaenobufs host=%s winhttp_err=\"%s\" "
				"socket_err=\"%s\"",
				pu.host.c_str(), e_winhttp.c_str(), e_socket.c_str());
		} else {
			out.error = "winhttp: " + e_winhttp + " | socket: " + e_socket;
		}
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

	stream_result_t stream(const char* verb, const std::string& url,
		const header_list_t& headers, const std::string& body,
		const std::string& content_type, int timeout_sec,
		const stream_chunk_cb_t& on_chunk)
	{
		stream_result_t out;
		parsed_url_t pu;
		if (!parse_url(url, pu)) {
			out.error = "invalid url: " + url;
			return out;
		}
		return raw_socket_stream(verb, pu, headers, body, content_type,
			timeout_sec, on_chunk);
	}

	void cleanup()
	{
		s_pool_enabled.store(false, std::memory_order_release);
		std::unique_lock<std::shared_mutex> lock(s_pool_mtx);
		drain_pool_locked();
	}

}
}
}

#endif
