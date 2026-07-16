#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "auth_http.hpp"

#include <string>

namespace aida {
namespace auth {
namespace http {

response_t request(const char* verb,
	const std::string&,
	const header_list_t&,
	const std::string&,
	const std::string&,
	int,
	const cancel_cb_t& cancelled)
{
	response_t result;
	if (cancelled) {
		try { result.cancelled = cancelled(); } catch (...) { result.cancelled = true; }
	}
	result.status = 0;
	result.ok = false;
	result.error = result.cancelled ? "preview_http_cancelled"
		: verb == nullptr || *verb == '\0'
		? "preview_http_invalid_method" : "preview_http_unavailable";
	return result;
}

response_t get(const std::string& url, const header_list_t& headers, int timeout_sec,
	const cancel_cb_t& cancelled)
{
	return request("GET", url, headers, {}, {}, timeout_sec, cancelled);
}

response_t post(const std::string& url,
	const header_list_t& headers,
	const std::string& body,
	const std::string& content_type,
	int timeout_sec,
	const cancel_cb_t& cancelled)
{
	return request("POST", url, headers, body, content_type, timeout_sec, cancelled);
}

stream_result_t stream(const char* verb,
	const std::string& url,
	const header_list_t& headers,
	const std::string& body,
	const std::string& content_type,
	int timeout_sec,
	const stream_chunk_cb_t&,
	const cancel_cb_t& cancelled)
{
	stream_result_t result;
	const response_t response = request(verb, url, headers, body, content_type,
		timeout_sec, cancelled);
	result.status = response.status;
	result.ok = response.ok;
	result.complete = response.complete;
	result.truncated = response.truncated;
	result.cancelled = response.cancelled;
	result.error = response.error;
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
#if !defined(CERT_CHAIN_PARA_HAS_EXTRA_FIELDS)
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#endif
#include "auth_http.hpp"
#include "../../helpers/diag_log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace aida {
namespace auth {
namespace http {

	namespace {

		struct parsed_url_t {
			bool https = true;
			bool ipv6 = false;
			bool ip_literal = false;
			std::string host;
			std::string authority;
			std::string path = "/";
			int port = 443;
		};

		constexpr std::size_t kMaximumResponseBytes = 8u * 1024u * 1024u;
		constexpr std::size_t kMaximumHeaderBytes = 64u * 1024u;
		constexpr std::size_t kMaximumUrlBytes = 16u * 1024u;
		using request_deadline_t = std::chrono::steady_clock::time_point;

		request_deadline_t request_deadline(int timeout_sec) noexcept
		{
			const int effective = timeout_sec > 0 ? timeout_sec : 30;
			return std::chrono::steady_clock::now() + std::chrono::seconds(effective);
		}

		int remaining_timeout_ms(const request_deadline_t& deadline) noexcept
		{
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) return 0;
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline - now).count();
			return remaining > static_cast<decltype(remaining)>((std::numeric_limits<int>::max)())
				? (std::numeric_limits<int>::max)() : static_cast<int>(remaining > 0 ? remaining : 1);
		}

		bool cancellation_requested(const cancel_cb_t& cancelled) noexcept
		{
			if (!cancelled) return false;
			try { return cancelled(); } catch (...) { return true; }
		}

		struct resolved_addr_t {
			int family = 0;
			sockaddr_storage sa = {};
			int sa_len = 0;
		};

		struct winhttp_handle_t {
			HINTERNET handle = nullptr;
			winhttp_handle_t() = default;
			explicit winhttp_handle_t(HINTERNET h) : handle(h) {}
			~winhttp_handle_t() { if (handle) WinHttpCloseHandle(handle); }
			winhttp_handle_t(const winhttp_handle_t&) = delete;
			winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
			explicit operator bool() const { return handle != nullptr; }
			HINTERNET release() noexcept
			{
				HINTERNET value = handle;
				handle = nullptr;
				return value;
			}
		};

		struct cancellable_winhttp_handle_t {
			std::atomic<HINTERNET> handle{ nullptr };
			const request_deadline_t deadline;
			const cancel_cb_t* cancelled = nullptr;
			std::atomic<bool> stopping{ false };
			std::atomic<bool> cancellation_observed{ false };
			std::atomic<bool> deadline_observed{ false };
			std::mutex wait_mutex;
			std::condition_variable wake;
			std::thread monitor;

			cancellable_winhttp_handle_t(const request_deadline_t& request_deadline_value,
				const cancel_cb_t& cancel_callback) noexcept
				: deadline(request_deadline_value), cancelled(&cancel_callback) {}

			~cancellable_winhttp_handle_t()
			{
				stopping.store(true, std::memory_order_release);
				wake.notify_all();
				if (monitor.joinable()) monitor.join();
				HINTERNET value = handle.exchange(nullptr, std::memory_order_acq_rel);
				if (value) WinHttpCloseHandle(value);
			}

			cancellable_winhttp_handle_t(const cancellable_winhttp_handle_t&) = delete;
			cancellable_winhttp_handle_t& operator=(const cancellable_winhttp_handle_t&) = delete;

			bool adopt(winhttp_handle_t& source, std::string& error)
			{
				HINTERNET value = source.release();
				if (!value) {
					error = "WinHTTP request handle is unavailable";
					return false;
				}
				handle.store(value, std::memory_order_release);
				try {
					monitor = std::thread([this]() noexcept { watch(); });
				} catch (...) {
					value = handle.exchange(nullptr, std::memory_order_acq_rel);
					if (value) WinHttpCloseHandle(value);
					error = "WinHTTP cancellation monitor allocation failed";
					return false;
				}
				return true;
			}

			HINTERNET get() const noexcept { return handle.load(std::memory_order_acquire); }
			bool was_cancelled() const noexcept
			{
				return cancellation_observed.load(std::memory_order_acquire);
			}
			bool deadline_expired() const noexcept
			{
				return deadline_observed.load(std::memory_order_acquire);
			}

			void watch() noexcept
			{
				for (;;) {
					if (stopping.load(std::memory_order_acquire)) return;
					if (cancelled && cancellation_requested(*cancelled)) {
						cancellation_observed.store(true, std::memory_order_release);
						break;
					}
					if (std::chrono::steady_clock::now() >= deadline) {
						deadline_observed.store(true, std::memory_order_release);
						break;
					}
					try {
						std::unique_lock<std::mutex> lock(wait_mutex);
						wake.wait_for(lock, std::chrono::milliseconds(50), [this]() noexcept {
							return stopping.load(std::memory_order_acquire);
						});
					} catch (...) {
						cancellation_observed.store(true, std::memory_order_release);
						break;
					}
				}
				HINTERNET value = handle.exchange(nullptr, std::memory_order_acq_rel);
				if (value) WinHttpCloseHandle(value);
			}
		};

		int cancellable_socket_poll(SOCKET socket_value, short events,
			const request_deadline_t& deadline, const cancel_cb_t& cancelled) noexcept
		{
			for (;;) {
				if (cancellation_requested(cancelled)) return -2;
				const int remaining = remaining_timeout_ms(deadline);
				if (remaining <= 0) return 0;
				WSAPOLLFD descriptor = {};
				descriptor.fd = socket_value;
				descriptor.events = events;
				const int result = WSAPoll(&descriptor, 1, (std::min)(remaining, 50));
				if (result != 0) return result;
			}
		}

		template <typename Callback>
		struct scope_exit_t {
			Callback* callback = nullptr;
			explicit scope_exit_t(Callback& value) noexcept : callback(&value) {}
			~scope_exit_t() noexcept
			{
				if (!callback) return;
				try { (*callback)(); } catch (...) {}
			}
			scope_exit_t(const scope_exit_t&) = delete;
			scope_exit_t& operator=(const scope_exit_t&) = delete;
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
			~pooled_conn_t() noexcept { release(); }
			void release() noexcept
			{
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
					::shutdown(sock, SD_BOTH);
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			}
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
			if (conn) conn->release();
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

		static bool pooled_connection_clean(const pooled_conn_t& conn) noexcept
		{
			if (conn.sock == INVALID_SOCKET) return false;
			if (conn.ssl && SSL_pending(conn.ssl) != 0) return false;
			WSAPOLLFD pfd = {};
			pfd.fd = conn.sock;
			pfd.events = POLLRDNORM;
			return WSAPoll(&pfd, 1, 0) == 0;
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
					if (!pooled_connection_clean(*p)) {
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
			if (!conn || !pooled_connection_clean(*conn)) {
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
			out = parsed_url_t{};
			if (url.empty() || url.size() > kMaximumUrlBytes) return false;
			std::size_t authority_begin = 0;
			if (url.rfind("https://", 0) == 0) {
				out.https = true;
				out.port = 443;
				authority_begin = 8;
			} else if (url.rfind("http://", 0) == 0) {
				out.https = false;
				out.port = 80;
				authority_begin = 7;
			} else {
				return false;
			}
			for (unsigned char ch : url) {
				if (ch < 0x21 || ch >= 0x7F || ch == '\\') return false;
			}
			if (url.find('#', authority_begin) != std::string::npos) return false;
			const std::size_t authority_end = url.find_first_of("/?", authority_begin);
			const std::size_t authority_stop = authority_end == std::string::npos
				? url.size() : authority_end;
			const std::string authority = url.substr(authority_begin,
				authority_stop - authority_begin);
			if (authority.empty() || authority.find('@') != std::string::npos) return false;
			std::string raw_host;
			std::string port_text;
			bool explicit_port = false;
			if (authority.front() == '[') {
				const std::size_t close = authority.find(']');
				if (close == std::string::npos || close == 1) return false;
				if (authority.find('[', 1) != std::string::npos
					|| authority.find(']', close + 1) != std::string::npos) return false;
				raw_host = authority.substr(1, close - 1);
				if (close + 1 < authority.size()) {
					if (authority[close + 1] != ':') return false;
					port_text = authority.substr(close + 2);
					explicit_port = true;
				}
				IN6_ADDR address{};
				if (InetPtonA(AF_INET6, raw_host.c_str(), &address) != 1) return false;
				char canonical[INET6_ADDRSTRLEN]{};
				if (InetNtopA(AF_INET6, &address, canonical,
					static_cast<DWORD>(sizeof(canonical))) == nullptr) return false;
				out.host = canonical;
				out.ipv6 = true;
				out.ip_literal = true;
			} else {
				const std::size_t colon = authority.find(':');
				if (colon != std::string::npos) {
					if (authority.find(':', colon + 1) != std::string::npos) return false;
					raw_host = authority.substr(0, colon);
					port_text = authority.substr(colon + 1);
					explicit_port = true;
				} else {
					raw_host = authority;
				}
				if (raw_host.empty() || raw_host.size() > 253 || raw_host.back() == '.') return false;
				IN_ADDR ipv4{};
				if (InetPtonA(AF_INET, raw_host.c_str(), &ipv4) == 1) {
					char canonical[INET_ADDRSTRLEN]{};
					if (InetNtopA(AF_INET, &ipv4, canonical,
						static_cast<DWORD>(sizeof(canonical))) == nullptr) return false;
					out.host = canonical;
					out.ip_literal = true;
				} else {
					if (raw_host.find_first_not_of("0123456789.") == std::string::npos) return false;
					std::size_t cursor = 0;
					while (cursor < raw_host.size()) {
						const std::size_t dot = raw_host.find('.', cursor);
						const std::size_t stop = dot == std::string::npos ? raw_host.size() : dot;
						if (stop == cursor || stop - cursor > 63 || raw_host[cursor] == '-'
							|| raw_host[stop - 1] == '-') return false;
						for (std::size_t index = cursor; index < stop; ++index) {
							const unsigned char ch = static_cast<unsigned char>(raw_host[index]);
							if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
								|| (ch >= '0' && ch <= '9') || ch == '-')) return false;
							out.host.push_back(ch >= 'A' && ch <= 'Z'
								? static_cast<char>(ch + ('a' - 'A')) : static_cast<char>(ch));
						}
						if (dot == std::string::npos) break;
						out.host.push_back('.');
						cursor = dot + 1;
					}
				}
			}
			if (explicit_port) {
				if (port_text.empty() || port_text.size() > 5) return false;
				unsigned port = 0;
				for (unsigned char ch : port_text) {
					if (ch < '0' || ch > '9') return false;
					port = port * 10u + static_cast<unsigned>(ch - '0');
				}
				if (port == 0 || port > 65535u) return false;
				out.port = static_cast<int>(port);
			}
			out.path = authority_end == std::string::npos ? std::string("/")
				: url[authority_end] == '?' ? std::string("/") + url.substr(authority_end)
					: url.substr(authority_end);
			if (out.path.empty() || out.path.front() != '/') return false;
			for (std::size_t index = 0; index < out.path.size(); ++index) {
				const unsigned char ch = static_cast<unsigned char>(out.path[index]);
				if (ch == '%') {
					if (index + 2 >= out.path.size()) return false;
					auto hex_value = [](unsigned char value) noexcept -> int {
						if (value >= '0' && value <= '9') return value - '0';
						if (value >= 'a' && value <= 'f') return value - 'a' + 10;
						if (value >= 'A' && value <= 'F') return value - 'A' + 10;
						return -1;
					};
					const int high = hex_value(static_cast<unsigned char>(out.path[index + 1]));
					const int low = hex_value(static_cast<unsigned char>(out.path[index + 2]));
					if (high < 0 || low < 0) return false;
					const unsigned char decoded = static_cast<unsigned char>((high << 4) | low);
					if (decoded < 0x20 || decoded == 0x7F || decoded == '\\') return false;
					index += 2;
				}
			}
			out.authority = out.ipv6 ? "[" + out.host + "]" : out.host;
			if ((out.https && out.port != 443) || (!out.https && out.port != 80))
				out.authority += ":" + std::to_string(out.port);
			return !out.host.empty();
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

		std::vector<resolved_addr_t> resolve_host_addrs(const std::string& host,
			int port, int timeout_ms, std::string& diag_out,
			const cancel_cb_t& cancelled)
		{
			std::vector<resolved_addr_t> results;
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%d", port);
			char gai_buf[160] = {};

			const int total_budget_ms = timeout_ms > 0 ? timeout_ms : 1;
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

			for (;;) {
				if (cancellation_requested(cancelled)) {
					diag_out = "cancelled";
					return results;
				}
				const int remaining = remaining_ms();
				if (remaining <= 0) break;
				ADDRINFOEXW hints = {};
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				PADDRINFOEXW gai_res = nullptr;
				const int gai_budget_ms = (std::min)(remaining, 100);
				timeval gai_timeout = {};
				gai_timeout.tv_sec = gai_budget_ms / 1000;
				gai_timeout.tv_usec = (gai_budget_ms % 1000) * 1000;
				const int gai_rc = GetAddrInfoExW(host_w.c_str(), port_w.c_str(), NS_DNS,
					nullptr, &hints, &gai_res, &gai_timeout, nullptr, nullptr, nullptr);
				auto release_gai = [&]() noexcept {
					if (gai_res) FreeAddrInfoExW(gai_res);
					gai_res = nullptr;
				};
				scope_exit_t<decltype(release_gai)> gai_guard(release_gai);
				static_cast<void>(gai_guard);
				if (gai_rc == 0 && gai_res) {
					append_addrinfoex_results(gai_res, results);
					break;
				} else {
					snprintf(gai_buf, sizeof(gai_buf), "GetAddrInfoExW rc=%d wsa=%lu",
						gai_rc, static_cast<unsigned long>(WSAGetLastError()));
					if (gai_rc != WSAETIMEDOUT && gai_rc != WSATRY_AGAIN)
						break;
				}
			}
			if (cancellation_requested(cancelled)) {
				diag_out = "cancelled";
				return {};
			}

			if (results.empty()) {
				diag_out.clear();
				if (gai_buf[0] != '\0')
					diag_out += gai_buf;
				if (diag_out.empty())
					diag_out = "no addresses returned";
			}
			return results;
		}

		struct response_framing_t {
			int status = 0;
			bool http_1_0 = false;
			bool chunked = false;
			bool connection_close = false;
			bool connection_keep_alive = false;
			bool content_length_present = false;
			std::uint64_t content_length = 0;
		};

		bool http_token_char(unsigned char value) noexcept
		{
			if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
				|| (value >= '0' && value <= '9')) return true;
			switch (value) {
			case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
			case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
				return true;
			default:
				return false;
			}
		}

		std::string trim_http_value(const std::string& input)
		{
			std::size_t begin = 0;
			while (begin < input.size() && (input[begin] == ' ' || input[begin] == '\t')) ++begin;
			std::size_t end = input.size();
			while (end > begin && (input[end - 1] == ' ' || input[end - 1] == '\t')) --end;
			return input.substr(begin, end - begin);
		}

		std::string lowercase_ascii(std::string input)
		{
			for (char& ch : input) {
				if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
			}
			return input;
		}

		bool valid_http_field_value(const std::string& value) noexcept
		{
			for (unsigned char ch : value) {
				if ((ch < 0x20 && ch != '\t') || ch == 0x7F) return false;
			}
			return true;
		}

		bool header_has_token(const std::string& value, const char* expected)
		{
			std::size_t cursor = 0;
			while (cursor <= value.size()) {
				const std::size_t comma = value.find(',', cursor);
				const std::size_t stop = comma == std::string::npos ? value.size() : comma;
				if (lowercase_ascii(trim_http_value(value.substr(cursor, stop - cursor))) == expected)
					return true;
				if (comma == std::string::npos) break;
				cursor = comma + 1;
			}
			return false;
		}

		std::string sanitize_http_error_snippet(const std::string& body)
		{
			const std::size_t count = (std::min)(body.size(), static_cast<std::size_t>(800));
			std::string result;
			result.reserve(count);
			bool prior_space = false;
			for (std::size_t index = 0; index < count; ++index) {
				const unsigned char ch = static_cast<unsigned char>(body[index]);
				const bool replace = ch < 0x20 || ch == 0x7F;
				if (replace) {
					if (!prior_space) result.push_back(' ');
					prior_space = true;
				} else {
					result.push_back(static_cast<char>(ch));
					prior_space = ch == ' ';
				}
			}
			while (!result.empty() && result.back() == ' ') result.pop_back();
			return result;
		}

		bool parse_decimal_size(const std::string& input, std::uint64_t& value) noexcept
		{
			if (input.empty()) return false;
			value = 0;
			for (unsigned char ch : input) {
				if (ch < '0' || ch > '9') return false;
				const unsigned digit = static_cast<unsigned>(ch - '0');
				if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u)
					return false;
				value = value * 10u + digit;
			}
			return true;
		}

		bool parse_response_head(const std::string& head, response_framing_t& framing,
			std::string& error)
		{
			framing = response_framing_t{};
			if (head.empty() || head.size() > kMaximumHeaderBytes) {
				error = "HTTP response headers exceed the limit";
				return false;
			}
			for (std::size_t index = 0; index < head.size(); ++index) {
				if (head[index] == '\r') {
					if (index + 1 >= head.size() || head[index + 1] != '\n') {
						error = "HTTP response contains a bare carriage return";
						return false;
					}
				} else if (head[index] == '\n' && (index == 0 || head[index - 1] != '\r')) {
					error = "HTTP response contains a bare line feed";
					return false;
				}
			}
			const std::size_t status_end = head.find("\r\n");
			const std::string status_line = status_end == std::string::npos
				? head : head.substr(0, status_end);
			if (status_line.size() < 12
				|| (status_line.rfind("HTTP/1.0 ", 0) != 0
					&& status_line.rfind("HTTP/1.1 ", 0) != 0)
				|| status_line[9] < '1' || status_line[9] > '5'
				|| status_line[10] < '0' || status_line[10] > '9'
				|| status_line[11] < '0' || status_line[11] > '9'
				|| (status_line.size() > 12 && status_line[12] != ' ')) {
				error = "malformed HTTP status line";
				return false;
			}
			framing.http_1_0 = status_line.rfind("HTTP/1.0 ", 0) == 0;
			framing.status = (status_line[9] - '0') * 100
				+ (status_line[10] - '0') * 10 + (status_line[11] - '0');
			if (status_line.size() > 12
				&& !valid_http_field_value(status_line.substr(12))) {
				error = "invalid HTTP reason phrase";
				return false;
			}
			std::size_t cursor = status_end == std::string::npos ? head.size() : status_end + 2;
			while (cursor < head.size()) {
				const std::size_t line_end = head.find("\r\n", cursor);
				const std::size_t stop = line_end == std::string::npos ? head.size() : line_end;
				if (stop == cursor) {
					error = "unexpected empty HTTP header line";
					return false;
				}
				const std::string line = head.substr(cursor, stop - cursor);
				const std::size_t colon = line.find(':');
				if (colon == std::string::npos || colon == 0) {
					error = "malformed HTTP header";
					return false;
				}
				std::string name = line.substr(0, colon);
				for (char& ch : name) {
					const unsigned char value = static_cast<unsigned char>(ch);
					if (!http_token_char(value)) {
						error = "invalid HTTP header name";
						return false;
					}
					if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
				}
				std::string value = trim_http_value(line.substr(colon + 1));
				if (!valid_http_field_value(value)) {
					error = "invalid HTTP header value";
					return false;
				}
				const std::string lower = lowercase_ascii(value);
				if (name == "content-length") {
					std::uint64_t parsed = 0;
					if (!parse_decimal_size(value, parsed)
						|| parsed > kMaximumResponseBytes
						|| framing.content_length_present) {
						error = "invalid or duplicate Content-Length";
						return false;
					}
					framing.content_length_present = true;
					framing.content_length = parsed;
				} else if (name == "transfer-encoding") {
					if (lower != "chunked" || framing.chunked) {
						error = "unsupported or duplicate Transfer-Encoding";
						return false;
					}
					framing.chunked = true;
				} else if (name == "connection") {
					framing.connection_close = framing.connection_close
						|| header_has_token(lower, "close");
					framing.connection_keep_alive = framing.connection_keep_alive
						|| header_has_token(lower, "keep-alive");
				}
				cursor = line_end == std::string::npos ? head.size() : line_end + 2;
			}
			if (framing.chunked && framing.content_length_present) {
				error = "HTTP response has conflicting body framing";
				return false;
			}
			return true;
		}

		bool response_connection_persistent(const response_framing_t& framing) noexcept
		{
			return !framing.connection_close
				&& (!framing.http_1_0 || framing.connection_keep_alive);
		}

		bool parse_chunk_size_line(const std::string& line, std::uint64_t& value) noexcept
		{
			const std::size_t semicolon = line.find(';');
			const std::size_t digits = semicolon == std::string::npos ? line.size() : semicolon;
			if (digits == 0 || digits > 16) return false;
			value = 0;
			for (std::size_t index = 0; index < digits; ++index) {
				const unsigned char ch = static_cast<unsigned char>(line[index]);
				unsigned digit = 0;
				if (ch >= '0' && ch <= '9') digit = ch - '0';
				else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
				else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
				else return false;
				if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 16u)
					return false;
				value = value * 16u + digit;
			}
			std::size_t cursor = digits;
			while (cursor < line.size()) {
				if (line[cursor++] != ';') return false;
				const std::size_t name_begin = cursor;
				while (cursor < line.size()
					&& http_token_char(static_cast<unsigned char>(line[cursor]))) ++cursor;
				if (cursor == name_begin) return false;
				if (cursor == line.size()) continue;
				if (line[cursor++] != '=') return false;
				if (cursor == line.size()) return false;
				if (line[cursor] == '"') {
					++cursor;
					bool closed = false;
					while (cursor < line.size()) {
						const unsigned char ch = static_cast<unsigned char>(line[cursor++]);
						if (ch == '"') {
							closed = true;
							break;
						}
						if (ch == '\\') {
							if (cursor == line.size()) return false;
							const unsigned char escaped = static_cast<unsigned char>(line[cursor++]);
							if ((escaped < 0x20 && escaped != '\t') || escaped == 0x7F)
								return false;
						} else if ((ch < 0x20 && ch != '\t') || ch == 0x7F) {
							return false;
						}
					}
					if (!closed) return false;
				} else {
					const std::size_t value_begin = cursor;
					while (cursor < line.size()
						&& http_token_char(static_cast<unsigned char>(line[cursor]))) ++cursor;
					if (cursor == value_begin) return false;
				}
			}
			return true;
		}

		bool validate_chunk_trailer(const std::string& trailer,
			std::size_t& aggregate_bytes, std::string& error)
		{
			if (trailer.size() + 2 > kMaximumHeaderBytes - aggregate_bytes) {
				error = "chunk trailers exceed the limit";
				return false;
			}
			aggregate_bytes += trailer.size() + 2;
			const std::size_t colon = trailer.find(':');
			if (colon == std::string::npos || colon == 0) {
				error = "malformed chunk trailer";
				return false;
			}
			std::string name = trailer.substr(0, colon);
			for (char& ch : name) {
				if (!http_token_char(static_cast<unsigned char>(ch))) {
					error = "invalid chunk trailer name";
					return false;
				}
				if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
			}
			if (name == "content-length" || name == "transfer-encoding"
				|| name == "host" || name == "connection" || name == "keep-alive"
				|| name == "proxy-authenticate" || name == "proxy-authorization"
				|| name == "te" || name == "trailer" || name == "upgrade") {
				error = "forbidden chunk trailer field";
				return false;
			}
			if (!valid_http_field_value(trim_http_value(trailer.substr(colon + 1)))) {
				error = "invalid chunk trailer value";
				return false;
			}
			return true;
		}

		bool decode_chunked_body(const std::string& encoded, std::string& decoded,
			std::string& error, bool& incomplete)
		{
			decoded.clear();
			incomplete = false;
			std::size_t cursor = 0;
			while (cursor < encoded.size()) {
				const std::size_t line_end = encoded.find("\r\n", cursor);
				if (line_end == std::string::npos) {
					incomplete = true;
					error = "incomplete chunk size line";
					return false;
				}
				if (line_end - cursor > 1024) {
					error = "chunk size line exceeds the limit";
					return false;
				}
				std::uint64_t size = 0;
				if (!parse_chunk_size_line(encoded.substr(cursor, line_end - cursor), size)) {
					error = "invalid chunk size";
					return false;
				}
				cursor = line_end + 2;
				if (size == 0) {
					std::size_t trailer_bytes = 0;
					for (;;) {
						const std::size_t trailer_end = encoded.find("\r\n", cursor);
						if (trailer_end == std::string::npos) {
							incomplete = true;
							error = "incomplete chunk trailers";
							return false;
						}
						if (trailer_end == cursor) {
							cursor += 2;
							if (cursor != encoded.size()) {
								error = "bytes follow terminal chunk";
								return false;
							}
							return true;
						}
						const std::string trailer = encoded.substr(cursor, trailer_end - cursor);
						if (!validate_chunk_trailer(trailer, trailer_bytes, error)) return false;
						cursor = trailer_end + 2;
					}
				}
				if (size > kMaximumResponseBytes - decoded.size()) {
					error = "decoded chunked body exceeds the limit";
					return false;
				}
				if (size > encoded.size() - cursor) {
					incomplete = true;
					error = "incomplete chunk data";
					return false;
				}
				const std::size_t count = static_cast<std::size_t>(size);
				decoded.append(encoded, cursor, count);
				cursor += count;
				if (cursor + 2 > encoded.size()) {
					incomplete = true;
					error = "chunk data terminator missing";
					return false;
				}
				if (encoded[cursor] != '\r' || encoded[cursor + 1] != '\n') {
					error = "chunk data terminator invalid";
					return false;
				}
				cursor += 2;
			}
			incomplete = true;
			error = "terminal chunk missing";
			return false;
		}

		void parse_http_response(const char* verb, const std::string& raw,
			bool eof_complete, response_t& out)
		{
			out = response_t{};
			if (raw.size() > kMaximumResponseBytes + kMaximumHeaderBytes) {
				out.truncated = true;
				out.error = "HTTP response exceeds the limit";
				return;
			}
			response_framing_t framing;
			std::size_t cursor = 0;
			std::size_t interim_count = 0;
			for (;;) {
				const std::size_t header_end = raw.find("\r\n\r\n", cursor);
				if (header_end == std::string::npos || header_end - cursor > kMaximumHeaderBytes) {
					out.truncated = header_end == std::string::npos;
					out.error = header_end == std::string::npos
						? "incomplete HTTP response headers"
						: "HTTP response headers exceed the limit";
					return;
				}
				if (!parse_response_head(raw.substr(cursor, header_end - cursor),
						framing, out.error)) return;
				cursor = header_end + 4;
				if (framing.status < 100 || framing.status >= 200) break;
				if (framing.status == 101 || framing.chunked
					|| framing.content_length_present) {
					out.error = framing.status == 101 ? "HTTP protocol switching is unsupported"
						: "interim HTTP response contains body framing";
					return;
				}
				if (++interim_count > 8) {
					out.error = "too many interim HTTP responses";
					return;
				}
			}
			out.status = framing.status;
			const std::string encoded = raw.substr(cursor);
			const bool head_response = verb && std::strcmp(verb, "HEAD") == 0;
			if (head_response || out.status == 304) {
				if (!encoded.empty()) {
					out.error = "body is forbidden for this HTTP status";
					return;
				}
			} else if (out.status == 204) {
				if (!encoded.empty() || framing.chunked || framing.content_length_present) {
					out.error = "body framing is forbidden for HTTP 204";
					return;
				}
			} else if (out.status == 205) {
				if (framing.content_length_present && framing.content_length != 0) {
					out.error = "HTTP 205 Content-Length must be zero";
					return;
				}
				if (framing.chunked) {
					std::string decoded;
					bool incomplete = false;
					if (!decode_chunked_body(encoded, decoded, out.error, incomplete)) {
						out.truncated = incomplete;
						return;
					}
					if (!decoded.empty()) {
						out.error = "body is forbidden for HTTP 205";
						return;
					}
				} else if (!encoded.empty()) {
					out.error = "body is forbidden for HTTP 205";
					return;
				}
			} else if (framing.chunked) {
				bool incomplete = false;
				if (!decode_chunked_body(encoded, out.body, out.error, incomplete)) {
					out.truncated = incomplete
						|| out.error == "decoded chunked body exceeds the limit";
					return;
				}
			} else if (framing.content_length_present) {
				if (encoded.size() != framing.content_length) {
					out.truncated = encoded.size() < framing.content_length;
					out.error = "HTTP body length does not match Content-Length";
					return;
				}
				out.body = encoded;
			} else {
				if (!eof_complete) {
					out.truncated = true;
					out.error = "close-delimited HTTP body is incomplete";
					return;
				}
				if (encoded.size() > kMaximumResponseBytes) {
					out.truncated = true;
					out.error = "HTTP body exceeds the limit";
					return;
				}
				out.body = encoded;
			}
			out.ok = true;
			out.complete = true;
			out.error.clear();
		}

		bool validate_request_metadata(const char* verb, const header_list_t& headers,
			const std::string& body, const std::string& content_type, int timeout_sec,
			std::string& error)
		{
			if (verb == nullptr || *verb == '\0') {
				error = "HTTP method is missing";
				return false;
			}
			std::size_t verb_length = 0;
			for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(verb);
				*cursor != 0; ++cursor) {
				if (++verb_length > 16 || !http_token_char(*cursor)) {
					error = "HTTP method is invalid";
					return false;
				}
			}
			if (body.size() > kMaximumResponseBytes) {
				error = "HTTP request body exceeds the limit";
				return false;
			}
			if (timeout_sec < 0 || timeout_sec > 300) {
				error = "HTTP timeout is outside the supported range";
				return false;
			}
			if (content_type.size() > 1024) {
				error = "HTTP content type exceeds the limit";
				return false;
			}
			for (unsigned char ch : content_type) {
				if ((ch < 0x20 && ch != '\t') || ch == 0x7F) {
					error = "HTTP content type is invalid";
					return false;
				}
			}
			std::size_t aggregate_header_bytes = 0;
			for (const auto& header : headers) {
				if (header.first.empty() || header.first.size() > 256
					|| header.second.size() > kMaximumHeaderBytes) {
					error = "HTTP request header size is invalid";
					return false;
				}
				if (header.first.size() + header.second.size() + 4
					> kMaximumHeaderBytes - aggregate_header_bytes) {
					error = "HTTP request headers exceed the limit";
					return false;
				}
				aggregate_header_bytes += header.first.size() + header.second.size() + 4;
				std::string lower;
				lower.reserve(header.first.size());
				for (unsigned char ch : header.first) {
					if (!http_token_char(ch)) {
						error = "HTTP request header name is invalid";
						return false;
					}
					lower.push_back(ch >= 'A' && ch <= 'Z'
						? static_cast<char>(ch + ('a' - 'A')) : static_cast<char>(ch));
				}
				if (lower == "host" || lower == "content-length"
					|| lower == "transfer-encoding" || lower == "connection") {
					error = "HTTP request header conflicts with managed framing";
					return false;
				}
				for (unsigned char ch : header.second) {
					if ((ch < 0x20 && ch != '\t') || ch == 0x7F) {
						error = "HTTP request header value is invalid";
						return false;
					}
				}
			}
			return true;
		}

		bool replay_safe_method(const char* verb) noexcept
		{
			return verb != nullptr && (std::strcmp(verb, "GET") == 0
				|| std::strcmp(verb, "HEAD") == 0
				|| std::strcmp(verb, "OPTIONS") == 0);
		}

		void load_windows_root_certs(SSL_CTX* ctx)
		{
			X509_STORE* ossl_store = SSL_CTX_get_cert_store(ctx);
			if (!ossl_store)
				return;
			HCERTSTORE win_store = CertOpenSystemStoreW(0, L"ROOT");
			if (!win_store) return;
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

		bool verify_windows_tls_chain(SSL* ssl, const std::string& host,
			const request_deadline_t& deadline, std::string& error,
			const cancel_cb_t& cancelled)
		{
			X509* openssl_cert = nullptr;
			PCCERT_CONTEXT certificate = nullptr;
			PCCERT_CHAIN_CONTEXT chain = nullptr;
			auto release = [&]() noexcept {
				if (chain) CertFreeCertificateChain(chain);
				if (certificate) CertFreeCertificateContext(certificate);
				if (openssl_cert) X509_free(openssl_cert);
			};
			try {
				if (cancellation_requested(cancelled)) {
					error = "TLS verification cancelled";
					return false;
				}
				const int remaining = remaining_timeout_ms(deadline);
				if (remaining <= 0) {
					error = "TLS verification deadline expired";
					return false;
				}
				openssl_cert = SSL_get1_peer_certificate(ssl);
				if (!openssl_cert) {
					error = "TLS peer certificate is missing";
					return false;
				}
				const int encoded_size = i2d_X509(openssl_cert, nullptr);
				if (encoded_size <= 0 || encoded_size > 1024 * 1024) {
					error = "TLS peer certificate encoding is invalid";
					release();
					return false;
				}
				std::vector<unsigned char> encoded(static_cast<std::size_t>(encoded_size));
				unsigned char* cursor = encoded.data();
				if (i2d_X509(openssl_cert, &cursor) != encoded_size) {
					error = "TLS peer certificate encoding failed";
					release();
					return false;
				}
				certificate = CertCreateCertificateContext(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, encoded.data(),
					static_cast<DWORD>(encoded.size()));
				if (!certificate) {
					error = "Windows TLS certificate import failed gle="
						+ std::to_string(GetLastError());
					release();
					return false;
				}
				CERT_CHAIN_PARA chain_parameters{};
				chain_parameters.cbSize = static_cast<DWORD>(sizeof(chain_parameters));
				chain_parameters.dwUrlRetrievalTimeout = static_cast<DWORD>(
					(std::min)(remaining, 200));
				if (!CertGetCertificateChain(nullptr, certificate, nullptr,
						certificate->hCertStore, &chain_parameters,
						CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, nullptr, &chain)) {
					error = "Windows TLS chain build failed gle="
						+ std::to_string(GetLastError());
					release();
					return false;
				}
				if (cancellation_requested(cancelled)) {
					error = "TLS verification cancelled";
					release();
					return false;
				}
				if (chain->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
					error = "Windows TLS chain or revocation validation failed status="
						+ std::to_string(chain->TrustStatus.dwErrorStatus);
					release();
					return false;
				}
				std::wstring host_w = utf8_to_utf16(host);
				HTTPSPolicyCallbackData ssl_policy{};
				ssl_policy.cbStruct = static_cast<DWORD>(sizeof(ssl_policy));
				ssl_policy.dwAuthType = AUTHTYPE_SERVER;
				ssl_policy.pwszServerName = host_w.empty() ? nullptr : host_w.data();
				CERT_CHAIN_POLICY_PARA policy_parameters{};
				policy_parameters.cbSize = static_cast<DWORD>(sizeof(policy_parameters));
				policy_parameters.pvExtraPolicyPara = &ssl_policy;
				CERT_CHAIN_POLICY_STATUS policy_status{};
				policy_status.cbSize = static_cast<DWORD>(sizeof(policy_status));
				if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
						&policy_parameters, &policy_status)
					|| policy_status.dwError != ERROR_SUCCESS) {
					error = "Windows TLS hostname policy failed status="
						+ std::to_string(policy_status.dwError);
					release();
					return false;
				}
				release();
				error.clear();
				return true;
			} catch (...) {
				release();
				error = "Windows TLS chain validation allocation failed";
				return false;
			}
		}

		bool set_winhttp_budget(HINTERNET handle, const request_deadline_t& deadline,
			bool split_connection_phases, std::string& error)
		{
			const int remaining = remaining_timeout_ms(deadline);
			if (remaining <= 0) {
				error = "HTTP request deadline expired";
				return false;
			}
			const int phase = split_connection_phases
				? ((remaining / 3) > 0 ? remaining / 3 : 1) : remaining;
			if (!WinHttpSetTimeouts(handle, phase, phase, phase, phase)) {
				error = "WinHttpSetTimeouts failed err=" + std::to_string(GetLastError());
				return false;
			}
			return true;
		}

		response_t winhttp_request(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, const request_deadline_t& deadline,
			const cancel_cb_t& cancelled)
		{
			response_t out;
			if (cancellation_requested(cancelled)) {
				out.cancelled = true;
				out.error = "HTTP request cancelled";
				return out;
			}
			if (!pu.https) {
				out.error = "WinHTTP requests are restricted to TLS URLs";
				return out;
			}

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

			if (!set_winhttp_budget(session.handle, deadline, true, out.error)) return out;
			DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#if defined(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
			protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
			if (!WinHttpSetOption(session.handle, WINHTTP_OPTION_SECURE_PROTOCOLS,
					&protocols, static_cast<DWORD>(sizeof(protocols)))) {
				out.error = "WinHttp TLS protocol policy failed err="
					+ std::to_string(GetLastError());
				return out;
			}

			winhttp_handle_t connection(WinHttpConnect(session.handle, host_w.c_str(),
				static_cast<INTERNET_PORT>(pu.port), 0));
			if (!connection) {
				out.error = "WinHttpConnect failed err=" + std::to_string(GetLastError());
				return out;
			}

			const DWORD req_flags = WINHTTP_FLAG_SECURE;
			winhttp_handle_t request_handle(WinHttpOpenRequest(connection.handle,
				verb_w.c_str(), path_w.c_str(), nullptr, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags));
			if (!request_handle) {
				out.error = "WinHttpOpenRequest failed err="
					+ std::to_string(GetLastError());
				return out;
			}
			cancellable_winhttp_handle_t request_guard(deadline, cancelled);
			if (!request_guard.adopt(request_handle, out.error))
				return out;
			auto interrupted = [&]() -> bool {
				if (request_guard.was_cancelled()) {
					out.cancelled = true;
					out.truncated = false;
					out.error = "HTTP request cancelled";
					return true;
				}
				if (request_guard.deadline_expired()
					|| remaining_timeout_ms(deadline) <= 0) {
					out.truncated = !out.body.empty();
					out.error = "HTTP request deadline expired";
					return true;
				}
				return false;
			};
			auto winhttp_failure = [&](const char* operation, DWORD error) -> bool {
				if (interrupted()) return true;
				out.error = std::string(operation) + " failed err="
					+ std::to_string(error);
				return false;
			};
			if (!set_winhttp_budget(request_guard.get(), deadline, true, out.error)) {
				interrupted();
				return out;
			}
			DWORD feature = WINHTTP_ENABLE_SSL_REVOCATION;
			if (!WinHttpSetOption(request_guard.get(), WINHTTP_OPTION_ENABLE_FEATURE,
					&feature, static_cast<DWORD>(sizeof(feature)))) {
				winhttp_failure("WinHttp revocation policy", GetLastError());
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

			if (!WinHttpSendRequest(request_guard.get(),
					all_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
						: all_headers.c_str(),
					headers_len, body_ptr, body_len, body_len, 0)) {
				winhttp_failure("WinHttpSendRequest", GetLastError());
				return out;
			}

			if (!set_winhttp_budget(request_guard.get(), deadline, false, out.error)) {
				interrupted();
				return out;
			}
			if (!WinHttpReceiveResponse(request_guard.get(), nullptr)) {
				winhttp_failure("WinHttpReceiveResponse", GetLastError());
				return out;
			}

			DWORD status_code = 0;
			DWORD status_size = sizeof(status_code);
			if (!WinHttpQueryHeaders(request_guard.get(),
					WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
					WINHTTP_NO_HEADER_INDEX)) {
				winhttp_failure("WinHttpQueryHeaders", GetLastError());
				return out;
			}
			out.status = static_cast<int>(status_code);

			bool body_complete = true;
			for (;;) {
				if (!set_winhttp_budget(request_guard.get(), deadline, false, out.error)) {
					body_complete = false;
					const bool stopped = interrupted();
					if (!stopped) out.truncated = true;
					break;
				}
				DWORD available = 0;
				if (!WinHttpQueryDataAvailable(request_guard.get(), &available)) {
					body_complete = false;
					const DWORD error = GetLastError();
					const bool stopped = winhttp_failure("WinHttpQueryDataAvailable", error);
					if (!stopped) out.truncated = true;
					break;
				}
				if (available == 0)
					break;
				if (static_cast<std::size_t>(available) > kMaximumResponseBytes - out.body.size()) {
					body_complete = false;
					out.truncated = true;
					out.body.clear();
					out.error = "WinHTTP response exceeds the limit";
					break;
				}
				std::string chunk(available, '\0');
				DWORD read = 0;
				if (!WinHttpReadData(request_guard.get(), &chunk[0], available, &read)) {
					body_complete = false;
					const DWORD error = GetLastError();
					const bool stopped = winhttp_failure("WinHttpReadData", error);
					if (!stopped) out.truncated = true;
					break;
				}
				if (read == 0) {
					body_complete = false;
					out.truncated = true;
					out.error = "WinHTTP response ended before the advertised data";
					break;
				}
				out.body.append(chunk.data(), read);
			}

			if (interrupted()) {
				out.ok = false;
				out.complete = false;
				return out;
			}
			if (out.status > 0 && body_complete) {
				out.ok = true;
				out.complete = true;
				out.error.clear();
			} else if (out.error.empty()) {
				out.error = "winhttp incomplete response";
			}
			return out;
		}

		response_t raw_socket_request(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, const request_deadline_t& deadline,
			const cancel_cb_t& cancelled)
		{
			response_t out;
			if (cancellation_requested(cancelled)) {
				out.cancelled = true;
				out.error = "HTTP request cancelled";
				return out;
			}
			if (pu.https) {
				out.error = "raw socket requests are restricted to explicit non-TLS URLs";
				return out;
			}

			const int wsa = ensure_winsock();
			if (wsa != 0) {
				out.error = "WSAStartup failed rc=" + std::to_string(wsa);
				return out;
			}

			const uint64_t req_start_ms = now_steady_ms();
			diag::log_tagged_fmt("net",
				"raw_socket_request begin host=%s port=%d verb=%s timeout_s=%d",
				pu.host.c_str(), pu.port, verb ? verb : "?",
				(remaining_timeout_ms(deadline) + 999) / 1000);

			const int initial_remaining = remaining_timeout_ms(deadline);
			if (initial_remaining <= 0) {
				out.error = "HTTP request deadline expired before DNS resolution";
				return out;
			}
			const int resolve_budget = (initial_remaining / 2) > 0
				? initial_remaining / 2 : 1;
			std::string resolve_diag;
			std::vector<resolved_addr_t> candidates =
				resolve_host_addrs(pu.host, pu.port, resolve_budget, resolve_diag,
					cancelled);
			if (candidates.empty()) {
				if (resolve_diag == "cancelled" || cancellation_requested(cancelled)) {
					out.cancelled = true;
					out.error = "HTTP request cancelled";
					return out;
				}
				out.error = "DNS resolution failed for " + pu.host
					+ " (" + resolve_diag + ")";
				return out;
			}

			std::stable_sort(candidates.begin(), candidates.end(),
				[](const resolved_addr_t& a, const resolved_addr_t& b) {
					return (a.family == AF_INET) && (b.family != AF_INET);
				});

			auto remaining_ms = [&]() -> int {
				return remaining_timeout_ms(deadline);
			};

			SOCKET sock = INVALID_SOCKET;
			std::string connect_errors;
			bool saw_wsaenobufs = false;
			bool transport_cancelled = false;
			bool transport_deadline = false;
			for (const resolved_addr_t& addr : candidates) {
				if (cancellation_requested(cancelled)) {
					transport_cancelled = true;
					break;
				}
				if (remaining_ms() <= 0) {
					transport_deadline = true;
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
				const int pr = cancellable_socket_poll(s, POLLOUT, deadline, cancelled);
				if (pr <= 0) {
					if (pr == -2) transport_cancelled = true;
					if (pr == 0) transport_deadline = true;
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
					if (transport_cancelled || transport_deadline) break;
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
				break;
			}
			if (sock == INVALID_SOCKET) {
				if (transport_cancelled) {
					out.cancelled = true;
					out.error = "HTTP request cancelled";
					return out;
				}
				if (transport_deadline) {
					out.error = "HTTP request deadline expired during connection";
					return out;
				}
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
			const char* close_reason = "success";
			auto cleanup = [&]() {
				if (sock != INVALID_SOCKET) {
					diag::log_tagged_fmt("net",
						"raw_socket_request close host=%s port=%d reason=%s",
						pu.host.c_str(), pu.port,
						close_reason ? close_reason : "?");
					closesocket(sock);
					sock = INVALID_SOCKET;
				}
			};
			scope_exit_t<decltype(cleanup)> cleanup_guard(cleanup);
			static_cast<void>(cleanup_guard);
			std::string req;
			req += verb;
			req += " ";
			req += pu.path.empty() ? std::string("/") : pu.path;
			req += " HTTP/1.1\r\n";
			req += "Host: " + pu.authority + "\r\n";
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
				(void)wait_ms;
				return cancellable_socket_poll(sock, events, deadline, cancelled);
			};

			const size_t total_to_send = req.size();
			size_t total_sent = 0;
			{
				const char* data = req.data();
				int len = static_cast<int>(req.size());
				bool send_ok = true;
				bool send_enobufs = false;
				while (len > 0) {
					if (cancellation_requested(cancelled)) {
						transport_cancelled = true;
						send_ok = false;
						break;
					}
					if (remaining_ms() <= 0) {
						transport_deadline = true;
						send_ok = false;
						break;
					}
					const int n = ::send(sock, data, len, 0);
					if (n > 0) {
						data += n;
						len -= n;
						total_sent += static_cast<size_t>(n);
						continue;
					}
					short events = POLLOUT;
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
					const int poll_result = poll_sock(events, remaining_ms());
					if (poll_result <= 0) {
						if (poll_result == -2) transport_cancelled = true;
						if (poll_result == 0) transport_deadline = true;
						send_ok = false;
						break;
					}
				}
				if (!send_ok) {
					if (transport_cancelled) {
						out.cancelled = true;
						out.error = "HTTP request cancelled";
					} else if (transport_deadline) {
						out.error = "HTTP request deadline expired during send";
					} else {
						out.error = "send failed to " + pu.host;
					}
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
			bool receive_complete = false;
			bool receive_failed = false;
			bool receive_truncated = false;
			for (;;) {
				if (cancellation_requested(cancelled)) {
					transport_cancelled = true;
					break;
				}
				if (remaining_ms() <= 0) {
					transport_deadline = true;
					break;
				}
				const int n = ::recv(sock, buf, static_cast<int>(sizeof(buf)), 0);
				if (n > 0) {
					const std::size_t received = static_cast<std::size_t>(n);
					if (received > kMaximumResponseBytes + kMaximumHeaderBytes - raw.size()) {
						receive_truncated = true;
						break;
					}
					raw.append(buf, received);
					total_recv += static_cast<size_t>(n);
					continue;
				}
				if (n == 0) {
					receive_complete = true;
					break;
				}
				short events = POLLIN;
				bool fatal = false;
				const int re = WSAGetLastError();
				if (re == WSAENOBUFS) {
					log_wsaenobufs("raw_socket_request:recv",
						pu.host, pu.port);
					fatal = true;
				} else if (re != WSAEWOULDBLOCK) {
					fatal = true;
				}
				if (fatal) {
					receive_failed = true;
					break;
				}
				const int poll_result = poll_sock(events, remaining_ms());
				if (poll_result <= 0) {
					if (poll_result == -2) transport_cancelled = true;
					if (poll_result == 0) transport_deadline = true;
					receive_failed = true;
					break;
				}
			}
			cleanup();
			if (transport_cancelled) {
				out.cancelled = true;
				out.error = "HTTP request cancelled";
				return out;
			}
			if (transport_deadline) {
				out.truncated = !raw.empty();
				out.error = "HTTP request deadline expired during receive";
				return out;
			}

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
			if (receive_truncated) {
				out.truncated = true;
				out.error = "HTTP response exceeds the limit";
				return out;
			}
			parse_http_response(verb, raw, receive_complete, out);
			if (receive_failed && !out.ok && out.error.empty())
				out.error = "HTTP response receive failed or timed out";
			return out;
		}

		thread_local int t_stream_pool_attempts = 0;

		stream_result_t raw_socket_stream(const char* verb, const parsed_url_t& pu,
			const header_list_t& headers, const std::string& body,
			const std::string& content_type, const request_deadline_t& deadline,
			const stream_chunk_cb_t& on_chunk, const cancel_cb_t& cancelled)
		{
			stream_result_t out;
			if (cancellation_requested(cancelled)) {
				out.cancelled = true;
				out.error = "HTTP stream cancelled";
				return out;
			}

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
				(remaining_timeout_ms(deadline) + 999) / 1000);
			auto remaining_ms = [&]() -> int {
				return remaining_timeout_ms(deadline);
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
			bool transport_cancelled = false;
			bool transport_deadline = false;

			if (!from_pool) {
				const int initial_remaining = remaining_ms();
				if (initial_remaining <= 0) {
					out.error = "HTTP stream deadline expired before DNS resolution";
					return out;
				}
				const int resolve_budget = (initial_remaining / 4) > 0
					? initial_remaining / 4 : 1;
				std::string resolve_diag;
				std::vector<resolved_addr_t> candidates =
					resolve_host_addrs(pu.host, pu.port, resolve_budget, resolve_diag,
						cancelled);
				if (candidates.empty()) {
					if (resolve_diag == "cancelled" || cancellation_requested(cancelled)) {
						out.cancelled = true;
						out.error = "HTTP stream cancelled";
						return out;
					}
					out.error = "DNS resolution failed for " + pu.host
						+ " (" + resolve_diag + ")";
					return out;
				}

				std::stable_sort(candidates.begin(), candidates.end(),
					[](const resolved_addr_t& a, const resolved_addr_t& b) {
						return (a.family == AF_INET) && (b.family != AF_INET);
					});

				for (const resolved_addr_t& addr : candidates) {
					if (cancellation_requested(cancelled)) {
						transport_cancelled = true;
						break;
					}
					if (remaining_ms() <= 0) {
						transport_deadline = true;
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
					const int pr = cancellable_socket_poll(s, POLLOUT, deadline,
						cancelled);
					if (pr <= 0) {
						if (pr == -2) transport_cancelled = true;
						if (pr == 0) transport_deadline = true;
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
						if (transport_cancelled || transport_deadline) break;
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
					if (transport_cancelled) {
						out.cancelled = true;
						out.error = "HTTP stream cancelled";
						return out;
					}
					if (transport_deadline) {
						out.error = "HTTP stream deadline expired during connection";
						return out;
					}
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
			scope_exit_t<decltype(cleanup)> cleanup_guard(cleanup);
			static_cast<void>(cleanup_guard);
			auto apply_transport_stop = [&]() -> bool {
				if (transport_cancelled) {
					out.ok = false;
					out.complete = false;
					out.truncated = false;
					out.cancelled = true;
					out.error = "HTTP stream cancelled";
					return true;
				}
				if (transport_deadline) {
					out.ok = false;
					out.complete = false;
					out.error = "HTTP stream deadline expired";
					return true;
				}
				return false;
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
				if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
					out.error = "set TLS minimum version failed";
					close_reason = "set_tls_minimum_failed";
					cleanup();
					return out;
				}
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
				if (!pu.ip_literal && SSL_set_tlsext_host_name(ssl, pu.host.c_str()) != 1) {
					out.error = "set TLS server name failed";
					close_reason = "set_tls_server_name_failed";
					cleanup();
					return out;
				}
				X509_VERIFY_PARAM* verify_param = SSL_get0_param(ssl);
				const int verify_name_set = !verify_param ? 0 : pu.ip_literal
					? X509_VERIFY_PARAM_set1_ip_asc(verify_param, pu.host.c_str())
					: X509_VERIFY_PARAM_set1_host(verify_param,
						pu.host.c_str(), pu.host.size());
				if (verify_name_set != 1) {
					out.error = "set verify host failed";
					close_reason = "set_verify_host_failed";
					cleanup();
					return out;
				}
				for (;;) {
					if (cancellation_requested(cancelled)) {
						transport_cancelled = true;
						apply_transport_stop();
						close_reason = "tls_handshake_cancelled";
						cleanup();
						return out;
					}
					if (remaining_ms() <= 0) {
						transport_deadline = true;
						apply_transport_stop();
						close_reason = "tls_handshake_deadline";
						cleanup();
						return out;
					}
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
					const int pr = cancellable_socket_poll(sock, events, deadline,
						cancelled);
					if (pr <= 0) {
						if (pr == -2) transport_cancelled = true;
						if (pr == 0) transport_deadline = true;
						if (!apply_transport_stop())
							out.error = "TLS handshake poll error";
						close_reason = transport_cancelled ? "tls_handshake_cancelled"
							: (transport_deadline ? "tls_handshake_timeout"
								: "tls_handshake_poll_error");
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
				if (!verify_windows_tls_chain(ssl, pu.host, deadline, out.error,
						cancelled)) {
					if (cancellation_requested(cancelled)) transport_cancelled = true;
					if (remaining_ms() <= 0) transport_deadline = true;
					apply_transport_stop();
					close_reason = "windows_tls_policy_failed";
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
			req += "Host: " + pu.authority + "\r\n";
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
				(void)wait_ms;
				return cancellable_socket_poll(sock, events, deadline, cancelled);
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
					if (cancellation_requested(cancelled)) {
						transport_cancelled = true;
						send_ok = false;
						break;
					}
					if (remaining_ms() <= 0) {
						transport_deadline = true;
						send_ok = false;
						break;
					}
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
					const int poll_result = poll_sock(events, remaining_ms());
					if (poll_result <= 0) {
						if (poll_result == -2) transport_cancelled = true;
						if (poll_result == 0) transport_deadline = true;
						send_ok = false;
						break;
					}
				}
				if (!send_ok) {
					if (from_pool && total_sent == 0 && replay_safe_method(verb)
						&& !transport_cancelled && !transport_deadline) {
						from_pool = false;
						reusable = pool_eligible;
						diag::log_tagged_fmt("net",
							"raw_socket_stream pooled send failed, retrying with "
							"fresh connection host=%s port=%d",
							pu.host.c_str(), pu.port);
						close_reason = "pool_stale_send_failed";
						cleanup();
						return raw_socket_stream(verb, pu, headers, body,
							content_type, deadline, on_chunk, cancelled);
					}
					if (!apply_transport_stop()) out.error = "send failed to " + pu.host;
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
			bool read_fatal_recv = false;
			bool read_clean_eof = false;

			auto read_more = [&](std::string& sink) -> int {
				if (cancellation_requested(cancelled)) {
					transport_cancelled = true;
					return -3;
				}
				if (remaining_ms() <= 0) {
					transport_deadline = true;
					return -3;
				}
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
				short events = POLLIN;
				bool fatal = false;
				if (ssl) {
					const int err = SSL_get_error(ssl, n);
					if (err == SSL_ERROR_ZERO_RETURN) {
						read_clean_eof = true;
						return 0;
					}
					if (err == SSL_ERROR_WANT_READ)
						events = POLLIN;
					else if (err == SSL_ERROR_WANT_WRITE)
						events = POLLOUT;
					else
						fatal = true;
				} else {
					if (n == 0) {
						read_clean_eof = true;
						return 0;
					}
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
				const int poll_result = poll_sock(events, remaining_ms());
				if (poll_result <= 0) {
					if (poll_result == -2) transport_cancelled = true;
					if (poll_result == 0) transport_deadline = true;
					read_fatal_recv = true;
					return (transport_cancelled || transport_deadline) ? -3 : -1;
				}
				return -2;
			};

			auto receive_header = [&]() -> bool {
				for (;;) {
					const std::size_t pos = header_buf.find("\r\n\r\n");
					if (pos != std::string::npos) {
						body_pending = header_buf.substr(pos + 4);
						header_buf.resize(pos);
						return true;
					}
					if (header_buf.size() > kMaximumHeaderBytes) {
						out.error = "response headers too large from " + pu.host;
						return false;
					}
					const int n = read_more(header_buf);
					if (n == -2) continue;
					if (n <= 0) return false;
				}
			};

			response_framing_t framing;
			std::size_t interim_count = 0;
			for (;;) {
				if (!receive_header()) {
					if (apply_transport_stop()) {
						close_reason = transport_cancelled ? "stream_cancelled"
							: "stream_deadline";
						reusable = false;
						cleanup();
						return out;
					}
					if (from_pool && interim_count == 0 && header_buf.empty()
						&& !read_fatal_recv && replay_safe_method(verb)) {
						diag::log_tagged_fmt("net",
							"raw_socket_stream pooled response empty, retrying with "
							"fresh connection host=%s port=%d",
							pu.host.c_str(), pu.port);
						close_reason = "pool_stale_no_response";
						reusable = false;
						cleanup();
						return raw_socket_stream(verb, pu, headers, body,
							content_type, deadline, on_chunk, cancelled);
					}
					if (out.error.empty()) out.error = "incomplete response headers from " + pu.host;
					out.truncated = true;
					close_reason = "incomplete_response_headers";
					reusable = false;
					cleanup();
					return out;
				}
				if (!parse_response_head(header_buf, framing, out.error)) {
					close_reason = "malformed_response_headers";
					reusable = false;
					cleanup();
					return out;
				}
				if (framing.status < 100 || framing.status >= 200) break;
				if (framing.status == 101 || framing.chunked
					|| framing.content_length_present) {
					out.error = framing.status == 101 ? "HTTP protocol switching is unsupported"
						: "interim HTTP response contains body framing";
					close_reason = "unsupported_interim_response";
					reusable = false;
					cleanup();
					return out;
				}
				if (++interim_count > 8) {
					out.error = "too many interim HTTP responses";
					close_reason = "too_many_interim_responses";
					reusable = false;
					cleanup();
					return out;
				}
				if (!response_connection_persistent(framing)) reusable = false;
				header_buf = std::move(body_pending);
				body_pending.clear();
			}
			out.status = framing.status;
			const bool chunked = framing.chunked;
			const bool head_response = verb && std::strcmp(verb, "HEAD") == 0;
			if (!response_connection_persistent(framing)) reusable = false;
			if (!chunked && !framing.content_length_present)
				reusable = false;

			bool callback_failed = false;
			auto emit_payload = [&](const char* data, size_t len) -> bool {
				if (len == 0)
					return true;
				if (!on_chunk)
					return true;
				try {
					return on_chunk(data, len);
				} catch (...) {
					callback_failed = true;
					out.error = "stream receiver callback failed";
					reusable = false;
					return false;
				}
			};

			if (out.status < 200 || out.status >= 300) {
				std::string encoded = std::move(body_pending);
				std::string error_body;
				bool error_complete = false;
				const bool no_body = head_response || out.status == 304;
				if (no_body) {
					error_complete = encoded.empty();
					if (!error_complete) out.error = "body is forbidden for this HTTP status";
				} else if (chunked) {
					for (;;) {
						std::string parse_error;
						bool incomplete = false;
						if (decode_chunked_body(encoded, error_body, parse_error, incomplete)) {
							error_complete = true;
							break;
						}
						if (!incomplete) {
							out.truncated = parse_error == "decoded chunked body exceeds the limit";
							out.error = parse_error;
							break;
						}
						if (encoded.size() > kMaximumResponseBytes + kMaximumHeaderBytes) {
							out.truncated = true;
							out.error = "chunked HTTP error body exceeds the limit";
							break;
						}
						const int read = read_more(encoded);
						if (read == -2) continue;
						if (read <= 0) {
							out.truncated = true;
							out.error = parse_error.empty()
								? "incomplete chunked HTTP error body" : parse_error;
							break;
						}
					}
				} else if (framing.content_length_present) {
					if (encoded.size() > framing.content_length) {
						out.error = "HTTP error body exceeds Content-Length";
					} else {
						while (encoded.size() < framing.content_length) {
							const int read = read_more(encoded);
							if (encoded.size() > framing.content_length) break;
							if (read == -2) continue;
							if (read <= 0) break;
						}
						error_complete = encoded.size() == framing.content_length;
						if (!error_complete) {
							out.truncated = true;
							out.error = "incomplete HTTP error body";
						}
						else error_body = std::move(encoded);
					}
				} else {
					while (encoded.size() <= kMaximumResponseBytes) {
						const int read = read_more(encoded);
						if (read == -2) continue;
						if (read <= 0) break;
					}
					if (encoded.size() > kMaximumResponseBytes) {
						out.truncated = true;
						out.error = "HTTP error body exceeds the limit";
					} else if (read_clean_eof && !read_fatal_recv) {
						error_complete = true;
						error_body = std::move(encoded);
					} else {
						out.truncated = true;
						out.error = "incomplete close-delimited HTTP error body";
					}
				}
				out.complete = error_complete;
				if (apply_transport_stop()) {
					close_reason = transport_cancelled ? "stream_cancelled"
						: "stream_deadline";
					reusable = false;
					cleanup();
					return out;
				}
				if (error_complete && out.error.empty()) {
					const std::string snippet = sanitize_http_error_snippet(error_body);
					out.error = "HTTP " + std::to_string(out.status)
						+ (snippet.empty() ? std::string() : (": " + snippet));
				}
				if (error_complete && !error_body.empty()
					&& !emit_payload(error_body.data(), error_body.size()))
					out.cancelled = !callback_failed;
				close_reason = "http_error";
				reusable = false;
				cleanup();
				return out;
			}

			bool delivery_cancelled = false;
			bool body_complete = false;
			std::size_t delivered = 0;
			if (head_response) {
				body_complete = body_pending.empty();
				if (!body_complete) out.error = "body is forbidden for a HEAD response";
			} else if (out.status == 204) {
				body_complete = body_pending.empty() && !framing.chunked
					&& !framing.content_length_present;
				if (!body_complete) out.error = "body framing is forbidden for HTTP 204";
			} else if (out.status == 205) {
				if (framing.content_length_present && framing.content_length != 0) {
					out.error = "HTTP 205 Content-Length must be zero";
				} else if (framing.chunked) {
					std::string encoded = std::move(body_pending);
					std::string decoded;
					for (;;) {
						std::string parse_error;
						bool incomplete = false;
						if (decode_chunked_body(encoded, decoded, parse_error, incomplete)) {
							body_complete = decoded.empty();
							if (!body_complete) out.error = "body is forbidden for HTTP 205";
							break;
						}
						if (!incomplete) {
							out.truncated = parse_error == "decoded chunked body exceeds the limit";
							out.error = parse_error;
							break;
						}
						if (encoded.size() > kMaximumResponseBytes + kMaximumHeaderBytes) {
							out.truncated = true;
							out.error = "HTTP 205 chunk framing exceeds the limit";
							break;
						}
						const int read = read_more(encoded);
						if (read == -2) continue;
						if (read <= 0) {
							out.truncated = true;
							out.error = parse_error.empty()
								? "incomplete HTTP 205 chunk framing" : parse_error;
							break;
						}
					}
				} else {
					body_complete = body_pending.empty();
					if (!body_complete) out.error = "body is forbidden for HTTP 205";
				}
			} else if (chunked) {
				std::string buffer = std::move(body_pending);
				while (!delivery_cancelled && !body_complete && out.error.empty()) {
					std::size_t line_end = buffer.find("\r\n");
					while (line_end == std::string::npos) {
						if (buffer.size() > 1024) {
							out.truncated = true;
							out.error = "chunk size line exceeds the limit";
							break;
						}
						const int read = read_more(buffer);
						if (read == -2) continue;
						if (read <= 0) {
							out.truncated = true;
							out.error = "incomplete chunk size line";
							break;
						}
						line_end = buffer.find("\r\n");
					}
					if (!out.error.empty()) break;
					std::uint64_t chunk_size = 0;
					if (!parse_chunk_size_line(buffer.substr(0, line_end), chunk_size)) {
						out.error = "invalid chunk size";
						break;
					}
					buffer.erase(0, line_end + 2);
					if (chunk_size == 0) {
						std::size_t trailer_bytes = 0;
						for (;;) {
							line_end = buffer.find("\r\n");
							while (line_end == std::string::npos) {
								if (buffer.size() > kMaximumHeaderBytes) {
									out.truncated = true;
									out.error = "chunk trailers exceed the limit";
									break;
								}
								const int read = read_more(buffer);
								if (read == -2) continue;
								if (read <= 0) {
									out.truncated = true;
									out.error = "incomplete chunk trailers";
									break;
								}
								line_end = buffer.find("\r\n");
							}
							if (!out.error.empty()) break;
							if (line_end == 0) {
								buffer.erase(0, 2);
								if (!buffer.empty()) out.error = "bytes follow terminal chunk";
								else body_complete = true;
								break;
							}
							const std::string trailer = buffer.substr(0, line_end);
							if (!validate_chunk_trailer(trailer, trailer_bytes, out.error)) break;
							buffer.erase(0, line_end + 2);
						}
						break;
					}
					if (chunk_size > kMaximumResponseBytes - delivered) {
						out.truncated = true;
						out.error = "stream body exceeds the limit";
						break;
					}
					const std::size_t required = static_cast<std::size_t>(chunk_size) + 2;
					while (buffer.size() < required) {
						const int read = read_more(buffer);
						if (read == -2) continue;
						if (read <= 0) {
							out.truncated = true;
							out.error = "incomplete chunk data";
							break;
						}
					}
					if (!out.error.empty()) break;
					const std::size_t payload_size = static_cast<std::size_t>(chunk_size);
					if (buffer[payload_size] != '\r' || buffer[payload_size + 1] != '\n') {
						out.error = "chunk data terminator missing";
						break;
					}
					if (!emit_payload(buffer.data(), payload_size)) {
						delivery_cancelled = true;
						break;
					}
					delivered += payload_size;
					buffer.erase(0, required);
				}
			} else if (framing.content_length_present) {
				if (body_pending.size() > framing.content_length) {
					out.error = "stream body exceeds Content-Length";
				} else {
					if (!body_pending.empty() && !emit_payload(body_pending.data(), body_pending.size()))
						delivery_cancelled = true;
					delivered = body_pending.size();
					body_pending.clear();
					std::string buffer;
					while (!delivery_cancelled && delivered < framing.content_length) {
						buffer.clear();
						const int read = read_more(buffer);
						if (read == -2) continue;
						if (read <= 0) {
							out.truncated = true;
							out.error = "stream ended before Content-Length";
							break;
						}
						if (buffer.size() > framing.content_length - delivered) {
							out.error = "stream body exceeds Content-Length";
							break;
						}
						if (!emit_payload(buffer.data(), buffer.size())) {
							delivery_cancelled = true;
							break;
						}
						delivered += buffer.size();
					}
					body_complete = !delivery_cancelled && out.error.empty()
						&& delivered == framing.content_length;
				}
			} else {
				if (body_pending.size() > kMaximumResponseBytes) {
					out.truncated = true;
					out.error = "stream body exceeds the limit";
				} else {
					if (!body_pending.empty() && !emit_payload(body_pending.data(), body_pending.size()))
						delivery_cancelled = true;
					delivered = body_pending.size();
					body_pending.clear();
					std::string buffer;
					while (!delivery_cancelled && out.error.empty()) {
						buffer.clear();
						const int read = read_more(buffer);
						if (read == -2) continue;
						if (read <= 0) break;
						if (buffer.size() > kMaximumResponseBytes - delivered) {
							out.truncated = true;
							out.error = "stream body exceeds the limit";
							break;
						}
						if (!emit_payload(buffer.data(), buffer.size())) {
							delivery_cancelled = true;
							break;
						}
						delivered += buffer.size();
					}
					body_complete = !delivery_cancelled && out.error.empty()
						&& read_clean_eof && !read_fatal_recv;
					if (!body_complete && !delivery_cancelled && out.error.empty())
						out.truncated = true;
				}
			}

			if (!apply_transport_stop()) {
				out.ok = body_complete && !delivery_cancelled && out.error.empty();
				out.complete = body_complete;
				out.cancelled = delivery_cancelled && !callback_failed;
				if (delivery_cancelled && !callback_failed && out.error.empty())
					out.error = "stream cancelled by receiver";
				if (!delivery_cancelled && !body_complete && out.error.empty())
					out.error = "stream body is incomplete";
			}

			pooled_conn_t pool_probe;
			pool_probe.sock = sock;
			pool_probe.ssl = ssl;
			const bool can_pool_back = reusable && out.ok && body_complete
				&& !delivery_cancelled && pool_eligible && sock != INVALID_SOCKET
				&& !read_fatal_recv && response_connection_persistent(framing)
				&& pooled_connection_clean(pool_probe);

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
				const std::string pool_key = make_pool_key(pu.host, pu.port);
				std::unique_ptr<pooled_conn_t> conn = std::make_unique<pooled_conn_t>();
				conn->host_key = pool_key;
				conn->family = chosen_family;
				conn->last_used_ms = now_steady_ms();
				conn->sock = sock;
				conn->ssl = ssl;
				conn->ctx = ctx;
				sock = INVALID_SOCKET;
				ssl = nullptr;
				ctx = nullptr;
				release_pooled_conn(std::move(conn));
				close_reason = "pooled";
			} else {
				close_reason = delivery_cancelled ? "stream_cancelled"
				: (transport_cancelled ? "stream_cancelled"
					: (transport_deadline ? "stream_deadline"
						: (body_complete ? "completed_unpoolable"
							: "incomplete_body"));
			}
			cleanup();
			return out;
		}

	}

	response_t request(const char* verb, const std::string& url,
		const header_list_t& headers, const std::string& body,
		const std::string& content_type, int timeout_sec,
		const cancel_cb_t& cancelled)
	{
		try {
			response_t out;
			if (cancellation_requested(cancelled)) {
				out.cancelled = true;
				out.error = "HTTP request cancelled";
				return out;
			}
			parsed_url_t pu;
			if (!parse_url(url, pu)) {
				out.error = "invalid HTTP URL";
				return out;
			}
			if (!validate_request_metadata(verb, headers, body, content_type,
				timeout_sec, out.error)) {
				return out;
			}

			const request_deadline_t deadline = request_deadline(timeout_sec);
			return pu.https
				? winhttp_request(verb, pu, headers, body, content_type, deadline, cancelled)
				: raw_socket_request(verb, pu, headers, body, content_type, deadline,
					cancelled);
		} catch (...) {
			response_t out;
			out.error = "HTTP request resource allocation failed";
			return out;
		}
	}

	response_t get(const std::string& url, const header_list_t& headers,
		int timeout_sec, const cancel_cb_t& cancelled)
	{
		return request("GET", url, headers, std::string(), std::string(), timeout_sec,
			cancelled);
	}

	response_t post(const std::string& url, const header_list_t& headers,
		const std::string& body, const std::string& content_type, int timeout_sec,
		const cancel_cb_t& cancelled)
	{
		return request("POST", url, headers, body, content_type, timeout_sec,
			cancelled);
	}

	stream_result_t stream(const char* verb, const std::string& url,
		const header_list_t& headers, const std::string& body,
		const std::string& content_type, int timeout_sec,
		const stream_chunk_cb_t& on_chunk, const cancel_cb_t& cancelled)
	{
		try {
			stream_result_t out;
			if (cancellation_requested(cancelled)) {
				out.cancelled = true;
				out.error = "HTTP stream cancelled";
				return out;
			}
			parsed_url_t pu;
			if (!parse_url(url, pu)) {
				out.error = "invalid HTTP URL";
				return out;
			}
			if (!validate_request_metadata(verb, headers, body, content_type,
				timeout_sec, out.error)) {
				return out;
			}
			const request_deadline_t deadline = request_deadline(timeout_sec);
			return raw_socket_stream(verb, pu, headers, body, content_type,
				deadline, on_chunk, cancelled);
		} catch (...) {
			stream_result_t out;
			out.error = "HTTP stream resource allocation failed";
			return out;
		}
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
