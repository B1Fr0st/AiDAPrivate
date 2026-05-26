#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <Windows.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <windns.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

	bool ensure_driver(test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return false;
		}
		return true;
	}

	std::string fmt_u32(std::uint32_t v) {
		char b[16];
		std::snprintf(b, sizeof(b), "%u", v);
		return std::string(b);
	}

	BOOL CALLBACK init_test_winsock_once(PINIT_ONCE, PVOID parameter, PVOID*) {
		bool* ok = static_cast<bool*>(parameter);
		WSADATA d{};
		*ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
		return TRUE;
	}

	bool ensure_test_winsock_ready() {
		static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
		static bool ok = false;
		if (!InitOnceExecuteOnce(&once, init_test_winsock_once, &ok, nullptr))
			return false;
		return ok;
	}

	std::wstring ascii_to_wide(const char* s) {
		std::wstring out;
		if (!s)
			return out;
		while (*s) {
			out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*s)));
			++s;
		}
		return out;
	}

	bool ensure_directory_tree_ascii(const char* path, DWORD* out_error = nullptr) {
		if (out_error) *out_error = 0u;
		if (path == nullptr || path[0] == '\0') {
			if (out_error) *out_error = ERROR_INVALID_PARAMETER;
			return false;
		}
		std::string p(path);
		for (char& ch : p) {
			if (ch == '/')
				ch = '\\';
		}
		while (!p.empty() && (p.back() == '\\' || p.back() == '/'))
			p.pop_back();
		if (p.empty()) {
			if (out_error) *out_error = ERROR_INVALID_PARAMETER;
			return false;
		}
		std::size_t start = 0;
		if (p.size() >= 3 && p[1] == ':' && p[2] == '\\')
			start = 3;
		for (std::size_t i = start; i <= p.size(); ++i) {
			if (i != p.size() && p[i] != '\\')
				continue;
			std::string part = p.substr(0, i);
			if (part.empty() || (part.size() == 2 && part[1] == ':'))
				continue;
			if (!CreateDirectoryA(part.c_str(), nullptr)) {
				DWORD err = GetLastError();
				if (err != ERROR_ALREADY_EXISTS) {
					if (out_error) *out_error = err;
					return false;
				}
			}
		}
		return true;
	}

	bool read_ascii_file(const char* path, std::string& out, DWORD* out_error = nullptr) {
		out.clear();
		if (out_error) *out_error = 0u;
		if (path == nullptr) {
			if (out_error) *out_error = ERROR_INVALID_PARAMETER;
			return false;
		}
		HANDLE h = CreateFileA(path,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			if (out_error) *out_error = GetLastError();
			return false;
		}
		char buf[256];
		DWORD read = 0;
		BOOL ok = ReadFile(h, buf, static_cast<DWORD>(sizeof(buf)), &read, nullptr);
		DWORD err = ok ? 0u : GetLastError();
		CloseHandle(h);
		if (!ok) {
			if (out_error) *out_error = err;
			return false;
		}
		out.assign(buf, buf + read);
		return true;
	}

	struct dns_query_context_t {
		OVERLAPPED overlapped{};
		PADDRINFOEXW result = nullptr;
		HANDLE event = nullptr;
		DWORD error = WSA_OPERATION_ABORTED;
		bool had_result = false;
	};

	void CALLBACK dns_query_complete(DWORD error, DWORD, LPWSAOVERLAPPED overlapped) {
		dns_query_context_t* ctx = CONTAINING_RECORD(overlapped, dns_query_context_t, overlapped);
		ctx->error = error;
		ctx->had_result = (ctx->result != nullptr);
		if (ctx->result != nullptr) {
			FreeAddrInfoExW(ctx->result);
			ctx->result = nullptr;
		}
		if (ctx->event != nullptr)
			SetEvent(ctx->event);
	}

	bool resolve_host_with_timeout(const char* host, int timeout_ms) {
		std::wstring host_w = ascii_to_wide(host);
		if (host_w.empty())
			return false;

		ADDRINFOEXW hints{};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		dns_query_context_t ctx{};
		ctx.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (ctx.event == nullptr)
			return false;

		HANDLE cancel_handle = nullptr;
		int rc = GetAddrInfoExW(host_w.c_str(), nullptr, NS_DNS, nullptr, &hints, &ctx.result, nullptr, &ctx.overlapped, dns_query_complete, &cancel_handle);
		if (rc != WSA_IO_PENDING) {
			dns_query_complete(static_cast<DWORD>(rc), 0, &ctx.overlapped);
		} else {
			DWORD wait_ms = timeout_ms > 0 ? static_cast<DWORD>(timeout_ms) : 1u;
			if (WaitForSingleObject(ctx.event, wait_ms) == WAIT_TIMEOUT) {
				if (cancel_handle != nullptr)
					GetAddrInfoExCancel(&cancel_handle);
				WaitForSingleObject(ctx.event, INFINITE);
			}
		}

		bool ok = (ctx.error == ERROR_SUCCESS && ctx.had_result);
		CloseHandle(ctx.event);
		return ok;
	}

	std::string fmt_u64(std::uint64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	std::string fmt_hex_u64(std::uint64_t v) {
		char b[24];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	std::string fmt_ip_v4(const std::uint8_t* a) {
		char b[24];
		std::snprintf(b, sizeof(b), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
		return std::string(b);
	}

	bool addr_is_one_one_one_one(const std::uint8_t* a, std::uint32_t family) {
		if (family != 0u && family != 2u) return false;
		return a[0] == 1u && a[1] == 1u && a[2] == 1u && a[3] == 1u;
	}

	bool addr_is_v4_endpoint(const std::uint8_t* a,
		std::uint32_t family,
		std::uint8_t b0,
		std::uint8_t b1,
		std::uint8_t b2,
		std::uint8_t b3)
	{
		if (family != 0u && family != 2u) return false;
		return a[0] == b0 && a[1] == b1 && a[2] == b2 && a[3] == b3;
	}

	struct tcp_probe_state_t {
		SOCKET primary = INVALID_SOCKET;
		SOCKET accepted = INVALID_SOCKET;
		std::uint8_t remote_addr[4]{};
		std::uint32_t remote_port = 0u;
		bool initiated = false;
		std::string mode;
		std::string diag;

		~tcp_probe_state_t() {
			close();
		}

		tcp_probe_state_t() = default;
		tcp_probe_state_t(const tcp_probe_state_t&) = delete;
		tcp_probe_state_t& operator=(const tcp_probe_state_t&) = delete;

		void close() {
			if (primary != INVALID_SOCKET) {
				closesocket(primary);
				primary = INVALID_SOCKET;
			}
			if (accepted != INVALID_SOCKET) {
				closesocket(accepted);
				accepted = INVALID_SOCKET;
			}
		}

		void set_remote(std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3, std::uint32_t port) {
			remote_addr[0] = b0;
			remote_addr[1] = b1;
			remote_addr[2] = b2;
			remote_addr[3] = b3;
			remote_port = port;
		}
	};

	bool tcp_probe_remote_matches(const tcp_probe_state_t& probe,
		const std::uint8_t* addr,
		std::uint32_t family,
		std::uint32_t port)
	{
		if (!probe.initiated || probe.remote_port == 0u || port != probe.remote_port)
			return false;
		if (probe.mode == "loopback" && addr_is_v4_endpoint(addr, family, 0u, 0u, 0u, 0u))
			return true;
		return addr_is_v4_endpoint(addr,
			family,
			probe.remote_addr[0],
			probe.remote_addr[1],
			probe.remote_addr[2],
			probe.remote_addr[3]);
	}

	struct wsa_guard_t {
		bool ok = false;
		wsa_guard_t() {
			ok = ensure_test_winsock_ready();
		}
		~wsa_guard_t() = default;
		wsa_guard_t(const wsa_guard_t&) = delete;
		wsa_guard_t& operator=(const wsa_guard_t&) = delete;
	};

	bool issue_short_http_get_to_one_one(std::string& diag) {
		HINTERNET h_session = WinHttpOpen(L"AiDA-VerifyLab/1.0",
			WINHTTP_ACCESS_TYPE_NO_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS,
			0);
		if (h_session == nullptr) {
			diag = "WinHttpOpen failed";
			return false;
		}
		WinHttpSetTimeouts(h_session, 1500, 1500, 1500, 1500);
		HINTERNET h_conn = WinHttpConnect(h_session, L"1.1.1.1", 80, 0);
		if (h_conn == nullptr) {
			diag = "WinHttpConnect failed";
			WinHttpCloseHandle(h_session);
			return false;
		}
		HINTERNET h_req = WinHttpOpenRequest(h_conn, L"GET", L"/", nullptr,
			WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			0);
		if (h_req == nullptr) {
			diag = "WinHttpOpenRequest failed";
			WinHttpCloseHandle(h_conn);
			WinHttpCloseHandle(h_session);
			return false;
		}
		BOOL sent = WinHttpSendRequest(h_req,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
		bool any_io = (sent != FALSE);
		if (sent) {
			BOOL got = WinHttpReceiveResponse(h_req, nullptr);
			if (!got) {
				diag = "WinHttpReceiveResponse failed (still counts as sent SYN)";
			}
		} else {
			DWORD err = GetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "WinHttpSendRequest err=%lu (SYN may still be on wire)",
				static_cast<unsigned long>(err));
			diag = b;
			any_io = true;
		}
		WinHttpCloseHandle(h_req);
		WinHttpCloseHandle(h_conn);
		WinHttpCloseHandle(h_session);
		return any_io;
	}

	bool issue_raw_tcp_probe_to_one_one(std::string& diag) {
		wsa_guard_t g;
		if (!g.ok) {
			diag = "WSAStartup failed";
			return false;
		}
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) {
			diag = "socket() failed";
			return false;
		}
		u_long nb = 1;
		ioctlsocket(s, FIONBIO, &nb);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(80);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		int rc = connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		bool initiated = false;
		if (rc == 0) {
			initiated = true;
		} else {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				initiated = true;
			} else {
				char b[64];
				std::snprintf(b, sizeof(b), "connect() err=%d", err);
				diag = b;
			}
		}
		if (initiated) {
			fd_set wf;
			FD_ZERO(&wf);
			FD_SET(s, &wf);
			timeval tv{};
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			int sel = select(0, nullptr, &wf, nullptr, &tv);
			if (sel > 0) {
				const char* req = "HEAD / HTTP/1.0\r\n\r\n";
				send(s, req, static_cast<int>(std::strlen(req)), 0);
				char recv_buf[64];
				recv(s, recv_buf, sizeof(recv_buf), 0);
			}
		}
		closesocket(s);
		return initiated;
	}

	bool build_dns_query_packet(const char* host, std::vector<unsigned char>& packet, std::uint16_t& qid, std::string& diag) {
		wsa_guard_t g;
		if (!g.ok) {
			diag = "WSAStartup failed";
			return false;
		}
		if (host == nullptr || host[0] == '\0') {
			diag = "empty DNS host";
			return false;
		}

		packet.clear();
		packet.reserve(512);
		qid = static_cast<std::uint16_t>(GetTickCount() & 0xffffu);
		packet.push_back(static_cast<unsigned char>(qid >> 8));
		packet.push_back(static_cast<unsigned char>(qid & 0xff));
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);

		const char* label = host;
		while (*label) {
			const char* dot = std::strchr(label, '.');
			std::size_t len = dot ? static_cast<std::size_t>(dot - label) : std::strlen(label);
			if (len == 0 || len > 63 || packet.size() + len + 6 > 512) {
				diag = "DNS host label invalid";
				return false;
			}
			packet.push_back(static_cast<unsigned char>(len));
			for (std::size_t i = 0; i < len; ++i)
				packet.push_back(static_cast<unsigned char>(label[i]));
			if (!dot)
				break;
			label = dot + 1;
		}
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x01);
		return true;
	}

	bool issue_udp_dns_probe_to_one_one(const char* host, std::string& diag) {
		std::vector<unsigned char> packet;
		std::uint16_t qid = 0;
		if (!build_dns_query_packet(host, packet, qid, diag))
			return false;
		::diag::log_tagged_fmt("verify_dns", "udp_probe start host=%s qid=%u packet_bytes=%zu",
			host ? host : "", qid, packet.size());

		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "DNS UDP socket failed err=%d", err);
			diag = b;
			::diag::log_tagged_fmt("verify_dns", "udp_probe socket_failed host=%s err=%d", host ? host : "", err);
			return false;
		}
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(53);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		DWORD timeout_ms = 250;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		int sent = send(s,
			reinterpret_cast<const char*>(packet.data()),
			static_cast<int>(packet.size()),
			0);
		if (sent == SOCKET_ERROR) {
			sent = sendto(s,
				reinterpret_cast<const char*>(packet.data()),
				static_cast<int>(packet.size()),
				0,
				reinterpret_cast<sockaddr*>(&dst),
				sizeof(dst));
		}
		int err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;
		char recv_buf[512];
		int recvd = sent == SOCKET_ERROR ? 0 : recv(s, recv_buf, sizeof(recv_buf), 0);
		closesocket(s);
		if (sent == SOCKET_ERROR) {
			char b[80];
			std::snprintf(b, sizeof(b), "DNS UDP sendto err=%d", err);
			diag = b;
			::diag::log_tagged_fmt("verify_dns", "udp_probe send_failed host=%s err=%d", host ? host : "", err);
			return false;
		}
		char b[128];
		std::snprintf(b, sizeof(b), "DNS UDP query host=%s bytes=%d response_bytes=%d id=%u",
			host, sent, recvd > 0 ? recvd : 0, qid);
		diag = b;
		::diag::log_tagged_fmt("verify_dns", "udp_probe done host=%s sent=%d recvd=%d qid=%u",
			host ? host : "", sent, recvd > 0 ? recvd : 0, qid);
		return true;
	}

	bool issue_tcp_dns_probe_to_one_one(const char* host, std::string& diag) {
		std::vector<unsigned char> packet;
		std::uint16_t qid = 0;
		if (!build_dns_query_packet(host, packet, qid, diag))
			return false;
		::diag::log_tagged_fmt("verify_dns", "tcp_probe start host=%s qid=%u packet_bytes=%zu",
			host ? host : "", qid, packet.size());

		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "DNS TCP socket failed err=%d", err);
			diag = b;
			::diag::log_tagged_fmt("verify_dns", "tcp_probe socket_failed host=%s err=%d", host ? host : "", err);
			return false;
		}
		DWORD timeout_ms = 1000;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		u_long nb = 1;
		ioctlsocket(s, FIONBIO, &nb);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(53);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		if (connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS && err != WSAEINVAL) {
				closesocket(s);
				char b[96];
				std::snprintf(b, sizeof(b), "DNS TCP connect err=%d", err);
				diag = b;
				::diag::log_tagged_fmt("verify_dns", "tcp_probe connect_immediate_failed host=%s err=%d", host ? host : "", err);
				return false;
			}
			fd_set wf;
			fd_set ef;
			FD_ZERO(&wf);
			FD_ZERO(&ef);
			FD_SET(s, &wf);
			FD_SET(s, &ef);
			timeval tv{};
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			int sel = select(0, nullptr, &wf, &ef, &tv);
			if (sel <= 0) {
				int sel_err = sel == SOCKET_ERROR ? WSAGetLastError() : WSAETIMEDOUT;
				closesocket(s);
				char b[128];
				std::snprintf(b, sizeof(b), "DNS TCP connect select err=%d sel=%d", sel_err, sel);
				diag = b;
				::diag::log_tagged_fmt("verify_dns", "tcp_probe connect_select_failed host=%s sel=%d err=%d", host ? host : "", sel, sel_err);
				return false;
			}
			int so_error = 0;
			int so_len = sizeof(so_error);
			getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &so_len);
			if (so_error != 0) {
				closesocket(s);
				char b[128];
				std::snprintf(b, sizeof(b), "DNS TCP connect so_error=%d", so_error);
				diag = b;
				::diag::log_tagged_fmt("verify_dns", "tcp_probe connect_so_error host=%s err=%d", host ? host : "", so_error);
				return false;
			}
		}
		std::vector<unsigned char> tcp_packet;
		tcp_packet.reserve(packet.size() + 2u);
		tcp_packet.push_back(static_cast<unsigned char>((packet.size() >> 8) & 0xffu));
		tcp_packet.push_back(static_cast<unsigned char>(packet.size() & 0xffu));
		tcp_packet.insert(tcp_packet.end(), packet.begin(), packet.end());
		int sent = send(s,
			reinterpret_cast<const char*>(tcp_packet.data()),
			static_cast<int>(tcp_packet.size()),
			0);
		int err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;
		closesocket(s);
		if (sent == SOCKET_ERROR) {
			char b[96];
			std::snprintf(b, sizeof(b), "DNS TCP send err=%d", err);
			diag = b;
			::diag::log_tagged_fmt("verify_dns", "tcp_probe send_failed host=%s err=%d", host ? host : "", err);
			return false;
		}
		char b[128];
		std::snprintf(b, sizeof(b), "DNS TCP query host=%s bytes=%d id=%u", host, sent, qid);
		diag = b;
		::diag::log_tagged_fmt("verify_dns", "tcp_probe done host=%s sent=%d qid=%u",
			host ? host : "", sent, qid);
		return true;
	}

	void render_inputs_empty(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("no inputs");
	}

	void run_verify_network_capture(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = self_pid;
		start_req.filter_port = 0u;
		start_req.filter_protocol = 0u;
		start_req.max_packet_bytes = 1500u;
		std::uint32_t br = 0;
		bool ok_start = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br);
		if (!ok_start) {
			r.ok = false;
			r.error = "NCAP start ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.bytes_returned = br;
			return;
		}
		r.parsed.push_back({ "step1_capture_started", "1" });
		r.parsed.push_back({ "filter_pid", fmt_u32(self_pid) });
		r.parsed.push_back({ "capture_active_after_start", fmt_u32(start_req.capture_active) });

		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		std::string http_diag;
		bool any_io = issue_short_http_get_to_one_one(http_diag);
		r.parsed.push_back({ "step2_http_attempted", any_io ? "1" : "0" });
		if (!http_diag.empty()) {
			r.parsed.push_back({ "http_diag", http_diag });
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		voyager::detail::net_cap_ctrl_request stop_req{};
		stop_req.operation = 1u;
		stop_req.filter_pid = self_pid;
		stop_req.max_packet_bytes = 1500u;
		std::uint32_t br2 = 0;
		device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br2);
		r.parsed.push_back({ "step3_capture_stopped", "1" });
		r.parsed.push_back({ "packets_captured_kernel_counter", fmt_u32(stop_req.packets_captured) });
		r.parsed.push_back({ "packets_dropped_kernel_counter", fmt_u32(stop_req.packets_dropped) });

		voyager::detail::net_cap_get_request* drain =
			static_cast<voyager::detail::net_cap_get_request*>(std::calloc(1, sizeof(voyager::detail::net_cap_get_request)));
		if (drain == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_cap_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		drain->max_packets = 32u;
		std::uint32_t br3 = 0;
		bool ok_drain = device->send_ioctl_raw(ioctl_codes::NCPG(), drain, sizeof(*drain), br3);
		r.bytes_returned = br3;
		if (!ok_drain) {
			r.ok = false;
			r.error = "NCPG drain ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			std::free(drain);
			return;
		}
		std::uint32_t total = drain->packet_count;
		std::uint32_t matching_pid = 0;
		std::uint32_t printed = 0;
		const std::uint32_t print_cap = 8u;
		for (std::uint32_t i = 0; i < total && i < voyager::detail::NET_CAP_GET_MAX; ++i) {
			const auto& p = drain->packets[i];
			if (p.pid == self_pid) ++matching_pid;
			if (printed < print_cap) {
				char label[24];
				std::snprintf(label, sizeof(label), "pkt[%u]", i);
				char val[256];
				std::snprintf(val, sizeof(val),
					"ts=%llu pid=%u proto=%u dir=%u %s:%u -> %s:%u size=%u",
					static_cast<unsigned long long>(p.timestamp),
					p.pid, p.protocol, p.direction,
					fmt_ip_v4(p.local_addr).c_str(), p.local_port,
					fmt_ip_v4(p.remote_addr).c_str(), p.remote_port,
					p.payload_size);
				r.parsed.push_back({ std::string(label), std::string(val) });
				++printed;
			}
		}
		r.parsed.push_back({ "packets_drained_total", fmt_u32(total) });
		r.parsed.push_back({ "packets_matching_self_pid", fmt_u32(matching_pid) });

		if (matching_pid > 0u) {
			r.ntstatus = 0;
			r.ok = true;
		} else if (total > 0u) {
			r.ok = false;
			r.error = "capture drained packets but none matched current PID -- PID filter may be ignored or attribution path is broken";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		} else {
			r.ok = false;
			r.error = "capture started but no packets seen for current PID -- capture path may not be working or PID filter mismatched";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
		std::free(drain);
	}

	enum class dns_log_stage_e : long {
		not_started = 0,
		ensure_driver,
		winsock,
		baseline_ndns,
		start_ncap,
		udp_probe,
		tcp_probe,
		windns_probe,
		poll_wait,
		poll_ndns,
		stop_ncap,
		drain_ncap,
		evaluate,
		exception
	};

	struct dns_log_ctx_t {
		test_lab::result_t result;
		std::atomic<bool> cancel{ false };
		std::atomic<bool> capture_started{ false };
		std::atomic<long> stage{ static_cast<long>(dns_log_stage_e::not_started) };
		std::atomic<std::uint64_t> stage_tick_ms{ 0 };
	};

	const char* dns_log_stage_name(long stage) {
		switch (static_cast<dns_log_stage_e>(stage)) {
		case dns_log_stage_e::not_started: return "not_started";
		case dns_log_stage_e::ensure_driver: return "ensure_driver";
		case dns_log_stage_e::winsock: return "winsock";
		case dns_log_stage_e::baseline_ndns: return "baseline_ndns";
		case dns_log_stage_e::start_ncap: return "start_ncap";
		case dns_log_stage_e::udp_probe: return "udp_probe";
		case dns_log_stage_e::tcp_probe: return "tcp_probe";
		case dns_log_stage_e::windns_probe: return "windns_probe";
		case dns_log_stage_e::poll_wait: return "poll_wait";
		case dns_log_stage_e::poll_ndns: return "poll_ndns";
		case dns_log_stage_e::stop_ncap: return "stop_ncap";
		case dns_log_stage_e::drain_ncap: return "drain_ncap";
		case dns_log_stage_e::evaluate: return "evaluate";
		case dns_log_stage_e::exception: return "exception";
		default: return "unknown";
		}
	}

	void dns_mark_stage(const std::shared_ptr<dns_log_ctx_t>& ctx, dns_log_stage_e stage) {
		ctx->stage.store(static_cast<long>(stage), std::memory_order_release);
		ctx->stage_tick_ms.store(static_cast<std::uint64_t>(GetTickCount64()), std::memory_order_release);
	}

	void dns_copy_result(test_lab::result_t& dst, const test_lab::result_t& src) {
		dst.ok = src.ok;
		dst.ntstatus = src.ntstatus;
		dst.bytes_returned = src.bytes_returned;
		dst.elapsed_us = src.elapsed_us;
		dst.error = src.error;
		dst.raw = src.raw;
		dst.parsed = src.parsed;
	}

	bool dns_stop_capture_best_effort(test_lab::result_t& r, DWORD timeout_ms) {
		auto stopped = std::make_shared<std::atomic<bool>>(false);
		auto ok = std::make_shared<std::atomic<bool>>(false);
		auto bytes = std::make_shared<std::atomic<std::uint32_t>>(0u);
		std::thread stop_thread;
		try {
			stop_thread = std::thread([stopped, ok, bytes]() {
				voyager::detail::net_cap_ctrl_request stop_req{};
				stop_req.operation = 1u;
				std::uint32_t br = 0;
				bool stop_ok = false;
				if (device && device->is_connected())
					stop_ok = device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br);
				bytes->store(br, std::memory_order_release);
				ok->store(stop_ok, std::memory_order_release);
				stopped->store(true, std::memory_order_release);
			});
		} catch (...) {
			r.parsed.push_back({ "dns_capture_timeout_stop_ok", "0" });
			r.parsed.push_back({ "dns_capture_timeout_stop_error", "thread_create_failed" });
			return false;
		}
		DWORD wait_rc = WaitForSingleObject(stop_thread.native_handle(), timeout_ms);
		if (wait_rc == WAIT_OBJECT_0) {
			stop_thread.join();
			r.parsed.push_back({ "dns_capture_timeout_stop_ok", ok->load(std::memory_order_acquire) ? "1" : "0" });
			r.parsed.push_back({ "dns_capture_timeout_stop_bytes", fmt_u32(bytes->load(std::memory_order_acquire)) });
			return ok->load(std::memory_order_acquire);
		}
		CancelSynchronousIo(stop_thread.native_handle());
		wait_rc = WaitForSingleObject(stop_thread.native_handle(), 500);
		if (wait_rc == WAIT_OBJECT_0) {
			stop_thread.join();
			r.parsed.push_back({ "dns_capture_timeout_stop_ok", ok->load(std::memory_order_acquire) ? "1" : "0" });
			r.parsed.push_back({ "dns_capture_timeout_stop_bytes", fmt_u32(bytes->load(std::memory_order_acquire)) });
			return ok->load(std::memory_order_acquire);
		}
		stop_thread.detach();
		r.parsed.push_back({ "dns_capture_timeout_stop_ok", "0" });
		r.parsed.push_back({ "dns_capture_timeout_stop_error", "timed_out" });
		return false;
	}

	static std::uint32_t parse_dns_name_user(const std::uint8_t* dns_data,
		std::uint32_t offset,
		std::uint32_t data_len,
		char* out,
		std::uint32_t out_size) {
		std::uint32_t pos = offset;
		std::uint32_t out_pos = 0;
		std::uint32_t jumps = 0;
		bool jumped = false;
		std::uint32_t return_pos = 0;
		while (pos < data_len && out_pos < out_size - 1) {
			std::uint8_t label_len = dns_data[pos];
			if (label_len == 0) {
				++pos;
				break;
			}
			if ((label_len & 0xC0u) == 0xC0u) {
				if (pos + 1 >= data_len) break;
				if (!jumped) return_pos = pos + 2;
				std::uint16_t ptr = static_cast<std::uint16_t>(((label_len & 0x3Fu) << 8) | dns_data[pos + 1]);
				pos = ptr;
				jumped = true;
				if (++jumps > 64) break;
				continue;
			}
			if (label_len > 63) break;
			++pos;
			if (pos + label_len > data_len) break;
			if (out_pos > 0 && out_pos < out_size - 1)
				out[out_pos++] = '.';
			for (std::uint8_t i = 0; i < label_len && out_pos < out_size - 1; ++i)
				out[out_pos++] = static_cast<char>(dns_data[pos + i]);
			pos += label_len;
		}
		out[out_pos] = '\0';
		return jumped ? return_pos : pos;
	}

	static bool dns_payload_matches_probe_hosts(const std::uint8_t* data,
		std::uint32_t data_len,
		const char* const* hosts,
		std::size_t host_count,
		std::string& matched) {
		if (data == nullptr || data_len < 12)
			return false;
		const std::uint8_t* dns_data = data;
		std::uint32_t dns_len = data_len;
		auto strip_udp_header = [&](const std::uint8_t* p, std::uint32_t n) -> bool {
			if (n < 20)
				return false;
			std::uint16_t udp_src = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
			std::uint16_t udp_dst = static_cast<std::uint16_t>((p[2] << 8) | p[3]);
			std::uint16_t udp_len = static_cast<std::uint16_t>((p[4] << 8) | p[5]);
			if ((udp_src == 53 || udp_dst == 53) && udp_len >= 20 && udp_len <= n) {
				dns_data = p + 8;
				dns_len = static_cast<std::uint32_t>(udp_len - 8);
				return true;
			}
			return false;
		};
		auto strip_tcp_header = [&](const std::uint8_t* p, std::uint32_t n) -> bool {
			if (n < 20)
				return false;
			std::uint16_t tcp_src = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
			std::uint16_t tcp_dst = static_cast<std::uint16_t>((p[2] << 8) | p[3]);
			std::uint32_t tcp_hlen = static_cast<std::uint32_t>((p[12] >> 4) * 4);
			if ((tcp_src == 53 || tcp_dst == 53) && tcp_hlen >= 20 && tcp_hlen < n) {
				dns_data = p + tcp_hlen;
				dns_len = n - tcp_hlen;
				return true;
			}
			return false;
		};
		if (data_len >= 28 && (data[0] >> 4) == 4) {
			std::uint32_t ihl = static_cast<std::uint32_t>((data[0] & 0x0Fu) * 4u);
			std::uint16_t total_len = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
			std::uint32_t frame_len = (total_len >= ihl && total_len <= data_len) ? total_len : data_len;
			if (ihl >= 20 && frame_len > ihl) {
				const std::uint8_t proto = data[9];
				if (proto == 17)
					strip_udp_header(data + ihl, frame_len - ihl);
				else if (proto == 6)
					strip_tcp_header(data + ihl, frame_len - ihl);
			}
		} else if (data_len >= 48 && (data[0] >> 4) == 6) {
			const std::uint8_t next = data[6];
			if (next == 17)
				strip_udp_header(data + 40, data_len - 40);
			else if (next == 6)
				strip_tcp_header(data + 40, data_len - 40);
		} else if (!strip_udp_header(data, data_len)) {
			strip_tcp_header(data, data_len);
		}
		auto match_dns_message = [&](const std::uint8_t* msg, std::uint32_t msg_len) -> bool {
			if (msg_len < 12)
				return false;
			std::uint16_t qdcount = static_cast<std::uint16_t>((msg[4] << 8) | msg[5]);
			if (qdcount == 0 || qdcount > 16)
				return false;
			char domain[261] = {};
			std::uint32_t pos = parse_dns_name_user(msg, 12, msg_len, domain, sizeof(domain));
			if (pos == 0 || pos + 4 > msg_len || domain[0] == '\0')
				return false;
			for (std::size_t i = 0; i < host_count; ++i) {
				if (std::strstr(domain, hosts[i]) != nullptr) {
					matched = hosts[i];
					return true;
				}
			}
			return false;
		};
		if (match_dns_message(dns_data, dns_len))
			return true;
		if (dns_len >= 14) {
			std::uint16_t tcp_dns_len = static_cast<std::uint16_t>((dns_data[0] << 8) | dns_data[1]);
			if (tcp_dns_len >= 12 && static_cast<std::uint32_t>(tcp_dns_len) + 2u <= dns_len &&
				match_dns_message(dns_data + 2, tcp_dns_len))
				return true;
		}
		return false;
	}

	static void dns_log_thread_proc(const std::shared_ptr<dns_log_ctx_t>& ctx) {
		test_lab::result_t& r = ctx->result;

		dns_mark_stage(ctx, dns_log_stage_e::ensure_driver);
		if (!ensure_driver(r)) {
			return;
		}
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		dns_mark_stage(ctx, dns_log_stage_e::winsock);
		wsa_guard_t g;
		if (!g.ok) {
			r.ok = false;
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		dns_mark_stage(ctx, dns_log_stage_e::baseline_ndns);
		voyager::detail::net_dns_get_request* baseline =
			static_cast<voyager::detail::net_dns_get_request*>(std::calloc(1, sizeof(voyager::detail::net_dns_get_request)));
		if (baseline == nullptr) {
			r.ok = false;
			r.error = "calloc failed for baseline net_dns_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		baseline->filter_pid = 0u;
		std::uint32_t br_base = 0;
		const std::uint64_t baseline_start = static_cast<std::uint64_t>(GetTickCount64());
		bool ok_base = device->send_ioctl_raw(ioctl_codes::NDNS(), baseline, sizeof(*baseline), br_base);
		const std::uint64_t baseline_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - baseline_start;
		const std::uint32_t baseline_total = ok_base ? baseline->entry_count : 0u;
		r.parsed.push_back({ "baseline_dns_ioctl_ok", ok_base ? "1" : "0" });
		r.parsed.push_back({ "baseline_dns_ioctl_elapsed_ms", fmt_u64(baseline_elapsed) });
		r.parsed.push_back({ "baseline_dns_entry_count", fmt_u32(baseline_total) });
		std::free(baseline);

		dns_mark_stage(ctx, dns_log_stage_e::start_ncap);
		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = 0u;
		start_req.filter_port = 53u;
		start_req.filter_protocol = 0u;
		start_req.max_packet_bytes = 512u;
		std::uint32_t br_start = 0;
		const std::uint64_t cap_start_tick = static_cast<std::uint64_t>(GetTickCount64());
		bool cap_started = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br_start);
		const std::uint64_t cap_start_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - cap_start_tick;
		ctx->capture_started.store(cap_started, std::memory_order_release);
		r.parsed.push_back({ "dns_capture_start_ok", cap_started ? "1" : "0" });
		r.parsed.push_back({ "dns_capture_start_elapsed_ms", fmt_u64(cap_start_elapsed) });
		r.parsed.push_back({ "dns_capture_filter_pid", "0" });
		r.parsed.push_back({ "dns_capture_filter_protocol", "0" });
		r.parsed.push_back({ "dns_probe_owner_pid", fmt_u32(self_pid) });
		if (!cap_started) {
			r.ok = false;
			r.error = "NCAP start failed before DNS probe";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		auto stop_capture_once = [&]() -> bool {
			if (!cap_started)
				return true;
			dns_mark_stage(ctx, dns_log_stage_e::stop_ncap);
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t br_stop = 0;
			const std::uint64_t stop_start = static_cast<std::uint64_t>(GetTickCount64());
			bool stop_ok = device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
			const std::uint64_t stop_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - stop_start;
			cap_started = false;
			ctx->capture_started.store(false, std::memory_order_release);
			r.parsed.push_back({ "dns_capture_stop_ok", stop_ok ? "1" : "0" });
			r.parsed.push_back({ "dns_capture_stop_elapsed_ms", fmt_u64(stop_elapsed) });
			r.parsed.push_back({ "dns_capture_stop_bytes", fmt_u32(br_stop) });
			return stop_ok;
		};

		auto finish_cancelled = [&]() -> bool {
			if (!ctx->cancel.load(std::memory_order_acquire))
				return false;
			stop_capture_once();
			r.ok = false;
			r.error = "DNS verifier cancelled after timeout";
			r.ntstatus = static_cast<std::int32_t>(0xC00000B5u);
			return true;
		};

		static const char* kCandidateHosts[] = {
			"aida-testlab-probe.invalid",
			"aida-testlab-dns.invalid",
			"www.microsoft.com"
		};
		const std::size_t kCandidateHostCount = sizeof(kCandidateHosts) / sizeof(kCandidateHosts[0]);

		std::string attempted_hosts;
		std::uint32_t any_io_count = 0u;

		for (std::size_t i = 0; i < kCandidateHostCount; ++i) {
			if (finish_cancelled())
				return;
			const char* host = kCandidateHosts[i];
			::diag::log_tagged_fmt("verify_dns", "candidate[%zu] start host=%s", i, host);

			std::string udp_diag;
			dns_mark_stage(ctx, dns_log_stage_e::udp_probe);
			bool lookup_ok = issue_udp_dns_probe_to_one_one(host, udp_diag);
			::diag::log_tagged_fmt("verify_dns", "candidate[%zu] udp_done ok=%d diag=%s",
				i, lookup_ok ? 1 : 0, udp_diag.c_str());
			std::string tcp_diag;
			dns_mark_stage(ctx, dns_log_stage_e::tcp_probe);
			bool tcp_ok = issue_tcp_dns_probe_to_one_one(host, tcp_diag);
			::diag::log_tagged_fmt("verify_dns", "candidate[%zu] tcp_done ok=%d diag=%s",
				i, tcp_ok ? 1 : 0, tcp_diag.c_str());
			dns_mark_stage(ctx, dns_log_stage_e::windns_probe);
			bool gai_ok = resolve_host_with_timeout(host, 2000);
			::diag::log_tagged_fmt("verify_dns", "candidate[%zu] gai_done ok=%d", i, gai_ok ? 1 : 0);
			lookup_ok = lookup_ok || tcp_ok || gai_ok;

			char label[40];
			std::snprintf(label, sizeof(label), "step1_gai[%zu]", i);
			char val[360];
			std::snprintf(val, sizeof(val), "host=%s ok=%d udp={%s} tcp={%s} gai=%d",
				host,
				lookup_ok ? 1 : 0,
				udp_diag.c_str(),
				tcp_diag.c_str(),
				gai_ok ? 1 : 0);
			r.parsed.push_back({ std::string(label), std::string(val) });
			if (!attempted_hosts.empty()) attempted_hosts.append(",");
			attempted_hosts.append(host);
			if (lookup_ok) ++any_io_count;
		}
		if (finish_cancelled())
			return;

		r.parsed.push_back({ "step1_attempted_hosts", attempted_hosts });
		r.parsed.push_back({ "step1_any_lookup_attempts", fmt_u32(any_io_count) });

		std::uint32_t after_total = 0u;
		std::uint32_t matches_name_and_pid = 0u;
		std::uint32_t matches_name_any_pid = 0u;
		std::uint32_t matches_name_self_or_unknown_pid = 0u;
		std::uint32_t any_self_pid_rows = 0u;
		std::uint32_t unknown_pid_rows = 0u;
		std::uint32_t printed = 0u;
		const std::uint32_t print_cap = 8u;
		std::string matched_host;

		for (int attempt = 0; attempt < 10; ++attempt) {
			if (finish_cancelled())
				return;
			dns_mark_stage(ctx, dns_log_stage_e::poll_wait);
			std::this_thread::sleep_for(std::chrono::milliseconds(200));

			voyager::detail::net_dns_get_request* req =
				static_cast<voyager::detail::net_dns_get_request*>(std::calloc(1, sizeof(voyager::detail::net_dns_get_request)));
			if (req == nullptr) {
				stop_capture_once();
				r.ok = false;
				r.error = "calloc failed for net_dns_get_request";
				r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
				return;
			}
			req->filter_pid = 0u;
			std::uint32_t br = 0;
			dns_mark_stage(ctx, dns_log_stage_e::poll_ndns);
			const std::uint64_t poll_start = static_cast<std::uint64_t>(GetTickCount64());
			bool ok = device->send_ioctl_raw(ioctl_codes::NDNS(), req, sizeof(*req), br);
			const std::uint64_t poll_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - poll_start;
			r.bytes_returned = br;
			if (!ok) {
				char label[40];
				std::snprintf(label, sizeof(label), "poll_ndns[%d]_elapsed_ms", attempt);
				r.parsed.push_back({ std::string(label), fmt_u64(poll_elapsed) });
				r.ok = false;
				r.error = "NDNS ioctl failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				std::free(req);
				stop_capture_once();
				return;
			}
			char poll_label[40];
			std::snprintf(poll_label, sizeof(poll_label), "poll_ndns[%d]_elapsed_ms", attempt);
			r.parsed.push_back({ std::string(poll_label), fmt_u64(poll_elapsed) });
			after_total = req->entry_count;
			std::uint32_t cap = after_total;
			if (cap > voyager::detail::NET_DNS_GET_MAX) cap = static_cast<std::uint32_t>(voyager::detail::NET_DNS_GET_MAX);
			matches_name_and_pid = 0u;
			matches_name_any_pid = 0u;
			matches_name_self_or_unknown_pid = 0u;
			any_self_pid_rows = 0u;
			unknown_pid_rows = 0u;
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& e = req->entries[i];
				char dom[261];
				std::memcpy(dom, e.domain, 260);
				dom[260] = '\0';
				bool pid_match = (e.pid == self_pid);
				bool pid_unknown = (e.pid == 0u);
				bool pid_accepted = pid_match || pid_unknown;
				if (pid_match) ++any_self_pid_rows;
				if (pid_unknown) ++unknown_pid_rows;
				bool name_match = false;
				for (std::size_t h = 0; h < kCandidateHostCount; ++h) {
					if (std::strstr(dom, kCandidateHosts[h]) != nullptr) {
						name_match = true;
						if (pid_accepted && matched_host.empty()) matched_host = kCandidateHosts[h];
						break;
					}
				}
				if (name_match) ++matches_name_any_pid;
				if (name_match && pid_match) ++matches_name_and_pid;
				if (name_match && pid_accepted) ++matches_name_self_or_unknown_pid;
				if (attempt == 9 && name_match && printed < print_cap) {
					char label[24];
					std::snprintf(label, sizeof(label), "dns[%u]", i);
					char val[384];
					std::snprintf(val, sizeof(val),
						"ts=%llu pid=%u type=%u rcode=%u ttl=%u %s -> %s pid_match=%u pid_unknown=%u",
						static_cast<unsigned long long>(e.timestamp),
						e.pid, e.query_type, e.response_code, e.ttl,
						dom,
						fmt_ip_v4(e.resolved_addr).c_str(),
						pid_match ? 1u : 0u,
						pid_unknown ? 1u : 0u);
					r.parsed.push_back({ std::string(label), std::string(val) });
					++printed;
				}
			}
			std::free(req);
			if (matches_name_self_or_unknown_pid > 0u) break;
		}

		stop_capture_once();

		std::uint32_t captured_dns_packets = 0u;
		std::uint32_t captured_probe_packets = 0u;
		std::uint32_t captured_total_packets = 0u;
		std::uint32_t capture_batches = 0u;
		std::uint32_t capture_drain_failures = 0u;
		std::string captured_probe_host;
		for (std::uint32_t batch = 0; batch < 8u; ++batch) {
			if (finish_cancelled())
				return;
			dns_mark_stage(ctx, dns_log_stage_e::drain_ncap);
			voyager::detail::net_cap_get_request* cap_req =
				static_cast<voyager::detail::net_cap_get_request*>(std::calloc(1, sizeof(voyager::detail::net_cap_get_request)));
			if (cap_req == nullptr) {
				++capture_drain_failures;
				break;
			}
			cap_req->max_packets = voyager::detail::NET_CAP_GET_MAX;
			std::uint32_t br_cap = 0;
			const std::uint64_t drain_start = static_cast<std::uint64_t>(GetTickCount64());
			bool cap_ok = device->send_ioctl_raw(ioctl_codes::NCPG(), cap_req, sizeof(*cap_req), br_cap);
			const std::uint64_t drain_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - drain_start;
			char drain_label[44];
			std::snprintf(drain_label, sizeof(drain_label), "drain_ncap[%u]_elapsed_ms", batch);
			r.parsed.push_back({ std::string(drain_label), fmt_u64(drain_elapsed) });
			if (!cap_ok) {
				++capture_drain_failures;
				std::free(cap_req);
				break;
			}
			++capture_batches;
			std::uint32_t cap_n = cap_req->packet_count;
			if (cap_n > voyager::detail::NET_CAP_GET_MAX)
				cap_n = static_cast<std::uint32_t>(voyager::detail::NET_CAP_GET_MAX);
			captured_total_packets += cap_n;
			for (std::uint32_t i = 0; i < cap_n; ++i) {
				const auto& p = cap_req->packets[i];
				if ((p.protocol != 17u && p.protocol != 6u) || (p.local_port != 53u && p.remote_port != 53u))
					continue;
				++captured_dns_packets;
				std::string host_match;
				if (dns_payload_matches_probe_hosts(p.payload, p.payload_size, kCandidateHosts, kCandidateHostCount, host_match)) {
					++captured_probe_packets;
					if (captured_probe_host.empty())
						captured_probe_host = host_match;
				}
			}
			std::free(cap_req);
			if (cap_n == 0u)
				break;
		}
		r.parsed.push_back({ "dns_capture_drain_ok", capture_drain_failures == 0u ? "1" : "0" });
		r.parsed.push_back({ "dns_capture_batches", fmt_u32(capture_batches) });
		r.parsed.push_back({ "dns_capture_packet_count", fmt_u32(captured_total_packets) });
		r.parsed.push_back({ "dns_capture_drain_failures", fmt_u32(capture_drain_failures) });
		r.parsed.push_back({ "captured_dns_packets", fmt_u32(captured_dns_packets) });
		r.parsed.push_back({ "captured_probe_dns_packets", fmt_u32(captured_probe_packets) });
		if (!captured_probe_host.empty())
			r.parsed.push_back({ "captured_probe_host", captured_probe_host });

		r.parsed.push_back({ "dns_entry_count_total", fmt_u32(after_total) });
		r.parsed.push_back({ "matches_name_and_pid", fmt_u32(matches_name_and_pid) });
		r.parsed.push_back({ "matches_name_any_pid", fmt_u32(matches_name_any_pid) });
		r.parsed.push_back({ "matches_name_self_or_unknown_pid", fmt_u32(matches_name_self_or_unknown_pid) });
		r.parsed.push_back({ "any_self_pid_rows", fmt_u32(any_self_pid_rows) });
		r.parsed.push_back({ "unknown_pid_rows", fmt_u32(unknown_pid_rows) });
		if (!matched_host.empty()) {
			r.parsed.push_back({ "matched_host", matched_host });
		}
		const std::uint32_t delta = (after_total >= baseline_total) ? (after_total - baseline_total) : 0u;
		r.parsed.push_back({ "delta_dns_entries", fmt_u32(delta) });

		dns_mark_stage(ctx, dns_log_stage_e::evaluate);
		r.parsed.push_back({ "dns_eval_stage", dns_log_stage_name(ctx->stage.load(std::memory_order_acquire)) });
		r.parsed.push_back({ "dns_stage", dns_log_stage_name(ctx->stage.load(std::memory_order_acquire)) });
		r.parsed.push_back({ "dns_eval_pid", fmt_u32(self_pid) });
		r.parsed.push_back({ "dns_pid", fmt_u32(self_pid) });
		r.parsed.push_back({ "dns_ndns_attributed_probe", matches_name_self_or_unknown_pid > 0u ? "1" : "0" });
		r.parsed.push_back({ "dns_ndns_self_pid_probe_matches", fmt_u32(matches_name_and_pid) });
		r.parsed.push_back({ "dns_ndns_self_or_unknown_probe_matches", fmt_u32(matches_name_self_or_unknown_pid) });
		r.parsed.push_back({ "dns_ndns_any_pid_probe_matches", fmt_u32(matches_name_any_pid) });
		r.parsed.push_back({ "dns_packet_fallback_probe_matches", fmt_u32(captured_probe_packets) });
		r.parsed.push_back({ "dns_packet_fallback_dns_packets", fmt_u32(captured_dns_packets) });
		const std::string dns_eval_host = !matched_host.empty() ? matched_host : (!captured_probe_host.empty() ? captured_probe_host : attempted_hosts);
		if (!dns_eval_host.empty()) {
			r.parsed.push_back({ "dns_eval_hostname", dns_eval_host });
			r.parsed.push_back({ "dns_hostname", dns_eval_host });
		}
		const bool packet_probe_seen = captured_probe_packets > 0u;
		const bool ndns_hostname_seen = matches_name_any_pid > 0u;
		const bool ndns_pid_attributed = matches_name_self_or_unknown_pid > 0u;
		r.parsed.push_back({ "dns_feature_capture_verified", (ndns_pid_attributed || (ndns_hostname_seen && packet_probe_seen)) ? "1" : "0" });
		r.parsed.push_back({ "dns_ndns_pid_attribution_degraded", (!ndns_pid_attributed && ndns_hostname_seen && packet_probe_seen) ? "1" : "0" });
		if (ndns_pid_attributed) {
			r.ntstatus = 0;
			r.ok = true;
			r.parsed.push_back({ "dns_pass_path", matches_name_and_pid > 0u ? "ndns_self_pid" : "ndns_unknown_pid" });
		} else if (ndns_hostname_seen && packet_probe_seen) {
			r.ntstatus = 0;
			r.ok = true;
			r.parsed.push_back({ "dns_pass_path", "ndns_hostname_packet_capture_pid_degraded" });
		} else if (packet_probe_seen) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS packet capture saw probe traffic but NDNS did not record the probe hostname";
			r.parsed.push_back({ "dns_pass_path", "none_packet_fallback_only" });
		} else if (ndns_hostname_seen) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logger contains probe hostnames without fresh packet evidence and attributed them to a different nonzero PID";
			r.parsed.push_back({ "dns_pass_path", "none_wrong_pid" });
		} else if (any_self_pid_rows > 0u) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logger captured self-PID rows but none contained the probe hostnames";
			r.parsed.push_back({ "dns_pass_path", "none_self_pid_without_probe" });
		} else if (delta > 0u && after_total > 0u) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS table changed during probe but no row matched both current PID and probe hostname";
			r.parsed.push_back({ "dns_pass_path", "none_table_changed" });
		} else {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logging did not capture the current process DNS probes";
			r.parsed.push_back({ "dns_pass_path", "none" });
		}
	}

	void run_verify_dns_log(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		const DWORD timeout_ms = 30000;
		const DWORD cancel_grace_ms = 3000;
		auto ctx = std::make_shared<dns_log_ctx_t>();
		dns_mark_stage(ctx, dns_log_stage_e::not_started);
		std::thread worker;
		try {
			worker = std::thread([ctx]() {
				try {
					dns_log_thread_proc(ctx);
				} catch (const std::exception& e) {
					dns_mark_stage(ctx, dns_log_stage_e::exception);
					if (ctx->capture_started.load(std::memory_order_acquire))
						dns_stop_capture_best_effort(ctx->result, 2000);
					ctx->result.ok = false;
					ctx->result.error = std::string("DNS verifier threw exception: ") + e.what();
					ctx->result.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				} catch (...) {
					dns_mark_stage(ctx, dns_log_stage_e::exception);
					if (ctx->capture_started.load(std::memory_order_acquire))
						dns_stop_capture_best_effort(ctx->result, 2000);
					ctx->result.ok = false;
					ctx->result.error = "DNS verifier threw an unknown exception";
					ctx->result.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				}
			});
		} catch (const std::exception& e) {
			std::string fallback_reason = e.what();
			try {
				dns_log_thread_proc(ctx);
				dns_copy_result(r, ctx->result);
				r.parsed.push_back({ "dns_thread_fallback", fallback_reason });
			} catch (const std::exception& run_e) {
				r.ok = false;
				r.error = std::string("DNS verifier fallback threw exception: ") + run_e.what();
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			} catch (...) {
				r.ok = false;
				r.error = "DNS verifier fallback threw an unknown exception";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			}
			return;
		} catch (...) {
			std::string fallback_reason = "unknown";
			try {
				dns_log_thread_proc(ctx);
				dns_copy_result(r, ctx->result);
				r.parsed.push_back({ "dns_thread_fallback", fallback_reason });
			} catch (const std::exception& run_e) {
				r.ok = false;
				r.error = std::string("DNS verifier fallback threw exception: ") + run_e.what();
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			} catch (...) {
				r.ok = false;
				r.error = "DNS verifier fallback threw an unknown exception";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			}
			return;
		}

		DWORD wait_rc = WaitForSingleObject(worker.native_handle(), timeout_ms);
		if (wait_rc == WAIT_OBJECT_0) {
			worker.join();
			dns_copy_result(r, ctx->result);
			return;
		}

		ctx->cancel.store(true, std::memory_order_release);
		CancelSynchronousIo(worker.native_handle());
		DWORD cancel_wait_rc = WaitForSingleObject(worker.native_handle(), cancel_grace_ms);
		const long stage = ctx->stage.load(std::memory_order_acquire);
		const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
		const std::uint64_t stage_tick = ctx->stage_tick_ms.load(std::memory_order_acquire);
		const std::uint64_t stage_elapsed = stage_tick == 0u ? 0u : now_ms - stage_tick;
		if (cancel_wait_rc == WAIT_OBJECT_0) {
			worker.join();
			dns_copy_result(r, ctx->result);
			r.ok = false;
			r.ntstatus = static_cast<std::int32_t>(0xC00000B5u);
			r.error = std::string("DNS round-trip exceeded ") + fmt_u32(timeout_ms) +
				" ms and completed during cancellation grace at stage " + dns_log_stage_name(stage);
			r.parsed.push_back({ "dns_timeout_stage", dns_log_stage_name(stage) });
			r.parsed.push_back({ "dns_timeout_stage_elapsed_ms", fmt_u64(stage_elapsed) });
			r.parsed.push_back({ "dns_timeout_cancelled_cleanly", "1" });
			return;
		}

		r.ok = false;
		r.ntstatus = static_cast<std::int32_t>(0xC00000B5u);
		r.error = std::string("DNS round-trip timed out after ") + fmt_u32(timeout_ms) +
			" ms at stage " + dns_log_stage_name(stage);
		r.parsed.push_back({ "dns_timeout_stage", dns_log_stage_name(stage) });
		r.parsed.push_back({ "dns_timeout_stage_elapsed_ms", fmt_u64(stage_elapsed) });
		r.parsed.push_back({ "dns_timeout_cancelled_cleanly", "0" });
		r.parsed.push_back({ "dns_timeout_capture_started", ctx->capture_started.load(std::memory_order_acquire) ? "1" : "0" });
		if (ctx->capture_started.load(std::memory_order_acquire))
			dns_stop_capture_best_effort(r, 2000);
		worker.detach();
	}

	void run_verify_net_stats(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;

		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = self_pid;
		start_req.filter_port = 0u;
		start_req.filter_protocol = 0u;
		start_req.max_packet_bytes = 1500u;
		std::uint32_t br_start = 0;
		bool cap_started = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br_start);
		r.parsed.push_back({ "stats_capture_start_ok", cap_started ? "1" : "0" });
		r.parsed.push_back({ "stats_capture_filter_pid", fmt_u32(self_pid) });
		if (!cap_started) {
			r.ok = false;
			r.error = "NCAP start failed before NSTS probe";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		voyager::detail::net_stats_request base_req{};
		std::uint32_t br1 = 0;
		bool ok1 = device->send_ioctl_raw(ioctl_codes::NSTS(), &base_req, sizeof(base_req), br1);
		if (!ok1) {
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t br_stop = 0;
			device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
			r.ok = false;
			r.error = "NSTS baseline ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "baseline_bytes_sent", fmt_u64(base_req.bytes_sent) });
		r.parsed.push_back({ "baseline_bytes_received", fmt_u64(base_req.bytes_received) });
		r.parsed.push_back({ "baseline_packets_sent", fmt_u64(base_req.packets_sent) });
		r.parsed.push_back({ "baseline_packets_received", fmt_u64(base_req.packets_received) });

		std::string probe_diag;
		bool probed = issue_raw_tcp_probe_to_one_one(probe_diag);
		r.parsed.push_back({ "probe_initiated", probed ? "1" : "0" });
		if (!probe_diag.empty()) {
			r.parsed.push_back({ "probe_diag", probe_diag });
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(300));

		voyager::detail::net_stats_request after_req{};
		std::uint32_t br2 = 0;
		bool ok2 = device->send_ioctl_raw(ioctl_codes::NSTS(), &after_req, sizeof(after_req), br2);
		r.bytes_returned = br2;
		if (!ok2) {
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t br_stop = 0;
			device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
			r.ok = false;
			r.error = "NSTS post-traffic ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		voyager::detail::net_cap_ctrl_request stop_req{};
		stop_req.operation = 1u;
		std::uint32_t br_stop = 0;
		device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
		r.parsed.push_back({ "stats_capture_stop_ok", "1" });
		r.parsed.push_back({ "after_bytes_sent", fmt_u64(after_req.bytes_sent) });
		r.parsed.push_back({ "after_bytes_received", fmt_u64(after_req.bytes_received) });
		r.parsed.push_back({ "after_packets_sent", fmt_u64(after_req.packets_sent) });
		r.parsed.push_back({ "after_packets_received", fmt_u64(after_req.packets_received) });

		const std::uint64_t d_bs = (after_req.bytes_sent >= base_req.bytes_sent) ? (after_req.bytes_sent - base_req.bytes_sent) : 0ull;
		const std::uint64_t d_br_v = (after_req.bytes_received >= base_req.bytes_received) ? (after_req.bytes_received - base_req.bytes_received) : 0ull;
		const std::uint64_t d_ps = (after_req.packets_sent >= base_req.packets_sent) ? (after_req.packets_sent - base_req.packets_sent) : 0ull;
		const std::uint64_t d_pr = (after_req.packets_received >= base_req.packets_received) ? (after_req.packets_received - base_req.packets_received) : 0ull;
		r.parsed.push_back({ "delta_bytes_sent", fmt_u64(d_bs) });
		r.parsed.push_back({ "delta_bytes_received", fmt_u64(d_br_v) });
		r.parsed.push_back({ "delta_packets_sent", fmt_u64(d_ps) });
		r.parsed.push_back({ "delta_packets_received", fmt_u64(d_pr) });

		bool any_increase = (d_bs > 0ull) || (d_br_v > 0ull) || (d_ps > 0ull) || (d_pr > 0ull);
		if (any_increase) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			r.error = "NSTS counters did not increase after generating traffic -- stats collection may be broken";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	__declspec(noinline) bool seh_write_pattern(std::uint64_t* dst, std::size_t count, std::uint64_t pattern) {
		__try {
			for (std::size_t i = 0; i < count; ++i) dst[i] = pattern;
			std::uint64_t check = dst[0] ^ dst[count - 1];
			return check == 0ull;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	void run_verify_memory_round_trip(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		voyager::detail::alloc_mem_request areq{};
		areq.pid = self_pid;
		areq.size = 4096ull;
		std::uint32_t br1 = 0;
		bool ok_a = device->send_ioctl_raw(ioctl_codes::AM(), &areq, sizeof(areq), br1);
		if (!ok_a || areq.allocated_address == 0ull) {
			r.ok = false;
			r.error = "AM allocate ioctl failed or returned null address";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		const std::uint64_t addr = areq.allocated_address;
		r.parsed.push_back({ "step1_allocated_address", fmt_hex_u64(addr) });
		r.parsed.push_back({ "step1_actual_size", fmt_u64(areq.actual_size) });

		void* user_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(addr));
		DWORD old_prot = 0;
		BOOL vp_ok = VirtualProtect(user_ptr, 4096, PAGE_READWRITE, &old_prot);
		if (!vp_ok) {
			DWORD err = GetLastError();
			char b[80];
			std::snprintf(b, sizeof(b), "VirtualProtect failed err=%lu", static_cast<unsigned long>(err));
			r.parsed.push_back({ "step2_virtualprotect_diag", std::string(b) });
		} else {
			r.parsed.push_back({ "step2_virtualprotect", "PAGE_READWRITE" });
		}
		const std::uint64_t pattern = 0xDEADBEEFCAFEBABEull;
		std::uint64_t* dst = static_cast<std::uint64_t*>(user_ptr);
		bool write_ok = seh_write_pattern(dst, 64, pattern);
		r.parsed.push_back({ "step2_write_pattern_ok", write_ok ? "1" : "0" });

		voyager::detail::query_memory_request qreq{};
		qreq.pid = self_pid;
		qreq.address = addr;
		std::uint32_t br2 = 0;
		bool ok_q = device->send_ioctl_raw(ioctl_codes::QM(), &qreq, sizeof(qreq), br2);
		if (!ok_q) {
			r.ok = false;
			r.error = "QM query (post-alloc) ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "step3_region_base", fmt_hex_u64(qreq.region_base) });
		r.parsed.push_back({ "step3_region_size", fmt_u64(qreq.region_size) });
		r.parsed.push_back({ "step3_state", fmt_hex_u64(static_cast<std::uint64_t>(qreq.state)) });
		r.parsed.push_back({ "step3_protect", fmt_hex_u64(static_cast<std::uint64_t>(qreq.protect)) });
		const bool committed_ok = (qreq.state == 0x1000u) && (qreq.region_size >= 4096ull);

		voyager::detail::free_mem_request freq{};
		freq.pid = self_pid;
		freq.address = addr;
		std::uint32_t br3 = 0;
		bool ok_f = device->send_ioctl_raw(ioctl_codes::FM(), &freq, sizeof(freq), br3);
		r.parsed.push_back({ "step4_free_ioctl_ok", ok_f ? "1" : "0" });

		voyager::detail::query_memory_request qreq2{};
		qreq2.pid = self_pid;
		qreq2.address = addr;
		std::uint32_t br4 = 0;
		bool ok_q2 = device->send_ioctl_raw(ioctl_codes::QM(), &qreq2, sizeof(qreq2), br4);
		r.bytes_returned = br4;
		bool freed_ok = false;
		if (ok_q2) {
			r.parsed.push_back({ "step5_post_free_state", fmt_hex_u64(static_cast<std::uint64_t>(qreq2.state)) });
			freed_ok = (qreq2.state == 0x10000u);
		} else {
			r.parsed.push_back({ "step5_post_free_query", "QM returned false (region likely gone)" });
			freed_ok = true;
		}

		if (write_ok && committed_ok && ok_f && freed_ok) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			if (!write_ok) r.error = "user-mode write into kernel-allocated region failed";
			else if (!committed_ok) r.error = "QM did not report MEM_COMMIT with >=4096 bytes after alloc";
			else if (!ok_f) r.error = "FM free ioctl failed";
			else r.error = "post-free QM reported region still committed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	bool start_external_tcp_probe(tcp_probe_state_t& probe) {
		probe.close();
		SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sk == INVALID_SOCKET) {
			probe.diag = "socket() failed";
			return false;
		}
		u_long nb = 1;
		ioctlsocket(sk, FIONBIO, &nb);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(80);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		int rc = connect(sk, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		bool initiated = false;
		if (rc == 0) {
			initiated = true;
		} else {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				initiated = true;
			} else {
				char b[64];
				std::snprintf(b, sizeof(b), "connect() err=%d", err);
				probe.diag = b;
			}
		}
		if (initiated) {
			fd_set wf;
			FD_ZERO(&wf);
			FD_SET(sk, &wf);
			timeval tv{};
			tv.tv_sec = 0;
			tv.tv_usec = 200000;
			select(0, nullptr, &wf, nullptr, &tv);
			probe.primary = sk;
			probe.initiated = true;
			probe.mode = "external";
			probe.set_remote(1u, 1u, 1u, 1u, 80u);
			probe.diag = "external 1.1.1.1:80 connect initiated";
			return true;
		}
		closesocket(sk);
		return false;
	}

	bool start_loopback_tcp_probe(tcp_probe_state_t& probe) {
		probe.close();
		SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener == INVALID_SOCKET) {
			probe.diag = "loopback listener socket() failed";
			return false;
		}
		SOCKET client = INVALID_SOCKET;
		SOCKET accepted = INVALID_SOCKET;
		auto cleanup = [&]() {
			if (client != INVALID_SOCKET) {
				closesocket(client);
				client = INVALID_SOCKET;
			}
			if (accepted != INVALID_SOCKET) {
				closesocket(accepted);
				accepted = INVALID_SOCKET;
			}
			if (listener != INVALID_SOCKET) {
				closesocket(listener);
				listener = INVALID_SOCKET;
			}
		};
		DWORD timeout_ms = 1000u;
		setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		sockaddr_in bind_addr{};
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_port = 0;
		bind_addr.sin_addr.s_addr = htonl(0x7f000001u);
		if (bind(listener, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "loopback bind err=%d", err);
			probe.diag = b;
			cleanup();
			return false;
		}
		if (listen(listener, 1) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "loopback listen err=%d", err);
			probe.diag = b;
			cleanup();
			return false;
		}
		int name_len = sizeof(bind_addr);
		if (getsockname(listener, reinterpret_cast<sockaddr*>(&bind_addr), &name_len) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "loopback getsockname err=%d", err);
			probe.diag = b;
			cleanup();
			return false;
		}
		client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (client == INVALID_SOCKET) {
			probe.diag = "loopback client socket() failed";
			cleanup();
			return false;
		}
		setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		if (connect(client, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "loopback connect err=%d", err);
			probe.diag = b;
			cleanup();
			return false;
		}
		accepted = accept(listener, nullptr, nullptr);
		if (accepted == INVALID_SOCKET) {
			int err = WSAGetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "loopback accept err=%d", err);
			probe.diag = b;
			cleanup();
			return false;
		}
		closesocket(listener);
		listener = INVALID_SOCKET;
		probe.primary = client;
		probe.accepted = accepted;
		client = INVALID_SOCKET;
		accepted = INVALID_SOCKET;
		probe.initiated = true;
		probe.mode = "loopback";
		probe.set_remote(127u, 0u, 0u, 1u, static_cast<std::uint32_t>(ntohs(bind_addr.sin_port)));
		char b[128];
		std::snprintf(b, sizeof(b), "loopback 127.0.0.1:%u connected",
			static_cast<unsigned>(probe.remote_port));
		probe.diag = b;
		cleanup();
		return true;
	}

	std::uint32_t count_self_pid_rows(const voyager::detail::tcpip_conn_dump_request& req,
		std::uint32_t self_pid,
		std::uint32_t& out_pid_and_one_one)
	{
		out_pid_and_one_one = 0u;
		std::uint32_t scan = req.connection_count;
		if (scan > voyager::detail::MAX_TCPIP_CONNECTIONS) scan = static_cast<std::uint32_t>(voyager::detail::MAX_TCPIP_CONNECTIONS);
		std::uint32_t pid_only = 0u;
		for (std::uint32_t i = 0; i < scan; ++i) {
			const auto& e = req.entries[i];
			if (e.pid == self_pid) {
				++pid_only;
				if (addr_is_one_one_one_one(e.remote_addr, e.address_family) && e.remote_port == 80u) {
					++out_pid_and_one_one;
				}
			}
		}
		return pid_only;
	}

	void run_verify_tcpip_connection_visible(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		wsa_guard_t g;
		if (!g.ok) {
			r.ok = false;
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		voyager::detail::tcpip_conn_dump_request* baseline_req =
			static_cast<voyager::detail::tcpip_conn_dump_request*>(std::calloc(1, sizeof(voyager::detail::tcpip_conn_dump_request)));
		if (baseline_req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for baseline tcpip_conn_dump_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		baseline_req->target_pid = 0u;
		baseline_req->filter_protocol = 0u;
		std::uint32_t br_base = 0;
		bool ok_base = device->send_ioctl_raw(ioctl_codes::DTCP(), baseline_req, sizeof(*baseline_req), br_base);
		std::uint32_t baseline_self_one_one = 0u;
		std::uint32_t baseline_self_pid_rows = ok_base ? count_self_pid_rows(*baseline_req, self_pid, baseline_self_one_one) : 0u;
		const std::uint32_t baseline_total = ok_base ? baseline_req->connection_count : 0u;
		std::free(baseline_req);
		r.parsed.push_back({ "baseline_tcb_total", fmt_u32(baseline_total) });
		r.parsed.push_back({ "baseline_self_pid_rows", fmt_u32(baseline_self_pid_rows) });
		r.parsed.push_back({ "baseline_self_to_1_1_1_1_port_80", fmt_u32(baseline_self_one_one) });

		tcp_probe_state_t probe;
		bool initiated = start_loopback_tcp_probe(probe);
		if (!initiated) {
			r.parsed.push_back({ "loopback_connect_diag", probe.diag });
			initiated = start_external_tcp_probe(probe);
		}
		r.parsed.push_back({ "step1_connect_initiated", initiated ? "1" : "0" });
		r.parsed.push_back({ "tcp_probe_mode", probe.mode });
		r.parsed.push_back({ "connect_diag", probe.diag });
		if (initiated) {
			char endpoint[64];
			std::snprintf(endpoint, sizeof(endpoint), "%u.%u.%u.%u:%u",
				static_cast<unsigned>(probe.remote_addr[0]),
				static_cast<unsigned>(probe.remote_addr[1]),
				static_cast<unsigned>(probe.remote_addr[2]),
				static_cast<unsigned>(probe.remote_addr[3]),
				static_cast<unsigned>(probe.remote_port));
			r.parsed.push_back({ "tcp_probe_expected_remote", std::string(endpoint) });
		}

		std::uint32_t total = 0u;
		std::uint32_t pid_only = 0u;
		std::uint32_t pid_and_remote = 0u;
		std::uint32_t printed = 0u;
		const std::uint32_t print_cap = 6u;
		bool ok_dtcp = false;
		std::int32_t last_status = 0;

		for (int attempt = 0; attempt < 3; ++attempt) {
			voyager::detail::tcpip_conn_dump_request* req =
				static_cast<voyager::detail::tcpip_conn_dump_request*>(std::calloc(1, sizeof(voyager::detail::tcpip_conn_dump_request)));
			if (req == nullptr) {
				probe.close();
				r.ok = false;
				r.error = "calloc failed for tcpip_conn_dump_request";
				r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
				return;
			}
			req->target_pid = 0u;
			req->filter_protocol = 0u;
			std::uint32_t br = 0;
			ok_dtcp = device->send_ioctl_raw(ioctl_codes::DTCP(), req, sizeof(*req), br);
			r.bytes_returned = br;
			if (!ok_dtcp) {
				std::free(req);
				last_status = static_cast<std::int32_t>(0xC0000001u);
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}
			total = req->connection_count;
			std::uint32_t scan = total;
			if (scan > voyager::detail::MAX_TCPIP_CONNECTIONS) scan = static_cast<std::uint32_t>(voyager::detail::MAX_TCPIP_CONNECTIONS);
			pid_only = 0u;
			pid_and_remote = 0u;
			printed = 0u;
			for (std::uint32_t i = 0; i < scan; ++i) {
				const auto& e = req->entries[i];
				if (e.pid == self_pid) {
					++pid_only;
					if (tcp_probe_remote_matches(probe, e.remote_addr, e.address_family, e.remote_port)) {
						++pid_and_remote;
					}
					if (printed < print_cap) {
						char label[24];
						std::snprintf(label, sizeof(label), "self_tcb[%u]", printed);
						char val[256];
						std::snprintf(val, sizeof(val),
							"pid=%u %s:%u -> %s:%u state=%u",
							e.pid,
							fmt_ip_v4(e.local_addr).c_str(), e.local_port,
							fmt_ip_v4(e.remote_addr).c_str(), e.remote_port,
							e.state);
						r.parsed.push_back({ std::string(label), std::string(val) });
						++printed;
					}
				}
			}
			std::free(req);
			if (pid_and_remote > 0u) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}

		r.parsed.push_back({ "tcb_table_total", fmt_u32(total) });
		r.parsed.push_back({ "self_pid_rows", fmt_u32(pid_only) });
		r.parsed.push_back({ "self_pid_rows_to_probe_remote", fmt_u32(pid_and_remote) });
		const std::uint32_t delta_self = (pid_only >= baseline_self_pid_rows) ? (pid_only - baseline_self_pid_rows) : 0u;
		r.parsed.push_back({ "delta_self_pid_rows", fmt_u32(delta_self) });
		r.parsed.push_back({ "tcpip_expected_remote_seen", pid_and_remote > 0u ? "1" : "0" });
		r.parsed.push_back({ "tcpip_self_pid_only_seen", pid_only > 0u ? "1" : "0" });
		r.parsed.push_back({ "tcpip_probe_initiated", initiated ? "1" : "0" });

		probe.close();

		if (!ok_dtcp) {
			r.ok = false;
			r.error = "DTCP ioctl failed across all retries";
			r.ntstatus = (last_status != 0) ? last_status : static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		if (pid_and_remote > 0u) {
			r.ntstatus = 0;
			r.ok = true;
			r.parsed.push_back({ "tcpip_pass_path", "self_pid_expected_remote" });
			r.parsed.push_back({ "tcpip_endpoint_attribution_degraded", "0" });
		} else if (!initiated) {
			r.ok = false;
			r.error = "TCP probe was not initiated, so the expected remote endpoint row could not be verified";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.parsed.push_back({ "tcpip_pass_path", "none_probe_not_initiated" });
		} else if (delta_self > 0u) {
			r.ok = false;
			r.error = "DTCP captured self-PID rows but none matched the expected remote endpoint";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.parsed.push_back({ "tcpip_pass_path", "self_pid_delta_endpoint_degraded" });
			r.parsed.push_back({ "tcpip_endpoint_attribution_degraded", "1" });
		} else if (pid_only > 0u) {
			r.ok = false;
			r.error = "DTCP captured self-PID rows but none matched the expected remote endpoint";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.parsed.push_back({ "tcpip_pass_path", "none_self_pid_only" });
		} else {
			r.ok = false;
			r.error = "DTCP did not expose a self-PID row for the expected remote endpoint after probe";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.parsed.push_back({ "tcpip_pass_path", "none" });
		}
	}

}

TESTLAB_REGISTER(g_reg_verify_network_capture,
	"verify",
	test_lab::driver_e::whoswho,
	"Network capture round-trip",
	"NCAP start (filter on self PID) -> issue HTTP GET to 1.1.1.1 -> NCAP stop -> NCPG drain -> assert at least one packet attributed to current PID.",
	&render_inputs_empty,
	&run_verify_network_capture);

TESTLAB_REGISTER(g_reg_verify_dns_log,
	"verify",
	test_lab::driver_e::whoswho,
	"DNS query log round-trip",
	"NCAP/NDNS around UDP, TCP, and resolver DNS probes -> assert NDNS attributed one probe hostname to the current or unknown PID.",
	&render_inputs_empty,
	&run_verify_dns_log);

TESTLAB_REGISTER(g_reg_verify_net_stats,
	"verify",
	test_lab::driver_e::whoswho,
	"Network stats sanity",
	"NSTS baseline -> raw TCP probe to 1.1.1.1:80 -> NSTS again -> assert at least one of bytes_in/out or packets_in/out increased.",
	&render_inputs_empty,
	&run_verify_net_stats);

TESTLAB_REGISTER(g_reg_verify_memory_round_trip,
	"verify",
	test_lab::driver_e::whoswho,
	"Memory alloc/write/read/free round-trip",
	"AM allocate 4096 in self -> user-mode write 0xDEADBEEFCAFEBABE pattern -> QM verify MEM_COMMIT -> FM free -> QM verify MEM_FREE.",
	&render_inputs_empty,
	&run_verify_memory_round_trip);

TESTLAB_REGISTER(g_reg_verify_tcpip_connection_visible,
	"verify",
	test_lab::driver_e::whoswho,
	"TCPIP connection table sanity",
	"Open TCP socket to 1.1.1.1:80 (non-blocking, SYN sent) -> DTCP dump -> assert self PID row to 1.1.1.1:80 visible in TCB table.",
	&render_inputs_empty,
	&run_verify_tcpip_connection_visible);
