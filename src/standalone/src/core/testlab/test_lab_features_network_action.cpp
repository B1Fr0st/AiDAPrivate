#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")

#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <ios>
#include <string>

namespace {

	bool ensure_driver(test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return false;
		}
		return true;
	}

	void push_hex64(test_lab::result_t& r, const char* label, std::uint64_t value) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(value));
		r.parsed.push_back({ std::string(label), std::string(buf) });
	}

	void push_u32(test_lab::result_t& r, const char* label, std::uint32_t value) {
		char buf[24];
		std::snprintf(buf, sizeof(buf), "%u (0x%08X)", value, value);
		r.parsed.push_back({ std::string(label), std::string(buf) });
	}

	void push_u64(test_lab::result_t& r, const char* label, std::uint64_t value) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(value));
		r.parsed.push_back({ std::string(label), std::string(buf) });
	}

	void push_text(test_lab::result_t& r, const char* label, const std::string& value) {
		r.parsed.push_back({ std::string(label), value });
	}

	void fail_result(test_lab::result_t& r, const std::string& error, std::uint32_t status = 0xC0000001u) {
		r.error = error;
		r.ntstatus = static_cast<std::int32_t>(status);
		r.ok = false;
		r.skipped = false;
	}

	void copy_into_string_buf(char* dst, std::size_t cap, const std::string& src) {
		if (cap == 0) return;
		std::size_t n = src.size();
		if (n >= cap) n = cap - 1;
		std::memcpy(dst, src.data(), n);
		dst[n] = '\0';
	}

	bool render_text_field(const char* label, std::string& storage, std::size_t cap) {
		char tmp[512];
		if (cap > sizeof(tmp)) cap = sizeof(tmp);
		copy_into_string_buf(tmp, cap, storage);
		bool changed = ImGui::InputText(label, tmp, cap);
		if (changed) {
			storage.assign(tmp);
		}
		return changed;
	}

	std::string format_ipv4(const std::uint8_t a[4]) {
		char buf[24];
		std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
			static_cast<unsigned>(a[0]), static_cast<unsigned>(a[1]),
			static_cast<unsigned>(a[2]), static_cast<unsigned>(a[3]));
		return std::string(buf);
	}

	std::string format_ipv6(const std::uint8_t a[16]) {
		char buf[64];
		std::snprintf(buf, sizeof(buf),
			"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
			a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
			a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
		return std::string(buf);
	}

	std::string format_addr(const std::uint8_t a[16], std::uint32_t af) {
		if (af == 23u) {
			return format_ipv6(a);
		}
		return format_ipv4(a);
	}

	std::string trim_copy(const std::string& s) {
		std::size_t b = 0;
		while (b < s.size() && (s[b] == ' ' || s[b] == '\t')) ++b;
		std::size_t e = s.size();
		while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
		return s.substr(b, e - b);
	}

	bool parse_uint16(const std::string& s, std::uint16_t& out) {
		if (s.empty()) return false;
		unsigned long v = 0;
		for (char c : s) {
			if (c < '0' || c > '9') return false;
			v = v * 10ul + static_cast<unsigned long>(c - '0');
			if (v > 0xFFFFul) return false;
		}
		out = static_cast<std::uint16_t>(v);
		return true;
	}

	bool parse_ipv4(const std::string& s, std::uint8_t out[16]) {
		std::memset(out, 0, 16);
		std::uint32_t parts[4] = { 0, 0, 0, 0 };
		int idx = 0;
		std::uint32_t cur = 0;
		bool any_digit = false;
		for (std::size_t i = 0; i <= s.size(); ++i) {
			char c = (i == s.size()) ? '.' : s[i];
			if (c == '.') {
				if (!any_digit) return false;
				if (idx >= 4) return false;
				parts[idx++] = cur;
				cur = 0;
				any_digit = false;
			}
			else if (c >= '0' && c <= '9') {
				cur = cur * 10u + static_cast<std::uint32_t>(c - '0');
				if (cur > 255u) return false;
				any_digit = true;
			}
			else {
				return false;
			}
		}
		if (idx != 4) return false;
		out[0] = static_cast<std::uint8_t>(parts[0]);
		out[1] = static_cast<std::uint8_t>(parts[1]);
		out[2] = static_cast<std::uint8_t>(parts[2]);
		out[3] = static_cast<std::uint8_t>(parts[3]);
		return true;
	}

	struct endpoint_spec_t {
		std::uint32_t protocol = 0;
		std::uint16_t port = 0;
		std::uint8_t  addr[16] = { 0 };
		std::uint32_t address_family = 2;
		bool          has_port = false;
		bool          has_addr = false;
		bool          has_protocol = false;
	};

	bool parse_endpoint_spec(const std::string& raw, endpoint_spec_t& out, std::string& err) {
		std::string s = trim_copy(raw);
		if (s.empty()) {
			err = "endpoint spec is empty";
			return false;
		}
		std::string proto_part;
		std::string rest = s;
		std::size_t colon_proto = s.find("://");
		if (colon_proto != std::string::npos) {
			proto_part = s.substr(0, colon_proto);
			rest = s.substr(colon_proto + 3);
		}
		else {
			std::size_t single = s.find(':');
			if (single != std::string::npos) {
				std::string candidate = s.substr(0, single);
				if (candidate == "tcp" || candidate == "TCP" ||
					candidate == "udp" || candidate == "UDP" ||
					candidate == "icmp" || candidate == "ICMP") {
					proto_part = candidate;
					rest = s.substr(single + 1);
				}
			}
		}
		if (!proto_part.empty()) {
			out.has_protocol = true;
			if (proto_part == "tcp" || proto_part == "TCP") out.protocol = 6u;
			else if (proto_part == "udp" || proto_part == "UDP") out.protocol = 17u;
			else if (proto_part == "icmp" || proto_part == "ICMP") out.protocol = 1u;
			else {
				err = "unknown protocol prefix '" + proto_part + "' (expected tcp/udp/icmp)";
				return false;
			}
		}
		std::string host;
		std::string port_str;
		if (!rest.empty() && rest.front() == '[') {
			err = "IPv6 literal addresses are not supported in this UI";
			return false;
		}
		std::size_t last_colon = rest.rfind(':');
		if (last_colon == std::string::npos) {
			host = rest;
		}
		else {
			host = rest.substr(0, last_colon);
			port_str = rest.substr(last_colon + 1);
		}
		host = trim_copy(host);
		port_str = trim_copy(port_str);
		if (!host.empty() && host != "*" && host != "0.0.0.0") {
			if (!parse_ipv4(host, out.addr)) {
				err = "invalid IPv4 host '" + host + "'";
				return false;
			}
			out.has_addr = true;
		}
		if (!port_str.empty() && port_str != "*") {
			if (!parse_uint16(port_str, out.port)) {
				err = "invalid port '" + port_str + "'";
				return false;
			}
			out.has_port = true;
		}
		out.address_family = 2u;
		return true;
	}

	const char* protocol_to_string(std::uint32_t p) {
		switch (p) {
			case 0:  return "ANY";
			case 1:  return "ICMP";
			case 6:  return "TCP";
			case 17: return "UDP";
			default: return "?";
		}
	}

	const char* af_to_string(std::uint32_t af) {
		switch (af) {
			case 2:  return "AF_INET";
			case 23: return "AF_INET6";
			default: return "AF_UNSPEC";
		}
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

	struct wsa_guard_t {
		bool ok = false;
		wsa_guard_t() {
			ok = ensure_test_winsock_ready();
		}
		~wsa_guard_t() = default;
		wsa_guard_t(const wsa_guard_t&) = delete;
		wsa_guard_t& operator=(const wsa_guard_t&) = delete;
	};

	struct tcp_pair_t {
		SOCKET listener = INVALID_SOCKET;
		SOCKET client = INVALID_SOCKET;
		SOCKET accepted = INVALID_SOCKET;
		std::uint16_t listen_port = 0;
		std::uint16_t client_port = 0;
		std::uint8_t client_addr[16] = { 0 };
		std::uint8_t server_addr[16] = { 0 };

		void close_all() {
			if (accepted != INVALID_SOCKET) { shutdown(accepted, SD_BOTH); closesocket(accepted); accepted = INVALID_SOCKET; }
			if (client != INVALID_SOCKET) { shutdown(client, SD_BOTH); closesocket(client); client = INVALID_SOCKET; }
			if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
		}

		~tcp_pair_t() { close_all(); }
	};

	void configure_fixture_socket(SOCKET s) {
		if (s == INVALID_SOCKET) return;
		int buf = 4096;
		setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
		setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf), sizeof(buf));
		int nodelay = 1;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
		LINGER lin{};
		lin.l_onoff = 1;
		lin.l_linger = 0;
		setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lin), sizeof(lin));
	}

	bool loopback_resource_precondition(const std::string& err) {
		return err.find("err=10055") != std::string::npos ||
			err.find("so_error=10055") != std::string::npos ||
			err.find("WSAENOBUFS") != std::string::npos;
	}

	bool bwmn_drive_udp_fixture(std::string& err, std::uint32_t& sent_packets);

	bool establish_local_tcp_pair_once(tcp_pair_t& p, std::string& err) {
		p.close_all();
		p.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (p.listener == INVALID_SOCKET) {
			err = "socket(listener) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		configure_fixture_socket(p.listener);
		BOOL reuse = TRUE;
		setsockopt(p.listener, SOL_SOCKET, SO_REUSEADDR,
			reinterpret_cast<const char*>(&reuse), sizeof(reuse));
		sockaddr_in la{};
		la.sin_family = AF_INET;
		la.sin_port = 0;
		la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(p.listener, reinterpret_cast<const sockaddr*>(&la), sizeof(la)) != 0) {
			err = "bind(listener) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		if (listen(p.listener, 1) != 0) {
			err = "listen(listener) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		sockaddr_in la_actual{};
		int la_len = static_cast<int>(sizeof(la_actual));
		if (getsockname(p.listener, reinterpret_cast<sockaddr*>(&la_actual), &la_len) != 0) {
			err = "getsockname(listener) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		p.listen_port = ntohs(la_actual.sin_port);

		p.client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (p.client == INVALID_SOCKET) {
			err = "socket(client) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		DWORD io_timeout_ms = 5000;
		setsockopt(p.client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
		setsockopt(p.client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&io_timeout_ms), sizeof(io_timeout_ms));
		sockaddr_in ra{};
		ra.sin_family = AF_INET;
		ra.sin_port = htons(p.listen_port);
		ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		int cr = connect(p.client, reinterpret_cast<const sockaddr*>(&ra), sizeof(ra));
		if (cr != 0) {
			err = "connect(client) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		configure_fixture_socket(p.client);

		sockaddr_in laddr{};
		int laddr_len = static_cast<int>(sizeof(laddr));
		if (getsockname(p.client, reinterpret_cast<sockaddr*>(&laddr), &laddr_len) != 0) {
			err = "getsockname(client) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		p.client_port = ntohs(laddr.sin_port);
		p.client_addr[0] = 127;
		p.client_addr[1] = 0;
		p.client_addr[2] = 0;
		p.client_addr[3] = 1;
		p.server_addr[0] = 127;
		p.server_addr[1] = 0;
		p.server_addr[2] = 0;
		p.server_addr[3] = 1;

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(p.listener, &rfds);
		timeval atv;
		atv.tv_sec = 5;
		atv.tv_usec = 0;
		int aret = select(0, &rfds, nullptr, nullptr, &atv);
		if (aret <= 0) {
			err = "select(listener) accept timeout";
			return false;
		}
		sockaddr_in raddr{};
		int raddr_len = static_cast<int>(sizeof(raddr));
		p.accepted = accept(p.listener, reinterpret_cast<sockaddr*>(&raddr), &raddr_len);
		if (p.accepted == INVALID_SOCKET) {
			err = "accept failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		configure_fixture_socket(p.accepted);
		return true;
	}

	bool establish_local_tcp_pair(tcp_pair_t& p, std::string& err, const char* log_code = nullptr) {
		const DWORD start_tick = GetTickCount();
		const int max_attempts = 18;
		const int max_resource_attempts = 12;
		int resource_attempts = 0;
		err.clear();
		for (int attempt = 1; attempt <= max_attempts; ++attempt) {
			std::string attempt_err;
			if (establish_local_tcp_pair_once(p, attempt_err)) {
				if (log_code != nullptr) {
					test_lab_format::testlab_diag_log_step("network-action", log_code, "tcp_pair_attempt",
						"attempt=%d ok=1 elapsed_ms=%lu client_port=%u listen_port=%u",
						attempt,
						static_cast<unsigned long>(GetTickCount() - start_tick),
						p.client_port,
						p.listen_port);
				}
				return true;
			}
			p.close_all();
			err = attempt_err;
			if (log_code != nullptr) {
				test_lab_format::testlab_diag_log_step("network-action", log_code, "tcp_pair_attempt",
					"attempt=%d ok=0 elapsed_ms=%lu err=\"%s\"",
					attempt,
					static_cast<unsigned long>(GetTickCount() - start_tick),
					attempt_err.c_str());
			}
			if (loopback_resource_precondition(attempt_err)) {
				++resource_attempts;
				if (resource_attempts >= max_resource_attempts) {
					if (log_code != nullptr) {
						test_lab_format::testlab_diag_log_step("network-action", log_code, "tcp_pair_resource_fast_fail",
							"attempt=%d resource_attempts=%d elapsed_ms=%lu err=\"%s\"",
							attempt,
							resource_attempts,
							static_cast<unsigned long>(GetTickCount() - start_tick),
							attempt_err.c_str());
					}
					return false;
				}
			}
			else {
				resource_attempts = 0;
			}
			if (attempt < max_attempts) {
				DWORD delay_ms = loopback_resource_precondition(attempt_err)
					? static_cast<DWORD>(40 + attempt * 20)
					: static_cast<DWORD>(100 + attempt * 25);
				Sleep(delay_ms);
			}
		}
		return false;
	}

	struct teardown_probe_t {
		bool observed = false;
		std::uint32_t iterations = 0;
		std::uint32_t successful_sends = 0;
		int client_recv_rc = SOCKET_ERROR;
		int client_recv_err = 0;
		int accepted_recv_rc = SOCKET_ERROR;
		int accepted_recv_err = 0;
		int client_send_rc = SOCKET_ERROR;
		int client_send_err = 0;
		int client_so_error = 0;
		int accepted_so_error = 0;
	};

	bool socket_has_so_error(SOCKET s, int& out_err) {
		out_err = 0;
		int value = 0;
		int len = static_cast<int>(sizeof(value));
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&value), &len) == 0) {
			out_err = value;
			return value != 0;
		}
		out_err = WSAGetLastError();
		return out_err != 0;
	}

	bool recv_observes_teardown(SOCKET s, int& out_rc, int& out_err) {
		out_err = 0;
		char buf[16];
		out_rc = recv(s, buf, static_cast<int>(sizeof(buf)), 0);
		if (out_rc == 0)
			return true;
		if (out_rc == SOCKET_ERROR) {
			out_err = WSAGetLastError();
			return out_err != WSAEWOULDBLOCK && out_err != WSAEINPROGRESS;
		}
		return false;
	}

	bool wait_for_tcp_teardown(tcp_pair_t& pair, DWORD budget_ms, teardown_probe_t& probe) {
		u_long nonblocking = 1;
		(void)ioctlsocket(pair.client, FIONBIO, &nonblocking);
		(void)ioctlsocket(pair.accepted, FIONBIO, &nonblocking);
		const DWORD start = GetTickCount();
		bool sent_probe = false;
		for (;;) {
			++probe.iterations;
			if (socket_has_so_error(pair.client, probe.client_so_error) ||
				socket_has_so_error(pair.accepted, probe.accepted_so_error)) {
				probe.observed = true;
				return true;
			}
			if (recv_observes_teardown(pair.client, probe.client_recv_rc, probe.client_recv_err) ||
				recv_observes_teardown(pair.accepted, probe.accepted_recv_rc, probe.accepted_recv_err)) {
				probe.observed = true;
				return true;
			}
			if (!sent_probe && GetTickCount() - start >= 75u) {
				const char poke = 'x';
				probe.client_send_rc = send(pair.client, &poke, 1, 0);
				if (probe.client_send_rc == SOCKET_ERROR) {
					probe.client_send_err = WSAGetLastError();
					if (probe.client_send_err != WSAEWOULDBLOCK && probe.client_send_err != WSAEINPROGRESS) {
						probe.observed = true;
						return true;
					}
				}
				else if (probe.client_send_rc > 0) {
					++probe.successful_sends;
				}
				sent_probe = true;
			}
			if (GetTickCount() - start >= budget_ms)
				break;
			Sleep(35);
		}
		probe.observed = false;
		return false;
	}

	bool drive_pcap_capture_fixture(std::string& err, std::uint32_t& tcp_bytes, std::uint32_t& udp_packets) {
		tcp_bytes = 0u;
		udp_packets = 0u;
		tcp_pair_t pair;
		std::string pair_err;
		if (!establish_local_tcp_pair(pair, pair_err, "PCEX")) {
			err = "tcp pair failed: " + pair_err;
			return false;
		}
		const char* request = "GET /aida-pcex-fixture HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
		int sent = send(pair.client, request, static_cast<int>(std::strlen(request)), 0);
		if (sent <= 0) {
			err = "tcp client send failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		tcp_bytes += static_cast<std::uint32_t>(sent);
		char buf[256];
		int got = recv(pair.accepted, buf, static_cast<int>(sizeof(buf)), 0);
		if (got > 0)
			tcp_bytes += static_cast<std::uint32_t>(got);
		const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nAIDA-PCEX-OK-000";
		sent = send(pair.accepted, response, static_cast<int>(std::strlen(response)), 0);
		if (sent <= 0) {
			err = "tcp accepted send failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		tcp_bytes += static_cast<std::uint32_t>(sent);
		got = recv(pair.client, buf, static_cast<int>(sizeof(buf)), 0);
		if (got > 0)
			tcp_bytes += static_cast<std::uint32_t>(got);
		std::string udp_err;
		if (!bwmn_drive_udp_fixture(udp_err, udp_packets)) {
			test_lab_format::testlab_diag_log_step("network-action", "PCEX", "udp_seed",
				"ok=0 err=\"%s\"", udp_err.c_str());
		}
		return true;
	}

	bool pred_send_rule(const char* step,
		voyager::detail::traffic_redirect_rule& req,
		std::uint32_t& bytes_returned)
	{
		bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PRED(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		test_lab_format::testlab_diag_log_step("network-action", "PRED", step,
			"ok=%d bytes_returned=%u op=%u rule_id=%u proto=%u match_port=%u redirect_port=%u af=%u active=%u match_count=%u exclude_pid=%u",
			ok ? 1 : 0,
			bytes_returned,
			req.operation,
			req.rule_id,
			req.protocol,
			req.match_port,
			req.redirect_port,
			req.address_family,
			req.active,
			req.match_count,
			req.exclude_pid);
		return ok;
	}

	bool pred_send_list(const char* step,
		voyager::detail::traffic_redirect_list& req,
		std::uint32_t& bytes_returned)
	{
		req.operation = 2u;
		req.rule_count = 0u;
		bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PRED(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		test_lab_format::testlab_diag_log_step("network-action", "PRED", step,
			"ok=%d bytes_returned=%u rule_count=%u max_rules=%u",
			ok ? 1 : 0,
			bytes_returned,
			req.rule_count,
			voyager::detail::REDIR_MAX_RULES);
		return ok;
	}

	bool dnss_send_rule(const char* step,
		voyager::detail::dns_spoof_rule& req,
		std::uint32_t& bytes_returned)
	{
		bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DNSS(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		char domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN + 1];
		std::memcpy(domain_safe, req.domain, voyager::detail::DNS_SPOOF_MAX_DOMAIN);
		domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN] = '\0';
		test_lab_format::testlab_diag_log_step("network-action", "DNSS", step,
			"ok=%d bytes_returned=%u op=%u rule_id=%u domain=\"%s\" af=%u active=%u ttl=%u match_count=%u",
			ok ? 1 : 0,
			bytes_returned,
			req.operation,
			req.rule_id,
			domain_safe,
			req.address_family,
			req.active,
			req.ttl,
			req.match_count);
		return ok;
	}

	bool dnss_send_list(const char* step,
		voyager::detail::dns_spoof_list& req,
		std::uint32_t& bytes_returned)
	{
		req.operation = 2u;
		req.rule_count = 0u;
		bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DNSS(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		test_lab_format::testlab_diag_log_step("network-action", "DNSS", step,
			"ok=%d bytes_returned=%u rule_count=%u max_rules=%u",
			ok ? 1 : 0,
			bytes_returned,
			req.rule_count,
			voyager::detail::DNS_SPOOF_MAX_RULES);
		return ok;
	}

	bool bwmn_send(const char* step,
		voyager::detail::bw_monitor_request& req,
		std::uint32_t& bytes_returned)
	{
		bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::BWMN(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		test_lab_format::testlab_diag_log_step("network-action", "BWMN", step,
			"ok=%d bytes_returned=%u op=%u active=%u filter_pid=%u total_sent=%llu total_recv=%llu packets_sent=%llu packets_recv=%llu process_count=%u",
			ok ? 1 : 0,
			bytes_returned,
			req.operation,
			req.monitoring_active,
			req.filter_pid,
			static_cast<unsigned long long>(req.total_bytes_sent),
			static_cast<unsigned long long>(req.total_bytes_recv),
			static_cast<unsigned long long>(req.total_packets_sent),
			static_cast<unsigned long long>(req.total_packets_recv),
			req.process_count);
		return ok;
	}

	bool bw_totals_nonzero(const voyager::detail::bw_monitor_request& req) {
		return req.total_bytes_sent != 0u || req.total_bytes_recv != 0u ||
			req.total_packets_sent != 0u || req.total_packets_recv != 0u;
	}

	bool bw_process_entry_nonzero(const voyager::detail::bw_process_entry& p) {
		return p.bytes_sent != 0u || p.bytes_recv != 0u ||
			p.packets_sent != 0u || p.packets_recv != 0u;
	}

	std::uint32_t count_matching_bw_processes(const voyager::detail::bw_monitor_request& req,
		std::uint32_t expected_pid,
		std::uint32_t& nonzero_entries)
	{
		nonzero_entries = 0u;
		std::uint32_t matches = 0u;
		std::uint32_t cap = req.process_count;
		if (cap > voyager::detail::BW_MAX_PROCESSES)
			cap = voyager::detail::BW_MAX_PROCESSES;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& p = req.processes[i];
			if (bw_process_entry_nonzero(p))
				++nonzero_entries;
			if (expected_pid == 0u || p.pid == expected_pid)
				++matches;
		}
		return matches;
	}

	struct bw_process_evidence_t {
		std::uint32_t matching_entries = 0u;
		std::uint32_t nonzero_matching_entries = 0u;
		std::uint64_t bytes_sent = 0u;
		std::uint64_t bytes_recv = 0u;
		std::uint64_t packets_sent = 0u;
		std::uint64_t packets_recv = 0u;
		std::uint64_t first_activity_time = 0u;
		std::uint64_t last_activity_time = 0u;
	};

	bw_process_evidence_t collect_bw_process_evidence(const voyager::detail::bw_monitor_request& req,
		std::uint32_t expected_pid)
	{
		bw_process_evidence_t evidence{};
		std::uint32_t cap = req.process_count;
		if (cap > voyager::detail::BW_MAX_PROCESSES)
			cap = voyager::detail::BW_MAX_PROCESSES;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& p = req.processes[i];
			if (expected_pid != 0u && p.pid != expected_pid)
				continue;
			++evidence.matching_entries;
			evidence.bytes_sent += p.bytes_sent;
			evidence.bytes_recv += p.bytes_recv;
			evidence.packets_sent += p.packets_sent;
			evidence.packets_recv += p.packets_recv;
			if (bw_process_entry_nonzero(p))
				++evidence.nonzero_matching_entries;
			if (p.last_activity_time != 0u) {
				if (evidence.first_activity_time == 0u || p.last_activity_time < evidence.first_activity_time)
					evidence.first_activity_time = p.last_activity_time;
				if (p.last_activity_time > evidence.last_activity_time)
					evidence.last_activity_time = p.last_activity_time;
			}
		}
		return evidence;
	}

	std::uint64_t current_system_time_100ns() {
		FILETIME ft{};
		GetSystemTimeAsFileTime(&ft);
		ULARGE_INTEGER value{};
		value.LowPart = ft.dwLowDateTime;
		value.HighPart = ft.dwHighDateTime;
		return value.QuadPart;
	}

	void push_bw_rate_evidence(test_lab::result_t& r,
		const voyager::detail::bw_monitor_request& aggregate,
		const bw_process_evidence_t& process_evidence,
		std::uint64_t rate_window_ms,
		bool fixture_ok,
		std::uint32_t fixture_packets)
	{
		const bool cumulative_activity =
			bw_totals_nonzero(aggregate) ||
			process_evidence.bytes_sent != 0u ||
			process_evidence.bytes_recv != 0u ||
			process_evidence.packets_sent != 0u ||
			process_evidence.packets_recv != 0u ||
			(fixture_ok && fixture_packets != 0u);
		const bool rate_sample_valid = rate_window_ms >= 1000u;
		const bool rate_nonzero = aggregate.bytes_per_second_out != 0u || aggregate.bytes_per_second_in != 0u;
		const std::uint64_t now_100ns = current_system_time_100ns();
		const std::uint64_t last_activity_age_ms =
			(process_evidence.last_activity_time != 0u && now_100ns >= process_evidence.last_activity_time)
			? ((now_100ns - process_evidence.last_activity_time) / 10000u)
			: 0u;
		push_u64(r, "Rate window elapsed ms", rate_window_ms);
		push_hex64(r, "Rate numerator bytes sent", aggregate.total_bytes_sent);
		push_hex64(r, "Rate numerator bytes recv", aggregate.total_bytes_recv);
		push_u64(r, "Rate divisor ms", rate_window_ms);
		push_u32(r, "Rate sample valid", rate_sample_valid ? 1u : 0u);
		push_text(r, "Rate sample invalid reason", rate_sample_valid ? "none" : "subsecond_monitoring_window");
		push_u32(r, "Rate throughput proof", (rate_sample_valid && rate_nonzero) ? 1u : 0u);
		push_u32(r, "Cumulative counter proof", cumulative_activity ? 1u : 0u);
		push_hex64(r, "First process activity time", process_evidence.first_activity_time);
		push_hex64(r, "Last process activity time", process_evidence.last_activity_time);
		push_u64(r, "Last activity age ms", last_activity_age_ms);
		push_hex64(r, "Matching process bytes sent", process_evidence.bytes_sent);
		push_hex64(r, "Matching process bytes recv", process_evidence.bytes_recv);
		push_hex64(r, "Matching process packets sent", process_evidence.packets_sent);
		push_hex64(r, "Matching process packets recv", process_evidence.packets_recv);
		push_u32(r, "Nonzero matching process entries", process_evidence.nonzero_matching_entries);
		const bool aggregate_receive_without_process_receive = aggregate.total_bytes_recv != 0u && process_evidence.bytes_recv == 0u;
		push_u32(r, "Aggregate receive without process receive", aggregate_receive_without_process_receive ? 1u : 0u);
		push_text(r, "Per-process receive attribution",
			aggregate_receive_without_process_receive ? "aggregate_receive_without_matching_process_receive_observed" : "matching_process_receive_consistent_or_no_aggregate_receive");
	}

	void append_bw_process_entries(test_lab::result_t& r, const voyager::detail::bw_monitor_request& req) {
		std::uint32_t cap = req.process_count;
		if (cap > voyager::detail::BW_MAX_PROCESSES)
			cap = voyager::detail::BW_MAX_PROCESSES;
		push_u32(r, "Process count", cap);
		char label[32];
		char value[160];
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& p = req.processes[i];
			std::snprintf(label, sizeof(label), "Process #%u", i);
			std::snprintf(value, sizeof(value),
				"pid=%u sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu last_activity=0x%016llX",
				p.pid,
				static_cast<unsigned long long>(p.bytes_sent),
				static_cast<unsigned long long>(p.bytes_recv),
				static_cast<unsigned long long>(p.packets_sent),
				static_cast<unsigned long long>(p.packets_recv),
				static_cast<unsigned long long>(p.last_activity_time));
			r.parsed.push_back({ std::string(label), std::string(value) });
		}
	}

	bool bwmn_drive_udp_fixture(std::string& err, std::uint32_t& sent_packets) {
		sent_packets = 0u;
		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET) {
			err = "socket(udp) failed err=" + std::to_string(WSAGetLastError());
			return false;
		}
		DWORD timeout = 250;
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(53535);
		dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		char payload[160];
		std::memset(payload, 'B', sizeof(payload));
		bool any = false;
		int last_err = 0;
		for (int i = 0; i < 24; ++i) {
			int rc = sendto(s,
				payload,
				static_cast<int>(sizeof(payload)),
				0,
				reinterpret_cast<const sockaddr*>(&dst),
				sizeof(dst));
			if (rc == SOCKET_ERROR) {
				last_err = WSAGetLastError();
			}
			else {
				any = true;
				++sent_packets;
			}
		}
		closesocket(s);
		if (!any) {
			err = "sendto(udp) failed err=" + std::to_string(last_err);
			return false;
		}
		return true;
	}

	void render_inputs_pred(test_lab::state_t& s) {
		const char* ops[] = { "Add (op=0)", "List (op=1 UI)", "Remove (op=2 UI)" };
		int sel = static_cast<int>(s.u32_a);
		if (sel < 0 || sel > 2) sel = 0;
		if (ImGui::Combo("Operation", &sel, ops, IM_ARRAYSIZE(ops))) {
			s.u32_a = static_cast<std::uint32_t>(sel);
		}
		render_text_field("Source spec (tcp://1.2.3.4:80 or udp:443 or 1.2.3.4:0)", s.text_a, 256);
		if (sel == 0) {
			render_text_field("Destination spec (tcp://10.0.0.1:8080)", s.text_b, 256);
		}
		else if (sel == 2) {
			ImGui::TextDisabled("Remove: enter the numeric rule_id in Destination spec.");
			render_text_field("Rule ID (decimal)", s.text_b, 32);
		}
		else {
			ImGui::TextDisabled("List: source/destination fields are ignored.");
		}
	}

	void run_pred(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		std::uint32_t ui_op = s.u32_a;
		std::uint32_t bytes_returned = 0;
		if (ui_op == 3u) {
			voyager::detail::traffic_redirect_rule add{};
			add.operation = 0u;
			add.protocol = 6u;
			add.match_port = 65000u;
			add.redirect_port = 65001u;
			add.address_family = 2u;
			add.match_addr[0] = 127u;
			add.match_addr[3] = 1u;
			add.redirect_addr[0] = 127u;
			add.redirect_addr[3] = 1u;
			add.exclude_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			if (!pred_send_rule("lifecycle_add", add, bytes_returned)) {
				r.bytes_returned = bytes_returned;
				r.raw.resize(sizeof(add));
				std::memcpy(r.raw.data(), &add, sizeof(add));
				fail_result(r, "PRED lifecycle add send_ioctl_raw returned false");
				return;
			}
			voyager::detail::traffic_redirect_list list{};
			if (!pred_send_list("lifecycle_list_after_add", list, bytes_returned)) {
				r.bytes_returned = bytes_returned;
				r.raw.resize(sizeof(list));
				std::memcpy(r.raw.data(), &list, sizeof(list));
				fail_result(r, "PRED lifecycle list send_ioctl_raw returned false");
				return;
			}
			bool found = false;
			for (std::uint32_t i = 0; i < list.rule_count && i < voyager::detail::REDIR_MAX_RULES; ++i) {
				const auto& rule = list.rules[i];
				if (rule.rule_id == add.rule_id &&
					rule.protocol == add.protocol &&
					rule.match_port == add.match_port &&
					rule.redirect_port == add.redirect_port &&
					rule.active == 1u) {
					found = true;
					break;
				}
			}
			voyager::detail::traffic_redirect_rule remove{};
			remove.operation = 1u;
			remove.rule_id = add.rule_id;
			remove.address_family = 2u;
			const bool removed = pred_send_rule("lifecycle_remove", remove, bytes_returned);
			r.bytes_returned = bytes_returned;
			r.raw.resize(sizeof(list));
			std::memcpy(r.raw.data(), &list, sizeof(list));
			push_text(r, "Operation", "Lifecycle add/list/remove");
			push_u32(r, "Added Rule ID", add.rule_id);
			push_u32(r, "List Rule Count", list.rule_count);
			push_u32(r, "Lifecycle rule found", found ? 1u : 0u);
			push_u32(r, "Remove IOCTL ok", removed ? 1u : 0u);
			push_text(r, "Match addr", format_addr(add.match_addr, add.address_family));
			push_text(r, "Redirect addr", format_addr(add.redirect_addr, add.address_family));
			if (add.rule_id == 0u) {
				fail_result(r, "PRED lifecycle add did not return a rule id");
				return;
			}
			if (!found) {
				fail_result(r, "PRED lifecycle list did not return the rule that was just added");
				return;
			}
			if (!removed) {
				fail_result(r, "PRED lifecycle remove send_ioctl_raw returned false");
				return;
			}
			r.ok = true;
			return;
		}
		if (ui_op == 1u) {
			voyager::detail::traffic_redirect_list req{};
			bool ok = pred_send_list("list_result", req, bytes_returned);
			r.bytes_returned = bytes_returned;
			r.raw.resize(sizeof(req));
			std::memcpy(r.raw.data(), &req, sizeof(req));
			if (!ok) {
				r.error = "send_ioctl_raw returned false (list)";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			push_text(r, "Operation", "List");
			push_u32(r, "Rule Count", req.rule_count);
			std::uint32_t cap = req.rule_count;
			if (cap > voyager::detail::REDIR_MAX_RULES) {
				cap = voyager::detail::REDIR_MAX_RULES;
			}
			char label[32];
			char value[160];
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& rule = req.rules[i];
				std::snprintf(label, sizeof(label), "Rule #%u", i);
				std::string match_addr = format_addr(rule.match_addr, rule.address_family);
				std::string redir_addr = format_addr(rule.redirect_addr, rule.address_family);
				std::snprintf(value, sizeof(value),
					"id=%u proto=%s af=%s match=%s:%u -> %s:%u hits=%u active=%u",
					rule.rule_id,
					protocol_to_string(rule.protocol),
					af_to_string(rule.address_family),
					match_addr.c_str(), rule.match_port,
					redir_addr.c_str(), rule.redirect_port,
					rule.match_count, rule.active);
				r.parsed.push_back({ std::string(label), std::string(value) });
			}
			if (req.rule_count == 0u) {
				fail_result(r, "PRED list returned zero rules after the traffic redirect fixture/action expected a populated rule set");
				return;
			}
			r.ok = true;
			return;
		}
		voyager::detail::traffic_redirect_rule req{};
		if (ui_op == 0u) {
			endpoint_spec_t src{};
			endpoint_spec_t dst{};
			std::string err;
			if (!parse_endpoint_spec(s.text_a, src, err)) {
				r.error = "source spec parse error: " + err;
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			if (!parse_endpoint_spec(s.text_b, dst, err)) {
				r.error = "destination spec parse error: " + err;
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			req.operation = 0u;
			req.rule_id = 0u;
			req.protocol = src.has_protocol ? src.protocol
				: (dst.has_protocol ? dst.protocol : 6u);
			req.match_port = src.has_port ? src.port : 0u;
			std::memcpy(req.match_addr, src.addr, 16);
			req.redirect_port = dst.has_port ? dst.port : 0u;
			std::memcpy(req.redirect_addr, dst.addr, 16);
			req.address_family = (src.address_family != 0u) ? src.address_family : 2u;
			req.match_count = 0u;
			req.active = 0u;
			req.exclude_pid = 0u;
		}
		else {
			std::string trimmed = trim_copy(s.text_b);
			if (trimmed.empty()) {
				r.error = "rule_id is required for Remove";
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			unsigned long parsed = 0;
			for (char c : trimmed) {
				if (c < '0' || c > '9') {
					r.error = "rule_id must be decimal";
					r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
					r.ok = false;
					return;
				}
				parsed = parsed * 10ul + static_cast<unsigned long>(c - '0');
			}
			req.operation = 1u;
			req.rule_id = static_cast<std::uint32_t>(parsed);
			req.address_family = 2u;
		}
		bool ok = device->send_ioctl_raw(ioctl_codes::PRED(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_text(r, "Operation", (ui_op == 0u) ? "Add" : "Remove");
		push_u32(r, "Rule ID", req.rule_id);
		push_u32(r, "Protocol", req.protocol);
		push_u32(r, "Match port", req.match_port);
		push_u32(r, "Redirect port", req.redirect_port);
		push_text(r, "Match addr", format_addr(req.match_addr, req.address_family));
		push_text(r, "Redirect addr", format_addr(req.redirect_addr, req.address_family));
		push_u32(r, "Address family", req.address_family);
		push_u32(r, "Active", req.active);
		r.ok = true;
	}

	void render_inputs_strm(test_lab::state_t&) {
		ImGui::TextDisabled("Self-bootstraps a localhost TCP pair, drives the full stream-reassembly "
			"lifecycle (START op=0 -> traffic -> GET op=2 -> STOP op=1) and verifies each step. "
			"No user input required.");
	}

	bool strm_send_ioctl(const char* step,
		voyager::detail::stream_reassemble_request& req,
		test_lab::result_t& r)
	{
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::STRM(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		r.bytes_returned = bytes_returned;
		test_lab_format::testlab_diag_log_step("network-action", "STRM", step,
			"ok=%d bytes_returned=%u op=%u src_port=%u dst_port=%u stream_size=%u total_packets=%u truncated=%u",
			ok ? 1 : 0, bytes_returned,
			req.operation, req.src_port, req.dst_port,
			req.stream_size, req.total_packets, req.truncated);
		return ok;
	}

	void run_strm(test_lab::state_t&, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;

		wsa_guard_t wsa;
		if (!wsa.ok) {
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			test_lab_format::testlab_diag_log_step("network-action", "STRM", "wsa_init",
				"failed err=%lu", static_cast<unsigned long>(GetLastError()));
			return;
		}

		tcp_pair_t pair;
		std::string pair_err;
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "tcp_pair_open",
			"establishing localhost TCP pair");
		if (!establish_local_tcp_pair(pair, pair_err, "STRM")) {
			test_lab_format::testlab_diag_log_step("network-action", "STRM", "tcp_pair_open",
				"failed err=\"%s\" (WFP callout may be intercepting loopback TCP)", pair_err.c_str());
			r.ntstatus = static_cast<std::int32_t>(loopback_resource_precondition(pair_err) ? 0xC000009Au : 0xC0000001u);
			r.ok = false;
			r.skipped = false;
			r.error = "loopback TCP unavailable (WFP callout intercept): " + pair_err;
			return;
		}
		std::uint32_t pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "tcp_pair_open",
			"ok client_port=%u listen_port=%u pid=%u",
			pair.client_port, pair.listen_port, pid);

		voyager::detail::stream_reassemble_request req{};
		req.operation = 0u;
		req.src_port = pair.client_port;
		req.dst_port = pair.listen_port;
		req.pid = pid;
		std::memcpy(req.src_addr, pair.client_addr, 16);
		std::memcpy(req.dst_addr, pair.server_addr, 16);
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "start",
			"registering slot sport=%u dport=%u pid=%u",
			req.src_port, req.dst_port, req.pid);
		if (!strm_send_ioctl("start_ioctl", req, r)) {
			r.error = "STRM start send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_u32(r, "Step1 START Src port", req.src_port);
		push_u32(r, "Step1 START Dst port", req.dst_port);
		push_u32(r, "Step1 START PID", req.pid);

		auto stop_stream_slot = [&]() {
			voyager::detail::stream_reassemble_request cleanup_req{};
			cleanup_req.operation = 1u;
			cleanup_req.src_port = pair.client_port;
			cleanup_req.dst_port = pair.listen_port;
			cleanup_req.pid = 0u;
			(void)strm_send_ioctl("stop_ioctl_cleanup", cleanup_req, r);
		};

		const char* probe_payload = "AIDA-STRM-PROBE-PAYLOAD-0123456789";
		int probe_len = static_cast<int>(std::strlen(probe_payload));
		int sent = send(pair.client, probe_payload, probe_len, 0);
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "send_traffic",
			"send()=%d errno=%lu", sent,
			(sent < 0) ? static_cast<unsigned long>(WSAGetLastError()) : 0ul);
		if (sent <= 0) {
			stop_stream_slot();
			r.error = "send() to accepted socket failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char drain[256];
		int drained = recv(pair.accepted, drain, sizeof(drain), 0);
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "drain_accepted",
			"recv()=%d", drained);

		std::uint32_t observed_size = 0;
		std::uint32_t observed_packets = 0;
		std::uint32_t observed_truncated = 0;
		bool got_assembled = false;
		const int kMaxIters = 10;
		const DWORD kSliceMs = 250;
		for (int iter = 0; iter < kMaxIters; ++iter) {
			voyager::detail::stream_reassemble_request greq{};
			greq.operation = 2u;
			greq.src_port = pair.client_port;
			greq.dst_port = pair.listen_port;
			greq.pid = 0u;
			if (!strm_send_ioctl("get_ioctl_poll", greq, r)) {
				test_lab_format::testlab_diag_log_step("network-action", "STRM", "get_poll",
					"send_ioctl_raw false iter=%d", iter);
			}
			observed_size = greq.stream_size;
			observed_packets = greq.total_packets;
			observed_truncated = greq.truncated;
			test_lab_format::testlab_diag_log_step("network-action", "STRM", "get_poll",
				"iter=%d stream_size=%u total_packets=%u truncated=%u",
				iter, observed_size, observed_packets, observed_truncated);
			if (observed_size > 0u || observed_packets > 0u) {
				got_assembled = true;
				std::uint32_t copy_len = observed_size;
				if (copy_len > voyager::detail::STREAM_MAX_SIZE) {
					copy_len = voyager::detail::STREAM_MAX_SIZE;
				}
				if (copy_len > 0u) {
					r.raw.assign(greq.stream_data, greq.stream_data + copy_len);
				}
				else {
					r.raw.clear();
				}
				break;
			}
			Sleep(kSliceMs);
		}

		voyager::detail::stream_reassemble_request sreq{};
		sreq.operation = 1u;
		sreq.src_port = pair.client_port;
		sreq.dst_port = pair.listen_port;
		sreq.pid = 0u;
		bool stop_ok = strm_send_ioctl("stop_ioctl", sreq, r);
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "stop",
			"ok=%d", stop_ok ? 1 : 0);

		push_u32(r, "Step2 SEND bytes", static_cast<std::uint32_t>(sent));
		push_u32(r, "Step3 GET stream_size", observed_size);
		push_u32(r, "Step3 GET total_packets", observed_packets);
		push_u32(r, "Step3 GET truncated", observed_truncated);
		push_u32(r, "Step3 GET assembled", got_assembled ? 1u : 0u);
		push_u32(r, "Step4 STOP ok", stop_ok ? 1u : 0u);
		push_text(r, "Driver path",
			got_assembled
				? std::string("lifecycle_ok (poll budget=2500ms)")
				: std::string("lifecycle_no_packets (WFP callout did not feed slot within 2500ms)"));

		if (!stop_ok) {
			r.error = "STRM stop send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		if (!got_assembled) {
			r.error = "STRM did not observe reassembled stream data within poll budget";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		r.ok = true;
	}

	void render_inputs_ckil(test_lab::state_t&) {
		ImGui::TextDisabled("Self-bootstraps a localhost TCP pair (127.0.0.1 listener+client), then asks "
			"the driver to kill the client side by 5-tuple. Validates kernel-side teardown via the "
			"driver-populated status code and a post-kill send() probe (expected to fail). "
			"No user input required.");
	}

	void run_ckil(test_lab::state_t&, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;

		wsa_guard_t wsa;
		if (!wsa.ok) {
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			test_lab_format::testlab_diag_log_step("network-action", "CKIL", "wsa_init",
				"failed err=%lu", static_cast<unsigned long>(GetLastError()));
			return;
		}

		tcp_pair_t pair;
		std::string pair_err;
		test_lab_format::testlab_diag_log_step("network-action", "CKIL", "tcp_pair_open",
			"establishing localhost TCP pair");
		if (!establish_local_tcp_pair(pair, pair_err, "CKIL")) {
			test_lab_format::testlab_diag_log_step("network-action", "CKIL", "tcp_pair_open",
				"failed err=\"%s\" (WFP callout may be intercepting loopback TCP)", pair_err.c_str());
			r.ntstatus = static_cast<std::int32_t>(loopback_resource_precondition(pair_err) ? 0xC000009Au : 0xC0000001u);
			r.ok = false;
			r.skipped = false;
			r.error = "loopback TCP unavailable (WFP callout intercept): " + pair_err;
			return;
		}
		std::uint32_t pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		test_lab_format::testlab_diag_log_step("network-action", "CKIL", "tcp_pair_open",
			"ok client_port=%u listen_port=%u pid=%u",
			pair.client_port, pair.listen_port, pid);

		voyager::detail::conn_kill_request req{};
		req.protocol = 6u;
		req.address_family = 2u;
		req.src_port = pair.client_port;
		req.dst_port = pair.listen_port;
		std::memcpy(req.src_addr, pair.client_addr, 16);
		std::memcpy(req.dst_addr, pair.server_addr, 16);
		req.pid = pid;
		req.status = 0u;

		test_lab_format::testlab_diag_log_step("network-action", "CKIL", "kill_call",
			"invoking proto=6 af=2 sport=%u dport=%u src=127.0.0.1 dst=127.0.0.1 pid=%u",
			req.src_port, req.dst_port, req.pid);
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::CKIL(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		test_lab_format::testlab_diag_log_step("network-action", "CKIL", "kill_call",
			"ok=%d bytes_returned=%u driver_status=%u",
			ok ? 1 : 0, bytes_returned, req.status);

		teardown_probe_t teardown_probe{};
		if (ok) {
			wait_for_tcp_teardown(pair, 2000, teardown_probe);
			test_lab_format::testlab_diag_log_step("network-action", "CKIL", "teardown_probe",
				"observed=%d iterations=%u successful_sends=%u client_recv_rc=%d client_recv_err=%d accepted_recv_rc=%d accepted_recv_err=%d client_send_rc=%d client_send_err=%d client_so_error=%d accepted_so_error=%d",
				teardown_probe.observed ? 1 : 0,
				teardown_probe.iterations,
				teardown_probe.successful_sends,
				teardown_probe.client_recv_rc,
				teardown_probe.client_recv_err,
				teardown_probe.accepted_recv_rc,
				teardown_probe.accepted_recv_err,
				teardown_probe.client_send_rc,
				teardown_probe.client_send_err,
				teardown_probe.client_so_error,
				teardown_probe.accepted_so_error);
		}

		push_u32(r, "Step1 Protocol", req.protocol);
		push_u32(r, "Step1 Address family", req.address_family);
		push_u32(r, "Step1 Src port", req.src_port);
		push_u32(r, "Step1 Dst port", req.dst_port);
		push_text(r, "Step1 Src addr", format_addr(req.src_addr, req.address_family));
		push_text(r, "Step1 Dst addr", format_addr(req.dst_addr, req.address_family));
		push_u32(r, "Step1 PID filter", req.pid);
		push_u32(r, "Step2 IOCTL ok", ok ? 1u : 0u);
		push_u32(r, "Step2 Driver status (0=success)", req.status);
		push_u32(r, "Step3 Teardown observed", teardown_probe.observed ? 1u : 0u);
		push_u32(r, "Step3 Teardown iterations", teardown_probe.iterations);
		push_u32(r, "Step3 Probe sends accepted", teardown_probe.successful_sends);
		push_u32(r, "Step3 Client recv WSA err", static_cast<std::uint32_t>(teardown_probe.client_recv_err));
		push_u32(r, "Step3 Accepted recv WSA err", static_cast<std::uint32_t>(teardown_probe.accepted_recv_err));

		if (!ok) {
			r.error = "CKIL send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		if (req.status != 0u) {
			char buf[96];
			std::snprintf(buf, sizeof(buf),
				"CKIL driver reported status=%u (non-zero means kill failed)", req.status);
			r.error = std::string(buf);
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		if (!teardown_probe.observed) {
			r.error = "CKIL did not produce observable TCP teardown within the 2000ms probe window";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		r.ok = true;
	}

	void render_inputs_dnss(test_lab::state_t& s) {
		const char* ops[] = { "Add (op=0)", "List (op=2)", "Remove (op=1)" };
		int sel = static_cast<int>(s.u32_a);
		if (sel < 0 || sel > 2) sel = 0;
		if (ImGui::Combo("Operation", &sel, ops, IM_ARRAYSIZE(ops))) {
			s.u32_a = static_cast<std::uint32_t>(sel);
		}
		render_text_field("Domain (e.g. example.com)", s.text_a, voyager::detail::DNS_SPOOF_MAX_DOMAIN);
		if (sel == 0) {
			render_text_field("Spoof IP (1.2.3.4)", s.text_b, 64);
			ImGui::TextDisabled("Adds a rule that resolves the domain to the spoof IP (AF_INET, TTL=300).");
		}
		else if (sel == 2) {
			ImGui::TextDisabled("Remove: enter the numeric rule_id in the Spoof IP field.");
			render_text_field("Rule ID (decimal)", s.text_b, 32);
		}
		else {
			ImGui::TextDisabled("List: domain / IP fields are ignored.");
		}
	}

	void run_dnss(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		std::uint32_t ui_op = s.u32_a;
		std::uint32_t bytes_returned = 0;
		if (ui_op == 3u) {
			const char* domain = "aida-test.local";
			voyager::detail::dns_spoof_rule add{};
			add.operation = 0u;
			std::memcpy(add.domain, domain, std::strlen(domain));
			add.spoof_addr[0] = 127u;
			add.spoof_addr[3] = 2u;
			add.address_family = 2u;
			add.ttl = 300u;
			if (!dnss_send_rule("lifecycle_add", add, bytes_returned)) {
				r.bytes_returned = bytes_returned;
				r.raw.resize(sizeof(add));
				std::memcpy(r.raw.data(), &add, sizeof(add));
				fail_result(r, "DNSS lifecycle add send_ioctl_raw returned false");
				return;
			}
			voyager::detail::dns_spoof_list list{};
			if (!dnss_send_list("lifecycle_list_after_add", list, bytes_returned)) {
				r.bytes_returned = bytes_returned;
				r.raw.resize(sizeof(list));
				std::memcpy(r.raw.data(), &list, sizeof(list));
				fail_result(r, "DNSS lifecycle list send_ioctl_raw returned false");
				return;
			}
			bool found = false;
			for (std::uint32_t i = 0; i < list.rule_count && i < voyager::detail::DNS_SPOOF_MAX_RULES; ++i) {
				const auto& rule = list.rules[i];
				char domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN + 1];
				std::memcpy(domain_safe, rule.domain, voyager::detail::DNS_SPOOF_MAX_DOMAIN);
				domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN] = '\0';
				if (rule.rule_id == add.rule_id &&
					std::strcmp(domain_safe, domain) == 0 &&
					rule.address_family == add.address_family &&
					rule.active == 1u) {
					found = true;
					break;
				}
			}
			voyager::detail::dns_spoof_rule remove{};
			remove.operation = 1u;
			remove.rule_id = add.rule_id;
			remove.address_family = 2u;
			const bool removed = dnss_send_rule("lifecycle_remove", remove, bytes_returned);
			r.bytes_returned = bytes_returned;
			r.raw.resize(sizeof(list));
			std::memcpy(r.raw.data(), &list, sizeof(list));
			push_text(r, "Operation", "Lifecycle add/list/remove");
			push_u32(r, "Added Rule ID", add.rule_id);
			push_text(r, "Domain", domain);
			push_text(r, "Spoof addr", format_addr(add.spoof_addr, add.address_family));
			push_u32(r, "List Rule Count", list.rule_count);
			push_u32(r, "Lifecycle rule found", found ? 1u : 0u);
			push_u32(r, "Remove IOCTL ok", removed ? 1u : 0u);
			if (add.rule_id == 0u) {
				fail_result(r, "DNSS lifecycle add did not return a rule id");
				return;
			}
			if (!found) {
				fail_result(r, "DNSS lifecycle list did not return the rule that was just added");
				return;
			}
			if (!removed) {
				fail_result(r, "DNSS lifecycle remove send_ioctl_raw returned false");
				return;
			}
			r.ok = true;
			return;
		}
		if (ui_op == 1u) {
			voyager::detail::dns_spoof_list req{};
			bool ok = dnss_send_list("list_result", req, bytes_returned);
			r.bytes_returned = bytes_returned;
			r.raw.resize(sizeof(req));
			std::memcpy(r.raw.data(), &req, sizeof(req));
			if (!ok) {
				r.error = "send_ioctl_raw returned false (list)";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			push_text(r, "Operation", "List");
			push_u32(r, "Rule Count", req.rule_count);
			std::uint32_t cap = req.rule_count;
			if (cap > voyager::detail::DNS_SPOOF_MAX_RULES) {
				cap = voyager::detail::DNS_SPOOF_MAX_RULES;
			}
			char label[32];
			char value[256];
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& rule = req.rules[i];
				char domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN + 1];
				std::memcpy(domain_safe, rule.domain, voyager::detail::DNS_SPOOF_MAX_DOMAIN);
				domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN] = '\0';
				std::snprintf(label, sizeof(label), "Rule #%u", i);
				std::snprintf(value, sizeof(value),
					"id=%u domain='%s' -> %s af=%s ttl=%u hits=%u active=%u",
					rule.rule_id,
					domain_safe,
					format_addr(rule.spoof_addr, rule.address_family).c_str(),
					af_to_string(rule.address_family),
					rule.ttl, rule.match_count, rule.active);
				r.parsed.push_back({ std::string(label), std::string(value) });
			}
			if (req.rule_count == 0u) {
				fail_result(r, "DNSS list returned zero rules after the DNS spoof fixture/action expected a populated rule set");
				return;
			}
			r.ok = true;
			return;
		}
		voyager::detail::dns_spoof_rule req{};
		if (ui_op == 0u) {
			std::string domain = trim_copy(s.text_a);
			std::string ip_str = trim_copy(s.text_b);
			if (domain.empty()) {
				r.error = "domain must not be empty";
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			if (domain.size() >= voyager::detail::DNS_SPOOF_MAX_DOMAIN) {
				r.error = "domain too long";
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			std::uint8_t spoof[16] = { 0 };
			if (!parse_ipv4(ip_str, spoof)) {
				r.error = "spoof IP must be a valid IPv4 dotted quad";
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			req.operation = 0u;
			req.rule_id = 0u;
			std::memcpy(req.domain, domain.data(), domain.size());
			req.domain[domain.size()] = '\0';
			std::memcpy(req.spoof_addr, spoof, 16);
			req.address_family = 2u;
			req.match_count = 0u;
			req.active = 0u;
			req.ttl = 300u;
		}
		else {
			std::string trimmed = trim_copy(s.text_b);
			if (trimmed.empty()) {
				r.error = "rule_id is required for Remove";
				r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
				r.ok = false;
				return;
			}
			unsigned long parsed = 0;
			for (char c : trimmed) {
				if (c < '0' || c > '9') {
					r.error = "rule_id must be decimal";
					r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
					r.ok = false;
					return;
				}
				parsed = parsed * 10ul + static_cast<unsigned long>(c - '0');
			}
			req.operation = 1u;
			req.rule_id = static_cast<std::uint32_t>(parsed);
			req.address_family = 2u;
		}
		bool ok = device->send_ioctl_raw(ioctl_codes::DNSS(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_text(r, "Operation", (ui_op == 0u) ? "Add" : "Remove");
		push_u32(r, "Rule ID", req.rule_id);
		char domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN + 1];
		std::memcpy(domain_safe, req.domain, voyager::detail::DNS_SPOOF_MAX_DOMAIN);
		domain_safe[voyager::detail::DNS_SPOOF_MAX_DOMAIN] = '\0';
		push_text(r, "Domain", std::string(domain_safe));
		push_text(r, "Spoof addr", format_addr(req.spoof_addr, req.address_family));
		push_u32(r, "Address family", req.address_family);
		push_u32(r, "TTL", req.ttl);
		push_u32(r, "Active", req.active);
		r.ok = true;
	}

	void render_inputs_bwmn(test_lab::state_t& s) {
		const char* scopes[] = { "Per-connection / per-PID (scope=0)", "Per-interface (scope=1)" };
		int sel = static_cast<int>(s.u32_a);
		if (sel < 0 || sel > 1) sel = 0;
		if (ImGui::Combo("Scope", &sel, scopes, IM_ARRAYSIZE(scopes))) {
			s.u32_a = static_cast<std::uint32_t>(sel);
		}
		if (sel == 0) {
			ImGui::InputScalar("Filter PID (0 = totals only)",
				ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "%llu");
			ImGui::TextDisabled("Queries aggregate totals with op=2 and per-process counters with op=4.");
		}
		else {
			ImGui::InputScalar("Interface index (informational)",
				ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "%llu");
			ImGui::TextDisabled("Per-interface scope is reported via aggregate totals only; the driver does not expose per-IF counters on BWMN.");
		}
	}

	void run_bwmn(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		if (s.u32_a == 3u) {
			wsa_guard_t wsa;
			if (!wsa.ok) {
				r.error = "WSAStartup failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				test_lab_format::testlab_diag_log_step("network-action", "BWMN", "wsa_init",
					"failed err=%lu", static_cast<unsigned long>(GetLastError()));
				return;
			}
			std::uint32_t bytes_returned = 0;
			voyager::detail::bw_monitor_request reset{};
			reset.operation = 3u;
			(void)bwmn_send("lifecycle_reset_before", reset, bytes_returned);
			voyager::detail::bw_monitor_request start{};
			start.operation = 0u;
			const std::uint64_t monitor_start_tick = static_cast<std::uint64_t>(GetTickCount64());
			if (!bwmn_send("lifecycle_start", start, bytes_returned)) {
				r.bytes_returned = bytes_returned;
				r.raw.resize(sizeof(start));
				std::memcpy(r.raw.data(), &start, sizeof(start));
				fail_result(r, "BWMN lifecycle start send_ioctl_raw returned false");
				return;
			}
			std::string fixture_err;
			std::uint32_t fixture_packets = 0u;
			const bool fixture_ok = bwmn_drive_udp_fixture(fixture_err, fixture_packets);
			test_lab_format::testlab_diag_log_step("network-action", "BWMN", "udp_fixture",
				"ok=%d packets=%u err=\"%s\" stimulus_pid=%u",
				fixture_ok ? 1 : 0,
				fixture_packets,
				fixture_err.c_str(),
				self_pid);
			Sleep(250);
			voyager::detail::bw_monitor_request aggregate{};
			aggregate.operation = 2u;
			aggregate.filter_pid = 0u;
			std::uint32_t aggregate_bytes_returned = 0u;
			const bool aggregate_ok = bwmn_send("lifecycle_query_aggregate", aggregate, aggregate_bytes_returned);
			const std::uint64_t aggregate_query_tick = static_cast<std::uint64_t>(GetTickCount64());
			voyager::detail::bw_monitor_request per_process{};
			per_process.operation = 4u;
			per_process.filter_pid = self_pid;
			std::uint32_t per_process_bytes_returned = 0u;
			const bool per_process_ok = bwmn_send("lifecycle_query_per_process", per_process, per_process_bytes_returned);
			voyager::detail::bw_monitor_request stop{};
			stop.operation = 1u;
			std::uint32_t stop_bytes_returned = 0u;
			const bool stop_ok = bwmn_send("lifecycle_stop", stop, stop_bytes_returned);
			voyager::detail::bw_monitor_request cleanup{};
			cleanup.operation = 3u;
			std::uint32_t cleanup_bytes_returned = 0u;
			(void)bwmn_send("lifecycle_reset_after", cleanup, cleanup_bytes_returned);
			r.bytes_returned = per_process_bytes_returned;
			r.raw.resize(sizeof(per_process));
			std::memcpy(r.raw.data(), &per_process, sizeof(per_process));
			std::uint32_t nonzero_process_entries = 0u;
			const std::uint32_t matching_self_pid = count_matching_bw_processes(per_process, self_pid, nonzero_process_entries);
			const bw_process_evidence_t process_evidence = collect_bw_process_evidence(per_process, self_pid);
			const std::uint64_t rate_window_elapsed_ms = aggregate_query_tick >= monitor_start_tick
				? aggregate_query_tick - monitor_start_tick
				: 0u;
			const bool rate_sample_valid = rate_window_elapsed_ms >= 1000u;
			const bool rate_nonzero = aggregate.bytes_per_second_out != 0u || aggregate.bytes_per_second_in != 0u;
			push_text(r, "Operation", "Lifecycle reset/start/traffic/aggregate/per-process/stop/reset");
			push_text(r, "Coverage", "aggregate_and_per_process");
			push_u32(r, "Stimulus PID", self_pid);
			push_u32(r, "Start active", start.monitoring_active);
			push_u32(r, "Fixture UDP ok", fixture_ok ? 1u : 0u);
			push_u32(r, "Fixture UDP packets", fixture_packets);
			push_u32(r, "Aggregate IOCTL ok", aggregate_ok ? 1u : 0u);
			push_u32(r, "Per-process IOCTL ok", per_process_ok ? 1u : 0u);
			push_u32(r, "Stop IOCTL ok", stop_ok ? 1u : 0u);
			push_u32(r, "Monitoring active at aggregate query", aggregate.monitoring_active);
			push_hex64(r, "Total bytes sent", aggregate.total_bytes_sent);
			push_hex64(r, "Total bytes recv", aggregate.total_bytes_recv);
			push_hex64(r, "Total packets sent", aggregate.total_packets_sent);
			push_hex64(r, "Total packets recv", aggregate.total_packets_recv);
			push_hex64(r, "Bytes/sec out", aggregate.bytes_per_second_out);
			push_hex64(r, "Bytes/sec in", aggregate.bytes_per_second_in);
			push_u32(r, "Matching stimulus PID entries", matching_self_pid);
			push_u32(r, "Nonzero process entries", nonzero_process_entries);
			push_bw_rate_evidence(r, aggregate, process_evidence, rate_window_elapsed_ms, fixture_ok, fixture_packets);
			append_bw_process_entries(r, per_process);
			if (!aggregate_ok) {
				fail_result(r, "BWMN lifecycle aggregate query send_ioctl_raw returned false");
				return;
			}
			if (!per_process_ok) {
				fail_result(r, "BWMN lifecycle per-process query send_ioctl_raw returned false");
				return;
			}
			if (!stop_ok) {
				fail_result(r, "BWMN lifecycle stop send_ioctl_raw returned false");
				return;
			}
			if (!fixture_ok) {
				fail_result(r, "BWMN lifecycle UDP fixture failed: " + fixture_err,
					loopback_resource_precondition(fixture_err) ? 0xC000009Au : 0xC0000001u);
				return;
			}
			if (aggregate.monitoring_active == 0u) {
				fail_result(r, "BWMN lifecycle aggregate query reported monitoring inactive after start");
				return;
			}
			if (!bw_totals_nonzero(aggregate)) {
				fail_result(r, "BWMN lifecycle aggregate query returned zero counters after UDP fixture traffic");
				return;
			}
			if (rate_sample_valid && !rate_nonzero) {
				fail_result(r, "BWMN lifecycle returned zero throughput rates after a valid monitoring window with fixture traffic");
				return;
			}
			if (per_process.process_count == 0u) {
				fail_result(r, "BWMN lifecycle per-process query returned zero process entries after UDP fixture traffic");
				return;
			}
			if (matching_self_pid == 0u) {
				fail_result(r, "BWMN lifecycle per-process query returned entries but none matched the stimulus PID");
				return;
			}
			if (nonzero_process_entries == 0u) {
				fail_result(r, "BWMN lifecycle per-process query returned only zero process counters after UDP fixture traffic");
				return;
			}
			r.ok = true;
			return;
		}
		std::uint32_t bytes_returned = 0;
		if (s.u32_a == 1u) {
			voyager::detail::bw_monitor_request aggregate{};
			aggregate.operation = 2u;
			aggregate.filter_pid = 0u;
			bool ok = bwmn_send("query_aggregate_only", aggregate, bytes_returned);
			r.bytes_returned = bytes_returned;
			r.raw.resize(sizeof(aggregate));
			std::memcpy(r.raw.data(), &aggregate, sizeof(aggregate));
			if (!ok) {
				fail_result(r, "BWMN aggregate-only query send_ioctl_raw returned false");
				return;
			}
			push_text(r, "Scope", "interface_aggregate_only");
			push_text(r, "Coverage", "aggregate_only_per_process_not_claimed");
			push_u32(r, "Monitoring active", aggregate.monitoring_active);
			push_hex64(r, "Total bytes sent", aggregate.total_bytes_sent);
			push_hex64(r, "Total bytes recv", aggregate.total_bytes_recv);
			push_hex64(r, "Total packets sent", aggregate.total_packets_sent);
			push_hex64(r, "Total packets recv", aggregate.total_packets_recv);
			push_hex64(r, "Bytes/sec out", aggregate.bytes_per_second_out);
			push_hex64(r, "Bytes/sec in", aggregate.bytes_per_second_in);
			push_text(r, "Per-process coverage", "not_claimed_for_interface_scope");
			if (!bw_totals_nonzero(aggregate)) {
				fail_result(r, "BWMN aggregate-only query returned zero aggregate counters");
				return;
			}
			r.ok = true;
			return;
		}
		const std::uint32_t filter_pid = static_cast<std::uint32_t>(s.u64_a & 0xFFFFFFFFull);
		voyager::detail::bw_monitor_request aggregate{};
		aggregate.operation = 2u;
		aggregate.filter_pid = 0u;
		bool aggregate_ok = bwmn_send("query_per_process_aggregate", aggregate, bytes_returned);
		voyager::detail::bw_monitor_request per_process{};
		per_process.operation = 4u;
		per_process.filter_pid = filter_pid;
		bool per_process_ok = bwmn_send("query_per_process_entries", per_process, bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(per_process));
		std::memcpy(r.raw.data(), &per_process, sizeof(per_process));
		if (!aggregate_ok) {
			fail_result(r, "BWMN per-process aggregate query send_ioctl_raw returned false");
			return;
		}
		if (!per_process_ok) {
			fail_result(r, "BWMN per-process entry query send_ioctl_raw returned false");
			return;
		}
		std::uint32_t nonzero_process_entries = 0u;
		const std::uint32_t matching_filter_pid = count_matching_bw_processes(per_process, filter_pid, nonzero_process_entries);
		push_text(r, "Scope", "per_process");
		push_text(r, "Coverage", "aggregate_and_per_process");
		push_u32(r, "Filter PID", filter_pid);
		push_u32(r, "Monitoring active", aggregate.monitoring_active);
		push_hex64(r, "Total bytes sent", aggregate.total_bytes_sent);
		push_hex64(r, "Total bytes recv", aggregate.total_bytes_recv);
		push_hex64(r, "Total packets sent", aggregate.total_packets_sent);
		push_hex64(r, "Total packets recv", aggregate.total_packets_recv);
		push_hex64(r, "Bytes/sec out", aggregate.bytes_per_second_out);
		push_hex64(r, "Bytes/sec in", aggregate.bytes_per_second_in);
		push_u32(r, "Matching filter PID entries", matching_filter_pid);
		push_u32(r, "Nonzero process entries", nonzero_process_entries);
		append_bw_process_entries(r, per_process);
		if (!bw_totals_nonzero(aggregate)) {
			fail_result(r, "BWMN per-process scope aggregate query returned zero aggregate counters");
			return;
		}
		if (per_process.process_count == 0u) {
			fail_result(r, "BWMN per-process scope returned zero process entries");
			return;
		}
		if (filter_pid != 0u && matching_filter_pid == 0u) {
			fail_result(r, "BWMN per-process scope returned entries but none matched the requested PID filter");
			return;
		}
		if (nonzero_process_entries == 0u) {
			fail_result(r, "BWMN per-process scope returned only zero process counters");
			return;
		}
		r.ok = true;
	}

	void render_inputs_pcex(test_lab::state_t& s) {
		render_text_field("Pcap output path (e.g. C:\\temp\\capture.pcap)", s.text_a, 512);
		ImGui::TextDisabled("Drains the kernel capture ring (up to 256 packets), then writes a valid libpcap-format file at the path.");
	}

	bool write_pcap_file(const std::string& path,
		const voyager::detail::pcap_export_request& req,
		std::string& out_err,
		std::uint64_t& out_bytes) {
		out_bytes = 0;
		if (path.empty()) {
			out_err = "output path is empty";
			return false;
		}
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		if (!out.is_open()) {
			out_err = "failed to open pcap output for writing";
			return false;
		}
		out.write(reinterpret_cast<const char*>(&req.header), sizeof(req.header));
		if (!out.good()) {
			out_err = "failed to write pcap global header";
			return false;
		}
		out_bytes += sizeof(req.header);
		std::uint32_t cap = req.packet_count;
		if (cap > voyager::detail::PCAP_MAX_EXPORT_PACKETS) {
			cap = voyager::detail::PCAP_MAX_EXPORT_PACKETS;
		}
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& rec = req.records[i];
			std::uint32_t incl = rec.incl_len;
			if (incl > voyager::detail::PCAP_RECORD_MAX_SIZE) {
				incl = voyager::detail::PCAP_RECORD_MAX_SIZE;
			}
			std::uint32_t hdr[4] = { rec.ts_sec, rec.ts_usec, incl, rec.orig_len };
			out.write(reinterpret_cast<const char*>(hdr), sizeof(hdr));
			if (!out.good()) {
				out_err = "failed to write pcap record header";
				return false;
			}
			out_bytes += sizeof(hdr);
			if (incl > 0u) {
				out.write(reinterpret_cast<const char*>(rec.data), incl);
				if (!out.good()) {
					out_err = "failed to write pcap record body";
					return false;
				}
				out_bytes += incl;
			}
		}
		out.flush();
		if (!out.good()) {
			out_err = "stream flush failed after pcap write";
			return false;
		}
		return true;
	}

	void run_pcex(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		std::string path = trim_copy(s.text_a);
		if (path.empty()) {
			r.error = "output pcap path is required";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			r.ok = false;
			return;
		}
		voyager::detail::pcap_export_request req{};
		std::string fixture_err;
		std::uint32_t fixture_tcp_bytes = 0u;
		std::uint32_t fixture_udp_packets = 0u;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		(void)device->stop_capture();
		const bool capture_started = device->start_capture(self_pid, 0u, 0u, nullptr, 1500u);
		test_lab_format::testlab_diag_log_step("network-action", "PCEX", "capture_start",
			"ok=%d pid=%u proto=0 max_payload=1500",
			capture_started ? 1 : 0,
			self_pid);
		if (!capture_started) {
			fail_result(r, "PCEX failed to start kernel capture before fixture traffic");
			return;
		}
		const bool fixture_ok = drive_pcap_capture_fixture(fixture_err, fixture_tcp_bytes, fixture_udp_packets);
		test_lab_format::testlab_diag_log_step("network-action", "PCEX", "capture_seed",
			"ok=%d tcp_bytes=%u udp_packets=%u err=\"%s\"",
			fixture_ok ? 1 : 0,
			fixture_tcp_bytes,
			fixture_udp_packets,
			fixture_err.c_str());
		bool capture_active = false;
		std::uint32_t captured_before_stop = 0u;
		std::uint32_t dropped_before_stop = 0u;
		for (int i = 0; i < 10; ++i) {
			bool status_ok = device->get_capture_status(capture_active, captured_before_stop, dropped_before_stop);
			test_lab_format::testlab_diag_log_step("network-action", "PCEX", "capture_poll",
				"iter=%d ok=%d active=%d captured=%u dropped=%u",
				i,
				status_ok ? 1 : 0,
				capture_active ? 1 : 0,
				captured_before_stop,
				dropped_before_stop);
			if (captured_before_stop > 0u)
				break;
			Sleep(75);
		}
		const bool capture_stopped = device->stop_capture();
		test_lab_format::testlab_diag_log_step("network-action", "PCEX", "capture_stop",
			"ok=%d captured=%u dropped=%u",
			capture_stopped ? 1 : 0,
			captured_before_stop,
			dropped_before_stop);
		req.operation = 0u;
		req.filter_pid = 0u;
		req.filter_protocol = 0u;
		req.max_packets = voyager::detail::PCAP_MAX_EXPORT_PACKETS;
		req.packet_count = 0u;
		req.data_size = 0u;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PCEX(),
			&req,
			static_cast<std::uint32_t>(sizeof(req)),
			bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req.header));
		std::memcpy(r.raw.data(), &req.header, sizeof(req.header));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		std::string write_err;
		std::uint64_t written = 0;
		if (!write_pcap_file(path, req, write_err, written)) {
			r.error = write_err;
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_text(r, "Output path", path);
		push_u32(r, "Fixture TCP bytes", fixture_tcp_bytes);
		push_u32(r, "Fixture UDP packets", fixture_udp_packets);
		push_u32(r, "Capture start ok", capture_started ? 1u : 0u);
		push_u32(r, "Capture stop ok", capture_stopped ? 1u : 0u);
		push_u32(r, "Captured before stop", captured_before_stop);
		push_u32(r, "Dropped before stop", dropped_before_stop);
		push_u32(r, "Packet count", req.packet_count);
		push_hex64(r, "Header magic", req.header.magic_number);
		push_u32(r, "PCAP version major", req.header.version_major);
		push_u32(r, "PCAP version minor", req.header.version_minor);
		push_u32(r, "Snaplen", req.header.snaplen);
		push_u32(r, "Link type", req.header.network);
		push_hex64(r, "Bytes written", written);
		push_hex64(r, "Kernel data size", req.data_size);
		test_lab_format::testlab_diag_log_step("network-action", "PCEX", "export_result",
			"ok=1 bytes_returned=%u output=\"%s\" packet_count=%u data_size=%llu bytes_written=%llu magic=0x%08X",
			bytes_returned,
			path.c_str(),
			req.packet_count,
			static_cast<unsigned long long>(req.data_size),
			static_cast<unsigned long long>(written),
			req.header.magic_number);
		if (!fixture_ok) {
			fail_result(r, "PCEX capture fixture failed before export: " + fixture_err,
				loopback_resource_precondition(fixture_err) ? 0xC000009Au : 0xC0000001u);
			return;
		}
		if (!capture_stopped) {
			fail_result(r, "PCEX failed to stop kernel capture before export");
			return;
		}
		if (req.packet_count == 0u || req.data_size <= sizeof(req.header) || written <= sizeof(req.header)) {
			fail_result(r, "PCEX exported only the pcap header and no packet records after the capture fixture/action expected packet data");
			return;
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_pred, "network-action", test_lab::driver_e::whoswho, "PRED",
	"Traffic redirect rule add/list/remove (kernel-side rewrite of dst addr/port).",
	&render_inputs_pred, &run_pred);

TESTLAB_REGISTER(g_reg_strm, "network-action", test_lab::driver_e::whoswho, "STRM",
	"Stream reassembly: fetch the reassembled TCP byte stream for a tracked (src_port, dst_port) flow.",
	&render_inputs_strm, &run_strm);

TESTLAB_REGISTER(g_reg_ckil, "network-action", test_lab::driver_e::whoswho, "CKIL",
	"Kill an open connection by 5-tuple (protocol/AF/ports/addrs + optional PID filter).",
	&render_inputs_ckil, &run_ckil);

TESTLAB_REGISTER(g_reg_dnss, "network-action", test_lab::driver_e::whoswho, "DNSS",
	"DNS spoofing rule add/list/remove (resolve target domain to spoof IPv4 with TTL).",
	&render_inputs_dnss, &run_dnss);

TESTLAB_REGISTER(g_reg_bwmn, "network-action", test_lab::driver_e::whoswho, "BWMN",
	"Bandwidth monitor: op=2 aggregate totals and op=4 per-process counters from the WhosWho BW ring.",
	&render_inputs_bwmn, &run_bwmn);

TESTLAB_REGISTER(g_reg_pcex, "network-action", test_lab::driver_e::whoswho, "PCEX",
	"Export the kernel capture ring to a libpcap-format file at the supplied path.",
	&render_inputs_pcex, &run_pcex);
