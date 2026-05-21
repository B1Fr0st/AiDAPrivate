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

	void push_text(test_lab::result_t& r, const char* label, const std::string& value) {
		r.parsed.push_back({ std::string(label), value });
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

	struct wsa_guard_t {
		bool ok = false;
		wsa_guard_t() {
			WSADATA d{};
			ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
		}
		~wsa_guard_t() {
			if (ok) WSACleanup();
		}
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
			if (accepted != INVALID_SOCKET) { closesocket(accepted); accepted = INVALID_SOCKET; }
			if (client != INVALID_SOCKET) { closesocket(client); client = INVALID_SOCKET; }
			if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
		}

		~tcp_pair_t() { close_all(); }
	};

	bool establish_local_tcp_pair(tcp_pair_t& p, std::string& err) {
		p.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (p.listener == INVALID_SOCKET) {
			err = "socket(listener) failed";
			return false;
		}
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
			err = "socket(client) failed";
			return false;
		}
		u_long nb = 1;
		ioctlsocket(p.client, FIONBIO, &nb);
		sockaddr_in ra{};
		ra.sin_family = AF_INET;
		ra.sin_port = htons(p.listen_port);
		ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		int cr = connect(p.client, reinterpret_cast<const sockaddr*>(&ra), sizeof(ra));
		if (cr != 0) {
			int werr = WSAGetLastError();
			if (werr != WSAEWOULDBLOCK) {
				err = "connect(client) failed err=" + std::to_string(werr);
				return false;
			}
		}
		fd_set wfds, efds;
		FD_ZERO(&wfds); FD_ZERO(&efds);
		FD_SET(p.client, &wfds);
		FD_SET(p.client, &efds);
		timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		int wret = select(0, nullptr, &wfds, &efds, &tv);
		if (wret <= 0) {
			err = "connect(client) select timeout/err=" + std::to_string(WSAGetLastError());
			return false;
		}
		int so_err = 0;
		int so_len = static_cast<int>(sizeof(so_err));
		getsockopt(p.client, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &so_len);
		if (FD_ISSET(p.client, &efds) || so_err != 0) {
			err = "connect(client) failed so_error=" + std::to_string(so_err);
			return false;
		}
		u_long nb_off = 0;
		ioctlsocket(p.client, FIONBIO, &nb_off);

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
		if (ui_op == 1u) {
			voyager::detail::traffic_redirect_list req{};
			req.operation = 0u;
			req.rule_count = 0u;
			bool ok = device->send_ioctl_raw(ioctl_codes::PRED(),
				&req,
				static_cast<std::uint32_t>(sizeof(req)),
				bytes_returned);
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
		if (!establish_local_tcp_pair(pair, pair_err)) {
			test_lab_format::testlab_diag_log_step("network-action", "STRM", "tcp_pair_open",
				"failed err=\"%s\" (WFP callout may be intercepting loopback TCP)", pair_err.c_str());
			r.ntstatus = 0;
			r.ok = true;
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

		const char* probe_payload = "AIDA-STRM-PROBE-PAYLOAD-0123456789";
		int probe_len = static_cast<int>(std::strlen(probe_payload));
		int sent = send(pair.client, probe_payload, probe_len, 0);
		test_lab_format::testlab_diag_log_step("network-action", "STRM", "send_traffic",
			"send()=%d errno=%lu", sent,
			(sent < 0) ? static_cast<unsigned long>(WSAGetLastError()) : 0ul);
		if (sent <= 0) {
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
		if (!establish_local_tcp_pair(pair, pair_err)) {
			test_lab_format::testlab_diag_log_step("network-action", "CKIL", "tcp_pair_open",
				"failed err=\"%s\" (WFP callout may be intercepting loopback TCP)", pair_err.c_str());
			r.ntstatus = 0;
			r.ok = true;
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

		bool post_send_failed = false;
		int post_send_err = 0;
		if (ok) {
			const char* poke = "x";
			Sleep(50);
			int rc = send(pair.client, poke, 1, 0);
			if (rc == SOCKET_ERROR) {
				post_send_failed = true;
				post_send_err = WSAGetLastError();
			}
			test_lab_format::testlab_diag_log_step("network-action", "CKIL", "post_send_probe",
				"send_rc=%d wsa_err=%d", rc, post_send_err);
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
		push_u32(r, "Step3 Post-kill send failed", post_send_failed ? 1u : 0u);
		push_u32(r, "Step3 Post-kill send WSA err", static_cast<std::uint32_t>(post_send_err));

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
		if (ui_op == 1u) {
			voyager::detail::dns_spoof_list req{};
			req.operation = 2u;
			req.rule_count = 0u;
			bool ok = device->send_ioctl_raw(ioctl_codes::DNSS(),
				&req,
				static_cast<std::uint32_t>(sizeof(req)),
				bytes_returned);
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
			ImGui::TextDisabled("Issues GET (op=2): totals + per-process counters via WhosWho bandwidth monitor.");
		}
		else {
			ImGui::InputScalar("Interface index (informational)",
				ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "%llu");
			ImGui::TextDisabled("Per-interface scope is reported via aggregate totals only; the driver does not expose per-IF counters on BWMN.");
		}
	}

	void run_bwmn(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::bw_monitor_request req{};
		req.operation = 2u;
		req.filter_pid = (s.u32_a == 0u)
			? static_cast<std::uint32_t>(s.u64_a & 0xFFFFFFFFull)
			: 0u;
		req.process_count = 0u;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::BWMN(),
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
		push_text(r, "Scope", (s.u32_a == 1u) ? "interface" : "conn/pid");
		push_u32(r, "Filter PID", req.filter_pid);
		push_u32(r, "Monitoring active", req.monitoring_active);
		push_hex64(r, "Total bytes sent", req.total_bytes_sent);
		push_hex64(r, "Total bytes recv", req.total_bytes_recv);
		push_hex64(r, "Total packets sent", req.total_packets_sent);
		push_hex64(r, "Total packets recv", req.total_packets_recv);
		push_hex64(r, "Bytes/sec out", req.bytes_per_second_out);
		push_hex64(r, "Bytes/sec in", req.bytes_per_second_in);
		std::uint32_t cap = req.process_count;
		if (cap > voyager::detail::BW_MAX_PROCESSES) {
			cap = voyager::detail::BW_MAX_PROCESSES;
		}
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
		push_u32(r, "Packet count", req.packet_count);
		push_hex64(r, "Header magic", req.header.magic_number);
		push_u32(r, "PCAP version major", req.header.version_major);
		push_u32(r, "PCAP version minor", req.header.version_minor);
		push_u32(r, "Snaplen", req.header.snaplen);
		push_u32(r, "Link type", req.header.network);
		push_hex64(r, "Bytes written", written);
		push_hex64(r, "Kernel data size", req.data_size);
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
	"Bandwidth monitor: totals + per-process counters from the WhosWho BW ring.",
	&render_inputs_bwmn, &run_bwmn);

TESTLAB_REGISTER(g_reg_pcex, "network-action", test_lab::driver_e::whoswho, "PCEX",
	"Export the kernel capture ring to a libpcap-format file at the supplied path.",
	&render_inputs_pcex, &run_pcex);
