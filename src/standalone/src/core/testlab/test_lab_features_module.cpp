#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../runtime/standalone_driver.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#pragma comment(lib, "ws2_32.lib")

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

	constexpr DWORD kLoopbackSocketTimeoutMs = 750u;

	std::uint32_t parse_hex_payload(const std::string& src, std::uint8_t* out, std::uint32_t out_cap) {
		std::uint32_t written = 0;
		std::uint8_t nibble = 0;
		bool have_high = false;
		for (std::size_t i = 0; i < src.size() && written < out_cap; ++i) {
			char c = src[i];
			std::uint8_t v = 0;
			if (c >= '0' && c <= '9')      v = static_cast<std::uint8_t>(c - '0');
			else if (c >= 'a' && c <= 'f') v = static_cast<std::uint8_t>(10 + (c - 'a'));
			else if (c >= 'A' && c <= 'F') v = static_cast<std::uint8_t>(10 + (c - 'A'));
			else continue;
			if (!have_high) {
				nibble = static_cast<std::uint8_t>(v << 4);
				have_high = true;
			} else {
				out[written++] = static_cast<std::uint8_t>(nibble | v);
				have_high = false;
			}
		}
		return written;
	}

	std::string format_dec_u32(std::uint32_t v) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%u", v);
		return std::string(buf);
	}

	std::string format_dec_i32(std::int32_t v) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%d", v);
		return std::string(buf);
	}

	std::string format_dec_u64(std::uint64_t v) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
		return std::string(buf);
	}

	BOOL CALLBACK init_module_winsock_once(PINIT_ONCE, PVOID parameter, PVOID*) {
		bool* ok = static_cast<bool*>(parameter);
		WSADATA d{};
		*ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
		return TRUE;
	}

	bool ensure_module_winsock_ready() {
		static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
		static bool ok = false;
		if (!InitOnceExecuteOnce(&once, init_module_winsock_once, &ok, nullptr))
			return false;
		return ok;
	}

	void configure_loopback_socket(SOCKET s) {
		DWORD timeout_ms = kLoopbackSocketTimeoutMs;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
		BOOL nodelay = TRUE;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
	}

	struct loopback_tcp_fixture_t {
		SOCKET listener = INVALID_SOCKET;
		SOCKET client = INVALID_SOCKET;
		SOCKET accepted = INVALID_SOCKET;
		std::uint32_t listen_port = 0;
		std::uint32_t client_port = 0;
		int setup_wsa_error = 0;
		int send_error = 0;
		int recv_error = 0;
		int sent_bytes = 0;
		int recv_bytes = 0;
		int response_sent_bytes = 0;
		int response_recv_bytes = 0;

		void close() {
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
		}

		~loopback_tcp_fixture_t() {
			close();
		}
	};

	bool open_loopback_tcp_fixture(loopback_tcp_fixture_t& fx, std::string& diag) {
		fx.close();
		fx.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fx.listener == INVALID_SOCKET) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "listener socket failed";
			return false;
		}
		configure_loopback_socket(fx.listener);
		sockaddr_in bind_addr{};
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_port = 0;
		bind_addr.sin_addr.s_addr = htonl(0x7f000001u);
		if (bind(fx.listener, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "bind failed";
			return false;
		}
		if (listen(fx.listener, 1) == SOCKET_ERROR) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "listen failed";
			return false;
		}
		int name_len = sizeof(bind_addr);
		if (getsockname(fx.listener, reinterpret_cast<sockaddr*>(&bind_addr), &name_len) == SOCKET_ERROR) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "getsockname listener failed";
			return false;
		}
		fx.listen_port = ntohs(bind_addr.sin_port);
		fx.client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fx.client == INVALID_SOCKET) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "client socket failed";
			return false;
		}
		configure_loopback_socket(fx.client);
		if (connect(fx.client, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "connect failed";
			return false;
		}
		fx.accepted = accept(fx.listener, nullptr, nullptr);
		if (fx.accepted == INVALID_SOCKET) {
			fx.setup_wsa_error = WSAGetLastError();
			diag = "accept failed";
			return false;
		}
		configure_loopback_socket(fx.accepted);
		sockaddr_in client_addr{};
		int client_len = sizeof(client_addr);
		if (getsockname(fx.client, reinterpret_cast<sockaddr*>(&client_addr), &client_len) == 0) {
			fx.client_port = ntohs(client_addr.sin_port);
		}
		closesocket(fx.listener);
		fx.listener = INVALID_SOCKET;
		diag = "loopback connected";
		return true;
	}

	bool emit_loopback_http(loopback_tcp_fixture_t& fx, const char* marker) {
		char payload[256];
		std::snprintf(payload, sizeof(payload),
			"GET /aida-testlab-%s HTTP/1.1\r\nHost: aida.testlab\r\nConnection: close\r\nUser-Agent: AiDA-TestLab\r\n\r\n",
			marker ? marker : "probe");
		fx.sent_bytes = send(fx.client, payload, static_cast<int>(std::strlen(payload)), 0);
		fx.send_error = (fx.sent_bytes == SOCKET_ERROR) ? WSAGetLastError() : 0;
		if (fx.sent_bytes == SOCKET_ERROR)
			return false;
		char recv_buf[256];
		fx.recv_bytes = recv(fx.accepted, recv_buf, sizeof(recv_buf), 0);
		fx.recv_error = (fx.recv_bytes == SOCKET_ERROR) ? WSAGetLastError() : 0;
		if (fx.recv_bytes > 0) {
			const char response[] = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			fx.response_sent_bytes = send(fx.accepted, response, static_cast<int>(sizeof(response) - 1), 0);
			char response_buf[128];
			fx.response_recv_bytes = recv(fx.client, response_buf, sizeof(response_buf), 0);
		}
		return true;
	}

	void append_loopback_fields(test_lab::result_t& r, const loopback_tcp_fixture_t& fx, const char* prefix) {
		char label[64];
		std::snprintf(label, sizeof(label), "%s_listen_port", prefix);
		r.parsed.push_back({ label, format_dec_u32(fx.listen_port) });
		std::snprintf(label, sizeof(label), "%s_client_port", prefix);
		r.parsed.push_back({ label, format_dec_u32(fx.client_port) });
		std::snprintf(label, sizeof(label), "%s_setup_wsa_error", prefix);
		r.parsed.push_back({ label, format_dec_i32(fx.setup_wsa_error) });
		std::snprintf(label, sizeof(label), "%s_sent_bytes", prefix);
		r.parsed.push_back({ label, format_dec_i32(fx.sent_bytes) });
		std::snprintf(label, sizeof(label), "%s_send_error", prefix);
		r.parsed.push_back({ label, format_dec_i32(fx.send_error) });
		std::snprintf(label, sizeof(label), "%s_recv_bytes", prefix);
		r.parsed.push_back({ label, format_dec_i32(fx.recv_bytes) });
		std::snprintf(label, sizeof(label), "%s_recv_error", prefix);
		r.parsed.push_back({ label, format_dec_i32(fx.recv_error) });
	}

	bool send_ihld_logged(const char* step,
		voyager::detail::intercept_request& req,
		std::uint32_t& bytes_returned,
		DWORD& gle_out,
		std::uint64_t& elapsed_ms_out)
	{
		const std::uint32_t attached_pid = driver_bridge::attached_pid();
		const ULONGLONG start = GetTickCount64();
		bytes_returned = 0;
		SetLastError(ERROR_SUCCESS);
		bool ok = device->send_ioctl_raw(ioctl_codes::IHLD(), &req,
			static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		gle_out = ok ? ERROR_SUCCESS : GetLastError();
		elapsed_ms_out = static_cast<std::uint64_t>(GetTickCount64() - start);
		const std::int32_t synthetic_ntstatus = ok ? 0 : static_cast<std::int32_t>(0xC0000001u);
		test_lab_format::testlab_diag_log_step("module", "IHLD", step,
			"status=%s ok=%d gle=%lu synthetic_ntstatus=0x%08X bytes_returned=%u op=%u filter_pid=%u filter_protocol=%u filter_port=%u hold_id=%llu attached_pid=%u intercepting=%u held_count=%u modify_payload_size=%u elapsed_ms=%llu",
			ok ? "success" : "ioctl_failed",
			ok ? 1 : 0,
			static_cast<unsigned long>(gle_out),
			static_cast<unsigned>(synthetic_ntstatus),
			bytes_returned,
			req.operation,
			req.filter_pid,
			req.filter_protocol,
			req.filter_port,
			static_cast<unsigned long long>(req.hold_id),
			attached_pid,
			req.intercepting,
			req.held_count,
			req.modify_payload_size,
			static_cast<unsigned long long>(elapsed_ms_out));
		if (!ok) {
			const std::string bridge_error = driver_bridge::last_error();
			test_lab_format::testlab_diag_log_step("module", "IHLD", step,
				"driver_last_error=\"%s\"", bridge_error.c_str());
		}
		return ok;
	}

	void render_inputs_pmod(test_lab::state_t& s) {
		static const char* items[] = {
			"0 add rule (single)",
			"1 delete rule by id (single)",
			"2 list rules (bulk)",
		};
		int current = static_cast<int>(s.u32_a);
		if (current < 0 || current >= static_cast<int>(sizeof(items) / sizeof(items[0]))) current = 0;
		if (ImGui::Combo("Operation", &current, items, static_cast<int>(sizeof(items) / sizeof(items[0])))) {
			s.u32_a = static_cast<std::uint32_t>(current);
		}
		ImGui::TextDisabled("Rule format (add): rule_id|direction|protocol|port|pid|pattern_hex|replacement_hex");
		ImGui::TextDisabled("Rule format (del): rule_id");
		ImGui::TextDisabled("List op ignores the rule string.");
		if (s.text_a.size() < 1) s.text_a.reserve(96);
		char buf[256];
		std::snprintf(buf, sizeof(buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Rule string", buf, sizeof(buf))) {
			s.text_a = buf;
		}
	}

	bool parse_rule_string_for_add(const std::string& src, voyager::detail::packet_mod_rule& out) {
		std::vector<std::string> parts;
		std::string cur;
		for (char c : src) {
			if (c == '|') { parts.push_back(cur); cur.clear(); }
			else { cur.push_back(c); }
		}
		parts.push_back(cur);
		if (parts.size() < 5) return false;
		out.rule_id = static_cast<std::uint32_t>(std::strtoul(parts[0].c_str(), nullptr, 0));
		out.direction = static_cast<std::uint32_t>(std::strtoul(parts[1].c_str(), nullptr, 0));
		out.protocol = static_cast<std::uint32_t>(std::strtoul(parts[2].c_str(), nullptr, 0));
		out.port = static_cast<std::uint32_t>(std::strtoul(parts[3].c_str(), nullptr, 0));
		out.pid = static_cast<std::uint32_t>(std::strtoul(parts[4].c_str(), nullptr, 0));
		std::uint32_t pat_written = 0;
		std::uint32_t rep_written = 0;
		if (parts.size() >= 6) {
			pat_written = parse_hex_payload(parts[5], out.pattern, voyager::detail::MOD_MAX_PATTERN);
		}
		if (parts.size() >= 7) {
			rep_written = parse_hex_payload(parts[6], out.replacement, voyager::detail::MOD_MAX_REPLACE);
		}
		out.pattern_size = pat_written;
		out.replace_size = rep_written;
		out.match_count = 0;
		out.active = 0;
		return true;
	}

	void run_pmod(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		std::uint32_t bytes_returned = 0;
		if (s.u32_a == 2u) {
			voyager::detail::packet_mod_rule seed{};
			seed.operation = 0u;
			seed.direction = 1u;
			seed.protocol = 6u;
			seed.port = 0u;
			seed.pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			const char pattern[] = "AIDA_TESTLAB_PMOD_PATTERN";
			const char replacement[] = "AIDA_TESTLAB_PMOD_REPLACED";
			seed.pattern_size = static_cast<std::uint32_t>(sizeof(pattern) - 1u);
			seed.replace_size = static_cast<std::uint32_t>(sizeof(replacement) - 1u);
			std::memcpy(seed.pattern, pattern, seed.pattern_size);
			std::memcpy(seed.replacement, replacement, seed.replace_size);
			std::uint32_t seed_bytes = 0;
			bool seed_ok = device->send_ioctl_raw(ioctl_codes::PMOD(), &seed,
				static_cast<std::uint32_t>(sizeof(seed)), seed_bytes);
			r.parsed.push_back({ "seed_add_ok", seed_ok ? "1" : "0" });
			r.parsed.push_back({ "seed_add_bytes", format_dec_u32(seed_bytes) });
			r.parsed.push_back({ "seed_rule_id", format_dec_u32(seed.rule_id) });
			r.parsed.push_back({ "seed_pid", format_dec_u32(seed.pid) });
			r.parsed.push_back({ "seed_protocol", format_dec_u32(seed.protocol) });
			r.parsed.push_back({ "seed_pattern_size", format_dec_u32(seed.pattern_size) });
			r.parsed.push_back({ "seed_replace_size", format_dec_u32(seed.replace_size) });
			if (!seed_ok || seed.rule_id == 0u) {
				r.error = "PMOD deterministic seed add failed before list";
				r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
				r.ok = false;
				return;
			}
			auto list_buf = std::make_unique<voyager::detail::packet_mod_rule_list>();
			std::memset(list_buf.get(), 0, sizeof(*list_buf));
			list_buf->operation = 2u;
			bool ok = device->send_ioctl_raw(ioctl_codes::PMOD(), list_buf.get(),
				static_cast<std::uint32_t>(sizeof(*list_buf)), bytes_returned);
			r.bytes_returned = bytes_returned;
			constexpr std::size_t kRawHeaderBytes = 32;
			r.raw.resize(kRawHeaderBytes);
			std::memcpy(r.raw.data(), list_buf.get(), kRawHeaderBytes);
			voyager::detail::packet_mod_rule del{};
			del.operation = 1u;
			del.rule_id = seed.rule_id;
			std::uint32_t del_bytes = 0;
			bool del_ok = device->send_ioctl_raw(ioctl_codes::PMOD(), &del,
				static_cast<std::uint32_t>(sizeof(del)), del_bytes);
			r.parsed.push_back({ "seed_delete_ok", del_ok ? "1" : "0" });
			r.parsed.push_back({ "seed_delete_bytes", format_dec_u32(del_bytes) });
			if (!ok) {
				r.error = "send_ioctl_raw returned false";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			char buf[96];
			std::snprintf(buf, sizeof(buf), "%u", list_buf->rule_count);
			r.parsed.push_back({ "rule_count", buf });
			std::uint32_t cap = list_buf->rule_count;
			if (cap > voyager::detail::MOD_MAX_RULES) cap = voyager::detail::MOD_MAX_RULES;
			if (cap > 16u) cap = 16u;
			bool seed_listed = false;
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& rl = list_buf->rules[i];
				if (rl.rule_id == seed.rule_id)
					seed_listed = true;
				char label[32];
				std::snprintf(label, sizeof(label), "rule[%u]", i);
				std::snprintf(buf, sizeof(buf),
					"id=%u dir=%u proto=%u port=%u pid=%u pat=%u repl=%u matched=%u active=%u",
					rl.rule_id, rl.direction, rl.protocol, rl.port, rl.pid,
					rl.pattern_size, rl.replace_size, rl.match_count, rl.active);
				r.parsed.push_back({ label, buf });
			}
			r.parsed.push_back({ "seed_listed", seed_listed ? "1" : "0" });
			if (list_buf->rule_count == 0u || !seed_listed) {
				r.error = "PMOD list did not return the deterministic seed rule";
				r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
				r.parsed.push_back({ "recommendation", "Verify PMOD add/list share the same active rule table and that operation=2 list is not clearing state before copy-out" });
				r.ok = false;
				return;
			}
			r.ok = true;
			return;
		}
		voyager::detail::packet_mod_rule req{};
		if (s.u32_a == 0u) {
			if (!parse_rule_string_for_add(s.text_a, req)) {
				r.error = "rule string must have at least 5 |-separated fields for add";
				r.ok = false;
				return;
			}
			req.operation = 0u;
		} else {
			req.rule_id = static_cast<std::uint32_t>(std::strtoul(s.text_a.c_str(), nullptr, 0));
			req.operation = 1u;
		}
		bool ok = device->send_ioctl_raw(ioctl_codes::PMOD(), &req,
			static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[64];
		std::snprintf(buf, sizeof(buf), "%u", req.operation);
		r.parsed.push_back({ "operation", buf });
		std::snprintf(buf, sizeof(buf), "%u", req.rule_id);
		r.parsed.push_back({ "rule_id", buf });
		std::snprintf(buf, sizeof(buf), "%u", req.pattern_size);
		r.parsed.push_back({ "pattern_size", buf });
		std::snprintf(buf, sizeof(buf), "%u", req.replace_size);
		r.parsed.push_back({ "replace_size", buf });
		std::snprintf(buf, sizeof(buf), "%u", req.active);
		r.parsed.push_back({ "active", buf });
		r.ok = true;
	}

	const char* af_label(std::uint32_t af) {
		switch (af) {
			case 2u:  return "AF_INET";
			case 23u: return "AF_INET6";
			default:  return "?";
		}
	}

	const char* proto_label(std::uint32_t p) {
		switch (p) {
			case 1u:  return "ICMP";
			case 6u:  return "TCP";
			case 17u: return "UDP";
			default:  return "?";
		}
	}

	void render_inputs_pinj(test_lab::state_t& s) {
		static const char* dir_items[] = {
			"0 outbound (send)",
			"1 inbound (recv)",
		};
		int dir = static_cast<int>(s.u32_a);
		if (dir < 0 || dir >= static_cast<int>(sizeof(dir_items) / sizeof(dir_items[0]))) dir = 0;
		if (ImGui::Combo("Direction", &dir, dir_items, static_cast<int>(sizeof(dir_items) / sizeof(dir_items[0])))) {
			s.u32_a = static_cast<std::uint32_t>(dir);
		}
		static int s_proto_choice = 6;
		ImGui::InputInt("Protocol (6=TCP, 17=UDP, 1=ICMP)", &s_proto_choice);
		if (s_proto_choice < 0) s_proto_choice = 0;
		s.u32_b = static_cast<std::uint32_t>(s_proto_choice);
		ImGui::InputScalar("src port", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::InputScalar("dst port", ImGuiDataType_U32, &s.tid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("src_addr / dst_addr default to 127.0.0.1, address_family=AF_INET.");
		ImGui::TextDisabled("Payload: paste raw hex bytes (\"DEADBEEF...\"). Capped at INJECT_MAX_PAYLOAD = %u.",
			voyager::detail::INJECT_MAX_PAYLOAD);
		char buf[1024];
		std::snprintf(buf, sizeof(buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Payload hex", buf, sizeof(buf))) {
			s.text_a = buf;
		}
	}

	void run_pinj(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		auto req = std::make_unique<voyager::detail::packet_inject_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->direction = s.u32_a;
		req->protocol = (s.u32_b != 0u) ? s.u32_b : 6u;
		req->address_family = 2u;
		req->src_port = s.size;
		req->dst_port = s.tid;
		req->src_addr[0] = 127u; req->src_addr[1] = 0u; req->src_addr[2] = 0u; req->src_addr[3] = 1u;
		req->dst_addr[0] = 127u; req->dst_addr[1] = 0u; req->dst_addr[2] = 0u; req->dst_addr[3] = 1u;
		std::uint32_t written = parse_hex_payload(s.text_a, req->payload, voyager::detail::INJECT_MAX_PAYLOAD);
		req->payload_size = written;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PINJ(), req.get(),
			static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		constexpr std::size_t kRawHeaderBytes = 96;
		r.raw.resize(kRawHeaderBytes);
		std::memcpy(r.raw.data(), req.get(), kRawHeaderBytes);
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[96];
		std::snprintf(buf, sizeof(buf), "%u", req->direction);
		r.parsed.push_back({ "direction", buf });
		std::snprintf(buf, sizeof(buf), "%u (%s)", req->protocol, proto_label(req->protocol));
		r.parsed.push_back({ "protocol", buf });
		std::snprintf(buf, sizeof(buf), "%u (%s)", req->address_family, af_label(req->address_family));
		r.parsed.push_back({ "address_family", buf });
		std::snprintf(buf, sizeof(buf), "%u -> %u", req->src_port, req->dst_port);
		r.parsed.push_back({ "ports", buf });
		std::snprintf(buf, sizeof(buf), "%u/%u (parsed/cap)", written, voyager::detail::INJECT_MAX_PAYLOAD);
		r.parsed.push_back({ "payload_size", buf });
		std::snprintf(buf, sizeof(buf), "%u", req->status);
		r.parsed.push_back({ "status_word", buf });
		r.ok = true;
	}

	void render_inputs_dpin(test_lab::state_t& s) {
		ImGui::InputScalar("PID filter (0 = any)", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		static int s_proto = 0;
		ImGui::InputInt("Protocol filter (0=any, 6=TCP, 17=UDP, 1=ICMP)", &s_proto);
		if (s_proto < 0) s_proto = 0;
		s.u32_a = static_cast<std::uint32_t>(s_proto);
		ImGui::InputScalar("Port filter (0 = any)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::InputScalar("Flags", ImGuiDataType_U32, &s.u32_b, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Driver returns up to DPI_MAX_RESULTS = %u header records.",
			voyager::detail::DPI_MAX_RESULTS);
	}

	void run_dpin(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		if (!ensure_module_winsock_ready()) {
			r.error = "WSAStartup failed before DPIN stimulus";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		r.parsed.push_back({ "requested_pid_filter", format_dec_u32(s.pid) });
		r.parsed.push_back({ "requested_protocol_filter", format_dec_u32(s.u32_a) });
		r.parsed.push_back({ "requested_port_filter", format_dec_u32(s.size) });
		r.parsed.push_back({ "requested_flags", format_dec_u32(s.u32_b) });
		r.parsed.push_back({ "stimulus_pid", format_dec_u32(self_pid) });
		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = self_pid;
		start_req.filter_protocol = 6u;
		start_req.max_packet_bytes = 1500u;
		std::uint32_t cap_start_bytes = 0;
		bool cap_started = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req,
			static_cast<std::uint32_t>(sizeof(start_req)), cap_start_bytes);
		r.parsed.push_back({ "capture_start_ok", cap_started ? "1" : "0" });
		r.parsed.push_back({ "capture_start_bytes", format_dec_u32(cap_start_bytes) });
		r.parsed.push_back({ "capture_active_after_start", format_dec_u32(start_req.capture_active) });
		if (!cap_started) {
			r.error = "NCAP start failed before DPIN deterministic stimulus";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		auto stop_capture = [&]() {
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			stop_req.filter_pid = self_pid;
			stop_req.filter_protocol = 6u;
			stop_req.max_packet_bytes = 1500u;
			std::uint32_t cap_stop_bytes = 0;
			bool stop_ok = device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req,
				static_cast<std::uint32_t>(sizeof(stop_req)), cap_stop_bytes);
			r.parsed.push_back({ "capture_stop_ok", stop_ok ? "1" : "0" });
			r.parsed.push_back({ "capture_stop_bytes", format_dec_u32(cap_stop_bytes) });
			r.parsed.push_back({ "capture_packets_captured", format_dec_u32(stop_req.packets_captured) });
			r.parsed.push_back({ "capture_packets_dropped", format_dec_u32(stop_req.packets_dropped) });
		};
		loopback_tcp_fixture_t fx;
		std::string fixture_diag;
		bool fixture_ok = open_loopback_tcp_fixture(fx, fixture_diag);
		r.parsed.push_back({ "loopback_fixture_ok", fixture_ok ? "1" : "0" });
		r.parsed.push_back({ "loopback_fixture_diag", fixture_diag });
		append_loopback_fields(r, fx, "loopback_before_send");
		if (!fixture_ok) {
			stop_capture();
			r.error = "loopback TCP fixture failed before DPIN query";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			return;
		}
		Sleep(80);
		bool traffic_ok = emit_loopback_http(fx, "dpin");
		r.parsed.push_back({ "loopback_traffic_ok", traffic_ok ? "1" : "0" });
		append_loopback_fields(r, fx, "loopback_after_send");
		Sleep(250);
		auto req = std::make_unique<voyager::detail::dpi_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->filter_pid = self_pid;
		req->filter_protocol = 6u;
		req->filter_port = 0u;
		req->flags = 0u;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DPIN(), req.get(),
			static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		constexpr std::size_t kRawHeaderBytes = 24;
		r.raw.resize(kRawHeaderBytes);
		std::memcpy(r.raw.data(), req.get(), kRawHeaderBytes);
		if (!ok) {
			stop_capture();
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[256];
		std::snprintf(buf, sizeof(buf), "%u", req->result_count);
		r.parsed.push_back({ "result_count", buf });
		std::uint32_t matching_self_pid = 0u;
		std::uint32_t http_records = 0u;
		std::uint32_t cap = req->result_count;
		if (cap > voyager::detail::DPI_MAX_RESULTS) cap = voyager::detail::DPI_MAX_RESULTS;
		if (cap > 16u) cap = 16u;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& h = req->results[i];
			if (h.pid == self_pid)
				++matching_self_pid;
			if (h.is_http != 0u)
				++http_records;
			char label[32];
			std::snprintf(label, sizeof(label), "rec[%u]", i);
			char host[64];
			std::size_t hl = 0;
			for (std::size_t k = 0; k < sizeof(h.http_host) && hl < sizeof(host) - 1; ++k) {
				char c = h.http_host[k];
				if (c == '\0') break;
				host[hl++] = (c >= 0x20 && c < 0x7F) ? c : '?';
			}
			host[hl] = '\0';
			char sni[64];
			std::size_t sl = 0;
			for (std::size_t k = 0; k < sizeof(h.tls_sni) && sl < sizeof(sni) - 1; ++k) {
				char c = h.tls_sni[k];
				if (c == '\0') break;
				sni[sl++] = (c >= 0x20 && c < 0x7F) ? c : '?';
			}
			sni[sl] = '\0';
			std::snprintf(buf, sizeof(buf),
				"dir=%u proto=%u(%s) %u->%u pid=%u http=%u tls=%u dns=%u host=%s sni=%s payload=%u",
				h.direction, h.protocol, proto_label(h.protocol),
				h.src_port, h.dst_port, h.pid,
				h.is_http, h.is_tls, h.is_dns,
				host, sni, h.payload_size);
			r.parsed.push_back({ label, buf });
		}
		r.parsed.push_back({ "results_matching_self_pid", format_dec_u32(matching_self_pid) });
		r.parsed.push_back({ "http_record_count", format_dec_u32(http_records) });
		stop_capture();
		if (req->result_count == 0u || matching_self_pid == 0u) {
			r.error = "DPIN did not return a self-PID record after NCAP self-PID start and loopback HTTP stimulus";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.parsed.push_back({ "recommendation", "Verify WFP classify paths call net_dpi::analyze_packet for loopback/self PID traffic before DPIN drains the ring" });
			r.ok = false;
			return;
		}
		r.ok = true;
	}

	const char* intercept_op_label(std::uint32_t op) {
		switch (op) {
			case 0u: return "start";
			case 1u: return "stop";
			case 2u: return "list_held";
			case 3u: return "release_and_inject";
			case 4u: return "drop";
			case 5u: return "modify_and_release";
			default: return "?";
		}
	}

	void render_inputs_ihld(test_lab::state_t& s) {
		static const char* items[] = {
			"0 start intercept",
			"1 stop intercept",
			"2 list held packets",
			"3 release + inject (needs hold_id)",
			"4 drop (needs hold_id)",
			"5 modify + release (needs hold_id, payload via text_a)",
		};
		int current = static_cast<int>(s.u32_a);
		if (current < 0 || current >= static_cast<int>(sizeof(items) / sizeof(items[0]))) current = 0;
		if (ImGui::Combo("Operation", &current, items, static_cast<int>(sizeof(items) / sizeof(items[0])))) {
			s.u32_a = static_cast<std::uint32_t>(current);
		}
		ImGui::InputScalar("hold_id", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "%llu");
		ImGui::InputScalar("filter pid (op 0)", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("filter port (op 0)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::InputScalar("filter protocol (op 0)", ImGuiDataType_U32, &s.u32_b, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Modify payload (op 5): hex bytes; capped at INTERCEPT_MAX_PAYLOAD = %u.",
			voyager::detail::INTERCEPT_MAX_PAYLOAD);
		char buf[1024];
		std::snprintf(buf, sizeof(buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Modify payload hex", buf, sizeof(buf))) {
			s.text_a = buf;
		}
	}

	void run_ihld(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		if (s.u32_a == 2u) {
			if (!ensure_module_winsock_ready()) {
				r.error = "WSAStartup failed before IHLD stimulus";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
			const std::uint32_t attached_pid = driver_bridge::attached_pid();
			r.parsed.push_back({ "requested_pid_filter", format_dec_u32(s.pid) });
			r.parsed.push_back({ "requested_protocol_filter", format_dec_u32(s.u32_b) });
			r.parsed.push_back({ "requested_port_filter", format_dec_u32(s.size) });
			r.parsed.push_back({ "stimulus_pid", format_dec_u32(self_pid) });
			r.parsed.push_back({ "attached_pid", format_dec_u32(attached_pid) });
			test_lab_format::testlab_diag_log_step("module", "IHLD", "deterministic_begin",
				"stimulus_pid=%u attached_pid=%u requested_filter_pid=%u requested_filter_protocol=%u requested_filter_port=%llu",
				self_pid,
				attached_pid,
				s.pid,
				s.u32_b,
				static_cast<unsigned long long>(s.size));
			loopback_tcp_fixture_t fx;
			std::string fixture_diag;
			const ULONGLONG fixture_start = GetTickCount64();
			bool fixture_ok = open_loopback_tcp_fixture(fx, fixture_diag);
			const std::uint64_t fixture_elapsed = static_cast<std::uint64_t>(GetTickCount64() - fixture_start);
			r.parsed.push_back({ "loopback_fixture_ok", fixture_ok ? "1" : "0" });
			r.parsed.push_back({ "loopback_fixture_diag", fixture_diag });
			r.parsed.push_back({ "loopback_fixture_elapsed_ms", format_dec_u64(fixture_elapsed) });
			append_loopback_fields(r, fx, "loopback_before_intercept");
			test_lab_format::testlab_diag_log_step("module", "IHLD", "loopback_open",
				"ok=%d diag=\"%s\" listen_port=%u client_port=%u setup_wsa_error=%d elapsed_ms=%llu",
				fixture_ok ? 1 : 0,
				fixture_diag.c_str(),
				fx.listen_port,
				fx.client_port,
				fx.setup_wsa_error,
				static_cast<unsigned long long>(fixture_elapsed));
			if (!fixture_ok) {
				r.error = "loopback TCP fixture failed before IHLD intercept start";
				r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
				r.ok = false;
				return;
			}
			voyager::detail::intercept_request clear_req{};
			clear_req.operation = 1u;
			std::uint32_t clear_bytes = 0;
			DWORD clear_gle = ERROR_SUCCESS;
			std::uint64_t clear_elapsed = 0;
			bool clear_ok = send_ihld_logged("preclear", clear_req, clear_bytes, clear_gle, clear_elapsed);
			r.parsed.push_back({ "intercept_preclear_ok", clear_ok ? "1" : "0" });
			r.parsed.push_back({ "intercept_preclear_bytes", format_dec_u32(clear_bytes) });
			r.parsed.push_back({ "intercept_preclear_gle", format_dec_u32(static_cast<std::uint32_t>(clear_gle)) });
			r.parsed.push_back({ "intercept_preclear_elapsed_ms", format_dec_u64(clear_elapsed) });
			if (!clear_ok) {
				r.error = "IHLD preclear failed before deterministic intercept start";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			voyager::detail::intercept_request start_req{};
			start_req.operation = 0u;
			start_req.filter_pid = self_pid;
			start_req.filter_protocol = 6u;
			r.parsed.push_back({ "effective_filter_pid", format_dec_u32(start_req.filter_pid) });
			r.parsed.push_back({ "effective_filter_protocol", format_dec_u32(start_req.filter_protocol) });
			r.parsed.push_back({ "effective_filter_protocol_name", proto_label(start_req.filter_protocol) });
			r.parsed.push_back({ "effective_filter_port", format_dec_u32(start_req.filter_port) });
			r.parsed.push_back({ "expected_receive_timeout_ms", format_dec_u32(kLoopbackSocketTimeoutMs) });
			r.parsed.push_back({ "expected_receive_timeout_semantics", "loopback recv timeout is expected while IHLD holds matching TCP traffic; PASS requires held_matching_self_pid > 0" });
			std::uint32_t start_bytes = 0;
			DWORD start_gle = ERROR_SUCCESS;
			std::uint64_t start_elapsed = 0;
			bool start_ok = send_ihld_logged("start", start_req, start_bytes, start_gle, start_elapsed);
			r.parsed.push_back({ "intercept_start_ok", start_ok ? "1" : "0" });
			r.parsed.push_back({ "intercept_start_bytes", format_dec_u32(start_bytes) });
			r.parsed.push_back({ "intercept_start_gle", format_dec_u32(static_cast<std::uint32_t>(start_gle)) });
			r.parsed.push_back({ "intercept_start_elapsed_ms", format_dec_u64(start_elapsed) });
			r.parsed.push_back({ "intercepting_after_start", format_dec_u32(start_req.intercepting) });
			if (!start_ok) {
				r.error = "IHLD deterministic intercept start failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			const ULONGLONG traffic_start = GetTickCount64();
			bool traffic_ok = emit_loopback_http(fx, "ihld");
			const std::uint64_t traffic_elapsed = static_cast<std::uint64_t>(GetTickCount64() - traffic_start);
			r.parsed.push_back({ "loopback_traffic_ok", traffic_ok ? "1" : "0" });
			r.parsed.push_back({ "loopback_traffic_elapsed_ms", format_dec_u64(traffic_elapsed) });
			r.parsed.push_back({ "loopback_recv_timeout_expected", fx.recv_error == WSAETIMEDOUT ? "1" : "0" });
			append_loopback_fields(r, fx, "loopback_after_send");
			test_lab_format::testlab_diag_log_step("module", "IHLD", "loopback_emit",
				"ok=%d listen_port=%u client_port=%u sent_bytes=%d send_error=%d recv_bytes=%d recv_error=%d recv_timeout_expected=%d response_sent_bytes=%d response_recv_bytes=%d timeout_ms=%lu elapsed_ms=%llu",
				traffic_ok ? 1 : 0,
				fx.listen_port,
				fx.client_port,
				fx.sent_bytes,
				fx.send_error,
				fx.recv_bytes,
				fx.recv_error,
				fx.recv_error == WSAETIMEDOUT ? 1 : 0,
				fx.response_sent_bytes,
				fx.response_recv_bytes,
				static_cast<unsigned long>(kLoopbackSocketTimeoutMs),
				static_cast<unsigned long long>(traffic_elapsed));
			Sleep(250);
			auto req = std::make_unique<voyager::detail::intercept_request>();
			std::memset(req.get(), 0, sizeof(*req));
			req->operation = 2u;
			std::uint32_t bytes_returned = 0;
			DWORD list_gle = ERROR_SUCCESS;
			std::uint64_t list_elapsed = 0;
			bool ok = send_ihld_logged("list", *req, bytes_returned, list_gle, list_elapsed);
			r.bytes_returned = bytes_returned;
			r.parsed.push_back({ "intercept_list_gle", format_dec_u32(static_cast<std::uint32_t>(list_gle)) });
			r.parsed.push_back({ "intercept_list_elapsed_ms", format_dec_u64(list_elapsed) });
			constexpr std::size_t kRawHeaderBytes = 48;
			r.raw.resize(kRawHeaderBytes);
			std::memcpy(r.raw.data(), req.get(), kRawHeaderBytes);
			voyager::detail::intercept_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t stop_bytes = 0;
			DWORD stop_gle = ERROR_SUCCESS;
			std::uint64_t stop_elapsed = 0;
			bool stop_ok = send_ihld_logged("stop", stop_req, stop_bytes, stop_gle, stop_elapsed);
			r.parsed.push_back({ "intercept_stop_ok", stop_ok ? "1" : "0" });
			r.parsed.push_back({ "intercept_stop_bytes", format_dec_u32(stop_bytes) });
			r.parsed.push_back({ "intercept_stop_gle", format_dec_u32(static_cast<std::uint32_t>(stop_gle)) });
			r.parsed.push_back({ "intercept_stop_elapsed_ms", format_dec_u64(stop_elapsed) });
			r.parsed.push_back({ "intercepting_after_stop", format_dec_u32(stop_req.intercepting) });
			r.parsed.push_back({ "held_count_after_stop", format_dec_u32(stop_req.held_count) });
			if (!ok) {
				r.error = "send_ioctl_raw returned false";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				r.ok = false;
				return;
			}
			char buf[160];
			std::snprintf(buf, sizeof(buf), "%u (%s)", req->operation, intercept_op_label(req->operation));
			r.parsed.push_back({ "operation", buf });
			std::snprintf(buf, sizeof(buf), "%u", req->intercepting);
			r.parsed.push_back({ "intercepting", buf });
			std::snprintf(buf, sizeof(buf), "%u", req->held_count);
			r.parsed.push_back({ "held_count", buf });
			std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(req->hold_id));
			r.parsed.push_back({ "hold_id_echo", buf });
			std::snprintf(buf, sizeof(buf), "%u", req->modify_payload_size);
			r.parsed.push_back({ "modify_payload_size", buf });
			std::uint32_t cap = req->held_count;
			if (cap > voyager::detail::INTERCEPT_MAX_HELD) cap = voyager::detail::INTERCEPT_MAX_HELD;
			if (cap > 8u) cap = 8u;
			std::uint32_t matching_self_pid = 0u;
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& h = req->held_packets[i];
				if (h.pid == self_pid)
					++matching_self_pid;
				char label[32];
				std::snprintf(label, sizeof(label), "held[%u]", i);
				std::snprintf(buf, sizeof(buf),
					"id=%llu dir=%u proto=%u(%s) %u->%u pid=%u payload=%u af=%u",
					static_cast<unsigned long long>(h.hold_id),
					h.direction, h.protocol, proto_label(h.protocol),
					h.src_port, h.dst_port, h.pid, h.payload_size, h.address_family);
				r.parsed.push_back({ label, buf });
			}
			r.parsed.push_back({ "held_matching_self_pid", format_dec_u32(matching_self_pid) });
			test_lab_format::testlab_diag_log_step("module", "IHLD", "list_summary",
				"ok=%d gle=%lu bytes_returned=%u held_count=%u output_cap=%u matching_self_pid=%u intercepting=%u attached_pid=%u effective_filter_pid=%u effective_filter_protocol=%u effective_filter_port=%u expected_receive_timeout_ms=%lu elapsed_ms=%llu",
				ok ? 1 : 0,
				static_cast<unsigned long>(list_gle),
				bytes_returned,
				req->held_count,
				cap,
				matching_self_pid,
				req->intercepting,
				driver_bridge::attached_pid(),
				start_req.filter_pid,
				start_req.filter_protocol,
				start_req.filter_port,
				static_cast<unsigned long>(kLoopbackSocketTimeoutMs),
				static_cast<unsigned long long>(list_elapsed));
			if (req->held_count == 0u || matching_self_pid == 0u) {
				r.error = "IHLD list did not return a self-PID held packet after deterministic intercept and loopback HTTP stimulus";
				r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
				r.parsed.push_back({ "recommendation", "Verify WFP classify paths call net_intercept::try_hold_packet for loopback/self PID traffic while IHLD operation=0 is active" });
				r.ok = false;
				return;
			}
			r.ok = true;
			return;
		}
		auto req = std::make_unique<voyager::detail::intercept_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->operation = s.u32_a;
		req->hold_id = s.u64_a;
		req->filter_pid = s.pid;
		req->filter_port = s.size;
		req->filter_protocol = s.u32_b;
		if (s.u32_a == 0u && req->filter_pid == 0u &&
			req->filter_port == 0u && req->filter_protocol == 0u) {
			r.error = "refusing wildcard intercept start; set pid, port, or protocol";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			r.ok = false;
			return;
		}
		if (s.u32_a == 5u) {
			std::uint32_t mod_written = parse_hex_payload(s.text_a, req->modify_payload,
				voyager::detail::INTERCEPT_MAX_PAYLOAD);
			req->modify_payload_size = mod_written;
		}
		std::uint32_t bytes_returned = 0;
		DWORD gle = ERROR_SUCCESS;
		std::uint64_t elapsed = 0;
		bool ok = send_ihld_logged("manual", *req, bytes_returned, gle, elapsed);
		r.bytes_returned = bytes_returned;
		r.parsed.push_back({ "ioctl_gle", format_dec_u32(static_cast<std::uint32_t>(gle)) });
		r.parsed.push_back({ "ioctl_elapsed_ms", format_dec_u64(elapsed) });
		r.parsed.push_back({ "attached_pid", format_dec_u32(driver_bridge::attached_pid()) });
		constexpr std::size_t kRawHeaderBytes = 48;
		r.raw.resize(kRawHeaderBytes);
		std::memcpy(r.raw.data(), req.get(), kRawHeaderBytes);
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[160];
		std::snprintf(buf, sizeof(buf), "%u (%s)", req->operation, intercept_op_label(req->operation));
		r.parsed.push_back({ "operation", buf });
		std::snprintf(buf, sizeof(buf), "%u", req->intercepting);
		r.parsed.push_back({ "intercepting", buf });
		std::snprintf(buf, sizeof(buf), "%u", req->held_count);
		r.parsed.push_back({ "held_count", buf });
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(req->hold_id));
		r.parsed.push_back({ "hold_id_echo", buf });
		std::snprintf(buf, sizeof(buf), "%u", req->modify_payload_size);
		r.parsed.push_back({ "modify_payload_size", buf });
		std::uint32_t cap = req->held_count;
		if (cap > voyager::detail::INTERCEPT_MAX_HELD) cap = voyager::detail::INTERCEPT_MAX_HELD;
		if (cap > 8u) cap = 8u;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& h = req->held_packets[i];
			char label[32];
			std::snprintf(label, sizeof(label), "held[%u]", i);
			std::snprintf(buf, sizeof(buf),
				"id=%llu dir=%u proto=%u(%s) %u->%u pid=%u payload=%u af=%u",
				static_cast<unsigned long long>(h.hold_id),
				h.direction, h.protocol, proto_label(h.protocol),
				h.src_port, h.dst_port, h.pid, h.payload_size, h.address_family);
			r.parsed.push_back({ label, buf });
		}
		test_lab_format::testlab_diag_log_step("module", "IHLD", "manual_summary",
			"ok=%d gle=%lu bytes_returned=%u op=%u held_count=%u output_cap=%u intercepting=%u filter_pid=%u filter_protocol=%u filter_port=%u elapsed_ms=%llu",
			ok ? 1 : 0,
			static_cast<unsigned long>(gle),
			bytes_returned,
			req->operation,
			req->held_count,
			cap,
			req->intercepting,
			req->filter_pid,
			req->filter_protocol,
			req->filter_port,
			static_cast<unsigned long long>(elapsed));
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_pmod, "module", test_lab::driver_e::whoswho,
	"PMOD", "Add / delete / list packet-modification rules (pattern -> replacement) consumed by the WFP layer.",
	&render_inputs_pmod, &run_pmod);

TESTLAB_REGISTER(g_reg_pinj, "module", test_lab::driver_e::whoswho,
	"PINJ", "Inject a transport-layer packet (TCP / UDP / ICMP) with a user-supplied hex payload via FwpsInjectSend0.",
	&render_inputs_pinj, &run_pinj);

TESTLAB_REGISTER(g_reg_dpin, "module", test_lab::driver_e::whoswho,
	"DPIN", "Deep-packet inspection: drain up to DPI_MAX_RESULTS classified records (HTTP / TLS-SNI / DNS).",
	&render_inputs_dpin, &run_dpin);

TESTLAB_REGISTER(g_reg_ihld, "module", test_lab::driver_e::whoswho,
	"IHLD", "Intercept-hold: pause / list / drop / release-with-inject / modify held packets matching filter.",
	&render_inputs_ihld, &run_ihld);
