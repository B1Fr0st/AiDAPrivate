#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

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
			auto list_buf = std::make_unique<voyager::detail::packet_mod_rule_list>();
			std::memset(list_buf.get(), 0, sizeof(*list_buf));
			list_buf->operation = 2u;
			bool ok = device->send_ioctl_raw(ioctl_codes::PMOD(), list_buf.get(),
				static_cast<std::uint32_t>(sizeof(*list_buf)), bytes_returned);
			r.bytes_returned = bytes_returned;
			constexpr std::size_t kRawHeaderBytes = 32;
			r.raw.resize(kRawHeaderBytes);
			std::memcpy(r.raw.data(), list_buf.get(), kRawHeaderBytes);
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
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& rl = list_buf->rules[i];
				char label[32];
				std::snprintf(label, sizeof(label), "rule[%u]", i);
				std::snprintf(buf, sizeof(buf),
					"id=%u dir=%u proto=%u port=%u pid=%u pat=%u repl=%u matched=%u active=%u",
					rl.rule_id, rl.direction, rl.protocol, rl.port, rl.pid,
					rl.pattern_size, rl.replace_size, rl.match_count, rl.active);
				r.parsed.push_back({ label, buf });
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
		auto req = std::make_unique<voyager::detail::dpi_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->filter_pid = s.pid;
		req->filter_protocol = s.u32_a;
		req->filter_port = s.size;
		req->flags = s.u32_b;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DPIN(), req.get(),
			static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		constexpr std::size_t kRawHeaderBytes = 24;
		r.raw.resize(kRawHeaderBytes);
		std::memcpy(r.raw.data(), req.get(), kRawHeaderBytes);
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		char buf[256];
		std::snprintf(buf, sizeof(buf), "%u", req->result_count);
		r.parsed.push_back({ "result_count", buf });
		std::uint32_t cap = req->result_count;
		if (cap > voyager::detail::DPI_MAX_RESULTS) cap = voyager::detail::DPI_MAX_RESULTS;
		if (cap > 16u) cap = 16u;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& h = req->results[i];
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
		auto req = std::make_unique<voyager::detail::intercept_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->operation = s.u32_a;
		req->hold_id = s.u64_a;
		req->filter_pid = s.pid;
		req->filter_port = s.size;
		req->filter_protocol = s.u32_b;
		if (s.u32_a == 5u) {
			std::uint32_t mod_written = parse_hex_payload(s.text_a, req->modify_payload,
				voyager::detail::INTERCEPT_MAX_PAYLOAD);
			req->modify_payload_size = mod_written;
		}
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::IHLD(), req.get(),
			static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		r.bytes_returned = bytes_returned;
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
