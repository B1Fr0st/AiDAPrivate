#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
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

	void set_fail_from_ioctl(test_lab::result_t& r, std::uint32_t bytes_returned) {
		r.ok = false;
		r.bytes_returned = bytes_returned;
		if (r.error.empty()) {
			r.error = "send_ioctl_raw returned false";
		}
		if (r.ntstatus == 0) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
		}
	}

	void capture_raw_struct(test_lab::result_t& r, const void* ptr, std::size_t sz) {
		r.raw.resize(sz);
		std::memcpy(r.raw.data(), ptr, sz);
	}

	std::string format_dec_u32(std::uint32_t v) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%u", v);
		return std::string(buf);
	}

	std::string format_dec_u64(std::uint64_t v) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
		return std::string(buf);
	}

	std::string format_hex_u32(std::uint32_t v) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "0x%08X", v);
		return std::string(buf);
	}

	std::string format_hex_u64(std::uint64_t v) {
		char buf[24];
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(v));
		return std::string(buf);
	}

	const char* proto_name(std::uint32_t p) {
		switch (p) {
			case 6u: return "TCP";
			case 17u: return "UDP";
			case 1u: return "ICMP";
			case 0u: return "ANY";
			default: return "?";
		}
	}

	const char* tcp_state_name(std::uint32_t s) {
		switch (s) {
			case 1u: return "CLOSED";
			case 2u: return "LISTEN";
			case 3u: return "SYN_SENT";
			case 4u: return "SYN_RCVD";
			case 5u: return "ESTAB";
			case 6u: return "FIN_WAIT1";
			case 7u: return "FIN_WAIT2";
			case 8u: return "CLOSE_WAIT";
			case 9u: return "CLOSING";
			case 10u: return "LAST_ACK";
			case 11u: return "TIME_WAIT";
			case 12u: return "DELETE_TCB";
			default: return "?";
		}
	}

	std::string format_ip(const std::uint8_t* addr, std::uint32_t family) {
		char buf[64];
		if (family == 23u) {
			std::snprintf(buf, sizeof(buf),
				"[%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X]",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
				addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
		} else {
			std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
				addr[0], addr[1], addr[2], addr[3]);
		}
		return std::string(buf);
	}

	std::string format_mac(const std::uint8_t* mac) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return std::string(buf);
	}

	bool parse_dotted_quad(const char* s, std::uint8_t out[4], std::uint32_t* opt_port) {
		if (s == nullptr) return false;
		std::uint32_t parts[4] = { 0, 0, 0, 0 };
		std::uint32_t idx = 0;
		std::uint32_t cur = 0;
		bool have_digit = false;
		const char* p = s;
		for (; *p != '\0' && *p != ':'; ++p) {
			if (*p == '.') {
				if (!have_digit || idx >= 3) return false;
				parts[idx++] = cur;
				cur = 0;
				have_digit = false;
				continue;
			}
			if (*p < '0' || *p > '9') return false;
			cur = cur * 10u + static_cast<std::uint32_t>(*p - '0');
			if (cur > 255u) return false;
			have_digit = true;
		}
		if (!have_digit || idx != 3) return false;
		parts[3] = cur;
		for (std::uint32_t i = 0; i < 4u; ++i) out[i] = static_cast<std::uint8_t>(parts[i]);
		if (opt_port != nullptr && *p == ':') {
			++p;
			std::uint32_t port = 0;
			bool any = false;
			for (; *p != '\0'; ++p) {
				if (*p < '0' || *p > '9') return false;
				port = port * 10u + static_cast<std::uint32_t>(*p - '0');
				if (port > 65535u) return false;
				any = true;
			}
			if (any) *opt_port = port;
		}
		return true;
	}

	void render_inputs_ncon(test_lab::state_t& s) {
		const char* items[] = { "All", "TCP only", "UDP only" };
		int cur = static_cast<int>(s.u32_a);
		if (cur < 0 || cur > 2) cur = 0;
		if (ImGui::Combo("Protocol filter (u32_a)", &cur, items, IM_ARRAYSIZE(items))) {
			s.u32_a = static_cast<std::uint32_t>(cur);
		}
		ImGui::TextDisabled("Enumerates kernel-side TCP/UDP connections (IPv4 + IPv6). Capped at 50 visible rows.");
	}

	void run_ncon(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		std::uint32_t proto_filter = 0;
		if (s.u32_a == 1u) proto_filter = 6u;
		else if (s.u32_a == 2u) proto_filter = 17u;
		voyager::detail::net_enum_conn_request* req =
			static_cast<voyager::detail::net_enum_conn_request*>(std::calloc(1, sizeof(voyager::detail::net_enum_conn_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_enum_conn_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->filter_pid = 0;
		req->filter_protocol = proto_filter;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NCON(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "connection_count", format_dec_u32(req->connection_count) });
		const std::uint32_t cap = (req->connection_count > 50u) ? 50u : req->connection_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Conn[%u]", i);
			char val[512];
			std::snprintf(val, sizeof(val),
				"%s %s:%u -> %s:%u state=%s pid=%u",
				proto_name(e.protocol),
				format_ip(e.local_addr, e.address_family).c_str(),
				e.local_port,
				format_ip(e.remote_addr, e.address_family).c_str(),
				e.remote_port,
				tcp_state_name(e.state),
				e.pid);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_ncap(test_lab::state_t& s) {
		const char* items[] = { "Start", "Stop", "Pause" };
		int cur = static_cast<int>(s.u32_a);
		if (cur < 0 || cur > 2) cur = 0;
		if (ImGui::Combo("Operation (u32_a)", &cur, items, IM_ARRAYSIZE(items))) {
			s.u32_a = static_cast<std::uint32_t>(cur);
		}
		ImGui::InputScalar("Interface index (u32_b, informational)", ImGuiDataType_U32, &s.u32_b, nullptr, nullptr, "%u");
		ImGui::TextDisabled("0=Start (op=0 in kernel), 1=Stop (op=1), 2=Pause (op=2). WFP capture engine control.");
	}

	void run_ncap(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::net_cap_ctrl_request req{};
		req.operation = s.u32_a;
		req.filter_pid = s.pid;
		req.filter_port = 0;
		req.filter_protocol = 0;
		req.max_packet_bytes = 1500u;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NCAP(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "operation", format_dec_u32(s.u32_a) });
		r.parsed.push_back({ "capture_active", format_dec_u32(req.capture_active) });
		r.parsed.push_back({ "packets_captured", format_dec_u32(req.packets_captured) });
		r.parsed.push_back({ "packets_dropped", format_dec_u32(req.packets_dropped) });
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_ncpg(test_lab::state_t& s) {
		ImGui::InputScalar("Max packets (u32_a, 1-32)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Drains captured packets from the kernel ring buffer.");
	}

	void run_ncpg(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::net_cap_get_request* req =
			static_cast<voyager::detail::net_cap_get_request*>(std::calloc(1, sizeof(voyager::detail::net_cap_get_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_cap_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		std::uint32_t mx = s.u32_a;
		if (mx == 0u || mx > voyager::detail::NET_CAP_GET_MAX) mx = static_cast<std::uint32_t>(voyager::detail::NET_CAP_GET_MAX);
		req->max_packets = mx;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NCPG(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "packet_count", format_dec_u32(req->packet_count) });
		const std::uint32_t cap = (req->packet_count > 50u) ? 50u : req->packet_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& p = req->packets[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Pkt[%u]", i);
			char val[512];
			std::snprintf(val, sizeof(val),
				"ts=%llu %s dir=%u %s:%u -> %s:%u payload=%u pid=%u",
				static_cast<unsigned long long>(p.timestamp),
				proto_name(p.protocol),
				p.direction,
				format_ip(p.local_addr, p.address_family).c_str(),
				p.local_port,
				format_ip(p.remote_addr, p.address_family).c_str(),
				p.remote_port,
				p.payload_size,
				p.pid);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_ndns(test_lab::state_t& s) {
		ImGui::InputScalar("Max entries (u32_a, 1-64)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Returns kernel-side DNS query log entries.");
	}

	void run_ndns(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::net_dns_get_request* req =
			static_cast<voyager::detail::net_dns_get_request*>(std::calloc(1, sizeof(voyager::detail::net_dns_get_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_dns_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->filter_pid = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NDNS(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		const std::uint32_t total = req->entry_count;
		r.parsed.push_back({ "entry_count", format_dec_u32(total) });
		std::uint32_t cap = total;
		if (cap > 50u) cap = 50u;
		if (cap > static_cast<std::uint32_t>(voyager::detail::NET_DNS_GET_MAX)) {
			cap = static_cast<std::uint32_t>(voyager::detail::NET_DNS_GET_MAX);
		}
		const std::uint32_t requested = s.u32_a;
		if (requested != 0u && cap > requested) cap = requested;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "DNS[%u]", i);
			char dom[261];
			std::memcpy(dom, e.domain, 260);
			dom[260] = '\0';
			char val[512];
			std::snprintf(val, sizeof(val),
				"ts=%llu pid=%u type=%u rcode=%u ttl=%u %s -> %s",
				static_cast<unsigned long long>(e.timestamp),
				e.pid, e.query_type, e.response_code, e.ttl,
				dom,
				format_ip(e.resolved_addr, 2u).c_str());
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_nflt(test_lab::state_t& s) {
		const char* items[] = { "Add (op=0)", "Remove (op=1)", "Clear all (op=2)", "Query count (op=3)" };
		int cur = static_cast<int>(s.u32_a);
		if (cur < 0 || cur > 3) cur = 0;
		if (ImGui::Combo("Operation (u32_a)", &cur, items, IM_ARRAYSIZE(items))) {
			s.u32_a = static_cast<std::uint32_t>(cur);
		}
		char buf[256];
		std::size_t copy = s.text_a.size();
		if (copy >= sizeof(buf)) copy = sizeof(buf) - 1u;
		std::memcpy(buf, s.text_a.data(), copy);
		buf[copy] = '\0';
		if (ImGui::InputText("Rule descriptor (text_a)", buf, sizeof(buf))) {
			s.text_a.assign(buf);
		}
		ImGui::TextDisabled("Add format: 'action=<0|1>;direction=<0|1|2>;protocol=<6|17|0>;pid=<u32>;port=<u32>;ip=<a.b.c.d>'. Remove: 'rule_id=<u32>'.");
	}

	void run_nflt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::net_filter_rule_request req{};
		req.operation = s.u32_a;
		const char* p = s.text_a.c_str();
		auto skip_sep = [](const char*& q) {
			while (*q == ';' || *q == ' ' || *q == '\t') ++q;
		};
		auto match_key = [&](const char* key) -> bool {
			std::size_t kl = std::strlen(key);
			if (std::strncmp(p, key, kl) == 0 && p[kl] == '=') {
				p += kl + 1u;
				return true;
			}
			return false;
		};
		auto read_u32 = [&]() -> std::uint32_t {
			std::uint32_t v = 0;
			while (*p >= '0' && *p <= '9') {
				v = v * 10u + static_cast<std::uint32_t>(*p - '0');
				++p;
			}
			return v;
		};
		while (*p != '\0') {
			skip_sep(p);
			if (*p == '\0') break;
			if (match_key("action")) { req.action = read_u32(); }
			else if (match_key("direction")) { req.direction = read_u32(); }
			else if (match_key("protocol")) { req.protocol = read_u32(); }
			else if (match_key("pid")) { req.pid = read_u32(); }
			else if (match_key("port")) { req.port = read_u32(); }
			else if (match_key("rule_id")) { req.rule_id = read_u32(); }
			else if (match_key("ip")) {
				std::uint8_t a[4] = { 0, 0, 0, 0 };
				const char* start = p;
				while (*p != '\0' && *p != ';') ++p;
				std::string tmp(start, static_cast<std::size_t>(p - start));
				if (parse_dotted_quad(tmp.c_str(), a, nullptr)) {
					req.ip_addr[0] = a[0]; req.ip_addr[1] = a[1]; req.ip_addr[2] = a[2]; req.ip_addr[3] = a[3];
					req.ip_mask[0] = 0xFFu; req.ip_mask[1] = 0xFFu; req.ip_mask[2] = 0xFFu; req.ip_mask[3] = 0xFFu;
				}
			}
			else {
				while (*p != '\0' && *p != ';') ++p;
			}
		}
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NFLT(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "operation", format_dec_u32(s.u32_a) });
		r.parsed.push_back({ "rule_id", format_dec_u32(req.rule_id) });
		r.parsed.push_back({ "rule_count", format_dec_u32(req.rule_count) });
		r.parsed.push_back({ "action", format_dec_u32(req.action) });
		r.parsed.push_back({ "direction", format_dec_u32(req.direction) });
		r.parsed.push_back({ "protocol", format_dec_u32(req.protocol) });
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_nsts(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Returns aggregated network counters (no inputs).");
	}

	void run_nsts(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		voyager::detail::net_stats_request req{};
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NSTS(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "bytes_sent", format_dec_u64(req.bytes_sent) });
		r.parsed.push_back({ "bytes_received", format_dec_u64(req.bytes_received) });
		r.parsed.push_back({ "packets_sent", format_dec_u64(req.packets_sent) });
		r.parsed.push_back({ "packets_received", format_dec_u64(req.packets_received) });
		r.parsed.push_back({ "active_connections", format_dec_u32(req.active_connections) });
		r.parsed.push_back({ "capture_active", format_dec_u32(req.capture_active) });
		r.parsed.push_back({ "total_captured", format_dec_u32(req.total_captured) });
		r.parsed.push_back({ "total_dropped", format_dec_u32(req.total_dropped) });
		r.parsed.push_back({ "total_dns_logged", format_dec_u32(req.total_dns_logged) });
		r.parsed.push_back({ "active_filter_rules", format_dec_u32(req.active_filter_rules) });
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_ewfp(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Enumerates registered WFP callouts (classifyFn / notifyFn / flowDeleteFn / owning module).");
	}

	void run_ewfp(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		voyager::detail::wfp_callout_enum_request* req =
			static_cast<voyager::detail::wfp_callout_enum_request*>(std::calloc(1, sizeof(voyager::detail::wfp_callout_enum_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for wfp_callout_enum_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::EWFP(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "callout_count", format_dec_u32(req->callout_count) });
		const std::uint32_t cap = (req->callout_count > 50u) ? 50u : req->callout_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Callout[%u]", i);
			char mod[65];
			std::memcpy(mod, e.owning_module, 64);
			mod[64] = '\0';
			char val[640];
			std::snprintf(val, sizeof(val),
				"id=%u layer=%u flags=%s classify=%s notify=%s flow_del=%s mod_base=%s mod=%s",
				e.callout_id, e.layer_id,
				format_hex_u32(e.flags).c_str(),
				format_hex_u64(e.classify_fn).c_str(),
				format_hex_u64(e.notify_fn).c_str(),
				format_hex_u64(e.flow_delete_fn).c_str(),
				format_hex_u64(e.owning_module_base).c_str(),
				mod);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_gskt(test_lab::state_t& s) {
		ImGui::InputScalar("Target PID (0 = all)", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Walks AFD endpoints owned by the target process.");
	}

	void run_gskt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::socket_handle_enum_request* req =
			static_cast<voyager::detail::socket_handle_enum_request*>(std::calloc(1, sizeof(voyager::detail::socket_handle_enum_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for socket_handle_enum_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->target_pid = s.pid;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::GSKT(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "socket_count", format_dec_u32(req->socket_count) });
		const std::uint32_t cap = (req->socket_count > 50u) ? 50u : req->socket_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Sock[%u]", i);
			char val[512];
			std::snprintf(val, sizeof(val),
				"pid=%u handle=%s afd=%s %s state=%s %s:%u -> %s:%u",
				e.pid,
				format_hex_u64(e.handle_value).c_str(),
				format_hex_u64(e.afd_endpoint_addr).c_str(),
				proto_name(e.protocol),
				tcp_state_name(e.state),
				format_ip(e.local_addr, e.address_family).c_str(),
				e.local_port,
				format_ip(e.remote_addr, e.address_family).c_str(),
				e.remote_port);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_snbf(test_lab::state_t& s) {
		ImGui::InputScalar("Max captures (u32_a, 1-16)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Drains accumulated NDIS NET_BUFFER captures (op=2 query). Use other features to arm a breakpoint first.");
	}

	void run_snbf(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::sniff_net_buffers_request* req =
			static_cast<voyager::detail::sniff_net_buffers_request*>(std::calloc(1, sizeof(voyager::detail::sniff_net_buffers_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for sniff_net_buffers_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->operation = 2u;
		std::uint32_t mx = s.u32_a;
		if (mx == 0u || mx > voyager::detail::SNIFF_MAX_CAPTURES) {
			mx = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_CAPTURES);
		}
		req->max_captures = mx;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::SNBF(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "active", format_dec_u32(req->active) });
		r.parsed.push_back({ "capture_count", format_dec_u32(req->capture_count) });
		std::uint32_t cap = req->capture_count;
		if (cap > 50u) cap = 50u;
		if (cap > static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_CAPTURES)) {
			cap = static_cast<std::uint32_t>(voyager::detail::SNIFF_MAX_CAPTURES);
		}
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& c = req->captures[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Buf[%u]", i);
			char val[160];
			std::snprintf(val, sizeof(val),
				"ts=%llu tid=%llu size=%u",
				static_cast<unsigned long long>(c.timestamp),
				static_cast<unsigned long long>(c.thread_id),
				c.buffer_size);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_dtcp(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Walks the TCPIP.SYS connection table (TCB list, owning_module_base, byte counters).");
	}

	void run_dtcp(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		voyager::detail::tcpip_conn_dump_request* req =
			static_cast<voyager::detail::tcpip_conn_dump_request*>(std::calloc(1, sizeof(voyager::detail::tcpip_conn_dump_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for tcpip_conn_dump_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->target_pid = 0;
		req->filter_protocol = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DTCP(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "connection_count", format_dec_u32(req->connection_count) });
		const std::uint32_t cap = (req->connection_count > 50u) ? 50u : req->connection_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "TCB[%u]", i);
			char val[640];
			std::snprintf(val, sizeof(val),
				"tcb=%s pid=%u %s state=%s %s:%u -> %s:%u in=%llu out=%llu mod=%s",
				format_hex_u64(e.tcb_address).c_str(),
				e.pid,
				proto_name(e.protocol),
				tcp_state_name(e.state),
				format_ip(e.local_addr, e.address_family).c_str(),
				e.local_port,
				format_ip(e.remote_addr, e.address_family).c_str(),
				e.remote_port,
				static_cast<unsigned long long>(e.bytes_in),
				static_cast<unsigned long long>(e.bytes_out),
				format_hex_u64(e.owning_module_base).c_str());
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_nifs(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Enumerates kernel-visible network interfaces (MAC, IPv4/IPv6, MTU, octets).");
	}

	void run_nifs(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		voyager::detail::net_interface_enum* req =
			static_cast<voyager::detail::net_interface_enum*>(std::calloc(1, sizeof(voyager::detail::net_interface_enum)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_interface_enum";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NIFS(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		r.parsed.push_back({ "interface_count", format_dec_u32(req->interface_count) });
		const std::uint32_t cap = (req->interface_count > 50u) ? 50u : req->interface_count;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->interfaces[i];
			char label[24];
			std::snprintf(label, sizeof(label), "If[%u]", i);
			char name_buf[voyager::detail::NET_IF_NAME_LEN + 1];
			std::memcpy(name_buf, e.name, voyager::detail::NET_IF_NAME_LEN);
			name_buf[voyager::detail::NET_IF_NAME_LEN] = '\0';
			char desc_buf[voyager::detail::NET_IF_NAME_LEN + 1];
			std::memcpy(desc_buf, e.description, voyager::detail::NET_IF_NAME_LEN);
			desc_buf[voyager::detail::NET_IF_NAME_LEN] = '\0';
			char val[640];
			std::snprintf(val, sizeof(val),
				"idx=%u type=%u mtu=%u oper=%u mac=%s ipv4=%u.%u.%u.%u/%u.%u.%u.%u speed=%llu in=%llu out=%llu name=%s desc=%s",
				e.if_index, e.if_type, e.mtu, e.oper_status,
				format_mac(e.mac_addr).c_str(),
				e.ipv4_addr[0], e.ipv4_addr[1], e.ipv4_addr[2], e.ipv4_addr[3],
				e.ipv4_mask[0], e.ipv4_mask[1], e.ipv4_mask[2], e.ipv4_mask[3],
				static_cast<unsigned long long>(e.speed),
				static_cast<unsigned long long>(e.in_octets),
				static_cast<unsigned long long>(e.out_octets),
				name_buf, desc_buf);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

	void render_inputs_nfpr(test_lab::state_t& s) {
		char buf[64];
		std::size_t copy = s.text_a.size();
		if (copy >= sizeof(buf)) copy = sizeof(buf) - 1u;
		std::memcpy(buf, s.text_a.data(), copy);
		buf[copy] = '\0';
		if (ImGui::InputText("Remote IPv4 [a.b.c.d[:port]] (text_a)", buf, sizeof(buf))) {
			s.text_a.assign(buf);
		}
		ImGui::InputScalar("Remote port (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		const char* ops[] = { "Start passive capture (op=0)", "Stop (op=1)", "Query results (op=2)" };
		int cur = static_cast<int>(s.u32_b);
		if (cur < 0 || cur > 2) cur = 2;
		if (ImGui::Combo("Operation (u32_b)", &cur, ops, IM_ARRAYSIZE(ops))) {
			s.u32_b = static_cast<std::uint32_t>(cur);
		}
		ImGui::TextDisabled("Passive TCP/IP stack fingerprint. Start capture, generate traffic to/from the endpoint, then Query.");
	}

	void run_nfpr(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		voyager::detail::net_fingerprint_request* req =
			static_cast<voyager::detail::net_fingerprint_request*>(std::calloc(1, sizeof(voyager::detail::net_fingerprint_request)));
		if (req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_fingerprint_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		req->operation = s.u32_b;
		std::uint8_t parsed_ip[4] = { 0, 0, 0, 0 };
		std::uint32_t parsed_port = s.u32_a;
		bool ip_valid = parse_dotted_quad(s.text_a.c_str(), parsed_ip, &parsed_port);
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::NFPR(), req, static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		capture_raw_struct(r, req, sizeof(*req));
		r.bytes_returned = bytes_returned;
		if (!ok) {
			set_fail_from_ioctl(r, bytes_returned);
			std::free(req);
			return;
		}
		char endpoint[64];
		if (ip_valid) {
			std::snprintf(endpoint, sizeof(endpoint), "%u.%u.%u.%u:%u",
				parsed_ip[0], parsed_ip[1], parsed_ip[2], parsed_ip[3], parsed_port);
		} else {
			std::snprintf(endpoint, sizeof(endpoint), "(unparsed) port=%u", parsed_port);
		}
		r.parsed.push_back({ "endpoint_input", std::string(endpoint) });
		r.parsed.push_back({ "operation", format_dec_u32(s.u32_b) });
		r.parsed.push_back({ "result_count", format_dec_u32(req->result_count) });
		std::uint32_t total = req->result_count;
		if (total > voyager::detail::FINGERPRINT_MAX) total = voyager::detail::FINGERPRINT_MAX;
		const std::uint32_t cap = (total > 50u) ? 50u : total;
		for (std::uint32_t i = 0; i < cap; ++i) {
			const auto& e = req->entries[i];
			char label[24];
			std::snprintf(label, sizeof(label), "Fp[%u]", i);
			char os_buf[65];
			std::memcpy(os_buf, e.os_guess, 64);
			os_buf[64] = '\0';
			char val[512];
			std::snprintf(val, sizeof(val),
				"%s ttl=%u win=%u mss=%u wscale=%u df=%u sack=%u nops=%u os=%s",
				format_ip(e.remote_addr, e.address_family).c_str(),
				e.ttl, e.window_size, e.mss, e.window_scale, e.df_flag, e.sack_permitted, e.nop_count,
				os_buf);
			r.parsed.push_back({ std::string(label), std::string(val) });
		}
		r.ntstatus = 0;
		r.ok = true;
		std::free(req);
	}

}

TESTLAB_REGISTER(g_reg_ncon_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NCON - enumerate active network connections",
	"ioctl_codes::NCON() with net_enum_conn_request. Protocol filter: 0=all, 1=TCP (6), 2=UDP (17).",
	&render_inputs_ncon,
	&run_ncon)

TESTLAB_REGISTER(g_reg_ncap_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NCAP - control packet capture (WFP)",
	"ioctl_codes::NCAP() with net_cap_ctrl_request. Operation: 0=Start, 1=Stop, 2=Pause.",
	&render_inputs_ncap,
	&run_ncap)

TESTLAB_REGISTER(g_reg_ncpg_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NCPG - drain captured packets",
	"ioctl_codes::NCPG() with net_cap_get_request. Pulls up to NET_CAP_GET_MAX (32) packets per call.",
	&render_inputs_ncpg,
	&run_ncpg)

TESTLAB_REGISTER(g_reg_ndns_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NDNS - drain DNS query log",
	"ioctl_codes::NDNS() with net_dns_get_request. Up to NET_DNS_GET_MAX (64) entries.",
	&render_inputs_ndns,
	&run_ndns)

TESTLAB_REGISTER(g_reg_nflt_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NFLT - add/remove/clear network filter rule",
	"ioctl_codes::NFLT() with net_filter_rule_request. Parses descriptor 'k=v;k=v' into action/direction/protocol/pid/port/ip/rule_id.",
	&render_inputs_nflt,
	&run_nflt)

TESTLAB_REGISTER(g_reg_nsts_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NSTS - aggregated network stats",
	"ioctl_codes::NSTS() with net_stats_request. Bytes/packets sent+recv, capture counters, DNS counters, filter-rule count.",
	&render_inputs_nsts,
	&run_nsts)

TESTLAB_REGISTER(g_reg_ewfp_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"EWFP - enumerate WFP callouts",
	"ioctl_codes::EWFP() with wfp_callout_enum_request. Returns classifyFn/notifyFn/flowDeleteFn/owning module for each callout.",
	&render_inputs_ewfp,
	&run_ewfp)

TESTLAB_REGISTER(g_reg_gskt_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"GSKT - enumerate socket handles per pid",
	"ioctl_codes::GSKT() with socket_handle_enum_request. Walks AFD endpoints of the target PID (0 = all).",
	&render_inputs_gskt,
	&run_gskt)

TESTLAB_REGISTER(g_reg_snbf_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"SNBF - drain sniffed NDIS NET_BUFFER captures",
	"ioctl_codes::SNBF() with sniff_net_buffers_request (op=2 query). Returns up to SNIFF_MAX_CAPTURES (16) buffers.",
	&render_inputs_snbf,
	&run_snbf)

TESTLAB_REGISTER(g_reg_dtcp_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"DTCP - dump TCPIP connection table",
	"ioctl_codes::DTCP() with tcpip_conn_dump_request. Walks TCPIP.SYS TCB list with owning_module_base and byte counters.",
	&render_inputs_dtcp,
	&run_dtcp)

TESTLAB_REGISTER(g_reg_nifs_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NIFS - enumerate network interfaces",
	"ioctl_codes::NIFS() with net_interface_enum. Returns MAC, IPv4/IPv6, MTU, oper_status, octets per interface.",
	&render_inputs_nifs,
	&run_nifs)

TESTLAB_REGISTER(g_reg_nfpr_netq,
	"network-query",
	test_lab::driver_e::whoswho,
	"NFPR - passive TCP/IP fingerprint",
	"ioctl_codes::NFPR() with net_fingerprint_request. Operation 0=start, 1=stop, 2=query. Endpoint text_a is informational (kernel collects globally).",
	&render_inputs_nfpr,
	&run_nfpr)
