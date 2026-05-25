#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

	constexpr std::uint16_t kAddressFamilyInet  = 2;
	constexpr std::uint16_t kAddressFamilyInet6 = 23;
	constexpr std::uint8_t  kProtoTcp           = 6;
	constexpr std::uint8_t  kProtoUdp           = 17;
	constexpr std::uint8_t  kProtoIcmp          = 1;
	constexpr std::uint8_t  kProtoIcmpV6        = 58;
	constexpr std::uint32_t kVisiblePacketCap   = 50u;
	constexpr std::uint32_t kDefaultRingPull    = 256u;
	std::mutex g_bootstrap_mtx;
	std::vector<std::uint32_t> g_bootstrap_pids;

	bool remember_bootstrap_pid(std::uint32_t pid) {
		std::lock_guard<std::mutex> lk(g_bootstrap_mtx);
		for (std::uint32_t existing : g_bootstrap_pids) {
			if (existing == pid)
				return false;
		}
		g_bootstrap_pids.push_back(pid);
		return true;
	}

	bool forget_bootstrap_pid(std::uint32_t pid) {
		std::lock_guard<std::mutex> lk(g_bootstrap_mtx);
		for (auto it = g_bootstrap_pids.begin(); it != g_bootstrap_pids.end(); ++it) {
			if (*it == pid) {
				g_bootstrap_pids.erase(it);
				return true;
			}
		}
		return false;
	}

	void cleanup_bootstrap_pid(std::uint32_t pid) {
		if (!device || !device->is_connected())
			return;
		if (!forget_bootstrap_pid(pid))
			return;
		device->net_log_register_pid(pid, false);
		std::uint64_t unreg_denials = 0;
		device->unprotect_sandbox_pid(pid, &unreg_denials);
	}

	void push_u32_field(test_lab::result_t& r, const char* label, std::uint32_t value) {
		char buf[40];
		std::snprintf(buf, sizeof(buf), "%u (0x%08X)", value, value);
		r.parsed.push_back({ label, buf });
	}

	void push_u64_field(test_lab::result_t& r, const char* label, std::uint64_t value) {
		char buf[40];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(value));
		r.parsed.push_back({ label, buf });
	}

	const char* proto_name(std::uint8_t proto) {
		switch (proto) {
			case kProtoTcp:    return "tcp";
			case kProtoUdp:    return "udp";
			case kProtoIcmp:   return "icmp";
			case kProtoIcmpV6: return "icmpv6";
			default:           return "ip";
		}
	}

	void format_address(char* out, std::size_t out_size,
		std::uint16_t family, const std::uint8_t addr[16]) {
		if (family == kAddressFamilyInet) {
			std::snprintf(out, out_size, "%u.%u.%u.%u",
				static_cast<unsigned>(addr[0]),
				static_cast<unsigned>(addr[1]),
				static_cast<unsigned>(addr[2]),
				static_cast<unsigned>(addr[3]));
			return;
		}
		if (family == kAddressFamilyInet6) {
			std::snprintf(out, out_size,
				"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
				static_cast<unsigned>(addr[0]),  static_cast<unsigned>(addr[1]),
				static_cast<unsigned>(addr[2]),  static_cast<unsigned>(addr[3]),
				static_cast<unsigned>(addr[4]),  static_cast<unsigned>(addr[5]),
				static_cast<unsigned>(addr[6]),  static_cast<unsigned>(addr[7]),
				static_cast<unsigned>(addr[8]),  static_cast<unsigned>(addr[9]),
				static_cast<unsigned>(addr[10]), static_cast<unsigned>(addr[11]),
				static_cast<unsigned>(addr[12]), static_cast<unsigned>(addr[13]),
				static_cast<unsigned>(addr[14]), static_cast<unsigned>(addr[15]));
			return;
		}
		std::snprintf(out, out_size, "fam=%u", static_cast<unsigned>(family));
	}

	const char* direction_arrow(std::uint8_t direction) {
		return (direction == 0) ? "<-" : "->";
	}

	void render_inputs_nlog(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Ring Hint (u32_a, non-zero = register)", ImGuiDataType_U32, &s.u32_a,
			nullptr, nullptr, "%u");
		if (ImGui::SmallButton("Enable (u32_a=1)")) {
			s.u32_a = 1u;
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("Disable (u32_a=0)")) {
			s.u32_a = 0u;
		}
		ImGui::TextDisabled("u32_a != 0 enables per-pid network logging; 0 disables it. "
			"Ring capacity is fixed kernel-side (NET_PKT_PULL_RING_CAPACITY).");
	}

	void run_nlog(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		if (s.pid == 0) {
			r.error = "pid must be non-zero";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			r.ok = false;
			return;
		}

		const bool enable = (s.u32_a != 0u);
		bool we_registered_for_test = false;
		if (enable) {
			std::uint64_t reg_denials = 0;
			const std::uint32_t reg_flags = voyager::detail::SANDBOX_FLAG_LOG_NETWORK;
			if (device->protect_sandbox_pid(s.pid, reg_flags, &reg_denials)) {
				we_registered_for_test = true;
			}
		}

		voyager::detail::net_log_register_request req{};
		req.pid = s.pid;
		req.operation = enable ? 1u : 0u;

		bool ok = device->net_log_register_pid(s.pid, enable);

		req.result = ok ? 1u : 0u;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(req));

		if (!ok) {
			if (we_registered_for_test) {
				std::uint64_t unreg_denials = 0;
				device->unprotect_sandbox_pid(s.pid, &unreg_denials);
			}
			r.error = enable
				? "net_log_register_pid(enable) returned false (pid not in sandbox table, ring alloc failed, or driver rejected)"
				: "net_log_register_pid(disable) returned false (pid not registered or driver rejected)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.ok = false;
			return;
		}

		if (enable && we_registered_for_test) {
			remember_bootstrap_pid(s.pid);
		} else if (!enable) {
			cleanup_bootstrap_pid(s.pid);
		}

		push_u32_field(r, "PID", s.pid);
		r.parsed.push_back({ "Operation", enable ? std::string("enable") : std::string("disable") });
		push_u32_field(r, "Ring Capacity (kernel)", voyager::detail::NET_PKT_PULL_RING_CAPACITY);
		push_u32_field(r, "Payload Retain (bytes)", voyager::detail::NET_PKT_PULL_PAYLOAD_RETAIN);
		if (we_registered_for_test) {
			r.parsed.push_back({ "Bootstrap", "self-PSBX/USBX (LOG_NETWORK flag)" });
		}
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_npkt(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Max Packets (u32_a, 0 = ring max)", ImGuiDataType_U32, &s.u32_a,
			nullptr, nullptr, "%u");
		if (ImGui::SmallButton("256")) s.u32_a = 256u;
		ImGui::SameLine();
		if (ImGui::SmallButton("1024")) s.u32_a = 1024u;
		ImGui::SameLine();
		if (ImGui::SmallButton("Ring Max")) s.u32_a = 0u;
		ImGui::TextDisabled("Drains buffered packets for the pid. Only the first 50 are listed; the full payload set "
			"is in the raw view.");
	}

	void run_npkt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		if (s.pid == 0) {
			r.error = "pid must be non-zero";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			r.ok = false;
			return;
		}

		std::uint32_t max_records = (s.u32_a == 0u) ? kDefaultRingPull : s.u32_a;
		if (max_records > voyager::detail::NET_PKT_PULL_RING_CAPACITY) {
			max_records = voyager::detail::NET_PKT_PULL_RING_CAPACITY;
		}

		std::vector<voyager::detail::net_packet_record> records;
		std::uint64_t dropped_since_last_pull = 0;
		bool ok = false;
		std::uint32_t attempts = 0;
		for (std::uint32_t attempt = 0; attempt < 16u; ++attempt) {
			++attempts;
			records.clear();
			dropped_since_last_pull = 0;
			ok = device->malware_safe_pull_packets(s.pid, max_records, records, &dropped_since_last_pull);
			if (!ok || !records.empty())
				break;
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}

		const std::size_t header_size = sizeof(voyager::detail::net_packet_pull_response_header);
		const std::size_t record_bytes = records.size() * sizeof(voyager::detail::net_packet_record);
		r.raw.resize(header_size + record_bytes);
		voyager::detail::net_packet_pull_response_header hdr{};
		hdr.magic = voyager::detail::NET_PKT_PULL_RESP_MAGIC;
		hdr.record_count = static_cast<std::uint32_t>(records.size());
		hdr.dropped_since_last_pull = dropped_since_last_pull;
		std::memcpy(r.raw.data(), &hdr, header_size);
		if (record_bytes > 0) {
			std::memcpy(r.raw.data() + header_size, records.data(), record_bytes);
		}
		r.bytes_returned = static_cast<std::uint32_t>(r.raw.size());

		if (!ok) {
			cleanup_bootstrap_pid(s.pid);
			r.error = "malware_safe_pull_packets returned false (pid not registered for net logging or driver rejected)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			return;
		}

		push_u32_field(r, "PID", s.pid);
		push_u32_field(r, "Requested Max", max_records);
		push_u32_field(r, "Pull Attempts", attempts);
		push_u32_field(r, "Records Returned", static_cast<std::uint32_t>(records.size()));
		push_u64_field(r, "Dropped Since Last Pull", dropped_since_last_pull);
		if (records.empty()) {
			cleanup_bootstrap_pid(s.pid);
			r.parsed.push_back({ "Packet Availability", "ring empty after successful drain" });
			r.ntstatus = 0;
			r.ok = true;
			return;
		}

		const std::uint32_t visible = (records.size() > kVisiblePacketCap)
			? kVisiblePacketCap
			: static_cast<std::uint32_t>(records.size());

		char label[24];
		char value[192];
		char local_addr_buf[64];
		char remote_addr_buf[64];

		for (std::uint32_t i = 0; i < visible; ++i) {
			const auto& rec = records[i];
			format_address(local_addr_buf, sizeof(local_addr_buf), rec.address_family, rec.local_addr);
			format_address(remote_addr_buf, sizeof(remote_addr_buf), rec.address_family, rec.remote_addr);
			const char* proto = proto_name(rec.protocol);
			const char* arrow = direction_arrow(rec.direction);
			const bool truncated = (rec.flags & voyager::detail::NET_PKT_FLAG_TRUNCATED) != 0;
			std::snprintf(label, sizeof(label), "Pkt[%u]", i);
			std::snprintf(value, sizeof(value),
				"%s %s:%u %s %s:%u len=%u%s",
				proto,
				local_addr_buf,
				static_cast<unsigned>(rec.local_port),
				arrow,
				remote_addr_buf,
				static_cast<unsigned>(rec.remote_port),
				rec.payload_len,
				truncated ? " [truncated]" : "");
			r.parsed.push_back({ std::string(label), std::string(value) });
		}

		if (records.size() > visible) {
			char overflow_label[24];
			char overflow_value[64];
			std::snprintf(overflow_label, sizeof(overflow_label), "Pkt[%u..%zu]",
				visible, records.size() - 1);
			std::snprintf(overflow_value, sizeof(overflow_value),
				"(%zu additional packets in raw view)", records.size() - visible);
			r.parsed.push_back({ std::string(overflow_label), std::string(overflow_value) });
		}

		r.ntstatus = 0;
		r.ok = true;
		cleanup_bootstrap_pid(s.pid);
	}

}

TESTLAB_REGISTER(g_reg_nlog, "net-logging", test_lab::driver_e::whoswho, "NLOG",
	"Register / unregister a sandboxed PID for per-process network packet capture. u32_a != 0 enables, 0 disables.",
	&render_inputs_nlog, &run_nlog);

TESTLAB_REGISTER(g_reg_npkt, "net-logging", test_lab::driver_e::whoswho, "NPKT",
	"Drain buffered network packets for the pid. u32_a caps max records (0 = ring max). First 50 shown; rest in raw.",
	&render_inputs_npkt, &run_npkt);
