#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

	void push_u64(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	void push_u32(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u", static_cast<unsigned>(v));
		r.parsed.push_back({ label, b });
	}

	void push_u32_hex(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[16];
		std::snprintf(b, sizeof(b), "0x%08X", static_cast<unsigned>(v));
		r.parsed.push_back({ label, b });
	}

	std::string narrow_wide(const std::wstring& w) {
		std::string out;
		out.reserve(w.size());
		for (wchar_t c : w) {
			std::uint32_t cp = static_cast<std::uint32_t>(static_cast<std::uint16_t>(c));
			if (cp < 0x80u) {
				out.push_back(static_cast<char>(cp));
			} else if (cp < 0x800u) {
				out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
				out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
			} else {
				out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
				out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
				out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
			}
		}
		return out;
	}

	std::string make_hv_vendor_string(const char (&buf)[16]) {
		char tmp[17];
		std::size_t n = 0;
		for (; n < sizeof(buf); ++n) {
			unsigned char c = static_cast<unsigned char>(buf[n]);
			if (c == 0) break;
			tmp[n] = (c >= 0x20u && c < 0x7Fu) ? static_cast<char>(c) : '?';
		}
		tmp[n] = '\0';
		return std::string(tmp);
	}

	void render_inputs_sentinel_hb(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Sends one heartbeat to WhosWho and reads back the SentinelBridge state (sentinel_tsc / whoswho_tsc).");
	}

	void run_sentinel_hb(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			return;
		}
		bool ok = device->send_heartbeat();
		r.bytes_returned = device->get_last_heartbeat_bytes_returned();
		r.ntstatus = static_cast<std::int32_t>(device->get_last_heartbeat_error());
		if (!ok) {
			r.ok = false;
			char buf[64];
			std::snprintf(buf, sizeof(buf), "send_heartbeat failed (err=%u)",
				static_cast<unsigned>(device->get_last_heartbeat_error()));
			r.error = buf;
			push_u32_hex(r, "ioctl_code", device->get_last_heartbeat_ioctl_code());
			push_u32_hex(r, "magic", device->get_last_heartbeat_magic());
			return;
		}
		push_u32_hex(r, "ioctl_code", device->get_last_heartbeat_ioctl_code());
		push_u32_hex(r, "magic", device->get_last_heartbeat_magic());
		push_u64(r, "response", device->get_last_heartbeat_response());
		bool bridge_ready = device->sentinel_bridge_ready();
		r.parsed.push_back({ "sentinel_bridge_ready", bridge_ready ? "1" : "0" });
		push_u64(r, "sentinel_ready_since_tsc", device->sentinel_ready_since_tsc());
		push_u32(r, "bytes_returned", r.bytes_returned);
		r.ok = true;
	}

	void render_inputs_sentinel_evidence(test_lab::state_t& s) {
		if (s.u32_a == 0) s.u32_a = 32;
		int v = static_cast<int>(s.u32_a);
		if (ImGui::InputInt("Max events", &v)) {
			if (v < 1) v = 1;
			if (v > static_cast<int>(voyager::detail::DRAIN_DEBUG_EVENTS_CAP)) {
				v = static_cast<int>(voyager::detail::DRAIN_DEBUG_EVENTS_CAP);
			}
			s.u32_a = static_cast<std::uint32_t>(v);
		}
		ImGui::TextDisabled("Drains the kernel debug-event ring (Sentinel-sourced image-load / process create-exit notifications).");
	}

	void run_sentinel_evidence(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			return;
		}
		std::size_t cap = (s.u32_a == 0) ? voyager::detail::DRAIN_DEBUG_EVENTS_CAP
		                                 : static_cast<std::size_t>(s.u32_a);
		if (cap > voyager::detail::DRAIN_DEBUG_EVENTS_CAP) {
			cap = voyager::detail::DRAIN_DEBUG_EVENTS_CAP;
		}
		std::vector<voyager::device_t::debug_event_record> events;
		voyager::device_t::debug_event_drain_stats stats{};
		bool ok = device->drain_debug_events(events, cap, &stats);
		if (!ok) {
			r.ok = false;
			r.error = "drain_debug_events failed";
			return;
		}
		push_u32(r, "returned_count", stats.returned_count);
		push_u32(r, "dropped_since_last_drain", stats.dropped_since_last_drain);
		push_u64(r, "total_dropped", stats.total_dropped);
		push_u64(r, "total_published", stats.total_published);
		for (std::size_t i = 0; i < events.size(); ++i) {
			const auto& e = events[i];
			const char* type_name = "invalid";
			switch (e.type) {
				case voyager::device_t::debug_event_type_e::image_loaded:    type_name = "image_loaded"; break;
				case voyager::device_t::debug_event_type_e::process_created: type_name = "process_created"; break;
				case voyager::device_t::debug_event_type_e::process_exited:  type_name = "process_exited"; break;
				case voyager::device_t::debug_event_type_e::invalid:
				default: type_name = "invalid"; break;
			}
			char label[32];
			char value[512];
			std::string path_utf8 = narrow_wide(e.image_path);
			if (path_utf8.size() > 200) path_utf8.resize(200);
			std::snprintf(label, sizeof(label), "event[%zu].type", i);
			r.parsed.push_back({ label, type_name });
			std::snprintf(label, sizeof(label), "event[%zu].pid", i);
			std::snprintf(value, sizeof(value), "%u", static_cast<unsigned>(e.process_id));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].tid", i);
			std::snprintf(value, sizeof(value), "%u", static_cast<unsigned>(e.thread_id));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].flags", i);
			std::snprintf(value, sizeof(value), "0x%08X", static_cast<unsigned>(e.flags));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].timestamp", i);
			std::snprintf(value, sizeof(value), "%llu", static_cast<unsigned long long>(e.timestamp));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].image_base", i);
			std::snprintf(value, sizeof(value), "0x%016llX", static_cast<unsigned long long>(e.image_base));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].image_size", i);
			std::snprintf(value, sizeof(value), "0x%llX", static_cast<unsigned long long>(e.image_size));
			r.parsed.push_back({ label, value });
			std::snprintf(label, sizeof(label), "event[%zu].image_path", i);
			r.parsed.push_back({ label, path_utf8 });
		}
		r.ok = true;
	}

	void render_inputs_sentinel_tier_a(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Queries the preloaded tier-A driver flag (Sentinel populates this set during its scan).");
	}

	void run_sentinel_tier_a(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			return;
		}
		bool present = false;
		std::uint32_t mask = 0;
		std::uint64_t first_base = 0;
		bool ok = device->tier_a_driver_present_query(present, &mask, &first_base);
		if (!ok) {
			r.ok = false;
			r.error = "tier_a_driver_present_query failed";
			return;
		}
		r.parsed.push_back({ "present_flag", present ? "1" : "0" });
		push_u32_hex(r, "tier_mask", mask);
		char b[32];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(first_base));
		r.parsed.push_back({ "first_driver_base", b });
		r.ok = true;
	}

	void render_inputs_sentinel_hv(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Runs the hypervisor-detection probe (Sentinel cooperates and consumes the result for its anti-VM checks).");
	}

	void run_sentinel_hv(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			return;
		}

		union {
			voyager::detail::hv_detect_request req;
			voyager::detail::hv_detect_result  result;
		} buf{};
		buf.req.flags = voyager::detail::HV_DETECT_FLAG_TESTLAB_SAFE;

		std::uint32_t bytes_returned = 0;
		test_lab_format::testlab_diag_log_step("sentinel", "Sentinel HV Detect", "request_pre",
			"flags=0x%016llX mode=testlab_safe_fingerprint_only",
			static_cast<unsigned long long>(buf.req.flags));
		bool ok = device->send_ioctl_raw(
			ioctl_codes::HVDT(),
			&buf,
			static_cast<std::uint32_t>(sizeof(buf)),
			bytes_returned);
		test_lab_format::testlab_diag_log_step("sentinel", "Sentinel HV Detect", "request_post",
			"ok=%d bytes_returned=%u total_run=%u total_positive=%u is_vm=%u ms_hv_root=%u vendor=\"%.16s\"",
			ok ? 1 : 0,
			bytes_returned,
			static_cast<unsigned>(buf.result.total_run),
			static_cast<unsigned>(buf.result.total_failed),
			static_cast<unsigned>(buf.result.is_virtual_machine),
			static_cast<unsigned>(buf.result.ms_hv_root),
			buf.result.vm_vendor_name);

		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(buf));
		std::memcpy(r.raw.data(), &buf, sizeof(buf));

		if (!ok) {
			DWORD le = GetLastError();
			char err[128];
			std::snprintf(err, sizeof(err),
				"send_ioctl_raw returned false (GetLastError=%lu)", le);
			r.ok = false;
			r.error = err;
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		if (bytes_returned != sizeof(voyager::detail::hv_detect_result)) {
			char err[160];
			std::snprintf(err, sizeof(err),
				"HVDT returned %u bytes, expected %zu",
				bytes_returned,
				sizeof(voyager::detail::hv_detect_result));
			r.ok = false;
			r.error = err;
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		const voyager::detail::hv_detect_result& hv = buf.result;
		r.parsed.push_back({ "mode", "testlab_safe_fingerprint_only" });
		r.parsed.push_back({ "request_flags", "0x0000000000000001" });
		r.parsed.push_back({ "kernel_probe_set", "skipped_by_testlab_safe_flag" });
		r.parsed.push_back({ "is_virtual_machine", hv.is_virtual_machine ? "1" : "0" });
		r.parsed.push_back({ "ms_hv_root", hv.ms_hv_root ? "1" : "0" });
		r.parsed.push_back({ "vm_vendor_name", make_hv_vendor_string(hv.vm_vendor_name) });
		const std::uint32_t vm_hits =
			static_cast<std::uint32_t>(hv.vmf_cpuid_vendor) +
			static_cast<std::uint32_t>(hv.vmf_hyperv_guest) +
			static_cast<std::uint32_t>(hv.vmf_smbios_vm) +
			static_cast<std::uint32_t>(hv.vmf_acpi_vm) +
			static_cast<std::uint32_t>(hv.vmf_pci_vm) +
			static_cast<std::uint32_t>(hv.vmf_disk_vm) +
			static_cast<std::uint32_t>(hv.vmf_mac_vm) +
			static_cast<std::uint32_t>(hv.vmf_registry_vm);
		const std::uint32_t total_positive = static_cast<std::uint32_t>(hv.total_failed);
		const std::uint32_t hv_probe_positive = total_positive >= vm_hits ? total_positive - vm_hits : 0;
		push_u32(r, "total_run", hv.total_run);
		push_u32(r, "total_positive", total_positive);
		push_u32(r, "vm_fingerprint_hits", vm_hits);
		push_u32(r, "hv_probe_positive", hv_probe_positive);
		push_u32(r, "sidt_lock_prefix", hv.sidt_lock_prefix);
		push_u32(r, "sidt_invalid_pf", hv.sidt_invalid_pf);
		push_u32(r, "sidt_tlb_only", hv.sidt_tlb_only);
		push_u32(r, "sidt_timing", hv.sidt_timing);
		push_u32(r, "sidt_compat_mode", hv.sidt_compat_mode);
		push_u32(r, "sidt_noncanonical_gp", hv.sidt_noncanonical_gp);
		push_u32(r, "sidt_noncanonical_ss", hv.sidt_noncanonical_ss);
		push_u32(r, "sidt_cpl3_umip_off", hv.sidt_cpl3_umip_off);
		push_u32(r, "sidt_cpl3_umip_on", hv.sidt_cpl3_umip_on);
		push_u32(r, "lidt_lock_prefix", hv.lidt_lock_prefix);
		push_u32(r, "lidt_invalid_pf", hv.lidt_invalid_pf);
		push_u32(r, "lidt_tlb_only", hv.lidt_tlb_only);
		push_u32(r, "lidt_timing", hv.lidt_timing);
		push_u32(r, "lidt_noncanonical_gp", hv.lidt_noncanonical_gp);
		push_u32(r, "lidt_noncanonical_ss", hv.lidt_noncanonical_ss);
		push_u32(r, "lidt_cpl3_gp", hv.lidt_cpl3_gp);
		push_u32(r, "ve_trigger", hv.ve_trigger);
		push_u32(r, "ve_lbr_stack", hv.ve_lbr_stack);
		push_u32(r, "ve_xsetbv_gp", hv.ve_xsetbv_gp);
		push_u32(r, "ve_cr4_vmxe", hv.ve_cr4_vmxe);
		push_u32(r, "vmf_cpuid_vendor", hv.vmf_cpuid_vendor);
		push_u32(r, "vmf_hyperv_guest", hv.vmf_hyperv_guest);
		push_u32(r, "vmf_smbios_vm", hv.vmf_smbios_vm);
		push_u32(r, "vmf_acpi_vm", hv.vmf_acpi_vm);
		push_u32(r, "vmf_pci_vm", hv.vmf_pci_vm);
		push_u32(r, "vmf_disk_vm", hv.vmf_disk_vm);
		push_u32(r, "vmf_mac_vm", hv.vmf_mac_vm);
		push_u32(r, "vmf_registry_vm", hv.vmf_registry_vm);
		r.ntstatus = 0;
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_sentinel_hb,
	"sentinel", test_lab::driver_e::sentinel,
	"Sentinel HB / TSC", "Heartbeat with SentinelBridge TSC observation",
	&render_inputs_sentinel_hb, &run_sentinel_hb);

TESTLAB_REGISTER(g_reg_sentinel_recu,
	"sentinel", test_lab::driver_e::sentinel,
	"Sentinel Evidence Ring", "Drain debug-event ring (Sentinel-sourced entries)",
	&render_inputs_sentinel_evidence, &run_sentinel_evidence);

TESTLAB_REGISTER(g_reg_sentinel_tira,
	"sentinel", test_lab::driver_e::sentinel,
	"Sentinel Tier-A Query", "Read preloaded tier-A driver flag and mask",
	&render_inputs_sentinel_tier_a, &run_sentinel_tier_a);

TESTLAB_REGISTER(g_reg_sentinel_hvdt,
	"sentinel", test_lab::driver_e::sentinel,
	"Sentinel HV Detect", "Hypervisor detection probe (consumed by Sentinel)",
	&render_inputs_sentinel_hv, &run_sentinel_hv);
