#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	std::string make_vendor_string(const char (&buf)[16]) {
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

	void render_inputs_hvdt(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("Run the kernel hypervisor-detection probe.");
		ImGui::TextDisabled("Combines CPUID/SIDT/LIDT/timing/VMF heuristics into a single result.");
	}

	void run_hvdt(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}

		union {
			voyager::detail::hv_detect_request req;
			voyager::detail::hv_detect_result  result;
		} buf{};
		buf.req.flags = 0;

		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(
			ioctl_codes::HVDT(), &buf,
			static_cast<std::uint32_t>(sizeof(buf)), bytes_returned);

		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(buf));
		std::memcpy(r.raw.data(), &buf, sizeof(buf));

		if (!ok) {
			DWORD le = GetLastError();
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			char err[128];
			std::snprintf(err, sizeof(err),
				"send_ioctl_raw returned false (GetLastError=%lu)", le);
			r.error = err;
			r.ok = false;
			return;
		}

		r.ntstatus = 0;
		r.ok = true;

		const voyager::detail::hv_detect_result& d = buf.result;
		r.parsed.push_back({ "is_virtual_machine", d.is_virtual_machine ? "true" : "false" });
		r.parsed.push_back({ "ms_hv_root", d.ms_hv_root ? "true" : "false" });
		r.parsed.push_back({ "vm_vendor_name", make_vendor_string(d.vm_vendor_name) });
		r.parsed.push_back({ "total_run", std::to_string(static_cast<unsigned>(d.total_run)) });
		r.parsed.push_back({ "total_failed", std::to_string(static_cast<unsigned>(d.total_failed)) });

		r.parsed.push_back({ "sidt.lock_prefix", std::to_string(static_cast<unsigned>(d.sidt_lock_prefix)) });
		r.parsed.push_back({ "sidt.invalid_pf", std::to_string(static_cast<unsigned>(d.sidt_invalid_pf)) });
		r.parsed.push_back({ "sidt.tlb_only", std::to_string(static_cast<unsigned>(d.sidt_tlb_only)) });
		r.parsed.push_back({ "sidt.timing", std::to_string(static_cast<unsigned>(d.sidt_timing)) });
		r.parsed.push_back({ "sidt.compat_mode", std::to_string(static_cast<unsigned>(d.sidt_compat_mode)) });
		r.parsed.push_back({ "sidt.noncanonical_gp", std::to_string(static_cast<unsigned>(d.sidt_noncanonical_gp)) });
		r.parsed.push_back({ "sidt.noncanonical_ss", std::to_string(static_cast<unsigned>(d.sidt_noncanonical_ss)) });
		r.parsed.push_back({ "sidt.cpl3_umip_off", std::to_string(static_cast<unsigned>(d.sidt_cpl3_umip_off)) });
		r.parsed.push_back({ "sidt.cpl3_umip_on", std::to_string(static_cast<unsigned>(d.sidt_cpl3_umip_on)) });

		r.parsed.push_back({ "lidt.lock_prefix", std::to_string(static_cast<unsigned>(d.lidt_lock_prefix)) });
		r.parsed.push_back({ "lidt.invalid_pf", std::to_string(static_cast<unsigned>(d.lidt_invalid_pf)) });
		r.parsed.push_back({ "lidt.tlb_only", std::to_string(static_cast<unsigned>(d.lidt_tlb_only)) });
		r.parsed.push_back({ "lidt.timing", std::to_string(static_cast<unsigned>(d.lidt_timing)) });
		r.parsed.push_back({ "lidt.noncanonical_gp", std::to_string(static_cast<unsigned>(d.lidt_noncanonical_gp)) });
		r.parsed.push_back({ "lidt.noncanonical_ss", std::to_string(static_cast<unsigned>(d.lidt_noncanonical_ss)) });
		r.parsed.push_back({ "lidt.cpl3_gp", std::to_string(static_cast<unsigned>(d.lidt_cpl3_gp)) });

		r.parsed.push_back({ "ve.trigger", std::to_string(static_cast<unsigned>(d.ve_trigger)) });
		r.parsed.push_back({ "ve.lbr_stack", std::to_string(static_cast<unsigned>(d.ve_lbr_stack)) });
		r.parsed.push_back({ "ve.xsetbv_gp", std::to_string(static_cast<unsigned>(d.ve_xsetbv_gp)) });
		r.parsed.push_back({ "ve.cr4_vmxe", std::to_string(static_cast<unsigned>(d.ve_cr4_vmxe)) });

		r.parsed.push_back({ "vmf.cpuid_vendor", std::to_string(static_cast<unsigned>(d.vmf_cpuid_vendor)) });
		r.parsed.push_back({ "vmf.hyperv_guest", std::to_string(static_cast<unsigned>(d.vmf_hyperv_guest)) });
		r.parsed.push_back({ "vmf.smbios_vm", std::to_string(static_cast<unsigned>(d.vmf_smbios_vm)) });
		r.parsed.push_back({ "vmf.acpi_vm", std::to_string(static_cast<unsigned>(d.vmf_acpi_vm)) });
		r.parsed.push_back({ "vmf.pci_vm", std::to_string(static_cast<unsigned>(d.vmf_pci_vm)) });
		r.parsed.push_back({ "vmf.disk_vm", std::to_string(static_cast<unsigned>(d.vmf_disk_vm)) });
		r.parsed.push_back({ "vmf.mac_vm", std::to_string(static_cast<unsigned>(d.vmf_mac_vm)) });
		r.parsed.push_back({ "vmf.registry_vm", std::to_string(static_cast<unsigned>(d.vmf_registry_vm)) });
	}

}

TESTLAB_REGISTER(g_reg_hvdt,
	"hv-detect",
	test_lab::driver_e::whoswho,
	"HVDT",
	"Run kernel hypervisor-detection probe (CPUID/SIDT/LIDT/timing/VMF).",
	&render_inputs_hvdt,
	&run_hvdt);
