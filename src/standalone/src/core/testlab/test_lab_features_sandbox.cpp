#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

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

	void push_flag_field(test_lab::result_t& r, const char* label, bool present) {
		r.parsed.push_back({ label, present ? std::string("yes") : std::string("no") });
	}

	void describe_flags(test_lab::result_t& r, std::uint32_t flags) {
		push_flag_field(r, "BLOCK_PERSISTENCE",   (flags & voyager::detail::SANDBOX_FLAG_BLOCK_PERSISTENCE)   != 0);
		push_flag_field(r, "BLOCK_DRIVER_INSTALL",(flags & voyager::detail::SANDBOX_FLAG_BLOCK_DRIVER_INSTALL)!= 0);
		push_flag_field(r, "BLOCK_RAW_DISK",      (flags & voyager::detail::SANDBOX_FLAG_BLOCK_RAW_DISK)      != 0);
		push_flag_field(r, "BLOCK_KERNEL_HANDLE", (flags & voyager::detail::SANDBOX_FLAG_BLOCK_KERNEL_HANDLE) != 0);
		push_flag_field(r, "LOG_NETWORK",         (flags & voyager::detail::SANDBOX_FLAG_LOG_NETWORK)         != 0);
		push_flag_field(r, "BLOCK_CHILD_SPAWN",   (flags & voyager::detail::SANDBOX_FLAG_BLOCK_CHILD_SPAWN)   != 0);
	}

	void copy_request_to_raw(test_lab::result_t& r, const voyager::detail::protect_sandbox_request& req) {
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
	}

	void render_inputs_psbx(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Flags (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%08X",
			ImGuiInputTextFlags_CharsHexadecimal);
		if (ImGui::SmallButton("Default (0 -> SANDBOX_FLAG_DEFAULT)")) {
			s.u32_a = 0u;
		}
		ImGui::SameLine();
		if (ImGui::SmallButton("All Blocks + Net Log")) {
			s.u32_a =
				voyager::detail::SANDBOX_FLAG_BLOCK_PERSISTENCE
				| voyager::detail::SANDBOX_FLAG_BLOCK_DRIVER_INSTALL
				| voyager::detail::SANDBOX_FLAG_BLOCK_RAW_DISK
				| voyager::detail::SANDBOX_FLAG_BLOCK_KERNEL_HANDLE
				| voyager::detail::SANDBOX_FLAG_LOG_NETWORK
				| voyager::detail::SANDBOX_FLAG_BLOCK_CHILD_SPAWN;
		}
		ImGui::TextDisabled("Marks the PID as malware-safe; kernel enforces the selected sandbox restrictions.");
	}

	void run_psbx(test_lab::state_t& s, test_lab::result_t& r) {
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

		voyager::detail::protect_sandbox_request req{};
		req.pid = s.pid;
		req.flags = (s.u32_a == 0u) ? voyager::detail::SANDBOX_FLAG_DEFAULT : s.u32_a;

		std::uint64_t denials = 0;
		bool ok = device->protect_sandbox_pid(s.pid, s.u32_a, &denials);

		req.result = ok ? 1u : 0u;
		req.denials_so_far = denials;
		copy_request_to_raw(r, req);
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(req));

		if (!ok) {
			r.error = "protect_sandbox_pid returned false (driver rejected, magic/session mismatch, or kernel table full)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
			r.ok = false;
			return;
		}

		push_u32_field(r, "Registered PID", s.pid);
		push_u32_field(r, "Applied Flags", req.flags);
		describe_flags(r, req.flags);
		push_u64_field(r, "Denials So Far", denials);
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_usbx(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Releases the PID from the malware-safe sandbox table (no-op if not registered).");
	}

	void run_usbx(test_lab::state_t& s, test_lab::result_t& r) {
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

		voyager::detail::protect_sandbox_request req{};
		req.pid = s.pid;
		req.flags = 0;

		std::uint64_t denials = 0;
		bool ok = device->unprotect_sandbox_pid(s.pid, &denials);

		req.result = ok ? 1u : 0u;
		req.denials_so_far = denials;
		copy_request_to_raw(r, req);
		r.bytes_returned = static_cast<std::uint32_t>(sizeof(req));

		if (!ok) {
			r.error = "unprotect_sandbox_pid returned false (pid not registered or driver rejected)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			return;
		}

		push_u32_field(r, "Unregistered PID", s.pid);
		push_u64_field(r, "Denials Recorded", denials);
		r.ntstatus = 0;
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_psbx, "sandbox", test_lab::driver_e::whoswho, "PSBX",
	"Register a PID with the malware-safe sandbox table. u32_a = flag bitmap (0 = SANDBOX_FLAG_DEFAULT).",
	&render_inputs_psbx, &run_psbx);

TESTLAB_REGISTER(g_reg_usbx, "sandbox", test_lab::driver_e::whoswho, "USBX",
	"Unregister a PID from the malware-safe sandbox table; reports total denials accrued while protected.",
	&render_inputs_usbx, &run_usbx);
