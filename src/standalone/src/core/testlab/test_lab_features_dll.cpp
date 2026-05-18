#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	const char* dprt_op_label(std::uint32_t op) {
		switch (op) {
			case voyager::detail::DPRT_OP_REGISTER:   return "REGISTER";
			case voyager::detail::DPRT_OP_QUERY:      return "QUERY";
			case voyager::detail::DPRT_OP_UNREGISTER: return "UNREGISTER";
			default: return "UNKNOWN";
		}
	}

	const char* dprt_status_label(std::uint32_t status) {
		switch (status) {
			case 0: return "INACTIVE";
			case voyager::detail::DPRT_STATUS_ACTIVE:   return "ACTIVE";
			case voyager::detail::DPRT_STATUS_TAMPERED: return "TAMPERED";
			case voyager::detail::DPRT_STATUS_DEBUGGER: return "DEBUGGER";
			default: return "UNKNOWN";
		}
	}

	void push_u32_hex(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u (0x%08X)", v, v);
		r.parsed.push_back({ label, b });
	}

	void push_u64_hex(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[40];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	void render_inputs_dprt(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");

		const char* items[] = { "REGISTER (0)", "QUERY (1)", "UNREGISTER (2)" };
		int sel = 1;
		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER)   sel = 0;
		else if (s.u32_a == voyager::detail::DPRT_OP_QUERY)      sel = 1;
		else if (s.u32_a == voyager::detail::DPRT_OP_UNREGISTER) sel = 2;
		if (ImGui::Combo("Operation", &sel, items, IM_ARRAYSIZE(items))) {
			if (sel == 0) s.u32_a = voyager::detail::DPRT_OP_REGISTER;
			else if (sel == 1) s.u32_a = voyager::detail::DPRT_OP_QUERY;
			else if (sel == 2) s.u32_a = voyager::detail::DPRT_OP_UNREGISTER;
		}

		char name_buf[260];
		std::snprintf(name_buf, sizeof(name_buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("DLL name pattern (informational)", name_buf, sizeof(name_buf))) {
			s.text_a.assign(name_buf);
		}

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			ImGui::InputScalar("module_base (u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::InputScalar("text_section_va (addr)", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::InputScalar("text size (size)",    ImGuiDataType_U32, &s.size,  nullptr, nullptr, "%u");
			ImGui::InputScalar("check_interval (u32_b, ms)", ImGuiDataType_U32, &s.u32_b, nullptr, nullptr, "%u");
			char hex_buf[64];
			std::snprintf(hex_buf, sizeof(hex_buf), "%s", s.text_b.c_str());
			if (ImGui::InputText("expected_hash hex (text_b)", hex_buf, sizeof(hex_buf), ImGuiInputTextFlags_CharsHexadecimal)) {
				s.text_b.assign(hex_buf);
			}
		}
		ImGui::TextDisabled("Note: kernel dll_protect struct has no name-pattern field; protection keys on (pid, module_base, text_va) text-section hash. text_a is preserved for protocol/log use.");
	}

	void run_dprt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		std::uint64_t expected_hash = 0;
		if (!s.text_b.empty()) {
			const char* p = s.text_b.c_str();
			if ((p[0] == '0') && (p[1] == 'x' || p[1] == 'X')) p += 2;
			std::uint64_t acc = 0;
			bool any = false;
			while (*p) {
				char c = *p++;
				std::uint64_t d = 0;
				if (c >= '0' && c <= '9') d = static_cast<std::uint64_t>(c - '0');
				else if (c >= 'a' && c <= 'f') d = static_cast<std::uint64_t>(10 + (c - 'a'));
				else if (c >= 'A' && c <= 'F') d = static_cast<std::uint64_t>(10 + (c - 'A'));
				else continue;
				acc = (acc << 4) | d;
				any = true;
			}
			if (any) expected_hash = acc;
		}

		voyager::detail::dll_protect_request req{};
		req.operation         = s.u32_a;
		req.pid               = s.pid;
		req.module_base       = s.u64_a;
		req.text_section_va   = s.addr;
		req.text_section_size = s.size;
		req.expected_hash     = expected_hash;
		req.check_interval    = s.u32_b;

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			if (s.pid == 0) {
				r.ok = false;
				r.error = "REGISTER requires a non-zero PID";
				return;
			}
			if (s.addr == 0 || s.size == 0 || expected_hash == 0) {
				r.ok = false;
				r.error = "REGISTER requires text_section_va, text size and expected_hash to be non-zero";
				return;
			}
		}

		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &req,
			static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.ok = false;
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		r.parsed.push_back({ "operation", dprt_op_label(req.operation) });
		push_u32_hex(r, "pid",            req.pid);
		push_u64_hex(r, "module_base",    req.module_base);
		push_u64_hex(r, "text_section_va",   req.text_section_va);
		push_u32_hex(r, "text_section_size", req.text_section_size);
		push_u64_hex(r, "expected_hash",  req.expected_hash);
		push_u64_hex(r, "current_hash",   req.current_hash);
		r.parsed.push_back({ "status", dprt_status_label(req.status) });
		push_u32_hex(r, "check_interval_ms", req.check_interval);
		push_u64_hex(r, "last_check_tsc", req.last_check_tsc);
		if (!s.text_a.empty()) {
			r.parsed.push_back({ "name_pattern (informational)", s.text_a });
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_dprt, "dll", test_lab::driver_e::whoswho, "DPRT",
	"DLL load protect register/query/unregister (kernel hashes a target module's .text section per PID).",
	&render_inputs_dprt, &run_dprt);
