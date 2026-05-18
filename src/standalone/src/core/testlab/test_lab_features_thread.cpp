#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	void push_hex_field(test_lab::result_t& r, const char* label, std::uint64_t value) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(value));
		r.parsed.push_back({ label, buf });
	}

	void push_u32_field(test_lab::result_t& r, const char* label, std::uint32_t value) {
		char buf[24];
		std::snprintf(buf, sizeof(buf), "%u (0x%08X)", value, value);
		r.parsed.push_back({ label, buf });
	}

	void render_inputs_tctx(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("TID", ImGuiDataType_U32, &s.tid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Captures GPR / RIP / RFLAGS / DR0-DR7 for the target thread.");
	}

	void run_tctx(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		voyager::detail::thread_ctx_request req{};
		req.pid = s.pid;
		req.tid = s.tid;
		req.should_set = 0;
		req.padding = 0;
		req.register_mask = 0xFFFFFFFFFFFFFFFFull;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::TCTX(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_u32_field(r, "PID", req.pid);
		push_u32_field(r, "TID", req.tid);
		push_hex_field(r, "RIP", req.rip);
		push_hex_field(r, "RSP", req.rsp);
		push_hex_field(r, "RBP", req.rbp);
		push_hex_field(r, "RAX", req.rax);
		push_hex_field(r, "RBX", req.rbx);
		push_hex_field(r, "RCX", req.rcx);
		push_hex_field(r, "RDX", req.rdx);
		push_hex_field(r, "RSI", req.rsi);
		push_hex_field(r, "RDI", req.rdi);
		push_hex_field(r, "R8",  req.r8);
		push_hex_field(r, "R9",  req.r9);
		push_hex_field(r, "R10", req.r10);
		push_hex_field(r, "R11", req.r11);
		push_hex_field(r, "R12", req.r12);
		push_hex_field(r, "R13", req.r13);
		push_hex_field(r, "R14", req.r14);
		push_hex_field(r, "R15", req.r15);
		push_hex_field(r, "RFLAGS", req.rflags);
		push_hex_field(r, "CS", req.cs);
		push_hex_field(r, "SS", req.ss);
		push_hex_field(r, "DR0", req.dr0);
		push_hex_field(r, "DR1", req.dr1);
		push_hex_field(r, "DR2", req.dr2);
		push_hex_field(r, "DR3", req.dr3);
		push_hex_field(r, "DR6", req.dr6);
		push_hex_field(r, "DR7", req.dr7);
		r.ok = true;
	}

	void render_inputs_tenum(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Lists up to 256 threads (TID, state, RIP) belonging to the process.");
	}

	const char* thread_state_to_string(std::uint32_t state) {
		switch (state) {
			case 0: return "Initialized";
			case 1: return "Ready";
			case 2: return "Running";
			case 3: return "Standby";
			case 4: return "Terminated";
			case 5: return "Waiting";
			case 6: return "Transition";
			case 7: return "DeferredReady";
			case 8: return "GateWaitObsolete";
			case 9: return "WaitingForProcessInSwap";
			default: return "Unknown";
		}
	}

	void run_tenum(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		voyager::detail::thread_enum_request req{};
		req.pid = s.pid;
		req.thread_count = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::TENUM(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		std::uint32_t count = req.thread_count;
		if (count > voyager::detail::MAX_ENUM_THREADS) {
			count = static_cast<std::uint32_t>(voyager::detail::MAX_ENUM_THREADS);
		}
		push_u32_field(r, "PID", req.pid);
		push_u32_field(r, "Thread Count", count);
		char label[32];
		char value[96];
		for (std::uint32_t i = 0; i < count; ++i) {
			std::snprintf(label, sizeof(label), "Thread #%u", i);
			std::snprintf(value, sizeof(value), "TID 0x%08X  state=%s  rip=0x%016llX",
				req.entries[i].tid,
				thread_state_to_string(req.entries[i].state),
				static_cast<unsigned long long>(req.entries[i].rip));
			r.parsed.push_back({ std::string(label), std::string(value) });
		}
		r.ok = true;
	}

	void render_inputs_tsr(test_lab::state_t& s) {
		ImGui::InputScalar("TID", ImGuiDataType_U32, &s.tid, nullptr, nullptr, "%u");
		const char* items[] = { "Suspend (u32_a=1)", "Resume (u32_a=0)" };
		int sel = (s.u32_a == 1u) ? 0 : 1;
		ImGui::Combo("Action", &sel, items, IM_ARRAYSIZE(items));
		s.u32_a = (sel == 0) ? 1u : 0u;
		ImGui::TextDisabled("Driver returns the previous suspend count.");
	}

	void run_tsr(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		voyager::detail::suspend_resume_request req{};
		req.tid = s.tid;
		req.should_resume = (s.u32_a == 0u) ? 1u : 0u;
		req.previous_count = 0;
		req.padding = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::TSR(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_u32_field(r, "TID", req.tid);
		r.parsed.push_back({ "Action", (s.u32_a == 1u) ? std::string("Suspend") : std::string("Resume") });
		push_u32_field(r, "Previous Count", req.previous_count);
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_tctx, "thread", test_lab::driver_e::whoswho, "TCTX",
	"Capture full thread CONTEXT (GPR/RIP/RFLAGS/DR0-DR7) for a given PID/TID.",
	&render_inputs_tctx, &run_tctx);

TESTLAB_REGISTER(g_reg_tenum, "thread", test_lab::driver_e::whoswho, "TENUM",
	"Enumerate up to 256 threads in a process (TID, state, RIP).",
	&render_inputs_tenum, &run_tenum);

TESTLAB_REGISTER(g_reg_tsr, "thread", test_lab::driver_e::whoswho, "TSR",
	"Suspend (u32_a=1) or resume (u32_a=0) a thread by TID.",
	&render_inputs_tsr, &run_tsr);
