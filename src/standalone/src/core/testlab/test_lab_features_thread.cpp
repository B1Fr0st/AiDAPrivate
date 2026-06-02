#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

	void push_u64_dec_field(test_lab::result_t& r, const char* label, std::uint64_t value) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(value));
		r.parsed.push_back({ label, buf });
	}

	void push_bool_field(test_lab::result_t& r, const char* label, bool value) {
		r.parsed.push_back({ label, value ? "1" : "0" });
	}

	void push_text_field(test_lab::result_t& r, const char* label, const std::string& value) {
		r.parsed.push_back({ label, value });
	}

	const char* thread_state_to_string(std::uint32_t state);

	bool find_thread_snapshot(std::uint32_t pid, std::uint32_t tid, driver_bridge::thread_info_t& out) {
		if (pid == 0 || tid == 0)
			return false;
		auto threads = driver_bridge::enumerate_threads_for(pid);
		for (const auto& th : threads) {
			if (th.tid == tid) {
				out = th;
				return true;
			}
		}
		return false;
	}

	void push_thread_snapshot(test_lab::result_t& r, const char* label, bool found, const driver_bridge::thread_info_t& th) {
		char buf[160];
		std::snprintf(buf, sizeof(buf),
			"found=%u owner_pid=%u tid=%u state=%s rip=0x%016llX priority=%d",
			found ? 1u : 0u,
			th.owner_pid,
			th.tid,
			thread_state_to_string(th.state),
			static_cast<unsigned long long>(th.rip),
			th.priority);
		r.parsed.push_back({ label, buf });
	}

	void copy_context_to_request(voyager::detail::thread_ctx_request& req, const voyager::device_t::thread_context& ctx) {
		req.rax = ctx.rax; req.rbx = ctx.rbx; req.rcx = ctx.rcx; req.rdx = ctx.rdx;
		req.rsi = ctx.rsi; req.rdi = ctx.rdi; req.rbp = ctx.rbp; req.rsp = ctx.rsp;
		req.r8 = ctx.r8; req.r9 = ctx.r9; req.r10 = ctx.r10; req.r11 = ctx.r11;
		req.r12 = ctx.r12; req.r13 = ctx.r13; req.r14 = ctx.r14; req.r15 = ctx.r15;
		req.rip = ctx.rip; req.rflags = ctx.rflags;
		req.cs = ctx.cs; req.ss = ctx.ss;
		req.dr0 = ctx.dr0; req.dr1 = ctx.dr1; req.dr2 = ctx.dr2; req.dr3 = ctx.dr3;
		req.dr6 = ctx.dr6; req.dr7 = ctx.dr7;
	}

	void push_context_fields(test_lab::result_t& r, const voyager::detail::thread_ctx_request& req) {
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
		const std::uint32_t attached_pid = driver_bridge::attached_pid();
		const std::uint32_t device_pid = device->get_process_id();
		driver_bridge::thread_info_t before{};
		driver_bridge::thread_info_t after{};
		const bool before_found = find_thread_snapshot(s.pid, s.tid, before);
		push_u32_field(r, "input_pid", s.pid);
		push_u32_field(r, "input_tid", s.tid);
		push_u32_field(r, "attached_pid", attached_pid);
		push_u32_field(r, "device_pid", device_pid);
		push_hex_field(r, "ioctl_code", ioctl_codes::TCTX());
		push_u64_dec_field(r, "request_size", sizeof(voyager::detail::thread_ctx_request));
		push_thread_snapshot(r, "thread_before", before_found, before);
		::diag::log_tagged_fmt("testlab_tctx",
			"START pid=%u tid=%u attached_pid=%u device_pid=%u ioctl=0x%08X request_size=%zu before_found=%d before_state=%u before_rip=0x%llX",
			s.pid,
			s.tid,
			attached_pid,
			device_pid,
			ioctl_codes::TCTX(),
			sizeof(voyager::detail::thread_ctx_request),
			before_found ? 1 : 0,
			before.state,
			static_cast<unsigned long long>(before.rip));
		voyager::detail::thread_ctx_request req{};
		req.pid = s.pid;
		req.tid = s.tid;
		req.should_set = 0;
		req.padding = 0;
		req.register_mask = 0xFFFFFFFFFFFFFFFFull;
		std::uint32_t bytes_returned = 0;
		SetLastError(ERROR_SUCCESS);
		const std::uint64_t raw_start = static_cast<std::uint64_t>(GetTickCount64());
		bool ok = device->send_ioctl_raw(ioctl_codes::TCTX(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		const DWORD raw_error = ok ? ERROR_SUCCESS : GetLastError();
		const std::uint64_t raw_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - raw_start;
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		const bool raw_context_valid = req.rip != 0 && req.rsp != 0;
		push_bool_field(r, "raw_ioctl_ok", ok);
		push_u32_field(r, "raw_ioctl_last_error", raw_error);
		push_u32_field(r, "raw_ioctl_bytes", bytes_returned);
		push_u64_dec_field(r, "raw_ioctl_elapsed_ms", raw_elapsed);
		push_bool_field(r, "raw_context_valid", raw_context_valid);
		::diag::log_tagged_fmt("testlab_tctx",
			"RAW pid=%u tid=%u ok=%d gle=%lu bytes=%u elapsed_ms=%llu rip=0x%llX rsp=0x%llX",
			s.pid,
			s.tid,
			ok ? 1 : 0,
			static_cast<unsigned long>(raw_error),
			bytes_returned,
			static_cast<unsigned long long>(raw_elapsed),
			static_cast<unsigned long long>(req.rip),
			static_cast<unsigned long long>(req.rsp));
		if (!ok || !raw_context_valid) {
			push_text_field(r, "fallback_reason", ok ? "raw ioctl returned zero RIP/RSP" : "raw ioctl failed");
			if (s.pid == device_pid && s.pid == attached_pid) {
				voyager::device_t::thread_context ctx{};
				SetLastError(ERROR_SUCCESS);
				const std::uint64_t helper_start = static_cast<std::uint64_t>(GetTickCount64());
				const bool helper_ok = device->get_thread_context(s.tid, ctx);
				const DWORD helper_error = helper_ok ? ERROR_SUCCESS : GetLastError();
				const std::uint64_t helper_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - helper_start;
				const bool helper_valid = helper_ok && ctx.rip != 0 && ctx.rsp != 0;
				push_bool_field(r, "fallback_helper_ok", helper_ok);
				push_u32_field(r, "fallback_helper_last_error", helper_error);
				push_u64_dec_field(r, "fallback_helper_elapsed_ms", helper_elapsed);
				push_bool_field(r, "fallback_context_valid", helper_valid);
				::diag::log_tagged_fmt("testlab_tctx",
					"FALLBACK pid=%u tid=%u helper_ok=%d gle=%lu elapsed_ms=%llu rip=0x%llX rsp=0x%llX",
					s.pid,
					s.tid,
					helper_ok ? 1 : 0,
					static_cast<unsigned long>(helper_error),
					static_cast<unsigned long long>(helper_elapsed),
					static_cast<unsigned long long>(ctx.rip),
					static_cast<unsigned long long>(ctx.rsp));
				if (helper_valid) {
					copy_context_to_request(req, ctx);
					req.pid = s.pid;
					req.tid = s.tid;
					req.should_set = 0;
					req.register_mask = 0xFFFFFFFFFFFFFFFFull;
					r.bytes_returned = static_cast<std::uint32_t>(sizeof(req));
					r.raw.resize(sizeof(req));
					std::memcpy(r.raw.data(), &req, sizeof(req));
					push_text_field(r, "tctx_pass_path", "device_get_thread_context_retry");
					push_context_fields(r, req);
					const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
					push_thread_snapshot(r, "thread_after", after_found, after);
					r.ntstatus = 0;
					r.ok = true;
					return;
				}
			} else {
				push_text_field(r, "fallback_skipped", "requested PID is not the attached device PID");
			}
			const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
			push_thread_snapshot(r, "thread_after", after_found, after);
			r.error = ok ? "TCTX returned an invalid zero RIP/RSP context" : "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_text_field(r, "tctx_pass_path", "raw_ioctl");
		push_context_fields(r, req);
		const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
		push_thread_snapshot(r, "thread_after", after_found, after);
		r.ntstatus = 0;
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
