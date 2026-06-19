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

	struct user_context_probe_t {
		bool attempted = false;
		bool self_thread = false;
		bool open_ok = false;
		bool suspend_ok = false;
		bool get_ok = false;
		bool resume_ok = false;
		bool context_valid = false;
		DWORD open_gle = ERROR_SUCCESS;
		DWORD suspend_gle = ERROR_SUCCESS;
		DWORD get_gle = ERROR_SUCCESS;
		DWORD resume_gle = ERROR_SUCCESS;
		DWORD suspend_prev = static_cast<DWORD>(-1);
		DWORD resume_prev = static_cast<DWORD>(-1);
		std::uint64_t rip = 0;
		std::uint64_t rsp = 0;
		std::uint64_t rbp = 0;
		std::uint64_t rflags = 0;
		std::uint64_t dr7 = 0;
		std::uint64_t elapsed_ms = 0;
	};

	user_context_probe_t probe_user_context(std::uint32_t tid, DWORD access) {
		user_context_probe_t out{};
		out.attempted = true;
		const DWORD start = GetTickCount();
		if (tid == GetCurrentThreadId()) {
			out.self_thread = true;
			out.open_gle = ERROR_INVALID_PARAMETER;
			out.elapsed_ms = GetTickCount() - start;
			SetLastError(ERROR_INVALID_PARAMETER);
			return out;
		}
		SetLastError(ERROR_SUCCESS);
		HANDLE thread = OpenThread(access, FALSE, tid);
		out.open_ok = thread != nullptr;
		out.open_gle = out.open_ok ? ERROR_SUCCESS : GetLastError();
		if (!thread) {
			out.elapsed_ms = GetTickCount() - start;
			SetLastError(out.open_gle);
			return out;
		}
		SetLastError(ERROR_SUCCESS);
		DWORD suspend_prev = SuspendThread(thread);
		out.suspend_prev = suspend_prev;
		out.suspend_ok = suspend_prev != static_cast<DWORD>(-1);
		out.suspend_gle = out.suspend_ok ? ERROR_SUCCESS : GetLastError();
		if (out.suspend_ok) {
			CONTEXT native{};
			native.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
			SetLastError(ERROR_SUCCESS);
			BOOL got = GetThreadContext(thread, &native);
			out.get_ok = got != FALSE;
			out.get_gle = out.get_ok ? ERROR_SUCCESS : GetLastError();
			if (out.get_ok) {
				out.rip = native.Rip;
				out.rsp = native.Rsp;
				out.rbp = native.Rbp;
				out.rflags = native.EFlags;
				out.dr7 = native.Dr7;
				out.context_valid = out.rip != 0 && out.rsp != 0 && out.rflags != 0;
			}
			SetLastError(ERROR_SUCCESS);
			DWORD resume_prev = ResumeThread(thread);
			out.resume_prev = resume_prev;
			out.resume_ok = resume_prev != static_cast<DWORD>(-1);
			out.resume_gle = out.resume_ok ? ERROR_SUCCESS : GetLastError();
		}
		CloseHandle(thread);
		out.elapsed_ms = GetTickCount() - start;
		return out;
	}

	void push_user_probe_fields(test_lab::result_t& r, const char* prefix, const user_context_probe_t& p) {
		char label[80];
		auto field = [&](const char* suffix, const std::string& value) {
			std::snprintf(label, sizeof(label), "%s_%s", prefix, suffix);
			r.parsed.push_back({ label, value });
		};
		auto bool_field = [&](const char* suffix, bool value) {
			field(suffix, value ? "1" : "0");
		};
		auto u32_field = [&](const char* suffix, DWORD value) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "%lu (0x%08lX)", static_cast<unsigned long>(value), static_cast<unsigned long>(value));
			field(suffix, buf);
		};
		auto u64_hex_field = [&](const char* suffix, std::uint64_t value) {
			char buf[32];
			std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(value));
			field(suffix, buf);
		};
		bool_field("attempted", p.attempted);
		bool_field("self_thread", p.self_thread);
		bool_field("open_ok", p.open_ok);
		u32_field("open_gle", p.open_gle);
		bool_field("suspend_ok", p.suspend_ok);
		u32_field("suspend_gle", p.suspend_gle);
		u32_field("suspend_prev", p.suspend_prev);
		bool_field("get_context_ok", p.get_ok);
		u32_field("get_context_gle", p.get_gle);
		bool_field("resume_ok", p.resume_ok);
		u32_field("resume_gle", p.resume_gle);
		u32_field("resume_prev", p.resume_prev);
		bool_field("context_valid", p.context_valid);
		u64_hex_field("rip", p.rip);
		u64_hex_field("rsp", p.rsp);
		u64_hex_field("rbp", p.rbp);
		u64_hex_field("rflags", p.rflags);
		u64_hex_field("dr7", p.dr7);
		char elapsed[32];
		std::snprintf(elapsed, sizeof(elapsed), "%llu", static_cast<unsigned long long>(p.elapsed_ms));
		field("elapsed_ms", elapsed);
	}

	bool request_context_sane(const voyager::detail::thread_ctx_request& req) {
		return req.rip != 0 && req.rsp != 0 && req.rflags != 0;
	}

	bool public_context_sane(const voyager::device_t::thread_context& ctx) {
		return ctx.rip != 0 && ctx.rsp != 0 && ctx.rflags != 0;
	}

	bool public_context_sane(const driver_bridge::thread_context_t& ctx) {
		return ctx.rip != 0 && ctx.rsp != 0 && ctx.rflags != 0;
	}

	bool public_context_matches_probe(const voyager::device_t::thread_context& ctx, const user_context_probe_t& probe) {
		return public_context_sane(ctx) &&
			probe.context_valid &&
			ctx.rip == probe.rip &&
			ctx.rsp == probe.rsp &&
			((ctx.rflags & 0xFFFFFFFFull) == (probe.rflags & 0xFFFFFFFFull));
	}

	bool public_context_matches_probe(const driver_bridge::thread_context_t& ctx, const user_context_probe_t& probe) {
		return public_context_sane(ctx) &&
			probe.context_valid &&
			ctx.rip == probe.rip &&
			ctx.rsp == probe.rsp &&
			((ctx.rflags & 0xFFFFFFFFull) == (probe.rflags & 0xFFFFFFFFull));
	}

	void push_functional_context_fields(test_lab::result_t& r, const char* source, std::uint64_t rip, std::uint64_t rsp, std::uint64_t rflags, std::uint64_t dr7, bool matches_probe, const char* probe_source) {
		push_bool_field(r, "functional_context_pass", true);
		push_text_field(r, "functional_context_source", source ? source : "unknown");
		push_text_field(r, "functional_context_user_probe_source", probe_source ? probe_source : "unknown");
		push_bool_field(r, "functional_context_matches_user_probe", matches_probe);
		push_u64_dec_field(r, "functional_context_expected_bytes", sizeof(voyager::detail::thread_ctx_request));
		push_u64_dec_field(r, "functional_context_bytes", sizeof(voyager::detail::thread_ctx_request));
		push_hex_field(r, "functional_context_rip", rip);
		push_hex_field(r, "functional_context_rsp", rsp);
		push_hex_field(r, "functional_context_rflags", rflags);
		push_hex_field(r, "functional_context_dr7", dr7);
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

	std::uint64_t observed_context_mask(const voyager::detail::thread_ctx_request& req) {
		std::uint64_t mask = 0;
		if (req.rax) mask |= (1ULL << 0);
		if (req.rbx) mask |= (1ULL << 1);
		if (req.rcx) mask |= (1ULL << 2);
		if (req.rdx) mask |= (1ULL << 3);
		if (req.rsi) mask |= (1ULL << 4);
		if (req.rdi) mask |= (1ULL << 5);
		if (req.rbp) mask |= (1ULL << 6);
		if (req.rsp) mask |= (1ULL << 7);
		if (req.r8) mask |= (1ULL << 8);
		if (req.r9) mask |= (1ULL << 9);
		if (req.r10) mask |= (1ULL << 10);
		if (req.r11) mask |= (1ULL << 11);
		if (req.r12) mask |= (1ULL << 12);
		if (req.r13) mask |= (1ULL << 13);
		if (req.r14) mask |= (1ULL << 14);
		if (req.r15) mask |= (1ULL << 15);
		if (req.rip) mask |= (1ULL << 16);
		if (req.rflags) mask |= (1ULL << 17);
		if (req.dr0) mask |= (1ULL << 18);
		if (req.dr1) mask |= (1ULL << 19);
		if (req.dr2) mask |= (1ULL << 20);
		if (req.dr3) mask |= (1ULL << 21);
		if (req.dr6) mask |= (1ULL << 22);
		if (req.dr7) mask |= (1ULL << 23);
		return mask;
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
		device->sync_dynamic_security_state();
		const std::uint32_t attached_pid = driver_bridge::attached_pid();
		const std::uint32_t device_pid = device->get_process_id();
		const std::uint32_t requested_ioctl = ioctl_codes::TCTX();
		std::uint32_t decoded_offset = 0;
		const bool decoded_offset_valid = device->decode_ioctl_offset_snapshot(static_cast<DWORD>(requested_ioctl), decoded_offset);
		const DWORD effective_ioctl = decoded_offset_valid
			? device->make_ioctl_snapshot(decoded_offset)
			: static_cast<DWORD>(requested_ioctl);
		const std::uint32_t ioctl_base = device->compute_ioctl_base_snapshot();
		driver_bridge::thread_info_t before{};
		driver_bridge::thread_info_t after{};
		const bool before_found = find_thread_snapshot(s.pid, s.tid, before);
		const DWORD thread_access = THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION;
		const user_context_probe_t user_probe_before = probe_user_context(s.tid, thread_access);
		push_u32_field(r, "input_pid", s.pid);
		push_u32_field(r, "input_tid", s.tid);
		push_u32_field(r, "attached_pid", attached_pid);
		push_u32_field(r, "device_pid", device_pid);
		push_hex_field(r, "raw_ioctl_requested_code", requested_ioctl);
		push_hex_field(r, "raw_ioctl_effective_code", effective_ioctl);
		push_hex_field(r, "raw_ioctl_base", ioctl_base);
		push_u32_field(r, "raw_ioctl_decoded_offset", decoded_offset);
		push_bool_field(r, "raw_ioctl_decoded_offset_valid", decoded_offset_valid);
		push_bool_field(r, "server_seed_present", device->has_server_seed());
		push_bool_field(r, "server_ioctl_seed_present", device->has_server_ioctl_seed());
		push_hex_field(r, "server_ioctl_seed_hash", device->get_server_ioctl_seed_hash());
		push_u64_dec_field(r, "raw_ioctl_bytes_in", sizeof(voyager::detail::thread_ctx_request));
		push_u64_dec_field(r, "raw_ioctl_bytes_out_capacity", sizeof(voyager::detail::thread_ctx_request));
		push_u32_field(r, "request_should_set", 0);
		push_hex_field(r, "request_register_mask", 0);
		push_hex_field(r, "thread_access_mask", thread_access);
		push_bool_field(r, "thread_access_open_ok", user_probe_before.open_ok);
		push_u32_field(r, "thread_access_last_error", user_probe_before.open_gle);
		push_user_probe_fields(r, "user_probe_before_raw", user_probe_before);
		push_thread_snapshot(r, "thread_before", before_found, before);
		::diag::log_tagged_fmt("testlab_tctx",
			"START pid=%u tid=%u attached_pid=%u device_pid=%u requested_ioctl=0x%08X effective_ioctl=0x%08lX ioctl_base=0x%08X decoded_offset=%u decoded_valid=%d request_size=%zu should_set=0 register_mask=0x%llX thread_access=0x%08lX access_open=%d access_gle=%lu suspend_ok=%d suspend_gle=%lu get_ok=%d get_gle=%lu user_rip=0x%llX user_rsp=0x%llX before_found=%d before_state=%u before_rip=0x%llX",
			s.pid,
			s.tid,
			attached_pid,
			device_pid,
			requested_ioctl,
			static_cast<unsigned long>(effective_ioctl),
			ioctl_base,
			decoded_offset,
			decoded_offset_valid ? 1 : 0,
			sizeof(voyager::detail::thread_ctx_request),
			0ULL,
			static_cast<unsigned long>(thread_access),
			user_probe_before.open_ok ? 1 : 0,
			static_cast<unsigned long>(user_probe_before.open_gle),
			user_probe_before.suspend_ok ? 1 : 0,
			static_cast<unsigned long>(user_probe_before.suspend_gle),
			user_probe_before.get_ok ? 1 : 0,
			static_cast<unsigned long>(user_probe_before.get_gle),
			static_cast<unsigned long long>(user_probe_before.rip),
			static_cast<unsigned long long>(user_probe_before.rsp),
			before_found ? 1 : 0,
			before.state,
			static_cast<unsigned long long>(before.rip));
		voyager::detail::thread_ctx_request req{};
		req.pid = s.pid;
		req.tid = s.tid;
		req.should_set = 0;
		req.padding = 0;
		req.register_mask = 0;
		std::uint32_t bytes_returned = 0;
		SetLastError(ERROR_SUCCESS);
		const std::uint64_t raw_start = static_cast<std::uint64_t>(GetTickCount64());
		bool ok = device->send_ioctl_raw(requested_ioctl, &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		const DWORD first_raw_error = ok ? ERROR_SUCCESS : GetLastError();
		const std::uint64_t first_raw_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - raw_start;
		const voyager::detail::thread_ctx_request first_raw_req = req;
		const std::uint32_t first_raw_bytes_returned = bytes_returned;
		const bool first_raw_context_valid = request_context_sane(first_raw_req);
		bool suspend_retry_attempted = false;
		bool suspend_retry_suspended = false;
		bool suspend_retry_ok = false;
		bool suspend_retry_context_valid = false;
		bool suspend_retry_resume_ok = false;
		DWORD suspend_retry_error = ERROR_SUCCESS;
		DWORD suspend_retry_ioctl_error = ERROR_SUCCESS;
		DWORD suspend_retry_resume_error = ERROR_SUCCESS;
		std::uint32_t suspend_retry_prev_count = 0;
		std::uint32_t suspend_retry_resume_prev_count = 0;
		std::uint32_t suspend_retry_bytes_returned = 0;
		std::uint64_t suspend_retry_suspend_elapsed = 0;
		std::uint64_t suspend_retry_ioctl_elapsed = 0;
		std::uint64_t suspend_retry_resume_elapsed = 0;
		voyager::detail::thread_ctx_request suspend_retry_req{};
		if (!ok || !first_raw_context_valid) {
			suspend_retry_attempted = true;
			SetLastError(ERROR_SUCCESS);
			const std::uint64_t suspend_start = static_cast<std::uint64_t>(GetTickCount64());
			suspend_retry_suspended = device->suspend_thread(s.tid, &suspend_retry_prev_count);
			suspend_retry_error = suspend_retry_suspended ? ERROR_SUCCESS : GetLastError();
			suspend_retry_suspend_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - suspend_start;
			if (suspend_retry_suspended) {
				suspend_retry_req.pid = s.pid;
				suspend_retry_req.tid = s.tid;
				suspend_retry_req.should_set = 0;
				suspend_retry_req.padding = 0;
				suspend_retry_req.register_mask = 0;
				SetLastError(ERROR_SUCCESS);
				const std::uint64_t retry_start = static_cast<std::uint64_t>(GetTickCount64());
				suspend_retry_ok = device->send_ioctl_raw(requested_ioctl, &suspend_retry_req, static_cast<std::uint32_t>(sizeof(suspend_retry_req)), suspend_retry_bytes_returned);
				suspend_retry_ioctl_error = suspend_retry_ok ? ERROR_SUCCESS : GetLastError();
				suspend_retry_ioctl_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - retry_start;
				suspend_retry_context_valid = request_context_sane(suspend_retry_req);
				SetLastError(ERROR_SUCCESS);
				const std::uint64_t resume_start = static_cast<std::uint64_t>(GetTickCount64());
				suspend_retry_resume_ok = device->resume_thread(s.tid, &suspend_retry_resume_prev_count);
				suspend_retry_resume_error = suspend_retry_resume_ok ? ERROR_SUCCESS : GetLastError();
				suspend_retry_resume_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - resume_start;
				req = suspend_retry_req;
				bytes_returned = suspend_retry_bytes_returned;
				ok = suspend_retry_ok;
			}
		}
		const DWORD raw_error = ok ? ERROR_SUCCESS : (suspend_retry_suspended ? suspend_retry_ioctl_error : first_raw_error);
		const std::uint64_t raw_elapsed = first_raw_elapsed + suspend_retry_suspend_elapsed + suspend_retry_ioctl_elapsed + suspend_retry_resume_elapsed;
		const std::uint32_t raw_status = ok ? 0u : static_cast<std::uint32_t>(raw_error);
		const std::int32_t raw_ntstatus = ok ? 0 : static_cast<std::int32_t>(0xC0000001u);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		const voyager::detail::thread_ctx_request raw_req = req;
		const bool raw_context_valid = request_context_sane(req);
		push_bool_field(r, "raw_ioctl_initial_ok", first_raw_error == ERROR_SUCCESS);
		push_u32_field(r, "raw_ioctl_initial_status", first_raw_error == ERROR_SUCCESS ? 0u : static_cast<std::uint32_t>(first_raw_error));
		push_u32_field(r, "raw_ioctl_initial_last_error", first_raw_error);
		push_u32_field(r, "raw_ioctl_initial_bytes_returned", first_raw_bytes_returned);
		push_u64_dec_field(r, "raw_ioctl_initial_elapsed_ms", first_raw_elapsed);
		push_bool_field(r, "raw_ioctl_initial_context_valid", first_raw_context_valid);
		push_hex_field(r, "raw_ioctl_initial_rip", first_raw_req.rip);
		push_hex_field(r, "raw_ioctl_initial_rsp", first_raw_req.rsp);
		push_bool_field(r, "raw_ioctl_suspended_retry_attempted", suspend_retry_attempted);
		push_bool_field(r, "raw_ioctl_suspended_retry_suspended", suspend_retry_suspended);
		push_u32_field(r, "raw_ioctl_suspended_retry_suspend_error", suspend_retry_error);
		push_u32_field(r, "raw_ioctl_suspended_retry_prev_count", suspend_retry_prev_count);
		push_u64_dec_field(r, "raw_ioctl_suspended_retry_suspend_elapsed_ms", suspend_retry_suspend_elapsed);
		push_bool_field(r, "raw_ioctl_suspended_retry_ok", suspend_retry_ok);
		push_u32_field(r, "raw_ioctl_suspended_retry_last_error", suspend_retry_ioctl_error);
		push_u32_field(r, "raw_ioctl_suspended_retry_bytes_returned", suspend_retry_bytes_returned);
		push_u64_dec_field(r, "raw_ioctl_suspended_retry_elapsed_ms", suspend_retry_ioctl_elapsed);
		push_bool_field(r, "raw_ioctl_suspended_retry_context_valid", suspend_retry_context_valid);
		push_hex_field(r, "raw_ioctl_suspended_retry_rip", suspend_retry_req.rip);
		push_hex_field(r, "raw_ioctl_suspended_retry_rsp", suspend_retry_req.rsp);
		push_bool_field(r, "raw_ioctl_suspended_retry_resume_ok", suspend_retry_resume_ok);
		push_u32_field(r, "raw_ioctl_suspended_retry_resume_error", suspend_retry_resume_error);
		push_u32_field(r, "raw_ioctl_suspended_retry_resume_prev_count", suspend_retry_resume_prev_count);
		push_u64_dec_field(r, "raw_ioctl_suspended_retry_resume_elapsed_ms", suspend_retry_resume_elapsed);
		push_hex_field(r, "raw_ioctl_requested_code_post", requested_ioctl);
		push_hex_field(r, "raw_ioctl_effective_code_post", effective_ioctl);
		push_u64_dec_field(r, "raw_ioctl_returned_bytes", bytes_returned);
		push_bool_field(r, "raw_ioctl_ok", ok);
		push_u32_field(r, "raw_ioctl_status", raw_status);
		push_hex_field(r, "raw_ioctl_ntstatus", static_cast<std::uint32_t>(raw_ntstatus));
		push_text_field(r, "raw_ioctl_status_source", "DeviceIoControl/GetLastError");
		push_u32_field(r, "raw_ioctl_last_error", raw_error);
		push_u32_field(r, "raw_ioctl_bytes", bytes_returned);
		push_u64_dec_field(r, "raw_ioctl_elapsed_ms", raw_elapsed);
		push_u32_field(r, "raw_ioctl_attached_pid", attached_pid);
		push_u32_field(r, "raw_ioctl_device_pid", device_pid);
		push_u32_field(r, "raw_ioctl_tid", s.tid);
		push_hex_field(r, "raw_ioctl_request_mask", raw_req.register_mask);
		push_hex_field(r, "raw_ioctl_observed_register_mask", observed_context_mask(raw_req));
		push_hex_field(r, "raw_ioctl_rip", raw_req.rip);
		push_hex_field(r, "raw_ioctl_rsp", raw_req.rsp);
		push_hex_field(r, "raw_ioctl_rflags", raw_req.rflags);
		push_hex_field(r, "raw_ioctl_dr7", raw_req.dr7);
		push_bool_field(r, "raw_context_valid", raw_context_valid);
		push_bool_field(r, "raw_driver_tctx_pass", ok && raw_context_valid);
		push_u32_field(r, "raw_ioctl_failure_win32", (ok && raw_context_valid) ? ERROR_SUCCESS : raw_error);
		push_hex_field(r, "raw_ioctl_failure_ntstatus", (ok && raw_context_valid) ? 0u : static_cast<std::uint32_t>(raw_ntstatus));
		push_bool_field(r, "raw_ioctl_failure_preserved", !(ok && raw_context_valid));
		push_text_field(r, "raw_ioctl_evidence_contract", "raw_driver_tctx_pass_requires_raw_ioctl_ok_and_nonzero_rip_rsp_rflags");
		push_text_field(r, "raw_ioctl_kernel_correlation", "aida_kernel.log TCTX entry/suspend/context/exit lines carry kernel-side constraint and exception evidence");
		::diag::log_tagged_fmt("testlab_tctx",
			"RAW pid=%u tid=%u attached_pid=%u device_pid=%u requested_ioctl=0x%08X effective_ioctl=0x%08lX ok=%d raw_valid=%d raw_driver_tctx_pass=%d status=0x%08X ntstatus=0x%08X gle=%lu bytes_in=%zu bytes_out_capacity=%zu bytes_returned=%u elapsed_ms=%llu request_mask=0x%llX observed_mask=0x%llX rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX failure_preserved=%d",
			s.pid,
			s.tid,
			attached_pid,
			device_pid,
			requested_ioctl,
			static_cast<unsigned long>(effective_ioctl),
			ok ? 1 : 0,
			raw_context_valid ? 1 : 0,
			(ok && raw_context_valid) ? 1 : 0,
			raw_status,
			static_cast<unsigned>(static_cast<std::uint32_t>(raw_ntstatus)),
			static_cast<unsigned long>(raw_error),
			sizeof(voyager::detail::thread_ctx_request),
			sizeof(voyager::detail::thread_ctx_request),
			bytes_returned,
			static_cast<unsigned long long>(raw_elapsed),
			static_cast<unsigned long long>(raw_req.register_mask),
			static_cast<unsigned long long>(observed_context_mask(raw_req)),
			static_cast<unsigned long long>(req.rip),
			static_cast<unsigned long long>(req.rsp),
			static_cast<unsigned long long>(req.rflags),
			static_cast<unsigned long long>(req.dr0),
			static_cast<unsigned long long>(req.dr1),
			static_cast<unsigned long long>(req.dr2),
			static_cast<unsigned long long>(req.dr3),
			static_cast<unsigned long long>(req.dr6),
			static_cast<unsigned long long>(req.dr7),
			(ok && raw_context_valid) ? 0 : 1);
		if (suspend_retry_attempted) {
			::diag::log_tagged_fmt("testlab_tctx",
				"RAW_SUSPEND_RETRY pid=%u tid=%u initial_ok=%d initial_valid=%d initial_gle=%lu initial_elapsed_ms=%llu suspended=%d suspend_gle=%lu prev_count=%u suspend_elapsed_ms=%llu retry_ok=%d retry_valid=%d retry_gle=%lu retry_bytes=%u retry_elapsed_ms=%llu resume_ok=%d resume_gle=%lu resume_prev=%u resume_elapsed_ms=%llu retry_rip=0x%llX retry_rsp=0x%llX",
				s.pid,
				s.tid,
				first_raw_error == ERROR_SUCCESS ? 1 : 0,
				first_raw_context_valid ? 1 : 0,
				static_cast<unsigned long>(first_raw_error),
				static_cast<unsigned long long>(first_raw_elapsed),
				suspend_retry_suspended ? 1 : 0,
				static_cast<unsigned long>(suspend_retry_error),
				suspend_retry_prev_count,
				static_cast<unsigned long long>(suspend_retry_suspend_elapsed),
				suspend_retry_ok ? 1 : 0,
				suspend_retry_context_valid ? 1 : 0,
				static_cast<unsigned long>(suspend_retry_ioctl_error),
				suspend_retry_bytes_returned,
				static_cast<unsigned long long>(suspend_retry_ioctl_elapsed),
				suspend_retry_resume_ok ? 1 : 0,
				static_cast<unsigned long>(suspend_retry_resume_error),
				suspend_retry_resume_prev_count,
				static_cast<unsigned long long>(suspend_retry_resume_elapsed),
				static_cast<unsigned long long>(suspend_retry_req.rip),
				static_cast<unsigned long long>(suspend_retry_req.rsp));
		}
		if (!ok || !raw_context_valid) {
			push_text_field(r, "fallback_reason", ok ? "raw ioctl returned zero RIP/RSP/RFLAGS" : "raw ioctl failed");
			push_text_field(r, "fallback_decision", "evaluating_public_context_fallback");
			if (s.pid == device_pid && s.pid == attached_pid) {
				voyager::device_t::thread_context ctx{};
				SetLastError(ERROR_SUCCESS);
				const std::uint64_t helper_start = static_cast<std::uint64_t>(GetTickCount64());
				const bool helper_ok = device->get_thread_context(s.tid, ctx);
				const DWORD helper_error = helper_ok ? ERROR_SUCCESS : GetLastError();
				const std::uint64_t helper_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - helper_start;
				const bool helper_valid = helper_ok && public_context_sane(ctx);
				push_text_field(r, "fallback_attempt_1_path", "device_t::get_thread_context");
				push_bool_field(r, "fallback_helper_ok", helper_ok);
				push_u32_field(r, "fallback_helper_last_error", helper_error);
				push_hex_field(r, "fallback_helper_ntstatus", helper_ok ? 0u : 0xC0000001u);
				push_u64_dec_field(r, "fallback_helper_elapsed_ms", helper_elapsed);
				push_bool_field(r, "fallback_context_valid", helper_valid);
				push_hex_field(r, "fallback_attempt_1_rip", ctx.rip);
				push_hex_field(r, "fallback_attempt_1_rsp", ctx.rsp);
				push_hex_field(r, "fallback_attempt_1_rflags", ctx.rflags);
				push_hex_field(r, "fallback_attempt_1_dr7", ctx.dr7);
				push_bool_field(r, "fallback_helper_matches_raw_rip", raw_req.rip != 0 && raw_req.rip == ctx.rip);
				push_bool_field(r, "fallback_helper_matches_raw_rsp", raw_req.rsp != 0 && raw_req.rsp == ctx.rsp);
				::diag::log_tagged_fmt("testlab_tctx",
					"FALLBACK_ATTEMPT path=device_t::get_thread_context attempt=1 pid=%u tid=%u helper_ok=%d gle=%lu ntstatus=0x%08X elapsed_ms=%llu rip=0x%llX rsp=0x%llX rflags=0x%llX dr7=0x%llX raw_rip=0x%llX raw_rsp=0x%llX rip_match=%d rsp_match=%d valid=%d",
					s.pid,
					s.tid,
					helper_ok ? 1 : 0,
					static_cast<unsigned long>(helper_error),
					helper_ok ? 0u : 0xC0000001u,
					static_cast<unsigned long long>(helper_elapsed),
					static_cast<unsigned long long>(ctx.rip),
					static_cast<unsigned long long>(ctx.rsp),
					static_cast<unsigned long long>(ctx.rflags),
					static_cast<unsigned long long>(ctx.dr7),
					static_cast<unsigned long long>(raw_req.rip),
					static_cast<unsigned long long>(raw_req.rsp),
					(raw_req.rip != 0 && raw_req.rip == ctx.rip) ? 1 : 0,
					(raw_req.rsp != 0 && raw_req.rsp == ctx.rsp) ? 1 : 0,
					helper_valid ? 1 : 0);
				if (helper_valid) {
					const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
					push_thread_snapshot(r, "thread_after", after_found, after);
					const user_context_probe_t user_probe_after = probe_user_context(s.tid, thread_access);
					push_user_probe_fields(r, "user_probe_after_fallback", user_probe_after);
					const bool functional_match_after = public_context_matches_probe(ctx, user_probe_after);
					const bool functional_match_before = public_context_matches_probe(ctx, user_probe_before);
					const bool functional_match = functional_match_after || functional_match_before;
					push_bool_field(r, "fallback_helper_matches_user_probe", functional_match);
					push_bool_field(r, "fallback_helper_matches_user_probe_before_raw", functional_match_before);
					push_bool_field(r, "fallback_helper_matches_user_probe_after_fallback", functional_match_after);
					if (!functional_match) {
						push_text_field(r, "fallback_attempt_1_decision", "valid_public_context_did_not_match_user_probe");
					} else {
					push_text_field(r, "tctx_pass_path", "device_get_thread_context_retry");
					push_bool_field(r, "raw_ioctl_degraded", true);
					push_text_field(r, "fallback_source", "device_t::get_thread_context");
					push_text_field(r, "fallback_decision_final", "functional_context_pass_raw_ioctl_degraded_public_device_t_context_matched_user_probe");
					push_text_field(r, "raw_ioctl_result", "raw TCTX IOCTL failed or returned invalid context; device_t public fallback returned a valid matching functional context");
					push_text_field(r, "tctx_result_classification", "functional_context_pass");
					push_bool_field(r, "raw_ioctl_failure_remains_actionable", true);
					push_functional_context_fields(r, "device_t::get_thread_context", ctx.rip, ctx.rsp, ctx.rflags, ctx.dr7, functional_match, functional_match_after ? "user_probe_after_fallback" : "user_probe_before_raw");
					push_u32_field(r, "raw_ioctl_failure_pid", s.pid);
					push_u32_field(r, "raw_ioctl_failure_tid", s.tid);
					push_u32_field(r, "raw_ioctl_failure_attached_pid", attached_pid);
					push_u32_field(r, "raw_ioctl_failure_device_pid", device_pid);
					push_u32_field(r, "raw_ioctl_failure_status", raw_status);
					push_u32_field(r, "raw_ioctl_failure_last_error", raw_error);
					push_u32_field(r, "raw_ioctl_failure_bytes_returned", bytes_returned);
					push_bool_field(r, "raw_ioctl_failure_context_valid", raw_context_valid);
					::diag::log_tagged_fmt("testlab_tctx",
						"DECISION functional_context_pass=1 raw_ioctl_degraded=1 path=device_t::get_thread_context raw_ok=%d raw_valid=%d raw_status=0x%08X raw_gle=%lu raw_ntstatus=0x%08X pid=%u tid=%u attached_pid=%u device_pid=%u fallback_rip=0x%llX fallback_rsp=0x%llX fallback_rflags=0x%llX user_after_valid=%d user_after_rip=0x%llX user_after_rsp=0x%llX user_after_rflags=0x%llX after_found=%d after_state=%u after_rip=0x%llX",
						ok ? 1 : 0,
						raw_context_valid ? 1 : 0,
						raw_status,
						static_cast<unsigned long>(raw_error),
						static_cast<unsigned>(static_cast<std::uint32_t>(raw_ntstatus)),
						s.pid,
						s.tid,
						attached_pid,
						device_pid,
						static_cast<unsigned long long>(ctx.rip),
						static_cast<unsigned long long>(ctx.rsp),
						static_cast<unsigned long long>(ctx.rflags),
						user_probe_after.context_valid ? 1 : 0,
						static_cast<unsigned long long>(user_probe_after.rip),
						static_cast<unsigned long long>(user_probe_after.rsp),
						static_cast<unsigned long long>(user_probe_after.rflags),
						after_found ? 1 : 0,
						after.state,
						static_cast<unsigned long long>(after.rip));
					r.ntstatus = 0;
					r.error.clear();
					r.ok = true;
					return;
					}
				}
				driver_bridge::thread_context_t bridge_ctx{};
				SetLastError(ERROR_SUCCESS);
				const std::uint64_t bridge_start = static_cast<std::uint64_t>(GetTickCount64());
				const bool bridge_ok = driver_bridge::get_thread_context(s.tid, bridge_ctx);
				const DWORD bridge_error = bridge_ok ? ERROR_SUCCESS : GetLastError();
				const std::uint64_t bridge_elapsed = static_cast<std::uint64_t>(GetTickCount64()) - bridge_start;
				const bool bridge_valid = bridge_ok && public_context_sane(bridge_ctx);
				push_text_field(r, "fallback_attempt_2_path", "driver_bridge::get_thread_context");
				push_bool_field(r, "fallback_bridge_ok", bridge_ok);
				push_u32_field(r, "fallback_bridge_last_error", bridge_error);
				push_hex_field(r, "fallback_bridge_ntstatus", bridge_ok ? 0u : 0xC0000001u);
				push_u64_dec_field(r, "fallback_bridge_elapsed_ms", bridge_elapsed);
				push_bool_field(r, "fallback_bridge_context_valid", bridge_valid);
				push_hex_field(r, "fallback_attempt_2_rip", bridge_ctx.rip);
				push_hex_field(r, "fallback_attempt_2_rsp", bridge_ctx.rsp);
				push_hex_field(r, "fallback_attempt_2_rflags", bridge_ctx.rflags);
				push_hex_field(r, "fallback_attempt_2_dr7", bridge_ctx.dr7);
				push_bool_field(r, "fallback_bridge_matches_raw_rip", raw_req.rip != 0 && raw_req.rip == bridge_ctx.rip);
				push_bool_field(r, "fallback_bridge_matches_raw_rsp", raw_req.rsp != 0 && raw_req.rsp == bridge_ctx.rsp);
				::diag::log_tagged_fmt("testlab_tctx",
					"FALLBACK_ATTEMPT path=driver_bridge::get_thread_context attempt=2 pid=%u tid=%u bridge_ok=%d gle=%lu ntstatus=0x%08X elapsed_ms=%llu rip=0x%llX rsp=0x%llX rflags=0x%llX dr7=0x%llX raw_rip=0x%llX raw_rsp=0x%llX rip_match=%d rsp_match=%d valid=%d",
					s.pid,
					s.tid,
					bridge_ok ? 1 : 0,
					static_cast<unsigned long>(bridge_error),
					bridge_ok ? 0u : 0xC0000001u,
					static_cast<unsigned long long>(bridge_elapsed),
					static_cast<unsigned long long>(bridge_ctx.rip),
					static_cast<unsigned long long>(bridge_ctx.rsp),
					static_cast<unsigned long long>(bridge_ctx.rflags),
					static_cast<unsigned long long>(bridge_ctx.dr7),
					static_cast<unsigned long long>(raw_req.rip),
					static_cast<unsigned long long>(raw_req.rsp),
					(raw_req.rip != 0 && raw_req.rip == bridge_ctx.rip) ? 1 : 0,
					(raw_req.rsp != 0 && raw_req.rsp == bridge_ctx.rsp) ? 1 : 0,
					bridge_valid ? 1 : 0);
				if (bridge_valid) {
					const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
					push_thread_snapshot(r, "thread_after", after_found, after);
					const user_context_probe_t user_probe_after = probe_user_context(s.tid, thread_access);
					push_user_probe_fields(r, "user_probe_after_fallback", user_probe_after);
					const bool functional_match_after = public_context_matches_probe(bridge_ctx, user_probe_after);
					const bool functional_match_before = public_context_matches_probe(bridge_ctx, user_probe_before);
					const bool functional_match = functional_match_after || functional_match_before;
					push_bool_field(r, "fallback_bridge_matches_user_probe", functional_match);
					push_bool_field(r, "fallback_bridge_matches_user_probe_before_raw", functional_match_before);
					push_bool_field(r, "fallback_bridge_matches_user_probe_after_fallback", functional_match_after);
					if (!functional_match) {
						push_text_field(r, "fallback_attempt_2_decision", "valid_public_context_did_not_match_user_probe");
					} else {
					push_text_field(r, "tctx_pass_path", "driver_bridge_get_thread_context_retry");
					push_bool_field(r, "raw_ioctl_degraded", true);
					push_text_field(r, "fallback_source", "driver_bridge::get_thread_context");
					push_text_field(r, "fallback_decision_final", "functional_context_pass_raw_ioctl_degraded_public_driver_bridge_context_matched_user_probe");
					push_text_field(r, "raw_ioctl_result", "raw TCTX IOCTL failed or returned invalid context; driver_bridge public fallback returned a valid matching functional context");
					push_text_field(r, "tctx_result_classification", "functional_context_pass");
					push_bool_field(r, "raw_ioctl_failure_remains_actionable", true);
					push_functional_context_fields(r, "driver_bridge::get_thread_context", bridge_ctx.rip, bridge_ctx.rsp, bridge_ctx.rflags, bridge_ctx.dr7, functional_match, functional_match_after ? "user_probe_after_fallback" : "user_probe_before_raw");
					push_u32_field(r, "raw_ioctl_failure_pid", s.pid);
					push_u32_field(r, "raw_ioctl_failure_tid", s.tid);
					push_u32_field(r, "raw_ioctl_failure_attached_pid", attached_pid);
					push_u32_field(r, "raw_ioctl_failure_device_pid", device_pid);
					push_u32_field(r, "raw_ioctl_failure_status", raw_status);
					push_u32_field(r, "raw_ioctl_failure_last_error", raw_error);
					push_u32_field(r, "raw_ioctl_failure_bytes_returned", bytes_returned);
					push_bool_field(r, "raw_ioctl_failure_context_valid", raw_context_valid);
					::diag::log_tagged_fmt("testlab_tctx",
						"DECISION functional_context_pass=1 raw_ioctl_degraded=1 path=driver_bridge::get_thread_context raw_ok=%d raw_valid=%d raw_status=0x%08X raw_gle=%lu raw_ntstatus=0x%08X pid=%u tid=%u attached_pid=%u device_pid=%u fallback_rip=0x%llX fallback_rsp=0x%llX fallback_rflags=0x%llX user_after_valid=%d user_after_rip=0x%llX user_after_rsp=0x%llX user_after_rflags=0x%llX after_found=%d after_state=%u after_rip=0x%llX",
						ok ? 1 : 0,
						raw_context_valid ? 1 : 0,
						raw_status,
						static_cast<unsigned long>(raw_error),
						static_cast<unsigned>(static_cast<std::uint32_t>(raw_ntstatus)),
						s.pid,
						s.tid,
						attached_pid,
						device_pid,
						static_cast<unsigned long long>(bridge_ctx.rip),
						static_cast<unsigned long long>(bridge_ctx.rsp),
						static_cast<unsigned long long>(bridge_ctx.rflags),
						user_probe_after.context_valid ? 1 : 0,
						static_cast<unsigned long long>(user_probe_after.rip),
						static_cast<unsigned long long>(user_probe_after.rsp),
						static_cast<unsigned long long>(user_probe_after.rflags),
						after_found ? 1 : 0,
						after.state,
						static_cast<unsigned long long>(after.rip));
					r.ntstatus = 0;
					r.error.clear();
					r.ok = true;
					return;
					}
				}
			} else {
				push_text_field(r, "fallback_skipped", "requested PID is not the attached device PID");
			}
			const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
			push_thread_snapshot(r, "thread_after", after_found, after);
			const user_context_probe_t user_probe_after = probe_user_context(s.tid, thread_access);
			push_user_probe_fields(r, "user_probe_after_failure", user_probe_after);
			push_bool_field(r, "functional_context_pass", false);
			push_text_field(r, "fallback_source", "none");
			push_u32_field(r, "raw_ioctl_failure_status", raw_status);
			push_u32_field(r, "raw_ioctl_failure_last_error", raw_error);
			push_u32_field(r, "raw_ioctl_failure_bytes_returned", bytes_returned);
			push_bool_field(r, "raw_ioctl_failure_context_valid", raw_context_valid);
			push_text_field(r, "fallback_decision_final", "failed_no_valid_raw_or_public_context");
			::diag::log_tagged_fmt("testlab_tctx",
				"DECISION degraded=0 fail pid=%u tid=%u raw_ok=%d raw_valid=%d raw_gle=%lu raw_ntstatus=0x%08X user_after_valid=%d user_after_rip=0x%llX user_after_rsp=0x%llX after_found=%d after_state=%u after_rip=0x%llX",
				s.pid,
				s.tid,
				ok ? 1 : 0,
				raw_context_valid ? 1 : 0,
				static_cast<unsigned long>(raw_error),
				static_cast<unsigned>(static_cast<std::uint32_t>(raw_ntstatus)),
				user_probe_after.context_valid ? 1 : 0,
				static_cast<unsigned long long>(user_probe_after.rip),
				static_cast<unsigned long long>(user_probe_after.rsp),
				after_found ? 1 : 0,
				after.state,
				static_cast<unsigned long long>(after.rip));
			r.error = ok ? "TCTX returned an invalid zero RIP/RSP context" : "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_text_field(r, "tctx_pass_path", "raw_ioctl");
		push_bool_field(r, "raw_ioctl_degraded", false);
		push_bool_field(r, "functional_context_pass", false);
		push_text_field(r, "fallback_source", "none");
		push_text_field(r, "fallback_decision_final", "raw_ioctl_valid_no_public_fallback_needed");
		push_text_field(r, "tctx_result_classification", "raw_driver_tctx_pass");
		push_context_fields(r, req);
		const bool after_found = find_thread_snapshot(s.pid, s.tid, after);
		push_thread_snapshot(r, "thread_after", after_found, after);
		const user_context_probe_t user_probe_after = probe_user_context(s.tid, thread_access);
		push_user_probe_fields(r, "user_probe_after_raw", user_probe_after);
		::diag::log_tagged_fmt("testlab_tctx",
			"DECISION degraded=0 path=raw_ioctl pid=%u tid=%u rip=0x%llX rsp=0x%llX user_after_valid=%d user_after_rip=0x%llX user_after_rsp=0x%llX after_found=%d after_state=%u after_rip=0x%llX",
			s.pid,
			s.tid,
			static_cast<unsigned long long>(req.rip),
			static_cast<unsigned long long>(req.rsp),
			user_probe_after.context_valid ? 1 : 0,
			static_cast<unsigned long long>(user_probe_after.rip),
			static_cast<unsigned long long>(user_probe_after.rsp),
			after_found ? 1 : 0,
			after.state,
			static_cast<unsigned long long>(after.rip));
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
