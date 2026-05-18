#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {

	struct rc_record_t {
		std::uint32_t pid = 0;
		std::uint64_t dtb = 0;
		std::uint64_t shellcode_address = 0;
		std::uint64_t target_function = 0;
		std::uint64_t arg1 = 0;
	};

	std::mutex& rc_map_mutex() {
		static std::mutex m;
		return m;
	}

	std::unordered_map<std::uint32_t, rc_record_t>& rc_map_storage() {
		static std::unordered_map<std::uint32_t, rc_record_t> m;
		return m;
	}

	std::atomic<std::uint32_t>& rc_call_id_seq() {
		static std::atomic<std::uint32_t> v{ 1u };
		return v;
	}

	bool resolve_dtb(std::uint32_t pid, std::uint64_t& out_dtb, std::string& out_err) {
		voyager::detail::dtb_solve req{};
		req.pid = pid;
		std::uint32_t br = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DTB(), &req, static_cast<std::uint32_t>(sizeof(req)), br);
		if (!ok) {
			out_err = "DTB IOCTL failed";
			return false;
		}
		if (req.dtb == 0ull) {
			out_err = "DTB IOCTL returned zero (pid not found?)";
			return false;
		}
		out_dtb = req.dtb;
		return true;
	}

	bool alloc_scratch(std::uint32_t pid, std::uint64_t size, std::uint64_t& out_address, std::string& out_err) {
		voyager::detail::alloc_mem_request req{};
		req.pid = pid;
		req.size = size;
		std::uint32_t br = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::AM(), &req, static_cast<std::uint32_t>(sizeof(req)), br);
		if (!ok) {
			out_err = "AM IOCTL failed";
			return false;
		}
		if (req.allocated_address == 0ull) {
			out_err = "AM IOCTL returned null address";
			return false;
		}
		out_address = req.allocated_address;
		return true;
	}

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

	void render_inputs_rc(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Function Address (addr)", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Arg1 (u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Issues a kernel-queued remote call. DTB and scratch buffer are auto-resolved via DTB+AM IOCTLs.");
		ImGui::TextDisabled("Returns a numeric call_id to be passed to CR for retrieval.");
	}

	void run_rc(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		if (s.addr == 0ull) {
			r.error = "target function address is zero";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			r.ok = false;
			return;
		}
		std::uint64_t dtb = 0;
		std::string err;
		if (!resolve_dtb(s.pid, dtb, err)) {
			r.error = err;
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		std::uint64_t scratch = 0;
		if (!alloc_scratch(s.pid, static_cast<std::uint64_t>(voyager::detail::SHELLCODE_ALLOC_SIZE), scratch, err)) {
			r.error = err;
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		voyager::detail::remote_call_request req{};
		req.dtb = dtb;
		req.target_function = s.addr;
		req.shellcode_address = scratch;
		req.spoof_return = 0;
		req.arg1 = s.u64_a;
		req.arg2 = 0;
		req.arg3 = 0;
		req.arg4 = 0;
		req.result = 0;
		req.completed = 0;
		req.original_rip = 0;
		req.trampoline_addr = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::RC(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		std::uint32_t call_id = rc_call_id_seq().fetch_add(1u, std::memory_order_acq_rel);
		if (call_id == 0u) {
			call_id = rc_call_id_seq().fetch_add(1u, std::memory_order_acq_rel);
		}
		rc_record_t rec{};
		rec.pid = s.pid;
		rec.dtb = dtb;
		rec.shellcode_address = scratch;
		rec.target_function = s.addr;
		rec.arg1 = s.u64_a;
		{
			std::lock_guard<std::mutex> lk(rc_map_mutex());
			rc_map_storage()[call_id] = rec;
		}
		push_u32_field(r, "Call ID (u32_a for CR)", call_id);
		push_u32_field(r, "PID", s.pid);
		push_hex_field(r, "DTB", dtb);
		push_hex_field(r, "Target Function", s.addr);
		push_hex_field(r, "Arg1", s.u64_a);
		push_hex_field(r, "Scratch / Result Address", scratch);
		push_hex_field(r, "Kernel Result", req.result);
		push_hex_field(r, "Completed Flag", req.completed);
		push_hex_field(r, "Original RIP", req.original_rip);
		push_hex_field(r, "Trampoline Addr", req.trampoline_addr);
		r.ok = true;
	}

	void render_inputs_cr(test_lab::state_t& s) {
		ImGui::InputScalar("Call ID (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Looks up the DTB/result-address bound when RC was issued, then reads the call result.");
	}

	void run_cr(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.error = "driver not connected";
			r.ok = false;
			return;
		}
		rc_record_t rec{};
		bool found = false;
		{
			std::lock_guard<std::mutex> lk(rc_map_mutex());
			auto& m = rc_map_storage();
			auto it = m.find(s.u32_a);
			if (it != m.end()) {
				rec = it->second;
				found = true;
			}
		}
		if (!found) {
			r.error = "unknown call_id (issue RC first to populate the call_id table)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			return;
		}
		voyager::detail::call_result_request req{};
		req.dtb = rec.dtb;
		req.result_address = rec.shellcode_address;
		req.result = 0;
		req.completed = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::CR(), &req, static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.ok = false;
			return;
		}
		push_u32_field(r, "Call ID", s.u32_a);
		push_u32_field(r, "Bound PID", rec.pid);
		push_hex_field(r, "Bound DTB", rec.dtb);
		push_hex_field(r, "Result Address", rec.shellcode_address);
		push_hex_field(r, "Target Function", rec.target_function);
		push_hex_field(r, "Arg1", rec.arg1);
		push_hex_field(r, "Result Value", req.result);
		push_hex_field(r, "Completed Flag", req.completed);
		r.parsed.push_back({ "Status", (req.completed != 0ull) ? std::string("DONE") : std::string("PENDING") });
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_rc, "remote-call", test_lab::driver_e::whoswho, "RC",
	"Issue a queued kernel-side remote function call (auto-resolves DTB + scratch buffer).",
	&render_inputs_rc, &run_rc);

TESTLAB_REGISTER(g_reg_cr, "remote-call", test_lab::driver_e::whoswho, "CR",
	"Retrieve the result of a previously-issued RC by call_id.",
	&render_inputs_cr, &run_cr);
