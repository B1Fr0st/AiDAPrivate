#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

	constexpr std::uint32_t kAdmpOpFullProtect      = 0;
	constexpr std::uint32_t kAdmpOpRegisterFilter   = 1;
	constexpr std::uint32_t kAdmpOpHideThreads      = 2;
	constexpr std::uint32_t kAdmpOpEraseHeaders     = 3;
	constexpr std::uint32_t kAdmpOpQuery            = 4;
	constexpr std::uint32_t kAdmpOpStartContinuous  = 5;
	constexpr std::uint32_t kAdmpOpStopContinuous   = 6;
	constexpr std::uint32_t kAdmpOpScanKill         = 7;
	constexpr std::uint32_t kAdmpOpCorruptSections  = 8;
	constexpr std::uint32_t kAdmpOpScramblePeb      = 9;
	constexpr std::uint32_t kAdmpOpPermitPid        = 10;
	constexpr std::uint32_t kAdmpOpUnpermitPid      = 11;

	const char* admp_op_label(std::uint32_t op) {
		switch (op) {
			case kAdmpOpFullProtect:     return "FULL_PROTECT";
			case kAdmpOpRegisterFilter:  return "REGISTER_FILTER";
			case kAdmpOpHideThreads:     return "HIDE_THREADS";
			case kAdmpOpEraseHeaders:    return "ERASE_HEADERS";
			case kAdmpOpQuery:           return "QUERY";
			case kAdmpOpStartContinuous: return "START_CONTINUOUS";
			case kAdmpOpStopContinuous:  return "STOP_CONTINUOUS";
			case kAdmpOpScanKill:        return "SCAN_KILL";
			case kAdmpOpCorruptSections: return "CORRUPT_SECTIONS";
			case kAdmpOpScramblePeb:     return "SCRAMBLE_PEB";
			case kAdmpOpPermitPid:       return "PERMIT_PID";
			case kAdmpOpUnpermitPid:     return "UNPERMIT_PID";
			default: return "UNKNOWN";
		}
	}

	bool admp_op_requires_pid(std::uint32_t op) {
		switch (op) {
			case kAdmpOpQuery:
			case kAdmpOpStopContinuous:
				return false;
			default:
				return true;
		}
	}

	void push_u32_hex(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u (0x%08X)", v, v);
		r.parsed.push_back({ label, b });
	}

	void push_u64_dec(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	struct admp_call_result_t {
		voyager::detail::anti_dump_request req{};
		std::uint32_t bytes_returned = 0;
		DWORD gle = ERROR_SUCCESS;
		std::uint64_t elapsed_ms = 0;
		bool ok = false;
	};

	std::string format_dec_u32(std::uint32_t v) {
		char b[16];
		std::snprintf(b, sizeof(b), "%u", v);
		return std::string(b);
	}

	admp_call_result_t send_admp_request(std::uint32_t operation, std::uint32_t pid) {
		admp_call_result_t out;
		out.req.operation = operation;
		out.req.pid = pid;
		SetLastError(ERROR_SUCCESS);
		const ULONGLONG start = GetTickCount64();
		out.ok = device->send_ioctl_raw(ioctl_codes::ADMP(), &out.req,
			static_cast<std::uint32_t>(sizeof(out.req)), out.bytes_returned);
		out.gle = out.ok ? ERROR_SUCCESS : GetLastError();
		out.elapsed_ms = static_cast<std::uint64_t>(GetTickCount64() - start);
		return out;
	}

	void append_admp_call_fields(test_lab::result_t& r, const char* prefix, const admp_call_result_t& call) {
		char label[80];
		std::snprintf(label, sizeof(label), "%s_ok", prefix);
		r.parsed.push_back({ label, call.ok ? "1" : "0" });
		std::snprintf(label, sizeof(label), "%s_gle", prefix);
		r.parsed.push_back({ label, format_dec_u32(static_cast<std::uint32_t>(call.gle)) });
		std::snprintf(label, sizeof(label), "%s_elapsed_ms", prefix);
		push_u64_dec(r, label, call.elapsed_ms);
		std::snprintf(label, sizeof(label), "%s_bytes_returned", prefix);
		r.parsed.push_back({ label, format_dec_u32(call.bytes_returned) });
		std::snprintf(label, sizeof(label), "%s_operation", prefix);
		r.parsed.push_back({ label, admp_op_label(call.req.operation) });
		std::snprintf(label, sizeof(label), "%s_pid", prefix);
		r.parsed.push_back({ label, format_dec_u32(call.req.pid) });
		std::snprintf(label, sizeof(label), "%s_result", prefix);
		r.parsed.push_back({ label, format_dec_u32(call.req.result) });
		std::snprintf(label, sizeof(label), "%s_blocks_count", prefix);
		push_u64_dec(r, label, call.req.blocks_count);
	}

	std::uint32_t choose_non_live_admp_probe_pid() {
		for (std::uint32_t i = 0; i < 32; ++i) {
			const std::uint32_t candidate = 0x70000001u + (i * 2u);
			SetLastError(ERROR_SUCCESS);
			HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, candidate);
			if (h) {
				CloseHandle(h);
				continue;
			}
			if (GetLastError() == ERROR_INVALID_PARAMETER)
				return candidate;
		}
		return 0;
	}

	void render_inputs_admp(test_lab::state_t& s) {
		const char* items[] = {
			"FULL_PROTECT (0)",
			"REGISTER_FILTER (1)",
			"HIDE_THREADS (2)",
			"ERASE_HEADERS (3)",
			"QUERY (4)",
			"START_CONTINUOUS (5)",
			"STOP_CONTINUOUS (6)",
			"SCAN_KILL (7)",
			"CORRUPT_SECTIONS (8)",
			"SCRAMBLE_PEB (9)",
			"PERMIT_PID (10)",
			"UNPERMIT_PID (11)"
		};
		int sel = static_cast<int>(s.u32_a);
		if (sel < 0 || sel >= IM_ARRAYSIZE(items)) sel = 0;
		if (ImGui::Combo("Subcommand (u32_a)", &sel, items, IM_ARRAYSIZE(items))) {
			s.u32_a = static_cast<std::uint32_t>(sel);
		}
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");

		switch (s.u32_a) {
			case kAdmpOpEraseHeaders:
				ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
					"WARNING: ERASE_HEADERS zeros the target process's PE DOS header in-memory.");
				break;
			case kAdmpOpScanKill:
				ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
					"WARNING: SCAN_KILL terminates suspicious foreign processes.");
				break;
			case kAdmpOpCorruptSections:
				ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
					"WARNING: CORRUPT_SECTIONS rewrites .text mid-flight; non-recoverable.");
				break;
			default:
				ImGui::TextDisabled("Driver returns blocks_count + result (1 on success).");
				break;
		}
	}

	void run_admp(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		const bool pid_required = admp_op_requires_pid(s.u32_a);
		r.parsed.push_back({ "requested_subcommand", admp_op_label(s.u32_a) });
		push_u32_hex(r, "requested_operation", s.u32_a);
		push_u32_hex(r, "requested_pid", s.pid);
		r.parsed.push_back({ "pid_required_for_subcommand", pid_required ? "1" : "0" });
		r.parsed.push_back({ "pid_zero_allowed_for_subcommand", (!pid_required && s.pid == 0) ? "1" : "0" });
		if (s.u32_a == kAdmpOpQuery && s.pid == 0)
			r.parsed.push_back({ "pid_zero_query_semantics", "pid=0 is valid for QUERY and returns global anti-dump block counters without targeting a process" });
		else if (s.u32_a == kAdmpOpStopContinuous && s.pid == 0)
			r.parsed.push_back({ "pid_zero_query_semantics", "pid=0 is valid for STOP_CONTINUOUS because the driver stops the global continuous anti-dump worker" });
		else if (s.pid == 0)
			r.parsed.push_back({ "pid_zero_query_semantics", "pid=0 is rejected for this subcommand" });
		if (admp_op_requires_pid(s.u32_a) && s.pid == 0) {
			r.ok = false;
			r.error = "selected subcommand requires a non-zero PID";
			r.ntstatus = static_cast<std::int32_t>(0xC000000Du);
			return;
		}

		const admp_call_result_t primary = send_admp_request(s.u32_a, s.pid);
		r.bytes_returned = primary.bytes_returned;
		r.raw.resize(sizeof(primary.req));
		std::memcpy(r.raw.data(), &primary.req, sizeof(primary.req));
		append_admp_call_fields(r, "primary", primary);
		test_lab_format::testlab_diag_log_step("anti-dump", "ADMP", "primary",
			"ok=%d gle=%lu bytes_returned=%u op=%u pid=%u result=%u blocks_count=%llu elapsed_ms=%llu",
			primary.ok ? 1 : 0,
			static_cast<unsigned long>(primary.gle),
			primary.bytes_returned,
			primary.req.operation,
			primary.req.pid,
			primary.req.result,
			static_cast<unsigned long long>(primary.req.blocks_count),
			static_cast<unsigned long long>(primary.elapsed_ms));
		if (!primary.ok) {
			r.ok = false;
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		r.parsed.push_back({ "subcommand", admp_op_label(primary.req.operation) });
		push_u32_hex(r, "operation", primary.req.operation);
		push_u32_hex(r, "pid",       primary.req.pid);
		push_u64_dec(r, "blocks_count", primary.req.blocks_count);
		push_u32_hex(r, "result",    primary.req.result);
		r.parsed.push_back({ "verdict", (primary.req.result == 1u) ? "OK" : "FAILED_OR_PARTIAL" });
		if (primary.req.operation == kAdmpOpQuery) {
			const std::uint32_t probe_pid = choose_non_live_admp_probe_pid();
			r.parsed.push_back({ "permit_roundtrip_attempted", probe_pid != 0 ? "1" : "0" });
			r.parsed.push_back({ "permit_roundtrip_pid", format_dec_u32(probe_pid) });
			r.parsed.push_back({ "permit_roundtrip_pid_semantics", "synthetic non-live PID selected so permit/unpermit proves the API without allowing a live process" });
			if (probe_pid == 0) {
				r.ok = false;
				r.error = "ADMP query succeeded but safe non-live PID probe selection failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
				return;
			}
			const admp_call_result_t permit = send_admp_request(kAdmpOpPermitPid, probe_pid);
			admp_call_result_t unpermit = send_admp_request(kAdmpOpUnpermitPid, probe_pid);
			append_admp_call_fields(r, "permit_roundtrip_permit", permit);
			append_admp_call_fields(r, "permit_roundtrip_unpermit", unpermit);
			bool unpermit_retry_attempted = false;
			admp_call_result_t unpermit_retry;
			if (permit.ok && permit.req.result == 1u && (!unpermit.ok || unpermit.req.result != 1u)) {
				unpermit_retry_attempted = true;
				unpermit_retry = send_admp_request(kAdmpOpUnpermitPid, probe_pid);
				append_admp_call_fields(r, "permit_roundtrip_unpermit_retry", unpermit_retry);
			}
			const bool unpermit_ok = (unpermit.ok && unpermit.req.result == 1u) ||
				(unpermit_retry_attempted && unpermit_retry.ok && unpermit_retry.req.result == 1u);
			const bool roundtrip_ok = permit.ok && permit.req.result == 1u && unpermit_ok;
			r.parsed.push_back({ "permit_roundtrip_unpermit_retry_attempted", unpermit_retry_attempted ? "1" : "0" });
			r.parsed.push_back({ "permit_roundtrip_ok", roundtrip_ok ? "1" : "0" });
			test_lab_format::testlab_diag_log_step("anti-dump", "ADMP", "permit_roundtrip",
				"probe_pid=%u permit_ok=%d permit_gle=%lu permit_result=%u permit_bytes=%u permit_elapsed_ms=%llu unpermit_ok=%d unpermit_gle=%lu unpermit_result=%u unpermit_bytes=%u unpermit_elapsed_ms=%llu unpermit_retry=%d unpermit_retry_ok=%d unpermit_retry_gle=%lu unpermit_retry_result=%u roundtrip_ok=%d",
				probe_pid,
				permit.ok ? 1 : 0,
				static_cast<unsigned long>(permit.gle),
				permit.req.result,
				permit.bytes_returned,
				static_cast<unsigned long long>(permit.elapsed_ms),
				unpermit.ok ? 1 : 0,
				static_cast<unsigned long>(unpermit.gle),
				unpermit.req.result,
				unpermit.bytes_returned,
				static_cast<unsigned long long>(unpermit.elapsed_ms),
				unpermit_retry_attempted ? 1 : 0,
				unpermit_retry.ok ? 1 : 0,
				static_cast<unsigned long>(unpermit_retry.gle),
				unpermit_retry.req.result,
				roundtrip_ok ? 1 : 0);
			if (!roundtrip_ok) {
				r.ok = false;
				r.error = "ADMP safe permit/unpermit roundtrip failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_admp, "anti-dump", test_lab::driver_e::whoswho, "ADMP",
	"Anti-dump request (FULL_PROTECT, ERASE_HEADERS, SCAN_KILL, START/STOP_CONTINUOUS, QUERY, etc).",
	&render_inputs_admp, &run_admp);
