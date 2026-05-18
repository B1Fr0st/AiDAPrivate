#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

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
		if (admp_op_requires_pid(s.u32_a) && s.pid == 0) {
			r.ok = false;
			r.error = "selected subcommand requires a non-zero PID";
			return;
		}

		voyager::detail::anti_dump_request req{};
		req.operation = s.u32_a;
		req.pid       = s.pid;

		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::ADMP(), &req,
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

		r.parsed.push_back({ "subcommand", admp_op_label(req.operation) });
		push_u32_hex(r, "operation", req.operation);
		push_u32_hex(r, "pid",       req.pid);
		push_u64_dec(r, "blocks_count", req.blocks_count);
		push_u32_hex(r, "result",    req.result);
		r.parsed.push_back({ "verdict", (req.result == 1u) ? "OK" : "FAILED_OR_PARTIAL" });
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_admp, "anti-dump", test_lab::driver_e::whoswho, "ADMP",
	"Anti-dump request (FULL_PROTECT, ERASE_HEADERS, SCAN_KILL, START/STOP_CONTINUOUS, QUERY, etc).",
	&render_inputs_admp, &run_admp);
