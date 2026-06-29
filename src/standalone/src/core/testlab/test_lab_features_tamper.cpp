#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <intrin.h>

namespace {

	bool hex_nibble(char c, std::uint8_t& out) {
		if (c >= '0' && c <= '9') { out = static_cast<std::uint8_t>(c - '0'); return true; }
		if (c >= 'a' && c <= 'f') { out = static_cast<std::uint8_t>(10 + (c - 'a')); return true; }
		if (c >= 'A' && c <= 'F') { out = static_cast<std::uint8_t>(10 + (c - 'A')); return true; }
		return false;
	}

	bool parse_hex_bytes(const std::string& text, std::vector<std::uint8_t>& out_bytes) {
		out_bytes.clear();
		std::string clean;
		clean.reserve(text.size());
		std::size_t i = 0;
		while (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
			i += 2;
		}
		for (; i < text.size(); ++i) {
			char c = text[i];
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-' || c == ':' || c == ',') continue;
			clean.push_back(c);
		}
		if (clean.empty() || (clean.size() % 2) != 0) return false;
		out_bytes.reserve(clean.size() / 2);
		for (std::size_t j = 0; j < clean.size(); j += 2) {
			std::uint8_t hi = 0;
			std::uint8_t lo = 0;
			if (!hex_nibble(clean[j], hi))     return false;
			if (!hex_nibble(clean[j + 1], lo)) return false;
			out_bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
		}
		return true;
	}

	std::uint32_t fold_bytes_to_u32(const std::vector<std::uint8_t>& bytes) {
		std::uint32_t acc = 0x811C9DC5u;
		for (std::uint8_t b : bytes) {
			acc ^= b;
			acc *= 0x01000193u;
		}
		return acc;
	}

	std::uint64_t fold_bytes_to_u64(const std::vector<std::uint8_t>& bytes) {
		std::uint64_t acc = 0xCBF29CE484222325ull;
		for (std::uint8_t b : bytes) {
			acc ^= b;
			acc *= 0x100000001B3ull;
		}
		return acc;
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

	void push_u64_dec(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	void push_bool(test_lab::result_t& r, const char* label, bool value) {
		r.parsed.push_back({ label, value ? "1" : "0" });
	}

	struct abrt_state_t {
		bool confirmed = false;
	};

	void render_inputs_abrt(test_lab::state_t& s) {
		if (s.user == nullptr) {
			static abrt_state_t s_fallback;
			s.user = &s_fallback;
		}
		auto* st = static_cast<abrt_state_t*>(s.user);

		ImGui::TextColored(ImVec4(1.0f, 0.30f, 0.30f, 1.0f),
			"WARNING: ABRT issues a tamper-abort to the kernel.");
		ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
			"It may trigger BugCheck 0xDEAD0001 (BSOD) if the kernel confirms");
		ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f),
			"the reason via anti-debug/scan. Save your work first.");
		ImGui::Spacing();

		ImGui::Checkbox("I understand this may trigger tamper kill", &st->confirmed);

		ImGui::InputScalar("Reason code (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "0x%08X",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Evidence hash (u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Common reasons: 0x0001 GENERIC, 0x0002 DEBUG, 0x0003 DR_SET, 0x0004 FOREIGN_HND, 0x0005 INJECTED_DLL, 0x0006 WATCHDOG.");
	}

	void run_abrt(test_lab::state_t& s, test_lab::result_t& r) {
		auto* st = static_cast<abrt_state_t*>(s.user);
		if (st == nullptr || !st->confirmed) {
			r.ok = false;
			r.error = "confirmation not set";
			return;
		}
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		(void)device->trigger_kernel_bsod(s.u32_a, s.u64_a);
		push_u32_hex(r, "reason_code", s.u32_a);
		push_u64_hex(r, "evidence_hash", s.u64_a);
		r.parsed.push_back({ "dispatch", "trigger_kernel_bsod posted via ABRT IOCTL" });
		r.parsed.push_back({ "note",
			"Kernel may BugCheck synchronously; if you read this, evidence did not pass kernel confirmation." });
		r.ok = true;
	}

	void render_inputs_srvt(test_lab::state_t& s) {
		char buf[513];
		std::snprintf(buf, sizeof(buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Token (hex)", buf, sizeof(buf))) {
			s.text_a.assign(buf);
		}
		ImGui::TextDisabled("Token bytes are folded into a 32-bit token_hash and posted with a TSC nonce.");
	}

	void run_srvt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		std::vector<std::uint8_t> bytes;
		if (!parse_hex_bytes(s.text_a, bytes) || bytes.empty()) {
			r.ok = false;
			r.error = "invalid or empty hex token";
			return;
		}
		std::uint32_t token_hash = fold_bytes_to_u32(bytes);
		std::uint64_t server_nonce = static_cast<std::uint64_t>(__rdtsc());
		const std::uint32_t caller_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		device->sync_dynamic_security_state();
		const bool server_seed_before = device->has_server_seed();
		const bool ioctl_seed_before = device->has_server_ioctl_seed();
		const std::uint64_t timestamp = static_cast<std::uint64_t>(__rdtsc());
		const std::uint64_t start_ms = static_cast<std::uint64_t>(GetTickCount64());

		bool ok = false;
		DWORD gle = ERROR_SUCCESS;
		for (int attempt = 0; attempt < 3; ++attempt) {
			SetLastError(ERROR_SUCCESS);
			ok = device->relay_server_token(token_hash, server_nonce);
			gle = ok ? ERROR_SUCCESS : GetLastError();
			if (ok || gle != ERROR_BUSY) break;
			Sleep(50);
		}
		const std::uint64_t elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_ms;
		voyager::detail::server_token_relay evidence{};
		evidence.token_hash = token_hash;
		evidence.timestamp = timestamp;
		evidence.server_nonce = server_nonce;
		evidence.result = ok ? 1u : 0u;
		r.bytes_returned = ok ? static_cast<std::uint32_t>(sizeof(evidence)) : 0u;
		r.raw.resize(sizeof(evidence));
		std::memcpy(r.raw.data(), &evidence, sizeof(evidence));
		push_u32_hex(r, "token_hash", token_hash);
		push_u64_hex(r, "server_nonce", server_nonce);
		push_u32_hex(r, "token_bytes_consumed", static_cast<std::uint32_t>(bytes.size()));
		r.parsed.push_back({ "ioctl", "SRVT" });
		push_bool(r, "accepted", ok);
		r.parsed.push_back({ "result", ok ? "accepted" : "rejected" });
		push_u32_hex(r, "last_error", gle);
		push_u32_hex(r, "expected_bytes", static_cast<std::uint32_t>(sizeof(evidence)));
		push_u32_hex(r, "returned_bytes", r.bytes_returned);
		push_u32_hex(r, "caller_pid", caller_pid);
		push_u32_hex(r, "registered_pid_expected", caller_pid);
		push_bool(r, "session_present", ok);
		push_bool(r, "session_presence_inferred_from_acceptance", ok);
		push_bool(r, "server_seed_present_before", server_seed_before);
		push_bool(r, "server_ioctl_seed_present_before", ioctl_seed_before);
		push_bool(r, "server_seed_present", device->has_server_seed());
		push_bool(r, "server_ioctl_seed_present", device->has_server_ioctl_seed());
		push_u64_dec(r, "elapsed_ms", elapsed_ms);
		if (!ok) {
			r.ok = false;
			r.error = "relay_server_token returned false (kernel rejected or session_key mismatch)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "accepted_effect", "driver activated, last_heartbeat_time updated" });
		r.ok = true;
	}

	void render_inputs_srv2(test_lab::state_t& s) {
		char buf[513];
		std::snprintf(buf, sizeof(buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Token (hex)", buf, sizeof(buf))) {
			s.text_a.assign(buf);
		}
		ImGui::InputScalar("Epoch (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Token folded to 32-bit hash. Epoch is XORed into server_nonce low dword; driver returns a per-session driver_proof.");
	}

	void run_srv2(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		std::vector<std::uint8_t> bytes;
		if (!parse_hex_bytes(s.text_a, bytes) || bytes.empty()) {
			r.ok = false;
			r.error = "invalid or empty hex token";
			return;
		}
		std::uint32_t token_hash = fold_bytes_to_u32(bytes);
		std::uint64_t tsc = static_cast<std::uint64_t>(__rdtsc());
		std::uint64_t server_nonce = (tsc & 0xFFFFFFFF00000000ull) | static_cast<std::uint64_t>(s.u32_a);
		const std::uint32_t caller_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		device->sync_dynamic_security_state();
		device->refresh_heartbeat();
		const bool server_seed_before = device->has_server_seed();
		const bool ioctl_seed_before = device->has_server_ioctl_seed();
		const std::uint64_t timestamp = static_cast<std::uint64_t>(__rdtsc());
		const std::uint64_t start_ms = static_cast<std::uint64_t>(GetTickCount64());

		std::uint64_t out_driver_proof = 0;
		bool ok = false;
		DWORD gle = ERROR_SUCCESS;
		for (int attempt = 0; attempt < 3; ++attempt) {
			SetLastError(ERROR_SUCCESS);
			ok = device->relay_server_token_v2(token_hash, server_nonce, &out_driver_proof);
			gle = ok ? ERROR_SUCCESS : GetLastError();
			if (ok || gle != ERROR_BUSY) break;
			Sleep(50);
		}
		const std::uint64_t elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_ms;
		voyager::detail::server_token_relay_v2 evidence{};
		evidence.token_hash = token_hash;
		evidence.timestamp = timestamp;
		evidence.server_nonce = server_nonce;
		evidence.driver_proof = out_driver_proof;
		evidence.result = ok ? 1u : 0u;
		r.bytes_returned = ok ? static_cast<std::uint32_t>(sizeof(evidence)) : 0u;
		r.raw.resize(sizeof(evidence));
		std::memcpy(r.raw.data(), &evidence, sizeof(evidence));
		push_u32_hex(r, "token_hash",      token_hash);
		push_u64_hex(r, "server_nonce",    server_nonce);
		push_u32_hex(r, "epoch",           s.u32_a);
		push_u64_hex(r, "fold_u64_preview", fold_bytes_to_u64(bytes));
		r.parsed.push_back({ "ioctl", "SRV2" });
		push_bool(r, "accepted", ok);
		r.parsed.push_back({ "result", ok ? "accepted" : "rejected" });
		push_u32_hex(r, "last_error", gle);
		push_u32_hex(r, "expected_bytes", static_cast<std::uint32_t>(sizeof(evidence)));
		push_u32_hex(r, "returned_bytes", r.bytes_returned);
		push_u32_hex(r, "caller_pid", caller_pid);
		push_u32_hex(r, "registered_pid_expected", caller_pid);
		push_bool(r, "session_present", ok);
		push_bool(r, "session_presence_inferred_from_acceptance", ok);
		push_bool(r, "server_seed_present_before", server_seed_before);
		push_bool(r, "server_ioctl_seed_present_before", ioctl_seed_before);
		push_bool(r, "server_seed_present", device->has_server_seed());
		push_bool(r, "server_ioctl_seed_present", device->has_server_ioctl_seed());
		push_bool(r, "driver_proof_present", out_driver_proof != 0);
		push_u64_dec(r, "elapsed_ms", elapsed_ms);
		if (!ok) {
			r.ok = false;
			const DWORD hb_err_val = device->get_last_heartbeat_error();
			const bool session_invalidated = device->session_invalidated();
			diag::log_tagged_fmt("testlab",
				"SRV2_fail_detail gle=%lu hb_err=%lu session_invalidated=%d token_hash=0x%08X nonce=0x%llX",
				static_cast<unsigned long>(gle),
				static_cast<unsigned long>(hb_err_val),
				session_invalidated ? 1 : 0,
				token_hash,
				static_cast<unsigned long long>(server_nonce));
			push_u64_hex(r, "driver_proof", out_driver_proof);
			r.error = "relay_server_token_v2 returned false (kernel rejected or session_key mismatch)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		push_u64_hex(r, "driver_proof", out_driver_proof);
		r.ok = true;
	}

	void render_inputs_rela(test_lab::state_t& s) {
		const char* items[] = {
			"GENERIC (1)",
			"DEBUG_ATTACH (2)",
			"DR_SET (3)",
			"FOREIGN_HND (4)",
			"INJECTED_DLL (5)",
			"WATCHDOG_STALL (6)",
			"Custom (u32_a)"
		};
		int sel = 6;
		switch (s.u32_a) {
			case 1: sel = 0; break;
			case 2: sel = 1; break;
			case 3: sel = 2; break;
			case 4: sel = 3; break;
			case 5: sel = 4; break;
			case 6: sel = 5; break;
			default: sel = 6; break;
		}
		if (ImGui::Combo("Reason", &sel, items, IM_ARRAYSIZE(items))) {
			switch (sel) {
				case 0: s.u32_a = 1; break;
				case 1: s.u32_a = 2; break;
				case 2: s.u32_a = 3; break;
				case 3: s.u32_a = 4; break;
				case 4: s.u32_a = 5; break;
				case 5: s.u32_a = 6; break;
				default: break;
			}
		}
		ImGui::InputScalar("Reason value (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "0x%08X",
			ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Latches a targeting reason against the registered client PID for re-arming the kernel anti-debug latch.");
	}

	void run_rela(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		const std::uint32_t caller_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		device->sync_dynamic_security_state();
		const bool server_seed_before = device->has_server_seed();
		const bool ioctl_seed_before = device->has_server_ioctl_seed();
		const std::uint64_t start_ms = static_cast<std::uint64_t>(GetTickCount64());
		SetLastError(ERROR_SUCCESS);
		bool ok = device->latch_targeting_from_usermode(s.u32_a);
		const DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
		const std::uint64_t elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_ms;
		voyager::detail::latch_targeting_request evidence{};
		evidence.reason = s.u32_a;
		r.bytes_returned = ok ? static_cast<std::uint32_t>(sizeof(evidence)) : 0u;
		r.raw.resize(sizeof(evidence));
		std::memcpy(r.raw.data(), &evidence, sizeof(evidence));
		push_u32_hex(r, "reason", s.u32_a);
		r.parsed.push_back({ "ioctl", "RELA" });
		push_bool(r, "accepted", ok);
		r.parsed.push_back({ "result", ok ? "latched" : "rejected" });
		push_u32_hex(r, "last_error", gle);
		push_u32_hex(r, "expected_bytes", static_cast<std::uint32_t>(sizeof(evidence)));
		push_u32_hex(r, "returned_bytes", r.bytes_returned);
		push_u32_hex(r, "caller_pid", caller_pid);
		push_u32_hex(r, "registered_pid_expected", caller_pid);
		push_bool(r, "session_present", ok);
		push_bool(r, "session_presence_inferred_from_acceptance", ok);
		push_bool(r, "server_seed_present_before", server_seed_before);
		push_bool(r, "server_ioctl_seed_present_before", ioctl_seed_before);
		push_bool(r, "server_seed_present", device->has_server_seed());
		push_bool(r, "server_ioctl_seed_present", device->has_server_ioctl_seed());
		push_u64_dec(r, "elapsed_ms", elapsed_ms);
		if (!ok) {
			r.ok = false;
			r.error = "latch_targeting_from_usermode returned false (session_key or magic mismatch)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "latched_scope", "registered client PID" });
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_abrt, "tamper", test_lab::driver_e::whoswho, "ABRT",
	"Tamper-abort / kill-switch test (may BugCheck the kernel - requires confirmation).",
	&render_inputs_abrt, &run_abrt);

TESTLAB_REGISTER(g_reg_srvt, "tamper", test_lab::driver_e::whoswho, "SRVT",
	"Server token relay v1 (folds hex token to 32-bit hash and posts with TSC nonce).",
	&render_inputs_srvt, &run_srvt);

TESTLAB_REGISTER(g_reg_srv2, "tamper", test_lab::driver_e::whoswho, "SRV2",
	"Server token relay v2 (adds epoch and reads back driver_proof).",
	&render_inputs_srv2, &run_srv2);

TESTLAB_REGISTER(g_reg_rela, "tamper", test_lab::driver_e::whoswho, "RELA",
	"Targeting latch / re-arm (pin a reason onto the registered client PID).",
	&render_inputs_rela, &run_rela);
