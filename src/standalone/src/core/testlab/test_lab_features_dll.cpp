#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "../runtime/standalone_driver.hpp"
#include "imgui/imgui.h"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <string>
#include <vector>

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

	void push_bool(test_lab::result_t& r, const char* label, bool v) {
		r.parsed.push_back({ label, v ? "1" : "0" });
	}

	bool parse_u64_hex_strict(const std::string& text, std::uint64_t& out) {
		out = 0;
		if (text.empty())
			return false;
		const char* p = text.c_str();
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		if (*p == '\0')
			return false;
		std::uint64_t acc = 0;
		std::uint32_t digits = 0;
		while (*p) {
			const char c = *p++;
			std::uint64_t d = 0;
			if (c >= '0' && c <= '9')
				d = static_cast<std::uint64_t>(c - '0');
			else if (c >= 'a' && c <= 'f')
				d = static_cast<std::uint64_t>(10 + (c - 'a'));
			else if (c >= 'A' && c <= 'F')
				d = static_cast<std::uint64_t>(10 + (c - 'A'));
			else
				return false;
			if (++digits > 16)
				return false;
			acc = (acc << 4) | d;
		}
		out = acc;
		return digits > 0;
	}

	std::uint64_t compute_dprt_hash(const std::vector<std::uint8_t>& bytes) {
		std::uint64_t h1 = 0xFFFFFFFFULL;
		std::uint64_t h2 = 0x85EBCA6BULL;
		const std::size_t aligned_end = bytes.size() & ~static_cast<std::size_t>(7);
		for (std::size_t i = 0; i < aligned_end; i += 8) {
			std::uint64_t block = 0;
			std::memcpy(&block, bytes.data() + i, sizeof(block));
			h1 = _mm_crc32_u64(h1, block);
			h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
		}
		for (std::size_t i = aligned_end; i < bytes.size(); ++i) {
			h1 = _mm_crc32_u8(static_cast<unsigned int>(h1), bytes[i]);
			h2 = _mm_crc32_u8(static_cast<unsigned int>(h2), bytes[i] ^ 0xA5u);
		}
		return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
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
		const bool supplied_hash = parse_u64_hex_strict(s.text_b, expected_hash);

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
			if (s.addr == 0 || s.size == 0) {
				r.ok = false;
				r.error = "REGISTER requires text_section_va and text size to be non-zero";
				return;
			}
			if (s.size > 0x100000u) {
				r.ok = false;
				r.error = "REGISTER text size exceeds safe Test Lab cap";
				r.ntstatus = static_cast<std::int32_t>(0xC0000206u);
				return;
			}
			if (s.u64_a == 0 && s.pid == GetCurrentProcessId()) {
				r.ok = false;
				r.error = "diagnostic module_base=0 DPRT registration is not allowed for the AiDA process";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			}
			r.parsed.push_back({ "module_base_policy", s.u64_a == 0 ? "diagnostic_fail_closed" : "module_hard_bugcheck" });

			std::vector<std::uint8_t> baseline;
			const bool read_ok = driver_bridge::read_memory_for(s.pid, s.addr, s.size, baseline);
			push_bool(r, "baseline_read_ok", read_ok);
			push_u32_hex(r, "baseline_requested_size", s.size);
			push_u32_hex(r, "baseline_bytes_read", static_cast<std::uint32_t>(baseline.size()));
			if (!read_ok || baseline.size() != s.size) {
				r.ok = false;
				r.error = "failed to read exact DPRT baseline bytes from target";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}

			const std::uint64_t live_hash = compute_dprt_hash(baseline);
			push_bool(r, "expected_hash_supplied", supplied_hash);
			push_u64_hex(r, "live_baseline_hash", live_hash);
			if (!supplied_hash || expected_hash == 0) {
				r.parsed.push_back({ "expected_hash_source", "computed_live_baseline_diagnostic" });
				push_bool(r, "dprt_functional_pass_eligible", false);
				r.ok = false;
				r.error = "DPRT functional registration requires a supplied known-good expected_hash; live baseline is diagnostic only";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			} else if (expected_hash != live_hash) {
				r.ok = false;
				r.error = "provided expected_hash does not match live target bytes; refusing to arm bugcheckable DPRT slot";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			} else {
				r.parsed.push_back({ "expected_hash_source", "provided_verified" });
				push_bool(r, "dprt_functional_pass_eligible", true);
			}
			if (req.check_interval == 0)
				req.check_interval = 30000u;
			push_u32_hex(r, "effective_check_interval_ms", req.check_interval);
		} else if (!s.text_b.empty() && !supplied_hash) {
			r.parsed.push_back({ "expected_hash_input", "ignored_non_hex" });
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

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			r.parsed.push_back({ "register_status", dprt_status_label(req.status) });
			push_u32_hex(r, "register_bytes_returned", bytes_returned);
			if (req.status != voyager::detail::DPRT_STATUS_ACTIVE || req.current_hash != req.expected_hash) {
				voyager::detail::dll_protect_request cleanup{};
				cleanup.operation = voyager::detail::DPRT_OP_UNREGISTER;
				cleanup.pid = s.pid;
				cleanup.module_base = req.module_base;
				std::uint32_t cleanup_bytes = 0;
				device->send_ioctl_raw(ioctl_codes::DPRT(), &cleanup, static_cast<std::uint32_t>(sizeof(cleanup)), cleanup_bytes);
				r.ok = false;
				r.error = "DPRT register did not return active matching status";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}

			voyager::detail::dll_protect_request query{};
			query.operation = voyager::detail::DPRT_OP_QUERY;
			query.pid = s.pid;
			query.module_base = req.module_base;
			std::uint32_t query_bytes = 0;
			const bool query_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &query,
				static_cast<std::uint32_t>(sizeof(query)), query_bytes);
			push_bool(r, "query_after_register_ok", query_ok);
			push_u32_hex(r, "query_after_register_bytes", query_bytes);
			r.parsed.push_back({ "query_after_register_status", dprt_status_label(query.status) });
			push_u64_hex(r, "query_after_register_current_hash", query.current_hash);

			voyager::detail::dll_protect_request unreg{};
			unreg.operation = voyager::detail::DPRT_OP_UNREGISTER;
			unreg.pid = s.pid;
			unreg.module_base = req.module_base;
			std::uint32_t unreg_bytes = 0;
			const bool unreg_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &unreg,
				static_cast<std::uint32_t>(sizeof(unreg)), unreg_bytes);
			push_bool(r, "unregister_ok", unreg_ok);
			push_u32_hex(r, "unregister_bytes", unreg_bytes);
			r.parsed.push_back({ "unregister_status", dprt_status_label(unreg.status) });

			voyager::detail::dll_protect_request post{};
			post.operation = voyager::detail::DPRT_OP_QUERY;
			post.pid = s.pid;
			post.module_base = req.module_base;
			std::uint32_t post_bytes = 0;
			const bool post_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &post,
				static_cast<std::uint32_t>(sizeof(post)), post_bytes);
			push_bool(r, "query_after_unregister_ok", post_ok);
			push_u32_hex(r, "query_after_unregister_bytes", post_bytes);
			r.parsed.push_back({ "query_after_unregister_status", dprt_status_label(post.status) });
			r.ok = query_ok &&
				unreg_ok &&
				post_ok &&
				query.status == voyager::detail::DPRT_STATUS_ACTIVE &&
				query.current_hash == expected_hash &&
				post.status == voyager::detail::DPRT_STATUS_INACTIVE;
			if (!r.ok) {
				r.error = "DPRT register/query/unregister round-trip did not verify all expected states";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}
			r.parsed.push_back({ "dprt_functional_proof", "provided_hash_register_query_unregister" });
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
