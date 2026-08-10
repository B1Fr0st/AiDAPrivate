#pragma once

#include "imgui/imgui.h"
#include "test_lab.hpp"
#include "../../helpers/diag_log.hpp"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace test_lab_format {

	inline const char* testlab_driver_name(test_lab::driver_e d) {
		switch (d) {
			case test_lab::driver_e::whoswho:  return "whoswho";
			case test_lab::driver_e::driverless: return "driverless";
		}
		return "unknown";
	}

	inline const char* testlab_outcome_name(test_lab::outcome_e outcome) {
		switch (outcome) {
			case test_lab::outcome_e::not_run: return "not_run";
			case test_lab::outcome_e::missing: return "missing";
			case test_lab::outcome_e::passed: return "passed";
			case test_lab::outcome_e::failed: return "failed";
			case test_lab::outcome_e::timed_out: return "timed_out";
			case test_lab::outcome_e::crashed: return "crashed";
			case test_lab::outcome_e::cancelled: return "cancelled";
			case test_lab::outcome_e::malformed_result: return "malformed_result";
			case test_lab::outcome_e::integrity_failure: return "integrity_failure";
		}
		return "not_run";
	}

	inline void testlab_diag_log_entry(const test_lab::feature_t& f, const test_lab::state_t& s) {
		diag::log_tagged_fmt("testlab",
			"%s/%s: entry pid=%u tid=%u addr=0x%llX size=%u u32_a=0x%08X u32_b=0x%08X u64_a=0x%llX buf_size=%zu text_a=\"%.96s\" text_b=\"%.96s\"",
			testlab_driver_name(f.driver),
			(f.name != nullptr ? f.name : "?"),
			static_cast<unsigned>(s.pid),
			static_cast<unsigned>(s.tid),
			static_cast<unsigned long long>(s.addr),
			static_cast<unsigned>(s.size),
			static_cast<unsigned>(s.u32_a),
			static_cast<unsigned>(s.u32_b),
			static_cast<unsigned long long>(s.u64_a),
			s.buf.size(),
			s.text_a.c_str(),
			s.text_b.c_str());
	}

	inline void testlab_diag_log_exit(const test_lab::feature_t& f,
		const test_lab::result_t& r,
		std::uint64_t elapsed_us)
	{
		std::uint32_t last_err = GetLastError();
		diag::log_tagged_fmt("testlab",
			"%s/%s: exit outcome=%s ok=%d skipped=%d ntstatus=0x%08X bytes=%u elapsed_us=%llu last_err=%lu parsed_fields=%zu raw_size=%zu error=\"%.256s\"",
			testlab_driver_name(f.driver),
			(f.name != nullptr ? f.name : "?"),
			testlab_outcome_name(test_lab::effective_outcome(r, f.driver == test_lab::driver_e::driverless)),
			r.ok ? 1 : 0,
			r.skipped ? 1 : 0,
			static_cast<unsigned>(static_cast<std::uint32_t>(r.ntstatus)),
			static_cast<unsigned>(r.bytes_returned),
			static_cast<unsigned long long>(elapsed_us),
			static_cast<unsigned long>(last_err),
			r.parsed.size(),
			r.raw.size(),
			r.error.c_str());
	}

	inline void testlab_diag_log_skip(const test_lab::feature_t& f, const char* reason) {
		diag::log_tagged_fmt("testlab",
			"%s/%s: skipped reason=\"%s\"",
			testlab_driver_name(f.driver),
			(f.name != nullptr ? f.name : "?"),
			(reason != nullptr ? reason : "(no reason)"));
	}

	inline void testlab_diag_log_step(const char* category,
		const char* feature,
		const char* step,
		const char* fmt,
		...)
	{
		char detail[1024];
		detail[0] = '\0';
		if (fmt != nullptr) {
			va_list ap;
			va_start(ap, fmt);
			_vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
			va_end(ap);
		}
		diag::log_tagged_fmt("testlab",
			"%s/%s: step=%s %s",
			(category != nullptr ? category : "?"),
			(feature != nullptr ? feature : "?"),
			(step != nullptr ? step : "?"),
			detail);
	}

	inline const char* ntstatus_to_string(std::int32_t status) {
		switch (static_cast<std::uint32_t>(status)) {
			case 0x00000000u: return "STATUS_SUCCESS";
			case 0xC000000Du: return "STATUS_INVALID_PARAMETER";
			case 0xC0000022u: return "STATUS_ACCESS_DENIED";
			case 0xC0000225u: return "STATUS_NOT_FOUND";
			case 0xC0000010u: return "STATUS_INVALID_DEVICE_REQUEST";
			case 0xC0000023u: return "STATUS_BUFFER_TOO_SMALL";
			case 0xC000009Au: return "STATUS_INSUFFICIENT_RESOURCES";
			case 0xC0000001u: return "STATUS_UNSUCCESSFUL";
			default: break;
		}
		static thread_local char s_buf[24];
		std::snprintf(s_buf, sizeof(s_buf), "STATUS_0x%08X",
			static_cast<unsigned>(static_cast<std::uint32_t>(status)));
		return s_buf;
	}

	inline void render_hex_ascii(const std::vector<std::uint8_t>& buf) {
		if (buf.empty()) {
			ImGui::TextDisabled("(empty)");
			return;
		}
		const std::size_t bytes_per_row = 16;
		char hex_part[3 * 16 + 1];
		char ascii_part[16 + 1];
		char line[256];
		for (std::size_t row = 0; row < buf.size(); row += bytes_per_row) {
			std::size_t row_len = buf.size() - row;
			if (row_len > bytes_per_row) row_len = bytes_per_row;
			std::size_t hp = 0;
			std::size_t ap = 0;
			for (std::size_t i = 0; i < bytes_per_row; ++i) {
				if (i < row_len) {
					unsigned b = static_cast<unsigned>(buf[row + i]);
					hp += static_cast<std::size_t>(std::snprintf(hex_part + hp, sizeof(hex_part) - hp,
						"%02X ", b));
					unsigned char c = static_cast<unsigned char>(b);
					ascii_part[ap++] = (c >= 0x20u && c < 0x7Fu) ? static_cast<char>(c) : '.';
				} else {
					hp += static_cast<std::size_t>(std::snprintf(hex_part + hp, sizeof(hex_part) - hp,
						"   "));
					ascii_part[ap++] = ' ';
				}
			}
			ascii_part[ap] = '\0';
			std::snprintf(line, sizeof(line), "%08zX  %s %s",
				row, hex_part, ascii_part);
			ImGui::TextUnformatted(line);
		}
	}

}
