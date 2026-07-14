#include "result_adapter.hpp"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <exception>
#include <limits>
#include <string_view>

namespace aida::analysis::c03_test::testlab_runtime {
namespace {

using json = nlohmann::json;

bool hex_digest(std::string_view value) noexcept {
	if (value.size() != 64) return false;
	for (const unsigned char ch : value) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
	}
	return true;
}

bool identifier(std::string_view value, std::size_t maximum) noexcept {
	if (value.empty() || value.size() > maximum) return false;
	for (const unsigned char ch : value) {
		if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') continue;
		return false;
	}
	return true;
}

bool parse_handle(std::string_view value, std::uintptr_t& output) noexcept {
	if (value.empty()) return false;
	std::uint64_t parsed = 0;
	const auto converted = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
	if (converted.ec != std::errc{} || converted.ptr != value.data() + value.size() || parsed == 0 ||
		parsed > std::numeric_limits<std::uintptr_t>::max()) return false;
	output = static_cast<std::uintptr_t>(parsed);
	return true;
}

bool write_all(HANDLE handle, const void* bytes, std::size_t size, std::string& error) {
	const auto* cursor = static_cast<const std::uint8_t*>(bytes);
	std::size_t offset = 0;
	while (offset < size) {
		DWORD written = 0;
		const DWORD requested = static_cast<DWORD>((std::min)(size - offset,
			static_cast<std::size_t>(64 * 1024)));
		if (!WriteFile(handle, cursor + offset, requested, &written, nullptr) || written == 0) {
			error = "result envelope WriteFile failed with Win32 error " + std::to_string(GetLastError());
			return false;
		}
		offset += written;
	}
	return true;
}

}

bool parse_adapter_control(int argc, char** argv, adapter_control_t& control, std::string& error) {
	if (argc <= 0 || argv == nullptr) {
		error = "adapter arguments are unavailable";
		return false;
	}
	bool have_handle = false;
	bool have_id = false;
	bool have_target = false;
	bool have_build = false;
	for (int index = 1; index < argc; ++index) {
		if (argv[index] == nullptr) {
			error = "adapter argument is null";
			return false;
		}
		const std::string_view argument(argv[index]);
		const auto parse_control = [&](std::string_view prefix, std::string& destination, bool& seen) {
			if (argument.rfind(prefix, 0) != 0) return false;
			if (seen) {
				error = "adapter control argument is duplicated";
				return true;
			}
			destination.assign(argument.substr(prefix.size()));
			seen = true;
			return true;
		};
		if (argument.rfind("--aida-c03-result-handle=", 0) == 0) {
			if (have_handle || !parse_handle(argument.substr(25), control.result_handle)) {
				error = "adapter result handle is invalid or duplicated";
				return false;
			}
			have_handle = true;
			continue;
		}
		if (parse_control("--aida-c03-entry-id=", control.entry_id, have_id)) {
			if (!error.empty()) return false;
			continue;
		}
		if (parse_control("--aida-c03-source-target=", control.source_target, have_target)) {
			if (!error.empty()) return false;
			continue;
		}
		if (parse_control("--aida-c03-build-identity=", control.build_identity, have_build)) {
			if (!error.empty()) return false;
			continue;
		}
		if (argument.rfind("--aida-c03-", 0) == 0) {
			error = "adapter received an unknown control argument";
			return false;
		}
		control.forwarded_arguments.emplace_back(argument);
	}
	if (!have_handle || !have_id || !have_target || !have_build ||
		!identifier(control.entry_id, 96) || !identifier(control.source_target, 160) ||
		!hex_digest(control.build_identity)) {
		error = "adapter control contract is incomplete or malformed";
		return false;
	}
	const HANDLE handle = reinterpret_cast<HANDLE>(control.result_handle);
	DWORD flags = 0;
	if (!GetHandleInformation(handle, &flags) || (flags & HANDLE_FLAG_INHERIT) == 0) {
		error = "adapter result handle is not an inherited handle";
		return false;
	}
	return true;
}

bool write_result_envelope(const adapter_control_t& control, int exit_code,
	std::uint64_t elapsed_us, const assertion_telemetry::assertion_report_t& report,
	std::string& error) {
	if (!report.valid || !report.finalized || report.error_flags != assertion_telemetry::ledger_error_none ||
		report.epoch == 0 || report.entry_id != control.entry_id || report.source_target != control.source_target ||
		report.total > assertion_telemetry::k_max_assertions || report.passed > report.total ||
		report.failed > report.total ||
		static_cast<std::uint64_t>(report.passed) + report.failed != report.total ||
		report.skipped > assertion_telemetry::k_max_skipped || report.reporting_threads == 0 ||
		report.reporting_threads > assertion_telemetry::k_max_reporting_threads || report.late_writes != 0 ||
		report.event_digest.size() != 32 || report.first_failure.size() > assertion_telemetry::k_max_failure_text ||
		(report.not_run && (report.total != 0 || report.skipped == 0 || exit_code != 0)) ||
		(!report.not_run && (report.total == 0 || report.skipped != 0 ||
			(exit_code == 0 && report.failed != 0) || (exit_code != 0 && report.failed == 0)))) {
		error = "adapter assertion ledger is invalid or inconsistent";
		return false;
	}
	for (const unsigned char ch : report.event_digest) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
			error = "adapter assertion ledger digest is invalid";
			return false;
		}
	}
	json evidence = json::array({
		{{"name", "adapter_exit_code"}, {"value", std::to_string(exit_code)}},
		{{"name", "ledger_epoch"}, {"value", std::to_string(report.epoch)}},
		{{"name", "ledger_digest"}, {"value", report.event_digest}},
		{{"name", "reporting_threads"}, {"value", std::to_string(report.reporting_threads)}}
	});
	if (!report.first_failure.empty())
		evidence.push_back({{"name", "first_failure"}, {"value", report.first_failure}});
	const json envelope = {
		{"schema", "aida.c03.safe-headless.result.v1"},
		{"version", 1},
		{"id", control.entry_id},
		{"source_target", control.source_target},
		{"build_identity", control.build_identity},
		{"outcome", report.not_run ? "not_run" : (exit_code == 0 ? "passed" : "failed")},
		{"assertions", {{"total", report.total}, {"passed", report.passed}, {"failed", report.failed},
			{"skipped", report.skipped}, {"not_run", report.not_run}}},
		{"ledger", {{"epoch", report.epoch}, {"finalized", report.finalized},
			{"event_digest", report.event_digest}, {"reporting_threads", report.reporting_threads},
			{"late_writes", report.late_writes}, {"error_flags", report.error_flags}}},
		{"elapsed_us", elapsed_us},
		{"evidence", std::move(evidence)}
	};
	const auto bytes = envelope.dump();
	if (bytes.empty() || bytes.size() > 1024 * 1024) {
		error = "adapter result envelope violates the size contract";
		return false;
	}
	return write_all(reinterpret_cast<HANDLE>(control.result_handle), bytes.data(), bytes.size(), error);
}

int run_adapted_entry(int argc, char** argv, const adapted_entry_t& entry) {
	adapter_control_t control;
	std::string error;
	if (!parse_adapter_control(argc, argv, control, error)) return 125;
	assertion_telemetry::entry_session_t session;
	if (!assertion_telemetry::begin_entry(control.entry_id, control.source_target, session, error)) return 120;
	const auto started = std::chrono::steady_clock::now();
	int exit_code = 124;
	try {
		if (entry) {
			exit_code = entry(control.forwarded_arguments);
		} else {
			assertion_telemetry::record_assertion(false, "adapted entry is unavailable", __FILE__, __LINE__);
			exit_code = 123;
		}
	} catch (const std::exception& exception) {
		assertion_telemetry::record_exception(exception.what());
		exit_code = 122;
	} catch (...) {
		assertion_telemetry::record_exception("adapted entry raised a non-standard exception");
		exit_code = 122;
	}
	const auto elapsed_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::steady_clock::now() - started).count());
	session.finalize(exit_code);
	const auto report = session.snapshot();
	if (!write_result_envelope(control, exit_code, elapsed_us, report, error)) return 121;
	session.close();
	return exit_code;
}

}
