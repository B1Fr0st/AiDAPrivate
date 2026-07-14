#include "result_adapter.hpp"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;

bool write_raw_result(std::uintptr_t result_handle, std::string_view bytes) {
	std::size_t offset = 0;
	while (offset < bytes.size()) {
		DWORD written = 0;
		const DWORD requested = static_cast<DWORD>((std::min)(bytes.size() - offset,
			static_cast<std::size_t>(64U * 1024U)));
		if (!WriteFile(reinterpret_cast<HANDLE>(result_handle), bytes.data() + offset,
			requested, &written, nullptr) || written == 0) return false;
		offset += written;
	}
	return true;
}

json strict_fixture_envelope(
	const aida::analysis::c03_test::testlab_runtime::adapter_control_t& control) {
	return {
		{"schema", "aida.c03.safe-headless.result.v1"},
		{"version", 1},
		{"id", control.entry_id},
		{"source_target", control.source_target},
		{"build_identity", control.build_identity},
		{"outcome", "passed"},
		{"assertions", {{"total", 1}, {"passed", 1}, {"failed", 0},
			{"skipped", 0}, {"not_run", false}}},
		{"ledger", {{"epoch", 1}, {"finalized", true},
			{"event_digest", std::string(32, 'a')}, {"reporting_threads", 1},
			{"late_writes", 0}, {"error_flags", 0}}},
		{"elapsed_us", 1},
		{"evidence", json::array({
			{{"name", "adapter_exit_code"}, {"value", "0"}},
			{{"name", "ledger_epoch"}, {"value", "1"}},
			{{"name", "ledger_digest"}, {"value", std::string(32, 'a')}},
			{{"name", "reporting_threads"}, {"value", "1"}}
		})}
	};
}

bool write_stdout_volume(std::size_t byte_count) {
	std::array<char, 16384> bytes{};
	bytes.fill('x');
	std::size_t offset = 0;
	while (offset < byte_count) {
		DWORD written = 0;
		const DWORD requested = static_cast<DWORD>((std::min)(bytes.size(), byte_count - offset));
		if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes.data(), requested, &written, nullptr) || written == 0)
			return false;
		offset += written;
	}
	return true;
}

bool child_process_creation_denied() {
	std::wstring executable(32768, L'\0');
	const DWORD size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
	if (size == 0 || size >= executable.size()) return false;
	executable.resize(size);
	std::wstring command = L"\"" + executable + L"\" --mode=empty";
	std::vector<wchar_t> command_buffer(command.begin(), command.end());
	command_buffer.push_back(L'\0');
	STARTUPINFOW startup{};
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESHOWWINDOW;
	startup.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION process{};
	if (!CreateProcessW(executable.c_str(), command_buffer.data(), nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
		const DWORD error = GetLastError();
		return error == ERROR_ACCESS_DENIED || error == ERROR_NOT_ENOUGH_QUOTA;
	}
	TerminateProcess(process.hProcess, 127);
	WaitForSingleObject(process.hProcess, 5000);
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	return false;
}

}

int main(int argc, char** argv) {
	aida::analysis::c03_test::testlab_runtime::adapter_control_t control;
	std::string error;
	if (!aida::analysis::c03_test::testlab_runtime::parse_adapter_control(argc, argv, control, error)) return 125;
	std::string_view mode = "pass";
	for (const auto& argument : control.forwarded_arguments) {
		if (argument.rfind("--mode=", 0) == 0) mode = std::string_view(argument).substr(7);
	}
	if (mode == "hang") {
		for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	if (mode == "crash") {
		RaiseException(0xC0420303U, EXCEPTION_NONCONTINUABLE, 0, nullptr);
		return 126;
	}
	if (mode == "malformed") {
		const char bytes[] = "{malformed";
		DWORD written = 0;
		WriteFile(reinterpret_cast<HANDLE>(control.result_handle), bytes,
			static_cast<DWORD>(sizeof(bytes) - 1), &written, nullptr);
		return 0;
	}
	if (mode == "empty") return 0;
	if (mode == "fabricated") {
		const std::string bytes = std::string("{\"schema\":\"aida.c03.safe-headless.result.v1\",") +
			"\"version\":1,\"id\":\"" + control.entry_id + "\",\"source_target\":\"" +
			control.source_target + "\",\"build_identity\":\"" + control.build_identity +
			"\",\"outcome\":\"passed\",\"assertions\":{\"total\":1,\"passed\":1,\"failed\":0}," +
			"\"elapsed_us\":1,\"evidence\":[]}";
		DWORD written = 0;
		WriteFile(reinterpret_cast<HANDLE>(control.result_handle), bytes.data(),
			static_cast<DWORD>(bytes.size()), &written, nullptr);
		return 0;
	}
	if (mode == "truncated") {
		const char bytes[] = "{\"schema\":\"aida.c03.safe-headless.result.v1\"";
		DWORD written = 0;
		WriteFile(reinterpret_cast<HANDLE>(control.result_handle), bytes,
			static_cast<DWORD>(sizeof(bytes) - 1), &written, nullptr);
		return 0;
	}
	if (mode == "zero_assertions" || mode == "count_mismatch" ||
		mode == "identity_mismatch" || mode == "not_finalized" ||
		mode == "duplicate_finalize" || mode == "late_write" ||
		mode == "count_overflow" || mode == "duplicate_evidence" ||
		mode == "unknown_top_field" || mode == "unknown_assertion_field" ||
		mode == "unknown_ledger_field" || mode == "invalid_digest" ||
		mode == "ledger_evidence_mismatch" || mode == "exit_evidence_mismatch" ||
		mode == "first_failure_on_pass" || mode == "empty_first_failure_on_pass" ||
		mode == "failed_without_first_failure" ||
		mode == "not_run_mixed" || mode == "reporting_thread_overflow") {
		auto envelope = strict_fixture_envelope(control);
		if (mode == "zero_assertions") {
			envelope["assertions"]["total"] = 0;
			envelope["assertions"]["passed"] = 0;
		} else if (mode == "count_mismatch") {
			envelope["assertions"]["total"] = 2;
		} else if (mode == "identity_mismatch") {
			envelope["id"] = "fixture.wrong_identity";
		} else if (mode == "not_finalized") {
			envelope["ledger"]["finalized"] = false;
		} else if (mode == "duplicate_finalize") {
			envelope["ledger"]["error_flags"] =
				aida::analysis::c03_test::assertion_telemetry::ledger_error_duplicate_finalize;
		} else if (mode == "late_write") {
			envelope["ledger"]["late_writes"] = 1;
			envelope["ledger"]["error_flags"] =
				aida::analysis::c03_test::assertion_telemetry::ledger_error_late_write;
		} else if (mode == "count_overflow") {
			envelope["assertions"]["total"] =
				static_cast<std::uint64_t>(aida::analysis::c03_test::assertion_telemetry::k_max_assertions) + 1U;
			envelope["assertions"]["passed"] = envelope["assertions"]["total"];
		} else if (mode == "duplicate_evidence") {
			envelope["evidence"].push_back(
				{{"name", "ledger_digest"}, {"value", std::string(32, 'a')}});
		} else if (mode == "unknown_top_field") {
			envelope["unexpected"] = true;
		} else if (mode == "unknown_assertion_field") {
			envelope["assertions"]["unexpected"] = true;
		} else if (mode == "unknown_ledger_field") {
			envelope["ledger"]["unexpected"] = true;
		} else if (mode == "invalid_digest") {
			envelope["ledger"]["event_digest"] = std::string(32, 'A');
			envelope["evidence"][2]["value"] = std::string(32, 'A');
		} else if (mode == "ledger_evidence_mismatch") {
			envelope["evidence"][2]["value"] = std::string(32, 'b');
		} else if (mode == "exit_evidence_mismatch") {
			envelope["evidence"][0]["value"] = "1";
		} else if (mode == "first_failure_on_pass") {
			envelope["evidence"].push_back(
				{{"name", "first_failure"}, {"value", "fabricated failure"}});
		} else if (mode == "empty_first_failure_on_pass") {
			envelope["evidence"].push_back(
				{{"name", "first_failure"}, {"value", ""}});
		} else if (mode == "failed_without_first_failure") {
			envelope["outcome"] = "failed";
			envelope["assertions"]["passed"] = 0;
			envelope["assertions"]["failed"] = 1;
			envelope["evidence"][0]["value"] = "1";
		} else if (mode == "not_run_mixed") {
			envelope["outcome"] = "not_run";
			envelope["assertions"]["not_run"] = true;
			envelope["assertions"]["skipped"] = 1;
		} else {
			envelope["ledger"]["reporting_threads"] =
				aida::analysis::c03_test::assertion_telemetry::k_max_reporting_threads + 1U;
			envelope["evidence"][3]["value"] = std::to_string(
				aida::analysis::c03_test::assertion_telemetry::k_max_reporting_threads + 1U);
		}
		write_raw_result(control.result_handle, envelope.dump());
		return mode == "failed_without_first_failure" ? 1 : 0;
	}
	if (mode == "oversize_result") {
		write_raw_result(control.result_handle, std::string(128U * 1024U, 'x'));
		return 0;
	}
	if (mode == "invalid_handle") {
		CloseHandle(reinterpret_cast<HANDLE>(control.result_handle));
	}
	return aida::analysis::c03_test::testlab_runtime::run_adapted_entry(argc, argv,
		[mode](const std::vector<std::string>&) -> int {
			using aida::analysis::c03_test::assertion_telemetry::k_max_assertions;
			using aida::analysis::c03_test::assertion_telemetry::record_assertion;
			using aida::analysis::c03_test::assertion_telemetry::record_not_run;
			if (mode == "stdout") {
				const bool written = write_stdout_volume(256U * 1024U);
				record_assertion(written, "bounded stdout fixture write completed", __FILE__, __LINE__);
				return written ? 0 : 119;
			}
			if (mode == "memory") {
				void* allocation = VirtualAlloc(nullptr, 128ULL * 1024ULL * 1024ULL,
					MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (allocation) VirtualFree(allocation, 0, MEM_RELEASE);
				record_assertion(allocation == nullptr, "job memory ceiling rejected oversized commitment",
					__FILE__, __LINE__);
				return allocation == nullptr ? 0 : 1;
			}
			if (mode == "child") {
				const bool denied = child_process_creation_denied();
				record_assertion(denied, "job child-process policy rejected process creation", __FILE__, __LINE__);
				return denied ? 0 : 1;
			}
			if (mode == "multi_pass" || mode == "pass") {
				record_assertion(true, "first execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(true, "middle execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(true, "last execution-owned assertion passed", __FILE__, __LINE__);
				return 0;
			}
			if (mode == "fail" || mode == "fail_first") {
				record_assertion(false, "first execution-owned assertion failed", __FILE__, __LINE__);
				record_assertion(true, "middle execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(true, "last execution-owned assertion passed", __FILE__, __LINE__);
				return 1;
			}
			if (mode == "fail_middle") {
				record_assertion(true, "first execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(false, "middle execution-owned assertion failed", __FILE__, __LINE__);
				record_assertion(true, "last execution-owned assertion passed", __FILE__, __LINE__);
				return 1;
			}
			if (mode == "fail_last") {
				record_assertion(true, "first execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(true, "middle execution-owned assertion passed", __FILE__, __LINE__);
				record_assertion(false, "last execution-owned assertion failed", __FILE__, __LINE__);
				return 1;
			}
			if (mode == "throw_after_passes") {
				record_assertion(true, "pre-exception assertion one passed", __FILE__, __LINE__);
				record_assertion(true, "pre-exception assertion two passed", __FILE__, __LINE__);
				throw std::runtime_error("fixture exception after passing assertions");
			}
			if (mode == "not_run") {
				record_not_run("fixture entry was explicitly not run");
				return 0;
			}
			if (mode == "threaded") {
				std::array<std::thread, 4> workers;
				std::atomic_uint32_t ready{0};
				std::atomic_bool start{false};
				std::size_t launched = 0;
				try {
					for (auto& worker : workers) {
						worker = std::thread([&] {
							ready.fetch_add(1, std::memory_order_acq_rel);
							while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
							for (std::uint32_t index = 0; index < 128U; ++index)
								record_assertion(true, "thread-isolated assertion passed", __FILE__, __LINE__);
						});
						++launched;
					}
				} catch (...) {
					start.store(true, std::memory_order_release);
					for (std::size_t index = 0; index < launched; ++index) workers[index].join();
					throw;
				}
				while (ready.load(std::memory_order_acquire) != workers.size()) std::this_thread::yield();
				start.store(true, std::memory_order_release);
				for (auto& worker : workers) worker.join();
				return 0;
			}
			if (mode == "overflow") {
				for (std::uint32_t index = 0; index <= k_max_assertions; ++index)
					record_assertion(true, "overflow-bound assertion", __FILE__, __LINE__);
				return 0;
			}
			record_assertion(false, "unknown fake adapter mode", __FILE__, __LINE__);
			return 120;
		});
}
