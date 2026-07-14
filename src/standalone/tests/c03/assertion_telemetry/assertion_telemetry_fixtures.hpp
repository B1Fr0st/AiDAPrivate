#pragma once

#include "assertion_telemetry.hpp"

#include <array>
#include <atomic>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace aida::analysis::c03_test::assertion_telemetry::fixtures {

inline void enforce(bool condition, std::string_view message) {
	record_assertion(condition, message, __FILE__, __LINE__);
	if (!condition) throw std::runtime_error(std::string(message));
}

inline void begin_required(std::string_view id, entry_session_t& session, std::string& error) {
	if (!begin_entry(id, "assertion_telemetry_fixture", session, error))
		throw std::runtime_error(error.empty() ? "assertion ledger could not begin" : error);
}

inline assertion_report_t run_sequence(std::string_view id,
	const std::array<bool, 3>& outcomes, int exit_code) {
	entry_session_t session;
	std::string error;
	begin_required(id, session, error);
	record_assertion(outcomes[0], "first sequence assertion", __FILE__, __LINE__);
	record_assertion(outcomes[1], "middle sequence assertion", __FILE__, __LINE__);
	record_assertion(outcomes[2], "last sequence assertion", __FILE__, __LINE__);
	auto report = session.finalize(exit_code);
	session.close();
	return report;
}

inline void validate_sequences() {
	const auto passed = run_sequence("fixture.multi_pass", {{true, true, true}}, 0);
	enforce(passed.valid && passed.total == 3 && passed.passed == 3 && passed.failed == 0,
		"multi-pass ledger counts are invalid");
	const auto first = run_sequence("fixture.fail_first", {{false, true, true}}, 1);
	enforce(first.valid && first.total == 3 && first.passed == 2 && first.failed == 1 &&
		first.first_failure == "first sequence assertion", "first-failure ledger counts are invalid");
	const auto middle = run_sequence("fixture.fail_middle", {{true, false, true}}, 1);
	enforce(middle.valid && middle.total == 3 && middle.passed == 2 && middle.failed == 1 &&
		middle.first_failure == "middle sequence assertion", "middle-failure ledger counts are invalid");
	const auto last = run_sequence("fixture.fail_last", {{true, true, false}}, 1);
	enforce(last.valid && last.total == 3 && last.passed == 2 && last.failed == 1 &&
		last.first_failure == "last sequence assertion", "last-failure ledger counts are invalid");
	const auto repeated = run_sequence("fixture.multi_pass_repeat", {{true, true, true}}, 0);
	enforce(repeated.valid && repeated.event_digest == passed.event_digest,
		"equivalent assertion sequences produced different digests");
}

inline void validate_empty_skip_and_exit_contracts() {
	entry_session_t empty;
	std::string error;
	begin_required("fixture.empty", empty, error);
	const auto empty_report = empty.finalize(0);
	empty.close();
	enforce(!empty_report.valid && (empty_report.error_flags & ledger_error_empty_execution) != 0,
		"empty execution was accepted");

	entry_session_t skipped;
	begin_required("fixture.not_run", skipped, error);
	record_not_run("fixture dependency is intentionally unavailable");
	const auto skipped_report = skipped.finalize(0);
	skipped.close();
	enforce(skipped_report.valid && skipped_report.not_run && skipped_report.total == 0 &&
		skipped_report.skipped == 1, "explicit not-run execution was rejected");

	entry_session_t mismatch;
	begin_required("fixture.exit_mismatch", mismatch, error);
	record_assertion(true, "passing assertion before mismatched exit", __FILE__, __LINE__);
	const auto mismatch_report = mismatch.finalize(1);
	mismatch.close();
	enforce(!mismatch_report.valid && (mismatch_report.error_flags & ledger_error_exit_mismatch) != 0,
		"exit/count mismatch was accepted");
}

inline void validate_lifecycle_rejection() {
	entry_session_t outer;
	entry_session_t nested;
	std::string error;
	begin_required("fixture.outer", outer, error);
	std::string nested_error;
	const bool nested_started = begin_entry("fixture.nested", "assertion_telemetry_fixture", nested, nested_error);
	record_assertion(!nested_started && !nested_error.empty(), "nested ledger activation was rejected",
		__FILE__, __LINE__);
	const auto outer_report = outer.finalize(0);
	outer.close();
	enforce(outer_report.valid && outer_report.total == 1,
		"nested activation contaminated the owning ledger");

	entry_session_t duplicate;
	begin_required("fixture.duplicate", duplicate, error);
	record_assertion(true, "pre-finalization assertion", __FILE__, __LINE__);
	const auto first = duplicate.finalize(0);
	const auto second = duplicate.finalize(0);
	duplicate.close();
	enforce(first.valid && !second.valid &&
		(second.error_flags & ledger_error_duplicate_finalize) != 0,
		"duplicate finalization was not rejected");

	entry_session_t late;
	begin_required("fixture.late", late, error);
	record_assertion(true, "pre-finalization assertion", __FILE__, __LINE__);
	late.finalize(0);
	record_assertion(true, "late assertion", __FILE__, __LINE__);
	const auto late_report = late.snapshot();
	late.close();
	enforce(!late_report.valid && late_report.late_writes == 1 &&
		(late_report.error_flags & ledger_error_late_write) != 0,
		"late assertion write was accepted");
}

inline void validate_thread_isolation_and_finalization_race() {
	entry_session_t threaded;
	std::string error;
	begin_required("fixture.threads", threaded, error);
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
					record_assertion(true, "thread fixture assertion", __FILE__, __LINE__);
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
	const auto threaded_report = threaded.finalize(0);
	threaded.close();
	enforce(threaded_report.valid && threaded_report.total == 512 &&
		threaded_report.reporting_threads == 4,
		"threaded ledger aggregation is invalid");

	entry_session_t thread_overflow;
	begin_required("fixture.thread_overflow", thread_overflow, error);
	std::array<std::thread, k_max_reporting_threads + 1U> overflow_workers;
	std::atomic_uint32_t overflow_ready{0};
	std::atomic_bool overflow_start{false};
	launched = 0;
	try {
		for (auto& worker : overflow_workers) {
			worker = std::thread([&] {
				overflow_ready.fetch_add(1, std::memory_order_acq_rel);
				while (!overflow_start.load(std::memory_order_acquire)) std::this_thread::yield();
				record_assertion(true, "thread overflow fixture assertion", __FILE__, __LINE__);
			});
			++launched;
		}
	} catch (...) {
		overflow_start.store(true, std::memory_order_release);
		for (std::size_t index = 0; index < launched; ++index) overflow_workers[index].join();
		throw;
	}
	while (overflow_ready.load(std::memory_order_acquire) != overflow_workers.size())
		std::this_thread::yield();
	overflow_start.store(true, std::memory_order_release);
	for (auto& worker : overflow_workers) worker.join();
	const auto thread_overflow_report = thread_overflow.finalize(0);
	thread_overflow.close();
	enforce(!thread_overflow_report.valid && thread_overflow_report.total == overflow_workers.size() &&
		thread_overflow_report.reporting_threads == k_max_reporting_threads &&
		(thread_overflow_report.error_flags & ledger_error_thread_overflow) != 0,
		"reporting thread overflow was not rejected");

	entry_session_t raced;
	begin_required("fixture.finalize_race", raced, error);
	record_assertion(true, "race fixture assertion", __FILE__, __LINE__);
	std::array<assertion_report_t, 2> reports;
	std::array<std::thread, 2> finalizers;
	launched = 0;
	try {
		for (std::size_t index = 0; index < finalizers.size(); ++index) {
			finalizers[index] = std::thread([&, index] { reports[index] = raced.finalize(0); });
			++launched;
		}
	} catch (...) {
		for (std::size_t index = 0; index < launched; ++index) finalizers[index].join();
		throw;
	}
	for (auto& finalizer : finalizers) finalizer.join();
	const auto race_snapshot = raced.snapshot();
	raced.close();
	const auto valid_reports = static_cast<unsigned>(reports[0].valid) + static_cast<unsigned>(reports[1].valid);
	enforce(valid_reports == 1 && !race_snapshot.valid &&
		(race_snapshot.error_flags & ledger_error_duplicate_finalize) != 0,
		"finalization race did not fail closed");
}

inline void validate_overflow_and_reset() {
	entry_session_t overflow;
	std::string error;
	begin_required("fixture.overflow", overflow, error);
	for (std::uint32_t index = 0; index <= k_max_assertions; ++index)
		record_assertion(true, "bounded overflow assertion", __FILE__, __LINE__);
	const auto overflow_report = overflow.finalize(0);
	overflow.close();
	enforce(!overflow_report.valid && overflow_report.total == k_max_assertions &&
		(overflow_report.error_flags & ledger_error_assertion_overflow) != 0,
		"assertion count overflow was not rejected");

	entry_session_t skip_overflow;
	begin_required("fixture.skip_overflow", skip_overflow, error);
	for (std::uint32_t index = 0; index <= k_max_skipped; ++index)
		record_not_run("bounded skip overflow event");
	const auto skip_overflow_report = skip_overflow.finalize(0);
	skip_overflow.close();
	enforce(!skip_overflow_report.valid && skip_overflow_report.not_run &&
		skip_overflow_report.skipped == k_max_skipped &&
		(skip_overflow_report.error_flags & ledger_error_skip_overflow) != 0,
		"skip count overflow was not rejected");

	entry_session_t reset;
	begin_required("fixture.reset", reset, error);
	record_assertion(true, "post-overflow reset assertion", __FILE__, __LINE__);
	const auto reset_report = reset.finalize(0);
	reset.close();
	enforce(reset_report.valid && reset_report.total == 1 && reset_report.error_flags == ledger_error_none,
		"ledger state was not securely reset between entries");
}

inline void validate_assertion_telemetry_contract() {
	validate_sequences();
	validate_empty_skip_and_exit_contracts();
	validate_lifecycle_rejection();
	validate_thread_isolation_and_finalization_race();
	validate_overflow_and_reset();
}

}
