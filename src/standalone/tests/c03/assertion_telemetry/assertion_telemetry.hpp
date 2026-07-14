#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace aida::analysis::c03_test::assertion_telemetry {

inline constexpr std::uint32_t k_max_assertions = 1'000'000U;
inline constexpr std::uint32_t k_max_skipped = 1'000'000U;
inline constexpr std::uint32_t k_max_reporting_threads = 64U;
inline constexpr std::size_t k_max_failure_text = 512U;

enum ledger_error_e : std::uint32_t {
	ledger_error_none = 0,
	ledger_error_assertion_overflow = 1U << 0,
	ledger_error_skip_overflow = 1U << 1,
	ledger_error_thread_overflow = 1U << 2,
	ledger_error_late_write = 1U << 3,
	ledger_error_duplicate_finalize = 1U << 4,
	ledger_error_empty_execution = 1U << 5,
	ledger_error_exit_mismatch = 1U << 6,
	ledger_error_mixed_not_run = 1U << 7,
	ledger_error_abandoned_entry = 1U << 8,
};

struct assertion_report_t {
	std::string entry_id;
	std::string source_target;
	std::uint64_t epoch = 0;
	std::uint32_t total = 0;
	std::uint32_t passed = 0;
	std::uint32_t failed = 0;
	std::uint32_t skipped = 0;
	std::uint32_t reporting_threads = 0;
	std::uint32_t late_writes = 0;
	std::uint32_t error_flags = ledger_error_none;
	bool not_run = false;
	bool finalized = false;
	bool valid = false;
	std::string event_digest;
	std::string first_failure;
};

namespace detail {

struct ledger_state_t final {
	std::mutex mutex;
	std::string entry_id;
	std::string source_target;
	std::uint64_t epoch = 0;
	std::uint32_t total = 0;
	std::uint32_t passed = 0;
	std::uint32_t failed = 0;
	std::uint32_t skipped = 0;
	std::uint32_t reporting_thread_count = 0;
	std::uint32_t late_writes = 0;
	std::uint32_t error_flags = ledger_error_none;
	std::array<std::thread::id, k_max_reporting_threads> reporting_threads{};
	std::array<char, k_max_failure_text + 1U> first_failure{};
	std::size_t first_failure_size = 0;
	std::uint64_t digest_sum = 0x243f6a8885a308d3ULL;
	std::uint64_t digest_xor = 0x13198a2e03707344ULL;
	bool not_run = false;
	bool finalized = false;
	int exit_code = 0;
};

inline std::mutex g_active_mutex;
inline std::shared_ptr<ledger_state_t> g_active;
inline std::uint64_t g_next_epoch = 1;

inline std::uint64_t rotate_left(std::uint64_t value, unsigned shift) noexcept {
	shift &= 63U;
	return shift == 0U ? value : (value << shift) | (value >> (64U - shift));
}

inline std::uint64_t hash_bytes(std::uint64_t value, std::string_view bytes) noexcept {
	for (const unsigned char byte : bytes) {
		value ^= byte;
		value *= 1099511628211ULL;
	}
	return value;
}

inline std::uint64_t event_hash(bool passed, std::string_view message,
	std::string_view file, std::uint32_t line) noexcept {
	std::uint64_t value = passed ? 0x9e3779b185ebca87ULL : 0xc2b2ae3d27d4eb4fULL;
	value = hash_bytes(value, message);
	value = hash_bytes(value, file);
	for (unsigned shift = 0; shift < 32U; shift += 8U) {
		value ^= static_cast<std::uint8_t>(line >> shift);
		value *= 1099511628211ULL;
	}
	return value;
}

inline void add_thread_locked(ledger_state_t& state) noexcept {
	const auto identity = std::this_thread::get_id();
	for (std::uint32_t index = 0; index < state.reporting_thread_count; ++index) {
		if (state.reporting_threads[index] == identity) return;
	}
	if (state.reporting_thread_count >= k_max_reporting_threads) {
		state.error_flags |= ledger_error_thread_overflow;
		return;
	}
	state.reporting_threads[state.reporting_thread_count++] = identity;
}

inline void add_event_locked(ledger_state_t& state, bool passed,
	std::string_view message, std::string_view file, std::uint32_t line) noexcept {
	add_thread_locked(state);
	const auto value = event_hash(passed, message, file, line);
	state.digest_sum += value + 0x9e3779b97f4a7c15ULL;
	state.digest_xor ^= rotate_left(value, static_cast<unsigned>(value & 63U));
	if (!passed && state.first_failure_size == 0) {
		const auto failure = message.empty() ? std::string_view("assertion failed") : message;
		const auto count = (std::min)(failure.size(), k_max_failure_text);
		if (count != 0) std::memcpy(state.first_failure.data(), failure.data(), count);
		state.first_failure[count] = '\0';
		state.first_failure_size = count;
	}
}

inline std::string digest_text(const ledger_state_t& state) {
	static constexpr char hex[] = "0123456789abcdef";
	std::string value(32, '0');
	const std::array<std::uint64_t, 2> words{{state.digest_sum, state.digest_xor}};
	for (std::size_t word = 0; word < words.size(); ++word) {
		for (std::size_t nibble = 0; nibble < 16; ++nibble) {
			const auto shift = static_cast<unsigned>((15U - nibble) * 4U);
			value[word * 16U + nibble] = hex[(words[word] >> shift) & 0x0fU];
		}
	}
	return value;
}

inline assertion_report_t report_locked(const ledger_state_t& state) {
	assertion_report_t report;
	report.entry_id = state.entry_id;
	report.source_target = state.source_target;
	report.epoch = state.epoch;
	report.total = state.total;
	report.passed = state.passed;
	report.failed = state.failed;
	report.skipped = state.skipped;
	report.reporting_threads = state.reporting_thread_count;
	report.late_writes = state.late_writes;
	report.error_flags = state.error_flags;
	report.not_run = state.not_run;
	report.finalized = state.finalized;
	report.event_digest = digest_text(state);
	report.first_failure.assign(state.first_failure.data(), state.first_failure_size);
	report.valid = state.finalized && state.error_flags == ledger_error_none &&
		state.total == state.passed + state.failed && state.reporting_thread_count != 0 &&
		((state.not_run && state.total == 0 && state.skipped != 0 && state.exit_code == 0) ||
		 (!state.not_run && state.total != 0 &&
		  ((state.failed == 0 && state.exit_code == 0) ||
		   (state.failed != 0 && state.exit_code != 0))));
	return report;
}

inline std::shared_ptr<ledger_state_t> active_state() noexcept {
	try {
		std::lock_guard<std::mutex> lock(g_active_mutex);
		return g_active;
	} catch (...) {
		return {};
	}
}

}

class entry_session_t final {
public:
	entry_session_t() = default;
	entry_session_t(const entry_session_t&) = delete;
	entry_session_t& operator=(const entry_session_t&) = delete;
	entry_session_t(entry_session_t&& other) noexcept : state_(std::move(other.state_)) {}
	entry_session_t& operator=(entry_session_t&& other) noexcept {
		if (this != &other) {
			close();
			state_ = std::move(other.state_);
		}
		return *this;
	}
	~entry_session_t() { close(); }

	explicit operator bool() const noexcept { return static_cast<bool>(state_); }

	assertion_report_t finalize(int exit_code) noexcept {
		if (!state_) return {};
		try {
			std::lock_guard<std::mutex> lock(state_->mutex);
			if (state_->finalized) {
				state_->error_flags |= ledger_error_duplicate_finalize;
				if (state_->late_writes != std::numeric_limits<std::uint32_t>::max()) ++state_->late_writes;
				return detail::report_locked(*state_);
			}
			state_->finalized = true;
			state_->exit_code = exit_code;
			if (state_->total == 0 && !state_->not_run)
				state_->error_flags |= ledger_error_empty_execution;
			if (state_->not_run && (state_->total != 0 || state_->skipped == 0))
				state_->error_flags |= ledger_error_mixed_not_run;
			if ((!state_->not_run && ((exit_code == 0 && state_->failed != 0) ||
				(exit_code != 0 && state_->failed == 0))) || (state_->not_run && exit_code != 0))
				state_->error_flags |= ledger_error_exit_mismatch;
			return detail::report_locked(*state_);
		} catch (...) {
			return {};
		}
	}

	assertion_report_t snapshot() const noexcept {
		if (!state_) return {};
		try {
			std::lock_guard<std::mutex> lock(state_->mutex);
			return detail::report_locked(*state_);
		} catch (...) {
			return {};
		}
	}

	void close() noexcept {
		if (!state_) return;
		try {
			{
				std::lock_guard<std::mutex> state_lock(state_->mutex);
				if (!state_->finalized) state_->error_flags |= ledger_error_abandoned_entry;
			}
			std::lock_guard<std::mutex> active_lock(detail::g_active_mutex);
			if (detail::g_active == state_) detail::g_active.reset();
		} catch (...) {
		}
		state_.reset();
	}

private:
	explicit entry_session_t(std::shared_ptr<detail::ledger_state_t> state) noexcept
		: state_(std::move(state)) {}
	std::shared_ptr<detail::ledger_state_t> state_;
	friend bool begin_entry(std::string_view, std::string_view, entry_session_t&, std::string&);
};

inline bool begin_entry(std::string_view entry_id, std::string_view source_target,
	entry_session_t& session, std::string& error) {
	try {
		if (entry_id.empty() || source_target.empty()) {
			error = "assertion ledger identity is empty";
			return false;
		}
		if (session) {
			error = "assertion ledger output session is already active";
			return false;
		}
		auto state = std::make_shared<detail::ledger_state_t>();
		state->entry_id.assign(entry_id);
		state->source_target.assign(source_target);
		std::lock_guard<std::mutex> lock(detail::g_active_mutex);
		if (detail::g_active) {
			error = "assertion ledger already owns an active entry";
			return false;
		}
		if (detail::g_next_epoch == 0 || detail::g_next_epoch == std::numeric_limits<std::uint64_t>::max()) {
			error = "assertion ledger epoch is exhausted";
			return false;
		}
		state->epoch = detail::g_next_epoch++;
		detail::g_active = state;
		session = entry_session_t(std::move(state));
		error.clear();
		return true;
	} catch (const std::exception&) {
		error = "assertion ledger activation failed";
		return false;
	} catch (...) {
		error = "assertion ledger activation failed with a non-standard exception";
		return false;
	}
}

inline void record_assertion(bool passed, std::string_view message,
	std::string_view file = {}, std::uint32_t line = 0) noexcept {
	auto state = detail::active_state();
	if (!state) return;
	try {
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->finalized) {
			state->error_flags |= ledger_error_late_write;
			if (state->late_writes != std::numeric_limits<std::uint32_t>::max()) ++state->late_writes;
			return;
		}
		if (state->not_run) {
			state->error_flags |= ledger_error_mixed_not_run;
			return;
		}
		if (state->total >= k_max_assertions) {
			state->error_flags |= ledger_error_assertion_overflow;
			return;
		}
		++state->total;
		if (passed) ++state->passed;
		else ++state->failed;
		detail::add_event_locked(*state, passed, message, file, line);
	} catch (...) {
	}
}

inline void record_exception(std::string_view message) noexcept {
	record_assertion(false, message.empty() ? std::string_view("unhandled entry exception") : message,
		"assertion_telemetry", 0);
}

inline void record_not_run(std::string_view reason) noexcept {
	auto state = detail::active_state();
	if (!state) return;
	try {
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->finalized) {
			state->error_flags |= ledger_error_late_write;
			if (state->late_writes != std::numeric_limits<std::uint32_t>::max()) ++state->late_writes;
			return;
		}
		if (state->total != 0) {
			state->error_flags |= ledger_error_mixed_not_run;
			return;
		}
		if (state->skipped >= k_max_skipped) {
			state->error_flags |= ledger_error_skip_overflow;
			return;
		}
		state->not_run = true;
		++state->skipped;
		detail::add_event_locked(*state, true,
			reason.empty() ? std::string_view("entry explicitly not run") : reason,
			"assertion_telemetry", 0);
	} catch (...) {
	}
}

}
