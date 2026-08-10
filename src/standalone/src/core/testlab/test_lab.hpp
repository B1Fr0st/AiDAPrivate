#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace test_lab {

	enum class driver_e : int {
		whoswho = 0,
		driverless = 2,
	};

	enum class run_state_e : int {
		idle = 0,
		running = 1,
		complete = 2,
	};

	enum class outcome_e : int {
		not_run = 0,
		missing = 1,
		passed = 2,
		failed = 3,
		timed_out = 4,
		crashed = 5,
		cancelled = 6,
		malformed_result = 7,
		integrity_failure = 8,
	};

	struct state_t {
		std::uint32_t            pid = 0;
		std::uint32_t            tid = 0;
		std::uint64_t            addr = 0;
		std::uint32_t            size = 0;
		std::uint32_t            u32_a = 0;
		std::uint32_t            u32_b = 0;
		std::uint64_t            u64_a = 0;
		std::vector<std::uint8_t> buf;
		std::string              text_a;
		std::string              text_b;
		void*                    user = nullptr;
	};

	struct parsed_field_t {
		std::string label;
		std::string value;
	};

	struct result_t {
		std::atomic<run_state_e>     state{ run_state_e::idle };
		outcome_e                    outcome = outcome_e::not_run;
		bool                         ok = false;
		bool                         skipped = false;
		std::int32_t                 ntstatus = 0;
		std::uint32_t                bytes_returned = 0;
		std::uint64_t                elapsed_us = 0;
		std::string                  error;
		std::vector<std::uint8_t>    raw;
		std::vector<parsed_field_t>  parsed;
	};

	inline outcome_e effective_outcome(const result_t& result, bool explicit_outcome = false) noexcept {
		if (explicit_outcome || result.outcome != outcome_e::not_run) return result.outcome;
		if (result.ok) return outcome_e::passed;
		if (result.skipped) return outcome_e::not_run;
		if (result.state.load(std::memory_order_acquire) != run_state_e::idle || !result.error.empty() ||
			result.ntstatus != 0) return outcome_e::failed;
		return outcome_e::not_run;
	}

	inline void normalize_legacy_result(result_t& result) noexcept {
		if (result.outcome != outcome_e::not_run) return;
		result.outcome = result.ok ? outcome_e::passed : (result.skipped ? outcome_e::not_run : outcome_e::failed);
	}

	using render_inputs_fn = void(*)(state_t&);
	using run_fn = void(*)(state_t&, result_t&);

	struct feature_t {
		const char*       category = nullptr;
		driver_e          driver = driver_e::whoswho;
		const char*       name = nullptr;
		const char*       summary = nullptr;
		render_inputs_fn  render_inputs = nullptr;
		run_fn            run = nullptr;
	};

	bool register_feature(const feature_t& f);
	const std::vector<feature_t>& all_features();
	const std::string& last_error();

	inline const char* destructive_guard_reason(const char* category, const char* name) noexcept {
		if (category == nullptr || name == nullptr) return nullptr;
		struct guarded_feature_t {
			const char* category;
			const char* name;
			const char* reason;
		};
		static constexpr guarded_feature_t guarded[] = {
			{ "remote-call", "RC", "executes a target-process remote call" },
			{ "thread", "TSR", "suspends or resumes a target thread" },
			{ "module", "PINJ", "injects a transport-layer packet" }
		};
		for (const auto& f : guarded) {
			if (std::strcmp(category, f.category) == 0 && std::strcmp(name, f.name) == 0)
				return f.reason;
		}
		return nullptr;
	}

	inline bool is_destructive_guarded_feature(const char* category, const char* name) noexcept {
		return destructive_guard_reason(category, name) != nullptr;
	}

	struct registrar_t {
		registrar_t(const feature_t& f) noexcept;
	};

}

#define TESTLAB_REGISTER_CAT_(a, b) a##b
#define TESTLAB_REGISTER_CAT(a, b) TESTLAB_REGISTER_CAT_(a, b)

#define TESTLAB_REGISTER(VAR, ...)                                                    \
	namespace {                                                                       \
		[[maybe_unused]] const ::test_lab::registrar_t                                \
			TESTLAB_REGISTER_CAT(VAR, _registrar_)(                                   \
				::test_lab::feature_t{ __VA_ARGS__ });                                \
	}
