#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace test_lab {

	enum class driver_e : int {
		whoswho = 0,
		sentinel = 1,
	};

	enum class run_state_e : int {
		idle = 0,
		running = 1,
		complete = 2,
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
		bool                         ok = false;
		std::int32_t                 ntstatus = 0;
		std::uint32_t                bytes_returned = 0;
		std::uint64_t                elapsed_us = 0;
		std::string                  error;
		std::vector<std::uint8_t>    raw;
		std::vector<parsed_field_t>  parsed;
	};

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
