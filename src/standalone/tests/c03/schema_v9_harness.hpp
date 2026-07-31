#pragma once

#include "workspace_schema_v9.hpp"
#include "packed_page_codec.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aida::analysis {

struct schema_v9_fixture_result_t {
    const char* name = "";
    bool passed = false;
    std::string message;
    std::uint64_t elapsed_us = 0;
};

struct schema_v9_harness_summary_t {
    std::size_t total = 0;
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::vector<schema_v9_fixture_result_t> results;
};

schema_v9_fixture_result_t run_golden_v8_migration();
schema_v9_fixture_result_t run_interrupted_commit();
schema_v9_fixture_result_t run_corruption_detection();
schema_v9_fixture_result_t run_packed_page_known_answer();
schema_v9_fixture_result_t run_rollback_after_failed_migration();
schema_v9_fixture_result_t run_fixed_width_address();
schema_v9_fixture_result_t run_concurrent_reader();
schema_v9_fixture_result_t run_cache_key_round_trip();
schema_v9_fixture_result_t run_workbench_round_trip();
schema_v9_fixture_result_t run_generation_atomicity();
schema_v9_fixture_result_t run_database_open_queue_path();
schema_v9_fixture_result_t run_baseline_persistence_entry_path();

schema_v9_harness_summary_t run_all_schema_v9_fixtures();

}
