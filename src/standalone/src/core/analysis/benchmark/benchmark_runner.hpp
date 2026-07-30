#pragma once

#include "../workspace/workspace_types.hpp"

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace aida::analysis::benchmark {

enum class benchmark_mode_t : std::uint8_t {
    synthetic = 0,
    real = 1
};

struct benchmark_run_request_t {
    benchmark_mode_t mode = benchmark_mode_t::real;
    std::uint64_t synthetic_code_bytes = 32ULL * 1024ULL * 1024ULL;
    std::uint64_t synthetic_seed = 0xA1DA0001ULL;
    std::string real_path;
    std::uint32_t lanes = 0;
    std::string out_dir;
    bool sla_relaxed = false;
    std::uint32_t decompile_batch_max_functions = 512;
    std::uint32_t decompile_batch_max_ms = 120000;
};

struct benchmark_run_result_t {
    bool ok = false;
    std::string verdict;
    std::string sla_overall;
    std::string scorecard_json;
    std::string report_json_path;
    std::string error;
};

benchmark_run_result_t run_benchmark(const benchmark_run_request_t& request,
                                     const cancellation_token_t& cancel = {});

bool start_benchmark_async(const benchmark_run_request_t& request);
nlohmann::json benchmark_run_status();
nlohmann::json benchmark_last_result();
std::string benchmark_results_dir();

}
