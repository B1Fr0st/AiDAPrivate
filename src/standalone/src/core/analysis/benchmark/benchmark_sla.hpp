#pragma once

#include <cstdint>

#include <nlohmann/json.hpp>

namespace aida::analysis::benchmark {

inline constexpr std::uint64_t program_sla_reference_bytes = 300ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t real_fixture_min_bytes = 300000000ULL;
inline constexpr std::uint64_t real_fixture_max_bytes = 500000000ULL;
inline constexpr std::uint64_t synthetic_code_bytes_min = 8ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t synthetic_code_bytes_max = 320ULL * 1024ULL * 1024ULL;

inline double program_sla_wall_scale(std::uint64_t workload_bytes)
{
    return static_cast<double>(workload_bytes) /
        static_cast<double>(program_sla_reference_bytes);
}

inline const nlohmann::json& program_sla_thresholds()
{
    static const nlohmann::json thresholds = {
        {"threshold_schema", "aida.hyperperf.program-sla-thresholds"},
        {"threshold_schema_version", 2},
        {"total_wall_ms_max_300mb", 300000.0},
        {"total_wall_ms_stretch_300mb", 180000.0},
        {"decode_throughput_bytes_per_s_min", 26214400.0},
        {"file_throughput_bytes_per_s_min", 1048576.0},
        {"instructions_per_s_min", 2000000.0},
        {"publish_ready_ms_max", 50.0},
        {"indexed_query_p95_ms_max", 50.0},
        {"metadata_ready_ms_max", 3000.0},
        {"warm_reopen_ms_max", 10000.0},
        {"cancellation_p95_ms_max", 250.0},
        {"incremental_private_bytes_max", 8589934592ULL},
        {"workspace_mapped_bytes_max", 1073741824ULL},
        {"global_mapped_bytes_max", 2147483648ULL},
        {"decompile_all_funcs_per_s_min", 12.0},
        {"decompile_all_funcs_per_s_stretch", 16.0},
        {"decompile_all_funcs_wall_per_s_min", 100.0},
        {"decompile_all_funcs_wall_per_s_stretch", 140.0},
        {"scaling_wall16_over_wall1_max", 0.20},
        {"scaling_efficiency_16_min", 0.5},
        {"determinism_hash_match", true}
    };
    return thresholds;
}

}
