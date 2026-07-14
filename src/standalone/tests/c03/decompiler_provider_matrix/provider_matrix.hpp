#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace aida::analysis::c03::provider_matrix {

enum class provider_selection_t : std::uint8_t {
    candidate,
    ghidra_printc,
    aida_current,
    all
};

struct matrix_config_t final {
    std::filesystem::path repository_root;
    std::filesystem::path runtime_root;
    std::filesystem::path materialized_root;
    std::filesystem::path output_root;
    provider_selection_t provider = provider_selection_t::all;
    std::uint64_t deadline_ms = 120000;
};

struct matrix_result_t final {
    int exit_code = 4;
    std::string error;
    std::vector<std::filesystem::path> output_files;
};

matrix_result_t run(const matrix_config_t& config);

}
