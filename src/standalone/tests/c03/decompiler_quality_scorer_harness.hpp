#pragma once

#include <filesystem>
#include <string>

namespace aida::analysis::c03
{
    struct quality_harness_paths_t
    {
        std::filesystem::path repository_root;
        std::filesystem::path evidence_root;
        std::filesystem::path harness_binary;
        std::filesystem::path provider_matrix_binary;
        std::filesystem::path runtime_root;
        std::filesystem::path candidate_results;
        std::filesystem::path ghidra_printc_results;
        std::filesystem::path aida_current_results;
    };

    bool run_decompiler_quality_scorer_harness(const quality_harness_paths_t& paths,
        std::string& failure);
}
