#pragma once

#include "decompiler_quality_schema.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace aida::analysis::c03
{
    struct quality_file_binding_request_t
    {
        std::string id;
        std::string kind;
        std::string relative_path;
        std::string expected_sha256;
        std::uint64_t maximum_bytes = 0;
    };

    struct decompiler_quality_score_request_t
    {
        std::filesystem::path evidence_root;
        std::string authorization_id;
        std::string receipt_id;
        std::string run_id;
        std::string started_utc;
        std::string ended_utc;
        std::string candidate_provider;
        std::string harness_binding_id;
        std::string scorer_binding_id;
        std::string corpus_manifest_binding_id;
        std::string recipes_binding_id;
        std::string ground_truth_binding_id;
        std::string materialization_receipt_binding_id;
        std::vector<quality_file_binding_request_t> file_bindings;
        json corpus_manifest;
        json recipes;
        json ground_truth;
        json materialization_receipt;
        json provider_runs;
    };

    struct decompiler_quality_score_result_t
    {
        bool ok = false;
        std::string error;
        json receipt;
        contract_validation_result_t validation;
    };

    decompiler_quality_score_result_t score_decompiler_quality(
        const decompiler_quality_score_request_t& request);
}
