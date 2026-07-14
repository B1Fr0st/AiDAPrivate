#pragma once

#include "decompiler_quality_schema.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace aida::analysis::c03
{
    struct materialized_fixture_t
    {
        std::string id;
        std::filesystem::path path;
        std::string artifact_sha256;
        std::string recipe_sha256;
        std::string ground_truth_sha256;
        std::uint64_t size_bytes = 0;
        std::string format;
        std::string architecture;
        std::string mode;
        std::string endian;
    };

    struct corpus_materialization_result_t
    {
        bool ok = false;
        std::string error;
        std::vector<materialized_fixture_t> fixtures;
        json receipt;
    };

    corpus_materialization_result_t materialize_c03_corpus(const json& manifest,
        const json& recipes, const json& ground_truth,
        const std::filesystem::path& output_root,
        const std::atomic_bool* cancellation = nullptr);
    contract_validation_result_t validate_materialization_receipt(const json& receipt,
        const json& manifest, const json& recipes, const json& ground_truth,
        const std::filesystem::path& output_root);
    corpus_materialization_result_t materialize_c03_malformed_corpus(const json& malformed_cases,
        const std::vector<materialized_fixture_t>& source_fixtures,
        const std::filesystem::path& output_root,
        const std::atomic_bool* cancellation = nullptr);
    contract_validation_result_t validate_malformed_materialization_receipt(const json& receipt,
        const json& malformed_cases, const std::filesystem::path& output_root);
}
