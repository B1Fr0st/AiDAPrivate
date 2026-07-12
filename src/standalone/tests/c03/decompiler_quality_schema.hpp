#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida::analysis::c03
{
    using json = nlohmann::json;

    struct contract_violation_t
    {
        std::string path;
        std::string code;
        std::string message;
    };

    struct contract_validation_result_t
    {
        bool valid = true;
        std::vector<contract_violation_t> violations;

        void reject(std::string path, std::string code, std::string message);
        std::string summary() const;
        json to_json() const;
    };

    const json& corpus_manifest_schema();
    const json& decompiler_quality_receipt_schema();
    const json& decompiler_quality_thresholds();

    contract_validation_result_t validate_corpus_manifest(const json& manifest);
    contract_validation_result_t validate_malformed_case_manifest(const json& manifest,
        const json& malformed_cases);
    contract_validation_result_t validate_decompiler_quality_receipt(const json& receipt);
}
