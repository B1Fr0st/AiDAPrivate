#pragma once

#include "decompiler_quality_schema.hpp"

namespace aida::analysis::c03
{
    const json& benchmark_sla_receipt_schema();
    const json& benchmark_sla_thresholds();
    const json& approved_external_sla_slot();

    contract_validation_result_t validate_external_sla_slot(const json& slot);
    contract_validation_result_t validate_benchmark_sla_receipt(const json& receipt);
    contract_validation_result_t validate_benchmark_sla_receipt(const json& receipt,
        const json& approved_external_slot);
    contract_validation_result_t validate_benchmark_sla_receipt_files(const json& receipt,
        const json& approved_external_slot, const std::filesystem::path& evidence_root);
}
