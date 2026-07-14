#pragma once

#include "benchmark_sla_schema.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace aida::analysis::c03
{
    struct benchmark_receipt_build_result_t
    {
        bool ok = false;
        json receipt;
        std::string error;
    };

    benchmark_receipt_build_result_t build_benchmark_sla_receipt(
        const std::filesystem::path& evidence_root,
        std::string_view measurement_manifest_path);

    benchmark_receipt_build_result_t build_benchmark_not_run_receipt(
        const std::filesystem::path& evidence_root,
        std::string_view search_receipt_path);
}
