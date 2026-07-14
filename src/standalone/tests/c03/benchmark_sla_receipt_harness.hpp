#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace aida::analysis::c03
{
    bool run_benchmark_sla_receipt_harness(const std::filesystem::path& evidence_root,
        std::string_view input_path, bool not_run, std::string& receipt_json, std::string& failure);
}
