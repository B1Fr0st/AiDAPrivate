#pragma once

#include "../../assertion_telemetry/assertion_telemetry.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace aida::c03::security
{
inline bool record_policy_case(bool accepted, std::string_view identity,
    std::string& failure)
{
    aida::analysis::c03_test::assertion_telemetry::record_assertion(
        accepted, identity, __FILE__, __LINE__);
    if (!accepted)
        failure.assign(identity);
    return accepted;
}

bool run_self_guard_policy_cases(std::string& failure);
bool run_prologue_policy_cases(std::string& failure);
bool run_dma_policy_cases(std::string& failure);
bool run_passive_probe_policy_cases(std::string& failure);
bool run_anti_tamper_integrity_harness(
    const std::filesystem::path& repository_root,
    std::string& failure);
}
