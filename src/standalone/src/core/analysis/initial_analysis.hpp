#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <utility>

#include "workspace/baseline_pipeline.hpp"

namespace initial_analysis {

inline aida::analysis::workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>
run_initial_analysis(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
                     aida::analysis::baseline_analysis_settings_t settings = {},
                     std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt)
{
    return aida::analysis::baseline_analysis_service_t::start(
        workspace, std::move(settings), deadline);
}

}
