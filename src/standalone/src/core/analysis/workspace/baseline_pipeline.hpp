#pragma once

#include "analysis_workspace.hpp"
#include "pe_baseline_analyzer.hpp"
#include "workspace_types.hpp"
#include "../../infra/taskflow_runtime.hpp"

#include <chrono>
#include <memory>
#include <optional>

namespace aida::analysis {

class baseline_analysis_service_t final {
public:
    static workspace_result_t<aida::infra::taskflow_runtime::job_handle_t> start(
        std::shared_ptr<analysis_workspace_t> workspace,
        baseline_analysis_settings_t settings = {},
        std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt);
    static bool cancel(aida::infra::taskflow_runtime::job_handle_t handle) noexcept;
};

}
