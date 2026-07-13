#pragma once

#include "analysis_workspace.hpp"
#include "baseline_pipeline.hpp"
#include "c03_analysis_contracts.hpp"
#include "pe_baseline_analyzer.hpp"
#include "workspace_types.hpp"
#include "../../infra/taskflow_runtime.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

struct baseline_engine_integration_config_t {
    c03::analysis_resource_budget_t resource_budget = {};
    baseline_analysis_settings_t baseline_settings = {};
    bool enforce_c03_contracts = true;
    bool enforce_resource_budget = true;
    bool reject_live_targets = true;
    std::uint64_t cancellation_checkpoint_interval_ms =
        c03::max_cancellation_checkpoint_milliseconds;
};

struct baseline_engine_integration_metrics_t {
    std::uint64_t contracts_validated = 0;
    std::uint64_t contracts_rejected = 0;
    std::uint64_t resource_budget_checks = 0;
    std::uint64_t resource_budget_rejections = 0;
    std::uint64_t cancellation_domain_activated = 0;
    std::uint64_t cancellation_domain_revoked = 0;
    std::uint64_t bulk_rejections = 0;
    std::uint64_t deadline_rejections = 0;
    std::uint64_t graph_submissions = 0;
    std::uint64_t graph_rejections = 0;
    std::uint64_t publish_completions = 0;
    std::uint64_t publish_failures = 0;
};

struct baseline_engine_integration_snapshot_t {
    baseline_engine_integration_metrics_t metrics;
    c03::publication_stage_t current_stage = c03::publication_stage_t::none;
    std::uint64_t active_generation = 0;
    std::uint64_t active_analysis_revision = 0;
    bool resource_budget_exceeded = false;
    bool cancellation_active = false;
};

class baseline_engine_integration_t final {
public:
    static workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>
        create(std::shared_ptr<analysis_workspace_t> workspace,
               baseline_engine_integration_config_t config = {});

    ~baseline_engine_integration_t();
    baseline_engine_integration_t(const baseline_engine_integration_t&) = delete;
    baseline_engine_integration_t& operator=(const baseline_engine_integration_t&) = delete;

    workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>
        start_baseline(std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt);

    bool cancel_baseline() noexcept;

    workspace_result_t<void> drain(std::chrono::steady_clock::time_point deadline);

    baseline_engine_integration_snapshot_t snapshot() const noexcept;

    workspace_result_t<c03::immutable_snapshot_contract_t>
        validate_snapshot_contract() const;

    workspace_result_t<c03::immutable_publication_contract_t>
        validate_publication_contract(c03::publication_stage_t stage) const;

    workspace_result_t<c03::cancellation_domain_t>
        active_cancellation_domain() const;

    const baseline_engine_integration_config_t& config() const noexcept { return config_; }
    std::shared_ptr<analysis_workspace_t> workspace() const noexcept { return workspace_; }

private:
    struct impl_t;
    explicit baseline_engine_integration_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;

    baseline_engine_integration_config_t config_;
    std::shared_ptr<analysis_workspace_t> workspace_;
    mutable std::atomic<baseline_engine_integration_metrics_t> metrics_;
};

}
