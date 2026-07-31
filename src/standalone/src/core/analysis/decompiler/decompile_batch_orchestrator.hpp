#pragma once

#include "../workspace/analysis_workspace.hpp"
#include "../workspace/analysis_metrics.hpp"
#include "decompiler_contracts.hpp"
#include "decompiler_provider_registry.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace aida::analysis {

enum class decompile_deadline_lane_t : std::uint8_t {
    batch = 0,
    interactive = 1
};

class decompile_batch_orchestrator_t final
    : public baseline_publish_observer_t
    , public workspace_lifecycle_participant_t
    , public std::enable_shared_from_this<decompile_batch_orchestrator_t> {
public:
    static workspace_result_t<std::shared_ptr<decompile_batch_orchestrator_t>> create(
        std::shared_ptr<analysis_workspace_t> workspace,
        std::shared_ptr<analysis_metrics_t> metrics);
    ~decompile_batch_orchestrator_t() override;

    decompile_batch_orchestrator_t(const decompile_batch_orchestrator_t&) = delete;
    decompile_batch_orchestrator_t& operator=(const decompile_batch_orchestrator_t&) = delete;

    void on_baseline_published(
        const std::shared_ptr<const analysis_publication_t>& publication) noexcept override;
    void request_cancel() noexcept override;
    workspace_result_t<void> drain(std::chrono::steady_clock::time_point deadline) override;
    void notify_interactive_request(const decompiler_entity_key_t& entity);
    bool admit_interactive_priority(const decompiler_entity_key_t& entity);

    static std::uint64_t compute_size_aware_deadline(
        std::uint64_t function_byte_size,
        architecture_id_t architecture,
        decompile_deadline_lane_t lane) noexcept;

    static workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>
        capture_generation_provider_context(
            const std::shared_ptr<analysis_workspace_t>& workspace,
            const std::shared_ptr<const analysis_publication_t>& publication,
            const cancellation_token_t& cancel);

    struct run_snapshot_t {
        bool active = false;
        std::uint64_t generation = 0;
        std::uint64_t analysis_revision = 0;
        std::uint64_t total = 0;
        std::uint64_t completed = 0;
        std::uint64_t failed = 0;
        std::uint64_t cancelled = 0;
        std::uint64_t queue_depth = 0;
        std::uint64_t interactive_pending = 0;
        std::uint64_t slots = 0;
        std::uint64_t slots_effective = 0;
        double rate_funcs_s = 0.0;
        double eta_s = 0.0;
    };
    run_snapshot_t run_snapshot() const;

    struct state_t;

private:
    explicit decompile_batch_orchestrator_t(std::shared_ptr<state_t> state);
    std::shared_ptr<state_t> state_;
};

}
