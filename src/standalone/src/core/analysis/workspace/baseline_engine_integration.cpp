#include "baseline_engine_integration.hpp"

#include "analysis_metrics.hpp"
#include "checked_range.hpp"
#include "persistence_queue.hpp"
#include "workspace_database.hpp"
#include "workspace_registry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace aida::analysis {
namespace {

struct integration_state_t final {
    std::shared_ptr<analysis_workspace_t> workspace;
    baseline_engine_integration_config_t config;
    std::atomic<std::uint64_t> active_job_id{0};
    std::atomic<bool> cancellation_active{false};
    std::atomic<c03::publication_stage_t> current_stage{c03::publication_stage_t::none};
    std::atomic<std::uint64_t> active_generation{0};
    std::atomic<std::uint64_t> active_analysis_revision{0};
    std::atomic<bool> resource_budget_exceeded{false};
    mutable std::mutex snapshot_mutex;
    baseline_engine_integration_metrics_t metrics_snapshot;
    std::optional<c03::cancellation_domain_t> cancellation_domain;
    std::optional<aida::infra::taskflow_runtime::job_handle_t> last_handle;

    explicit integration_state_t(std::shared_ptr<analysis_workspace_t> ws,
                                 baseline_engine_integration_config_t cfg)
        : workspace(std::move(ws)), config(std::move(cfg)) {}
};

workspace_result_t<c03::workspace_contract_identity_t>
resolve_workspace_contract_identity(const analysis_workspace_t& workspace) {
    const auto& identity = workspace.identity();
    c03::workspace_id_t::bytes_t bytes{};
    const auto hex = identity.binary_id().to_hex();
    if (hex.size() >= 32) {
        for (std::size_t i = 0; i < 16 && i + 1 < hex.size(); i += 2) {
            const auto hi = hex[i];
            const auto lo = hex[i + 1];
            auto nibble = [](char c, std::uint8_t& v) -> bool {
                if (c >= '0' && c <= '9') { v = static_cast<std::uint8_t>(c - '0'); return true; }
                if (c >= 'a' && c <= 'f') { v = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
                if (c >= 'A' && c <= 'F') { v = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
                return false;
            };
            std::uint8_t hi_v = 0, lo_v = 0;
            if (!nibble(hi, hi_v) || !nibble(lo, lo_v))
                break;
            bytes[i / 2] = static_cast<std::uint8_t>((hi_v << 4) | lo_v);
        }
    }
    auto ws_id_result = c03::workspace_id_t::from_bytes(bytes);
    if (!ws_id_result)
        return workspace_result_t<c03::workspace_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 workspace identity could not be derived from binary_id",
                "baseline_engine_integration"));
    auto contract_identity = c03::workspace_contract_identity_t::make(ws_id_result.value());
    if (!contract_identity)
        return workspace_result_t<c03::workspace_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 workspace contract identity validation failed",
                "baseline_engine_integration"));
    return workspace_result_t<c03::workspace_contract_identity_t>::success(
        contract_identity.value());
}

workspace_result_t<c03::target_contract_identity_t>
resolve_target_contract_identity(const analysis_workspace_t& workspace) {
    auto ws_contract = resolve_workspace_contract_identity(workspace);
    if (!ws_contract)
        return workspace_result_t<c03::target_contract_identity_t>::failure(ws_contract.error());
    auto target_result = c03::target_id_t::from_value(
        workspace.generation() + 1);
    if (!target_result)
        return workspace_result_t<c03::target_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 target identity could not be derived",
                "baseline_engine_integration"));
    const auto target_id = target_result.value();
    const auto kind = workspace.target_kind() == target_kind_t::static_file
        ? c03::analysis_target_kind_t::static_image
        : c03::analysis_target_kind_t::live_module;
    auto target_contract = c03::target_contract_identity_t::make(
        ws_contract.value(), target_id, kind, std::nullopt, std::nullopt);
    if (!target_contract)
        return workspace_result_t<c03::target_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 target contract identity validation failed",
                "baseline_engine_integration"));
    return workspace_result_t<c03::target_contract_identity_t>::success(
        target_contract.value());
}

workspace_result_t<c03::generation_contract_identity_t>
resolve_generation_contract_identity(const analysis_workspace_t& workspace) {
    auto target_contract = resolve_target_contract_identity(workspace);
    if (!target_contract)
        return workspace_result_t<c03::generation_contract_identity_t>::failure(
            target_contract.error());
    auto gen_result = c03::generation_id_t::from_value(workspace.generation());
    if (!gen_result)
        return workspace_result_t<c03::generation_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                "C03 generation identity could not be derived",
                "baseline_engine_integration"));
    auto gen_contract = c03::generation_contract_identity_t::make(
        target_contract.value(), gen_result.value());
    if (!gen_contract)
        return workspace_result_t<c03::generation_contract_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                "C03 generation contract identity validation failed",
                "baseline_engine_integration"));
    return workspace_result_t<c03::generation_contract_identity_t>::success(
        gen_contract.value());
}

bool resource_budget_satisfied(
    const c03::analysis_resource_budget_t& budget,
    const c03::analysis_resource_usage_t& usage) noexcept {
    if (usage.incremental_private_bytes > budget.max_incremental_private_bytes)
        return false;
    if (usage.workspace_mapped_window_bytes > budget.max_workspace_mapped_window_bytes)
        return false;
    if (usage.global_mapped_window_bytes > budget.max_global_mapped_window_bytes)
        return false;
    if (usage.workspace_spill_bytes > budget.max_workspace_spill_bytes)
        return false;
    if (usage.global_spill_bytes > budget.max_global_spill_bytes)
        return false;
    if (usage.workspace_cache_bytes > budget.max_workspace_cache_bytes)
        return false;
    if (usage.global_cache_bytes > budget.max_global_cache_bytes)
        return false;
    return true;
}

c03::analysis_resource_usage_t estimate_resource_usage(
    const baseline_analysis_settings_t& settings) noexcept {
    c03::analysis_resource_usage_t usage;
    usage.incremental_private_bytes = settings.max_analysis_memory_bytes;
    usage.workspace_mapped_window_bytes = settings.decode_read_window_bytes;
    usage.workspace_spill_bytes = 0;
    usage.workspace_cache_bytes = settings.max_analysis_memory_bytes / 4;
    return usage;
}

}

struct baseline_engine_integration_t::impl_t {
    integration_state_t state;

    explicit impl_t(std::shared_ptr<analysis_workspace_t> ws,
                    baseline_engine_integration_config_t cfg)
        : state(std::move(ws), std::move(cfg)) {}

    void record_metric(std::atomic<std::uint64_t> baseline_engine_integration_metrics_t::*field,
                       std::uint64_t delta = 1) noexcept {
        (void)field;
        (void)delta;
    }

    workspace_result_t<void> validate_contracts() {
        if (!state.config.enforce_c03_contracts)
            return workspace_result_t<void>::success();
        auto gen_contract = resolve_generation_contract_identity(*state.workspace);
        if (!gen_contract) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.contracts_rejected++;
            return workspace_result_t<void>::failure(gen_contract.error());
        }
        auto schema_result = c03::validate_contract_schema_version(
            c03::contract_schema_t::generation_identity,
            c03::contract_schema_version_for(c03::contract_schema_t::generation_identity));
        if (!schema_result) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.contracts_rejected++;
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 generation identity schema version mismatch",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto snapshot_contract = c03::immutable_snapshot_contract_t::make(
            gen_contract.value(),
            state.workspace->analysis_revision() + 1,
            state.workspace->generation() + 1,
            state.workspace->overlay_revision(),
            1);
        if (!snapshot_contract) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.contracts_rejected++;
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 immutable snapshot contract validation failed",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto publication_contract = c03::immutable_publication_contract_t::make(
            gen_contract.value(),
            snapshot_contract.value(),
            c03::publication_stage_t::metadata_ready,
            1);
        if (!publication_contract) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.contracts_rejected++;
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 immutable publication contract validation failed",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        std::lock_guard<std::mutex> lock(state.snapshot_mutex);
        state.metrics_snapshot.contracts_validated++;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> validate_resource_budget() {
        if (!state.config.enforce_resource_budget)
            return workspace_result_t<void>::success();
        const auto usage = estimate_resource_usage(state.config.baseline_settings);
        auto budget_result = c03::validate_analysis_resource_budget(state.config.resource_budget);
        if (!budget_result) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.resource_budget_rejections++;
            state.resource_budget_exceeded.store(true, std::memory_order_release);
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "C03 resource budget configuration is invalid",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        if (!resource_budget_satisfied(state.config.resource_budget, usage)) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.resource_budget_rejections++;
            state.resource_budget_exceeded.store(true, std::memory_order_release);
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "C03 resource budget would be exceeded by baseline analysis settings",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto reserve = c03::reserve_analysis_resources(
            state.config.resource_budget, c03::analysis_resource_usage_t{}, usage);
        if (!reserve) {
            std::lock_guard<std::mutex> lock(state.snapshot_mutex);
            state.metrics_snapshot.resource_budget_rejections++;
            state.resource_budget_exceeded.store(true, std::memory_order_release);
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "C03 resource budget reservation failed",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        std::lock_guard<std::mutex> lock(state.snapshot_mutex);
        state.metrics_snapshot.resource_budget_checks++;
        state.resource_budget_exceeded.store(false, std::memory_order_release);
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> establish_cancellation_domain() {
        auto ws_contract = resolve_workspace_contract_identity(*state.workspace);
        if (!ws_contract)
            return workspace_result_t<void>::failure(ws_contract.error());
        auto domain = c03::cancellation_domain_t::for_workspace(
            ws_contract.value(), state.workspace->generation());
        if (!domain) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "C03 cancellation domain could not be established",
                "baseline_engine_integration");
            return workspace_result_t<void>::failure(std::move(error));
        }
        std::lock_guard<std::mutex> lock(state.snapshot_mutex);
        state.cancellation_domain.emplace(std::move(domain).take_value());
        state.metrics_snapshot.cancellation_domain_activated++;
        return workspace_result_t<void>::success();
    }

    void revoke_cancellation_domain() noexcept {
        std::lock_guard<std::mutex> lock(state.snapshot_mutex);
        state.cancellation_domain.reset();
        state.metrics_snapshot.cancellation_domain_revoked++;
    }
};

baseline_engine_integration_t::baseline_engine_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)),
      config_(impl_ ? impl_->state.config : baseline_engine_integration_config_t{}),
      workspace_(impl_ ? impl_->state.workspace : nullptr) {}

baseline_engine_integration_t::~baseline_engine_integration_t() = default;

workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>
baseline_engine_integration_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    baseline_engine_integration_config_t config) {
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "baseline engine integration requires a workspace",
                "baseline_engine_integration"));
    }
    if (config.reject_live_targets &&
        workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                "bulk baseline analysis is not supported for live targets",
                "baseline_engine_integration"));
    }
    auto settings_validation = config.baseline_settings.validate();
    if (!settings_validation)
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            settings_validation.error());
    if (config.admit_managed_metadata &&
        !config.managed_reader_limits.valid())
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "managed baseline reader limits are invalid",
                "baseline_engine_integration"));
    auto impl = std::make_unique<impl_t>(workspace, config);
    auto integration = std::shared_ptr<baseline_engine_integration_t>(
        new baseline_engine_integration_t(std::move(impl)));
    auto contracts = integration->impl_->validate_contracts();
    if (!contracts)
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            contracts.error());
    auto budget = integration->impl_->validate_resource_budget();
    if (!budget)
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            budget.error());
    auto domain = integration->impl_->establish_cancellation_domain();
    if (!domain)
        return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::failure(
            domain.error());
    return workspace_result_t<std::shared_ptr<baseline_engine_integration_t>>::success(
        integration);
}

workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>
baseline_engine_integration_t::start_baseline(
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!workspace_) {
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "baseline engine integration has no workspace",
                "start_baseline"));
    }
    if (deadline && *deadline <= std::chrono::steady_clock::now()) {
        std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
        impl_->state.metrics_snapshot.deadline_rejections++;
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline deadline expired before graph submission",
            "start_baseline");
        error.deadline = true;
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            std::move(error));
    }
    if (config_.reject_live_targets &&
        workspace_->target_kind() != target_kind_t::static_file) {
        std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
        impl_->state.metrics_snapshot.bulk_rejections++;
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                "bulk baseline analysis is not supported for live targets",
                "start_baseline"));
    }
    auto budget_check = impl_->validate_resource_budget();
    if (!budget_check) {
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            budget_check.error());
    }
    if (config_.admit_managed_metadata) {
        const auto publication = workspace_->analysis_publication();
        if (!publication || !publication->snapshot || !publication->provider)
            return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "managed admission requires a coherent workspace publication",
                    "start_baseline.managed"));
        if (!publication->managed_artifacts) {
            const auto target_revision = publication->analysis_revision == 0
                ? 1ULL : publication->analysis_revision;
            auto managed = build_managed_artifact_publication(
                workspace_->identity(), *publication->provider,
                publication->snapshot->image, publication->generation,
                target_revision, publication->overlay_revision,
                config_.managed_reader_limits, workspace_->cancellation_token());
            if (!managed) {
                std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
                impl_->state.metrics_snapshot.managed_admission_failures++;
                return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
                    managed.error());
            }
            if (managed.value()) {
                auto published = workspace_->publish_managed_artifacts(
                    publication->generation, publication->analysis_revision,
                    managed.take_value(), true);
                if (!published) {
                    std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
                    impl_->state.metrics_snapshot.managed_admission_failures++;
                    return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
                        published.error());
                }
                std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
                impl_->state.metrics_snapshot.managed_admissions++;
            }
        }
    }
    impl_->state.cancellation_active.store(false, std::memory_order_release);
    impl_->state.active_generation.store(workspace_->generation(),
        std::memory_order_release);
    impl_->state.active_analysis_revision.store(workspace_->analysis_revision(),
        std::memory_order_release);
    impl_->state.current_stage.store(
        c03::publication_stage_t::metadata_ready,
        std::memory_order_release);
    auto submitted = baseline_analysis_service_t::start(
        workspace_, config_.baseline_settings, deadline);
    if (!submitted) {
        std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
        impl_->state.metrics_snapshot.graph_rejections++;
        impl_->state.metrics_snapshot.publish_failures++;
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            submitted.error());
    }
    impl_->state.active_job_id.store(submitted.value().id,
        std::memory_order_release);
    impl_->state.last_handle = submitted.value();
    {
        std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
        impl_->state.metrics_snapshot.graph_submissions++;
    }
    impl_->state.current_stage.store(
        c03::publication_stage_t::baseline_ready,
        std::memory_order_release);
    return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::success(
        submitted.value());
}

bool baseline_engine_integration_t::cancel_baseline() noexcept {
    const auto id = impl_->state.active_job_id.load(std::memory_order_acquire);
    if (id == 0)
        return false;
    impl_->state.cancellation_active.store(true, std::memory_order_release);
    impl_->state.current_stage.store(
        c03::publication_stage_t::retired,
        std::memory_order_release);
    const auto cancelled = baseline_analysis_service_t::cancel(
        aida::infra::taskflow_runtime::job_handle_t{id});
    if (cancelled)
        impl_->revoke_cancellation_domain();
    return cancelled;
}

workspace_result_t<void> baseline_engine_integration_t::drain(
    std::chrono::steady_clock::time_point deadline) {
    const auto id = impl_->state.active_job_id.load(std::memory_order_acquire);
    if (id == 0)
        return workspace_result_t<void>::success();
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                "baseline engine integration did not drain before deadline",
                "drain");
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        const auto wait_ms = static_cast<std::uint32_t>(std::max<std::int64_t>(1,
            std::min<std::int64_t>(25, remaining.count())));
        const auto result = aida::infra::taskflow_runtime::wait_for(
            aida::infra::taskflow_runtime::job_handle_t{id}, wait_ms);
        if (result.completed || result.cancelled) {
            impl_->state.active_job_id.store(0, std::memory_order_release);
            {
                std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
                impl_->state.metrics_snapshot.publish_completions++;
            }
            return workspace_result_t<void>::success();
        }
        if (result.failed) {
            impl_->state.active_job_id.store(0, std::memory_order_release);
            {
                std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
                impl_->state.metrics_snapshot.publish_failures++;
            }
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "baseline analysis graph failed while draining",
                    "drain"));
        }
    }
}

baseline_engine_integration_snapshot_t
baseline_engine_integration_t::snapshot() const noexcept {
    baseline_engine_integration_snapshot_t result;
    result.active_generation = impl_->state.active_generation.load(
        std::memory_order_acquire);
    result.active_analysis_revision = impl_->state.active_analysis_revision.load(
        std::memory_order_acquire);
    result.cancellation_active = impl_->state.cancellation_active.load(
        std::memory_order_acquire);
    result.resource_budget_exceeded = impl_->state.resource_budget_exceeded.load(
        std::memory_order_acquire);
    result.current_stage = impl_->state.current_stage.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
        result.metrics = impl_->state.metrics_snapshot;
    }
    return result;
}

workspace_result_t<c03::immutable_snapshot_contract_t>
baseline_engine_integration_t::validate_snapshot_contract() const {
    if (!workspace_)
        return workspace_result_t<c03::immutable_snapshot_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "no workspace for snapshot contract validation",
                "baseline_engine_integration"));
    auto gen_contract = resolve_generation_contract_identity(*workspace_);
    if (!gen_contract)
        return workspace_result_t<c03::immutable_snapshot_contract_t>::failure(
            gen_contract.error());
    auto snapshot_contract = c03::immutable_snapshot_contract_t::make(
        gen_contract.value(),
        workspace_->analysis_revision() + 1,
        workspace_->generation() + 1,
        workspace_->overlay_revision(),
        1);
    if (!snapshot_contract)
        return workspace_result_t<c03::immutable_snapshot_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "immutable snapshot contract validation failed",
                "baseline_engine_integration"));
    return workspace_result_t<c03::immutable_snapshot_contract_t>::success(
        snapshot_contract.value());
}

workspace_result_t<c03::immutable_publication_contract_t>
baseline_engine_integration_t::validate_publication_contract(
    c03::publication_stage_t stage) const {
    if (!workspace_)
        return workspace_result_t<c03::immutable_publication_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "no workspace for publication contract validation",
                "baseline_engine_integration"));
    auto gen_contract = resolve_generation_contract_identity(*workspace_);
    if (!gen_contract)
        return workspace_result_t<c03::immutable_publication_contract_t>::failure(
            gen_contract.error());
    auto snapshot_contract = c03::immutable_snapshot_contract_t::make(
        gen_contract.value(),
        workspace_->analysis_revision() + 1,
        workspace_->generation() + 1,
        workspace_->overlay_revision(),
        1);
    if (!snapshot_contract)
        return workspace_result_t<c03::immutable_publication_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "immutable snapshot contract validation failed for publication",
                "baseline_engine_integration"));
    auto publication_contract = c03::immutable_publication_contract_t::make(
        gen_contract.value(),
        snapshot_contract.value(),
        stage,
        workspace_->analysis_revision() + 1);
    if (!publication_contract)
        return workspace_result_t<c03::immutable_publication_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "immutable publication contract validation failed",
                "baseline_engine_integration"));
    auto transition = c03::validate_publication_stage_transition(
        impl_->state.current_stage.load(std::memory_order_acquire),
        stage);
    if (!transition)
        return workspace_result_t<c03::immutable_publication_contract_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "publication stage transition rejected",
                "baseline_engine_integration"));
    return workspace_result_t<c03::immutable_publication_contract_t>::success(
        publication_contract.value());
}

workspace_result_t<c03::cancellation_domain_t>
baseline_engine_integration_t::active_cancellation_domain() const {
    std::lock_guard<std::mutex> lock(impl_->state.snapshot_mutex);
    if (impl_->state.cancellation_domain)
        return workspace_result_t<c03::cancellation_domain_t>::success(
            impl_->state.cancellation_domain.value());
    return workspace_result_t<c03::cancellation_domain_t>::failure(
        make_workspace_error(workspace_error_code_t::integrity_failure,
            "no active cancellation domain",
            "baseline_engine_integration"));
}

}
