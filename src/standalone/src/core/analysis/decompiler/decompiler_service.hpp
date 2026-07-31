#pragma once

#include "decompiler_cache_v9.hpp"
#include "decompiler_provider_registry.hpp"
#include "pseudocode_readability.hpp"
#include "pseudocode_renderer_v2.hpp"
#include "type_graph_builder.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

class analysis_metrics_t;
class workspace_database_t;

enum class decompiler_pipeline_invocation_t : std::uint8_t {
    unspecified = 0,
    explicit_ui = 1,
    explicit_mcp = 2,
    explicit_api = 3,
    baseline_analysis = 4,
    background_batch = 5
};

enum class decompiler_pipeline_cache_mode_t : std::uint8_t {
    read_write = 1,
    read_only = 2,
    refresh = 3,
    bypass = 4
};

enum class decompiler_pipeline_status_t : std::uint8_t {
    completed = 1,
    invalid_request = 2,
    explicit_request_required = 3,
    provider_unavailable = 4,
    provider_failed = 5,
    provider_crashed = 6,
    deadline_exceeded = 7,
    cancelled = 8,
    resource_limit = 9,
    stale_generation = 10,
    normalization_failed = 11,
    rendering_failed = 12,
    cache_integrity_failure = 13,
    service_stopped = 14
};

struct decompiler_profile_policy_t {
    decompiler_profile_budget_t fast;
    decompiler_profile_budget_t balanced;
    decompiler_profile_budget_t thorough;
};

decompiler_profile_policy_t default_decompiler_profile_policy();

enum class decompiler_rendered_probe_stage_t : std::uint8_t {
    none = 0,
    memory_rendered = 1,
    persistent_rendered = 2
};

struct decompiler_rendered_probe_result_t {
    decompiler_rendered_probe_stage_t hit_stage = decompiler_rendered_probe_stage_t::none;
    std::shared_ptr<const decompiler_rendered_cache_value_t> rendered;
};

struct decompiler_pipeline_cache_identity_t {
    sha256_digest_t worker_protocol_hash;
    sha256_digest_t loader_layout_hash;
    sha256_digest_t function_bytes_hash;
    std::vector<decompiler_chunk_fingerprint_t> chunk_fingerprints;
    std::uint64_t metadata_revision = 0;
    std::uint64_t type_graph_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::vector<decompiler_dependency_version_t> dependencies;
};

using decompiler_provider_context_factory_t = std::function<
    workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>(
        const decompiler_provider_request_t&, const cancellation_token_t&)>;

struct decompiler_pipeline_request_t {
    decompiler_pipeline_invocation_t invocation = decompiler_pipeline_invocation_t::unspecified;
    decompiler_pipeline_cache_mode_t cache_mode = decompiler_pipeline_cache_mode_t::read_write;
    std::string workspace_id;
    std::uint64_t workspace_generation = 0;
    std::uint64_t analysis_revision = 0;
    decompiler_entity_key_t entity;
    decompiler_language_identity_t language;
    decompiler_profile_id_t profile = decompiler_profile_id_t::balanced;
    std::optional<decompiler_profile_budget_t> budget;
    std::optional<decompiler_renderer_settings_t> renderer;
    std::optional<std::string> provider_registration_id;
    decompiler_pipeline_cache_identity_t cache_identity;
    std::shared_ptr<const decompiler_provider_context_t> provider_context;
    decompiler_provider_context_factory_t provider_context_factory;
    std::vector<type_graph::type_seed_batch_t> type_evidence;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct decompiler_pipeline_result_t {
    decompiler_pipeline_status_t status = decompiler_pipeline_status_t::invalid_request;
    decompiler_profile_budget_t effective_budget;
    std::optional<decompiler_provider_descriptor_t> provider;
    std::shared_ptr<const decompiler_provider_ir_cache_value_t> provider_stage;
    std::shared_ptr<const decompiler_normalized_cache_value_t> normalized_stage;
    std::shared_ptr<const decompiler_rendered_cache_value_t> rendered_stage;
    std::optional<pseudocode_readability_report_t> readability;
    std::optional<decompiler_cache_stage_t> cache_hit_stage;
    decompiler_semantic_proof_availability_t semantic_proof_availability =
        decompiler_semantic_proof_availability_t::not_requested;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint64_t elapsed_wall_clock_ms = 0;

    bool succeeded() const noexcept;
};

struct decompiler_pipeline_service_config_t {
    std::size_t max_parallel_requests = 4;
    std::size_t max_diagnostics = 65536;
    std::uint64_t max_provider_payload_bytes = 64ULL << 20;
    std::uint64_t max_normalized_payload_bytes = 128ULL << 20;
    typed_ast_v2_build_limits_t ast_limits;
    pseudocode_renderer_v2_limits_t renderer_limits;
    decompiler_profile_policy_t profiles = default_decompiler_profile_policy();
    std::shared_ptr<decompiler_isolated_provider_host_t> isolated_provider_host;
    pseudocode_readability_limits_t readability_limits;
    bool require_complete_source_map = true;
    bool batch_rendered_only_memory_cache = true;
    std::shared_ptr<workspace_database_t> database;
    std::shared_ptr<analysis_metrics_t> metrics_sink;
};

struct decompiler_pipeline_service_snapshot_t {
    std::uint64_t requests = 0;
    std::uint64_t completed = 0;
    std::uint64_t invalid_requests = 0;
    std::uint64_t provider_failures = 0;
    std::uint64_t cancellations = 0;
    std::uint64_t deadline_exceeded = 0;
    std::uint64_t stale_generations = 0;
    std::uint64_t resource_limits = 0;
    std::uint64_t provider_invocations = 0;
    std::uint64_t isolated_provider_invocations = 0;
    std::uint64_t isolated_host_rejections = 0;
    std::uint64_t provider_ir_cache_hits = 0;
    std::uint64_t normalized_cache_hits = 0;
    std::uint64_t rendered_cache_hits = 0;
    std::uint64_t semantic_proof_requests = 0;
    std::uint64_t semantic_proof_adapter_denials = 0;
    std::size_t active_requests = 0;
    bool accepting = false;
    std::uint64_t attest_stage_submitted = 0;
    std::uint64_t attest_stage_inline = 0;
    std::uint64_t attest_stage_completed = 0;
    std::size_t attest_in_flight = 0;
    std::size_t attest_in_flight_peak = 0;
};

class decompiler_pipeline_service_t final {
public:
    using decompiler_completion_t = std::function<void(decompiler_pipeline_result_t&&)>;

    static workspace_result_t<std::shared_ptr<decompiler_pipeline_service_t>> create(
        std::shared_ptr<decompiler_provider_registry_t> providers,
        std::shared_ptr<decompiler_cache_v9_t> cache,
        std::shared_ptr<semantic_refiner_t> semantic_refiner = {},
        decompiler_pipeline_service_config_t config = {});

    ~decompiler_pipeline_service_t();
    decompiler_pipeline_service_t(const decompiler_pipeline_service_t&) = delete;
    decompiler_pipeline_service_t& operator=(const decompiler_pipeline_service_t&) = delete;

    decompiler_pipeline_result_t decompile(
        const decompiler_pipeline_request_t& request,
        const cancellation_token_t& cancel = {});
    void decompile_async(
        const decompiler_pipeline_request_t& request,
        const cancellation_token_t& cancel,
        decompiler_completion_t completion);
    decompiler_rendered_probe_result_t probe_rendered_cache(
        const decompiler_pipeline_request_t& request);
    workspace_result_t<void> invalidate_workspace(
        const std::string& workspace_id,
        std::uint64_t generation);
    workspace_result_t<void> invalidate_entities(
        const std::string& workspace_id,
        std::uint64_t generation,
        const std::vector<decompiler_entity_key_t>& entities);
    decompiler_pipeline_service_snapshot_t snapshot() const;
    void request_stop() noexcept;

private:
    struct state_t;
    explicit decompiler_pipeline_service_t(std::shared_ptr<state_t> state);
    std::shared_ptr<state_t> state_;
};

}
