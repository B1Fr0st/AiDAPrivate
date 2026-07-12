#pragma once

#include "semantic_refiner.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class decompiler_provider_execution_status_t : std::uint8_t {
    completed = 1,
    unsupported = 2,
    failed = 3,
    crashed = 4,
    timed_out = 5,
    cancelled = 6
};

class decompiler_provider_context_t {
public:
    virtual ~decompiler_provider_context_t() = default;
};

struct decompiler_provider_descriptor_t {
    std::string registration_id;
    decompiler_provider_identity_t identity;
    decompiler_entity_kind_t entity_kind = decompiler_entity_kind_t::native_function;
    std::vector<decompiler_profile_id_t> profiles;
    std::uint32_t priority = 0;
    bool isolated = true;
};

struct decompiler_provider_request_t {
    decompiler_pipeline_cache_key_t cache_key;
    std::chrono::steady_clock::time_point deadline;
    std::shared_ptr<const decompiler_provider_context_t> context;
};

struct decompiler_provider_artifacts_t {
    provider_ir_t provider_ir;
    std::optional<hir_function_t> hir;
    type_graph_t type_graph;
    std::uint64_t return_type_id = 0;
    std::vector<semantic_refinement_query_t> semantic_queries;
};

struct decompiler_provider_result_t {
    decompiler_provider_execution_status_t status = decompiler_provider_execution_status_t::failed;
    std::optional<decompiler_provider_artifacts_t> artifacts;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint64_t elapsed_wall_clock_ms = 0;
    std::uint64_t elapsed_cpu_ms = 0;
    std::uint64_t peak_memory_bytes = 0;

    bool succeeded() const noexcept;
};

class decompiler_provider_t {
public:
    virtual ~decompiler_provider_t() = default;

    virtual decompiler_provider_descriptor_t descriptor() const = 0;
    virtual bool supports_language(const decompiler_language_identity_t& language) const noexcept = 0;
    virtual decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) = 0;
};

struct decompiler_provider_route_t {
    decompiler_provider_descriptor_t descriptor;
    std::shared_ptr<decompiler_provider_t> provider;
};

struct decompiler_provider_registry_snapshot_t {
    std::vector<decompiler_provider_descriptor_t> providers;
    std::uint64_t revision = 0;
};

class decompiler_provider_registry_t final {
public:
    decompiler_provider_registry_t();
    ~decompiler_provider_registry_t();

    decompiler_provider_registry_t(const decompiler_provider_registry_t&) = delete;
    decompiler_provider_registry_t& operator=(const decompiler_provider_registry_t&) = delete;

    workspace_result_t<void> register_provider(
        std::shared_ptr<decompiler_provider_t> provider,
        bool replace_existing = false);
    workspace_result_t<void> unregister_provider(const std::string& registration_id);
    workspace_result_t<decompiler_provider_route_t> resolve(
        const decompiler_entity_key_t& entity,
        const decompiler_language_identity_t& language,
        const decompiler_profile_budget_t& profile,
        const std::optional<std::string>& registration_id = {}) const;
    decompiler_provider_registry_snapshot_t snapshot() const;

    static std::optional<decompiler_provider_id_t> expected_provider(
        decompiler_entity_kind_t entity_kind) noexcept;
    static std::optional<decompiler_entity_kind_t> expected_entity_kind(
        decompiler_provider_id_t provider) noexcept;

private:
    struct state_t;
    std::shared_ptr<state_t> state_;
};

}
