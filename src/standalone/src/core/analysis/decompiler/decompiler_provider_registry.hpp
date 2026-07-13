#pragma once

#include "semantic_refiner.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

namespace managed_cli {
struct request_t;
}

namespace jvm_ssa {
struct jvm_method_input_t;
}

namespace dalvik_ssa {
struct dalvik_ssa_capture_t;
}

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

class ghidra_native_provider_context_t final : public decompiler_provider_context_t {
public:
    explicit ghidra_native_provider_context_t(
        std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
        sha256_digest_t snapshot_hash);

    const std::shared_ptr<const std::vector<std::uint8_t>>& snapshot() const noexcept;
    const sha256_digest_t& snapshot_hash() const noexcept;

private:
    std::shared_ptr<const std::vector<std::uint8_t>> snapshot_;
    sha256_digest_t snapshot_hash_;
};

class managed_cli_provider_context_t final : public decompiler_provider_context_t {
public:
    managed_cli_provider_context_t(
        std::shared_ptr<const managed_cli::request_t> request);

    const std::shared_ptr<const managed_cli::request_t>& request() const noexcept;

private:
    std::shared_ptr<const managed_cli::request_t> request_;
};

class jvm_ssa_provider_context_t final : public decompiler_provider_context_t {
public:
    explicit jvm_ssa_provider_context_t(
        std::shared_ptr<const jvm_ssa::jvm_method_input_t> input);

    const std::shared_ptr<const jvm_ssa::jvm_method_input_t>& input() const noexcept;

private:
    std::shared_ptr<const jvm_ssa::jvm_method_input_t> input_;
};

class dalvik_ssa_provider_context_t final : public decompiler_provider_context_t {
public:
    explicit dalvik_ssa_provider_context_t(
        std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t> capture);

    const std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>& capture() const noexcept;

private:
    std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t> capture_;
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
    std::optional<decompiler_document_t> attested_document;
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

class decompiler_isolated_provider_host_t {
public:
    virtual ~decompiler_isolated_provider_host_t() = default;

    virtual bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept = 0;
    virtual decompiler_provider_result_t execute(
        const decompiler_provider_route_t& route,
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) = 0;
};

struct decompiler_builtin_provider_registration_t {
    decompiler_provider_identity_t identity;
    std::vector<decompiler_profile_id_t> profiles{
        decompiler_profile_id_t::fast,
        decompiler_profile_id_t::balanced,
        decompiler_profile_id_t::thorough};
    std::uint32_t priority = 100;
    bool isolated = true;
};

struct decompiler_builtin_provider_config_t {
    decompiler_builtin_provider_registration_t native;
    decompiler_builtin_provider_registration_t cli;
    decompiler_builtin_provider_registration_t jvm;
    decompiler_builtin_provider_registration_t dalvik;

    decompiler_builtin_provider_config_t();
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
    workspace_result_t<void> register_providers(
        std::vector<std::shared_ptr<decompiler_provider_t>> providers,
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

workspace_result_t<void> register_builtin_decompiler_providers(
    decompiler_provider_registry_t& registry,
    const decompiler_builtin_provider_config_t& config,
    bool replace_existing = false);

}
