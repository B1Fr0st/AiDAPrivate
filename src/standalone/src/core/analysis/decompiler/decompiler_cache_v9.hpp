#pragma once

#include "semantic_refiner.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis {

struct decompiler_provider_ir_cache_value_t {
    provider_ir_t provider_ir;
    std::optional<hir_function_t> provider_hir;
    type_graph_t provider_type_graph;
    std::uint64_t return_type_id = 0;
    std::vector<semantic_refinement_query_t> semantic_queries;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint64_t provider_wall_clock_ms = 0;
    std::uint64_t provider_cpu_ms = 0;
    std::uint64_t provider_peak_memory_bytes = 0;
};

struct decompiler_normalized_cache_value_t {
    sha256_digest_t provider_ir_hash;
    hir_function_t hir;
    type_graph_t type_graph;
    typed_pseudocode_ast_v2_t ast;
    std::vector<semantic_refinement_fact_t> semantic_facts;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint64_t provider_wall_clock_ms = 0;
    std::uint64_t provider_cpu_ms = 0;
    std::uint64_t provider_peak_memory_bytes = 0;
};

struct decompiler_rendered_cache_value_t {
    decompiler_document_t document;
    std::vector<semantic_refinement_fact_t> semantic_facts;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint64_t provider_wall_clock_ms = 0;
    std::uint64_t provider_cpu_ms = 0;
    std::uint64_t provider_peak_memory_bytes = 0;
};

template <typename T>
struct decompiler_cache_v9_lookup_t {
    std::shared_ptr<const T> value;

    bool hit() const noexcept { return static_cast<bool>(value); }
};

std::string serialize_decompiler_rendered_cache_value(
    const decompiler_rendered_cache_value_t& value);
std::optional<decompiler_rendered_cache_value_t>
    deserialize_decompiler_rendered_cache_value(std::string_view bytes) noexcept;

struct decompiler_cache_v9_limits_t {
    std::size_t max_workspaces = 256;
    std::size_t max_entries_per_workspace = 384;
    std::uint64_t max_bytes_per_workspace = 128ULL << 20;
    std::size_t max_total_entries = 4096;
    std::uint64_t max_total_bytes = 512ULL << 20;
    std::uint64_t max_entry_bytes = 64ULL << 20;
    std::size_t max_cache_key_bytes = 1U << 20;
    std::size_t max_workspace_id_bytes = 256;
};

struct decompiler_cache_v9_stage_snapshot_t {
    std::uint64_t hits = 0;
    std::uint64_t misses = 0;
    std::uint64_t stores = 0;
    std::uint64_t rejections = 0;
    std::uint64_t evictions = 0;
};

struct decompiler_cache_v9_snapshot_t {
    decompiler_cache_v9_stage_snapshot_t provider_ir;
    decompiler_cache_v9_stage_snapshot_t normalized_hir_ast;
    decompiler_cache_v9_stage_snapshot_t rendered_document;
    std::size_t workspaces = 0;
    std::size_t entries = 0;
    std::uint64_t resident_bytes = 0;
    std::uint64_t generation_invalidations = 0;
    std::uint64_t explicit_invalidations = 0;
};

class decompiler_cache_v9_t final {
public:
    static workspace_result_t<std::shared_ptr<decompiler_cache_v9_t>> create(
        decompiler_cache_v9_limits_t limits = {});

    ~decompiler_cache_v9_t();
    decompiler_cache_v9_t(const decompiler_cache_v9_t&) = delete;
    decompiler_cache_v9_t& operator=(const decompiler_cache_v9_t&) = delete;

    workspace_result_t<void> activate_workspace_generation(
        const std::string& workspace_id,
        std::uint64_t generation);
    bool is_current_generation(
        const std::string& workspace_id,
        std::uint64_t generation) const;

    workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_provider_ir_cache_value_t>>
        lookup_provider_ir(const decompiler_pipeline_cache_key_t& key);
    workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_normalized_cache_value_t>>
        lookup_normalized(const decompiler_pipeline_cache_key_t& key);
    workspace_result_t<decompiler_cache_v9_lookup_t<decompiler_rendered_cache_value_t>>
        lookup_rendered(const decompiler_pipeline_cache_key_t& key);

    workspace_result_t<void> store_provider_ir(
        decompiler_pipeline_cache_key_t key,
        decompiler_provider_ir_cache_value_t value);
    workspace_result_t<void> store_normalized(
        decompiler_pipeline_cache_key_t key,
        decompiler_normalized_cache_value_t value);
    workspace_result_t<void> store_rendered(
        decompiler_pipeline_cache_key_t key,
        decompiler_rendered_cache_value_t value);

    workspace_result_t<void> invalidate_stage(
        const std::string& workspace_id,
        std::uint64_t generation,
        decompiler_cache_stage_t stage);
    workspace_result_t<void> invalidate_entities(
        const std::string& workspace_id,
        std::uint64_t generation,
        const std::vector<decompiler_entity_key_t>& entities);
    workspace_result_t<void> invalidate_workspace(
        const std::string& workspace_id,
        std::uint64_t generation);
    workspace_result_t<void> retire_workspace(
        const std::string& workspace_id,
        std::uint64_t generation);
    void clear() noexcept;

    decompiler_cache_v9_snapshot_t snapshot() const;

private:
    struct state_t;
    explicit decompiler_cache_v9_t(std::shared_ptr<state_t> state);
    std::shared_ptr<state_t> state_;
};

}
