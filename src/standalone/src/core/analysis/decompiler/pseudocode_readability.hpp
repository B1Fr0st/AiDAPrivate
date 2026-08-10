#pragma once

#include "legacy_document_adapter.hpp"
#include "typed_ast.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_pseudocode_readability_schema_version = 2;

struct readability_transform_metrics_t {
    std::uint64_t variables_renamed = 0;
    std::uint64_t loop_counters_named = 0;
    std::uint64_t api_call_names_applied = 0;
    std::uint64_t type_based_names_applied = 0;
    std::uint64_t string_reference_names_applied = 0;
    std::uint64_t constants_folded = 0;
    std::uint64_t identities_simplified = 0;
    std::uint64_t casts_simplified = 0;
    std::uint64_t double_negations_simplified = 0;
    std::uint64_t comparisons_normalized = 0;
    std::uint64_t compound_assignments_marked = 0;
    std::uint64_t temporaries_inlined = 0;
    std::uint64_t copies_propagated = 0;
    std::uint64_t dead_stores_eliminated = 0;
    std::uint64_t member_names_propagated = 0;
    std::uint64_t member_accesses_rewritten = 0;
    std::uint64_t min_max_idioms_rewritten = 0;
    std::uint64_t idioms_recognized = 0;
    std::uint64_t declarations_relocated = 0;
    std::uint64_t string_comments_injected = 0;
    std::uint64_t user_comments_injected = 0;
    std::uint64_t nodes_removed = 0;
    std::uint64_t string_literals_inlined = 0;
    std::uint64_t global_scalar_comments_injected = 0;
    std::uint64_t cast_masks_folded = 0;
    std::uint64_t bit_operation_idioms_rewritten = 0;
    std::uint64_t loop_intrinsics_rewritten = 0;
    std::uint64_t magic_divisions_recognized = 0;
    std::uint64_t ternaries_formed = 0;
    std::uint64_t array_indexes_formed = 0;
    std::uint64_t method_calls_restructured = 0;
    std::uint64_t semantic_facts_applied = 0;
    std::uint64_t dead_branches_eliminated = 0;
    std::uint64_t casts_inserted = 0;
    std::uint64_t vararg_format_comments_injected = 0;
    std::uint64_t unsigned_folds = 0;
    std::uint64_t overflow_guards_hit = 0;
};

struct rt_semantic_fact_view_t {
    std::string refinement_key;
    std::uint8_t confidence = 0;
};

using rt_binding_id = std::uint32_t;

struct rt_binding_t {
    rt_binding_id id = 0;
    std::string name;
    std::uint64_t scope_node_id = 0;
    std::uint64_t declaration_node_id = 0;
    std::uint64_t type_id = 0;
    bool is_parameter = false;
};

struct rt_binding_table_t {
    std::vector<rt_binding_t> bindings;
    std::map<std::pair<std::uint64_t, std::string>, rt_binding_id> scope_name;
    std::unordered_map<std::uint64_t, rt_binding_id> by_declaration;
    std::unordered_map<std::uint64_t, rt_binding_id> by_identifier;
};

struct readability_transform_result_t {
    bool transformed = false;
    readability_transform_metrics_t metrics;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

struct pseudocode_local_rename_result_t {
    bool applied = false;
    std::uint64_t nodes_renamed = 0;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

pseudocode_local_rename_result_t apply_pseudocode_local_rename(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    std::string_view old_name,
    std::string_view new_name);

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings = {});

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings,
    const decompiler_render_evidence_t& evidence);

readability_transform_result_t apply_readability_transforms(
    typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const readability_transform_settings_t& settings,
    const decompiler_render_evidence_t& evidence,
    const std::vector<rt_semantic_fact_view_t>& semantic_facts,
    const std::vector<typed_ast_branch_bridge_entry_t>& branch_bridge);

bool readability_transforms_enabled(const readability_transform_settings_t& settings) noexcept;

readability_transform_settings_t to_rt_settings(const readability_transform_settings_t& settings) noexcept;

enum class pseudocode_baseline_provider_t : std::uint8_t {
    ghidra_printc = 1,
    aida_current = 2
};

struct pseudocode_readability_limits_t {
    std::size_t max_ast_nodes = 500000;
    std::size_t max_traversal_edges = 2000000;
    std::size_t max_nesting = 512;
    std::size_t max_document_bytes = 8U * 1024U * 1024U;
    std::size_t max_tokens = 500000;
    std::size_t max_source_maps = 500000;
    std::size_t max_diagnostics = 65536;
    std::size_t max_unknowns = 65536;
    std::size_t max_baseline_bytes = 8U * 1024U * 1024U;
    std::size_t max_fixture_id_bytes = 512;
};

struct pseudocode_readability_metrics_t {
    std::uint64_t declaration_count = 0;
    double naming_consistency_ratio = 1.0;
    std::uint64_t max_expression_depth = 0;
    std::uint64_t max_control_nesting = 0;
    std::uint64_t dead_placeholder_count = 0;
    std::uint64_t cast_count = 0;
    std::uint64_t fabricated_body_count = 0;
    std::uint64_t ternary_count = 0;
    std::uint64_t array_index_count = 0;
    std::uint64_t method_call_count = 0;
};

struct pseudocode_baseline_capture_request_t {
    pseudocode_baseline_provider_t provider = pseudocode_baseline_provider_t::aida_current;
    sha256_digest_t provider_build_hash;
    sha256_digest_t fixture_set_hash;
    std::string fixture_id;
    std::string rendered_text;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct pseudocode_baseline_capture_t {
    std::uint32_t schema_version = k_pseudocode_readability_schema_version;
    pseudocode_baseline_provider_t provider = pseudocode_baseline_provider_t::aida_current;
    sha256_digest_t provider_build_hash;
    sha256_digest_t fixture_set_hash;
    std::string fixture_id;
    std::string rendered_text;
    std::vector<decompiler_diagnostic_t> diagnostics;
    sha256_digest_t rendered_text_hash;
    sha256_digest_t capture_hash;
};

struct pseudocode_baseline_capture_result_t {
    std::optional<pseudocode_baseline_capture_t> capture;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

struct pseudocode_readability_request_t {
    pseudocode_readability_limits_t limits;
    std::optional<pseudocode_baseline_capture_request_t> baseline;
    bool require_complete_source_map = true;
};

struct pseudocode_readability_report_t {
    std::uint32_t schema_version = k_pseudocode_readability_schema_version;
    decompiler_entity_key_t entity;
    pseudocode_readability_metrics_t metrics;
    std::size_t ast_node_count = 0;
    std::size_t document_bytes = 0;
    std::size_t source_mapped_bytes = 0;
    double source_map_coverage_ratio = 0.0;
    double mean_confidence = 0.0;
    std::uint8_t minimum_confidence = 0;
    double explicit_unknown_ratio = 0.0;
    sha256_digest_t ast_hash;
    sha256_digest_t document_hash;
    sha256_digest_t source_map_hash;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;
    std::optional<pseudocode_baseline_capture_t> baseline;
};

struct pseudocode_readability_result_t {
    std::optional<pseudocode_readability_report_t> report;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

pseudocode_baseline_capture_result_t capture_pseudocode_readability_baseline(
    const pseudocode_baseline_capture_request_t& request,
    const pseudocode_readability_limits_t& limits = {});

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t* ast,
    const decompiler_document_t* document,
    const pseudocode_readability_request_t& request = {});

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request = {});

struct pseudocode_readability_precomputed_t {
    std::optional<sha256_digest_t> ast_digest;
    std::optional<sha256_digest_t> document_digest;
    bool ast_validated = false;
    bool document_validated = false;
};

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request,
    const pseudocode_readability_precomputed_t& precomputed);

}
