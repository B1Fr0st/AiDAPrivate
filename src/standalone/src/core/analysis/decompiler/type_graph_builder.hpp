#pragma once

#include "decompiler_contracts.hpp"
#include "metadata_provenance.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida::analysis::type_graph {

constexpr std::uint32_t k_default_max_nodes = 65536;
constexpr std::uint32_t k_default_max_edges_per_node = 4096;
constexpr std::uint32_t k_default_max_total_edges = 1U << 20;
constexpr std::uint32_t k_default_max_recursion_depth = 64;

struct type_edge_candidate_t {
    decompiler_type_edge_kind_t kind = decompiler_type_edge_kind_t::member;
    std::string target_canonical_name;
    std::string stable_name;
    std::optional<std::uint64_t> byte_offset;
    std::uint32_t local_ordinal = 0;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
    std::string source_detail;
};

struct type_candidate_t {
    decompiler_type_kind_t kind = decompiler_type_kind_t::unknown;
    std::string canonical_name;
    std::string display_name;
    std::optional<std::uint64_t> byte_size;
    std::uint32_t alignment = 0;
    bool is_signed = false;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
    std::string source_detail;
    source_coordinate_t coordinate;
    std::vector<type_edge_candidate_t> edges;
};

struct type_seed_batch_t {
    decompiler_fact_provenance_t source = decompiler_fact_provenance_t::unknown;
    std::string source_label;
    std::vector<type_candidate_t> candidates;
};

struct type_conflict_record_t {
    std::string canonical_name;
    std::string field_name;
    std::string resolved_value;
    std::string rejected_value;
    type_provenance_record_t resolved_provenance;
    type_provenance_record_t rejected_provenance;
};

struct type_graph_builder_config_t {
    std::uint32_t max_nodes = k_default_max_nodes;
    std::uint32_t max_edges_per_node = k_default_max_edges_per_node;
    std::uint32_t max_total_edges = k_default_max_total_edges;
    std::uint32_t max_recursion_depth = k_default_max_recursion_depth;
    bool preserve_unknowns = true;
    bool strict_conflict_reporting = true;
};

struct type_graph_builder_stats_t {
    std::uint32_t total_candidates = 0;
    std::uint32_t unique_types = 0;
    std::uint32_t total_edges = 0;
    std::uint32_t conflicts = 0;
    std::uint32_t unknowns_preserved = 0;
    std::uint32_t nodes_bounded = 0;
    std::uint32_t edges_bounded = 0;
    std::uint32_t unresolved_references = 0;
    std::uint32_t recursive_types = 0;
};

class type_graph_builder_t {
public:
    type_graph_builder_t(decompiler_entity_key_t entity, type_graph_builder_config_t config = {});

    type_graph_builder_t(const type_graph_builder_t&) = delete;
    type_graph_builder_t& operator=(const type_graph_builder_t&) = delete;
    type_graph_builder_t(type_graph_builder_t&&) = default;
    type_graph_builder_t& operator=(type_graph_builder_t&&) = default;

    void add_seed_batch(type_seed_batch_t batch);

    type_graph_t build();

    const std::vector<type_conflict_record_t>& conflicts() const noexcept { return conflicts_; }
    const std::vector<provenance_conflict_t>& edge_conflicts() const noexcept { return edge_conflicts_; }
    const type_graph_builder_stats_t& stats() const noexcept { return stats_; }
    const provenance_journal_t& provenance() const noexcept { return provenance_; }

private:
    struct merged_node_t {
        std::string canonical_name;
        decompiler_type_kind_t kind = decompiler_type_kind_t::unknown;
        std::string display_name;
        std::optional<std::uint64_t> byte_size;
        std::uint32_t alignment = 0;
        bool is_signed = false;
        std::uint8_t confidence = 0;
        decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
        std::vector<type_provenance_record_t> provenance_records;
        std::vector<source_coordinate_t> coordinates;
        std::vector<type_edge_candidate_t> edges;
        std::uint64_t assigned_id = 0;
        bool is_unknown_placeholder = false;
        bool is_recursive = false;
    };

    struct merged_edge_t {
        std::uint64_t source_id = 0;
        std::uint64_t target_id = 0;
        decompiler_type_edge_kind_t kind = decompiler_type_edge_kind_t::member;
        std::string stable_name;
        std::optional<std::uint64_t> byte_offset;
        std::uint8_t confidence = 0;
        decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
    };

    decompiler_entity_key_t entity_;
    type_graph_builder_config_t config_;
    std::vector<type_seed_batch_t> batches_;
    std::vector<type_conflict_record_t> conflicts_;
    std::vector<provenance_conflict_t> edge_conflicts_;
    type_graph_builder_stats_t stats_;
    provenance_journal_t provenance_;

    source_coordinate_t make_coordinate(std::uint64_t address_value) const;

    void merge_candidates(const std::vector<type_candidate_t>& candidates, merged_node_t& merged);
    void merge_field_conflict(const std::string& canonical_name, const std::string& field_name,
                              const std::string& resolved, const std::string& rejected,
                              const type_provenance_record_t& resolved_prov,
                              const type_provenance_record_t& rejected_prov);
    void merge_edges(merged_node_t& merged, const type_candidate_t& candidate);
    void detect_recursive_types(std::unordered_map<std::string, merged_node_t>& merged_nodes);
    void assign_stable_ids(std::unordered_map<std::string, merged_node_t>& merged_nodes,
                           std::vector<std::string>& sorted_names) const;
    void resolve_edges(const std::unordered_map<std::string, merged_node_t>& merged_nodes,
                       std::vector<merged_edge_t>& resolved_edges,
                       std::vector<decompiler_unknown_t>& unknowns);
    void enforce_bounds(std::vector<merged_node_t>& nodes,
                        std::vector<merged_edge_t>& edges,
                        std::vector<decompiler_unknown_t>& unknowns);
    void emit_diagnostics(type_graph_t& graph, std::uint32_t& ordinal_counter);
    decompiler_unknown_t make_unknown(const std::string& token,
                                      decompiler_unknown_reason_t reason,
                                      std::uint8_t confidence,
                                      decompiler_fact_provenance_t provenance) const;
    decompiler_diagnostic_t make_diagnostic(decompiler_diagnostic_severity_t severity,
                                            decompiler_diagnostic_code_t code,
                                            const std::string& key,
                                            std::uint32_t ordinal,
                                            std::uint8_t confidence) const;
};

workspace_result_t<type_graph_t> merge_type_evidence(
    type_graph_t provider_graph,
    std::vector<type_seed_batch_t> evidence,
    const type_graph_builder_config_t& config = {});

workspace_result_t<type_graph_t> merge_type_evidence(
    type_graph_t provider_graph,
    std::vector<type_seed_batch_t> evidence,
    const hir_function_t& live_hir,
    const type_graph_builder_config_t& config = {});

}
