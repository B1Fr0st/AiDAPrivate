#pragma once

#include "workspace/function_recovery.hpp"
#include "workspace/workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

enum class indirect_call_candidate_kind_t : std::uint8_t {
    target_fact = 0,
    relocation,
    import_slot,
    jump_table,
    vtable,
    pointer_scan,
    decompiler
};

struct indirect_call_candidate_t {
    entity_id_t instruction_id = 0;
    address_t call_site;
    address_t target;
    std::optional<entity_id_t> target_function_id;
    indirect_call_candidate_kind_t kind =
        indirect_call_candidate_kind_t::pointer_scan;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint64_t stable_source_id = 0;
    bool external_target = false;
};

struct call_graph_builder_limits_t {
    std::uint64_t max_nodes = 1ULL << 24;
    std::uint64_t max_sites = 1ULL << 26;
    std::uint64_t max_edges = 1ULL << 27;
    std::uint64_t max_candidates = 1ULL << 27;
    std::uint64_t max_conflicts = 1ULL << 24;
    std::uint64_t max_result_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t max_candidates_per_site = 4096;
    std::uint32_t cancellation_check_interval = 1024;
};

struct call_graph_quality_t {
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint32_t contributor_count = 0;
    bool conflicted = false;
};

enum class call_graph_resolution_t : std::uint8_t {
    direct = 0,
    tail_call,
    indirect_candidate,
    unresolved
};

enum class call_graph_conflict_kind_t : std::uint8_t {
    candidate_target_disagreement = 0,
    candidate_identity_mismatch,
    candidate_limit,
    unresolved_site,
    orphan_candidate
};

struct call_graph_conflict_t {
    call_graph_conflict_kind_t kind =
        call_graph_conflict_kind_t::candidate_target_disagreement;
    entity_id_t instruction_id = 0;
    entity_id_t source_function_id = 0;
    std::uint64_t call_site_rva = 0;
    std::uint64_t selected_target_rva = 0;
    std::uint64_t competing_target_rva = 0;
    entity_id_t selected_target_function_id = 0;
    entity_id_t competing_target_function_id = 0;
};

struct recovered_call_candidate_t {
    entity_id_t id = 0;
    entity_id_t call_site_id = 0;
    address_t target;
    std::optional<entity_id_t> target_function_id;
    indirect_call_candidate_kind_t kind =
        indirect_call_candidate_kind_t::target_fact;
    call_graph_quality_t quality;
    std::uint64_t stable_source_id = 0;
    std::uint32_t rank = 0;
    bool external_target = false;
};

struct recovered_call_site_t {
    entity_id_t id = 0;
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    entity_id_t instruction_id = 0;
    address_t address;
    std::uint32_t first_candidate = 0;
    std::uint32_t candidate_count = 0;
    bool indirect = false;
    bool tail_call = false;
    bool unresolved = false;
};

struct call_graph_edge_record_t {
    entity_id_t id = 0;
    entity_id_t call_site_id = 0;
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    std::optional<entity_id_t> target_function_id;
    address_t call_site;
    address_t target;
    call_graph_resolution_t resolution = call_graph_resolution_t::unresolved;
    call_graph_quality_t quality;
    std::uint32_t candidate_rank = 0;
    bool external_target = false;
    bool target_noreturn = false;
};

struct call_graph_node_record_t {
    entity_id_t function_id = 0;
    address_t address;
    std::uint64_t incoming_edges = 0;
    std::uint64_t outgoing_edges = 0;
    std::uint64_t indirect_edges = 0;
    std::uint64_t unresolved_sites = 0;
};

struct call_graph_result_t {
    std::vector<call_graph_node_record_t> nodes;
    std::vector<recovered_call_site_t> call_sites;
    std::vector<recovered_call_candidate_t> candidates;
    std::vector<call_graph_edge_record_t> edges;
    std::vector<call_graph_conflict_t> conflicts;
    std::uint64_t indirect_site_count = 0;
    std::uint64_t unresolved_site_count = 0;
    std::uint64_t storage_bytes = 0;
    bool bounded = false;
};

class call_graph_builder_t final {
public:
    static workspace_result_t<call_graph_result_t> build(
        const std::vector<instruction_record_t>& instructions,
        const std::vector<target_fact_t>& targets,
        const function_recovery_result_t& recovery,
        const std::vector<indirect_call_candidate_t>& indirect_candidates,
        const call_graph_builder_limits_t& limits,
        const cancellation_token_t& cancel);
};

}
