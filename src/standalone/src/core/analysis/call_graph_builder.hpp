#pragma once

#include "workspace/function_recovery.hpp"
#include "workspace/workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

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

struct call_graph_result_t {
    std::vector<call_graph_node_record_t> nodes;
    std::vector<recovered_call_site_t> call_sites;
    std::vector<recovered_call_candidate_t> candidates;
    std::vector<call_graph_edge_record_t> edges;
    std::vector<call_graph_conflict_t> conflicts;
    std::uint64_t indirect_site_count = 0;
    std::uint64_t unresolved_site_count = 0;
    std::uint64_t storage_bytes = 0;
    std::uint64_t shard_merge_ns = 0;
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

    static workspace_result_t<void> publish(
        analysis_snapshot_t& snapshot,
        call_graph_result_t result,
        const cancellation_token_t& cancel = {});
};

}
