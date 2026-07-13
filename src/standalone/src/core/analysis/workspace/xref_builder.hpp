#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "data_discovery.hpp"
#include "string_discovery.hpp"
#include "symbol_type_candidates.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <vector>

namespace aida::analysis {

struct xref_build_limits_t {
    std::uint64_t max_xrefs = 1ULL << 28;
    std::uint64_t max_type_xrefs = 1ULL << 26;
    std::uint64_t max_data_candidates = 1ULL << 27;
    std::uint64_t max_pointer_facts = 1ULL << 27;
    std::uint64_t max_data_conflicts = 1ULL << 20;
    std::uint64_t max_pointer_scan_bytes = 1ULL << 34;
    std::uint64_t max_result_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint32_t cancellation_check_interval = 4096;
};

struct xref_build_result_t {
    std::vector<xref_record_t> xrefs;
    std::vector<type_reference_fact_t> type_xrefs;
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<data_pointer_fact_t> data_pointer_facts;
    std::vector<data_candidate_conflict_t> data_conflicts;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t invalid_pointer_values = 0;
    std::uint64_t duplicate_xrefs = 0;
    std::uint64_t duplicate_type_xrefs = 0;
};

class xref_builder_t final {
public:
    static workspace_result_t<xref_build_result_t> build(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<operand_fact_t>& operands,
        const std::vector<target_fact_t>& targets,
        const xref_build_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<xref_build_result_t> build(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<operand_fact_t>& operands,
        const std::vector<target_fact_t>& targets,
        const std::vector<data_pointer_seed_t>& pointer_seeds,
        const std::vector<type_reference_fact_t>& type_references,
        const xref_build_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<xref_build_result_t> build(
        const workspace_image_t& image,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<operand_fact_t>& operands,
        const std::vector<target_fact_t>& targets,
        data_discovery_result_t data,
        std::vector<type_reference_fact_t> type_references,
        const xref_build_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<void> publish(
        analysis_snapshot_t& snapshot,
        xref_build_result_t xrefs,
        string_discovery_result_t strings,
        symbol_type_candidate_result_t symbols,
        const cancellation_token_t& cancel = {});
};

}
