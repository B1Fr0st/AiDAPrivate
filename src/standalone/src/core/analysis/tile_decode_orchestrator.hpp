#pragma once

#include "analysis_budget.hpp"
#include "decode/capstone_tile_decoder.hpp"
#include "decode/x86_tile_decoder.hpp"
#include "decode_frontier.hpp"
#include "image_layout_index.hpp"
#include "packed_analysis_store.hpp"
#include "provider_snapshot.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace aida::analysis {

enum class tile_decode_pass_t : std::uint8_t {
    recursive = 0,
    gap = 1
};

enum class tile_coverage_detail_t : std::uint32_t {
    none = 0,
    undecodable_gap = 1,
    zero_fill = 2
};

struct tile_decode_executor_capabilities_t final {
    arch_decoder_key_t decoder_key;
    std::uint64_t maximum_request_bytes = 0;
    std::uint16_t minimum_instruction_bytes = 0;
    std::uint16_t maximum_instruction_bytes = 0;
    std::uint16_t instruction_alignment = 0;
    std::uint32_t worker_count = 0;
    std::uint32_t maximum_batch_requests = 0;
};

struct tile_decode_request_t final {
    std::uint64_t request_id = 0;
    decode_tile_id_t tile_id = 0;
    tile_decode_pass_t pass = tile_decode_pass_t::recursive;
    decode_frontier_seed_kind_t seed_kind = decode_frontier_seed_kind_t::fallthrough;
    address_t start;
    std::uint64_t provider_offset = 0;
    std::uint64_t runtime_address = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t byte_count = 0;
    std::uint64_t owned_end_rva = 0;
    std::uint64_t stable_source_id = 0;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 0;
};

struct tile_decode_records_t final {
    std::vector<instruction_record_t> instructions;
    std::vector<operand_fact_t> operand_facts;
    std::vector<target_fact_t> target_facts;
    std::vector<std::uint8_t> delay_slot_counts;
    std::vector<coverage_span_t> coverage;
    std::uint64_t bytes_consumed = 0;
    std::uint64_t invalid_bytes = 0;
};

struct tile_decode_completion_t final {
    std::uint64_t request_id = 0;
    tile_decode_records_t records;
    std::optional<workspace_error_t> error;

    bool succeeded() const noexcept { return !error.has_value(); }
};

class tile_decode_executor_t {
public:
    virtual ~tile_decode_executor_t() = default;

    virtual const tile_decode_executor_capabilities_t& capabilities() const noexcept = 0;
    virtual workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation = {}) = 0;
};

struct production_tile_decode_executor_options_t final {
    arch_decoder_key_t decoder_key;
    std::uint32_t worker_count = 0;
    analysis_budget_t analysis_budget;
    decode::x86_tile_decode_limits_t x86_limits;
    decode::capstone_tile_decoder_options_t capstone_options;
};

workspace_result_t<std::unique_ptr<tile_decode_executor_t>>
create_production_tile_decode_executor(
    production_tile_decode_executor_options_t options,
    const cancellation_token_t& cancellation = {});

struct tile_decode_seed_t final {
    address_t address;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 100;
    std::uint64_t stable_source_id = 0;
};

struct tile_invalid_run_policy_t final {
    std::uint64_t maximum_gap_resynchronization_bytes = 4096;
    std::uint64_t maximum_invalid_bytes_per_tile = 64ULL * 1024ULL;
    std::uint64_t maximum_invalid_runs_per_tile = 4096;
};

struct tile_decode_orchestrator_limits_t final {
    std::uint64_t target_tile_bytes = 16ULL * 1024ULL;
    std::uint32_t maximum_tiles = 65535;
    std::uint64_t maximum_frontier_seeds = 4'000'000;
    std::uint64_t maximum_frontier_wave = 4096;
    std::uint64_t maximum_decode_requests = 8'000'000;
    std::uint64_t maximum_instructions = 32'000'000;
    std::uint64_t maximum_operand_facts = 256'000'000;
    std::uint64_t maximum_target_facts = 256'000'000;
    std::uint64_t maximum_edges = 128'000'000;
    std::uint64_t maximum_coverage_spans = 8'000'000;
    bool seed_executable_range_starts = true;
    tile_invalid_run_policy_t invalid_run_policy;
};

struct executable_decode_range_t final {
    std::uint32_t range_id = 0;
    std::uint32_t mapping_id = 0;
    std::uint64_t start_rva = 0;
    std::uint64_t start_virtual_address = 0;
    std::uint64_t provider_offset = 0;
    std::uint64_t byte_count = 0;
};

struct executable_decode_tile_t final {
    decode_tile_id_t tile_id = 0;
    std::uint16_t shard_id = 0;
    std::uint32_t range_id = 0;
    std::uint32_t mapping_id = 0;
    std::uint64_t start_rva = 0;
    std::uint64_t start_virtual_address = 0;
    std::uint64_t provider_offset = 0;
    std::uint64_t byte_count = 0;
    std::uint64_t lookahead_bytes = 0;
};

struct executable_decode_partition_t final {
    std::vector<executable_decode_range_t> ranges;
    std::vector<executable_decode_range_t> zero_fill_ranges;
    std::vector<executable_decode_tile_t> tiles;
    std::uint64_t initialized_executable_bytes = 0;
    std::uint64_t zero_fill_executable_bytes = 0;
};

workspace_result_t<executable_decode_partition_t> partition_executable_decode_ranges(
    const image_layout_index_t& layout,
    const tile_decode_executor_capabilities_t& capabilities,
    const tile_decode_orchestrator_limits_t& limits,
    const cancellation_token_t& cancellation = {});

struct tile_decode_cross_tile_edge_t final {
    decode_tile_id_t source_tile_id = 0;
    decode_tile_id_t target_tile_id = 0;
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
};

struct tile_decode_shard_summary_t final {
    decode_tile_id_t tile_id = 0;
    std::uint16_t shard_id = 0;
    std::uint32_t instruction_count = 0;
    std::uint32_t operand_count = 0;
    std::uint32_t target_count = 0;
    std::uint32_t edge_count = 0;
};

struct tile_decode_orchestrator_statistics_t final {
    std::uint64_t initialized_executable_bytes = 0;
    std::uint64_t zero_fill_executable_bytes = 0;
    std::uint64_t recursive_requests = 0;
    std::uint64_t gap_requests = 0;
    std::uint64_t decoded_instruction_candidates = 0;
    std::uint64_t accepted_instructions = 0;
    std::uint64_t duplicate_instruction_candidates = 0;
    std::uint64_t overlap_instruction_candidates = 0;
    std::uint64_t accepted_operands = 0;
    std::uint64_t accepted_target_facts = 0;
    std::uint64_t accepted_edges = 0;
    std::uint64_t duplicate_edges = 0;
    std::uint64_t cross_tile_edges = 0;
    std::uint64_t invalid_bytes = 0;
    std::uint64_t invalid_runs = 0;
    decode_frontier_snapshot_t frontier;
};

struct tile_decode_orchestration_result_t final {
    std::unique_ptr<packed_analysis_store_t> packed_store;
    std::vector<std::uint8_t> delay_slot_counts;
    std::vector<coverage_span_t> coverage;
    std::vector<tile_decode_cross_tile_edge_t> cross_tile_edges;
    std::vector<tile_decode_shard_summary_t> shards;
    tile_decode_orchestrator_statistics_t statistics;
};

class tile_decode_orchestrator_t final {
public:
    static workspace_result_t<tile_decode_orchestrator_t> create(
        tile_decode_orchestrator_limits_t limits = {});

    workspace_result_t<tile_decode_orchestration_result_t> run(
        const provider_snapshot_t& snapshot,
        const image_layout_index_t& layout,
        std::vector<tile_decode_seed_t> seeds,
        tile_decode_executor_t& executor,
        const cancellation_token_t& cancellation = {}) const;

    const tile_decode_orchestrator_limits_t& limits() const noexcept { return limits_; }

private:
    explicit tile_decode_orchestrator_t(tile_decode_orchestrator_limits_t limits) noexcept;

    tile_decode_orchestrator_limits_t limits_;
};

}
