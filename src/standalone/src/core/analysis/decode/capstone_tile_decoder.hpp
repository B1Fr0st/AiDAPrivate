#pragma once

#include "../provider_snapshot.hpp"
#include "../workspace/arch_decoder.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace aida::analysis::decode {

struct capstone_tile_decode_limits_t final {
    static constexpr std::uint64_t hard_maximum_tile_bytes = 1024ULL * 1024ULL;
    static constexpr std::uint64_t hard_maximum_instruction_records = 131'072;
    static constexpr std::uint64_t hard_maximum_operand_facts =
        hard_maximum_instruction_records * arch_decode_result_t::operand_capacity;
    static constexpr std::uint64_t hard_maximum_target_facts =
        hard_maximum_instruction_records * arch_decode_result_t::target_capacity;

    std::uint64_t maximum_tile_bytes = 16ULL * 1024ULL;
    std::uint64_t maximum_instruction_records = 8192;
    std::uint64_t maximum_operand_facts =
        maximum_instruction_records * arch_decode_result_t::operand_capacity;
    std::uint64_t maximum_target_facts =
        maximum_instruction_records * arch_decode_result_t::target_capacity;
    std::uint64_t maximum_coverage_spans = maximum_instruction_records;
    std::uint64_t maximum_consecutive_undecodable_bytes = 4096;
};

workspace_result_t<void> validate_capstone_tile_decode_limits(
    const capstone_tile_decode_limits_t& limits);

struct capstone_tile_identity_t final {
    arch_decoder_key_t decoder_key;
    address_t start;
    std::uint64_t provider_offset = 0;
    std::uint64_t runtime_address = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t byte_count = 0;
    std::uint64_t snapshot_generation = 0;
    std::uint64_t stable_source_id = 0;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 100;
};

std::uint64_t capstone_tile_identity_hash(const capstone_tile_identity_t& identity) noexcept;

struct capstone_tile_decode_usage_t final {
    std::uint64_t input_bytes = 0;
    std::uint64_t bytes_consumed = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t undecodable_bytes = 0;
    std::uint64_t decode_attempts = 0;
    std::uint64_t instructions = 0;
    std::uint64_t operand_facts = 0;
    std::uint64_t target_facts = 0;
    std::uint64_t coverage_spans = 0;
    std::uint64_t snapshot_window_leases = 0;
    std::uint64_t snapshot_window_bytes = 0;
};

struct capstone_tile_result_t final {
    capstone_tile_identity_t identity;
    capstone_tile_decode_usage_t usage;
    std::vector<instruction_record_t> instructions;
    std::vector<operand_fact_t> operand_facts;
    std::vector<target_fact_t> target_facts;
    std::vector<std::uint8_t> delay_slot_counts;
    std::vector<coverage_span_t> coverage;
};

struct capstone_tile_decoder_options_t final {
    arch_decode_budget_t worker_budget;
    capstone_tile_decode_limits_t tile_limits;
};

class worker_owned_capstone_tile_decoder_t final {
public:
    ~worker_owned_capstone_tile_decoder_t();
    worker_owned_capstone_tile_decoder_t(const worker_owned_capstone_tile_decoder_t&) = delete;
    worker_owned_capstone_tile_decoder_t& operator=(const worker_owned_capstone_tile_decoder_t&) = delete;
    worker_owned_capstone_tile_decoder_t(worker_owned_capstone_tile_decoder_t&&) = delete;
    worker_owned_capstone_tile_decoder_t& operator=(worker_owned_capstone_tile_decoder_t&&) = delete;

    static workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>> create(
        const arch_decoder_key_t& key,
        capstone_tile_decoder_options_t options = {},
        const cancellation_token_t& cancellation = {});
    static workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>> create(
        arch_decoder_registry_t& registry,
        const arch_decoder_key_t& key,
        capstone_tile_decoder_options_t options = {},
        const cancellation_token_t& cancellation = {});

    const arch_decoder_key_t& key() const noexcept;
    const arch_decoder_registration_t& registration() const noexcept;
    const arch_decode_usage_t& worker_usage() const noexcept;
    const capstone_tile_decode_limits_t& tile_limits() const noexcept;

    workspace_result_t<capstone_tile_result_t> decode_tile(
        const provider_snapshot_t& snapshot,
        const capstone_tile_identity_t& identity,
        const cancellation_token_t& cancellation = {});

private:
    worker_owned_capstone_tile_decoder_t(
        std::unique_ptr<worker_owned_arch_decoder_t> worker,
        capstone_tile_decode_limits_t tile_limits) noexcept;

    std::unique_ptr<worker_owned_arch_decoder_t> worker_;
    capstone_tile_decode_limits_t tile_limits_;
};

}
