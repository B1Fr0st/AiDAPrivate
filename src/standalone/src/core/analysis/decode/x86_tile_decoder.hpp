#pragma once

#include "../provider_snapshot.hpp"
#include "../workspace/compact_ir.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace aida::analysis::decode {

struct x86_tile_decode_limits_t final {
    static constexpr std::uint64_t hard_maximum_window_bytes = 1024ULL * 1024ULL;
    static constexpr std::uint64_t hard_maximum_decode_attempts = hard_maximum_window_bytes;
    static constexpr std::uint64_t hard_maximum_instructions = 65536;
    static constexpr std::uint64_t hard_maximum_operand_facts =
        hard_maximum_instructions * 10ULL;
    static constexpr std::uint64_t hard_maximum_target_facts =
        hard_maximum_instructions * 11ULL;
    static constexpr std::uint64_t hard_maximum_invalid_bytes = hard_maximum_window_bytes;
    static constexpr std::uint64_t hard_maximum_coverage_spans = 65536;

    std::uint64_t maximum_window_bytes = 64ULL * 1024ULL;
    std::uint64_t maximum_decode_attempts = 64ULL * 1024ULL;
    std::uint64_t maximum_instructions = 8192;
    std::uint64_t maximum_operand_facts = 81920;
    std::uint64_t maximum_target_facts = 90112;
    std::uint64_t maximum_invalid_bytes = 64ULL * 1024ULL;
    std::uint64_t maximum_coverage_spans = 8192;
};

struct x86_tile_decode_request_t final {
    address_t start_address;
    std::uint64_t provider_offset = 0;
    std::uint64_t byte_count = 0;
    std::uint64_t runtime_address = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 100;
    std::uint64_t stable_source_id = 0;
    x86_tile_decode_limits_t limits;
};

struct x86_tile_decode_usage_t final {
    std::uint64_t input_bytes = 0;
    std::uint64_t bytes_consumed = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t decode_attempts = 0;
    std::uint64_t instructions = 0;
    std::uint64_t operand_facts = 0;
    std::uint64_t target_facts = 0;
    std::uint64_t invalid_bytes = 0;
    std::uint64_t coverage_spans = 0;
    std::uint64_t snapshot_window_leases = 0;
    std::uint64_t snapshot_window_bytes = 0;
    std::uint64_t source_validations = 0;
};

struct x86_tile_decode_result_t final {
    architecture_mode_t mode = architecture_mode_t::unknown;
    address_t start_address;
    std::uint64_t provider_offset = 0;
    std::uint64_t byte_count = 0;
    x86_tile_decode_usage_t usage;
    std::vector<instruction_record_t> instructions;
    std::vector<operand_fact_t> operand_facts;
    std::vector<target_fact_t> target_facts;
    std::vector<coverage_span_t> coverage;
};

class worker_owned_x86_tile_decoder_t final {
public:
    static workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>
        create(architecture_mode_t mode);

    ~worker_owned_x86_tile_decoder_t();
    worker_owned_x86_tile_decoder_t(const worker_owned_x86_tile_decoder_t&) = delete;
    worker_owned_x86_tile_decoder_t& operator=(const worker_owned_x86_tile_decoder_t&) = delete;
    worker_owned_x86_tile_decoder_t(worker_owned_x86_tile_decoder_t&&) = delete;
    worker_owned_x86_tile_decoder_t& operator=(worker_owned_x86_tile_decoder_t&&) = delete;

    architecture_mode_t mode() const noexcept;
    workspace_result_t<x86_tile_decode_result_t>
        decode_tile(const provider_snapshot_t& snapshot,
                    const x86_tile_decode_request_t& request,
                    const cancellation_token_t& cancel = {});

private:
    struct impl_t;

    explicit worker_owned_x86_tile_decoder_t(std::unique_ptr<impl_t> impl);

    std::unique_ptr<impl_t> impl_;
    std::atomic_flag active_ = ATOMIC_FLAG_INIT;
};

}
