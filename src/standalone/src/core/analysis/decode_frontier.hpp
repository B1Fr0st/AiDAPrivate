#pragma once

#include "workspace/compact_ir.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace aida::analysis {

using decode_tile_id_t = std::uint32_t;

enum class decode_frontier_seed_kind_t : std::uint8_t {
    fallthrough = 0,
    branch_target = 1,
    call_target = 2,
    range_entry = 3,
    explicit_entry = 4
};

struct decode_frontier_tile_t final {
    decode_tile_id_t id = 0;
    std::uint64_t start_rva = 0;
    std::uint64_t byte_count = 0;
};

struct decode_frontier_seed_t final {
    decode_tile_id_t tile_id = 0;
    std::uint64_t rva = 0;
    decode_frontier_seed_kind_t kind = decode_frontier_seed_kind_t::fallthrough;
    fact_provenance_t provenance = fact_provenance_t::recursive_decode;
    std::uint8_t confidence = 0;
    std::uint64_t stable_source_id = 0;
    std::optional<std::uint64_t> source_rva;
};

enum class decode_frontier_add_disposition_t : std::uint8_t {
    queued = 0,
    strengthened = 1,
    duplicate = 2,
    already_claimed = 3,
    outside_executable = 4
};

struct decode_frontier_add_result_t final {
    decode_frontier_add_disposition_t disposition =
        decode_frontier_add_disposition_t::outside_executable;
    std::optional<decode_tile_id_t> tile_id;
    bool cross_tile = false;
};

struct decode_frontier_snapshot_t final {
    std::uint64_t unique_seed_count = 0;
    std::uint64_t pending_seed_count = 0;
    std::uint64_t claimed_seed_count = 0;
    std::uint64_t duplicate_seed_count = 0;
    std::uint64_t strengthened_seed_count = 0;
    std::uint64_t outside_seed_count = 0;
    std::uint64_t cross_tile_route_count = 0;
};

std::uint8_t decode_frontier_seed_priority(decode_frontier_seed_kind_t kind) noexcept;

struct decode_frontier_claim_t final {
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint64_t stable_source_id = 0;
};

class decode_frontier_t final {
public:
    static workspace_result_t<decode_frontier_t> build(
        std::vector<decode_frontier_tile_t> tiles,
        std::uint64_t maximum_unique_seeds);
    static workspace_result_t<decode_frontier_t> build(
        std::vector<decode_frontier_tile_t> tiles,
        std::uint64_t maximum_unique_seeds,
        std::atomic<std::uint64_t>* shared_unique_seed_count);

    decode_frontier_t();
    decode_frontier_t(decode_frontier_t&&) noexcept;
    decode_frontier_t& operator=(decode_frontier_t&&) noexcept;
    ~decode_frontier_t();

    decode_frontier_t(const decode_frontier_t&) = delete;
    decode_frontier_t& operator=(const decode_frontier_t&) = delete;

    workspace_result_t<decode_frontier_add_result_t> add_seed(
        decode_frontier_seed_t seed,
        std::optional<decode_tile_id_t> source_tile = std::nullopt);
    workspace_result_t<std::vector<decode_frontier_seed_t>> take_wave(
        std::uint64_t maximum_items);
    workspace_result_t<void> mark_claimed(decode_tile_id_t tile_id,
                                           std::uint64_t rva);
    workspace_result_t<void> mark_claimed(decode_tile_id_t tile_id,
                                           std::uint64_t rva,
                                           const decode_frontier_claim_t& claim);

    std::optional<decode_tile_id_t> locate_tile(std::uint64_t rva) const noexcept;
    bool empty() const noexcept;
    decode_frontier_snapshot_t snapshot() const noexcept;
    const std::vector<decode_frontier_tile_t>& tiles() const noexcept;

private:
    struct impl_t;
    explicit decode_frontier_t(std::unique_ptr<impl_t> impl) noexcept;

    std::unique_ptr<impl_t> impl_;
};

}
