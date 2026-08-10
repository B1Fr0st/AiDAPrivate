#pragma once

#include "workspace_types.hpp"

#include "../tile_decode_orchestrator.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace aida::analysis {

struct analysis_snapshot_t;
struct tile_decode_orchestration_result_t;
class packed_analysis_shard_t;

namespace decode_materializer {

struct materialize_plan_t;

workspace_result_t<std::shared_ptr<materialize_plan_t>> materialize_begin(
    const std::vector<decode_accepted_tile_counts_t>& tile_counts,
    analysis_snapshot_t& snapshot, std::uint64_t remaining_budget_bytes);

workspace_result_t<void> materialize_tile(
    materialize_plan_t& plan, std::size_t tile_ordinal,
    packed_analysis_shard_t& tile, analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel);

workspace_result_t<void> materialize_finish(
    materialize_plan_t& plan, tile_decode_orchestration_result_t& decoded,
    analysis_snapshot_t& snapshot, std::uint32_t workers,
    const cancellation_token_t& cancel);

}

}
