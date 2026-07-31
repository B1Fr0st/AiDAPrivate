#pragma once

#include "workspace_types.hpp"

#include <cstdint>

namespace aida::analysis {

struct analysis_snapshot_t;
struct tile_decode_orchestration_result_t;

namespace decode_materializer {

workspace_result_t<void> materialize(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint64_t remaining_budget_bytes, std::uint32_t workers,
    const cancellation_token_t& cancel);

}

}
