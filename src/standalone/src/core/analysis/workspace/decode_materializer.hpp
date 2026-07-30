#pragma once

#include "workspace_types.hpp"

#include <cstdint>

namespace aida::analysis {

struct analysis_snapshot_t;
struct tile_decode_orchestration_result_t;

namespace decode_materializer {

inline constexpr std::uint64_t kLowMemoryR0Bytes = 6ULL * 1024ULL * 1024ULL * 1024ULL;

workspace_result_t<void> materialize(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint64_t remaining_budget_bytes, const cancellation_token_t& cancel);

}

}
