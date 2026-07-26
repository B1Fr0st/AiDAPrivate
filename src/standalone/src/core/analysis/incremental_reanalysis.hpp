#pragma once

#include "overlay_projection.hpp"
#include "workspace/pe_baseline_analyzer.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace analysis {

class analysis_workspace_t;
struct analysis_snapshot_t;
class byte_provider_t;
class analysis_metrics_t;
class cancellation_token_t;

enum class reanalysis_stage_t : std::uint8_t {
    none = 0,
    disassembly = 1,
    basic_blocks = 2,
    functions = 3,
    decompilation = 4,
    xrefs = 5,
    strings = 6,
    types = 7,
    symbols = 8,
    coverage = 9
};

struct reanalysis_scope_t final {
    std::vector<projected_range_t> ranges;
    std::vector<overlay_entity_key_v9_t> entities;
    projection_stage_flag_t stage_flags = projection_stage_flag_t::none;
    std::uint64_t generation = 0;
    std::uint64_t total_patched_bytes = 0;
    bool requires_full_reanalysis = false;
    bool generation_conflict = false;

    bool empty() const noexcept
    {
        return ranges.empty() && entities.empty() &&
               stage_flags == projection_stage_flag_t::none && !requires_full_reanalysis &&
               !generation_conflict;
    }

    bool valid() const noexcept { return !generation_conflict; }
};

struct reanalysis_result_t final {
    bool ok = false;
    reanalysis_scope_t scope;
    projection_invalidation_set_t invalidation;
    std::uint64_t new_generation = 0;
    std::string detail;

    explicit operator bool() const noexcept { return ok; }
};

struct undo_redo_identity_t final {
    overlay_entity_key_v9_t entity;
    bool forward_valid = false;
    bool inverse_valid = false;
    bool keys_match = false;
    bool payloads_are_inverse = false;
    bool provenance_is_inverse = false;

    bool identity_preserved() const noexcept
    {
        return forward_valid && inverse_valid && keys_match &&
               payloads_are_inverse && provenance_is_inverse;
    }
};

class incremental_reanalysis_t final {
public:
    static reanalysis_result_t compute_scope(
        const std::vector<overlay_change_v9_t>& changes,
        const overlay_static_state_v9_t& state,
        std::uint64_t current_generation);

    static reanalysis_scope_t minimal_invalidation(
        const overlay_change_v9_t& change);

    static bool stage_requires_reanalysis(
        reanalysis_stage_t stage,
        overlay_operation_kind_v9_t operation_kind) noexcept;

    static projection_stage_flag_t stage_flags_for_operation(
        overlay_operation_kind_v9_t kind) noexcept;

    static undo_redo_identity_t validate_undo_redo_identity(
        const overlay_change_v9_t& forward_change,
        const overlay_change_v9_t& inverse_change);

    static std::vector<reanalysis_stage_t> stages_for_flags(
        projection_stage_flag_t flags);

    static bool scope_contains_range(
        const reanalysis_scope_t& scope,
        const projected_range_t& range) noexcept;

    static reanalysis_scope_t merge_scopes(
        const reanalysis_scope_t& lhs,
        const reanalysis_scope_t& rhs);
};

struct incremental_reanalysis_executor_settings_t final {
    baseline_analysis_settings_t baseline_settings;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct incremental_reanalysis_executor_result_t final {
    bool ok = false;
    bool fallback_to_full = false;
    std::shared_ptr<const analysis_snapshot_t> merged_snapshot;
    std::shared_ptr<analysis_metrics_t> metrics;
    std::string detail;

    explicit operator bool() const noexcept { return ok; }
};

class incremental_reanalysis_executor_t final {
public:
    static incremental_reanalysis_executor_result_t execute(
        std::shared_ptr<analysis_workspace_t> workspace,
        const reanalysis_scope_t& scope,
        const projection_invalidation_set_t& invalidation,
        std::shared_ptr<const byte_provider_t> projected_provider,
        incremental_reanalysis_executor_settings_t settings,
        const cancellation_token_t& cancel = {});
};

}
}
