#include "decode_materializer.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"
#include "snapshot_tables.hpp"

#include "../packed_analysis_store.hpp"
#include "../tile_decode_orchestrator.hpp"
#include "../working_set_governor.hpp"

#include "compact_ir.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kCancellationStride = 256;

workspace_error_t materialize_cancellation_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", "decode_merge");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", "decode_merge");
    error.cancellation = true;
    return error;
}

workspace_error_t materialize_integrity_error(std::string message) {
    return make_workspace_error(workspace_error_code_t::integrity_failure,
        std::move(message), "decode_merge");
}

workspace_error_t materialize_limit_error(const char* message) {
    return make_workspace_error(workspace_error_code_t::limit_exceeded,
        message, "decode_merge");
}

workspace_result_t<std::uint32_t> resolve_instruction_owner(
    std::uint64_t packed_id, std::uint16_t shard_id, std::uint64_t instruction_count,
    const char* row_kind) {
    const auto domain = packed_id >> 48U;
    const auto shard = static_cast<std::uint16_t>((packed_id >> 32U) & 0xffffULL);
    const auto ordinal = packed_id & 0xffffffffULL;
    if (packed_id == 0 ||
        domain != static_cast<std::uint64_t>(packed_entity_domain_t::instruction) ||
        ordinal == 0 || ordinal > instruction_count) {
        std::string message = "tile decode ";
        message += row_kind;
        message += " references an unknown instruction";
        return workspace_result_t<std::uint32_t>::failure(
            materialize_integrity_error(std::move(message)));
    }
    if (shard != shard_id) {
        std::string message = "tile decode ";
        message += row_kind;
        message += " references an instruction outside its shard";
        return workspace_result_t<std::uint32_t>::failure(
            materialize_integrity_error(std::move(message)));
    }
    return workspace_result_t<std::uint32_t>::success(
        static_cast<std::uint32_t>(ordinal - 1ULL));
}

struct shard_base_ordinals_t {
    std::vector<std::uint64_t> instruction_bases;
    std::vector<std::uint64_t> operand_bases;
    std::vector<std::uint64_t> target_bases;
    std::uint64_t instruction_total = 0;
    std::uint64_t operand_total = 0;
    std::uint64_t target_total = 0;
};

workspace_result_t<shard_base_ordinals_t> compute_shard_bases(
    const std::vector<packed_analysis_shard_t>& shards) {
    shard_base_ordinals_t bases;
    bases.instruction_bases.reserve(shards.size());
    bases.operand_bases.reserve(shards.size());
    bases.target_bases.reserve(shards.size());
    for (const auto& shard : shards) {
        bases.instruction_bases.push_back(bases.instruction_total);
        bases.operand_bases.push_back(bases.operand_total);
        bases.target_bases.push_back(bases.target_total);
        if (!checked_add_u64(bases.instruction_total,
                static_cast<std::uint64_t>(shard.instruction_count()),
                bases.instruction_total) ||
            !checked_add_u64(bases.operand_total,
                static_cast<std::uint64_t>(shard.operand_count()),
                bases.operand_total) ||
            !checked_add_u64(bases.target_total,
                static_cast<std::uint64_t>(shard.target_fact_count()),
                bases.target_total)) {
            return workspace_result_t<shard_base_ordinals_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "tile decode merge accounting overflows", "decode_merge"));
        }
    }
    return workspace_result_t<shard_base_ordinals_t>::success(std::move(bases));
}

workspace_result_t<void> materialize_shard_rows(
    packed_analysis_shard_t& shard, analysis_snapshot_t& snapshot,
    std::uint64_t instruction_base, std::uint64_t operand_base,
    std::uint64_t target_base, const cancellation_token_t& cancel) {
    auto validated = shard.validate();
    if (!validated) {
        auto error = materialize_integrity_error(
            "tile decode packed shard validation failed");
        error.details.emplace_back("shard", std::to_string(shard.shard_id()));
        error.details.emplace_back("packed_code",
            std::to_string(static_cast<unsigned>(validated.error().code)));
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto view = shard.compatibility_view();
    const auto shard_id = shard.shard_id();
    const auto instruction_count =
        static_cast<std::uint64_t>(shard.instruction_count());
    const auto operand_count = static_cast<std::uint64_t>(shard.operand_count());
    const auto target_count = static_cast<std::uint64_t>(shard.target_fact_count());
    std::uint64_t operand_cursor = 0;
    std::uint64_t target_cursor = 0;
    std::uint64_t polls = 0;
    for (std::uint64_t index = 0; index < instruction_count; ++index) {
        if (++polls >= kCancellationStride) {
            polls = 0;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
        }
        auto instruction = view.instruction(static_cast<std::size_t>(index));
        if (!instruction) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode instruction compatibility row is missing"));
        }
        instruction->id = kInstructionEntityTag | (instruction_base + index + 1ULL);
        const auto operand_first = operand_cursor;
        while (operand_cursor < operand_count) {
            if (++polls >= kCancellationStride) {
                polls = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
            }
            auto operand = view.operand(static_cast<std::size_t>(operand_cursor));
            if (!operand) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode operand compatibility row is missing"));
            }
            auto owner = resolve_instruction_owner(operand->instruction_id,
                shard_id, instruction_count, "operand");
            if (!owner)
                return workspace_result_t<void>::failure(owner.error());
            if (owner.value() > index)
                break;
            if (owner.value() < index) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode operand rows are not grouped by instruction"));
            }
            operand->instruction_id = kInstructionEntityTag |
                (instruction_base + static_cast<std::uint64_t>(owner.value()) + 1ULL);
            snapshot.operand_facts[static_cast<std::size_t>(operand_base + operand_cursor)] =
                std::move(*operand);
            ++operand_cursor;
        }
        const auto operand_group = operand_cursor - operand_first;
        if (operand_group > (std::numeric_limits<std::uint16_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode operand count exceeds Compact IR capacity"));
        }
        if (operand_base + operand_first >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode operand table exceeds Compact IR capacity"));
        }
        instruction->operand_fact_begin =
            static_cast<std::uint32_t>(operand_base + operand_first);
        instruction->operand_fact_count = static_cast<std::uint16_t>(operand_group);
        const auto target_first = target_cursor;
        while (target_cursor < target_count) {
            if (++polls >= kCancellationStride) {
                polls = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
            }
            auto target = view.target_fact(static_cast<std::size_t>(target_cursor));
            if (!target) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode target compatibility row is missing"));
            }
            auto owner = resolve_instruction_owner(target->instruction_id,
                shard_id, instruction_count, "target");
            if (!owner)
                return workspace_result_t<void>::failure(owner.error());
            if (owner.value() > index)
                break;
            if (owner.value() < index) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode target rows are not grouped by instruction"));
            }
            target->instruction_id = kInstructionEntityTag |
                (instruction_base + static_cast<std::uint64_t>(owner.value()) + 1ULL);
            snapshot.target_facts[static_cast<std::size_t>(target_base + target_cursor)] =
                std::move(*target);
            ++target_cursor;
        }
        const auto target_group = target_cursor - target_first;
        if (target_group > (std::numeric_limits<std::uint16_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode target count exceeds Compact IR capacity"));
        }
        if (target_base + target_first >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode target table exceeds Compact IR capacity"));
        }
        instruction->target_fact_begin =
            static_cast<std::uint32_t>(target_base + target_first);
        instruction->target_fact_count = static_cast<std::uint16_t>(target_group);
        snapshot.instructions[static_cast<std::size_t>(instruction_base + index)] =
            std::move(*instruction);
    }
    if (operand_cursor != operand_count) {
        return workspace_result_t<void>::failure(materialize_integrity_error(
            "tile decode operand rows are not grouped by instruction"));
    }
    if (target_cursor != target_count) {
        return workspace_result_t<void>::failure(materialize_integrity_error(
            "tile decode target rows are not grouped by instruction"));
    }
    shard.release();
    return workspace_result_t<void>::success();
}

}

namespace decode_materializer {

workspace_result_t<void> materialize(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint64_t remaining_budget_bytes, std::uint32_t workers,
    const cancellation_token_t& cancel) {
    auto bases = compute_shard_bases(decoded.packed_shards);
    if (!bases)
        return workspace_result_t<void>::failure(bases.error());
    auto ordinals = bases.take_value();
    std::uint64_t required_bytes = 0;
    std::uint64_t term = 0;
    if (!checked_mul_u64(ordinals.instruction_total,
            static_cast<std::uint64_t>(sizeof(instruction_record_t)), term) ||
        !checked_add_u64(required_bytes, term, required_bytes) ||
        !checked_mul_u64(ordinals.operand_total,
            static_cast<std::uint64_t>(sizeof(operand_fact_t)), term) ||
        !checked_add_u64(required_bytes, term, required_bytes) ||
        !checked_mul_u64(ordinals.target_total,
            static_cast<std::uint64_t>(sizeof(target_fact_t)), term) ||
        !checked_add_u64(required_bytes, term, required_bytes) ||
        !checked_add_u64(required_bytes,
            static_cast<std::uint64_t>(decoded.delay_slot_counts.size()),
            required_bytes)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (required_bytes > remaining_budget_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decoded snapshot exceeds analysis memory budget", "decode_merge"));
    }
    if (!working_set_governor_t::instance().check(
            working_set_metrics::subsystem_t::resident_facts, required_bytes)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decoded snapshot exceeds the working-set governor resident-facts budget",
            "decode_merge"));
    }
    snapshot.instructions.clear();
    snapshot.operand_facts.clear();
    snapshot.target_facts.clear();
    reserve_exact(snapshot.instructions,
        static_cast<std::size_t>(ordinals.instruction_total));
    reserve_exact(snapshot.operand_facts,
        static_cast<std::size_t>(ordinals.operand_total));
    reserve_exact(snapshot.target_facts,
        static_cast<std::size_t>(ordinals.target_total));
    resize_uninitialized(snapshot.instructions,
        static_cast<std::size_t>(ordinals.instruction_total));
    resize_uninitialized(snapshot.operand_facts,
        static_cast<std::size_t>(ordinals.operand_total));
    resize_uninitialized(snapshot.target_facts,
        static_cast<std::size_t>(ordinals.target_total));
    const auto shard_ranges =
        parallel_shards(decoded.packed_shards.size(), workers);
    auto materialized = parallel_run_shards(shard_ranges,
        [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
            for (std::size_t shard_index = range.begin; shard_index < range.end;
                 ++shard_index) {
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
                auto consumed = materialize_shard_rows(
                    decoded.packed_shards[shard_index], snapshot,
                    ordinals.instruction_bases[shard_index],
                    ordinals.operand_bases[shard_index],
                    ordinals.target_bases[shard_index], cancel);
                if (!consumed)
                    return consumed;
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!materialized)
        return materialized;
    if (decoded.delay_slot_counts.size() != snapshot.instructions.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode delay-slot metadata is not instruction-aligned", "decode_merge"));
    }
    snapshot.delay_slot_counts = std::move(decoded.delay_slot_counts);
    decoded.packed_shards.clear();
    return workspace_result_t<void>::success();
}

}

}
