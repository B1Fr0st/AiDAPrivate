#include "overlay_projection_harness.hpp"

#include "../../src/core/analysis/overlay_projection.hpp"
#include "../../src/core/analysis/incremental_reanalysis.hpp"
#include "../../src/core/analysis/overlay_apply_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {

namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

overlay_target_identity_v9_t target(std::uint64_t generation = 7)
{
    overlay_target_identity_v9_t result;
    result.image_hash.fill(0x31);
    result.provenance_hash.fill(0x62);
    result.image_base = 0x140000000ULL;
    result.image_size = 0x4000;
    result.generation = generation;
    result.kind = overlay_target_kind_v9_t::static_image;
    result.architecture = overlay_architecture_v9_t::x86_64;
    result.address_width = 8;
    return result;
}

overlay_static_range_v9_t range(std::uint64_t offset, std::uint64_t size = 1)
{
    return {offset, size};
}

overlay_operation_v9_t byte_patch_op(std::uint64_t offset, std::vector<std::uint8_t> bytes)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::byte_patch;
    op.range = {offset, bytes.size()};
    op.payload.bytes = std::move(bytes);
    return op;
}

overlay_operation_v9_t comment_op(std::uint64_t offset, std::string text)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::comment;
    op.range = {offset, 1};
    op.payload.text = std::move(text);
    return op;
}

overlay_operation_v9_t name_op(std::uint64_t offset, std::string name)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::name;
    op.range = {offset, 4};
    op.payload.name = std::move(name);
    return op;
}

overlay_operation_v9_t type_app_op(std::uint64_t offset, std::string type_name)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::type_application;
    op.range = {offset, 4};
    op.payload.name = "field_" + std::to_string(offset);
    op.payload.variable = "field_" + std::to_string(offset);
    op.payload.type = std::move(type_name);
    return op;
}

overlay_operation_v9_t define_function_op(std::uint64_t offset, std::uint64_t size,
                                          std::string signature)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::define_function;
    op.range = {offset, size};
    op.payload.signature = std::move(signature);
    return op;
}

overlay_change_v9_t make_change(overlay_operation_kind_v9_t kind, std::uint64_t offset,
                                std::uint64_t size, std::optional<overlay_payload_v9_t> before,
                                std::optional<overlay_payload_v9_t> after)
{
    overlay_change_v9_t change;
    change.entity.domain = kind;
    change.entity.range = {offset, size};
    change.operation_kind = kind;
    change.before = std::move(before);
    change.after = std::move(after);
    return change;
}

overlay_static_state_v9_t make_state(std::uint64_t generation = 7)
{
    overlay_static_state_v9_t state;
    auto identity = target(generation);
    require(overlay_apply_engine_v9_t::initialize(state, identity).ok(),
            "projection fixture state init failed");

    overlay_transaction_v9_t txn;
    txn.target = identity;
    txn.expected_revision = 0;
    txn.operations = {
        byte_patch_op(0x100, {0xAA, 0xBB}),
        byte_patch_op(0x200, {0xCC, 0xDD}),
        comment_op(0x120, "fixture comment"),
        name_op(0x140, "fixture_name"),
        type_app_op(0x160, "std::uint32_t"),
        define_function_op(0x400, 0x20, "std::uint32_t fixture_entry()"),
    };
    auto result = overlay_apply_engine_v9_t::apply(state, txn);
    require(result.ok(), "projection baseline transaction failed");
    require(state.revision == 1, "projection baseline revision must be 1");
    return state;
}

void verify_patch_comment_type_rename_fixtures()
{
    auto state = make_state();
    std::string image_bytes(0x4000, 0x41);

    auto result = overlay_projection_t::project(state, image_bytes, 7);
    require(result.ok(), "project must succeed on valid state");
    require(result.new_generation == 7, "project generation must match current");
    require(result.revision == 1, "project revision must match state");
    require(!result.changes.empty(), "project must produce changes");
    require(result.projected_bytes.size() == image_bytes.size(),
            "projected bytes must match image size");

    require(result.projected_bytes[0x100] == 0xAA && result.projected_bytes[0x101] == 0xBB,
            "byte patch at 0x100 must be applied to projected bytes");
    require(result.projected_bytes[0x200] == 0xCC && result.projected_bytes[0x201] == 0xDD,
            "byte patch at 0x200 must be applied to projected bytes");
    require(result.projected_bytes[0x102] == 0x41,
            "non-patched bytes must remain unchanged in projection");

    require(result.invalidation.has_byte_patches(),
            "invalidation must detect byte patches in projection");
    require(result.invalidation.total_patched_bytes == 4,
            "total patched bytes must equal 4 (2+2)");
    require(result.invalidation.max_contiguous_range >= 2,
            "max contiguous range must be at least 2");
    require(!result.invalidation.affected_ranges.empty(),
            "affected ranges must not be empty");
    require(!result.invalidation.affected_entities.empty(),
            "affected entities must not be empty");

    require(stage_test(result.invalidation.invalidated_stages,
                       projection_stage_flag_t::disassembler),
            "byte patches must invalidate disassembler stage");
    require(stage_test(result.invalidation.invalidated_stages,
                       projection_stage_flag_t::decompiler),
            "byte patches must invalidate decompiler stage");
    require(stage_test(result.invalidation.invalidated_stages,
                       projection_stage_flag_t::symbol_table),
            "name operations must invalidate symbol table stage");
    require(stage_test(result.invalidation.invalidated_stages,
                       projection_stage_flag_t::type_table),
            "type applications must invalidate type table stage");
    require(stage_test(result.invalidation.invalidated_stages,
                       projection_stage_flag_t::function_table),
            "function definitions must invalidate function table stage");

    auto stale = overlay_projection_t::project(state, image_bytes, 99);
    require(stale.code == projection_code_t::stale_generation,
            "stale generation must be rejected by project");

    overlay_static_state_v9_t empty_state;
    auto empty = overlay_projection_t::project(empty_state, image_bytes, 7);
    require(empty.code == projection_code_t::state_not_initialized,
            "uninitialized state must be rejected by project");

    auto short_bytes = overlay_projection_t::project(state, std::string_view("AB"), 7);
    require(short_bytes.code == projection_code_t::range_out_of_bounds,
            "insufficient bytes must be rejected by project");

    auto patched = overlay_projection_t::apply_patches(image_bytes, state);
    require(patched.size() == image_bytes.size(),
            "apply_patches output size must match input");
    require(patched[0x100] == 0xAA && patched[0x101] == 0xBB,
            "apply_patches must apply byte patch at 0x100");
    require(patched[0x200] == 0xCC && patched[0x201] == 0xDD,
            "apply_patches must apply byte patch at 0x200");
    require(patched[0x300] == 0x41,
            "apply_patches must not alter non-patched regions");

    auto identity = target();
    overlay_transaction_v9_t txn;
    txn.target = identity;
    txn.expected_revision = 1;
    txn.operations = {
        byte_patch_op(0x300, {0x99, 0x88}),
        comment_op(0x310, "projected comment"),
        name_op(0x320, "projected_name"),
        type_app_op(0x330, "std::uint64_t"),
    };
    auto txn_result = overlay_projection_t::project_transaction(state, txn, image_bytes, 7);
    require(txn_result.ok(), "non-conflicting project_transaction must succeed");
    require(txn_result.projected_bytes[0x300] == 0x99,
            "project_transaction must apply new byte patches");
    require(!txn_result.changes.empty(),
            "project_transaction must produce changes");
    require(!txn_result.invalidation.empty(),
            "project_transaction must produce invalidation");
    require(stage_test(txn_result.invalidation.invalidated_stages,
                       projection_stage_flag_t::disassembler),
            "project_transaction byte patch must invalidate disassembler");
    require(stage_test(txn_result.invalidation.invalidated_stages,
                       projection_stage_flag_t::symbol_table),
            "project_transaction name must invalidate symbol table");
    require(stage_test(txn_result.invalidation.invalidated_stages,
                       projection_stage_flag_t::type_table),
            "project_transaction type must invalidate type table");

    overlay_transaction_v9_t empty_txn;
    empty_txn.target = identity;
    empty_txn.expected_revision = 1;
    auto empty_txn_result = overlay_projection_t::project_transaction(state, empty_txn, image_bytes, 7);
    require(empty_txn_result.code == projection_code_t::empty_projection,
            "empty transaction must be rejected");

    auto stale_txn_result = overlay_projection_t::project_transaction(state, txn, image_bytes, 99);
    require(stale_txn_result.code == projection_code_t::stale_generation,
            "stale generation must be rejected by project_transaction");

    auto mismatched_target = identity;
    mismatched_target.generation = 8;
    overlay_transaction_v9_t mismatch_txn;
    mismatch_txn.target = mismatched_target;
    mismatch_txn.expected_revision = 1;
    mismatch_txn.operations = {comment_op(0x100, "mismatch")};
    auto mismatch_result = overlay_projection_t::project_transaction(state, mismatch_txn, image_bytes, 7);
    require(mismatch_result.code == projection_code_t::invalid_target,
            "mismatched target must be rejected by project_transaction");
}

void verify_minimal_invalidation()
{
    overlay_payload_v9_t comment_payload;
    comment_payload.text = "test comment";
    auto comment_change = make_change(overlay_operation_kind_v9_t::comment, 0x100, 1,
                                      std::nullopt, comment_payload);
    auto comment_scope = incremental_reanalysis_t::minimal_invalidation(comment_change);
    require(!comment_scope.requires_full_reanalysis,
            "comment must not require full reanalysis");
    require(comment_scope.stage_flags == projection_stage_flag_t::none,
            "comment must not invalidate any stages");
    require(comment_scope.total_patched_bytes == 0,
            "comment must not contribute patched bytes");
    require(comment_scope.entities.size() == 1,
            "comment scope must include exactly one entity");
    require(!comment_scope.ranges.empty(),
            "comment scope must include at least one range");

    overlay_payload_v9_t patch_payload;
    patch_payload.bytes = {0xAA, 0xBB};
    auto patch_change = make_change(overlay_operation_kind_v9_t::byte_patch, 0x200, 2,
                                    std::nullopt, patch_payload);
    auto patch_scope = incremental_reanalysis_t::minimal_invalidation(patch_change);
    require(!patch_scope.requires_full_reanalysis,
            "byte patch must not require full reanalysis");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::disassembler),
            "byte patch must invalidate disassembler");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::decompiler),
            "byte patch must invalidate decompiler");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::string_table),
            "byte patch must invalidate string table");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::xref_table),
            "byte patch must invalidate xref table");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::coverage_table),
            "byte patch must invalidate coverage table");
    require(stage_test(patch_scope.stage_flags, projection_stage_flag_t::basic_block_table),
            "byte patch must invalidate basic block table");
    require(patch_scope.total_patched_bytes == 2,
            "byte patch total patched bytes must be 2");
    require(!patch_scope.ranges.empty(), "byte patch must produce ranges");
    require(patch_scope.ranges[0].is_byte_patch,
            "byte patch range must be flagged as byte patch");
    require(patch_scope.ranges[0].offset == 0x200,
            "byte patch range offset must match");
    require(patch_scope.ranges[0].size == 2,
            "byte patch range size must match payload");

    overlay_payload_v9_t name_payload;
    name_payload.name = "renamed";
    auto name_change = make_change(overlay_operation_kind_v9_t::name, 0x140, 4,
                                   std::nullopt, name_payload);
    auto name_scope = incremental_reanalysis_t::minimal_invalidation(name_change);
    require(stage_test(name_scope.stage_flags, projection_stage_flag_t::symbol_table),
            "name must invalidate symbol table");
    require(!stage_test(name_scope.stage_flags, projection_stage_flag_t::disassembler),
            "name must not invalidate disassembler");
    require(name_scope.total_patched_bytes == 0,
            "name must not contribute patched bytes");

    overlay_payload_v9_t type_payload;
    type_payload.type = "std::uint32_t";
    type_payload.name = "field_160";
    type_payload.variable = "field_160";
    auto type_change = make_change(overlay_operation_kind_v9_t::type_application, 0x160, 4,
                                   std::nullopt, type_payload);
    auto type_scope = incremental_reanalysis_t::minimal_invalidation(type_change);
    require(stage_test(type_scope.stage_flags, projection_stage_flag_t::type_table),
            "type application must invalidate type table");
    require(stage_test(type_scope.stage_flags, projection_stage_flag_t::decompiler),
            "type application must invalidate decompiler");
    require(!stage_test(type_scope.stage_flags, projection_stage_flag_t::disassembler),
            "type application must not invalidate disassembler");
    require(type_scope.total_patched_bytes == 0,
            "type application must not contribute patched bytes");

    overlay_payload_v9_t func_payload;
    func_payload.signature = "std::uint32_t entry()";
    auto func_change = make_change(overlay_operation_kind_v9_t::define_function, 0x400, 0x20,
                                   std::nullopt, func_payload);
    auto func_scope = incremental_reanalysis_t::minimal_invalidation(func_change);
    require(stage_test(func_scope.stage_flags, projection_stage_flag_t::function_table),
            "define_function must invalidate function table");
    require(stage_test(func_scope.stage_flags, projection_stage_flag_t::decompiler),
            "define_function must invalidate decompiler");
    require(stage_test(func_scope.stage_flags, projection_stage_flag_t::basic_block_table),
            "define_function must invalidate basic block table");

    overlay_payload_v9_t reanalysis_payload;
    reanalysis_payload.reanalysis_flags = 3;
    auto reanalysis_change = make_change(overlay_operation_kind_v9_t::reanalysis, 0x200, 0x20,
                                         std::nullopt, reanalysis_payload);
    auto reanalysis_scope = incremental_reanalysis_t::minimal_invalidation(reanalysis_change);
    require(reanalysis_scope.requires_full_reanalysis,
            "reanalysis must require full reanalysis");
    require(reanalysis_scope.stage_flags == projection_stage_flag_t::all_stages,
            "reanalysis must invalidate all stages");

    require(incremental_reanalysis_t::stage_requires_reanalysis(
                reanalysis_stage_t::disassembly,
                overlay_operation_kind_v9_t::byte_patch),
            "stage_requires_reanalysis must confirm byte_patch triggers disassembly");
    require(!incremental_reanalysis_t::stage_requires_reanalysis(
                reanalysis_stage_t::symbols,
                overlay_operation_kind_v9_t::byte_patch),
            "stage_requires_reanalysis must deny byte_patch triggers symbols");
    require(incremental_reanalysis_t::stage_requires_reanalysis(
                reanalysis_stage_t::symbols,
                overlay_operation_kind_v9_t::name),
            "stage_requires_reanalysis must confirm name triggers symbols");
    require(!incremental_reanalysis_t::stage_requires_reanalysis(
                reanalysis_stage_t::none,
                overlay_operation_kind_v9_t::reanalysis),
            "stage_requires_reanalysis must deny none stage for any operation");

    auto stages = incremental_reanalysis_t::stages_for_flags(
        projection_stage_flag_t::disassembler |
        projection_stage_flag_t::symbol_table |
        projection_stage_flag_t::type_table);
    require(stages.size() == 3, "stages_for_flags must return 3 stages");
    require(std::find(stages.begin(), stages.end(), reanalysis_stage_t::disassembly) != stages.end(),
            "stages_for_flags must include disassembly");
    require(std::find(stages.begin(), stages.end(), reanalysis_stage_t::symbols) != stages.end(),
            "stages_for_flags must include symbols");
    require(std::find(stages.begin(), stages.end(), reanalysis_stage_t::types) != stages.end(),
            "stages_for_flags must include types");
}

void verify_undo_redo_identity()
{
    auto state = make_state();
    auto identity = target();

    overlay_transaction_v9_t update_txn;
    update_txn.target = identity;
    update_txn.expected_revision = 1;
    update_txn.operations = {byte_patch_op(0x100, {0xFF, 0xEE})};
    auto update_result = overlay_apply_engine_v9_t::apply(state, update_txn);
    require(update_result.ok() && update_result.changes.size() == 1,
            "undo/redo update transaction must succeed");
    require(state.revision == 2, "revision must be 2 after update");

    const auto& forward_change = update_result.changes[0];
    require(forward_change.before && forward_change.after,
            "forward change must have before and after payloads");
    require(forward_change.before->bytes == std::vector<std::uint8_t>({0xAA, 0xBB}),
            "forward before must be original patch bytes");
    require(forward_change.after->bytes == std::vector<std::uint8_t>({0xFF, 0xEE}),
            "forward after must be new patch bytes");

    auto undo_result = overlay_apply_engine_v9_t::undo(state, identity, 2);
    require(undo_result.ok() && undo_result.changes.size() == 1,
            "undo must succeed for identity test");
    require(state.revision == 3, "revision must be 3 after undo");
    const auto& inverse_change = undo_result.changes[0];
    require(inverse_change.before && inverse_change.after,
            "inverse change must have before and after payloads");

    auto identity_result = incremental_reanalysis_t::validate_undo_redo_identity(
        forward_change, inverse_change);
    require(identity_result.keys_match,
            "undo/redo entity keys must match");
    require(identity_result.forward_valid,
            "forward change must be valid");
    require(identity_result.inverse_valid,
            "inverse change must be valid");
    require(identity_result.payloads_are_inverse,
            "undo/redo payloads must be inverse of each other");
    require(identity_result.identity_preserved(),
            "undo/redo identity must be fully preserved");

    auto mismatched = forward_change;
    mismatched.entity.range.offset = 0x999;
    auto mismatch_result = incremental_reanalysis_t::validate_undo_redo_identity(
        mismatched, inverse_change);
    require(!mismatch_result.keys_match,
            "mismatched entity keys must not match");
    require(!mismatch_result.identity_preserved(),
            "mismatched identity must not be preserved");

    overlay_payload_v9_t add_payload;
    add_payload.text = "new comment";
    auto add_change = make_change(overlay_operation_kind_v9_t::comment, 0x300, 1,
                                  std::nullopt, add_payload);
    auto remove_change = make_change(overlay_operation_kind_v9_t::comment, 0x300, 1,
                                     add_payload, std::nullopt);
    auto add_remove = incremental_reanalysis_t::validate_undo_redo_identity(
        add_change, remove_change);
    require(add_remove.keys_match,
            "add/remove entity keys must match");
    require(add_remove.payloads_are_inverse,
            "add/remove payloads must be inverse");
    require(add_remove.identity_preserved(),
            "add/remove identity must be preserved");

    auto redo_result = overlay_apply_engine_v9_t::redo(state, identity, 3);
    require(redo_result.ok(), "redo must succeed after undo");
    require(state.revision == 4, "revision must be 4 after redo");
    require(state.items.at(overlay_entity_key_for_operation_v9(
                byte_patch_op(0x100, {0xFF, 0xEE}))).bytes ==
            std::vector<std::uint8_t>({0xFF, 0xEE}),
            "redo must restore the updated patch bytes");

    overlay_payload_v9_t delete_payload;
    delete_payload.text = "new comment";
    auto delete_change = make_change(overlay_operation_kind_v9_t::comment, 0x300, 1,
                                     delete_payload, std::nullopt);
    auto restore_change = make_change(overlay_operation_kind_v9_t::comment, 0x300, 1,
                                      std::nullopt, delete_payload);
    auto delete_restore = incremental_reanalysis_t::validate_undo_redo_identity(
        delete_change, restore_change);
    require(delete_restore.keys_match,
            "delete/restore entity keys must match");
    require(delete_restore.payloads_are_inverse,
            "delete/restore payloads must be inverse");
    require(delete_restore.identity_preserved(),
            "delete/restore identity must be preserved");

    overlay_payload_v9_t unrelated_payload;
    unrelated_payload.text = "unrelated";
    auto non_inverse = make_change(overlay_operation_kind_v9_t::comment, 0x300, 1,
                                   add_payload, unrelated_payload);
    auto non_inverse_result = incremental_reanalysis_t::validate_undo_redo_identity(
        add_change, non_inverse);
    require(non_inverse_result.keys_match,
            "non-inverse keys must still match");
    require(!non_inverse_result.payloads_are_inverse,
            "non-inverse payloads must not be inverse");
    require(!non_inverse_result.identity_preserved(),
            "non-inverse identity must not be preserved");
}

void verify_cache_invalidation()
{
    auto state = make_state();

    overlay_payload_v9_t patch_payload;
    patch_payload.bytes = {0xAA, 0xBB};
    auto patch_change = make_change(overlay_operation_kind_v9_t::byte_patch, 0x100, 2,
                                    std::nullopt, patch_payload);
    auto scope = incremental_reanalysis_t::minimal_invalidation(patch_change);

    auto check = incremental_reanalysis_t::check_cache_invalidation(scope, state);
    require(check.cache_invalidated,
            "cache must be invalidated for overlapping patch scope");
    require(check.invalidated_entry_count > 0,
            "at least one state entry must be invalidated by overlapping patch");
    require(check.invalidated_stages == scope.stage_flags,
            "invalidated stages must match scope stage flags");
    require(!check.invalidated_ranges.empty(),
            "invalidated ranges must be populated");

    reanalysis_scope_t empty_scope;
    auto empty_check = incremental_reanalysis_t::check_cache_invalidation(empty_scope, state);
    require(!empty_check.cache_invalidated,
            "empty scope must not invalidate cache");
    require(empty_check.invalidated_entry_count == 0,
            "empty scope must invalidate zero entries");

    reanalysis_scope_t full_scope;
    full_scope.requires_full_reanalysis = true;
    full_scope.stage_flags = projection_stage_flag_t::all_stages;
    projected_range_t full_range;
    full_range.offset = 0;
    full_range.size = state.target.image_size;
    full_range.is_byte_patch = true;
    full_scope.ranges = {full_range};

    auto full_check = incremental_reanalysis_t::check_cache_invalidation(full_scope, state);
    require(full_check.cache_invalidated,
            "full reanalysis scope must invalidate cache");
    require(full_check.invalidated_entry_count == state.items.size(),
            "full reanalysis must invalidate all state entries");
    require(full_check.invalidated_stages == projection_stage_flag_t::all_stages,
            "full reanalysis must invalidate all stages");

    overlay_payload_v9_t comment_payload;
    comment_payload.text = "isolated comment";
    auto comment_change = make_change(overlay_operation_kind_v9_t::comment, 0x500, 1,
                                      std::nullopt, comment_payload);
    auto comment_scope = incremental_reanalysis_t::minimal_invalidation(comment_change);
    auto comment_check = incremental_reanalysis_t::check_cache_invalidation(comment_scope, state);
    require(comment_check.cache_invalidated,
            "comment scope with non-none stage flags must invalidate cache");
    require(comment_check.invalidated_stages == projection_stage_flag_t::none,
            "comment scope must have none stage flags");

    auto merged = incremental_reanalysis_t::merge_scopes(scope, comment_scope);
    require(merged.stage_flags == scope.stage_flags,
            "merged scope must preserve byte patch stage flags");
    require(merged.total_patched_bytes == scope.total_patched_bytes,
            "merged scope must sum patched bytes");
    require(merged.ranges.size() == scope.ranges.size() + comment_scope.ranges.size(),
            "merged scope must combine ranges");
    require(merged.entities.size() == scope.entities.size() + comment_scope.entities.size(),
            "merged scope must combine entities");

    auto full_merge = incremental_reanalysis_t::merge_scopes(scope, full_scope);
    require(full_merge.requires_full_reanalysis,
            "merge with full reanalysis must require full reanalysis");
    require(full_merge.stage_flags == projection_stage_flag_t::all_stages,
            "merge with full reanalysis must have all stages");

    auto test_range = scope.ranges[0];
    require(incremental_reanalysis_t::scope_contains_range(scope, test_range),
            "scope must contain its own range");

    projected_range_t outside_range;
    outside_range.offset = 0x4000;
    outside_range.size = 4;
    require(!incremental_reanalysis_t::scope_contains_range(scope, outside_range),
            "scope must not contain a range outside its bounds");
}

void verify_conflict_rejection()
{
    auto identity = target();
    auto state = make_state();
    std::string image_bytes(0x4000, 0x41);

    overlay_transaction_v9_t conflict_txn;
    conflict_txn.target = identity;
    conflict_txn.expected_revision = 1;
    conflict_txn.operations = {
        byte_patch_op(0x100, {0x11, 0x22, 0x33}),
        byte_patch_op(0x101, {0x44, 0x55}),
    };
    auto conflict_result = overlay_projection_t::project_transaction(
        state, conflict_txn, image_bytes, 7);
    require(conflict_result.code == projection_code_t::conflict_detected,
            "overlapping byte patches must be detected as conflict");
    require(!conflict_result.detail.empty(),
            "conflict result must include detail message");

    std::vector<overlay_change_v9_t> test_changes;
    overlay_payload_v9_t payload_a, payload_b;
    payload_a.bytes = {0x11, 0x22, 0x33, 0x44};
    payload_b.bytes = {0x55, 0x66, 0x77, 0x88};
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::byte_patch, 0x100, 4,
                                       std::nullopt, payload_a));
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::byte_patch, 0x102, 4,
                                       std::nullopt, payload_b));
    auto conflicts = overlay_projection_t::detect_conflicts(test_changes);
    require(!conflicts.empty(),
            "overlapping byte patch ranges must produce conflicts");
    require(conflicts[0].valid(),
            "conflict must be valid (ranges must overlap)");
    require(conflicts[0].range_a.overlaps(conflicts[0].range_b),
            "conflict ranges must overlap");

    test_changes[1].entity.range = range(0x200, 4);
    auto no_conflicts = overlay_projection_t::detect_conflicts(test_changes);
    require(no_conflicts.empty(),
            "non-overlapping ranges must not produce conflicts");

    test_changes.clear();
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::comment, 0x100, 1,
                                       std::nullopt, overlay_payload_v9_t{}));
    test_changes[0].after->text = "comment A";
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::comment, 0x100, 1,
                                       std::nullopt, overlay_payload_v9_t{}));
    test_changes[1].after->text = "comment B";
    auto comment_conflicts = overlay_projection_t::detect_conflicts(test_changes);
    require(comment_conflicts.empty(),
            "metadata-only comment operations must not conflict");

    test_changes.clear();
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::byte_patch, 0x100, 4,
                                       std::nullopt, payload_a));
    test_changes.push_back(make_change(overlay_operation_kind_v9_t::define_function, 0x102, 0x20,
                                       std::nullopt, overlay_payload_v9_t{}));
    test_changes[1].after->signature = "std::uint32_t conflict_fn()";
    auto patch_define_conflicts = overlay_projection_t::detect_conflicts(test_changes);
    require(!patch_define_conflicts.empty(),
            "byte patch overlapping define_function must conflict");

    overlay_transaction_v9_t clean_txn;
    clean_txn.target = identity;
    clean_txn.expected_revision = 1;
    clean_txn.operations = {
        byte_patch_op(0x300, {0x99, 0x88}),
        comment_op(0x310, "another comment"),
        name_op(0x320, "new_name"),
    };
    auto clean_result = overlay_projection_t::project_transaction(
        state, clean_txn, image_bytes, 7);
    require(clean_result.ok(),
            "non-conflicting transaction must succeed");
    require(!clean_result.changes.empty(),
            "clean transaction must produce changes");
    require(clean_result.projected_bytes[0x300] == 0x99,
            "clean transaction must apply byte patches to projected bytes");
    require(clean_result.projected_bytes[0x301] == 0x88,
            "clean transaction must apply full byte patch");
    require(clean_result.projected_bytes[0x310] == 0x41,
            "clean transaction must not alter non-patched regions");

    std::vector<projected_range_t> in_bounds = {{0x100, 2, true}, {0x200, 4, true}};
    require(overlay_projection_t::validate_ranges_in_bounds(in_bounds, 0x4000),
            "in-bounds ranges must validate");

    std::vector<projected_range_t> out_of_bounds = {{0x3FFF, 4, true}};
    require(!overlay_projection_t::validate_ranges_in_bounds(out_of_bounds, 0x4000),
            "out-of-bounds ranges must fail validation");

    std::vector<projected_range_t> empty_ranges;
    require(overlay_projection_t::validate_ranges_in_bounds(empty_ranges, 0x4000),
            "empty ranges must validate");

    std::vector<projected_range_t> zero_ranges = {{0x100, 0, false}};
    require(overlay_projection_t::validate_ranges_in_bounds(zero_ranges, 0x4000),
            "zero-size ranges must validate");

    std::vector<projected_range_t> exact_fit = {{0x3FFC, 4, true}};
    require(overlay_projection_t::validate_ranges_in_bounds(exact_fit, 0x4000),
            "range ending exactly at image boundary must validate");

    std::vector<projected_range_t> one_past = {{0x3FFD, 4, true}};
    require(!overlay_projection_t::validate_ranges_in_bounds(one_past, 0x4000),
            "range extending past image boundary must fail");
}

void verify_atomic_publication()
{
    auto state = make_state(7);

    overlay_payload_v9_t patch_payload;
    patch_payload.bytes = {0xAA, 0xBB};
    auto patch_change = make_change(overlay_operation_kind_v9_t::byte_patch, 0x100, 2,
                                    std::nullopt, patch_payload);
    auto invalidation = overlay_projection_t::compute_invalidation({patch_change});
    require(!invalidation.empty(),
            "invalidation set for byte patch must not be empty");
    require(invalidation.has_byte_patches(),
            "invalidation set must detect byte patches");
    require(invalidation.total_patched_bytes == 2,
            "invalidation total patched bytes must be 2");

    auto pub_result = overlay_projection_t::publish_generation(
        state, 7, invalidation, {patch_change});
    require(pub_result.ok(),
            "publish_generation must succeed with correct expected_generation");
    require(pub_result.new_generation == 8,
            "publish_generation must increment generation");
    require(pub_result.revision == state.revision,
            "publish_generation must preserve revision");
    require(!pub_result.changes.empty(),
            "publish_generation must preserve changes");
    require(pub_result.invalidation.has_byte_patches(),
            "publish_generation must preserve invalidation");
    require(state.target.generation == 8,
            "state generation must be updated after publication");

    auto stale_pub = overlay_projection_t::publish_generation(
        state, 7, invalidation, {patch_change});
    require(stale_pub.code == projection_code_t::stale_generation,
            "stale generation must be rejected by publish_generation");

    auto scope = incremental_reanalysis_t::minimal_invalidation(patch_change);
    auto reanalysis_result = incremental_reanalysis_t::publish_reanalysis(state, 8, scope);
    require(reanalysis_result.ok(),
            "publish_reanalysis must succeed with correct expected_generation");
    require(reanalysis_result.new_generation == 9,
            "publish_reanalysis must increment generation");
    require(reanalysis_result.scope.generation == 9,
            "publish_reanalysis scope generation must match new generation");

    auto stale_reanalysis = incremental_reanalysis_t::publish_reanalysis(state, 7, scope);
    require(!stale_reanalysis.ok(),
            "stale generation must be rejected by publish_reanalysis");
    require(!stale_reanalysis.detail.empty(),
            "stale reanalysis must include detail");

    overlay_static_state_v9_t overflow_state;
    require(overlay_apply_engine_v9_t::initialize(overflow_state, target(7)).ok(),
            "overflow publication init must succeed");
    overflow_state.target.generation = (std::numeric_limits<std::uint64_t>::max)();
    auto overflow_pub = overlay_projection_t::publish_generation(
        overflow_state, (std::numeric_limits<std::uint64_t>::max)(),
        invalidation, {patch_change});
    require(overflow_pub.code == projection_code_t::publication_failed,
            "max generation must fail publication");

    auto overflow_reanalysis = incremental_reanalysis_t::publish_reanalysis(
        overflow_state, (std::numeric_limits<std::uint64_t>::max)(), scope);
    require(!overflow_reanalysis.ok(),
            "max generation must fail reanalysis publication");

    overlay_static_state_v9_t uninitialized;
    auto uninit_pub = overlay_projection_t::publish_generation(
        uninitialized, 0, invalidation, {patch_change});
    require(uninit_pub.code == projection_code_t::state_not_initialized,
            "uninitialized state must fail publication");

    auto uninit_reanalysis = incremental_reanalysis_t::publish_reanalysis(
        uninitialized, 0, scope);
    require(!uninit_reanalysis.ok(),
            "uninitialized state must fail reanalysis publication");

    auto compute_result = incremental_reanalysis_t::compute_scope(
        {patch_change}, state, state.target.generation);
    require(compute_result.ok(),
            "compute_scope must succeed for valid state and generation");
    require(compute_result.scope.generation == state.target.generation,
            "compute_scope generation must match current generation");
    require(!compute_result.scope.ranges.empty(),
            "compute_scope must produce ranges for byte patch");
    require(compute_result.scope.total_patched_bytes == 2,
            "compute_scope total patched bytes must be 2");

    auto stale_compute = incremental_reanalysis_t::compute_scope(
        {patch_change}, state, 999);
    require(!stale_compute.ok(),
            "compute_scope must fail for stale generation");

    overlay_payload_v9_t reanalysis_payload;
    reanalysis_payload.reanalysis_flags = 1;
    auto reanalysis_change = make_change(overlay_operation_kind_v9_t::reanalysis, 0x200, 0x20,
                                         std::nullopt, reanalysis_payload);
    auto reanalysis_compute = incremental_reanalysis_t::compute_scope(
        {reanalysis_change}, state, state.target.generation);
    require(reanalysis_compute.ok(),
            "compute_scope must succeed for reanalysis change");
    require(reanalysis_compute.scope.requires_full_reanalysis,
            "compute_scope must set full reanalysis for reanalysis operation");
    require(reanalysis_compute.scope.stage_flags == projection_stage_flag_t::all_stages,
            "compute_scope must set all stages for reanalysis operation");
    require(reanalysis_compute.scope.ranges.size() == 1,
            "compute_scope must produce single full-image range for reanalysis");
    require(reanalysis_compute.scope.ranges[0].offset == 0,
            "compute_scope reanalysis range must start at offset 0");
    require(reanalysis_compute.scope.ranges[0].size == state.target.image_size,
            "compute_scope reanalysis range must cover full image");
}

}

void run_overlay_projection_harness()
{
    verify_patch_comment_type_rename_fixtures();
    verify_minimal_invalidation();
    verify_undo_redo_identity();
    verify_cache_invalidation();
    verify_conflict_rejection();
    verify_atomic_publication();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_overlay_projection_harness();
        std::cout << "overlay_projection_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
