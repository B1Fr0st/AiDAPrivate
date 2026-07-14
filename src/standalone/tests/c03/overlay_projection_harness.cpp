#include "overlay_projection_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/overlay_projection.hpp"
#include "../../src/core/analysis/incremental_reanalysis.hpp"
#include "../../src/core/analysis/overlay_apply_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {

namespace {

void require(bool condition, const char* message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
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

overlay_operation_v9_t assembly_patch_op(std::uint64_t offset,
                                         std::string assembly,
                                         std::vector<std::uint8_t> bytes)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::assembly_patch;
    op.range = {offset, bytes.size()};
    op.payload.assembly = std::move(assembly);
    op.payload.bytes = std::move(bytes);
    return op;
}

overlay_operation_v9_t integer_patch_op(std::uint64_t offset,
                                        std::string integer_type,
                                        std::string integer_value,
                                        std::vector<std::uint8_t> bytes)
{
    overlay_operation_v9_t op;
    op.kind = overlay_operation_kind_v9_t::integer_patch;
    op.range = {offset, bytes.size()};
    op.payload.integer_type = std::move(integer_type);
    op.payload.integer_value = std::move(integer_value);
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
    if (before)
        change.before_kind = kind;
    if (after)
        change.after_kind = kind;
    change.before = std::move(before);
    change.after = std::move(after);
    return change;
}

const overlay_change_v9_t& change_for(
    const std::vector<overlay_change_v9_t>& changes,
    overlay_operation_kind_v9_t kind)
{
    const auto found = std::find_if(
        changes.begin(), changes.end(),
        [&](const auto& change) {
            return change.after_kind && *change.after_kind == kind;
        });
    require(found != changes.end(), "expected projected change provenance was not found");
    return *found;
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
        assembly_patch_op(0x240, "nop; nop", {0x90, 0x90}),
        integer_patch_op(0x260, "u32le", "305419896", {0x78, 0x56, 0x34, 0x12}),
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

    auto metadata = overlay_projection_t::prepare(state, 7);
    require(metadata.ok() && metadata.projected_state.has_value(),
            "metadata projection preparation must succeed");
    require(metadata.projected_bytes.empty() &&
            metadata.projected_size == image_bytes.size(),
            "metadata projection preparation must not materialize image bytes");

    auto result = overlay_projection_t::project(state, image_bytes, 7);
    require(result.ok(), "project must succeed on valid state");
    require(result.new_generation == 7, "project generation must match current");
    require(result.revision == 1, "project revision must match state");
    require(!result.changes.empty(), "project must produce changes");
    require(result.projected_state.has_value(),
            "project must include projected static metadata");
    require(result.projected_state->items.size() == 8,
            "projected metadata must preserve all eight overlay entities");
    require(result.projected_bytes.size() == image_bytes.size(),
            "projected bytes must match image size");

    require(result.projected_bytes[0x100] == 0xAA && result.projected_bytes[0x101] == 0xBB,
            "byte patch at 0x100 must be applied to projected bytes");
    require(result.projected_bytes[0x200] == 0xCC && result.projected_bytes[0x201] == 0xDD,
            "byte patch at 0x200 must be applied to projected bytes");
    require(result.projected_bytes[0x240] == 0x90 && result.projected_bytes[0x241] == 0x90,
            "assembly patch bytes must be applied to projected bytes");
    require(result.projected_bytes[0x260] == 0x78 && result.projected_bytes[0x261] == 0x56 &&
            result.projected_bytes[0x262] == 0x34 && result.projected_bytes[0x263] == 0x12,
            "integer patch bytes must be applied to projected bytes");
    require(result.projected_bytes[0x102] == 0x41,
            "non-patched bytes must remain unchanged in projection");

    const auto& assembly_change = change_for(
        result.changes, overlay_operation_kind_v9_t::assembly_patch);
    require(assembly_change.after_kind == overlay_operation_kind_v9_t::assembly_patch &&
            assembly_change.after && assembly_change.after->assembly == "nop; nop",
            "assembly projection must preserve operation and source-text provenance");
    const auto& integer_change = change_for(
        result.changes, overlay_operation_kind_v9_t::integer_patch);
    require(integer_change.after_kind == overlay_operation_kind_v9_t::integer_patch &&
            integer_change.after && integer_change.after->integer_type == "u32le" &&
            integer_change.after->integer_value == "305419896",
            "integer projection must preserve type and value provenance");

    require(result.invalidation.has_byte_patches(),
            "invalidation must detect byte patches in projection");
    require(result.invalidation.total_patched_bytes == 10,
            "total patched bytes must equal 10 across static patch forms");
    require(result.invalidation.max_contiguous_range == 0x20,
            "max contiguous affected range must equal the function definition range");
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

    auto invalid_comment_state = state;
    overlay_entity_key_v9_t invalid_comment_key;
    invalid_comment_key.domain = overlay_operation_kind_v9_t::comment;
    invalid_comment_key.range.offset = invalid_comment_state.target.image_size;
    overlay_payload_v9_t invalid_comment_payload;
    invalid_comment_payload.text = "outside image";
    invalid_comment_state.items.emplace(
        std::move(invalid_comment_key), std::move(invalid_comment_payload));
    const auto invalid_comment = overlay_projection_t::project(
        invalid_comment_state, image_bytes, 7);
    require(invalid_comment.code == projection_code_t::range_out_of_bounds,
            "entity-only comments must still retain an in-image address contract");

    auto invalid_provenance_state = state;
    const auto assembly_key = overlay_entity_key_for_operation_v9(
        assembly_patch_op(0x240, "nop; nop", {0x90, 0x90}));
    invalid_provenance_state.items.at(assembly_key).integer_type = "u16le";
    invalid_provenance_state.items.at(assembly_key).integer_value = "37008";
    const auto invalid_provenance = overlay_projection_t::project(
        invalid_provenance_state, image_bytes, 7);
    require(invalid_provenance.code == projection_code_t::invalid_patch_provenance,
            "ambiguous static patch provenance must be rejected");

    auto invalid_integer_state = state;
    const auto integer_key = overlay_entity_key_for_operation_v9(
        integer_patch_op(0x260, "u32le", "305419896",
                         {0x78, 0x56, 0x34, 0x12}));
    invalid_integer_state.items.at(integer_key).integer_value = "1";
    const auto invalid_integer = overlay_projection_t::project(
        invalid_integer_state, image_bytes, 7);
    require(invalid_integer.code == projection_code_t::invalid_patch_provenance,
            "integer patch bytes must match their declared static value provenance");

    auto patched = overlay_projection_t::apply_patches(image_bytes, state);
    require(patched.size() == image_bytes.size(),
            "apply_patches output size must match input");
    require(patched[0x100] == 0xAA && patched[0x101] == 0xBB,
            "apply_patches must apply byte patch at 0x100");
    require(patched[0x200] == 0xCC && patched[0x201] == 0xDD,
            "apply_patches must apply byte patch at 0x200");
    require(patched[0x240] == 0x90 && patched[0x241] == 0x90,
            "apply_patches must apply assembly patch bytes");
    require(patched[0x260] == 0x78 && patched[0x263] == 0x12,
            "apply_patches must apply integer patch bytes");
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
    auto prepared_txn = overlay_projection_t::prepare_transaction(
        state, txn, 7);
    require(prepared_txn.ok() && prepared_txn.publication_ready &&
            prepared_txn.projected_state.has_value(),
            "metadata transaction preparation must succeed");
    require(prepared_txn.projected_bytes.empty() &&
            prepared_txn.projected_size == image_bytes.size(),
            "metadata transaction preparation must not materialize image bytes");
    auto txn_result = overlay_projection_t::project_transaction(state, txn, image_bytes, 7);
    require(txn_result.ok(), "non-conflicting project_transaction must succeed");
    require(txn_result.publication_ready && txn_result.projected_state.has_value(),
            "project_transaction must produce a publication-ready metadata candidate");
    require(txn_result.new_generation == 8 &&
            txn_result.projected_state->target.generation == 8,
            "project_transaction must prepare the next workspace generation");
    require(state.target.generation == 7 && state.revision == 1,
            "project_transaction must not mutate the source overlay state");
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
    require(comment_scope.ranges.empty(),
            "comment scope must remain entity-only and range-free");

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

    overlay_payload_v9_t assembly_payload;
    assembly_payload.assembly = "xor eax, eax";
    assembly_payload.bytes = {0x31, 0xC0};
    auto assembly_change = make_change(
        overlay_operation_kind_v9_t::assembly_patch, 0x240, 2,
        std::nullopt, assembly_payload);
    auto assembly_scope = incremental_reanalysis_t::minimal_invalidation(assembly_change);
    require(assembly_scope.ranges.size() == 1 &&
            assembly_scope.ranges[0].source_kind ==
                overlay_operation_kind_v9_t::assembly_patch,
            "assembly invalidation must preserve static operation provenance");
    require(assembly_scope.total_patched_bytes == 2 &&
            stage_test(assembly_scope.stage_flags, projection_stage_flag_t::decompiler),
            "assembly invalidation must account for bytes and decompiler state");
    require(!stage_test(assembly_scope.stage_flags, projection_stage_flag_t::string_table),
            "assembly invalidation must retain its narrower provenance-specific stage set");

    overlay_payload_v9_t integer_payload;
    integer_payload.integer_type = "u32le";
    integer_payload.integer_value = "305419896";
    integer_payload.bytes = {0x78, 0x56, 0x34, 0x12};
    auto integer_change = make_change(
        overlay_operation_kind_v9_t::integer_patch, 0x260, 4,
        std::nullopt, integer_payload);
    auto integer_scope = incremental_reanalysis_t::minimal_invalidation(integer_change);
    require(integer_scope.ranges.size() == 1 &&
            integer_scope.ranges[0].source_kind ==
                overlay_operation_kind_v9_t::integer_patch,
            "integer invalidation must preserve static operation provenance");
    require(integer_scope.total_patched_bytes == 4,
            "integer invalidation must account for its encoded width");

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
    require(identity_result.provenance_is_inverse,
            "undo/redo patch provenance must be inverse of each other");
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

    overlay_payload_v9_t assembly_payload;
    assembly_payload.assembly = "nop; nop";
    assembly_payload.bytes = {0x90, 0x90};
    overlay_payload_v9_t integer_payload;
    integer_payload.integer_type = "u16le";
    integer_payload.integer_value = "4660";
    integer_payload.bytes = {0x34, 0x12};
    auto provenance_forward = make_change(
        overlay_operation_kind_v9_t::integer_patch, 0x240, 2,
        assembly_payload, integer_payload);
    provenance_forward.entity.domain = overlay_operation_kind_v9_t::byte_patch;
    provenance_forward.before_kind = overlay_operation_kind_v9_t::assembly_patch;
    provenance_forward.after_kind = overlay_operation_kind_v9_t::integer_patch;
    auto provenance_inverse = provenance_forward;
    std::swap(provenance_inverse.before, provenance_inverse.after);
    std::swap(provenance_inverse.before_kind, provenance_inverse.after_kind);
    provenance_inverse.operation_kind = overlay_operation_kind_v9_t::assembly_patch;
    const auto provenance_identity =
        incremental_reanalysis_t::validate_undo_redo_identity(
            provenance_forward, provenance_inverse);
    require(provenance_identity.identity_preserved(),
            "assembly-to-integer undo identity must preserve both patch provenances");

    provenance_inverse.after_kind = overlay_operation_kind_v9_t::byte_patch;
    const auto bad_provenance_identity =
        incremental_reanalysis_t::validate_undo_redo_identity(
            provenance_forward, provenance_inverse);
    require(!bad_provenance_identity.provenance_is_inverse &&
            !bad_provenance_identity.identity_preserved(),
            "payload inversion must not hide mismatched patch provenance");
}

void verify_cache_invalidation()
{
    auto state = make_state();

    overlay_payload_v9_t patch_payload;
    patch_payload.bytes = {0xAA, 0xBB};
    auto patch_change = make_change(
        overlay_operation_kind_v9_t::byte_patch, 0x100, 2,
        std::nullopt, patch_payload);
    const auto patch_result = incremental_reanalysis_t::compute_scope(
        {patch_change}, state, state.target.generation);
    require(patch_result.ok,
            "patch reanalysis scope must be computed");
    require(patch_result.invalidation.packed_index.required(),
            "patch invalidation must require the packed-index hook");
    require(patch_result.invalidation.decompiler_cache.required(),
            "patch invalidation must require the decompiler-cache hook");
    require(patch_result.invalidation.packed_index.source_generation == 7 &&
            patch_result.invalidation.packed_index.target_generation == 7,
            "incremental hook request must remain bound to the active generation");

    std::size_t packed_calls = 0;
    std::size_t decompiler_calls = 0;
    projection_invalidation_hooks_t hooks;
    hooks.packed_index = [&](const packed_index_invalidation_request_t& request) {
        ++packed_calls;
        require(stage_test(request.invalidated_stages,
                           projection_stage_flag_t::disassembler),
                "packed-index request must include disassembly invalidation");
        require(request.affected_ranges.size() == 1 &&
                request.affected_ranges[0].offset == 0x100 &&
                request.affected_ranges[0].size == 2,
                "packed-index request must retain the minimal patch range");
        return projection_invalidation_hook_result_t{
            true, request.affected_ranges.size(), {}};
    };
    hooks.decompiler_cache = [&](
        const decompiler_cache_invalidation_request_t& request) {
        ++decompiler_calls;
        require(request.invalidated_stages ==
                    decompiler_cache_invalidation_flag_t::all_stages,
                "decompiler request must invalidate all derived cache stages");
        require(!request.invalidate_workspace,
                "minimal patch invalidation must not retire the whole workspace cache");
        return projection_invalidation_hook_result_t{
            true, request.affected_ranges.size(), {}};
    };

    const auto dispatched = overlay_projection_t::dispatch_invalidation(
        patch_result.invalidation, hooks);
    require(dispatched.satisfies(patch_result.invalidation),
            "both concrete invalidation hooks must complete");
    require(packed_calls == 1 && decompiler_calls == 1,
            "each required invalidation hook must run exactly once");

    std::size_t preflight_calls = 0;
    projection_invalidation_hooks_t incomplete_hooks;
    incomplete_hooks.packed_index = [&](
        const packed_index_invalidation_request_t&) {
        ++preflight_calls;
        return projection_invalidation_hook_result_t{true, 1, {}};
    };
    const auto missing_hook = overlay_projection_t::dispatch_invalidation(
        patch_result.invalidation, incomplete_hooks);
    require(missing_hook.code ==
                projection_invalidation_dispatch_code_t::missing_decompiler_cache_hook,
            "missing decompiler hook must fail before invalidation starts");
    require(preflight_calls == 0,
            "hook availability must be preflighted before any invalidation effect");

    overlay_payload_v9_t comment_payload;
    comment_payload.text = "isolated comment";
    auto comment_change = make_change(
        overlay_operation_kind_v9_t::comment, 0x500, 1,
        std::nullopt, comment_payload);
    const auto comment_result = incremental_reanalysis_t::compute_scope(
        {comment_change}, state, state.target.generation);
    require(comment_result.ok && comment_result.scope.ranges.empty(),
            "comment reanalysis must remain range-free");
    require(!comment_result.invalidation.packed_index.required() &&
            !comment_result.invalidation.decompiler_cache.required(),
            "comment metadata must not request packed-index or decompiler-cache invalidation");
    const auto comment_dispatch = overlay_projection_t::dispatch_invalidation(
        comment_result.invalidation, {});
    require(comment_dispatch.satisfies(comment_result.invalidation),
            "comment-only invalidation must complete without cache hooks");

    overlay_transaction_v9_t comment_publication;
    comment_publication.target = state.target;
    comment_publication.expected_revision = state.revision;
    comment_publication.operations = {comment_op(0x580, "next generation comment")};
    std::string image_bytes(0x4000, 0x41);
    const auto comment_publication_result = overlay_projection_t::project_transaction(
        state, comment_publication, image_bytes, state.target.generation);
    require(comment_publication_result.ok() &&
            comment_publication_result.invalidation.invalidated_stages ==
                projection_stage_flag_t::none &&
            comment_publication_result.invalidation.packed_index.required() &&
            comment_publication_result.invalidation.decompiler_cache.required(),
            "metadata-only publication must rebind index and cache generations without invalidating stages");
    std::vector<std::string> metadata_hook_order;
    projection_invalidation_hooks_t metadata_hooks;
    metadata_hooks.decompiler_cache = [&metadata_hook_order](
        const decompiler_cache_invalidation_request_t& request) {
        metadata_hook_order.push_back("decompiler");
        require(request.invalidated_stages ==
                    decompiler_cache_invalidation_flag_t::none &&
                request.affected_ranges.empty() &&
                request.affected_entities.size() == 1 &&
                !request.invalidate_workspace,
                "comment publication must not invalidate decompiler code ranges or stages");
        return projection_invalidation_hook_result_t{true, 0, {}};
    };
    metadata_hooks.packed_index = [&metadata_hook_order](
        const packed_index_invalidation_request_t& request) {
        metadata_hook_order.push_back("packed");
        require(request.invalidated_stages == projection_stage_flag_t::none &&
                request.affected_ranges.empty() &&
                request.affected_entities.size() == 1 &&
                !request.rebuild_all,
                "comment publication must rebind packed metadata without code invalidation");
        return projection_invalidation_hook_result_t{true, 1, {}};
    };
    const auto metadata_dispatch = overlay_projection_t::dispatch_invalidation(
        comment_publication_result.invalidation, metadata_hooks);
    require(metadata_dispatch.satisfies(
                comment_publication_result.invalidation) &&
            metadata_dispatch.decompiler_cache.invalidated_entry_count == 0 &&
            metadata_hook_order ==
                std::vector<std::string>({"decompiler", "packed"}),
            "metadata publication must complete cache preflight before atomic packed publication");

    overlay_payload_v9_t full_payload;
    full_payload.reanalysis_flags = 1;
    auto full_change = make_change(
        overlay_operation_kind_v9_t::reanalysis, 0x200, 0x20,
        std::nullopt, full_payload);
    const auto full_result = incremental_reanalysis_t::compute_scope(
        {full_change}, state, state.target.generation);
    require(full_result.ok && full_result.scope.requires_full_reanalysis,
            "explicit reanalysis must produce a full scope");
    require(full_result.invalidation.packed_index.rebuild_all &&
            full_result.invalidation.decompiler_cache.invalidate_workspace,
            "full reanalysis must request complete index and cache invalidation");
    require(full_result.invalidation.affected_ranges.size() == 1 &&
            full_result.invalidation.affected_ranges[0].offset == 0 &&
            full_result.invalidation.affected_ranges[0].size == state.target.image_size,
            "full invalidation request must cover the complete static image");

    const auto patch_scope = patch_result.scope;
    const auto comment_scope = comment_result.scope;
    const auto merged = incremental_reanalysis_t::merge_scopes(
        patch_scope, comment_scope);
    require(merged.stage_flags == patch_scope.stage_flags,
            "comment merge must preserve patch stage flags");
    require(merged.total_patched_bytes == patch_scope.total_patched_bytes,
            "comment merge must not add patched bytes");
    require(merged.ranges == patch_scope.ranges,
            "entity-only comment merge must not expand patch ranges");
    require(merged.entities.size() ==
                patch_scope.entities.size() + comment_scope.entities.size(),
            "comment merge must retain both affected entities");

    overlay_payload_v9_t overlapping_payload;
    overlapping_payload.bytes = {0xCC, 0xDD};
    const auto overlapping_change = make_change(
        overlay_operation_kind_v9_t::byte_patch, 0x101, 2,
        std::nullopt, overlapping_payload);
    const auto overlapping_scope =
        incremental_reanalysis_t::minimal_invalidation(overlapping_change);
    const auto overlapping_merge = incremental_reanalysis_t::merge_scopes(
        patch_scope, overlapping_scope);
    require(overlapping_merge.ranges.size() == 1 &&
            overlapping_merge.ranges[0].offset == 0x100 &&
            overlapping_merge.ranges[0].size == 3 &&
            overlapping_merge.total_patched_bytes == 3,
            "merged scopes must count unique patched-byte coverage");

    auto stale_scope = patch_scope;
    stale_scope.generation = patch_scope.generation + 1;
    const auto stale_merge = incremental_reanalysis_t::merge_scopes(
        patch_scope, stale_scope);
    require(!stale_merge.valid() && stale_merge.generation_conflict &&
            stale_merge.generation == 0,
            "scope merging must expose incompatible nonzero generations");

    const auto full_merge = incremental_reanalysis_t::merge_scopes(
        patch_scope, full_result.scope);
    require(full_merge.requires_full_reanalysis &&
            full_merge.stage_flags == projection_stage_flag_t::all_stages,
            "merge with full reanalysis must preserve full-stage semantics");
    require(incremental_reanalysis_t::scope_contains_range(
                patch_scope, patch_scope.ranges[0]),
            "scope must contain its own range");

    projected_range_t outside_range;
    outside_range.offset = 0x4000;
    outside_range.size = 4;
    require(!incremental_reanalysis_t::scope_contains_range(
                patch_scope, outside_range),
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

    overlay_transaction_v9_t existing_conflict_txn;
    existing_conflict_txn.target = identity;
    existing_conflict_txn.expected_revision = 1;
    existing_conflict_txn.operations = {
        integer_patch_op(0x101, "u16le", "17459", {0x33, 0x44}),
    };
    const auto existing_conflict_result = overlay_projection_t::project_transaction(
        state, existing_conflict_txn, image_bytes, 7);
    require(existing_conflict_result.code == projection_code_t::conflict_detected,
            "patch overlap with existing projected bytes must be rejected");
    require(existing_conflict_result.detail.find("against projected state") !=
                std::string::npos,
            "existing-state conflict detail must identify the projected-state comparison");

    overlay_payload_v9_t existing_payload;
    existing_payload.integer_type = "u16le";
    existing_payload.integer_value = "17459";
    existing_payload.bytes = {0x33, 0x44};
    auto existing_change = make_change(
        overlay_operation_kind_v9_t::integer_patch, 0x101, 2,
        std::nullopt, existing_payload);
    existing_change.entity.domain = overlay_operation_kind_v9_t::byte_patch;
    const auto existing_conflicts = overlay_projection_t::detect_conflicts(
        {existing_change}, state);
    require(existing_conflicts.size() == 1 &&
            existing_conflicts[0].against_projected_state() &&
            existing_conflicts[0].entity_b.range.offset == 0x100,
            "conflict report must retain the exact existing projected entity");

    overlay_transaction_v9_t assembly_conflict_txn;
    assembly_conflict_txn.target = identity;
    assembly_conflict_txn.expected_revision = 1;
    assembly_conflict_txn.operations = {
        byte_patch_op(0x241, {0xCC, 0xCC}),
    };
    const auto assembly_conflict_result = overlay_projection_t::project_transaction(
        state, assembly_conflict_txn, image_bytes, 7);
    require(assembly_conflict_result.code == projection_code_t::conflict_detected,
            "existing assembly patch range must participate in projected-state conflicts");

    auto legacy_conflict_state = make_state();
    overlay_transaction_v9_t legacy_conflict;
    legacy_conflict.target = identity;
    legacy_conflict.expected_revision = legacy_conflict_state.revision;
    legacy_conflict.operations = {
        integer_patch_op(0x101, "u16le", "17459", {0x33, 0x44}),
    };
    require(overlay_apply_engine_v9_t::apply(
                legacy_conflict_state, legacy_conflict).ok(),
            "legacy conflict fixture setup must succeed in the journal engine");
    auto remove_original = byte_patch_op(0x100, {0xAA, 0xBB});
    remove_original.remove = true;
    overlay_transaction_v9_t repair;
    repair.target = identity;
    repair.expected_revision = legacy_conflict_state.revision;
    repair.operations = {remove_original};
    const auto repaired = overlay_projection_t::project_transaction(
        legacy_conflict_state, repair, image_bytes, 7);
    require(repaired.ok() && repaired.projected_state &&
            repaired.projected_state->items.find(
                overlay_entity_key_for_operation_v9(remove_original)) ==
                repaired.projected_state->items.end(),
            "a transaction that removes a legacy projected conflict must remain publishable");

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

    overlay_payload_v9_t overflow_payload;
    overflow_payload.bytes = {0x10, 0x20, 0x30, 0x40};
    auto overflow_change = make_change(
        overlay_operation_kind_v9_t::byte_patch,
        (std::numeric_limits<std::uint64_t>::max)() - 2, 4,
        std::nullopt, overflow_payload);
    overlay_payload_v9_t tail_payload;
    tail_payload.bytes = {0x50};
    auto tail_change = make_change(
        overlay_operation_kind_v9_t::byte_patch,
        (std::numeric_limits<std::uint64_t>::max)() - 1, 1,
        std::nullopt, tail_payload);
    const auto overflow_invalidation = overlay_projection_t::compute_invalidation(
        {overflow_change, tail_change});
    require(!overlay_projection_t::validate_ranges_in_bounds(
                overflow_invalidation.affected_ranges,
                (std::numeric_limits<std::uint64_t>::max)()),
            "range coalescing must not hide unsigned overflow");
}

void verify_atomic_publication()
{
    std::string image_bytes(0x4000, 0x41);
    auto state = make_state(7);
    overlay_transaction_v9_t transaction;
    transaction.target = state.target;
    transaction.expected_revision = state.revision;
    transaction.operations = {
        byte_patch_op(0x300, {0xDE, 0xAD, 0xBE, 0xEF}),
    };

    const auto prepared = overlay_projection_t::project_transaction(
        state, transaction, image_bytes, state.target.generation);
    require(prepared.ok() && prepared.publication_ready &&
            prepared.projected_state.has_value(),
            "transaction projection must prepare an atomic publication candidate");
    require(prepared.source_generation == 7 && prepared.new_generation == 8 &&
            prepared.source_revision == 1 && prepared.revision == 2,
            "publication candidate must bind both source and target versions");
    require(prepared.projected_state->target.generation == 8 &&
            prepared.projected_state->revision == 2,
            "projected metadata must carry the next generation and overlay revision");
    require(state.target.generation == 7 && state.revision == 1 &&
            state.items.size() == 8,
            "publication preparation must leave source state unchanged");

    std::size_t packed_calls = 0;
    std::size_t decompiler_calls = 0;
    std::size_t finalizer_calls = 0;
    projection_invalidation_hooks_t hooks;
    hooks.packed_index = [&](const packed_index_invalidation_request_t& request) {
        ++packed_calls;
        require(request.source_generation == 7 && request.target_generation == 8,
                "packed-index hook must receive the publication generation transition");
        return projection_invalidation_hook_result_t{
            true, request.affected_ranges.size(), {}};
    };
    hooks.decompiler_cache = [&](
        const decompiler_cache_invalidation_request_t& request) {
        ++decompiler_calls;
        require(request.source_generation == 7 && request.target_generation == 8,
                "decompiler hook must receive the publication generation transition");
        return projection_invalidation_hook_result_t{
            true, request.affected_ranges.size(), {}};
    };
    projection_publication_finalizer_t finalizer =
        [&](const projection_publication_view_t& view,
            const projection_invalidation_hooks_t& supplied_hooks) {
            ++finalizer_calls;
            require(view.source_generation == 7 && view.target_generation == 8 &&
                    view.source_revision == 1 && view.target_revision == 2,
                    "finalizer view must expose the complete version transition");
            require(view.projected_state.target.generation == 8 &&
                    view.projected_state.revision == 2 &&
                    view.projected_state.items.size() == 9,
                    "finalizer must receive complete projected overlay metadata");
            require(view.projected_bytes[0x300] == 0xDE &&
                    view.projected_bytes[0x303] == 0xEF,
                    "finalizer must receive the projected immutable-byte view");
            require(std::all_of(
                        view.projected_state.history.begin(),
                        view.projected_state.history.end(),
                        [&](const auto& entry) {
                            return entry.target == view.projected_state.target &&
                                   entry.generation == view.target_generation;
                        }),
                    "publication candidate history must be rebased atomically");
            projection_publication_commit_t commit;
            commit.invalidation = overlay_projection_t::dispatch_invalidation(
                view.invalidation, supplied_hooks);
            commit.committed = commit.invalidation.satisfies(view.invalidation);
            return commit;
        };

    const auto published = overlay_projection_t::finalize_publication(
        state, prepared, hooks, finalizer);
    require(published.ok() && published.new_generation == 8 &&
            published.revision == 2,
            "atomic finalizer must publish the prepared generation and revision");
    require(packed_calls == 1 && decompiler_calls == 1 && finalizer_calls == 1,
            "atomic publication must execute each integration hook exactly once");
    require(state.target.generation == 8 && state.revision == 2 &&
            state.items.size() == 9,
            "successful finalization must install the exact projected metadata state");
    require(state.items.at(overlay_entity_key_for_operation_v9(
                byte_patch_op(0x300, {0xDE, 0xAD, 0xBE, 0xEF}))).bytes ==
                std::vector<std::uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}),
            "successful finalization must install projected patch bytes");

    auto undo_state = state;
    const auto undo = overlay_apply_engine_v9_t::undo(
        undo_state, undo_state.target, undo_state.revision);
    require(undo.ok() && undo_state.target.generation == 8 &&
            undo_state.revision == 3,
            "rebased history must remain valid for undo after publication");

    auto missing_hook_state = make_state(7);
    const auto missing_hook_prepared = overlay_projection_t::project_transaction(
        missing_hook_state, transaction, image_bytes, 7);
    std::size_t missing_hook_finalizer_calls = 0;
    projection_invalidation_hooks_t missing_hooks;
    missing_hooks.packed_index = [&](const packed_index_invalidation_request_t&) {
        return projection_invalidation_hook_result_t{true, 1, {}};
    };
    projection_publication_finalizer_t missing_hook_finalizer =
        [&](const projection_publication_view_t& view,
            const projection_invalidation_hooks_t& supplied_hooks) {
            ++missing_hook_finalizer_calls;
            projection_publication_commit_t commit;
            commit.invalidation = overlay_projection_t::dispatch_invalidation(
                view.invalidation, supplied_hooks);
            commit.committed = commit.invalidation.satisfies(view.invalidation);
            return commit;
        };
    const auto missing_hook_publish = overlay_projection_t::finalize_publication(
        missing_hook_state, missing_hook_prepared, missing_hooks,
        missing_hook_finalizer);
    require(missing_hook_publish.code == projection_code_t::finalizer_failed &&
            missing_hook_publish.invalidation.code ==
                projection_invalidation_dispatch_code_t::missing_decompiler_cache_hook &&
            missing_hook_finalizer_calls == 0,
            "required hooks must be preflighted before the atomic finalizer");
    require(missing_hook_state.target.generation == 7 &&
            missing_hook_state.revision == 1 &&
            missing_hook_state.items.size() == 8,
            "failed invalidation must leave overlay metadata unchanged");

    auto rejected_state = make_state(7);
    const auto rejected_prepared = overlay_projection_t::project_transaction(
        rejected_state, transaction, image_bytes, 7);
    projection_publication_finalizer_t rejecting_finalizer =
        [](const projection_publication_view_t&,
           const projection_invalidation_hooks_t&) {
            projection_publication_commit_t commit;
            commit.detail = "fixture rejected publication";
            return commit;
        };
    const auto rejected = overlay_projection_t::finalize_publication(
        rejected_state, rejected_prepared, hooks, rejecting_finalizer);
    require(rejected.code == projection_code_t::finalizer_failed &&
            rejected_state.target.generation == 7 &&
            rejected_state.revision == 1,
            "rejected finalizer must not partially publish local state");

    auto tampered_state = make_state(7);
    auto tampered_prepared = overlay_projection_t::project_transaction(
        tampered_state, transaction, image_bytes, 7);
    tampered_prepared.projected_state->target.image_hash[0] ^= 0xFFU;
    std::size_t tampered_finalizer_calls = 0;
    projection_publication_finalizer_t tampered_finalizer =
        [&](const projection_publication_view_t&,
            const projection_invalidation_hooks_t&) {
            ++tampered_finalizer_calls;
            projection_publication_commit_t commit;
            commit.committed = true;
            return commit;
        };
    const auto tampered = overlay_projection_t::finalize_publication(
        tampered_state, tampered_prepared, hooks, tampered_finalizer);
    require(tampered.code == projection_code_t::invalid_publication &&
            tampered_finalizer_calls == 0 &&
            tampered_state.target.generation == 7 &&
            tampered_state.revision == 1,
            "tampered projected metadata must fail before finalizer effects");

    auto stale_state = make_state(7);
    const auto stale_prepared = overlay_projection_t::project_transaction(
        stale_state, transaction, image_bytes, 7);
    overlay_transaction_v9_t intervening;
    intervening.target = stale_state.target;
    intervening.expected_revision = stale_state.revision;
    intervening.operations = {comment_op(0x700, "intervening")};
    require(overlay_apply_engine_v9_t::apply(stale_state, intervening).ok(),
            "intervening transaction fixture must succeed");
    std::size_t stale_finalizer_calls = 0;
    projection_publication_finalizer_t stale_finalizer =
        [&](const projection_publication_view_t&,
            const projection_invalidation_hooks_t&) {
            ++stale_finalizer_calls;
            projection_publication_commit_t commit;
            commit.committed = true;
            return commit;
        };
    const auto stale = overlay_projection_t::finalize_publication(
        stale_state, stale_prepared, hooks, stale_finalizer);
    require(stale.code == projection_code_t::revision_conflict &&
            stale_finalizer_calls == 0,
            "stale source revision must be rejected before finalizer effects");
    require(stale_state.revision == 2 && stale_state.target.generation == 7,
            "stale rejection must preserve the intervening state");

    auto overflow_state = make_state(
        (std::numeric_limits<std::uint64_t>::max)() - 1U);
    overlay_transaction_v9_t overflow_transaction;
    overflow_transaction.target = overflow_state.target;
    overflow_transaction.expected_revision = overflow_state.revision;
    overflow_transaction.operations = {
        byte_patch_op(0x300, {0x10, 0x20}),
    };
    const auto overflow = overlay_projection_t::project_transaction(
        overflow_state, overflow_transaction, image_bytes,
        overflow_state.target.generation);
    require(overflow.code == projection_code_t::publication_failed,
            "exhausted generation must fail during publication preparation");

    overlay_static_state_v9_t uninitialized;
    const auto uninitialized_result = overlay_projection_t::finalize_publication(
        uninitialized, prepared, hooks, finalizer);
    require(uninitialized_result.code == projection_code_t::state_not_initialized,
            "uninitialized state must fail before publication finalization");
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
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
