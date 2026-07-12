#include "overlay_journal_v9_harness.hpp"

#include "../../src/core/analysis/overlay_apply_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
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

overlay_operation_v9_t operation_for(overlay_operation_kind_v9_t kind)
{
    overlay_operation_v9_t operation;
    operation.kind = kind;
    operation.range = range(0x100 + static_cast<std::uint8_t>(kind) * 0x20ULL);
    switch (kind) {
    case overlay_operation_kind_v9_t::comment:
        operation.payload.text = "fixture comment";
        break;
    case overlay_operation_kind_v9_t::name:
        operation.payload.name = "fixture_name";
        break;
    case overlay_operation_kind_v9_t::bookmark:
        operation.payload.name = "fixture bookmark";
        break;
    case overlay_operation_kind_v9_t::type_declaration:
        operation.range = {};
        operation.payload.name = "fixture_record";
        operation.payload.type = "struct fixture_record { std::uint32_t value; };";
        break;
    case overlay_operation_kind_v9_t::define_function:
        operation.range.size = 0x20;
        operation.payload.signature = "std::uint32_t fixture_entry()";
        break;
    case overlay_operation_kind_v9_t::define_code:
        operation.range.size = 4;
        break;
    case overlay_operation_kind_v9_t::define_data:
        operation.range.size = 8;
        operation.payload.type = "std::uint64_t";
        break;
    case overlay_operation_kind_v9_t::undefine:
        operation.range.size = 4;
        break;
    case overlay_operation_kind_v9_t::stack_variable:
        operation.payload.name = "local_value";
        operation.payload.type = "std::uint32_t";
        operation.payload.stack_offset = -8;
        break;
    case overlay_operation_kind_v9_t::delete_stack_variable:
        operation.payload.name = "retired_local";
        operation.payload.stack_offset = -16;
        break;
    case overlay_operation_kind_v9_t::type_application:
        operation.range.size = 4;
        operation.payload.name = "field_240";
        operation.payload.variable = "field_240";
        operation.payload.type = "std::uint16_t";
        break;
    case overlay_operation_kind_v9_t::byte_patch:
        operation.range.size = 2;
        operation.payload.bytes = {0xaa, 0xbb};
        break;
    case overlay_operation_kind_v9_t::assembly_patch:
        operation.payload.assembly = "nop";
        operation.payload.bytes = {0x90};
        break;
    case overlay_operation_kind_v9_t::integer_patch:
        operation.range.size = 2;
        operation.payload.bytes = {0x34, 0x12};
        operation.payload.integer_type = "u16le";
        operation.payload.integer_value = "4660";
        break;
    case overlay_operation_kind_v9_t::comment_update:
        operation.payload.text = "updated fixture comment";
        break;
    case overlay_operation_kind_v9_t::type_update:
        operation.range.size = 4;
        operation.payload.name = "field_2e0";
        operation.payload.variable = "field_2e0";
        operation.payload.type = "std::uint32_t";
        break;
    case overlay_operation_kind_v9_t::enum_definition:
        operation.range = {};
        operation.payload.name = "fixture_flags";
        operation.payload.type = "enum class fixture_flags : std::uint32_t { enabled = 1 };";
        break;
    case overlay_operation_kind_v9_t::reanalysis:
        operation.range.size = 0x20;
        operation.payload.reanalysis_flags = 3;
        break;
    }
    return operation;
}

const overlay_change_v9_t& change_for(const overlay_apply_result_v9_t& result,
                                      overlay_operation_kind_v9_t kind)
{
    const auto found = std::find_if(result.changes.begin(), result.changes.end(),
        [kind](const overlay_change_v9_t& change) {
            return change.operation_kind == kind;
        });
    if (found == result.changes.end())
        throw std::runtime_error("expected overlay change is missing");
    return *found;
}

void verify_ordinals_identity_and_round_trips()
{
    static_assert(std::is_trivially_copyable_v<overlay_target_identity_v9_t>);
    static_assert(sizeof(overlay_target_identity_v9_t) == 96);
    const auto identity = target();
    const auto target_serialized = serialize_overlay_target_identity_v9(identity);
    const auto target_decoded = deserialize_overlay_target_identity_v9(target_serialized);
    require(target_decoded && *target_decoded == identity, "target identity round-trip failed");

    for (std::uint8_t ordinal = 0; ordinal <= 17; ++ordinal) {
        const auto decoded_kind = overlay_operation_kind_from_ordinal(ordinal);
        require(decoded_kind && static_cast<std::uint8_t>(*decoded_kind) == ordinal,
                "overlay operation ordinal round-trip failed");
        require(is_legacy_overlay_operation_ordinal(ordinal) == (ordinal <= 13),
                "legacy ordinal boundary drifted");
        const overlay_operation_record_v9_t record{identity, operation_for(*decoded_kind)};
        const auto serialized = serialize_overlay_operation_record_v9(record);
        const auto decoded = deserialize_overlay_operation_record_v9(serialized);
        require(decoded && *decoded == record, "overlay operation record round-trip failed");
    }
    require(!overlay_operation_kind_from_ordinal(18), "invalid ordinal was accepted");

    auto fixture_operation = operation_for(overlay_operation_kind_v9_t::comment);
    fixture_operation.range = range(0x120);
    const std::string expected =
        "{\"operation\":{\"kind\":0,\"payload\":{\"assembly\":\"\",\"bytes\":\"\","
        "\"integer_type\":\"\",\"integer_value\":\"\",\"name\":\"\",\"reanalysis_flags\":0,"
        "\"signature\":\"\",\"stack_offset\":\"0\",\"text\":\"fixture comment\",\"type\":\"\","
        "\"variable\":\"\"},\"range\":{\"offset\":\"288\",\"size\":\"1\"},\"remove\":false},"
        "\"schema\":9,\"target\":{\"address_width\":8,\"architecture\":2,\"generation\":\"7\","
        "\"image_base\":\"5368709120\",\"image_hash\":\"3131313131313131313131313131313131313131313131313131313131313131\","
        "\"image_size\":\"16384\",\"kind\":1,\"provenance_hash\":\"6262626262626262626262626262626262626262626262626262626262626262\","
        "\"reserved\":0,\"schema\":9}}";
    require(serialize_overlay_operation_record_v9({identity, fixture_operation}) == expected,
            "schema v9 serialization fixture drifted");
    auto invalid_fixture = expected;
    const auto schema = invalid_fixture.find("\"schema\":9");
    require(schema != std::string::npos, "schema fixture marker is missing");
    invalid_fixture.replace(schema, 10, "\"schema\":8");
    require(!deserialize_overlay_operation_record_v9(invalid_fixture),
            "non-v9 serialization fixture was accepted");
}

void verify_apply_history_and_conflicts()
{
    overlay_static_state_v9_t state;
    const auto identity = target();
    require(overlay_apply_engine_v9_t::initialize(state, identity).ok(),
            "static state initialization failed");

    auto comment = operation_for(overlay_operation_kind_v9_t::comment);
    comment.range = range(0x120);
    comment.payload.text = "first comment";
    auto type_application = operation_for(overlay_operation_kind_v9_t::type_application);
    type_application.range = range(0x180, 2);
    type_application.payload.name = "field_180";
    type_application.payload.variable = "field_180";
    type_application.payload.type = "std::uint16_t";
    auto enum_value = operation_for(overlay_operation_kind_v9_t::enum_definition);
    enum_value.payload.type = "enum class fixture_flags : std::uint32_t { first = 1 };";
    auto reanalysis_value = operation_for(overlay_operation_kind_v9_t::reanalysis);
    reanalysis_value.range = range(0x200, 0x20);
    reanalysis_value.payload.reanalysis_flags = 1;
    auto patch = operation_for(overlay_operation_kind_v9_t::byte_patch);
    patch.range = range(0x240, 2);

    overlay_transaction_v9_t baseline;
    baseline.target = identity;
    baseline.expected_revision = 0;
    baseline.operations = {comment, type_application, enum_value, reanalysis_value, patch};
    const auto first = overlay_apply_engine_v9_t::apply(state, baseline);
    require(first.ok() && first.revision == 1 && first.transaction_id == 1 &&
            first.changes.size() == baseline.operations.size(),
            "baseline overlay transaction failed");
    for (const auto& change : first.changes)
        require(!change.before && change.after, "baseline change did not retain an after payload");

    overlay_transaction_v9_t stale = baseline;
    stale.operations = {comment};
    require(overlay_apply_engine_v9_t::apply(state, stale).code ==
                overlay_apply_code_v9_t::revision_conflict,
            "revision conflict was accepted");

    auto comment_update = operation_for(overlay_operation_kind_v9_t::comment_update);
    comment_update.range = comment.range;
    comment_update.payload.text = "second comment";
    auto type_update = operation_for(overlay_operation_kind_v9_t::type_update);
    type_update.range = range(type_application.range.offset, 4);
    type_update.payload.name = type_application.payload.name;
    type_update.payload.variable = type_application.payload.variable;
    type_update.payload.type = "std::uint32_t";
    auto enum_update = enum_value;
    enum_update.payload.type = "enum class fixture_flags : std::uint32_t { second = 2 };";
    auto reanalysis_update = reanalysis_value;
    reanalysis_update.payload.reanalysis_flags = 7;
    auto patch_update = patch;
    patch_update.payload.bytes = {0xcc, 0xdd};

    require(overlay_entity_key_for_operation_v9(type_application) ==
                overlay_entity_key_for_operation_v9(type_update),
            "type update does not target the prior type application");
    overlay_transaction_v9_t expansion;
    expansion.target = identity;
    expansion.expected_revision = 1;
    expansion.operations = {
        comment_update, type_update, enum_update, reanalysis_update, patch_update
    };
    const auto expanded = overlay_apply_engine_v9_t::apply(state, expansion);
    require(expanded.ok() && expanded.revision == 2 && expanded.changes.size() == 5,
            "expanded overlay transaction failed");

    const auto& comment_change = change_for(expanded, overlay_operation_kind_v9_t::comment_update);
    require(comment_change.before && comment_change.before->text == "first comment" &&
            comment_change.after && comment_change.after->text == "second comment",
            "comment update lost reversible payloads");
    const auto& type_change = change_for(expanded, overlay_operation_kind_v9_t::type_update);
    require(type_change.before && type_change.before->type == "std::uint16_t" &&
            type_change.after && type_change.after->type == "std::uint32_t",
            "type update did not replace the prior type application");
    const auto& enum_change = change_for(expanded, overlay_operation_kind_v9_t::enum_definition);
    require(enum_change.before && enum_change.before->type.find("first = 1") != std::string::npos &&
            enum_change.after && enum_change.after->type.find("second = 2") != std::string::npos,
            "enum definition did not retain before and after payloads");
    const auto& reanalysis_change = change_for(expanded, overlay_operation_kind_v9_t::reanalysis);
    require(reanalysis_change.before && reanalysis_change.before->reanalysis_flags == 1 &&
            reanalysis_change.after && reanalysis_change.after->reanalysis_flags == 7,
            "reanalysis request did not retain before and after flags");
    const auto& patch_change = change_for(expanded, overlay_operation_kind_v9_t::byte_patch);
    require(patch_change.before && patch_change.before->bytes == std::vector<std::uint8_t>({0xaa, 0xbb}) &&
            patch_change.after && patch_change.after->bytes == std::vector<std::uint8_t>({0xcc, 0xdd}),
            "byte patch did not retain before and after bytes");
    require(state.items.size() == 5, "updates created duplicate overlay entities");

    const auto undone = overlay_apply_engine_v9_t::undo(state, identity, 2);
    require(undone.ok() && undone.revision == 3 && state.items.size() == 5,
            "undo did not restore the preceding static overlay state");
    require(state.items.at(overlay_entity_key_for_operation_v9(type_application)).type ==
                "std::uint16_t",
            "undo restored the wrong type payload");
    require(state.items.at(overlay_entity_key_for_operation_v9(enum_value)).type.find("first = 1") !=
                std::string::npos,
            "undo restored the wrong enum payload");
    require(state.items.at(overlay_entity_key_for_operation_v9(reanalysis_value)).reanalysis_flags == 1,
            "undo restored the wrong reanalysis flags");
    require(state.items.at(overlay_entity_key_for_operation_v9(patch)).bytes ==
                std::vector<std::uint8_t>({0xaa, 0xbb}),
            "undo restored the wrong patch bytes");

    const auto redone = overlay_apply_engine_v9_t::redo(state, identity, 3);
    require(redone.ok() && redone.revision == 4 && state.items.size() == 5,
            "redo did not restore expanded overlay state");
    require(state.items.at(overlay_entity_key_for_operation_v9(type_update)).type ==
                "std::uint32_t",
            "redo restored the wrong type payload");
    require(state.items.at(overlay_entity_key_for_operation_v9(enum_update)).type.find("second = 2") !=
                std::string::npos,
            "redo restored the wrong enum payload");
    require(state.items.at(overlay_entity_key_for_operation_v9(reanalysis_update)).reanalysis_flags == 7,
            "redo restored the wrong reanalysis flags");
    require(state.items.at(overlay_entity_key_for_operation_v9(patch_update)).bytes ==
                std::vector<std::uint8_t>({0xcc, 0xdd}),
            "redo restored the wrong patch bytes");

    comment_update.payload = {};
    comment_update.remove = true;
    overlay_transaction_v9_t removal;
    removal.target = identity;
    removal.expected_revision = 4;
    removal.operations = {comment_update};
    const auto removed = overlay_apply_engine_v9_t::apply(state, removal);
    require(removed.ok() && removed.changes.size() == 1 && removed.changes[0].before &&
            !removed.changes[0].after, "removal did not retain before and after payloads");
    require(overlay_apply_engine_v9_t::undo(state, identity, 5).ok(),
            "undo did not restore removed payload");
}

void verify_static_and_generation_rejections()
{
    overlay_static_state_v9_t state;
    const auto identity = target();
    require(overlay_apply_engine_v9_t::initialize(state, identity).ok(),
            "fixture initialization failed");
    overlay_transaction_v9_t transaction;
    transaction.target = identity;
    transaction.expected_revision = 0;
    transaction.operations = {operation_for(overlay_operation_kind_v9_t::comment)};

    auto stale_target = identity;
    ++stale_target.generation;
    transaction.target = stale_target;
    require(overlay_apply_engine_v9_t::apply(state, transaction).code ==
                overlay_apply_code_v9_t::stale_generation,
            "stale generation was accepted");

    auto live_target = identity;
    live_target.kind = overlay_target_kind_v9_t::live_image;
    transaction.target = live_target;
    require(overlay_apply_engine_v9_t::apply(state, transaction).code ==
                overlay_apply_code_v9_t::static_target_required,
            "live target was accepted by static apply engine");

    overlay_static_state_v9_t overflow_state;
    require(overlay_apply_engine_v9_t::initialize(overflow_state, identity).ok(),
            "overflow fixture initialization failed");
    overflow_state.revision = (std::numeric_limits<std::uint64_t>::max)();
    transaction.target = identity;
    require(overlay_apply_engine_v9_t::apply(overflow_state, transaction).code ==
                overlay_apply_code_v9_t::revision_overflow,
            "revision overflow was accepted");

    overlay_static_state_v9_t invalid_generation_state;
    auto overflow_generation = identity;
    overflow_generation.generation = (std::numeric_limits<std::uint64_t>::max)();
    require(overlay_apply_engine_v9_t::initialize(invalid_generation_state, overflow_generation).code ==
                overlay_apply_code_v9_t::invalid_target,
            "overflow generation was accepted");
}

}

void run_overlay_journal_v9_harness()
{
    verify_ordinals_identity_and_round_trips();
    verify_apply_history_and_conflicts();
    verify_static_and_generation_rejections();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_overlay_journal_v9_harness();
        std::cout << "overlay_journal_v9_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
