#include "overlay_journal_v9_harness.hpp"

#include "../../src/core/analysis/overlay_apply_engine.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

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

overlay_operation_v9_t comment(std::string text, bool remove = false)
{
    overlay_operation_v9_t result;
    result.kind = overlay_operation_kind_v9_t::comment;
    result.range = range(0x120);
    result.payload.text = std::move(text);
    result.remove = remove;
    return result;
}

overlay_operation_v9_t comment_update(std::string text, bool remove = false)
{
    auto result = comment(std::move(text), remove);
    result.kind = overlay_operation_kind_v9_t::comment_update;
    return result;
}

overlay_operation_v9_t type_update()
{
    overlay_operation_v9_t result;
    result.kind = overlay_operation_kind_v9_t::type_update;
    result.range = range(0x180, 4);
    result.payload.variable = "field_180";
    result.payload.type = "std::uint32_t";
    return result;
}

overlay_operation_v9_t enum_definition()
{
    overlay_operation_v9_t result;
    result.kind = overlay_operation_kind_v9_t::enum_definition;
    result.payload.name = "fixture_flags";
    result.payload.type = "enum class fixture_flags : std::uint32_t { enabled = 1 };";
    return result;
}

overlay_operation_v9_t reanalysis()
{
    overlay_operation_v9_t result;
    result.kind = overlay_operation_kind_v9_t::reanalysis;
    result.range = range(0x200, 0x20);
    result.payload.reanalysis_flags = 3;
    return result;
}

void verify_ordinals_and_identity()
{
    static_assert(std::is_trivially_copyable_v<overlay_target_identity_v9_t>);
    static_assert(sizeof(overlay_target_identity_v9_t) == 96);
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::comment) == 0,
            "legacy comment ordinal drifted");
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::integer_patch) == 13,
            "legacy integer patch ordinal drifted");
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::comment_update) == 14,
            "comment update ordinal is not appended");
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::type_update) == 15,
            "type update ordinal is not appended");
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::enum_definition) == 16,
            "enum ordinal is not appended");
    require(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::reanalysis) == 17,
            "reanalysis ordinal is not appended");
    for (std::uint8_t ordinal = 0; ordinal <= 13; ++ordinal) {
        const auto decoded = overlay_operation_kind_from_ordinal(ordinal);
        require(decoded.has_value() && static_cast<std::uint8_t>(*decoded) == ordinal,
                "legacy ordinal compatibility failed");
        require(is_legacy_overlay_operation_ordinal(ordinal), "legacy ordinal was not marked compatible");
    }
    require(!overlay_operation_kind_from_ordinal(18).has_value(), "invalid ordinal was accepted");
}

void verify_apply_history_and_conflicts()
{
    overlay_static_state_v9_t state;
    const auto identity = target();
    require(overlay_apply_engine_v9_t::initialize(state, identity).ok(), "static state initialization failed");

    overlay_transaction_v9_t first;
    first.target = identity;
    first.expected_revision = 0;
    first.operations = {comment("first comment")};
    const auto first_result = overlay_apply_engine_v9_t::apply(state, first);
    require(first_result.ok() && first_result.revision == 1 && first_result.transaction_id == 1,
            "legacy comment transaction failed");
    require(first_result.changes.size() == 1 && !first_result.changes[0].before &&
            first_result.changes[0].after && first_result.changes[0].after->text == "first comment",
            "first transaction did not retain before and after payloads");

    overlay_transaction_v9_t stale = first;
    stale.operations = {comment_update("must not apply")};
    require(overlay_apply_engine_v9_t::apply(state, stale).code == overlay_apply_code_v9_t::revision_conflict,
            "revision conflict was accepted");

    overlay_transaction_v9_t expansion;
    expansion.target = identity;
    expansion.expected_revision = 1;
    expansion.operations = {comment_update("second comment"), type_update(), enum_definition(), reanalysis()};
    const auto expanded = overlay_apply_engine_v9_t::apply(state, expansion);
    require(expanded.ok() && expanded.revision == 2 && expanded.changes.size() == 4,
            "expanded overlay transaction failed");
    require(expanded.changes[0].before && expanded.changes[0].before->text == "first comment" &&
            expanded.changes[0].after && expanded.changes[0].after->text == "second comment",
            "comment update lost its reversible payloads");

    const auto undone = overlay_apply_engine_v9_t::undo(state, identity, 2);
    require(undone.ok() && undone.revision == 3 && state.items.size() == 1,
            "undo did not restore the preceding static overlay state");
    require(state.items.begin()->second.text == "first comment", "undo restored the wrong comment payload");

    const auto redone = overlay_apply_engine_v9_t::redo(state, identity, 3);
    require(redone.ok() && redone.revision == 4 && state.items.size() == 4,
            "redo did not restore expanded overlay state");

    overlay_transaction_v9_t removal;
    removal.target = identity;
    removal.expected_revision = 4;
    removal.operations = {comment_update({}, true)};
    const auto removed = overlay_apply_engine_v9_t::apply(state, removal);
    require(removed.ok() && removed.changes.size() == 1 && removed.changes[0].before &&
            !removed.changes[0].after, "removal did not retain before and after payloads");
    require(overlay_apply_engine_v9_t::undo(state, identity, 5).ok(), "undo did not restore removed payload");
}

void verify_static_and_generation_rejections()
{
    overlay_static_state_v9_t state;
    const auto identity = target();
    require(overlay_apply_engine_v9_t::initialize(state, identity).ok(), "fixture initialization failed");
    overlay_transaction_v9_t transaction;
    transaction.target = identity;
    transaction.expected_revision = 0;
    transaction.operations = {comment("static-only")};

    auto stale_target = identity;
    ++stale_target.generation;
    transaction.target = stale_target;
    require(overlay_apply_engine_v9_t::apply(state, transaction).code == overlay_apply_code_v9_t::stale_generation,
            "stale generation was accepted");

    auto live_target = identity;
    live_target.kind = overlay_target_kind_v9_t::live_image;
    transaction.target = live_target;
    require(overlay_apply_engine_v9_t::apply(state, transaction).code == overlay_apply_code_v9_t::static_target_required,
            "live target was accepted by static apply engine");

    overlay_static_state_v9_t overflow_state;
    require(overlay_apply_engine_v9_t::initialize(overflow_state, identity).ok(), "overflow fixture initialization failed");
    overflow_state.revision = (std::numeric_limits<std::uint64_t>::max)();
    transaction.target = identity;
    require(overlay_apply_engine_v9_t::apply(overflow_state, transaction).code == overlay_apply_code_v9_t::revision_overflow,
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
    verify_ordinals_and_identity();
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
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
