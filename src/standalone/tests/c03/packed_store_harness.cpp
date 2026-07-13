#include "packed_store_harness.hpp"

#include "../../src/core/analysis/packed_analysis_store.hpp"

#include <cstdint>
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

template <typename value_t>
value_t require_value(packed_store_result_t<value_t> result, const char* message)
{
    if (!result)
        throw std::runtime_error(message);
    return std::move(result).take_value();
}

void require_success(packed_store_result_t<void> result, const char* message)
{
    if (!result)
        throw std::runtime_error(message);
}

address_t fixture_address(std::uint64_t value)
{
    address_t address;
    address.space = address_space_id_t::relative_virtual;
    address.value = value;
    address.architecture = architecture_id_t::x86_64;
    address.mode = architecture_mode_t::x86_64;
    return address;
}

packed_analysis_shard_t first_fixture()
{
    packed_analysis_shard_builder_t builder(11);

    packed_instruction_input_t second_instruction;
    second_instruction.source_id = 2;
    second_instruction.address = fixture_address(0x1010);
    second_instruction.length = 3;
    second_instruction.mnemonic_id = 12;
    second_instruction.mnemonic = "mov";
    second_instruction.opcode_id = 0x8b;
    second_instruction.flow_flags = flow_fallthrough;
    second_instruction.provenance = fact_provenance_t::recursive_decode;
    second_instruction.confidence = 93;
    second_instruction.stable_source_id = 0x1002;
    require_success(builder.add_instruction(second_instruction), "second instruction was rejected");

    packed_instruction_input_t first_instruction;
    first_instruction.source_id = 1;
    first_instruction.address = fixture_address(0x1000);
    first_instruction.length = 5;
    first_instruction.mnemonic_id = 10;
    first_instruction.mnemonic = "mov";
    first_instruction.opcode_id = 0xb8;
    first_instruction.flow_flags = flow_fallthrough;
    first_instruction.provenance = fact_provenance_t::linear_validation;
    first_instruction.confidence = 98;
    first_instruction.stable_source_id = 0x1001;
    require_success(builder.add_instruction(first_instruction), "first instruction was rejected");

    packed_operand_input_t operand;
    operand.source_id = 8;
    operand.instruction = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 2);
    operand.operand_index = 0;
    operand.decoder_operand_id = 4;
    operand.kind = operand_kind_t::reg;
    operand.access = 3;
    operand.bit_width = 64;
    operand.reg = 1;
    require_success(builder.add_operand(operand), "operand was rejected");

    packed_edge_input_t edge;
    edge.source_id = 4;
    edge.source_entity = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    edge.target_entity = packed_entity_reference_t::in_shard(
        packed_entity_domain_t::instruction, 12, 1);
    edge.source = fixture_address(0x1000);
    edge.target = fixture_address(0x2000);
    edge.kind = edge_kind_t::call;
    edge.provenance = fact_provenance_t::call_target;
    edge.confidence = 100;
    require_success(builder.add_edge(edge), "cross-shard edge was rejected");

    packed_string_input_t string_record;
    string_record.source_id = 3;
    string_record.address = fixture_address(0x3000);
    string_record.byte_length = 4;
    string_record.encoding = string_encoding_t::utf8;
    string_record.value = "main";
    string_record.provenance = fact_provenance_t::user_definition;
    string_record.confidence = 88;
    require_success(builder.add_string(string_record), "string record was rejected");

    packed_symbol_input_t symbol;
    symbol.source_id = 7;
    symbol.address = fixture_address(0x1000);
    symbol.name = "main";
    symbol.kind = symbol_kind_t::function;
    symbol.provenance = fact_provenance_t::debug_symbol;
    symbol.confidence = 97;
    require_success(builder.add_symbol(symbol), "symbol was rejected");

    return require_value(std::move(builder).finalize(), "first fixture finalization failed");
}

packed_analysis_shard_t second_fixture()
{
    packed_analysis_shard_builder_t builder(12);

    packed_instruction_input_t instruction;
    instruction.source_id = 1;
    instruction.address = fixture_address(0x2000);
    instruction.length = 5;
    instruction.mnemonic_id = 20;
    instruction.mnemonic = "call";
    instruction.opcode_id = 0xe8;
    instruction.flow_flags = flow_call | flow_direct | flow_fallthrough;
    instruction.provenance = fact_provenance_t::call_target;
    instruction.confidence = 96;
    instruction.stable_source_id = 0x2001;
    require_success(builder.add_instruction(instruction), "second fixture instruction was rejected");

    packed_operand_input_t operand;
    operand.source_id = 2;
    operand.instruction = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    operand.operand_index = 0;
    operand.decoder_operand_id = 6;
    operand.kind = operand_kind_t::pointer;
    operand.relative = true;
    operand.has_displacement = true;
    operand.displacement = 0x14;
    operand.address_expression_kind = address_expression_kind_t::instruction_relative;
    operand.address_resolution = target_resolution_t::image_relative;
    require_success(builder.add_operand(operand), "second fixture operand was rejected");

    packed_string_input_t string_record;
    string_record.source_id = 4;
    string_record.address = fixture_address(0x4000);
    string_record.byte_length = 4;
    string_record.encoding = string_encoding_t::utf8;
    string_record.value = "main";
    string_record.provenance = fact_provenance_t::debug_symbol;
    string_record.confidence = 85;
    require_success(builder.add_string(string_record), "second fixture string was rejected");

    packed_symbol_input_t symbol;
    symbol.source_id = 5;
    symbol.address = fixture_address(0x2000);
    symbol.name = "callee";
    symbol.kind = symbol_kind_t::function;
    symbol.provenance = fact_provenance_t::call_target;
    symbol.confidence = 90;
    require_success(builder.add_symbol(symbol), "second fixture symbol was rejected");

    return require_value(std::move(builder).finalize(), "second fixture finalization failed");
}

std::string signature(const packed_analysis_store_t& store)
{
    std::string result;
    result.append(std::to_string(store.string_pool().size()));
    for (std::size_t index = 0; index < store.instruction_count(); ++index) {
        const auto instruction = store.instruction(index);
        require(instruction.has_value(), "instruction view was absent");
        result.append("|i:");
        result.append(std::to_string(instruction->id.value()));
        result.push_back(':');
        result.append(std::to_string(instruction->address.value));
        result.push_back(':');
        result.append(instruction->mnemonic.data(), instruction->mnemonic.size());
        result.push_back(':');
        result.append(std::to_string(instruction->first_operand));
        result.push_back(':');
        result.append(std::to_string(instruction->operand_count));
    }
    for (std::size_t index = 0; index < store.operand_count(); ++index) {
        const auto operand = store.operand(index);
        require(operand.has_value(), "operand view was absent");
        result.append("|o:");
        result.append(std::to_string(operand->id.value()));
        result.push_back(':');
        result.append(std::to_string(operand->instruction_id.value()));
        result.push_back(':');
        result.append(std::to_string(operand->address_expression_id.value()));
    }
    for (std::size_t index = 0; index < store.edge_count(); ++index) {
        const auto edge = store.edge(index);
        require(edge.has_value(), "edge view was absent");
        result.append("|e:");
        result.append(std::to_string(edge->id.value()));
        result.push_back(':');
        result.append(std::to_string(edge->source_entity.value()));
        result.push_back(':');
        result.append(std::to_string(edge->target_entity ? edge->target_entity->value() : 0));
    }
    for (std::size_t index = 0; index < store.string_record_count(); ++index) {
        const auto string = store.string(index);
        require(string.has_value(), "string view was absent");
        result.append("|s:");
        result.append(std::to_string(string->id.value()));
        result.push_back(':');
        result.append(string->value.data(), string->value.size());
    }
    for (std::size_t index = 0; index < store.symbol_count(); ++index) {
        const auto symbol = store.symbol(index);
        require(symbol.has_value(), "symbol view was absent");
        result.append("|y:");
        result.append(std::to_string(symbol->id.value()));
        result.push_back(':');
        result.append(symbol->name.data(), symbol->name.size());
    }
    return result;
}

packed_analysis_store_t merged_fixture(bool reverse)
{
    std::vector<packed_analysis_shard_t> shards;
    if (reverse) {
        shards.push_back(second_fixture());
        shards.push_back(first_fixture());
    } else {
        shards.push_back(first_fixture());
        shards.push_back(second_fixture());
    }
    return require_value(packed_analysis_store_t::merge(std::move(shards)),
                         "fixture merge failed");
}

void verify_ids_and_string_pool()
{
    const auto id = require_value(
        packed_entity_id_t::make(packed_entity_domain_t::instruction, 0x1030, 0xdecafbad),
        "packed entity id creation failed");
    require(id.value() == 0x00011030decafbadULL, "packed entity id layout changed");
    require(id.parts() == packed_entity_id_parts_t{packed_entity_domain_t::instruction, 0x1030,
                                                    0xdecafbad},
            "packed entity id decomposition changed");
    require(!packed_entity_id_t::make(packed_entity_domain_t::invalid, 0, 1),
            "invalid packed entity domain was accepted");
    require(!packed_entity_id_t::make(packed_entity_domain_t::instruction, 0, 0),
            "zero packed entity ordinal was accepted");
    require(!packed_entity_id_t::make(packed_entity_domain_t::instruction, 0, 0x100000000ULL),
            "overflowing packed entity ordinal was accepted");

    packed_string_pool_builder_t builder;
    const auto first = require_value(builder.intern("repeat"), "first intern failed");
    const auto second = require_value(builder.intern("repeat"), "second intern failed");
    require(first == second && first.valid(), "interning did not deduplicate within a shard");
    const auto local_pool = require_value(builder.freeze(), "local pool freeze failed");
    require(local_pool.size() == 1 && local_pool.lookup(first) == std::optional<std::string_view>("repeat"),
            "local string pool did not preserve the interned value");
    const auto deterministic = require_value(
        packed_string_pool_t::build_deterministic({"zeta", "alpha", "zeta"}),
        "deterministic pool creation failed");
    require(deterministic.size() == 2 &&
            deterministic.lookup(packed_string_id_t::from_value(1)) ==
                std::optional<std::string_view>("alpha") &&
            deterministic.lookup(packed_string_id_t::from_value(2)) ==
                std::optional<std::string_view>("zeta"),
            "deterministic string pool order changed");
}

void verify_store_merge_and_compatibility()
{
    auto forward = merged_fixture(false);
    auto reverse = merged_fixture(true);
    require(forward.valid() && reverse.valid(), "merged store failed integrity validation");
    require(signature(forward) == signature(reverse), "shard merge order changed final packed output");
    require(forward.instruction_count() == 3 && forward.operand_count() == 2 &&
            forward.edge_count() == 1 && forward.string_record_count() == 2 &&
            forward.symbol_count() == 2,
            "fixture row counts changed");
    require(forward.string_pool().size() == 4, "global string interning did not deduplicate values");

    const auto first_instruction = forward.instruction(0);
    const auto second_instruction = forward.instruction(1);
    require(first_instruction && second_instruction && first_instruction->address.value == 0x1000 &&
            second_instruction->address.value == 0x1010 && first_instruction->operand_count == 0 &&
            second_instruction->operand_count == 1,
            "deterministic instruction order or operand range changed");
    const auto first_operand = forward.operand(0);
    require(first_operand && first_operand->instruction_id == second_instruction->id &&
            first_operand->kind == operand_kind_t::reg,
            "packed operand ownership changed");
    const auto edge = forward.edge(0);
    require(edge && edge->target_entity.has_value() &&
            edge->target_entity->parts().shard == 12 && edge->target_entity->parts().ordinal == 1,
            "cross-shard packed edge target changed");

    const auto compatibility = forward.compatibility_view();
    const auto instruction = compatibility.instruction(1);
    const auto operand = compatibility.operand(0);
    const auto compatibility_edge = compatibility.edge(0);
    const auto string = compatibility.string(0);
    const auto symbol = compatibility.symbol(0);
    require(instruction && operand && compatibility_edge && string && symbol &&
            instruction->id == second_instruction->id.value() &&
            operand->instruction_id == second_instruction->id.value() &&
            compatibility_edge->target_entity.has_value() && !string->value.empty() &&
            !symbol->name.empty(),
            "compatibility materialization changed packed fields");

    const auto sizes = forward.size_accounting();
    require(sizes.payload_bytes > 0 && sizes.reserved_bytes >= sizes.payload_bytes &&
            sizes.string_pool_bytes > 0 && sizes.instruction_bytes > 0 && sizes.operand_bytes > 0 &&
            sizes.edge_bytes > 0 && sizes.string_record_bytes > 0 && sizes.symbol_bytes > 0,
            "packed size accounting omitted stored columns");
}

void verify_rejections()
{
    std::vector<packed_analysis_shard_t> duplicate_shards;
    duplicate_shards.push_back(first_fixture());
    duplicate_shards.push_back(first_fixture());
    const auto duplicate = packed_analysis_store_t::merge(std::move(duplicate_shards));
    require(!duplicate &&
            duplicate.error().code == packed_store_error_code_t::duplicate_final_mirror,
            "duplicate final shard mirror was accepted");

    packed_analysis_shard_builder_t builder(13);
    packed_operand_input_t dangling;
    dangling.source_id = 1;
    dangling.instruction = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 77);
    require_success(builder.add_operand(dangling), "dangling operand fixture was rejected too early");
    std::vector<packed_analysis_shard_t> dangling_shards;
    dangling_shards.push_back(require_value(std::move(builder).finalize(),
                                            "dangling fixture finalization failed"));
    const auto merged = packed_analysis_store_t::merge(std::move(dangling_shards));
    require(!merged && merged.error().code == packed_store_error_code_t::dangling_reference,
            "dangling packed operand owner was accepted");

    const auto expected_source = require_value(
        packed_entity_id_t::make(packed_entity_domain_t::basic_block, 14, 9),
        "dangling edge source identifier creation failed");
    packed_analysis_shard_builder_t source_builder(14);
    packed_edge_input_t dangling_source;
    dangling_source.source_id = 1;
    dangling_source.source_entity = packed_entity_reference_t::local(
        packed_entity_domain_t::basic_block, 9);
    dangling_source.source = fixture_address(0x5000);
    dangling_source.target = fixture_address(0x5010);
    require_success(source_builder.add_edge(dangling_source),
                    "dangling edge source fixture was rejected too early");
    std::vector<packed_analysis_shard_t> source_shards;
    source_shards.push_back(require_value(std::move(source_builder).finalize(),
                                          "dangling edge source finalization failed"));
    const auto source_merged = packed_analysis_store_t::merge(std::move(source_shards));
    require(!source_merged &&
            source_merged.error().code == packed_store_error_code_t::dangling_reference &&
            source_merged.error().phase == "edge" && source_merged.error().shard == 14 &&
            source_merged.error().subject == expected_source.value(),
            "dangling edge source in an unmaterialized domain was accepted");

    const auto expected_target = require_value(
        packed_entity_id_t::make(packed_entity_domain_t::function, 15, 7),
        "dangling edge target identifier creation failed");
    packed_analysis_shard_builder_t target_builder(15);
    packed_instruction_input_t target_owner;
    target_owner.source_id = 1;
    target_owner.address = fixture_address(0x6000);
    require_success(target_builder.add_instruction(target_owner),
                    "dangling edge target owner was rejected");
    packed_edge_input_t dangling_target;
    dangling_target.source_id = 2;
    dangling_target.source_entity = packed_entity_reference_t::local(
        packed_entity_domain_t::instruction, 1);
    dangling_target.target_entity = packed_entity_reference_t::local(
        packed_entity_domain_t::function, 7);
    dangling_target.source = fixture_address(0x6000);
    dangling_target.target = fixture_address(0x7000);
    require_success(target_builder.add_edge(dangling_target),
                    "dangling edge target fixture was rejected too early");
    std::vector<packed_analysis_shard_t> target_shards;
    target_shards.push_back(require_value(std::move(target_builder).finalize(),
                                          "dangling edge target finalization failed"));
    const auto target_merged = packed_analysis_store_t::merge(std::move(target_shards));
    require(!target_merged &&
            target_merged.error().code == packed_store_error_code_t::dangling_reference &&
            target_merged.error().phase == "edge" && target_merged.error().shard == 15 &&
            target_merged.error().subject == expected_target.value(),
            "dangling edge target in an unmaterialized domain was accepted");
}

packed_analysis_shard_t new_domains_first_fixture()
{
    packed_analysis_shard_builder_t builder(20);

    packed_instruction_input_t instruction;
    instruction.source_id = 1;
    instruction.address = fixture_address(0x1000);
    instruction.length = 5;
    instruction.mnemonic_id = 10;
    instruction.mnemonic = "mov";
    instruction.opcode_id = 0xb8;
    instruction.flow_flags = flow_fallthrough;
    instruction.provenance = fact_provenance_t::linear_validation;
    instruction.confidence = 98;
    instruction.stable_source_id = 0x1001;
    require_success(builder.add_instruction(instruction), "new domain fixture instruction was rejected");

    packed_address_expression_input_t addr_expr;
    addr_expr.source_id = 3;
    addr_expr.instruction = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    addr_expr.base_reg = 1;
    addr_expr.index_reg = 0;
    addr_expr.scale = 1;
    addr_expr.displacement = 0x1000;
    addr_expr.address_components = address_component_base | address_component_displacement;
    addr_expr.kind = address_expression_kind_t::base_displacement;
    addr_expr.resolution = target_resolution_t::image_relative;
    addr_expr.provenance = fact_provenance_t::recursive_decode;
    addr_expr.confidence = 90;
    require_success(builder.add_address_expression(addr_expr),
                    "address_expression was rejected");

    packed_basic_block_input_t basic_block;
    basic_block.source_id = 2;
    basic_block.start_address = fixture_address(0x1000);
    basic_block.end_address = fixture_address(0x1010);
    basic_block.instruction_begin = 0;
    basic_block.instruction_count = 1;
    basic_block.predecessor_count = 1;
    basic_block.successor_count = 1;
    basic_block.flags = 0;
    basic_block.provenance = fact_provenance_t::linear_validation;
    basic_block.confidence = 95;
    require_success(builder.add_basic_block(basic_block), "basic_block was rejected");

    packed_function_input_t function;
    function.source_id = 4;
    function.start_address = fixture_address(0x1000);
    function.end_address = fixture_address(0x2000);
    function.entry_block = packed_entity_reference_t::local(packed_entity_domain_t::basic_block, 2);
    function.name = "test_func";
    function.chunk_count = 1;
    function.flags = 0;
    function.return_type_id = 0;
    function.provenance = fact_provenance_t::debug_symbol;
    function.confidence = 98;
    require_success(builder.add_function(function), "function was rejected");

    packed_function_chunk_input_t function_chunk;
    function_chunk.source_id = 5;
    function_chunk.function = packed_entity_reference_t::local(packed_entity_domain_t::function, 4);
    function_chunk.start_address = fixture_address(0x1000);
    function_chunk.end_address = fixture_address(0x2000);
    function_chunk.block_begin = 0;
    function_chunk.block_count = 1;
    function_chunk.flags = 0;
    function_chunk.provenance = fact_provenance_t::debug_symbol;
    function_chunk.confidence = 95;
    require_success(builder.add_function_chunk(function_chunk), "function_chunk was rejected");

    packed_target_fact_input_t target_fact;
    target_fact.source_id = 6;
    target_fact.instruction = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    target_fact.target = fixture_address(0x2000);
    target_fact.kind = target_kind_record_t::call;
    target_fact.resolution = target_resolution_t::image_relative;
    target_fact.operand_index = 0;
    target_fact.direct = true;
    target_fact.is_external = false;
    target_fact.provenance = fact_provenance_t::call_target;
    target_fact.confidence = 92;
    require_success(builder.add_target_fact(target_fact), "target_fact was rejected");

    packed_xref_input_t xref;
    xref.source_id = 7;
    xref.source_entity = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    xref.source_address = fixture_address(0x1000);
    xref.target_address = fixture_address(0x1000);
    xref.kind = xref_kind_t::code;
    xref.is_direct = true;
    xref.provenance = fact_provenance_t::linear_validation;
    xref.confidence = 88;
    require_success(builder.add_xref(xref), "xref was rejected");

    packed_coverage_input_t coverage;
    coverage.source_id = 8;
    coverage.span_begin = fixture_address(0x1000);
    coverage.span_end = fixture_address(0x2000);
    coverage.reason = coverage_reason_t::decoded;
    coverage.undecodable_count = 0;
    coverage.provenance = fact_provenance_t::linear_validation;
    coverage.confidence = 100;
    require_success(builder.add_coverage(coverage), "coverage was rejected");

    return require_value(std::move(builder).finalize(),
                         "new domains first fixture finalization failed");
}

packed_analysis_shard_t new_domains_second_fixture()
{
    packed_analysis_shard_builder_t builder(21);

    packed_basic_block_input_t basic_block;
    basic_block.source_id = 1;
    basic_block.start_address = fixture_address(0x2000);
    basic_block.end_address = fixture_address(0x3000);
    basic_block.instruction_begin = 0;
    basic_block.instruction_count = 0;
    basic_block.predecessor_count = 0;
    basic_block.successor_count = 0;
    basic_block.flags = 0;
    basic_block.provenance = fact_provenance_t::gap_recovery;
    basic_block.confidence = 80;
    require_success(builder.add_basic_block(basic_block),
                    "new domains second fixture basic_block was rejected");

    packed_coverage_input_t coverage;
    coverage.source_id = 1;
    coverage.span_begin = fixture_address(0x2000);
    coverage.span_end = fixture_address(0x3000);
    coverage.reason = coverage_reason_t::padding;
    coverage.undecodable_count = 2;
    coverage.provenance = fact_provenance_t::gap_recovery;
    coverage.confidence = 70;
    require_success(builder.add_coverage(coverage),
                    "new domains second fixture coverage was rejected");

    return require_value(std::move(builder).finalize(),
                         "new domains second fixture finalization failed");
}

void verify_new_domains()
{
    std::vector<packed_analysis_shard_t> shards;
    shards.push_back(new_domains_first_fixture());
    shards.push_back(new_domains_second_fixture());
    auto store = require_value(packed_analysis_store_t::merge(std::move(shards)),
                               "new domains merge failed");
    require(store.valid(), "new domains store failed integrity validation");

    require(store.address_expression_count() == 1, "address_expression count mismatch");
    require(store.basic_block_count() == 2, "basic_block count mismatch");
    require(store.function_count() == 1, "function count mismatch");
    require(store.function_chunk_count() == 1, "function_chunk count mismatch");
    require(store.target_fact_count() == 1, "target_fact count mismatch");
    require(store.xref_count() == 1, "xref count mismatch");
    require(store.coverage_count() == 2, "coverage count mismatch");

    const auto addr_expr = store.address_expression(0);
    require(addr_expr.has_value(), "address_expression view was absent");
    require(addr_expr->base_reg == 1 && addr_expr->displacement == 0x1000 &&
            addr_expr->kind == address_expression_kind_t::base_displacement &&
            addr_expr->instruction_id.valid() &&
            addr_expr->instruction_id.parts().domain == packed_entity_domain_t::instruction,
            "address_expression view fields changed");

    const auto block0 = store.basic_block(0);
    const auto block1 = store.basic_block(1);
    require(block0.has_value() && block1.has_value(), "basic_block views were absent");
    require(block0->start_address.value == 0x1000 && block0->end_address.value == 0x1010 &&
            block0->instruction_count == 1 && block0->predecessor_count == 1,
            "first basic_block view fields changed");
    require(block1->start_address.value == 0x2000 && block1->end_address.value == 0x3000 &&
            block1->predecessor_count == 0,
            "second basic_block view fields changed");

    const auto func = store.function(0);
    require(func.has_value(), "function view was absent");
    require(func->start_address.value == 0x1000 && func->end_address.value == 0x2000 &&
            func->name == "test_func" && func->chunk_count == 1 &&
            func->entry_block_id.valid() &&
            func->entry_block_id.parts().domain == packed_entity_domain_t::basic_block,
            "function view fields changed");

    const auto chunk = store.function_chunk(0);
    require(chunk.has_value(), "function_chunk view was absent");
    require(chunk->start_address.value == 0x1000 && chunk->end_address.value == 0x2000 &&
            chunk->block_count == 1 &&
            chunk->function_id.valid() &&
            chunk->function_id.parts().domain == packed_entity_domain_t::function,
            "function_chunk view fields changed");

    const auto tFact = store.target_fact(0);
    require(tFact.has_value(), "target_fact view was absent");
    require(tFact->target.value == 0x2000 && tFact->kind == target_kind_record_t::call &&
            tFact->direct && !tFact->is_external &&
            tFact->instruction_id.valid() &&
            tFact->instruction_id.parts().domain == packed_entity_domain_t::instruction,
            "target_fact view fields changed");

    const auto xr = store.xref(0);
    require(xr.has_value(), "xref view was absent");
    require(xr->source_address.value == 0x1000 && xr->target_address.value == 0x1000 &&
            xr->kind == xref_kind_t::code && xr->is_direct &&
            xr->source_entity.valid() &&
            xr->source_entity.parts().domain == packed_entity_domain_t::instruction,
            "xref view fields changed");

    const auto cov0 = store.coverage(0);
    const auto cov1 = store.coverage(1);
    require(cov0.has_value() && cov1.has_value(), "coverage views were absent");
    require(cov0->span_begin.value == 0x1000 && cov0->span_end.value == 0x2000 &&
            cov0->reason == coverage_reason_t::decoded && cov0->undecodable_count == 0,
            "first coverage view fields changed");
    require(cov1->span_begin.value == 0x2000 && cov1->span_end.value == 0x3000 &&
            cov1->reason == coverage_reason_t::padding && cov1->undecodable_count == 2,
            "second coverage view fields changed");

    const auto compat = store.compatibility_view();
    const auto compat_block = compat.basic_block(0);
    const auto compat_func = compat.function(0);
    const auto compat_chunk = compat.function_chunk(0);
    const auto compat_tfact = compat.target_fact(0);
    const auto compat_xref = compat.xref(0);
    const auto compat_cov = compat.coverage(0);
    require(compat_block && compat_func && compat_chunk && compat_tfact && compat_xref &&
            compat_cov,
            "compatibility view was absent for new domains");
    require(compat_block->id != 0 && compat_block->start.value == 0x1000 &&
            compat_block->end.value == 0x1010 && compat_block->instruction_count == 1,
            "compatibility basic_block fields changed");
    require(compat_func->id != 0 && compat_func->start.value == 0x1000 &&
            compat_func->end.value == 0x2000 && compat_func->chunk_count == 1,
            "compatibility function fields changed");
    require(compat_chunk->id != 0 && compat_chunk->function_id != 0 &&
            compat_chunk->start.value == 0x1000 && compat_chunk->block_count == 1,
            "compatibility function_chunk fields changed");
    require(compat_tfact->target.value == 0x2000 &&
            compat_tfact->kind == target_kind_record_t::call && compat_tfact->direct,
            "compatibility target_fact fields changed");
    require(compat_xref->id != 0 && compat_xref->source.value == 0x1000 &&
            compat_xref->kind == xref_kind_t::code,
            "compatibility xref fields changed");
    require(compat_cov->start.value == 0x1000 && compat_cov->size == 0x1000 &&
            compat_cov->reason == coverage_reason_t::decoded,
            "compatibility coverage fields changed");

    const auto sizes = store.size_accounting();
    require(sizes.payload_bytes > 0 && sizes.reserved_bytes >= sizes.payload_bytes,
            "new domains size accounting payload mismatch");
    require(sizes.address_expression_bytes > 0 && sizes.basic_block_bytes > 0 &&
            sizes.function_bytes > 0 && sizes.function_chunk_bytes > 0 &&
            sizes.target_fact_bytes > 0 && sizes.xref_bytes > 0 && sizes.coverage_bytes > 0,
            "new domains size accounting omitted domain columns");
}

void verify_new_domain_rejections()
{
    packed_analysis_shard_builder_t dup_builder(22);
    packed_basic_block_input_t block1;
    block1.source_id = 1;
    block1.start_address = fixture_address(0x1000);
    block1.end_address = fixture_address(0x1010);
    block1.provenance = fact_provenance_t::linear_validation;
    require_success(dup_builder.add_basic_block(block1), "first basic_block was rejected");
    packed_basic_block_input_t block2 = block1;
    require(!dup_builder.add_basic_block(block2), "duplicate basic_block source id was accepted");
    require(dup_builder.add_basic_block(block2).error().code ==
                packed_store_error_code_t::duplicate_source_id,
            "duplicate basic_block error code changed");

    packed_analysis_shard_builder_t bad_builder(23);
    packed_basic_block_input_t bad_block;
    bad_block.source_id = 1;
    bad_block.start_address = fixture_address(0x1000);
    bad_block.end_address = fixture_address(0x1010);
    bad_block.provenance = static_cast<fact_provenance_t>(200);
    require(!bad_builder.add_basic_block(bad_block), "invalid basic_block provenance was accepted");
    require(bad_builder.add_basic_block(bad_block).error().code ==
                packed_store_error_code_t::invalid_row,
            "invalid basic_block error code changed");

    packed_analysis_shard_builder_t bad_func_builder(24);
    packed_function_chunk_input_t bad_chunk;
    bad_chunk.source_id = 1;
    bad_chunk.function = packed_entity_reference_t::local(packed_entity_domain_t::instruction, 1);
    bad_chunk.start_address = fixture_address(0x1000);
    bad_chunk.end_address = fixture_address(0x2000);
    bad_chunk.provenance = fact_provenance_t::linear_validation;
    require(!bad_func_builder.add_function_chunk(bad_chunk),
            "function_chunk with wrong function domain was accepted");
    require(bad_func_builder.add_function_chunk(bad_chunk).error().code ==
                packed_store_error_code_t::invalid_row,
            "function_chunk wrong domain error code changed");

    packed_analysis_shard_builder_t bad_xref_builder(25);
    packed_xref_input_t bad_xref;
    bad_xref.source_id = 1;
    bad_xref.source_address = fixture_address(0x1000);
    bad_xref.target_address = fixture_address(0x2000);
    bad_xref.kind = static_cast<xref_kind_t>(200);
    bad_xref.provenance = fact_provenance_t::linear_validation;
    require(!bad_xref_builder.add_xref(bad_xref), "invalid xref kind was accepted");
    require(bad_xref_builder.add_xref(bad_xref).error().code ==
                packed_store_error_code_t::invalid_row,
            "invalid xref error code changed");

    packed_analysis_shard_builder_t bad_cov_builder(26);
    packed_coverage_input_t bad_cov;
    bad_cov.source_id = 1;
    bad_cov.span_begin = fixture_address(0x1000);
    bad_cov.span_end = fixture_address(0x2000);
    bad_cov.reason = static_cast<coverage_reason_t>(200);
    bad_cov.provenance = fact_provenance_t::linear_validation;
    require(!bad_cov_builder.add_coverage(bad_cov), "invalid coverage reason was accepted");
    require(bad_cov_builder.add_coverage(bad_cov).error().code ==
                packed_store_error_code_t::invalid_row,
            "invalid coverage error code changed");

    packed_analysis_shard_builder_t bad_tfact_builder(27);
    packed_target_fact_input_t bad_tfact;
    bad_tfact.source_id = 1;
    bad_tfact.target = fixture_address(0x2000);
    bad_tfact.kind = static_cast<target_kind_record_t>(200);
    bad_tfact.provenance = fact_provenance_t::linear_validation;
    require(!bad_tfact_builder.add_target_fact(bad_tfact), "invalid target_fact kind was accepted");
    require(bad_tfact_builder.add_target_fact(bad_tfact).error().code ==
                packed_store_error_code_t::invalid_row,
            "invalid target_fact error code changed");

    packed_analysis_shard_builder_t bad_expr_builder(28);
    packed_address_expression_input_t bad_expr;
    bad_expr.source_id = 1;
    bad_expr.kind = static_cast<address_expression_kind_t>(200);
    bad_expr.provenance = fact_provenance_t::linear_validation;
    require(!bad_expr_builder.add_address_expression(bad_expr),
            "invalid address_expression kind was accepted");
    require(bad_expr_builder.add_address_expression(bad_expr).error().code ==
                packed_store_error_code_t::invalid_row,
            "invalid address_expression error code changed");
}

}

void run_packed_store_harness()
{
    verify_ids_and_string_pool();
    verify_store_merge_and_compatibility();
    verify_rejections();
    verify_new_domains();
    verify_new_domain_rejections();
}

}
