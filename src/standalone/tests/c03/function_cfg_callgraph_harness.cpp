#include "function_cfg_callgraph_harness.hpp"

#include "../../src/core/analysis/call_graph_builder.hpp"
#include "../../src/core/analysis/workspace/advanced_cfg.hpp"
#include "../../src/core/analysis/workspace/function_recovery.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename T>
T require_value(workspace_result_t<T> result, std::string_view message)
{
    if (!result)
        throw std::runtime_error(std::string(message) + ": " + result.error().message);
    return result.take_value();
}

address_t address(std::uint64_t value,
                  architecture_id_t architecture = architecture_id_t::x86_64,
                  architecture_mode_t mode = architecture_mode_t::x86_64)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture;
    result.mode = mode;
    return result;
}

workspace_image_t image(architecture_id_t architecture,
                        architecture_mode_t mode,
                        std::uint64_t executable_start,
                        std::uint64_t executable_size)
{
    workspace_image_t result;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture;
    result.architecture_mode = mode;
    result.address_width_bits = architecture == architecture_id_t::x86_64 ? 64 : 32;
    result.image_base = 0x140000000ULL;
    result.image_size = executable_start + executable_size + 0x1000;
    image_section_t section;
    section.index = 1;
    section.name = ".text";
    section.virtual_address = executable_start;
    section.virtual_size = executable_size;
    section.file_size = executable_size;
    section.permissions = image_permission_read | image_permission_execute;
    result.sections.push_back(std::move(section));
    return result;
}

struct target_spec_t {
    std::uint64_t target_rva = 0;
    target_kind_record_t kind = target_kind_record_t::branch;
    bool direct = true;
    bool external = false;
};

void append_instruction(std::vector<instruction_record_t>& instructions,
                        std::vector<target_fact_t>& targets,
                        const address_t& instruction_address,
                        std::uint32_t flow_flags,
                        std::vector<target_spec_t> target_specs = {})
{
    instruction_record_t instruction;
    instruction.id = 0x100000ULL + instructions.size() + 1;
    instruction.address = instruction_address;
    instruction.length = 1;
    instruction.flow_flags = flow_flags;
    instruction.target_fact_begin = static_cast<std::uint32_t>(targets.size());
    instruction.target_fact_count = static_cast<std::uint16_t>(target_specs.size());
    instruction.provenance = fact_provenance_t::recursive_decode;
    instruction.confidence = 94;
    instruction.coverage = coverage_reason_t::decoded;
    instruction.stable_source_id = instruction.address.value;
    for (const auto& spec : target_specs) {
        target_fact_t target;
        target.instruction_id = instruction.id;
        target.target = address(spec.target_rva, instruction_address.architecture,
                                instruction_address.mode);
        target.kind = spec.kind;
        target.resolution = spec.external
            ? target_resolution_t::external_virtual
            : target_resolution_t::image_relative;
        target.direct = spec.direct;
        target.is_external = spec.external;
        targets.push_back(std::move(target));
    }
    instructions.push_back(std::move(instruction));
}

function_seed_t seed(std::uint64_t start, std::optional<std::uint64_t> end,
                     std::string name)
{
    function_seed_t result;
    result.address = address(start);
    if (end)
        result.known_end = address(*end);
    result.confidence = 91;
    result.stable_source_id = start;
    result.name = std::move(name);
    return result;
}

struct recovery_fixture_t {
    workspace_image_t normalized_image;
    std::vector<instruction_record_t> instructions;
    std::vector<target_fact_t> targets;
    function_recovery_result_t recovery;
};

std::uint64_t mix(std::uint64_t value) noexcept
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

std::uint64_t combine(std::uint64_t seed_value, std::uint64_t value) noexcept
{
    return mix(seed_value ^ (mix(value) + 0x9e3779b97f4a7c15ULL +
        (seed_value << 6U) + (seed_value >> 2U)));
}

std::uint64_t recovery_signature(const function_recovery_result_t& recovery) noexcept
{
    std::uint64_t value = 0x43a3c02ULL;
    value = combine(value, recovery.reachability_mark_slots);
    value = combine(value, recovery.reachability_passes);
    value = combine(value, recovery.synthetic_gap_functions);
    for (const auto& block : recovery.blocks) {
        value = combine(value, block.id);
        value = combine(value, block.function_id);
        value = combine(value, block.start.value);
        value = combine(value, block.end.value);
        value = combine(value, block.first_instruction);
        value = combine(value, block.instruction_count);
    }
    for (const auto& function : recovery.functions) {
        value = combine(value, function.id);
        value = combine(value, function.start.value);
        value = combine(value, function.end.value);
        value = combine(value, function.first_block);
        value = combine(value, function.block_count);
        value = combine(value, function.first_chunk);
        value = combine(value, function.chunk_count);
        value = combine(value, function.first_block_membership);
        value = combine(value, function.block_membership_count);
        value = combine(value, static_cast<std::uint64_t>(function.provenance));
        value = combine(value, function.confidence);
        value = combine(value, function.thunk ? 1 : 0);
        value = combine(value, function.noreturn ? 1 : 0);
    }
    for (const auto& chunk : recovery.function_chunks) {
        value = combine(value, chunk.id);
        value = combine(value, chunk.function_id);
        value = combine(value, chunk.start.value);
        value = combine(value, chunk.end.value);
        value = combine(value, chunk.first_block);
        value = combine(value, chunk.block_count);
        value = combine(value, chunk.shared ? 1 : 0);
    }
    for (const auto& membership : recovery.function_block_memberships) {
        value = combine(value, membership.function_id);
        value = combine(value, membership.chunk_id);
        value = combine(value, membership.block_id);
        value = combine(value, membership.block_index);
        value = combine(value, membership.ordinal);
        value = combine(value, membership.shared ? 1 : 0);
    }
    for (const auto& conflict : recovery.conflicts) {
        value = combine(value, static_cast<std::uint64_t>(conflict.kind));
        value = combine(value, conflict.rva);
        value = combine(value, conflict.related_rva);
        value = combine(value, conflict.selected_source_id);
        value = combine(value, conflict.competing_source_id);
        value = combine(value, conflict.selected_function_id);
        value = combine(value, conflict.competing_function_id);
    }
    return value;
}

recovery_fixture_t build_recovery_fixture(bool reverse_seed_order)
{
    recovery_fixture_t fixture;
    fixture.normalized_image = image(
        architecture_id_t::x86_64, architecture_mode_t::x86_64,
        0x1000, 0x1000);
    append_instruction(fixture.instructions, fixture.targets, address(0x1000),
        flow_branch | flow_direct, {{0x1040, target_kind_record_t::branch, true, false}});
    append_instruction(fixture.instructions, fixture.targets, address(0x1020),
        flow_branch | flow_direct, {{0x1040, target_kind_record_t::branch, true, false}});
    append_instruction(fixture.instructions, fixture.targets, address(0x1040),
        flow_return | flow_terminal);
    append_instruction(fixture.instructions, fixture.targets, address(0x1060),
        flow_branch | flow_direct, {{0x1080, target_kind_record_t::branch, true, false}});
    append_instruction(fixture.instructions, fixture.targets, address(0x1080),
        flow_return | flow_terminal);
    append_instruction(fixture.instructions, fixture.targets, address(0x10a0),
        flow_return | flow_terminal);
    append_instruction(fixture.instructions, fixture.targets, address(0x10c0),
        flow_call | flow_indirect | flow_fallthrough);
    append_instruction(fixture.instructions, fixture.targets, address(0x10c1),
        flow_return | flow_terminal);
    append_instruction(fixture.instructions, fixture.targets, address(0x10d0),
        flow_call | flow_direct | flow_fallthrough,
        {{0x1080, target_kind_record_t::call, true, false}});
    append_instruction(fixture.instructions, fixture.targets, address(0x10d1),
        flow_return | flow_terminal);
    append_instruction(fixture.instructions, fixture.targets, address(0x10e0),
        flow_call | flow_indirect | flow_fallthrough);
    append_instruction(fixture.instructions, fixture.targets, address(0x10e1),
        flow_return | flow_terminal);
    function_seed_sources_t sources;
    auto symbol = seed(0x1000, 0x1041, "symbol_entry");
    symbol.provenance = fact_provenance_t::debug_symbol;
    sources.symbols.push_back(symbol);
    auto exported = seed(0x1020, 0x1041, "export_entry");
    exported.provenance = fact_provenance_t::export_entry;
    sources.exports.push_back(exported);
    auto unwind = seed(0x1060, 0x1061, "unwind_thunk");
    unwind.provenance = fact_provenance_t::unwind_metadata;
    sources.unwind_ranges.push_back(unwind);
    auto call = seed(0x1080, std::nullopt, "call_target");
    call.provenance = fact_provenance_t::call_target;
    sources.call_targets.push_back(call);
    auto pointer = seed(0x10a0, std::nullopt, "pointer_target");
    pointer.provenance = fact_provenance_t::relocation;
    sources.pointer_targets.push_back(pointer);
    auto duplicate = seed(0x1000, std::nullopt, "pointer_duplicate");
    duplicate.provenance = fact_provenance_t::relocation;
    duplicate.confidence = 70;
    sources.pointer_targets.push_back(duplicate);
    function_recovery_limits_t limits;
    auto seeds = require_value(function_recovery_t::combine_seed_sources(
        sources, limits, {}), "seed source combination failed");
    if (reverse_seed_order)
        std::reverse(seeds.begin(), seeds.end());
    auto blocks = require_value(function_recovery_t::build_blocks(
        fixture.normalized_image, fixture.instructions, fixture.targets,
        seeds, limits, {}), "block recovery fixture failed");
    fixture.recovery = require_value(function_recovery_t::recover_functions(
        fixture.normalized_image, fixture.instructions, seeds,
        std::move(blocks), limits, {}), "function recovery fixture failed");
    return fixture;
}

const function_record_t& function_at(const function_recovery_result_t& recovery,
                                     std::uint64_t start)
{
    const auto found = std::find_if(recovery.functions.begin(), recovery.functions.end(),
        [&](const function_record_t& function) {
            return function.start.value == start;
        });
    require(found != recovery.functions.end(), "expected function was not recovered");
    return *found;
}

const basic_block_record_t& block_at(const function_recovery_result_t& recovery,
                                     std::uint64_t start)
{
    const auto found = std::find_if(recovery.blocks.begin(), recovery.blocks.end(),
        [&](const basic_block_record_t& block) {
            return block.start.value == start;
        });
    require(found != recovery.blocks.end(), "expected block was not recovered");
    return *found;
}

void test_seed_recovery_shared_tails_and_thunks()
{
    const auto forward = build_recovery_fixture(false);
    const auto reverse = build_recovery_fixture(true);
    require(recovery_signature(forward.recovery) ==
                recovery_signature(reverse.recovery),
            "shuffled seed order changed recovered functions or conflicts");
    require(forward.recovery.reachability_mark_slots ==
                forward.recovery.blocks.size() &&
                forward.recovery.reachability_passes >=
                    forward.recovery.functions.size(),
            "function recovery did not use one generation-mark table");
    const auto& first = function_at(forward.recovery, 0x1000);
    const auto& second = function_at(forward.recovery, 0x1020);
    const auto& thunk = function_at(forward.recovery, 0x1060);
    require(first.chunk_count >= 2 && second.chunk_count >= 2,
            "discontiguous function chunks were not recovered");
    require(thunk.thunk, "compact transfer thunk was not recognized");
    const auto& shared_tail = block_at(forward.recovery, 0x1040);
    std::size_t tail_memberships = 0;
    std::size_t shared_memberships = 0;
    for (const auto& membership : forward.recovery.function_block_memberships) {
        if (membership.block_id != shared_tail.id)
            continue;
        ++tail_memberships;
        if (membership.shared)
            ++shared_memberships;
    }
    require(tail_memberships == 2 && shared_memberships == 1 &&
                shared_tail.function_id == first.id,
            "shared tail ownership or secondary membership changed");
    const auto duplicate = std::find_if(forward.recovery.conflicts.begin(),
        forward.recovery.conflicts.end(), [](const function_recovery_conflict_t& conflict) {
            return conflict.kind ==
                function_recovery_conflict_kind_t::duplicate_seed;
        });
    const auto overlap = std::find_if(forward.recovery.conflicts.begin(),
        forward.recovery.conflicts.end(), [](const function_recovery_conflict_t& conflict) {
            return conflict.kind ==
                function_recovery_conflict_kind_t::overlapping_seed_ranges;
        });
    const auto ownership = std::find_if(forward.recovery.conflicts.begin(),
        forward.recovery.conflicts.end(), [](const function_recovery_conflict_t& conflict) {
            return conflict.kind ==
                function_recovery_conflict_kind_t::competing_block_ownership;
        });
    require(duplicate != forward.recovery.conflicts.end() &&
                overlap != forward.recovery.conflicts.end() &&
                ownership != forward.recovery.conflicts.end(),
            "deterministic seed or ownership conflicts were not retained");
}

void test_delay_slots()
{
    const auto normalized = image(
        architecture_id_t::mips, architecture_mode_t::mips32,
        0x1000, 0x1000);
    std::vector<instruction_record_t> instructions;
    std::vector<target_fact_t> targets;
    append_instruction(instructions, targets,
        address(0x1000, architecture_id_t::mips, architecture_mode_t::mips32),
        flow_branch | flow_conditional | flow_direct | flow_fallthrough,
        {{0x1010, target_kind_record_t::branch, true, false}});
    append_instruction(instructions, targets,
        address(0x1001, architecture_id_t::mips, architecture_mode_t::mips32),
        flow_none);
    append_instruction(instructions, targets,
        address(0x1002, architecture_id_t::mips, architecture_mode_t::mips32),
        flow_return | flow_terminal);
    append_instruction(instructions, targets,
        address(0x1010, architecture_id_t::mips, architecture_mode_t::mips32),
        flow_return | flow_terminal);
    function_seed_t entry;
    entry.address = address(0x1000, architecture_id_t::mips,
                            architecture_mode_t::mips32);
    entry.kind = function_seed_kind_t::image_entry;
    entry.provenance = fact_provenance_t::image_entry;
    entry.confidence = 100;
    function_recovery_limits_t limits;
    const std::vector<std::uint8_t> delays{1, 0, 0, 0};
    const auto blocks = require_value(function_recovery_t::build_blocks(
        normalized, instructions, targets, {entry}, delays, limits, {}),
        "delay-slot block recovery failed");
    require(blocks.blocks.size() == 3 &&
                blocks.blocks.front().instruction_count == 2 &&
                blocks.terminator_instruction_indices.front() == 0,
            "delay-slot transfer was not kept with its slot instruction");
    bool branch_edge = false;
    bool fallthrough_edge = false;
    for (const auto& edge : blocks.edges) {
        if (edge.source.value != 0x1000)
            continue;
        branch_edge = branch_edge ||
            (edge.target.value == 0x1010 &&
             edge.kind == edge_kind_t::conditional_taken);
        fallthrough_edge = fallthrough_edge ||
            (edge.target.value == 0x1002 &&
             edge.kind == edge_kind_t::fallthrough);
    }
    require(branch_edge && fallthrough_edge,
            "delay-slot transfer edges did not originate at the transfer instruction");
}

void append_cfg_instruction(analysis_snapshot_t& snapshot, std::uint64_t rva,
                            std::uint32_t flow_flags,
                            std::vector<target_spec_t> target_specs,
                            bool switch_operand)
{
    instruction_record_t instruction;
    instruction.id = 0x5000 + snapshot.instructions.size();
    instruction.address = address(rva);
    instruction.length = 1;
    instruction.flow_flags = flow_flags;
    instruction.provenance = fact_provenance_t::recursive_decode;
    instruction.confidence = 95;
    instruction.coverage = coverage_reason_t::decoded;
    instruction.stable_source_id = rva;
    if (switch_operand) {
        operand_fact_t operand;
        operand.id = 0x6000 + snapshot.operand_facts.size();
        operand.instruction_id = instruction.id;
        operand.kind = operand_kind_t::memory;
        operand.address_expression =
            address_expression_kind_t::base_index_displacement;
        operand.has_resolved_expression_value = true;
        operand.resolved_expression_value = 0x3000;
        operand.access_width_bits = 32;
        operand.relative = true;
        operand.address_resolution = target_resolution_t::image_relative;
        instruction.operand_fact_begin =
            static_cast<std::uint32_t>(snapshot.operand_facts.size());
        instruction.operand_fact_count = 1;
        snapshot.operand_facts.push_back(std::move(operand));
    }
    instruction.target_fact_begin =
        static_cast<std::uint32_t>(snapshot.target_facts.size());
    instruction.target_fact_count =
        static_cast<std::uint16_t>(target_specs.size());
    for (const auto& spec : target_specs) {
        target_fact_t target;
        target.instruction_id = instruction.id;
        target.target = address(spec.target_rva);
        target.kind = spec.kind;
        target.resolution = target_resolution_t::image_relative;
        target.direct = spec.direct;
        snapshot.target_facts.push_back(std::move(target));
    }
    snapshot.instructions.push_back(std::move(instruction));
}

void append_cfg_block(analysis_snapshot_t& snapshot, std::uint64_t id,
                      std::uint64_t function_id, std::uint64_t rva,
                      std::uint32_t instruction_index)
{
    basic_block_record_t block;
    block.id = id;
    block.function_id = function_id;
    block.start = address(rva);
    block.end = address(rva + 1);
    block.first_instruction = instruction_index;
    block.instruction_count = 1;
    block.provenance = fact_provenance_t::recursive_decode;
    block.confidence = 95;
    snapshot.blocks.push_back(std::move(block));
}

void append_cfg_edge(analysis_snapshot_t& snapshot, std::uint64_t source_block,
                     std::uint64_t target_block, std::uint64_t source_rva,
                     std::uint64_t target_rva, edge_kind_t kind)
{
    edge_record_t edge;
    edge.id = 0x7000 + snapshot.edges.size();
    edge.source_entity = source_block;
    edge.target_entity = target_block;
    edge.source = address(source_rva);
    edge.target = address(target_rva);
    edge.kind = kind;
    edge.provenance = fact_provenance_t::recursive_decode;
    edge.confidence = 95;
    snapshot.edges.push_back(std::move(edge));
}

analysis_snapshot_t build_cfg_snapshot()
{
    analysis_snapshot_t snapshot;
    snapshot.baseline_complete = true;
    snapshot.generation = 7;
    snapshot.analysis_revision = 11;
    snapshot.normalized_image = std::make_shared<const workspace_image_t>(
        image(architecture_id_t::x86_64, architecture_mode_t::x86_64,
              0x2000, 0x2000));
    constexpr entity_id_t function_id = 0x3001;
    constexpr entity_id_t block0 = 0x2001;
    constexpr entity_id_t block1 = 0x2002;
    constexpr entity_id_t block2 = 0x2003;
    constexpr entity_id_t block3 = 0x2004;
    constexpr entity_id_t block4 = 0x2005;
    append_cfg_instruction(snapshot, 0x2000, flow_fallthrough, {}, false);
    append_cfg_instruction(snapshot, 0x2010,
        flow_branch | flow_conditional | flow_direct | flow_fallthrough,
        {{0x2020, target_kind_record_t::branch, true, false}}, false);
    append_cfg_instruction(snapshot, 0x2020,
        flow_branch | flow_indirect,
        {{0x2010, target_kind_record_t::branch, false, false},
         {0x2030, target_kind_record_t::branch, false, false}}, true);
    append_cfg_instruction(snapshot, 0x2030,
        flow_branch | flow_direct,
        {{0x2010, target_kind_record_t::branch, true, false}}, false);
    append_cfg_instruction(snapshot, 0x2040,
        flow_return | flow_terminal, {}, false);
    append_cfg_block(snapshot, block0, function_id, 0x2000, 0);
    append_cfg_block(snapshot, block1, function_id, 0x2010, 1);
    append_cfg_block(snapshot, block2, function_id, 0x2020, 2);
    append_cfg_block(snapshot, block3, function_id, 0x2030, 3);
    append_cfg_block(snapshot, block4, function_id, 0x2040, 4);
    append_cfg_edge(snapshot, block0, block1, 0x2000, 0x2010,
                    edge_kind_t::fallthrough);
    append_cfg_edge(snapshot, block1, block2, 0x2010, 0x2020,
                    edge_kind_t::conditional_taken);
    append_cfg_edge(snapshot, block1, block4, 0x2010, 0x2040,
                    edge_kind_t::fallthrough);
    append_cfg_edge(snapshot, block2, block1, 0x2020, 0x2010,
                    edge_kind_t::indirect);
    append_cfg_edge(snapshot, block2, block3, 0x2020, 0x2030,
                    edge_kind_t::indirect);
    append_cfg_edge(snapshot, block3, block1, 0x2030, 0x2010,
                    edge_kind_t::unconditional);
    append_cfg_edge(snapshot, block1, block4, 0x2010, 0x2040,
                    edge_kind_t::exception_edge);
    function_record_t function;
    function.id = function_id;
    function.start = address(0x2000);
    function.end = address(0x2041);
    function.first_block = 0;
    function.block_count = 5;
    function.provenance = fact_provenance_t::debug_symbol;
    function.confidence = 98;
    snapshot.functions.push_back(std::move(function));
    return snapshot;
}

void test_cfg_dominance_loops_switches_exceptions_and_overlaps()
{
    const auto snapshot = build_cfg_snapshot();
    const auto cfg = require_value(analyze_advanced_cfg(snapshot, 0x2000, {}),
        "advanced CFG fixture failed");
    require(cfg.dominator_tree.complete &&
                cfg.dominator_tree.immediate_dominators.size() == 5 &&
                cfg.dominator_tree.immediate_dominators[1] == 0x2001,
            "CFG immediate dominance was not recovered");
    require(!cfg.loops.empty() && cfg.loops.front().header_block_id == 0x2002,
            "CFG natural loop header was not recovered");
    require(cfg.switches.size() == 1 &&
                cfg.switches.front().dispatch_block_id == 0x2003 &&
                cfg.switches.front().cases.size() == 2 &&
                cfg.switches.front().complete,
            "jump-table switch candidates were not recovered");
    const auto exception = std::find_if(cfg.exception_regions.begin(),
        cfg.exception_regions.end(), [](const exception_region_t& region) {
            return region.region_kind ==
                exception_region_kind_t::cfg_exception_edge;
        });
    require(exception != cfg.exception_regions.end(),
            "exception CFG edge did not produce an exception region");
    auto malformed = snapshot;
    malformed.blocks[1].start = malformed.blocks[0].start;
    malformed.blocks[1].end = address(0x2011);
    const auto rejected = analyze_advanced_cfg(malformed, 0x2000, {});
    require(!rejected &&
                rejected.error().code == workspace_error_code_t::integrity_failure,
            "malformed overlapping CFG blocks were accepted");
}

entity_id_t instruction_id_at(const recovery_fixture_t& fixture,
                              std::uint64_t rva)
{
    const auto found = std::find_if(fixture.instructions.begin(),
        fixture.instructions.end(), [&](const instruction_record_t& instruction) {
            return instruction.address.value == rva;
        });
    require(found != fixture.instructions.end(), "fixture instruction was absent");
    return found->id;
}

std::uint64_t call_graph_signature(const call_graph_result_t& graph) noexcept
{
    std::uint64_t value = 0xc4116a9ULL;
    value = combine(value, graph.indirect_site_count);
    value = combine(value, graph.unresolved_site_count);
    value = combine(value, graph.bounded ? 1 : 0);
    for (const auto& site : graph.call_sites) {
        value = combine(value, site.id);
        value = combine(value, site.source_function_id);
        value = combine(value, site.source_block_id);
        value = combine(value, site.instruction_id);
        value = combine(value, site.address.value);
        value = combine(value, site.first_candidate);
        value = combine(value, site.candidate_count);
        value = combine(value, site.indirect ? 1 : 0);
        value = combine(value, site.tail_call ? 1 : 0);
        value = combine(value, site.unresolved ? 1 : 0);
    }
    for (const auto& candidate : graph.candidates) {
        value = combine(value, candidate.call_site_id);
        value = combine(value, candidate.target.value);
        value = combine(value, candidate.target_function_id.value_or(0));
        value = combine(value, static_cast<std::uint64_t>(candidate.kind));
        value = combine(value, static_cast<std::uint64_t>(
            candidate.quality.provenance));
        value = combine(value, candidate.quality.confidence);
        value = combine(value, candidate.quality.contributor_count);
        value = combine(value, candidate.rank);
    }
    for (const auto& edge : graph.edges) {
        value = combine(value, edge.source_function_id);
        value = combine(value, edge.target_function_id.value_or(0));
        value = combine(value, edge.call_site.value);
        value = combine(value, edge.target.value);
        value = combine(value, static_cast<std::uint64_t>(edge.resolution));
        value = combine(value, edge.candidate_rank);
    }
    for (const auto& conflict : graph.conflicts) {
        value = combine(value, static_cast<std::uint64_t>(conflict.kind));
        value = combine(value, conflict.instruction_id);
        value = combine(value, conflict.source_function_id);
        value = combine(value, conflict.call_site_rva);
        value = combine(value, conflict.selected_target_rva);
        value = combine(value, conflict.competing_target_rva);
    }
    return value;
}

call_graph_result_t build_call_graph_fixture(const recovery_fixture_t& fixture,
                                             bool reverse_candidates)
{
    const auto instruction_id = instruction_id_at(fixture, 0x10c0);
    const auto& first_target = function_at(fixture.recovery, 0x1080);
    const auto& second_target = function_at(fixture.recovery, 0x10a0);
    std::vector<indirect_call_candidate_t> candidates;
    indirect_call_candidate_t vtable;
    vtable.instruction_id = instruction_id;
    vtable.call_site = address(0x10c0);
    vtable.target = address(0x1080);
    vtable.target_function_id = first_target.id;
    vtable.kind = indirect_call_candidate_kind_t::vtable;
    vtable.provenance = fact_provenance_t::decompiler_feedback;
    vtable.confidence = 88;
    vtable.stable_source_id = 10;
    candidates.push_back(vtable);
    indirect_call_candidate_t corroborating = vtable;
    corroborating.kind = indirect_call_candidate_kind_t::relocation;
    corroborating.provenance = fact_provenance_t::relocation;
    corroborating.confidence = 75;
    corroborating.stable_source_id = 11;
    candidates.push_back(corroborating);
    indirect_call_candidate_t pointer;
    pointer.instruction_id = instruction_id;
    pointer.call_site = address(0x10c0);
    pointer.target = address(0x10a0);
    pointer.target_function_id = second_target.id;
    pointer.kind = indirect_call_candidate_kind_t::pointer_scan;
    pointer.provenance = fact_provenance_t::relocation;
    pointer.confidence = 96;
    pointer.stable_source_id = 12;
    candidates.push_back(pointer);
    if (reverse_candidates)
        std::reverse(candidates.begin(), candidates.end());
    call_graph_builder_limits_t limits;
    return require_value(call_graph_builder_t::build(
        fixture.instructions, fixture.targets, fixture.recovery,
        candidates, limits, {}), "call graph fixture failed");
}

void test_call_graph_candidates_and_determinism()
{
    const auto fixture = build_recovery_fixture(false);
    const auto forward = build_call_graph_fixture(fixture, false);
    const auto reverse = build_call_graph_fixture(fixture, true);
    require(call_graph_signature(forward) == call_graph_signature(reverse),
            "shuffled indirect evidence changed the call graph");
    const auto site = std::find_if(forward.call_sites.begin(),
        forward.call_sites.end(), [](const recovered_call_site_t& candidate) {
            return candidate.address.value == 0x10c0;
        });
    require(site != forward.call_sites.end() && site->indirect &&
                site->candidate_count == 2,
            "indirect call candidate set was not retained");
    require(forward.candidates[site->first_candidate].target.value == 0x1080 &&
                forward.candidates[site->first_candidate].quality.contributor_count == 2,
            "indirect candidate ranking or evidence merge changed");
    require(forward.unresolved_site_count == 1,
            "unresolved indirect call site was not preserved");
    const auto direct = std::find_if(forward.edges.begin(), forward.edges.end(),
        [](const call_graph_edge_record_t& edge) {
            return edge.call_site.value == 0x10d0 &&
                edge.resolution == call_graph_resolution_t::direct &&
                edge.target.value == 0x1080;
        });
    const auto disagreement = std::find_if(forward.conflicts.begin(),
        forward.conflicts.end(), [](const call_graph_conflict_t& conflict) {
            return conflict.kind ==
                call_graph_conflict_kind_t::candidate_target_disagreement;
        });
    const auto unresolved = std::find_if(forward.conflicts.begin(),
        forward.conflicts.end(), [](const call_graph_conflict_t& conflict) {
            return conflict.kind ==
                call_graph_conflict_kind_t::unresolved_site;
        });
    require(direct != forward.edges.end() &&
                disagreement != forward.conflicts.end() &&
                unresolved != forward.conflicts.end(),
            "direct, conflicting, or unresolved call graph evidence was dropped");
}

}

bool run_function_cfg_callgraph_harness(std::string& failure)
{
    try {
        test_seed_recovery_shared_tails_and_thunks();
        test_delay_slots();
        test_cfg_dominance_loops_switches_exceptions_and_overlaps();
        test_call_graph_candidates_and_determinism();
        return true;
    } catch (const std::exception& error) {
        failure = error.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    return aida::analysis::c03::run_function_cfg_callgraph_harness(failure)
        ? 0 : 1;
}
