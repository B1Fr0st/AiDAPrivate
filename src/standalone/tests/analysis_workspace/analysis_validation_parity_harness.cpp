#include "../../src/core/analysis/workspace/analysis_workspace.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <optional>
#include <process.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

struct harness_log_t {
    using clock_t = std::chrono::steady_clock;
    static unsigned long pid() { return static_cast<unsigned long>(_getpid()); }
    static unsigned long tid() { return static_cast<unsigned long>(std::hash<std::thread::id>{}(std::this_thread::get_id())); }
    static std::uint64_t epoch_ms() { return std::chrono::duration_cast<std::chrono::milliseconds>(clock_t::now().time_since_epoch()).count(); }
    static void emit(const char* test, const char* phase, const char* status, std::uint64_t elapsed_ms, const std::string& detail = {}) {
        std::fprintf(stderr, "[C03-HARNESS] test=%s phase=%s status=%s elapsed=%llums pid=%lu tid=%lu detail=%s\n",
            test, phase, status, static_cast<unsigned long long>(elapsed_ms), pid(), tid(),
            detail.empty() ? "-" : detail.c_str());
        std::fflush(stderr);
    }
};

namespace {

using namespace aida::analysis;

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

address_t rva(std::uint64_t value) {
    return address_t{address_space_id_t::relative_virtual, value,
        architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

entity_id_t tagged_id(std::uint8_t domain, std::uint64_t ordinal) {
    return (static_cast<entity_id_t>(domain) << 56U) | ordinal;
}

binary_id_t identity_bytes(std::uint8_t seed) {
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index)
        result.bytes[index] = static_cast<std::uint8_t>(seed + index);
    return result;
}

struct fixture_params_t {
    std::uint32_t function_count = 64;
    std::uint32_t instructions_per_function = 8;
    std::uint32_t exec_sections = 5;
    bool delay_slots = false;
};

constexpr std::uint64_t kSectionExtent = 0x1000;
constexpr std::uint64_t kImageBaseRva = 0x1000;

std::shared_ptr<analysis_snapshot_t> make_fixture(const fixture_params_t& params) {
    const auto function_count = params.function_count;
    const auto ipf = params.instructions_per_function;
    require(function_count >= 8 && ipf >= 8 && params.exec_sections >= 5,
        "fixture parameters are below the structural minimum");
    const std::uint64_t function_stride =
        params.delay_slots ? ipf * 4ULL : 0x100ULL;
    const std::uint64_t function_span = function_count * function_stride;
    const std::uint64_t function_sections =
        (function_span + kSectionExtent - 1ULL) / kSectionExtent;
    require(params.exec_sections >= function_sections,
        "fixture exec sections do not cover the function span");
    const auto rdata_rva = kImageBaseRva + params.exec_sections * kSectionExtent;

    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->binary_id = identity_bytes(0x31U);
    snapshot->load_profile_hash = identity_bytes(0xA7U);
    snapshot->generation = 77;
    snapshot->analysis_revision = 9;
    snapshot->overlay_revision = 4;
    snapshot->baseline_complete = true;

    auto image = std::make_shared<workspace_image_t>();
    image->schema_version = 1;
    image->format = format_id_t::pe32_plus;
    image->architecture = architecture_id_t::x86_64;
    image->architecture_mode = architecture_mode_t::x86_64;
    image->abi = abi_id_t::windows_x64;
    image->endian = endian_t::little;
    image->address_width_bits = 64;
    image->image_base = 0x140000000ULL;
    image->image_size = rdata_rva + kSectionExtent;
    image->header_size = 0x400;
    image->provider_size = 0x400 + (params.exec_sections + 1ULL) * kSectionExtent;
    image->format_name = "pe32plus";
    for (std::uint32_t section = 0; section < params.exec_sections; ++section) {
        image_section_t record;
        record.index = section;
        record.name = ".text" + std::to_string(section);
        record.virtual_address = kImageBaseRva + section * kSectionExtent;
        record.virtual_size = kSectionExtent;
        record.file_offset = 0x400 + section * kSectionExtent;
        record.file_size = kSectionExtent;
        record.permissions = image_permission_read | image_permission_execute;
        image->sections.push_back(record);
    }
    image_section_t rdata;
    rdata.index = params.exec_sections;
    rdata.name = ".rdata";
    rdata.virtual_address = rdata_rva;
    rdata.virtual_size = kSectionExtent;
    rdata.file_offset = 0x400 + params.exec_sections * kSectionExtent;
    rdata.file_size = kSectionExtent;
    rdata.permissions = image_permission_read;
    image->sections.push_back(rdata);
    snapshot->normalized_image = std::move(image);

    const auto instruction_address = [&](std::uint32_t function,
                                         std::uint32_t slot) {
        return 0x1000ULL + function * function_stride + slot * 4ULL;
    };
    const std::uint32_t instruction_total = function_count * ipf;
    for (std::uint32_t function = 0; function < function_count; ++function) {
        for (std::uint32_t slot = 0; slot < ipf; ++slot) {
            const auto index = function * ipf + slot;
            instruction_record_t record;
            record.id = tagged_id(1, index + 1ULL);
            record.address = rva(instruction_address(function, slot));
            record.length = 4;
            record.flow_flags = flow_fallthrough;
            if (slot + 2 == ipf)
                record.flow_flags = flow_call | flow_direct | flow_fallthrough;
            if (slot + 1 == ipf)
                record.flow_flags = flow_return | flow_terminal;
            if (params.delay_slots && function == 7 && slot == 4)
                record.flow_flags = flow_call | flow_indirect;
            record.provenance = fact_provenance_t::recursive_decode;
            record.confidence = 95;
            record.coverage = coverage_reason_t::decoded;
            record.operand_fact_begin = index;
            record.operand_fact_count = 1;
            record.target_fact_begin = index;
            record.target_fact_count = 1;
            record.stable_source_id = record.address.value;
            snapshot->instructions.push_back(record);

            operand_fact_t operand;
            operand.id = tagged_id(11, index + 1ULL);
            operand.instruction_id = record.id;
            operand.operand_index = 0;
            operand.kind = operand_kind_t::immediate;
            operand.bit_width = 64;
            operand.immediate = 0x1234;
            snapshot->operand_facts.append(operand, index);

            target_fact_t target;
            target.instruction_id = record.id;
            target.target = rva(instruction_address(
                (function + 1U) % function_count, 0));
            target.kind = target_kind_record_t::branch;
            snapshot->target_facts.push_back(target);
        }
    }
    if (params.delay_slots) {
        snapshot->delay_slot_counts.assign(instruction_total, 0);
        snapshot->delay_slot_counts[7 * ipf + 4] = 1;
    }

    for (std::uint32_t function = 0; function < function_count; ++function) {
        basic_block_record_t block;
        block.id = tagged_id(2, function + 1ULL);
        block.function_id = tagged_id(3, function + 1ULL);
        block.start = rva(instruction_address(function, 0));
        block.end = rva(instruction_address(function, 0) + ipf * 4ULL);
        block.first_instruction = function * ipf;
        block.instruction_count = ipf;
        block.provenance = fact_provenance_t::recursive_decode;
        block.confidence = 92;
        snapshot->blocks.push_back(block);
    }

    constexpr std::uint32_t kChunkedFunction = 2;
    for (std::uint32_t function = 0; function < function_count; ++function) {
        function_record_t record;
        record.id = tagged_id(3, function + 1ULL);
        record.start = rva(instruction_address(function, 0));
        record.end = rva(instruction_address(function, 0) + ipf * 4ULL);
        record.first_block = function;
        record.block_count = 1;
        record.symbol_id = tagged_id(7, function + 1ULL);
        record.provenance = fact_provenance_t::recursive_decode;
        record.confidence = 90;
        if (function == kChunkedFunction) {
            record.first_chunk = 0;
            record.chunk_count = 1;
            record.first_block_membership = 0;
            record.block_membership_count = 1;
            record.chunks.push_back(address_range_t{
                record.start.value, record.end.value,
                static_cast<std::uint8_t>(function_chunk_none)});
        }
        snapshot->functions.push_back(record);
    }
    {
        const auto& chunked = snapshot->functions[kChunkedFunction];
        function_chunk_record_t chunk;
        chunk.id = tagged_id(19, 1);
        chunk.function_id = chunked.id;
        chunk.start = chunked.start;
        chunk.end = chunked.end;
        chunk.first_block = kChunkedFunction;
        chunk.block_count = 1;
        chunk.provenance = fact_provenance_t::recursive_decode;
        chunk.confidence = 88;
        snapshot->function_chunks.push_back(chunk);
        function_block_membership_record_t membership;
        membership.function_id = chunked.id;
        membership.chunk_id = chunk.id;
        membership.block_id = tagged_id(2, kChunkedFunction + 1ULL);
        membership.block_index = kChunkedFunction;
        membership.ordinal = 0;
        membership.shared = false;
        snapshot->function_block_memberships.push_back(membership);
    }

    {
        edge_record_t edge;
        edge.id = tagged_id(4, 1);
        edge.source_entity = tagged_id(3, 1);
        edge.target_entity = tagged_id(3, 2);
        edge.source = rva(instruction_address(0, 0));
        edge.target = rva(instruction_address(1, 0));
        edge.kind = edge_kind_t::call;
        edge.provenance = fact_provenance_t::call_target;
        edge.confidence = 91;
        snapshot->edges.push_back(edge);
    }
    for (std::uint32_t index = 0; index < 2; ++index) {
        xref_record_t xref;
        xref.id = tagged_id(5, index + 1ULL);
        xref.source = rva(instruction_address(index, 2));
        xref.target = rva(instruction_address(index + 1U, 0));
        xref.kind = index == 0 ? xref_kind_t::call : xref_kind_t::read;
        xref.provenance = fact_provenance_t::recursive_decode;
        xref.confidence = 87;
        snapshot->xrefs.push_back(xref);
    }
    for (std::uint32_t index = 0; index < 2; ++index) {
        string_record_t string;
        string.id = tagged_id(6, index + 1ULL);
        string.address = rva(rdata_rva + 0x40 + index * 0x10ULL);
        string.byte_length = 4;
        string.encoding = string_encoding_t::ascii;
        string.value = index == 0 ? "str0" : "str1";
        string.provenance = fact_provenance_t::recursive_decode;
        string.confidence = 86;
        snapshot->strings.push_back(string);
    }
    for (std::uint32_t function = 0; function < function_count; ++function) {
        symbol_record_t symbol;
        symbol.id = tagged_id(7, function + 1ULL);
        symbol.address = rva(instruction_address(function, 0));
        symbol.name = "func_" + std::to_string(function);
        symbol.kind = symbol_kind_t::function;
        symbol.provenance = fact_provenance_t::debug_symbol;
        symbol.confidence = 94;
        snapshot->symbols.push_back(symbol);
    }

    for (std::uint32_t index = 0; index < 2; ++index) {
        data_candidate_record_t candidate;
        candidate.id = tagged_id(8, index + 1ULL);
        candidate.address = rva(rdata_rva + 0x20 + index * 0x8ULL);
        candidate.size = 8;
        candidate.kind = data_candidate_kind_t::referenced_storage;
        candidate.provenance = fact_provenance_t::relocation;
        candidate.confidence = 80;
        snapshot->rich_facts.data_candidates.push_back(candidate);
    }
    {
        data_pointer_fact_t pointer;
        pointer.id = tagged_id(12, 1);
        pointer.slot = rva(rdata_rva + 0x30);
        pointer.target = rva(0x1000);
        pointer.candidate_kind = data_candidate_kind_t::in_image_pointer;
        pointer.encoding = data_pointer_encoding_t::absolute_virtual;
        pointer.width_bytes = 8;
        pointer.provenance = fact_provenance_t::relocation;
        pointer.confidence = 82;
        snapshot->rich_facts.data_pointer_facts.push_back(pointer);
        data_candidate_conflict_t conflict;
        conflict.id = tagged_id(13, 1);
        conflict.address = rva(rdata_rva + 0x38);
        conflict.kind = data_candidate_kind_t::referenced_storage;
        conflict.selected_target = rva(0x1000);
        conflict.rejected_target = rva(0x1100);
        conflict.selected_provenance = fact_provenance_t::relocation;
        conflict.rejected_provenance = fact_provenance_t::debug_symbol;
        conflict.selected_confidence = 80;
        conflict.rejected_confidence = 70;
        snapshot->rich_facts.data_conflicts.push_back(conflict);
    }
    for (std::uint32_t index = 0; index < 2; ++index) {
        symbol_type_candidate_record_t candidate;
        candidate.id = tagged_id(10, index + 1ULL);
        candidate.kind = symbol_type_candidate_kind_t::global_object;
        candidate.display_name = index == 0 ? "TypeA" : "TypeB";
        candidate.canonical_type = index == 0 ? "struct TypeA" : "struct TypeB";
        candidate.source_key = index == 0 ? "keyA" : "keyB";
        candidate.provenance = metadata_provenance_t::debug_metadata;
        candidate.confidence = 85;
        candidate.explicitly_unknown = false;
        snapshot->rich_facts.type_candidates.push_back(candidate);
    }
    {
        type_reference_fact_t reference;
        reference.id = tagged_id(9, 1);
        reference.source_entity = tagged_id(10, 1);
        reference.target_entity = tagged_id(10, 2);
        reference.kind = type_reference_kind_t::definition;
        reference.provenance = metadata_provenance_t::decoded;
        reference.confidence = 80;
        reference.source_key = "keyA";
        snapshot->rich_facts.type_references.push_back(reference);
        metadata_conflict_record_t conflict;
        conflict.id = tagged_id(14, 1);
        conflict.identity = "sym0";
        conflict.kind = metadata_conflict_kind_t::symbol_kind;
        conflict.selected_value = "a";
        conflict.rejected_value = "b";
        conflict.selected_provenance = metadata_provenance_t::debug_metadata;
        conflict.rejected_provenance = metadata_provenance_t::rtti;
        conflict.selected_confidence = 90;
        conflict.rejected_confidence = 60;
        snapshot->rich_facts.metadata_conflicts.push_back(conflict);
    }

    for (std::uint32_t function = 0; function < function_count; ++function) {
        call_graph_node_record_t node;
        node.function_id = tagged_id(3, function + 1ULL);
        node.address = rva(instruction_address(function, 0));
        node.incoming_edges = function == 0 ? 0 : 1;
        node.outgoing_edges = function + 1U == function_count ? 0 : 1;
        snapshot->call_graph.nodes.push_back(node);
    }
    for (std::uint32_t function = 0; function + 1U < function_count; ++function) {
        const auto site_index = snapshot->call_graph.call_sites.size();
        const auto site_instruction = function * ipf + (ipf - 2U);
        recovered_call_site_t site;
        site.id = tagged_id(15, site_index + 1ULL);
        site.source_function_id = tagged_id(3, function + 1ULL);
        site.source_block_id = tagged_id(2, function + 1ULL);
        site.instruction_id = tagged_id(1, site_instruction + 1ULL);
        site.address = rva(instruction_address(function, ipf - 2U));
        site.first_candidate = static_cast<std::uint32_t>(site_index);
        site.candidate_count = 1;
        snapshot->call_graph.call_sites.push_back(site);

        recovered_call_candidate_t candidate;
        candidate.id = tagged_id(16, site_index + 1ULL);
        candidate.call_site_id = site.id;
        candidate.target = rva(instruction_address(function + 1U, 0));
        candidate.target_function_id = tagged_id(3, function + 2ULL);
        candidate.kind = indirect_call_candidate_kind_t::target_fact;
        candidate.quality.provenance = fact_provenance_t::call_target;
        candidate.quality.confidence = 89;
        candidate.quality.contributor_count = 1;
        candidate.rank = 0;
        snapshot->call_graph.candidates.push_back(candidate);

        call_graph_edge_record_t edge;
        edge.id = tagged_id(17, site_index + 1ULL);
        edge.call_site_id = site.id;
        edge.source_function_id = site.source_function_id;
        edge.source_block_id = site.source_block_id;
        edge.target_function_id = candidate.target_function_id;
        edge.call_site = site.address;
        edge.target = candidate.target;
        edge.resolution = call_graph_resolution_t::direct;
        edge.quality = candidate.quality;
        edge.candidate_rank = 0;
        snapshot->call_graph.edges.push_back(edge);
    }
    {
        call_graph_conflict_t conflict;
        conflict.id = tagged_id(18, 1);
        conflict.kind = call_graph_conflict_kind_t::candidate_limit;
        conflict.source_function_id = tagged_id(3, 1);
        snapshot->call_graph.conflicts.push_back(conflict);
    }

    for (std::uint32_t section = 0; section < params.exec_sections; ++section) {
        coverage_span_t span;
        span.start = rva(kImageBaseRva + section * kSectionExtent);
        span.size = kSectionExtent;
        span.reason = coverage_reason_t::decoded;
        span.provenance = fact_provenance_t::recursive_decode;
        span.confidence = 100;
        snapshot->coverage.push_back(span);
    }
    return snapshot;
}

struct mutation_case_t {
    std::string name;
    std::function<void(analysis_snapshot_t&)> apply;
    const char* message;
    bool delay_fixture = false;
    bool rich_facts_direct = false;
    bool call_graph_direct = false;
};

void expect_error(const workspace_result_t<void>& result,
                  const mutation_case_t& mutation, std::uint32_t workers,
                  const char* entry_point) {
    require(!result, mutation.name + ": validation unexpectedly passed at workers=" +
        std::to_string(workers) + " via " + entry_point);
    require(result.error().code == workspace_error_code_t::integrity_failure,
        mutation.name + ": error code diverged at workers=" +
        std::to_string(workers) + " via " + entry_point + ": " +
        result.error().stable_code());
    require(result.error().message == mutation.message,
        mutation.name + ": message diverged at workers=" +
        std::to_string(workers) + " via " + entry_point + ": \"" +
        result.error().message + "\"");
    require(result.error().phase == "snapshot_validate",
        mutation.name + ": phase diverged at workers=" +
        std::to_string(workers) + " via " + entry_point + ": " +
        result.error().phase);
}

void verify_mutation_matrix() {
    std::vector<mutation_case_t> cases;
    const auto add = [&](std::string name,
                         std::function<void(analysis_snapshot_t&)> apply,
                         const char* message, bool delay_fixture = false,
                         bool rich_direct = false, bool graph_direct = false) {
        cases.push_back(mutation_case_t{std::move(name), std::move(apply),
            message, delay_fixture, rich_direct, graph_direct});
    };

    add("identity_missing", [](analysis_snapshot_t& snapshot) {
            snapshot.binary_id = binary_id_t{};
        }, "snapshot workspace identity is missing");
    add("generation_zero", [](analysis_snapshot_t& snapshot) {
            snapshot.generation = 0;
        }, "snapshot generation is zero");
    add("baseline_incomplete", [](analysis_snapshot_t& snapshot) {
            snapshot.baseline_complete = false;
        }, "snapshot is not marked baseline complete");
    add("instructions_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.instructions[100], snapshot.instructions[101]);
        }, "instructions are not in deterministic unique order");
    add("delay_column_misaligned", [](analysis_snapshot_t& snapshot) {
            snapshot.delay_slot_counts.pop_back();
        }, "delay-slot column does not align with instructions", true);
    add("delay_metadata_malformed", [](analysis_snapshot_t& snapshot) {
            snapshot.delay_slot_counts[0] = 3;
        }, "delay-slot metadata is malformed", true);
    add("delay_sequence_malformed", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions[7 * 8 + 4].length = 8;
        }, "delay-slot instruction sequence is malformed", true);
    add("delay_double_claim_same_shard", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions[62].flow_flags = flow_call | flow_indirect;
            snapshot.delay_slot_counts[62] = 1;
            snapshot.delay_slot_counts[63] = 1;
        }, "delay-slot metadata is malformed", true);
    add("delay_double_claim_cross_shard", [](analysis_snapshot_t& snapshot) {
            snapshot.delay_slot_counts[63] = 2;
            snapshot.delay_slot_counts[64] = 1;
        }, "delay-slot metadata is malformed", true);
    add("delay_split_block", [](analysis_snapshot_t& snapshot) {
            snapshot.delay_slot_counts[63] = 2;
        }, "basic block splits a delay-slot sequence", true);
    add("entity_id_zero", [](analysis_snapshot_t& snapshot) {
            snapshot.strings[0].id = 0;
        }, "snapshot contains a zero or duplicate entity id");
    add("entity_id_duplicate", [](analysis_snapshot_t& snapshot) {
            snapshot.symbols[1].id = snapshot.symbols[0].id;
        }, "snapshot contains a zero or duplicate entity id");
    add("instruction_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions[150].confidence = 200;
        }, "compact instruction record is invalid");
    add("fact_range_broken_mid_shard", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions[200].operand_fact_begin += 1;
        }, "instruction fact range exceeds its table");
    add("fact_range_broken_shard_first", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions[64].operand_fact_begin += 1;
        }, "instruction fact range exceeds its table");
    add("fact_range_out_of_bounds", [](analysis_snapshot_t& snapshot) {
            snapshot.instructions.back().operand_fact_count = 2;
        }, "instruction fact range exceeds its table");
    add("orphan_instruction_facts", [](analysis_snapshot_t& snapshot) {
            const auto extra = operand_fact_materialize(snapshot.operand_facts,
                snapshot.operand_facts.size() - 1, snapshot.instructions);
            snapshot.operand_facts.append(extra,
                static_cast<std::uint32_t>(snapshot.instructions.size() - 1));
        }, "snapshot contains orphan instruction facts");
    add("operand_wrong_instruction", [](analysis_snapshot_t& snapshot) {
            snapshot.operand_facts.hot[100].operand_index = 5;
        }, "operand fact belongs to a different instruction");
    add("operand_memory_facts_on_nonmemory", [](analysis_snapshot_t& snapshot) {
            snapshot.operand_facts.hot[101].base_reg = 3;
        }, "non-memory operand contains memory-only facts");
    add("target_fact_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.target_facts[150].kind = static_cast<target_kind_record_t>(99);
        }, "target fact belongs to a different instruction");
    add("blocks_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.blocks[20], snapshot.blocks[21]);
        }, "snapshot fact tables are not in deterministic order");
    add("functions_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.functions[22], snapshot.functions[23]);
        }, "snapshot fact tables are not in deterministic order");
    add("xrefs_unsorted", [](analysis_snapshot_t& snapshot) {
            snapshot.xrefs.push_back(snapshot.xrefs[0]);
            snapshot.xrefs.back().id = tagged_id(5, 3);
        }, "snapshot fact tables are not in deterministic order");
    add("strings_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.strings[0], snapshot.strings[1]);
        }, "snapshot fact tables are not in deterministic order");
    add("symbols_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.symbols[5], snapshot.symbols[6]);
        }, "snapshot fact tables are not in deterministic order");
    add("block_without_instructions", [](analysis_snapshot_t& snapshot) {
            snapshot.blocks[30].instruction_count = 0;
        }, "basic block has no instructions");
    add("block_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.blocks[30].confidence = 200;
        }, "basic block record is invalid");
    add("block_end_mismatch", [](analysis_snapshot_t& snapshot) {
            snapshot.blocks[31].end.value += 0x40;
        }, "basic block end does not match its instruction range");
    add("block_instruction_range_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.blocks[32].start.value -= 4;
        }, "basic block instruction range is inconsistent");
    add("function_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.functions[10].confidence = 200;
        }, "function record is invalid");
    add("function_unknown_symbol", [](analysis_snapshot_t& snapshot) {
            snapshot.functions[11].symbol_id = tagged_id(7, 777);
        }, "function references an unknown symbol");
    add("function_foreign_block", [](analysis_snapshot_t& snapshot) {
            snapshot.functions[12].block_count = 2;
        }, "function block range contains a foreign block");
    add("function_zero_chunk_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.functions[14].first_chunk = 3;
        }, "function compact-IR ranges are inconsistent");
    add("chunk_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.function_chunks[0].confidence = 200;
        }, "function chunk record is invalid");
    add("primary_chunk_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.function_chunks[0].first_block = 99;
        }, "function primary chunk is inconsistent");
    add("membership_references_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.function_block_memberships[0].ordinal = 7;
        }, "function block membership references are inconsistent");
    add("orphan_compact_ir", [](analysis_snapshot_t& snapshot) {
            function_chunk_record_t extra;
            extra.id = tagged_id(19, 2);
            extra.function_id = tagged_id(3, 63);
            extra.start = rva(0x1000 + 62ULL * 0x100ULL);
            extra.end = rva(0x1000 + 62ULL * 0x100ULL + 0x20ULL);
            extra.first_block = 62;
            extra.block_count = 1;
            extra.provenance = fact_provenance_t::recursive_decode;
            extra.confidence = 80;
            snapshot.function_chunks.push_back(extra);
        }, "snapshot contains orphan function compact-IR records");
    add("edge_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.edges[0].kind = static_cast<edge_kind_t>(99);
        }, "edge record is invalid");
    add("edge_unknown_source", [](analysis_snapshot_t& snapshot) {
            snapshot.edges[0].source_entity = tagged_id(1, 999999);
        }, "edge references an unknown source entity");
    add("xref_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.xrefs[0].confidence = 200;
        }, "xref record is invalid");
    add("string_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.strings[0].byte_length = 0;
        }, "string record is invalid");
    add("symbol_record_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.symbols[0].name.clear();
        }, "symbol record is invalid");

    add("rich_data_candidate_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.data_candidates[0].size = 0;
        }, "published data candidate is invalid", false, true);
    add("rich_data_pointer_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.data_pointer_facts[0].width_bytes = 3;
        }, "published data pointer fact is invalid", false, true);
    add("rich_data_conflict_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.data_conflicts[0].rejected_target =
                snapshot.rich_facts.data_conflicts[0].selected_target;
        }, "published data conflict is invalid", false, true);
    add("rich_type_candidate_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.type_candidates[0].display_name.clear();
        }, "published symbol type candidate is invalid", false, true);
    add("rich_type_candidate_duplicate", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.type_candidates[1].id =
                snapshot.rich_facts.type_candidates[0].id;
        }, "published symbol type candidate is invalid", false, true);
    add("rich_type_reference_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.type_references[0].source_entity =
                tagged_id(10, 9999);
        }, "published type reference fact is invalid", false, true);
    add("rich_metadata_conflict_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.rich_facts.metadata_conflicts[0].selected_value =
                snapshot.rich_facts.metadata_conflicts[0].rejected_value;
        }, "published metadata conflict is invalid", false, true);

    add("graph_node_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.nodes[1].address = rva(0xDEAD);
        }, "published call graph node is invalid", false, false, true);
    add("graph_node_catalog_incomplete", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.nodes.pop_back();
        }, "published call graph node catalog is incomplete", false, false, true);
    add("graph_empty_nonempty_state", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.nodes.clear();
            snapshot.call_graph.call_sites.clear();
            snapshot.call_graph.candidates.clear();
            snapshot.call_graph.edges.clear();
            snapshot.call_graph.conflicts.clear();
            snapshot.call_graph.bounded = true;
        }, "empty call graph publication has nonempty state", false, false, true);
    add("graph_site_chain_broken_mid", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.call_sites[2].first_candidate += 1;
        }, "published call site is invalid", false, false, true);
    add("graph_site_chain_broken_shard_first", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.call_sites[8].first_candidate += 1;
        }, "published call site is invalid", false, false, true);
    add("graph_site_unresolved_mismatch", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.call_sites[0].candidate_count = 0;
        }, "published call site is invalid", false, false, true);
    add("graph_site_counters_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.indirect_site_count = 1;
        }, "published call graph site counters are inconsistent", false, false, true);
    add("graph_candidate_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.candidates[0].rank = 3;
        }, "published call candidate is invalid", false, false, true);
    add("graph_edge_candidate_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.edges[0].candidate_rank = 1;
        }, "published call edge candidate is invalid", false, false, true);
    add("graph_edge_candidate_mismatch", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.edges[0].target = rva(0x2000);
        }, "published call edge does not match its candidate", false, false, true);
    add("graph_edge_ranges_inconsistent", [](analysis_snapshot_t& snapshot) {
            auto& edge = snapshot.call_graph.edges[0];
            const auto& site = snapshot.call_graph.call_sites[1];
            edge.call_site_id = site.id;
            edge.source_function_id = site.source_function_id;
            edge.source_block_id = site.source_block_id;
            edge.call_site = site.address;
            const auto& candidate = snapshot.call_graph.candidates[1];
            edge.target = candidate.target;
            edge.target_function_id = candidate.target_function_id;
            edge.quality = candidate.quality;
        }, "published call graph edge ranges are inconsistent", false, false, true);
    add("graph_node_counters_inconsistent", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.nodes[0].outgoing_edges = 5;
        }, "published call graph node counters are inconsistent", false, false, true);
    add("graph_conflict_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.call_graph.conflicts[0].instruction_id = tagged_id(1, 999999);
        }, "published call graph conflict is invalid", false, false, true);

    add("coverage_span_invalid", [](analysis_snapshot_t& snapshot) {
            snapshot.coverage[0].confidence = 200;
        }, "coverage span is invalid");
    add("coverage_unsorted", [](analysis_snapshot_t& snapshot) {
            std::swap(snapshot.coverage[0], snapshot.coverage[1]);
        }, "snapshot fact tables are not in deterministic order");
    add("coverage_overlap", [](analysis_snapshot_t& snapshot) {
            snapshot.coverage[1].start.value -= 0x800;
        }, "coverage spans overlap or overflow");
    add("coverage_gap", [](analysis_snapshot_t& snapshot) {
            snapshot.coverage[1].start.value += 0x100;
            snapshot.coverage[1].size -= 0x100;
        }, "executable coverage contains a gap or overlap");
    add("coverage_pending", [](analysis_snapshot_t& snapshot) {
            snapshot.coverage[0].reason = coverage_reason_t::pending;
        }, "executable coverage contains pending or empty data");
    add("coverage_incomplete_range", [](analysis_snapshot_t& snapshot) {
            snapshot.coverage.pop_back();
        }, "executable coverage does not account for the full image range");

    std::size_t case_index = 0;
    for (const auto& mutation : cases) {
        ++case_index;
        fixture_params_t params;
        params.delay_slots = mutation.delay_fixture;
        std::optional<workspace_error_t> sequenced;
        for (const std::uint32_t workers : {1U, 8U}) {
            auto snapshot = make_fixture(params);
            mutation.apply(*snapshot);
            auto result = validate_analysis_snapshot_parallel(*snapshot, true,
                workers, {});
            expect_error(result, mutation, workers, "validate_analysis_snapshot");
            if (mutation.rich_facts_direct) {
                auto direct = validate_rich_fact_publication_parallel(*snapshot,
                    snapshot->rich_facts, workers, {});
                expect_error(direct, mutation, workers,
                    "validate_rich_fact_publication");
            }
            if (mutation.call_graph_direct) {
                auto direct = validate_call_graph_publication_parallel(*snapshot,
                    snapshot->call_graph, workers, {});
                expect_error(direct, mutation, workers,
                    "validate_call_graph_publication");
            }
            if (workers == 1U)
                sequenced = result.error();
            else {
                require(sequenced.has_value(), mutation.name + ": oracle capture failed");
                require(sequenced->code == result.error().code &&
                        sequenced->message == result.error().message &&
                        sequenced->phase == result.error().phase,
                    mutation.name + ": first-failure identity diverged between workers=1 and workers=8");
            }
        }
        harness_log_t::emit("validation_parity", "mutation", "pass", 0,
            std::to_string(case_index) + "/" + std::to_string(cases.size()) + " " +
            mutation.name);
    }
}

void verify_valid_fixtures() {
    for (const std::uint32_t workers : {0U, 1U, 8U}) {
        auto snapshot = make_fixture({});
        auto result = validate_analysis_snapshot_parallel(*snapshot, true, workers, {});
        require(static_cast<bool>(result), "valid fixture failed validation at workers=" +
            std::to_string(workers) + ": " +
            (result ? std::string() : result.error().message));
        auto relaxed = validate_analysis_snapshot_parallel(*snapshot, false,
            workers, {});
        require(static_cast<bool>(relaxed), "valid fixture failed relaxed validation at workers=" +
            std::to_string(workers));
        auto delay_snapshot = make_fixture(fixture_params_t{64U, 8U, 5U, true});
        auto delay_result = validate_analysis_snapshot_parallel(*delay_snapshot,
            true, workers, {});
        require(static_cast<bool>(delay_result), "valid delay-slot fixture failed validation at workers=" +
            std::to_string(workers) + ": " +
            (delay_result ? std::string() : delay_result.error().message));
        auto rich = validate_rich_fact_publication_parallel(*snapshot,
            snapshot->rich_facts, workers, {});
        require(static_cast<bool>(rich), "valid rich facts failed at workers=" + std::to_string(workers));
        auto graph = validate_call_graph_publication_parallel(*snapshot,
            snapshot->call_graph, workers, {});
        require(static_cast<bool>(graph), "valid call graph failed at workers=" + std::to_string(workers));
    }
    fixture_params_t large;
    large.function_count = 2048;
    large.exec_sections = 34;
    for (const std::uint32_t workers : {1U, 8U}) {
        auto snapshot = make_fixture(large);
        auto result = validate_analysis_snapshot_parallel(*snapshot, true, workers, {});
        require(static_cast<bool>(result), "large valid fixture failed validation at workers=" +
            std::to_string(workers) + ": " +
            (result ? std::string() : result.error().message));
    }
}

void verify_cancellation() {
    auto snapshot = make_fixture({});
    cancellation_source_t pre_cancelled;
    pre_cancelled.request_cancel();
    for (const std::uint32_t workers : {1U, 8U}) {
        auto result = validate_analysis_snapshot_parallel(*snapshot, true, workers,
            pre_cancelled.token());
        require(!result && result.error().code == workspace_error_code_t::cancelled &&
            result.error().cancellation &&
            result.error().phase == "snapshot_validate",
            "pre-cancelled snapshot validation envelope diverged at workers=" +
            std::to_string(workers));
        auto rich = validate_rich_fact_publication_parallel(*snapshot,
            snapshot->rich_facts, workers, pre_cancelled.token());
        require(!rich && rich.error().code == workspace_error_code_t::cancelled &&
            rich.error().cancellation &&
            rich.error().phase == "rich_fact_validate",
            "pre-cancelled rich fact validation envelope diverged at workers=" +
            std::to_string(workers));
        auto graph = validate_call_graph_publication_parallel(*snapshot,
            snapshot->call_graph, workers, pre_cancelled.token());
        require(!graph && graph.error().code == workspace_error_code_t::cancelled &&
            graph.error().cancellation &&
            graph.error().phase == "call_graph_validate",
            "pre-cancelled call graph validation envelope diverged at workers=" +
            std::to_string(workers));
    }
    cancellation_source_t expired(
        std::chrono::steady_clock::now() - std::chrono::seconds(1));
    for (const std::uint32_t workers : {1U, 8U}) {
        auto result = validate_analysis_snapshot_parallel(*snapshot, true, workers,
            expired.token());
        require(!result &&
            result.error().code == workspace_error_code_t::deadline_exceeded &&
            result.error().deadline,
            "expired-deadline validation envelope diverged at workers=" +
            std::to_string(workers));
    }
    fixture_params_t large;
    large.function_count = 8192;
    large.exec_sections = 130;
    auto stress = make_fixture(large);
    for (const std::uint32_t workers : {1U, 8U}) {
        cancellation_source_t source;
        std::atomic<bool> finished{false};
        std::thread canceller([&] {
            std::this_thread::sleep_for(std::chrono::microseconds(150));
            if (!finished.load(std::memory_order_acquire))
                source.request_cancel();
        });
        const auto started = harness_log_t::clock_t::now();
        auto result = validate_analysis_snapshot_parallel(*stress, true, workers,
            source.token());
        finished.store(true, std::memory_order_release);
        canceller.join();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            harness_log_t::clock_t::now() - started).count();
        require(elapsed_ms < 2000,
            "cancellation quiesce exceeded 2s at workers=" +
            std::to_string(workers));
        require(!result && result.error().code == workspace_error_code_t::cancelled &&
            result.error().cancellation,
            "mid-validation cancellation did not fail closed at workers=" +
            std::to_string(workers) +
            (result ? std::string(" (validation completed before the cancel landed)")
                    : std::string(" code=") + result.error().stable_code()));
    }
}

void verify_coverage_scaling_diagnostic() {
    for (const std::uint32_t sections : {64U, 256U}) {
        fixture_params_t params;
        params.exec_sections = sections;
        for (const std::uint32_t workers : {1U, 8U}) {
            auto snapshot = make_fixture(params);
            const auto started = harness_log_t::clock_t::now();
            auto result = validate_analysis_snapshot_parallel(*snapshot, true,
                workers, {});
            const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                harness_log_t::clock_t::now() - started).count();
            require(static_cast<bool>(result), "coverage scaling fixture failed at workers=" +
                std::to_string(workers));
            harness_log_t::emit("validation_parity", "coverage_scaling", "pass",
                static_cast<std::uint64_t>(elapsed_ms),
                "sections=" + std::to_string(sections) +
                " workers=" + std::to_string(workers));
        }
    }
}

}

int main() {
    const auto harness_start = harness_log_t::epoch_ms();
    harness_log_t::emit("validation_parity", "main", "enter", 0);
    try {
        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("validation_parity", "valid_fixtures", "enter", 0);
            verify_valid_fixtures();
            harness_log_t::emit("validation_parity", "valid_fixtures", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }
        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("validation_parity", "mutation_matrix", "enter", 0);
            verify_mutation_matrix();
            harness_log_t::emit("validation_parity", "mutation_matrix", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }
        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("validation_parity", "cancellation", "enter", 0);
            verify_cancellation();
            harness_log_t::emit("validation_parity", "cancellation", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }
        {
            const auto phase_start = harness_log_t::epoch_ms();
            harness_log_t::emit("validation_parity", "coverage_scaling", "enter", 0);
            verify_coverage_scaling_diagnostic();
            harness_log_t::emit("validation_parity", "coverage_scaling", "pass",
                harness_log_t::epoch_ms() - phase_start);
        }
        harness_log_t::emit("validation_parity", "main", "pass",
            harness_log_t::epoch_ms() - harness_start);
        std::printf("analysis_validation_parity_harness source contract satisfied\n");
        return 0;
    } catch (const std::exception& error) {
        const auto elapsed = harness_log_t::epoch_ms() - harness_start;
        harness_log_t::emit("validation_parity", "main", "fail", elapsed, error.what());
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    } catch (...) {
        const auto elapsed = harness_log_t::epoch_ms() - harness_start;
        harness_log_t::emit("validation_parity", "main", "fail", elapsed,
            "analysis validation parity harness failed with a non-standard exception");
        return 1;
    }
}
