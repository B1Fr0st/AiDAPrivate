#pragma once

#include "workspace_fixture_builder.hpp"

#include "../../src/core/analysis/workspace/compact_ir.hpp"
#include "../../src/core/analysis/workspace/function_recovery.hpp"
#include "../../src/core/analysis/workspace/search_index.hpp"
#include "../c03/evidence_hash.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::test_fixture {

class fnv1a64_t {
public:
    void byte(std::uint8_t value) noexcept
    {
        hash_ ^= value;
        hash_ *= prime;
    }

    void bytes(const void* data, std::size_t size) noexcept
    {
        const auto* first = static_cast<const std::uint8_t*>(data);
        for (std::size_t index = 0; index < size; ++index)
            byte(first[index]);
    }

    void u16(std::uint16_t value) noexcept
    {
        byte(static_cast<std::uint8_t>(value & 0xFFU));
        byte(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    }

    void u32(std::uint32_t value) noexcept
    {
        byte(static_cast<std::uint8_t>(value & 0xFFU));
        byte(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
        byte(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
        byte(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
    }

    void u64(std::uint64_t value) noexcept
    {
        u32(static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
        u32(static_cast<std::uint32_t>((value >> 32) & 0xFFFFFFFFULL));
    }

    void i64(std::int64_t value) noexcept
    {
        u64(static_cast<std::uint64_t>(value));
    }

    void boolean(bool value) noexcept
    {
        byte(value ? 1 : 0);
    }

    void address(const address_t& value) noexcept
    {
        u32(static_cast<std::uint32_t>(value.space));
        u64(value.value);
    }

    template <typename T, typename Fn>
    void optional(const std::optional<T>& value, Fn&& payload) noexcept
    {
        boolean(value.has_value());
        if (value)
            payload(*value);
    }

    void string(const std::string& value) noexcept
    {
        u64(value.size());
        bytes(value.data(), value.size());
    }

    std::uint64_t value() const noexcept { return hash_; }

private:
    static constexpr std::uint64_t offset_basis = 14695981039346656037ULL;
    static constexpr std::uint64_t prime = 1099511628211ULL;
    std::uint64_t hash_ = offset_basis;
};

struct snapshot_hash_input_t {
    const analysis_snapshot_t* snapshot = nullptr;
    const std::vector<data_candidate_record_t>* data_candidates = nullptr;
    const std::vector<switch_record_t>* switches = nullptr;
    const std::vector<type_candidate_record_t>* types = nullptr;
    sha256_digest_t content_hash{};
};

struct snapshot_hash_class_digest_t {
    std::uint64_t count = 0;
    std::uint64_t fnv = 0;
};

struct snapshot_hash_result_t {
    std::map<std::string, snapshot_hash_class_digest_t> classes;
    std::string manifest_sha256;

    nlohmann::json manifest_json() const
    {
        nlohmann::json classes_json = nlohmann::json::object();
        for (const auto& entry : classes) {
            classes_json[entry.first] = nlohmann::json{
                {"count", entry.second.count},
                {"fnv1a64", fnv_hex(entry.second.fnv)}};
        }
        return nlohmann::json{
            {"hash_contract", "aida.hyperperf.snapshot-hash"},
            {"version", 1},
            {"classes", std::move(classes_json)},
            {"manifest_sha256", manifest_sha256}};
    }

    static std::string fnv_hex(std::uint64_t value)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string hex(16, '0');
        for (int shift = 60; shift >= 0; shift -= 4)
            hex[(60 - shift) / 4] = digits[(value >> shift) & 0xF];
        return hex;
    }
};

namespace detail {

inline void hash_address_opt(fnv1a64_t& hash, const std::optional<address_t>& value)
{
    hash.optional<address_t>(value, [&hash](const address_t& address) {
        hash.address(address);
    });
}

inline void hash_entity_opt(fnv1a64_t& hash, const std::optional<entity_id_t>& value)
{
    hash.optional<entity_id_t>(value, [&hash](const entity_id_t& id) {
        hash.u64(id);
    });
}

inline void hash_instruction(fnv1a64_t& hash, const instruction_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.address);
    hash.byte(record.length);
    hash.u16(record.mnemonic_id);
    hash.u32(record.opcode_id);
    hash.u32(record.flow_flags);
    hash.u32(record.operand_fact_begin);
    hash.u16(record.operand_fact_count);
    hash.u32(record.target_fact_begin);
    hash.u16(record.target_fact_count);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
    hash.byte(static_cast<std::uint8_t>(record.coverage));
    hash.u64(record.stable_source_id);
}

inline void hash_operand_fact(fnv1a64_t& hash, const operand_fact_t& record)
{
    hash.u64(record.id);
    hash.u64(record.instruction_id);
    hash.u64(record.address_expression_id);
    hash.byte(record.operand_index);
    hash.byte(record.decoder_operand_id);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.byte(record.access);
    hash.byte(record.visibility);
    hash.byte(record.encoding);
    hash.byte(record.memory_type);
    hash.byte(record.access_width);
    hash.u16(record.bit_width);
    hash.u16(record.access_width_bits);
    hash.u16(record.access_count);
    hash.u16(record.element_width_bits);
    hash.u16(record.element_count);
    hash.u16(record.address_width_bits);
    hash.u16(record.reg);
    hash.u16(record.segment_reg);
    hash.u16(record.base_reg);
    hash.u16(record.index_reg);
    hash.byte(record.scale);
    hash.boolean(record.relative);
    hash.boolean(record.signed_value);
    hash.boolean(record.has_displacement);
    hash.boolean(record.has_resolved_expression_value);
    hash.i64(record.displacement);
    hash.u64(record.immediate);
    hash.u64(record.resolved_expression_value);
    hash.u16(record.address_components);
    hash.byte(static_cast<std::uint8_t>(record.address_expression));
    hash.byte(static_cast<std::uint8_t>(record.address_resolution));
}

inline void hash_target_fact(fnv1a64_t& hash, const target_fact_t& record)
{
    hash.u64(record.instruction_id);
    hash.u64(record.operand_fact_id);
    hash.u64(record.address_expression_id);
    hash.address(record.target);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.byte(static_cast<std::uint8_t>(record.resolution));
    hash.byte(record.operand_index);
    hash.u16(record.access_width_bits);
    hash.u16(record.access_count);
    hash.boolean(record.direct);
    hash.boolean(record.is_external);
}

inline void hash_block(fnv1a64_t& hash, const basic_block_record_t& record)
{
    hash.u64(record.id);
    hash.u64(record.function_id);
    hash.address(record.start);
    hash.address(record.end);
    hash.u32(record.first_instruction);
    hash.u32(record.instruction_count);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_chunk(fnv1a64_t& hash, const function_chunk_record_t& record)
{
    hash.u64(record.id);
    hash.u64(record.function_id);
    hash.address(record.start);
    hash.address(record.end);
    hash.u32(record.first_block);
    hash.u32(record.block_count);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
    hash.boolean(record.cold);
    hash.boolean(record.shared);
}

inline void hash_membership(fnv1a64_t& hash,
                            const function_block_membership_record_t& record)
{
    hash.u64(record.function_id);
    hash.u64(record.chunk_id);
    hash.u64(record.block_id);
    hash.u32(record.block_index);
    hash.u32(record.ordinal);
    hash.boolean(record.shared);
}

inline void hash_function(fnv1a64_t& hash, const analysis_snapshot_t& snapshot,
                          const function_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.start);
    hash.address(record.end);
    hash.u32(record.first_block);
    hash.u32(record.block_count);
    hash.u32(record.first_chunk);
    hash.u32(record.chunk_count);
    hash.u32(record.first_block_membership);
    hash.u32(record.block_membership_count);
    hash_entity_opt(hash, record.symbol_id);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
    hash.boolean(record.thunk);
    hash.boolean(record.noreturn);
    const auto chunks = snapshot.function_chunks_of(record);
    hash.u64(chunks.size());
    for (const auto& chunk : chunks) {
        hash.u64(chunk.rva_start);
        hash.u64(chunk.rva_end);
        hash.byte(chunk.chunk_kind);
    }
}

inline void hash_edge(fnv1a64_t& hash, const edge_record_t& record)
{
    hash.u64(record.id);
    hash.u64(record.source_entity);
    hash_entity_opt(hash, record.target_entity);
    hash.address(record.source);
    hash.address(record.target);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_call_quality(fnv1a64_t& hash, const call_graph_quality_t& quality)
{
    hash.byte(static_cast<std::uint8_t>(quality.provenance));
    hash.byte(quality.confidence);
    hash.u32(quality.contributor_count);
    hash.boolean(quality.conflicted);
}

inline void hash_call_node(fnv1a64_t& hash, const call_graph_node_record_t& record)
{
    hash.u64(record.function_id);
    hash.address(record.address);
    hash.u64(record.incoming_edges);
    hash.u64(record.outgoing_edges);
    hash.u64(record.indirect_edges);
    hash.u64(record.unresolved_sites);
}

inline void hash_call_site(fnv1a64_t& hash, const recovered_call_site_t& record)
{
    hash.u64(record.id);
    hash.u64(record.source_function_id);
    hash.u64(record.source_block_id);
    hash.u64(record.instruction_id);
    hash.address(record.address);
    hash.u32(record.first_candidate);
    hash.u32(record.candidate_count);
    hash.boolean(record.indirect);
    hash.boolean(record.tail_call);
    hash.boolean(record.unresolved);
}

inline void hash_call_candidate(fnv1a64_t& hash,
                                const recovered_call_candidate_t& record)
{
    hash.u64(record.id);
    hash.u64(record.call_site_id);
    hash.address(record.target);
    hash_entity_opt(hash, record.target_function_id);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash_call_quality(hash, record.quality);
    hash.u64(record.stable_source_id);
    hash.u32(record.rank);
    hash.boolean(record.external_target);
}

inline void hash_call_edge(fnv1a64_t& hash, const call_graph_edge_record_t& record)
{
    hash.u64(record.id);
    hash.u64(record.call_site_id);
    hash.u64(record.source_function_id);
    hash.u64(record.source_block_id);
    hash_entity_opt(hash, record.target_function_id);
    hash.address(record.call_site);
    hash.address(record.target);
    hash.byte(static_cast<std::uint8_t>(record.resolution));
    hash_call_quality(hash, record.quality);
    hash.u32(record.candidate_rank);
    hash.boolean(record.external_target);
    hash.boolean(record.target_noreturn);
}

inline void hash_call_conflict(fnv1a64_t& hash, const call_graph_conflict_t& record)
{
    hash.u64(record.id);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.u64(record.instruction_id);
    hash.u64(record.source_function_id);
    hash.u64(record.call_site_rva);
    hash.u64(record.selected_target_rva);
    hash.u64(record.competing_target_rva);
    hash.u64(record.selected_target_function_id);
    hash.u64(record.competing_target_function_id);
}

inline void hash_xref(fnv1a64_t& hash, const xref_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.source);
    hash.address(record.target);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_string_record(fnv1a64_t& hash, const string_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.address);
    hash.u64(record.byte_length);
    hash.byte(static_cast<std::uint8_t>(record.encoding));
    hash.string(record.value);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_symbol(fnv1a64_t& hash, const symbol_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.address);
    hash.string(record.name);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_coverage(fnv1a64_t& hash, const coverage_span_t& record)
{
    hash.address(record.start);
    hash.u64(record.size);
    hash.byte(static_cast<std::uint8_t>(record.reason));
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
    hash.u32(record.detail_code);
}

inline void hash_data_candidate(fnv1a64_t& hash,
                                const data_candidate_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.address);
    hash.u64(record.size);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash_address_opt(hash, record.target);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_switch(fnv1a64_t& hash, const switch_record_t& record)
{
    hash.u64(record.id);
    hash.u64(record.function_id);
    hash.address(record.dispatch);
    hash.address(record.table);
    hash_address_opt(hash, record.default_target);
    hash.u64(record.case_targets.size());
    for (const auto& target : record.case_targets)
        hash.address(target);
    hash.byte(record.entry_size);
    hash.boolean(record.relative_entries);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
}

inline void hash_type_candidate(fnv1a64_t& hash,
                                const type_candidate_record_t& record)
{
    hash.u64(record.id);
    hash.address(record.address);
    hash.byte(static_cast<std::uint8_t>(record.kind));
    hash.string(record.display_name);
    hash.string(record.canonical_type);
    hash.byte(static_cast<std::uint8_t>(record.provenance));
    hash.byte(record.confidence);
    hash.boolean(record.explicitly_unknown);
}

template <typename T, typename Fn>
inline snapshot_hash_class_digest_t hash_vector(const std::vector<T>& values,
                                                Fn&& element_hash)
{
    fnv1a64_t hash;
    hash.u64(values.size());
    for (const auto& value : values)
        element_hash(hash, value);
    return {static_cast<std::uint64_t>(values.size()), hash.value()};
}

inline snapshot_hash_class_digest_t hash_operand_facts(
    const operand_fact_store_t& facts,
    const snapshot_table_t<instruction_record_t>& instructions)
{
    fnv1a64_t hash;
    hash.u64(facts.size());
    for (std::size_t index = 0; index < facts.size(); ++index)
        hash_operand_fact(hash, operand_fact_materialize(facts, index, instructions));
    return {static_cast<std::uint64_t>(facts.size()), hash.value()};
}

}

inline snapshot_hash_result_t compute_snapshot_hash(const snapshot_hash_input_t& input)
{
    if (!input.snapshot || !input.data_candidates || !input.switches || !input.types)
        throw fixture_error_t("snapshot hash input is incomplete");
    const auto& snapshot = *input.snapshot;
    snapshot_hash_result_t result;
    auto& classes = result.classes;

    classes["instructions"] = detail::hash_vector(snapshot.instructions,
        detail::hash_instruction);
    {
        fnv1a64_t hash;
        hash.u64(snapshot.delay_slot_counts.size());
        hash.bytes(snapshot.delay_slot_counts.data(), snapshot.delay_slot_counts.size());
        classes["delay_slot_counts"] = {
            static_cast<std::uint64_t>(snapshot.delay_slot_counts.size()), hash.value()};
    }
    classes["operand_facts"] = detail::hash_operand_facts(snapshot.operand_facts,
        snapshot.instructions);
    classes["target_facts"] = detail::hash_vector(snapshot.target_facts,
        detail::hash_target_fact);
    classes["blocks"] = detail::hash_vector(snapshot.blocks,
        detail::hash_block);
    classes["function_chunks"] = detail::hash_vector(snapshot.function_chunks,
        detail::hash_chunk);
    classes["function_block_memberships"] =
        detail::hash_vector(snapshot.function_block_memberships,
            detail::hash_membership);
    classes["functions"] = detail::hash_vector(snapshot.functions,
        [&snapshot](fnv1a64_t& hash, const function_record_t& record) {
            detail::hash_function(hash, snapshot, record);
        });
    classes["edges"] = detail::hash_vector(snapshot.edges,
        detail::hash_edge);
    {
        fnv1a64_t hash;
        hash.u64(snapshot.call_graph.nodes.size());
        for (const auto& record : snapshot.call_graph.nodes)
            detail::hash_call_node(hash, record);
        hash.u64(snapshot.call_graph.call_sites.size());
        for (const auto& record : snapshot.call_graph.call_sites)
            detail::hash_call_site(hash, record);
        hash.u64(snapshot.call_graph.candidates.size());
        for (const auto& record : snapshot.call_graph.candidates)
            detail::hash_call_candidate(hash, record);
        hash.u64(snapshot.call_graph.edges.size());
        for (const auto& record : snapshot.call_graph.edges)
            detail::hash_call_edge(hash, record);
        hash.u64(snapshot.call_graph.conflicts.size());
        for (const auto& record : snapshot.call_graph.conflicts)
            detail::hash_call_conflict(hash, record);
        hash.u64(snapshot.call_graph.indirect_site_count);
        hash.u64(snapshot.call_graph.unresolved_site_count);
        hash.boolean(snapshot.call_graph.bounded);
        classes["call_graph"] = {static_cast<std::uint64_t>(
            snapshot.call_graph.nodes.size() + snapshot.call_graph.call_sites.size() +
            snapshot.call_graph.candidates.size() + snapshot.call_graph.edges.size() +
            snapshot.call_graph.conflicts.size()), hash.value()};
    }
    classes["xrefs"] = detail::hash_vector(snapshot.xrefs,
        detail::hash_xref);
    classes["strings"] = detail::hash_vector(snapshot.strings,
        detail::hash_string_record);
    classes["symbols"] = detail::hash_vector(snapshot.symbols,
        detail::hash_symbol);
    classes["coverage"] = detail::hash_vector(snapshot.coverage,
        detail::hash_coverage);
    classes["search.data_candidates"] = detail::hash_vector(*input.data_candidates,
        detail::hash_data_candidate);
    classes["search.switches"] = detail::hash_vector(*input.switches,
        detail::hash_switch);
    classes["search.types"] = detail::hash_vector(*input.types,
        detail::hash_type_candidate);
    {
        fnv1a64_t hash;
        hash.string(snapshot.binary_id.to_hex());
        hash.string(input.content_hash.to_hex());
        hash.string(snapshot.load_profile_hash.to_hex());
        hash.u64(snapshot.generation);
        hash.u64(snapshot.analysis_revision);
        hash.u64(snapshot.overlay_revision);
        classes["identity"] = {1, hash.value()};
    }

    nlohmann::json class_digests = nlohmann::json::object();
    for (const auto& entry : classes) {
        class_digests[entry.first] = nlohmann::json{
            {"count", entry.second.count},
            {"fnv1a64", snapshot_hash_result_t::fnv_hex(entry.second.fnv)}};
    }
    const auto digest = c03::sha256_evidence_text(class_digests.dump());
    if (!digest.ok)
        throw fixture_error_t("snapshot hash manifest digest failed: " + digest.error);
    result.manifest_sha256 = digest.sha256;
    return result;
}

inline nlohmann::json build_hash_manifest(
    const std::vector<std::pair<std::string,
        std::pair<std::uint32_t, snapshot_hash_result_t>>>& runs,
    bool& match_out)
{
    bool all_equal = true;
    for (std::size_t index = 1; index < runs.size(); ++index) {
        if (runs[index].second.second.manifest_sha256 !=
            runs.front().second.second.manifest_sha256)
            all_equal = false;
    }
    match_out = runs.size() >= 2 && all_equal;
    nlohmann::json manifest;
    if (runs.empty()) {
        manifest = nlohmann::json{
            {"hash_contract", "aida.hyperperf.snapshot-hash"},
            {"version", 1},
            {"classes", nlohmann::json::object()},
            {"manifest_sha256", ""}};
    } else {
        manifest = runs.front().second.second.manifest_json();
    }
    nlohmann::json run_entries = nlohmann::json::array();
    for (const auto& run : runs) {
        run_entries.push_back(nlohmann::json{
            {"label", run.first},
            {"lanes", run.second.first},
            {"manifest_sha256", run.second.second.manifest_sha256}});
    }
    manifest["runs"] = std::move(run_entries);
    manifest["match"] = runs.size() < 2 ? nlohmann::json(nullptr) : nlohmann::json(match_out);
    return manifest;
}

}
